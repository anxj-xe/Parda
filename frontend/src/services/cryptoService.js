/**
 * @file frontend/src/services/cryptoService.js
 * @notice Client-Side End-to-End Encryption (E2EE) Module for Parda Health Records
 * 
 * Uses standard W3C Web Crypto API (SubtleCrypto):
 * - Algorithm: AES-256-GCM (Authenticated Encryption with Associated Data)
 * - 96-bit (12-byte) cryptographically secure random Initialization Vector (IV)
 * - Computes SHA-256 digests for on-chain integrity anchoring (Sepolia ClaimManager & AccessLog)
 * - Zero plaintext ever leaves the patient's browser
 */

const webCrypto = typeof globalThis !== 'undefined' && globalThis.crypto ? globalThis.crypto : window.crypto;

// Convert ArrayBuffer to Base64
export function bufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return globalThis.btoa(binary);
}

// Convert Base64 to ArrayBuffer
export function base64ToBuffer(base64) {
  const binary = globalThis.atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// Convert ArrayBuffer to Hex String (0x...)
export function bufferToHex(buffer) {
  const bytes = new Uint8Array(buffer);
  return '0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Generates a high-entropy 256-bit AES-GCM symmetric key.
 * @returns {Promise<CryptoKey>}
 */
export async function generatePatientKey() {
  return await webCrypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256,
    },
    true, // extractable so patient can save or share with authorized doctor
    ['encrypt', 'decrypt']
  );
}

/**
 * Deterministically derives an AES-256-GCM CryptoKey from a patient's sovereign identity
 * (wallet address or seed) using PBKDF2 (100,000 rounds of SHA-256).
 * Ensures that ANY device (laptop, phone, tablet) logging into the account derives
 * the exact same cryptographic key to decrypt records fetched from Supabase.
 * 
 * @param {string} patientAddress - The patient's Ethereum wallet address or identity
 * @returns {Promise<CryptoKey>}
 */
export async function derivePatientKeyFromIdentity(patientAddress) {
  const enc = new TextEncoder();
  const normalized = (patientAddress || '0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc').toLowerCase();
  const salt = enc.encode('parda-sovereign-vault-v1-salt');

  const keyMaterial = await window.crypto.subtle.importKey(
    'raw',
    enc.encode(normalized),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

/**
 * Exports a CryptoKey to a portable Base64 key string.
 * @param {CryptoKey} key 
 * @returns {Promise<string>}
 */
export async function exportKeyToBase64(key) {
  const exported = await webCrypto.subtle.exportKey('raw', key);
  return bufferToBase64(exported);
}

/**
 * Imports a Base64 key string back into a CryptoKey object.
 * @param {string} base64Key 
 * @returns {Promise<CryptoKey>}
 */
export async function importKeyFromBase64(base64Key) {
  const rawBuffer = base64ToBuffer(base64Key);
  return await webCrypto.subtle.importKey(
    'raw',
    rawBuffer,
    {
      name: 'AES-GCM',
      length: 256,
    },
    true,
    ['encrypt', 'decrypt']
  );
}

/**
 * Computes deterministic SHA-256 hash of an object or string for on-chain anchoring.
 * @param {object|string} data 
 * @returns {Promise<string>} Hex string starting with 0x
 */
export async function computeSha256(data) {
  const jsonStr = typeof data === 'string' ? data : JSON.stringify(data);
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(jsonStr);
  const hashBuffer = await webCrypto.subtle.digest('SHA-256', dataBuffer);
  return bufferToHex(hashBuffer);
}

/**
 * Encrypts arbitrary health data (e.g. FHIR bundle, prescriptions, diagnosis)
 * using AES-256-GCM authenticated encryption.
 * 
 * @param {object|string} data - Plaintext record
 * @param {CryptoKey} key - 256-bit AES-GCM key
 * @returns {Promise<{ ciphertext: string, iv: string, recordHash: string }>}
 */
export async function encryptHealthRecord(data, key) {
  const jsonStr = typeof data === 'string' ? data : JSON.stringify(data);
  const encoder = new TextEncoder();
  const plaintextBytes = encoder.encode(jsonStr);

  // 96-bit cryptographically random IV for GCM
  const iv = webCrypto.getRandomValues(new Uint8Array(12));

  // Compute on-chain integrity anchor hash before encryption
  const recordHash = await computeSha256(jsonStr);

  // AES-GCM authenticated encryption
  const encryptedBuffer = await webCrypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
      tagLength: 128, // 128-bit authentication tag
    },
    key,
    plaintextBytes
  );

  return {
    ciphertext: bufferToBase64(encryptedBuffer),
    iv: bufferToBase64(iv.buffer),
    recordHash,
  };
}

/**
 * Decrypts an AES-256-GCM encrypted health record payload.
 * 
 * @param {string} ciphertextBase64 
 * @param {string} ivBase64 
 * @param {CryptoKey} key 
 * @returns {Promise<object>} Decrypted parsed JSON record
 */
export async function decryptHealthRecord(ciphertextBase64, ivBase64, key) {
  const ciphertextBuffer = base64ToBuffer(ciphertextBase64);
  const ivBuffer = base64ToBuffer(ivBase64);

  const decryptedBuffer = await webCrypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: new Uint8Array(ivBuffer),
      tagLength: 128,
    },
    key,
    ciphertextBuffer
  );

  const decoder = new TextDecoder();
  const jsonStr = decoder.decode(decryptedBuffer);
  return JSON.parse(jsonStr);
}

const DEK_WRAP_INFO = new TextEncoder().encode('PARDA-DEK-WRAP-V1');

/**
 * Wraps the patient's 256-bit AES-GCM Data Encryption Key (DEK) for a target grantee
 * using ephemeral ECDH P-256 + HKDF-SHA256 + AES-256-GCM key wrapping.
 * Safe to store in Supabase or transmit over pub/sub without revealing the raw DEK.
 *
 * @param {string} base64AesKey - Raw 256-bit patient AES key in Base64
 * @param {object} recipientEcdhPublicJwk - Recipient hospital ECDH P-256 public JWK
 * @returns {Promise<object>} Wrapped key bundle (ephemeralPublicKey, wrapIvBase64, wrappedDekBase64, alg)
 */
export async function wrapPatientKeyForGrantee(base64AesKey, recipientEcdhPublicJwk) {
  const dekRaw = base64ToBuffer(base64AesKey);

  const recipientPubKey = await webCrypto.subtle.importKey(
    'jwk',
    recipientEcdhPublicJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );

  const ephemeralPair = await webCrypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );

  const sharedBits = await webCrypto.subtle.deriveBits(
    { name: 'ECDH', public: recipientPubKey },
    ephemeralPair.privateKey,
    256
  );

  const hkdfBaseKey = await webCrypto.subtle.importKey(
    'raw',
    sharedBits,
    'HKDF',
    false,
    ['deriveKey']
  );

  const wrapKey = await webCrypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(32),
      info: DEK_WRAP_INFO,
    },
    hkdfBaseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  const wrapIv = webCrypto.getRandomValues(new Uint8Array(12));
  const wrappedDekBuffer = await webCrypto.subtle.encrypt(
    { name: 'AES-GCM', iv: wrapIv, tagLength: 128 },
    wrapKey,
    dekRaw
  );

  const ephemeralPublicKey = await webCrypto.subtle.exportKey('jwk', ephemeralPair.publicKey);

  return {
    alg: 'ECDH-P256-HKDF-SHA256-A256GCM',
    ephemeralPublicKey,
    wrapIvBase64: bufferToBase64(wrapIv.buffer),
    wrappedDekBase64: bufferToBase64(wrappedDekBuffer),
  };
}

/**
 * Unwraps a patient's ECDH-wrapped DEK bundle inside the authorized Hospital enclave browser.
 *
 * @param {object} wrappedBundle - { ephemeralPublicKey, wrapIvBase64, wrappedDekBase64 }
 * @param {object} recipientEcdhPrivateJwk - Recipient hospital ECDH P-256 private JWK
 * @returns {Promise<CryptoKey>} Unwrapped 256-bit AES-GCM CryptoKey ready for decryptHealthRecord
 */
export async function unwrapPatientKeyWithPrivateKey(wrappedBundle, recipientEcdhPrivateJwk) {
  if (!wrappedBundle?.ephemeralPublicKey || !wrappedBundle?.wrapIvBase64 || !wrappedBundle?.wrappedDekBase64) {
    throw new Error('Invalid wrapped DEK bundle');
  }

  const ephemeralPubKey = await webCrypto.subtle.importKey(
    'jwk',
    wrappedBundle.ephemeralPublicKey,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );

  const recipientPrivKey = await webCrypto.subtle.importKey(
    'jwk',
    recipientEcdhPrivateJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits']
  );

  const sharedBits = await webCrypto.subtle.deriveBits(
    { name: 'ECDH', public: ephemeralPubKey },
    recipientPrivKey,
    256
  );

  const hkdfBaseKey = await webCrypto.subtle.importKey(
    'raw',
    sharedBits,
    'HKDF',
    false,
    ['deriveKey']
  );

  const wrapKey = await webCrypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(32),
      info: DEK_WRAP_INFO,
    },
    hkdfBaseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  const rawDekBuffer = await webCrypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: new Uint8Array(base64ToBuffer(wrappedBundle.wrapIvBase64)),
      tagLength: 128,
    },
    wrapKey,
    base64ToBuffer(wrappedBundle.wrappedDekBase64)
  );

  return await webCrypto.subtle.importKey(
    'raw',
    rawDekBuffer,
    { name: 'AES-GCM', length: 256 },
    true,
    ['decrypt']
  );
}
