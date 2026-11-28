/**
 * @file frontend/src/services/healthRecordService.js
 * @notice High-level service managing client-side encryption and Supabase sync
 */

import { supabase, isSupabaseConfigured } from './supabaseClient';
import {
  generatePatientKey,
  derivePatientKeyFromIdentity,
  exportKeyToBase64,
  importKeyFromBase64,
  encryptHealthRecord,
  decryptHealthRecord,
} from './cryptoService';

const PATIENT_KEY_STORAGE_PREFIX = 'parda_patient_key_';
const LOCAL_RECORD_STORAGE_PREFIX = 'parda_encrypted_record_';

/**
 * Gets or creates a sovereign AES-256-GCM encryption key for a given patient wallet.
 * Uses deterministic derivation so that across multiple laptops/browsers,
 * the patient reconstructs the EXACT same key to decrypt records from Supabase.
 * 
 * @param {string} patientAddress 
 * @returns {Promise<{ key: CryptoKey, base64Key: string }>}
 */
export async function getOrCreatePatientKey(patientAddress) {
  const normalizedAddr = patientAddress ? patientAddress.toLowerCase() : '0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc';
  const storageKey = PATIENT_KEY_STORAGE_PREFIX + normalizedAddr;
  const existingBase64 = localStorage.getItem(storageKey);

  if (existingBase64) {
    try {
      const key = await importKeyFromBase64(existingBase64);
      return { key, base64Key: existingBase64 };
    } catch (e) {
      console.warn('[Parda] Corrupt key in storage, regenerating:', e);
    }
  }

  // Derive deterministically so ANY device logging into this patient account
  // can reconstruct the exact same key to decrypt the Supabase Cloud Vault ciphertext
  try {
    const key = await derivePatientKeyFromIdentity(normalizedAddr);
    const base64Key = await exportKeyToBase64(key);
    localStorage.setItem(storageKey, base64Key);
    return { key, base64Key };
  } catch (err) {
    console.warn('[Parda] Fallback to random key generation:', err);
    const newKey = await generatePatientKey();
    const base64Key = await exportKeyToBase64(newKey);
    localStorage.setItem(storageKey, base64Key);
    return { key: newKey, base64Key };
  }
}

/**
 * Encrypts a health record and saves the ciphertext to Supabase.
 * Zero plaintext ever leaves the patient's device.
 * 
 * @param {object} params
 * @param {string} params.patientAddress - Patient's Ethereum account address
 * @param {object} params.recordData - FHIR bundle / medical records
 * @param {CryptoKey} [params.key] - Optional encryption key; generates/retrieves if omitted
 * @returns {Promise<object>} Upload receipt with recordHash, storageLocation, and recordId
 */
export async function uploadEncryptedRecord({ patientAddress, recordData, key }) {
  let activeKey = key;
  let base64Key = '';

  if (!activeKey) {
    const keyBundle = await getOrCreatePatientKey(patientAddress);
    activeKey = keyBundle.key;
    base64Key = keyBundle.base64Key;
  } else {
    base64Key = await exportKeyToBase64(activeKey);
  }

  // 1. Client-Side Encryption
  const encrypted = await encryptHealthRecord(recordData, activeKey);

  const payloadToStore = {
    patient_address: patientAddress ? patientAddress.toLowerCase() : 'unknown',
    record_hash: encrypted.recordHash,
    ciphertext: encrypted.ciphertext,
    iv: encrypted.iv,
    metadata: {
      resourceType: recordData.resourceType || 'Bundle',
      timestamp: new Date().toISOString(),
      policyId: recordData.coverage?.policyCommitment || 'POL-DEFAULT',
      encryptedAt: new Date().toISOString(),
    },
  };

  // Always save a local copy for offline resilience
  localStorage.setItem(
    LOCAL_RECORD_STORAGE_PREFIX + (patientAddress ? patientAddress.toLowerCase() : 'default'),
    JSON.stringify(payloadToStore)
  );

  // 2. Upload to Supabase if configured
  if (isSupabaseConfigured() && supabase) {
    try {
      const { data, error } = await supabase
        .from('encrypted_health_records')
        .upsert(payloadToStore, { onConflict: 'record_hash' })
        .select()
        .single();

      if (error) {
        console.warn('[Parda] Supabase upload failed, saved locally:', error.message);
        return {
          success: true,
          storage: 'local_encrypted',
          recordHash: encrypted.recordHash,
          base64Key,
          id: 'local-' + Date.now(),
          message: `Saved locally in encrypted vault (${error.message})`,
        };
      }

      return {
        success: true,
        storage: 'supabase_cloud',
        recordHash: encrypted.recordHash,
        base64Key,
        id: data?.id || 'supabase-' + Date.now(),
        message: 'Successfully encrypted and synced to Supabase Cloud Vault',
      };
    } catch (err) {
      console.warn('[Parda] Supabase exception:', err);
    }
  }

  // Supabase not configured yet (waiting for anon key)
  return {
    success: true,
    storage: 'local_encrypted',
    recordHash: encrypted.recordHash,
    base64Key,
    id: 'local-' + Date.now(),
    message: 'Encrypted locally with AES-256-GCM (Awaiting Supabase API Key for Cloud Sync)',
  };
}

/**
 * Fetches an encrypted record for a patient from Supabase (or local cache).
 * Prefers exact recordHash match when provided (for cross-laptop wrapped DEK grants).
 * @param {string} patientAddress 
 * @param {string} [preferredRecordHash]
 * @returns {Promise<object|null>}
 */
export async function fetchEncryptedRecord(patientAddress, preferredRecordHash = null) {
  const normalizedAddr = patientAddress ? patientAddress.toLowerCase() : 'default';

  if (isSupabaseConfigured() && supabase) {
    try {
      if (preferredRecordHash) {
        const { data: exactData, error: exactErr } = await supabase
          .from('encrypted_health_records')
          .select('*')
          .eq('record_hash', preferredRecordHash)
          .maybeSingle();

        if (!exactErr && exactData) {
          return { ...exactData, source: 'supabase' };
        }
      }

      const { data, error } = await supabase
        .from('encrypted_health_records')
        .select('*')
        .eq('patient_address', normalizedAddr)
        .order('created_at', { ascending: false })
        .limit(1)
        .maybeSingle();

      if (!error && data) {
        return { ...data, source: 'supabase' };
      }
    } catch (e) {
      console.warn('[Parda] Error fetching from Supabase:', e);
    }
  }

  // Fallback to local storage
  const local = localStorage.getItem(LOCAL_RECORD_STORAGE_PREFIX + normalizedAddr);
  if (local) {
    try {
      return { ...JSON.parse(local), source: 'local' };
    } catch (e) {
      return null;
    }
  }

  return null;
}

/**
 * Decrypts a fetched record using the shared decryption key.
 * 
 * @param {object} encryptedRecord 
 * @param {string|CryptoKey} decryptionKey - Base64 key string or CryptoKey
 * @returns {Promise<object>} Decrypted FHIR health record
 */
export async function decryptRecordWithKey(encryptedRecord, decryptionKey) {
  let key = decryptionKey;
  if (typeof decryptionKey === 'string') {
    key = await importKeyFromBase64(decryptionKey);
  }

  return await decryptHealthRecord(
    encryptedRecord.ciphertext,
    encryptedRecord.iv,
    key
  );
}
