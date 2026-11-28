/**
 * @file frontend/src/services/authService.js
 * @notice Centralized Role Authentication & Cross-Portal State Persistence
 * 
 * Enforces role segregation between:
 * 1. Patient: Sovereign health record custody & DEK delegation
 * 2. Hospital: Clinical inspection & Groth16 ZKP claim generation
 * 3. Insurer: Solvency pool & on-chain settlement via MetaMask
 */

import { MOCK_PATIENT, MOCK_HOSPITALS, MOCK_ACCOUNTS } from '../data/mockData';
import { supabase, isSupabaseConfigured } from './supabaseClient';

export const ROLES = {
  PATIENT: 'patient',
  HOSPITAL: 'hospital',
  INSURER: 'insurer',
  XRAY: 'xray',
  REDTEAM: 'redteam',
  PRICING: 'pricing',
};

export const DEMO_USERS = {
  patient: {
    role: 'patient',
    id: 'patient-001',
    name: 'Alex Doe',
    email: 'alex.doe@parda.health',
    password: 'parda@patient2026',
    address: '0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC',
    policyId: 'POL-987654-ZKP',
    policyProvider: 'HealthShield Mutual Decentralized Pool',
    policyLimitEth: '5.0',
    policyExpiry: '2030-12-31',
    abhaId: 'ABHA-9821-4412-8801',
  },
  hospital: {
    role: 'hospital',
    id: 'hosp-101',
    name: 'St. Jude Medical Center',
    loginId: 'stjude@parda.health',
    password: 'parda@hospital2026',
    licenseNo: 'LIC-NY-2024-8849',
    address: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
    merkleRootVerified: true,
    department: 'Department of Internal Medicine & Cardiology',
  },
  hospital_alt: {
    role: 'hospital',
    id: 'hosp-102',
    name: 'Metropolitan General Hospital',
    loginId: 'metropolitan@parda.health',
    password: 'parda@hospital2026',
    licenseNo: 'LIC-CA-2023-1102',
    address: '0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65',
    merkleRootVerified: true,
    department: 'Acute Care & Inpatient Services',
  },
  insurer: {
    role: 'insurer',
    id: 'ins-001',
    name: 'HealthShield Mutual',
    loginId: 'underwriting@healthshield.eth',
    password: 'parda@insurer2026',
    poolId: 'INS-ETH-POOL-01',
    address: '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
    merkleRoot: '0x08581786b454cf726808eca1e5bddfbb948f741cd5ae3d89b6c65f3aeda1da7b',
    coverageCapEth: '5.0',
  },
  insurer_alt: {
    role: 'insurer',
    id: 'ins-002',
    name: 'Star Health Decentralized Pool',
    loginId: 'claims@starhealth.eth',
    password: 'parda@insurer2026',
    poolId: 'INS-ETH-STAR-02',
    address: '0x90F79bf6EB2c4f870365E785982E1f101E93b906',
    merkleRoot: '0x08581786b454cf726808eca1e5bddfbb948f741cd5ae3d89b6c65f3aeda1da7b',
    coverageCapEth: '5.0',
  },
};

/**
 * Verify credentials against demo store or custom format
 */
export function verifyCredentials(role, loginId, password) {
  const normLogin = (loginId || '').trim().toLowerCase();

  if (role === 'patient') {
    if (normLogin === 'alex.doe@parda.health' || normLogin === 'alex') {
      return { success: true, user: DEMO_USERS.patient };
    }
  } else if (role === 'hospital') {
    if (normLogin === 'stjude@parda.health' || normLogin === 'stjude' || normLogin === 'lic-ny-2024-8849') {
      return { success: true, user: DEMO_USERS.hospital };
    }
    if (normLogin === 'metropolitan@parda.health' || normLogin === 'metropolitan' || normLogin === 'lic-ca-2023-1102') {
      return { success: true, user: DEMO_USERS.hospital_alt };
    }
  } else if (role === 'insurer') {
    if (normLogin === 'underwriting@healthshield.eth' || normLogin === 'healthshield' || normLogin === 'ins-eth-pool-01') {
      return { success: true, user: DEMO_USERS.insurer };
    }
    if (normLogin === 'claims@starhealth.eth' || normLogin === 'starhealth' || normLogin === 'ins-eth-star-02') {
      return { success: true, user: DEMO_USERS.insurer_alt };
    }
  }
  return { success: false };
}

const STORAGE_KEYS = {
  ACTIVE_SESSION: 'parda_role_active_session_v3',
  PENDING_CLAIMS: 'parda_pending_claims_queue_v3',
  SETTLED_CLAIMS: 'parda_settled_claims_ledger_v3',
  HOSPITAL_BALANCE: 'parda_hospital_balance_eth_v3',
  POOL_BALANCE: 'parda_pool_balance_eth_v3',
  ACCESS_GRANTED: 'parda_doctor_access_granted_v3',
  SELECTED_HOSPITAL: 'parda_selected_delegated_hospital_v3',
};

// -------------------------------------------------------------
// Authentication Session Management
// -------------------------------------------------------------

export function getActiveRoleSession() {
  if (typeof window === 'undefined') return null;
  try {
    const raw = localStorage.getItem(STORAGE_KEYS.ACTIVE_SESSION);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export function setActiveRoleSession(sessionData) {
  if (typeof window === 'undefined') return;
  if (!sessionData) {
    localStorage.removeItem(STORAGE_KEYS.ACTIVE_SESSION);
  } else {
    localStorage.setItem(STORAGE_KEYS.ACTIVE_SESSION, JSON.stringify(sessionData));
  }
}

export function clearActiveRoleSession() {
  if (typeof window === 'undefined') return;
  localStorage.removeItem(STORAGE_KEYS.ACTIVE_SESSION);
}

// -------------------------------------------------------------
// Shared Workflow State Persistence (Cross-Portal & Cloud Sync)
// -------------------------------------------------------------

export function getPendingClaims() {
  if (typeof window === 'undefined') return [];
  try {
    const raw = localStorage.getItem(STORAGE_KEYS.PENDING_CLAIMS);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

export function savePendingClaims(claims) {
  if (typeof window === 'undefined') return;
  localStorage.setItem(STORAGE_KEYS.PENDING_CLAIMS, JSON.stringify(claims));
}

export async function fetchPendingClaimsFromCloud() {
  if (typeof window === 'undefined') return [];
  if (!isSupabaseConfigured() || !supabase) return getPendingClaims();

  try {
    const { data, error } = await supabase
      .from('claims')
      .select('*')
      .eq('status', 'PENDING')
      .order('created_at', { ascending: false });

    if (!error && data && data.length > 0) {
      const mapped = data.map((c) => ({
        id: c.id,
        hospitalName: c.hospital_name,
        hospitalLicense: c.hospital_license,
        hospitalAddress: c.hospital_address,
        payee: c.hospital_address,
        amountEth: parseFloat(c.amount_eth),
        amountInr: c.amount_inr,
        nullifier: c.nullifier,
        recordHash: c.patient_record_hash,
        treatmentCategory: c.treatment_category,
        diagnosisCode: c.diagnosis_code,
        status: 'PENDING',
        submittedAt: c.created_at,
      }));
      const local = getPendingClaims();
      const ids = new Set(mapped.map((m) => m.id));
      const combined = [...mapped, ...local.filter((l) => !ids.has(l.id))];
      savePendingClaims(combined);
      return combined;
    }
  } catch (err) {
    console.warn('[Parda] Could not fetch claims from Supabase:', err);
  }
  return getPendingClaims();
}

export function addPendingClaim(claim) {
  const existing = getPendingClaims();
  const updated = [claim, ...existing.filter((c) => c.id !== claim.id)];
  savePendingClaims(updated);

  // Background sync to Supabase Cloud so other laptops immediately see the claim
  if (isSupabaseConfigured() && supabase) {
    supabase
      .from('claims')
      .upsert({
        id: claim.id,
        hospital_name: claim.hospitalName || 'St. Jude Medical Center',
        hospital_license: claim.hospitalLicense || 'LIC-NY-2024-8849',
        hospital_address: claim.hospitalAddress || claim.payee || '',
        amount_eth: parseFloat(claim.amountEth) || 1.5,
        amount_inr: claim.amountInr || Math.round((parseFloat(claim.amountEth) || 1.5) * 10000),
        nullifier: claim.nullifier,
        patient_record_hash: claim.recordHash || '',
        treatment_category: claim.treatmentCategory || 'General Inpatient',
        diagnosis_code: claim.diagnosisCode || 'Z00.00',
        status: 'PENDING',
      })
      .then(({ error }) => {
        if (error) console.info('[Parda] Supabase claims sync:', error.message);
      })
      .catch(() => {});
  }

  return updated;
}

export function removePendingClaim(claimId) {
  const existing = getPendingClaims();
  const updated = existing.filter((c) => c.id !== claimId);
  savePendingClaims(updated);
  return updated;
}

export function getSettledClaims() {
  if (typeof window === 'undefined') return [];
  try {
    const raw = localStorage.getItem(STORAGE_KEYS.SETTLED_CLAIMS);
    if (raw) return JSON.parse(raw);
  } catch {}
  return [
    {
      id: 'tx-hist-001',
      nullifier: '0x7c81412089400ae9812739482019482019482019f3',
      hospitalName: 'Metropolitan General Hospital',
      payee: '0x15d3...6A65 (Metropolitan)',
      amountEth: 2.80,
      amountInr: 28000,
      status: 'VERIFIED VALID',
      timestamp: '11:30:00 AM',
      isReplayBlocked: false,
    },
  ];
}

export function saveSettledClaims(claims) {
  if (typeof window === 'undefined') return;
  localStorage.setItem(STORAGE_KEYS.SETTLED_CLAIMS, JSON.stringify(claims));
}

export async function fetchSettledClaimsFromCloud() {
  if (typeof window === 'undefined') return [];
  if (!isSupabaseConfigured() || !supabase) return getSettledClaims();

  try {
    const { data, error } = await supabase
      .from('claims')
      .select('*')
      .eq('status', 'SETTLED')
      .order('created_at', { ascending: false });

    if (!error && data && data.length > 0) {
      const mapped = data.map((c) => ({
        id: c.id,
        hospitalName: c.hospital_name,
        payee: c.hospital_address,
        amountEth: parseFloat(c.amount_eth),
        amountInr: c.amount_inr,
        nullifier: c.nullifier,
        status: 'VERIFIED VALID',
        timestamp: new Date(c.created_at).toLocaleTimeString(),
        txHash: c.tx_hash,
      }));
      const local = getSettledClaims();
      const ids = new Set(mapped.map((m) => m.id));
      const combined = [...mapped, ...local.filter((l) => !ids.has(l.id))];
      saveSettledClaims(combined);
      return combined;
    }
  } catch (err) {}
  return getSettledClaims();
}

export function addSettledClaim(claim) {
  const existing = getSettledClaims();
  const updated = [claim, ...existing.filter((c) => c.id !== claim.id)];
  saveSettledClaims(updated);

  // Mark settled in Supabase Cloud
  if (isSupabaseConfigured() && supabase) {
    supabase
      .from('claims')
      .update({
        status: 'SETTLED',
        tx_hash: claim.txHash || claim.id,
      })
      .eq('id', claim.id)
      .then(({ error }) => {
        if (error) console.info('[Parda] Supabase settle sync:', error.message);
      })
      .catch(() => {});
  }

  return updated;
}

export function getHospitalBalanceEth() {
  if (typeof window === 'undefined') return 14.20;
  const raw = localStorage.getItem(STORAGE_KEYS.HOSPITAL_BALANCE);
  return raw ? parseFloat(raw) : 14.20;
}

export function setHospitalBalanceEth(bal) {
  if (typeof window === 'undefined') return;
  localStorage.setItem(STORAGE_KEYS.HOSPITAL_BALANCE, String(bal));
}

export function getPoolBalanceEth() {
  if (typeof window === 'undefined') return 10.00;
  const raw = localStorage.getItem(STORAGE_KEYS.POOL_BALANCE);
  return raw ? parseFloat(raw) : 10.00;
}

export function setPoolBalanceEth(bal) {
  if (typeof window === 'undefined') return;
  localStorage.setItem(STORAGE_KEYS.POOL_BALANCE, String(bal));
}

export function getStoredDoctorAccessGranted() {
  if (typeof window === 'undefined') return false;
  return localStorage.getItem(STORAGE_KEYS.ACCESS_GRANTED) === 'true';
}

export function setStoredDoctorAccessGranted(val) {
  if (typeof window === 'undefined') return;
  localStorage.setItem(STORAGE_KEYS.ACCESS_GRANTED, val ? 'true' : 'false');

  if (isSupabaseConfigured() && supabase) {
    supabase
      .from('access_grants')
      .upsert({
        id: 'grant-alex-doe',
        patient_address: '0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc',
        hospital_name: 'St. Jude Medical Center',
        status: val ? 'ACTIVE' : 'REVOKED',
        updated_at: new Date().toISOString(),
      })
      .then(({ error }) => {
        if (error) console.info('[Parda] Supabase grant sync:', error.message);
      })
      .catch(() => {});
  }
}

export async function fetchDoctorAccessFromCloud() {
  if (typeof window === 'undefined') return getStoredDoctorAccessGranted();
  if (!isSupabaseConfigured() || !supabase) return getStoredDoctorAccessGranted();

  try {
    const { data, error } = await supabase
      .from('access_grants')
      .select('status')
      .eq('id', 'grant-alex-doe')
      .maybeSingle();

    if (!error && data) {
      const isGranted = data.status === 'ACTIVE';
      setStoredDoctorAccessGranted(isGranted);
      return isGranted;
    }
  } catch (e) {}
  return getStoredDoctorAccessGranted();
}

export function getSelectedDelegatedHospital() {
  if (typeof window === 'undefined') return MOCK_HOSPITALS[0];
  try {
    const raw = localStorage.getItem(STORAGE_KEYS.SELECTED_HOSPITAL);
    return raw ? JSON.parse(raw) : MOCK_HOSPITALS[0];
  } catch {
    return MOCK_HOSPITALS[0];
  }
}

export function setSelectedDelegatedHospital(hosp) {
  if (typeof window === 'undefined') return;
  localStorage.setItem(STORAGE_KEYS.SELECTED_HOSPITAL, JSON.stringify(hosp));
}

// Hospital enclave ECDH P-256 private decryption keys (only loaded inside Hospital role context)
const HOSPITAL_ECDH_PRIVATE_KEYS = {
  '0x70997970c51812dc3a010c7d01b50e0d17dc79c8': {
    key_ops: ['deriveBits'],
    ext: true,
    kty: 'EC',
    x: 'Xd45IOo_hAqzak3KFn0Omk0vpMeWtXD1vLwwiDaTFkA',
    y: 'OEjb__iLmQqQaAiIsl2nmrzD-RcPknPeDYu4yMEQ438',
    crv: 'P-256',
    d: 'VUKjemwwYtCkYZp8ahP8DMrlXw0NGogRgupp333RBhk',
  },
  '0x15d34aaf54267db7d7c367839aaf71a00a2c6a65': {
    key_ops: ['deriveBits'],
    ext: true,
    kty: 'EC',
    x: 'K_gG4Gfv8rR3AH3sM4A7qb8xZ5FFwiORy8WXhfUqTCo',
    y: 'Zimwlf3PXA9JEoC1SGAi02UN9rSlLe1CI314ZJdloMI',
    crv: 'P-256',
    d: 'NaYdJFmW8LGOgQxXv-egO645Vje94yxJwRL78wftHBA',
  },
};

export function getHospitalPrivateEcdhJwk(hospitalSession) {
  const addr = hospitalSession?.address?.toLowerCase();
  if (addr && HOSPITAL_ECDH_PRIVATE_KEYS[addr]) {
    return HOSPITAL_ECDH_PRIVATE_KEYS[addr];
  }
  const idStr = String(hospitalSession?.id || '');
  if (idStr.includes('102')) {
    return HOSPITAL_ECDH_PRIVATE_KEYS['0x15d34aaf54267db7d7c367839aaf71a00a2c6a65'];
  }
  return HOSPITAL_ECDH_PRIVATE_KEYS['0x70997970c51812dc3a010c7d01b50e0d17dc79c8'];
}
