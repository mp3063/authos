/**
 * PKCE (Proof Key for Code Exchange) utilities
 */

import type {PKCEChallenge} from '../types';

/**
 * Generate a cryptographically random string
 */
function generateRandomString(length: number): string {
  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  const randomValues = new Uint8Array(length);

  if (typeof window !== 'undefined' && window.crypto) {
    window.crypto.getRandomValues(randomValues);
  } else if (typeof global !== 'undefined' && global.crypto) {
    global.crypto.getRandomValues(randomValues);
  } else {
    // Fallback for environments without crypto
    for (let i = 0; i < length; i++) {
      randomValues[i] = Math.floor(Math.random() * 256);
    }
  }

  let result = '';
  for (let i = 0; i < length; i++) {
    result += charset[randomValues[i] % charset.length];
  }

  return result;
}

/**
 * Base64 URL encode
 */
function base64UrlEncode(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }

  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Generate SHA-256 hash
 */
async function sha256(plain: string): Promise<ArrayBuffer> {
  const encoder = new TextEncoder();
  const data = encoder.encode(plain);

  if (typeof window !== 'undefined' && window.crypto?.subtle) {
    return await window.crypto.subtle.digest('SHA-256', data);
  } else if (typeof global !== 'undefined' && global.crypto?.subtle) {
    return await global.crypto.subtle.digest('SHA-256', data);
  }

  throw new Error('SubtleCrypto is not available');
}

/**
 * Generate PKCE code verifier and challenge
 */
export async function generatePKCEChallenge(): Promise<PKCEChallenge> {
  const codeVerifier = generateRandomString(128);
  const hashed = await sha256(codeVerifier);
  const codeChallenge = base64UrlEncode(hashed);

  return {
    code_verifier: codeVerifier,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  };
}

/**
 * Generate plain PKCE challenge (fallback)
 */
export function generatePlainPKCEChallenge(): PKCEChallenge {
  const codeVerifier = generateRandomString(128);

  return {
    code_verifier: codeVerifier,
    code_challenge: codeVerifier,
    code_challenge_method: 'plain',
  };
}

/**
 * Generate random state parameter
 */
export function generateState(): string {
  return generateRandomString(32);
}
