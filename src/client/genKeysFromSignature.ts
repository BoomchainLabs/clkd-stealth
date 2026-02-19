import { hexToBytes, toHex, slice } from 'viem';
import { genKeys } from './genKeys';

/**
 * Derives stealth key pairs from an ECDSA signature.
 *
 * This is a convenience wrapper around {@link genKeys} for callers whose
 * entropy source is a message signature (e.g. from `account.signMessage`).
 * The r and s components of the signature provide two 32-byte secrets; the
 * recovery byte (v) is ignored.
 *
 * For non-signature entropy sources (WebAuthn PRF, raw randomness, HKDF),
 * use {@link genKeys} directly.
 *
 * Credit: Adapted from {@link https://github.com/ScopeLift/umbra-protocol Umbra Protocol}.
 *
 * @param signature - ECDSA signature as a hex string. Must be exactly 65 bytes (0x + 130 hex characters).
 * @returns Spending and viewing key pairs (private + public).
 * @throws If signature format is invalid.
 */
export function genKeysFromSignature(signature: `0x${string}`): {
  p_view: `0x${string}`;
  P_view: `0x${string}`;
  p_spend: `0x${string}`;
  P_spend: `0x${string}`;
} {
  if (!signature.startsWith('0x')) {
    throw new Error('Signature is not valid.');
  }

  // ECDSA signature: 0x + r (32 bytes) + s (32 bytes) + v (1 byte) = 0x + 130 hex chars
  if (signature.length !== 132) {
    throw new Error('Signature is not valid.');
  }

  const bytes = hexToBytes(signature);

  return genKeys({
    spendSecret: toHex(slice(bytes, 0, 32)) as `0x${string}`,
    viewSecret: toHex(slice(bytes, 32, 64)) as `0x${string}`,
  });
}
