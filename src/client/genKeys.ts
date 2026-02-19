import { keccak256, hexToBytes } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

const SECRET_BYTES = 32;

/**
 * Derives stealth key pairs from two separate secrets.
 *
 * Each secret is hashed with keccak256 to produce a secp256k1 private key,
 * and the corresponding public key is derived on the curve.
 *
 * This is the recommended entry point for callers whose entropy naturally
 * arrives as two independent values — such as WebAuthn PRF with two salts:
 *
 * ```ts
 * import { genKeys } from '@cloakedxyz/clkd-stealth';
 *
 * const prfResults = assertion.getClientExtensionResults().prf.results;
 * const keys = genKeys({
 *   spendSecret: toHex(prfResults.first),
 *   viewSecret: toHex(prfResults.second),
 * });
 * ```
 *
 * The secrets can come from any source that provides at least 32 bytes of
 * cryptographic randomness: WebAuthn PRF, `crypto.getRandomValues()`,
 * `openssl rand`, HKDF output, etc.
 *
 * @param spendSecret - 32 bytes of entropy for the spending key (0x-prefixed hex).
 * @param viewSecret - 32 bytes of entropy for the viewing key (0x-prefixed hex).
 * @returns Spending and viewing key pairs (private + public).
 * @throws If either secret is not exactly 32 bytes.
 */
export function genKeys({
  spendSecret,
  viewSecret,
}: {
  spendSecret: `0x${string}`;
  viewSecret: `0x${string}`;
}): {
  p_view: `0x${string}`;
  P_view: `0x${string}`;
  p_spend: `0x${string}`;
  P_spend: `0x${string}`;
} {
  const spendBytes = parseSecret(spendSecret, 'spendSecret');
  const viewBytes = parseSecret(viewSecret, 'viewSecret');

  const p_spend = keccak256(spendBytes) as `0x${string}`;
  const p_view = keccak256(viewBytes) as `0x${string}`;

  const P_spend = privateKeyToAccount(p_spend).publicKey;
  const P_view = privateKeyToAccount(p_view).publicKey;

  return { p_view, P_view, p_spend, P_spend };
}

function parseSecret(secret: `0x${string}`, name: string): Uint8Array {
  if (!secret.startsWith('0x')) {
    throw new Error(`Invalid ${name}: expected 0x-prefixed hex string.`);
  }

  const bytes = hexToBytes(secret);

  if (bytes.length !== SECRET_BYTES) {
    throw new Error(
      `Invalid ${name}: expected exactly ${SECRET_BYTES} bytes, got ${bytes.length}.`
    );
  }

  return bytes;
}
