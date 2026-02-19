import { describe, it, expect } from 'vitest';
import { keccak256, toHex } from 'viem';
import { genKeys } from '../src/client/genKeys';
import { genKeysFromSignature } from '../src/client/genKeysFromSignature';

describe('genKeys', () => {
  const spendSecret =
    '0xd6bf71e45d06a0ccc68523f090148e38941cbdf4113edb59ecad3e0a5f1e7ceb' as const;
  const viewSecret =
    '0x7b6fd1e1ddd1d2141f263bcfa4b1a3f8bf64f809aaed1b03e722cd88c82344c2' as const;

  it('should derive key pairs from two secrets', () => {
    const { p_spend, p_view, P_spend, P_view } = genKeys({
      spendSecret,
      viewSecret,
    });

    expect(p_spend).toMatch(/^0x[0-9a-f]{64}$/);
    expect(p_view).toMatch(/^0x[0-9a-f]{64}$/);
    expect(P_spend).toMatch(/^0x04[0-9a-f]{128}$/);
    expect(P_view).toMatch(/^0x04[0-9a-f]{128}$/);
  });

  it('should hash secrets with keccak256 to produce private keys', () => {
    const { p_spend, p_view } = genKeys({ spendSecret, viewSecret });

    expect(p_spend).toEqual(keccak256(spendSecret));
    expect(p_view).toEqual(keccak256(viewSecret));
  });

  it('should produce identical output to genKeysFromSignature for equivalent input', () => {
    // An ECDSA signature: r (32 bytes) + s (32 bytes) + v (1 byte)
    const signature = (spendSecret +
      viewSecret.slice(2) +
      '1b') as `0x${string}`;

    const fromPair = genKeys({ spendSecret, viewSecret });
    const fromSig = genKeysFromSignature(signature);

    expect(fromPair).toEqual(fromSig);
  });

  it('should be deterministic', () => {
    const a = genKeys({ spendSecret, viewSecret });
    const b = genKeys({ spendSecret, viewSecret });

    expect(a).toEqual(b);
  });

  it('should produce different spending and viewing keys', () => {
    const { p_spend, p_view, P_spend, P_view } = genKeys({
      spendSecret,
      viewSecret,
    });

    expect(p_spend).not.toEqual(p_view);
    expect(P_spend).not.toEqual(P_view);
  });

  it('should produce different keys for different secrets', () => {
    const other =
      '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef' as const;

    const a = genKeys({ spendSecret, viewSecret });
    const b = genKeys({ spendSecret: other, viewSecret });

    expect(a.p_spend).not.toEqual(b.p_spend);
    expect(a.p_view).toEqual(b.p_view); // viewSecret unchanged
  });

  it('should work with Uint8Array-sourced secrets via toHex', () => {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) bytes[i] = i;
    const hex = toHex(bytes);

    const { p_spend, P_spend } = genKeys({
      spendSecret: hex,
      viewSecret: hex,
    });

    expect(p_spend).toMatch(/^0x[0-9a-f]{64}$/);
    expect(P_spend).toMatch(/^0x04[0-9a-f]{128}$/);
  });

  it('should throw if spendSecret is not 32 bytes', () => {
    const short = ('0x' + 'ab'.repeat(16)) as `0x${string}`;

    expect(() => genKeys({ spendSecret: short, viewSecret })).toThrow(
      'Invalid spendSecret: expected exactly 32 bytes, got 16.'
    );
  });

  it('should throw if viewSecret is not 32 bytes', () => {
    const long = ('0x' + 'ab'.repeat(64)) as `0x${string}`;

    expect(() => genKeys({ spendSecret, viewSecret: long })).toThrow(
      'Invalid viewSecret: expected exactly 32 bytes, got 64.'
    );
  });

  it('should throw if secret is missing 0x prefix', () => {
    const noPrefix = spendSecret.slice(2) as `0x${string}`;

    expect(() => genKeys({ spendSecret: noPrefix, viewSecret })).toThrow(
      'Invalid spendSecret'
    );
  });
});
