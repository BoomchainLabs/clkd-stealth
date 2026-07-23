import { describe, it, expect } from 'vitest';
import { genCloakedMessage } from '../src/client/genCloakedMessage';

const PREFIX = `Sign this message to generate your Cloaked private payment keys.

WARNING: Only sign this message within a trusted website or platform to avoid loss of funds.

Secret: `;

describe('genCloakedMessage', () => {
  // Captured from v1.1.0 before EIP-55 normalization was added. These pin the
  // exact derivation for the checksummed addresses used by existing production
  // callers. They do not claim compatibility for non-checksummed SDK inputs.
  describe('checksummed backwards compatibility', () => {
    it.each([
      {
        pin: '1234',
        address: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045',
        secret:
          'e6e501b47423bde3f2346249f779ff925ae35c159607d0fc804f94304fd513c3',
      },
      {
        pin: '0000',
        address: '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
        secret:
          '2ac9dc78114c5c5b5c502f414dc91394d3178f68731e4c6202830dcb703e1d34',
      },
    ])(
      'derives the pre-normalization message for $address / $pin',
      ({ pin, address, secret }) => {
        expect(genCloakedMessage({ pin, address }).message).toEqual(
          PREFIX + secret
        );
      }
    );
  });

  describe('address casing', () => {
    const checksummed = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';
    const messageFor = (address: string) =>
      genCloakedMessage({ pin: '1234', address }).message;

    it('derives the same message regardless of input casing', () => {
      const expected = messageFor(checksummed);

      expect(messageFor(checksummed.toLowerCase())).toEqual(expected);
      expect(messageFor('0x' + checksummed.slice(2).toUpperCase())).toEqual(
        expected
      );
      // Mixed case that is not a valid EIP-55 checksum.
      expect(messageFor('0xD8Da6bF26964Af9d7EEd9E03e53415d37Aa96045')).toEqual(
        expected
      );
    });

    it('does not alter the message for an already-checksummed address', () => {
      expect(messageFor(checksummed)).toContain(
        'e6e501b47423bde3f2346249f779ff925ae35c159607d0fc804f94304fd513c3'
      );
    });

    it('derives different messages for different addresses', () => {
      expect(messageFor(checksummed)).not.toEqual(
        messageFor('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed')
      );
    });
  });

  describe('validation', () => {
    const address = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';

    it.each(['0x', '0xnotanaddress', address.slice(0, -1), ''])(
      'throws for invalid address %s',
      (invalid) => {
        expect(() =>
          genCloakedMessage({ pin: '1234', address: invalid })
        ).toThrow('Address is not valid.');
      }
    );

    it.each(['123', '12345', 'abcd', '12a4', '', ' 123'])(
      'throws for invalid pin %s',
      (pin) => {
        expect(() => genCloakedMessage({ pin, address })).toThrow(
          'PIN must be exactly 4 digits.'
        );
      }
    );

    it('derives different messages for different pins', () => {
      expect(genCloakedMessage({ pin: '1234', address }).message).not.toEqual(
        genCloakedMessage({ pin: '4321', address }).message
      );
    });
  });
});
