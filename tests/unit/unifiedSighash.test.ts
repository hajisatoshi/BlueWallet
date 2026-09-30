import assert from 'assert';
import * as bitcoin from 'bitcoinjs-lib';
import ECPairFactory from 'ecpair';
import ecc from '../../blue_modules/noble_ecc';
import {
  hashForUnifiedSighash,
  isValidHashType,
  encodeDERSignature,
  signPsbtInputWithUnifiedSighash,
  SIGHASH_UNIFIED,
  SIGHASH_ALL,
} from '../../blue_modules/unifiedSighash';
import { isV2Header, extractTimestamp, validateHeaderLength } from '../../blue_modules/blake2bHeader';

const ECPair = ECPairFactory(ecc);
bitcoin.initEccLib(ecc);

describe('BLAKE2b Fork & Unified Sighash', () => {
  describe('Header v2 (BLAKE2b) parsing', () => {
    it('detects classic 80-byte header vs v2 164-byte header', () => {
      // Classic 80-byte header: 160 hex chars, version without top bit
      const classicHeader = '00000020' + '00'.repeat(32) + '11'.repeat(32) + 'aabbccdd' + 'ffff001f' + '12345678';
      assert.strictEqual(isV2Header(classicHeader), false);
      assert.strictEqual(validateHeaderLength(classicHeader), 'v1');

      // v2 164-byte header: 328 hex chars, version with top bit set (0x80000000)
      const v2Header = '00000080' + '00'.repeat(32) + '11'.repeat(32) + 'aabbccdd' + 'ffff001f' + '12345678' + '22'.repeat(84);
      assert.strictEqual(isV2Header(v2Header), true);
      assert.strictEqual(validateHeaderLength(v2Header), 'v2');
    });

    it('extracts timestamp correctly from both header formats', () => {
      // Timestamp at bytes 68-71 (chars 136-144): 0x68593412 LE = 0x12345968 = 305420648
      const tsHex = '68593412';
      const header80 = '00'.repeat(68) + tsHex + '00'.repeat(8);
      const header164 = '00'.repeat(68) + tsHex + '00'.repeat(92);

      const ts80 = extractTimestamp(header80);
      const ts164 = extractTimestamp(header164);

      assert.strictEqual(ts80, ts164);
      assert.strictEqual(ts80, 0x12345968);
    });
  });

  describe('Unified Sighash (0x21)', () => {
    it('validates hash types correctly', () => {
      assert.strictEqual(isValidHashType(0x21), true); // ALL | UNIFIED
      assert.strictEqual(isValidHashType(0x22), true); // NONE | UNIFIED
      assert.strictEqual(isValidHashType(0x23), true); // SINGLE | UNIFIED
      assert.strictEqual(isValidHashType(0xa1), true); // ALL | ANYONECANPAY | UNIFIED
      assert.strictEqual(isValidHashType(0x01), false); // legacy ALL without UNIFIED
      assert.strictEqual(isValidHashType(0x20), false); // bare UNIFIED without base type
    });

    it('signs PSBT input with 0x21 unified sighash', () => {
      const keyPair = ECPair.makeRandom();
      const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: keyPair.publicKey });

      const psbt = new bitcoin.Psbt();
      psbt.addInput({
        hash: '00'.repeat(32),
        index: 0,
        witnessUtxo: {
          script: p2wpkh.output!,
          value: BigInt(50000),
        },
      });
      psbt.addOutput({
        address: p2wpkh.address!,
        value: BigInt(45000),
      });

      signPsbtInputWithUnifiedSighash(psbt, 0, keyPair);

      const partialSigs = psbt.data.inputs[0].partialSig;
      assert.ok(partialSigs && partialSigs.length === 1);
      assert.strictEqual(partialSigs[0].signature[partialSigs[0].signature.length - 1], 0x21);
    });
  });

  describe('Somali Localization (Af-Soomaali)', () => {
    it('provides Somali translations for key Bitcoin and wallet terms', () => {
      const soJson = require('../../loc/so.json');
      assert.ok(soJson);
      assert.strictEqual(soJson._.cancel, 'Jooji');
      assert.strictEqual(soJson.wallets.list_title, 'Boorsooyinka');
      assert.strictEqual(soJson.wallets.add_title, 'Ku dar Boorso');
      assert.strictEqual(soJson.send.header, 'Dir Lacag');
      assert.strictEqual(soJson.receive.header, 'Hel Lacag');
      assert.strictEqual(soJson.settings.header, 'Dejinta');
    });
  });
});