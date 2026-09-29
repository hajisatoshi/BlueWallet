/**
 * Unified opt-in signature hash (SIGHASH_UNIFIED = 0x20)
 *
 * Implements the opt-in sighash from Bitcoin Knots PR #357 / v29.4.1 BLAKE2b hardfork.
 * One signature hash for all input types, selected by setting bit 0x20 in the hash type byte.
 *
 * Specification: https://github.com/bitcoinknots/bitcoin/blob/main/doc/unified-sighash.md
 *
 * Tag: "UnifiedSighash"
 * Tagged hash: SHA256(SHA256("UnifiedSighash") || SHA256("UnifiedSighash") || message)
 */

import { sha256 } from '@noble/hashes/sha256';
import * as bitcoin from 'bitcoinjs-lib';
import type { Psbt } from 'bitcoinjs-lib';
import * as tools from 'uint8array-tools';

export const SIGHASH_UNIFIED = 0x20;
export const SIGHASH_ALL = 0x01;
export const SIGHASH_NONE = 0x02;
export const SIGHASH_SINGLE = 0x03;
export const SIGHASH_ANYONECANPAY = 0x80;

const TAG = 'UnifiedSighash';

const ZERO = tools.fromHex('0000000000000000000000000000000000000000000000000000000000000000');
const ONE = tools.fromHex('0000000000000000000000000000000000000000000000000000000000000001');

function varSliceSize(someScript: Uint8Array): number {
  const length = someScript.length;
  if (length < 0xfd) return 1 + length;
  if (length <= 0xffff) return 3 + length;
  if (length <= 0xffffffff) return 5 + length;
  return 9 + length;
}

function writeVarInt(buffer: Uint8Array, offset: number, value: number): number {
  if (value < 0xfd) {
    tools.writeUInt8(buffer, offset, value);
    return offset + 1;
  } else if (value <= 0xffff) {
    tools.writeUInt8(buffer, offset, 0xfd);
    tools.writeUInt16(buffer, offset + 1, value, 'LE');
    return offset + 3;
  } else if (value <= 0xffffffff) {
    tools.writeUInt8(buffer, offset, 0xfe);
    tools.writeUInt32(buffer, offset + 1, value, 'LE');
    return offset + 5;
  } else {
    tools.writeUInt8(buffer, offset, 0xff);
    tools.writeBigUInt64(buffer, offset + 1, BigInt(value), 'LE');
    return offset + 9;
  }
}

function writeVarSlice(buffer: Uint8Array, offset: number, slice: Uint8Array): number {
  offset = writeVarInt(buffer, offset, slice.length);
  tools.copy(slice, 0, slice.length, buffer, offset);
  return offset + slice.length;
}

/**
 * Hash type is valid for the unified algorithm if:
 * - SIGHASH_UNIFIED is set
 * - No bits outside 0x1f | SIGHASH_UNIFIED | SIGHASH_ANYONECANPAY are set
 * - hash_type & 0x1f is one of ALL, NONE, SINGLE
 */
export function isValidHashType(hashType: number): boolean {
  if (!(hashType & SIGHASH_UNIFIED)) return false;
  if (hashType & ~(0x1f | SIGHASH_UNIFIED | SIGHASH_ANYONECANPAY)) return false;
  const baseType = hashType & 0x1f;
  return baseType === SIGHASH_ALL || baseType === SIGHASH_NONE || baseType === SIGHASH_SINGLE;
}

/**
 * Compute the unified opt-in signature hash for a transaction input.
 */
export function hashForUnifiedSighash(
  tx: any,
  inIndex: number,
  prevOutScripts: Uint8Array[],
  values: bigint[],
  hashType: number,
  scriptType: number,
  scriptCode?: Uint8Array,
  tapLeafHash?: Uint8Array,
  annex?: Uint8Array,
): Uint8Array {
  if (!isValidHashType(hashType)) {
    throw new Error(`Invalid hash type for unified sighash: 0x${hashType.toString(16)}`);
  }

  if (inIndex >= tx.ins.length) {
    return ONE;
  }

  if (values.length !== tx.ins.length || prevOutScripts.length !== tx.ins.length) {
    throw new Error('Must supply prevout script and value for all inputs');
  }

  const baseType = hashType & 0x1f;
  const isAnyoneCanPay = !!(hashType & SIGHASH_ANYONECANPAY);
  const isNone = baseType === SIGHASH_NONE;
  const isSingle = baseType === SIGHASH_SINGLE;

  // SIGHASH_SINGLE with no output at the input's index is invalid
  if (isSingle && inIndex >= tx.outs.length) {
    return ONE;
  }

  // --- Compute aggregates (single SHA256) ---

  let hashPrevouts = ZERO;
  let hashAmounts = ZERO;
  let hashScripts = ZERO;
  let hashSequences = ZERO;
  let hashOutputs = ZERO;

  if (!isAnyoneCanPay) {
    // sha_prevouts
    {
      const buf = new Uint8Array(36 * tx.ins.length);
      let off = 0;
      for (const txIn of tx.ins) {
        tools.copy(txIn.hash, 0, 32, buf, off);
        off += 32;
        tools.writeUInt32(buf, off, txIn.index, 'LE');
        off += 4;
      }
      hashPrevouts = sha256(buf);
    }

    // sha_amounts
    {
      const buf = new Uint8Array(8 * values.length);
      let off = 0;
      for (const val of values) {
        tools.writeBigInt64(buf, off, val, 'LE');
        off += 8;
      }
      hashAmounts = sha256(buf);
    }

    // sha_scripts
    {
      const size = prevOutScripts.reduce((sum: number, s: Uint8Array) => sum + varSliceSize(s), 0);
      const buf = new Uint8Array(size);
      let off = 0;
      for (const script of prevOutScripts) {
        off = writeVarSlice(buf, off, script);
      }
      hashScripts = sha256(buf);
    }

    // sha_sequences
    {
      const buf = new Uint8Array(4 * tx.ins.length);
      let off = 0;
      for (const txIn of tx.ins) {
        tools.writeUInt32(buf, off, txIn.sequence, 'LE');
        off += 4;
      }
      hashSequences = sha256(buf);
    }
  }

  // sha_outputs
  if (!(isNone || isSingle)) {
    const outSize = tx.outs.reduce((sum: number, out: any) => sum + 8 + varSliceSize(out.script), 0);
    const buf = new Uint8Array(outSize);
    let off = 0;
    for (const out of tx.outs) {
      tools.writeBigInt64(buf, off, out.value, 'LE');
      off += 8;
      off = writeVarSlice(buf, off, out.script);
    }
    hashOutputs = sha256(buf);
  } else if (isSingle && inIndex < tx.outs.length) {
    const out = tx.outs[inIndex];
    const buf = new Uint8Array(8 + varSliceSize(out.script));
    let off = 0;
    tools.writeBigInt64(buf, off, out.value, 'LE');
    off += 8;
    writeVarSlice(buf, off, out.script);
    hashOutputs = sha256(buf);
  }

  // --- Build the message ---
  const messageSize = 1000 + prevOutScripts.reduce((acc: number, s: Uint8Array) => acc + s.length, 0);
  const msg = new Uint8Array(messageSize);
  let off = 0;

  // 1 byte: script type
  tools.writeUInt8(msg, off, scriptType);
  off += 1;

  // 4 bytes: hash type (little endian)
  tools.writeUInt32(msg, off, hashType, 'LE');
  off += 4;

  // 4 bytes: transaction version
  tools.writeUInt32(msg, off, tx.version, 'LE');
  off += 4;

  // 4 bytes: transaction locktime
  tools.writeUInt32(msg, off, tx.locktime, 'LE');
  off += 4;

  if (!isAnyoneCanPay) {
    tools.copy(hashPrevouts, 0, 32, msg, off);
    off += 32;

    tools.copy(hashAmounts, 0, 32, msg, off);
    off += 32;

    tools.copy(hashScripts, 0, 32, msg, off);
    off += 32;

    tools.copy(hashSequences, 0, 32, msg, off);
    off += 32;
  }

  // sha_outputs
  if (baseType === SIGHASH_ALL) {
    tools.copy(hashOutputs, 0, 32, msg, off);
    off += 32;
  } else if (isSingle) {
    tools.copy(hashOutputs, 0, 32, msg, off);
    off += 32;
  }

  // Input info
  if (isAnyoneCanPay) {
    tools.copy(tx.ins[inIndex].hash, 0, 32, msg, off);
    off += 32;
    tools.writeUInt32(msg, off, tx.ins[inIndex].index, 'LE');
    off += 4;

    tools.writeBigInt64(msg, off, values[inIndex], 'LE');
    off += 8;
    off = writeVarSlice(msg, off, prevOutScripts[inIndex]);

    tools.writeUInt32(msg, off, tx.ins[inIndex].sequence, 'LE');
    off += 4;
  } else {
    tools.writeUInt32(msg, off, inIndex, 'LE');
    off += 4;
  }

  // Tail for script type
  if (scriptType === 0 || scriptType === 1) {
    if (scriptCode) {
      off = writeVarSlice(msg, off, scriptCode);
    } else {
      off = writeVarSlice(msg, off, new Uint8Array(0));
    }
  } else if (scriptType === 2 || scriptType === 3) {
    tools.writeUInt8(msg, off, annex ? 1 : 0);
    off += 1;

    if (annex) {
      const annexSize = varSliceSize(annex);
      const annexBuf = new Uint8Array(annexSize);
      writeVarSlice(annexBuf, 0, annex);
      tools.copy(sha256(annexBuf), 0, 32, msg, off);
    } else {
      tools.copy(ZERO, 0, 32, msg, off);
    }
    off += 32;

    if (scriptType === 3) {
      if (tapLeafHash) {
        tools.copy(tapLeafHash, 0, 32, msg, off);
      } else {
        tools.copy(ZERO, 0, 32, msg, off);
      }
      off += 32;

      tools.writeUInt8(msg, off, 0);
      off += 1;

      tools.writeUInt32(msg, off, 0xffffffff, 'LE');
      off += 4;
    }
  }

  const message = msg.slice(0, off);
  const tagDigest = sha256(TAG);
  return sha256(tools.concat([tagDigest, tagDigest, message]));
}

/** Helper for DER encoding */
function toDER(x: Uint8Array): Uint8Array {
  let i = 0;
  while (x[i] === 0) ++i;
  if (i === x.length) return new Uint8Array([0]);
  x = x.slice(i);
  if (x[0] & 0x80) {
    const buf = new Uint8Array(x.length + 1);
    buf[0] = 0;
    buf.set(x, 1);
    return buf;
  }
  return x;
}

/**
 * Encode raw ECDSA signature bytes (r || s, 64 bytes) into DER format with hash type byte.
 */
export function encodeDERSignature(sig64: Uint8Array, hashType: number): Uint8Array {
  const r = toDER(sig64.slice(0, 32));
  const s = toDER(sig64.slice(32, 64));

  const derSig = new Uint8Array(6 + r.length + s.length);
  derSig[0] = 0x30; // SEQUENCE
  derSig[1] = 4 + r.length + s.length;
  derSig[2] = 0x02; // INTEGER
  derSig[3] = r.length;
  derSig.set(r, 4);
  derSig[4 + r.length] = 0x02; // INTEGER
  derSig[5 + r.length] = s.length;
  derSig.set(s, 6 + r.length);

  const finalSig = new Uint8Array(derSig.length + 1);
  finalSig.set(derSig, 0);
  finalSig[derSig.length] = hashType;
  return finalSig;
}

/**
 * Extract all spent output scripts and amounts from a PSBT.
 */
export function getPrevoutsFromPsbt(psbt: Psbt): { prevOutScripts: Uint8Array[]; values: bigint[] } {
  const prevOutScripts: Uint8Array[] = [];
  const values: bigint[] = [];
  const unsignedTx = (psbt as any).__CACHE.__TX;

  for (let i = 0; i < psbt.inputCount; i++) {
    const inp = psbt.data.inputs[i];
    if (inp.witnessUtxo) {
      prevOutScripts.push(inp.witnessUtxo.script);
      values.push(inp.witnessUtxo.value);
    } else if (inp.nonWitnessUtxo) {
      const utxoTx = inp.nonWitnessUtxo;
      const outIdx = unsignedTx.ins[i].index;
      prevOutScripts.push(utxoTx.outs[outIdx].script);
      values.push(utxoTx.outs[outIdx].value);
    } else {
      throw new Error(`Missing UTXO data for PSBT input #${i}`);
    }
  }
  return { prevOutScripts, values };
}

/**
 * Sign a single PSBT input using the unified opt-in signature hash (0x21 by default).
 */
export function signPsbtInputWithUnifiedSighash(
  psbt: Psbt,
  inputIndex: number,
  keyPair: any,
  hashType: number = SIGHASH_ALL | SIGHASH_UNIFIED,
): void {
  const { prevOutScripts, values } = getPrevoutsFromPsbt(psbt);
  const inputData = psbt.data.inputs[inputIndex];
  const unsignedTx = (psbt as any).__CACHE.__TX;

  let scriptType = 1; // default segwit v0
  let scriptCode: Uint8Array | undefined;

  if (inputData.witnessUtxo) {
    const witnessScript = inputData.witnessUtxo.script;
    if (witnessScript.length === 22 && witnessScript[0] === 0x00 && witnessScript[1] === 0x14) {
      // P2WPKH
      scriptType = 1;
      scriptCode = bitcoin.payments.p2pkh({
        hash: witnessScript.slice(2),
      }).output;
    } else if (inputData.witnessScript) {
      // P2WSH
      scriptType = 1;
      scriptCode = inputData.witnessScript;
    } else if (inputData.redeemScript) {
      // P2SH-P2WPKH or P2SH-P2WSH
      if (inputData.redeemScript.length === 22 && inputData.redeemScript[0] === 0x00 && inputData.redeemScript[1] === 0x14) {
        scriptType = 1;
        scriptCode = bitcoin.payments.p2pkh({
          hash: inputData.redeemScript.slice(2),
        }).output;
      } else {
        scriptType = 1;
        scriptCode = inputData.witnessScript || inputData.redeemScript;
      }
    } else {
      scriptType = 1;
      scriptCode = witnessScript;
    }
  } else {
    // Legacy P2PKH or P2SH
    scriptType = 0;
    if (inputData.redeemScript) {
      scriptCode = inputData.redeemScript;
    } else {
      scriptCode = prevOutScripts[inputIndex];
    }
  }

  const hash = hashForUnifiedSighash(
    unsignedTx,
    inputIndex,
    prevOutScripts,
    values,
    hashType,
    scriptType,
    scriptCode,
  );

  const sigRaw = keyPair.sign(hash);
  const finalSig = encodeDERSignature(sigRaw, hashType);

  const currentPartialSig = [...(inputData.partialSig || [])];
  const existingIndex = currentPartialSig.findIndex(
    ps => tools.compare(ps.pubkey, keyPair.publicKey) === 0,
  );
  if (existingIndex >= 0) {
    currentPartialSig[existingIndex] = { pubkey: keyPair.publicKey, signature: finalSig };
  } else {
    currentPartialSig.push({ pubkey: keyPair.publicKey, signature: finalSig });
  }

  psbt.data.updateInput(inputIndex, { partialSig: currentPartialSig });
}

/**
 * Sign a PSBT input using HD derivation (bip32Derivation) with the unified sighash.
 */
export function signPsbtInputHDWithUnifiedSighash(
  psbt: Psbt,
  inputIndex: number,
  hdRoot: any,
  hashType: number = SIGHASH_ALL | SIGHASH_UNIFIED,
): boolean {
  const inputData = psbt.data.inputs[inputIndex];
  if (!inputData.bip32Derivation || inputData.bip32Derivation.length === 0) {
    return false;
  }

  let signed = false;
  for (const derivation of inputData.bip32Derivation) {
    const isMatchingFingerprint =
      !derivation.masterFingerprint ||
      tools.compare(derivation.masterFingerprint, hdRoot.fingerprint) === 0;

    if (isMatchingFingerprint) {
      try {
        const child = hdRoot.derivePath(derivation.path);
        if (child.privateKey && tools.compare(child.publicKey, derivation.pubkey) === 0) {
          signPsbtInputWithUnifiedSighash(psbt, inputIndex, child, hashType);
          signed = true;
        }
      } catch (_) {}
    }
  }
  return signed;
}