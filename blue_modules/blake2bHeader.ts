/**
 * BLAKE2b v2 block header support for the Bitcoin BLAKE2b hardfork.
 *
 * Classic Bitcoin headers are 80 bytes. Post-fork (height >= 961,640 on mainnet),
 * BLAKE2b blocks use a 164-byte v2 header format.
 *
 * v2 header layout (164 bytes):
 *   [0..3]    version (4 bytes LE) — top bit set indicates v2 header
 *   [4..35]   previous block hash (32 bytes)
 *   [36..67]  merkle root (32 bytes)
 *   [68..71]  timestamp (4 bytes LE)
 *   [72..75]  bits (4 bytes LE)
 *   [76..79]  nonce (4 bytes LE) — for v2 headers, this is treated differently
 *   [80..163] extended data (84 bytes) — contains BLAKE2b PoW data
 *
 * Timestamp extraction: bytes 68-71 (hex chars 136-143) - same offset as classic headers
 * but the header is 164 bytes total instead of 80.
 *
 * Note: For simple timestamp extraction, the offset is the same (bytes 68-71 of the header).
 * The only change for many light-client operations is recognizing the header is 164 bytes
 * instead of 80, and the PoW hash uses BLAKE2b instead of SHA256d.
 */

/**
 * Detect if a header hex string is a v2 header (post-fork).
 * v2 headers have the top bit of the version word set.
 */
export function isV2Header(headerHex: string): boolean {
  if (headerHex.length < 8) return false;
  // Version is the first 8 hex chars (4 bytes LE).
  // The most significant byte is bytes[3], which is hex chars 6..7.
  const msb = parseInt(headerHex.slice(6, 8), 16);
  return (msb & 0x80) !== 0;
}

/**
 * Get the expected header hex length for a given header string.
 * Classic: 160 hex chars (80 bytes)
 * v2: 328 hex chars (164 bytes)
 */
export function getExpectedHeaderHexLength(headerHex: string): number {
  return isV2Header(headerHex) ? 328 : 160;
}

/**
 * Extract the timestamp from a block header hex string (works for both 80-byte and 164-byte headers).
 * Timestamp is always at bytes 68-71 (hex chars 136-143) in both formats.
 */
export function extractTimestamp(headerHex: string): number {
  // Ensure we have at least enough chars
  if (headerHex.length < 144) {
    throw new Error(`Header too short: ${headerHex.length} hex chars`);
  }
  // Timestamp is always at bytes 68-71 in both classic and v2 headers
  // Hex: 136-143 (16 hex chars * 68/4 = 136, 16 hex chars * 72/4 = 144)
  const tsHex = headerHex.slice(136, 144);
  const timestamp =
    parseInt(tsHex.slice(0, 2), 16) |
    (parseInt(tsHex.slice(2, 4), 16) << 8) |
    (parseInt(tsHex.slice(4, 6), 16) << 16) |
    ((parseInt(tsHex.slice(6, 8), 16) << 24) >>> 0);
  return timestamp;
}

/**
 * Validate a header hex string by length.
 * Returns 'v1' for 80-byte, 'v2' for 164-byte, or throws for unexpected lengths.
 */
export function validateHeaderLength(headerHex: string): 'v1' | 'v2' {
  const len = headerHex.length;
  if (len === 160 && headerHex.length % 2 === 0) return 'v1';
  if (len === 328 && headerHex.length % 2 === 0) return 'v2';
  throw new Error(
    `Unexpected header length: ${len} hex chars (expected 160 for v1 or 328 for v2)`,
  );
}