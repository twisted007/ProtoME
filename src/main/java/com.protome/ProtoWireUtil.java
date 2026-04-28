package com.protome;

import java.io.ByteArrayOutputStream;

/**
 * ProtoWireUtil — shared low-level Protobuf wire format helpers.
 *
 * These three operations (read varint, write varint, skip payload) are needed
 * by both ProtoMutator (which deliberately corrupts wire bytes) and the new
 * BlackboxDecoder/BlackboxEncoder (which parse and reconstruct wire bytes without
 * a schema). Centralising them here avoids duplicating the bit-manipulation logic
 * across multiple classes.
 *
 * All methods are static — this class has no state and is never instantiated.
 *
 * Protobuf wire format quick reference:
 *   Each field on the wire is a (tag, payload) pair.
 *   The tag is a varint encoding: (field_number << 3) | wire_type
 *   Wire types:
 *     0 = VARINT  — 1-10 bytes, variable length, continuation bit on each byte
 *     1 = I64     — exactly 8 bytes (double, fixed64, sfixed64)
 *     2 = LEN     — length varint followed by that many bytes (string, bytes, nested msg, packed)
 *     5 = I32     — exactly 4 bytes (float, fixed32, sfixed32)
 *     NOTE: Type 3 (SGROUP) and Type 4(EGROUP) are both deprecated wire types. They are not currently included, but may be in a future update.
 */
public class ProtoWireUtil {

    /**
     * Reads a varint from data[] starting at pos[0], advances pos[0] past it,
     * and returns the decoded value.
     *
     * Varint encoding: each byte contributes 7 bits of value (its lower 7 bits).
     * The high bit (0x80) is a continuation flag — set means more bytes follow,
     * clear means this is the last byte. Bytes are in little-endian order.
     *
     * Example: value 300 encodes as [0xAC, 0x02]
     *   byte 0: 0xAC = 1_010_1100  → continuation set, value bits = 010_1100 = 44
     *   byte 1: 0x02 = 0_000_0010  → continuation clear, value bits = 10 → shifted 7 = 256
     *   result: 44 + 256 = 300
     *
     * We cap at 70 bits (10 bytes) as a safety guard against malformed input that
     * never clears the continuation bit.
     */
    public static long readVarint(byte[] data, int[] pos) {
        long value = 0;
        int shift = 0;
        while (pos[0] < data.length) {
            byte b = data[pos[0]++];
            value |= (long)(b & 0x7F) << shift;  // accumulate 7 payload bits
            if ((b & 0x80) == 0) break;           // high bit clear = last byte
            shift += 7;
            if (shift >= 70) break;               // safety: 10-byte spec maximum
        }
        return value;
    }

    /**
     * Encodes value as a varint and writes it to out.
     *
     * Each output byte holds 7 bits of value in its lower bits.
     * The high bit is set on every byte except the last, signalling "more follows".
     */
    public static void writeVarint(ByteArrayOutputStream out, long value) {
        while (true) {
            if ((value & ~0x7FL) == 0) {          // all remaining bits fit in 7 bits
                out.write((int) value);
                return;
            }
            out.write((int)((value & 0x7F) | 0x80)); // write 7 bits with continuation flag
            value >>>= 7;                            // unsigned right shift — no sign extension
        }
    }

    /**
     * Advances pos[0] past the payload of a single field without returning the bytes.
     * Used when we want to skip over a field we are not modifying.
     *
     * Returns true if the skip succeeded, false if the data is malformed or truncated.
     * Callers should bail out (stop processing) if this returns false.
     */
    public static boolean skipPayload(byte[] data, int[] pos, int wireType) {
        switch (wireType) {
            case 0: // VARINT — read until a byte with no continuation bit
                readVarint(data, pos);
                return pos[0] <= data.length;
            case 1: // I64 — always exactly 8 bytes
                if (pos[0] + 8 > data.length) return false;
                pos[0] += 8;
                return true;
            case 2: // LEN — length varint followed by that many payload bytes
                long len = readVarint(data, pos);
                if (len < 0 || pos[0] + len > data.length) return false;
                pos[0] += (int) len;
                return true;
            case 5: // I32 — always exactly 4 bytes
                if (pos[0] + 4 > data.length) return false;
                pos[0] += 4;
                return true;
            default:
                return false; // unrecognised wire type — caller should stop processing
        }
    }
}
