package com.protome;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * ProtoMutator — the fuzzing engine.
 *
 * Takes a valid binary Protobuf message and deliberately corrupts it in one of
 * five structured ways, each designed to stress-test a different weakness in
 * server-side Protobuf parsers.
 *
 * Background — Protobuf wire format basics:
 *   A serialized Protobuf message is a flat sequence of (tag, payload) pairs.
 *   Each tag is a varint that encodes two things packed together:
 *     - field number (upper bits): which field in the schema this is
 *     - wire type  (lower 3 bits): how to interpret the bytes that follow
 *
 *   The four wire types we deal with here:
 *     0 = VARINT  — variable-length integer (1-10 bytes, continuation bit on each byte)
 *     1 = I64     — fixed 8 bytes (doubles, fixed64)
 *     2 = LEN     — length-delimited (strings, bytes, nested messages): length varint + payload
 *     5 = I32     — fixed 4 bytes (floats, fixed32)
 *
 * Why mutate at the binary level rather than the JSON level?
 *   JSON mutations can only produce semantically invalid values (wrong type, out of range).
 *   Binary mutations can produce structurally invalid wire frames that JSON-level tools
 *   can't express — wrong wire type for a field, overlapping length prefixes, varints
 *   longer than the spec allows, etc. These are the kinds of inputs that expose parser
 *   bugs in generated code and hand-rolled decoders alike.
 *
 * Usage: ProtomeHttpHandler calls mutate() after serialization but before gRPC framing,
 * triggered by the "protome-mutate: <strategy>" request header.
 *
 * Wire format helpers (readVarint, writeVarint, skipPayload) live in ProtoWireUtil
 * and are shared with BlackboxDecoder and BlackboxEncoder.
 */
public class ProtoMutator {

    // Dispatcher — maps the header value string to the corresponding strategy method.
    public static byte[] mutate(byte[] input, String strategy) throws Exception {
        switch (strategy.toLowerCase()) {
            case "wire-type-flip":  return wireTypeFlip(input);
            case "varint-overflow": return varintOverflow(input);
            case "length-bomb":     return lengthBomb(input);
            case "duplicate-field": return duplicateField(input);
            case "unknown-field":   return unknownField(input);
            default: throw new IllegalArgumentException("Unknown mutation strategy: " + strategy);
        }
    }

    // =========================================================================
    // STRATEGY 1: wire-type-flip
    // =========================================================================
    // Walks every field tag in the message and flips its wire type:
    //   VARINT (0) <-> LEN (2)
    //   I64    (1) <-> I32 (5)
    //
    // The payload bytes are copied unchanged — only the tag is modified.
    // The parser will see the correct field number but the wrong type, forcing
    // it to interpret, say, a string's length-delimited bytes as a raw integer.
    // Well-hardened parsers reject the mismatch; buggy ones may read garbage
    // or panic trying to decode an incompatible payload.
    private static byte[] wireTypeFlip(byte[] input) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int[] pos = {0}; // pos is an array so the helper methods can update it (Java pass-by-value limitation)
        while (pos[0] < input.length) {
            int fieldStart = pos[0];
            long tag = ProtoWireUtil.readVarint(input, pos);
            int wireType = (int)(tag & 0x7);       // lower 3 bits = wire type
            long fieldNum = tag >>> 3;              // upper bits = field number (>>> is unsigned right shift)

            int payloadStart = pos[0];
            if (!ProtoWireUtil.skipPayload(input, pos, wireType)) {
                // Malformed or truncated — copy the rest as-is and stop
                out.write(input, fieldStart, input.length - fieldStart);
                return out.toByteArray();
            }

            // Write a new tag with the same field number but a flipped wire type,
            // then copy the original payload bytes unchanged.
            ProtoWireUtil.writeVarint(out, (fieldNum << 3) | flipWireType(wireType));
            out.write(input, payloadStart, pos[0] - payloadStart);
        }
        return out.toByteArray();
    }

    // =========================================================================
    // STRATEGY 2: varint-overflow
    // =========================================================================
    // For every VARINT-type field, re-encodes the value using exactly 11 bytes
    // instead of the minimum needed. The Protobuf spec caps varints at 10 bytes
    // (sufficient for any 64-bit integer). The 11th byte, with its continuation
    // bit set, signals "more bytes follow" — exceeding the spec limit.
    //
    // Strict parsers reject 11-byte varints outright. Lenient parsers may read
    // past the buffer boundary or silently truncate the value in unpredictable ways.
    private static byte[] varintOverflow(byte[] input) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int[] pos = {0};
        while (pos[0] < input.length) {
            int fieldStart = pos[0];
            long tag = ProtoWireUtil.readVarint(input, pos);
            int wireType = (int)(tag & 0x7);
            ProtoWireUtil.writeVarint(out, tag); // tag is written unchanged

            if (wireType == 0) {
                // VARINT field — read the value and re-encode it with intentional overflow
                long value = ProtoWireUtil.readVarint(input, pos);
                writeOverflowVarint(out, value);
            } else {
                // Non-VARINT field — copy payload as-is
                int payloadStart = pos[0];
                if (!ProtoWireUtil.skipPayload(input, pos, wireType)) {
                    out.write(input, fieldStart, input.length - fieldStart);
                    return out.toByteArray();
                }
                out.write(input, payloadStart, pos[0] - payloadStart);
            }
        }
        return out.toByteArray();
    }

    // =========================================================================
    // STRATEGY 3: length-bomb
    // =========================================================================
    // For every LEN-type field (strings, bytes, nested messages), replaces the
    // actual length prefix with Integer.MAX_VALUE (2,147,483,647 = ~2 GB).
    // The real payload bytes still follow, but the parser is told to expect 2 GB.
    //
    // Targets parsers that pre-allocate a buffer of the declared size before
    // reading bytes. A 2 GB allocation attempt will either OOM-crash the server
    // or trigger an out-of-bounds read when the actual data runs out.
    private static byte[] lengthBomb(byte[] input) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int[] pos = {0};
        while (pos[0] < input.length) {
            int fieldStart = pos[0];
            long tag = ProtoWireUtil.readVarint(input, pos);
            int wireType = (int)(tag & 0x7);
            ProtoWireUtil.writeVarint(out, tag);

            if (wireType == 2) {
                // LEN field — read the real length, then write MAX_VALUE instead
                long realLen = ProtoWireUtil.readVarint(input, pos);
                long safeLen = Math.min(realLen, input.length - pos[0]); // don't read past end of input
                ProtoWireUtil.writeVarint(out, 0x7FFFFFFFL); // 2,147,483,647
                out.write(input, pos[0], (int) safeLen); // real payload bytes follow
                pos[0] += (int) safeLen;
            } else {
                int payloadStart = pos[0];
                if (!ProtoWireUtil.skipPayload(input, pos, wireType)) {
                    out.write(input, fieldStart, input.length - fieldStart);
                    return out.toByteArray();
                }
                out.write(input, payloadStart, pos[0] - payloadStart);
            }
        }
        return out.toByteArray();
    }

    // =========================================================================
    // STRATEGY 4: duplicate-field
    // =========================================================================
    // Appends the entire message to itself, so every field appears twice.
    //
    // In proto3, for singular fields, the last occurrence wins — so a conforming
    // parser should produce the same result as the original. But hand-rolled or
    // streaming parsers may merge fields, reject duplicates, double-count repeated
    // fields, or behave inconsistently when the same field number appears twice
    // with different wire types. Also useful for spotting idempotency bugs in
    // upstream services that process the same message twice.
    private static byte[] duplicateField(byte[] input) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(input);
        out.write(input);
        return out.toByteArray();
    }

    // =========================================================================
    // STRATEGY 5: unknown-field
    // =========================================================================
    // Appends four synthetic fields with high field numbers (10000-10003) that
    // won't exist in any real schema, covering all four wire types.
    //
    // In proto3, unknown fields are preserved by default and forwarded when the
    // message is re-serialized. This tests whether downstream services that
    // receive a forwarded message choke on unexpected field numbers, and whether
    // the server's unknown-field handling is resilient to extreme values
    // (Long.MAX_VALUE varint, 0xFF-filled fixed-width fields, 16 zero bytes).
    private static byte[] unknownField(byte[] input) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(input);

        // Field 10000, wire type 0 (VARINT): value = Long.MAX_VALUE
        ProtoWireUtil.writeVarint(out, (10000L << 3) | 0);
        ProtoWireUtil.writeVarint(out, Long.MAX_VALUE);

        // Field 10001, wire type 2 (LEN): 16 zero bytes
        ProtoWireUtil.writeVarint(out, (10001L << 3) | 2);
        ProtoWireUtil.writeVarint(out, 16);
        out.write(new byte[16]);

        // Field 10002, wire type 1 (I64): 8 bytes of 0xFF
        ProtoWireUtil.writeVarint(out, (10002L << 3) | 1);
        out.write(new byte[]{(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF});

        // Field 10003, wire type 5 (I32): 4 bytes of 0xFF
        ProtoWireUtil.writeVarint(out, (10003L << 3) | 5);
        out.write(new byte[]{(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF});

        return out.toByteArray();
    }

    // =========================================================================
    // MUTATION-SPECIFIC HELPERS
    // (General wire format helpers live in ProtoWireUtil)
    // =========================================================================

    // Maps each wire type to its "opposite" for the wire-type-flip strategy.
    private static int flipWireType(int wireType) {
        switch (wireType) {
            case 0: return 2; // VARINT -> LEN
            case 2: return 0; // LEN -> VARINT
            case 1: return 5; // I64 -> I32
            case 5: return 1; // I32 -> I64
            default: return wireType; // unknown types pass through unchanged
        }
    }

    // Writes exactly 11 bytes for a varint value — one more than the 10-byte spec maximum.
    // The first 10 bytes all have the continuation bit (0x80) set; the 11th is 0x00.
    // Any parser that enforces the 10-byte limit will reject this as malformed.
    private static void writeOverflowVarint(ByteArrayOutputStream out, long value) {
        for (int i = 0; i < 10; i++) {
            out.write((int)((value & 0x7F) | 0x80)); // continuation bit always set
            value >>>= 7;
        }
        out.write(0x00); // 11th byte — terminates the varint but exceeds the spec
    }
}
