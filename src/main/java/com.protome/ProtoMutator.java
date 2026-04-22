package com.protome;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class ProtoMutator {

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

    // Flips wire types in all field tags: VARINT(0)↔LEN(2), I64(1)↔I32(5).
    // Payload bytes are preserved unchanged, so the parser sees a structurally
    // wrong type for every field.
    private static byte[] wireTypeFlip(byte[] input) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int[] pos = {0};
        while (pos[0] < input.length) {
            int fieldStart = pos[0];
            long tag = readVarint(input, pos);
            int wireType = (int)(tag & 0x7);
            long fieldNum = tag >>> 3;

            int payloadStart = pos[0];
            if (!skipPayload(input, pos, wireType)) {
                out.write(input, fieldStart, input.length - fieldStart);
                return out.toByteArray();
            }

            writeVarint(out, (fieldNum << 3) | flipWireType(wireType));
            out.write(input, payloadStart, pos[0] - payloadStart);
        }
        return out.toByteArray();
    }

    // Pads all VARINT-type field values to 11 bytes. The protobuf spec limits
    // varints to 10 bytes; the 11th byte with continuation bit triggers overflow
    // in most parsers.
    private static byte[] varintOverflow(byte[] input) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int[] pos = {0};
        while (pos[0] < input.length) {
            int fieldStart = pos[0];
            long tag = readVarint(input, pos);
            int wireType = (int)(tag & 0x7);
            writeVarint(out, tag);

            if (wireType == 0) {
                long value = readVarint(input, pos);
                writeOverflowVarint(out, value);
            } else {
                int payloadStart = pos[0];
                if (!skipPayload(input, pos, wireType)) {
                    out.write(input, fieldStart, input.length - fieldStart);
                    return out.toByteArray();
                }
                out.write(input, payloadStart, pos[0] - payloadStart);
            }
        }
        return out.toByteArray();
    }

    // Replaces the length varint of every LEN-type field with Integer.MAX_VALUE.
    // The parser attempts to allocate/read 2GB of data for each field.
    private static byte[] lengthBomb(byte[] input) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int[] pos = {0};
        while (pos[0] < input.length) {
            int fieldStart = pos[0];
            long tag = readVarint(input, pos);
            int wireType = (int)(tag & 0x7);
            writeVarint(out, tag);

            if (wireType == 2) {
                long realLen = readVarint(input, pos);
                long safeLen = Math.min(realLen, input.length - pos[0]);
                writeVarint(out, 0x7FFFFFFFL);
                out.write(input, pos[0], (int) safeLen);
                pos[0] += (int) safeLen;
            } else {
                int payloadStart = pos[0];
                if (!skipPayload(input, pos, wireType)) {
                    out.write(input, fieldStart, input.length - fieldStart);
                    return out.toByteArray();
                }
                out.write(input, payloadStart, pos[0] - payloadStart);
            }
        }
        return out.toByteArray();
    }

    // Appends the entire serialized message to itself. Every field appears twice;
    // in proto3 the last value wins for singular fields, but hand-rolled or
    // streaming parsers may merge or reject duplicates inconsistently.
    private static byte[] duplicateField(byte[] input) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(input);
        out.write(input);
        return out.toByteArray();
    }

    // Appends synthetic fields with high field numbers (10000-10003) that won't
    // exist in any real schema. Proto3 parsers preserve unknown fields by default,
    // which can cause issues when messages are forwarded to downstream services.
    private static byte[] unknownField(byte[] input) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(input);

        // Field 10000, VARINT: Long.MAX_VALUE
        writeVarint(out, (10000L << 3) | 0);
        writeVarint(out, Long.MAX_VALUE);

        // Field 10001, LEN: 16 zero bytes
        writeVarint(out, (10001L << 3) | 2);
        writeVarint(out, 16);
        out.write(new byte[16]);

        // Field 10002, I64: 8 0xFF bytes
        writeVarint(out, (10002L << 3) | 1);
        out.write(new byte[]{(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF});

        // Field 10003, I32: 4 0xFF bytes
        writeVarint(out, (10003L << 3) | 5);
        out.write(new byte[]{(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF});

        return out.toByteArray();
    }

    // --- Wire format helpers ---

    private static int flipWireType(int wireType) {
        switch (wireType) {
            case 0: return 2;
            case 2: return 0;
            case 1: return 5;
            case 5: return 1;
            default: return wireType;
        }
    }

    // Advances pos past a field's payload without returning bytes.
    // Returns false if the data is malformed or truncated.
    private static boolean skipPayload(byte[] data, int[] pos, int wireType) {
        switch (wireType) {
            case 0:
                readVarint(data, pos);
                return pos[0] <= data.length;
            case 1:
                if (pos[0] + 8 > data.length) return false;
                pos[0] += 8;
                return true;
            case 2: {
                long len = readVarint(data, pos);
                if (len < 0 || pos[0] + len > data.length) return false;
                pos[0] += (int) len;
                return true;
            }
            case 5:
                if (pos[0] + 4 > data.length) return false;
                pos[0] += 4;
                return true;
            default:
                return false;
        }
    }

    private static long readVarint(byte[] data, int[] pos) {
        long value = 0;
        int shift = 0;
        while (pos[0] < data.length) {
            byte b = data[pos[0]++];
            value |= (long)(b & 0x7F) << shift;
            if ((b & 0x80) == 0) break;
            shift += 7;
            if (shift >= 70) break;
        }
        return value;
    }

    private static void writeVarint(ByteArrayOutputStream out, long value) {
        while (true) {
            if ((value & ~0x7FL) == 0) {
                out.write((int) value);
                return;
            }
            out.write((int)((value & 0x7F) | 0x80));
            value >>>= 7;
        }
    }

    // Writes exactly 11 bytes: the value encoded across 10 bytes all with the
    // continuation bit set, followed by a terminal 0x00. Exceeds the 10-byte
    // maximum for 64-bit varints defined by the protobuf spec.
    private static void writeOverflowVarint(ByteArrayOutputStream out, long value) {
        for (int i = 0; i < 10; i++) {
            out.write((int)((value & 0x7F) | 0x80));
            value >>>= 7;
        }
        out.write(0x00);
    }
}
