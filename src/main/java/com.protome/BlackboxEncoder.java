package com.protome;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

/**
 * BlackboxEncoder — field_n JSON → binary Protobuf wire format, no schema required.
 *
 * This is the reverse of BlackboxDecoder. It reads the field_n JSON that the tester
 * has edited in Repeater and re-encodes it into the binary Protobuf wire format that
 * the server expects. No .proto file is needed — all type information comes from either
 * the JSON value type (for unambiguous cases) or the @type/@value wrapper objects that
 * BlackboxDecoder emits for ambiguous fields.
 *
 * === JSON format expected ===
 *
 * Keys must be "field_N" where N is the field number (positive integer).
 * Keys starting with "_" are meta-fields (error info, hex dump) and are skipped.
 * Any other key format is skipped silently.
 *
 * Values:
 *   Plain number   → VARINT (int64)
 *   Plain boolean  → VARINT (0 or 1)
 *   Plain string   → LEN (UTF-8 bytes)
 *   Plain array    → each element encoded as a separate field with the same field number
 *                    (standard proto repeated field encoding, not packed)
 *   Nested object (field_N keys, no @type) → LEN (recursively encoded nested message)
 *   @type/@value wrapper → encoded per the @type (see table below)
 *
 * === Supported @type values ===
 *
 *   int32, int64, uint32, uint64  → VARINT, raw value
 *   sint32, sint64                → VARINT, zigzag encoded
 *   bool                          → VARINT, 0 or 1
 *   double                        → I64, 8-byte little-endian IEEE 754
 *   fixed64, sfixed64             → I64, 8-byte little-endian
 *   float                         → I32, 4-byte little-endian IEEE 754
 *   fixed32, sfixed32             → I32, 4-byte little-endian
 *   string                        → LEN, UTF-8 bytes
 *   bytes                         → LEN, base64-decoded bytes
 *   packed_int64, packed_int32,
 *   packed_uint64, packed_uint32  → LEN, varint-encoded sequence
 *   packed_sint64, packed_sint32  → LEN, zigzag + varint-encoded sequence
 *
 * === Round-trip fidelity ===
 *
 * If the tester has not changed any @type values and has not reordered fields,
 * the re-encoded binary should produce the same wire bytes as the original request
 * (modulo field ordering, which proto parsers treat as equivalent). If a @type was
 * wrong (e.g. a sint64 decoded as int64), the server's response will guide the tester
 * toward the correct interpretation.
 */
public class BlackboxEncoder {

    /**
     * Entry point. Parses the field_n JSON string and encodes it to binary Protobuf.
     * Throws if the JSON is malformed or contains an unrecognised @type.
     */
    public static byte[] encode(String json) throws Exception {
        JsonObject obj;
        try {
            obj = JsonParser.parseString(json).getAsJsonObject();
        } catch (Exception e) {
            throw new IllegalArgumentException("Request body is not valid JSON: " + e.getMessage());
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        encodeMessage(obj, out);
        return out.toByteArray();
    }

    // =========================================================================
    // Core encoder
    // =========================================================================

    /**
     * Iterates the fields of a JsonObject and writes each one to out.
     * Used recursively for nested message objects.
     */
    private static void encodeMessage(JsonObject obj, ByteArrayOutputStream out) throws Exception {
        for (java.util.Map.Entry<String, JsonElement> entry : obj.entrySet()) {
            String key = entry.getKey();

            if (key.startsWith("_")) continue;       // skip meta-fields (_error, _raw_hex, etc.)
            if (!key.startsWith("field_")) continue; // skip unrecognised keys

            int fieldNum;
            try {
                fieldNum = Integer.parseInt(key.substring(6));
                if (fieldNum <= 0) continue; // field numbers must be positive
            } catch (NumberFormatException e) {
                continue;
            }

            encodeField(fieldNum, entry.getValue(), out);
        }
    }

    /**
     * Encodes a single field (tag + payload) and writes it to out.
     * Handles plain values, @type wrappers, nested objects, and arrays.
     */
    private static void encodeField(int fieldNum, JsonElement value, ByteArrayOutputStream out) throws Exception {
        if (value.isJsonArray()) {
            // A JSON array means a repeated field — encode each element separately
            // with the same field number (standard proto repeated encoding, not packed).
            for (JsonElement elem : value.getAsJsonArray()) {
                encodeField(fieldNum, elem, out);
            }
            return;
        }

        if (value.isJsonPrimitive()) {
            JsonPrimitive prim = value.getAsJsonPrimitive();
            if (prim.isNumber()) {
                // Plain number → VARINT (int64)
                writeTag(out, fieldNum, 0);
                ProtoWireUtil.writeVarint(out, prim.getAsLong());
            } else if (prim.isString()) {
                // Plain string → LEN (UTF-8)
                byte[] strBytes = prim.getAsString().getBytes(StandardCharsets.UTF_8);
                writeTag(out, fieldNum, 2);
                ProtoWireUtil.writeVarint(out, strBytes.length);
                out.write(strBytes);
            } else if (prim.isBoolean()) {
                // Plain boolean → VARINT
                writeTag(out, fieldNum, 0);
                ProtoWireUtil.writeVarint(out, prim.getAsBoolean() ? 1L : 0L);
            }
            return;
        }

        if (value.isJsonObject()) {
            JsonObject obj = value.getAsJsonObject();

            if (obj.has("@type") && obj.has("@value")) {
                // @type/@value wrapper — use the explicit type
                String type = obj.get("@type").getAsString();
                JsonElement val = obj.get("@value");
                encodeTypedField(fieldNum, type, val, out);
            } else {
                // No @type — treat as a nested Protobuf message
                ByteArrayOutputStream nested = new ByteArrayOutputStream();
                encodeMessage(obj, nested);
                byte[] nestedBytes = nested.toByteArray();
                writeTag(out, fieldNum, 2);
                ProtoWireUtil.writeVarint(out, nestedBytes.length);
                out.write(nestedBytes);
            }
        }
    }

    /**
     * Handles all @type-annotated fields. The type string determines the wire type
     * and the encoding applied to @value.
     */
    private static void encodeTypedField(int fieldNum, String type, JsonElement val,
                                          ByteArrayOutputStream out) throws Exception {
        switch (type.toLowerCase()) {

            // --- VARINT types: raw value ---
            case "int32": case "int64": case "uint32": case "uint64": {
                writeTag(out, fieldNum, 0);
                ProtoWireUtil.writeVarint(out, val.getAsLong());
                break;
            }

            // --- VARINT types: zigzag encoded ---
            // Zigzag maps signed integers to unsigned varints so that small negative
            // numbers (like -1) encode compactly. Formula: (n << 1) ^ (n >> 63)
            // Example: -1 → 1, 1 → 2, -2 → 3, 2 → 4
            case "sint32": {
                int n = val.getAsInt();
                long zigzag = ((long)n << 1) ^ ((long)n >> 31);
                writeTag(out, fieldNum, 0);
                ProtoWireUtil.writeVarint(out, zigzag);
                break;
            }
            case "sint64": {
                long n = val.getAsLong();
                long zigzag = (n << 1) ^ (n >> 63);
                writeTag(out, fieldNum, 0);
                ProtoWireUtil.writeVarint(out, zigzag);
                break;
            }

            // --- VARINT: boolean ---
            case "bool": {
                writeTag(out, fieldNum, 0);
                ProtoWireUtil.writeVarint(out, val.getAsBoolean() ? 1L : 0L);
                break;
            }

            // --- I64: 8 bytes little-endian ---
            case "double": {
                writeTag(out, fieldNum, 1);
                writeLittleEndianLong(out, Double.doubleToRawLongBits(val.getAsDouble()));
                break;
            }
            case "fixed64": {
                writeTag(out, fieldNum, 1);
                writeLittleEndianLong(out, val.getAsLong());
                break;
            }
            case "sfixed64": {
                writeTag(out, fieldNum, 1);
                writeLittleEndianLong(out, val.getAsLong());
                break;
            }

            // --- I32: 4 bytes little-endian ---
            case "float": {
                writeTag(out, fieldNum, 5);
                writeLittleEndianInt(out, Float.floatToRawIntBits(val.getAsFloat()));
                break;
            }
            case "fixed32": {
                writeTag(out, fieldNum, 5);
                writeLittleEndianInt(out, val.getAsInt());
                break;
            }
            case "sfixed32": {
                writeTag(out, fieldNum, 5);
                writeLittleEndianInt(out, val.getAsInt());
                break;
            }

            // --- LEN: string ---
            case "string": {
                byte[] strBytes = val.getAsString().getBytes(StandardCharsets.UTF_8);
                writeTag(out, fieldNum, 2);
                ProtoWireUtil.writeVarint(out, strBytes.length);
                out.write(strBytes);
                break;
            }

            // --- LEN: raw bytes (base64 input) ---
            case "bytes": {
                byte[] bytes;
                try {
                    bytes = Base64.getDecoder().decode(val.getAsString());
                } catch (IllegalArgumentException e) {
                    throw new IllegalArgumentException(
                        "field_" + fieldNum + " @type bytes: invalid base64 — " + e.getMessage());
                }
                writeTag(out, fieldNum, 2);
                ProtoWireUtil.writeVarint(out, bytes.length);
                out.write(bytes);
                break;
            }

            // --- LEN: packed repeated integers (unsigned varints) ---
            case "packed_int64": case "packed_int32":
            case "packed_uint64": case "packed_uint32": {
                byte[] packed = encodePackedVarints(val.getAsJsonArray(), false);
                writeTag(out, fieldNum, 2);
                ProtoWireUtil.writeVarint(out, packed.length);
                out.write(packed);
                break;
            }

            // --- LEN: packed repeated integers (zigzag varints) ---
            case "packed_sint64": case "packed_sint32": {
                byte[] packed = encodePackedVarints(val.getAsJsonArray(), true);
                writeTag(out, fieldNum, 2);
                ProtoWireUtil.writeVarint(out, packed.length);
                out.write(packed);
                break;
            }

            default:
                throw new IllegalArgumentException(
                    "Unknown @type '" + type + "' on field_" + fieldNum + ". " +
                    "Supported types: int32, int64, uint32, uint64, sint32, sint64, bool, " +
                    "double, fixed64, sfixed64, float, fixed32, sfixed32, string, bytes, " +
                    "packed_int64, packed_int32, packed_uint64, packed_uint32, packed_sint64, packed_sint32");
        }
    }

    // =========================================================================
    // Wire format helpers
    // =========================================================================

    /**
     * Writes a field tag: (field_number << 3) | wire_type, encoded as a varint.
     * This is how every field on the wire is prefixed.
     */
    private static void writeTag(ByteArrayOutputStream out, int fieldNum, int wireType) {
        ProtoWireUtil.writeVarint(out, ((long)fieldNum << 3) | wireType);
    }

    /**
     * Encodes a JSON array of numbers as a sequence of packed varints.
     * If zigzag is true, applies zigzag encoding before varint encoding (for sint types).
     */
    private static byte[] encodePackedVarints(JsonArray arr, boolean zigzag) throws Exception {
        ByteArrayOutputStream packed = new ByteArrayOutputStream();
        for (JsonElement elem : arr) {
            long n = elem.getAsLong();
            if (zigzag) n = (n << 1) ^ (n >> 63);
            ProtoWireUtil.writeVarint(packed, n);
        }
        return packed.toByteArray();
    }

    /** Writes a long as 8 bytes in little-endian order (Protobuf I64 wire format). */
    private static void writeLittleEndianLong(ByteArrayOutputStream out, long value) {
        for (int i = 0; i < 8; i++) {
            out.write((int)(value & 0xFF));
            value >>>= 8;
        }
    }

    /** Writes an int as 4 bytes in little-endian order (Protobuf I32 wire format). */
    private static void writeLittleEndianInt(ByteArrayOutputStream out, int value) {
        for (int i = 0; i < 4; i++) {
            out.write(value & 0xFF);
            value >>>= 8;
        }
    }
}
