package com.protome;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * BlackboxDecoder — binary Protobuf → field_n JSON without a schema.
 *
 * Given raw bytes from an intercepted request body (no .proto file required),
 * this class produces a human-editable JSON representation using field numbers
 * as keys ("field_1", "field_2", ...). The JSON can be sent back through
 * BlackboxEncoder to reconstruct binary Protobuf for re-transmission.
 *
 * === How it works ===
 *
 * Protobuf's wire format is partially self-describing: each field's wire type
 * is encoded in its tag, so we always know HOW to read the bytes. What we
 * don't know without a schema is the SEMANTIC type (e.g. is this varint a
 * bool, an enum, or an int64?). We use heuristics to make best-guess choices:
 *
 *   VARINT (wire type 0) → plain JSON number (default: int64)
 *     The value is always readable as a number. If it's actually a bool or
 *     sint64 (zigzag), the tester can wrap it with @type to override.
 *
 *   I64 (wire type 1) → {"@type":"double","@value":...}
 *     Could be a double or fixed64. Always wrapped so the ambiguity is visible.
 *
 *   I32 (wire type 5) → {"@type":"float","@value":...}
 *     Could be a float or fixed32. Always wrapped for the same reason.
 *
 *   LEN (wire type 2) — tried in order:
 *     1. Valid UTF-8 with ≥80% printable chars → plain JSON string
 *     2. Recursively parses as nested Protobuf (depth-limited) → nested object
 *     3. Decodes as packed varints (≥2 values) → {"@type":"packed_int64","@value":[...]}
 *     4. Anything else → {"@type":"bytes","@value":"<base64>"}
 *
 * === @type / @value wrappers ===
 *
 * For ambiguous fields, the decoder emits a wrapper object instead of a bare value:
 *   {"@type": "double", "@value": 3.14}
 *
 * The tester can edit @type to change the interpretation without touching @value,
 * or change both to supply a completely different value. BlackboxEncoder reads
 * these wrappers and encodes accordingly. Supported @type values:
 *   int32, int64, uint32, uint64, sint32, sint64, bool,
 *   double, fixed64, sfixed64, float, fixed32, sfixed32,
 *   string, bytes, packed_int64, packed_int32, packed_sint64, packed_sint32
 *
 * === Error handling ===
 *
 * If the body cannot be parsed at all (encrypted, unknown envelope, not proto),
 * decode() returns a structured error JSON with a _raw_hex field and next-step
 * guidance rather than throwing — so the Repeater tab always opens with something
 * useful for the tester to work from.
 */
public class BlackboxDecoder {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    // Maximum recursion depth for nested message parsing.
    // Prevents infinite loops on self-referential schemas and limits blast radius
    // of false-positive nested-message detection.
    private static final int MAX_DEPTH = 5;

    // =========================================================================
    // Public API
    // =========================================================================

    /**
     * Result object returned by decode(). Contains the JSON string, a flag
     * indicating whether gRPC framing was detected and stripped, and a success
     * flag so callers know whether to warn the tester.
     */
    public static class DecoderResult {
        public final String json;
        public final boolean wasGrpc;
        public final boolean success;

        DecoderResult(String json, boolean wasGrpc, boolean success) {
            this.json = json;
            this.wasGrpc = wasGrpc;
            this.success = success;
        }
    }

    /**
     * Entry point. Accepts raw request body bytes, auto-detects gRPC framing,
     * parses the Protobuf payload, and returns a DecoderResult.
     */
    public static DecoderResult decode(byte[] body) {
        // === STEP 1: Detect and strip gRPC framing ===
        // gRPC wraps protobuf in a 5-byte header: 1 byte compression flag +
        // 4 bytes big-endian message length. We verify the declared length
        // matches the actual remaining bytes before treating it as gRPC.
        boolean wasGrpc = false;
        byte[] payload = body;

        if (isGrpcFrame(body)) {
            wasGrpc = true;
            payload = Arrays.copyOfRange(body, 5, body.length);
        }

        // === STEP 2: Parse the protobuf payload ===
        try {
            JsonObject result = parseMessage(payload, 0);

            // A completely empty result (zero fields) is suspicious — the bytes
            // may be encrypted or use a custom envelope. Treat as partial failure.
            if (result.size() == 0 && payload.length > 0) {
                return errorResult(body, wasGrpc,
                    "Parsing produced no fields. The payload may be encrypted, " +
                    "compressed, or use a custom framing format not recognized by ProtoME.");
            }

            return new DecoderResult(GSON.toJson(result), wasGrpc, true);

        } catch (Exception e) {
            return errorResult(body, wasGrpc,
                "Could not parse body as Protobuf: " + e.getMessage() +
                ". The payload may be encrypted or use an unsupported envelope format.");
        }
    }

    // =========================================================================
    // Core parser
    // =========================================================================

    /**
     * Parses a sequence of Protobuf fields from data[] and returns them as a
     * JsonObject keyed by "field_N". Recurses for nested LEN fields.
     *
     * Throws if the data is structurally invalid (bad wire type, truncated field).
     * Returns an empty JsonObject if data is zero-length (valid empty message).
     */
    private static JsonObject parseMessage(byte[] data, int depth) throws Exception {
        JsonObject obj = new JsonObject();
        int[] pos = {0};

        while (pos[0] < data.length) {
            // Read the field tag: lower 3 bits = wire type, upper bits = field number
            long tag = ProtoWireUtil.readVarint(data, pos);
            if (tag == 0) break; // tag 0 is invalid — treat as end of message

            int wireType = (int)(tag & 0x7);
            int fieldNum = (int)(tag >>> 3);

            if (fieldNum == 0) throw new Exception("Invalid field number 0 at byte " + (pos[0] - 1));

            String key = "field_" + fieldNum;

            switch (wireType) {
                case 0: { // VARINT — default to int64; tester can override with @type
                    long value = ProtoWireUtil.readVarint(data, pos);
                    // If this field already exists (repeated field on wire), promote to array
                    obj.add(key, mergeOrSet(obj, key, new JsonPrimitive(value)));
                    break;
                }

                case 1: { // I64 — always ambiguous (double vs fixed64), always wrap
                    if (pos[0] + 8 > data.length) throw new Exception("Truncated I64 at field " + fieldNum);
                    byte[] bytes = Arrays.copyOfRange(data, pos[0], pos[0] + 8);
                    pos[0] += 8;
                    double doubleVal = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getDouble();
                    JsonObject wrapper = new JsonObject();
                    wrapper.addProperty("@type", "double");
                    wrapper.addProperty("@value", doubleVal);
                    obj.add(key, mergeOrSet(obj, key, wrapper));
                    break;
                }

                case 2: { // LEN — apply heuristic decision tree
                    long len = ProtoWireUtil.readVarint(data, pos);
                    if (len < 0 || pos[0] + len > data.length)
                        throw new Exception("Invalid LEN at field " + fieldNum + ": declared " + len + " bytes");
                    byte[] bytes = Arrays.copyOfRange(data, pos[0], pos[0] + (int)len);
                    pos[0] += (int)len;
                    JsonElement value = inferLenField(bytes, depth);
                    obj.add(key, mergeOrSet(obj, key, value));
                    break;
                }

                case 5: { // I32 — always ambiguous (float vs fixed32), always wrap
                    if (pos[0] + 4 > data.length) throw new Exception("Truncated I32 at field " + fieldNum);
                    byte[] bytes = Arrays.copyOfRange(data, pos[0], pos[0] + 4);
                    pos[0] += 4;
                    float floatVal = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getFloat();
                    JsonObject wrapper = new JsonObject();
                    wrapper.addProperty("@type", "float");
                    wrapper.addProperty("@value", floatVal);
                    obj.add(key, mergeOrSet(obj, key, wrapper));
                    break;
                }

                default:
                    throw new Exception("Unknown wire type " + wireType + " at field " + fieldNum);
            }
        }

        return obj;
    }

    /**
     * Handles repeated fields: if a key already exists in the object, we
     * promote the value to a JSON array and append to it. This covers the
     * case where the same field number appears more than once on the wire
     * (proto's standard encoding for repeated fields without packing).
     */
    private static JsonElement mergeOrSet(JsonObject obj, String key, JsonElement newValue) {
        if (!obj.has(key)) return newValue;

        JsonElement existing = obj.get(key);
        JsonArray arr;
        if (existing.isJsonArray()) {
            arr = existing.getAsJsonArray();
        } else {
            arr = new JsonArray();
            arr.add(existing);
        }
        arr.add(newValue);
        return arr;
    }

    // =========================================================================
    // LEN field heuristics
    // =========================================================================

    /**
     * Applies the four-step decision tree to a LEN field's payload bytes:
     *   1. Nested Protobuf     → nested JsonObject  (tried first — see note in impl)
     *   2. Valid UTF-8 string  → plain string
     *   3. Packed varints      → @type:packed_int64 array
     *   4. Raw bytes           → @type:bytes base64
     */
    private static JsonElement inferLenField(byte[] bytes, int depth) {
        // Empty bytes: treat as empty string (most benign interpretation)
        if (bytes.length == 0) return new JsonPrimitive("");

        // --- Attempt 1: Nested Protobuf message (depth-limited) ---
        // Must run BEFORE the UTF-8 string check. Varint tag bytes for small field
        // numbers (e.g. field 1, wire type 2 = 0x0A = '\n') are in printable ASCII
        // range, so an inner message with string or integer fields routinely passes
        // the 80%-printable threshold and would be returned as a garbled string.
        // A clean proto parse is a stronger structural signal than "looks like UTF-8".
        // We require at least 2 bytes because the smallest valid one-field message
        // is a tag byte + at least one payload byte.
        if (depth < MAX_DEPTH && bytes.length >= 2) {
            try {
                JsonObject nested = parseMessage(bytes, depth + 1);
                if (nested.size() > 0) return nested;
            } catch (Exception ignored) {
                // Not a valid proto message at this depth; fall through
            }
        }

        // --- Attempt 2: UTF-8 string ---
        if (isReadableString(bytes)) {
            return new JsonPrimitive(new String(bytes, StandardCharsets.UTF_8));
        }

        // --- Attempt 3: Packed repeated varints ---
        JsonArray packed = tryDecodePacked(bytes);
        if (packed != null) {
            JsonObject wrapper = new JsonObject();
            wrapper.addProperty("@type", "packed_int64");
            wrapper.add("@value", packed);
            return wrapper;
        }

        // --- Attempt 4: Raw bytes (base64) ---
        JsonObject wrapper = new JsonObject();
        wrapper.addProperty("@type", "bytes");
        wrapper.addProperty("@value", Base64.getEncoder().encodeToString(bytes));
        return wrapper;
    }

    /**
     * Returns true if bytes decode as valid UTF-8 AND at least 80% of the
     * resulting characters are printable (including common whitespace).
     *
     * We use the strict CharsetDecoder (rather than new String(bytes, UTF_8))
     * because the latter silently replaces bad bytes with the replacement
     * character, making everything look like "valid" UTF-8. We want to actually
     * detect invalid byte sequences.
     *
     * The 80% printability threshold catches binary data that happens to be
     * valid UTF-8 (e.g. a sequence of low ASCII control characters).
     */
    private static boolean isReadableString(byte[] bytes) {
        try {
            CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
            decoder.decode(ByteBuffer.wrap(bytes));
        } catch (CharacterCodingException e) {
            return false;
        }

        String s = new String(bytes, StandardCharsets.UTF_8);
        long printable = s.chars()
            .filter(c -> c >= 32 || c == '\n' || c == '\r' || c == '\t')
            .count();
        return (double) printable / s.length() >= 0.80;
    }

    /**
     * Attempts to decode bytes as a packed sequence of varints.
     * Returns a JsonArray of the decoded values if successful (≥2 values),
     * or null if the bytes don't cleanly decode as varints.
     *
     * We require at least 2 values because a single varint is indistinguishable
     * from the start of a nested message or a short byte string. Two or more
     * makes packed encoding a much more confident interpretation.
     */
    private static JsonArray tryDecodePacked(byte[] bytes) {
        if (bytes.length == 0) return null;
        JsonArray arr = new JsonArray();
        int[] pos = {0};
        while (pos[0] < bytes.length) {
            int before = pos[0];
            long val = ProtoWireUtil.readVarint(bytes, pos);
            if (pos[0] == before) return null; // readVarint made no progress — malformed
            arr.add(val);
        }
        return arr.size() >= 2 ? arr : null;
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /**
     * Returns true if body looks like a gRPC data frame:
     *   byte[0]   = 0x00 (uncompressed) or 0x01 (compressed)
     *   byte[1-4] = big-endian uint32 message length
     *   remaining = exactly that many bytes
     */
    private static boolean isGrpcFrame(byte[] body) {
        if (body.length < 5) return false;
        if (body[0] != 0x00 && body[0] != 0x01) return false;
        int declaredLength = ByteBuffer.wrap(body, 1, 4).getInt();
        return declaredLength >= 0 && declaredLength == body.length - 5;
    }

    /** Builds a structured error DecoderResult with hex dump and next-step guidance. */
    private static DecoderResult errorResult(byte[] body, boolean wasGrpc, String message) {
        JsonObject error = new JsonObject();
        error.addProperty("_error", message);
        error.addProperty("_raw_hex", bytesToHex(body));
        error.addProperty("_next_steps",
            "If you have a .proto specification file for this endpoint, load it in the " +
            "ProtoME Settings tab and use the schema-based workflow (protome-type header) instead. " +
            "The hex dump above may help identify the encoding or framing format in use.");
        return new DecoderResult(GSON.toJson(error), wasGrpc, false);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
