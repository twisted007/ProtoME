package com.protome;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.core.ByteArray;

import java.nio.ByteBuffer;
import java.util.List;

/**
 * ProtomeHttpHandler — the traffic cop between Burp and the wire.
 *
 * Burp's Montoya API lets extensions register an HttpHandler, which gives us a
 * hook that fires on EVERY outgoing request before it leaves Burp. This class
 * is that hook. Its job is to:
 *   1. Decide whether this request is meant for Protome (opt-in via headers).
 *   2. If yes, convert the human-readable JSON body into binary Protobuf.
 *   3. Optionally corrupt the binary (fuzzing mutations) or wrap it in a gRPC frame.
 *   4. Strip the Protome control headers so the server never sees them.
 *   5. Forward the modified request and record it in the Logger tab.
 *
 * If anything goes wrong, the original request is forwarded unchanged — we
 * never silently drop traffic.
 */
public class ProtomeHttpHandler implements HttpHandler {
    private MontoyaApi api;
    private ProtoManager protoManager;
    private RequestLogger logger;

    public ProtomeHttpHandler(MontoyaApi api, ProtoManager protoManager, RequestLogger logger) {
        this.api = api;
        this.protoManager = protoManager;
        this.logger = logger;
    }

    /**
     * Called by Burp automatically for every outgoing HTTP request.
     * This is the main transformation pipeline — it runs in order, top to bottom.
     */
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {

        // === STEP 1: OPT-IN CHECK ===
        // We only act on requests that have "protome: true". Every other request
        // passes through untouched. This is the on/off switch — without it,
        // the extension would try to process every single request Burp sees.
        String triggerValue = getHeaderValueIgnoreCase(requestToBeSent, "protome");
        if (triggerValue == null || !triggerValue.equalsIgnoreCase("true")) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        // === STEP 2: READ CONTROL HEADERS ===
        // "protome-type" tells us which Protobuf message schema to serialize into.
        // Required for the schema-based path; omitted for the blackbox path.
        String msgType = getHeaderValueIgnoreCase(requestToBeSent, "protome-type");

        // "protome-blackbox: true" activates the schema-free encoding path.
        // When set, protome-type is not required — type information comes from the
        // @type/@value wrappers embedded in the JSON by BlackboxDecoder.
        String blackboxHeader = getHeaderValueIgnoreCase(requestToBeSent, "protome-blackbox");
        boolean isBlackbox = (blackboxHeader != null && blackboxHeader.equalsIgnoreCase("true"));

        if (msgType == null && !isBlackbox) {
            api.logging().logToOutput(
                "Protome: Missing 'protome-type' header. " +
                "Add 'protome-blackbox: true' to use schema-free mode.");
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        // "protome-grpc: true" signals that we should wrap the binary in a gRPC frame
        // (handled in Step 5 below). Absent or false means raw Protobuf only.
        String grpcHeader = getHeaderValueIgnoreCase(requestToBeSent, "protome-grpc");
        boolean isGrpc = (grpcHeader != null && grpcHeader.equalsIgnoreCase("true"));

        try {
            // === STEP 3: JSON → BINARY PROTOBUF ===
            // Two paths — same JSON input, different serializers:
            //   Schema path (protome-type set): ProtoManager uses the loaded .proto
            //     descriptor to serialize. Field names must match the schema exactly.
            //   Blackbox path (protome-blackbox: true): BlackboxEncoder reads field_n
            //     keys and @type/@value wrappers to write raw wire format bytes.
            //     No schema or loaded .proto file required.
            String jsonBody = requestToBeSent.bodyToString();
            byte[] protoBytes;
            if (isBlackbox) {
                protoBytes = BlackboxEncoder.encode(jsonBody);
                api.logging().logToOutput("Protome Blackbox: Encoded JSON to binary. Size: " + protoBytes.length + " bytes.");
            } else {
                protoBytes = protoManager.jsonToProto(jsonBody, msgType);
            }

            api.logging().logToOutput("Converted '" + msgType + "'. Raw Size: " + protoBytes.length + " bytes.");

            // A 0-byte result means serialization "succeeded" but produced nothing —
            // almost always because the JSON field names don't match the .proto field names.
            // The protobuf library silently ignores fields it can't map rather than erroring.
            if (protoBytes.length == 0) {
                api.logging().logToOutput("WARNING: Resulting Protobuf message is empty (0 bytes). Check JSON key spelling!");
            }

            // === STEP 4: OPTIONAL MUTATION (FUZZING) ===
            // If the user added a "protome-mutate: <strategy>" header, we pass the
            // valid binary through ProtoMutator which deliberately corrupts it in a
            // structured way (e.g. flipping wire types, overflowing varints).
            // Mutation happens BEFORE gRPC framing so we're fuzzing the payload itself,
            // not the transport wrapper.
            String mutationStrategy = getHeaderValueIgnoreCase(requestToBeSent, "protome-mutate");
            if (mutationStrategy != null) {
                protoBytes = ProtoMutator.mutate(protoBytes, mutationStrategy);
                api.logging().logToOutput("Applied mutation '" + mutationStrategy + "'. Mutated size: " + protoBytes.length + " bytes.");
            }

            // === STEP 5: OPTIONAL gRPC FRAMING ===
            // gRPC doesn't send raw Protobuf — it wraps it in a 5-byte envelope:
            //   Byte 0:   compression flag (0 = not compressed)
            //   Bytes 1-4: payload length as a 4-byte big-endian integer
            // Without this wrapper a gRPC server will reject the request immediately.
            // We only add it when "protome-grpc: true" is set.
            if (isGrpc) {
                ByteBuffer buffer = ByteBuffer.allocate(5 + protoBytes.length);
                buffer.put((byte) 0);            // compression flag
                buffer.putInt(protoBytes.length); // 4-byte length prefix
                buffer.put(protoBytes);           // the actual protobuf payload
                protoBytes = buffer.array();
                api.logging().logToOutput("Applied gRPC framing. New Size: " + protoBytes.length + " bytes.");
            }

            // === STEP 6: REBUILD THE REQUEST ===
            // Strip all Protome control headers (the server should never see them),
            // set the correct Content-Type for the wire format, and swap in the
            // binary body. The Montoya API uses a builder/fluent style — each
            // "withX" call returns a new modified copy of the request rather than
            // mutating the original.
            var modifiedRequest = requestToBeSent
                    .withRemovedHeader("protome")
                    .withRemovedHeader("Protome")
                    .withRemovedHeader("protome-type")
                    .withRemovedHeader("Protome-Type")
                    .withRemovedHeader("protome-grpc")
                    .withRemovedHeader("protome-blackbox")
                    .withRemovedHeader("Protome-Blackbox")
                    .withRemovedHeader("protome-mutate")
                    .withRemovedHeader("Protome-Mutate")
                    .withHeader("Content-Type", isGrpc ? "application/grpc" : "application/x-protobuf")
                    .withBody(ByteArray.byteArray(protoBytes));

            // === STEP 7: LOG AND FORWARD ===
            logger.log(modifiedRequest, mutationStrategy);
            return RequestToBeSentAction.continueWith(modifiedRequest);

        } catch (Exception e) {
            // If anything in the pipeline fails, forward the original request unchanged.
            // We never drop traffic — a failed conversion is surfaced in Burp's error log
            // but doesn't break the user's session.
            api.logging().logToError("Protome Conversion Error: " + e.getMessage());
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }
    }

    // We don't inspect responses — Protome is request-only.
    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    // HTTP header names are case-insensitive by spec, but Java string comparison
    // is not — so we do our own case-insensitive scan instead of using a plain map lookup.
    private String getHeaderValueIgnoreCase(HttpRequestToBeSent request, String headerName) {
        for (HttpHeader header : request.headers()) {
            if (header.name().equalsIgnoreCase(headerName)) {
                return header.value();
            }
        }
        return null;
    }
}
