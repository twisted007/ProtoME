package com.protome;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.core.ByteArray;

import java.nio.ByteBuffer;
import java.util.List;

public class ProtomeHttpHandler implements HttpHandler {
    private MontoyaApi api;
    private ProtoManager protoManager;
    private RequestLogger logger;

    public ProtomeHttpHandler(MontoyaApi api, ProtoManager protoManager, RequestLogger logger) {
        this.api = api;
        this.protoManager = protoManager;
        this.logger = logger;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        // Check for Trigger Header
        String triggerValue = getHeaderValueIgnoreCase(requestToBeSent, "protome");
        if (triggerValue == null || !triggerValue.equalsIgnoreCase("true")) {
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        // Get Message Type
        String msgType = getHeaderValueIgnoreCase(requestToBeSent, "protome-type");
        if (msgType == null) {
            api.logging().logToOutput("Protome: Missing 'protome-type' header.");
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }

        // Check for gRPC mode
        String grpcHeader = getHeaderValueIgnoreCase(requestToBeSent, "protome-grpc");
        boolean isGrpc = (grpcHeader != null && grpcHeader.equalsIgnoreCase("true"));

        try {
            String jsonBody = requestToBeSent.bodyToString();
            byte[] protoBytes = protoManager.jsonToProto(jsonBody, msgType);

            api.logging().logToOutput("Converted '" + msgType + "'. Raw Size: " + protoBytes.length + " bytes.");

            // WARNING: If size is 0, your JSON keys probably don't match the .proto field names!
            if (protoBytes.length == 0) {
                api.logging().logToOutput("WARNING: Resulting Protobuf message is empty (0 bytes). Check JSON key spelling!");
            }

            // Apply binary mutation before gRPC framing (if requested)
            String mutationStrategy = getHeaderValueIgnoreCase(requestToBeSent, "protome-mutate");
            if (mutationStrategy != null) {
                protoBytes = ProtoMutator.mutate(protoBytes, mutationStrategy);
                api.logging().logToOutput("Applied mutation '" + mutationStrategy + "'. Mutated size: " + protoBytes.length + " bytes.");
            }

            // Handle gRPC Wrapping if requested
            if (isGrpc) {
                ByteBuffer buffer = ByteBuffer.allocate(5 + protoBytes.length);
                buffer.put((byte) 0); // Compression flag (0)
                buffer.putInt(protoBytes.length); // Length (4 bytes)
                buffer.put(protoBytes); // Payload
                protoBytes = buffer.array();
                api.logging().logToOutput("Applied gRPC framing. New Size: " + protoBytes.length + " bytes.");
            }

            // Construct new request
            var modifiedRequest = requestToBeSent
                    .withRemovedHeader("protome")
                    .withRemovedHeader("Protome")
                    .withRemovedHeader("protome-type")
                    .withRemovedHeader("Protome-Type")
                    .withRemovedHeader("protome-grpc")
                    .withRemovedHeader("protome-mutate")
                    .withRemovedHeader("Protome-Mutate")
                    .withHeader("Content-Type", isGrpc ? "application/grpc" : "application/x-protobuf")
                    .withBody(ByteArray.byteArray(protoBytes));

            logger.log(modifiedRequest, mutationStrategy);

            return RequestToBeSentAction.continueWith(modifiedRequest);

        } catch (Exception e) {
            api.logging().logToError("Protome Conversion Error: " + e.getMessage());
            return RequestToBeSentAction.continueWith(requestToBeSent);
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        return ResponseReceivedAction.continueWith(responseReceived);
    }

    private String getHeaderValueIgnoreCase(HttpRequestToBeSent request, String headerName) {
        for (HttpHeader header : request.headers()) {
            if (header.name().equalsIgnoreCase(headerName)) {
                return header.value();
            }
        }
        return null;
    }
}
