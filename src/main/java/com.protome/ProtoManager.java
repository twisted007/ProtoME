package com.protome;

import burp.api.montoya.MontoyaApi;
import com.github.os72.protocjar.Protoc;
import com.google.protobuf.ByteString;
import com.google.protobuf.Descriptors;
import com.google.protobuf.DynamicMessage;
import com.google.protobuf.DescriptorProtos;
import com.google.protobuf.util.JsonFormat;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * ProtoManager — the schema brain of the extension.
 *
 * Everything that requires understanding the structure of a .proto file lives here.
 * The two other classes that need proto knowledge (ProtomeHttpHandler for serialization,
 * ProtomeExtension for the UI tree) both delegate to this class rather than touching
 * the protobuf library directly.
 *
 * It has three responsibilities:
 *   1. COMPILE: Take a .proto source file and invoke the protoc compiler to produce
 *      a binary "descriptor set" — a machine-readable summary of all message schemas.
 *   2. PARSE: Walk the descriptor set and build an in-memory registry of every message
 *      type by name, so lookups during request handling are fast (HashMap, not file I/O).
 *   3. SERIALIZE / GENERATE: Convert JSON → binary Protobuf (for live requests), and
 *      generate dummy JSON payloads (for the "Build Request" helper in the UI).
 *
 * Key design choice — DynamicMessage vs. generated classes:
 *   Normally you'd run protoc to generate Java source files (.java) and compile them
 *   into your project. That would give you strongly-typed classes like SearchRequest.java.
 *   We can't do that here because we don't know what .proto file the user will load at
 *   runtime. Instead we use protobuf's DynamicMessage API, which can serialize any
 *   message schema described by a Descriptor object at runtime — no code generation needed.
 */
public class ProtoManager {
    private MontoyaApi api;

    // The central registry: maps both short name ("SearchRequest") and fully-qualified
    // name ("com.example.SearchRequest") to the Descriptor object for that message.
    // Storing both lets users use either form in the protome-type header.
    private Map<String, Descriptors.Descriptor> messageDescriptors = new HashMap<>();
    private File loadedProtoFile;

    public ProtoManager(MontoyaApi api) {
        this.api = api;
    }

    public File getLoadedProtoFile() {
        return loadedProtoFile;
    }

    public Map<String, Descriptors.Descriptor> getMessageDescriptors() {
        return messageDescriptors;
    }

    /**
     * Loads a .proto file in two phases: compile it with protoc, then parse
     * the resulting binary descriptor set into our in-memory registry.
     */
    public void loadProto(File userProtoFile) throws Exception {
        api.logging().logToOutput("Attempting to load proto file: " + userProtoFile.getAbsolutePath());

        File parentDir = userProtoFile.getParentFile();
        // We write the descriptor output to a temp file so protoc has somewhere to put it.
        // The file is just a staging area — we parse it immediately and don't keep it.
        File descFile = File.createTempFile("protome", ".desc");

        // === PHASE 1: COMPILE WITH PROTOC ===
        // protoc-jar bundles the protoc binary inside the extension jar, so we don't
        // require the user to have protoc installed separately. We invoke it with
        // --descriptor_set_out instead of --java_out because we want the binary schema
        // description, not generated Java source files.
        //
        // --include_imports is critical: if the .proto imports other .proto files
        // (e.g. google/protobuf/timestamp.proto), those dependencies must also be
        // included in the descriptor set or we won't be able to resolve their types later.
        String[] args = {
                "-v3.11.4",
                "--include_imports",
                "--include_std_types",
                "--descriptor_set_out=" + descFile.getAbsolutePath(),
                "--proto_path=" + parentDir.getAbsolutePath(),
                userProtoFile.getName()
        };

        // Capture protoc's stdout/stderr into a string so we can relay it to Burp's
        // output log rather than letting it disappear into /dev/null.
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        PrintStream printStream = new PrintStream(outputStream);

        api.logging().logToOutput("Running protoc...");
        int exitCode = Protoc.runProtoc(args, printStream, printStream);

        String protocOutput = outputStream.toString();
        if (!protocOutput.isEmpty()) {
            api.logging().logToOutput("--- PROTOC OUTPUT ---\n" + protocOutput);
        }

        if (exitCode != 0) {
            throw new RuntimeException("Protoc compilation failed. See output above.");
        }

        // === PHASE 2: PARSE THE DESCRIPTOR SET ===
        // The descriptor set file is a binary Protobuf message (FileDescriptorSet) that
        // contains one FileDescriptorProto per .proto file. Each FileDescriptorProto is
        // still "raw" — it lists its imports by filename string but doesn't link them yet.
        // We have to build them in dependency order ourselves so that each FileDescriptor
        // has live references to its dependencies, not just names.
        api.logging().logToOutput("Parsing descriptors...");
        messageDescriptors.clear();

        try (FileInputStream fis = new FileInputStream(descFile)) {
            DescriptorProtos.FileDescriptorSet set = DescriptorProtos.FileDescriptorSet.parseFrom(fis);

            // fileCache holds the fully-linked FileDescriptor objects we've built so far.
            // When we encounter a file that imports another, we look up the dependency here.
            // protoc writes files in dependency order (imports before importers), so a
            // dependency will always be in the cache by the time we need it.
            Map<String, Descriptors.FileDescriptor> fileCache = new HashMap<>();

            for (DescriptorProtos.FileDescriptorProto fdp : set.getFileList()) {

                // Gather the already-built FileDescriptor objects for each import this file declares.
                List<Descriptors.FileDescriptor> dependencies = new ArrayList<>();
                for (String depName : fdp.getDependencyList()) {
                    if (fileCache.containsKey(depName)) {
                        dependencies.add(fileCache.get(depName));
                    } else {
                        api.logging().logToOutput("WARNING: Could not find dependency '" + depName + "' for " + fdp.getName());
                    }
                }

                // buildFrom links the raw proto into a fully-resolved FileDescriptor.
                // From this point on the descriptor knows the actual Java types of its fields,
                // not just the import filenames.
                Descriptors.FileDescriptor fd = Descriptors.FileDescriptor.buildFrom(
                        fdp, dependencies.toArray(new Descriptors.FileDescriptor[0]));

                fileCache.put(fd.getName(), fd);

                // Walk every top-level message in this file and add it to our registry.
                // registerMessage recurses into nested message types automatically.
                for (Descriptors.Descriptor msgType : fd.getMessageTypes()) {
                    registerMessage(msgType);
                }
            }
        } catch (Throwable t) {
            // We catch Throwable (not just Exception) because some protobuf descriptor
            // failures surface as Errors (e.g. DescriptorValidationException extends
            // Exception but other internal failures can be deeper). We want every failure
            // visible in Burp's error log, not silently swallowed.
            api.logging().logToError(t);
            api.logging().logToOutput("CRITICAL ERROR PARSING DESCRIPTORS: " + t.getMessage());
            t.printStackTrace();
            throw new RuntimeException("Failed to parse descriptors: " + t.getMessage());
        }

        this.loadedProtoFile = userProtoFile;
        api.logging().logToOutput("Total messages loaded: " + messageDescriptors.size());
    }

    /**
     * Adds a message and all its nested messages to the registry under both
     * short name and fully-qualified name. Recursion handles arbitrarily deep nesting.
     */
    private void registerMessage(Descriptors.Descriptor msgType) {
        api.logging().logToOutput(">> REGISTERED: " + msgType.getFullName());
        // Register under short name ("SearchRequest") for convenience in the header value,
        // and under full name ("com.example.SearchRequest") for uniqueness across packages.
        messageDescriptors.put(msgType.getName(), msgType);
        messageDescriptors.put(msgType.getFullName(), msgType);

        for (Descriptors.Descriptor nested : msgType.getNestedTypes()) {
            registerMessage(nested);
        }
    }

    /**
     * Converts a JSON string into binary Protobuf bytes using the schema for the
     * named message type. This is what ProtomeHttpHandler calls on every intercepted request.
     *
     * JsonFormat.parser() is Google's official JSON-to-proto bridge. It maps JSON keys
     * to proto field names and handles type coercion. ignoringUnknownFields() means extra
     * JSON keys that don't exist in the schema are silently dropped rather than throwing —
     * useful when the user includes comments or extra debug fields in their JSON.
     */
    public byte[] jsonToProto(String json, String messageTypeName) throws Exception {
        if (!messageDescriptors.containsKey(messageTypeName)) {
            String availableKeys = String.join(", ", messageDescriptors.keySet());
            throw new IllegalArgumentException("Unknown message type: " + messageTypeName + ". Available: [" + availableKeys + "]");
        }

        Descriptors.Descriptor descriptor = messageDescriptors.get(messageTypeName);
        DynamicMessage.Builder builder = DynamicMessage.newBuilder(descriptor);
        JsonFormat.parser().ignoringUnknownFields().merge(json, builder);
        // toByteArray() produces the compact binary wire format — this is what gets
        // sent on the wire (or passed to ProtoMutator for fuzzing).
        return builder.build().toByteArray();
    }

    /**
     * Generates a JSON template with dummy values for every field in the given message.
     * Used by the "Build Request" right-click menu and the proto_gen.py helper script.
     *
     * preservingProtoFieldNames() ensures the output uses the original snake_case field
     * names from the .proto file rather than camelCase. This matters because the JSON
     * keys must match the .proto field names exactly when we later call jsonToProto().
     */
    public String generateDummyJson(Descriptors.Descriptor descriptor) throws Exception {
        DynamicMessage.Builder builder = DynamicMessage.newBuilder(descriptor);
        fillWithDummyData(builder, descriptor, 0);
        return JsonFormat.printer().preservingProtoFieldNames().print(builder.build());
    }

    /**
     * Recursively fills every field in a message builder with a plausible dummy value.
     * The depth limit of 3 prevents infinite recursion when a message type contains
     * a field of its own type (self-referential schemas).
     */
    private void fillWithDummyData(DynamicMessage.Builder builder, Descriptors.Descriptor descriptor, int depth) {
        if (depth > 3) return;
        for (Descriptors.FieldDescriptor field : descriptor.getFields()) {
            try {
                if (field.isRepeated()) {
                    // "repeated" in proto means a list/array. We add one example element.
                    if (field.getType() == Descriptors.FieldDescriptor.Type.MESSAGE) {
                        DynamicMessage.Builder sub = DynamicMessage.newBuilder(field.getMessageType());
                        fillWithDummyData(sub, field.getMessageType(), depth + 1);
                        builder.addRepeatedField(field, sub.build());
                    } else {
                        builder.addRepeatedField(field, getDummyValue(field));
                    }
                } else if (field.getType() == Descriptors.FieldDescriptor.Type.MESSAGE) {
                    // Nested message — recurse to fill its fields too.
                    DynamicMessage.Builder sub = DynamicMessage.newBuilder(field.getMessageType());
                    fillWithDummyData(sub, field.getMessageType(), depth + 1);
                    builder.setField(field, sub.build());
                } else {
                    Object val = getDummyValue(field);
                    if (val != null) builder.setField(field, val);
                }
            } catch (Exception ignored) {
            }
        }
    }

    /**
     * Returns a recognizable dummy value for a scalar field type.
     * String fields get "<fieldName>_value" so you can tell which field is which in the output.
     * Numeric fields all get 12345 / 12.34 — easy to spot and non-zero (zero is the proto3
     * default, so a zero value would be omitted from the serialized output, making the
     * template less useful as a reference).
     * For enums we pick the second value (index 1) when available — index 0 is the required
     * zero-value default in proto3, so picking index 1 produces a more interesting template.
     */
    private Object getDummyValue(Descriptors.FieldDescriptor field) {
        switch (field.getType()) {
            case STRING:   return field.getName() + "_value";
            case BOOL:     return true;
            case INT32: case SINT32: case SFIXED32: return 12345;
            case INT64: case SINT64: case SFIXED64: return 12345L;
            case UINT32: case FIXED32: return 12345;
            case UINT64: case FIXED64: return 12345L;
            case FLOAT:    return 12.34f;
            case DOUBLE:   return 12.34d;
            case BYTES:    return ByteString.copyFromUtf8("sample_bytes");
            case ENUM: {
                Descriptors.EnumDescriptor e = field.getEnumType();
                return e.getValues().size() > 1 ? e.getValues().get(1) : e.getValues().get(0);
            }
            default: return null;
        }
    }
}
