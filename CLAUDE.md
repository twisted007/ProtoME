# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

**Protome** is a Burp Suite extension (Java, Montoya API) that intercepts HTTP requests and converts JSON bodies into binary Protobuf on-the-fly. Primary user audience are security researchers, pentesters, and security engineers. Users edit requests as JSON in Burp Repeater/Intruder; the extension serializes them to binary before the request leaves Burp.

## Project Context
- This is a Burp Suite extension written in Java using Gradle with the Shadow plugin.
- Primary use cases include protobuf fuzzing and protocol-level attack tooling.
- When adding UI, follow Burp's Montoya API patterns for request building and viewers.

## Build

Must be run with the Java 17 JDK explicitly — the system default (`java-23-openjdk`) is a JRE-only install that lacks the compiler:

```bash
JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64 ./gradlew shadowJar
```

Output: `build/libs/ProtoMe-1.0-SNAPSHOT-all.jar`

Always use the `-all` jar — it bundles `protobuf-java`, `protobuf-java-util`, `protoc-jar`, and `gson`. The Burp API (`montoya-api`) is `compileOnly` and must not be bundled.

No tests exist in this project.

## Build Debugging
- When build failures occur, diagnose the ROOT CAUSE before applying fixes. Do not stack incremental workarounds.
- If you see `Toolchain installation does not provide the required capabilities: [JAVA_COMPILER]`, the wrong JDK is active — prefix the command with `JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64`.
- For Gradle/Shadow plugin errors, check plugin version compatibility and relocate directives first.
- Verify the build succeeds (`JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64 ./gradlew build`) after each fix attempt before moving on.


## Architecture

All source is under `src/main/java/com.protome/`. Four classes, each with a single responsibility:

| Class | Role |
|---|---|
| `ProtomeExtension` | Burp entry point (`BurpExtension`). Builds the Swing UI (Settings + Logger tabs), wires all components together. |
| `ProtoManager` | Core logic. Uses `protoc-jar` to compile a `.proto` file to a `FileDescriptorSet`, parses descriptors, and exposes `jsonToProto()` (JSON → binary) and `generateDummyJson()` (generate sample payloads). |
| `ProtomeHttpHandler` | Burp `HttpHandler`. Checks every outgoing request for `protome: true`, reads `protome-type` and `protome-grpc` headers, calls `ProtoManager.jsonToProto()`, strips the control headers, and replaces the body with binary. |
| `RequestLogger` | Swing component (table + Burp request viewer) that records each transformed request for review in the Logger tab. |

### Request transformation flow

1. User adds `protome: true` and `protome-type: <MessageName>` headers to a JSON request in Repeater.
2. `ProtomeHttpHandler.handleHttpRequestToBeSent()` fires, detects the headers.
3. It calls `ProtoManager.jsonToProto(jsonBody, msgType)` → binary `byte[]`.
4. If `protome-grpc: true`, a 5-byte gRPC framing header is prepended.
5. Control headers are removed; `Content-Type` is set to `application/x-protobuf` (or `application/grpc`).
6. Modified request is forwarded; `RequestLogger` records it.

### Proto loading flow

`ProtoManager.loadProto(File)` runs `protoc` (via `protoc-jar`) with `--descriptor_set_out` to produce a binary `FileDescriptorSet`, then walks the set in dependency order to build `Descriptors.FileDescriptor` objects. All messages (including nested) are registered in `messageDescriptors` under both short name and full name (e.g., `SearchRequest` and `com.example.SearchRequest`).

## Helper Script

`proto_gen.py` — standalone Python script. Given a `.proto` file and a message name, prints a JSON template with dummy values. Requires `grpcio-tools` and `protobuf` (`pip install grpcio-tools protobuf`). Run as:

```bash
python proto_gen.py path/to/file.proto MessageName
```

The same dummy-data logic exists inside `ProtoManager.generateDummyJson()` (Java) and is also accessible via right-click → "Build Request" in the Settings tree view.
