# Protome: Burp Suite Protobuf Bridge

**Protome** is a Burp Suite extension for testing Protobuf and gRPC services. It intercepts requests and converts JSON bodies into binary Protobuf on-the-fly, so you can use Burp's **Repeater**, **Intruder**, and **Scanner** with human-readable JSON while the extension handles binary serialization in the background.

Two modes are available:

- **Schema mode** — load a `.proto` file and serialize using named fields. Best when you have the schema.
- **Blackbox mode** — decode intercepted binary Protobuf with no schema required. Best for reverse engineering.

---

## Features

- **JSON-to-Protobuf:** Edit requests as JSON; send them as binary Protobuf.
- **Blackbox decoding:** Right-click any binary Protobuf request to decode it into editable JSON with no `.proto` file needed.
- **gRPC support:** Optional 5-byte gRPC framing header.
- **Fuzzing mutations:** Five binary-level mutation strategies for stress-testing server-side parsers.
- **Traffic logging:** Dedicated Logger tab showing every transformed request.
- **Payload generation:** Right-click any message in the Settings tree to generate a JSON template or a complete ready-to-paste Burp request.

---

## Installation

1. Download the pre-compiled JAR, or build it yourself (see below).
2. In Burp Suite, go to **Extensions** → **Add**.
3. Set **Extension type** to **Java**.
4. Select `ProtoMe-1.0-SNAPSHOT-all.jar` (use the `-all` jar — it bundles all dependencies).
5. Click **Next**. A new **Protome** tab will appear in the main Burp interface.

### Building from source

```bash
JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64 ./gradlew shadowJar
```

Output: `build/libs/ProtoMe-1.0-SNAPSHOT-all.jar`

---

## Schema Mode

Use this when you have the `.proto` definition for the target service.

### 1. Load a .proto file

1. Open the **Protome → Settings** tab.
2. Click **Select .proto File** and browse to your schema.
3. The left pane shows a tree of all message types and their fields. The right pane shows the raw source.

> If your `.proto` imports other files, keep them in the same directory so the compiler can resolve them.

### 2. Generate a payload

Right-click any message node in the tree:

- **Build Request** — copies a JSON body with dummy values for every field to your clipboard.
- **Copy as Full Burp Request** — copies a complete HTTP request string with all Protome headers pre-filled. Paste directly into Repeater.

### 3. Send the request

Add these headers to your request in Repeater or Intruder:

| Header | Value | Notes |
| :--- | :--- | :--- |
| `protome` | `true` | Required. Activates the extension for this request. |
| `protome-type` | `MessageName` | Required. Case-sensitive message name (e.g. `SearchRequest` or `com.example.SearchRequest`). |
| `protome-grpc` | `true` | Optional. Wraps the binary in a 5-byte gRPC framing header. |
| `protome-mutate` | `<strategy>` | Optional. Applies a fuzzing mutation before sending. See [Mutations](#mutations). |

**Example:**

```http
POST /api/search HTTP/1.1
Host: example.com
Content-Type: application/json
protome: true
protome-type: SearchRequest

{
    "query": "test_payload",
    "page_number": 1
}
```

The server receives binary Protobuf. The `protome` headers are stripped and `Content-Type` is set to `application/x-protobuf` (or `application/grpc` if gRPC framing is active).

---

## Blackbox Mode

Use this when you don't have a `.proto` file. Protome decodes intercepted binary Protobuf using wire-type heuristics, produces editable JSON with field numbers as keys (`field_1`, `field_2`, ...), and re-encodes it when you send the request. No schema file is loaded or required.

### 1. Decode a request

Right-click any request with a binary Protobuf body — in Proxy history, Repeater, Target site map, or anywhere else Burp shows a request — and select **Send to Protome (Blackbox)**.

A new Repeater tab opens with the decoded JSON. If gRPC framing was detected, it is stripped automatically and the `protome-grpc: true` header is added so framing is re-applied on send.

### 2. Edit and send

The JSON uses `field_N` keys matching the wire field numbers. Edit the values and send normally. Protome re-encodes the JSON to binary wire format.

For fields where the wire type is ambiguous, the decoder emits a typed wrapper object:

```json
{
    "field_1": "search query",
    "field_2": 42,
    "field_3": {"@type": "double", "@value": 3.14},
    "field_4": {"@type": "bytes", "@value": "SGVsbG8="}
}
```

You can change `@type` to reinterpret a field without touching the value. Supported types:

`int32` `int64` `uint32` `uint64` `sint32` `sint64` `bool` `double` `fixed64` `sfixed64` `float` `fixed32` `sfixed32` `string` `bytes` `packed_int64` `packed_int32` `packed_sint64` `packed_sint32`

### 3. Headers added automatically

Blackbox decoding sets these headers in the new Repeater tab — you don't add them manually:

| Header | Value | Notes |
| :--- | :--- | :--- |
| `protome` | `true` | Activates the extension. |
| `protome-blackbox` | `true` | Selects schema-free encoding. |
| `protome-grpc` | `true` | Only present if gRPC framing was detected in the original. |

---

## Mutations

Protome can deliberately corrupt a serialized Protobuf message at the binary level before sending, targeting weaknesses in server-side parsers that JSON-level tools can't reach.

Add the `protome-mutate` header to any schema-mode or blackbox-mode request:

```
protome-mutate: wire-type-flip
```

Mutation is applied after JSON→binary serialization and before gRPC framing.

### Strategies

| Strategy | What it does |
| :--- | :--- |
| `wire-type-flip` | Flips wire types on all field tags (VARINT↔LEN, I64↔I32). Parser receives the correct field number but the wrong type. |
| `varint-overflow` | Re-encodes all VARINT values as 11 bytes — one more than the 10-byte spec maximum. Strict parsers reject this outright. |
| `length-bomb` | Replaces all LEN field length prefixes with `2,147,483,647`. Targets parsers that pre-allocate a buffer of the declared size. |
| `duplicate-field` | Appends the entire message to itself so every field appears twice. |
| `unknown-field` | Appends four synthetic fields (numbers 10000–10003, all wire types) that won't exist in any real schema. |

### Using with Intruder

Open the **Protome → Mutations** tab to see all strategies with descriptions. Use **Copy All (Intruder Payload List)** to copy every strategy name as a line-separated list, then paste it into an Intruder simple list payload. Set the `protome-mutate` header value as the insertion point.

---

## Troubleshooting

**400 Bad Request in schema mode?**
- Check the Burp **Extensions → Output** tab. `Raw Size: 0 bytes` means your JSON field names don't match the `.proto` definition — they are case-sensitive. Use the right-click **Build Request** option to generate a correctly named template.
- If targeting a gRPC endpoint, add `protome-grpc: true`.

**"Unknown Message Type" error?**
- You must reload the `.proto` file in the Settings tab every time the extension is reloaded.
- Try the fully qualified name: `com.example.MessageName` instead of just `MessageName`.

**Blackbox decode produced no fields / error JSON?**
- The payload may be encrypted, compressed, or use a custom framing format. If you have a `.proto` file for this endpoint, use schema mode instead.
- The decoded JSON will include a `_raw_hex` field with the original bytes for manual inspection.

**Changes not visible in Repeater?**
- Transformation happens in-flight — the binary body won't appear in the Repeater editor. Check the **Protome → Logger** tab to inspect the final outgoing request.
