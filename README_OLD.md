# Protome: Burp Suite Protobuf Bridge

**Protome** is a Burp Suite extension that allows you to test Protobuf services using user-friendly JSON. It intercepts requests, converts the JSON body into binary Protobuf "in-flight" based on a provided `.proto` definition, and sends the binary payload to the server.

This enables you to use Burp's **Repeater**, **Intruder**, and **Scanner** with standard JSON payloads, while the extension handles the complex binary serialization in the background.

## Features
* **Dynamic Compilation:** Loads `.proto` files directly without manual compilation.
* **JSON-to-Protobuf:** Edit requests as JSON; send them as Protobuf.
* **gRPC Support:** Optional toggling of gRPC framing (5-byte header).
* **Traffic Logging:** Dedicated tab to view the transformed requests.

---

## 1. Installation

1.  **Download the JAR file**
    * Download the pre-compiled .jar file from this repository.
2.  **(OPTIONAL) Build the Project:** If you want to customize
    * Open the project in IntelliJ IDEA.
    * Run the Gradle task: `Tasks` > `shadow` > `shadowJar`.
    * Locate the file `build/libs/Protome-1.0-SNAPSHOT-all.jar`. (Note: Use the **`-all`** jar, which includes dependencies).
3.  **Load into Burp Suite:**
    * Go to the **Extensions** tab in Burp Suite.
    * Click **Add**.
    * Select **Extension type: Java**.
    * Click **Select file...** and choose the `Protome-1.0-SNAPSHOT-all.jar`.
    * Click **Next**. You should see a new tab titled **Protome** appear in the main interface.

---

## 2. Configuration

Before intercepting traffic, you must tell Protome what your data structures look like.

1.  Click the **Protome** tab in Burp Suite.
2.  Go to the **Settings** sub-tab.
3.  Click **Select .proto File**.
4.  Browse to your target `.proto` definition file.
5.  Check the **Extensions > Output** tab to confirm the file was loaded and to see a list of available Message Types.

> **Note:** If your `.proto` file imports other files, ensure they are located in the same directory so the compiler can resolve them.

---

## 3. Usage

Protome uses specific **HTTP Headers** to trigger transformations. If these headers are not present, the request is passed through unchanged.

### Required Headers
To modify a request in **Repeater** or **Intruder**, add these headers:

| Header | Value | Description |
| :--- | :--- | :--- |
| `protome` | `true` | **Required.** Activates the extension for this request. |
| `protome-type` | `MessageName` | **Required.** The case-sensitive name of the message (e.g., `SearchRequest` or `com.example.SearchRequest`). |

### Optional Headers

| Header | Value | Description |
| :--- | :--- | :--- |
| `protome-grpc` | `true` | Wraps the binary payload in the standard 5-byte gRPC header (Compression + Length). Use this if the target is a gRPC endpoint. |

### Example Request (Repeater)

**Input (What you see):**
```http
POST /api/search HTTP/1.1
Host: example.com
protome: true
protome-type: SearchRequest
Content-Type: application/json

{
    "query": "test_payload",
    "page_number": 1
}
```
**Output (What the server sees):**
- **Headers:** 
	- `protome` headers are removed. 
	- `Content-Type` is set to `application/x-protobuf`.
- **Body:** The JSON is serialized into binary Protobuf.


---

## 4. Generating Sample JSON

Protobuf parsers are strict. If your JSON keys do not match the `.proto` field names exactly (case-sensitive), the fields will be ignored, resulting in empty messages and `400 Bad Request` errors.

Use the provided Python script `proto_gen.py` to generate a valid JSON template.

### Setup (Virtual Environment)
Keep your system clean by running this in a virtual environment:

```bash
# 1. Create the virtual environment
python3 -m venv venv

# 2. Activate it
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

# 3. Install dependencies
pip install grpcio-tools protobuf
```

### How to use
1.  **Identify the Message Name:**
    * Load your `.proto` file in the Burp Extension.
    * Look at the **Extensions > Output** tab. It lists all registered messages (e.g., `>> REGISTERED: com.example.SearchRequest`).
2.  **Run the script:**
    Pass the path to your `.proto` file and the message name you want to generate.

```bash
python proto_gen.py path/to/config.proto SearchRequest
```

3.  **Result:**
    The script will print a valid JSON object with dummy data for every field. Copy this into Burp Repeater to ensure your structure is correct.

---

## Troubleshooting

* **400 Bad Request?**
    * Check the Burp **Extensions > Output** tab. If it says `Raw Size: 0 bytes`, your JSON keys do not match the `.proto` definition. Use `proto_gen.py` to verify spelling.
    * Try adding `protome-grpc: true` if targeting a gRPC service.
* **"Unknown Message Type" Error?**
    * Did you reload the extension? You must reload the `.proto` file in the Settings tab every time you reload the extension JAR.
    * Check if the message is inside a package. You may need to use `com.example.MessageName` instead of just `MessageName`.
* **Changes not appearing?**
    * Modifications happen "in-flight." You won't see the binary in Repeater. Check the **Protome > Logger** tab to see the final outgoing request.
