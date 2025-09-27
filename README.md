nativeHTTP - Advanced HTTP/WebSocket Client Library & CLI

A feature-rich C++ HTTP/WebSocket client library with a curl-like command-line interface, supporting HTTP/1.1, HTTP/2, WebSockets, multipart uploads, cookies, and advanced proxy authentication.
📦 Features
HTTP Capabilities

    ✅ Full HTTP Method Support: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS

    ✅ HTTP Versions: HTTP/1.1, HTTP/2 (HTTP/3 optional)

    ✅ Advanced Features: Redirect following, compression, keep-alive connections

    ✅ Security: SSL/TLS with certificate verification options

    ⬜ Authentication: Basic, Bearer, Digest, NTLM, AWS Signature v4

WebSocket Support

    ✅ Full RFC 6455 Compliance: Text and binary messages, ping/pong, fragmentation

    ✅ Advanced Features: Automatic reconnection, message queuing, event handlers

    ✅ Protocol Support: WS and WSS (secure WebSocket)

Data Handling

    ✅ Multipart Form Uploads: File uploads with automatic content-type detection

    ✅ JSON Support: Built-in JSON serialization/deserialization

    ✅ Cookie Management: Session persistence, file-based cookie jars

    ✅ Progress Tracking: Real-time upload/download progress

Platform Support

    ✅ Windows: Native WinHTTP implementation

    ⬜ Linux/Unix: OpenSSL-based implementation (fallback)

    ✅ Cross-platform: Standard C++17 with minimal dependencies

🚀 Quick Start
Building from Source
```bash

# Clone and build
git clone <repository>
cd nativeHTTP

# Build with WebSocket support (Windows)
g++ -std=c++17 -O2 -I. -DNATIVE_HTTP_HTTP3_SUPPORT=0 -DNATIVE_HTTP_WEBSOCKET_MINIMAL=0 -o nativehttp.exe nativeHTTP_W.cpp -lwinhttp -lsecur32 -lcrypt32 -lws2_32

# Build minimal version (no WebSocket)
g++ -std=c++17 -O2 -I. -DNATIVE_HTTP_WEBSOCKET_MINIMAL=1 -o nativehttp.exe nativeHTTP_W.cpp -lwinhttp -lsecur32 -lcrypt32
```
Basic CLI Usage
```bash
# Simple GET request
./nativehttp.exe https://httpbin.org/get

# POST JSON data
./nativehttp.exe -X POST https://httpbin.org/post -d '{"key":"value"}'

# WebSocket echo test
./nativehttp.exe --ws ws://echo.websocket.org --ws-message "Hello" --ws-listen
```
📖 CLI Reference
Basic HTTP Requests
```bash

# GET request
./nativehttp.exe https://api.example.com/data

# POST with data
./nativehttp.exe -X POST https://api.example.com/create -d '{"name":"test"}'

# POST JSON specifically
./nativehttp.exe -X POST https://api.example.com/create --json '{"name":"test"}'

# PUT request
./nativehttp.exe -X PUT https://api.example.com/update -d '{"id":1,"value":"new"}'

# DELETE request
./nativehttp.exe -X DELETE https://api.example.com/delete/123
```
Headers and Authentication
```bash

# Custom headers
./nativehttp.exe -H "Authorization: Bearer token" -H "X-API-Key: secret" https://api.example.com/data

# Multiple headers in one option
./nativehttp.exe -H "Authorization: Bearer token;X-API-Key: secret;Content-Type: application/json" https://api.example.com/data

# Basic authentication
./nativehttp.exe -u username:password https://api.example.com/protected

# User agent
./nativehttp.exe -A "MyApp/1.0" https://api.example.com/data
```
File Uploads and Multipart Forms
```bash

# Upload single file
./nativehttp.exe -F "file=@document.pdf" https://api.example.com/upload

# Multipart form with fields and files
./nativehttp.exe -F "name=John" -F "email=john@example.com" -F "avatar=@photo.jpg" https://api.example.com/profile

# Auto content-type detection
./nativehttp.exe -F "document=@file.pdf" -c "auto" https://api.example.com/upload

# Specific content-type
./nativehttp.exe -F "image=@photo.png" -c "image/png" https://api.example.com/upload
```
WebSocket Operations
```bash

# Connect to WebSocket and send message
./nativehttp.exe --ws wss://echo.websocket.org --ws-message "Hello World"

# Listen for incoming messages
./nativehttp.exe --ws wss://echo.websocket.org --ws-listen

# Send binary data
./nativehttp.exe --ws wss://example.com/ws --ws-binary data.bin

# With custom headers
./nativehttp.exe --ws wss://api.example.com/ws -H "Authorization: Bearer token" --ws-listen

# Ping every 30 seconds
./nativehttp.exe --ws wss://example.com/ws --ws-ping 30 --ws-listen
```
Advanced Options
```bash

# Follow redirects
./nativehttp.exe -L https://example.com/redirect

# Maximum redirects
./nativehttp.exe -L --max-redirects 10 https://example.com

# Timeout settings
./nativehttp.exe --connect-timeout 30 --max-time 60 https://api.example.com/slow

# SSL verification disabled
./nativehttp.exe -k https://self-signed.example.com

# Verbose output
./nativehttp.exe -v https://api.example.com/data

# Save output to file
./nativehttp.exe -o response.json https://api.example.com/data

# Headers only
./nativehttp.exe --headers-only https://api.example.com/data

# Include headers in output
./nativehttp.exe -i https://api.example.com/data
```
Proxy Support
```bash

# HTTP proxy
./nativehttp.exe -x http://proxy.example.com:8080 https://api.example.com/data

# HTTPS proxy
./nativehttp.exe -x https://proxy.example.com:8443 https://api.example.com/data

# Proxy with authentication
./nativehttp.exe -x http://user:pass@proxy.example.com:8080 https://api.example.com/data
```
Cookie Management
```bash

# Send cookies
./nativehttp.exe -b "session=abc123;user=john" https://api.example.com/data

# Save cookies to jar
./nativehttp.exe -c cookies.txt https://api.example.com/login

# Use cookie jar
./nativehttp.exe -b cookies.txt https://api.example.com/protected
```
📚 Library Usage
Basic HTTP Client
```cpp

#include "nativeHTTP.h"

// Simple GET request
nativeHTTP::Client client;
auto response = client.get("https://httpbin.org/get");

if (response.success()) {
    std::cout << "Status: " << response.status_code << std::endl;
    std::cout << "Body: " << response.get_body_text() << std::endl;
}
```
POST Requests
```cpp

// POST JSON data
nativeHTTP::Client client;
auto response = client.post_json("https://httpbin.org/post", 
    R"({"name":"John","age":30})");

// POST raw data
std::vector<uint8_t> data = {1, 2, 3, 4, 5};
auto response = client.post("https://api.example.com/upload", data);
```
Multipart Form Upload
```cpp

nativeHTTP::Client client;
nativeHTTP::MultipartFormData form;

// Add text fields
form.add_text("name", "John Doe");
form.add_text("email", "john@example.com");

// Add files (auto content-type detection)
form.add_file("document", "report.pdf");
form.add_file("photo", "avatar.jpg", "profile.jpg", "image/jpeg");

auto response = client.post_form("https://api.example.com/upload", form);
```
WebSocket Client
```cpp

#include "nativeHTTP.h"

class MyWebSocketHandler : public nativeHTTP::Client::WebSocket::EventHandler {
public:
    void on_open(nativeHTTP::Client::WebSocket* ws) override {
        std::cout << "Connected!" << std::endl;
    }
    
    void on_message(nativeHTTP::Client::WebSocket* ws, 
                   const std::string& message) override {
        std::cout << "Received: " << message << std::endl;
    }
    
    void on_error(nativeHTTP::Client::WebSocket* ws, 
                 const std::string& error) override {
        std::cerr << "Error: " << error << std::endl;
    }
};

// Usage
nativeHTTP::Client client;
MyWebSocketHandler handler;

auto ws = client.create_websocket("wss://echo.websocket.org");
ws->set_event_handler(&handler);

if (ws->connect()) {
    ws->send("Hello WebSocket!");
    std::this_thread::sleep_for(std::chrono::seconds(2));
    ws->close();
}
```
Advanced Configuration
```cpp

nativeHTTP::Client client;

// Configure client
client.set_timeout(30000); // 30 seconds
client.set_follow_redirects(true);
client.set_max_redirects(5);
client.set_verify_ssl(true);
client.set_user_agent("MyApp/1.0");
client.set_verbose(true);

// Set proxy
nativeHTTP::ProxyConfig proxy;
proxy.host = "proxy.example.com";
proxy.port = 8080;
proxy.username = "user";
proxy.password = "pass";
client.set_proxy(proxy);

// Custom headers
std::vector<std::string> headers = {
    "Authorization: Bearer token123",
    "X-Custom-Header: value"
};

auto response = client.get("https://api.example.com/data", headers);
```
Cookie Management
```cpp

nativeHTTP::Client client;

// Add cookies manually
nativeHTTP::CookieJar::Cookie cookie;
cookie.name = "session";
cookie.value = "abc123";
cookie.domain = "example.com";
cookie.path = "/";
client.get_cookie_jar().add_cookie(cookie);

// Save/load cookies from file
client.get_cookie_jar().save_to_file("cookies.txt");
client.get_cookie_jar().load_from_file("cookies.txt");
```
Progress Tracking
```cpp

bool progress_callback(size_t downloaded, size_t total, 
                      size_t uploaded, size_t upload_total) {
    if (total > 0) {
        int percent = (downloaded * 100) / total;
        std::cout << "\rProgress: " << percent << "%";
        std::cout.flush();
    }
    return true; // Return false to cancel transfer
}

// Use with request
auto response = client.get("https://example.com/largefile.zip", 
                          {}, progress_callback);
```
🔧 Advanced Examples
REST API Client
```cpp

class ApiClient {
    nativeHTTP::Client client;
    std::string base_url;
    std::string auth_token;
    
public:
    ApiClient(const std::string& url, const std::string& token) 
        : base_url(url), auth_token(token) {
        client.set_timeout(10000);
    }
    
    Json::Value get_user(int user_id) {
        auto response = client.get(base_url + "/users/" + std::to_string(user_id), 
                                 {"Authorization: Bearer " + auth_token});
        
        if (response.success()) {
            return parse_json(response.get_body_text());
        }
        throw std::runtime_error("API request failed");
    }
    
    Json::Value create_user(const std::string& name, const std::string& email) {
        std::string json_data = R"({"name":")" + name + R"(","email":")" + email + "\"}";
        auto response = client.post_json(base_url + "/users", json_data,
                                        {"Authorization: Bearer " + auth_token});
        
        if (response.success()) {
            return parse_json(response.get_body_text());
        }
        throw std::runtime_error("User creation failed");
    }
};
```
Real-time WebSocket Application
```cpp

class ChatClient : public nativeHTTP::Client::WebSocket::EventHandler {
    nativeHTTP::Client::WebSocket* ws;
    
public:
    void connect(const std::string& url) {
        nativeHTTP::Client client;
        ws = client.create_websocket(url).get();
        ws->set_event_handler(this);
        ws->connect();
    }
    
    void on_open(nativeHTTP::Client::WebSocket* ws) override {
        std::cout << "Connected to chat!" << std::endl;
        ws->send(R"({"type":"join","room":"general"})");
    }
    
    void on_message(nativeHTTP::Client::WebSocket* ws, 
                   const std::string& message) override {
        auto data = parse_json(message);
        if (data["type"] == "message") {
            std::cout << data["user"].asString() << ": " 
                      << data["text"].asString() << std::endl;
        }
    }
    
    void send_message(const std::string& text) {
        std::string message = R"({"type":"message","text":")" + text + "\"}";
        ws->send(message);
    }
};
```
File Upload Service
```cpp

class FileUploader {
public:
    bool upload_file(const std::string& url, const std::string& filepath, 
                    const std::string& auth_token) {
        nativeHTTP::Client client;
        nativeHTTP::MultipartFormData form;
        
        form.add_file("file", filepath, "", "auto");
        form.add_text("description", "Uploaded via nativeHTTP");
        form.add_text("timestamp", get_current_time());
        
        std::vector<std::string> headers = {
            "Authorization: Bearer " + auth_token,
            "X-Upload-Source: nativeHTTP-CLI"
        };
        
        auto response = client.post_form(url, form, headers, 
            [](size_t uploaded, size_t total, size_t, size_t) {
                if (total > 0) {
                    int percent = (uploaded * 100) / total;
                    std::cout << "\rUploading: " << percent << "%";
                    std::cout.flush();
                }
                return true;
            });
        
        std::cout << std::endl;
        return response.success();
    }
};
```
🎯 Feature Status
✅ Implemented & Tested

    Core HTTP Methods: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS

    WebSocket Protocol: Full RFC 6455 compliance

    Multipart Form Data: File uploads with auto content-type detection

    Cookie Management: Session persistence and file-based storage

    Proxy Support: HTTP/HTTPS proxies with authentication

    SSL/TLS: Secure connections with verification options

    Redirect Following: Automatic redirect handling

    Progress Tracking: Real-time upload/download progress

    Header Management: Custom headers and user agents

    JSON Support: Built-in JSON handling

    Timeout Configuration: Connection and operation timeouts

    Verbose Logging: Detailed request/response logging

⬜ Planned / In Progress

    Advanced Authentication: Digest, NTLM, AWS Signature v4

    Linux/Unix Support: Full OpenSSL implementation

    HTTP/3 Support: QUIC protocol implementation

    WebSocket Compression: permessage-deflate extension

    Connection Pooling: Reusable connection management

    Rate Limiting: Request throttling and backoff

    Streaming Responses: Chunked transfer encoding

    HTTP/2 Push Promises: Server push support

    OCSP Stapling: Online Certificate Status Protocol

    DNS-over-HTTPS: Secure DNS resolution

🔄 Known Issues & Limitations

    WebSocket Fragmentation: Basic support (treats fragments as complete messages)

    Linux Fallback: Limited functionality compared to Windows implementation

    Advanced Auth Methods: Structure exists but not fully implemented

    HTTP/3: Conditional compilation support but no implementation

🐛 Troubleshooting
Common Issues

WebSocket Connection Fails:
```bash

# Check if URL protocol is correct
./nativehttp.exe --ws ws://localhost:8765  # not http://

# Enable verbose logging
./nativehttp.exe --ws ws://localhost:8765 --verbose

# Check firewall and port accessibility
```
SSL Certificate Errors:
```bash

# Temporarily disable verification (not recommended for production)
./nativehttp.exe -k https://self-signed.example.com

# Or add certificate to system trust store
```
Timeout Issues:
```bash

# Increase timeout values
./nativehttp.exe --connect-timeout 60 --max-time 300 https://slow.api.com
```
Debug Mode

Enable detailed logging:
```cpp

nativeHTTP::Logger::set_level(nativeHTTP::Logger::DEBUG_LEVEL);
```
Or via CLI:
```bash

./nativehttp.exe -v https://api.example.com/data
```
🤝 Roadmap
Short Term (Next Release)

    Fix WebSocket fragmentation handling

    Implement Digest authentication

    Add Linux CI/CD pipeline

    Improve error messages and documentation

Medium Term

    Full Linux/Unix support

    HTTP/3 implementation

    Advanced proxy authentication methods

    Performance optimization

Long Term

    WebSocket compression support

    HTTP/2 server push

    DNS-over-HTTPS integration

    gRPC protocol support

Areas where help is especially needed:

    Linux/Unix implementation

    Advanced authentication methods

    HTTP/3 support

    Documentation improvements

    Test coverage

📞 Support

For issues and questions:

    Check the troubleshooting section above

    Review the code examples

    Open an issue on the project repository
