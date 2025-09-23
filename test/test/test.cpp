// test.cpp - Enhanced CLI tool with full feature support
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <map>
#include <algorithm>
#include <thread>
#include <chrono>
#include "nativeHTTP.h"

// Enhanced usage with all features
void show_usage(const char* program_name) {
    std::cout << "nativeHTTP CLI v2.6.1\n\n";
    std::cout << "Usage: " << program_name << " [OPTIONS] [URL]\n\n";
    
    std::cout << "HTTP Methods:\n";
    std::cout << "  -X, --request METHOD     HTTP method (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD)\n";
    std::cout << "  -G, --get                Send GET request (default)\n";
    std::cout << "  -I, --head               Send HEAD request\n";
    std::cout << "  -d, --data DATA          HTTP POST data\n";
    std::cout << "  -F, --form KEY=VALUE     Add multipart form data (can be used multiple times)\n";
    std::cout << "  -F, --form KEY@FILE      Upload file as form data (can be used multiple times)\n";
    std::cout << "  -T, --upload-file FILE   Upload file using PUT or POST\n";
    std::cout << "  --data-binary DATA       POST data without processing\n";
    std::cout << "  --data-urlencode DATA    URL-encoded form data\n\n";
    
    std::cout << "Headers and Cookies:\n";
    std::cout << "  -H, --header HEADER      Add custom header (can be used multiple times)\n";
    std::cout << "  -A, --user-agent AGENT   Send User-Agent string\n";
    std::cout << "  -e, --referer URL        Referer URL\n";
    std::cout << "  -b, --cookie DATA        Send cookies from string\n";
    std::cout << "  -c, --cookie-jar FILE    Write cookies to file after operation\n";
    std::cout << "  -j, --junk-session-cookies Ignore session cookies\n\n";
    
    std::cout << "Advanced HTTP Features:\n";
    std::cout << "  -L, --location           Follow redirects\n";
    std::cout << "  --max-redirects NUM      Maximum redirects (default: 5)\n";
    std::cout << "  --compressed             Request compressed response\n";
    std::cout << "  --http1.0                Use HTTP/1.0\n";
    std::cout << "  --http1.1                Use HTTP/1.1 (default)\n";
    std::cout << "  --http2                  Use HTTP/2\n";
#if NATIVE_HTTP_HTTP3_SUPPORT
    std::cout << "  --http3                  Use HTTP/3\n";
#endif
    std::cout << "  --max-time SEC           Maximum time for operation\n\n";
    
    std::cout << "Proxy and Authentication:\n";
    std::cout << "  -x, --proxy [PROTOCOL://]HOST[:PORT]  Use proxy\n";
    std::cout << "  -U, --proxy-user USER[:PASS]          Proxy user and password\n";
    std::cout << "  --proxy-ntlm                          Use NTLM proxy authentication\n";
    std::cout << "  --proxy-negotiate                     Use Negotiate (Kerberos) authentication\n";
    std::cout << "  --proxy-bearer TOKEN                  Use Bearer token authentication\n";
    std::cout << "  -u, --user USER[:PASS]                Server user and password\n";
    std::cout << "  --oauth2-bearer TOKEN                 OAuth 2.0 Bearer Token\n";
    std::cout << "  --aws-sigv4 KEY:SECRET:REGION:SERVICE AWS Signature Version 4\n\n";
    
    std::cout << "SSL/TLS Security:\n";
    std::cout << "  -k, --insecure           Allow insecure SSL connections\n";
    std::cout << "  --cacert FILE            CA certificate to verify peer against\n";
    std::cout << "  --cert FILE              Client certificate file\n";
    std::cout << "  --key FILE               Private key file\n";
    std::cout << "  --tlsv1.0                Use TLSv1.0\n";
    std::cout << "  --tlsv1.1                Use TLSv1.1\n";
    std::cout << "  --tlsv1.2                Use TLSv1.2\n";
    std::cout << "  --tlsv1.3                Use TLSv1.3\n";
    std::cout << "  --ssl-revoke-best-effort Enable certificate revocation checks\n\n";
    
    std::cout << "WebSocket Features:\n";
#if !NATIVE_HTTP_WEBSOCKET_MINIMAL
    std::cout << "  --ws                     Use WebSocket protocol\n";
    std::cout << "  --ws-version VER         WebSocket version (default: 13)\n";
    std::cout << "  --ws-protocol PROTO      WebSocket subprotocol\n";
    std::cout << "  --ws-message MESSAGE     Send WebSocket message\n";
    std::cout << "  --ws-binary FILE         Send binary file over WebSocket\n";
    std::cout << "  --ws-ping INTERVAL       Send ping every INTERVAL seconds\n";
    std::cout << "  --ws-listen              Listen for incoming messages\n";
    std::cout << "  --ws-timeout SEC         WebSocket connection timeout\n";
#endif
    std::cout << "\n";
    
    std::cout << "Output and Debugging:\n";
    std::cout << "  -i, --include            Include response headers in output\n";
    std::cout << "  -v, --verbose            Verbose output (show request/response)\n";
    std::cout << "  --trace FILE             Write debug trace to file\n";
    std::cout << "  --trace-ascii FILE       Write debug trace (ASCII) to file\n";
    std::cout << "  -s, --silent             Silent mode (no progress/output)\n";
    std::cout << "  -o, --output FILE        Write output to file\n";
    std::cout << "  -D, --dump-header FILE   Write headers to file\n";
    std::cout << "  --progress-bar           Show progress bar\n";
    std::cout << "  --write-out FORMAT       Use output format string\n\n";
    
    std::cout << "Miscellaneous:\n";
    std::cout << "  -h, --help               Show this help\n";
    std::cout << "  -V, --version            Show version information\n";
    std::cout << "  --libcurl                Output libcurl equivalent command\n";
    std::cout << "  --max-filesize BYTES     Maximum file size to download\n\n";
    
    std::cout << "Examples:\n";
    std::cout << "  " << program_name << " https://httpbin.org/get\n";
    std::cout << "  " << program_name << " -X POST https://httpbin.org/post -d '{\"test\":\"data\"}'\n";
    std::cout << "  " << program_name << " -F \"file1=@document.pdf\" -F \"name=test\" https://httpbin.org/post\n";
    std::cout << "  " << program_name << " -x http://proxy:8080 -U user:pass https://httpbin.org/ip\n";
    std::cout << "  " << program_name << " --http2 -v https://http2.akamai.com/demo\n";
#if !NATIVE_HTTP_WEBSOCKET_MINIMAL
    std::cout << "  " << program_name << " --ws wss://echo.websocket.org --ws-message \"Hello\" --ws-listen\n";
#endif
}

// Enhanced WebSocket handler
#if !NATIVE_HTTP_WEBSOCKET_MINIMAL
class EnhancedWebSocketHandler : public nativeHTTP::Client::WebSocket::EventHandler {
private:
    std::ostream* output;
    bool verbose;
    bool show_timestamps;
    
public:
    EnhancedWebSocketHandler(std::ostream* out = &std::cout, bool verb = false, bool ts = false) 
        : output(out), verbose(verb), show_timestamps(ts) {}
    
    void on_open(nativeHTTP::Client::WebSocket* ws) override {
        std::string timestamp = show_timestamps ? get_timestamp() + " " : "";
        *output << timestamp << " WebSocket connected to: " << ws->get_url() << "\n";
    }
    
    void on_message(nativeHTTP::Client::WebSocket* ws, const std::string& message) override {
        std::string timestamp = show_timestamps ? get_timestamp() + " " : "";
        *output << timestamp << " " << message << "\n";
        if (verbose) {
            *output << timestamp << "   Message size: " << message.size() << " bytes\n";
        }
    }
    
    void on_binary(nativeHTTP::Client::WebSocket* ws, const std::vector<uint8_t>& data) override {
        std::string timestamp = show_timestamps ? get_timestamp() + " " : "";
        *output << timestamp << " Binary data: " << data.size() << " bytes\n";
        if (verbose && data.size() <= 1024) {
            // Show hex dump for small binary messages
            *output << hex_dump(data) << "\n";
        }
    }
    
    void on_error(nativeHTTP::Client::WebSocket* ws, const std::string& error) override {
        std::string timestamp = show_timestamps ? get_timestamp() + " " : "";
        *output << timestamp << " Error: " << error << "\n";
    }
    
    void on_close(nativeHTTP::Client::WebSocket* ws, uint16_t code, const std::string& reason) override {
        std::string timestamp = show_timestamps ? get_timestamp() + " " : "";
        *output << timestamp << " Connection closed: " << code;
        if (!reason.empty()) *output << " - " << reason;
        *output << "\n";
    }
    
    void on_ping(nativeHTTP::Client::WebSocket* ws, const std::vector<uint8_t>& data) override {
        if (verbose) {
            std::string timestamp = show_timestamps ? get_timestamp() + " " : "";
            *output << timestamp << " Ping received (" << data.size() << " bytes)\n";
        }
    }
    
    void on_pong(nativeHTTP::Client::WebSocket* ws, const std::vector<uint8_t>& data) override {
        if (verbose) {
            std::string timestamp = show_timestamps ? get_timestamp() + " " : "";
            *output << timestamp << " Pong received (" << data.size() << " bytes)\n";
        }
    }
    
private:
    std::string get_timestamp() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;
        
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%H:%M:%S");
        ss << "." << std::setfill('0') << std::setw(3) << ms.count();
        return ss.str();
    }
    
    std::string hex_dump(const std::vector<uint8_t>& data) {
        std::stringstream ss;
        for (size_t i = 0; i < data.size(); i++) {
            if (i > 0 && i % 16 == 0) ss << "\n";
            ss << std::hex << std::setw(2) << std::setfill('0') 
               << static_cast<int>(data[i]) << " ";
        }
        return ss.str();
    }
};
#endif

// Progress callback for file transfers
bool progress_callback(size_t downloaded, size_t total, size_t uploaded, size_t upload_total) {
    static auto start_time = std::chrono::steady_clock::now();
    
    if (total > 0) {
        int percent = static_cast<int>((downloaded * 100) / total);
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
        
        if (elapsed > 0) {
            double speed = downloaded / elapsed / 1024.0; // KB/s
            std::cout << "\rProgress: " << percent << "% (" << downloaded << "/" << total 
                      << ") Speed: " << std::fixed << std::setprecision(1) << speed << " KB/s";
            std::cout.flush();
        }
    }
    
    return true; // Return false to cancel transfer
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        show_usage(argv[0]);
        return 1;
    }
    
    // Enhanced argument parsing
    std::vector<std::string> args(argv + 1, argv + argc);
    std::string url;
    std::string method = "GET";
    std::vector<std::string> headers;
    std::vector<std::pair<std::string, std::string>> form_data; // key-value pairs
    std::vector<std::tuple<std::string, std::string, std::string>> form_files; // key, file, filename
    std::string data;
    std::string output_file;
    std::string header_file;
    std::string proxy;
    std::string cookie_data;
    std::string cookie_jar_file;
    bool include_headers = false;
    bool verbose = false;
    bool silent = false;
    bool follow_redirects = false;
    bool insecure = false;
    bool show_progress = false;
    bool is_websocket = false;
    bool show_help = false;
    bool show_version = false;
    int timeout = 30;
    int max_redirects = 5;
    
    // Parse all arguments
    for (size_t i = 0; i < args.size(); i++) {
        const auto& arg = args[i];
        
        if (arg == "-h" || arg == "--help") {
            show_help = true;
        }
        else if (arg == "-V" || arg == "--version") {
            show_version = true;
        }
        else if (arg == "-X" || arg == "--request") {
            if (i + 1 < args.size()) method = nativeHTTP::utils::to_upper(args[++i]);
        }
        else if (arg == "-H" || arg == "--header") {
            if (i + 1 < args.size()) headers.push_back(args[++i]);
        }
        else if (arg == "-d" || arg == "--data") {
            if (i + 1 < args.size()) data = args[++i];
        }
        else if (arg == "-F" || arg == "--form") {
            if (i + 1 < args.size()) {
                std::string form_arg = args[++i];
                size_t equals_pos = form_arg.find('=');
                if (equals_pos != std::string::npos) {
                    std::string key = form_arg.substr(0, equals_pos);
                    std::string value = form_arg.substr(equals_pos + 1);
                    
                    if (value.size() > 1 && value[0] == '@') {
                        // File upload
                        std::string filepath = value.substr(1);
                        form_files.emplace_back(key, filepath, "");
                    } else {
                        // Text field
                        form_data.emplace_back(key, value);
                    }
                }
            }
        }
        else if (arg == "-o" || arg == "--output") {
            if (i + 1 < args.size()) output_file = args[++i];
        }
        else if (arg == "-i" || arg == "--include") {
            include_headers = true;
        }
        else if (arg == "-v" || arg == "--verbose") {
            verbose = true;
            nativeHTTP::Logger::set_level(nativeHTTP::Logger::DEBUG_LEVEL);
        }
        else if (arg == "-s" || arg == "--silent") {
            silent = true;
        }
        else if (arg == "-L" || arg == "--location") {
            follow_redirects = true;
        }
        else if (arg == "-k" || arg == "--insecure") {
            insecure = true;
        }
        else if (arg == "-x" || arg == "--proxy") {
            if (i + 1 < args.size()) proxy = args[++i];
        }
        else if (arg == "--progress-bar") {
            show_progress = true;
        }
        else if (arg == "--ws") {
            is_websocket = true;
        }
        else if (arg == "-u" || arg == "--user") {
            if (i + 1 < args.size()) {
                std::string user_pass = args[++i];
                std::string auth = "Authorization: Basic " + nativeHTTP::unicode::base64_encode(user_pass);
                headers.push_back(auth);
            }
        }
        else if (arg == "-b" || arg == "--cookie") {
            if (i + 1 < args.size()) cookie_data = args[++i];
        }
        else if (arg == "-A" || arg == "--user-agent") {
            if (i + 1 < args.size()) headers.push_back("User-Agent: " + args[++i]);
        }
        else if (arg == "--max-redirects") {
            if (i + 1 < args.size()) max_redirects = std::stoi(args[++i]);
        }
        else if (arg == "--connect-timeout") {
            if (i + 1 < args.size()) timeout = std::stoi(args[++i]);
        }
        else if (!arg.empty() && arg[0] != '-') {
            url = arg;
        }
    }
    
    if (show_help) {
        show_usage(argv[0]);
        return 0;
    }
    
    if (show_version) {
        std::cout << "nativeHTTP CLI v2.1.6\n";
        std::cout << "Features: HTTP/1.1, HTTP/2";
#if NATIVE_HTTP_HTTP3_SUPPORT
        std::cout << ", HTTP/3";
#endif
        std::cout << ", WebSocket, Advanced Proxy Auth, Multipart, Cookies\n";
        std::cout << "WebSocket: " << 
#if NATIVE_HTTP_WEBSOCKET_MINIMAL
            "Minimal" 
#else
            "Full"
#endif
            << " implementation\n";
        return 0;
    }
    
    if (url.empty()) {
        std::cerr << "Error: URL is required\n\n";
        show_usage(argv[0]);
        return 1;
    }
    
    try {
        // Setup output
        std::ostream* output = &std::cout;
        std::ofstream file_output;
        if (!output_file.empty()) {
            file_output.open(output_file, std::ios::binary);
            if (file_output.is_open()) {
                output = &file_output;
            } else {
                std::cerr << "Error: Cannot open output file: " << output_file << "\n";
                return 1;
            }
        }
        
        nativeHTTP::Client client;
        client.set_verbose(verbose);
        client.set_timeout(timeout * 1000);
        client.set_follow_redirects(follow_redirects);
        client.set_verify_ssl(!insecure);
        client.set_max_redirects(max_redirects);
        
        // Setup proxy if specified
        if (!proxy.empty()) {
            nativeHTTP::ProxyConfig proxy_config;
            nativeHTTP::ParsedURL parsed_proxy = nativeHTTP::ParsedURL::parse(proxy);
            if (parsed_proxy.valid) {
                proxy_config.host = parsed_proxy.host;
                proxy_config.port = parsed_proxy.port;
                proxy_config.type = parsed_proxy.protocol;
                client.set_proxy(proxy_config);
            }
        }
        
        // Setup cookies
        if (!cookie_data.empty()) {
            auto cookies = nativeHTTP::utils::split(cookie_data, ';');
            for (const auto& cookie : cookies) {
                auto parts = nativeHTTP::utils::split(cookie, '=');
                if (parts.size() == 2) {
                    nativeHTTP::CookieJar::Cookie c;
                    c.name = nativeHTTP::utils::trim(parts[0]);
                    c.value = nativeHTTP::utils::trim(parts[1]);
                    nativeHTTP::ParsedURL parsed_url = nativeHTTP::ParsedURL::parse(url);
                    if (parsed_url.valid) {
                        c.domain = parsed_url.host;
                        c.path = "/";
                        client.get_cookie_jar().add_cookie(c);
                    }
                }
            }
        }
        
#if !NATIVE_HTTP_WEBSOCKET_MINIMAL
        if (is_websocket) {
            // Enhanced WebSocket mode
            EnhancedWebSocketHandler handler(output, verbose, true);
            
            auto ws = client.create_websocket(url, headers);
            if (ws) {
                ws->set_event_handler(&handler);
                
                if (ws->connect()) {
                    if (!silent) *output << " WebSocket connected successfully!\n";
                    
                    // Handle WebSocket commands
                    bool listening = false;
                    int ping_interval = 0;
                    
                    for (size_t i = 0; i < args.size(); i++) {
                        if (args[i] == "--ws-message" && i + 1 < args.size()) {
                            ws->send(args[++i]);
                        }
                        else if (args[i] == "--ws-binary" && i + 1 < args.size()) {
                            std::string filename = args[++i];
                            std::ifstream file(filename, std::ios::binary);
                            if (file) {
                                std::vector<uint8_t> data(
                                    (std::istreambuf_iterator<char>(file)),
                                    std::istreambuf_iterator<char>());
                                ws->send_binary(data);
                            }
                        }
                        else if (args[i] == "--ws-ping" && i + 1 < args.size()) {
                            ping_interval = std::stoi(args[++i]);
                        }
                        else if (args[i] == "--ws-listen") {
                            listening = true;
                        }
                    }
                    
                    // Ping loop if requested
                    if (ping_interval > 0) {
                        std::thread ping_thread([ws, ping_interval]() {
                            while (ws->is_connected()) {
                                std::this_thread::sleep_for(std::chrono::seconds(ping_interval));
                                ws->ping();
                            }
                        });
                        ping_thread.detach();
                    }
                    
                    // Listen mode
                    if (listening) {
                        if (!silent) *output << "🎧 Listening for messages (Ctrl+C to exit)...\n";
                        while (ws->is_connected()) {
                            std::this_thread::sleep_for(std::chrono::milliseconds(100));
                        }
                    } else {
                        // Wait a bit for responses
                        std::this_thread::sleep_for(std::chrono::seconds(3));
                    }
                    
                    ws->close(1000, "CLI completed");
                } else {
                    *output << " Failed to connect to WebSocket\n";
                    return 1;
                }
            }
        } else 
#endif
        {
            // Enhanced HTTP mode with multipart support
            nativeHTTP::Client::Response response;
            nativeHTTP::Client::ProgressCallback progress_cb = nullptr;
            
            if (show_progress) {
                progress_cb = progress_callback;
            }
            
            if (method == "GET") {
                response = client.get(url, headers, progress_cb);
            }
            else if (method == "POST") {
                if (!form_data.empty() || !form_files.empty()) {
                    // Multipart form data
                    nativeHTTP::MultipartFormData form;
                    
                    // Add text fields
                    for (const auto& field : form_data) {
                        form.add_text(field.first, field.second);
                    }
                    
                    // Add files
                    for (const auto& file : form_files) {
                        form.add_file(std::get<0>(file), std::get<1>(file), std::get<2>(file));
                    }
                    
                    response = client.post_form(url, form, headers, progress_cb);
                }
                else if (!data.empty()) {
                    response = client.post_json(url, data, headers, progress_cb);
                }
                else {
                    response = client.post(url, {}, headers, progress_cb);
                }
            }
            else if (method == "PUT") {
                std::vector<uint8_t> put_data(data.begin(), data.end());
                response = client.put(url, put_data, headers, progress_cb);
            }
            else if (method == "DELETE") {
                response = client.delete_(url, headers, progress_cb);
            }
            else if (method == "HEAD") {
                response = client.head(url, headers);
            }
            else if (method == "PATCH") {
                std::vector<uint8_t> patch_data(data.begin(), data.end());
                response = client.patch(url, patch_data, headers, progress_cb);
            }
            else if (method == "OPTIONS") {
                response = client.options(url, headers);
            }
            else {
                *output << " Unsupported method: " << method << "\n";
                return 1;
            }
            
            // Enhanced output formatting
            if (include_headers) {
                *output << response.get_headers_string();
            }
            
            if (!response.body.empty()) {
                output->write(reinterpret_cast<const char*>(response.body.data()), 
                             response.body.size());
            }
            
            if (!silent) {
                if (verbose) {
                    *output << "\n\n=== Response Summary ===\n";
                    *output << "URL: " << (response.effective_url.empty() ? response.url : response.effective_url) << "\n";
                    *output << "Status: " << response.status_code << " " << response.status_text << "\n";
                    *output << "Time: " << std::fixed << std::setprecision(2) << response.elapsed_time << " ms\n";
                    *output << "Size: " << response.downloaded_bytes << " bytes downloaded, " 
                           << response.uploaded_bytes << " bytes uploaded\n";
                    *output << "HTTP Version: " 
                           << (response.http_version == nativeHTTP::constants::HttpVersion::HTTP1_0 ? "1.0" :
                              response.http_version == nativeHTTP::constants::HttpVersion::HTTP2_0 ? "2.0" :
                              response.http_version == nativeHTTP::constants::HttpVersion::HTTP3_0 ? "3.0" : "1.1") << "\n";
                    
                    if (!response.error_message.empty()) {
                        *output << "Error: " << response.error_message << "\n";
                    }
                    
                    if (response.redirect()) {
                        *output << "Redirect: " << response.get_header("Location") << "\n";
                    }
                } else {
                    *output << "\n"; // Ensure newline after content
                }
            }
            
            // Save cookies if requested
            if (!cookie_jar_file.empty()) {
                client.get_cookie_jar().save_to_file(cookie_jar_file);
                if (!silent) {
                    std::cout << "Cookies saved to: " << cookie_jar_file << "\n";
                }
            }
            
            // Return appropriate exit code
            if (response.success()) {
                return 0;
            } else {
                return response.status_code > 0 ? response.status_code / 100 : 1;
            }
        }
        
    } catch (const std::exception& e) {
        std::cerr << " Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}
