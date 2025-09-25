#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <map>
#include <algorithm>
#include <thread>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <atomic>
#include <condition_variable>
#include <mutex>

#include "nativeHTTP.h"

using namespace std;

void show_usage(const char* program_name) {
    cout << "nativeHTTP CLI v3.0\n\n";
    cout << "Usage: " << program_name << " [OPTIONS] [URL]\n\n";
    cout << "HTTP Methods:\n";
    cout << "  -X, --request METHOD     HTTP method (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD)\n";
    cout << "  -G, --get                Send GET request (default)\n";
    cout << "  -I, --head               Send HEAD request\n";
    cout << "  -d, --data DATA          HTTP POST data\n";
    cout << "  -F, --form KEY=VALUE     Add multipart form data (can be used multiple times)\n";
    cout << "  -F, --form KEY@FILE      Upload file as form data (can be used multiple times)\n";
    cout << "  -T, --upload-file FILE   Upload file using PUT or POST\n";
    cout << "  -c, --content-type TYPE  Set content type for file uploads (use 'auto' for auto-detection)\n";
    cout << "  --data-binary DATA       POST data without processing\n";
    cout << "  --data-urlencode DATA    URL-encoded form data\n\n";

    cout << "Headers and Cookies:\n";
    cout << "  -H, --header HEADER      Add custom header (can be used multiple times, use ; for multiple)\n";
    cout << "  -A, --user-agent AGENT   Send User-Agent string\n";
    cout << "  -e, --referer URL        Referer URL\n";
    cout << "  -b, --cookie DATA        Send cookies from string\n";
    cout << "  -c, --cookie-jar FILE    Write cookies to file after operation\n";
    cout << "  -j, --junk-session-cookies Ignore session cookies\n\n";

    cout << "Advanced HTTP Features:\n";
    cout << "  -L, --location           Follow redirects\n";
    cout << "  --max-redirects NUM      Maximum redirects (default: 5)\n";
    cout << "  --compressed             Request compressed response\n";
    cout << "  --http1.0                Use HTTP/1.0\n";
    cout << "  --http1.1                Use HTTP/1.1 (default)\n";
    cout << "  --http2                  Use HTTP/2\n";
#if NATIVE_HTTP_HTTP3_SUPPORT
    cout << "  --http3                  Use HTTP/3\n";
#endif
    cout << "  --max-time SEC           Maximum time for operation\n\n";

    cout << "Output and Debugging:\n";
    cout << "  -i, --include            Include response headers in output\n";
    cout << "  --headers-only           Output only response headers (no body)\n";
    cout << "  -v, --verbose            Verbose output (show request/response)\n";
    cout << "  --trace FILE             Write debug trace to file\n";
    cout << "  --trace-ascii FILE       Write debug trace (ASCII) to file\n";
    cout << "  -s, --silent             Silent mode (no progress/output)\n";
    cout << "  -o, --output FILE        Write output to file\n";
    cout << "  -D, --dump-header FILE   Write headers to file\n";
    cout << "  --progress-bar           Show progress bar\n";
    cout << "  --write-out FORMAT       Use output format string\n\n";

    cout << "Miscellaneous:\n";
    cout << "  -h, --help               Show this help\n";
    cout << "  -V, --version            Show version information\n";
    cout << "  --libcurl                Output libcurl equivalent command\n";
    cout << "  --max-filesize BYTES     Maximum file size to download\n\n";

    cout << "Examples:\n";
    cout << "  " << program_name << " https://httpbin.org/get\n";
    cout << "  " << program_name << " -X POST https://httpbin.org/post -d '{\"test\":\"data\"}'\n";
    cout << "  " << program_name << " -F \"file1=@document.pdf\" -c \"application/pdf\" https://httpbin.org/post\n";
    cout << "  " << program_name << " -F \"file1=@image.png\" -c \"auto\" https://httpbin.org/post\n";
    cout << "  " << program_name << " -H \"Authorization: Bearer token;X-API-Key: key\" https://httpbin.org/headers\n";
    cout << "  " << program_name << " --headers-only https://httpbin.org/get\n";
#if !NATIVE_HTTP_WEBSOCKET_MINIMAL
    cout << "  " << program_name << " --ws wss://echo.websocket.org --ws-message \"Hello\" --ws-listen\n";
#endif
}

// Enhanced WebSocket handler (keeps the timestamp/hex-dump helpers)
#if !NATIVE_HTTP_WEBSOCKET_MINIMAL
class EnhancedWebSocketHandler : public nativeHTTP::Client::WebSocket::EventHandler {
private:
    std::ostream* output;
    bool verbose;
    bool show_timestamps;

    std::mutex mu;
    std::condition_variable cv;
    std::string last_message;
    bool got_message = false;
    bool closed = false;

public:
    EnhancedWebSocketHandler(std::ostream* out = &std::cout, bool verb = false, bool ts = false)
        : output(out), verbose(verb), show_timestamps(ts) {}

    void on_open(nativeHTTP::Client::WebSocket* ws) override {
        (void)ws;
        std::string timestamp = show_timestamps ? get_timestamp() + " " : "";
        if (output) *output << timestamp << " WebSocket connected to: " << ws->get_url() << "\n";
    }

    void on_message(nativeHTTP::Client::WebSocket* ws, const std::string& message) override {
        (void)ws;
        std::string timestamp = show_timestamps ? get_timestamp() + " " : "";
        if (output) *output << timestamp << " " << message << "\n";
        if (verbose) {
            if (output) *output << timestamp << "   Message size: " << message.size() << " bytes\n";
        }
        {
            std::lock_guard<std::mutex> lk(mu);
            last_message = message;
            got_message = true;
        }
        cv.notify_one();
    }

    void on_binary(nativeHTTP::Client::WebSocket* ws, const std::vector<uint8_t>& data) override {
        (void)ws;
        std::string timestamp = show_timestamps ? get_timestamp() + " " : "";
        if (output) *output << timestamp << " Binary data: " << data.size() << " bytes\n";
        if (verbose && data.size() <= 1024) {
            if (output) *output << hex_dump(data) << "\n";
        }
    }

    void on_error(nativeHTTP::Client::WebSocket* ws, const std::string& error) override {
        (void)ws;
        std::string timestamp = show_timestamps ? get_timestamp() + " " : "";
        if (output) *output << timestamp << " Error: " << error << "\n";
    }

    void on_close(nativeHTTP::Client::WebSocket* ws, uint16_t code, const std::string& reason) override {
        (void)ws;
        std::string timestamp = show_timestamps ? get_timestamp() + " " : "";
        if (output) {
            *output << timestamp << " Connection closed: " << code;
            if (!reason.empty()) *output << " - " << reason;
            *output << "\n";
        }
        {
            std::lock_guard<std::mutex> lk(mu);
            closed = true;
        }
        cv.notify_one();
    }

    void on_ping(nativeHTTP::Client::WebSocket* ws, const std::vector<uint8_t>& data) override {
        (void)ws;
        if (verbose) {
            std::string timestamp = show_timestamps ? get_timestamp() + " " : "";
            if (output) *output << timestamp << " Ping received (" << data.size() << " bytes)\n";
        }
    }

    void on_pong(nativeHTTP::Client::WebSocket* ws, const std::vector<uint8_t>& data) override {
        (void)ws;
        if (verbose) {
            std::string timestamp = show_timestamps ? get_timestamp() + " " : "";
            if (output) *output << timestamp << " Pong received (" << data.size() << " bytes)\n";
        }
    }

    // wait for a message with timeout in milliseconds
    bool wait_for_message(int timeout_ms, std::string& out_msg) {
        std::unique_lock<std::mutex> lk(mu);
        if (got_message) { out_msg = last_message; return true; }
        if (cv.wait_for(lk, std::chrono::milliseconds(timeout_ms), [this](){ return got_message || closed; })) {
            if (got_message) { out_msg = last_message; return true; }
        }
        return false;
    }

    bool is_closed() {
        std::lock_guard<std::mutex> lk(mu);
        return closed;
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
               << (static_cast<int>(data[i]) & 0xff) << " ";
        }
        return ss.str();
    }
};
#endif

// Progress callback for file transfers
bool progress_callback(size_t downloaded, size_t total, size_t uploaded, size_t upload_total) {
    (void)uploaded; (void)upload_total;
    static auto start_time = std::chrono::steady_clock::now();

    if (total > 0) {
        int percent = static_cast<int>((downloaded * 100) / total);
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();

        if (elapsed > 0) {
            double speed = downloaded / (double)elapsed / 1024.0;
            std::cout << "\rProgress: " << percent << "% (" << downloaded << "/" << total
                      << ") Speed: " << std::fixed << std::setprecision(1) << speed << " KB/s";
            std::cout.flush();
        }
    }

    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        show_usage(argv[0]);
        return 1;
    }

    // Collect arguments
    std::vector<std::string> args(argv + 1, argv + argc);

    // Core vars (many options kept as in your original)
    std::string url;
    std::string method = "GET";
    std::vector<std::string> headers;
    std::vector<std::pair<std::string, std::string>> form_data;
    std::vector<std::tuple<std::string, std::string, std::string, std::string>> form_files; // key,file,filename,content_type
    std::string data;
    std::string output_file;
    std::string header_file;
    std::string proxy;
    std::string cookie_data;
    std::string cookie_jar_file;
    std::string content_type; // for file uploads
    bool include_headers = false;
    bool headers_only = false;
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
    bool junk_session_cookies = false;
    bool output_headers_to_file = false;

    // WebSocket-specific parsed options (collect during main parse)
    std::string ws_message;
    bool ws_listen = false;
    int ws_ping_interval = 0;
    bool ws_send_binary = false;
    std::string ws_binary_file;

    // Parse all arguments (single pass)
    for (size_t i = 0; i < args.size(); ++i) {
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
            if (i + 1 < args.size()) {
                std::string header_line = args[++i];
                auto multiple_headers = nativeHTTP::utils::split_headers(header_line);
                headers.insert(headers.end(), multiple_headers.begin(), multiple_headers.end());
            }
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
                    if (!value.empty() && value[0] == '@') {
                        std::string filepath = value.substr(1);
                        form_files.emplace_back(key, filepath, "", content_type);
                        content_type.clear();
                    } else {
                        form_data.emplace_back(key, value);
                    }
                }
            }
        }
        else if (arg == "-c" || arg == "--content-type") {
            if (i + 1 < args.size()) content_type = args[++i];
        }
        else if (arg == "-o" || arg == "--output") {
            if (i + 1 < args.size()) output_file = args[++i];
        }
        else if (arg == "-i" || arg == "--include") {
            include_headers = true;
        }
        else if (arg == "--headers-only") {
            headers_only = true;
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
            // consume next token as websocket URL
            if (i + 1 < args.size()) {
                url = args[++i];
                is_websocket = true;
            } else {
                std::cerr << "Error: --ws requires a URL argument\n";
                return 1;
            }
        }
        else if (arg == "--ws-message") {
            if (i + 1 < args.size()) ws_message = args[++i];
            else { std::cerr << "Error: --ws-message requires a message argument\n"; return 1; }
        }
        else if (arg == "--ws-listen") {
            ws_listen = true;
        }
        else if (arg == "--ws-ping") {
            if (i + 1 < args.size()) ws_ping_interval = std::stoi(args[++i]);
        }
        else if (arg == "--ws-binary") {
            if (i + 1 < args.size()) {
                ws_send_binary = true;
                ws_binary_file = args[++i];
            }
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
        else if (arg == "--junk-session-cookies") {
            junk_session_cookies = true;
        }
        else if (!arg.empty() && arg[0] != '-') {
            // only set positional url if not already set via --ws
            if (url.empty()) url = arg;
        }
    }

    if (show_help) {
        show_usage(argv[0]);
        return 0;
    }

    if (show_version) {
        std::cout << "nativeHTTP CLI v3.0.0\n";
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

    if (verbose) {
        std::cout << "DEBUG: final url variable = '" << url << "'\n";
    }

    try {
        // Setup output
        std::ostream* output = &std::cout;
        std::ofstream file_output;
        if (!output_file.empty()) {
            file_output.open(output_file, std::ios::binary);
            if (file_output.is_open()) output = &file_output;
            else { std::cerr << "Error: Cannot open output file: " << output_file << "\n"; return 1; }
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
            EnhancedWebSocketHandler handler(output, verbose, true);

            auto ws = client.create_websocket(url, headers);
            if (!ws) {
                std::cerr << "Error: Failed to create WebSocket object\n";
                return 1;
            }
            ws->set_event_handler(&handler);

            if (!ws->connect()) {
                *output << " Failed to connect to WebSocket\n";
                return 1;
            }

            if (!silent) *output << " WebSocket connected successfully!\n";

            // Send optional binary payload if requested
            if (ws_send_binary && !ws_binary_file.empty()) {
                std::ifstream ifs(ws_binary_file, std::ios::binary);
                if (ifs) {
                    std::vector<uint8_t> data((std::istreambuf_iterator<char>(ifs)),
                                               std::istreambuf_iterator<char>());
                    ws->send_binary(data);
                }
            }

            // If --ws-message was provided, send it
            if (!ws_message.empty()) {
                if (!silent) *output << " Sending message: " << ws_message << "\n";
                ws->send(ws_message);

                // Wait for an echo reply. Use a reasonable timeout (5s).
                std::string reply;
                bool got = handler.wait_for_message(5000, reply);

                if (got) {
                    if (!silent) *output << " Received reply: " << reply << "\n";
                } else {
                    if (!silent) *output << " No reply within timeout\n";
                }
            }

            // If user requested ping interval, spawn a ping thread (non-owning pointer capture)
            if (ws_ping_interval > 0) {
                auto ws_ptr = ws.get();
                std::thread ping_thread([ws_ptr, ws_ping_interval]() {
                    while (ws_ptr && ws_ptr->is_connected()) {
                        std::this_thread::sleep_for(std::chrono::seconds(ws_ping_interval));
                        ws_ptr->ping();
                    }
                });
                ping_thread.detach();
            }

            // Listen mode: keep process alive and print messages as they come
            if (ws_listen) {
                if (!silent) *output << "🎧 Listening for messages (Ctrl+C to exit)...\n";
                while (ws->is_connected() && !handler.is_closed()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
                // When loop breaks, close gracefully
                ws->close(1000, "CLI listen exiting");
            } else {
                // Not in listen mode: after sending message+wait (if used), close and exit
                ws->close(1000, "CLI completed");
            }

            return 0;
        }
#endif
        {
            // Enhanced HTTP mode with multipart support
            nativeHTTP::Client::Response response;
            nativeHTTP::Client::ProgressCallback progress_cb = nullptr;

            if (show_progress) progress_cb = progress_callback;

            if (method == "GET") {
                response = client.get(url, headers, progress_cb);
            } else if (method == "POST") {
                if (!form_data.empty() || !form_files.empty()) {
                    nativeHTTP::MultipartFormData form;
                    for (const auto& field : form_data) {
                        form.add_text(field.first, field.second);
                    }
                    for (const auto& file : form_files) {
                        const auto& key = std::get<0>(file);
                        const auto& filepath = std::get<1>(file);
                        const auto& filename = std::get<2>(file);
                        const auto& ctype = std::get<3>(file);
                        if (ctype == "auto" || ctype.empty()) form.add_file(key, filepath, filename);
                        else form.add_file(key, filepath, filename, ctype);
                    }
                    response = client.post_form(url, form, headers, progress_cb);
                } else if (!data.empty()) {
                    response = client.post_json(url, data, headers, progress_cb);
                } else {
                    response = client.post(url, {}, headers, progress_cb);
                }
            } else if (method == "PUT") {
                std::vector<uint8_t> put_data(data.begin(), data.end());
                response = client.put(url, put_data, headers, progress_cb);
            } else if (method == "DELETE") {
                response = client.delete_(url, headers, progress_cb);
            } else if (method == "HEAD") {
                response = client.head(url, headers);
            } else if (method == "PATCH") {
                std::vector<uint8_t> patch_data(data.begin(), data.end());
                response = client.patch(url, patch_data, headers, progress_cb);
            } else if (method == "OPTIONS") {
                response = client.options(url, headers);
            } else {
                *output << " Unsupported method: " << method << "\n";
                return 1;
            }

            // Output handling: headers-only support preserved
            if (headers_only) {
                *output << response.get_headers_string();
            } else {
                if (include_headers) *output << response.get_headers_string();
                if (!response.body.empty()) {
                    output->write(reinterpret_cast<const char*>(response.body.data()), response.body.size());
                }
            }

            if (!silent && !headers_only) {
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
                    if (!response.error_message.empty()) *output << "Error: " << response.error_message << "\n";
                    if (response.redirect()) *output << "Redirect: " << response.get_header("Location") << "\n";
                } else {
                    *output << "\n";
                }
            }

            // Save cookies if requested
            if (!cookie_jar_file.empty()) {
                client.get_cookie_jar().save_to_file(cookie_jar_file);
                if (!silent) std::cout << "Cookies saved to: " << cookie_jar_file << "\n";
            }

            if (response.success()) return 0;
            else return response.status_code > 0 ? response.status_code / 100 : 1;
        }

    } catch (const std::exception& e) {
        std::cerr << " Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
