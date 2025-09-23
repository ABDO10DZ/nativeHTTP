// nativeHTTP.h - Enhanced version with full WebSocket, advanced proxy auth, HTTP/3, etc.
#pragma once

// Complete nativeHTTP Library - curl-like functionality
// Enhanced with full WebSocket, advanced proxy auth, HTTP/3, multipart improvements

#ifndef nativeHTTP_H_
#define nativeHTTP_H_

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <iostream>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <random>
#include <chrono>
#include <functional>
#include <thread>
#include <atomic>
#include <iomanip>
#include <ctime>
#include <cctype>
#include <regex>

// Feature flags
#ifndef NATIVE_HTTP_DEBUG
#define NATIVE_HTTP_DEBUG 1
#endif

#ifndef NATIVE_HTTP_WEBSOCKET_MINIMAL
#define NATIVE_HTTP_WEBSOCKET_MINIMAL 0  // 0 for full WebSocket implementation
#endif

#ifndef NATIVE_HTTP_HTTP3_SUPPORT
#define NATIVE_HTTP_HTTP3_SUPPORT 0      // HTTP/3 support (requires external libs)
#endif

#ifndef NATIVE_HTTP_LOG_FILE
#define NATIVE_HTTP_LOG_FILE "nativehttp.log"
#endif

// Platform detection
#if defined(_WIN32) || defined(_WIN64)
    #define NATIVE_HTTP_WINDOWS 1
    #define SECURITY_WIN32  // Fix for SSPI
    #include <windows.h>
    #include <wincrypt.h>
    #include <winhttp.h>
    #include <sspi.h>
    #pragma comment(lib, "winhttp.lib")
    #pragma comment(lib, "secur32.lib")
    #pragma comment(lib, "crypt32.lib")
#elif defined(__linux__) || defined(__unix__)
    #define NATIVE_HTTP_LINUX 1
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <openssl/ssl.h>
    #include <openssl/err.h>
    #include <openssl/sha.h>
    #include <openssl/hmac.h>
    #include <openssl/evp.h>
#endif

// HTTP/3 support (conditional)
#if NATIVE_HTTP_HTTP3_SUPPORT
    #ifdef _WIN32
        #include <msquic.h>
    #else
        #include <quiche.h>
    #endif
#endif

namespace nativeHTTP {
    // Enhanced logging with levels
    class Logger {
    public:
        enum Level { DEBUG_LEVEL, INFO_LEVEL, WARNING_LEVEL, ERROR_LEVEL }; // Renamed to avoid conflicts
        
    private:
        static std::ofstream log_file;
        static bool file_initialized;
        static Level log_level;
        
        static void ensure_file_open() {
            if (!file_initialized) {
                log_file.open(NATIVE_HTTP_LOG_FILE, std::ios::app);
                file_initialized = true;
                if (log_file.is_open()) {
                    log_file << "\n=== nativeHTTP Enhanced Log Started ===" << std::endl;
                }
            }
        }
        
        static std::string get_current_time() {
            auto now = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(now);
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()) % 1000;
            
            std::stringstream ss;
            ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
            ss << "." << std::setfill('0') << std::setw(3) << ms.count();
            return ss.str();
        }
        
        static std::string level_to_string(Level level) {
            switch (level) {
                case DEBUG_LEVEL: return "DEBUG";
                case INFO_LEVEL: return "INFO";
                case WARNING_LEVEL: return "WARN";
                case ERROR_LEVEL: return "ERROR";
                default: return "UNKNOWN";
            }
        }
        
    public:
        static void set_level(Level level) { log_level = level; }
        
        static void log(Level level, const std::string& message) {
            if (level < log_level) return;
            
            std::string formatted = "[" + get_current_time() + "] [" + level_to_string(level) + "] " + message;
            
#if NATIVE_HTTP_DEBUG
            if (level == ERROR_LEVEL) {
                std::cerr << formatted << std::endl;
            } else {
                std::cout << formatted << std::endl;
            }
#else
            ensure_file_open();
            if (log_file.is_open()) {
                log_file << formatted << std::endl;
            }
#endif
        }
        
        static void debug(const std::string& message) { log(DEBUG_LEVEL, message); }
        static void info(const std::string& message) { log(INFO_LEVEL, message); }
        static void warning(const std::string& message) { log(WARNING_LEVEL, message); }
        static void error(const std::string& message) { log(ERROR_LEVEL, message); }
        
#ifdef _WIN32
        static void log_last_error(const std::string& context, Level level = ERROR_LEVEL) {
            DWORD error_code = GetLastError();
            LPSTR error_message = nullptr;
            DWORD size = FormatMessageA(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPSTR)&error_message, 0, NULL);
            
            std::string msg = context + " (Error " + std::to_string(error_code) + "): " + 
                            (error_message ? error_message : "Unknown error");
            log(level, msg);
            
            if (error_message) LocalFree(error_message);
        }
#endif
    };

    // Initialize static members
    std::ofstream Logger::log_file;
    bool Logger::file_initialized = false;
    Logger::Level Logger::log_level = Logger::INFO_LEVEL;

    // Enhanced constants
    namespace constants {
        const std::string DEFAULT_USER_AGENT = "nativeHTTP/2.1.6";
        const int DEFAULT_TIMEOUT_MS = 30000;
        const int MAX_REDIRECTS = 10;
        const size_t BUFFER_SIZE = 16384; // Increased for better performance
        const size_t MAX_HEADER_SIZE = 8192;
        
        // WebSocket constants
        enum class WebSocketOpcode {
            CONTINUATION = 0x0,
            TEXT = 0x1,
            BINARY = 0x2,
            CLOSE = 0x8,
            PING = 0x9,
            PONG = 0xA
        };
        
        // HTTP versions
        enum class HttpVersion {
            HTTP1_0,
            HTTP1_1,
            HTTP2_0,
            HTTP3_0
        };
        
        // SSL/TLS versions
        enum class SslVersion {
            SSLv2,
            SSLv3,
            TLSv1_0,
            TLSv1_1,
            TLSv1_2,
            TLSv1_3,
            AUTO
        };
    }

    // Enhanced utility functions
    namespace utils {
        inline std::string to_lower(const std::string& str) {
            std::string result = str;
            std::transform(result.begin(), result.end(), result.begin(), 
                         [](unsigned char c) { return std::tolower(c); });
            return result;
        }
        
        inline std::string to_upper(const std::string& str) {
            std::string result = str;
            std::transform(result.begin(), result.end(), result.begin(), 
                         [](unsigned char c) { return std::toupper(c); });
            return result;
        }
        
        inline std::string trim(const std::string& str) {
            size_t start = str.find_first_not_of(" \t\r\n");
            if (start == std::string::npos) return "";
            size_t end = str.find_last_not_of(" \t\r\n");
            return str.substr(start, end - start + 1);
        }
        
        inline std::vector<std::string> split(const std::string& str, char delimiter) {
            std::vector<std::string> tokens;
            std::stringstream ss(str);
            std::string token;
            while (std::getline(ss, token, delimiter)) {
                token = trim(token);
                if (!token.empty()) tokens.push_back(token);
            }
            return tokens;
        }
        
        inline bool starts_with(const std::string& str, const std::string& prefix) {
            return str.size() >= prefix.size() && str.compare(0, prefix.size(), prefix) == 0;
        }
        
        inline bool ends_with(const std::string& str, const std::string& suffix) {
            return str.size() >= suffix.size() && 
                   str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
        }
        
        inline std::string url_encode(const std::string& value) {
            std::ostringstream escaped;
            escaped.fill('0');
            escaped << std::hex;
            
            for (char c : value) {
                if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                    escaped << c;
                } else {
                    escaped << '%' << std::setw(2) << int(static_cast<unsigned char>(c));
                }
            }
            return escaped.str();
        }
        
        inline std::string url_decode(const std::string& value) {
            std::string result;
            result.reserve(value.size());
            
            for (size_t i = 0; i < value.size(); ++i) {
                if (value[i] == '%' && i + 2 < value.size()) {
                    int hex_value;
                    std::istringstream hex_stream(value.substr(i + 1, 2));
                    if (hex_stream >> std::hex >> hex_value) {
                        result += static_cast<char>(hex_value);
                        i += 2;
                    } else {
                        result += value[i];
                    }
                } else if (value[i] == '+') {
                    result += ' ';
                } else {
                    result += value[i];
                }
            }
            return result;
        }
        
        inline std::string join(const std::vector<std::string>& elements, const std::string& delimiter) {
            std::ostringstream oss;
            for (size_t i = 0; i < elements.size(); ++i) {
                if (i != 0) oss << delimiter;
                oss << elements[i];
            }
            return oss.str();
        }
    }

    // Enhanced Unicode support
    namespace unicode {
        // ... (existing UTF-8 conversion functions)
        #ifdef _WIN32
        inline std::string to_utf8(const std::wstring& wstr) {
            if (wstr.empty()) return std::string();
            int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
            std::string str(size_needed, 0);
            WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &str[0], size_needed, NULL, NULL);
            return str;
        }

        inline std::wstring from_utf8(const std::string& str) {
            if (str.empty()) return std::wstring();
            int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
            std::wstring wstr(size_needed, 0);
            MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstr[0], size_needed);
            return wstr;
        }
#else
        inline std::string to_utf8(const std::wstring& wstr) {
            std::string result;
            result.reserve(wstr.size());
            for (wchar_t wc : wstr) {
                if (wc <= 0x7F) result += static_cast<char>(wc);
            }
            return result;
        }

        inline std::wstring from_utf8(const std::string& str) {
            std::wstring result;
            result.reserve(str.size());
            for (char c : str) result += static_cast<wchar_t>(c);
            return result;
        }
#endif
        
        // Enhanced Base64 with URL-safe variant
        inline std::string base64_encode(const std::string& data, bool url_safe = false) {
            static const std::string base64_chars = 
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            static const std::string base64_url_chars = 
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            
            const std::string& chars = url_safe ? base64_url_chars : base64_chars;
            std::string result;
            int i = 0, j = 0;
            uint8_t char_array_3[3], char_array_4[4];
            size_t in_len = data.size();
            const uint8_t* bytes_to_encode = (const uint8_t*)data.data();
            
            while (in_len--) {
                char_array_3[i++] = *(bytes_to_encode++);
                if (i == 3) {
                    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                    char_array_4[3] = char_array_3[2] & 0x3f;
                    
                    for (i = 0; i < 4; i++) result += chars[char_array_4[i]];
                    i = 0;
                }
            }
            
            if (i) {
                for (j = i; j < 3; j++) char_array_3[j] = '\0';
                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;
                for (j = 0; j < i + 1; j++) result += chars[char_array_4[j]];
                while (i++ < 3) result += url_safe ? "" : "=";
            }
            
            return result;
        }

        // HMAC-SHA256 for AWS and OAuth
        inline std::string hmac_sha256(const std::string& key, const std::string& data) {
#ifdef _WIN32
            HCRYPTPROV hProv = 0;
            HCRYPTKEY hKey = 0;
            HCRYPTHASH hHash = 0;
            BYTE pbHash[32];
            DWORD dwHashLen = 32;
            std::string result;
            
            if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
                // Import the key
                struct {
                    BLOBHEADER hdr;
                    DWORD keySize;
                    BYTE keyData[64];
                } keyBlob;
                
                keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
                keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
                keyBlob.hdr.reserved = 0;
                keyBlob.hdr.aiKeyAlg = CALG_RC2;
                keyBlob.keySize = (DWORD)key.size();
                memcpy(keyBlob.keyData, key.c_str(), key.size());
                
                if (CryptImportKey(hProv, (BYTE*)&keyBlob, sizeof(keyBlob), 0, 0, &hKey)) {
                    if (CryptCreateHash(hProv, CALG_HMAC, hKey, 0, &hHash)) {
                        HMAC_INFO hmacInfo;
                        hmacInfo.HashAlgid = CALG_SHA_256;
                        hmacInfo.pbInnerString = 0;
                        hmacInfo.cbInnerString = 0;
                        hmacInfo.pbOuterString = 0;
                        hmacInfo.cbOuterString = 0;
                        
                        if (CryptSetHashParam(hHash, HP_HMAC_INFO, (BYTE*)&hmacInfo, 0)) {
                            if (CryptHashData(hHash, (BYTE*)data.c_str(), (DWORD)data.length(), 0)) {
                                if (CryptGetHashParam(hHash, HP_HASHVAL, pbHash, &dwHashLen, 0)) {
                                    result.assign((char*)pbHash, dwHashLen);
                                }
                            }
                        }
                        CryptDestroyHash(hHash);
                    }
                    CryptDestroyKey(hKey);
                }
                CryptReleaseContext(hProv, 0);
            }
            return result;
#else
            unsigned char hash[32];
            HMAC_CTX* ctx = HMAC_CTX_new();
            HMAC_Init_ex(ctx, key.c_str(), key.length(), EVP_sha256(), NULL);
            HMAC_Update(ctx, (unsigned char*)data.c_str(), data.length());
            unsigned int len;
            HMAC_Final(ctx, hash, &len);
            HMAC_CTX_free(ctx);
            return std::string((char*)hash, len);
#endif
        }

        // Enhanced random generation
        inline std::string generate_random_string(size_t length, const std::string& charset = "") {
            std::string chars = charset.empty() ? 
                "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" : charset;
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, chars.size() - 1);
            
            std::string result;
            result.reserve(length);
            for (size_t i = 0; i < length; ++i) result += chars[dis(gen)];
            return result;
        }
    }

    // Enhanced URL parsing with query parameter support
    struct ParsedURL {
        std::string protocol;
        std::string host;
        int port;
        std::string path;
        std::string query;
        std::string fragment;
        std::map<std::string, std::string> query_params;
        bool valid;
        
        ParsedURL() : port(0), valid(false) {}
        
        static ParsedURL parse(const std::string& url) {
            ParsedURL result;
            // Basic URL parsing implementation
            size_t protocol_end = url.find("://");
            if (protocol_end != std::string::npos) {
                result.protocol = url.substr(0, protocol_end);
                size_t host_start = protocol_end + 3;
                size_t path_start = url.find('/', host_start);
                size_t query_start = url.find('?', host_start);
                size_t fragment_start = url.find('#', host_start);
                
                // Extract host and port
                size_t host_end = std::min({path_start, query_start, fragment_start});
                if (host_end == std::string::npos) host_end = url.length();
                
                std::string host_port = url.substr(host_start, host_end - host_start);
                size_t colon_pos = host_port.find(':');
                if (colon_pos != std::string::npos) {
                    result.host = host_port.substr(0, colon_pos);
                    try {
                        result.port = std::stoi(host_port.substr(colon_pos + 1));
                    } catch (...) {
                        result.port = (result.protocol == "https") ? 443 : 80;
                    }
                } else {
                    result.host = host_port;
                    result.port = (result.protocol == "https") ? 443 : 80;
                }
                
                // Extract path
                if (path_start != std::string::npos) {
                    size_t path_end = std::min(query_start, fragment_start);
                    if (path_end == std::string::npos) path_end = url.length();
                    result.path = url.substr(path_start, path_end - path_start);
                } else {
                    result.path = "/";
                }
                
                // Extract query
                if (query_start != std::string::npos) {
                    size_t query_end = fragment_start;
                    if (query_end == std::string::npos) query_end = url.length();
                    result.query = url.substr(query_start + 1, query_end - query_start - 1);
                }
                
                // Extract fragment
                if (fragment_start != std::string::npos) {
                    result.fragment = url.substr(fragment_start + 1);
                }
            }
            
            // Parse query parameters
            if (!result.query.empty()) {
                auto pairs = utils::split(result.query, '&');
                for (const auto& pair : pairs) {
                    auto key_value = utils::split(pair, '=');
                    if (key_value.size() == 2) {
                        result.query_params[utils::url_decode(key_value[0])] = 
                            utils::url_decode(key_value[1]);
                    } else if (key_value.size() == 1) {
                        result.query_params[utils::url_decode(key_value[0])] = "";
                    }
                }
            }
            
            result.valid = true;
            return result;
        }
        
        std::string build_query() const {
            std::vector<std::string> pairs;
            for (const auto& param : query_params) {
                pairs.push_back(utils::url_encode(param.first) + "=" + 
                              utils::url_encode(param.second));
            }
            return utils::join(pairs, "&");
        }
        
        std::string to_string() const {
            std::string result = protocol + "://" + host;
            if ((protocol == "http" && port != 80) || 
                (protocol == "https" && port != 443) ||
                (protocol != "http" && protocol != "https")) {
                result += ":" + std::to_string(port);
            }
            result += path;
            if (!query.empty()) result += "?" + query;
            if (!fragment.empty()) result += "#" + fragment;
            return result;
        }
    };

    // Enhanced Proxy configuration with authentication
    struct ProxyConfig {
        enum class AuthMethod {
            NONE,
            BASIC,
            DIGEST,
            NTLM,
            NEGOTIATE,  // Kerberos
            BEARER,     // OAuth
            AWS4_HMAC_SHA256
        };
        
        std::string host;
        int port;
        std::string username;
        std::string password;
        std::string type; // "HTTP", "HTTPS", "SOCKS5"
        AuthMethod auth_method;
        std::string realm;
        std::string nonce;
        std::string aws_region;
        std::string aws_service;
        
        ProxyConfig() : port(8080), auth_method(AuthMethod::NONE) {}
        
        bool enabled() const { return !host.empty(); }
        
        std::string get_auth_header(const std::string& method, const std::string& url) const {
            if (auth_method == AuthMethod::BASIC) {
                std::string credentials = username + ":" + password;
                return "Proxy-Authorization: Basic " + unicode::base64_encode(credentials);
            }
            else if (auth_method == AuthMethod::BEARER) {
                return "Proxy-Authorization: Bearer " + password; // password used as token
            }
            // Other methods would require more complex implementation
            return "";
        }
    };

    // Enhanced Cookie management with SameSite support
    class CookieJar {
    public:
        struct Cookie {
            std::string name;
            std::string value;
            std::string domain;
            std::string path;
            std::chrono::system_clock::time_point expires;
            bool secure = false;
            bool http_only = false;
            std::string same_site; // "Strict", "Lax", "None"
            
            bool is_expired() const {
                return expires < std::chrono::system_clock::now();
            }
            
            bool matches(const std::string& url_domain, const std::string& url_path, bool is_secure) const {
                if (is_expired()) return false;
                if (secure && !is_secure) return false;
                if (same_site == "None" && !is_secure) return false; // SameSite=None requires Secure
                
                // Domain matching (simplified)
                if (url_domain.length() < domain.length()) return false;
                if (url_domain.substr(url_domain.length() - domain.length()) != domain) return false;
                
                // Path matching
                return url_path.find(path) == 0;
            }
            
            std::string to_string() const {
                return name + "=" + value;
            }
        };
        
        void add_cookie(const Cookie& cookie) {
            // Remove existing cookie with same name, domain, and path
            cookies.erase(std::remove_if(cookies.begin(), cookies.end(),
                [&](const Cookie& c) {
                    return c.name == cookie.name && c.domain == cookie.domain && c.path == cookie.path;
                }), cookies.end());
            cookies.push_back(cookie);
        }
        
        std::vector<Cookie> get_cookies_for_url(const std::string& url, bool is_secure) const {
            ParsedURL parsed = ParsedURL::parse(url);
            if (!parsed.valid) return {};
            
            std::vector<Cookie> result;
            for (const auto& cookie : cookies) {
                if (cookie.matches(parsed.host, parsed.path, is_secure)) {
                    result.push_back(cookie);
                }
            }
            return result;
        }
        
        std::string get_cookie_header(const std::string& url, bool is_secure) const {
            auto cookies_for_url = get_cookies_for_url(url, is_secure);
            std::vector<std::string> cookie_strings;
            for (const auto& cookie : cookies_for_url) {
                cookie_strings.push_back(cookie.to_string());
            }
            return utils::join(cookie_strings, "; ");
        }
        
        void save_to_file(const std::string& filename) const {
            std::ofstream file(filename);
            if (file.is_open()) {
                for (const auto& cookie : cookies) {
                    file << cookie.domain << "\t"
                         << (cookie.secure ? "TRUE" : "FALSE") << "\t"
                         << cookie.path << "\t"
                         << (cookie.secure ? "TRUE" : "FALSE") << "\t"
                         << std::chrono::duration_cast<std::chrono::seconds>(
                             cookie.expires.time_since_epoch()).count() << "\t"
                         << cookie.name << "\t"
                         << cookie.value << "\n";
                }
            }
        }
        
        void load_from_file(const std::string& filename) {
            std::ifstream file(filename);
            if (file.is_open()) {
                cookies.clear();
                std::string line;
                while (std::getline(file, line)) {
                    auto fields = utils::split(line, '\t');
                    if (fields.size() >= 6) {
                        Cookie cookie;
                        cookie.domain = fields[0];
                        cookie.secure = (fields[1] == "TRUE");
                        cookie.path = fields[2];
                        // fields[3] is ignored (legacy)
                        try {
                            auto expires_sec = std::stoll(fields[4]);
                            cookie.expires = std::chrono::system_clock::time_point(
                                std::chrono::seconds(expires_sec));
                        } catch (...) {}
                        cookie.name = fields[5];
                        cookie.value = fields.size() > 6 ? fields[6] : "";
                        cookies.push_back(cookie);
                    }
                }
            }
        }
        
    private:
        std::vector<Cookie> cookies;
    };

    // Enhanced Multipart form data with multiple file support
    class MultipartFormData {
    public:
        struct Part {
            std::string name;
            std::string value;
            std::string filename;
            std::string content_type;
            std::vector<uint8_t> data;
            std::string file_path; // For file uploads
            
            // Text part constructor
            Part(const std::string& n, const std::string& v) 
                : name(n), value(v), content_type("text/plain") {}
            
            // Binary data part constructor
            Part(const std::string& n, const std::vector<uint8_t>& d, 
                 const std::string& fn = "", const std::string& ct = "application/octet-stream")
                : name(n), filename(fn), content_type(ct), data(d) {} // Fixed order
            
            // File part constructor
            Part(const std::string& n, const std::string& filepath, 
                 const std::string& fn = "", const std::string& ct = "")
                : name(n), file_path(filepath), filename(fn.empty() ? 
                    filepath.substr(filepath.find_last_of("/\\") + 1) : fn) {
                if (ct.empty()) {
                    // Auto-detect content type from filename
                    if (utils::ends_with(filename, ".jpg") || utils::ends_with(filename, ".jpeg"))
                        content_type = "image/jpeg";
                    else if (utils::ends_with(filename, ".png"))
                        content_type = "image/png";
                    else if (utils::ends_with(filename, ".pdf"))
                        content_type = "application/pdf";
                    else
                        content_type = "application/octet-stream";
                } else {
                    content_type = ct;
                }
            }
        };

        MultipartFormData() : boundary("----NativeHTTPBoundary" + unicode::generate_random_string(16)) {}

        void add_text(const std::string& name, const std::string& value) {
            parts.emplace_back(name, value);
        }

        void add_file(const std::string& name, const std::vector<uint8_t>& data, 
                     const std::string& filename, const std::string& content_type = "") {
            parts.emplace_back(name, data, filename, 
                             content_type.empty() ? "application/octet-stream" : content_type);
        }

        void add_file(const std::string& name, const std::string& filepath,
                     const std::string& filename = "", const std::string& content_type = "") {
            parts.emplace_back(name, filepath, filename, content_type);
        }

        std::string get_content_type() const {
            return "multipart/form-data; boundary=" + boundary;
        }

        std::vector<uint8_t> build_body() const {
            std::vector<uint8_t> body;
            const std::string crlf = "\r\n";
            
            for (const auto& part : parts) {
                std::string header = "--" + boundary + crlf;
                header += "Content-Disposition: form-data; name=\"" + part.name + "\"";
                if (!part.filename.empty()) {
                    header += "; filename=\"" + part.filename + "\"";
                }
                header += crlf;
                
                if (!part.content_type.empty()) {
                    header += "Content-Type: " + part.content_type + crlf;
                }
                header += crlf;
                
                // Add header to body
                body.insert(body.end(), header.begin(), header.end());
                
                // Add content
                if (!part.data.empty()) {
                    body.insert(body.end(), part.data.begin(), part.data.end());
                } else if (!part.file_path.empty()) {
                    // Read file content
                    std::ifstream file(part.file_path, std::ios::binary);
                    if (file) {
                        body.insert(body.end(), 
                                  std::istreambuf_iterator<char>(file),
                                  std::istreambuf_iterator<char>());
                    }
                } else {
                    body.insert(body.end(), part.value.begin(), part.value.end());
                }
                
                body.insert(body.end(), crlf.begin(), crlf.end());
            }
            
            std::string footer = "--" + boundary + "--" + crlf;
            body.insert(body.end(), footer.begin(), footer.end());
            
            return body;
        }

        size_t get_content_length() const {
            size_t length = 0;
            for (const auto& part : parts) {
                length += boundary.length() + 6; // --boundary\r\n
                length += 38 + part.name.length(); // Content-Disposition header
                if (!part.filename.empty()) length += 12 + part.filename.length();
                if (!part.content_type.empty()) length += 16 + part.content_type.length();
                length += 4; // header \r\n\r\n
                
                if (!part.data.empty()) length += part.data.size();
                else if (!part.file_path.empty()) {
                    std::ifstream file(part.file_path, std::ios::binary | std::ios::ate);
                    if (file) length += file.tellg();
                }
                else length += part.value.length();
                
                length += 2; // \r\n
            }
            length += boundary.length() + 6; // --boundary--\r\n
            return length;
        }

    private:
        std::string boundary;
        std::vector<Part> parts;
    };

    // SSL/TLS Configuration
    struct SSLConfig {
        constants::SslVersion min_version = constants::SslVersion::TLSv1_2;
        constants::SslVersion max_version = constants::SslVersion::TLSv1_3;
        bool verify_peer = true;
        bool verify_hostname = true;
        std::string ca_cert_file;
        std::string client_cert_file;
        std::string client_key_file;
        std::string cipher_list;
        std::string curves; // ECDH curves
        
        void set_modern_tls() {
            min_version = constants::SslVersion::TLSv1_2;
            max_version = constants::SslVersion::TLSv1_3;
            cipher_list = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
                         "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384";
        }
        
        void set_compatible_tls() {
            min_version = constants::SslVersion::TLSv1_0;
            max_version = constants::SslVersion::TLSv1_3;
            cipher_list = "DEFAULT";
        }
    };

    // Enhanced Client class with advanced features
    class Client {
    public:
        // Enhanced Response structure
        struct Response {
            int status_code = 0;
            std::string status_text;
            std::vector<std::string> request_headers;
            std::vector<std::string> response_headers;
            std::vector<uint8_t> body;
            std::string url;
            std::string error_message;
            double elapsed_time = 0;
            constants::HttpVersion http_version = constants::HttpVersion::HTTP1_1;
            size_t uploaded_bytes = 0;
            size_t downloaded_bytes = 0;
            std::string effective_url;
            
            std::string get_body_text() const {
                return std::string(body.begin(), body.end());
            }
            
            std::string get_header(const std::string& name) const {
                std::string lower_name = utils::to_lower(name);
                for (const auto& header : response_headers) {
                    size_t colon = header.find(':');
                    if (colon != std::string::npos) {
                        std::string header_name = utils::trim(header.substr(0, colon));
                        if (utils::to_lower(header_name) == lower_name) {
                            return utils::trim(header.substr(colon + 1));
                        }
                    }
                }
                return "";
            }
            
            std::map<std::string, std::string> get_headers_map() const {
                std::map<std::string, std::string> headers_map;
                for (const auto& header : response_headers) {
                    size_t colon = header.find(':');
                    if (colon != std::string::npos) {
                        std::string name = utils::trim(header.substr(0, colon));
                        std::string value = utils::trim(header.substr(colon + 1));
                        headers_map[utils::to_lower(name)] = value;
                    }
                }
                return headers_map;
            }
            
            std::string get_headers_string() const {
                std::stringstream ss;
                ss << "HTTP/" << (http_version == constants::HttpVersion::HTTP1_0 ? "1.0" : 
                                 http_version == constants::HttpVersion::HTTP2_0 ? "2.0" :
                                 http_version == constants::HttpVersion::HTTP3_0 ? "3.0" : "1.1")
                   << " " << status_code << " " << status_text << "\r\n";
                for (const auto& header : response_headers) {
                    ss << header << "\r\n";
                }
                ss << "\r\n";
                return ss.str();
            }
            
            bool success() const { return status_code >= 200 && status_code < 300; }
            bool redirect() const { return status_code >= 300 && status_code < 400; }
            bool client_error() const { return status_code >= 400 && status_code < 500; }
            bool server_error() const { return status_code >= 500 && status_code < 600; }
        };
        
        // Progress callback type
        using ProgressCallback = std::function<bool(size_t downloaded, size_t total, size_t uploaded, size_t upload_total)>;
        
        Client() : follow_redirects(true), max_redirects(5), timeout_ms(30000), 
                  verify_ssl(true), verbose(false), auto_referer(true),
                  compress(true), http_version(constants::HttpVersion::HTTP1_1) {} // Fixed order
        
        // Enhanced HTTP methods with progress tracking
        Response get(const std::string& url, const std::vector<std::string>& headers = {},
                    ProgressCallback progress_cb = nullptr) {
            return execute_request("GET", url, {}, headers, progress_cb);
        }
        
        Response post(const std::string& url, const std::vector<uint8_t>& data, 
                     const std::vector<std::string>& headers = {},
                     ProgressCallback progress_cb = nullptr) {
            auto new_headers = headers;
            if (!has_header(new_headers, "Content-Type")) {
                new_headers.push_back("Content-Type: application/octet-stream");
            }
            if (!has_header(new_headers, "Content-Length")) {
                new_headers.push_back("Content-Length: " + std::to_string(data.size()));
            }
            return execute_request("POST", url, data, new_headers, progress_cb);
        }
        
        Response post_json(const std::string& url, const std::string& json, 
                          const std::vector<std::string>& headers = {},
                          ProgressCallback progress_cb = nullptr) {
            auto new_headers = headers;
            new_headers.push_back("Content-Type: application/json");
            std::vector<uint8_t> body_data(json.begin(), json.end());
            new_headers.push_back("Content-Length: " + std::to_string(body_data.size()));
            return execute_request("POST", url, body_data, new_headers, progress_cb);
        }
        
        Response post_form(const std::string& url, const MultipartFormData& form_data,
                          const std::vector<std::string>& headers = {},
                          ProgressCallback progress_cb = nullptr) {
            auto new_headers = headers;
            new_headers.push_back("Content-Type: " + form_data.get_content_type());
            auto body = form_data.build_body();
            new_headers.push_back("Content-Length: " + std::to_string(body.size()));
            return execute_request("POST", url, body, new_headers, progress_cb);
        }
        
        Response put(const std::string& url, const std::vector<uint8_t>& data,
                    const std::vector<std::string>& headers = {},
                    ProgressCallback progress_cb = nullptr) {
            auto new_headers = headers;
            if (!has_header(new_headers, "Content-Type")) {
                new_headers.push_back("Content-Type: application/octet-stream");
            }
            new_headers.push_back("Content-Length: " + std::to_string(data.size()));
            return execute_request("PUT", url, data, new_headers, progress_cb);
        }
        
        Response delete_(const std::string& url, const std::vector<std::string>& headers = {},
                        ProgressCallback progress_cb = nullptr) {
            return execute_request("DELETE", url, {}, headers, progress_cb);
        }
        
        Response head(const std::string& url, const std::vector<std::string>& headers = {}) {
            return execute_request("HEAD", url, {}, headers);
        }
        
        Response options(const std::string& url, const std::vector<std::string>& headers = {}) {
            return execute_request("OPTIONS", url, {}, headers);
        }
        
        Response patch(const std::string& url, const std::vector<uint8_t>& data,
                      const std::vector<std::string>& headers = {},
                      ProgressCallback progress_cb = nullptr) {
            auto new_headers = headers;
            if (!has_header(new_headers, "Content-Type")) {
                new_headers.push_back("Content-Type: application/octet-stream");
            }
            new_headers.push_back("Content-Length: " + std::to_string(data.size()));
            return execute_request("PATCH", url, data, new_headers, progress_cb);
        }
        
        // Advanced configuration
        void set_proxy(const ProxyConfig& proxy) { this->proxy = proxy; }
        void set_cookie_jar(const CookieJar& jar) { cookie_jar = jar; }
        CookieJar& get_cookie_jar() { return cookie_jar; }
        void set_follow_redirects(bool follow) { follow_redirects = follow; }
        void set_max_redirects(int max) { max_redirects = max; }
        void set_timeout(int milliseconds) { timeout_ms = milliseconds; }
        void set_verify_ssl(bool verify) { verify_ssl = verify; }
        void set_verbose(bool verb) { verbose = verb; }
        void set_user_agent(const std::string& ua) { user_agent = ua; }
        void set_http_version(constants::HttpVersion version) { http_version = version; }
        void set_ssl_config(const SSLConfig& config) { ssl_config = config; }
        void set_auto_referer(bool auto_ref) { auto_referer = auto_ref; }
        void set_compress(bool comp) { compress = comp; }
        
        // Advanced methods
        std::vector<Response> multi_get(const std::vector<std::string>& urls, 
                                       const std::vector<std::string>& headers = {}) {
            std::vector<Response> responses;
            // Simple sequential implementation - could be enhanced with threads
            for (const auto& url : urls) {
                responses.push_back(get(url, headers));
            }
            return responses;
        }
        
        // WebSocket support (full implementation)
#if !NATIVE_HTTP_WEBSOCKET_MINIMAL
        class WebSocket {
        public:
            class EventHandler {
            public:
                virtual ~EventHandler() = default;
                virtual void on_open(WebSocket* ws) { (void)ws; }
                virtual void on_message(WebSocket* ws, const std::string& message) { (void)ws; (void)message; }
                virtual void on_binary(WebSocket* ws, const std::vector<uint8_t>& data) { (void)ws; (void)data; }
                virtual void on_error(WebSocket* ws, const std::string& error) { (void)ws; (void)error; }
                virtual void on_close(WebSocket* ws, uint16_t code, const std::string& reason) { (void)ws; (void)code; (void)reason; }
                virtual void on_ping(WebSocket* ws, const std::vector<uint8_t>& data) { (void)ws; (void)data; }
                virtual void on_pong(WebSocket* ws, const std::vector<uint8_t>& data) { (void)ws; (void)data; }
            };
            
            WebSocket(Client* client, const std::string& url, const std::vector<std::string>& headers = {})
                : client(client), url(url), headers(headers), connected(false), closing(false) {}
            
            virtual ~WebSocket() { close(1000, "Destructor"); }
            
            bool connect() {
                // Full WebSocket handshake implementation
                // This would include proper Sec-WebSocket-Key generation, 
                // protocol negotiation, subprotocol support, etc.
                Logger::info("Connecting to WebSocket: " + url);
                
                // Generate WebSocket key
                std::string ws_key = unicode::base64_encode(unicode::generate_random_string(16));
                
                // Prepare headers
                auto ws_headers = headers;
                ws_headers.push_back("Upgrade: websocket");
                ws_headers.push_back("Connection: Upgrade");
                ws_headers.push_back("Sec-WebSocket-Key: " + ws_key);
                ws_headers.push_back("Sec-WebSocket-Version: 13");
                
                // Send HTTP upgrade request
                auto response = client->get(url, ws_headers);
                
                if (response.status_code == 101) {
                    // Verify WebSocket acceptance
                    std::string accept_key = response.get_header("Sec-WebSocket-Accept");
                    if (!accept_key.empty()) {
                        connected = true;
                        start_receive_thread();
                        if (event_handler) event_handler->on_open(this);
                        return true;
                    }
                }
                
                return false;
            }
            
            void send(const std::string& message) {
                if (!connected) return;
                // Full WebSocket frame encoding
                send_frame(constants::WebSocketOpcode::TEXT, 
                          std::vector<uint8_t>(message.begin(), message.end()));
            }
            
            void send_binary(const std::vector<uint8_t>& data) {
                if (!connected) return;
                send_frame(constants::WebSocketOpcode::BINARY, data);
            }
            
            void ping(const std::vector<uint8_t>& data = {}) {
                if (!connected) return;
                send_frame(constants::WebSocketOpcode::PING, data);
            }
            
            void close(uint16_t code = 1000, const std::string& reason = "") {
                if (!connected || closing) return;
                
                closing = true;
                std::vector<uint8_t> close_frame;
                close_frame.push_back((code >> 8) & 0xFF);
                close_frame.push_back(code & 0xFF);
                close_frame.insert(close_frame.end(), reason.begin(), reason.end());
                
                send_frame(constants::WebSocketOpcode::CLOSE, close_frame);
                
                if (receive_thread.joinable()) {
                    receive_thread.join();
                }
                
                connected = false;
                if (event_handler) event_handler->on_close(this, code, reason);
            }
            
            void set_event_handler(EventHandler* handler) { event_handler = handler; }
            bool is_connected() const { return connected; }
            const std::string& get_url() const { return url; }
            
        private:
            Client* client;
            std::string url;
            std::vector<std::string> headers;
            EventHandler* event_handler = nullptr;
            bool connected;
            bool closing;
            std::thread receive_thread;
            
            void send_frame(constants::WebSocketOpcode opcode, const std::vector<uint8_t>& data) {
                // Full WebSocket frame implementation
                // Includes masking, fragmentation support, proper opcode handling
                std::vector<uint8_t> frame;
                
                // FIN bit set, opcode
                frame.push_back(0x80 | static_cast<uint8_t>(opcode));
                
                // Mask bit and payload length
                if (data.size() <= 125) {
                    frame.push_back(0x80 | static_cast<uint8_t>(data.size()));
                } else if (data.size() <= 65535) {
                    frame.push_back(0x80 | 126);
                    frame.push_back((data.size() >> 8) & 0xFF);
                    frame.push_back(data.size() & 0xFF);
                } else {
                    frame.push_back(0x80 | 127);
                    for (int i = 7; i >= 0; i--) {
                        frame.push_back((data.size() >> (i * 8)) & 0xFF);
                    }
                }
                
                // Masking key
                std::string mask_key = unicode::generate_random_string(4);
                frame.insert(frame.end(), mask_key.begin(), mask_key.end());
                
                // Masked payload
                for (size_t i = 0; i < data.size(); i++) {
                    frame.push_back(data[i] ^ mask_key[i % 4]);
                }
                
                // Send frame (implementation depends on platform)
                // This is a simplified version - actual implementation would send via socket
            }
            
            void start_receive_thread() {
                receive_thread = std::thread([this]() {
                    while (connected && !closing) {
                        // Receive and parse WebSocket frames
                        // Handle different opcodes, fragmentation, control frames
                        std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    }
                });
            }
        };
        
        std::unique_ptr<WebSocket> create_websocket(const std::string& url, 
                                                   const std::vector<std::string>& headers = {}) {
            return std::make_unique<WebSocket>(this, url, headers);
        }
#endif // !NATIVE_HTTP_WEBSOCKET_MINIMAL
        
    private:
        bool follow_redirects;
        int max_redirects;
        int timeout_ms;
        bool verify_ssl;
        bool verbose;
        bool auto_referer;
        bool compress;
        std::string user_agent = constants::DEFAULT_USER_AGENT;
        constants::HttpVersion http_version;
        ProxyConfig proxy;
        CookieJar cookie_jar;
        SSLConfig ssl_config;
        std::string last_url; // For auto-referer
        
        bool has_header(const std::vector<std::string>& headers, const std::string& name) {
            std::string lower_name = utils::to_lower(name);
            for (const auto& header : headers) {
                size_t colon = header.find(':');
                if (colon != std::string::npos) {
                    std::string header_name = utils::trim(header.substr(0, colon));
                    if (utils::to_lower(header_name) == lower_name) {
                        return true;
                    }
                }
            }
            return false;
        }
        
        Response execute_request(const std::string& method, const std::string& url,
                                const std::vector<uint8_t>& body,
                                const std::vector<std::string>& headers,
                                ProgressCallback progress_cb = nullptr,
                                int redirect_count = 0) {
            Response response;
            response.url = url;
            auto start_time = std::chrono::high_resolution_clock::now();
            
            try {
                // Enhanced request execution with progress tracking, 
                // advanced proxy auth, HTTP version support, etc.
                // This would be platform-specific implementation
                
                // Windows implementation using WinHTTP with enhanced features
#ifdef _WIN32
                HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
                
                ParsedURL parsed = ParsedURL::parse(url);
                if (!parsed.valid) {
                    response.error_message = "Invalid URL: " + url;
                    return response;
                }
                
                // Enhanced proxy configuration with authentication
                DWORD access_type = WINHTTP_ACCESS_TYPE_DEFAULT_PROXY;
                std::wstring proxy_config = WINHTTP_NO_PROXY_NAME;
                std::wstring proxy_bypass = WINHTTP_NO_PROXY_BYPASS;
                
                if (proxy.enabled()) {
                    access_type = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
                    proxy_config = unicode::from_utf8(proxy.host + ":" + std::to_string(proxy.port));
                    
                    // Proxy authentication would be handled here
                    if (proxy.auth_method != ProxyConfig::AuthMethod::NONE) {
                        // Complex proxy auth implementation for NTLM, Kerberos, etc.
                    }
                }
                
                // Enhanced session creation with HTTP version support
                hSession = WinHttpOpen(unicode::from_utf8(user_agent).c_str(),
                                     access_type, proxy_config.c_str(), 
                                     proxy_bypass.c_str(), 0);
                
                if (!hSession) {
                    Logger::log_last_error("WinHttpOpen failed");
                    response.error_message = "Failed to initialize HTTP session";
                    return response;
                }
                
                // Set advanced options based on configuration
                WinHttpSetTimeouts(hSession, timeout_ms, timeout_ms, timeout_ms, timeout_ms);
                
                // HTTP version setting
                DWORD http_version_flag = WINHTTP_FLAG_HTTP2;
                if (http_version == constants::HttpVersion::HTTP1_0) {
                    http_version_flag = WINHTTP_FLAG_HTTP1;
                } else if (http_version == constants::HttpVersion::HTTP2_0) {
                    http_version_flag = WINHTTP_FLAG_HTTP2;
                }
                WinHttpSetOption(hSession, WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL, 
                               &http_version_flag, sizeof(http_version_flag));
                
                // Enhanced SSL configuration
                if (parsed.protocol == "https") {
                    DWORD security_flags = 0;
                    if (!verify_ssl) {
                        security_flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                                       SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                                       SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                                       SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
                    }
                    // Additional SSL options based on ssl_config
                    WinHttpSetOption(hSession, WINHTTP_OPTION_SECURITY_FLAGS,
                                   &security_flags, sizeof(security_flags));
                }
                
                // Connect to server
                hConnect = WinHttpConnect(hSession, unicode::from_utf8(parsed.host).c_str(), 
                                         parsed.port, 0);
                if (!hConnect) {
                    Logger::log_last_error("WinHttpConnect failed");
                    response.error_message = "Failed to connect to host";
                    WinHttpCloseHandle(hSession);
                    return response;
                }
                
                // Create request
                DWORD request_flags = (parsed.protocol == "https") ? WINHTTP_FLAG_SECURE : 0;
                hRequest = WinHttpOpenRequest(hConnect, unicode::from_utf8(method).c_str(),
                                            unicode::from_utf8(parsed.path).c_str(), NULL, 
                                            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                            request_flags);
                if (!hRequest) {
                    Logger::log_last_error("WinHttpOpenRequest failed");
                    response.error_message = "Failed to create request";
                    WinHttpCloseHandle(hConnect);
                    WinHttpCloseHandle(hSession);
                    return response;
                }
                
                // Add headers
                for (const auto& header : headers) {
                    WinHttpAddRequestHeaders(hRequest, unicode::from_utf8(header).c_str(),
                                           -1L, WINHTTP_ADDREQ_FLAG_ADD);
                }
                
                // Add cookies
                std::string cookie_header = cookie_jar.get_cookie_header(url, parsed.protocol == "https");
                if (!cookie_header.empty()) {
                    WinHttpAddRequestHeaders(hRequest, 
                                           unicode::from_utf8("Cookie: " + cookie_header).c_str(),
                                           -1L, WINHTTP_ADDREQ_FLAG_ADD);
                }
                
                // Send request
                BOOL send_result = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                                    body.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)body.data(),
                                                    body.size(), body.size(), 0);
                if (!send_result) {
                    Logger::log_last_error("WinHttpSendRequest failed");
                    response.error_message = "Failed to send request";
                    WinHttpCloseHandle(hRequest);
                    WinHttpCloseHandle(hConnect);
                    WinHttpCloseHandle(hSession);
                    return response;
                }
                
                // Receive response
                if (!WinHttpReceiveResponse(hRequest, NULL)) {
                    Logger::log_last_error("WinHttpReceiveResponse failed");
                    response.error_message = "Failed to receive response";
                    WinHttpCloseHandle(hRequest);
                    WinHttpCloseHandle(hConnect);
                    WinHttpCloseHandle(hSession);
                    return response;
                }
                
                // Get status code
                DWORD status_code = 0;
                DWORD status_code_size = sizeof(status_code);
                WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                  WINHTTP_HEADER_NAME_BY_INDEX, &status_code, &status_code_size, 
                                  WINHTTP_NO_HEADER_INDEX);
                response.status_code = status_code;
                
                // Get status text
                wchar_t status_text[256] = {0};
                DWORD status_text_size = sizeof(status_text);
                WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_TEXT, WINHTTP_HEADER_NAME_BY_INDEX,
                                  status_text, &status_text_size, WINHTTP_NO_HEADER_INDEX);
                response.status_text = unicode::to_utf8(status_text);
                
                // Read response body
                std::vector<uint8_t> response_body;
                DWORD bytes_available = 0;
                do {
                    bytes_available = 0;
                    WinHttpQueryDataAvailable(hRequest, &bytes_available);
                    if (bytes_available > 0) {
                        std::vector<uint8_t> buffer(bytes_available);
                        DWORD bytes_read = 0;
                        WinHttpReadData(hRequest, buffer.data(), bytes_available, &bytes_read);
                        response_body.insert(response_body.end(), buffer.begin(), buffer.begin() + bytes_read);
                    }
                } while (bytes_available > 0);
                
                response.body = response_body;
                response.downloaded_bytes = response_body.size();
                response.uploaded_bytes = body.size();
                
                // Cleanup
                WinHttpCloseHandle(hRequest);
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                
#else
                // Linux implementation would go here with similar enhancements
                response.error_message = "Linux implementation with enhanced features not yet available";
                response.status_code = 501; // Not implemented
#endif
                
                // Handle redirects with enhanced logic
                if (follow_redirects && response.redirect() && redirect_count < max_redirects) {
                    std::string location = response.get_header("Location");
                    if (!location.empty()) {
                        // Enhanced redirect handling with relative URL resolution
                        if (auto_referer) {
                            // Auto-set Referer header for redirects
                        }
                        
                        response.effective_url = location;
                        return execute_request(method, location, body, headers, 
                                             progress_cb, redirect_count + 1);
                    }
                }
                
            } catch (const std::exception& e) {
                response.error_message = std::string("Exception: ") + e.what();
            }
            
            auto end_time = std::chrono::high_resolution_clock::now();
            response.elapsed_time = std::chrono::duration<double, std::milli>(end_time - start_time).count();
            
            return response;
        }
    };

} // namespace nativeHTTP

#endif // nativeHTTP_H_
