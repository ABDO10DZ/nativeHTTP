#pragma once
// drop INTERNET_FLAG_SECURE for http connecting (keep it for ssl connect) / or wait next update

// (C) ABDO10_DZ
#ifndef nativeHTTP_H_
#define nativeHTTP_H_
#ifndef __cplusplus
#error this header should be compiled with c++ compiler , try mingw/msvc
#endif
#ifndef _MSC_VER
#warning "you may get some compiler Errors , prefered MSVC currently"
#endif
#ifdef __unix__
#error "asap will be available for unix like" 
#elif _WIN32 || _WIN64
#include <windows.h>
#include <wininet.h>
#include <winhttp.h>
#include <tchar.h>
#include "unibytes.h"
#pragma comment (lib, "wininet.lib")
#pragma comment(lib,"winhttp.lib")
#else
#error unsupported OS
#endif
#include <iostream>
#include <string>

#if defined (_UNICODE) && defined(_WININET_) || defined(_WININET_H)
// wininet funcs 
#define bInternetOpen InternetOpenW
#define bInternetConnect InternetConnectW
#define bHttpOpenRequest HttpOpenRequestW
#define bHttpAddRequestHeaders HttpAddRequestHeadersW
#define bHttpSendRequest HttpSendRequestW
#define bHttpQueryInfo HttpQueryInfoW
#elif defined(_WININET_) || defined(_WININET_H) && !defined(_UNICODE)
#define bInternetOpen InternetOpenA
#define bInternetConnect InternetConnectA
#define bHttpOpenRequest HttpOpenRequestA
#define bHttpAddRequestHeaders HttpAddRequestHeadersA
#define bHttpSendRequest HttpSendRequestA
#define bHttpQueryInfo HttpQueryInfoA

#elif defined(_UNICODE) && defined(_WINHTTPX_) || defined(__WINE_WINHTTP_H)
// winhttp funcs / soon
#define bInternetOpen WinHttpOpen
#define bInternetConnect WinHttpConnect
#define bHttpOpenRequest WinHttpOpenRequest
#define bHttpAddRequestHeaders WinHttpAddRequestHeaders
#define bHttpSendRequest WinHttpSendRequest
#define bHttpQueryInfo WinHttpQueryHeaders

//...
#endif

#ifdef _UNICODE // soon to apply this lines to all of the code 
typedef WCHAR bchar;
#define bcout std::wcout;
typedef std::wstring bstring;
#else
typedef char bchar;
#define bcout std::cout;
typedef std::string bstring;
#endif

void Dconsole(void* log, const bool& exception = false) {
    if (exception == false) {
#ifndef NDEBUG
        std::cout << "[nativeHTTP] Debug: " << (char*)log << std::endl;
#endif
    }
    else std::cout << "[nativeHTTP] Exception: " << (char*)log << std::endl;
}
namespace nativeHTTP {
    class Request {
    private:
        struct HTTPrequest {
            int port = 80;
            bool isSSL = false;
            std::wstring host = L"";        // host
            std::wstring uri = L"/";
            std::wstring UA = L"nativeHTTP";		// UserAgent 
            std::wstring prms = L"";			// parameters
            LPVOID headers = NULL;// headers , will be handled in this var
            const std::string defheaders[10] = { "Connection:", "keep-Alive\r\n"
        , "Content-Type:","application/json\r\n"
        , "Accept-Language:","en-US,en;q=0.8\r\n"
        , "Accept:","*/*\r\n"
        , "Accept-Encoding:","gzip,deflate,sdch\r\n" };
            std::wstring cookies = L"";
            std::wstring method = L"GET";
            std::wstring proto = L"HTTP/1.1";
            DWORD StatusCode;
            std::string response;
        };
        HTTPrequest myreq;
        struct Settings {
            bool ssl = false;
            bool cookies = false;
            bool proxy = false;
            bool OwnHeaders = false;
        };
        Settings Options;
        struct CustomHeaders {
            size_t AddedHeaderSize = 0;
            std::string AddedHeaders[MAX_PATH];
            bool SaveDefault = true;
        };
        CustomHeaders OwnedHeader;
        struct Url {
            std::string url;
            std::string uri;
            std::string hypertext = "http://";
            int port = 80;
        };
        Url UrlStructure;
        bool StartWith(std::string FullStr, std::string SubStr) {
            for (int i = 0; i < SubStr.length(); i++) {
                if (FullStr[i] != SubStr[i]) return false;
            }
            return true;
        }
        void SetUrl(std::string URL) {
            // (http?://)(url):(port)/(uri)
            // https://www.facebook.com:443/index.php
            // if start with http?s
            //if (IsCharLowerA());
            if (!sizeof(URL) > 9) return; // make sure sizeof url not wrong
            std::string ProtoTmp;    // save url proto
            std::string PortTmp;    // save url port
            std::string UrlTmp;
            std::string UriTmp;
            std::string hypertext[] = { "http://","https://" };
            bool port = false;
            bool uri = false;
            if (StartWith(URL, hypertext[0])) {
                // http 
                ProtoTmp = hypertext[0];
            }
            else if (StartWith(URL, hypertext[1])) {
                //https
                ProtoTmp = hypertext[1];
            }
            else ProtoTmp = "";
            for (int i = ProtoTmp.length(); i < URL.length(); i++) {
                if (URL[i] == ':') port = true;
                else if (URL[i] == '/') {
                    uri = true;
                    port = false;
                }
                else;
                if (port) { if (URL[i] != ':') PortTmp += URL[i]; }
                else if (uri) UriTmp += URL[i];
                else UrlTmp += URL[i];
            }
            UrlStructure.url = UrlTmp;
            if (!UriTmp.empty()) UrlStructure.uri = UriTmp;
            else UrlStructure.uri = "/";
            if (PortTmp.length() > 1) UrlStructure.port = stoi(PortTmp);
            else {
                //std::cout << "Protocol:" << ProtoTmp << "\n";
                if (ProtoTmp == "https://" && PortTmp != "443") PortTmp = "443";
                else if (ProtoTmp == "http://" && PortTmp != "80") PortTmp = "80";
                UrlStructure.port = stoi(PortTmp);
            }
            if (!ProtoTmp.empty()) UrlStructure.hypertext = ProtoTmp;
        }
        void SetHeaders(const std::string* headers, const int& HSize = 10) {
            bool nock = true;

            for (int i = 0; i < HSize - 1; i++) {
                if ((nock == true) && (i + 1) <= (HSize) && !headers[i + 1].empty()) {
                    //std::cout << headers[i] << headers[i + 1] << "\r\n"; // push header 
                    nock = false;
                }
                else nock = true;
            }
        }
        HTTPrequest send(std::string method, std::string data,std::string prms, std::string cookies) {

            try
            {
                SetUrl(wstring_to_utf8(myreq.host));
                myreq.host = utf8_to_wstring(UrlStructure.url);
                myreq.uri = utf8_to_wstring(UrlStructure.uri);
                // something i'll add here later
                myreq.port = UrlStructure.port;
                std::wcout << "connecting to :h=" << myreq.host << "/U=" << myreq.uri << "/P=" << myreq.port << "\n";
                if (Options.OwnHeaders) {
                    SetHeaders(OwnedHeader.AddedHeaders, OwnedHeader.AddedHeaderSize);
                }
                else {
                    Dconsole((char*)"using Default headers , no custom headers passed\n");
                    SetHeaders(myreq.defheaders);
                }

                HINTERNET internet = bInternetOpen((myreq.UA.c_str()), INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
                if (internet == NULL) Dconsole((char*)"InternetOpen failed");
                if (internet != NULL)
                {

                    HINTERNET connect = bInternetConnect(internet, (myreq.host.c_str()), myreq.port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
                    if (connect == NULL) Dconsole((char*)"InternetConnect failed");
                    if (connect != NULL)
                    {

                        HINTERNET request = bHttpOpenRequest(connect, myreq.method.c_str(), myreq.uri.c_str(), myreq.proto.c_str(), NULL, NULL,
                            INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_CN_INVALID |
                            INTERNET_FLAG_IGNORE_CERT_DATE_INVALID |
                            INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP |
                            INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS |
                            INTERNET_FLAG_NO_AUTH |
                            INTERNET_FLAG_NO_CACHE_WRITE |
                            INTERNET_FLAG_NO_UI |
                            INTERNET_FLAG_PRAGMA_NOCACHE |
                            INTERNET_FLAG_SECURE |
                            INTERNET_FLAG_RELOAD, NULL);       // fih method / uri / http version api  ssl =INTERNET_FLAG_SECURE |
                        if (request == NULL) Dconsole((char*)"HttpOpenRequest failed");  // failed

                        if (request != NULL)
                        {
                            int  datalen = data.length();
                            // headers , addi wela dropi 

                            std::string RH = "Connection: keep-Alive\r\n";
                            bHttpAddRequestHeaders(request, (LPCWSTR)RH.c_str(), _tcslen((LPCWSTR)RH.c_str()), HTTP_ADDREQ_FLAG_REPLACE | HTTP_ADDREQ_FLAG_ADD);
                            std::string RH1 = "Content-Type: application/json\r\n";
                            bHttpAddRequestHeaders(request, (LPCWSTR)RH1.c_str(), _tcslen((LPCWSTR)RH1.c_str()), HTTP_ADDREQ_FLAG_REPLACE | HTTP_ADDREQ_FLAG_ADD);

                            std::string RH3 = "Accept-Language: en-US,en;q=0.8\r\n";
                            bHttpAddRequestHeaders(request, (LPCWSTR)RH3.c_str(), _tcslen((LPCWSTR)RH3.c_str()), HTTP_ADDREQ_FLAG_REPLACE | HTTP_ADDREQ_FLAG_ADD);
                            std::string RH4 = "Accept: */*\r\n";
                            bHttpAddRequestHeaders(request, (LPCWSTR)RH4.c_str(), _tcslen((LPCWSTR)RH4.c_str()), HTTP_ADDREQ_FLAG_REPLACE | HTTP_ADDREQ_FLAG_ADD);
                            std::string RH5 = "Accept-Encoding: gzip,deflate,sdch\r\n";
                            bHttpAddRequestHeaders(request, (LPCWSTR)RH5.c_str(), _tcslen((LPCWSTR)RH5.c_str()), HTTP_ADDREQ_FLAG_REPLACE | HTTP_ADDREQ_FLAG_ADD);

                            int Rs = bHttpSendRequest(request, NULL, 0, (LPVOID)data.c_str(), datalen); // request status
                            if (Rs == 0) Dconsole((char*)"Failed to send");
                            DWORD StatusCode = 0;
                            DWORD StatusCodeLen = sizeof(StatusCode);
                            LPVOID headers = NULL;
                            DWORD headersLen = 0;
                            // tmnyik not needed below :
                            bHttpQueryInfo(request, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &StatusCode, &StatusCodeLen, NULL);
                        retry:
                            if (!bHttpQueryInfo(request, HTTP_QUERY_RAW_HEADERS_CRLF, (LPVOID)headers, &headersLen, NULL)) {
                                //std::cout << GetLastError();
                                if (GetLastError() == ERROR_HTTP_HEADER_NOT_FOUND)
                                {
                                    // Code to handle the case where the header isn't available.
                                }
                                else
                                {
                                    // Check for an insufficient buffer.
                                    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
                                    {
                                        // Allocate the necessary buffer.
                                        headers = new char[headersLen];

                                        // Retry the call.
                                        goto retry;
                                    }
                                    else
                                    {
                                        // Error handling code.
                                        if (headers) delete[] headers;
                                    }
                                }
                            }
                            if (headers) delete[] headers;

                            DWORD blocksize = 4096;
                            DWORD received = 0;
                            std::string temp;
                            std::string block(blocksize, 0);
                            while (InternetReadFile(request, &block[0], blocksize, &received) && received)
                            {
                                block.resize(received);
                                temp += block;
                            }

                            myreq.response = temp;
                            myreq.StatusCode = StatusCode;
                            myreq.headers = headers;

                            InternetCloseHandle(request);
                        }
                    }
                    if (connect)InternetCloseHandle(connect);
                }
                if (internet)InternetCloseHandle(internet);
            }
            catch (std::exception& e)
            {
                Dconsole((void*)e.what(), true);
            }
            return myreq;
        }



    public:
        template<size_t hsize>bool SetHeader(const std::string(&header)[hsize]) {
            if (hsize >= MAX_PATH) return false;
            Request::Options.OwnHeaders = true;
            Request::OwnedHeader.AddedHeaderSize = hsize;
            std::copy(header, header + hsize, Request::OwnedHeader.AddedHeaders);
            Request::OwnedHeader.SaveDefault = false;
            return true;
        }
        bool SetProxy(const std::string& host = "localhost", const int& port = 8080) {  //default ::1:8080 .. Soon 
            return true;
        }
        HTTPrequest sendReq(std::wstring host, const std::string& method = std::string("GET"), std::string data = "", std::string prms = "", std::string cookies = "") {
            myreq.host = host;
            myreq.method = utf8_to_wstring(method);
            return Request::send(method, data,prms, cookies);
        }
    };
}
#endif
