// i found on stackoverflow help to convert wstring to string or vice versa 
// i'll delete this file once complete some stuff and make it work in one file 
#pragma once
#ifndef unibytes_H_  
#define unibytes_H_

#include <codecvt>
#include <string>

// convert UTF-8 string to wstring
std::wstring utf8_to_wstring(const std::string& str) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> myconv;
    return myconv.from_bytes(str);
}

// convert wstring to UTF-8 string
std::string wstring_to_utf8(const std::wstring& str) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> myconv;
    return myconv.to_bytes(str);
}
#endif
