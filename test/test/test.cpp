#include <iostream>
#include "../../include/nativehttp.h"

int main() {
	nativeHTTP::Request req;
	std::string myip = req.sendReq(L"https://www.myexternalip.com/raw").response;
	std::cout << "my ip is :" << myip << "\n";
	return 0;
}