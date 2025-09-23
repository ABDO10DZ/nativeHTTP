# nativeHTTP
native C/C++ single header for Win/Unix implementation for http/s connections <br>
- example :
```
	nativeHTTP::Request req;
	std::string myip = req.sendReq(L"https://www.myexternalip.com/raw").response;
	std::cout << "my ip is :" << myip << "\n";
```
- example on json post :
```
        std::string JsonData = "{\"ab\":10}";
        req.sendReq(L"https://ptsv2.com/t/66j3d-1668215687/post", "POST", "{\"ab\":10}");
	/* json post ab = 10 - test room:https://ptsv2.com/t/66j3d-1668215687/d/4687238942162944 */
```
- POST other methods ?
<br>if wanna application/x-www-form-urlencoded, multipart/form-data, or text/plain..etc edit line <a href="https://github.com/ABDO10DZ/nativeHTTP/blob/main/include/nativehttp.h#L228">nativehttp:258</a>
- HTTP/S mode ?
<br>to connect through http instead of https remove the SECURE flag defined in or use NULL instead <a href="https://github.com/ABDO10DZ/nativeHTTP/blob/main/include/nativehttp.h#L217">nativehttp:217</a>
<br><br>#next <br>
*add cookies support<br>
*add full support unicode <br>
*add file upload post data with easy usage (mutipart file upload .. etc)<br>
*add switch btw json post and other post requests <br>

<br>huge updates are coming </br>
*add winhttp support<br>
*add unix support
