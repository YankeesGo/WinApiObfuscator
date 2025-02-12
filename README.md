# WinApi Call (import) Obfuscator
Header-only c++17 library for obfuscation import winapi functions.
This based on https://github.com/XShar/Win_API_Obfuscation and https://xakep.ru/2018/12/06/hidden-winapi/

It's hide your table of import functions.


### How it work?

Importing win api functions calling by hash-value function 


### How to using?
```c++
#include <iostream>

#include "winapi_import.hpp"

int main()
{
    // Define function types we want to import
    using MessageBoxType = int(WINAPI)(HWND, LPCSTR, LPCSTR, UINT);
    using GetSystemMetricsType = int(WINAPI)(int);

    auto msgBox = win_api::get<MessageBoxType>("MessageBoxA", "user32.dll");
    auto msgBox2 = win_api::get<MessageBoxType>("MessageBoxA2", "user32.dll");

    auto GetSystemMetrics = win_api::get<GetSystemMetricsType>("GetSystemMetrics", "user32.dll");

    // Use the imported functions
    if (msgBox) {
        msgBox(nullptr, "Hello from dynamic import!", "Dynamic Import", MB_OK);
    }

    if (GetSystemMetrics) {
        int screenWidth = GetSystemMetrics(SM_CXSCREEN);
        int screenHeight = GetSystemMetrics(SM_CYSCREEN);
        std::cout << "Screen resolution: " << screenWidth << "x" << screenHeight << std::endl;
    }

    if (!msgBox2) {
        std::cout << "invalid link" << '\n';
    }

    std::cout << "Hello World!\n";
}       
```
