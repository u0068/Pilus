#include <cstdint>
#include <windows.h>
#include <unordered_map>
#include <string>

#include "func_decls.h"
#include "data_decls.h"

extern "C" __declspec(dllexport) bool READY = false;

DWORD WINAPI MainThread(LPVOID)
{
    AllocConsole();

    FILE* file;
    freopen_s(&file, "CONOUT$", "w", stdout);

    SetFunctionDeclerationAddresses();
    SetDataDeclarationAddresses();

    printf("API DLL active\n");

    READY = true;

    while (true)
    {
        Sleep(1000);
    }

    return 0;
}

BOOL APIENTRY DllMain(
    HMODULE module,
    DWORD reason,
    LPVOID)
{

    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(module);

        CreateThread(
            nullptr,
            0,
            MainThread,
            nullptr,
            0,
            nullptr);
    }

    return TRUE;
}