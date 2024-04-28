#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <stdbool.h>
#include <string.h>
#include "beacon.h"

typedef HMODULE (WINAPI * LoadLibraryA_t)(LPCSTR lpLibFileName);
typedef NTSTATUS (NTAPI * NtContinue_t)(PCONTEXT ThreadContext, BOOLEAN RaiseAlert);
WINBASEAPI size_t WINAPI MSVCRT$strlen(const char* str);
WINBASEAPI int __cdecl MSVCRT$printf(const char * _Format,...);
WINBASEAPI int WINAPI MSVCRT$strncmp(const char* str1, const char* str2, size_t n);
WINBASEAPI void *__cdecl MSVCRT$malloc(size_t _Size);
WINBASEAPI int __cdecl MSVCRT$memcmp(const void * _Buf1, const void * _Buf2, size_t _Size);

BOOL DetectHook(LPVOID hookedfuncaddr) {
    BYTE realbytes[] = "\x4C\x8B\xD1\xB8";
    if (MSVCRT$memcmp(realbytes, hookedfuncaddr, 4) == 0) {
        return TRUE;
    }
    else {
        return FALSE;
    }
}

int go(int argc, char* argv[]) {
    bool hasHook = false;

    LoadLibraryA_t pLoadLibraryA = (LoadLibraryA_t)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    if (pLoadLibraryA != NULL) {
        HMODULE hNtdll = pLoadLibraryA("ntdll.dll");
        if (hNtdll == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Error loading ntdll.dll\n");
            return 1;
        }

        PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)hNtdll;
        PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((char*)dos_header + dos_header->e_lfanew);
        PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((char*)hNtdll + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

        DWORD* function_names = (DWORD*)((char*)hNtdll + exports->AddressOfNames);

        BeaconPrintf(CALLBACK_OUTPUT, "[*] NT API being hooked:\n");
        BeaconPrintf(CALLBACK_OUTPUT, "=========================================================================================\n");
        for (int i = 0; i < exports->NumberOfFunctions; i++) {
            char* ntFunction = (char*)hNtdll + function_names[i];
            if (MSVCRT$strncmp(ntFunction, "Nt", 2) == 0) {
                if (MSVCRT$strncmp(ntFunction, "NtdllDialogWndProc", 18) != 0 && MSVCRT$strncmp(ntFunction, "NtdllDefWindowProc", 18) != 0) {       // blacklist nt funcs
                    FARPROC procaddr = GetProcAddress(hNtdll, (LPCSTR)ntFunction);
                    if (procaddr == NULL) {
                        BeaconPrintf(CALLBACK_ERROR, "[-] Error finding function %s\n", ntFunction);
                        return 1;
                    }
                    LPBYTE lpprocaddr = (LPBYTE)procaddr;
                    DWORD dwprocaddr = *(DWORD*)lpprocaddr;
                    char realbytes[] = "0xB8D18B4C";

                    if (MSVCRT$strncmp(ntFunction, "NtQuerySystemTime", 17) == 0 && MSVCRT$memcmp("\xE9\x4B", procaddr, 2) != 0) {
                        hasHook = true;
                        BeaconPrintf(CALLBACK_OUTPUT, "[-] %s [%s != 0x%02X]\n", ntFunction, "0x****4BE9", dwprocaddr);
                    }
                    else if (MSVCRT$strncmp(ntFunction, "NtGetTickCount", 14) == 0 && MSVCRT$memcmp("\xB9\x20", procaddr, 2) != 0) {
                        hasHook = true;
                        BeaconPrintf(CALLBACK_OUTPUT, "[-] %s [%s != 0x%02X]\n", ntFunction, "0x****20B9", dwprocaddr);
                    }
                    else if (MSVCRT$strncmp(ntFunction, "NtQuerySystemTime", 17) != 0 && MSVCRT$strncmp(ntFunction, "NtGetTickCount", 14) != 0 && !DetectHook(procaddr)) {
                        hasHook = true;
                        BeaconPrintf(CALLBACK_OUTPUT, "[-] %s [%s != 0x%02X]\n", ntFunction, realbytes, dwprocaddr);
                    }
                }
            }
        }

        if (!hasHook) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] You are safe, there is no hook in the NT API\n");
        }

        BeaconPrintf(CALLBACK_OUTPUT, "=========================================================================================\n");

        FreeLibrary(hNtdll);
        return 0;
    }
    else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Error getting address of LoadLibraryA function\n");
        return 1;
    }
}
