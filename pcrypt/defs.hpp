#pragma once
#include "rc4.hpp"
#include <windows.h>
#include <TlHelp32.h>
//make life less annoying
typedef uintptr_t intl;
typedef void* ptr;
typedef HANDLE handle;
typedef unsigned char ubyte;
typedef LPVOID lvoid;

#define dosh IMAGE_DOS_HEADER
#define iopth IMAGE_OPTIONAL_HEADER
#define ifh IMAGE_FILE_HEADER
#define inth IMAGE_NT_HEADERS
#define null NULL

#define nbs std::noshowbase
#define shx std::hex

#define RELOC_FLAG32(rinf)((rinf >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(rinf)((rinf >> 0x0C) == IMAGE_REL_BASED_DIR64)
#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif
#pragma region Function Prototypes
//kernel32
typedef BOOL(__stdcall* _WriteProcessMemory)(handle hproc, lvoid addr, LPCVOID buff, SIZE_T sz, SIZE_T* byteswritten);
typedef BOOL(__stdcall* _TerminateProcess)(handle h, UINT ec);
typedef BOOL(__stdcall* _CreateProcessW)(LPCWSTR an, LPWSTR cl, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta, BOOL ih, DWORD cf, LPVOID e, LPCWSTR cd, LPSTARTUPINFOW si, LPPROCESS_INFORMATION lpi);
typedef BOOL(__stdcall* _GetThreadContext)(handle ht, LPCONTEXT lc);
typedef BOOL(__stdcall* _SetThreadContext)(handle ht, const CONTEXT* lc);
typedef lvoid(__stdcall* _VirtualAlloc)(lvoid addr, SIZE_T dsz, DWORD falloct, DWORD flprot);
typedef lvoid(__stdcall* _VirtualAllocEx)(handle hp, lvoid addr, SIZE_T dsz, DWORD at, DWORD fproc);
typedef BOOL(__stdcall* _VirtualProtect)(lvoid  la, SIZE_T dsz, DWORD np, PDWORD op);
typedef lvoid(__stdcall* _VirtualProtectEx)(handle hp, lvoid la, SIZE_T dsz, DWORD at, PDWORD fp);
typedef BOOL(__stdcall* _VirtualFree)(lvoid addr, SIZE_T sz, DWORD ft);
typedef BOOL(__stdcall* _VirtualFreeEx)(handle h, lvoid addr, SIZE_T dsz, DWORD dft);
typedef DWORD(__stdcall* _GetModuleFileNameW)(HMODULE hmod, LPWSTR lfn, DWORD nsz);
typedef handle(__stdcall* _GetCurrentProcess)();
typedef BOOL(__stdcall* _CloseHandle)(handle h);
typedef handle(__stdcall* _CreateThread)(LPSECURITY_ATTRIBUTES lpta, SIZE_T ssz, LPTHREAD_START_ROUTINE sr, lvoid param, DWORD cf, LPDWORD tip);
typedef DWORD(__stdcall* _ResumeThread)(handle htrd);
typedef DWORD(__stdcall* _GetLastError)();
typedef DWORD(__stdcall* _WaitForSingleObject)(handle h, DWORD p);
typedef BOOL(__stdcall* _GetExitCodeProcess)(handle h, LPDWORD dw);
#pragma endregion