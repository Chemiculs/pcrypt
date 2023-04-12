#pragma once
#include "objects.hpp"
HMODULE _api::_h_krn32 = nullptr;
HMODULE _api::_h_advapi32 = nullptr;
_WriteProcessMemory _api::__WriteProcessMemory = nullptr;
_TerminateProcess _api::__TerminateProcess = nullptr;
_CreateProcessW _api::__CreateProcessW = nullptr;
_GetThreadContext _api::__GetThreadContext = nullptr;
_SetThreadContext _api::__SetThreadContext = nullptr;
_VirtualAlloc _api::__VirtualAlloc = nullptr;
_VirtualAllocEx _api::__VirtualAllocEx = nullptr;
_VirtualProtect _api::__VirtualProtect = nullptr;
_VirtualProtectEx _api::__VirtualProtectEx = nullptr;
_VirtualFree _api::__VirtualFree = nullptr;
_VirtualFreeEx _api::__VirtualFreeEx = nullptr;
_GetModuleFileNameW _api::__GetModuleFileNameW = nullptr;
_GetCurrentProcess _api::__GetCurrentProcess = nullptr;
_CloseHandle _api::__CloseHandle = nullptr;
_CreateThread _api::__CreateThread = nullptr;
_ResumeThread _api::__ResumeThread = nullptr;
_WaitForSingleObject _api::__WaitForSingleObject = nullptr;
_GetLastError _api::__GetLastError = nullptr;
_GetExitCodeProcess _api::__GetExitCodeProcess = nullptr;