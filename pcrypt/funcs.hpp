#pragma once
#include "objects.hpp"
class _funcs {
public:
#pragma region Memory utilities
    static ubyte* _loc_alloc(intl _base, intl _size, DWORD* _old_flags);
    static bool _loc_img_reloc(handle _hdl, ubyte* _base, ubyte* _src, IMAGE_NT_HEADERS* _hdr);
#pragma endregion
#pragma region Shellcode generation
    static int _shellcode_gen_pe_loc(LPPROCESS_INFORMATION _pinf, LPSTARTUPINFOW _psi, LPVOID lpImage, LPWSTR _wargs, SIZE_T _argsz);
#pragma endregion
};