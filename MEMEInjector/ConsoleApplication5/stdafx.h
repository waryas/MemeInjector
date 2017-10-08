// stdafx.h : fichier Include pour les fichiers Include système standard,
// ou les fichiers Include spécifiques aux projets qui sont utilisés fréquemment,
// et sont rarement modifiés
//

#pragma once

#include <stdio.h>
#include <tchar.h>
#include <windows.h>

#ifdef _WIN64
#define WIN_X64
#else
#define WIN_X32
#endif

typedef NTSTATUS(NTAPI *NtRtlCreateUserThread)(IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits,
	IN OUT PULONG StackReserved,
	IN OUT PULONG StackCommit,
	IN PVOID StartAddress,
	IN PVOID StartParameter OPTIONAL,
	OUT PHANDLE ThreadHandle,
	OUT VOID* ClientID
	);

NtRtlCreateUserThread pfnNtRtlCreateUserThread = (NtRtlCreateUserThread)GetProcAddress(GetModuleHandleA("ntdll"), "RtlCreateUserThread");

FARPROC WINAPI GetProcAddressR(HANDLE hModule, LPCSTR lpProcName);

DWORD GetReflectiveLoaderOffset(VOID * lpReflectiveDllBuffer);

HANDLE WINAPI LoadRemoteLibraryR(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, DWORD reflectiveOffset);

#define DLL_METASPLOIT_ATTACH	4
#define DLL_METASPLOIT_DETACH	5
#define DLL_QUERY_HMODULE		6

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

typedef ULONG_PTR(WINAPI * REFLECTIVELOADER)(VOID);
typedef BOOL(WINAPI * DLLMAIN)(HINSTANCE, DWORD, LPVOID);

#define DLLEXPORT   __declspec( dllexport ) 

// TODO: faites référence ici aux en-têtes supplémentaires nécessaires au programme
