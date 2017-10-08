// dllmain.cpp : Définit le point d'entrée pour l'application DLL.
#include "stdafx.h"
#include <stdio.h>
#include <Psapi.h>

extern HINSTANCE hAppInstance;


//===============================================================================================//
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	char buffer[MAX_PATH];
	HMODULE hMods[1024] = { 0 };
	DWORD cbNeeded = 0;
	BOOL bReturnValue = TRUE;
	TCHAR szModName[MAX_PATH];

	switch (dwReason)
	{
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
			*(HMODULE *)lpReserved = hAppInstance;
		break;
	case DLL_PROCESS_ATTACH:

		hAppInstance = hinstDLL;
		NtContinue fnNtContinue;
		fnNtContinue = (NtContinue)(*(uintptr_t*)(0x55550000));

		VirtualFree((LPVOID)0x55550000, 0, MEM_RELEASE);
		VirtualFree((LPVOID)0x55560000, 0, MEM_RELEASE);

		AllocConsole();

		freopen("CONOUT$", "w", stdout);
		GetModuleFileNameA(0, buffer, MAX_PATH);

		printf("Mapped inside %s\n", buffer);

		fnNtContinue((PCONTEXT)lpReserved, false);

		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}