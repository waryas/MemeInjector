// dllmain.cpp : Définit le point d'entrée pour l'application DLL.
#include "stdafx.h"
#include <stdio.h>
#include <Psapi.h>
extern HINSTANCE hAppInstance;


//===============================================================================================//
#pragma code_seg("001")  
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	char buffer[MAX_PATH];
	HMODULE hMods[1024] = { 0 };
	DWORD cbNeeded = 0;
	BOOL bReturnValue = TRUE;
	TCHAR szModName[MAX_PATH];
	uint64_t * ptr;

	switch (dwReason)
	{
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
			*(HMODULE *)lpReserved = hAppInstance;
		break;
	case DLL_PROCESS_ATTACH:

		hAppInstance = hinstDLL;
		NtContinue fnNtContinue;
		DWORD oldProt;
		
		/* Cleanup */
		fnNtContinue = (NtContinue)(*(uintptr_t*)(0x55550000));
		ptr = (uint64_t*)(*(uintptr_t*)(0x55550000));
		VirtualProtect(fnNtContinue, 8, PAGE_EXECUTE_READWRITE, &oldProt);
		*ptr = *(uint64_t*)(0x55550000 + sizeof(uintptr_t));
		VirtualProtect(fnNtContinue, 8, oldProt, &oldProt);
		VirtualFree((LPVOID)0x55550000, 0, MEM_RELEASE);
		VirtualFree((LPVOID)0x55560000, 0, MEM_RELEASE);
		/*End of Cleanup*/

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