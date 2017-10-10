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
	CONTEXT ctx;

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
		VirtualProtect(fnNtContinue, 8, PAGE_EXECUTE_READ, &oldProt);
		VirtualFree((LPVOID)0x55550000, 0, MEM_RELEASE);
		VirtualFree((LPVOID)0x55560000, 0, MEM_RELEASE);
		/*End of Cleanup*/

		AllocConsole();
		freopen("CONOUT$", "w", stdout);
		GetModuleFileNameA(0, buffer, MAX_PATH);
		printf("Mapped inside %s\n", buffer);
		ctx = *(PCONTEXT)lpReserved;
#ifdef _WIN64
		printf("Going to Rip : %p\n", ctx.Rip);
#else
		printf("Going to Eip : %p\n", ctx.Eip);
#endif
		//Go to hijacked process EP
		fnNtContinue((PCONTEXT)lpReserved, false);

		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return 1;
}