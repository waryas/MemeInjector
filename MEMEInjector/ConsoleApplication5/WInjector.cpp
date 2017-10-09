#include "stdafx.h"

#include <Psapi.h>
#include <stdint.h>
#include <tlhelp32.h>


auto ptr = 0ULL;

auto oldProtect = 0UL;	

struct rDll {
	char* buffer;
	DWORD size;
	DWORD offset;
};

rDll reflectiveDll = { 0,0,0 };

char* exeToInjectTo = 0;

auto ntContinue = GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtContinue");


rDll loadDll(char* toInject) {
	rDll result = { 0,0,0 };
	auto f = fopen(toInject, "rb");
	if (!f)
		return result;
	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	if (fsize <= 0)
		return result;
	fseek(f, 0, SEEK_SET);
	char *string = (char*)malloc(fsize + 1);
	fread(string, fsize, 1, f);
	fclose(f);
	string[fsize] = 0;
	result.buffer = string;
	result.size = fsize;
	result.offset = GetReflectiveLoaderOffset(string);
	return result;
}

auto HandleReceiver(HANDLE *io_port) {


	DWORD nOfBytes;
	ULONG_PTR cKey;
	char buffer[MAX_PATH];
	LPOVERLAPPED pid;

	BYTE ntContinueHook[8] = { 0x68, 0x00, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90 };

	struct myHook {
		FARPROC ptrFn;
		BYTE ntContinueOriginal[8];
	};

	myHook sNtContinueHook = { ntContinue, {0} };
	
	while (GetQueuedCompletionStatus(*io_port, &nOfBytes, &cKey, &pid, -1))
		if (nOfBytes == 6) {
			auto race_handle = OpenProcess(PROCESS_ALL_ACCESS, false, (DWORD)pid);
			GetModuleFileNameExA(race_handle, 0, buffer, MAX_PATH);
			if (strstr(buffer, exeToInjectTo)) {
				auto ret = LoadRemoteLibraryR(race_handle, reflectiveDll.buffer, reflectiveDll.size, reflectiveDll.offset);
				ptr = (uint64_t)ret;
				*(unsigned int*)(ntContinueHook + 1) = (unsigned int)ret;
				auto toFreeOne = VirtualAllocEx(race_handle, (LPVOID)0x55550000, sizeof(sNtContinueHook), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
				ReadProcessMemory(race_handle, sNtContinueHook.ptrFn, &sNtContinueHook.ntContinueOriginal[0], sizeof(sNtContinueHook.ntContinueOriginal), 0);
				WriteProcessMemory(race_handle, (LPVOID)0x55550000, &sNtContinueHook, sizeof(sNtContinueHook), 0);
				//Install hook
				WriteProcessMemory(race_handle, sNtContinueHook.ptrFn, ntContinueHook, sizeof(ntContinueHook), 0);
				CloseHandle(race_handle);
				ExitThread(0);
			}
			else {
				CloseHandle(race_handle);
				continue;
			}
			


		}
}


int main(int argc,char** argv)
{
	auto pid = 0UL;
	if (argc != 4) {
		printf("Usage : %s DLLPATH[C:\PATH\TO\DLL.DLL] EXECUTABLE[Name.exe] ISSTEAM[0|1]\n", argv[0]);
		printf("Usage : %s C:\\reflectivedll.dll Unturned.exe 1 for injecting into the steam game Unturned.\n", argv[0]);
		printf("Usage : %s C:\\reflectivedll.dll notepad.exe 0 for injecting into the desktop app Notepad.\n", argv[0]);
		return -1;
	}

	reflectiveDll = loadDll(argv[1]);

	if (reflectiveDll.offset <= 0) {
		printf("%s is not a reflective dll, look at sample\n", argv[1]);
		return -1;
	}

	auto desk_hwnd = (HWND)0;

	if (atoi(argv[3]) == 1) {
		printf("Monitoring app launched from Steam...\n");
		desk_hwnd = FindWindow(NULL, L"Steam");
		if (!desk_hwnd) {
			printf("Steam isn't running...\n");
			return -1;
		}
	} else {
		printf("Monitoring app launched from Desktop...\n");
		desk_hwnd = GetShellWindow();
		if (!desk_hwnd) {
			printf("Explorer isn't running...\n");
			return -1;
		}
	}
	exeToInjectTo = argv[2];

	printf("Waiting for %s to launch...\n", argv[2]);

	auto ret = GetWindowThreadProcessId(desk_hwnd, &pid);
	auto exp_handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	auto io_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, 0, 0, 0);
	auto job_object = CreateJobObjectW(0, 0);
	auto job_io_port = JOBOBJECT_ASSOCIATE_COMPLETION_PORT{ 0, io_port };
	auto result = SetInformationJobObject(job_object, JobObjectAssociateCompletionPortInformation, &job_io_port, sizeof(job_io_port));
	result = AssignProcessToJobObject(job_object, exp_handle);
	auto threadHandle = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)HandleReceiver, &io_port, 0, 0);
	SetThreadPriority(threadHandle, THREAD_PRIORITY_TIME_CRITICAL);
	WaitForSingleObject(threadHandle, -1);
	
	CloseHandle(threadHandle);
	CloseHandle(exp_handle);
	CloseHandle(job_object);
	CloseHandle(io_port);
	return 0;
}