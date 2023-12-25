#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <shlwapi.h>
#include <list>
#include "ChromiumDumper.h"

#define SystemHandleInformation 0x10
#define SystemHandleInformationSize 2048 * 2048 * 2

int pCount = 0;
int fCount = 0;

std::list<DWORD> parents;
std::list<DWORD> processes;
std::list<HANDLE> pHandles;
std::list<HANDLE> fHandles;

using namespace std;


BOOL FindProcess(WCHAR* procname){
    ULONG returnLength = 0;
    PSYSTEM_PROCESSES pProcInfo = NULL;
    LPVOID pProcInfoBuffer = NULL;
    SIZE_T procInfoSize = 0x10000;
    NTSTATUS status;
    UNICODE_STRING uProcName;

    

    NTQUERYSYSTEMINFORMATION NtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandle("ntdll"), "NtQuerySystemInformation");
    ZWFREEVIRTUALMEMORY ZwFreeVirtualMemory = (ZWFREEVIRTUALMEMORY)GetProcAddress(GetModuleHandle("ntdll"), "ZwFreeVirtualMemory");
    RTLEQUALUNICODESTRING RtlEqualUnicodeString = (RTLEQUALUNICODESTRING)GetProcAddress(GetModuleHandle("ntdll"), "RtlEqualUnicodeString");
    RTLINITUNICODESTRING RtlInitUnicodeString = (RTLINITUNICODESTRING)GetProcAddress(GetModuleHandle("ntdll"), "RtlInitUnicodeString");
    ZWALLOCATEVIRTUALMEMORY ZwAllocateVirtualMemory = (ZWALLOCATEVIRTUALMEMORY)GetProcAddress(GetModuleHandle("ntdll"), "ZwAllocateVirtualMemory");
    
    do {
		pProcInfoBuffer  = NULL;
        status = ZwAllocateVirtualMemory((HANDLE)-1, &pProcInfoBuffer, 0, &procInfoSize, MEM_COMMIT, PAGE_READWRITE);
        if (status != 0) {
			return 0;
		}
		status = NtQuerySystemInformation(SystemProcessInformation, pProcInfoBuffer, procInfoSize, &returnLength);
    
		if(status == 0xC0000004) {
			ZwFreeVirtualMemory((HANDLE)-1, &pProcInfoBuffer, &procInfoSize, MEM_RELEASE);
			procInfoSize += returnLength;
		}

	} while (status != 0);

    RtlInitUnicodeString(&uProcName, procname);
   


    pProcInfo = (PSYSTEM_PROCESSES)pProcInfoBuffer;
    do {
		pProcInfo = (PSYSTEM_PROCESSES)(((LPBYTE)pProcInfo) + pProcInfo->NextEntryDelta);

		if (RtlEqualUnicodeString(&pProcInfo->ProcessName, &uProcName, TRUE)) {
			processes.push_back((DWORD)(DWORD_PTR)pProcInfo->ProcessId);
            parents.push_back((DWORD)(DWORD_PTR)pProcInfo->InheritedFromProcessId);
		}
		if (pProcInfo->NextEntryDelta == 0) {
			break;
		}

	} while (pProcInfo && pProcInfo->NextEntryDelta);

    if(processes.empty()){
        printf("[ChromiumDumper] Chrome is not running\n");
        return 0;
    } 
    parents.sort();
    parents.unique();

    int size = parents.size();
    for(int i=0; i<size; i++){      
        bool found = (std::find(processes.begin(), processes.end(), parents.front()) != processes.end());
        if(found)
            processes.remove(parents.front());
        parents.remove(parents.front());
    }
    size = processes.size();
 
    list<DWORD>::iterator it = processes.begin(); 
    printf("[ChromiumDumper] Found %ws PID(s): [", procname);
    for(int i=0; i<size; i++){

        if(processes.size()-i != 1)
            printf("%i, ", *it);
        else
            printf("%i]. Parents removed.\n", *it);
        advance(it, 1);      
    }

    return 1;
}


int main(int argc, char *argv[])
{   
    char* path;
    char* hFileOut;
    if(argc <2){
        printf("Too few arguments provided.\nUsage:\n       ChromiumDumper.exe <chrome|edge> [Output File]\n");
        return 0;
    }
    FindProcess(L"msedge.exe")
     


    return 1;
}