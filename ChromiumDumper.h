#pragma once
#include "Windows.h"  

typedef NTSTATUS (NTAPI* ZWALLOCATEVIRTUALMEMORY)(
    HANDLE ProcessHandle, 
    PVOID *BaseAddress, 
    ULONG_PTR ZeroBits, 
    PSIZE_T RegionSize, 
    ULONG AllocationType, 
    ULONG Protect
    );

typedef NTSTATUS(NTAPI* NTQUERYSYSTEMINFORMATION)(
	ULONG SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength);

typedef NTSTATUS(NTAPI* ZWFREEVIRTUALMEMORY)(
  HANDLE  ProcessHandle,
  PVOID   *BaseAddress,
  PSIZE_T RegionSize,
  ULONG   FreeType
);
typedef struct _FILE_NAME_INFORMATION {
  ULONG FileNameLength;
  WCHAR FileName[1];
} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;

typedef NTSTATUS(NTAPI* NTQUERYINFORMATIONPROCESS)(
  HANDLE                 FileHandle,
  PIO_STATUS_BLOCK       IoStatusBlock,
  PVOID                  FileInformation,
  ULONG                  Length,
  FILE_INFORMATION_CLASS FileInformationClass
);

typedef VOID(WINAPI* RTLINITUNICODESTRING)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);

typedef BOOLEAN(NTAPI* RTLEQUALUNICODESTRING)(
	PUNICODE_STRING String1,
	PCUNICODE_STRING String2,
	BOOLEAN CaseInSensitive
	);


struct OBJECT_NAME_INFORMATION 
{
    UNICODE_STRING Name; // defined in winternl.h
    WCHAR NameBuffer;
};	
typedef NTSTATUS (NTAPI* t_NtQueryObject)(HANDLE Handle, OBJECT_INFORMATION_CLASS Info, PVOID Buffer, ULONG BufferSize, PULONG ReturnLength); 
// handle information
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

// handle table information
typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_PROCESSES {
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	ULONG Reserved1[6];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	KPRIORITY BasePriority;
	HANDLE ProcessId;
	HANDLE InheritedFromProcessId;
} SYSTEM_PROCESSES, * PSYSTEM_PROCESSES;