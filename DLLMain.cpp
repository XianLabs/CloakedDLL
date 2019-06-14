#include <Windows.h>
#include <Winternl.h>
#include <Psapi.h> //process watching
#include <stdio.h>

inline PPEB GetPEB() 
{ 
	return (PPEB)__readgsqword(0x60); 
}

VOID CheckSumBaseCloak();

typedef struct _MYPEB {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR Spare;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PEB_LDR_DATA *Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID FastPebLockRoutine;
	PVOID FastPebUnlockRoutine;
	ULONG EnvironmentUpdateCount;
	PVOID* KernelCallbackTable;
	PVOID EventLogSection;
	PVOID EventLog;
	PVOID FreeList;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[0x2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID ReadOnlySharedMemoryHeap;
	PVOID* ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	UCHAR Spare2[0x4];
	ULARGE_INTEGER CriticalSectionTimeout;
	ULONG HeapSegmentReserve;
	ULONG HeapSegmentCommit;
	ULONG HeapDeCommitTotalFreeThreshold;
	ULONG HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID** ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper; //PPS_POST_PREOCESS_INIT_ROUTINE?
	PVOID GdiDCAttributeList;
	PVOID LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	ULONG OSBuildNumber;
	ULONG OSPlatformId;
	ULONG ImageSubSystem;
	ULONG ImageSubSystemMajorVersion;
	ULONG ImageSubSystemMinorVersion;
	ULONG GdiHandleBuffer[0x22];
	PVOID ProcessWindowStation;
} MYPEB, *PMYPEB;


void NTAPI tls_callback(PVOID DllHandle, DWORD dwReason, PVOID Reserved)
{
	if (dwReason == DLL_THREAD_ATTACH)
	{
		CheckSumBaseCloak();
		printf("TLS_CALLBACK: New Thread spawned by process\n");
	}
	else if (dwReason == DLL_PROCESS_ATTACH)
	{
		CheckSumBaseCloak();
		printf("TLS_CALLBACK: Process attached!\n");
	}
}

#pragma comment (linker, "/INCLUDE:_tls_used") 
#pragma comment (linker, "/INCLUDE:tls_callback_func")
#pragma const_seg(".CRT$XLF") //set segment
EXTERN_C const PIMAGE_TLS_CALLBACK tls_callback_func = tls_callback;
#pragma const_seg() //set segment back to .rdata

VOID CheckSumBaseCloak()
{
	PPEB PEB = GetPEB();
	_LIST_ENTRY* f = PEB->Ldr->InMemoryOrderModuleList.Flink;
	UINT64 ProcessBase = (UINT64)GetModuleHandle(NULL);
	bool Found = FALSE;

	PLDR_DATA_TABLE_ENTRY CacheEntry;

	while (!Found)
	{	
		PLDR_DATA_TABLE_ENTRY dataEntry = CONTAINING_RECORD(f, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		
		if (wcsstr(dataEntry->FullDllName.Buffer, L"CloakDLLExample.dll") != NULL)
		{
			dataEntry->CheckSum = 0x123456; //seems to successfully cloak from non-admin mode protections, more methods to come soon
			dataEntry->DllBase = 0x0;
			wprintf(L"%s, %llX\n", dataEntry->FullDllName.Buffer, (UINT64)dataEntry->DllBase);
			Found = TRUE;		
			return;
		}

		f = dataEntry->InMemoryOrderLinks.Flink;
	}
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ulReason, LPVOID lpReserved) {
	
	// Get rid of compiler warnings since we do not use this parameter
	UNREFERENCED_PARAMETER(lpReserved);

	switch (ulReason) {

	case DLL_PROCESS_ATTACH:

		CheckSumBaseCloak();
		MessageBoxA(0, "DLL Locked and Loaded.", "DLL Injection Works!", 0);
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	}

	return (TRUE);
}
