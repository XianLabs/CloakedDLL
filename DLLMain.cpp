#include <Windows.h>
#include <Winternl.h>
#include <stdio.h>

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWCH   Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;

typedef struct _PEB_LDR_DATA
{
	ULONG           Length;
	BOOLEAN         Initialized;
	PVOID           SsHandle;
	LIST_ENTRY      InLoadOrderModuleList;
	LIST_ENTRY      InMemoryOrderModuleList;
	LIST_ENTRY      InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_MODULE
{
	LIST_ENTRY      InLoadOrderModuleList;
	LIST_ENTRY      InMemoryOrderModuleList;
	LIST_ENTRY      InInitializationOrderModuleList;
	PVOID           BaseAddress;
	PVOID           EntryPoint;
	ULONG           SizeOfImage;
	UNICODE_STRING  FullDllName;
	UNICODE_STRING  BaseDllName;
	ULONG           Flags;
	SHORT           LoadCount;
	SHORT           TlsIndex;
	LIST_ENTRY      HashTableEntry;
	ULONG           TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;

void RemovePeHeader(HANDLE GetModuleBase);
void UnlinkModule(char *szModule);

void UnlinkModule(char *szModule)
{
	DWORD dwPEB = 0, dwOffset = 0;
	PLIST_ENTRY pUserModuleHead, pUserModule;
	PPEB_LDR_DATA pLdrData;
	PLDR_MODULE pLdrModule = NULL;
	PUNICODE_STRING lpModule = NULL;
	char szModuleName[512];
	int i = 0, n = 0;

	BYTE* _teb = (BYTE*)__readgsqword(0x30);
	pLdrData = (PPEB_LDR_DATA)(PULONGLONG)(*(PULONGLONG)((*(PULONGLONG)(_teb + 0x60)) + 0x18));


	for (; i < 3; i++)
	{
		switch (i)
		{
		case 0:
			pUserModuleHead = pUserModule = (PLIST_ENTRY)(&(pLdrData->InLoadOrderModuleList));
			dwOffset = 0;
			break;

		case 1:
			pUserModuleHead = pUserModule = (PLIST_ENTRY)(&(pLdrData->InMemoryOrderModuleList));
			dwOffset = sizeof(UINT64)*2;
			break;
		case 2:
			pUserModuleHead = pUserModule = (PLIST_ENTRY)(&(pLdrData->InInitializationOrderModuleList));
			dwOffset = sizeof(UINT64)*4;
			break;
		}

		while (pUserModule->Flink != pUserModuleHead)
		{
			pUserModule = pUserModule->Flink;
			lpModule = (PUNICODE_STRING)(((LONGLONG)(pUserModule)) + (72 - dwOffset));
        
			for (n = 0; n <(lpModule->Length) / 2 && n < 512; n++)
				szModuleName[n] = (CHAR)(*((lpModule->Buffer) + (n)));

			szModuleName[n] = '\0';
			if (strstr(szModuleName, szModule))
			{
				if (!pLdrModule)
					pLdrModule = (PLDR_MODULE)(((LONGLONG)(pUserModule)) - dwOffset);
             
				pUserModule->Blink->Flink = pUserModule->Flink;
				pUserModule->Flink->Blink = pUserModule->Blink;
				printf("Found...\n");
			}
		}
	}

	// Unlink from LdrpHashTable
	if (pLdrModule)
	{
		pLdrModule->HashTableEntry.Blink->Flink = pLdrModule->HashTableEntry.Flink;
		pLdrModule->HashTableEntry.Flink->Blink = pLdrModule->HashTableEntry.Blink;
	}
}

void RemovePeHeader(HANDLE GetModuleBase)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)GetModuleBase;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader + (DWORD)pDosHeader->e_lfanew);

	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
		return;

	if (pNTHeader->FileHeader.SizeOfOptionalHeader)
	{
		DWORD Protect;
		WORD Size = pNTHeader->FileHeader.SizeOfOptionalHeader;
		VirtualProtect((void*)GetModuleBase, Size, PAGE_EXECUTE_READWRITE, &Protect);
		RtlZeroMemory((void*)GetModuleBase, Size);
		VirtualProtect((void*)GetModuleBase, Size, Protect, &Protect);
	}
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		AllocConsole();
		freopen("CON", "w", stdout);
		freopen("CON", "r", stdin);

		//RemovePeHeader causes crash on .NET assemblies - .NET does check on integrity of PE header/image
		CHAR dllName[] = "YourDLL.dll";
		ULONG len = (ULONG)strlen(dllName);
		DisableThreadLibraryCalls(hDLLModule);
		RemovePeHeader(GetModuleHandleA("YourDLL.dll"));
		printf("PE Header removed..\n");
		UnlinkModule(dllName);
		printf("Module unlinked...\n");
		ZeroMemory(dllName, len);
		
	}break;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
