// NewDll.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include <Windows.h>
#include <Winternl.h>
#include <iostream>
#include <fstream>
#include <string>
#include "MinHook.h"
#include "NewDll.h"
//#include <aclapi.h>
//#define _WIN32_WINNT 0x0501
//#include <aclapi.h>

#define BUFSIZE MAX_PATH

using namespace std;

HMODULE moduleHandle = GetModuleHandleW(L"ntdll");
LPVOID pTarget_1 = (LPVOID)GetProcAddress(moduleHandle, "NtOpenFile");
LPVOID pTarget_2 = (LPVOID)GetProcAddress(moduleHandle, "NtCreateFile");

HMODULE moduleHandle2 = GetModuleHandleW(L"advapi32.dll");
LPVOID pTarget_3 = (LPVOID)GetProcAddress(moduleHandle2, "RegCreateKeyExW");
LPVOID ptarget_4 = (LPVOID)GetProcAddress(moduleHandle2, "RegDeleteKeyW");
LPVOID ptarget_5 = (LPVOID)GetProcAddress(moduleHandle2, "RegSetValueEx");


int target_module_index = 1;
// Helper function for MH_CreateHook().
template <typename T>
inline MH_STATUS MH_CreateHookHelper(LPVOID pTarget, LPVOID pDetour, T** ppOriginal)
{

	std::cout << "\n" << std::endl;
	std::cout << "CreateHookHelper is called for ptarget_" << target_module_index << std::endl;
	target_module_index++;
	return MH_CreateHook(pTarget, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
}

// Helper for cleaning path string 
void CleanPath(WCHAR *path) {
	int i;
	int j = 0;
	int len = wcslen(path);

	for (i = 0; i <= len; i++) {
		if (path[i] != ':' && path[i] != '?' && path[i] != '\"' && path[i] != '<' && path[i] != '>'
			&& path[i] != '|') {

			// First character should be always alphabet
			if (j == 0) {
				if (isalpha(path[i])) {
					path[j] = path[i];
					j++;
				}
			}

			else {
				path[j] = path[i];
				j++;
			}
		}
	}

	wcout << "Cleaned path : " << path << endl;
}

/*typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
	union {
		LONG Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;*/

typedef LONG(WINAPI *NTOPENFILE)(OUT PHANDLE FileHandle, IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock, IN ULONG ShareAccess,
	IN ULONG OpenOptions);


typedef LONG(WINAPI *NTCREATEFILE)(OUT PHANDLE FileHandle, IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes, OUT PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER AllocationSize, IN ULONG FileAttributes, IN ULONG ShareAccess,
	IN ULONG CreateDisposition, IN ULONG CreateOptions, IN PVOID EaBuffer,
	IN ULONG EaLength);


typedef LONG(WINAPI *REGCREATEKEYEXW)(_In_       HKEY                  hKey,
	_In_       LPCTSTR               lpSubKey,
	_Reserved_ DWORD                 Reserved,
	_In_opt_   LPTSTR                lpClass,
	_In_       DWORD                 dwOptions,
	_In_       REGSAM                samDesired,
	_In_opt_   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_Out_      PHKEY                 phkResult,
	_Out_opt_  LPDWORD               lpdwDisposition);

typedef LONG(WINAPI *REGSETVALUEEXW)(_In_             HKEY    hKey,
	_In_opt_         LPCTSTR lpValueName,
	_Reserved_       DWORD   Reserved,
	_In_             DWORD   dwType,
	_In_       const BYTE    *lpData,
	_In_             DWORD   cbData);

typedef LONG(WINAPI *REGDELETEKEYW)(_In_ HKEY    hKey,
	_In_ LPCTSTR lpSubKey);

NTOPENFILE fpNtOpenFile = NULL;
NTCREATEFILE fpNtCreateFile = NULL;

REGCREATEKEYEXW fpRegCreateKeyExW = NULL;
REGSETVALUEEXW fpRegSetValueExW = NULL;
REGDELETEKEYW fpRegDeleteKeyW = NULL;

// Replacement Function for NtOpenFile
NTSTATUS WINAPI MyNtOpenFile(OUT PHANDLE FileHandle, IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes, OUT PIO_STATUS_BLOCK IoStatusBlock, IN ULONG ShareAccess,
	IN ULONG OpenOptions) {

	/*cout << "OIn NtOpenFile" << endl;

	DWORD dwRet;
	TCHAR path[BUFSIZE];

	if ((ObjectAttributes->RootDirectory) != NULL) {
	dwRet = GetFinalPathNameByHandle((ObjectAttributes->RootDirectory), path, BUFSIZE, VOLUME_NAME_DOS);

	if (dwRet < BUFSIZE) {
	cout << "OPath : " << path << endl;
	}

	else {
	cout << "OThe required buffer size is" << dwRet << endl;
	}
	}

	else {
	cout << "ORoot Directory NULL" << endl;
	}

	wcout << "OObject Attributes : " << (ObjectAttributes->ObjectName->Buffer) << endl;
	*/

	//return fpNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
	//ShareAccess, OpenOptions);

	static BOOL isRecursive = FALSE;

	if (!isRecursive) {
		cout << "OIn NtOpenFile" << endl;

		LONG ret_value;
		HANDLE dir_handle;
		DWORD dwRet;
		WCHAR path[BUFSIZE] = L"\0";
		WCHAR cleaned_path[BUFSIZE] = L"\0";
		WCHAR dir_path[BUFSIZE] = L"\0";
		WCHAR virtual_file_path[BUFSIZE] = L"\0";
		WCHAR temp[BUFSIZE] = L"\0";
		WCHAR *t1 = NULL;
		WCHAR *t2 = NULL;

		int len = 0;
		int i;
		bool ret;

		if ((ObjectAttributes->RootDirectory) != NULL) {
			//dwRet = GetFinalPathNameByHandleA((ObjectAttributes->RootDirectory), path, BUFSIZE, VOLUME_NAME_DOS);
			dwRet = GetFinalPathNameByHandleW((ObjectAttributes->RootDirectory), path, BUFSIZE, VOLUME_NAME_DOS);
			len = wcslen(path);
			wcout << "Root Directory Path : " << path << endl;

			if (dwRet >= BUFSIZE) {
				cout << "OThe required buffer size is" << dwRet << endl;
				cout << "Not enough buffer";
				return NULL;
			}
		}

		else {
			cout << "ORoot Directory NULL" << endl;
		}

		/* ================== Extracting the path from ObjecAttribute ==================*/

		wcout << "OPath : " << path << endl;
		if (len > 0 && path[len - 1] != '\\') {
			wcscat_s(path, L"\\");
		}

		wcscat_s(path, ObjectAttributes->ObjectName->Buffer);

		wcout << "Concatenated Path : " << path << endl;
		wcscpy_s(cleaned_path, path);
		CleanPath(cleaned_path);

		t1 = wcsrchr(path, '.');
		t1++;

		if (wcscmp(t1, L"txt") == 0) {

			/* =============== Creating Directory structure for new file in VM ===================== */

			wcscpy_s(dir_path, L"\\\\?\\");
			wcscat_s(dir_path, L"C:\\VM");


			wcout << "Dirpath : " << dir_path << endl;

			isRecursive = TRUE;
			CreateDirectoryW(dir_path, NULL);
			isRecursive = FALSE;
			//OriginalCreateDirWrapper(dir_path);

			t1 = cleaned_path;
			t2 = wcschr(t1, '\\');

			while (t2 != NULL) {
				wcout << "t1 : " << t1 << endl;
				wcout << "t2 : " << t2 << endl;

				wcscat_s(dir_path, L"\\");
				wcsncat_s(dir_path, t1, t2 - t1);

				isRecursive = TRUE;
				CreateDirectoryW(dir_path, NULL);
				isRecursive = FALSE;

				wcout << "While dir_path : " << dir_path << endl;

				t1 = t2 + 1;
				t2 = wcschr(t1, '\\');
			}

			wcscpy_s(virtual_file_path, dir_path);
			wcscat_s(virtual_file_path, L"\\");
			wcscat_s(virtual_file_path, t1);

			/* Checking if file already exists*/
			if (GetFileAttributes(path) != INVALID_FILE_ATTRIBUTES) {

				/* Copy the file into VM*/
				isRecursive = TRUE;
				ifstream f_src(path, ios::in);
				isRecursive = FALSE;

				f_src.seekg(0, ios::end);
				int length = f_src.tellg();
				f_src.seekg(0, ios::beg);
				string filecont;
				filecont.resize(length);
				f_src.read(&filecont[0], length);
				f_src.close();
				cout << "Data : " << filecont;
				isRecursive = TRUE;
				ofstream f_dest(virtual_file_path, ios::binary);
				isRecursive = FALSE;

				f_dest.write(&filecont[0], length);
				f_dest.close();
			}

			/* Manipulating the structure ObjectAttributes */

			/*isRecursive = TRUE;
			dir_handle = CreateFile(dir_path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL,OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

			isRecursive = FALSE;

			isRecursive = TRUE;
			GetFinalPathNameByHandleW(dir_handle, temp, BUFSIZE, VOLUME_NAME_DOS);
			isRecursive = FALSE;*/

			t1 = virtual_file_path;

			for (i = 0; i < 3; i++) {
				t1 = wcschr(t1, L'\\');
				t1++;
			}

			wcout << "T1 : " << t1 << endl;

			wcscpy_s(temp, t1);
			wcscpy_s(virtual_file_path, L"\\??\\");
			wcscat_s(virtual_file_path, temp);

			wcout << "Virtual file path : " << virtual_file_path << endl;
			ObjectAttributes->ObjectName->Buffer = virtual_file_path;
			ObjectAttributes->ObjectName->Length = wcslen(virtual_file_path) * 2;
			wcout << "Object Attributes now : " << (ObjectAttributes->ObjectName->Buffer) << endl;


			ret = fpNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
				ShareAccess, OpenOptions);

			if (NT_ERROR(ret)) {
				cout << "Call Error" << endl;
			}
			else if (NT_SUCCESS(ret)) {
				cout << "Call Success" << endl;
			}

			return ret;
		}

	}

	else {

		DWORD dwRet;
		WCHAR path[BUFSIZE];

		if ((ObjectAttributes->RootDirectory) != NULL) {
			dwRet = GetFinalPathNameByHandle((ObjectAttributes->RootDirectory), path, BUFSIZE, VOLUME_NAME_DOS);

			if (dwRet < BUFSIZE) {
				cout << "OEPath : " << path << endl;
			}

			else {
				cout << "OEThe required buffer size is" << dwRet << endl;
			}
		}

		else {
			cout << "OERoot Directory NULL" << endl;
		}

		wcout << "OEObject Attributes : " << (ObjectAttributes->ObjectName->Buffer) << endl;

		return fpNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
			ShareAccess, OpenOptions);
	}
}

// Replacement Function for NtCreateFIle
NTSTATUS WINAPI MyNtCreateFile(OUT PHANDLE FileHandle, IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes, OUT PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER AllocationSize, IN ULONG FileAttributes, IN ULONG ShareAccess,
	IN ULONG CreateDisposition, IN ULONG CreateOptions, IN PVOID EaBuffer,
	IN ULONG EaLength) {

	static BOOL isRecursive = FALSE;

	if (!isRecursive) {

		cout << "CIn NtCreateFile" << endl;

		NTSTATUS ret_value;
		HANDLE dir_handle;
		DWORD dwRet;
		WCHAR path[BUFSIZE] = L"\0";
		WCHAR cleaned_path[BUFSIZE] = L"\0";
		WCHAR dir_path[BUFSIZE] = L"\0";
		WCHAR virtual_file_path[BUFSIZE] = L"\0";
		WCHAR temp[BUFSIZE] = L"\0";
		WCHAR *t1 = NULL;
		WCHAR *t2 = NULL;

		int len = 0;
		int i;
		bool ret;

		if ((ObjectAttributes->RootDirectory) != NULL) {
			cout << "RootDirectory : " << (ObjectAttributes->RootDirectory) << endl;
			//dwRet = GetFinalPathNameByHandleA((ObjectAttributes->RootDirectory), path, BUFSIZE, VOLUME_NAME_DOS);
			//isRecursive = TRUE;
			dwRet = GetFinalPathNameByHandleW((ObjectAttributes->RootDirectory), path, BUFSIZE, VOLUME_NAME_DOS);
			//isRecursive = FALSE;

			len = wcslen(path);
			wcout << "Root Directory Path : " << path << endl;

			if (dwRet == 0) {
				cout << "Error : " << GetLastError() << endl;
			}

			else if (dwRet >= BUFSIZE) {
				cout << "CThe required buffer size is" << dwRet << endl;
				cout << "Not enough buffer";
				return NULL;
			}
		}

		else {
			cout << "CRoot Directory NULL" << endl;
		}

		wcout << "Object Attributes initially : " << (ObjectAttributes->ObjectName->Buffer) << endl;

		/* ================== Extracting the path from ObjecAttribute ==================*/

		wcout << "CPath : " << path << endl;
		if (len > 0 && path[len - 1] != '\\') {
			wcscat_s(path, L"\\");
		}

		wcscat_s(path, ObjectAttributes->ObjectName->Buffer);

		wcout << "Concatenated Path : " << path << endl;
		wcscpy_s(cleaned_path, path);
		CleanPath(cleaned_path);

		t1 = wcsrchr(path, '.');
		t1++;

		if (wcscmp(t1, L"txt") == 0) {
			/* =============== Creating Directory structure for new file in VM ===================== */

			wcscpy_s(dir_path, L"\\\\?\\");
			wcscat_s(dir_path, L"C:\\VM");


			wcout << "Dirpath : " << dir_path << endl;

			isRecursive = TRUE;
			CreateDirectoryW(dir_path, NULL);
			isRecursive = FALSE;
			//OriginalCreateDirWrapper(dir_path);

			t1 = cleaned_path;
			t2 = wcschr(t1, '\\');

			while (t2 != NULL) {
				wcout << "t1 : " << t1 << endl;
				wcout << "t2 : " << t2 << endl;

				wcscat_s(dir_path, L"\\");
				wcsncat_s(dir_path, t1, t2 - t1);

				isRecursive = TRUE;
				CreateDirectoryW(dir_path, NULL);
				isRecursive = FALSE;

				wcout << "While dir_path : " << dir_path << endl;

				t1 = t2 + 1;
				t2 = wcschr(t1, '\\');
			}

			wcscpy_s(virtual_file_path, dir_path);
			wcscat_s(virtual_file_path, L"\\");
			wcscat_s(virtual_file_path, t1);

			/* Checking if file already exists*/
			if (GetFileAttributes(path) != INVALID_FILE_ATTRIBUTES) {

				/* Copy the file into VM*/
				/*isRecursive = TRUE;
				ifstream f_src(path, ios::in);
				isRecursive = FALSE;

				f_src.seekg(0, ios::end);
				int length = f_src.tellg();
				f_src.seekg(0, ios::beg);
				string filecont;
				filecont.resize(length);
				f_src.read(&filecont[0], length);
				f_src.close();
				cout << "Data : " << filecont;
				isRecursive = TRUE;
				ofstream f_dest(virtual_file_path, ios::binary);
				isRecursive = FALSE;

				f_dest.write(&filecont[0], length);
				f_dest.close();*/
				isRecursive = TRUE;
				CopyFileW(path, virtual_file_path, FALSE);
				isRecursive = FALSE;
			}

			/* Manipulating the structure ObjectAttributes */

			/*isRecursive = TRUE;
			dir_handle = CreateFile(dir_path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL,OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

			isRecursive = FALSE;

			isRecursive = TRUE;
			GetFinalPathNameByHandleW(dir_handle, temp, BUFSIZE, VOLUME_NAME_DOS);
			isRecursive = FALSE;*/

			t1 = virtual_file_path;

			for (i = 0; i < 3; i++) {
				t1 = wcschr(t1, L'\\');
				t1++;
			}

			wcout << "T1 : " << t1 << endl;

			wcscpy_s(temp, t1);
			wcscpy_s(virtual_file_path, L"\\??\\");
			wcscat_s(virtual_file_path, temp);

			wcout << "Virtual file path : " << virtual_file_path << endl;
			ObjectAttributes->ObjectName->Buffer = virtual_file_path;
			ObjectAttributes->ObjectName->Length = wcslen(virtual_file_path) * 2;
			wcout << "Object Attributes now : " << (ObjectAttributes->ObjectName->Buffer) << endl;


			ret = fpNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
				AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
				CreateOptions, EaBuffer, EaLength);

			if (NT_ERROR(ret)) {
				cout << "Call Error" << endl;
			}
			else if (NT_SUCCESS(ret)) {
				cout << "Call Success" << endl;
			}

			return ret;
		}

	}

	else {
		/*DWORD dwRet;
		WCHAR path[BUFSIZE];

		if ((ObjectAttributes->RootDirectory) != NULL) {
		dwRet = GetFinalPathNameByHandle((ObjectAttributes->RootDirectory), path, BUFSIZE, VOLUME_NAME_DOS);

		if (dwRet < BUFSIZE) {
		cout << "EPath : " << path << endl;
		}

		else {
		cout << "EThe required buffer size is" << dwRet << endl;
		}
		}

		else {
		cout << "ERoot Directory NULL" << endl;
		}

		wcout << "EObject Attributes : " << (ObjectAttributes->ObjectName->Buffer) << endl;*/

		return fpNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
			AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
			CreateOptions, EaBuffer, EaLength);
	}

	/*WCHAR path[BUFSIZE] = L"\0";
	DWORD dwRet;
	cout << "In NtCreateFile : " << endl;
	cout << "Root Directory : " << (ObjectAttributes->RootDirectory) << endl;
	wcout << "Object Attributes : " << (ObjectAttributes->ObjectName->Buffer) << endl;
	//dwRet = GetFinalPathNameByHandleW((ObjectAttributes->RootDirectory), path, BUFSIZE, VOLUME_NAME_DOS);

	if (dwRet == 0) {
	cout << "Error : " << GetLastError() << endl;
	}
	else if (dwRet > BUFSIZE) {
	cout << "Buffer size greater" << endl;
	}
	else {
	wcout << "Path : " << path << endl;
	}

	return fpNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
	AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
	CreateOptions, EaBuffer, EaLength);*/
}

NTSTATUS WINAPI MyRegCreateKeyExW(_In_       HKEY                  hKey,
	_In_       LPCTSTR               lpSubKey,
	_Reserved_ DWORD                 Reserved,
	_In_opt_   LPTSTR                lpClass,
	_In_       DWORD                 dwOptions,
	_In_       REGSAM                samDesired,
	_In_opt_   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	_Out_      PHKEY                 phkResult,
	_Out_opt_  LPDWORD               lpdwDisposition) {

	std::cout << "\nIn MyRegCreateKeyExW\n=====================" << std::endl;

	HKEY new_hKey = HKEY_LOCAL_MACHINE;
	std::wstring mywstring(lpSubKey);
	std::wstring concatted_stdstr = L"Virtual_Registry \\ " + mywstring;
	lpSubKey = concatted_stdstr.c_str();
	std::wcout << "\n\nKEY IS " << lpSubKey << "\n\n" << std::endl;
	return fpRegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
}

NTSTATUS WINAPI MyRegSetValueExW(_In_             HKEY    hKey,
	_In_opt_         LPCTSTR lpValueName,
	_Reserved_       DWORD   Reserved,
	_In_             DWORD   dwType,
	_In_       const BYTE    *lpData,
	_In_             DWORD   cbData) {

	return fpRegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}

NTSTATUS WINAPI MyRegDeleteKeyW(_In_ HKEY    hKey,
	_In_ LPCTSTR lpSubKey) {
	std::cout << "\nIn MyRegDeleteKeyW\n====================" << std::endl;

	HKEY new_hKey = HKEY_LOCAL_MACHINE;
	std::wstring mywstring(lpSubKey);
	std::wstring concatted_stdstr = L"Virtual_Registry \\ " + mywstring;
	lpSubKey = concatted_stdstr.c_str();
	std::wcout << "\n\nKEY IS " << lpSubKey << "\n\n" << std::endl;
	return fpRegDeleteKeyW(hKey, lpSubKey);
}
// Define main hoooking functions
int create_hooks() {

	MessageBoxW(NULL, L"Creating Hooks", L"Creating Hooks", MB_OK);
	//system("cls");

	// Initialize Minhook
	if (MH_Initialize() != MH_OK) {
		return 11;
	}

	// Get address of actual NtOpenProcess
	if (moduleHandle == NULL)
		return MH_ERROR_MODULE_NOT_FOUND;

	if (moduleHandle2 == NULL)
		return MH_ERROR_MODULE_NOT_FOUND;

	if (MH_CreateHookHelper(ptarget_4, &MyRegDeleteKeyW, &fpRegDeleteKeyW) != MH_OK) {
		return 4;
	}
	if (MH_CreateHookHelper(pTarget_3, &MyRegCreateKeyExW, &fpRegCreateKeyExW) != MH_OK) {
		return 3;
	}

	// Hooking the file open system call
	if (MH_CreateHookHelper(pTarget_1, &MyNtOpenFile, &fpNtOpenFile) != MH_OK) {
		return 1;
	}

	// Hooking the file create system call
	if (MH_CreateHookHelper(pTarget_2, &MyNtCreateFile, &fpNtCreateFile) != MH_OK) {
		return 2;
	}
	
	/*
	if (MH_CreateHookHelper(ptarget_5, &MyRegSetValueExW, &fpRegSetValueExW) != MH_OK) {
	return 5;
	}*/
	
	if (MH_EnableHook(pTarget_3) != MH_OK) {
		return -3;
	}

	/*if (MH_EnableHook(ptarget_5) != MH_OK) {
		return -5;
	}*/

	if (MH_EnableHook(ptarget_4) != MH_OK) {
		return -4;
	}

	//Sleep(7000);

	// Enabling the hook for open file
	if (MH_EnableHook(pTarget_1) != MH_OK) {
		return -1;
	}

	// Enabling the hook for create file
	if (MH_EnableHook(pTarget_2) != MH_OK) {
		return -2;
	}
	
	return 0;
}

int destroy_hooks() {
	// Disable the hook for open file
	if (MH_DisableHook(pTarget_1) != MH_OK) {
		return 1;
	}

	// Disable the hook for create file
	if (MH_DisableHook(pTarget_2) != MH_OK) {
		return 1;
	}
	/*if (MH_DisableHook(pTarget_3) != MH_OK) {
		return 1;
	}
	 if (MH_DisableHook(ptarget_5) != MH_OK) {
	 return 1;
	 }
	if (MH_DisableHook(ptarget_4) != MH_OK) {
		return 1;
	}*/
	// Uninitialize MinHook.
	if (MH_Uninitialize() != MH_OK) {
		return 1;
	}

	return 0;
}