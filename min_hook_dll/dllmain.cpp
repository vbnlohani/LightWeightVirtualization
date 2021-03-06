// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <iostream>
#include <fstream>
#include <conio.h>
#include <stdlib.h>
#include <typeinfo>
#include <string.h>
#include "MinHook.h"

// #include "min_hook_dll.cpp"

#define BUFSIZE MAX_PATH

// Helper function for MH_CreateHook().
template <typename T>
inline MH_STATUS MH_CreateHookHelper(LPVOID pTarget, LPVOID pDetour, T** ppOriginal)
{
	std::cout << "/*/*/*/*/*/*/*/*/*/*/*/*/" << std::endl;
	return MH_CreateHook(pTarget, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
}

typedef struct _UNICODE_STRING {
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
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef LONG(WINAPI *NTOPENFILE)(OUT PHANDLE FileHandle, IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock, IN ULONG ShareAccess,
	IN ULONG OpenOptions);


typedef LONG(WINAPI *NTCREATEFILE)(OUT PHANDLE FileHandle, IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes, OUT PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER AllocationSize, IN ULONG FileAttributes, IN ULONG ShareAccess,
	IN ULONG CreateDisposition, IN ULONG CreateOptions, IN PVOID EaBuffer,
	IN ULONG EaLength);

NTOPENFILE fpNtOpenFile = NULL;
NTCREATEFILE fpNtCreateFile = NULL;

// Replacement Function for NtOpenFile
LONG WINAPI MyNtOpenFile(OUT PHANDLE FileHandle, IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes, OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess, IN ULONG OpenOptions) {

	std::cout << "OIn NtOpenFile" << std::endl;

	DWORD dwRet;
	TCHAR path[BUFSIZE];

	if ((ObjectAttributes->RootDirectory) != NULL) {
		dwRet = GetFinalPathNameByHandle((ObjectAttributes->RootDirectory), path, BUFSIZE, VOLUME_NAME_DOS);

		if (dwRet < BUFSIZE) {
			std::cout << "OPath : " << path << std::endl;
		}

		else {
			std::cout << "OThe required buffer size is" << dwRet << std::endl;
		}
	}

	else {
		std::cout << "ORoot Directory NULL" << std::endl;
	}

	std::wcout << "OObject Attributes : " << (ObjectAttributes->ObjectName->Buffer) << std::endl;

	return fpNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
		ShareAccess, OpenOptions);
}

// Replacement Function for NtCreateFIle
LONG WINAPI MyNtCreateFile(OUT PHANDLE FileHandle, IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes, OUT PIO_STATUS_BLOCK IoStatusBlock,
	_In_opt_ PLARGE_INTEGER AllocationSize, IN ULONG FileAttributes, IN ULONG ShareAccess,
	IN ULONG CreateDisposition, IN ULONG CreateOptions, IN PVOID EaBuffer,
	IN ULONG EaLength) {

	std::cout << "CIn NtCreateFile" << std::endl;

	DWORD dwRet;
	WCHAR path[BUFSIZE];
	WCHAR *t1;
	WCHAR *t2;

	WCHAR dir_path[BUFSIZE];
	size_t len;

	if ((ObjectAttributes->RootDirectory) != NULL) {
		//dwRet = GetFinalPathNameByHandleA((ObjectAttributes->RootDirectory), path, BUFSIZE, VOLUME_NAME_DOS);
		dwRet = GetFinalPathNameByHandleW((ObjectAttributes->RootDirectory), path, BUFSIZE, VOLUME_NAME_DOS);

		len = wcslen(path);

		if (dwRet < BUFSIZE) {
			std::wcout << "CPath : " << path << std::endl;


			t1 = wcschr(path, '\\');
			t1++;
			t1 = wcschr(t1, '\\');
			t1++;
			t1 = wcschr(t1, '\\');

			wcsncpy_s(dir_path, path, t1 - path);
			wcscat_s(dir_path, L"\\C:\\VM");

			//wcout << "Occurence : " << t1 << endl;
			//wcout << "Dirpath : " << dir_path << endl;

			CreateDirectoryW(dir_path, NULL);
			t1++;
			t2 = wcschr(t1, '\\');
			wcscat_s(dir_path, L"\\");
			wcsncat_s(dir_path, t1, t2 - 1 - t1);
			std::wcout << "Again dirpath : " << dir_path << std::endl;
			CreateDirectoryW(dir_path, NULL);

			while (*(t2) != '\0') {
				t1 = t2;
				t1++;
				t2 = wcschr(t1, '\\');

				if (t2 != NULL) {
					wcscat_s(dir_path, L"\\");
					wcsncat_s(dir_path, t1, t2 - t1);
				}

				else {
					t2 = &(path[len - 1]);
					t2++;
					wcscat_s(dir_path, L"\\");
					wcsncat_s(dir_path, t1, t2 - t1);
				}

				CreateDirectoryW(dir_path, NULL);
			}

			wcscat_s(dir_path, L"\\");
			wcscat_s(dir_path, (ObjectAttributes->ObjectName->Buffer));
			wcscat_s(path, L"\\");
			wcscat_s(path, (ObjectAttributes->ObjectName->Buffer));
			std::wcout << "Again virtual dirpath : " << dir_path << std::endl;
			std::wcout << "Again original dirpath : " << path << std::endl;
			/*BOOL WINAPI CopyFile(
			_In_ LPCTSTR path,
			_In_ LPCTSTR dir_path,
			_In_ BOOL    bFailIfExists
			);	*/

			std::ifstream f_src(path, std::ios::in | std::ios::app);
			f_src.seekg(0, std::ios::end);
			int length = f_src.tellg();
			f_src.seekg(0, std::ios::beg);
			std::string filecont;
			filecont.resize(length);
			f_src.read(&filecont[0], length);
			f_src.close();
			std::ofstream f_dest(dir_path, std::ios::binary);
			f_dest.write(&filecont[0], length);
			f_dest.close();
			/*CHAR ch;
			while (!f_src.eof())
			{
			f_src.get(ch);
			f_dest << ch;
			}
			f_dest.close();
			f_src.close();
			filebuf infile, outfile;
			infile.open(dir_path, ios::in | ios::binary);
			outfile.open(path, ios::out | ios::binary);
			copy(istreambuf_iterator<char>(&infile), {}, ostreambuf_iterator<char>(&outfile));*/
		}

		else {
			std::cout << "CThe required buffer size is" << dwRet << std::endl;
		}
	}

	else {
		std::cout << "CRoot Directory NULL" << std::endl;
	}

	//cout << "FileHandle : " << FileHandle << endl;
	//cout << "DesiredAccess : " << DesiredAccess << endl;
	std::wcout << "CObject Attributes : " << (ObjectAttributes->ObjectName->Buffer) << std::endl;
	//cout << "IoStatusBlock : " << IoStatusBlock << endl;
	//cout << "CreateDisposition : " << CreateDisposition << endl;
	//cout << "CreateOptions : " << CreateOptions << endl;
	//cout << "EaBuffer : " << EaBuffer << endl;
	//cout << "EaLength : " << EaLength << endl;
	//cout << "AllocationSize : " << AllocationSize << endl;
	//cout << "FileAttributes : " << FileAttributes << endl;
	//cout << "ShareAccess : " << ShareAccess << endl;

	return fpNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
		AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
		CreateOptions, EaBuffer, EaLength);
}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {

	MessageBoxW(NULL, L"Coming till here", L"Coming till here", MB_OK);
	LPVOID pTarget_1;
	LPVOID pTarget_2;
	HMODULE moduleHandle;

	moduleHandle = GetModuleHandleW(L"ntdll");

	pTarget_1 = (LPVOID)GetProcAddress(moduleHandle, "NtOpenFile");
	pTarget_2 = (LPVOID)GetProcAddress(moduleHandle, "NtCreateFile");

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		std::cout << "Coming till here" << std::endl;
		system("cls");

		// Initialize Minhook
		if (MH_Initialize() != MH_OK) {
			return 1;
		}

		// Get address of actual NtOpenProcess
		if (hModule == NULL)
			return MH_ERROR_MODULE_NOT_FOUND;

		// Hooking the file open system call
		if (MH_CreateHookHelper(pTarget_1, &MyNtOpenFile, &fpNtOpenFile) != MH_OK) {
			return 1;
		}

		// Hooking the file create system call
		if (MH_CreateHookHelper(pTarget_2, &MyNtCreateFile, &fpNtCreateFile) != MH_OK) {
			return 1;
		}

		// Enabling the hook for open file
		if (MH_EnableHook(pTarget_1) != MH_OK) {
			return 1;
		}

		// Enabling the hook for create file
		if (MH_EnableHook(pTarget_2) != MH_OK) {
			return 1;
		}
		return 0;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
		// Disable the hook for open file
		if (MH_DisableHook(pTarget_1) != MH_OK) {
			return 1;
		}

		// Disable the hook for create file
		if (MH_DisableHook(pTarget_2) != MH_OK) {
			return 1;
		}

		// Uninitialize MinHook.
		if (MH_Uninitialize() != MH_OK) {
			return 1;
		}

        break;
    }
    return TRUE;
}

