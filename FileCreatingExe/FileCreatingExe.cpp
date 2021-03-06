// Creating a security descriptor for a new object,

// a registry key and then delete the key...



// #define _WIN32_WINNT 0x0502   // Windows Server 2003 family

// For Win Xp, change accordingly...
#include "stdafx.h"
#define _WIN32_WINNT 0x0501

// #define _WIN32_WINNT 0x0500   // Windows 2000

// #define _WIN32_WINNT 0x0400   // Windows NT 4.0

// #define _WIN32_WINDOWS 0x0500 // Windows ME

// #define _WIN32_WINDOWS 0x0410 // Windows 98

// #define _WIN32_WINDOWS 0x0400 // Windows 95



#include <windows.h>

#include <stdio.h>

#include <aclapi.h>
#include <fstream>
#include <iostream>



// Buffer clean up routine

void Cleanup(PSID pEveryoneSID, PSID pAdminSID, PACL pACL, PSECURITY_DESCRIPTOR pSD, HKEY hkSub)

{

	if (pEveryoneSID)

		FreeSid(pEveryoneSID);

	if (pAdminSID)

		FreeSid(pAdminSID);

	if (pACL)

		LocalFree(pACL);

	if (pSD)

		LocalFree(pSD);

	if (hkSub)

		RegCloseKey(hkSub);

}



int main(int argc, char *argv[])

{
	Sleep(10000);
	DWORD dwRes, dwDisposition;

	PSID pEveryoneSID = NULL, pAdminSID = NULL;

	PACL pACL = NULL;

	PSECURITY_DESCRIPTOR pSD = NULL;

	// An array of EXPLICIT_ACCESS structure

	EXPLICIT_ACCESS ea[2];

	SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;

	SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;

	SECURITY_ATTRIBUTES sa;

	LONG lRes;

	HKEY hkSub = NULL;

	// Create a well-known SID for the Everyone group.

	if (!AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID,

		0, 0, 0, 0, 0, 0, 0, &pEveryoneSID))

	{

		printf("AllocateAndInitializeSid() error %u\n", GetLastError());

		Cleanup(pEveryoneSID, pAdminSID, pACL, pSD, hkSub);

	}

	else

		printf("AllocateAndInitializeSid() for the Everyone group is OK\n");

	// Initialize an EXPLICIT_ACCESS structure for an ACE. The ACE will allow Everyone read access to the key.

	ZeroMemory(&ea, 2 * sizeof(EXPLICIT_ACCESS));

	ea[0].grfAccessPermissions = KEY_READ;

	ea[0].grfAccessMode = SET_ACCESS;

	ea[0].grfInheritance = NO_INHERITANCE;

	ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;

	ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;

	ea[0].Trustee.ptstrName = (LPTSTR)pEveryoneSID;

	// Create a SID for the BUILTIN\Administrators group.

	if (!AllocateAndInitializeSid(&SIDAuthNT, 2, SECURITY_BUILTIN_DOMAIN_RID,

		DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdminSID))

	{

		printf("AllocateAndInitializeSid() error %u\n", GetLastError());

		Cleanup(pEveryoneSID, pAdminSID, pACL, pSD, hkSub);

	}

	else

		printf("AllocateAndInitializeSid() for the BUILTIN\\Administrators group is OK\n");

	// Initialize an EXPLICIT_ACCESS structure for an ACE. The ACE will allow the Administrators group full access to the key.

	ea[1].grfAccessPermissions = KEY_ALL_ACCESS;

	ea[1].grfAccessMode = SET_ACCESS;

	ea[1].grfInheritance = NO_INHERITANCE;

	ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;

	ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;

	ea[1].Trustee.ptstrName = (LPTSTR)pAdminSID;

	// Create a new ACL that contains the new ACEs.

	dwRes = SetEntriesInAcl(2, ea, NULL, &pACL);

	if (dwRes != ERROR_SUCCESS)

	{

		printf("SetEntriesInAcl() error %u\n", GetLastError());

		Cleanup(pEveryoneSID, pAdminSID, pACL, pSD, hkSub);

	}

	else

		printf("SetEntriesInAcl() for the Administrators group is OK\n");

	// Initialize a security descriptor. 

	pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);

	if (pSD == NULL)

	{

		printf("LocalAlloc() error %u\n", GetLastError());

		Cleanup(pEveryoneSID, pAdminSID, pACL, pSD, hkSub);

	}

	else

		printf("LocalAlloc() is OK\n");



	if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))

	{

		printf("InitializeSecurityDescriptor Error %u\n", GetLastError());

		Cleanup(pEveryoneSID, pAdminSID, pACL, pSD, hkSub);

	}

	else

		printf("InitializeSecurityDescriptor() is OK\n");

	// Add the ACL to the security descriptor.

	if (!SetSecurityDescriptorDacl(pSD,

		TRUE,     // bDaclPresent flag  

		pACL,

		FALSE))   // not a default DACL

	{

		printf("SetSecurityDescriptorDacl() Error %u\n", GetLastError());

		Cleanup(pEveryoneSID, pAdminSID, pACL, pSD, hkSub);

	}

	else

		printf("SetSecurityDescriptorDacl() is OK\n");

	// Initialize a security attributes structure.

	sa.nLength = sizeof(SECURITY_ATTRIBUTES);

	sa.lpSecurityDescriptor = pSD;

	sa.bInheritHandle = FALSE;



	//******************* Registry key **********************

	// Use the security attributes to set the security descriptor

	// when you create a registry key.

	// make the subkey as char...

#define MAX_KEY_NAME 255

	//char cname[MAX_KEY_NAME] = "AnotherTestKey";  // Change accordingly...

	HKEY hKey = HKEY_CURRENT_USER; // Change to other key accordingly...


	lRes = RegCreateKeyExW(hKey, // handle to an open key

		L"AnotherTestKey \\ SubTestKey",        // name of the subkey

		0,                 // Reserved, must be 0

		NULL,                // class or object type of this key, may be ignored

		0,                // Options

		KEY_ALL_ACCESS, // Access right for the key

		&sa,              // Pointer to security attribute structure, can be inherited or not. NULL is not inherited

		&hkSub,       // variable that receives a handle to the opened or created key

		&dwDisposition);  // variable that receives:

						  // REG_CREATED_NEW_KEY - create new key (non-exist)

						  // REG_OPENED_EXISTING_KEY - just open the existing key (already exist)

						  // If successful

	if (lRes == 0)

	{

		printf("The value of the \'&dwDisposition\': %u\n", dwDisposition);

		printf("\n----------------\nKey is created\n----------------");

	}

	else

		printf("Creating and opening key failed");

	// TODO: Call other functions such as setting the key values...

	// Just to see the key has been created before it is deleted...

	// You can verify through the regedit/regedt32...

	system("pause");

	// Then delete the subkey...
	//Sleep(12000);
	LONG res = RegDeleteKeyW(

		hKey,      // The key

		L"AnotherTestKey \\ SubTestKey"   // The subkey

	);

	if (res == ERROR_SUCCESS)

		printf("\n----------------\nK ey is deleted\n----------------");

	RegCloseKey(hKey); 
	
	std::cout << "Creating new file : " << std::endl;
	//Sleep(5000);
	std::ofstream ofile;
	ofile.open("C:\\boot-repair\\file.txt");
	ofile << "Hello my name is vaibhav";
	ofile.close();
	
	return 0;
}
