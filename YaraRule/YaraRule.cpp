#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <yara.h>
#include <stdio.h>
#include <string>
#include <fstream>
#include <streambuf>
#include <vector>
#include <system_error>
#include <algorithm>
#include <filesystem>

#include <unordered_map>
#include <thread>
#include <tchar.h>

#define MAX_PATH_EX 512

void GetMyPath(wchar_t* wtr)
{
	GetModuleFileName(GetModuleHandle(NULL), wtr, MAX_PATH_EX);
	for (int i = (int)wcslen(wtr) - 1; i >= 0; i--)
	{
		if (wtr[i] == '\\')
		{
			wtr[i] = '\x0';
			break;
		}
	}
}

bool hasMatched = false;

class YaraManger {
public:
	YaraManger() {
		// Step 1: Initialize YARA
		if (yr_initialize() != ERROR_SUCCESS)
		{
			std::cerr << "Failed to initialize YARA." << std::endl;
		}
		// Step 2: Create a YARA compiler
		if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
		{
			std::cerr << "Failed to create YARA compiler." << std::endl;
			yr_finalize();
		}
	}
	~YaraManger() {
		// Clean up resources
		yr_rules_destroy(rules);
		yr_compiler_destroy(compiler);
		yr_finalize();
	}

	bool AddRuleFromFile(std::string file_name)
	{
		// Step 3: Add YARA rules to the compiler
		FILE* rule_file = NULL;
		rule_file = fopen(file_name.c_str(), "r");
		if (!rule_file)
		{
			std::cerr << "Failed to open file: " << file_name << std::endl;
			return FALSE;
		}
		if (yr_compiler_add_file(compiler, rule_file, NULL, file_name.c_str()) != ERROR_SUCCESS)
		{
			std::cerr << "Failed to add YARA rule %s." << file_name << std::endl;
			return FALSE;
		}
		printf("_ Added %s!\n", file_name.c_str());

		return TRUE;
	}

	//BOOL AddRulesFromDirectory(std::string rule_directory)
	//{
	//	int file_count = 0;
	//	int success_count = 0;
	//	for (const auto& dirEntry : std::filesystem::recursive_directory_iterator(rule_directory))
	//	{
	//		if (".yar" != dirEntry.path().extension() and ".yara" != dirEntry.path().extension())
	//		{
	//			continue;
	//		}
	//		if (AddRuleFromFile(dirEntry.path().string()))
	//		{
	//			success_count++;
	//		}
	//		file_count++;
	//	}

	//	printf("\\_ Added %ld/%ld rules!\n", success_count, file_count);

	//	// Check the rule was added
	//	int result = yr_compiler_get_rules(compiler, &rules);

	//	if (result != ERROR_SUCCESS)
	//	{
	//		printf("Failed to get rules from %s: %s\n", rule_directory.c_str(), GetErrorMsg(result).c_str());
	//		return FALSE;
	//	}
	//	else
	//	{
	//		printf("\\_ Successfully verified rules!\n");
	//		return TRUE;
	//	}
	//}

	BOOL GetRules() {
		// Step 4: Get the compiled rules
		if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS)
		{
			std::cerr << "Failed to get compiled rules." << std::endl;
			// yr_compiler_destroy(compiler);
			// yr_finalize();
			return 1;
		}
	}

	void scanFile(std::string filename)
	{
		// Perform YARA scan

		//printf("scan start %s\n", filename.c_str());
		int result = yr_rules_scan_file(rules, filename.c_str(), 0, capture_matches, NULL, 0);

		if (hasMatched) {
			TCHAR* YaraRule_txt = new TCHAR[MAX_PATH_EX];
			GetMyPath(YaraRule_txt);
			_tcscat_s(YaraRule_txt, MAX_PATH_EX, _T("\\YaraRule.txt"));

			std::wofstream outFile(YaraRule_txt, std::ios::app);
			if (outFile.good()) outFile << "|" << filename.c_str() << "\n";
			outFile.close();
			hasMatched = false;
		}

		//printf("result: %d\n", result);
		//
		//if (result == ERROR_SUCCESS)
		//{
		//	// No match found
		//	std::cout << "No match found in file: " << filename << std::endl;
		//}
		//else if (result == ERROR_CALLBACK_ERROR)
		//{
		//	// Error during scanning
		//	std::cerr << "Error during scanning file: " << filename << std::endl;
		//}
		//else if (result == ERROR_INSUFFICIENT_MEMORY)
		//{
		//	// Memory allocation failure
		//	std::cerr << "Memory allocation failure during scanning file: " << filename << std::endl;
		//}
		//else
		//{
		//	// Match found
		//	std::cout << "Match found " << filename << std::endl;
		//	TCHAR* YaraRule_txt = new TCHAR[MAX_PATH_EX];
		//	GetMyPath(YaraRule_txt);
		//	_tcscat_s(YaraRule_txt, MAX_PATH_EX, _T("\\YaraRule.txt"));

		//	std::wofstream outFile(YaraRule_txt, std::ios::app);
		//	if (outFile.good()) outFile << "|" << filename.c_str() << "\n";
		//	outFile.close();
		//}


	}

private:
	// Compiler object
	YR_COMPILER* compiler = NULL;

	// Rules object
	YR_RULES* rules = NULL;

	// Scann object
	YR_SCANNER* scanner = NULL;

	std::string GetErrorMsg(int err)
	{
		std::string msg;
		switch (err)
		{
		case 0:
			msg = "ERROR_SUCCESS";
			break;
		case 1:
			msg = "ERROR_INSUFFICIENT_MEMORY";
			break;
		case 2:
			msg = "ERROR_COULD_NOT_OPEN_FILE";
			break;
		case 3:
			msg = "ERROR_COULD_NOT_MAP_FILE";
			break;
		case 4:
			msg = "ERROR_INVALID_FILE";
			break;
		case 5:
			msg = "ERROR_UNSUPPORTED_FILE_VERSION";
			break;
		case 6:
			msg = "ERROR_TOO_MANY_SCAN_THREADS";
			break;
		case 7:
			msg = "ERROR_SCAN_TIMEOUT";
			break;
		case 8:
			msg = "ERROR_CALLBACK_ERROR";
			break;
		case 9:
			msg = "ERROR_TOO_MANY_MATCHES";
			break;
		default:
			break;
		}
		return msg;
	}

	static int capture_matches(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data)
	{
		if (message == CALLBACK_MSG_RULE_MATCHING)
		{
			YR_RULE* rule = (YR_RULE*)message_data;
			const char* rule_name = rule->identifier;
			printf("*******************************[MATCH %s]******************************8\n", rule_name);

			TCHAR* YaraRule_txt = new TCHAR[MAX_PATH_EX];
			GetMyPath(YaraRule_txt);
			_tcscat_s(YaraRule_txt, MAX_PATH_EX, _T("\\YaraRule.txt"));

			std::wofstream outFile(YaraRule_txt, std::ios::app);

			if (outFile.good()) outFile << rule_name << ";";
			outFile.close();

			hasMatched = true;

			// 
			//std::this_thread::sleep_for(std::chrono::seconds(30));
		}

		return CALLBACK_CONTINUE;
	}
};

void SysExplorerSearch(TCHAR* m_Path, unsigned int& FileIndex, YaraManger* yaraManger, std::string task)
{

	TCHAR szTempPath[256];
	lstrcpy(szTempPath, m_Path);
	lstrcat(szTempPath, TEXT("*.*"));

	clock_t start, end;
	start = clock();
	WIN32_FIND_DATA fd;
	HANDLE hSearch = FindFirstFile(szTempPath, &fd);

	std::wcout << L": " << szTempPath << std::endl;

	if (INVALID_HANDLE_VALUE == hSearch)
	{
		printf("INVALID_HANDLE_VALUE\n");
		return;
	}
	do
	{
		if ((0 != (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) && (0 != lstrcmp(fd.cFileName, TEXT("."))) && (0 != lstrcmp(fd.cFileName, TEXT(".."))))/*&& (0 == (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) */
		{
			FileIndex++;
			TCHAR szPath[256];
			swprintf_s(szPath, 256, L"%s%s\\", m_Path, fd.cFileName);

			std::wcout << L"folder: " << FileIndex << L": " << szPath << std::endl;
			SysExplorerSearch(szPath, FileIndex, yaraManger, task);



		}
		else if ((0 == (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) && (0 != lstrcmp(fd.cFileName, TEXT("."))) && (0 != lstrcmp(fd.cFileName, TEXT(".."))))
		{
			FileIndex++;
			TCHAR* szPath = new TCHAR[256];
			swprintf_s(szPath, 256, L"%s%s", m_Path, fd.cFileName);

			std::wstring wstr = szPath;
			int bufferSize = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
			std::string str(bufferSize, '\0');
			WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], bufferSize, nullptr, nullptr);

			//std::wcout << L"file: " << FileIndex << L": " << szPath << std::endl;
			std::cout << "file: " << FileIndex << ": " << str << std::endl;


			if (task == "AddYaraRule") yaraManger->AddRuleFromFile(str);
			else yaraManger->scanFile(str);

			std::wcout << L"finish file: " << FileIndex << L": " << szPath << std::endl;

		}
	} while (FindNextFile(hSearch, &fd) != FALSE);
	FindClose(hSearch);

}






int main()
{

	YaraManger* yaraManger = new YaraManger();

	TCHAR* YaraRule_folder = new TCHAR[MAX_PATH_EX];
	GetMyPath(YaraRule_folder);
	_tcscat_s(YaraRule_folder, MAX_PATH_EX, _T("\\YaraRule\\"));
	unsigned int FileIndex = 0;
	SysExplorerSearch(YaraRule_folder, FileIndex, yaraManger, "AddYaraRule");

	yaraManger->GetRules();
	FileIndex = 0;
	TCHAR* drive = new TCHAR[256];
	swprintf_s(drive, 256, L"%s", L"C:\\james\\eDetectorWindowsAgent_VS2019\\x64\\");
	SysExplorerSearch(drive, FileIndex, yaraManger, "CheckIsMatchYaraRule");


	//std::string rule_name, file_name, dir_name;
	//dir_name = ".\\YaraRule";
	//rule_name = ".\\YaraRule\\banker.yara";
	//file_name = "test.txt";

	//YaraManger yaraManger = YaraManger();
	//if (!yaraManger.AddRuleFromFile(rule_name))
	//	return 1;

	//yaraManger.GetRules();
	//yaraManger.scanFile(file_name);


}