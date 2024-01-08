#pragma once

#include <yara.h>

#include "Log.h"


class YaraManger {
public:
	YaraManger();
	~YaraManger();

	bool AddRuleFromFile(std::string file_name);
	BOOL GetRules();

	void scanFile(std::string filename);
	static int capture_matches(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data);

	TCHAR* YaraRule_txt;
	std::wofstream outFile;
	std::string current_file;

private:
	Log log;

	// Compiler object
	YR_COMPILER* compiler = NULL;

	// Rules object
	YR_RULES* rules = NULL;

	// Scann object
	YR_SCANNER* scanner = NULL;

	std::string GetErrorMsg(int err);

	
};
