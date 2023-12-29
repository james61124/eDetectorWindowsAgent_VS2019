#define _CRT_SECURE_NO_WARNINGS

#include "YaraManager.h"

YaraManger::YaraManger() {

	YaraRule_txt = new TCHAR[MAX_PATH_EX];
	GetMyPath(YaraRule_txt);
	_tcscat_s(YaraRule_txt, MAX_PATH_EX, _T("\\YaraRule.txt"));
	DeleteFile(YaraRule_txt);

	outFile.open(YaraRule_txt, std::ios::app);
	if (!outFile.is_open()) log.logger("Error", "YaraRule.txt open failed");

	// Step 1: Initialize YARA
	if (yr_initialize() != ERROR_SUCCESS) {
		log.logger("Error", "Failed to initialize YARA.");
	}

	// Step 2: Create a YARA compiler
	if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
		log.logger("Error", "Failed to create YARA compiler.");
		yr_finalize();
	}
}

YaraManger::~YaraManger() {

	// Clean up resources
	yr_rules_destroy(rules);
	yr_compiler_destroy(compiler);
	yr_finalize();
}

bool YaraManger::AddRuleFromFile(std::string file_name) {

	current_file = file_name;

	// Step 3: Add YARA rules to the compiler
	FILE* rule_file = NULL;
	rule_file = fopen(file_name.c_str(), "r");
	if (!rule_file) {
		std::string LogMsg = "Failed to open file: " + file_name;
		log.logger("Error", LogMsg);
		return FALSE;
	}
	if (yr_compiler_add_file(compiler, rule_file, NULL, file_name.c_str()) != ERROR_SUCCESS)
	{
		std::string LogMsg = "Failed to add YARA rule " + file_name;
		log.logger("Error", LogMsg);
		return FALSE;
	}
	printf("_ Added %s!\n", file_name.c_str());

	return TRUE;
}

BOOL YaraManger::GetRules() {

	// Step 4: Get the compiled rules
	if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS) {
		log.logger("Error", "Failed to get compiled rules.");
		return 1;
	}
}

void YaraManger::scanFile(std::string filename) {
	int result = yr_rules_scan_file(rules, filename.c_str(), 0, capture_matches, NULL, 0);
}

std::string YaraManger::GetErrorMsg(int err) {
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

int YaraManger::capture_matches(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {

	if (message == CALLBACK_MSG_RULE_MATCHING)
	{
		YR_RULE* rule = (YR_RULE*)message_data;
		const char* rule_name = rule->identifier;
		//if (outFile.good()) outFile << "GiveMemData\n";
		printf("*******************************[MATCH %s]******************************8\n", rule_name);

	}

	return CALLBACK_CONTINUE;
}