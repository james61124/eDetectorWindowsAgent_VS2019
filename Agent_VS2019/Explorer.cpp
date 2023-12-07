#include "Explorer.h"

Explorer::Explorer(Info* infoInstance, SocketSend* socketSendInstance, char* input_drive, char* input_filesystem) {
	info = infoInstance;
	socketsend = socketSendInstance;
	Drive = input_drive;
	FileSystem = input_filesystem;
}

void Explorer::DoTask() {
	int ret = 0;
	ExplorerInfo* m_Info = new ExplorerInfo;
	wchar_t DriveName[20];
	size_t convertedChars = 0;
	mbstowcs_s(&convertedChars, DriveName, sizeof(DriveName) / sizeof(wchar_t), Drive, sizeof(Drive) - 1);


	log.logger("Debug", FileSystem);

	m_Info->Drive = static_cast<wchar_t>(Drive[0]);
	//mbstowcs_s(&convertedChars, m_Info->DriveInfo, sizeof(m_Info->DriveInfo) / sizeof(wchar_t), FileSystem, sizeof(FileSystem) - 1);
	MultiByteToWideChar(CP_ACP, 0, FileSystem, -1, m_Info->DriveInfo, _countof(m_Info->DriveInfo));
	//_tcscpy(m_Info->DriveInfo, FileSystem);
	//wcscpy(m_Info->DriveInfo, FileSystem);

	/*m_Info->Drive = 'F';
	_tcscpy_s(m_Info->DriveInfo, _T("FAT32"));*/

	wchar_t* drive = new wchar_t[5];
	swprintf_s(drive, 5, L"%c:\\", m_Info->Drive);

	std::wstring wstr = m_Info->DriveInfo;
	int bufferSize = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
	std::string str(bufferSize, '\0');
	WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], bufferSize, nullptr, nullptr);
	log.logger("Debug", str);

	wchar_t* volname = new wchar_t[_MAX_FNAME];
	wchar_t* filesys = new wchar_t[_MAX_FNAME];
	DWORD VolumeSerialNumber, MaximumComponentLength, FileSystemFlags;
	if (GetVolumeInformation(drive, volname, _MAX_FNAME, &VolumeSerialNumber, &MaximumComponentLength, &FileSystemFlags, filesys, _MAX_FNAME))
	{
		if ((wcsstr(m_Info->DriveInfo, filesys) != 0))
		{
			if (!wcscmp(filesys, L"NTFS"))
			{
				NTFSSearchCore* searchCore = new NTFSSearchCore;
				try {
					ret = NTFSSearch(m_Info->Drive, info->MAC, info->IP, info->tcpSocket, Drive, FileSystem);
				}
				catch (...) {
					ret = 1;
				}

				delete searchCore;
			}
			else if (!wcscmp(filesys, L"FAT32"))
			{
				CFileSystem* pfat = new CFileSystem(drive);
				int ret1 = 1;
				char* TempStr = new char[DATASTRINGMESSAGELEN];
				memset(TempStr, '\0', DATASTRINGMESSAGELEN);

				std::string timeString = "1970/01/01 08:00:00";
				std::tm tm = {};
				std::istringstream ss(timeString);
				ss >> std::get_time(&tm, "%Y/%m/%d %H:%M:%S");
				if (ss.fail()) log.logger("Error", "parse time failed");
				std::time_t unixTime = std::mktime(&tm);
				char timeBuffer[100];
				std::snprintf(timeBuffer, sizeof(timeBuffer), "%ld", unixTime);

				char* m_DataStr = new char[1000];
				sprintf_s(m_DataStr, 1000, ".|0|2|%s|%s|%s|null,null|0|0|0\n", timeBuffer, timeBuffer, timeBuffer);

				strcat_s(TempStr, DATASTRINGMESSAGELEN, m_DataStr);
				vector<DeleteFATFileInfo> FATDeleteFile;
				//DWORD LastCluster = 0;
				DWORD LastCluster = 1;
				unsigned int Count = 1;
				unsigned int ProgressCount = 1;
				clock_t start;
				start = clock();

				char* RecordCount = new char[DATASTRINGMESSAGELEN];
				sprintf_s(RecordCount, DATASTRINGMESSAGELEN, "%s|%s", Drive, FileSystem);
				int tmp = SendDataPacketToServer("Explorer", RecordCount, info->tcpSocket);

				TCHAR* Explorer_txt = new TCHAR[MAX_PATH_EX];
				GetMyPath(Explorer_txt);
				_tcscat_s(Explorer_txt, MAX_PATH_EX, _T("\\Explorer.txt"));
				DeleteFile(Explorer_txt);
				TCHAR* Explorer_zip = new TCHAR[MAX_PATH_EX];
				GetMyPath(Explorer_zip);
				_tcscat_s(Explorer_zip, MAX_PATH_EX, _T("\\Explorer.zip"));
				DeleteFile(Explorer_zip);

				std::wofstream outFile(Explorer_txt, std::ios::app);

				bool ret = pfat->initFDT(this, Explorer_txt, info->MAC, info->IP, TempStr, ProgressCount, Count, LastCluster, &FATDeleteFile, start);

				if (ret)
				{
					if (!FATDeleteFile.empty())
					{
						vector<DeleteFATFileInfo>::iterator it;
						for (it = FATDeleteFile.begin(); it != FATDeleteFile.end(); it++)
						{
							LastCluster++;
							//if (LastCluster == 5) LastCluster++;
							wchar_t* wstr = new wchar_t[1024];
							DWORD FirstClister = (*it).FirstDataCluster + 5;
							if ((*it).isDirectory == 0)
							{
								TCHAR* m_MD5Str = new TCHAR[50];
								memset(m_MD5Str, '\0', 50);
								TCHAR* Signaturestr = new TCHAR[20];
								memset(Signaturestr, '\0', 20);
								//DWORD FirstCluster = newEntry->GetTheFirstDataCluster()+5;
								if (pfat->FileHashAndSignature((*it).FirstDataCluster, (*it).FileSize, (*it).FileName, m_MD5Str, Signaturestr))
								{
									wchar_t* create_time = SystemTimeToUnixTime((*it).CT);
									wchar_t* write_time = SystemTimeToUnixTime((*it).WT);
									wchar_t* access_time = SystemTimeToUnixTime((*it).AT);
									swprintf_s(wstr, 1024, L"%s|1|%d|%s|%s|%s|%s,%s|%lu|%lu|%lu\n",
										(*it).FileName, (*it).isDirectory
										, create_time, write_time, access_time, m_MD5Str, Signaturestr, (*it).FileSize, (*it).ParentFirstDataCluster, LastCluster);
								}
								else
								{
									wchar_t* create_time = SystemTimeToUnixTime((*it).CT);
									wchar_t* write_time = SystemTimeToUnixTime((*it).WT);
									wchar_t* access_time = SystemTimeToUnixTime((*it).AT);
									swprintf_s(wstr, 1024, L"%s|1|%d|%s|%s|%s|null,null|%lu|%lu|%lu\n",
										(*it).FileName, (*it).isDirectory
										, create_time, write_time, access_time, (*it).FileSize, (*it).ParentFirstDataCluster, LastCluster);
								}
								delete[] Signaturestr;
								delete[] m_MD5Str;
							}
							else
							{
								wchar_t* create_time = SystemTimeToUnixTime((*it).CT);
								wchar_t* write_time = SystemTimeToUnixTime((*it).WT);
								wchar_t* access_time = SystemTimeToUnixTime((*it).AT);
								swprintf_s(wstr, 1024, L"%s|1|%d|%s|%s|%s|null,null|%lu|%lu|%lu\n",
									(*it).FileName, (*it).isDirectory
									, create_time, write_time, access_time, (*it).FileSize, (*it).ParentFirstDataCluster, LastCluster);
							}
							char* m_DataStr = CStringToCharArray(wstr, CP_UTF8);
							strcat_s(TempStr, DATASTRINGMESSAGELEN, m_DataStr);
							ProgressCount++;
							Count++;
							clock_t endTime = clock();
							if ((endTime - start) > 300000)
							{
								char* ProgressStr = new char[10];
								sprintf_s(ProgressStr, 10, "%u", ProgressCount);
								//strcat_s(TempStr, DATASTRINGMESSAGELEN, ProgressStr);
								if (outFile.good()) outFile << TempStr;
								if (ret1 <= 0)
								{
									delete[] ProgressStr;
									delete[] m_DataStr;
									delete[] wstr;
									break;
								}
								start = clock();
								Count = 0;
								memset(TempStr, '\0', DATASTRINGMESSAGELEN);
								delete[] ProgressStr;
							}
							else
							{
								if ((Count % 60) == 0 && Count >= 60)
								{
									char* ProgressStr = new char[10];
									sprintf_s(ProgressStr, 10, "%u", ProgressCount);
									//strcat_s(TempStr, DATASTRINGMESSAGELEN, ProgressStr);
									if (outFile.good()) outFile << TempStr;
									if (ret1 <= 0)
									{
										delete[] ProgressStr;
										delete[] m_DataStr;
										delete[] wstr;
										break;
									}
									start = clock();
									Count = 0;
									memset(TempStr, '\0', DATASTRINGMESSAGELEN);
									delete[] ProgressStr;
								}
							}
							delete[] m_DataStr;
							delete[] wstr;
						}
					}
					if (ret1 > 0)
					{
						if (TempStr[0] != '\0')
						{
							char* ProgressStr = new char[10];
							sprintf_s(ProgressStr, 10, "%u", ProgressCount);
							//strcat_s(TempStr, DATASTRINGMESSAGELEN, ProgressStr);
							if (outFile.good()) outFile << TempStr;
							delete[] ProgressStr;
						}
					}
					//if (ret1 > 0) {
					//	char* null = new char[1];
					//	strcpy_s(null, 1, "");
					//	int	ret = SendDataPacketToServer("GiveExplorerEnd", null, info->tcpSocket);
					//}

				}
				else {
					char* null = new char[1];
					strcpy_s(null, 1, "");
					ret = SendDataPacketToServer("GiveExplorerEnd", null, info->tcpSocket);
					log.logger("Error", "ErrorLoadingFATTable");
				}

				outFile.close();

				// Compress Explorer.txt
				if (tool.CompressFileToZip(Explorer_zip, Explorer_txt)) _tprintf(_T("File compressed and added to ZIP successfully.\n"));
				else log.logger("Error", "failed to add file to Zip");

				// Get Explorer.txt Size
				std::ifstream file(Explorer_zip, std::ios::binary);
				if (!file.is_open()) {
					std::cout << "Failed to open file." << std::endl;
					log.logger("Error", "failed to open zip file");
					return;
				}
				file.seekg(0, std::ios::end);
				std::streampos fileSize = file.tellg();
				file.close();
				long long fileSizeLL = static_cast<long long>(fileSize);

				// send GiveExplorerInfo
				char* FileSize = new char[DATASTRINGMESSAGELEN];
				sprintf_s(FileSize, DATASTRINGMESSAGELEN, "%lld", fileSizeLL);
				SendDataPacketToServer("GiveExplorerInfo", FileSize, info->tcpSocket);
				delete[] FileSize;

				// send zip file
				SendFileToServer("Explorer", Explorer_zip, info->tcpSocket);

				DeleteFile(Explorer_txt);
				DeleteFile(Explorer_zip);

				FATDeleteFile.clear();
				delete[] m_DataStr;
				delete[] TempStr;
			}
			else
			{
				//char* TempStr = new char[DATASTRINGMESSAGELEN];
				//memset(TempStr, '\0', DATASTRINGMESSAGELEN);
				//char* m_DataStr = new char[1000];
				//sprintf_s(m_DataStr, 1000, "5|.|5|0|2|1970/01/01 08:00:00|1970/01/01 08:00:00|1970/01/01 08:00:00|null|0|9\n");
				//strcat_s(TempStr, DATASTRINGMESSAGELEN, m_DataStr);
				////wchar_t * DriveStr = CharArrayToWString(drive,CP_UTF8);
				//unsigned int ProgressCount = 1;
				//unsigned int Index = 5;
				//unsigned int Count = 1;
				//int ret = 1;
				//SysExplorerSearch(drive, 5, Index, TempStr, ProgressCount, Count);
				///*if (TempStr[0] != '\0')
				//{
				//	char* ProgressStr = new char[10];
				//	sprintf_s(ProgressStr, 10, "%u", ProgressCount);
				//	strcat_s(TempStr, DATASTRINGMESSAGELEN, ProgressStr);
				//	ret = socketsend->SendDataToServer(functionName_GiveExplorerData, TempStr);
				//	delete[] ProgressStr;
				//}*/
				////if(Client_Socket->IsOpened())
				////if (ret > 0) int	ret = socketsend->SendMessageToServer(functionName_GiveExplorerEnd, null);
				//delete[] m_DataStr;
				//delete[] TempStr;
			}
		}
		else
		{
			char* msg = new char[22];
			strcpy_s(msg, 22, "ErrorNotFormat");
			ret = SendDataPacketToServer("GiveExplorerEnd", msg, info->tcpSocket);
			delete[] msg;

		}
	}
	else
	{
		char* msg = new char[22];
		strcpy_s(msg, 22, "ErrorNoDrive");
		ret = SendDataPacketToServer("GiveExplorerEnd", msg, info->tcpSocket);
		delete[] msg;
	}

	delete[] filesys;
	delete[] volname;
	delete[] drive;
	delete m_Info;

}
int Explorer::NTFSSearch(wchar_t vol_name, char* pMAC, char* pIP, SOCKET* tcpSocket, char* Drive, char* FileSystem) {

	CNTFSVolume* m_curSelectedVol = new CNTFSVolume(vol_name);
	if (m_curSelectedVol == NULL) {
		log.logger("Error", "Error when getVolumeByName");
		delete m_curSelectedVol;
		return 1;
	}

	if (!m_curSelectedVol->IsVolumeOK()) {
		log.logger("Error", "Not a valid NTFS volume or NTFS version < 3.0");
		delete m_curSelectedVol;
		return 1;
	}

	unsigned int m_progressIdx;
	unsigned int m_Count = 0;
	char* TempStr = new char[DATASTRINGMESSAGELEN];
	memset(TempStr, '\0', DATASTRINGMESSAGELEN);

	// Give Drive Info to Server
	char* RecordCount = new char[DATASTRINGMESSAGELEN];
	sprintf_s(RecordCount, DATASTRINGMESSAGELEN, "%s|%s", Drive, FileSystem);
	int ret = SendDataPacketToServer("Explorer", RecordCount, tcpSocket);

	TCHAR* Explorer_txt = new TCHAR[MAX_PATH_EX];
	GetMyPath(Explorer_txt);
	_tcscat_s(Explorer_txt, MAX_PATH_EX, _T("\\Explorer.txt"));
	DeleteFile(Explorer_txt);
	TCHAR* Explorer_zip = new TCHAR[MAX_PATH_EX];
	GetMyPath(Explorer_zip);
	_tcscat_s(Explorer_zip, MAX_PATH_EX, _T("\\Explorer.zip"));
	DeleteFile(Explorer_zip);


	std::wofstream outFile(Explorer_txt, std::ios::app);
	if (!outFile.is_open()) {
		log.logger("Error", "Explorer.txt open failed");
	}

	// collect Explorer
	for (m_progressIdx = MFT_IDX_MFT; m_progressIdx < m_curSelectedVol->GetRecordsCount(); m_progressIdx++) {
		if (m_progressIdx % 10000 == 0) {
			printf("%d\n", m_progressIdx);
			char* Progress = new char[DATASTRINGMESSAGELEN];
			sprintf_s(Progress, DATASTRINGMESSAGELEN, "%u/%d", m_progressIdx, m_curSelectedVol->GetRecordsCount());
			SendDataPacketToServer("GiveExplorerProgress", Progress, tcpSocket);
			delete[] Progress;
		}

		CFileRecord* fr = new CFileRecord(m_curSelectedVol);
		if (fr == NULL) {
			printf("CFileRecord is null\n");
			continue;	// skip to next
		}

		// Only parse Standard Information and File Name attributes
		fr->SetAttrMask(MASK_FILE_NAME | MASK_DATA);	// StdInfo will always be parsed
		if (!fr->ParseFileRecord(m_progressIdx))
		{
			delete fr;
			continue;	// skip to next
		}

		if (!fr->ParseFileAttrs())
		{
			delete fr;
			continue;	// skip to next
		}

		TCHAR fn[MAX_PATH];
		if (fr->GetFileName(fn, MAX_PATH) <= 0)
		{
			delete fr;
			continue;	// skip to next
		}

		ULONGLONG datalen = 0;

		if (!fr->IsDirectory())
		{
			const CAttrBase* data = fr->FindStream();
			if (data)
			{
				datalen = data->GetDataSize();
				if (fr->IsCompressed() && datalen == 0)
					datalen = fr->GetFileSize();
			}
			else
			{
				if (fr->IsCompressed() && datalen == 0)
					datalen = fr->GetFileSize();
			}
		}
		ULONGLONG ParentId = 0;
		ParentId = fr->GetParentRef();
		if (ParentId == 0)
			ParentId = 5;
		else
			ParentId = ParentId & 0x0000FFFFFFFFFFFF;

		FILETIME	FileCreateTime;		// File creation time
		FILETIME	FileWriteTime;		// File altered time
		FILETIME	FileAccessTime;		// File read time
		FILETIME	EntryModifiedTime;
		fr->GetFileCreateTime(&FileCreateTime);
		fr->GetFileWriteTime(&FileWriteTime);
		fr->GetFileAccessTime(&FileAccessTime);
		fr->GetEntryModifiedTime(&EntryModifiedTime);

		time_t createTimeUnix = tool.FileTimeToUnixTime(FileCreateTime);
		time_t writeTimeUnix = tool.FileTimeToUnixTime(FileWriteTime);
		time_t accessTimeUnix = tool.FileTimeToUnixTime(FileAccessTime);
		time_t modifiedTimeUnix = tool.FileTimeToUnixTime(EntryModifiedTime);

		wchar_t CreateTimeWstr[50];
		wchar_t WriteTimeWstr[50];
		wchar_t AccessTimeWstr[50];
		wchar_t EntryModifiedTimeWstr[50];
		swprintf_s(CreateTimeWstr, 50, L"%lld", static_cast<long long>(createTimeUnix));
		swprintf_s(WriteTimeWstr, 50, L"%lld", static_cast<long long>(writeTimeUnix));
		swprintf_s(AccessTimeWstr, 50, L"%lld", static_cast<long long>(accessTimeUnix));
		if (EntryModifiedTime.dwLowDateTime != 0) swprintf_s(EntryModifiedTimeWstr, 50, L"%lld", static_cast<long long>(modifiedTimeUnix));
		else swprintf_s(EntryModifiedTimeWstr, 50, L"1");

		wchar_t* wstr = new wchar_t[1024];
		swprintf_s(wstr, 1024, L"%s|%d|%d|%s|%s|%s|%s|%llu|%u|%llu\n", fn, fr->IsDeleted(), fr->IsDirectory(), CreateTimeWstr, WriteTimeWstr, AccessTimeWstr, EntryModifiedTimeWstr, datalen, m_progressIdx, ParentId);

		// write to Explorer.txt
		char* m_DataStr = CStringToCharArray(wstr, CP_UTF8);
		strcat_s(TempStr, DATASTRINGMESSAGELEN, m_DataStr);
		delete[] wstr;
		if ((m_Count % 60) == 0 && m_Count >= 60) {
			if (outFile.good()) outFile << TempStr;
			else {
				log.logger("Error", "write to explorer txt failed");
			}
			memset(TempStr, '\0', DATASTRINGMESSAGELEN);
		}

		m_Count++;
		delete fr;
	}
	outFile.close();

	// Compress Explorer.txt
	if (tool.CompressFileToZip(Explorer_zip, Explorer_txt)) _tprintf(_T("File compressed and added to ZIP successfully.\n"));
	else log.logger("Error", "failed to add file to Zip");

	// Get Explorer.txt Size
	std::ifstream file(Explorer_zip, std::ios::binary);
	if (!file.is_open()) {
		std::cout << "Failed to open file." << std::endl;
		log.logger("Error", "failed to open zip file");
		return 0;
	}
	file.seekg(0, std::ios::end);
	std::streampos fileSize = file.tellg();
	file.close();
	long long fileSizeLL = static_cast<long long>(fileSize);

	// send GiveExplorerInfo
	char* FileSize = new char[DATASTRINGMESSAGELEN];
	sprintf_s(FileSize, DATASTRINGMESSAGELEN, "%lld", fileSizeLL);
	SendDataPacketToServer("GiveExplorerInfo", FileSize, tcpSocket);
	delete[] FileSize;

	// send zip file
	SendFileToServer("Explorer", Explorer_zip, tcpSocket);

	DeleteFile(Explorer_txt);
	DeleteFile(Explorer_zip);


	delete[] TempStr;
	delete m_curSelectedVol;

	return 0;
}
void Explorer::SysExplorerSearch(TCHAR* m_Path, unsigned int FatherNum, unsigned int& FileIndex, char* TmpSend, unsigned int& m_ProgressCount, unsigned int& m_Count)
{
	TCHAR szTempPath[MAX_PATH_EX];
	lstrcpy(szTempPath, m_Path);
	lstrcat(szTempPath, TEXT("*.*"));
	//MessageBox(0,szTempPath,0,0);
	clock_t start, end;
	start = clock();
	WIN32_FIND_DATA fd;
	HANDLE hSearch = FindFirstFile(szTempPath, &fd);
	if (INVALID_HANDLE_VALUE == hSearch)
	{
		return;
	}
	do
	{
		if ((0 != (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) && (0 != lstrcmp(fd.cFileName, TEXT("."))) && (0 != lstrcmp(fd.cFileName, TEXT(".."))) && (0 != lstrcmp(fd.cFileName, TEXT("EN2022110301_NB02-SSD01"))))/*&& (0 == (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) */
		{
			FileIndex++;
			unsigned int MyID = FileIndex;

			TCHAR* MyDataInfo = new TCHAR[1000];
			SYSTEMTIME systemCreateTime, systemWriteTime, systemAccessTime, localCreateTime, localWriteTime, localAccessTime;
			FileTimeToSystemTime(&fd.ftCreationTime, &systemCreateTime);
			FileTimeToSystemTime(&fd.ftLastWriteTime, &systemWriteTime);
			FileTimeToSystemTime(&fd.ftLastAccessTime, &systemAccessTime);
			SystemTimeToTzSpecificLocalTime(NULL, &systemCreateTime, &localCreateTime);
			SystemTimeToTzSpecificLocalTime(NULL, &systemWriteTime, &localWriteTime);
			SystemTimeToTzSpecificLocalTime(NULL, &systemAccessTime, &localAccessTime);
			swprintf_s(MyDataInfo, 1000, L"%u|%s|%u|0|2|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|null|%lu|9\n",
				FileIndex, fd.cFileName, FatherNum,
				localCreateTime.wYear, localCreateTime.wMonth, localCreateTime.wDay, localCreateTime.wHour, localCreateTime.wMinute, localCreateTime.wSecond,
				localWriteTime.wYear, localWriteTime.wMonth, localWriteTime.wDay, localWriteTime.wHour, localWriteTime.wMinute, localWriteTime.wSecond,
				localAccessTime.wYear, localAccessTime.wMonth, localAccessTime.wDay, localAccessTime.wHour, localAccessTime.wMinute, localAccessTime.wSecond,
				fd.nFileSizeLow);

			char* m_DataStr = CStringToCharArray(MyDataInfo, CP_UTF8);
			strcat_s(TmpSend, DATASTRINGMESSAGELEN, m_DataStr);
			SendDataPacketToServer("GiveExplorerData", TmpSend, info->tcpSocket);
			m_ProgressCount++;
			m_Count++;
			end = clock();
			if ((end - start) > 300000)
			{
				char* ProgressStr = new char[10];
				sprintf_s(ProgressStr, 10, "%u", m_ProgressCount);
				strcat_s(TmpSend, DATASTRINGMESSAGELEN, ProgressStr);
				int ret1 = SendDataPacketToServer("GiveExplorerData", TmpSend, info->tcpSocket);
				if (ret1 <= 0)
				{
					delete[] ProgressStr;
					break;
				}
				start = clock();
				m_Count = 0;
				memset(TmpSend, '\0', DATASTRINGMESSAGELEN);
				delete[] ProgressStr;
			}
			else
			{
				if ((m_Count % 60) == 0 && m_Count >= 60)
				{
					char* ProgressStr = new char[10];
					sprintf_s(ProgressStr, 10, "%u", m_ProgressCount);
					strcat_s(TmpSend, DATASTRINGMESSAGELEN, ProgressStr);
					int ret1 = SendDataPacketToServer("GiveExplorerData", TmpSend, info->tcpSocket);
					if (ret1 <= 0)
					{
						delete[] ProgressStr;
						break;
					}
					start = clock();
					m_Count = 0;
					memset(TmpSend, '\0', DATASTRINGMESSAGELEN);
					delete[] ProgressStr;
				}
			}

			delete[] m_DataStr;
			delete[] MyDataInfo;

			TCHAR szPath[MAX_PATH_EX];
			swprintf_s(szPath, MAX_PATH_EX, L"%s%s\\", m_Path, fd.cFileName);

			SysExplorerSearch(szPath, MyID, FileIndex, TmpSend, m_ProgressCount, m_Count);

		}
		else if ((0 == (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) && (0 != lstrcmp(fd.cFileName, TEXT("."))) && (0 != lstrcmp(fd.cFileName, TEXT(".."))) && (0 != lstrcmp(fd.cFileName, TEXT("EN2022110301_NB02-SSD01"))))
		{
			FileIndex++;
			TCHAR* szPath = new TCHAR[MAX_PATH_EX];
			swprintf_s(szPath, MAX_PATH_EX, L"%s%s", m_Path, fd.cFileName);
			BOOL IsSig = FALSE;
			TCHAR* Md5Str = new TCHAR[50];
			memset(Md5Str, '\0', 50);
			TCHAR* SignatureStr = new TCHAR[50];
			TCHAR* HASStr = new TCHAR[128];
			//MessageBox(0,szPath,0,0);
			DWORD ret = Md5HashAndSignature(szPath, Md5Str, 50, IsSig);
			if (ret == 0)
			{
				if (IsSig)
				{
					if (IsPEExt(fd.cFileName))
						lstrcpy(SignatureStr, _T("Match"));
					else
						lstrcpy(SignatureStr, _T("Bad Signature"));
				}
				else
				{
					if (IsPEExt(fd.cFileName))
						lstrcpy(SignatureStr, _T("Not PE Format"));
					else
						lstrcpy(SignatureStr, _T("Match"));
				}
				swprintf_s(HASStr, 128, _T("%s,%s"), Md5Str, SignatureStr);
			}
			else
				swprintf_s(HASStr, 128, _T("null"));
			TCHAR* MyDataInfo = new TCHAR[1000];
			SYSTEMTIME systemCreateTime, systemWriteTime, systemAccessTime, localCreateTime, localWriteTime, localAccessTime;
			FileTimeToSystemTime(&fd.ftCreationTime, &systemCreateTime);
			FileTimeToSystemTime(&fd.ftLastWriteTime, &systemWriteTime);
			FileTimeToSystemTime(&fd.ftLastAccessTime, &systemAccessTime);
			SystemTimeToTzSpecificLocalTime(NULL, &systemCreateTime, &localCreateTime);
			SystemTimeToTzSpecificLocalTime(NULL, &systemWriteTime, &localWriteTime);
			SystemTimeToTzSpecificLocalTime(NULL, &systemAccessTime, &localAccessTime);
			swprintf_s(MyDataInfo, 1000, L"%u|%s|%u|0|0|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%s|%lu|9\n",
				FileIndex, fd.cFileName, FatherNum,
				localCreateTime.wYear, localCreateTime.wMonth, localCreateTime.wDay, localCreateTime.wHour, localCreateTime.wMinute, localCreateTime.wSecond,
				localWriteTime.wYear, localWriteTime.wMonth, localWriteTime.wDay, localWriteTime.wHour, localWriteTime.wMinute, localWriteTime.wSecond,
				localAccessTime.wYear, localAccessTime.wMonth, localAccessTime.wDay, localAccessTime.wHour, localAccessTime.wMinute, localAccessTime.wSecond,
				HASStr, fd.nFileSizeLow);
			char* m_DataStr = CStringToCharArray(MyDataInfo, CP_UTF8);
			strcat_s(TmpSend, DATASTRINGMESSAGELEN, m_DataStr);
			SendDataPacketToServer("GiveExplorerData", TmpSend, info->tcpSocket);
			m_ProgressCount++;
			m_Count++;
			end = clock();
			if ((end - start) > 300000)
			{
				char* ProgressStr = new char[10];
				sprintf_s(ProgressStr, 10, "%u", m_ProgressCount);
				strcat_s(TmpSend, DATASTRINGMESSAGELEN, ProgressStr);
				int ret1 = SendDataPacketToServer("GiveExplorerData", TmpSend, info->tcpSocket);
				if (ret1 <= 0)
				{
					delete[] ProgressStr;
					break;
				}
				start = clock();
				m_Count = 0;
				memset(TmpSend, '\0', DATASTRINGMESSAGELEN);
				delete[] ProgressStr;
			}
			else
			{
				if ((m_Count % 60) == 0 && m_Count >= 60)
				{
					char* ProgressStr = new char[10];
					sprintf_s(ProgressStr, 10, "%u", m_ProgressCount);
					strcat_s(TmpSend, DATASTRINGMESSAGELEN, ProgressStr);
					int ret1 = SendDataPacketToServer("GiveExplorerData", TmpSend, info->tcpSocket);
					if (ret1 <= 0)
					{
						delete[] ProgressStr;
						break;
					}
					start = clock();
					m_Count = 0;
					memset(TmpSend, '\0', DATASTRINGMESSAGELEN);
					delete[] ProgressStr;
				}
			}
			/*int ret = SendMessageToServer("ForExplorerData",m_DataStr);*/
			delete[] m_DataStr;
			delete[] MyDataInfo;
			delete[] HASStr;
			delete[] SignatureStr;
			delete[] Md5Str;
			delete[] szPath;
		}
	} while (FindNextFile(hSearch, &fd) != FALSE);
	FindClose(hSearch);
}