#include <iostream>
#include <string>
#include <cstring>
#include<fstream>
#include<sstream>
#include <future>
#include <algorithm>
#include <cctype>

#include "task.h"

#define DATABUFFER 65536
#define	BUFSIZE64 65536
#define	BUFSIZE	1024

TCHAR* MyName = NULL;
using fstream = basic_fstream<char, char_traits<char>>;

const int BUF_SIZE = 1024;
int CollectionNums[] = {
						101, 102, 103, 104, 105, 201, 202, 203, 204, 205,
						206, 207, 208, 209, 210, 211, 212, 213, 214, 215,
						216, 217, 218, 219, 220, 221, 222, 223, 224, 225,
						226, 227, 228, 229, 230, 231, 232, 233, 234, 235,
						236, 237, 238, 239, 240, 241, 242, 243
};

TCHAR* CollectionNum = new TCHAR[100];


Task::Task(Info* infoInstance, SocketSend* socketSendInstance) {
    functionMap["GiveInfo"] = std::bind(&Task::GiveInfo, this);
    functionMap["GiveDetectInfoFirst"] = std::bind(&Task::GiveDetectInfoFirst, this);
    functionMap["GiveDetectInfo"] = std::bind(&Task::GiveDetectInfo, this);
    // functionMap["Process"] = std::bind(&Task::Process, this);
    functionMap["GetScanInfoData"] = std::bind(&Task::GetScanInfoData, this);
    functionMap["GiveProcessData"] = std::bind(&Task::GiveProcessData, this);
    functionMap["GiveProcessDataEnd"] = std::bind(&Task::GiveProcessDataEnd, this);
    functionMap["GiveScanProgress"] = std::bind(&Task::GiveScanProgress, this);
    functionMap["GiveDriveInfo"] = std::bind(&Task::GiveDriveInfo, this);
    functionMap["Explorer"] = std::bind(&Task::Explorer, this);
    functionMap["GiveExplorerData"] = std::bind(&Task::GiveExplorerData, this);
    functionMap["GiveExplorerEnd"] = std::bind(&Task::GiveExplorerEnd, this);
    functionMap["CollectInfo"] = std::bind(&Task::CollectInfo, this);
    functionMap["GiveCollectProgress"] = std::bind(&Task::GiveCollectProgress, this);
    functionMap["GiveCollectDataInfo"] = std::bind(&Task::GiveCollectDataInfo, this);
    // functionMap["GiveCollectData"] = std::bind(&Task::GiveCollectData, this);
    //functionMap["GiveCollectDataEnd"] = std::bind(&Task::GiveCollectDataEnd, this);

    // packet from server
    functionFromServerMap["OpenCheckthread"] = &Task::OpenCheckthread;
    functionFromServerMap["UpdateDetectMode"] = &Task::UpdateDetectMode;
    functionFromServerMap["GetScanInfoData"] = &Task::GetScanInfoData_;
    functionFromServerMap["GetProcessInfo"] = &Task::GetProcessInfo;
    functionFromServerMap["GetDrive"] = &Task::GetDrive;
    //functionFromServerMap["ExplorerInfo"] = &Task::ExplorerInfo;
    functionFromServerMap["TransportExplorer"] = &Task::TransportExplorer;
    functionFromServerMap["GetCollectInfo"] = &Task::GetCollectInfo;
    functionFromServerMap["GetCollectInfoData"] = &Task::GetCollectInfoData;
    functionFromServerMap["DataRight"] = &Task::DataRight;

    info = infoInstance;
    socketsend = socketSendInstance;
}

void Task::startThread(const std::string& key, std::string functionName) {
    std::any argument;
    auto functionIter = threadMap.find(functionName);
    if (functionIter == threadMap.end()) {
        threadMap[functionName] = std::thread(functionMap[functionName], this, argument);
    }
}

int Task::GiveInfo() {
    // getSystemInfo();
    char* buffer = new char[STRINGMESSAGELEN];
    char* SysInfo = tool.GetSysInfo();
    char* OsStr = tool.GetOSVersion();
    char* cComputerName = tool.GetComputerNameUTF8();
    char* cUserName = tool.GetUserNameUTF8();
    char* FileVersion = new char[10];
    unsigned long long BootTime = tool.GetBootTime();
    char* Key = new char[10];
    char* DigitalSignatureHash = new char[10];
    char* functionName = new char[24];

    strcpy_s(FileVersion, sizeof(FileVersion), "0.0.0.0");
	strcpy_s(Key, sizeof(Key), "");
	strcpy_s(DigitalSignatureHash, sizeof(DigitalSignatureHash), "123456");
	strcpy_s(functionName, 24, "GiveInfo");

    //if (strcpy_s(Key, sizeof(Key), "") == 0) printf("copy key success\n");
    //else printf("copy key failed\n");
    //if (strcpy_s(DigitalSignatureHash, sizeof(DigitalSignatureHash), "123456") == 0) printf("copy sign success\n");
    //else printf("copy sign failed\n");
    //if (strcpy_s(functionName, 24, "GiveInfo") == 0) printf("copy function success\n");
    //else printf("copy function failed\n");



    snprintf(buffer, STRINGMESSAGELEN, "%s|%s|%s|%s|%s,%d,%d|%d|%s|%lu", SysInfo, OsStr, cComputerName, cUserName, FileVersion, 1988, 1989, BootTime, Key, DigitalSignatureHash);
    
    return socketsend->SendMessageToServer(functionName, buffer);
}

int Task::CheckConnect() {

    // while(true){
    //     std::this_thread::sleep_for(std::chrono::seconds(2));
    //     if (!socketmanager->SendMessageToServer("CheckConnect", "")) {
    //         printf("CheckConnect sent failed\n");
    //     } else {
    //         printf("CheckConnect sent\n");
    //     }
    // }

    // to do
    // open a thread to send it forever
    // check kill time

    return 0;
}

int Task::GiveDetectInfoFirst() {
    char* buff = new char[STRINGMESSAGELEN];
    char* functionName = new char[24];
    strcpy_s(functionName, 24, "GiveDetectInfoFirst\0");
    snprintf(buff, STRINGMESSAGELEN, "%d|%d", info->DetectProcess, info->DetectNetwork);
    return socketsend->SendMessageToServer(functionName, buff);
}

int Task::GiveDetectInfo() {
    char* buff = new char[STRINGMESSAGELEN];
    char* functionName = new char[24];
    strcpy_s(functionName, 24, "GiveDetectInfo");
    snprintf(buff, STRINGMESSAGELEN, "%d|%d", info->DetectProcess, info->DetectNetwork);
	int ret = socketsend->SendMessageToServer(functionName, buff);
	GiveProcessData();
    return ret;
}


int Task::GetScanInfoData() {
    // return socketmanager->SendMessageToServer("GetScanInfoData","Ring0Process");
    return 0;
}

int Task::GiveProcessData() {
	printf("sending GiveProcessData\n");
	//char* Scan = new char[5];
	//strcpy_s(Scan, 5, "Scan");

 //   std::set<DWORD> m_ApiName;
 //   tool.LoadApiPattern(&m_ApiName);
 //   std::map<DWORD, ProcessInfoData> m_ProcessInfo;
 //   std::vector<UnKnownDataInfo> m_UnKnownData;
 //   MemProcess* m_MemPro = new MemProcess;
 //   m_MemPro->ScanRunNowProcess(this, &m_ProcessInfo, &m_ApiName, &m_UnKnownData);
 //   
 //   if (!m_ProcessInfo.empty()) GiveScanDataSendServer(info->MAC, info->IP, Scan, &m_ProcessInfo, &m_UnKnownData);

	//delete m_MemPro;
 //   m_UnKnownData.clear();
 //   m_ProcessInfo.clear();
 //   m_ApiName.clear();
 //   int ret = 1;
 //   return ret;

	char* functionName_GiveProcessData = new char[24];
	strcpy_s(functionName_GiveProcessData, 24, "GiveProcessData");


		map<DWORD, process_info> process_list;
		map<DWORD, process_info> Checkprocess_list;
		bool ret = false;
		time_t LoadProcessTime = 0;
		MemProcess* m_MemPro = new MemProcess;
		ret = m_MemPro->EnumProcess(&process_list, LoadProcessTime);

		if (ret)
		{
			//printf("ret true\n");
			char* TempStr = new char[DATASTRINGMESSAGELEN];
			memset(TempStr, '\0', DATASTRINGMESSAGELEN);
			//printf("memset success\n");
			int DataCount = 0;
			map<DWORD, process_info>::iterator it;
			map<DWORD, process_info>::iterator st;
			//printf("entering for loop\n");
			for (it = process_list.begin(); it != process_list.end(); it++)
			{
				//printf("enter for loop\n");
				TCHAR* m_Path = new TCHAR[512];
				TCHAR* m_ComStr = new TCHAR[512];
				//TCHAR * m_Time = new TCHAR[20];
				TCHAR* ParentName = new TCHAR[MAX_PATH];
				TCHAR* m_UserName = new TCHAR[_MAX_FNAME];
				BOOL IsPacked = FALSE;
				time_t ParentTime = 0;
				_tcscpy_s(m_Path, 512, _T("null"));
				_tcscpy_s(m_ComStr, 512, _T("null"));
				//_tcscpy_s(m_Time,20,_T("null"));
				_tcscpy_s(ParentName, MAX_PATH, _T("null"));
				_tcscpy_s(m_UserName, _MAX_FNAME, _T("null"));
				//printf("CheckIsPackedPE start\n");
				m_MemPro->GetProcessInfo(it->first, m_Path, NULL, m_UserName, m_ComStr);
				if (_tcscmp(m_Path, _T("null")))
				{
					IsPacked = CheckIsPackedPE(m_Path);
				}
				st = process_list.find(it->second.parent_pid);
				//printf("process create time start\n");
				if (st != process_list.end())
				{
					if (st->second.ProcessCreateTime <= it->second.ProcessCreateTime)
					{
						_tcscpy_s(ParentName, MAX_PATH, st->second.process_name);
						ParentTime = st->second.ProcessCreateTime;
					}
					//GetProcessOnlyTime(it->second.parent_pid,ParentTime);
					//if(ParentTime < 0)
					//	ParentTime = 0;
				}
				wchar_t* wstr = new wchar_t[2048];
				// swprintf_s(wstr, 2048, L"%lu|%d|%s|%lld|%s|%lld|%s|%s|%d|%s|%d\n", it->first, it->second.process_name, m_ComStr, m_Path, it->second.parent_pid, ParentName);
				swprintf_s(wstr, 2048, L"%lu|%d|%s|%lld|%s|%lld|%s|%s|%d|%s|%d\n", it->first, it->second.parent_pid, it->second.process_name, it->second.ProcessCreateTime, ParentName, ParentTime, m_Path, m_UserName, IsPacked, m_ComStr, it->second.IsHide);
				DataCount++;
				//wprintf(L"%s\n",wstr);
				char* m_DataStr = CStringToCharArray(wstr, CP_UTF8);
				strcat_s(TempStr, DATASTRINGMESSAGELEN, m_DataStr);

				//delete[] wstr;
				delete[] m_UserName;
				delete[] ParentName;
				delete[] m_ComStr;
				delete[] m_Path;

				//printf("send start %d\n", DataCount);
				if ((DataCount % 30) == 0 && DataCount >= 30)
				{
					//printf("%s\n", TempStr);
					int ret = socketsend->SendDataToServer(functionName_GiveProcessData, TempStr);
					if (ret == 0 || ret == -1)
					{
						delete[] m_DataStr;
						delete[] TempStr;
						process_list.clear();
						return ret;
					}
					memset(TempStr, '\0', DATASTRINGMESSAGELEN);
				}
				delete[] m_DataStr;
			}
			//printf("send start second\n");
			if (TempStr[0] != '\0')
			{
				//printf("send start second in\n");
				//MessageBoxA(0,TempStr,0,0);
				int ret = socketsend->SendDataToServer(functionName_GiveProcessData, TempStr);
				if (ret == 0 || ret == -1)
				{
					delete[] TempStr;
					process_list.clear();
					return ret;
				}
			}
			delete[] TempStr;
		}
		Checkprocess_list.clear();
		process_list.clear();
		return 1;
    
}

int Task::GiveProcessDataEnd() {
	// return socketmanager->SendDataToServer("GiveProcessDataEnd","");
	return 0;
}
int Task::GiveScanProgress() { return 0; }
int Task::GiveDriveInfo() { return 0; }
int Task::Explorer() { return 0; }
int Task::GiveExplorerData() {
	//char* functionName_GiveExplorerData = new char[24];
	//strcpy_s(functionName_GiveExplorerData, 24, "GiveExplorerData");
	//char* functionName_GiveExplorerEnd = new char[24];
	//strcpy_s(functionName_GiveExplorerEnd, 24, "GiveExplorerEnd");
	//char* functionName_GiveExplorerError = new char[24];
	//strcpy_s(functionName_GiveExplorerError, 24, "GiveExplorerError");


	////wchar_t* wMgs = CharArrayToWString(Mgs->csMsg, CP_UTF8);
	//ExplorerInfo* m_Info = new ExplorerInfo;
	//CFileSystem* pfat;
	////LoadExplorerInfo(wMgs, m_Info);
	//m_Info->Drive = L'C';
	//wcscpy_s(m_Info->DriveInfo, L"NTFS");

	//wchar_t* drive = new wchar_t[5];
	//swprintf_s(drive, 5, L"%c:\\", m_Info->Drive);
	//wchar_t* volname = new wchar_t[_MAX_FNAME];
	//wchar_t* filesys = new wchar_t[_MAX_FNAME];
	//DWORD VolumeSerialNumber, MaximumComponentLength, FileSystemFlags;
	//if (GetVolumeInformation(drive, volname, _MAX_FNAME, &VolumeSerialNumber, &MaximumComponentLength, &FileSystemFlags, filesys, _MAX_FNAME))
	//{
	//	if ((wcsstr(m_Info->DriveInfo, filesys) != 0))
	//	{
	//		if (!wcscmp(filesys, L"NTFS"))
	//		{
	//			NTFSSearchCore* searchCore = new NTFSSearchCore;
	//			int ret = 0;
	//			try
	//			{
	//				ret = searchCore->Search(this, m_Info->Drive, info->MAC, info->IP);
	//			}
	//			catch (...)
	//			{
	//				ret = 1;
	//			}
	//			if (ret == 0)
	//			{
	//				SendDataMsgToServer(MyMAC, MyIP, "GiveExplorerEnd", "");
	//			}
	//			else
	//			{
	//				SendDataMsgToServer(MyMAC, MyIP, "GiveExplorerError", "*Error Loading MFT Table");
	//			}
	//			delete searchCore;
	//		}
	//		else if (!wcscmp(filesys, L"FAT32"))
	//		{
	//			int ret1 = 1;
	//			char* TempStr = new char[DATASTRINGMESSAGELEN];
	//			memset(TempStr, '\0', DATASTRINGMESSAGELEN);
	//			char* m_DataStr = new char[1000];
	//			sprintf_s(m_DataStr, 1000, "5|.|5|0|2|1970/01/01 08:00:00|1970/01/01 08:00:00|1970/01/01 08:00:00|null,null,null|0|1\n");
	//			strcat_s(TempStr, DATASTRINGMESSAGELEN, m_DataStr);
	//			vector<DeleteFATFileInfo> FATDeleteFile;
	//			DWORD LastCluster = 0;
	//			unsigned int Count = 1;
	//			unsigned int ProgressCount = 1;
	//			clock_t start;
	//			start = clock();
	//			bool ret = pfat->initFDT(this, info->MAC, info->IP, TempStr, ProgressCount, Count, LastCluster, &FATDeleteFile, start);
	//			if (ret)
	//			{
	//				if (!FATDeleteFile.empty())
	//				{
	//					vector<DeleteFATFileInfo>::iterator it;
	//					for (it = FATDeleteFile.begin(); it != FATDeleteFile.end(); it++)
	//					{
	//						LastCluster++;
	//						if (LastCluster == 5)
	//							LastCluster++;
	//						wchar_t* wstr = new wchar_t[1024];
	//						DWORD FirstClister = (*it).FirstDataCluster + 5;
	//						if ((*it).isDirectory == 0)
	//						{
	//							TCHAR* m_MD5Str = new TCHAR[50];
	//							memset(m_MD5Str, '\0', 50);
	//							TCHAR* Signaturestr = new TCHAR[20];
	//							memset(Signaturestr, '\0', 20);
	//							//DWORD FirstCluster = newEntry->GetTheFirstDataCluster()+5;
	//							if (pfat->FileHashAndSignature((*it).FirstDataCluster, (*it).FileSize, (*it).FileName, m_MD5Str, Signaturestr))
	//							{
	//								swprintf_s(wstr, 1024, L"%lu|%s|%lu|1|%d|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%s,%s,%lu|%lu|1\n",
	//									LastCluster, (*it).FileName, (*it).ParentFirstDataCluster, (*it).isDirectory
	//									, (*it).CT.wYear, (*it).CT.wMonth, (*it).CT.wDay, (*it).CT.wHour, (*it).CT.wMinute, (*it).CT.wSecond,
	//									(*it).WT.wYear, (*it).WT.wMonth, (*it).WT.wDay, (*it).WT.wHour, (*it).WT.wMinute, (*it).WT.wSecond,
	//									(*it).AT.wYear, (*it).AT.wMonth, (*it).AT.wDay, (*it).AT.wHour, (*it).AT.wMinute, (*it).AT.wSecond, m_MD5Str, Signaturestr, FirstClister, (*it).FileSize);
	//							}
	//							else
	//							{
	//								swprintf_s(wstr, 1024, L"%lu|%s|%lu|1|%d|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|null,null,%lu|%lu|1\n",
	//									LastCluster, (*it).FileName, (*it).ParentFirstDataCluster, (*it).isDirectory
	//									, (*it).CT.wYear, (*it).CT.wMonth, (*it).CT.wDay, (*it).CT.wHour, (*it).CT.wMinute, (*it).CT.wSecond,
	//									(*it).WT.wYear, (*it).WT.wMonth, (*it).WT.wDay, (*it).WT.wHour, (*it).WT.wMinute, (*it).WT.wSecond,
	//									(*it).AT.wYear, (*it).AT.wMonth, (*it).AT.wDay, (*it).AT.wHour, (*it).AT.wMinute, (*it).AT.wSecond, FirstClister, (*it).FileSize);
	//							}
	//							delete[] Signaturestr;
	//							delete[] m_MD5Str;
	//						}
	//						else
	//						{
	//							swprintf_s(wstr, 1024, L"%lu|%s|%lu|1|%d|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|null,null,%lu|%lu|1\n",
	//								LastCluster, (*it).FileName, (*it).ParentFirstDataCluster, (*it).isDirectory
	//								, (*it).CT.wYear, (*it).CT.wMonth, (*it).CT.wDay, (*it).CT.wHour, (*it).CT.wMinute, (*it).CT.wSecond,
	//								(*it).WT.wYear, (*it).WT.wMonth, (*it).WT.wDay, (*it).WT.wHour, (*it).WT.wMinute, (*it).WT.wSecond,
	//								(*it).AT.wYear, (*it).AT.wMonth, (*it).AT.wDay, (*it).AT.wHour, (*it).AT.wMinute, (*it).AT.wSecond, FirstClister, (*it).FileSize);
	//						}
	//						char* m_DataStr = CStringToCharArray(wstr, CP_UTF8);
	//						strcat_s(TempStr, DATASTRINGMESSAGELEN, m_DataStr);
	//						ProgressCount++;
	//						Count++;
	//						clock_t endTime = clock();
	//						if ((endTime - start) > 300000)
	//						{
	//							char* ProgressStr = new char[10];
	//							sprintf_s(ProgressStr, 10, "%u", ProgressCount);
	//							strcat_s(TempStr, DATASTRINGMESSAGELEN, ProgressStr);
	//							ret1 = socketsend->SendDataToServer(functionName_GiveExplorerData, TempStr);
	//							if (ret1 <= 0)
	//							{
	//								delete[] ProgressStr;
	//								delete[] m_DataStr;
	//								delete[] wstr;
	//								break;
	//							}
	//							start = clock();
	//							Count = 0;
	//							memset(TempStr, '\0', DATASTRINGMESSAGELEN);
	//							delete[] ProgressStr;
	//						}
	//						else
	//						{
	//							if ((Count % 60) == 0 && Count >= 60)
	//							{
	//								char* ProgressStr = new char[10];
	//								sprintf_s(ProgressStr, 10, "%u", ProgressCount);
	//								strcat_s(TempStr, DATASTRINGMESSAGELEN, ProgressStr);
	//								ret1 = socketsend->SendDataToServer(functionName_GiveExplorerData, TempStr);
	//								if (ret1 <= 0)
	//								{
	//									delete[] ProgressStr;
	//									delete[] m_DataStr;
	//									delete[] wstr;
	//									break;
	//								}
	//								start = clock();
	//								Count = 0;
	//								memset(TempStr, '\0', DATASTRINGMESSAGELEN);
	//								delete[] ProgressStr;
	//							}
	//						}
	//						delete[] m_DataStr;
	//						delete[] wstr;
	//					}
	//				}
	//				if (ret1 > 0)
	//				{
	//					if (TempStr[0] != '\0')
	//					{
	//						char* ProgressStr = new char[10];
	//						sprintf_s(ProgressStr, 10, "%u", ProgressCount);
	//						strcat_s(TempStr, DATASTRINGMESSAGELEN, ProgressStr);
	//						ret1 = socketsend->SendDataToServer(functionName_GiveExplorerData, TempStr);
	//						delete[] ProgressStr;
	//					}
	//				}
	//				if (ret1 > 0)
	//					SendDataMsgToServer(MyMAC, MyIP, "GiveExplorerEnd", "");
	//			}
	//			else
	//				SendDataMsgToServer(MyMAC, MyIP, "GiveExplorerError", "*Error Loading FAT Table");
	//			FATDeleteFile.clear();
	//			delete[] m_DataStr;
	//			delete[] TempStr;
	//		}
	//		else
	//		{
	//			char* TempStr = new char[DATASTRINGMESSAGELEN];
	//			memset(TempStr, '\0', DATASTRINGMESSAGELEN);
	//			char* m_DataStr = new char[1000];
	//			sprintf_s(m_DataStr, 1000, "5|.|5|0|2|1970/01/01 08:00:00|1970/01/01 08:00:00|1970/01/01 08:00:00|null|0|9\n");
	//			strcat_s(TempStr, DATASTRINGMESSAGELEN, m_DataStr);
	//			//wchar_t * DriveStr = CharArrayToWString(drive,CP_UTF8);
	//			unsigned int ProgressCount = 1;
	//			unsigned int Index = 5;
	//			unsigned int Count = 1;
	//			int ret = 1;
	//			SysExplorerSearch(drive, 5, Index, TempStr, ProgressCount, Count);
	//			if (TempStr[0] != '\0')
	//			{
	//				char* ProgressStr = new char[10];
	//				sprintf_s(ProgressStr, 10, "%u", ProgressCount);
	//				strcat_s(TempStr, DATASTRINGMESSAGELEN, ProgressStr);
	//				ret = SendDataMsgToServer(MyMAC, MyIP, "GiveExplorerData", TempStr);
	//				if (ret <= 0)
	//				{
	//					Client_Socket->Close();
	//				}
	//				delete[] ProgressStr;
	//			}
	//			//if(Client_Socket->IsOpened())
	//			if (ret > 0)
	//				SendDataMsgToServer(MyMAC, MyIP, "GiveExplorerEnd", "");
	//			delete[] m_DataStr;
	//			delete[] TempStr;
	//		}
	//	}
	//	else
	//	{
	//		SendDataMsgToServer(MyMAC, MyIP, "GiveExplorerError", "*Error Not Format");
	//	}
	//}
	//else
	//{
	//	SendDataMsgToServer(MyMAC, MyIP, "GiveExplorerError", "*Error No Drive");
	//}
	//delete[] filesys;
	//delete[] volname;
	//delete[] drive;
	//delete m_Info;
	//delete[] wMgs;
	return 0;

}

int Task::GiveExplorerEnd() { return 0; }
int Task::CollectInfo() { return 0; }
int Task::GiveCollectProgress() { return 0; }
int Task::GiveCollectDataInfo() { return 0; }

int Task::GiveCollectData(StrPacket* Mgs) {
	DWORD UserModePid = (DWORD)atoi(Mgs->csMsg);
	CollectionComputerInfo(UserModePid);
	return 0;
}

int Task::OpenCheckthread(StrPacket* udata) {
	// strcpy(UUID,udata->csMsg);
	// GiveDetectInfoFirst();

	// std::thread CheckConnectThread(&SocketManager::CheckConnect, this);
	// CheckConnectThread.join();

	// store key into registry

	return GiveDetectInfoFirst();

}

int Task::UpdateDetectMode(StrPacket* udata) {

	std::vector<std::string>DetectMode = tool.SplitMsg(udata->csMsg);
	for (int i = 0; i < DetectMode.size(); i++) {
		if (i == 0) info->DetectProcess = DetectMode[i][0] - '0';
		else if (i == 1) info->DetectNetwork = DetectMode[i][0] - '0';
		else printf("UpdateDetectMode parse failed\n");
	}
	return GiveDetectInfo();

}

int Task::GetProcessInfo(StrPacket* udata) { return 0; }
int Task::GetDrive(StrPacket* udata) { return 0; }
int Task::GetScanInfoData_(StrPacket* udata) { return GiveProcessData(); }
//int Task::ExplorerInfo(StrPacket* udata) { return 0; }
int Task::TransportExplorer(StrPacket* udata) { return 0; }
int Task::GetCollectInfo(StrPacket* udata) { return 0; }
int Task::GetCollectInfoData(StrPacket* udata) { return 0; }
int Task::DataRight(StrPacket* udata) { return 0; }








/*---------------------------------------------------------------------------------------------------------------------------------------------------------*/

void Task::CollectionComputerInfo(DWORD UserModePid)
{
	TCHAR* m_FullDbPath = new TCHAR[MAX_PATH_EX];
	GetMyPath(m_FullDbPath);
	_tcscat_s(m_FullDbPath, MAX_PATH_EX, _T("\\collectcomputerinfo.db"));

	if (_waccess(m_FullDbPath, 00))
	{
		CreateProcessForCollection(m_FullDbPath);
		TCHAR* ConfigPath = new TCHAR[MAX_PATH_EX];
		GetMyPath(ConfigPath);
		_tcscat_s(ConfigPath, MAX_PATH_EX, _T("\\predefine.config"));
		map<string, vector<PredefineObj>> mapPredefine;
		if (LoadPredefineConfig(ConfigPath, &mapPredefine))
		{
			char* InfoStr = new char[MAX_PATH_EX];
			BYTE* TmpBuffer = new BYTE[DATABUFFER];
			InsertFromToInCombination(m_FullDbPath, &mapPredefine, MyMAC, MyIP);
		}
		if (!_waccess(m_FullDbPath, 00))
		{
			SendDbFileToServer(m_FullDbPath);
			DeleteFile(m_FullDbPath);
		}
		delete[] ConfigPath;
	}
	delete[] m_FullDbPath;
}

bool Task::LoadPredefineConfig(TCHAR* ConfigPath, map<string, vector<PredefineObj>>* mapPredefine)
{
	bool bResult = false;
	if (!_waccess(ConfigPath, 00))
	{
		fstream fin;
		fin.open(ConfigPath, ios::in);
		{
			char* linestr = new char[BUF_SIZE];
			string DefineName, TableName, OutStr;
			while (fin.getline(linestr, BUF_SIZE, '\n'))
			{
				DefineName.clear();
				vector<PredefineObj> tmpVec;
				ParsePredefineConfig(linestr, &DefineName, &tmpVec);
				if (!DefineName.empty() && tmpVec.size() > 0)
				{
					mapPredefine->insert(pair<string, vector<PredefineObj>>(DefineName, tmpVec));
				}
				// DefineName.clear();
				// TableName.clear();
				// ParsePredefineConfig(linestr, &DefineName, &TableName, &OutStr);
				// TableName.erase(remove_if(TableName.begin(), TableName.end(), isspace), TableName.end());
				// DefineName.erase(remove_if(DefineName.begin(), DefineName.end(), isspace), DefineName.end());
				// 
				// if (!TableName.empty() && !DefineName.empty())
				// {
				// 	PredefineObj tmpPredefineObj;
				// 	tmpPredefineObj.DefineName = DefineName;
				// 	tmpPredefineObj.FilterCondition = OutStr;
				// 	if (mapPredefine->find(TableName) != mapPredefine->end())
				// 	{
				// 		mapPredefine->at(TableName).push_back(tmpPredefineObj);
				// 	}
				// 	else
				// 	{
				// 		vector<PredefineObj> tmpvecPredefineObj;
				// 		tmpvecPredefineObj.push_back(tmpPredefineObj);
				// 		mapPredefine->insert(pair <string, vector<PredefineObj>>(TableName, tmpvecPredefineObj));
				// 	}
				// }
			}
		}
		fin.close();
		if (mapPredefine->size() > 0)
		{
			bResult = true;
		}
	}

	return bResult;
}

void Task::ParsePredefineConfig(char* str, string* defineName, vector<PredefineObj>* Vmp)
{
	char* psc;
	char* next_token = NULL;
	bool bFirst = true;
	psc = strtok_s(str, ";", &next_token);

	while (psc != NULL)
	{
		if (bFirst == true)
		{
			*defineName = psc;
			bFirst = false;
		}
		else
		{
			char* subStr;
			char* next_token_subStr = NULL;
			subStr = strtok_s(psc, "|", &next_token_subStr);
			char* next_token_client = NULL;
			subStr = strtok_s(subStr, ",", &next_token_client);
			vector<string> vecClients;
			while (subStr != NULL)
			{
				string client = subStr;
				vecClients.push_back(client);
				subStr = strtok_s(NULL, ",", &next_token_client);
			}

			subStr = strtok_s(psc, "|", &next_token_subStr);
			string TableName = subStr;
			subStr = strtok_s(NULL, "|", &next_token_subStr);
			string FilterStr = subStr;
			PredefineObj tmpObj;
			//TableName.erase(std::remove_if(TableName.begin(), TableName.end(), isspace), TableName.end());
			TableName.erase(std::remove_if(TableName.begin(), TableName.end(), [](char c) {
				return std::isspace(static_cast<unsigned char>(c));
				}), TableName.end());

			tmpObj.TableName = TableName;
			tmpObj.vecFilterCondition = FilterStr;
			if (!tmpObj.TableName.empty() && !tmpObj.vecFilterCondition.empty())
			{
				Vmp->push_back(tmpObj);
			}
		}
		psc = strtok_s(NULL, ";", &next_token);
	}
}

bool Task::GetQueryByTable(string* query, string TableName, string QueryFilter)
{
	bool bResult = true;
	*query += "SELECT ";
	if (TableName == "ARPCache") { *query += "id, internetaddress, physicaladdress "; }
	else if (TableName == "BaseService") { *query += "id, name, pathname FROM "; }
	else if (TableName == "ChromeDownload") { *query += "id, download_url, start_time, target_path "; }
	else if (TableName == "ChromeHistory") { *query += "id, url, last_visit_time, title FROM "; }
	else if (TableName == "ChromeKeywordSearch") { *query += "id, term, title FROM "; }
	else if (TableName == "ChromeLogin") { *query += "id, origin_url, date_created, username_value "; }
	else if (TableName == "EventApplication") { *query += "id, eventid, createdsystemtime, evtrenderdata "; }
	else if (TableName == "EventSecurity") { *query += "id, eventid, createdsystemtime, evtrenderdata "; }
	else if (TableName == "EventSystem") { *query += "id, eventid, createdsystemtime, evtrenderdata "; }
	else if (TableName == "FirefoxHistory") { *query += "id, url, last_visit_time, title "; }
	else if (TableName == "FirefoxLogin") { *query += "id, hostname, timelastused, username "; }
	else if (TableName == "IECache") { *query += "id, sourceurlname, lastaccesstime, localfilename "; }
	else if (TableName == "IEHistory") { *query += "id, url, visitedtime, title "; }
	else if (TableName == "InstalledSoftware") { *query += "id, displayname, registrytime, publisher "; }
	else if (TableName == "MUICache") { *query += "id, applicationpath, applicationname "; }
	else if (TableName == "Network") { *query += "id, processname, remoteaddress "; }
	else if (TableName == "NetworkResources") { *query += "id, resourcesname, ipaddress "; }
	else if (TableName == "OpenedFiles") { *query += "id, processname, processid "; }
	else if (TableName == "Prefetch") { *query += "id, processname, lastruntime, processpath "; }
	else if (TableName == "Process") { *query += "id, process_name, processcreatetime, process_path "; }
	else if (TableName == "RecentFile") { *query += "id, name, accesstime, fullpath "; }
	else if (TableName == "Service") { *query += "id, name, pathname "; }
	else if (TableName == "ShellBags") { *query += "id, path, lastmodifiedtime, slotpath "; }
	else if (TableName == "Shortcuts") { *query += "id, shortcutname, modifytime, linkto "; }
	else if (TableName == "StartRun") { *query += "id, name, command "; }
	else if (TableName == "SystemInfo") { *query += "id, hotfix, os "; }
	else if (TableName == "TaskSchedule") { *query += "id, name, lastruntime, path "; }
	else if (TableName == "USBdevices") { *query += "id, device_description, last_arrival_date, device_letter "; }
	else if (TableName == "UserAssist") { *query += "id, name, modifiedtime, of_times_executed "; }
	else if (TableName == "UserProfiles") { *query += "id, username, lastlogontime, usersid "; }
	else if (TableName == "Wireless") { *query += "id, profilename, lastmodifiedtime, authentication "; }
	else if (TableName == "JumpList") { *query += "id, fullpath, recordtime, application_id "; }
	else if (TableName == "WindowsActivity") { *query += "id, app_id, last_modified_on_client, activity_type "; }
	else if (TableName == "NetworkDataUsageMonitor") { *query += "id, app_name, timestamp, bytes_sent "; }
	else if (TableName == "AppResourceUsageMonitor") { *query += "id, app_name, timestamp, backgroundbyteswritten "; }
	else { bResult = false; }

	if (bResult == true)
	{
		*query += "FROM ";
		*query += TableName;
		if (!QueryFilter.empty())
		{
			*query += " WHERE ";
			*query += QueryFilter;
		}
	}

	return bResult;
}

void Task::CreateProcessForCollection(TCHAR* DBName)
{
	TCHAR* RunExeStr = new TCHAR[MAX_PATH];
	TCHAR* RunComStr = new TCHAR[512];
	GetModuleFileName(GetModuleHandle(NULL), RunExeStr, MAX_PATH);
	//TCHAR* InfoStr = CharArrayToWString(Mgs->csMsg, CP_UTF8);

	int Sendret;
	char* InfoStr = new char[MAX_PATH_EX];
	char* TmpBuffer = new char[DATABUFFER];

	int iLen = sizeof(CollectionNums) / sizeof(CollectionNums[0]);
	for (int i = 0; i < iLen; i++)
	{
		//memset(RunComStr, '\0', MAX_PATH_EX);
		//swprintf_s(RunComStr, MAX_PATH_EX, L"\"%s\" 42780 \"%s\" %d", MyName, DBName, CollectionNums[i]);
		//RunProcess(RunExeStr, RunComStr, TRUE, FALSE);
		
		TCHAR* m_FilePath = new TCHAR[MAX_PATH_EX];
		GetMyPath(m_FilePath);
		_tcscat_s(m_FilePath, MAX_PATH_EX, _T("\\Collection.dll"));
		HMODULE m_lib = LoadLibrary(m_FilePath);
		if (m_lib)
		{
			TCHAR buffer[20]; // Adjust the buffer size as needed
			_sntprintf_s(buffer, sizeof(buffer) / sizeof(TCHAR), _T("%d"), CollectionNums[i]);
			TCHAR* tcharString = buffer;

			//CollectionProcess(m_lib, DBName, tcharString);
			FreeLibrary(m_lib);
		}
		
		memset(InfoStr, '\0', MAX_PATH_EX);
		sprintf_s(InfoStr, MAX_PATH_EX, "%d/%d", i + 1, iLen);
		memset(TmpBuffer, '\x0', DATABUFFER);
		memcpy(TmpBuffer, InfoStr, strlen(InfoStr));
		const char* GiveCollectProgress = "GiveCollectProgress";
		char* pc = new char[100];
		strcpy_s(pc, sizeof(pc), GiveCollectProgress);
		pc = const_cast<char*>(GiveCollectProgress);
		Sendret = socketsend->SendMessageToServer(pc, TmpBuffer);
//		Sendret = SendDataBufToServer(MyMAC, MyIP, "GiveCollectProgress", TmpBuffer);  //改成senddata

	}
	//delete[] InfoStr;
	delete[] RunComStr;
	delete[] RunExeStr;
}

void Task::CollectionComputeInfo(DWORD UserModePid)
{
	TCHAR* m_FullDbPath = new TCHAR[MAX_PATH_EX];
	GetMyPath(m_FullDbPath);
	_tcscat_s(m_FullDbPath, MAX_PATH_EX, _T("\\collectcomputerinfo.db"));

	if (_waccess(m_FullDbPath, 00))
	{
		CreateProcessForCollection(m_FullDbPath);
		TCHAR* ConfigPath = new TCHAR[MAX_PATH_EX];
		GetMyPath(ConfigPath);
		_tcscat_s(ConfigPath, MAX_PATH_EX, _T("\\predefine.config"));
		map<string, vector<PredefineObj>> mapPredefine;
		if (LoadPredefineConfig(ConfigPath, &mapPredefine))
		{
			char* InfoStr = new char[MAX_PATH_EX];
			BYTE* TmpBuffer = new BYTE[DATABUFFER];
			InsertFromToInCombination(m_FullDbPath, &mapPredefine, MyMAC, MyIP);
		}
		if (!_waccess(m_FullDbPath, 00))
		{
			SendDbFileToServer(m_FullDbPath);
			DeleteFile(m_FullDbPath);
		}
		delete[] ConfigPath;
	}
	delete[] m_FullDbPath;
}


void Task::GiveScanDataSendServer(char* pMAC, char* pIP, char* pMode, map<DWORD, ProcessInfoData>* pFileInfo, vector<UnKnownDataInfo>* pUnKnownData)
{
	char* functionName_GiveScanDataInfo = new char[24];
	strcpy_s(functionName_GiveScanDataInfo, 24, "GiveScanDataInfo");
	char* functionName_GiveScanData = new char[24];
	strcpy_s(functionName_GiveScanData, 24, "GiveScanData");
	char* functionName_GiveScanDataOver = new char[24];
	strcpy_s(functionName_GiveScanDataOver, 24, "GiveScanDataOver");
	char* functionName_GiveProcessUnknownInfo = new char[24];
	strcpy_s(functionName_GiveProcessUnknownInfo, 24, "GiveProcessUnknownInfo");
	char* functionName_GiveProcessUnknownEnd = new char[24];
	strcpy_s(functionName_GiveProcessUnknownEnd, 24, "GiveProcessUnknownEnd");
	char* null = new char[5];
	strcpy_s(null, 5, "null");
	char* functionName_GiveScanDataEnd = new char[24];
	strcpy_s(functionName_GiveScanDataEnd, 24, "GiveScanDataEnd");
	
	
	
	char* TempStr = new char[DATASTRINGMESSAGELEN];
	//set<wstring> m_Hash;
	//set<wstring>::iterator ht;
	map<DWORD, ProcessInfoData>::iterator vit;
	int AllCount = (int)pFileInfo->size();
	int m_Count = 0;
	for (vit = pFileInfo->begin(); vit != pFileInfo->end(); vit++)
	{
		if (_tcscmp(vit->second.ProcessHash, _T("null")))
		{
			TCHAR* wtr1 = new TCHAR[4096];
			swprintf_s(wtr1, 4096, _T("%lu|%s|%s|%s|%d"), vit->first, vit->second.ProcessName, vit->second.ProcessPath, vit->second.ProcessHash, vit->second.Injected);
			char* str1 = CStringToCharArray(wtr1, CP_UTF8);
			sprintf_s(TempStr, DATASTRINGMESSAGELEN, "%s|%s|%d|%d|0", str1, pMode, m_Count, AllCount);
			int ret = socketsend->SendMessageToServer(functionName_GiveScanDataInfo, TempStr);
			if (ret <= 0)
			{
				printf("data info send failed\n");
				delete[] str1;
				delete[] wtr1;
				break;
			}
			else
			{
				printf("data info send success\n");
				wchar_t* wTempStr = new wchar_t[DATASTRINGMESSAGELEN];
				swprintf_s(wTempStr, DATASTRINGMESSAGELEN, L"%lu|ProcessScan|%s|%s|%s|%s|%s|%lu|%s|%s|%d,%s|%d|%d|%d|%s|%d,%d"
					, vit->first, vit->second.ProcessCTime, vit->second.ProcessTime, vit->second.ProcessName, vit->second.ProcessPath, vit->second.ProcessHash,
					vit->second.ParentID, vit->second.ParentCTime, vit->second.ParentPath, vit->second.Injected, vit->second.UnKnownHash, vit->second.StartRun, vit->second.HideAttribute, vit->second.HideProcess
					, vit->second.SignerSubjectName, vit->second.InjectionPE, vit->second.InjectionOther);
				char* cTempStr = CStringToCharArray(wTempStr, CP_UTF8);
				strcpy_s(TempStr, DATASTRINGMESSAGELEN, cTempStr);
				delete[] cTempStr;
				//delete[] wTempStr;
				printf("entering abnormal dll\n");

				if (!vit->second.Abnormal_dll.empty())
				{
					printf("abnormal dll not empty\n");
					strcat_s(TempStr, DATASTRINGMESSAGELEN, "|");
					set<string>::iterator dllit;
					printf("loop start\n");
					for (dllit = vit->second.Abnormal_dll.begin(); dllit != vit->second.Abnormal_dll.end(); dllit++)
					{
						printf("sending GiveScanData\n");
						char* dllstr = new char[4096];
						sprintf_s(dllstr, 4096, "%s;", (*dllit).c_str());
						printf("sprintf_s success\n");
						if ((strlen(dllstr) + strlen(TempStr)) >= DATASTRINGMESSAGELEN)
						{
							printf("length bigger than DATASTRINGMESSAGELEN\n");
							ret = socketsend->SendMessageToServer(functionName_GiveScanData, TempStr);
							memset(TempStr, '\0', DATASTRINGMESSAGELEN);
							if (ret <= 0)
							{
								delete[] dllstr;
								break;
							}
						}
						else {
							printf("length smaller than DATASTRINGMESSAGELEN\n");
						}
						strcat_s(TempStr, DATASTRINGMESSAGELEN, dllstr);
						delete[] dllstr;
					}
					if (ret <= 0)
						break;
				}
				else
					strcat_s(TempStr, DATASTRINGMESSAGELEN, "|null");
				if (!vit->second.InlineHookInfo.empty())
				{
					strcat_s(TempStr, DATASTRINGMESSAGELEN, "|");
					set<string>::iterator Inlineit;
					for (Inlineit = vit->second.InlineHookInfo.begin(); Inlineit != vit->second.InlineHookInfo.end(); Inlineit++)
					{
						char* Inlinestr = new char[4096];
						sprintf_s(Inlinestr, 4096, "%s;", (*Inlineit).c_str());
						if ((strlen(Inlinestr) + strlen(TempStr)) >= DATASTRINGMESSAGELEN)
						{
							ret = socketsend->SendMessageToServer(functionName_GiveScanData, TempStr);
							memset(TempStr, '\0', DATASTRINGMESSAGELEN);
							if (ret <= 0)
							{
								delete[] Inlinestr;
								break;
							}
						}
						strcat_s(TempStr, DATASTRINGMESSAGELEN, Inlinestr);
						delete[] Inlinestr;
					}
					if (ret <= 0)
						break;
				}
				else
					strcat_s(TempStr, DATASTRINGMESSAGELEN, "|null");
				if (!vit->second.NetString.empty())
				{
					strcat_s(TempStr, DATASTRINGMESSAGELEN, "|");
					set<string>::iterator netit;
					for (netit = vit->second.NetString.begin(); netit != vit->second.NetString.end(); netit++)
					{
						char* netstr = new char[4096];
						sprintf_s(netstr, 4096, "%s;", (*netit).c_str());
						if ((strlen(netstr) + strlen(TempStr)) >= DATASTRINGMESSAGELEN)
						{
							ret = socketsend->SendMessageToServer(functionName_GiveScanData, TempStr);
							memset(TempStr, '\0', DATASTRINGMESSAGELEN);
							if (ret <= 0)
							{
								delete[] netstr;
								break;
							}
						}
						strcat_s(TempStr, DATASTRINGMESSAGELEN, netstr);
						delete[] netstr;
					}
					if (ret <= 0)
						break;
				}
				else
					strcat_s(TempStr, DATASTRINGMESSAGELEN, "|null");
			}
			delete[] str1;
			delete[] wtr1;
			//if(ret <= 0)
			//	break;
			//else
			//{
			//	ret = SendDataMsgToServer(pMAC,pIP,"GiveScanDataOver",TempStr);
			//	if(ret <= 0)
			//		break;
			//	else
			//		memset(TempStr,'\0',DATASTRINGMESSAGELEN);
			//}
			ret = socketsend->SendMessageToServer(functionName_GiveScanDataOver, TempStr);

			if (ret <= 0)
				break;
			else
				memset(TempStr, '\0', DATASTRINGMESSAGELEN);
		}
		m_Count++;
	}
	//m_Hash.clear();
	if (!pUnKnownData->empty())
	{
		vector<UnKnownDataInfo>::iterator ut;
		memset(TempStr, '\0', DATASTRINGMESSAGELEN);
		wchar_t* wUnKownInfoStr = new wchar_t[DATASTRINGMESSAGELEN];
		int ret = 1;
		char* cUnKownInfoStr = NULL;
		for (ut = pUnKnownData->begin(); ut != pUnKnownData->end(); ut++)
		{
			swprintf_s(wUnKownInfoStr, DATASTRINGMESSAGELEN, L"%lu|%s|%d", (*ut).Pid, (*ut).ProcessName, (*ut).SizeInfo);
			cUnKownInfoStr = CStringToCharArray(wUnKownInfoStr, CP_UTF8);
			sprintf_s(TempStr, DATASTRINGMESSAGELEN, "%s", cUnKownInfoStr);
			ret = socketsend->SendMessageToServer(functionName_GiveProcessUnknownInfo, TempStr);
			if (ret <= 0)
				break;
			memset(TempStr, '\0', DATASTRINGMESSAGELEN);
			if ((*ut).SizeInfo > DATASTRINGMESSAGELEN /*&& ret != -3*/){
				int tmplen = (*ut).SizeInfo;
				for (DWORD i = 0; i < (*ut).SizeInfo; i += DATASTRINGMESSAGELEN)
				{
					char* TmpBuffer = new char[DATASTRINGMESSAGELEN];
					memset(TmpBuffer, '\x00', DATASTRINGMESSAGELEN);
					if (tmplen < DATASTRINGMESSAGELEN)
						memcpy(TmpBuffer, (*ut).Data + i, tmplen);
					else
					{
						memcpy(TmpBuffer, (*ut).Data + i, DATASTRINGMESSAGELEN);
						tmplen -= DATASTRINGMESSAGELEN;
					}
					ret = socketsend->SendMessageToServer(functionName_GiveProcessUnknownInfo, TmpBuffer);
					//Sendret = m_Client->SendDataBufToServer(pInfo->MAC,pInfo->IP,WorkStr,TmpBuffer);
					delete[] TmpBuffer;
					if (ret <= 0)
					{
						break;
					}
				}
				if (ret <= 0)
					break;
			}
			else
			{
				char* TmpBuffer = new char[DATASTRINGMESSAGELEN];
				memset(TmpBuffer, '\x00', DATASTRINGMESSAGELEN);
				memcpy(TmpBuffer, (*ut).Data, (*ut).SizeInfo);
				ret = socketsend->SendMessageToServer(functionName_GiveProcessUnknownInfo, TmpBuffer);
				//Sendret = m_Client->SendDataBufToServer(pInfo->MAC,pInfo->IP,WorkStr,TmpBuffer);
				delete[] TmpBuffer;
				if (ret <= 0)
					break;
			}
			
			ret = socketsend->SendMessageToServer(functionName_GiveProcessUnknownEnd, null);
			if (ret <= 0)
				break;
			delete[] cUnKownInfoStr;
			cUnKownInfoStr = NULL;
		}
		if (cUnKownInfoStr != NULL)
			delete[] cUnKownInfoStr;
		delete[] wUnKownInfoStr;
		for (ut = pUnKnownData->begin(); ut != pUnKnownData->end(); ut++)
		{
			delete[](*ut).Data;
		}
	}
	delete[] TempStr;
	socketsend->SendMessageToServer(functionName_GiveScanDataEnd, pMode);
}



void Task::SendDbFileToServer(TCHAR* DBName)
{
	HANDLE m_File = CreateFile(DBName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (m_File != INVALID_HANDLE_VALUE)
	{
		DWORD m_Filesize = GetFileSize(m_File, NULL);
		int Sendret;
		char* InfoStr = new char[MAX_PATH_EX];
		sprintf_s(InfoStr, MAX_PATH_EX, "%lu", m_Filesize);
		char* TmpBuffer = new char[DATABUFFER];
		memset(TmpBuffer, '\x0', DATABUFFER);
		memcpy(TmpBuffer, InfoStr, strlen(InfoStr));
		const char* GiveCollectDataInfo = "GiveCollectDataInfo";
		const char* GiveCollectData = "GiveCollectData";
		const char* GiveCollectDataEnd = "GiveCollectDataEnd";
		char* pc = new char[100];
		strcpy_s(pc, sizeof(pc),  GiveCollectDataInfo);
		pc = const_cast<char*>(GiveCollectDataInfo);
		Sendret = socketsend->SendMessageToServer(pc, TmpBuffer);
		//Sendret = SendDataBufToServer(MyMAC, MyIP, "GiveCollectDataInfo", TmpBuffer);
		if (Sendret > 0)
		{
			DWORD readsize;
			BYTE* buffer = new BYTE[m_Filesize];
			ReadFile(m_File, buffer, m_Filesize, &readsize, NULL);
			if (m_Filesize > DATABUFFER)
			{
				DWORD tmplen = m_Filesize;
				for (DWORD i = 0; i < m_Filesize; i += DATABUFFER)
				{
					memset(TmpBuffer, '\x00', DATABUFFER);
					if (tmplen < DATABUFFER)
						memcpy(TmpBuffer, buffer + i, tmplen);
					else
					{
						memcpy(TmpBuffer, buffer + i, DATABUFFER);
						tmplen -= DATABUFFER;
					}
					char* pc = new char[100];
					strcpy_s(pc, sizeof(pc), GiveCollectData);
					pc = const_cast<char*>(GiveCollectData);
					Sendret = socketsend->SendMessageToServer(pc, TmpBuffer);
					//Sendret = SendDataBufToServer(MyMAC, MyIP, "GiveCollectData", TmpBuffer);

					if (Sendret == 0 || Sendret == -1)
						break;
				}
				memset(TmpBuffer, '\x00', BUFSIZE64);
				char* pc = new char[100];
				strcpy_s(pc, sizeof(pc), GiveCollectDataEnd);
				pc = const_cast<char*>(GiveCollectDataEnd);
				Sendret = socketsend->SendMessageToServer(pc, TmpBuffer);
				//SendDataBufToServer(MyMAC, MyIP, "GiveCollectDataEnd", TmpBuffer);
			}
			else
			{
				memset(TmpBuffer, '\x00', DATABUFFER);
				memcpy(TmpBuffer, buffer, m_Filesize);
				char* pc = new char[100];
				strcpy_s(pc, sizeof(pc), GiveCollectData);
				pc = const_cast<char*>(GiveCollectData);
				Sendret = socketsend->SendMessageToServer(pc, TmpBuffer);
				//Sendret = SendDataBufToServer(MyMAC, MyIP, "GiveCollectData", TmpBuffer);
				memset(TmpBuffer, '\x00', BUFSIZE64);
				//SendDataBufToServer(MyMAC, MyIP, "GiveCollectDataEnd", TmpBuffer);
			}
			delete[] buffer;
		}
		if (Sendret > 0)
		{
			memset(TmpBuffer, '\x00', BUFSIZE64);
			char* pc = new char[100];
			strcpy_s(pc, sizeof(pc), GiveCollectDataEnd);
			pc = const_cast<char*>(GiveCollectDataEnd);
			Sendret = socketsend->SendMessageToServer(pc, TmpBuffer);
			//SendDataBufToServer(MyMAC, MyIP, "GiveCollectDataEnd", TmpBuffer);
			delete[] TmpBuffer;
			CloseHandle(m_File);

		}
	}
	else
	{
		BYTE* TmpBuffer = new BYTE[DATABUFFER];
		memset(TmpBuffer, '\x00', BUFSIZE64);
		//SendDataBufToServer(MyMAC, MyIP, "GiveCollectDataError", TmpBuffer);
		delete[] TmpBuffer;
	}
}

int Task::IsSendDataRight(StrPacket* Mgs)
{
	if (!strcmp(Mgs->MAC, MyMAC) && !strcmp(Mgs->IP, MyIP))
	{
		printf("%s\n%s\n", Mgs->DoWorking, Mgs->csMsg);
		if (!strcmp(Mgs->DoWorking, "DataRight"))
		{
			//MessageBox(0,L"A",0,0);
			return 1;
		}
		else if (!strcmp(Mgs->DoWorking, "Again"))
		{
			return 0;
		}
		else
		{
			printf("%s\n", "Error Work");
			return -1;
		}
	}
	else
	{
		printf("%s\n", "Packet Error");
		return -1;
	}
}

/*
int Task::SendDataBufToServer(char* m_MAC, char* m_IP, char* m_Work, BYTE* buf)
{
	BufferDataPacket GetServerMessage;
	strcpy_s(GetServerMessage.MAC, m_MAC);
	strcpy_s(GetServerMessage.IP, m_IP);
	strcpy_s(GetServerMessage.Status, m_Work);
	memset(GetServerMessage.Buffer, '\x00', DATABUFFER);
	memcpy(GetServerMessage.Buffer, buf, DATABUFFER);
	char* buff = (char*)&GetServerMessage;
	CAES* aes;
	aes = new CAES;
	aes->SetKeys(BIT128, AESKey);
	aes->EncryptBuffer((BYTE*)buff, SENDBUFSIZE);
	int ret = Client_Socket->OnSend(buff, SENDBUFSIZE);
	delete aes;
	if (ret == 0 || ret == -1)
		return ret;
	else
	{
		for (int i = 0; i <= 10; i++)
		{
			BYTE data[RECVSIZE];
			memset(data, 0, RECVSIZE);
			long ret_len;
			if (!Client_Socket->OnReceive(&data, RECVSIZE, ret_len))
				return -1;
			if (ret_len == 0)
				return -1; // 對方已斷線 //

			CAES* aes;
			aes = new CAES;
			aes->SetKeys(BIT128, AESKey);
			aes->DecryptBuffer(data, RECVSIZE);
			delete aes;
			StrPacket* udata;
			udata = (StrPacket*)data;
			int ret1 = IsSendDataRight(udata);
			if (ret1 == 1)
				break;
			else if (ret1 == 0)
			{
				printf("Again\n");
				if (i == 10)
					ret = -1;
				else
					ret = Client_Socket->OnSend(buff, SENDBUFSIZE);
			}
			else
				ret = -1;
		}
		return ret;
	}
}
*/


bool Task::InsertFromToInCombination(TCHAR* DBName, const map<string, vector<PredefineObj>>* mapPredefine, char* MAC, char* IP)
{
	bool bResult = false;
	sqlite3* m_db;
	string query;
	if (!sqlite3_open16(DBName, &m_db))
	{
		for (auto& Predefine : *mapPredefine)
		{
			query.clear();
			query = "CREATE TABLE ";
			query += Predefine.first;
			query += " (id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT, ip TEXT, \
													table_id INTEGER, item TEXT, date TEXT, type TEXT, etc TEXT)";
			// 可能已存在，所以不判斷建成功失敗 或者進去調整function
			WriteSQLiteDB(m_db, (char*)query.c_str());
			for (auto& TableFilter : Predefine.second)
			{
				query.clear();
				if (GetQueryByTable(&query, TableFilter.TableName, TableFilter.vecFilterCondition))
				{
					vector<CombineObj> vecCombineObj;
					GetDataByQuery(query, m_db, &vecCombineObj);
					int id = 0;
					query.clear();
					query = "SELECT MAX(id) FROM";
					query += Predefine.first;

					sqlite3_stmt* statement;
					if (sqlite3_prepare(m_db, query.c_str(), -1, &statement, 0) == SQLITE_OK)
					{
						int res = 0;
						if (res != SQLITE_DONE && res != SQLITE_ERROR)
						{
							res = sqlite3_step(statement);
							if (res == SQLITE_ROW)
							{
								id = sqlite3_column_int(statement, 0);
							}
						}
					}
					sqlite3_finalize(statement);
					WriteDataSetToDB(m_db, vecCombineObj, Predefine.first, MAC, IP, TableFilter.TableName, id);
				}
			}
		}

		// for (auto& Predefine : *mapPredefine)
		// {
		// 	string query;
		// 	vector<CombineObj> vecCombineObj;
		// 	for (auto& defineObj : Predefine.second)
		// 	{
		// 		query = "CREATE TABLE ";
		// 		query += defineObj.DefineName;
		// 		query += " (id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT, ip TEXT, \
		// 											table_id INTEGER, item TEXT, date TEXT, type TEXT, etc TEXT)";
		// 		if (WriteSQLiteDB(m_db, (char*)query.c_str()))
		// 		{
		// 			query.clear();
		// 			if (GetQueryByTable(&query, Predefine.first, defineObj.FilterCondition))
		// 			{
		// 				GetDataByQuery(query, m_db, &vecCombineObj);
		// 				if (vecCombineObj.size() > 0)
		// 				{
		// 					WriteDataSetToDB(m_db, vecCombineObj, defineObj.DefineName, MAC, IP, Predefine.first);
		// 				}
		// 			}
		// 		}
		// 	}
		// 	logBuffer = "MergeDb query : " + query;
		// 	m_pLogObj->EnqueueErrorLog(logBuffer);
		// }

		char* InfoStr = new char[MAX_PATH_EX];
		BYTE* TmpBuffer = new BYTE[DATABUFFER];
		memset(InfoStr, '\0', MAX_PATH_EX);
		sprintf_s(InfoStr, MAX_PATH_EX, "%d/%d", 35, 35);
		memset(TmpBuffer, '\x0', DATABUFFER);
		memcpy(TmpBuffer, InfoStr, strlen(InfoStr));
		auto Sendret = socketsend->SendMessageToServer(functionName_GiveProcessUnknownInfo, TmpBuffer);
		//auto Sendret = SendDataBufToServer(MyMAC, MyIP, "GiveCollectProgress", TmpBuffer);
	}
	sqlite3_close(m_db);
	return bResult;
}


/*
bool Task::GetDataByQuery(const string& query, sqlite3* m_db, vector<CombineObj>* vecCombineObj)
{
	sqlite3_stmt* statement;
	if (sqlite3_prepare(m_db, query.c_str(), -1, &statement, 0) == SQLITE_OK)
	{
		int ctotal = sqlite3_column_count(statement);
		int res = 0;
		while (res != SQLITE_DONE && res != SQLITE_ERROR)
		{
			res = sqlite3_step(statement);
			if (res == SQLITE_ROW)
			{
				CombineObj tmp;
				tmp.Table_id = (char*)sqlite3_column_text(statement, 0);
				tmp.Item = (char*)sqlite3_column_text(statement, 1);
				if (ctotal == 4)
				{
					tmp.Date = (char*)sqlite3_column_text(statement, 2);
					tmp.ETC = (char*)sqlite3_column_text(statement, 3);
				}
				else
				{
					tmp.Date = "";
					tmp.ETC = (char*)sqlite3_column_text(statement, 2);
				}
				vecCombineObj->push_back(tmp);
			}
		}
	}
	sqlite3_finalize(statement);
	return vecCombineObj->size() > 0 ? true : false;
}

bool Task::WriteDataSetToDB(sqlite3* m_db, const vector<CombineObj> vecCombineObj, const string DefineName, const string MAC, const string IP, const string TableName, int id)
{
	string query;
	int index = id;
	for (auto CombineObj : vecCombineObj)
	{
		query.clear();
		query += "INSERT INTO ";
		query += DefineName;
		query += " VALUES (";
		query += to_string(index);
		query += ", \'";
		query += MAC;
		query += "\', \'";
		query += IP;
		query += "\', ";
		query += CombineObj.Table_id;
		query += ", \"";
		if (CombineObj.Item.find("\"") != string::npos)
		{
			replace(CombineObj.Item.begin(), CombineObj.Item.end(), '\"', '\'');
		}
		query += CombineObj.Item;
		query += "\", \'";
		query += CombineObj.Date;
		query += "\', \'";
		query += TableName;
		query += "\', \"";
		if (CombineObj.ETC.find("\"") != string::npos)
		{
			replace(CombineObj.ETC.begin(), CombineObj.ETC.end(), '\"', '\'');
		}
		query += CombineObj.ETC;
		query += "\")";
		WriteSQLiteDB(m_db, (char*)query.c_str());
		index++;
	}
	return true;
}

bool Task::WriteSQLiteDB(sqlite3* pdb, char* pQuery)
{
	bool ret = false;
	//char* query = CStringToCharArray((wchar_t *)pQuery.c_str(), CP_UTF8);
	char* ErrMsg = NULL;
	if (sqlite3_exec(pdb, pQuery, NULL, 0, &ErrMsg) == SQLITE_OK)
	{
		ret = true;
	}
	//printf("%s\n",ErrMsg);
	sqlite3_free(ErrMsg);
	//delete [] query;
	return ret;
}
*/
