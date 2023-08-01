#include <iostream>
#include <string>
#include <cstring>
#include <future>

#include "task.h"



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
    functionMap["GiveCollectData"] = std::bind(&Task::GiveCollectData, this);
    functionMap["GiveCollectDataEnd"] = std::bind(&Task::GiveCollectDataEnd, this);

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

	// test
	GiveProcessData();

    return ret;
}


int Task::GetScanInfoData() {
    // return socketmanager->SendMessageToServer("GetScanInfoData","Ring0Process");
    return 0;
}

int Task::GiveProcessData() {
	printf("sending GiveProcessData\n");
	char* Scan = new char[5];
	strcpy_s(Scan, 5, "Scan");

    std::set<DWORD> m_ApiName;
    tool.LoadApiPattern(&m_ApiName);
    std::map<DWORD, ProcessInfoData> m_ProcessInfo;
    std::vector<UnKnownDataInfo> m_UnKnownData;
    MemProcess* m_MemPro = new MemProcess;
	printf("start scan...\n");
    m_MemPro->ScanRunNowProcess(this, &m_ProcessInfo, &m_ApiName, &m_UnKnownData);
	printf("finish scan...\n");
    if (!m_ProcessInfo.empty()) GiveScanDataSendServer(info->MAC, info->IP, Scan, &m_ProcessInfo, &m_UnKnownData);

	delete m_MemPro;
    m_UnKnownData.clear();
    m_ProcessInfo.clear();
    m_ApiName.clear();
    int ret = 1;
    return ret;

	//char* functionName_GiveProcessData = new char[24];
	//strcpy_s(functionName_GiveProcessData, 24, "GiveProcessData");


	//map<DWORD, process_info> process_list;
	//bool ret = false;
	//time_t LoadProcessTime = 0;
	//MemProcess* m_MemPro = new MemProcess;
	//ret = m_MemPro->EnumProcess(&process_list, LoadProcessTime);

	//if (ret) {
	//	char* TempStr = new char[DATASTRINGMESSAGELEN];
	//	memset(TempStr, '\0', DATASTRINGMESSAGELEN);
	//	int DataCount = 0;
	//	map<DWORD, process_info>::iterator it;
	//	map<DWORD, process_info>::iterator st;
	//	for (it = process_list.begin(); it != process_list.end(); it++)
	//	{
	//		//printf("enter for loop\n");
	//		TCHAR* m_Path = new TCHAR[512];
	//		TCHAR* m_ComStr = new TCHAR[512];
	//		//TCHAR * m_Time = new TCHAR[20];
	//		TCHAR* ParentName = new TCHAR[MAX_PATH];
	//		TCHAR* m_UserName = new TCHAR[_MAX_FNAME];
	//		BOOL IsPacked = FALSE;
	//		time_t ParentTime = 0;
	//		_tcscpy_s(m_Path, 512, _T("null"));
	//		_tcscpy_s(m_ComStr, 512, _T("null"));
	//		//_tcscpy_s(m_Time,20,_T("null"));
	//		_tcscpy_s(ParentName, MAX_PATH, _T("null"));
	//		_tcscpy_s(m_UserName, _MAX_FNAME, _T("null"));
	//		//printf("CheckIsPackedPE start\n");
	//		m_MemPro->GetProcessInfo(it->first, m_Path, NULL, m_UserName, m_ComStr);
	//		if (_tcscmp(m_Path, _T("null")))
	//		{
	//			IsPacked = CheckIsPackedPE(m_Path);
	//		}
	//		st = process_list.find(it->second.parent_pid);
	//		//printf("process create time start\n");
	//		if (st != process_list.end())
	//		{
	//			if (st->second.ProcessCreateTime <= it->second.ProcessCreateTime)
	//			{
	//				_tcscpy_s(ParentName, MAX_PATH, st->second.process_name);
	//				ParentTime = st->second.ProcessCreateTime;
	//			}
	//			//GetProcessOnlyTime(it->second.parent_pid,ParentTime);
	//			//if(ParentTime < 0)
	//			//	ParentTime = 0;
	//		}
	//		wchar_t* wstr = new wchar_t[2048];
	//		// swprintf_s(wstr, 2048, L"%lu|%d|%s|%lld|%s|%lld|%s|%s|%d|%s|%d\n", it->first, it->second.process_name, m_ComStr, m_Path, it->second.parent_pid, ParentName);
	//		swprintf_s(wstr, 2048, L"%lu|%d|%s|%lld|%s|%lld|%s|%s|%d|%s|%d\n", it->first, it->second.parent_pid, it->second.process_name, it->second.ProcessCreateTime, ParentName, ParentTime, m_Path, m_UserName, IsPacked, m_ComStr, it->second.IsHide);
	//		DataCount++;
	//		//wprintf(L"%s\n",wstr);
	//		char* m_DataStr = CStringToCharArray(wstr, CP_UTF8);
	//		strcat_s(TempStr, DATASTRINGMESSAGELEN, m_DataStr);

	//		//delete[] wstr;
	//		delete[] m_UserName;
	//		delete[] ParentName;
	//		delete[] m_ComStr;
	//		delete[] m_Path;

	//		//printf("send start %d\n", DataCount);
	//		if ((DataCount % 30) == 0 && DataCount >= 30)
	//		{
	//			//printf("%s\n", TempStr);
	//			int ret = socketsend->SendDataToServer(functionName_GiveProcessData, TempStr);
	//			if (ret == 0 || ret == -1)
	//			{
	//				delete[] m_DataStr;
	//				delete[] TempStr;
	//				process_list.clear();
	//				return ret;
	//			}
	//			memset(TempStr, '\0', DATASTRINGMESSAGELEN);
	//		}
	//		delete[] m_DataStr;
	//	}
	//	//printf("send start second\n");
	//	if (TempStr[0] != '\0')
	//	{
	//		//printf("send start second in\n");
	//		//MessageBoxA(0,TempStr,0,0);
	//		int ret = socketsend->SendDataToServer(functionName_GiveProcessData, TempStr);
	//		if (ret == 0 || ret == -1)
	//		{
	//			delete[] TempStr;
	//			process_list.clear();
	//			return ret;
	//		}
	//	}
	//	delete[] TempStr;
	//}
	//process_list.clear();
	//return 1;
    
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
		std::cout << m_Count << std::endl;
		if (_tcscmp(vit->second.ProcessHash, _T("null")))
		{
			/*TCHAR* wtr1 = new TCHAR[4096];
			swprintf_s(wtr1, 4096, _T("%lu|%s|%s|%s|%d"), vit->first, vit->second.ProcessName, vit->second.ProcessPath, vit->second.ProcessHash, vit->second.Injected);
			char* str1 = CStringToCharArray(wtr1, CP_UTF8);
			sprintf_s(TempStr, DATASTRINGMESSAGELEN, "%s|%s|%d|%d|0", str1, pMode, m_Count, AllCount);
			int ret = socketsend->SendDataToServer(functionName_GiveScanDataInfo, TempStr);*/
			int ret = 1;
			if (ret <= 0)
			{
				printf("data info send failed\n");
				//delete[] str1;
				//delete[] wtr1;
				break;
			}
			else
			{
				/*printf("data info send success\n");*/
				wchar_t* wTempStr = new wchar_t[DATASTRINGMESSAGELEN];


				HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, vit->first);
				MemProcess* m_MemPro = new MemProcess;
				TCHAR* Comstr = new TCHAR[MAX_PATH_EX];
				DWORD ret1 = m_MemPro->GetRemoteCommandLineW(processHandle, Comstr, MAX_PATH_EX);
				if (ret1 == 0) _tcscpy_s(Comstr, MAX_PATH_EX, _T(""));
				CloseHandle(processHandle);

				TCHAR* ParentName = new TCHAR[MAX_PATH];
				TCHAR* ParentPath = new TCHAR[MAX_PATH];
				_tcscpy_s(ParentName, 512, _T("null"));
				_tcscpy_s(ParentPath, 512, _T("null"));
				auto it = pFileInfo->find(vit->second.ParentID);
				if (it != pFileInfo->end()) {
					_tcscpy_s(ParentName, MAX_PATH, it->second.ProcessName);
					_tcscpy_s(ParentPath, MAX_PATH, it->second.ProcessPath);
				}


				//swprintf_s(wTempStr, DATASTRINGMESSAGELEN, L"%lu|ProcessScan|%s|%s|%s|%s|%s|%lu|%s|%s|%d,%s|%d|%d|%d|%s|%d,%d"
				//	, vit->first, vit->second.ProcessCTime, vit->second.ProcessTime, vit->second.ProcessName, vit->second.ProcessPath, vit->second.ProcessHash,
				//	vit->second.ParentID, vit->second.ParentCTime, vit->second.ParentPath, vit->second.Injected, vit->second.UnKnownHash, vit->second.StartRun, vit->second.HideAttribute, vit->second.HideProcess
				//	, vit->second.SignerSubjectName, vit->second.InjectionPE, vit->second.InjectionOther);
				
				

				swprintf_s(wTempStr, DATASTRINGMESSAGELEN, L"%s|%s|%s|%s|%s|%ld|%s|%s|%s|%ld|%d,%d|%d|%d|%d,%d"
					, vit->second.ProcessName, vit->second.ProcessCTime, Comstr, vit->second.ProcessHash, vit->second.ProcessPath,
					vit->second.ParentID, ParentName, ParentPath, vit->second.SignerSubjectName, vit->first, vit->second.InjectionPE, vit->second.InjectionOther
					, vit->second.Injected, vit->second.StartRun, vit->second.HideProcess, vit->second.HideAttribute
					);


				delete[] Comstr;

				char* cTempStr = CStringToCharArray(wTempStr, CP_UTF8);
				strcpy_s(TempStr, DATASTRINGMESSAGELEN, cTempStr);
				delete[] cTempStr;
				//delete[] wTempStr;
				printf("entering abnormal dll\n");
				if (!vit->second.Abnormal_dll.empty())
				{
					strcat_s(TempStr, DATASTRINGMESSAGELEN, "|");
					set<string>::iterator dllit;
					for (dllit = vit->second.Abnormal_dll.begin(); dllit != vit->second.Abnormal_dll.end(); dllit++)
					{
						char* dllstr = new char[4096];
						sprintf_s(dllstr, 4096, "%s;", (*dllit).c_str());
						if ((strlen(dllstr) + strlen(TempStr)) >= DATASTRINGMESSAGELEN)
						{
							ret = socketsend->SendDataToServer(functionName_GiveScanData, TempStr);
							memset(TempStr, '\0', DATASTRINGMESSAGELEN);
							if (ret <= 0)
							{
								delete[] dllstr;
								break;
							}
						}
						strcat_s(TempStr, DATASTRINGMESSAGELEN, dllstr);
						delete[] dllstr;
					}
					if (ret <= 0)
						break;
				}
				else
					strcat_s(TempStr, DATASTRINGMESSAGELEN, "|null");


				printf("entering inline hook\n");
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
							ret = socketsend->SendDataToServer(functionName_GiveScanData, TempStr);
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



				/*if (!vit->second.NetString.empty())
				{
					strcat_s(TempStr, DATASTRINGMESSAGELEN, "|");
					set<string>::iterator netit;
					for (netit = vit->second.NetString.begin(); netit != vit->second.NetString.end(); netit++)
					{
						char* netstr = new char[4096];
						sprintf_s(netstr, 4096, "%s;", (*netit).c_str());
						if ((strlen(netstr) + strlen(TempStr)) >= DATASTRINGMESSAGELEN)
						{
							ret = socketsend->SendDataToServer(functionName_GiveScanData, TempStr);
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
					strcat_s(TempStr, DATASTRINGMESSAGELEN, "|null");*/


			}
			//delete[] str1;
			//delete[] wtr1;


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


			ret = socketsend->SendDataToServer(functionName_GiveScanDataOver, TempStr);
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
		printf("pUnKnownData\n");
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
			if ((*ut).SizeInfo > DATASTRINGMESSAGELEN /*&& ret != -3*/)
			{
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
int Task::GiveCollectData() { 
	
	return 0;
}
int Task::GiveCollectDataEnd() { return 0; }


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