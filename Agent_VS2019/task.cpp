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
    functionFromServerMap["ExplorerInfo"] = &Task::ExplorerInfo;
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

    if (strcpy_s(Key, sizeof(Key), "") == 0) printf("copy key success\n");
    else printf("copy key failed\n");

    if (strcpy_s(DigitalSignatureHash, sizeof(DigitalSignatureHash), "123456") == 0) printf("copy sign success\n");
    else printf("copy sign failed\n");

    if (strcpy_s(functionName, 24, "GiveInfo") == 0) printf("copy function success\n");
    else printf("copy function failed\n");



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
    return socketsend->SendMessageToServer(functionName, buff);
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
    m_MemPro->ScanRunNowProcess(this, &m_ProcessInfo, &m_ApiName, &m_UnKnownData);
    
    if (!m_ProcessInfo.empty()) GiveScanDataSendServer(info->MAC, info->IP, Scan, &m_ProcessInfo, &m_UnKnownData);

	delete m_MemPro;
    m_UnKnownData.clear();
    m_ProcessInfo.clear();
    m_ApiName.clear();
    int ret = 1;
    return ret;

//#ifndef _WIN64
//    SystemModules* m_SysModules = new SystemModules;
//    map<string, SendSSDTINFO> m_SSDTInfo;
//    map<DWORD,IDTINFO> m_IDTInfo;
//    m_SysModules->ScanSystemModules(/*this,*/&m_SSDTInfo/*,&m_IDTInfo*/);
//    if (m_SSDTInfo.empty())
//    {
//        if (!m_ProcessInfo.empty())
//            GiveScanDataSendServer(Mgs->MAC, Mgs->IP, ScanMode, &m_ProcessInfo, &m_UnKnownData);
//    }
//    else
//    {
//        if(!m_ProcessInfo.empty())
//        GiveScanDataSendServerRing0(Mgs->MAC, Mgs->IP, ScanMode, &m_ProcessInfo, &m_SSDTInfo, &m_UnKnownData);
//    }
//    m_IDTInfo.clear();
//    m_SSDTInfo.clear();
//    delete m_SysModules;
//#else
//#endif
    

    
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
				delete[] str1;
				delete[] wtr1;
				break;
			}
			else
			{
				wchar_t* wTempStr = new wchar_t[DATASTRINGMESSAGELEN];
				swprintf_s(wTempStr, DATASTRINGMESSAGELEN, L"%lu|ProcessScan|%s|%s|%s|%s|%s|%lu|%s|%s|%d,%s|%d|%d|%d|%s|%d,%d"
					, vit->first, vit->second.ProcessCTime, vit->second.ProcessTime, vit->second.ProcessName, vit->second.ProcessPath, vit->second.ProcessHash,
					vit->second.ParentID, vit->second.ParentCTime, vit->second.ParentPath, vit->second.Injected, vit->second.UnKnownHash, vit->second.StartRun, vit->second.HideAttribute, vit->second.HideProcess
					, vit->second.SignerSubjectName, vit->second.InjectionPE, vit->second.InjectionOther);
				char* cTempStr = CStringToCharArray(wTempStr, CP_UTF8);
				strcpy_s(TempStr, DATASTRINGMESSAGELEN, cTempStr);
				delete[] cTempStr;
				delete[] wTempStr;

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
							ret = socketsend->SendMessageToServer(functionName_GiveScanData, TempStr);
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
    return 0;

}
int Task::GiveExplorerEnd() { return 0; }
int Task::CollectInfo() { return 0; }
int Task::GiveCollectProgress() { return 0; }
int Task::GiveCollectDataInfo() { return 0; }
int Task::GiveCollectData() { return 0; }
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
int Task::ExplorerInfo(StrPacket* udata) { return 0; }
int Task::TransportExplorer(StrPacket* udata) { return 0; }
int Task::GetCollectInfo(StrPacket* udata) { return 0; }
int Task::GetCollectInfoData(StrPacket* udata) { return 0; }
int Task::DataRight(StrPacket* udata) { return 0; }