#include "MemoryTree.h"


MemoryTree::MemoryTree(Info* infoInstance, SocketSend* socketSendInstance) {
	info = infoInstance;
	socketsend = socketSendInstance;

	MemoryTree_txt = new TCHAR[MAX_PATH_EX];
	GetMyPath(MemoryTree_txt);
	_tcscat_s(MemoryTree_txt, MAX_PATH_EX, MemoryTree_txt_filename);
	DeleteFile(MemoryTree_txt);
	MemoryTree_zip = new TCHAR[MAX_PATH_EX];
	GetMyPath(MemoryTree_zip);
	_tcscat_s(MemoryTree_zip, MAX_PATH_EX, MemoryTree_zip_filename);
	DeleteFile(MemoryTree_zip);
	outFile.open(MemoryTree_txt, std::ios::app);
	if (!outFile.is_open()) log.logger("Error", "MemoryTree.txt open failed");

}

void MemoryTree::DoTask() {

	MemProcess* mem_process = new MemProcess;
	map<DWORD, process_info> process_list;
	map<DWORD, process_info> Checkprocess_list;
	bool ret = false;
	time_t LoadProcessTime = 0;
#if defined _M_X64
	ret = mem_process->EnumProcess(&process_list, LoadProcessTime);
#elif defined _M_IX86
	ret = EnumRing0Process(&process_list, LoadProcessTime);
	if (!ret)
		ret = EnumProcess(&process_list, LoadProcessTime);
	else
	{
		time_t LoadCheckProcessTime = 0;
		if (EnumProcess(&Checkprocess_list, LoadCheckProcessTime))
			CheckProcessHide(&process_list, &Checkprocess_list, LoadProcessTime);
	}
#endif
	if (ret)
	{
		char* TempStr = new char[DATASTRINGMESSAGELEN];
		memset(TempStr, '\0', DATASTRINGMESSAGELEN);
		int DataCount = 0;
		map<DWORD, process_info>::iterator it;
		map<DWORD, process_info>::iterator st;
		for (it = process_list.begin();it != process_list.end();it++)
		{
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
			mem_process->GetProcessInfo(it->first, m_Path, NULL, m_UserName, m_ComStr);
			if (_tcscmp(m_Path, _T("null")))
			{
				IsPacked = CheckIsPackedPE(m_Path);
			}
			st = process_list.find(it->second.parent_pid);
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
			swprintf_s(wstr, 2048, L"%lu|%d|%s|%lld|%s|%lld|%s|%s|%d|%s|%d\n", it->first, it->second.parent_pid, it->second.process_name, it->second.ProcessCreateTime, ParentName, ParentTime, m_Path, m_UserName, IsPacked, m_ComStr, it->second.IsHide);
			DataCount++;
			//wprintf(L"%s\n",wstr);
			char* m_DataStr = CStringToCharArray(wstr, CP_UTF8);
			strcat_s(TempStr, DATASTRINGMESSAGELEN, m_DataStr);
			//int ret = m_Client->SendDataMsgToServer(pMAC,pIP,"GiveExplorerData",m_DataStr);
			delete[] wstr;
			delete[] m_UserName;
			delete[] ParentName;
			//delete [] m_Time;
			delete[] m_ComStr;
			delete[] m_Path;
			if ((DataCount % 30) == 0 && DataCount >= 30)
			{
				if (outFile.good()) outFile << TempStr;
				else log.logger("Error", "write to MemoryTree.txt failed");
				//int ret = m_Client->SendDataMsgToServer(pMAC, pIP, "GiveProcessData", TempStr);
				int ret = 1;
				if (ret == 0 || ret == -1)
				{
					delete[] m_DataStr;
					delete[] TempStr;
					process_list.clear();
					return;
				}
				memset(TempStr, '\0', DATASTRINGMESSAGELEN);
			}
			delete[] m_DataStr;
		}
		if (TempStr[0] != '\0')
		{
			//MessageBoxA(0,TempStr,0,0);
			if (outFile.good()) outFile << TempStr;
			else log.logger("Error", "write to MemoryTree.txt failed");
			//int ret = m_Client->SendDataMsgToServer(pMAC, pIP, "GiveProcessData", TempStr);
			int ret = 1;
			if (ret == 0 || ret == -1)
			{
				delete[] TempStr;
				process_list.clear();
				return;
			}
		}
		delete[] TempStr;
	}
	Checkprocess_list.clear();
	process_list.clear();
}