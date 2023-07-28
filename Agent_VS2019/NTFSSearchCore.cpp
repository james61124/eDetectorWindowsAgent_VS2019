//#include "stdafx.h"
#include "NTFSSearchCore.h"
#include "NTFS.h"
#include "AES.h"
#include "internal.h"
//#include "TransportData.h"


static MSCompStatus lznt1_decompress_chunk(const_rest_bytes in, const const_bytes in_end, rest_bytes out, const const_bytes out_end, size_t* RESTRICT _out_len);
ENTRY_POINT MSCompStatus lznt1_decompress(const_rest_bytes in, size_t in_len, rest_bytes out, size_t* RESTRICT _out_len);
typedef NTSTATUS(*pRtlDecompressBufferEx)(
	USHORT CompressionFormat,
	PUCHAR UncompressedBuffer,
	ULONG  UncompressedBufferSize,
	PUCHAR CompressedBuffer,
	ULONG  CompressedBufferSize,
	PULONG FinalUncompressedSize,
	PVOID  WorkSpace
	);
typedef NTSTATUS(*pRtlGetCompressionWorkSpaceSize)(
	USHORT CompressionFormatAndEngine,
	PULONG CompressBufferWorkSpaceSize,
	PULONG CompressFragmentWorkSpaceSize
	);
NTFSSearchCore::NTFSSearchCore()
{

}
NTFSSearchCore::~NTFSSearchCore()
{

}
ULONGLONG NTFSSearchCore::GetRecordsCount(wchar_t vol_name)
{
	CNTFSVolume* m_curSelectedVol = new CNTFSVolume(vol_name);

	if (m_curSelectedVol == NULL)
	{
		delete m_curSelectedVol;
		return 0;
	}
	if (!m_curSelectedVol->IsVolumeOK())
	{
		delete m_curSelectedVol;
		return 0;
	}
	ULONGLONG m_Count = m_curSelectedVol->GetRecordsCount();
	delete m_curSelectedVol;
	return m_Count;
}
BOOL NTFSSearchCore::GetRecoverInfo(wchar_t vol_name, unsigned int pIndex, TCHAR* pFileName, ULONGLONG& m_FileSize)
{
	CNTFSVolume* m_curSelectedVol = new CNTFSVolume(vol_name);
	if (m_curSelectedVol == NULL)
	{
		delete m_curSelectedVol;
		return FALSE;
	}
	if (!m_curSelectedVol->IsVolumeOK())
	{
		delete m_curSelectedVol;
		return FALSE;
	}
	CFileRecord* fr = new CFileRecord(m_curSelectedVol);
	if (fr == NULL)
	{
		delete m_curSelectedVol;
		return FALSE;
	}
	fr->SetAttrMask(MASK_FILE_NAME | MASK_DATA);	// StdInfo will always be parsed
	if (!fr->ParseFileRecord(pIndex))
	{
		delete fr;
		delete m_curSelectedVol;
		return FALSE;
	}
	if (!fr->ParseFileAttrs())
	{
		delete fr;
		delete m_curSelectedVol;
		return FALSE;
	}
	TCHAR fn[MAX_PATH];
	if (fr->GetFileName(fn, MAX_PATH) <= 0)
	{
		delete fr;
		delete m_curSelectedVol;
		return FALSE;
	}
	if (_tcsicmp(fn, pFileName))
	{
		delete fr;
		delete m_curSelectedVol;
		return FALSE;
	}
	if (!fr->IsDirectory())
	{
		const CAttrBase* data = fr->FindStream();
		if (data)
		{
			m_FileSize = data->GetDataSize();
		}
	}
	else
	{
		delete fr;
		delete m_curSelectedVol;
		return FALSE;
	}
	delete fr;
	delete m_curSelectedVol;
	return TRUE;
}
int NTFSSearchCore::Search(void* argv, wchar_t vol_name, char* pMAC, char* pIP)
{
	//TransportData* m_Client = (TransportData*)argv;

	//CNTFSVolume* m_curSelectedVol = new CNTFSVolume(vol_name);

	//if (m_curSelectedVol == NULL)
	//{
	//	//AfxMessageBox(L"Error when getVolumeByName");
	//	delete m_curSelectedVol;
	//	return 1;
	//}

	//if (!m_curSelectedVol->IsVolumeOK())
	//{
	//	//AfxMessageBox(L"Not a valid NTFS volume or NTFS version < 3.0\n");
	//	delete m_curSelectedVol;
	//	return 1;
	//}

	//unsigned int m_progressIdx;
	//unsigned int m_Count = 0;
	//char* TempStr = new char[DATASTRINGMESSAGELEN];
	//memset(TempStr, '\0', DATASTRINGMESSAGELEN);
	//for (m_progressIdx = MFT_IDX_MFT; m_progressIdx < m_curSelectedVol->GetRecordsCount(); m_progressIdx++)
	//{
	//	CFileRecord* fr = new CFileRecord(m_curSelectedVol);

	//	if (fr == NULL)
	//		continue;	// skip to next

	//	// Only parse Standard Information and File Name attributes
	//	fr->SetAttrMask(MASK_FILE_NAME | MASK_DATA);	// StdInfo will always be parsed
	//	if (!fr->ParseFileRecord(m_progressIdx))
	//	{
	//		delete fr;
	//		continue;	// skip to next
	//	}

	//	if (!fr->ParseFileAttrs())
	//	{
	//		delete fr;
	//		continue;	// skip to next
	//	}

	//	TCHAR fn[MAX_PATH];
	//	if (fr->GetFileName(fn, MAX_PATH) <= 0)
	//	{
	//		delete fr;
	//		continue;	// skip to next
	//	}

	//	ULONGLONG datalen = 0;

	//	if (!fr->IsDirectory())
	//	{
	//		const CAttrBase* data = fr->FindStream();

	//		//if(data)
	//		//{
	//		//	datalen = data->GetDataSize();
	//		//		//delete data;
	//		//}
	//		if (data)
	//		{
	//			datalen = data->GetDataSize();
	//			if (fr->IsCompressed() && datalen == 0)
	//				datalen = fr->GetFileSize();
	//		}
	//		else
	//		{
	//			if (fr->IsCompressed() && datalen == 0)
	//				datalen = fr->GetFileSize();
	//		}
	//	}
	//	ULONGLONG ParentId = 0;
	//	ParentId = fr->GetParentRef();
	//	if (ParentId == 0)
	//		ParentId = 5;
	//	else
	//		ParentId = ParentId & 0x0000FFFFFFFFFFFF;
	//	FILETIME	FileCreateTime;		// File creation time
	//	FILETIME	FileWriteTime;		// File altered time
	//	FILETIME	FileAccessTime;		// File read time
	//	FILETIME	EntryModifiedTime;
	//	fr->GetFileCreateTime(&FileCreateTime);
	//	fr->GetFileWriteTime(&FileWriteTime);
	//	fr->GetFileAccessTime(&FileAccessTime);
	//	fr->GetEntryModifiedTime(&EntryModifiedTime);
	//	SYSTEMTIME systemCreateTime;
	//	SYSTEMTIME systemWriteTime;
	//	SYSTEMTIME systemAccessTime;
	//	SYSTEMTIME systemModifiedTime;
	//	FileTimeToSystemTime(&FileCreateTime, &systemCreateTime);
	//	FileTimeToSystemTime(&FileWriteTime, &systemWriteTime);
	//	FileTimeToSystemTime(&FileAccessTime, &systemAccessTime);
	//	FileTimeToSystemTime(&EntryModifiedTime, &systemModifiedTime);
	//	wchar_t CreateTimeWstr[50];
	//	wchar_t WriteTimeWstr[50];
	//	wchar_t AccessTimeWstr[50];
	//	wchar_t EntryModifiedTimeWstr[50];
	//	swprintf_s(CreateTimeWstr, 50, L"%02hu/%02hu/%02hu %02hu:%02hu:%02hu", systemCreateTime.wYear, systemCreateTime.wMonth, systemCreateTime.wDay, systemCreateTime.wHour, systemCreateTime.wMinute, systemCreateTime.wSecond);
	//	swprintf_s(WriteTimeWstr, 50, L"%02hu/%02hu/%02hu %02hu:%02hu:%02hu", systemWriteTime.wYear, systemWriteTime.wMonth, systemWriteTime.wDay, systemWriteTime.wHour, systemWriteTime.wMinute, systemWriteTime.wSecond);
	//	swprintf_s(AccessTimeWstr, 50, L"%02hu/%02hu/%02hu %02hu:%02hu:%02hu", systemAccessTime.wYear, systemAccessTime.wMonth, systemAccessTime.wDay, systemAccessTime.wHour, systemAccessTime.wMinute, systemAccessTime.wSecond);
	//	if (EntryModifiedTime.dwLowDateTime != 0)
	//		swprintf_s(EntryModifiedTimeWstr, 50, L"%02hu/%02hu/%02hu %02hu:%02hu:%02hu", systemModifiedTime.wYear, systemModifiedTime.wMonth, systemModifiedTime.wDay, systemModifiedTime.wHour, systemModifiedTime.wMinute, systemModifiedTime.wSecond);
	//	else
	//		swprintf_s(EntryModifiedTimeWstr, 50, L"1");
	//	wchar_t* wstr = new wchar_t[1024];
	//	swprintf_s(wstr, 1024, L"%u|%s|%llu|%d|%d|%s|%s|%s|%s|%llu|0\n", m_progressIdx, fn, ParentId, fr->IsDeleted(), fr->IsDirectory(), CreateTimeWstr, WriteTimeWstr, AccessTimeWstr, EntryModifiedTimeWstr, datalen);
	//	//wprintf(L"%s\n",wstr);
	//	char* m_DataStr = CStringToCharArray(wstr, CP_UTF8);
	//	strcat_s(TempStr, DATASTRINGMESSAGELEN, m_DataStr);
	//	//int ret = m_Client->SendDataMsgToServer(pMAC,pIP,"GiveExplorerData",m_DataStr);
	//	delete[] wstr;
	//	if ((m_Count % 60) == 0 && m_Count >= 60)
	//	{
	//		char* ProgressStr = new char[10];
	//		sprintf_s(ProgressStr, 10, "%u", m_progressIdx);
	//		strcat_s(TempStr, DATASTRINGMESSAGELEN, ProgressStr);
	//		int ret = m_Client->SendDataMsgToServer(pMAC, pIP, "GiveExplorerData", TempStr);
	//		if (ret == 0 || ret == -1)
	//		{
	//			delete[] ProgressStr;
	//			delete[] m_DataStr;
	//			delete[] TempStr;
	//			delete fr;
	//			delete m_curSelectedVol;
	//			return 1;
	//		}
	//		memset(TempStr, '\0', DATASTRINGMESSAGELEN);
	//		delete[] ProgressStr;
	//	}
	//	//if(ret == 0 || ret == -1)
	//	//{
	//	//	delete [] m_DataStr;
	//	//	delete fr;
	//	//	delete m_curSelectedVol;
	//	//	return 1;
	//	//}
	//	m_Count++;
	//	delete[] m_DataStr;
	//	delete fr;
	//}
	//if (TempStr[0] != '\0')
	//{
	//	char* ProgressStr = new char[10];
	//	sprintf_s(ProgressStr, 10, "%u", m_progressIdx);
	//	strcat_s(TempStr, DATASTRINGMESSAGELEN, ProgressStr);
	//	int ret = m_Client->SendDataMsgToServer(pMAC, pIP, "GiveExplorerData", TempStr);
	//	if (ret == 0 || ret == -1)
	//	{
	//		delete[] ProgressStr;
	//		delete[] TempStr;
	//		delete m_curSelectedVol;
	//		return 1;
	//	}
	//	delete[] ProgressStr;
	//}
	//delete[] TempStr;
	//delete m_curSelectedVol;

	return 0;
}
int NTFSSearchCore::LoadScanExplorer(void* argv, ScanExplorerInfo* pInfo, char* pMAC, char* pIP)
{
	//TransportData* m_Client = (TransportData*)argv;

	//CNTFSVolume* m_curSelectedVol = new CNTFSVolume(pInfo->Drive);

	//if (m_curSelectedVol == NULL)
	//{
	//	//AfxMessageBox(L"Error when getVolumeByName");
	//	delete m_curSelectedVol;
	//	return 1;
	//}

	//if (!m_curSelectedVol->IsVolumeOK())
	//{
	//	//AfxMessageBox(L"Not a valid NTFS volume or NTFS version < 3.0\n");
	//	delete m_curSelectedVol;
	//	return 1;
	//}

	//unsigned int m_progressIdx, IdxCount = 0;
	//clock_t start, end;
	//start = clock();
	//char* TempStr = new char[DATASTRINGMESSAGELEN];
	//memset(TempStr, '\0', DATASTRINGMESSAGELEN);

	//for (m_progressIdx = MFT_IDX_MFT; m_progressIdx < m_curSelectedVol->GetRecordsCount(); m_progressIdx++)
	//{
	//	CFileRecord* fr = new CFileRecord(m_curSelectedVol);

	//	if (fr == NULL)
	//		continue;	// skip to next

	//	// Only parse Standard Information and File Name attributes
	//	fr->SetAttrMask(MASK_FILE_NAME | MASK_DATA);	// StdInfo will always be parsed
	//	if (!fr->ParseFileRecord(m_progressIdx))
	//	{
	//		delete fr;
	//		continue;	// skip to next
	//	}

	//	if (!fr->ParseFileAttrs())
	//	{
	//		delete fr;
	//		continue;	// skip to next
	//	}

	//	TCHAR fn[MAX_PATH];
	//	if (fr->GetFileName(fn, MAX_PATH) <= 0)
	//	{
	//		delete fr;
	//		continue;	// skip to next
	//	}
	//	if (lstrcmp(pInfo->KeywordStr, _T("*")))
	//	{
	//		if (!MatchKeyword(pInfo->KeywordStr, fn))
	//		{
	//			delete fr;
	//			continue;
	//		}
	//	}

	//	ULONGLONG datalen = 0;

	//	if (!fr->IsDirectory())
	//	{
	//		const CAttrBase* data = fr->FindStream();

	//		if (data)
	//		{
	//			datalen = data->GetDataSize();
	//			//delete data;
	//		}
	//	}
	//	//TCHAR * wStr = new TCHAR[100];
	//	//swprintf_s(wStr,100,_T("%llu_%lu_%s"),datalen,pInfo->MAXSize,fn);
	//	//MessageBox(0,wStr,0,0);
	//	//delete [] wStr;
	//	if (datalen <= 0 || datalen > pInfo->MAXSize)
	//	{
	//		delete fr;
	//		continue;
	//	}

	//	if (!pInfo->IsScanDeleteFile)
	//	{
	//		if (fr->IsDeleted())
	//		{
	//			delete fr;
	//			continue;
	//		}
	//	}
	//	TCHAR* m_FilePath = new TCHAR[MAX_PATH_EX];
	//	_tcscpy_s(m_FilePath, MAX_PATH_EX, fn);
	//	//MessageBox(0,m_FilePath,0,0);
	//	GetNTFSFilePath(m_curSelectedVol, m_FilePath, pInfo->Drive, (unsigned int)fr->GetParentRef());
	//	//MessageBox(0,m_FilePath,0,0);
	//	TCHAR* Md5Hashstr = new TCHAR[50];
	//	memset(Md5Hashstr, '\0', 50);
	//	TCHAR* Signaturestr = new TCHAR[20];
	//	memset(Signaturestr, '\0', 20);
	//	try
	//	{
	//		if (!FileHashAndSignature(m_progressIdx, m_curSelectedVol, fr, fn, Md5Hashstr, Signaturestr))
	//		{
	//			_tcscpy_s(Md5Hashstr, 50, _T("null"));
	//		}
	//	}
	//	catch (...)
	//	{
	//		_tcscpy_s(Md5Hashstr, 50, _T("null"));
	//	}
	//	wchar_t* wstr = new wchar_t[1024];
	//	swprintf_s(wstr, 1024, L"%c|0|%u|%s|%s|%s|0\n", pInfo->Drive, m_progressIdx, Md5Hashstr, fn, m_FilePath);
	//	char* m_DataStr = CStringToCharArray(wstr, CP_UTF8);
	//	strcat_s(TempStr, DATASTRINGMESSAGELEN, m_DataStr);
	//	IdxCount++;
	//	end = clock();
	//	if ((end - start) > 300000)
	//	{
	//		char* ProgressStr = new char[10];
	//		sprintf_s(ProgressStr, 10, "%u", m_progressIdx);
	//		strcat_s(TempStr, DATASTRINGMESSAGELEN, ProgressStr);
	//		int ret = m_Client->SendDataMsgToServer(pMAC, pIP, "ScanExplorerData", TempStr);
	//		if (ret <= 0)
	//		{
	//			delete[] ProgressStr;
	//			delete[] m_FilePath;
	//			delete[] Signaturestr;
	//			delete[] Md5Hashstr;
	//			delete[] m_DataStr;
	//			delete[] TempStr;
	//			delete fr;
	//			delete m_curSelectedVol;
	//			return 1;
	//		}
	//		start = clock();
	//		IdxCount = 0;
	//		memset(TempStr, '\0', DATASTRINGMESSAGELEN);
	//		delete[] ProgressStr;
	//	}
	//	else
	//	{
	//		if ((IdxCount % 60) == 0 && IdxCount >= 60)
	//		{
	//			char* ProgressStr = new char[10];
	//			sprintf_s(ProgressStr, 10, "%u", m_progressIdx);
	//			strcat_s(TempStr, DATASTRINGMESSAGELEN, ProgressStr);
	//			int ret = m_Client->SendDataMsgToServer(pMAC, pIP, "ScanExplorerData", TempStr);
	//			if (ret <= 0)
	//			{
	//				delete[] ProgressStr;
	//				delete[] m_FilePath;
	//				delete[] Signaturestr;
	//				delete[] Md5Hashstr;
	//				delete[] m_DataStr;
	//				delete[] TempStr;
	//				delete fr;
	//				delete m_curSelectedVol;
	//				return 1;
	//			}
	//			start = clock();
	//			IdxCount = 0;
	//			memset(TempStr, '\0', DATASTRINGMESSAGELEN);
	//			delete[] ProgressStr;
	//		}
	//	}
	//	delete[] wstr;
	//	delete[] m_FilePath;
	//	delete[] Signaturestr;
	//	delete[] Md5Hashstr;
	//	delete[] m_DataStr;
	//	delete fr;
	//}
	//if (TempStr[0] != '\0')
	//{
	//	char* ProgressStr = new char[10];
	//	sprintf_s(ProgressStr, 10, "%u", m_progressIdx);
	//	strcat_s(TempStr, DATASTRINGMESSAGELEN, ProgressStr);
	//	int ret = m_Client->SendDataMsgToServer(pMAC, pIP, "ScanExplorerData", TempStr);
	//	if (ret == 0 || ret == -1)
	//	{
	//		delete[] ProgressStr;
	//		delete[] TempStr;
	//		delete m_curSelectedVol;
	//		return 1;
	//	}
	//	delete[] ProgressStr;
	//}
	//delete[] TempStr;
	//delete m_curSelectedVol;

	return 0;
}
void NTFSSearchCore::GetNTFSFilePath(void* pcurSelectedVol, TCHAR* PathStr, wchar_t pDrive, unsigned int ParentFileID)
{
	//CNTFSVolume * pCurSelectedVol = (CNTFSVolume *)pcurSelectedVol;
	//TCHAR * m_Path = new TCHAR[MAX_PATH_EX];
	//TCHAR * m_TempPath = new TCHAR[MAX_PATH_EX];
	//bool IsRoot = true;
	unsigned int ParentId = 5;
	//_tcscat_s(m_TempPath,MAX_PATH_EX,PathStr);
	//swprintf_s(m_Path,MAX_PATH_EX,_T("%c:\\"),pDrive);
	CFileRecord* fr = new CFileRecord((CNTFSVolume*)pcurSelectedVol);
	if (fr != NULL)
	{
		fr->SetAttrMask(MASK_FILE_NAME | MASK_DATA);	// StdInfo will always be parsed
		if (fr->ParseFileRecord(ParentFileID))
		{
			if (fr->ParseFileAttrs())
			{
				TCHAR fn[MAX_PATH];
				if (fr->GetFileName(fn, MAX_PATH) > 0)
				{
					ParentId = (unsigned int)fr->GetParentRef();
					if (ParentId != 5 || wcscmp(fn, L"."))
					{
						if (fr->IsDirectory())
						{
							TCHAR* str2 = new TCHAR[MAX_PATH_EX];
							lstrcpy(str2, PathStr);
							TCHAR* str1 = new TCHAR[MAX_PATH_EX];
							swprintf_s(str1, MAX_PATH_EX, _T("%s\\"), fn);
							swprintf_s(PathStr, MAX_PATH_EX, _T("%s%s"), str1, str2);
							delete[] str1;
							delete[] str2;
							GetNTFSFilePath(pcurSelectedVol, PathStr, pDrive, ParentId);
						}
						else
						{
							IsRootPath(PathStr, pDrive);
						}
					}
					else
					{
						IsRootPath(PathStr, pDrive);
					}
				}
				else
				{
					IsRootPath(PathStr, pDrive);
				}
			}
			else
			{
				IsRootPath(PathStr, pDrive);
			}
		}
		else
		{
			IsRootPath(PathStr, pDrive);
		}
		delete fr;
	}
	else
	{
		IsRootPath(PathStr, pDrive);
	}
}
void NTFSSearchCore::IsRootPath(TCHAR* PathStr, wchar_t pDrive)
{
	TCHAR* str2 = new TCHAR[MAX_PATH_EX];
	lstrcpy(str2, PathStr);
	TCHAR* str1 = new TCHAR[5];
	swprintf_s(str1, 5, _T("%c:\\"), pDrive);
	swprintf_s(PathStr, MAX_PATH_EX, _T("%s%s"), str1, str2);
	delete[] str1;
	delete[] str2;
}
int NTFSSearchCore::LoadEventLogInfo(void* argv, wchar_t pDrive, wchar_t* pSystemFolderpath, char* pMAC, char* pIP)
{
	//TransportData* m_Client = (TransportData*)argv;
	//CNTFSVolume* m_curSelectedVol = new CNTFSVolume(pDrive);

	//if (m_curSelectedVol == NULL)
	//{
	//	//AfxMessageBox(L"Error when getVolumeByName");
	//	delete m_curSelectedVol;
	//	return 1;
	//}

	//if (!m_curSelectedVol->IsVolumeOK())
	//{
	//	//AfxMessageBox(L"Not a valid NTFS volume or NTFS version < 3.0\n");
	//	delete m_curSelectedVol;
	//	return 1;
	//}

	//unsigned int m_progressIdx, IdxCount = 0;
	//clock_t start, end;
	//start = clock();
	//char* TempStr = new char[DATASTRINGMESSAGELEN];
	//memset(TempStr, '\0', DATASTRINGMESSAGELEN);
	//char* OSstr = GetOSVersion();
	//for (m_progressIdx = MFT_IDX_MFT; m_progressIdx < m_curSelectedVol->GetRecordsCount(); m_progressIdx++)
	//{
	//	CFileRecord* fr = new CFileRecord(m_curSelectedVol);

	//	if (fr == NULL)
	//		continue;	// skip to next

	//	// Only parse Standard Information and File Name attributes
	//	fr->SetAttrMask(MASK_FILE_NAME | MASK_DATA);	// StdInfo will always be parsed
	//	if (!fr->ParseFileRecord(m_progressIdx))
	//	{
	//		delete fr;
	//		continue;	// skip to next
	//	}

	//	if (!fr->ParseFileAttrs())
	//	{
	//		delete fr;
	//		continue;	// skip to next
	//	}

	//	TCHAR fn[MAX_PATH];
	//	if (fr->GetFileName(fn, MAX_PATH) <= 0)
	//	{
	//		delete fr;
	//		continue;	// skip to next
	//	}

	//	if ((strstr(OSstr, "Windows XP") != 0) || (strstr(OSstr, "Windows Server 2003") != 0))
	//	{
	//		if (!MatchKeyword(_T("*.evt"), fn))
	//		{
	//			delete fr;
	//			continue;
	//		}
	//	}
	//	else
	//	{
	//		if (!MatchKeyword(_T("*.evtx"), fn))
	//		{
	//			delete fr;
	//			continue;
	//		}
	//	}
	//	ULONGLONG datalen = 0;

	//	if (!fr->IsDirectory())
	//	{
	//		const CAttrBase* data = fr->FindStream();

	//		if (data)
	//		{
	//			datalen = data->GetDataSize();
	//			//delete data;
	//		}
	//	}

	//	TCHAR* m_FilePath = new TCHAR[MAX_PATH_EX];
	//	_tcscpy_s(m_FilePath, MAX_PATH_EX, fn);
	//	//MessageBox(0,m_FilePath,0,0);
	//	GetNTFSFilePath(m_curSelectedVol, m_FilePath, pDrive, (unsigned int)fr->GetParentRef());
	//	if ((strstr(OSstr, "Windows XP") != 0) || (strstr(OSstr, "Windows Server 2003") != 0))
	//	{
	//		TCHAR* m_PathName = new TCHAR[MAX_PATH_EX];
	//		swprintf_s(m_PathName, MAX_PATH_EX, _T("%s\\config\\%s"), pSystemFolderpath, fn);
	//		if (_tcsicmp(m_FilePath, m_PathName))
	//		{
	//			delete[] m_PathName;
	//			delete[] m_FilePath;
	//			delete fr;
	//			continue;
	//		}
	//		delete[] m_PathName;
	//	}
	//	else
	//	{
	//		TCHAR* m_PathName = new TCHAR[MAX_PATH_EX];
	//		swprintf_s(m_PathName, MAX_PATH_EX, _T("%s\\winevt\\Logs\\%s"), pSystemFolderpath, fn);
	//		if (_tcsicmp(m_FilePath, m_PathName))
	//		{
	//			delete[] m_PathName;
	//			delete[] m_FilePath;
	//			delete fr;
	//			continue;
	//		}
	//		delete[] m_PathName;
	//	}
	//	//MessageBox(0,m_FilePath,0,0);
	//	wchar_t* wstr = new wchar_t[1024];
	//	swprintf_s(wstr, 1024, L"%c|%u|0|%s|%s|EventLog\\|%llu\n", pDrive, m_progressIdx, fn, m_FilePath, datalen);
	//	char* m_DataStr = CStringToCharArray(wstr, CP_UTF8);
	//	strcat_s(TempStr, DATASTRINGMESSAGELEN, m_DataStr);
	//	IdxCount++;
	//	end = clock();
	//	if ((end - start) > 300000)
	//	{
	//		if (TempStr[0] != '\0')
	//		{
	//			int ret = m_Client->SendDataMsgToServer(pMAC, pIP, "DownloadEventData", TempStr);
	//			if (ret <= 0)
	//			{
	//				delete[] m_FilePath;
	//				delete[] m_DataStr;
	//				delete[] TempStr;
	//				delete fr;
	//				delete m_curSelectedVol;
	//				return 1;
	//			}
	//			start = clock();
	//			IdxCount = 0;
	//			memset(TempStr, '\0', DATASTRINGMESSAGELEN);
	//		}
	//		else
	//		{
	//			int ret = m_Client->SendDataMsgToServer(pMAC, pIP, "DownloadEventSignal", TempStr);
	//			if (ret <= 0)
	//			{
	//				delete[] m_FilePath;
	//				delete[] m_DataStr;
	//				delete[] TempStr;
	//				delete fr;
	//				delete m_curSelectedVol;
	//				return 1;
	//			}
	//			start = clock();
	//		}
	//	}
	//	else
	//	{
	//		if ((IdxCount % 60) == 0 && IdxCount >= 60)
	//		{
	//			int ret = m_Client->SendDataMsgToServer(pMAC, pIP, "DownloadEventData", TempStr);
	//			if (ret <= 0)
	//			{
	//				delete[] m_FilePath;
	//				delete[] m_DataStr;
	//				delete[] TempStr;
	//				delete fr;
	//				delete m_curSelectedVol;
	//				return 1;
	//			}
	//			start = clock();
	//			IdxCount = 0;
	//			memset(TempStr, '\0', DATASTRINGMESSAGELEN);
	//		}
	//	}
	//	delete[] wstr;
	//	delete[] m_FilePath;
	//	delete[] m_DataStr;
	//	delete fr;
	//}
	//if (TempStr[0] != '\0')
	//{
	//	int ret = m_Client->SendDataMsgToServer(pMAC, pIP, "DownloadEventData", TempStr);
	//	if (ret == 0 || ret == -1)
	//	{
	//		delete[] TempStr;
	//		delete m_curSelectedVol;
	//		return 1;
	//	}
	//}
	//delete[] OSstr;
	//delete[] TempStr;
	//delete m_curSelectedVol;

	return 0;
}
BOOL NTFSSearchCore::ComputeHashMD5(wchar_t m_Vol, unsigned Fid, TCHAR* Md5Str)
{
	CNTFSVolume* m_curSelectedVol = new CNTFSVolume(m_Vol);

	if (m_curSelectedVol == NULL)
	{
		//AfxMessageBox(L"Error when getVolumeByName");
		delete m_curSelectedVol;
		return FALSE;
	}

	if (!m_curSelectedVol->IsVolumeOK())
	{
		//AfxMessageBox(L"Not a valid NTFS volume or NTFS version < 3.0\n");
		delete m_curSelectedVol;
		return FALSE;
	}
	CFileRecord* fr = new CFileRecord(m_curSelectedVol);

	if (fr == NULL)
	{
		delete m_curSelectedVol;
		return FALSE;	// skip to next
	}
	// Only parse Standard Information and File Name attributes
	fr->SetAttrMask(MASK_FILE_NAME | MASK_DATA);	// StdInfo will always be parsed
	if (!fr->ParseFileRecord(Fid))
	{
		delete fr;
		delete m_curSelectedVol;
		return FALSE;	// skip to next
	}

	if (!fr->ParseFileAttrs())
	{
		delete fr;
		delete m_curSelectedVol;
		return FALSE;	// skip to next
	}

	TCHAR fn[MAX_PATH];
	if (fr->GetFileName(fn, MAX_PATH) <= 0)
	{
		delete fr;
		delete m_curSelectedVol;
		return FALSE;	// skip to next
	}
	if (fr->IsDeleted() || fr->IsDirectory())
	{
		delete fr;
		delete m_curSelectedVol;
		return FALSE;	// skip to next
	}
	TCHAR* Signaturestr = new TCHAR[20];
	memset(Signaturestr, '\0', 20);
	if (!FileHashAndSignature(Fid, m_curSelectedVol, fr, fn, Md5Str, Signaturestr))
	{
		delete[] Signaturestr;
		delete fr;
		delete m_curSelectedVol;
		return FALSE;	// skip to next
	}
	delete[] Signaturestr;
	delete m_curSelectedVol;
	return TRUE;
}
void NTFSSearchCore::GetMyFilePath(map<unsigned int, MFTFileInfo>* pMap, TCHAR* str, unsigned int FatherID, wchar_t m_Vol)
{
	map<unsigned int, MFTFileInfo>::iterator it;
	it = pMap->find(FatherID);
	if (it == pMap->end())
	{
		TCHAR* str2 = new TCHAR[MAX_PATH_EX];
		lstrcpy(str2, str);
		TCHAR* str1 = new TCHAR[5];
		swprintf_s(str1, 5, _T("%c:\\"), m_Vol);
		swprintf_s(str, MAX_PATH_EX, _T("%s%s"), str1, str2);
		delete[] str1;
		delete[] str2;
		return;
	}
	if (!it->second.IsDirectory || wcscmp(it->second.FileName, L".") == 0)
	{
		TCHAR* str2 = new TCHAR[MAX_PATH_EX];
		lstrcpy(str2, str);
		TCHAR* str1 = new TCHAR[5];
		swprintf_s(str1, 5, _T("%c:\\"), m_Vol);
		swprintf_s(str, MAX_PATH_EX, _T("%s%s"), str1, str2);
		delete[] str1;
		delete[] str2;
		return;
	}
	TCHAR* str2 = new TCHAR[MAX_PATH_EX];
	lstrcpy(str2, str);
	TCHAR* str1 = new TCHAR[MAX_PATH_EX];
	swprintf_s(str1, MAX_PATH_EX, _T("%s\\"), it->second.FileName);
	swprintf_s(str, MAX_PATH_EX, _T("%s%s"), str1, str2);
	delete[] str1;
	delete[] str2;
	GetMyFilePath(pMap, str, (unsigned int)it->second.ParentID, m_Vol);
}
int NTFSSearchCore::HashAndSignature(void* argv, wchar_t vol_name, char* pMAC, char* pIP, BOOL IsHASDeleteFile, DWORD pMAXSize)
{
	//TransportData* m_Client = (TransportData*)argv;

	//CNTFSVolume* m_curSelectedVol = new CNTFSVolume(vol_name);

	//if (m_curSelectedVol == NULL)
	//{
	//	//AfxMessageBox(L"Error when getVolumeByName");
	//	delete m_curSelectedVol;
	//	return 1;
	//}

	//if (!m_curSelectedVol->IsVolumeOK())
	//{
	//	//AfxMessageBox(L"Not a valid NTFS volume or NTFS version < 3.0\n");
	//	delete m_curSelectedVol;
	//	return 1;
	//}

	//unsigned int m_progressIdx, IdxCount = 0;
	//clock_t start, end;
	//start = clock();
	//char* TempStr = new char[DATASTRINGMESSAGELEN];
	//memset(TempStr, '\0', DATASTRINGMESSAGELEN);
	//for (m_progressIdx = MFT_IDX_MFT; m_progressIdx < m_curSelectedVol->GetRecordsCount(); m_progressIdx++)
	//{
	//	if (m_progressIdx <= 34)
	//		continue;
	//	CFileRecord* fr = new CFileRecord(m_curSelectedVol);

	//	if (fr == NULL)
	//		continue;	// skip to next

	//	// Only parse Standard Information and File Name attributes
	//	fr->SetAttrMask(MASK_FILE_NAME | MASK_DATA);	// StdInfo will always be parsed
	//	if (!fr->ParseFileRecord(m_progressIdx))
	//	{
	//		delete fr;
	//		continue;	// skip to next
	//	}

	//	if (!fr->ParseFileAttrs())
	//	{
	//		delete fr;
	//		continue;	// skip to next
	//	}

	//	TCHAR fn[MAX_PATH];
	//	if (fr->GetFileName(fn, MAX_PATH) <= 0)
	//	{
	//		delete fr;
	//		continue;	// skip to next
	//	}
	//	if (!IsHASDeleteFile)
	//	{
	//		if (fr->IsDeleted())
	//		{
	//			delete fr;
	//			continue;	// skip to next
	//		}
	//	}
	//	const CAttrBase* data = fr->FindStream();

	//	if (data)
	//	{
	//		ULONGLONG DataSize = data->GetDataSize();
	//		if (DataSize <= 0 || DataSize > pMAXSize)
	//		{
	//			delete fr;
	//			continue;	// skip to next
	//		}
	//	}
	//	//ULONGLONG datalen = 0;
	//	TCHAR* Md5Hashstr = new TCHAR[50];
	//	memset(Md5Hashstr, '\0', 50);
	//	TCHAR* Signaturestr = new TCHAR[20];
	//	memset(Signaturestr, '\0', 20);
	//	if (fr->IsDirectory())
	//	{
	//		delete[] Signaturestr;
	//		delete[] Md5Hashstr;
	//		delete fr;
	//		continue;	// skip to next
	//		//const CAttrBase * data = fr->FindStream();
	//		//	
	//		//if(data)
	//		//{
	//		//	datalen = data->GetDataSize();
	//		//		//delete data;
	//		//}
	//	}
	//	else
	//	{
	//		try
	//		{
	//			if (!FileHashAndSignature(m_progressIdx, m_curSelectedVol, fr, fn, Md5Hashstr, Signaturestr))
	//			{
	//				delete[] Signaturestr;
	//				delete[] Md5Hashstr;
	//				delete fr;
	//				continue;
	//			}
	//		}
	//		catch (...)
	//		{
	//			delete[] Signaturestr;
	//			delete[] Md5Hashstr;
	//			delete fr;
	//			continue;
	//		}
	//	}
	//	wchar_t* wstr = new wchar_t[1024];
	//	swprintf_s(wstr, 1024, L"%u|%s|%s|%s\n", m_progressIdx, fn, Md5Hashstr, Signaturestr);

	//	char* m_DataStr = CStringToCharArray(wstr, CP_UTF8);
	//	strcat_s(TempStr, DATASTRINGMESSAGELEN, m_DataStr);
	//	//int ret = m_Client->SendDataMsgToServer(pMAC,pIP,"GiveExplorerData",m_DataStr);
	//	delete[] wstr;
	//	end = clock();
	//	IdxCount++;
	//	if ((end - start) > 300000)
	//	{
	//		char* ProgressStr = new char[10];
	//		sprintf_s(ProgressStr, 10, "%u", m_progressIdx);
	//		strcat_s(TempStr, DATASTRINGMESSAGELEN, ProgressStr);
	//		int ret = m_Client->SendDataMsgToServer(pMAC, pIP, "HashAndSignatureData", TempStr);
	//		if (ret == 0 || ret == -1)
	//		{
	//			delete[] ProgressStr;
	//			delete[] Signaturestr;
	//			delete[] Md5Hashstr;
	//			delete[] m_DataStr;
	//			delete[] TempStr;
	//			delete fr;
	//			delete m_curSelectedVol;
	//			return 1;
	//		}
	//		memset(TempStr, '\0', DATASTRINGMESSAGELEN);
	//		IdxCount = 0;
	//		start = clock();
	//		delete[] ProgressStr;
	//	}
	//	else
	//	{
	//		if ((IdxCount % 100) == 0 && IdxCount >= 100)
	//		{
	//			char* ProgressStr = new char[10];
	//			sprintf_s(ProgressStr, 10, "%u", m_progressIdx);
	//			strcat_s(TempStr, DATASTRINGMESSAGELEN, ProgressStr);
	//			int ret = m_Client->SendDataMsgToServer(pMAC, pIP, "HashAndSignatureData", TempStr);
	//			if (ret == 0 || ret == -1)
	//			{
	//				delete[] ProgressStr;
	//				delete[] Signaturestr;
	//				delete[] Md5Hashstr;
	//				delete[] m_DataStr;
	//				delete[] TempStr;
	//				delete fr;
	//				delete m_curSelectedVol;
	//				return 1;
	//			}
	//			memset(TempStr, '\0', DATASTRINGMESSAGELEN);
	//			IdxCount = 0;
	//			start = clock();
	//			delete[] ProgressStr;
	//		}
	//	}
	//	//if(ret == 0 || ret == -1)
	//	//{
	//	//	delete [] m_DataStr;
	//	//	delete fr;
	//	//	delete m_curSelectedVol;
	//	//	return 1;
	//	//}
	//	delete[] Signaturestr;
	//	delete[] Md5Hashstr;
	//	delete[] m_DataStr;
	//	delete fr;
	//}
	//if (TempStr[0] != '\0')
	//{
	//	char* ProgressStr = new char[10];
	//	sprintf_s(ProgressStr, 10, "%u", m_progressIdx);
	//	strcat_s(TempStr, DATASTRINGMESSAGELEN, ProgressStr);
	//	int ret = m_Client->SendDataMsgToServer(pMAC, pIP, "HashAndSignatureData", TempStr);
	//	if (ret == 0 || ret == -1)
	//	{
	//		delete[] ProgressStr;
	//		delete[] TempStr;
	//		delete m_curSelectedVol;
	//		return 1;
	//	}
	//	delete[] ProgressStr;
	//}
	//delete[] TempStr;
	//delete m_curSelectedVol;

	return 0;
}
BOOL NTFSSearchCore::FileHashAndSignature(ULONGLONG FID, void* pcurSelectedVol, void* pfr, TCHAR* m_FileName, TCHAR* Md5Str, TCHAR* SignatureStr)
{
	CFileRecord* fr = (CFileRecord*)pfr;
	CNTFSVolume* pVol = (CNTFSVolume*)pcurSelectedVol;
	//const CAttrBase* data = fr->FindRecoveryFirstAttr(ATTR_TYPE_DATA);
	const CAttrBase* data = fr->FindStream();
	BOOL IsSignature = FALSE;
	//MessageBox(0,m_FileName,0,0);
	if (data) // No 80
	{
		//BOOL bResult = FALSE;
		HCRYPTPROV hProv = 0;
		HCRYPTHASH hHash = 0;
		BYTE rgbHash[16];
		DWORD cbHash = 0;
		CHAR rgbDigits[] = "0123456789abcdef";
		bool IsError = false;
		if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		{
			return FALSE;
		}
		if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
		{
			CryptReleaseContext(hProv, 0);
			return FALSE;
		}

		int m_Count = fr->FindAttrTypeCount(ATTR_TYPE_ATTRIBUTE_LIST);
		if (m_Count > 0)
		{
			const CAttrBase* data = fr->FindFirstAttr(ATTR_TYPE_ATTRIBUTE_LIST);
			ULONGLONG offset = 0;
			DWORD len;
			ATTR_ATTRIBUTE_LIST alRecord;
			ULONGLONG m_Size = 0;
			ULONGLONG m_SizeTemp = 0;
			BOOL m_IsCompressed = FALSE;
			bool IsFirstData = true;
			BYTE* TempBuf = NULL;
			DWORD TempLen = 0;
			DWORD DeCompressedSize = 0;
			//HMODULE hModule = NULL;
			while (data->ReadData(offset, &alRecord, sizeof(ATTR_ATTRIBUTE_LIST), &len) && len == sizeof(ATTR_ATTRIBUTE_LIST))
			{
				if (IsError)
					break;
				if (ATTR_INDEX(alRecord.AttrType) > ATTR_NUMS)
				{
					//NTFS_TRACE("Attribute List parse error1\n");
					IsError = true;
					break;
				}
				//NTFS_TRACE1("Attribute List: 0x%04x\n", alRecord.AttrType);
				ULONGLONG recordRef = alRecord.BaseRef & 0x0000FFFFFFFFFFFFUL;
				DWORD am = ATTR_MASK(alRecord.AttrType);
				//printf("File ID:%llu 0x%04x\n",recordRef,am);
				if (am == ATTR_TYPE_DATA)	// Skip unwanted attributes
				{
					CFileRecord* frnew = new CFileRecord(pVol);
					//printf("File ID:%llu\n",recordRef);
					frnew->SetAttrMask(MASK_DATA);
					if (!frnew->ParseFileRecord(recordRef))
					{
						//NTFS_TRACE("Attribute List parse error2\n");
						IsError = true;
						break;
					}
					frnew->ParseAttrs();

					const CAttrBase* ab = (CAttrBase*)frnew->FindFirstAttr(ATTR_TYPE_DATA);
					DWORD m_ClusterSize = ab->GetClusterSize();
					if (IsFirstData)
					{
						m_Size = ab->GetDataSize();//ab->GetAllocSize();
						m_SizeTemp = m_Size;
						IsFirstData = false;
						m_IsCompressed = ab->CheckCompressed();
						if (m_IsCompressed)
						{
							m_Size = ab->GetAllocSize();
							DeCompressedSize = GetDeCompressedSize(m_ClusterSize);
							if (DeCompressedSize == 0)
							{
								IsError = true;
								break;
							}
							TempBuf = new BYTE[DeCompressedSize];
						}
						//printf("Size:%llu\n",m_Size);
					}
					while (ab)
					{
						if (IsError)
							break;
						for (ULONGLONG i = 0; i < m_Size; i += m_ClusterSize)
						{
							BYTE* buf = new BYTE[m_ClusterSize];
							memset(buf, '\x00', m_ClusterSize);
							DWORD len1;
							if (ab->ReadRecoveryData(i, buf, m_ClusterSize, &len1, m_Size) && m_SizeTemp > 0)
							{
								if (m_IsCompressed)
								{
									memcpy(TempBuf + TempLen, buf, m_ClusterSize);
									TempLen += m_ClusterSize;
									if (TempLen >= DeCompressedSize/*|| m_Size <= DeCompressedSize*/)
									{
										BYTE* OutBuf = new BYTE[DeCompressedSize];
										DWORD len3 = 0;
										BOOL retDecompress = ProcessDecompress(TempBuf, DeCompressedSize, OutBuf, DeCompressedSize, &len3);
										if (!retDecompress || len3 < DeCompressedSize)
										{
											//printf("Decompress Error\n");
											if (m_SizeTemp > DeCompressedSize)
											{
												//DWORD resize = 0;
												//WriteFile(hf,TempBuf,DeCompressedSize,&resize,NULL);
												if (!IsSignature)
													IsSignature = IsPESignature(TempBuf, DeCompressedSize);
												if (!CryptHashData(hHash, TempBuf, DeCompressedSize, 0))
												{
													IsError = true;
													break;
												}
												m_SizeTemp -= DeCompressedSize;
												//printf("A-%llu\n",m_SizeTemp);
											}
											else
											{
												if (m_SizeTemp > 0)
												{
													//DWORD resize = 0;
													//WriteFile(hf,TempBuf,(DWORD)m_SizeTemp,&resize,NULL);
													if (!IsSignature)
														IsSignature = IsPESignature(TempBuf, (DWORD)m_SizeTemp);
													if (!CryptHashData(hHash, TempBuf, (DWORD)m_SizeTemp, 0))
													{
														m_SizeTemp = 0;
														IsError = true;
														break;
													}
													m_SizeTemp = 0;
												}
												//printf("B-%llu\n",m_SizeTemp);
											}
										}
										else
										{
											//printf("Decompress OK %lu\n",len3);
											if (m_SizeTemp > DeCompressedSize)
											{
												//DWORD resize = 0;
												//WriteFile(hf,OutBuf,DeCompressedSize,&resize,NULL);
												if (!IsSignature)
													IsSignature = IsPESignature(OutBuf, DeCompressedSize);
												if (!CryptHashData(hHash, OutBuf, DeCompressedSize, 0))
												{
													IsError = true;
													break;
												}
												m_SizeTemp -= DeCompressedSize;
												//printf("A-%llu\n",m_SizeTemp);
											}
											else
											{
												if (m_SizeTemp > 0)
												{
													//DWORD resize = 0;
													//WriteFile(hf,OutBuf,(DWORD)m_SizeTemp,&resize,NULL);
													if (!IsSignature)
														IsSignature = IsPESignature(OutBuf, (DWORD)m_SizeTemp);
													if (!CryptHashData(hHash, OutBuf, (DWORD)m_SizeTemp, 0))
													{
														m_SizeTemp = 0;
														IsError = true;
														break;
													}
													m_SizeTemp = 0;
												}
												//printf("B-%llu\n",m_SizeTemp);
											}
										}
										delete[] OutBuf;
										memset(TempBuf, '\x0', DeCompressedSize);
										TempLen = 0;
									}
								}
								else
								{
									if (m_SizeTemp > len1)
									{
										//DWORD resize = 0;
										//WriteFile(hf,buf,len1,&resize,NULL);
										if (!IsSignature)
											IsSignature = IsPESignature(buf, len1);
										if (!CryptHashData(hHash, buf, len1, 0))
										{
											IsError = true;
											break;
										}
										m_SizeTemp -= len1;
									}
									else
									{
										if (m_SizeTemp > 0)
										{
											//DWORD resize = 0;
											//WriteFile(hf,buf,(DWORD)m_SizeTemp,&resize,NULL);
											if (!IsSignature)
												IsSignature = IsPESignature(buf, (DWORD)m_SizeTemp);
											if (!CryptHashData(hHash, buf, (DWORD)m_SizeTemp, 0))
											{
												m_SizeTemp = 0;
												IsError = true;
												break;
											}
											m_SizeTemp = 0;
										}
									}
								}
							}
							else
								break;
							delete[] buf;
						}
						//getchar();
						ab = frnew->FindNextAttr(ATTR_TYPE_DATA);
					}
					delete frnew;
				}
				offset += alRecord.RecordSize;
			}
			if (TempBuf != NULL)
			{
				delete[] TempBuf;
			}
		}
		else
		{
			ULONGLONG m_Size = 0;
			ULONGLONG m_SizeTemp = 0;
			ULONGLONG IniSize = 0;
			BOOL m_IsCompressed = FALSE;
			BOOL m_IsIniSizeltReadSize = FALSE;
			bool IsFirstData = true;
			BYTE* TempBuf = NULL;
			DWORD TempLen = 0;
			DWORD DeCompressedSize = 0;
			const CAttrBase* ab = (CAttrBase*)fr->FindFirstAttr(ATTR_TYPE_DATA);
			DWORD m_ClusterSize = ab->GetClusterSize();
			if (IsFirstData)
			{
				m_Size = ab->GetDataSize();//ab->GetAllocSize();
				IniSize = ab->GetComSize();
				if (m_Size > IniSize)
				{
					m_IsIniSizeltReadSize = TRUE;
					m_SizeTemp = IniSize;
				}
				else
					m_SizeTemp = m_Size;
				IsFirstData = false;
				m_IsCompressed = ab->CheckCompressed();
				if (m_IsCompressed)
				{
					m_Size = ab->GetAllocSize();
					DeCompressedSize = GetDeCompressedSize(m_ClusterSize);
					if (DeCompressedSize == 0)
					{
						IsError = true;
						goto Ending;
					}
					TempBuf = new BYTE[DeCompressedSize];
				}
				//printf("Size:%llu %llu\n",m_Size,m_SizeTemp);
			}
			while (ab)
			{
				if (IsError)
					break;
				for (ULONGLONG i = 0; i < m_Size; i += m_ClusterSize)
				{
					BYTE* buf = new BYTE[m_ClusterSize];
					memset(buf, '\x00', m_ClusterSize);
					DWORD len1;
					if (ab->ReadRecoveryData(i, buf, m_ClusterSize, &len1, m_Size) && m_SizeTemp > 0)
					{
						if (m_IsCompressed)
						{
							memcpy(TempBuf + TempLen, buf, m_ClusterSize);
							TempLen += m_ClusterSize;
							if (TempLen >= DeCompressedSize/* || m_Size <= DeCompressedSize*/)
							{//printf("%llu\n",ab->GetDataSize());
								BYTE* OutBuf = new BYTE[DeCompressedSize];
								DWORD len3 = 0;
								BOOL retDecompress = ProcessDecompress(TempBuf, DeCompressedSize, OutBuf, DeCompressedSize, &len3);
								if (!retDecompress || len3 < DeCompressedSize)
								{
									//printf("Decompress Error\n");
									if (m_SizeTemp > DeCompressedSize)
									{
										//DWORD resize = 0;
										//WriteFile(hf,TempBuf,DeCompressedSize,&resize,NULL);
										if (!IsSignature)
											IsSignature = IsPESignature(TempBuf, DeCompressedSize);
										if (!CryptHashData(hHash, TempBuf, DeCompressedSize, 0))
										{
											IsError = true;
											break;
										}
										m_SizeTemp -= DeCompressedSize;
										//printf("A1-%llu\n",m_SizeTemp);
									}
									else
									{
										if (m_SizeTemp > 0)
										{
											//DWORD resize = 0;
											//WriteFile(hf,TempBuf,(DWORD)m_SizeTemp,&resize,NULL);
											if (!IsSignature)
												IsSignature = IsPESignature(TempBuf, (DWORD)m_SizeTemp);
											if (!CryptHashData(hHash, TempBuf, (DWORD)m_SizeTemp, 0))
											{
												m_SizeTemp = 0;
												IsError = true;
												break;
											}
											m_SizeTemp = 0;
										}
										//printf("B1-%llu\n",m_SizeTemp);
									}
								}
								else
								{
									//printf("Decompress OK %lu\n",len3);
									if (m_SizeTemp > DeCompressedSize)
									{
										//DWORD resize = 0;
										//WriteFile(hf,OutBuf,DeCompressedSize,&resize,NULL);
										if (!IsSignature)
											IsSignature = IsPESignature(OutBuf, DeCompressedSize);
										if (!CryptHashData(hHash, OutBuf, DeCompressedSize, 0))
										{
											IsError = true;
											break;
										}
										m_SizeTemp -= DeCompressedSize;
										//printf("A2-%llu\n",m_SizeTemp);
										//getchar();
									}
									else
									{
										if (m_SizeTemp > 0)
										{
											//printf("Write %llu\n",m_SizeTemp);
											//DWORD resize = 0;
											//WriteFile(hf,OutBuf,(DWORD)m_SizeTemp,&resize,NULL);
											if (!IsSignature)
												IsSignature = IsPESignature(OutBuf, (DWORD)m_SizeTemp);
											if (!CryptHashData(hHash, OutBuf, (DWORD)m_SizeTemp, 0))
											{
												m_SizeTemp = 0;
												IsError = true;
												break;
											}
											m_SizeTemp = 0;
										}
										//printf("B2-%llu %lu %lu\n",m_SizeTemp,DeCompressedSize,len3);
									}
								}
								delete[] OutBuf;
								memset(TempBuf, '\x0', DeCompressedSize);
								TempLen = 0;
							}
						}
						else
						{
							if (m_SizeTemp > len1)
							{
								//DWORD resize = 0;
								//WriteFile(hf,buf,len1,&resize,NULL);
								if (!IsSignature)
									IsSignature = IsPESignature(buf, len1);
								if (!CryptHashData(hHash, buf, len1, 0))
								{
									IsError = true;
									break;
								}
								m_SizeTemp -= len1;
							}
							else
							{
								if (m_SizeTemp > 0)
								{
									//DWORD resize = 0;
									//WriteFile(hf,buf,(DWORD)m_SizeTemp,&resize,NULL);
									if (!IsSignature)
										IsSignature = IsPESignature(buf, (DWORD)m_SizeTemp);
									if (!CryptHashData(hHash, buf, (DWORD)m_SizeTemp, 0))
									{
										m_SizeTemp = 0;
										IsError = true;
										break;
									}
									m_SizeTemp = 0;
								}
							}
						}
					}
					else
						break;
					delete[] buf;
				}
				//printf("%lu\n",TempLen);
				//getchar();
				ab = fr->FindNextAttr(ATTR_TYPE_DATA);
			}
			//printf("%llu %llu\n",m_Size,IniSize);
			if (m_IsIniSizeltReadSize)
			{
				ULONGLONG Writebuflen = m_Size - IniSize;
				BYTE* Writebuf = new BYTE[(DWORD)Writebuflen];
				memset(Writebuf, '\x0', (DWORD)Writebuflen);
				//DWORD resize = 0;
				//printf("C\n");
				//WriteFile(hf,Writebuf,(DWORD)Writebuflen,&resize,NULL);
				if (!CryptHashData(hHash, Writebuf, (DWORD)Writebuflen, 0))
				{
					IsError = true;
				}
				delete[] Writebuf;
			}
			if (TempBuf != NULL)
			{
				delete[] TempBuf;
			}
		}
	Ending:
		if (!IsError)
		{
			if (IsSignature)
			{
				if (IsPEExt(m_FileName))
					lstrcpy(SignatureStr, _T("Match"));
				else
					lstrcpy(SignatureStr, _T("Bad Signature"));
			}
			else
			{
				if (IsPEExt(m_FileName))
					lstrcpy(SignatureStr, _T("Not PE Format"));
				else
					lstrcpy(SignatureStr, _T("Match"));
			}
			cbHash = 16;
			if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
			{
				for (DWORD i = 0; i < cbHash; i++)
				{
					TCHAR* cstr = new TCHAR[10];
					swprintf_s(cstr, 10, _T("%c%c"), rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
					lstrcat(Md5Str, cstr);
					delete[] cstr;
				}
				// printf("\n");
			}
			else
			{
				CryptDestroyHash(hHash);
				CryptReleaseContext(hProv, 0);
				return FALSE;
			}
		}
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		if (IsError)
			return FALSE;
	}
	else
	{
		return FALSE;
	}

	return TRUE;
}

int NTFSSearchCore::FileRecover(void* argv, char* WorkStr, DownloadMessageInfo* pInfo)
{
	//TransportData* m_Client = (TransportData*)argv;

	//CNTFSVolume* m_curSelectedVol = new CNTFSVolume(pInfo->Drive);
	//if (m_curSelectedVol == NULL)
	//{
	//	delete m_curSelectedVol;
	//	return -1;
	//}
	//if (!m_curSelectedVol->IsVolumeOK())
	//{
	//	delete m_curSelectedVol;
	//	return -1;
	//}

	//CFileRecord fr(m_curSelectedVol);

	//if (!fr.ParseFileRecord(pInfo->FileID))
	//{
	//	printf("File Record parse error\n");
	//	delete m_curSelectedVol;
	//	return -1;
	//}
	//fr.SetAttrMask(MASK_ALL);
	//if (!fr.ParseFileAttrs())
	//{
	//	if (fr.IsCompressed())
	//	{
	//		printf("Compressed directory not supported yet\n");
	//	}
	//	else if (fr.IsEncrypted())
	//	{
	//		printf("Encrypted directory not supported yet\n");
	//	}
	//	else
	//	{
	//		printf("File Record attribute parse error\n");
	//	}
	//	delete m_curSelectedVol;
	//	return -1;
	//}
	//TCHAR fn[MAX_PATH];
	//if (fr.GetFileName(fn, MAX_PATH) <= 0)
	//{
	//	delete m_curSelectedVol;
	//	return -1;
	//}
	//if (_wcsicmp(pInfo->FileName, fn))
	//{
	//	delete m_curSelectedVol;
	//	return -1;
	//}
	////const CAttrBase* data = fr.FindRecoveryFirstAttr(ATTR_TYPE_DATA);
	//const CAttrBase* data = fr.FindStream();
	//if (data) // No 80
	//{

	//	BYTE* SendBuf = new BYTE[SENDSIZE64];
	//	DWORD SendSize = 0;
	//	int Sendret = 1;
	//	int m_Count = fr.FindAttrTypeCount(ATTR_TYPE_ATTRIBUTE_LIST);
	//	if (m_Count > 0)
	//	{
	//		const CAttrBase* data = fr.FindFirstAttr(ATTR_TYPE_ATTRIBUTE_LIST);
	//		ULONGLONG offset = 0;
	//		DWORD len;
	//		ATTR_ATTRIBUTE_LIST alRecord;
	//		ULONGLONG m_Size = 0;
	//		ULONGLONG m_SizeTemp = 0;
	//		BOOL m_IsCompressed = FALSE;
	//		bool IsFirstData = true;
	//		BYTE* TempBuf = NULL;
	//		DWORD TempLen = 0;
	//		DWORD DeCompressedSize = 0;
	//		//HMODULE hModule = NULL;
	//		while (data->ReadData(offset, &alRecord, sizeof(ATTR_ATTRIBUTE_LIST), &len) && len == sizeof(ATTR_ATTRIBUTE_LIST))
	//		{
	//			if (Sendret < 1)
	//				break;
	//			if (ATTR_INDEX(alRecord.AttrType) > ATTR_NUMS)
	//			{
	//				//NTFS_TRACE("Attribute List parse error1\n");
	//				delete m_curSelectedVol;
	//				return -1;
	//			}
	//			//NTFS_TRACE1("Attribute List: 0x%04x\n", alRecord.AttrType);
	//			ULONGLONG recordRef = alRecord.BaseRef & 0x0000FFFFFFFFFFFFUL;
	//			DWORD am = ATTR_MASK(alRecord.AttrType);
	//			//printf("File ID:%llu 0x%04x\n",recordRef,am);
	//			if (am == ATTR_TYPE_DATA)	// Skip unwanted attributes
	//			{
	//				CFileRecord* frnew = new CFileRecord(m_curSelectedVol);
	//				//printf("File ID:%llu\n",recordRef);
	//				frnew->SetAttrMask(MASK_DATA);
	//				if (!frnew->ParseFileRecord(recordRef))
	//				{
	//					//NTFS_TRACE("Attribute List parse error2\n");
	//					//break;
	//					delete frnew;
	//					delete m_curSelectedVol;
	//					return -1;
	//				}
	//				frnew->ParseAttrs();
	//				const CAttrBase* ab = (CAttrBase*)frnew->FindFirstAttr(ATTR_TYPE_DATA);
	//				DWORD m_ClusterSize = ab->GetClusterSize();
	//				if (IsFirstData)
	//				{
	//					m_Size = ab->GetDataSize();//ab->GetAllocSize();
	//					m_SizeTemp = m_Size;
	//					IsFirstData = false;
	//					m_IsCompressed = ab->CheckCompressed();
	//					if (m_IsCompressed)
	//					{
	//						m_Size = ab->GetAllocSize();
	//						DeCompressedSize = GetDeCompressedSize(m_ClusterSize);
	//						if (DeCompressedSize == 0)
	//							break;
	//						TempBuf = new BYTE[DeCompressedSize];
	//					}
	//					//printf("Size:%llu\n",m_Size);
	//				}

	//				while (ab)
	//				{
	//					if (Sendret < 1)
	//						break;
	//					for (ULONGLONG i = 0; i < m_Size; i += m_ClusterSize)
	//					{
	//						BYTE* buf = new BYTE[m_ClusterSize];
	//						memset(buf, '\x00', m_ClusterSize);
	//						DWORD len1;
	//						if (ab->ReadRecoveryData(i, buf, m_ClusterSize, &len1, m_Size) && m_SizeTemp > 0)
	//						{
	//							if (m_IsCompressed)
	//							{
	//								memcpy(TempBuf + TempLen, buf, m_ClusterSize);
	//								TempLen += m_ClusterSize;
	//								if (TempLen >= DeCompressedSize/*|| m_Size <= DeCompressedSize*/)
	//								{
	//									BYTE* OutBuf = new BYTE[DeCompressedSize];
	//									DWORD len3 = 0;
	//									BOOL retDecompress = ProcessDecompress(TempBuf, DeCompressedSize, OutBuf, DeCompressedSize, &len3);
	//									if (!retDecompress || len3 < DeCompressedSize)
	//									{
	//										//printf("Decompress Error\n");
	//										if (m_SizeTemp > DeCompressedSize)
	//										{
	//											//DWORD resize = 0;
	//											//WriteFile(hf,TempBuf,DeCompressedSize,&resize,NULL);
	//											memcpy(SendBuf + SendSize, TempBuf, DeCompressedSize);
	//											SendSize += DeCompressedSize;
	//											m_SizeTemp -= DeCompressedSize;
	//											if (SendSize >= SENDSIZE64 || m_SizeTemp == 0)
	//											{
	//												Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, WorkStr, SendBuf);
	//												memset(SendBuf, '\x0', SENDSIZE64);
	//												SendSize = 0;
	//												if (Sendret < 1)
	//													break;
	//											}
	//											//printf("A-%llu\n",m_SizeTemp);
	//										}
	//										else
	//										{
	//											if (m_SizeTemp > 0)
	//											{
	//												//DWORD resize = 0;
	//												//WriteFile(hf,TempBuf,(DWORD)m_SizeTemp,&resize,NULL);
	//												memcpy(SendBuf + SendSize, TempBuf, (DWORD)m_SizeTemp);
	//												SendSize += (DWORD)m_SizeTemp;
	//												m_SizeTemp = 0;
	//												if (SendSize >= SENDSIZE64 || m_SizeTemp == 0)
	//												{
	//													Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, WorkStr, SendBuf);
	//													memset(SendBuf, '\x0', SENDSIZE64);
	//													SendSize = 0;
	//													if (Sendret < 1)
	//														break;
	//												}

	//											}
	//											//printf("B-%llu\n",m_SizeTemp);
	//										}
	//									}
	//									else
	//									{
	//										//printf("Decompress OK %lu\n",len3);
	//										if (m_SizeTemp > DeCompressedSize)
	//										{
	//											//DWORD resize = 0;
	//											//WriteFile(hf,OutBuf,DeCompressedSize,&resize,NULL);
	//											memcpy(SendBuf + SendSize, OutBuf, DeCompressedSize);
	//											SendSize += DeCompressedSize;
	//											m_SizeTemp -= DeCompressedSize;
	//											if (SendSize >= SENDSIZE64 || m_SizeTemp == 0)
	//											{
	//												Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, WorkStr, SendBuf);
	//												memset(SendBuf, '\x0', SENDSIZE64);
	//												SendSize = 0;
	//												if (Sendret < 1)
	//													break;
	//											}
	//											//printf("A-%llu\n",m_SizeTemp);
	//										}
	//										else
	//										{
	//											if (m_SizeTemp > 0)
	//											{
	//												//DWORD resize = 0;
	//												//WriteFile(hf,OutBuf,(DWORD)m_SizeTemp,&resize,NULL);
	//												memcpy(SendBuf + SendSize, OutBuf, (DWORD)m_SizeTemp);
	//												SendSize += (DWORD)m_SizeTemp;
	//												m_SizeTemp = 0;
	//												if (SendSize >= SENDSIZE64 || m_SizeTemp == 0)
	//												{
	//													Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, WorkStr, SendBuf);
	//													memset(SendBuf, '\x0', SENDSIZE64);
	//													SendSize = 0;
	//													if (Sendret < 1)
	//														break;
	//												}
	//											}
	//											//printf("B-%llu\n",m_SizeTemp);
	//										}
	//									}
	//									delete[] OutBuf;
	//									memset(TempBuf, '\x0', DeCompressedSize);
	//									TempLen = 0;
	//								}
	//							}
	//							else
	//							{
	//								if (m_SizeTemp > len1)
	//								{
	//									//DWORD resize = 0;
	//									//WriteFile(hf,buf,len1,&resize,NULL);
	//									memcpy(SendBuf + SendSize, buf, len1);
	//									SendSize += len1;
	//									m_SizeTemp -= len1;
	//									if (SendSize >= SENDSIZE64 || m_SizeTemp == 0)
	//									{
	//										Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, WorkStr, SendBuf);
	//										memset(SendBuf, '\x0', SENDSIZE64);
	//										SendSize = 0;
	//										if (Sendret < 1)
	//											break;
	//									}
	//								}
	//								else
	//								{
	//									if (m_SizeTemp > 0)
	//									{
	//										//DWORD resize = 0;
	//										//WriteFile(hf,buf,(DWORD)m_SizeTemp,&resize,NULL);
	//										memcpy(SendBuf + SendSize, buf, (DWORD)m_SizeTemp);
	//										SendSize += (DWORD)m_SizeTemp;
	//										m_SizeTemp = 0;
	//										if (SendSize >= SENDSIZE64 || m_SizeTemp == 0)
	//										{
	//											Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, WorkStr, SendBuf);
	//											memset(SendBuf, '\x0', SENDSIZE64);
	//											SendSize = 0;
	//											if (Sendret < 1)
	//												break;
	//										}
	//									}
	//								}
	//							}
	//						}
	//						else
	//							break;
	//						delete[] buf;
	//					}
	//					//getchar();
	//					ab = frnew->FindNextAttr(ATTR_TYPE_DATA);
	//				}
	//				delete frnew;
	//			}
	//			offset += alRecord.RecordSize;
	//		}
	//		if (TempBuf != NULL)
	//		{
	//			delete[] TempBuf;
	//		}
	//	}
	//	else
	//	{
	//		ULONGLONG m_Size = 0;
	//		ULONGLONG m_SizeTemp = 0;
	//		ULONGLONG IniSize = 0;
	//		ULONGLONG LastSize = 0;
	//		BOOL m_IsCompressed = FALSE;
	//		BOOL m_IsIniSizeltReadSize = FALSE;
	//		bool IsFirstData = true;
	//		BYTE* TempBuf = NULL;
	//		DWORD TempLen = 0;
	//		DWORD DeCompressedSize = 0;
	//		const CAttrBase* ab = (CAttrBase*)fr.FindFirstAttr(ATTR_TYPE_DATA);
	//		DWORD m_ClusterSize = ab->GetClusterSize();
	//		if (IsFirstData)
	//		{
	//			m_Size = ab->GetDataSize();//ab->GetAllocSize();
	//			IniSize = ab->GetComSize();
	//			if (m_Size > IniSize)
	//			{
	//				m_IsIniSizeltReadSize = TRUE;
	//				LastSize = m_Size - IniSize;
	//				//m_SizeTemp = IniSize;
	//			}
	//			//else
	//			m_SizeTemp = m_Size;
	//			IsFirstData = false;
	//			m_IsCompressed = ab->CheckCompressed();
	//			if (m_IsCompressed)
	//			{
	//				m_Size = ab->GetAllocSize();
	//				DeCompressedSize = GetDeCompressedSize(m_ClusterSize);
	//				if (DeCompressedSize == 0)
	//					goto Ending;
	//				TempBuf = new BYTE[DeCompressedSize];
	//			}
	//			//printf("Size:%llu %llu\n",m_Size,m_SizeTemp);
	//		}
	//		while (ab)
	//		{
	//			if (Sendret < 1)
	//				break;
	//			for (ULONGLONG i = 0; i < m_Size; i += m_ClusterSize)
	//			{
	//				BYTE* buf = new BYTE[m_ClusterSize];
	//				memset(buf, '\x00', m_ClusterSize);
	//				DWORD len1;
	//				if (ab->ReadRecoveryData(i, buf, m_ClusterSize, &len1, m_Size) && m_SizeTemp > 0)
	//				{
	//					if (m_IsIniSizeltReadSize)
	//					{
	//						if (m_SizeTemp <= LastSize)
	//						{
	//							memset(buf, '\x00', m_ClusterSize);
	//						}
	//					}
	//					if (m_IsCompressed)
	//					{
	//						memcpy(TempBuf + TempLen, buf, m_ClusterSize);
	//						TempLen += m_ClusterSize;
	//						if (TempLen >= DeCompressedSize/* || m_Size <= DeCompressedSize*/)
	//						{//printf("%llu\n",ab->GetDataSize());
	//							BYTE* OutBuf = new BYTE[DeCompressedSize];
	//							DWORD len3 = 0;
	//							BOOL retDecompress = ProcessDecompress(TempBuf, DeCompressedSize, OutBuf, DeCompressedSize, &len3);
	//							if (!retDecompress || len3 < DeCompressedSize)
	//							{
	//								//printf("Decompress Error\n");
	//								if (m_SizeTemp > DeCompressedSize)
	//								{
	//									//DWORD resize = 0;
	//									//WriteFile(hf,TempBuf,DeCompressedSize,&resize,NULL);
	//									memcpy(SendBuf + SendSize, TempBuf, DeCompressedSize);
	//									SendSize += DeCompressedSize;
	//									m_SizeTemp -= DeCompressedSize;
	//									if (SendSize >= SENDSIZE64 || m_SizeTemp == 0)
	//									{
	//										Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, WorkStr, SendBuf);
	//										memset(SendBuf, '\x0', SENDSIZE64);
	//										SendSize = 0;
	//										if (Sendret < 1)
	//											break;
	//									}
	//									//printf("A1-%llu\n",m_SizeTemp);
	//								}
	//								else
	//								{
	//									if (m_SizeTemp > 0)
	//									{
	//										//DWORD resize = 0;
	//										//WriteFile(hf,TempBuf,(DWORD)m_SizeTemp,&resize,NULL);
	//										memcpy(SendBuf + SendSize, TempBuf, (DWORD)m_SizeTemp);
	//										SendSize += (DWORD)m_SizeTemp;
	//										m_SizeTemp = 0;
	//										if (SendSize >= SENDSIZE64 || m_SizeTemp == 0)
	//										{
	//											Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, WorkStr, SendBuf);
	//											memset(SendBuf, '\x0', SENDSIZE64);
	//											SendSize = 0;
	//											if (Sendret < 1)
	//												break;
	//										}
	//									}
	//									//printf("B1-%llu\n",m_SizeTemp);
	//								}
	//							}
	//							else
	//							{
	//								//printf("Decompress OK %lu\n",len3);
	//								if (m_SizeTemp > DeCompressedSize)
	//								{
	//									//DWORD resize = 0;
	//									//WriteFile(hf,OutBuf,DeCompressedSize,&resize,NULL);
	//									memcpy(SendBuf + SendSize, OutBuf, DeCompressedSize);
	//									SendSize += DeCompressedSize;
	//									m_SizeTemp -= DeCompressedSize;
	//									if (SendSize >= SENDSIZE64 || m_SizeTemp == 0)
	//									{
	//										Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, WorkStr, SendBuf);
	//										memset(SendBuf, '\x0', SENDSIZE64);
	//										SendSize = 0;
	//										if (Sendret < 1)
	//											break;
	//									}
	//									//printf("A2-%llu\n",m_SizeTemp);
	//									//getchar();
	//								}
	//								else
	//								{
	//									if (m_SizeTemp > 0)
	//									{
	//										//printf("Write %llu\n",m_SizeTemp);
	//										//DWORD resize = 0;
	//										//WriteFile(hf,OutBuf,(DWORD)m_SizeTemp,&resize,NULL);
	//										memcpy(SendBuf + SendSize, OutBuf, (DWORD)m_SizeTemp);
	//										SendSize += (DWORD)m_SizeTemp;
	//										m_SizeTemp = 0;
	//										if (SendSize >= SENDSIZE64 || m_SizeTemp == 0)
	//										{
	//											Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, WorkStr, SendBuf);
	//											memset(SendBuf, '\x0', SENDSIZE64);
	//											SendSize = 0;
	//											if (Sendret < 1)
	//												break;
	//										}
	//									}
	//									//printf("B2-%llu %lu %lu\n",m_SizeTemp,DeCompressedSize,len3);
	//								}
	//							}
	//							delete[] OutBuf;
	//							memset(TempBuf, '\x0', DeCompressedSize);
	//							TempLen = 0;
	//						}
	//					}
	//					else
	//					{
	//						if (m_SizeTemp > len1)
	//						{
	//							//DWORD resize = 0;
	//							//WriteFile(hf,buf,len1,&resize,NULL);
	//							memcpy(SendBuf + SendSize, buf, len1);
	//							SendSize += len1;
	//							m_SizeTemp -= len1;
	//							if (SendSize >= SENDSIZE64 || m_SizeTemp == 0)
	//							{
	//								Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, WorkStr, SendBuf);
	//								memset(SendBuf, '\x0', SENDSIZE64);
	//								SendSize = 0;
	//								if (Sendret < 1)
	//									break;
	//							}
	//						}
	//						else
	//						{
	//							if (m_SizeTemp > 0)
	//							{
	//								//DWORD resize = 0;
	//								//WriteFile(hf,buf,(DWORD)m_SizeTemp,&resize,NULL);
	//								memcpy(SendBuf + SendSize, buf, (DWORD)m_SizeTemp);
	//								SendSize += (DWORD)m_SizeTemp;
	//								m_SizeTemp = 0;
	//								if (SendSize >= SENDSIZE64 || m_SizeTemp == 0)
	//								{
	//									Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, WorkStr, SendBuf);
	//									memset(SendBuf, '\x0', SENDSIZE64);
	//									SendSize = 0;
	//									if (Sendret < 1)
	//										break;
	//								}
	//							}
	//						}
	//					}
	//				}
	//				else
	//					break;
	//				delete[] buf;
	//			}
	//			//printf("%lu\n",TempLen);
	//			//getchar();
	//			ab = fr.FindNextAttr(ATTR_TYPE_DATA);
	//		}
	//		//printf("%llu %llu\n",m_Size,IniSize);
	//		//if(m_IsIniSizeltReadSize)
	//		//{
	//		//	ULONGLONG Writebuflen = m_Size - IniSize;
	//		//	BYTE * Writebuf = new BYTE[(DWORD)Writebuflen];
	//		//	memset(Writebuf,'\x0',(DWORD)Writebuflen);
	//		//	memcpy(SendBuf+SendSize,Writebuf,(DWORD)Writebuflen);
	//		//	SendSize += (DWORD)m_SizeTemp;
	//		//	Sendret = m_Client->SendDataBufToServer(pInfo->MAC,pInfo->IP,WorkStr,SendBuf);
	//		//	memset(SendBuf,'\x0',SENDSIZE64);
	//		//	SendSize = 0;
	//		//	//DWORD resize = 0;
	//		//	//printf("C\n");
	//		//	//WriteFile(hf,Writebuf,(DWORD)Writebuflen,&resize,NULL);
	//		//	delete [] Writebuf;
	//		//}
	//		if (TempBuf != NULL)
	//		{
	//			delete[] TempBuf;
	//		}
	//	}
	//Ending:
	//	if (SendBuf[0] != '\x0')
	//	{
	//		Sendret = m_Client->SendDataBufToServer(pInfo->MAC, pInfo->IP, WorkStr, SendBuf);
	//	}
	//	delete[] SendBuf;
	//}
	//delete m_curSelectedVol;
	return 0;
}
static MSCompStatus lznt1_decompress_chunk(const_rest_bytes in, const const_bytes in_end, rest_bytes out, const const_bytes out_end, size_t* RESTRICT _out_len)
{
	const const_bytes                  in_endx = in_end - 0x11; // 1 + 8 * 2 from the end
	const const_bytes out_start = out, out_endx = out_end - 8 * FAST_COPY_ROOM;
	byte flags, flagged;

	uint_fast16_t pow2 = 0x10, mask = 0xFFF, shift = 12;
	const_bytes pow2_target = out_start + 0x10;
	uint_fast16_t len, off;

	// Most of the decompression happens here
	// Very few bounds checks are done but we can only go to near the end and not the end
	while (LIKELY(in < in_endx && out < out_endx))
	{
		// Handle a fragment
		flagged = (flags = *in++) & 0x01;
		flags = (flags >> 1) | 0x80;
		do
		{
			if (flagged)  // Offset/length symbol
			{
				// Offset/length symbol
				while (UNLIKELY(out > pow2_target)) { pow2 <<= 1; pow2_target = out_start + pow2; mask >>= 1; --shift; } // Update the current power of two available bytes
				uint16_t sym = GET_UINT16(in);
				in += 2;
				len = (sym & mask) + 3;
				off = (sym >> shift) + 1;
				const_rest_bytes o = out - off;
				if (UNLIKELY(o < out_start)) { /*SET_ERROR(stream, "LZNT1 Decompression Error: Invalid data: Illegal offset (%p-%u < %p)", out, off, out_start);*/ return MSCOMP_DATA_ERROR; }
				FAST_COPY_SHORT(out, o, len, off, out_endx,
					if (UNLIKELY(out + len > out_end)) { return (out - out_start) + len > CHUNK_SIZE ? MSCOMP_DATA_ERROR : MSCOMP_BUF_ERROR; }
				goto CHECKED_COPY);
			}
			else { *out++ = *in++; } // Copy byte directly
			flagged = flags & 0x01;
			flags >>= 1;
		} while (LIKELY(flags));
	}

	// Slower decompression but with full bounds checking
	while (LIKELY(in < in_end))
	{
		// Handle a fragment
		flagged = (flags = *in++) & 0x01;
		flags = (flags >> 1) | 0x80;
		do
		{
			if (in == in_end) { *_out_len = out - out_start; return MSCOMP_OK; }
			else if (flagged) // Offset/length symbol
			{
				// Offset/length symbol
				if (UNLIKELY(in + 2 > in_end)) { /*SET_ERROR(stream, "LZNT1 Decompression Error: Invalid data: Unable to read 2 bytes for offset/length");*/ return MSCOMP_DATA_ERROR; }
				while (UNLIKELY(out > pow2_target)) { pow2 <<= 1; pow2_target = out_start + pow2; mask >>= 1; --shift; } // Update the current power of two available bytes
				{
					const uint16_t sym = GET_UINT16(in);
					off = (sym >> shift) + 1;
					len = (sym & mask) + 3;
				}
				in += 2;
				if (UNLIKELY(out - off < out_start)) { /*SET_ERROR(stream, "LZNT1 Decompression Error: Invalid data: Illegal offset (%p-%u < %p)", out, off, out_start);*/ return MSCOMP_DATA_ERROR; }
				if (UNLIKELY(out + len > out_end)) { return (out - out_start) + len > CHUNK_SIZE ? MSCOMP_DATA_ERROR : MSCOMP_BUF_ERROR; }

				// Copy bytes
				if (off == 1)
				{
					memset(out, out[-1], len);
					out += len;
				}
				else
				{
					const_bytes end;
				CHECKED_COPY:		for (end = out + len; out < end; ++out) { *out = *(out - off); }
				}
			}
			//else if (out == out_end) { printf("D %p %p %zu\n", out, out_end, out_end-out_start); return MSCOMP_BUF_ERROR; }
			else { *out++ = *in++; } // Copy byte directly
			flagged = flags & 0x01;
			flags >>= 1;
		} while (LIKELY(flags));
	}

	if (UNLIKELY(in != in_end)) { /*SET_ERROR(stream, "LZNT1 Decompression Error: Invalid data: Unable to read byte for flags");*/ return MSCOMP_DATA_ERROR; }
	*_out_len = out - out_start;
	return MSCOMP_OK;
}
ENTRY_POINT MSCompStatus lznt1_decompress(const_rest_bytes in, size_t in_len, rest_bytes out, size_t* RESTRICT _out_len)
{
	const size_t out_len = *_out_len;
	const const_bytes in_end = in + in_len - 1;
	const const_bytes out_end = out + out_len, out_start = out;

	// Go through every chunk
	while (in < in_end && out < out_end)
	{
		// Read chunk header
		const uint16_t header = GET_UINT16(in);
		if (UNLIKELY(header == 0)) { *_out_len = out - out_start; return MSCOMP_OK; }
		const uint_fast16_t in_size = (header & 0x0FFF) + 1;
		if (UNLIKELY(in + in_size >= in_end)) { return MSCOMP_DATA_ERROR; }
		in += 2;

		// Flags:
		//   Highest bit (0x8) means compressed
		// The other bits are always 011 (0x3) and have unknown meaning:
		//   The last two bits are possibly uncompressed chunk size (512, 1024, 2048, or 4096)
		//   However in NT 3.51, NT 4 SP1, XP SP2, Win 7 SP1 the actual chunk size is always 4096 and the unknown flags are always 011 (0x3)

		size_t out_size;
		if (header & 0x8000) // read compressed chunk
		{
			MSCompStatus err = lznt1_decompress_chunk(in, in + in_size, out, out_end, &out_size);
			if (err != MSCOMP_OK) { return err; }
		}
		else // read uncompressed chunk
		{
			out_size = in_size;
			if (out + out_size > out_end) { break; } // chunk is longer than the available space
			memcpy(out, in, out_size);
		}
		out += out_size;
		in += in_size;
	}

	// Return insufficient buffer or uncompressed size
	if (in < in_end) { return MSCOMP_BUF_ERROR; }
	*_out_len = out - out_start;
	return MSCOMP_OK;
}
BOOL NTFSSearchCore::ProcessDecompress(BYTE* pBuf, DWORD pBuflen, BYTE* pOutBuf, DWORD plen, DWORD* _out_len)
{
	HMODULE hModule = LoadLibrary(L"ntdll.dll");
	if (hModule)
	{
		pRtlGetCompressionWorkSpaceSize _RtlGetCompressionWorkSpaceSize = (pRtlGetCompressionWorkSpaceSize)GetProcAddress(hModule, "RtlGetCompressionWorkSpaceSize");
		pRtlDecompressBufferEx _RtlDecompressBufferEx = (pRtlDecompressBufferEx)GetProcAddress(hModule, "RtlDecompressBufferEx");
		if (_RtlDecompressBufferEx == NULL || _RtlGetCompressionWorkSpaceSize == NULL)
		{
			FreeLibrary(hModule);
			return FALSE;
		}
		//BYTE * OutBuf = new BYTE[plen];
		DWORD compressBufferWorkSpaceSize = 0;
		DWORD compressFragmentWorkSpaceSize = 0;
		if (_RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_LZNT1, &compressBufferWorkSpaceSize, &compressFragmentWorkSpaceSize) != 0)
		{
			FreeLibrary(hModule);
			return FALSE;
		}
		//printf("%lu-%lu\n",compressBufferWorkSpaceSize,compressFragmentWorkSpaceSize);
		BYTE* workSpace = new BYTE[compressFragmentWorkSpaceSize];
		//DWORD dstSize = 0;
		if (_RtlDecompressBufferEx(COMPRESSION_FORMAT_LZNT1, pOutBuf, plen, pBuf, pBuflen, _out_len, workSpace) == 0)
		{
			//FILE *fp;
			//_wfopen_s(&fp,L"Outbuf.bin",L"wb+");
			//fwrite(pOutBuf,1,plen,fp);
			//fclose(fp);
			delete[] workSpace;
			FreeLibrary(hModule);
			//free(*_RtlGetCompressionWorkSpaceSize);
			//free(*_RtlDecompressBuffer);
			//_out_len = dstSize;
			return TRUE;
		}
		else
		{
			delete[] workSpace;
			FreeLibrary(hModule);
			//free(*_RtlGetCompressionWorkSpaceSize);
			//free(*_RtlDecompressBuffer);
			return FALSE;
		}
	}
	else
		return FALSE;
}
DWORD NTFSSearchCore::GetDeCompressedSize(DWORD pClusterSize)
{
	if (pClusterSize == 512)
		return 0x2000;
	else if (pClusterSize == 1024)
		return 0x4000;
	else if (pClusterSize == 2048)
		return 0x8000;
	else if (pClusterSize == 4096)
		return 0x10000;
	else if (pClusterSize == 8192)
		return 0x10000;
	else if (pClusterSize == 16384)
		return 0x10000;
	else if (pClusterSize == 32768)
		return 0x10000;
	else if (pClusterSize == 65536)
		return 0x10000;
	else
		return 0;
}