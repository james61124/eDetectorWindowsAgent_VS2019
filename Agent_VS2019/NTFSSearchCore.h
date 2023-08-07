//#pragma once
#include <map>

#include "File.h"
#include "GlobalFunction.h"
#include "StrPacket.h"

//#include "NTFS.h"
#include "NTFS_Common.h"
#include "NTFS_FileRecord.h"
//#include "NTFS_Attribute.h"







using namespace std;

#define	BUFSIZE	1024
#define	BUFSIZE64 65536
#define CHUNK_SIZE 0x1000

class NTFSSearchCore
{
public:
	NTFSSearchCore();
	virtual ~NTFSSearchCore();
	//char *DecompressData( char *szBuff, size_t nBufSize, DWORD *dwSizeOut );
	ULONGLONG GetRecordsCount(wchar_t vol_name);
	BOOL GetRecoverInfo(wchar_t vol_name, unsigned int pIndex, TCHAR* pFileName, ULONGLONG& m_FileSize);
	int Search(void* argv, wchar_t vol_name, char* pMAC, char* pIP);
	int LoadScanExplorer(void* argv, ScanExplorerInfo* pInfo, char* pMAC, char* pIP);
	//int LiveSearchRecover(void* argv,wchar_t vol_name ,unsigned int FileIndex,char* pMAC,char* pIP);
	int HashAndSignature(void* argv, wchar_t vol_name, char* pMAC, char* pIP, BOOL IsHASDeleteFile, DWORD pMAXSize);
	int FileRecover(void* argv, char* WorkStr, DownloadMessageInfo* pInfo);
	int LoadEventLogInfo(void* argv, wchar_t pDrive, wchar_t* pSystemFolderpath, char* pMAC, char* pIP);
//private:
	BOOL FileHashAndSignature(ULONGLONG FID, void* pcurSelectedVol, void* pfr, TCHAR* m_FileName, TCHAR* Md5Str, TCHAR* SignatureStr);
	void GetMyFilePath(map<unsigned int, MFTFileInfo>* pMap, TCHAR* str, unsigned int FatherID, wchar_t m_Vol);
	BOOL ComputeHashMD5(wchar_t m_Vol, unsigned Fid, TCHAR* Md5Str);
	void GetNTFSFilePath(void* pcurSelectedVol, TCHAR* PathStr, wchar_t pDrive, unsigned int ParentFileID);
	void IsRootPath(TCHAR* PathStr, wchar_t pDrive);
	BOOL ProcessDecompress(BYTE* pBuf, DWORD pBuflen, BYTE* pOutBuf, DWORD plen, DWORD* _out_len);
	DWORD GetDeCompressedSize(DWORD pClusterSize);
	//int GetCopyIndex(CString OutPutFile);

};

