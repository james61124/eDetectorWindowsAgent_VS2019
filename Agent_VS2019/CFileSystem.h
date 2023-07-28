#pragma once
#include "CVolumeAccess.h"
#include "CRootFolder.h"

class CFileSystem
{
private:
	CRootFolder*	m_rootDir;
public:
	CFileSystem(TCHAR* aDriveLetter);
	~CFileSystem(void);

	bool initFDT(void *argv,char* pMAC,char* pIP,char * SendStr,unsigned int & pProgressCount,unsigned int & pCount,DWORD & pLastCluster,vector<DeleteFATFileInfo>* pDelInfo,clock_t & pStartTime);
	bool LoadScanExplorer(void *argv,char* pMAC,char* pIP,char * SendStr,unsigned int & pProgressCount,unsigned int & pCount,DWORD & pLastCluster,vector<DeleteFATFileInfo>* pDelInfo,clock_t & pStartTime,ScanExplorerInfo * pInfo,TCHAR* pFilePath);
	int GetRecordsCount();
	BOOL GetRecoverInfo(unsigned int pIndex,TCHAR * pFileName,ULONGLONG & m_FileSize);
	BOOL FileRecover(void *argv,char* WorkStr,unsigned int pIndex,unsigned long pFileSize,char* pMAC,char* pIP);
	BOOL FileHashAndSignature(unsigned int pIndex,unsigned long pFileSize,TCHAR * m_FileName,TCHAR* HashStr,TCHAR* SignatureStr);
	//void sort();
	//void flushDataToDevice();
	//void exportFoldersList(TCHAR* aFileName);
	void changeDriveLetter(TCHAR* aDriveLetter);
	TCHAR* getCurrentDriveLetter();

	// Backup function for the files table
	//void dumpFilesTable(TCHAR* aFileName);
	//void loadFilesTable(TCHAR* aFileName);

	// Dumping the FAT tables to files
	//void dumpFatsTable(TCHAR* aDestFolder);
};
