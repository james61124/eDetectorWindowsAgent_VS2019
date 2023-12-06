#pragma once

#include "FAT32General.h"
#include "CEntry.h"
#include "CFileEntry.h"
//#include "CSpecialEntry.h"
#include "CVolumeAccess.h"
#include <vector>
#include <algorithm>
#include <fstream>

#include "Log.h"

#define LAST_LONG_ENTRY 0x40
#define	BUFSIZE64 65536

#define DATASTRINGMESSAGELEN 65436

class CFolderEntry : public CEntry
{
private:
	Log log;
	virtual DWORD	getFirstClusterInDataChain();
	//void			addNewSubFolder(FATDirEntry aFatDirEntry, LFNEntry* aLFNEntries, WORD aNumEntries);
	//void			addNewFile(FATDirEntry aFatDirEntry, LFNEntry* aLFNEntries, WORD aNumEntries);
protected:
	//vector<CFolderEntry*>	m_folders;
	//vector<CFileEntry*>		m_files;
	//vector<CEntry*>			m_recycleBin;
	//vector<CEntry*>			m_recycleBinDir;
	//vector<CSpecialEntry*>	m_specialEntries;

	// In use only with inherited types
	CFolderEntry();

	//bool dumpData(ofstream* aFile);
public:
	CFolderEntry(FATDirEntry aEntryToAnalyze, LFNEntry* aLFNEntries, WORD aNumLFNEntries);

	virtual void loadCount(int & retCount);
	virtual bool load(void *argv, TCHAR* FileName, char* pMAC,char* pIP,DWORD FatherID,char * SendStr,unsigned int & pProgressCount,unsigned int & pCount,DWORD & pLastCluster,vector<DeleteFATFileInfo>* pDelInfo,clock_t & pStartTime);
	virtual bool LoadScanExplorer(void *argv,char* pMAC,char* pIP,char * SendStr,unsigned int & pProgressCount,unsigned int & pCount,DWORD & pLastCluster,vector<DeleteFATFileInfo>* pDelInfo,clock_t & pStartTime,ScanExplorerInfo * pInfo,TCHAR* pFilePath);
	virtual BOOL GetRecoverInfo(unsigned int pIndex,TCHAR * pFileName,ULONGLONG & m_FileSize);
	virtual BOOL FileRecover(void *argv,char* WorkStr,unsigned int pIndex,unsigned long pFileSize,char* pMAC,char* pIP);
	virtual BOOL FileHashAndSignature(unsigned int pIndex,unsigned long pFileSize,TCHAR * m_FileName,TCHAR* HashStr,TCHAR* SignatureStr);
	//bool writeData();
	//void sortEntries();
	//void exportToFile(FILE* aFileStream, int aCurrDepth);
	~CFolderEntry(void);

	static int g_runningNum;
};

