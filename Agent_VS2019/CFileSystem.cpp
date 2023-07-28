
#include "CFileSystem.h"
#include <io.h>
#include <fcntl.h>

CFileSystem::CFileSystem(TCHAR* aDriveLetter)
{
	CVolumeAccess::setWorkingDriveLetter(aDriveLetter);
	m_rootDir = NULL;
}

CFileSystem::~CFileSystem(void)
{
	CVolumeAccess::cleanResources();

	if (m_rootDir != NULL)
		delete m_rootDir;
}

bool CFileSystem::initFDT(void *argv,char* pMAC,char* pIP,char * SendStr,unsigned int & pProgressCount,unsigned int & pCount,DWORD & pLastCluster,vector<DeleteFATFileInfo>* pDelInfo,clock_t & pStartTime)
{	
	// Cleans any older data
	if (m_rootDir != NULL)
		delete m_rootDir;

	if (CVolumeAccess::getInstance() == NULL)
	{
		_tprintf(_T("The device is not ready.."));
		return false;
	}
	else
	{
		m_rootDir = new CRootFolder();
		bool ret = m_rootDir->load(argv, pMAC,pIP,5,SendStr,pProgressCount,pCount,pLastCluster,pDelInfo,pStartTime);
		return ret;
	}
}
bool CFileSystem::LoadScanExplorer(void *argv,char* pMAC,char* pIP,char * SendStr,unsigned int & pProgressCount,unsigned int & pCount,DWORD & pLastCluster,vector<DeleteFATFileInfo>* pDelInfo,clock_t & pStartTime,ScanExplorerInfo * pInfo,TCHAR* pFilePath)
{
	if (m_rootDir != NULL)
		delete m_rootDir;

	if (CVolumeAccess::getInstance() == NULL)
	{
		_tprintf(_T("The device is not ready.."));
		return false;
	}
	else
	{
		m_rootDir = new CRootFolder();
		//unsigned int m_Count = 0;
		bool ret = m_rootDir->LoadScanExplorer(argv, pMAC,pIP,SendStr,pProgressCount,pCount,pLastCluster,pDelInfo,pStartTime,pInfo,pFilePath);
		return ret;
	}
}
int CFileSystem::GetRecordsCount()
{	
	// Cleans any older data
	int ret = 0;
	if (m_rootDir != NULL)
		delete m_rootDir;

	if (CVolumeAccess::getInstance() == NULL)
	{
		_tprintf(_T("The device is not ready.."));
		//return false;
	}
	else
	{
		m_rootDir = new CRootFolder();
		m_rootDir->loadCount(ret);
		//return true;
	}
	return ret;
}
BOOL CFileSystem::GetRecoverInfo(unsigned int pIndex,TCHAR * pFileName,ULONGLONG & m_FileSize)
{	
	// Cleans any older data
	BOOL ret = FALSE;
	if (m_rootDir != NULL)
		delete m_rootDir;

	if (CVolumeAccess::getInstance() == NULL)
	{
		_tprintf(_T("The device is not ready.."));
		//return false;
	}
	else
	{
		m_rootDir = new CRootFolder();
		ret = m_rootDir->GetRecoverInfo(pIndex,pFileName,m_FileSize);
		//return true;
	}
	return ret;
}
BOOL CFileSystem::FileRecover(void *argv,char* WorkStr,unsigned int pIndex,unsigned long pFileSize,char* pMAC,char* pIP)
{
		// Cleans any older data
	BOOL ret = FALSE;
	if (m_rootDir != NULL)
		delete m_rootDir;

	if (CVolumeAccess::getInstance() == NULL)
	{
		_tprintf(_T("The device is not ready.."));
		//return false;
	}
	else
	{
		m_rootDir = new CRootFolder();
		ret = m_rootDir->FileRecover(argv,WorkStr,pIndex,pFileSize,pMAC,pIP);
		//return true;
	}
	return ret;
}
BOOL CFileSystem::FileHashAndSignature(unsigned int pIndex,unsigned long pFileSize,TCHAR * m_FileName,TCHAR* HashStr,TCHAR* SignatureStr)
{
	BOOL ret = FALSE;
	if (m_rootDir != NULL)
		delete m_rootDir;

	if (CVolumeAccess::getInstance() == NULL)
	{
		_tprintf(_T("The device is not ready.."));
		//return false;
	}
	else
	{
		m_rootDir = new CRootFolder();
		ret = m_rootDir->FileHashAndSignature(pIndex, pFileSize,  m_FileName, HashStr, SignatureStr);
		//return true;
	}
	return ret;
}
void CFileSystem::changeDriveLetter(TCHAR *aDriveLetter)
{
	CVolumeAccess::setWorkingDriveLetter(aDriveLetter);
}
TCHAR* CFileSystem::getCurrentDriveLetter()
{
	return CVolumeAccess::getWorkingDriveLetter();
}
