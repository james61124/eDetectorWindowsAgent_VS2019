#pragma once

#include <iostream>
#include <tchar.h>
#include <Windows.h>

#define MACLEN 20
#define IPLEN 20
#define MAX_PATH_EX 512

struct ScanExplorerInfo
{
	wchar_t Drive;
	TCHAR KeywordStr[1024];
	TCHAR ScheduleName[MAX_PATH];
	BOOL IsScanDeleteFile;
	DWORD MAXSize;
};

struct DownloadMessageInfo
{
	char MAC[MACLEN];
	char IP[IPLEN];
	unsigned int Num;
	wchar_t Drive;
	int ProcessID;
	unsigned int FileID;
	TCHAR FileName[MAX_PATH];
	TCHAR FilePath[MAX_PATH_EX];
	DWORD FileSize;
};

struct MFTFileInfo
{
	BOOL IsDirectory;
	unsigned int ParentID;
	TCHAR FileName[MAX_PATH];
};

struct DeleteFATFileInfo
{
	DWORD FirstDataCluster;
	TCHAR FileName[_MAX_FNAME];
	DWORD ParentFirstDataCluster;
	int isDirectory;
	SYSTEMTIME CT;
	SYSTEMTIME WT;
	SYSTEMTIME AT;
	DWORD FileSize;
	TCHAR FilePath[MAX_PATH_EX];
};