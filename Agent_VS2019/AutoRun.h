#pragma once
#include <shlobj.h>
#include <taskschd.h>
#include <vector>
#include <string>
#include <cstring>
#include <map>
#include <set>
#include <tchar.h>

#include "GlobalFunction.h"
using namespace std;



class AutoRun
{
public:
	AutoRun();
	virtual ~AutoRun();
	void GetThisPCAllUser(vector<wstring>* wtr);
	BOOL GetUserStartUp(wchar_t* pUserName, const wchar_t* pDirectory, TCHAR* pPath);
	BOOL GetAllUserStartUp(TCHAR* wtr);
	//void SearchStartUpFile(vector<StartRunInfoData> *pInfo,wchar_t * m_Path);
	//void ParsingRegisterAutoRun(vector<StartRunInfoData> *pInfo/*,HKEY pKey,TCHAR * RegPath*/);
	//void ParsingRegisterAutoRunFromUser(vector<StartRunInfoData> *pInfo,wchar_t * pUserName);
	void GetUserNamePath(wchar_t* pUserName, TCHAR* pPath);
	void StartupServiceInfo(void* argv, char* pMAC, char* pIP);
	void StartupAutoRunInfo(void* argv, char* pMAC, char* pIP);
	void StartupTaskSchedulerInfo(void* argv, char* pMAC, char* pIP);
	void LoadServiceStartCommand(map<wstring, BOOL>* pImagePath);
	void LoadAutoRunStartCommand(set<wstring>* pImagePath);
	void LoadAllStartRunInfo(vector<StartRunInfoData>* pStartRunInfo);
private:
	//void ParsingAutoRunFile(vector<StartRunInfoData> *pInfo,TCHAR * m_Path,TCHAR *m_Name);
	//void ParsingRegisterInfo(vector<StartRunInfoData> *pInfo,HKEY pKey,TCHAR * RegPath);
	//void ParsingRegisterInfox32(vector<StartRunInfoData> *pInfo,HKEY pKey,TCHAR * RegPath);	
	void LoadInstallService(map<wstring, SerivceInformation>* pServiceMap);
	void DoQuerySvc(SerivceInformation* pInfo);
	void SearchAutoRunFile(vector<AutoRunInfo>* pInfo, wchar_t* m_Path);
	void ParsingStartupFile(vector<AutoRunInfo>* pInfo, TCHAR* m_Path, TCHAR* m_Name);
	void LoadRegisterAutoRun(vector<AutoRunInfo>* pInfo);
	void LoadRegisterInfo(vector<AutoRunInfo>* pInfo, HKEY pKey, const wchar_t* RegPath);
	void LoadRegisterInfox32(vector<AutoRunInfo>* pInfo, HKEY pKey, const wchar_t* RegPath);
	void LoadRegisterAutoRunFromUser(vector<AutoRunInfo>* pInfo, wchar_t* pUserName);
	void LoadRegisterInfoEx(vector<AutoRunInfo>* pInfo, HKEY pKey, const wchar_t* RegPath, const wchar_t* KeyStr, bool IsChildItem, bool Is32Bit = false);
	void LoadRegisterChildItem(vector<wstring>* pStrInfo, HKEY pKey, const wchar_t* RegPath, bool Is32Bit);
	void LoadRegisterDataEx(vector<AutoRunInfo>* pInfo, HKEY pKey, const wchar_t* RegPath, const wchar_t* KeyStr, bool Is32Bit);
	void LoadTaskSchedulerInfo(vector<TaskSchedulerInfo>* pInfo, set<wstring>* pstr);
	void LoadStartRunServiceInfo(vector<StartRunInfoData>* pStartRunInfo);
	void LoadStartRunAutoRunInfo(vector<StartRunInfoData>* pStartRunInfo);
	void LoadStartRunTaskSchedulerInfo(vector<StartRunInfoData>* pStartRunInfo);
};

#define MAX_LEVEL 10

class TaskSchedulerInfoProcessor
{
public:
	TaskSchedulerInfoProcessor();
	void GetTaskSchedulerInfo(vector<TaskSchedulerInfo>* pInfo);

private:
	HRESULT RecTaskSchedulerFolder(ITaskFolder* pParentFolder, int level);
	HRESULT GetFolderCount(ITaskFolder* pTaskFolder, LONG* pCount);
	HRESULT GetTaskCount(ITaskFolder* pTaskFolder, LONG* pCount);

	ITaskFolder* GetTaskFolder(ITaskFolder* pParentTaskFolder, LONG idx);
	IRegisteredTask* GetTask(ITaskFolder* pParentTaskFolder, LONG idx);

	HRESULT GetTaskProperty(IRegisteredTask* pRegisteredTask);
	void GetStatusString(wchar_t* StatusString, TASK_STATE& state);
	HRESULT GetDefinitionProperty(ITaskDefinition* pDefinition, TaskSchedulerInfo* pInfo);
	wstring GetTriggerString(TASK_TRIGGER_TYPE2& trigger_type);
	void ParsingXmlData(TaskSchedulerInfo* pInfo, char* m_Xmlstr);

	vector<TaskSchedulerInfo>* m_pInfo;
};