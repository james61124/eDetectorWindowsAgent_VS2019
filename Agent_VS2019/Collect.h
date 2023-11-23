#pragma once

#include <tchar.h>
#include <windows.h>
#include <fstream>
#include <algorithm>

#include "GlobalFunction.h"
#include "StrPacket.h"
#include "sqlite3.h"

#if defined _M_IX86
#pragma comment(lib,"SQLite3_x86.lib")
#elif defined _M_X64
#pragma comment(lib,"SQLite3_x64.lib")
#endif

class PredefineObj //Yen
{
public:
    string TableName;
    string vecFilterCondition;
};

class TableFilter //Yen
{
public:
    string TableName;
    string ConnectCondition;
    vector<string> vecFilterCondition;
};

class CombineObj
{
public:
    string IP;
    string MAC;
    string Table_id;
    string Item;
    string ETC;
    string Date;
};


class Collect {
public:
    //int CollectionNums[48];
    int CollectionNums[2];

    Collect();

    void CollectionProcess(HMODULE plib, TCHAR* pdbName, TCHAR* pWorkNum);
    void CollectionWorking(HMODULE plib, wstring pdbName, wstring pSavePath, wstring pWorkNum);
    bool WriteSQLiteDB(sqlite3* pdb, char* pQuery);
    bool GetQueryByTable(string* query, string TableName, string QueryFilter);
    bool GetDataByQuery(const string& query, sqlite3* m_db, vector<CombineObj>* vecCombineObj);
    bool WriteDataSetToDB(sqlite3* m_db, const vector<CombineObj> vecCombineObj, const string DefineName, const string MAC, const string IP, const string TableName, int id);

};