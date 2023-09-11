#include "Collect.h"

Collect::Collect() {
	CollectionNums[0] = 101;
	CollectionNums[1] = 102;
	CollectionNums[2] = 103;
	CollectionNums[3] = 104;
	CollectionNums[4] = 105;
	CollectionNums[5] = 201;
	CollectionNums[6] = 202;
	CollectionNums[7] = 203;
	CollectionNums[8] = 204;
	CollectionNums[9] = 205;
	CollectionNums[10] = 206;
	CollectionNums[11] = 207;
	CollectionNums[12] = 208;
	CollectionNums[13] = 209;
	CollectionNums[14] = 210;
	CollectionNums[15] = 211;
	CollectionNums[16] = 212;
	CollectionNums[17] = 213;
	CollectionNums[18] = 214;
	CollectionNums[19] = 215;
	CollectionNums[20] = 216;
	CollectionNums[21] = 217;
	CollectionNums[22] = 218;
	CollectionNums[23] = 219;
	CollectionNums[24] = 220;
	CollectionNums[25] = 221;
	CollectionNums[26] = 222;
	CollectionNums[27] = 223;
	CollectionNums[28] = 224;
	CollectionNums[29] = 225;
	CollectionNums[30] = 226;
	CollectionNums[31] = 227;
	CollectionNums[32] = 228;
	CollectionNums[33] = 229;
	CollectionNums[34] = 230;
	CollectionNums[35] = 231;
	CollectionNums[36] = 232;
	CollectionNums[37] = 233;
	CollectionNums[38] = 234;
	CollectionNums[39] = 235;
	CollectionNums[40] = 236;
	CollectionNums[41] = 237;
	CollectionNums[42] = 238;
	CollectionNums[43] = 239;
	CollectionNums[44] = 240;
	CollectionNums[45] = 241;
	CollectionNums[46] = 242;
	CollectionNums[47] = 243;

	//CollectionNums[0] = 239;
	//CollectionNums[1] = 240;

	// 241 delete

}

void Collect::CollectionProcess(HMODULE plib, TCHAR* pdbName, TCHAR* pWorkNum)
{
	wstring m_TempPath = GetMyTempPath(pdbName);
	CollectionWorking(plib, pdbName, m_TempPath, pWorkNum);
}
void Collect::CollectionWorking(HMODULE plib, wstring pdbName, wstring pSavePath, wstring pWorkNum)
{
	int m_Num = _wtoi(pWorkNum.c_str());
	if (m_Num == 101)//Process
	{
		typedef void (*Collection_EnumProcess)(TCHAR*, int);//目前正在執行程式
		Collection_EnumProcess pCollection_EnumProcess = (Collection_EnumProcess)GetProcAddress(plib, "Collection_EnumProcess");
		if (pCollection_EnumProcess != NULL)
		{
			pCollection_EnumProcess((TCHAR*)pdbName.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 102)//NetworkResources
	{
		typedef void (*Collection_NetworkResources)(TCHAR*, int);//網路上分享的設備及檔案目錄
		Collection_NetworkResources pCollection_NetworkResources = (Collection_NetworkResources)GetProcAddress(plib, "Collection_NetworkResources");
		if (pCollection_NetworkResources != NULL)
		{
			pCollection_NetworkResources((TCHAR*)pdbName.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 103)//Network
	{
		typedef void (*Collection_Network)(TCHAR*, int);//目前正在連線的網路資訊
		Collection_Network pCollection_Network = (Collection_Network)GetProcAddress(plib, "Collection_Network");
		if (pCollection_Network != NULL)
		{
			pCollection_Network((TCHAR*)pdbName.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 104)//OpenedFiles
	{
		typedef void (*Collection_OpenedFiles)(TCHAR*, int);//目前程式所開啟的檔案列表資訊
		Collection_OpenedFiles pCollection_OpenedFiles = (Collection_OpenedFiles)GetProcAddress(plib, "Collection_OpenedFiles");
		if (pCollection_OpenedFiles != NULL)
		{
			pCollection_OpenedFiles((TCHAR*)pdbName.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 105)//ARPCache
	{
		typedef void (*Collection_ARPCache)(TCHAR*, int);//系統ARP暫存檔
		Collection_ARPCache pCollection_ARPCache = (Collection_ARPCache)GetProcAddress(plib, "Collection_ARPCache");
		if (pCollection_ARPCache != NULL)
		{
			pCollection_ARPCache((TCHAR*)pdbName.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 201)//Service
	{
		typedef void (*Collection_Service)(TCHAR*, int);//所有服務列表
		Collection_Service pCollection_Service = (Collection_Service)GetProcAddress(plib, "Collection_Service");
		if (pCollection_Service != NULL)
		{
			pCollection_Service((TCHAR*)pdbName.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 202)//StartRun
	{
		typedef void (*Collection_StartRun)(TCHAR*, int);//開機啟動程式
		Collection_StartRun pCollection_StartRun = (Collection_StartRun)GetProcAddress(plib, "Collection_StartRun");
		if (pCollection_StartRun != NULL)
		{
			pCollection_StartRun((TCHAR*)pdbName.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 203)//Wireless
	{
		typedef void (*Collection_Wireless)(TCHAR*, int);//無線網路連線資訊
		Collection_Wireless pCollection_Wireless = (Collection_Wireless)GetProcAddress(plib, "Collection_Wireless");
		if (pCollection_Wireless != NULL)
		{
			pCollection_Wireless((TCHAR*)pdbName.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 204)//InstalledSoftware
	{
		typedef void (*Collection_InstalledSoftware)(TCHAR*, int);//已安裝軟體資訊
		Collection_InstalledSoftware pCollection_InstalledSoftware = (Collection_InstalledSoftware)GetProcAddress(plib, "Collection_InstalledSoftware");
		if (pCollection_InstalledSoftware != NULL)
		{
			pCollection_InstalledSoftware((TCHAR*)pdbName.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 205)//SystemInfo
	{
		typedef void (*Collection_SystemInfo)(TCHAR*);//Windows 系統資訊
		Collection_SystemInfo pCollection_SystemInfo = (Collection_SystemInfo)GetProcAddress(plib, "Collection_SystemInfo");
		if (pCollection_SystemInfo != NULL)
		{
			pCollection_SystemInfo((TCHAR*)pdbName.c_str());
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 206)//USBdevices
	{
		typedef void (*Collection_USBdevices)(TCHAR*, int);//USB設備列表
		Collection_USBdevices pCollection_USBdevices = (Collection_USBdevices)GetProcAddress(plib, "Collection_USBdevices");
		if (pCollection_USBdevices != NULL)
		{
			pCollection_USBdevices((TCHAR*)pdbName.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 207)//Shortcuts
	{
		typedef void (*Collection_Shortcuts)(TCHAR*, int);//桌面及開始功能表捷徑資訊
		Collection_Shortcuts pCollection_Shortcuts = (Collection_Shortcuts)GetProcAddress(plib, "Collection_Shortcuts");
		if (pCollection_Shortcuts != NULL)
		{
			pCollection_Shortcuts((TCHAR*)pdbName.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 208)//UserProfiles
	{
		typedef void (*Collection_UserProfiles)(TCHAR*, int);//本機所有使用者資訊
		Collection_UserProfiles pCollection_UserProfiles = (Collection_UserProfiles)GetProcAddress(plib, "Collection_UserProfiles");
		if (pCollection_UserProfiles != NULL)
		{
			pCollection_UserProfiles((TCHAR*)pdbName.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 209)//MUICache
	{
		typedef void (*Collection_MUICache)(TCHAR*, int);//MUICache
		Collection_MUICache pCollection_MUICache = (Collection_MUICache)GetProcAddress(plib, "Collection_MUICache");
		if (pCollection_MUICache != NULL)
		{
			pCollection_MUICache((TCHAR*)pdbName.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 210)//Prefetch
	{
		typedef void (*Collection_Prefetch)(TCHAR*, int);//程式執行紀錄
		Collection_Prefetch pCollection_Prefetch = (Collection_Prefetch)GetProcAddress(plib, "Collection_Prefetch");
		if (pCollection_Prefetch != NULL)
		{
			pCollection_Prefetch((TCHAR*)pdbName.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 211)//EventSecurity
	{
		typedef void (*Collection_EventQuery_Security)(TCHAR*, TCHAR*, int);//事件紀錄 Security
		Collection_EventQuery_Security pCollection_EventQuery_Security = (Collection_EventQuery_Security)GetProcAddress(plib, "Collection_EventQuery_Security");
		if (pCollection_EventQuery_Security != NULL)
		{
			pCollection_EventQuery_Security((TCHAR*)pdbName.c_str(), (TCHAR*)pSavePath.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 212)//EventApplication
	{
		typedef void (*Collection_EventQuery_Application)(TCHAR*, TCHAR*, int);//事件紀錄 Application
		Collection_EventQuery_Application pCollection_EventQuery_Application = (Collection_EventQuery_Application)GetProcAddress(plib, "Collection_EventQuery_Application");
		if (pCollection_EventQuery_Application != NULL)
		{
			pCollection_EventQuery_Application((TCHAR*)pdbName.c_str(), (TCHAR*)pSavePath.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 213)//EventSystem
	{
		typedef void (*Collection_EventQuery_System)(TCHAR*, TCHAR*, int);//事件紀錄 System
		Collection_EventQuery_System pCollection_EventQuery_System = (Collection_EventQuery_System)GetProcAddress(plib, "Collection_EventQuery_System");
		if (pCollection_EventQuery_System != NULL)
		{
			pCollection_EventQuery_System((TCHAR*)pdbName.c_str(), (TCHAR*)pSavePath.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 214)//TaskSchedule
	{
		typedef void (*Collection_TaskSchedule)(TCHAR*, int);//工作排程資訊
		Collection_TaskSchedule pCollection_TaskSchedule = (Collection_TaskSchedule)GetProcAddress(plib, "Collection_TaskSchedule");
		if (pCollection_TaskSchedule != NULL)
		{
			pCollection_TaskSchedule((TCHAR*)pdbName.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 215)//UserAssist
	{
		typedef void (*Collection_UserAssist)(TCHAR*, int);//UserAssist
		Collection_UserAssist pCollection_UserAssist = (Collection_UserAssist)GetProcAddress(plib, "Collection_UserAssist");
		if (pCollection_UserAssist != NULL)
		{
			pCollection_UserAssist((TCHAR*)pdbName.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 216)//IECache
	{
		typedef void (*Collection_IECache)(TCHAR*, int);//Internet Explorer Cache
		Collection_IECache pCollection_IECache = (Collection_IECache)GetProcAddress(plib, "Collection_IECache");
		if (pCollection_IECache != NULL)
		{
			pCollection_IECache((TCHAR*)pdbName.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 217)//IEHistory
	{
		typedef void (*Collection_IEHistory)(TCHAR*, int);//Internet Explorer 網頁瀏覽紀錄
		Collection_IEHistory pCollection_IEHistory = (Collection_IEHistory)GetProcAddress(plib, "Collection_IEHistory");
		if (pCollection_IEHistory != NULL)
		{
			pCollection_IEHistory((TCHAR*)pdbName.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 218)//ShellBags
	{
		typedef void (*Collection_ShellBags)(TCHAR*, int);//曾經開啟的資料夾路徑
		Collection_ShellBags pCollection_ShellBags = (Collection_ShellBags)GetProcAddress(plib, "Collection_ShellBags");
		if (pCollection_ShellBags != NULL)
		{
			pCollection_ShellBags((TCHAR*)pdbName.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 219)//RecentFile
	{
		typedef void (*Collection_RecentFile)(TCHAR*, int);//檢視電腦中最近開啟的文件
		Collection_RecentFile pCollection_RecentFile = (Collection_RecentFile)GetProcAddress(plib, "Collection_RecentFile");
		if (pCollection_RecentFile != NULL)
		{
			pCollection_RecentFile((TCHAR*)pdbName.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 220)//FirefoxLogin
	{
		typedef void (*Collection_FirefoxLogin)(TCHAR*, int);//Mozilla Firefox所儲存登入資訊
		Collection_FirefoxLogin pCollection_FirefoxLogin = (Collection_FirefoxLogin)GetProcAddress(plib, "Collection_FirefoxLogin");
		if (pCollection_FirefoxLogin != NULL)
		{
			pCollection_FirefoxLogin((TCHAR*)pdbName.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 221)//FirefoxHistory
	{
		typedef void (*Collection_FirefoxHistory)(TCHAR*, TCHAR*, int);//Mozilla Firefox 網頁瀏覽紀錄
		Collection_FirefoxHistory pCollection_FirefoxHistory = (Collection_FirefoxHistory)GetProcAddress(plib, "Collection_FirefoxHistory");
		if (pCollection_FirefoxHistory != NULL)
		{
			pCollection_FirefoxHistory((TCHAR*)pdbName.c_str(), (TCHAR*)pSavePath.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 222)//ChromeLogin
	{
		typedef void (*Collection_ChromeLogin)(TCHAR*, TCHAR*, int);//Chrome 所儲存登入資訊
		Collection_ChromeLogin pCollection_ChromeLogin = (Collection_ChromeLogin)GetProcAddress(plib, "Collection_ChromeLogin");
		if (pCollection_ChromeLogin != NULL)
		{
			pCollection_ChromeLogin((TCHAR*)pdbName.c_str(), (TCHAR*)pSavePath.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 223)//ChromeKeywordSearch
	{
		typedef void (*Collection_ChromeKeywordSearch)(TCHAR*, TCHAR*, int);//Chrome 關鍵字搜尋
		Collection_ChromeKeywordSearch pCollection_ChromeKeywordSearch = (Collection_ChromeKeywordSearch)GetProcAddress(plib, "Collection_ChromeKeywordSearch");
		if (pCollection_ChromeKeywordSearch != NULL)
		{
			pCollection_ChromeKeywordSearch((TCHAR*)pdbName.c_str(), (TCHAR*)pSavePath.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 224)//ChromeDownload
	{
		typedef void (*Collection_ChromeDownload)(TCHAR*, TCHAR*, int);//Chrome 下載紀錄
		Collection_ChromeDownload pCollection_ChromeDownload = (Collection_ChromeDownload)GetProcAddress(plib, "Collection_ChromeDownload");
		if (pCollection_ChromeDownload != NULL)
		{
			pCollection_ChromeDownload((TCHAR*)pdbName.c_str(), (TCHAR*)pSavePath.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 225)//ChromeHistory
	{
		typedef void (*Collection_ChromeHistory)(TCHAR*, TCHAR*, int);//Chrome 網頁瀏覽紀錄
		Collection_ChromeHistory pCollection_ChromeHistory = (Collection_ChromeHistory)GetProcAddress(plib, "Collection_ChromeHistory");
		if (pCollection_ChromeHistory != NULL)
		{
			pCollection_ChromeHistory((TCHAR*)pdbName.c_str(), (TCHAR*)pSavePath.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 226)//BaseService
	{
		typedef void (*Collection_BaseService)(TCHAR*, int);//所有服務列表
		Collection_BaseService pCollection_BaseService = (Collection_BaseService)GetProcAddress(plib, "Collection_BaseService");
		if (pCollection_BaseService != NULL)
		{
			pCollection_BaseService((TCHAR*)pdbName.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 227)//JumpList
	{
		typedef void (*Collection_JumpList)(TCHAR*, int);//JumpList
		Collection_JumpList pCollection_JumpList = (Collection_JumpList)GetProcAddress(plib, "Collection_JumpList");
		if (pCollection_JumpList != NULL)
		{
			pCollection_JumpList((TCHAR*)pdbName.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 228)//Windows_Activity
	{
		typedef void (*Collection_Windows_Activity)(TCHAR*, TCHAR*, int);
		Collection_Windows_Activity pCollection_Windows_Activity = (Collection_Windows_Activity)GetProcAddress(plib, "Collection_Windows_Activity");
		if (pCollection_Windows_Activity != NULL)
		{
			pCollection_Windows_Activity((TCHAR*)pdbName.c_str(), (TCHAR*)pSavePath.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 229)//Network_Data_Usage
	{
		typedef void (*Collection_Network_Data_Usage_Monitor)(TCHAR*, TCHAR*, int);
		Collection_Network_Data_Usage_Monitor pCollection_Network_Data_Usage_Monitor = (Collection_Network_Data_Usage_Monitor)GetProcAddress(plib, "Collection_Network_Data_Usage_Monitor");
		if (pCollection_Network_Data_Usage_Monitor != NULL)
		{
			pCollection_Network_Data_Usage_Monitor((TCHAR*)pdbName.c_str(), (TCHAR*)pSavePath.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 230)//AppResourceUsageMonitor
	{
		typedef void (*Collection_App_Resource_Usage_Monitor)(TCHAR*, TCHAR*, int);
		Collection_App_Resource_Usage_Monitor pCollection_App_Resource_Usage_Monitor = (Collection_App_Resource_Usage_Monitor)GetProcAddress(plib, "Collection_App_Resource_Usage_Monitor");
		if (pCollection_App_Resource_Usage_Monitor != NULL)
		{
			pCollection_App_Resource_Usage_Monitor((TCHAR*)pdbName.c_str(), (TCHAR*)pSavePath.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 231)
	{
		typedef void (*Collection_DNS_INFO)(TCHAR*, TCHAR*, int);
		Collection_DNS_INFO  pCollection_DNS_INFO = (Collection_DNS_INFO)GetProcAddress(plib, "Collection_DNS_INFO");
		if (pCollection_DNS_INFO != NULL)
		{
			pCollection_DNS_INFO((TCHAR*)pdbName.c_str(), (TCHAR*)pSavePath.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 232)
	{
		typedef void (*Collection_EdgeLogin)(TCHAR*, TCHAR*, int);
		Collection_EdgeLogin pCollection_EdgeLogin = (Collection_EdgeLogin)GetProcAddress(plib, "Collection_EdgeLogin");
		if (pCollection_EdgeLogin != NULL)
		{
			pCollection_EdgeLogin((TCHAR*)pdbName.c_str(), (TCHAR*)pSavePath.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 233)
	{
		typedef void (*Collection_EdgeHistory)(TCHAR*, TCHAR*, int);
		Collection_EdgeHistory  pCollection_EdgeHistory = (Collection_EdgeHistory)GetProcAddress(plib, "Collection_EdgeHistory");
		if (pCollection_EdgeHistory != NULL)
		{
			pCollection_EdgeHistory((TCHAR*)pdbName.c_str(), (TCHAR*)pSavePath.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 234)
	{
		typedef void (*Collection_IELogin)(TCHAR*, TCHAR*, int);
		Collection_IELogin pCollection_IELogin = (Collection_IELogin)GetProcAddress(plib, "Collection_IELogin");
		if (pCollection_IELogin != NULL)
		{
			pCollection_IELogin((TCHAR*)pdbName.c_str(), (TCHAR*)pSavePath.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 235)
	{
		typedef void (*Collection_ChromeBookmarks)(TCHAR*, TCHAR*, int);
		Collection_ChromeBookmarks pCollection_ChromeBookmarks = (Collection_ChromeBookmarks)GetProcAddress(plib, "Collection_ChromeBookmarks");
		if (pCollection_ChromeBookmarks != NULL)
		{
			pCollection_ChromeBookmarks((TCHAR*)pdbName.c_str(), (TCHAR*)pSavePath.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 236)
	{
		typedef void (*Collection_EdgeBookmarks)(TCHAR*, TCHAR*, int);
		Collection_EdgeBookmarks pCollection_EdgeBookmarks = (Collection_EdgeBookmarks)GetProcAddress(plib, "Collection_EdgeBookmarks");
		if (pCollection_EdgeBookmarks != NULL)
		{
			pCollection_EdgeBookmarks((TCHAR*)pdbName.c_str(), (TCHAR*)pSavePath.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 237)
	{
		typedef void (*Collection_FirefoxBookmarks)(TCHAR*, TCHAR*, int);
		Collection_FirefoxBookmarks pCollection_FirefoxBookmarks = (Collection_FirefoxBookmarks)GetProcAddress(plib, "Collection_FirefoxBookmarks");
		if (pCollection_FirefoxBookmarks != NULL)
		{
			pCollection_FirefoxBookmarks((TCHAR*)pdbName.c_str(), (TCHAR*)pSavePath.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 238)
	{
		typedef void (*Collection_ChromeCookies)(TCHAR*, TCHAR*, int);
		Collection_ChromeCookies pCollection_ChromeCookies = (Collection_ChromeCookies)GetProcAddress(plib, "Collection_ChromeCookies");
		if (pCollection_ChromeCookies != NULL)
		{
			pCollection_ChromeCookies((TCHAR*)pdbName.c_str(), (TCHAR*)pSavePath.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 239)
	{
		typedef void (*Collection_EdgeCookies)(TCHAR*, TCHAR*, int);
		Collection_EdgeCookies  pCollection_EdgeCookies = (Collection_EdgeCookies)GetProcAddress(plib, "Collection_EdgeCookies");
		if (pCollection_EdgeCookies != NULL)
		{
			printf("pCollection_EdgeCookies\n");
			try {
				pCollection_EdgeCookies((TCHAR*)pdbName.c_str(), (TCHAR*)pSavePath.c_str(), m_Num);
			}
			catch (...) {
				printf("pCollection_EdgeCookies failed\n");
			}
			
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 240)
	{
		typedef void (*Collection_FirefoxCookies)(TCHAR*, TCHAR*, int);
		Collection_FirefoxCookies   pCollection_FirefoxCookies = (Collection_FirefoxCookies)GetProcAddress(plib, "Collection_FirefoxCookies");
		if (pCollection_FirefoxCookies != NULL)
		{
			pCollection_FirefoxCookies((TCHAR*)pdbName.c_str(), (TCHAR*)pSavePath.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 241)
	{
		typedef void (*Collection_ChromeCache)(TCHAR*, TCHAR*, int);
		Collection_ChromeCache pCollection_ChromeCache = (Collection_ChromeCache)GetProcAddress(plib, "Collection_ChromeCache");
		if (pCollection_ChromeCache != NULL)
		{
			pCollection_ChromeCache((TCHAR*)pdbName.c_str(), (TCHAR*)pSavePath.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 242)
	{
		typedef void (*Collection_EdgeCache)(TCHAR*, TCHAR*, int);
		Collection_EdgeCache pCollection_EdgeCache = (Collection_EdgeCache)GetProcAddress(plib, "Collection_EdgeCache");
		if (pCollection_EdgeCache != NULL)
		{
			pCollection_EdgeCache((TCHAR*)pdbName.c_str(), (TCHAR*)pSavePath.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	else if (m_Num == 243)
	{
		typedef void (*Collection_FirefoxCache)(TCHAR*, TCHAR*, int);
		Collection_FirefoxCache pCollection_FirefoxCache = (Collection_FirefoxCache)GetProcAddress(plib, "Collection_FirefoxCache");
		if (pCollection_FirefoxCache != NULL)
		{
			pCollection_FirefoxCache((TCHAR*)pdbName.c_str(), (TCHAR*)pSavePath.c_str(), m_Num);
			wprintf(L"STATUS_CODE:0");
		}
		else
			wprintf(L"STATUS_CODE:R00034");//dll function error
	}
	printf("\n\n");
}
bool Collect::WriteSQLiteDB(sqlite3* pdb, char* pQuery)
{
	bool ret = false;
	//char* query = CStringToCharArray((wchar_t *)pQuery.c_str(), CP_UTF8);
	char* ErrMsg = NULL;
	if (sqlite3_exec(pdb, pQuery, NULL, 0, &ErrMsg) == SQLITE_OK)
	{
		ret = true;
	}
	//printf("%s\n",ErrMsg);
	sqlite3_free(ErrMsg);
	//delete [] query;
	return ret;
}

bool Collect::GetQueryByTable(string* query, string TableName, string QueryFilter)
{
	bool bResult = true;
	*query += "SELECT ";
	if (TableName == "ARPCache") { *query += "id, internetaddress, physicaladdress "; }
	else if (TableName == "BaseService") { *query += "id, name, pathname FROM "; }
	else if (TableName == "ChromeDownload") { *query += "id, download_url, start_time, target_path "; }
	else if (TableName == "ChromeHistory") { *query += "id, url, last_visit_time, title FROM "; }
	else if (TableName == "ChromeKeywordSearch") { *query += "id, term, title FROM "; }
	else if (TableName == "ChromeLogin") { *query += "id, origin_url, date_created, username_value "; }
	else if (TableName == "EventApplication") { *query += "id, eventid, createdsystemtime, evtrenderdata "; }
	else if (TableName == "EventSecurity") { *query += "id, eventid, createdsystemtime, evtrenderdata "; }
	else if (TableName == "EventSystem") { *query += "id, eventid, createdsystemtime, evtrenderdata "; }
	else if (TableName == "FirefoxHistory") { *query += "id, url, last_visit_time, title "; }
	else if (TableName == "FirefoxLogin") { *query += "id, hostname, timelastused, username "; }
	else if (TableName == "IECache") { *query += "id, sourceurlname, lastaccesstime, localfilename "; }
	else if (TableName == "IEHistory") { *query += "id, url, visitedtime, title "; }
	else if (TableName == "InstalledSoftware") { *query += "id, displayname, registrytime, publisher "; }
	else if (TableName == "MUICache") { *query += "id, applicationpath, applicationname "; }
	else if (TableName == "Network") { *query += "id, processname, remoteaddress "; }
	else if (TableName == "NetworkResources") { *query += "id, resourcesname, ipaddress "; }
	else if (TableName == "OpenedFiles") { *query += "id, processname, processid "; }
	else if (TableName == "Prefetch") { *query += "id, processname, lastruntime, processpath "; }
	else if (TableName == "Process") { *query += "id, process_name, processcreatetime, process_path "; }
	else if (TableName == "RecentFile") { *query += "id, name, accesstime, fullpath "; }
	else if (TableName == "Service") { *query += "id, name, pathname "; }
	else if (TableName == "ShellBags") { *query += "id, path, lastmodifiedtime, slotpath "; }
	else if (TableName == "Shortcuts") { *query += "id, shortcutname, modifytime, linkto "; }
	else if (TableName == "StartRun") { *query += "id, name, command "; }
	else if (TableName == "SystemInfo") { *query += "id, hotfix, os "; }
	else if (TableName == "TaskSchedule") { *query += "id, name, lastruntime, path "; }
	else if (TableName == "USBdevices") { *query += "id, device_description, last_arrival_date, device_letter "; }
	else if (TableName == "UserAssist") { *query += "id, name, modifiedtime, of_times_executed "; }
	else if (TableName == "UserProfiles") { *query += "id, username, lastlogontime, usersid "; }
	else if (TableName == "Wireless") { *query += "id, profilename, lastmodifiedtime, authentication "; }
	else if (TableName == "JumpList") { *query += "id, fullpath, recordtime, application_id "; }
	else if (TableName == "WindowsActivity") { *query += "id, app_id, last_modified_on_client, activity_type "; }
	else if (TableName == "NetworkDataUsageMonitor") { *query += "id, app_name, timestamp, bytes_sent "; }
	else if (TableName == "AppResourceUsageMonitor") { *query += "id, app_name, timestamp, backgroundbyteswritten "; }
	else { bResult = false; }

	if (bResult == true)
	{
		*query += "FROM ";
		*query += TableName;
		if (!QueryFilter.empty())
		{
			*query += " WHERE ";
			*query += QueryFilter;
		}
	}

	return bResult;
}

bool Collect::GetDataByQuery(const string& query, sqlite3* m_db, vector<CombineObj>* vecCombineObj)
{
	sqlite3_stmt* statement;
	if (sqlite3_prepare(m_db, query.c_str(), -1, &statement, 0) == SQLITE_OK)
	{
		int ctotal = sqlite3_column_count(statement);
		int res = 0;
		while (res != SQLITE_DONE && res != SQLITE_ERROR)
		{
			res = sqlite3_step(statement);
			if (res == SQLITE_ROW)
			{
				CombineObj tmp;
				tmp.Table_id = (char*)sqlite3_column_text(statement, 0);
				tmp.Item = (char*)sqlite3_column_text(statement, 1);
				if (ctotal == 4)
				{
					tmp.Date = (char*)sqlite3_column_text(statement, 2);
					tmp.ETC = (char*)sqlite3_column_text(statement, 3);
				}
				else
				{
					tmp.Date = "";
					tmp.ETC = (char*)sqlite3_column_text(statement, 2);
				}
				vecCombineObj->push_back(tmp);
			}
		}
	}
	sqlite3_finalize(statement);
	return vecCombineObj->size() > 0 ? true : false;
}

bool Collect::WriteDataSetToDB(sqlite3* m_db, const vector<CombineObj> vecCombineObj, const string DefineName, const string MAC, const string IP, const string TableName, int id)
{
	/*CombineObj combineObj;*/
	string query;
	int index = id;
	for (auto CombineObj : vecCombineObj)
	{
		query.clear();
		query += "INSERT INTO ";
		query += DefineName;
		query += " VALUES (";
		query += to_string(index);
		query += ", \'";
		query += MAC;
		query += "\', \'";
		query += IP;
		query += "\', ";
		query += CombineObj.Table_id;
		query += ", \"";
		if (CombineObj.Item.find("\"") != string::npos)
		{
			replace(CombineObj.Item.begin(), CombineObj.Item.end(), '\"', '\'');
		}
		query += CombineObj.Item;
		query += "\", \'";
		query += CombineObj.Date;
		query += "\', \'";
		query += TableName;
		query += "\', \"";
		if (CombineObj.ETC.find("\"") != string::npos)
		{
			replace(CombineObj.ETC.begin(), CombineObj.ETC.end(), '\"', '\'');
		}
		query += CombineObj.ETC;
		query += "\")";
		WriteSQLiteDB(m_db, (char*)query.c_str());
		index++;
	}
	return true;
}