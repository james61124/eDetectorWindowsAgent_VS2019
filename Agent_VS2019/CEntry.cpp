
#include <atlconv.h>
#include <atlbase.h>
#include "CEntry.h"

CEntry::CEntry(FATDirEntry aHexData, LFNEntry* aLFNEntries, WORD aNumLFNEntries)
{
	m_data = aHexData;
	m_numOfEntryElements = aNumLFNEntries;
	m_chainedLFNEntry = aLFNEntries;
}
CEntry::CEntry()
{
	// Incase this it the ROOT DIR - Initialize the data as an empty buffer.
	memset(&m_data,0,sizeof(FATDirEntry));
	m_chainedLFNEntry = NULL;
	m_numOfEntryElements = 0;
}

CEntry::~CEntry(void)
{
	if (m_chainedLFNEntry != NULL)
		delete[] m_chainedLFNEntry;
}

// Retrieve the total bytes amount of the short file name entry, and the LFN Entry
DWORD CEntry::getEntrySize()
{
	return sizeof(FATDirEntry) + m_numOfEntryElements*sizeof(LFNEntry);
}

bool CEntry::isDeleted()
{
	return isDeletedEntry(m_data);
}

// Returns the data of the entry
// DON'T FORGET TO FREE THE MEMORY OF THE BUFFER
BYTE* CEntry::getData()
{
	BYTE* entryData = new BYTE[getEntrySize()];
	memcpy(entryData, 
			m_chainedLFNEntry, getEntrySize()-sizeof(FATDirEntry));
	memcpy(entryData+getEntrySize()-sizeof(FATDirEntry), 
			&m_data, sizeof(FATDirEntry));
	return entryData;
}

void CEntry::setData(BYTE* aData)
{
	memcpy(&m_data, aData, sizeof(m_data));
}

WCHAR* CEntry::getName()
{
	WCHAR* udini = getLongName();
	if (udini != NULL)
		return udini;
	else
		return getShortName();	
}

WCHAR* CEntry::getShortName()
{
	char* udini = new char[sizeof(m_data.DIR_Name)+1];
	memset(udini,'\0',sizeof(m_data.DIR_Name)+1);
	memcpy_s(udini, sizeof(m_data.DIR_Name), m_data.DIR_Name, sizeof(m_data.DIR_Name));
	//udini[sizeof(m_data.DIR_Name)] = '\0';

	char* udini1 = new char[sizeof(m_data.DIR_Name)+1];
	memset(udini1,'\0',sizeof(m_data.DIR_Name)+1);
	int len = sizeof(m_data.DIR_Name)+1;//(int)strlen(udini);
	bool isHaveExt = false;
	int j = 0;
	for(int i = 0;i<len;i++)
	{
		if(i==(len-2)||i==(len-3)||i==(len-4))
		{

			if(udini[i]==' ')
			{
				continue;
			}
			else
			{
				if(!isHaveExt)
				{
					//udini1[j] = udini[i];
					udini1[j] = '.';
					j++;
					udini1[j] = udini[i];
					j++;
					isHaveExt = true;
				}
				else
				{
					udini1[j] = udini[i];
					j++;
				}
			}
		}
		else
		{
			if(udini[i]==' ')
			{
				continue;
			}
			else
			{
				udini1[j] = udini[i];
				j++;
			}
		}
	}
	// Convert ASCII to UNICODE
	//CA2W temp(udini1);
	WCHAR *temp  = CharArrayToWString(udini1,CP_UTF8);
	delete[] udini1;
	delete[] udini;

	int size = (int)wcslen(temp);

	// Since the ATL macro to convert from ASCII to UNICODE is freeing the data when 
	// the buffer is out of scope - we'll copy the data into out own heap-managed buffer
	WCHAR* ret = new WCHAR[size+1];

	// Using memcpy, cause wcscpy expect \0 in the end of the source, 
	// and the ATL macro don't put it there from some reason...

	memcpy(ret, temp, size*sizeof(WORD));
	ret[size] = '\0';

	return ret;
}
WCHAR* CEntry::getLongName()
{
	// If this is not an LFN
	if (m_numOfEntryElements == 0)
		return NULL;

	LFNEntry* lfnCurrEntry = m_chainedLFNEntry;

	// The size of the name in BYTES, for each LFN entry
	int entryNameSize = sizeof(lfnCurrEntry->LDIR_Name1)+
						sizeof(lfnCurrEntry->LDIR_Name2)+
						sizeof(lfnCurrEntry->LDIR_Name3);

	// The size of the name in BYTES, for the WHOLE dir entry

	int size = m_numOfEntryElements*entryNameSize;

	WCHAR* wName = new WCHAR[size/sizeof(WCHAR) + 1];
	// Adding the \0 ourselves, cause there's a chance that the file name won't have it
	// (Happens if the file name if fully populate all the bytes reserved for the name, 
	//  and there's no place left for the \0)
	wName[size/sizeof(WCHAR)] = '\0';
	// The order of the entries is reverse to the order in this entries array (m_numOfEntryElements-1,.., 2, 1,0)
	for (int i=m_numOfEntryElements-1; i>=0; --i)
	{
		// This is a pointer to the start position in the Name buffer for this LFN entry
		WCHAR* wCurrNamePosition = wName+(m_numOfEntryElements-1-i)*entryNameSize/sizeof(WCHAR);

		// Copies the data
		memcpy_s(wCurrNamePosition, 
				sizeof(lfnCurrEntry[i].LDIR_Name1), lfnCurrEntry[i].LDIR_Name1, sizeof(lfnCurrEntry[i].LDIR_Name1));

		wCurrNamePosition += sizeof(lfnCurrEntry[i].LDIR_Name1)/sizeof(WCHAR);
		memcpy_s(wCurrNamePosition, 
				sizeof(lfnCurrEntry[i].LDIR_Name2), lfnCurrEntry[i].LDIR_Name2, sizeof(lfnCurrEntry[i].LDIR_Name2));

		wCurrNamePosition += sizeof(lfnCurrEntry[i].LDIR_Name2)/sizeof(WCHAR);
		memcpy_s(wCurrNamePosition,
				sizeof(lfnCurrEntry[i].LDIR_Name3), lfnCurrEntry[i].LDIR_Name3, sizeof(lfnCurrEntry[i].LDIR_Name3));
	}
	/*MessageBox(0,wName,0,0);*/
	return wName;
}
//WCHAR* CEntry::getShortName()
//{
//	char* udini = new char[sizeof(m_data.DIR_Name)+1];
//	memcpy_s(udini, sizeof(m_data.DIR_Name), m_data.DIR_Name, sizeof(m_data.DIR_Name));
//	udini[sizeof(m_data.DIR_Name)] = '\0';
//
//	char* udini1 = new char[sizeof(m_data.DIR_Name)+1];
//	memset(udini1,'\0',sizeof(m_data.DIR_Name)+1);
//	int len = (int)strlen(udini);
//	bool isHaveExt = false;
//	int j = 0;
//	for(int i = 0;i<len;i++)
//	{
//		if(i==(len-1)||i==(len-2)||i==(len-3))
//		{
//			if(udini[i]==' ')
//			{
//				continue;
//			}
//			else
//			{
//				if(!isHaveExt)
//				{
//					//udini1[j] = udini[i];
//					udini1[j] = '.';
//					j++;
//					udini1[j] = udini[i];
//					j++;
//					isHaveExt = true;
//				}
//				else
//				{
//					udini1[j] = udini[i];
//					j++;
//				}
//			}
//		}
//		else
//		{
//			if(udini[i]==' ')
//			{
//				continue;
//			}
//			else
//			{
//				udini1[j] = udini[i];
//				j++;
//			}
//		}
//	}
//	// Convert ASCII to UNICODE
//	//CA2W temp(udini1);
//	WCHAR *temp  = CharArrayToWString(udini1,CP_UTF8);
//	delete[] udini1;
//	delete[] udini;
//
//	int size = (int)wcslen(temp);
//
//	// Since the ATL macro to convert from ASCII to UNICODE is freeing the data when 
//	// the buffer is out of scope - we'll copy the data into out own heap-managed buffer
//	WCHAR* ret = new WCHAR[size+1];
//
//	// Using memcpy, cause wcscpy expect \0 in the end of the source, 
//	// and the ATL macro don't put it there from some reason...
//
//	memcpy(ret, temp, size*sizeof(WORD));
//	ret[size] = '\0';
//
//	return ret;
//}
unsigned long CEntry::getFileSize()
{
	return m_data.DIR_FileSize;
}
int CEntry::getFileTime(SYSTEMTIME* m_CreateTime,SYSTEMTIME* m_WriteTime,SYSTEMTIME* m_AccessTime)
{
	int cyear, cmonth, cday, chour, cmin, csec;
	int wyear, wmonth, wday, whour, wmin, wsec;
	int ayear, amonth, aday;

	parseDosDateStamp(m_data.DIR_CrtDate, &cyear, &cmonth, &cday);

	parseDosDateStamp(m_data.DIR_WrtDate, &wyear, &wmonth, &wday);

	parseDosDateStamp(m_data.DIR_LstAccDate, &ayear, &amonth, &aday);
	SYSTEMTIME st;
    GetSystemTime(&st);
	int cur_year = st.wYear;

	if(cyear < 1990 || cyear > cur_year)
		return -1;
	else if(wyear < 1990 || wyear > cur_year)
		return -1;
	else if(ayear < 1990 || ayear > cur_year)
		return -1;
	else
	{
		m_CreateTime->wYear = cyear;
		m_CreateTime->wMonth = cmonth;
		m_CreateTime->wDay = cday;

		m_WriteTime->wYear = wyear;
		m_WriteTime->wMonth = wmonth;
		m_WriteTime->wDay = wday;

		m_AccessTime->wYear = ayear;
		m_AccessTime->wMonth = amonth;
		m_AccessTime->wDay = aday;

		parseDosTimeStamp(m_data.DIR_CrtTime, &chour, &cmin, &csec);

		parseDosTimeStamp(m_data.DIR_WrtTime, &whour, &wmin, &wsec);

		m_CreateTime->wHour = chour;
		m_CreateTime->wMinute = cmin;
		m_CreateTime->wSecond = csec;
		m_CreateTime->wMilliseconds = 0;
		m_CreateTime->wDayOfWeek = 0;

		m_WriteTime->wHour = whour;
		m_WriteTime->wMinute = wmin;
		m_WriteTime->wSecond = wsec;
		m_WriteTime->wMilliseconds = 0;
		m_WriteTime->wDayOfWeek = 0;

		m_AccessTime->wHour = 8;
		m_AccessTime->wMinute = 0;
		m_AccessTime->wSecond = 0;
		m_AccessTime->wMilliseconds = 0;
		m_AccessTime->wDayOfWeek = 0;
	}
	return 0;
}
void CEntry::parseDosDateStamp(short ms_date, int * year, int * month, int * day)
{
	*day = ms_date & DAY_MASK;

	*month = ms_date & MONTH_MASK;
	*month >>= 5;

	*year = ms_date & YEAR_MASK;
	*year >>= 9;
	*year += 1980;
}
void CEntry::parseDosTimeStamp(short ms_time, int * hour, int * min, int * sec)
{
	*sec = ms_time & SecByTwo_MASK;
	*sec *= 2;

	*min = ms_time & MIN_MASK;
	*min >>= 5;

	*hour = ms_time & HOUR_MASK;
	*hour >>= 11;
}
DWORD CEntry::GetTheFirstDataCluster()
{
	DWORD dwFirstCluster = 0x00000000;
	dwFirstCluster |= m_data.DIR_FstClusHi;
	dwFirstCluster <<= 16;
	dwFirstCluster |= m_data.DIR_FstClusLo;

	return dwFirstCluster;
}