#pragma once

#include "FAT32General.h"

class CEntry
{
protected:
	// The hex data of the entry.
	// If this is the entry of the root dir - this field will contain the volume id
	FATDirEntry		m_data;

	// The LFN Data, in case this file has LFN
	LFNEntry*		m_chainedLFNEntry;
	WORD			m_numOfEntryElements;

	CEntry();

	virtual WCHAR* getShortName();
	virtual WCHAR* getLongName();

	void setData(BYTE* aData);

	void parseDosDateStamp(short ms_date, int * year, int * month, int * day);
	void parseDosTimeStamp(short ms_time, int * hour, int * min, int * sec);
private:
	enum TimeStampMask
	{
		DAY_MASK			= 0x1F,
		MONTH_MASK		= 0x1E0,
		YEAR_MASK			= 0xFE00,

		SecByTwo_MASK	= 0x1F,
		MIN_MASK				= 0x7E0,
		HOUR_MASK			= 0xF800	
	};
public:
	CEntry(FATDirEntry aHexData, LFNEntry* aLFNEntries, WORD aNumLFNEntries);
	~CEntry(void);


	bool isDeleted();
	// Get a glance in the Hex data of the entry
	BYTE* getData();
	// Retrieve this entry size in bytes
	virtual DWORD getEntrySize();
	// Retrieve the file name. 
	// The boolean arg tells the function to retrieve all the names in lowercase
	virtual WCHAR* getName();
	virtual unsigned long getFileSize();
	virtual int getFileTime(SYSTEMTIME* m_CreateTime,SYSTEMTIME* m_WriteTime,SYSTEMTIME* m_AccessTime);
	virtual DWORD GetTheFirstDataCluster();
};
