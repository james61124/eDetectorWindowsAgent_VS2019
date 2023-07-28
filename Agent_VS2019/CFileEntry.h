#pragma once

#include "FAT32General.h"
#include "CEntry.h"

class CFileEntry : public CEntry
{
public:
	CFileEntry(FATDirEntry aDirEntry, LFNEntry* aLFNEntries, WORD aNumLFNEntries);
	~CFileEntry(void);
};

	