
#include <iostream>
#include "NTFS_FileRecord.h"
//#include "NTFS_Attribute.h"
//#include "NTFS_Attribute.cpp"



CFileRecord::CFileRecord(const CNTFSVolume* volume)
{
	_ASSERT(volume);
	Volume = volume;
	FileRecord = NULL;
	FileReference = (ULONGLONG)-1;

	ClearAttrRawCB();

	// Default to parse all attributes
	AttrMask = MASK_ALL;
}

CFileRecord::~CFileRecord()
{
	ClearAttrs();

	if (FileRecord)
		delete FileRecord;
}

// Free all CAttr_xxx
void CFileRecord::ClearAttrs()
{
	for (int i = 0; i < ATTR_NUMS; i++)
	{
		AttrList[i].RemoveAll();
	}
}

// Verify US and update sectors
BOOL CFileRecord::PatchUS(WORD* sector, int sectors, WORD usn, WORD* usarray)
{
	int i;

	for (i = 0; i < sectors; i++)
	{
		sector += ((Volume->SectorSize >> 1) - 1);
		if (*sector != usn)
			return FALSE;	// USN error
		*sector = usarray[i];	// Write back correct data
		sector++;
	}
	return TRUE;
}

// Call user defined Callback routines for an attribute
void CFileRecord::UserCallBack(DWORD attType, ATTR_HEADER_COMMON* ahc, BOOL* bDiscard)
{
	*bDiscard = FALSE;

	if (AttrRawCallBack[attType])
		AttrRawCallBack[attType](ahc, bDiscard);
	else if (Volume->AttrRawCallBack[attType])
		Volume->AttrRawCallBack[attType](ahc, bDiscard);
}

CAttrBase* CFileRecord::AllocAttr(ATTR_HEADER_COMMON* ahc, BOOL* bUnhandled)
{
	switch (ahc->Type)
	{
	case ATTR_TYPE_STANDARD_INFORMATION:
		return new CAttr_StdInfo(ahc, this);

	case ATTR_TYPE_ATTRIBUTE_LIST:
		if (ahc->NonResident)
			return new CAttr_AttrList<CAttrNonResident>(ahc, this);
		else
			return new CAttr_AttrList<CAttrResident>(ahc, this);

	case ATTR_TYPE_FILE_NAME:
		return new CAttr_FileName(ahc, this);

	case ATTR_TYPE_VOLUME_NAME:
		return new CAttr_VolName(ahc, this);

	case ATTR_TYPE_VOLUME_INFORMATION:
		return new CAttr_VolInfo(ahc, this);

	case ATTR_TYPE_DATA:
		if (ahc->NonResident)
			return new CAttr_Data<CAttrNonResident>(ahc, this);
		else
			return new CAttr_Data<CAttrResident>(ahc, this);

	case ATTR_TYPE_INDEX_ROOT:
		return new CAttr_IndexRoot(ahc, this);

	case ATTR_TYPE_INDEX_ALLOCATION:
		return new CAttr_IndexAlloc(ahc, this);

	case ATTR_TYPE_BITMAP:
		if (ahc->NonResident)
			return new CAttr_Bitmap<CAttrNonResident>(ahc, this);
		else
			// Resident Bitmap may exist in a directory's FileRecord
			// or in $MFT for a very small volume in theory
			return new CAttr_Bitmap<CAttrResident>(ahc, this);

		// Unhandled Attributes
	default:
		*bUnhandled = TRUE;
		if (ahc->NonResident)
			return new CAttrNonResident(ahc, this);
		else
			return new CAttrResident(ahc, this);
	}
}

// Parse a single Attribute
// Return False on error
BOOL CFileRecord::ParseAttr(ATTR_HEADER_COMMON* ahc)
{
	DWORD attrIndex = ATTR_INDEX(ahc->Type);
	if (attrIndex < ATTR_NUMS)
	{
		BOOL bDiscard = FALSE;
		UserCallBack(attrIndex, ahc, &bDiscard);

		if (!bDiscard)
		{
			BOOL bUnhandled = FALSE;
			CAttrBase* attr = AllocAttr(ahc, &bUnhandled);
			if (attr)
			{
				if (bUnhandled)
				{
					NTFS_TRACE1("Unhandled attribute: 0x%04X\n", ahc->Type);
				}
				AttrList[attrIndex].InsertEntry(attr);
				return TRUE;
			}
			else
			{
				NTFS_TRACE1("Attribute Parse error: 0x%04X\n", ahc->Type);
				return FALSE;
			}
		}
		else
		{
			NTFS_TRACE1("User Callback has processed this Attribute: 0x%04X\n", ahc->Type);
			return TRUE;
		}
	}
	else
	{
		NTFS_TRACE1("Invalid Attribute Type: 0x%04X\n", ahc->Type);
		return FALSE;
	}
}

// Read File Record
FILE_RECORD_HEADER* CFileRecord::ReadFileRecord(ULONGLONG& fileRef)
{
	FILE_RECORD_HEADER* fr = NULL;
	DWORD len;

	if (fileRef < MFT_IDX_USER || Volume->MFTData == NULL)
	{
		// Take as continuous disk allocation
		//printf("Take as continuous disk allocation\n");
		LARGE_INTEGER frAddr;
		frAddr.QuadPart = Volume->MFTAddr + (Volume->FileRecordSize) * fileRef;
		frAddr.LowPart = SetFilePointer(Volume->hVolume, frAddr.LowPart, &frAddr.HighPart, FILE_BEGIN);

		if (frAddr.LowPart == DWORD(-1) && GetLastError() != NO_ERROR) {
			//printf("error\n");
			return FALSE;
		}
		else
		{
			fr = (FILE_RECORD_HEADER*)new BYTE[Volume->FileRecordSize];
			//printf("start read file\n");
			if (ReadFile(Volume->hVolume, fr, Volume->FileRecordSize, &len, NULL)
				&& len == Volume->FileRecordSize) {
				//std::cout << len << " " << Volume->FileRecordSize << std::endl;
				return fr;
			}
			else
			{
				//printf("read file failed\n");
				delete fr;
				return NULL;
			}
		}
	}
	else
	{
		// May be fragmented $MFT
		//printf("May be fragmented $MFT\n");
		ULONGLONG frAddr;
		frAddr = (Volume->FileRecordSize) * fileRef;

		fr = (FILE_RECORD_HEADER*)new BYTE[Volume->FileRecordSize];

		if (Volume->MFTData->ReadData(frAddr, fr, Volume->FileRecordSize, &len)
			&& len == Volume->FileRecordSize)
			return fr;
		else
		{
			delete fr;
			return NULL;
		}
	}
}

// Read File Record, verify and patch the US (update sequence)
BOOL CFileRecord::ParseFileRecord(ULONGLONG fileRef)
{
	// Clear previous data
	ClearAttrs();
	if (FileRecord)
	{
		delete FileRecord;
		FileRecord = NULL;
	}

	FILE_RECORD_HEADER* fr = ReadFileRecord(fileRef);
	if (fr == NULL)
	{
		printf("Cannot read file record %I64u\n", fileRef);
		FileReference = (ULONGLONG)-1;
	}
	else
	{
		FileReference = fileRef;


		printf("Magic: %x\n", fr->Magic);
		printf("OffsetOfUS: %04X\n", fr->OffsetOfUS);
		printf("SizeOfUS: %04X\n", fr->SizeOfUS);
		printf("LSN: %llu\n", fr->LSN);
		printf("SeqNo: %04X\n", fr->SeqNo);
		printf("Hardlinks: %04X\n", fr->Hardlinks);
		printf("OffsetOfAttr: %04X\n", fr->OffsetOfAttr);
		printf("Flags: %04X\n", fr->Flags);
		printf("RealSize: %08X\n", fr->RealSize);
		printf("AllocSize: %08X\n", fr->AllocSize);
		printf("RefToBase: %llu\n", fr->RefToBase);
		printf("NextAttrId: %04X\n", fr->NextAttrId);
		printf("Align: %04X\n", fr->Align);
		printf("RecordNo: %08X\n", fr->RecordNo);

		if ( fr->Magic == FILE_RECORD_MAGIC )
		{
			// Patch US
			WORD* usnaddr = (WORD*)((BYTE*)fr + fr->OffsetOfUS);
			WORD usn = *usnaddr;
			WORD* usarray = usnaddr + 1;
			if (PatchUS((WORD*)fr, Volume->FileRecordSize / Volume->SectorSize, usn, usarray))
			{
				printf("File Record %I64u Found\n", fileRef);
				FileRecord = fr;

				return TRUE;
			}
			else
			{
				printf("Update Sequence Number error\n");
			}
		}
		else
		{
			printf("Invalid file record\n");
			return FALSE;
		}

		delete fr;
	}

	return FALSE;
}

// Visit IndexBlocks recursivly to find a specific FileName
BOOL CFileRecord::VisitIndexBlock(const ULONGLONG& vcn, const _TCHAR* fileName, CIndexEntry& ieFound) const
{
	CAttr_IndexAlloc* ia = (CAttr_IndexAlloc*)FindFirstAttr(ATTR_TYPE_INDEX_ALLOCATION);
	if (ia == NULL)
		return FALSE;

	CIndexBlock ib;
	if (ia->ParseIndexBlock(vcn, ib))
	{
		CIndexEntry* ie = ib.FindFirstEntry();
		while (ie)
		{
			if (ie->HasName())
			{
				// Compare name
				int i = ie->Compare(fileName);
				if (i == 0)
				{
					ieFound = *ie;
					return TRUE;
				}
				else if (i < 0)		// fileName is smaller than IndexEntry
				{
					// Visit SubNode
					if (ie->IsSubNodePtr())
					{
						// Search in SubNode (IndexBlock), recursive call
						if (VisitIndexBlock(ie->GetSubNodeVCN(), fileName, ieFound))
							return TRUE;
					}
					else
						return FALSE;	// not found
				}
				// Just step forward if fileName is bigger than IndexEntry
			}
			else if (ie->IsSubNodePtr())
			{
				// Search in SubNode (IndexBlock), recursive call
				if (VisitIndexBlock(ie->GetSubNodeVCN(), fileName, ieFound))
					return TRUE;
			}

			ie = ib.FindNextEntry();
		}
	}

	return FALSE;
}

// Traverse SubNode recursivly in ascending order
// Call user defined callback routine once found an subentry
void CFileRecord::TraverseSubNode(const ULONGLONG& vcn, SUBENTRY_CALLBACK seCallBack) const
{
	CAttr_IndexAlloc* ia = (CAttr_IndexAlloc*)FindFirstAttr(ATTR_TYPE_INDEX_ALLOCATION);
	if (ia == NULL)
		return;

	CIndexBlock ib;
	if (ia->ParseIndexBlock(vcn, ib))
	{
		CIndexEntry* ie = ib.FindFirstEntry();
		while (ie)
		{
			if (ie->IsSubNodePtr())
				TraverseSubNode(ie->GetSubNodeVCN(), seCallBack);	// recursive call

			if (ie->HasName())
				seCallBack(ie);

			ie = ib.FindNextEntry();
		}
	}
}

// Parse all the attributes in a File Record
// And insert them into a link list
BOOL CFileRecord::ParseAttrs()
{
	_ASSERT(FileRecord);

	// Clear previous data
	ClearAttrs();

	// Visit all attributes

	DWORD dataPtr = 0;	// guard if data exceeds FileRecordSize bounds
	ATTR_HEADER_COMMON* ahc = (ATTR_HEADER_COMMON*)((BYTE*)FileRecord + FileRecord->OffsetOfAttr);
	dataPtr += FileRecord->OffsetOfAttr;

	while (ahc->Type != (DWORD)-1 && (dataPtr + ahc->TotalSize) <= Volume->FileRecordSize)
	{
		//if (ATTR_MASK(ahc->Type) & AttrMask)	// Skip unwanted attributes
		//{
		if (!ParseAttr(ahc))	// Parse error
			return FALSE;

		//if (IsEncrypted() || IsCompressed())
		//{
			//NTFS_TRACE("Compressed and Encrypted file not supported yet !\n");
			//return FALSE;
		//}
	//}

		dataPtr += ahc->TotalSize;
		ahc = (ATTR_HEADER_COMMON*)((BYTE*)ahc + ahc->TotalSize);	// next attribute
	}

	return TRUE;
}
BOOL CFileRecord::ParseFileAttrs()
{
	_ASSERT(FileRecord);

	// Clear previous data
	ClearAttrs();

	// Visit all attributes

	DWORD dataPtr = 0;	// guard if data exceeds FileRecordSize bounds
	ATTR_HEADER_COMMON* ahc = (ATTR_HEADER_COMMON*)((BYTE*)FileRecord + FileRecord->OffsetOfAttr);
	dataPtr += FileRecord->OffsetOfAttr;

	while (ahc->Type != (DWORD)-1 && (dataPtr + ahc->TotalSize) <= Volume->FileRecordSize)
	{
		if (ahc->Type == 16 || ahc->Type == 32 || ahc->Type == 48 || ahc->Type == 128)	// Skip unwanted attributes
		{
			if (!ParseAttr(ahc))	// Parse error
				return FALSE;

			//if (IsEncrypted() || IsCompressed())
			//{
				//NTFS_TRACE("Compressed and Encrypted file not supported yet !\n");
				//return FALSE;
			//}
		}

		dataPtr += ahc->TotalSize;
		ahc = (ATTR_HEADER_COMMON*)((BYTE*)ahc + ahc->TotalSize);	// next attribute
	}

	return TRUE;
}
int CFileRecord::FindAttrTypeCount(DWORD pAttrType)
{
	_ASSERT(FileRecord);
	int TypeCount = 0;
	DWORD dataPtr = 0;
	ATTR_HEADER_COMMON* ahc = (ATTR_HEADER_COMMON*)((BYTE*)FileRecord + FileRecord->OffsetOfAttr);
	dataPtr += FileRecord->OffsetOfAttr;

	while (ahc->Type != (DWORD)-1 && (dataPtr + ahc->TotalSize) <= Volume->FileRecordSize)
	{//printf("%02x\n",ahc->Type);
		if (ahc->Type == pAttrType)
			TypeCount++;
		dataPtr += ahc->TotalSize;
		ahc = (ATTR_HEADER_COMMON*)((BYTE*)ahc + ahc->TotalSize);	// next attribute
	}
	return TypeCount;
}
// Install Attribute raw data CallBack routines for a single File Record
BOOL CFileRecord::InstallAttrRawCB(DWORD attrType, ATTR_RAW_CALLBACK cb)
{
	DWORD atIdx = ATTR_INDEX(attrType);
	if (atIdx < ATTR_NUMS)
	{
		AttrRawCallBack[atIdx] = cb;
		return TRUE;
	}
	else
		return FALSE;
}

// Clear all Attribute CallBack routines
void CFileRecord::ClearAttrRawCB()
{
	for (int i = 0; i < ATTR_NUMS; i++)
		AttrRawCallBack[i] = NULL;
}

// Choose attributes to handle, unwanted attributes will be discarded silently
void CFileRecord::SetAttrMask(DWORD mask)
{
	// Standard Information and Attribute List is needed always
	AttrMask = mask | MASK_STANDARD_INFORMATION | MASK_ATTRIBUTE_LIST;
}

// Traverse all Attribute and return CAttr_xxx classes to User Callback routine
void CFileRecord::TraverseAttrs(ATTRS_CALLBACK attrCallBack, void* context)
{
	_ASSERT(attrCallBack);

	for (int i = 0; i < ATTR_NUMS; i++)
	{
		if (AttrMask & (((DWORD)1) << i))	// skip masked attributes
		{
			const CAttrBase* ab = AttrList[i].FindFirstEntry();
			while (ab)
			{
				BOOL bStop;
				bStop = FALSE;
				attrCallBack(ab, context, &bStop);
				if (bStop)
					return;

				ab = AttrList[i].FindNextEntry();
			}
		}
	}
}

// Find Attributes
const CAttrBase* CFileRecord::FindFirstAttr(DWORD attrType) const
{
	DWORD attrIdx = ATTR_INDEX(attrType);

	return attrIdx < ATTR_NUMS ? AttrList[attrIdx].FindFirstEntry() : NULL;
}

// 11202012 Debug add ->
const CAttrBase* CFileRecord::FindRecoveryFirstAttr(DWORD attrType) const
{
	//AfxMessageBox(L"FindRecoveryFirstAttr");
	DWORD attrIdx = ATTR_INDEX(attrType);

	return attrIdx < ATTR_NUMS ? AttrList[attrIdx].FindFirstEntry() : NULL;
}

// 11202012 Debug add <-

const CAttrBase* CFileRecord::FindNextAttr(DWORD attrType) const
{
	DWORD attrIdx = ATTR_INDEX(attrType);

	return attrIdx < ATTR_NUMS ? AttrList[attrIdx].FindNextEntry() : NULL;
}

// Get File Name (First Win32 name)
int CFileRecord::GetFileName(_TCHAR* buf, DWORD bufLen) const
{
	// A file may have several filenames
	// Return the first Win32 filename
	CAttr_FileName* fn = (CAttr_FileName*)AttrList[ATTR_INDEX(ATTR_TYPE_FILE_NAME)].FindFirstEntry();
	while (fn)
	{
		if (fn->IsWin32Name())
		{
			int len = fn->GetFileName(buf, bufLen);
			if (len != 0)
				return len;	// success or fail
		}

		fn = (CAttr_FileName*)AttrList[ATTR_INDEX(ATTR_TYPE_FILE_NAME)].FindNextEntry();
	}

	return 0;
}

// Get File Size
ULONGLONG CFileRecord::GetFileSize() const
{
	CAttr_FileName* fn = (CAttr_FileName*)AttrList[ATTR_INDEX(ATTR_TYPE_FILE_NAME)].FindFirstEntry();
	return fn ? fn->GetFileSize() : 0;
}

//Get Parent Ref
ULONGLONG CFileRecord::GetParentRef() const
{
	CAttr_FileName* fn = (CAttr_FileName*)AttrList[ATTR_INDEX(ATTR_TYPE_FILE_NAME)].FindFirstEntry();
	return fn ? fn->GetParentRef() : 0;
}

// Get File Times
void CFileRecord::GetFileTime(FILETIME* writeTm, FILETIME* createTm, FILETIME* accessTm) const
{
	// Standard Information attribute hold the most updated file time
	CAttr_StdInfo* si = (CAttr_StdInfo*)AttrList[ATTR_INDEX(ATTR_TYPE_STANDARD_INFORMATION)].FindFirstEntry();
	if (si)
		si->GetFileTime(writeTm, createTm, accessTm);
	else
	{
		writeTm->dwHighDateTime = 0;
		writeTm->dwLowDateTime = 0;
		if (createTm)
		{
			createTm->dwHighDateTime = 0;
			createTm->dwLowDateTime = 0;
		}
		if (accessTm)
		{
			accessTm->dwHighDateTime = 0;
			accessTm->dwLowDateTime = 0;
		}
	}
}

// Get File Create Times
void CFileRecord::GetFileCreateTime(FILETIME* createTm) const
{
	// Standard Information attribute hold the most updated file time
	CAttr_StdInfo* si = (CAttr_StdInfo*)AttrList[ATTR_INDEX(ATTR_TYPE_STANDARD_INFORMATION)].FindFirstEntry();
	if (si)
		si->GetFileCreateTime(createTm);
	else
	{
		CAttr_StdInfo* si = (CAttr_StdInfo*)AttrList[ATTR_INDEX(ATTR_TYPE_FILE_NAME)].FindFirstEntry();
		si->GetFileFileCreateTime(createTm);
		//createTm->dwHighDateTime = 0;
		//createTm->dwLowDateTime = 0;
	}
}

// Get File Write Times
void CFileRecord::GetFileWriteTime(FILETIME* writeTm) const
{
	// Standard Information attribute hold the most updated file time
	CAttr_StdInfo* si = (CAttr_StdInfo*)AttrList[ATTR_INDEX(ATTR_TYPE_STANDARD_INFORMATION)].FindFirstEntry();
	if (si)
		si->GetFileWriteTime(writeTm);
	else
	{
		CAttr_StdInfo* si = (CAttr_StdInfo*)AttrList[ATTR_INDEX(ATTR_TYPE_FILE_NAME)].FindFirstEntry();
		si->GetFileFileWriteTime(writeTm);
		//writeTm->dwHighDateTime = 0;
		//writeTm->dwLowDateTime = 0;
	}
}

// Get File Access Times
void CFileRecord::GetFileAccessTime(FILETIME* accessTm) const
{
	// Standard Information attribute hold the most updated file time
	CAttr_StdInfo* si = (CAttr_StdInfo*)AttrList[ATTR_INDEX(ATTR_TYPE_STANDARD_INFORMATION)].FindFirstEntry();
	if (si)
		si->GetFileAccessTime(accessTm);
	else
	{
		CAttr_StdInfo* si = (CAttr_StdInfo*)AttrList[ATTR_INDEX(ATTR_TYPE_FILE_NAME)].FindFirstEntry();
		si->GetFileFileAccessTime(accessTm);
		//accessTm->dwHighDateTime = 0;
		//accessTm->dwLowDateTime = 0;
	}
}

void CFileRecord::GetEntryModifiedTime(FILETIME* entrymodTm) const
{
	// Standard Information attribute hold the most updated file time
	CAttr_StdInfo* si = (CAttr_StdInfo*)AttrList[ATTR_INDEX(ATTR_TYPE_STANDARD_INFORMATION)].FindFirstEntry();
	if (si)
		si->GetEntryModifiedTime(entrymodTm);
	else
	{
		CAttr_StdInfo* si = (CAttr_StdInfo*)AttrList[ATTR_INDEX(ATTR_TYPE_FILE_NAME)].FindFirstEntry();
		si->GetFileEntryModifiedTime(entrymodTm);
		//entrymodTm->dwHighDateTime = 0;
		//entrymodTm->dwLowDateTime = 0;
	}
}

// Traverse all sub directories and files contained
// Call user defined callback routine once found an entry
void CFileRecord::TraverseSubEntries(SUBENTRY_CALLBACK seCallBack) const
{
	_ASSERT(seCallBack);

	// Start traversing from IndexRoot (B+ tree root node)

	CAttr_IndexRoot* ir = (CAttr_IndexRoot*)FindFirstAttr(ATTR_TYPE_INDEX_ROOT);
	if (ir == NULL || !ir->IsFileName())
		return;

	CIndexEntryList* ieList = (CIndexEntryList*)ir;
	CIndexEntry* ie = ieList->FindFirstEntry();
	while (ie)
	{
		// Visit subnode first
		if (ie->IsSubNodePtr())
			TraverseSubNode(ie->GetSubNodeVCN(), seCallBack);

		if (ie->HasName())
			seCallBack(ie);

		ie = ieList->FindNextEntry();
	}
}

// Find a specific FileName from InexRoot described B+ tree
const BOOL CFileRecord::FindSubEntry(const _TCHAR* fileName, CIndexEntry& ieFound) const
{
	// Start searching from IndexRoot (B+ tree root node)
	CAttr_IndexRoot* ir = (CAttr_IndexRoot*)FindFirstAttr(ATTR_TYPE_INDEX_ROOT);
	if (ir == NULL || !ir->IsFileName())
		return FALSE;

	CIndexEntryList* ieList = (CIndexEntryList*)ir;
	CIndexEntry* ie = ieList->FindFirstEntry();
	while (ie)
	{
		if (ie->HasName())
		{
			// Compare name
			int i = ie->Compare(fileName);
			if (i == 0)
			{
				ieFound = *ie;
				return TRUE;
			}
			else if (i < 0)		// fileName is smaller than IndexEntry
			{
				// Visit SubNode
				if (ie->IsSubNodePtr())
				{
					// Search in SubNode (IndexBlock)
					if (VisitIndexBlock(ie->GetSubNodeVCN(), fileName, ieFound))
						return TRUE;
				}
				else
					return FALSE;	// not found
			}
			// Just step forward if fileName is bigger than IndexEntry
		}
		else if (ie->IsSubNodePtr())
		{
			// Search in SubNode (IndexBlock)
			if (VisitIndexBlock(ie->GetSubNodeVCN(), fileName, ieFound))
				return TRUE;
		}

		ie = ieList->FindNextEntry();
	}

	return FALSE;
}

// Find Data attribute class of 
const CAttrBase* CFileRecord::FindStream(_TCHAR* name)
{
	const CAttrBase* data = FindFirstAttr(ATTR_TYPE_DATA);
	while (data)
	{
		if (data->IsUnNamed() && name == NULL)	// Unnamed stream
			break;
		if ((!data->IsUnNamed()) && name)	// Named stream
		{
			_TCHAR an[MAX_PATH];
			if (data->GetAttrName(an, MAX_PATH))
			{
				if (_tcscmp(an, name) == 0)
					break;
			}
		}

		data = FindNextAttr(ATTR_TYPE_DATA);
	}

	return data;
}

// 11202012 Debug add ->
const CAttrBase* CFileRecord::FindRecoveryStream(_TCHAR* name)
{
	//AfxMessageBox(L"FindRecoveryStream");
	const CAttrBase* data = FindRecoveryFirstAttr(ATTR_TYPE_DATA);
	while (data)
	{

		if (data->IsUnNamed() && name == NULL)
		{
			// Unnamed stream
			//AfxMessageBox(L"CFileRecord::FindRecoveryStream line 817 break");
			break;
		}
		if ((!data->IsUnNamed()) && name)	// Named stream
		{
			_TCHAR an[MAX_PATH];
			if (data->GetAttrName(an, MAX_PATH))
			{
				if (_tcscmp(an, name) == 0)
				{
					wprintf(L"CFileRecord::FindRecoveryStream line 827 break");
					break;
				}
			}
		}

		data = FindNextAttr(ATTR_TYPE_DATA);
	}

	return data;
}


// 11202012 Debug add <-

// Check if it's deleted or in use
BOOL CFileRecord::IsDeleted() const
{
	return !(FileRecord->Flags & FILE_RECORD_FLAG_INUSE);
}

// Check if it's a directory
BOOL CFileRecord::IsDirectory() const
{
	return FileRecord->Flags & FILE_RECORD_FLAG_DIR;
}

BOOL CFileRecord::IsReadOnly() const
{
	// Standard Information attribute holds the most updated file time
	const CAttr_StdInfo* si = (CAttr_StdInfo*)AttrList[ATTR_INDEX(ATTR_TYPE_STANDARD_INFORMATION)].FindFirstEntry();
	return si ? si->IsReadOnly() : FALSE;
}

BOOL CFileRecord::IsHidden() const
{
	const CAttr_StdInfo* si = (CAttr_StdInfo*)AttrList[ATTR_INDEX(ATTR_TYPE_STANDARD_INFORMATION)].FindFirstEntry();
	return si ? si->IsHidden() : FALSE;
}

BOOL CFileRecord::IsSystem() const
{
	const CAttr_StdInfo* si = (CAttr_StdInfo*)AttrList[ATTR_INDEX(ATTR_TYPE_STANDARD_INFORMATION)].FindFirstEntry();
	return si ? si->IsSystem() : FALSE;
}

BOOL CFileRecord::IsCompressed() const
{
	const CAttr_StdInfo* si = (CAttr_StdInfo*)AttrList[ATTR_INDEX(ATTR_TYPE_STANDARD_INFORMATION)].FindFirstEntry();
	return si ? si->IsCompressed() : FALSE;
}

BOOL CFileRecord::IsEncrypted() const
{
	const CAttr_StdInfo* si = (CAttr_StdInfo*)AttrList[ATTR_INDEX(ATTR_TYPE_STANDARD_INFORMATION)].FindFirstEntry();
	return si ? si->IsEncrypted() : FALSE;
}

BOOL CFileRecord::IsSparse() const
{
	const CAttr_StdInfo* si = (CAttr_StdInfo*)AttrList[ATTR_INDEX(ATTR_TYPE_STANDARD_INFORMATION)].FindFirstEntry();
	return si ? si->IsSparse() : FALSE;
}


///////////////////////////////////////
// NTFS Volume Implementation
///////////////////////////////////////
CNTFSVolume::CNTFSVolume(_TCHAR volume)
{
	printf("init NTFS\n");
	hVolume = INVALID_HANDLE_VALUE;
	VolumeOK = FALSE;
	MFTRecord = NULL;
	MFTData = NULL;
	Version = 0;
	ClearAttrRawCB();

	if (!OpenVolume(volume)) {
		printf("OpenVolume failed\n");
		return;
	}


	// Verify NTFS volume version (must >= 3.0)

	CFileRecord vol(this);
	vol.SetAttrMask(MASK_VOLUME_NAME | MASK_VOLUME_INFORMATION);
	if (!vol.ParseFileRecord(MFT_IDX_VOLUME)) {
		printf("ParseFileRecord failed\n");
		return;
	}
		
	vol.ParseAttrs();
	CAttr_VolInfo* vi = (CAttr_VolInfo*)vol.FindFirstAttr(ATTR_TYPE_VOLUME_INFORMATION);
	if (!vi) {
		printf("FindFirstAttr failed\n");
		return;
	}
		

	Version = vi->GetVersion();
	printf("NTFS volume version: %u.%u\n", HIBYTE(Version), LOBYTE(Version));
	NTFS_TRACE2("NTFS volume version: %u.%u\n", HIBYTE(Version), LOBYTE(Version));
	if (Version < 0x0300)	// NT4 ?
		return;

#ifdef	_DEBUG
	CAttr_VolName* vn = (CAttr_VolName*)vol.FindFirstAttr(ATTR_TYPE_VOLUME_NAME);
	if (vn)
	{
		char volname[MAX_PATH];
		if (vn->GetName(volname, MAX_PATH) > 0)
		{
			NTFS_TRACE1("NTFS volume name: %s\n", volname);
		}
	}
#endif

	VolumeOK = TRUE;

	MFTRecord = new CFileRecord(this);
	MFTRecord->SetAttrMask(MASK_DATA);
	if (MFTRecord->ParseFileRecord(MFT_IDX_MFT))
	{
		MFTRecord->ParseAttrs();
		MFTData = MFTRecord->FindFirstAttr(ATTR_TYPE_DATA);
		if (MFTData == NULL)
		{
			delete MFTRecord;
			MFTRecord = NULL;
		}
	}
}

CNTFSVolume::~CNTFSVolume()
{
	if (hVolume != INVALID_HANDLE_VALUE)
		CloseHandle(hVolume);

	if (MFTRecord)
		delete MFTRecord;
}

// Open a volume ('a' - 'z', 'A' - 'Z'), get volume handle and BPB
BOOL CNTFSVolume::OpenVolume(_TCHAR volume)
{
	// Verify parameter
	if (!_istalpha(volume))
	{
		//NTFS_TRACE("Volume name error, should be like 'C', 'D'\n");
		printf("Volume name error, should be like 'C', 'D'\n");
		return FALSE;
	}

	_TCHAR volumePath[7];
	_sntprintf_s(volumePath, 6, _T("\\\\.\\%c:"), volume);
	volumePath[6] = _T('\0');


	hVolume = CreateFile(volumePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL);

	if (hVolume != INVALID_HANDLE_VALUE)
	{
		DWORD num;
		NTFS_BPB bpb;

		// Read the first sector (boot sector)
		if (ReadFile(hVolume, &bpb, 512, &num, NULL) && num == 512)
		{
			if (strncmp((const char*)bpb.Signature, NTFS_SIGNATURE, 8) == 0)
			{
				// Log important volume parameters

				SectorSize = bpb.BytesPerSector;
				NTFS_TRACE1("Sector Size = %u bytes\n", SectorSize);
				printf("Sector Size = %u bytes\n", SectorSize);

				ClusterSize = SectorSize * bpb.SectorsPerCluster;
				NTFS_TRACE1("Cluster Size = %u bytes\n", ClusterSize);

				int sz = (char)bpb.ClustersPerFileRecord;
				if (sz > 0)
					FileRecordSize = ClusterSize * sz;
				else
					FileRecordSize = 1 << (-sz);
				//NTFS_TRACE1("FileRecord Size = %u bytes\n", FileRecordSize);
				printf("FileRecord Size = %u bytes\n", FileRecordSize);

				sz = (char)bpb.ClustersPerIndexBlock;
				if (sz > 0)
					IndexBlockSize = ClusterSize * sz;
				else
					IndexBlockSize = 1 << (-sz);
				//NTFS_TRACE1("IndexBlock Size = %u bytes\n", IndexBlockSize);
				printf("IndexBlock Size = %u bytes\n", IndexBlockSize);

				MFTAddr = bpb.LCN_MFT * ClusterSize;
				NTFS_TRACE1("MFT address = 0x%016I64X\n", MFTAddr);
			}
			else
			{
				//NTFS_TRACE("Volume file system is not NTFS\n");
				printf("Volume file system is not NTFS\n");
				goto IOError;
			}
		}
		else
		{
			//NTFS_TRACE("Read boot sector error\n");
			printf("Read boot sector error\n");
			goto IOError;
		}
	}
	else
	{
		//NTFS_TRACE1("Cannnot open volume %c\n", (char)volume);
		printf("Cannnot open volume %c\n", (char)volume);
	IOError:
		if (hVolume != INVALID_HANDLE_VALUE)
		{
			CloseHandle(hVolume);
			hVolume = INVALID_HANDLE_VALUE;
		}
		return FALSE;
	}

	//if (hVolume != INVALID_HANDLE_VALUE)
	//{
	//	DWORD num;
	//	NTFS_BPB bpb;

	//	// Read the first sector (boot sector)
	//	if (ReadFile(hVolume, &bpb, 512, &num, NULL) && num == 512)
	//	{
	//		if (strncmp((const char*)bpb.Signature, NTFS_SIGNATURE, 8) == 0)
	//		{
	//			// Log important volume parameters

	//			SectorSize = bpb.BytesPerSector;
	//			//NTFS_TRACE1("Sector Size = %u bytes\n", SectorSize);
	//			printf("Sector Size = %u bytes\n", SectorSize);

	//			ClusterSize = SectorSize * bpb.SectorsPerCluster;
	//			NTFS_TRACE1("Cluster Size = %u bytes\n", ClusterSize);

	//			int sz = (char)bpb.ClustersPerFileRecord;
	//			if (sz > 0)
	//				FileRecordSize = ClusterSize * sz;
	//			else
	//				FileRecordSize = 1 << (-sz);
	//			NTFS_TRACE1("FileRecord Size = %u bytes\n", FileRecordSize);

	//			sz = (char)bpb.ClustersPerIndexBlock;
	//			if (sz > 0)
	//				IndexBlockSize = ClusterSize * sz;
	//			else
	//				IndexBlockSize = 1 << (-sz);
	//			NTFS_TRACE1("IndexBlock Size = %u bytes\n", IndexBlockSize);

	//			MFTAddr = bpb.LCN_MFT * ClusterSize;
	//			NTFS_TRACE1("MFT address = 0x%016I64X\n", MFTAddr);
	//		}
	//		else
	//		{
	//			NTFS_TRACE("Volume file system is not NTFS\n");
	//			goto IOError;
	//		}
	//	}
	//	else
	//	{
	//		NTFS_TRACE("Read boot sector error\n");
	//		goto IOError;
	//	}
	//}
	//else
	//{
	//	NTFS_TRACE1("Cannnot open volume %c\n", (char)volume);
	//	printf("Cannnot open volume %c\n", (char)volume);
	//IOError:
	//	if (hVolume != INVALID_HANDLE_VALUE)
	//	{
	//		CloseHandle(hVolume);
	//		hVolume = INVALID_HANDLE_VALUE;
	//	}
	//	return FALSE;
	//}

	return TRUE;
}

// Check if Volume is successfully opened
BOOL CNTFSVolume::IsVolumeOK() const
{
	return VolumeOK;
}

// Get NTFS volume version
WORD CNTFSVolume::GetVersion() const
{
	return Version;
}

// Get File Record count
ULONGLONG CNTFSVolume::GetRecordsCount() const
{
	return (MFTData->GetDataSize() / FileRecordSize);
}

// Get BPB information

DWORD CNTFSVolume::GetSectorSize() const
{
	return SectorSize;
}

DWORD CNTFSVolume::GetClusterSize() const
{
	return ClusterSize;
}

DWORD CNTFSVolume::GetFileRecordSize() const
{
	return FileRecordSize;
}

DWORD CNTFSVolume::GetIndexBlockSize() const
{
	return IndexBlockSize;
}

// Get MFT starting address
ULONGLONG CNTFSVolume::GetMFTAddr() const
{
	return MFTAddr;
}

// Install Attribute CallBack routines for the whole Volume
BOOL CNTFSVolume::InstallAttrRawCB(DWORD attrType, ATTR_RAW_CALLBACK cb)
{
	DWORD atIdx = ATTR_INDEX(attrType);
	if (atIdx < ATTR_NUMS)
	{
		AttrRawCallBack[atIdx] = cb;
		return TRUE;
	}
	else
		return FALSE;
}

// Clear all Attribute CallBack routines
void CNTFSVolume::ClearAttrRawCB()
{
	for (int i = 0; i < ATTR_NUMS; i++)
		AttrRawCallBack[i] = NULL;
}




// add 

CAttrBase::CAttrBase(const ATTR_HEADER_COMMON* ahc, const CFileRecord* fr)
{
	_ASSERT(ahc);
	_ASSERT(fr);

	AttrHeader = ahc;
	FileRecord = fr;


	_SectorSize = fr->Volume->SectorSize;
	_ClusterSize = fr->Volume->ClusterSize;
	_IndexBlockSize = fr->Volume->IndexBlockSize;
	_hVolume = fr->Volume->hVolume;
}

//CAttrBase::CAttrBase(const ATTR_HEADER_COMMON* ahc)
//{
//	_ASSERT(ahc);
//	_ASSERT(fr);
//
//	AttrHeader = ahc;
//	FileRecord = fr;
//
//
//	_SectorSize = fr->Volume->SectorSize;
//	_ClusterSize = fr->Volume->ClusterSize;
//	_IndexBlockSize = fr->Volume->IndexBlockSize;
//	_hVolume = fr->Volume->hVolume;
//}

CAttrBase::~CAttrBase()
{
}

const ATTR_HEADER_COMMON* CAttrBase::GetAttrHeader() const
{
	return AttrHeader;
}

DWORD CAttrBase::GetAttrType() const
{
	return AttrHeader->Type;
}

DWORD CAttrBase::GetAttrTotalSize() const
{
	return AttrHeader->TotalSize;
}

BOOL CAttrBase::IsNonResident() const
{
	return AttrHeader->NonResident;
}

WORD CAttrBase::GetAttrFlags() const
{
	return AttrHeader->Flags;
}

// Get ANSI Attribute name
// Return 0: Unnamed, <0: buffer too small, -buffersize, >0 Name length
int CAttrBase::GetAttrName(char* buf, DWORD bufLen) const
{
	if (AttrHeader->NameLength)
	{
		if (bufLen < AttrHeader->NameLength)
			return -1 * AttrHeader->NameLength;	// buffer too small

		wchar_t* namePtr = (wchar_t*)((BYTE*)AttrHeader + AttrHeader->NameOffset);
		int len = WideCharToMultiByte(CP_ACP, 0, namePtr, AttrHeader->NameLength,
			buf, bufLen, NULL, NULL);
		if (len)
		{
			buf[len] = '\0';
			NTFS_TRACE1("Attribute name: %s\n", buf);
			return len;
		}
		else
		{
			NTFS_TRACE("Unrecognized attribute name or Name buffer too small\n");
			return -1 * AttrHeader->NameLength;
		}
	}
	else
	{
		NTFS_TRACE("Attribute is unnamed\n");
		return 0;
	}
}

// Get UNICODE Attribute name
// Return 0: Unnamed, <0: buffer too small, -buffersize, >0 Name length
int CAttrBase::GetAttrName(wchar_t* buf, DWORD bufLen) const
{
	if (AttrHeader->NameLength)
	{
		if (bufLen < AttrHeader->NameLength)
			return -1 * AttrHeader->NameLength;	// buffer too small

		bufLen = AttrHeader->NameLength;
		wchar_t* namePtr = (wchar_t*)((BYTE*)AttrHeader + AttrHeader->NameOffset);
		wcsncpy_s(buf, bufLen + 1, namePtr, bufLen);
		buf[bufLen] = '\0\0';

		NTFS_TRACE("Unicode Attribute Name\n");
		return bufLen;
	}
	else
	{
		NTFS_TRACE("Attribute is unnamed\n");
		return 0;
	}
}

// Verify if this attribute is unnamed
// Useful in analyzing MultiStream files
BOOL CAttrBase::IsUnNamed() const
{
	return (AttrHeader->NameLength == 0);
}



CAttrResident::CAttrResident(const ATTR_HEADER_COMMON* ahc, const CFileRecord* fr) : CAttrBase(ahc, fr)
{
	AttrHeaderR = (ATTR_HEADER_RESIDENT*)ahc;
	AttrBody = (void*)((BYTE*)AttrHeaderR + AttrHeaderR->AttrOffset);
	AttrBodySize = AttrHeaderR->AttrSize;
}

CAttrResident::~CAttrResident()
{
}

BOOL CAttrResident::IsDataRunOK() const
{
	return TRUE;	// Always OK for a resident attribute
}

// Return Actural Data Size
// *allocSize = Allocated Size
ULONGLONG CAttrResident::GetDataSize(ULONGLONG* allocSize) const
{
	if (allocSize)
		*allocSize = AttrBodySize;

	return (ULONGLONG)AttrBodySize;
}

//0709-2013 ->
ULONGLONG CAttrResident::GetAllocSize(ULONGLONG* allocSize) const
{
	if (allocSize)
		*allocSize = AttrBodySize;

	return (ULONGLONG)AttrBodySize;
}
//0709-2013<-
ULONGLONG CAttrResident::GetComSize(ULONGLONG* allocSize) const
{
	if (allocSize)
		*allocSize = AttrBodySize;

	return (ULONGLONG)AttrBodySize;
}
DWORD CAttrResident::GetClusterSize() const
{
	return _ClusterSize;
}
//0715-2013
// Read "bufLen" bytes from "offset" into "bufv"
// Number of bytes acturally read is returned in "*actural"
BOOL CAttrResident::ReadData(const ULONGLONG& offset, void* bufv, DWORD bufLen, DWORD* actural) const
{
	_ASSERT(bufv);

	*actural = 0;
	if (bufLen == 0)
		return TRUE;

	DWORD offsetd = (DWORD)offset;
	if (offsetd >= AttrBodySize)
	{
		//AfxMessageBox(L"CAttrResident::ReadData");
		return FALSE;	// offset parameter error
	}

	if ((offsetd + bufLen) > AttrBodySize)
		*actural = AttrBodySize - offsetd;	// Beyond scope
	else
		*actural = bufLen;

	memcpy(bufv, (BYTE*)AttrBody + offsetd, *actural);

	return TRUE;
}

//0709-2013 ->
BOOL CAttrResident::ReadCompressedData(const ULONGLONG& offset, void* bufv, DWORD bufLen, DWORD* actural) const
{
	_ASSERT(bufv);

	*actural = 0;
	if (bufLen == 0)
		return TRUE;

	DWORD offsetd = (DWORD)offset;
	if (offsetd >= AttrBodySize)
	{
		//AfxMessageBox(L"CAttrResident::ReadData");
		return FALSE;	// offset parameter error
	}

	if ((offsetd + bufLen) > AttrBodySize)
		*actural = AttrBodySize - offsetd;	// Beyond scope
	else
		*actural = bufLen;

	memcpy(bufv, (BYTE*)AttrBody + offsetd, *actural);

	return TRUE;
}
//0709-2013 <-
BOOL CAttrResident::ReadIniSizeData(const ULONGLONG& offset, void* bufv, DWORD bufLen, DWORD* actural) const
{
	_ASSERT(bufv);

	*actural = 0;
	if (bufLen == 0)
		return TRUE;

	DWORD offsetd = (DWORD)offset;
	if (offsetd >= AttrBodySize)
	{
		//AfxMessageBox(L"CAttrResident::ReadData");
		return FALSE;	// offset parameter error
	}

	if ((offsetd + bufLen) > AttrBodySize)
		*actural = AttrBodySize - offsetd;	// Beyond scope
	else
		*actural = bufLen;

	memcpy(bufv, (BYTE*)AttrBody + offsetd, *actural);

	return TRUE;
}
//0715-2013
// 20121212 ->
BOOL CAttrResident::ReadRecoveryData(const ULONGLONG& offset, void* bufv, DWORD bufLen, DWORD* actural, ULONGLONG RealSize) const
{
	_ASSERT(bufv);

	*actural = 0;
	if (bufLen == 0)
		return TRUE;

	DWORD offsetd = (DWORD)offset;
	if (offsetd >= AttrBodySize)
	{
		//AfxMessageBox(L"CAttrResident::ReadData");
		return FALSE;	// offset parameter error
	}

	if ((offsetd + bufLen) > AttrBodySize)
		*actural = AttrBodySize - offsetd;	// Beyond scope
	else
		*actural = bufLen;

	memcpy(bufv, (BYTE*)AttrBody + offsetd, *actural);

	return TRUE;
}

BOOL CAttrResident::GetVCNSize() const
{
	return 0;
}
BOOL CAttrResident::CheckCompressed(/*ULONGLONG fileid*/) const
{
	//CString st;
	//st.Format(L"ID:%I64u Resident CheckCompressed", fileid);
	//AfxMessageBox(st);
	return 0;
}
// 20121212 <-
BOOL CAttrResident::CompressedLessReal(ULONGLONG fileid) const
{
	return 0;
}




CAttrNonResident::CAttrNonResident(const ATTR_HEADER_COMMON* ahc, const CFileRecord* fr) : CAttrBase(ahc, fr)
{
	AttrHeaderNR = (ATTR_HEADER_NON_RESIDENT*)ahc;

	UnalignedBuf = new BYTE[_ClusterSize];

	bDataRunOK = ParseDataRun();
}

CAttrNonResident::~CAttrNonResident()
{
	delete UnalignedBuf;

	DataRunList.RemoveAll();
}

// Parse a single DataRun unit
BOOL CAttrNonResident::PickData(const BYTE** dataRun, LONGLONG* length, LONGLONG* LCNOffset)
{
	BYTE size = **dataRun;
	(*dataRun)++;
	int lengthBytes = size & 0x0F;
	int offsetBytes = size >> 4;

	if (lengthBytes > 8 || offsetBytes > 8)
	{
		NTFS_TRACE1("DataRun decode error 1: 0x%02X\n", size);
		return FALSE;
	}

	*length = 0;
	memcpy(length, *dataRun, lengthBytes);
	if (*length < 0)
	{
		NTFS_TRACE1("DataRun length error: %I64d\n", *length);
		return FALSE;
	}

	(*dataRun) += lengthBytes;
	*LCNOffset = 0;
	if (offsetBytes)	// Not Sparse File
	{
		if ((*dataRun)[offsetBytes - 1] & 0x80)
			*LCNOffset = -1;
		memcpy(LCNOffset, *dataRun, offsetBytes);

		(*dataRun) += offsetBytes;
	}

	return TRUE;
}

// Travers DataRun and insert into a link list
BOOL CAttrNonResident::ParseDataRun()
{
	NTFS_TRACE("Parsing Non Resident DataRun\n");
	NTFS_TRACE2("Start VCN = %I64u, End VCN = %I64u\n",
		AttrHeaderNR->StartVCN, AttrHeaderNR->LastVCN);

	const BYTE* dataRun = (BYTE*)AttrHeaderNR + AttrHeaderNR->DataRunOffset;
	LONGLONG length;
	LONGLONG LCNOffset;
	LONGLONG LCN = 0;
	ULONGLONG VCN = 0;

	while (*dataRun)
	{
		if (PickData(&dataRun, &length, &LCNOffset))
		{
			LCN += LCNOffset;
			if (LCN < 0)
			{
				NTFS_TRACE("DataRun decode error 2\n");
				return FALSE;
			}

			NTFS_TRACE2("Data length = %I64d clusters, LCN = %I64d", length, LCN);
			NTFS_TRACE(LCNOffset == 0 ? ", Sparse Data\n" : "\n");

			// Store LCN, Data size (clusters) into list
			DataRun_Entry* dr = new DataRun_Entry;
			dr->LCN = (LCNOffset == 0) ? -1 : LCN;
			dr->Clusters = length;
			dr->StartVCN = VCN;
			VCN += length;
			dr->LastVCN = VCN - 1;

			if (dr->LastVCN <= (AttrHeaderNR->LastVCN - AttrHeaderNR->StartVCN))
			{
				DataRunList.InsertEntry(dr);
			}
			else
			{
				NTFS_TRACE("DataRun decode error: VCN exceeds bound\n");

				// Remove entries
				DataRunList.RemoveAll();

				return FALSE;
			}
		}
		else
			break;
	}

	return TRUE;
}

// Read clusters from disk, or sparse data
// *actural = Clusters acturally read
BOOL CAttrNonResident::ReadClusters(void* buf, DWORD clusters, LONGLONG lcn)
{
	if (lcn == -1)	// sparse data
	{
		//AfxMessageBox(L"Sparse Data, Fill the buffer with 0");

		// Fill the buffer with 0
		memset(buf, 0, clusters * _ClusterSize);

		return TRUE;
	}

	LARGE_INTEGER addr;
	DWORD len;

	addr.QuadPart = lcn * _ClusterSize;
	len = SetFilePointer(_hVolume, addr.LowPart, &addr.HighPart, FILE_BEGIN);

	if (len == (DWORD)-1 && GetLastError() != NO_ERROR)
	{
		//CString st;
		wprintf(L"Cannot locate cluster with LCN %I64d", lcn);
		//AfxMessageBox(st);
	}
	else
	{
		if (ReadFile(_hVolume, buf, clusters * _ClusterSize, &len, NULL) &&
			len == clusters * _ClusterSize)
		{
			NTFS_TRACE2("Successfully read %u clusters from LCN %I64d\n", clusters, lcn);
			return TRUE;
		}
		else
		{
			//NTFS_TRACE1("Cannot read cluster with LCN %I64d\n", lcn);
			//CString st;
			//st.Format(L"Cannot read cluster with LCN %I64d", lcn);
			wprintf(L"Please check the disk connection");
			//AfxMessageBox(st);
		}
	}

	return FALSE;
}

// Read Data, cluster based
// clusterNo: Begnning cluster Number
// clusters: Clusters to read
// bufv, bufLen: Returned data
// *actural = Number of bytes acturally read
BOOL CAttrNonResident::ReadVirtualClusters(ULONGLONG vcn, DWORD clusters,
	void* bufv, DWORD bufLen, DWORD* actural)
{
	_ASSERT(bufv);
	_ASSERT(clusters);

	*actural = 0;
	BYTE* buf = (BYTE*)bufv;

	// Verify if clusters exceeds DataRun bounds

	if (vcn + clusters > (AttrHeaderNR->LastVCN - AttrHeaderNR->StartVCN + 1))
	{
		//CString st;
		//st.Format(L"vcn:%d<=>cluster:%d<=>LastVCN:%d<=>StartVCN:%d",vcn, clusters, AttrHeaderNR->LastVCN, AttrHeaderNR->StartVCN);
		//AfxMessageBox(st);
		//AfxMessageBox(L"CAttrNonResident::ReadVirtualClusters-Cluster exceeds DataRun bounds");
		NTFS_TRACE("Cluster exceeds DataRun bounds\n");
		return FALSE;
	}


	// Verify buffer size
	if (bufLen < clusters * _ClusterSize)
	{
		//AfxMessageBox(L"CAttrNonResident::ReadVirtualClusters-Buffer size too small");
		NTFS_TRACE("Buffer size too small\n");
		return FALSE;
	}

	// Traverse the DataRun List to find the according LCN
	const DataRun_Entry* dr = DataRunList.FindFirstEntry();
	while (dr)
	{
		if (vcn >= dr->StartVCN && vcn <= dr->LastVCN)
		{
			DWORD clustersToRead;

			ULONGLONG vcns = dr->LastVCN - vcn + 1;	// Clusters from read pointer to the end

			if ((ULONGLONG)clusters > vcns)	// Fragmented data, we must go on
				clustersToRead = (DWORD)vcns;
			else
				clustersToRead = clusters;
			if (ReadClusters(buf, clustersToRead, dr->LCN + (vcn - dr->StartVCN)))
			{
				buf += clustersToRead * _ClusterSize;
				clusters -= clustersToRead;
				*actural += clustersToRead;
				vcn += clustersToRead;
			}
			else
				break;

			if (clusters == 0)
				break;
		}

		dr = DataRunList.FindNextEntry();
	}

	*actural *= _ClusterSize;
	return TRUE;
}

// Judge if the DataRun is successfully parsed
BOOL CAttrNonResident::IsDataRunOK() const
{
	return bDataRunOK;
}

// Return Actural Data Size
// *allocSize = Allocated Size
ULONGLONG CAttrNonResident::GetDataSize(ULONGLONG* allocSize) const
{
	if (allocSize)
		*allocSize = AttrHeaderNR->AllocSize;

	return AttrHeaderNR->RealSize;
	//return AttrHeaderNR->IniSize;
}

//0709-2013 ->
ULONGLONG CAttrNonResident::GetAllocSize(ULONGLONG* allocSize) const
{
	if (allocSize)
		*allocSize = AttrHeaderNR->AllocSize;

	return AttrHeaderNR->AllocSize;
}
//0709-2013 <-
ULONGLONG CAttrNonResident::GetComSize(ULONGLONG* allocSize) const
{
	if (allocSize)
		*allocSize = AttrHeaderNR->AllocSize;

	return AttrHeaderNR->IniSize;
}
DWORD CAttrNonResident::GetClusterSize() const
{
	return _ClusterSize;
}
//0715-2013
// Read "bufLen" bytes from "offset" into "bufv"
// Number of bytes acturally read is returned in "*actural"
BOOL CAttrNonResident::ReadData(const ULONGLONG& offset, void* bufv, DWORD bufLen, DWORD* actural) const
{
	// Hard disks can only be accessed by sectors
	// To be simple and efficient, only implemented cluster based accessing
	// So cluster unaligned data address should be processed carefully here

	_ASSERT(bufv);

	*actural = 0;
	if (bufLen == 0)
		return TRUE;

	// Bounds check
	if (offset > AttrHeaderNR->RealSize)
	{
		//AfxMessageBox(L"CAttrNonResident::ReadData-offset > AttrHeaderNR");
		return FALSE;
	}
	if ((offset + bufLen) > AttrHeaderNR->RealSize)
		bufLen = (DWORD)(AttrHeaderNR->RealSize - offset);

	DWORD len;
	BYTE* buf = (BYTE*)bufv;

	// First cluster Number
	ULONGLONG startVCN = offset / _ClusterSize;
	// Bytes in first cluster
	DWORD startBytes = _ClusterSize - (DWORD)(offset % _ClusterSize);
	// Read first cluster
	if (startBytes != _ClusterSize)
	{
		// First cluster, Unaligned
		if (((CAttrNonResident*)this)->ReadVirtualClusters(startVCN, 1, UnalignedBuf, _ClusterSize, &len)
			&& len == _ClusterSize)
		{
			len = (startBytes < bufLen) ? startBytes : bufLen;
			memcpy(buf, UnalignedBuf + _ClusterSize - startBytes, len);
			buf += len;
			bufLen -= len;
			*actural += len;
			startVCN++;
		}
		else
		{
			//AfxMessageBox(L"CAttrNonResident::ReadData-ReadVirtualClusters");
			return FALSE;
		}
	}
	if (bufLen == 0)
		return TRUE;

	DWORD alignedClusters = bufLen / _ClusterSize;
	if (alignedClusters)
	{
		//AfxMessageBox(L"CAttrNonResident::ReadData-ReadVirtualClusters-Aligned clusters");
				// Aligned clusters
		DWORD alignedSize = alignedClusters * _ClusterSize;
		if (((CAttrNonResident*)this)->ReadVirtualClusters(startVCN, alignedClusters, buf, alignedSize, &len)
			&& len == alignedSize)
		{
			startVCN += alignedClusters;
			buf += alignedSize;
			bufLen %= _ClusterSize;
			*actural += len;

			if (bufLen == 0)
				return TRUE;
		}
		else
		{
			//AfxMessageBox(L"CAttrNonResident::ReadData-alignedClusters");
			return FALSE;
		}
	}

	// Last cluster, Unaligned
	if (((CAttrNonResident*)this)->ReadVirtualClusters(startVCN, 1, UnalignedBuf, _ClusterSize, &len)
		&& len == _ClusterSize)
	{
		memcpy(buf, UnalignedBuf, bufLen);
		*actural += bufLen;

		return TRUE;
	}
	else
	{
		//AfxMessageBox(L"CAttrNonResident::ReadData-Last cluster, Unaligned");
		return FALSE;
	}
}

// 0709-2013 ->
BOOL CAttrNonResident::ReadCompressedData(const ULONGLONG& offset, void* bufv, DWORD bufLen, DWORD* actural) const
{
	// Hard disks can only be accessed by sectors
	// To be simple and efficient, only implemented cluster based accessing
	// So cluster unaligned data address should be processed carefully here

	_ASSERT(bufv);

	*actural = 0;
	if (bufLen == 0)
		return TRUE;

	// Bounds check
	if (offset > AttrHeaderNR->AllocSize)
	{
		//AfxMessageBox(L"CAttrNonResident::ReadData-offset > AttrHeaderNR");
		return FALSE;
	}
	if ((offset + bufLen) > AttrHeaderNR->AllocSize)
		bufLen = (DWORD)(AttrHeaderNR->AllocSize - offset);

	DWORD len;
	BYTE* buf = (BYTE*)bufv;

	// First cluster Number
	ULONGLONG startVCN = offset / _ClusterSize;
	// Bytes in first cluster
	DWORD startBytes = _ClusterSize - (DWORD)(offset % _ClusterSize);
	// Read first cluster
	if (startBytes != _ClusterSize)
	{
		// First cluster, Unaligned
		if (((CAttrNonResident*)this)->ReadVirtualClusters(startVCN, 1, UnalignedBuf, _ClusterSize, &len)
			&& len == _ClusterSize)
		{
			len = (startBytes < bufLen) ? startBytes : bufLen;
			memcpy(buf, UnalignedBuf + _ClusterSize - startBytes, len);
			buf += len;
			bufLen -= len;
			*actural += len;
			startVCN++;
		}
		else
		{
			//AfxMessageBox(L"CAttrNonResident::ReadData-ReadVirtualClusters");
			return FALSE;
		}
	}
	if (bufLen == 0)
		return TRUE;

	DWORD alignedClusters = bufLen / _ClusterSize;
	if (alignedClusters)
	{
		//AfxMessageBox(L"CAttrNonResident::ReadData-ReadVirtualClusters-Aligned clusters");
				// Aligned clusters
		DWORD alignedSize = alignedClusters * _ClusterSize;
		if (((CAttrNonResident*)this)->ReadVirtualClusters(startVCN, alignedClusters, buf, alignedSize, &len)
			&& len == alignedSize)
		{
			startVCN += alignedClusters;
			buf += alignedSize;
			bufLen %= _ClusterSize;
			*actural += len;

			if (bufLen == 0)
				return TRUE;
		}
		else
		{
			//AfxMessageBox(L"CAttrNonResident::ReadData-alignedClusters");
			return FALSE;
		}
	}

	// Last cluster, Unaligned
	if (((CAttrNonResident*)this)->ReadVirtualClusters(startVCN, 1, UnalignedBuf, _ClusterSize, &len)
		&& len == _ClusterSize)
	{
		memcpy(buf, UnalignedBuf, bufLen);
		*actural += bufLen;

		return TRUE;
	}
	else
	{
		//AfxMessageBox(L"CAttrNonResident::ReadData-Last cluster, Unaligned");
		return FALSE;
	}
}


// 0709-2013 <-
BOOL CAttrNonResident::ReadIniSizeData(const ULONGLONG& offset, void* bufv, DWORD bufLen, DWORD* actural) const
{
	// Hard disks can only be accessed by sectors
	// To be simple and efficient, only implemented cluster based accessing
	// So cluster unaligned data address should be processed carefully here

	_ASSERT(bufv);

	*actural = 0;
	if (bufLen == 0)
		return TRUE;

	// Bounds check
	if (offset > AttrHeaderNR->IniSize)
	{
		//AfxMessageBox(L"CAttrNonResident::ReadData-offset > AttrHeaderNR");
		return FALSE;
	}
	if ((offset + bufLen) > AttrHeaderNR->IniSize)
		bufLen = (DWORD)(AttrHeaderNR->IniSize - offset);

	DWORD len;
	BYTE* buf = (BYTE*)bufv;

	// First cluster Number
	ULONGLONG startVCN = offset / _ClusterSize;
	// Bytes in first cluster
	DWORD startBytes = _ClusterSize - (DWORD)(offset % _ClusterSize);
	// Read first cluster
	if (startBytes != _ClusterSize)
	{
		// First cluster, Unaligned
		if (((CAttrNonResident*)this)->ReadVirtualClusters(startVCN, 1, UnalignedBuf, _ClusterSize, &len)
			&& len == _ClusterSize)
		{
			len = (startBytes < bufLen) ? startBytes : bufLen;
			memcpy(buf, UnalignedBuf + _ClusterSize - startBytes, len);
			buf += len;
			bufLen -= len;
			*actural += len;
			startVCN++;
		}
		else
		{
			//AfxMessageBox(L"CAttrNonResident::ReadData-ReadVirtualClusters");
			return FALSE;
		}
	}
	if (bufLen == 0)
		return TRUE;

	DWORD alignedClusters = bufLen / _ClusterSize;
	if (alignedClusters)
	{
		//AfxMessageBox(L"CAttrNonResident::ReadData-ReadVirtualClusters-Aligned clusters");
				// Aligned clusters
		DWORD alignedSize = alignedClusters * _ClusterSize;
		if (((CAttrNonResident*)this)->ReadVirtualClusters(startVCN, alignedClusters, buf, alignedSize, &len)
			&& len == alignedSize)
		{
			startVCN += alignedClusters;
			buf += alignedSize;
			bufLen %= _ClusterSize;
			*actural += len;

			if (bufLen == 0)
				return TRUE;
		}
		else
		{
			//AfxMessageBox(L"CAttrNonResident::ReadData-alignedClusters");
			return FALSE;
		}
	}

	// Last cluster, Unaligned
	if (((CAttrNonResident*)this)->ReadVirtualClusters(startVCN, 1, UnalignedBuf, _ClusterSize, &len)
		&& len == _ClusterSize)
	{
		memcpy(buf, UnalignedBuf, bufLen);
		*actural += bufLen;

		return TRUE;
	}
	else
	{
		//AfxMessageBox(L"CAttrNonResident::ReadData-Last cluster, Unaligned");
		return FALSE;
	}
}
//0715-2013

// 20121212 ->
BOOL CAttrNonResident::ReadRecoveryData(const ULONGLONG& offset, void* bufv, DWORD bufLen, DWORD* actural, ULONGLONG VCNSize) const
{
	// Hard disks can only be accessed by sectors
	// To be simple and efficient, only implemented cluster based accessing
	// So cluster unaligned data address should be processed carefully here

	_ASSERT(bufv);

	*actural = 0;
	if (bufLen == 0)
		return TRUE;

	// Bounds check
	if (offset > VCNSize)
	{
		//AfxMessageBox(L"CAttrNonResident::ReadData-offset > AttrHeaderNR");
		return FALSE;
	}
	if ((offset + bufLen) > VCNSize)
		bufLen = (DWORD)(VCNSize - offset);

	DWORD len;
	BYTE* buf = (BYTE*)bufv;

	// First cluster Number
	ULONGLONG startVCN = offset / _ClusterSize;
	// Bytes in first cluster
	DWORD startBytes = _ClusterSize - (DWORD)(offset % _ClusterSize);
	// Read first cluster
	if (startBytes != _ClusterSize)
	{
		// First cluster, Unaligned
		if (((CAttrNonResident*)this)->ReadVirtualClusters(startVCN, 1, UnalignedBuf, _ClusterSize, &len)
			&& len == _ClusterSize)
		{
			len = (startBytes < bufLen) ? startBytes : bufLen;
			memcpy(buf, UnalignedBuf + _ClusterSize - startBytes, len);
			buf += len;
			bufLen -= len;
			*actural += len;
			startVCN++;
		}
		else
		{
			//AfxMessageBox(L"CAttrNonResident::ReadData-ReadVirtualClusters");
			return FALSE;
		}
	}
	if (bufLen == 0)
		return TRUE;

	DWORD alignedClusters = bufLen / _ClusterSize;
	if (alignedClusters)
	{
		//AfxMessageBox(L"CAttrNonResident::ReadData-ReadVirtualClusters-Aligned clusters");
				// Aligned clusters
		DWORD alignedSize = alignedClusters * _ClusterSize;
		if (((CAttrNonResident*)this)->ReadVirtualClusters(startVCN, alignedClusters, buf, alignedSize, &len)
			&& len == alignedSize)
		{
			startVCN += alignedClusters;
			buf += alignedSize;
			bufLen %= _ClusterSize;
			*actural += len;

			if (bufLen == 0)
				return TRUE;
		}
		else
		{
			//AfxMessageBox(L"CAttrNonResident::ReadData-alignedClusters");
			return FALSE;
		}
	}

	// Last cluster, Unaligned
	if (((CAttrNonResident*)this)->ReadVirtualClusters(startVCN, 1, UnalignedBuf, _ClusterSize, &len)
		&& len == _ClusterSize)
	{
		memcpy(buf, UnalignedBuf, bufLen);
		*actural += bufLen;

		return TRUE;
	}
	else
	{
		//AfxMessageBox(L"CAttrNonResident::ReadData-Last cluster, Unaligned");
		return FALSE;
	}
}

BOOL CAttrNonResident::ReadRecoveryVirtualClusters(ULONGLONG vcn, DWORD clusters,
	void* bufv, DWORD bufLen, DWORD* actural)
{
	_ASSERT(bufv);
	_ASSERT(clusters);

	*actural = 0;
	BYTE* buf = (BYTE*)bufv;

	// Verify if clusters exceeds DataRun bounds

	if (vcn + clusters > (AttrHeaderNR->LastVCN - AttrHeaderNR->StartVCN + 1))
	{
		//CString st;
		//st.Format(L"vcn:%d<=>cluster:%d<=>LastVCN:%d<=>StartVCN:%d",vcn, clusters, AttrHeaderNR->LastVCN, AttrHeaderNR->StartVCN);
		//AfxMessageBox(st);
		//AfxMessageBox(L"CAttrNonResident::ReadVirtualClusters-Cluster exceeds DataRun bounds");
		NTFS_TRACE("Cluster exceeds DataRun bounds\n");
		return FALSE;
	}


	// Verify buffer size
	if (bufLen < clusters * _ClusterSize)
	{
		//AfxMessageBox(L"CAttrNonResident::ReadVirtualClusters-Buffer size too small");
		NTFS_TRACE("Buffer size too small\n");
		return FALSE;
	}

	// Traverse the DataRun List to find the according LCN
	const DataRun_Entry* dr = DataRunList.FindFirstEntry();
	while (dr)
	{
		if (vcn >= dr->StartVCN && vcn <= dr->LastVCN)
		{
			DWORD clustersToRead;

			ULONGLONG vcns = dr->LastVCN - vcn + 1;	// Clusters from read pointer to the end

			if ((ULONGLONG)clusters > vcns)	// Fragmented data, we must go on
				clustersToRead = (DWORD)vcns;
			else
				clustersToRead = clusters;
			if (ReadClusters(buf, clustersToRead, dr->LCN + (vcn - dr->StartVCN)))
			{
				buf += clustersToRead * _ClusterSize;
				clusters -= clustersToRead;
				*actural += clustersToRead;
				vcn += clustersToRead;
			}
			else
				break;

			if (clusters == 0)
				break;
		}

		dr = DataRunList.FindNextEntry();
	}

	*actural *= _ClusterSize;
	return TRUE;
}

BOOL CAttrNonResident::GetVCNSize() const
{
	ULONGLONG VCNSize = ((AttrHeaderNR->LastVCN - AttrHeaderNR->StartVCN) + 1) * _ClusterSize;

	return (BOOL)VCNSize; //w20140408
}

BOOL CAttrNonResident::CheckCompressed(/*ULONGLONG fileid*/) const
{
	//CString st;
	if (AttrHeaderNR->CompUnitSize > 0)
	{
		//st.Format(L"ID: %I64u NonResident::CheckCompressed > 0", fileid);
		//AfxMessageBox(st);
		return 1;
	}
	//	else
	//	{
	//		if ( AttrHeaderNR->IniSize == AttrHeaderNR->RealSize )
	//		{
				//st.Format(L"ID: %I64u NonResident::CheckCompressed IniSize=RealSize ", fileid);
				//AfxMessageBox(st);
	//			return 0;
	//		}
	//		else
	//		{
				//st.Format(L"ID: %I64u NonResident::CheckCompressed IniSize!=RealSize ", fileid);
				//AfxMessageBox(st);
	//			return 1;
	//		}
	//	}
	return FALSE;
}
// 20121212 add <-
BOOL CAttrNonResident::CompressedLessReal(ULONGLONG fileid) const
{
	if (AttrHeaderNR->IniSize == AttrHeaderNR->RealSize)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}


CAttr_StdInfo::CAttr_StdInfo(const ATTR_HEADER_COMMON* ahc, const CFileRecord* fr) : CAttrResident(ahc, fr)
{
	NTFS_TRACE("Attribute: Standard Information\n");

	StdInfo = (ATTR_STANDARD_INFORMATION*)AttrBody;
	StdFile = (ATTR_FILE_NAME*)AttrBody;
}

CAttr_StdInfo::~CAttr_StdInfo()
{
	NTFS_TRACE("CAttr_StdInfo deleted\n");
}

// Change from UTC time to local time
void CAttr_StdInfo::GetFileTime(FILETIME* writeTm, FILETIME* createTm, FILETIME* accessTm) const
{
	UTC2Local(StdInfo->AlterTime, writeTm);

	if (createTm)
		UTC2Local(StdInfo->CreateTime, createTm);

	if (accessTm)
		UTC2Local(StdInfo->ReadTime, accessTm);
}

void CAttr_StdInfo::GetFileCreateTime(FILETIME* createTm) const
{
	UTC2Local(StdInfo->CreateTime, createTm);
}
void CAttr_StdInfo::GetFileFileCreateTime(FILETIME* createTm) const
{
	UTC2Local(StdFile->CreateTime, createTm);
}

void CAttr_StdInfo::GetFileWriteTime(FILETIME* writeTm) const
{
	UTC2Local(StdInfo->AlterTime, writeTm);
}
void CAttr_StdInfo::GetFileFileWriteTime(FILETIME* writeTm) const
{
	UTC2Local(StdFile->AlterTime, writeTm);
}
void CAttr_StdInfo::GetFileAccessTime(FILETIME* accessTm) const
{
	UTC2Local(StdInfo->ReadTime, accessTm);
}
void CAttr_StdInfo::GetFileFileAccessTime(FILETIME* accessTm) const
{
	UTC2Local(StdFile->ReadTime, accessTm);
}
void CAttr_StdInfo::GetEntryModifiedTime(FILETIME* entrymodTm) const
{
	//UTC2Local(StdFile->MFTTime, entrymodTm);	
	UTC2Local(StdInfo->MFTTime, entrymodTm);
}
void CAttr_StdInfo::GetFileEntryModifiedTime(FILETIME* entrymodTm) const
{
	UTC2Local(StdFile->MFTTime, entrymodTm);
}
DWORD CAttr_StdInfo::GetFilePermission() const
{
	return StdInfo->Permission;
}

BOOL CAttr_StdInfo::IsReadOnly() const
{
	return ((StdInfo->Permission) & ATTR_STDINFO_PERMISSION_READONLY);
}

BOOL CAttr_StdInfo::IsHidden() const
{
	return ((StdInfo->Permission) & ATTR_STDINFO_PERMISSION_HIDDEN);
}

BOOL CAttr_StdInfo::IsSystem() const
{
	return ((StdInfo->Permission) & ATTR_STDINFO_PERMISSION_SYSTEM);
}

BOOL CAttr_StdInfo::IsCompressed() const
{
	return ((StdInfo->Permission) & ATTR_STDINFO_PERMISSION_COMPRESSED);
}

BOOL CAttr_StdInfo::IsEncrypted() const
{
	return ((StdInfo->Permission) & ATTR_STDINFO_PERMISSION_ENCRYPTED);
}

BOOL CAttr_StdInfo::IsSparse() const
{
	return ((StdInfo->Permission) & ATTR_STDINFO_PERMISSION_SPARSE);
}

// UTC filetime to Local filetime
void CAttr_StdInfo::UTC2Local(const ULONGLONG& ultm, FILETIME* lftm)
{
	LARGE_INTEGER fti;
	FILETIME ftt;

	fti.QuadPart = ultm;
	ftt.dwHighDateTime = fti.HighPart;
	ftt.dwLowDateTime = fti.LowPart;

	if (!FileTimeToLocalFileTime(&ftt, lftm))
		*lftm = ftt;
}

CFileName::CFileName(ATTR_FILE_NAME* fn)
{
	IsCopy = FALSE;

	FileName = fn;

	FileNameWUC = NULL;
	FileNameLength = 0;

	if (fn)
		GetFileNameWUC();
}

CFileName::~CFileName()
{
	if (FileNameWUC)
		delete FileNameWUC;
}

void CFileName::SetFileName(ATTR_FILE_NAME* fn)
{
	FileName = fn;

	GetFileNameWUC();
}

// Copy pointer buffers
void CFileName::CopyFileName(const CFileName* fn, const ATTR_FILE_NAME* afn)
{
	if (!IsCopy)
	{
		NTFS_TRACE("Cannot call this routine\n");
		return;
	}

	_ASSERT(fn && afn);

	NTFS_TRACE("FileName Copied\n");

	if (FileNameWUC)
		delete FileNameWUC;

	FileNameLength = fn->FileNameLength;
	FileName = afn;

	if (fn->FileNameWUC)
	{
		FileNameWUC = new wchar_t[FileNameLength + 1];
		wcsncpy_s(FileNameWUC, FileNameLength + 1, fn->FileNameWUC, FileNameLength);
		FileNameWUC[FileNameLength] = wchar_t('\0');
	}
	else
		FileNameWUC = NULL;
}

// Get uppercase unicode filename and store it in a buffer
void CFileName::GetFileNameWUC()
{
#ifdef	_DEBUG
	char fna[MAX_PATH];
	GetFileName(fna, MAX_PATH);	// Just show filename in debug window
#endif

	if (FileNameWUC)
	{
		delete FileNameWUC;
		FileNameWUC = NULL;
		FileNameLength = 0;
	}

	wchar_t fns[MAX_PATH];
	FileNameLength = GetFileName(fns, MAX_PATH);

	if (FileNameLength > 0)
	{
		FileNameWUC = new wchar_t[FileNameLength + 1];
		for (int i = 0; i < FileNameLength; i++)
			FileNameWUC[i] = towupper(fns[i]);
		FileNameWUC[FileNameLength] = wchar_t('\0');
	}
	else
	{
		FileNameLength = 0;
		FileNameWUC = NULL;
	}
}

// Compare Unicode file name
int CFileName::Compare(const wchar_t* fn) const
{
	// Change fn to upper case
	int len = (int)wcslen(fn);
	if (len > MAX_PATH)
		return 1;	// Assume bigger

	wchar_t fns[MAX_PATH];

	for (int i = 0; i < len; i++)
		fns[i] = towupper(fn[i]);
	fns[len] = wchar_t('\0');

	return wcscmp(fns, FileNameWUC);
}

// Compare ANSI file name
int CFileName::Compare(const char* fn) const
{
	wchar_t fnw[MAX_PATH];

	int len = MultiByteToWideChar(CP_ACP, 0, fn, -1, fnw, MAX_PATH);
	if (len)
		return Compare(fnw);
	else
		return 1;	// Assume bigger
}

ULONGLONG CFileName::GetFileSize() const
{
	return FileName ? FileName->RealSize : 0;
}
ULONGLONG CFileName::GetFileAllocSize() const
{
	return FileName ? FileName->AllocSize : 0;
}
DWORD CFileName::GetFilePermission() const
{
	return FileName ? FileName->Flags : 0;
}

BOOL CFileName::IsReadOnly() const
{
	return FileName ? ((FileName->Flags) & ATTR_FILENAME_FLAG_READONLY) : FALSE;
}

BOOL CFileName::IsHidden() const
{
	return FileName ? ((FileName->Flags) & ATTR_FILENAME_FLAG_HIDDEN) : FALSE;
}

BOOL CFileName::IsSystem() const
{
	return FileName ? ((FileName->Flags) & ATTR_FILENAME_FLAG_SYSTEM) : FALSE;
}

BOOL CFileName::IsDirectory() const
{
	return FileName ? ((FileName->Flags) & ATTR_FILENAME_FLAG_DIRECTORY) : FALSE;
}

BOOL CFileName::IsCompressed() const
{
	return FileName ? ((FileName->Flags) & ATTR_FILENAME_FLAG_COMPRESSED) : FALSE;
}

BOOL CFileName::IsEncrypted() const
{
	return FileName ? ((FileName->Flags) & ATTR_FILENAME_FLAG_ENCRYPTED) : FALSE;
}

BOOL CFileName::IsSparse() const
{
	return FileName ? ((FileName->Flags) & ATTR_FILENAME_FLAG_SPARSE) : FALSE;
}

// Get ANSI File Name
// Return 0: Unnamed, <0: buffer too small, -buffersize, >0 Name length
int CFileName::GetFileName(char* buf, DWORD bufLen) const
{
	if (FileName == NULL)
		return 0;

	int len = 0;

	if (FileName->NameLength)
	{
		if (bufLen < FileName->NameLength)
			return -1 * FileName->NameLength;	// buffer too small

		len = WideCharToMultiByte(CP_ACP, 0, (wchar_t*)FileName->Name, FileName->NameLength,
			buf, bufLen, NULL, NULL);
		if (len)
		{
			buf[len] = '\0';
			NTFS_TRACE1("File Name: %s\n", buf);
			NTFS_TRACE4("File Permission: %s\t%c%c%c\n", IsDirectory() ? "Directory" : "File",
				IsReadOnly() ? 'R' : ' ', IsHidden() ? 'H' : ' ', IsSystem() ? 'S' : ' ');
		}
		else
		{
			NTFS_TRACE("Unrecognized File Name or FileName buffer too small\n");
		}
	}

	return len;
}

// Get Unicode File Name
// Return 0: Unnamed, <0: buffer too small, -buffersize, >0 Name length
int CFileName::GetFileName(wchar_t* buf, DWORD bufLen) const
{
	if (FileName == NULL)
		return 0;

	if (FileName->NameLength)
	{
		if (bufLen < FileName->NameLength)
			return -1 * FileName->NameLength;	// buffer too small

		bufLen = FileName->NameLength;
		wcsncpy_s(buf, bufLen + 1, (wchar_t*)FileName->Name, bufLen);
		buf[bufLen] = wchar_t('\0');

		return bufLen;
	}

	return 0;
}

BOOL CFileName::HasName() const
{
	return FileNameLength > 0;
}

BOOL CFileName::IsWin32Name() const
{
	if (FileName == NULL || FileNameLength <= 0)
		return FALSE;

	return (FileName->NameSpace != ATTR_FILENAME_NAMESPACE_DOS);	// POSIX, WIN32, WIN32_DOS
}

// Change from UTC time to local time
void CFileName::GetFileTime(FILETIME* writeTm, FILETIME* createTm, FILETIME* accessTm) const
{
	CAttr_StdInfo::UTC2Local(FileName ? FileName->AlterTime : 0, writeTm);

	if (createTm)
		CAttr_StdInfo::UTC2Local(FileName ? FileName->CreateTime : 0, createTm);

	if (accessTm)
		CAttr_StdInfo::UTC2Local(FileName ? FileName->ReadTime : 0, accessTm);
}

void CFileName::GetFileCreateTime(FILETIME* createTm) const
{
	CAttr_StdInfo::UTC2Local(FileName ? FileName->CreateTime : 0, createTm);
}
void CFileName::GetFileWriteTime(FILETIME* writeTm) const
{
	CAttr_StdInfo::UTC2Local(FileName ? FileName->AlterTime : 0, writeTm);
}
void CFileName::GetFileAccessTime(FILETIME* accessTm) const
{
	CAttr_StdInfo::UTC2Local(FileName ? FileName->ReadTime : 0, accessTm);
}

ULONGLONG CFileName::GetParentRef() const
{
	return FileName ? FileName->ParentRef : 0;
}




CAttr_IndexAlloc::CAttr_IndexAlloc(const ATTR_HEADER_COMMON* ahc, const CFileRecord* fr) : CAttrNonResident(ahc, fr)
{
	NTFS_TRACE("Attribute: Index Allocation\n");

	IndexBlockCount = 0;

	if (IsDataRunOK())
	{
		// Get total number of Index Blocks
		ULONGLONG ibTotalSize;
		ibTotalSize = GetDataSize();
		if (ibTotalSize % _IndexBlockSize)
		{
			NTFS_TRACE2("Cannot calulate number of IndexBlocks, total size = %I64u, unit = %u\n",
				ibTotalSize, _IndexBlockSize);
			return;
		}
		IndexBlockCount = ibTotalSize / _IndexBlockSize;
	}
	else
	{
		NTFS_TRACE("Index Allocation DataRun parse error\n");
	}
}

CAttr_IndexAlloc::~CAttr_IndexAlloc()
{
	NTFS_TRACE("CAttr_IndexAlloc deleted\n");
}

// Verify US and update sectors
BOOL CAttr_IndexAlloc::PatchUS(WORD* sector, int sectors, WORD usn, WORD* usarray)
{
	int i;

	for (i = 0; i < sectors; i++)
	{
		sector += ((_SectorSize >> 1) - 1);
		if (*sector != usn)
			return FALSE;		// USN error
		*sector = usarray[i];	// Write back correct data
		sector++;
	}
	return TRUE;
}

ULONGLONG CAttr_IndexAlloc::GetIndexBlockCount()
{
	return IndexBlockCount;
}

// Parse a single Index Block
// vcn = Index Block VCN in Index Allocation Data Attributes
// ibClass holds the parsed Index Entries
BOOL CAttr_IndexAlloc::ParseIndexBlock(const ULONGLONG& vcn, CIndexBlock& ibClass)
{
	if (vcn >= IndexBlockCount)	// Bounds check
		return FALSE;

	// Allocate buffer for a single Index Block
	INDEX_BLOCK* ibBuf = ibClass.AllocIndexBlock(_IndexBlockSize);

	// Sectors Per Index Block
	DWORD sectors = _IndexBlockSize / _SectorSize;

	// Read one Index Block
	DWORD len;
	//if (ReadData(vcn*_IndexBlockSize, ibBuf, _IndexBlockSize, &len) &&
	/*
	if (ReadData(vcn*_ClusterSize, ibBuf, _IndexBlockSize, &len) &&
		len == _IndexBlockSize)
	*/
	if (ReadData(vcn * _ClusterSize, ibBuf, _ClusterSize, &len) &&
		len == _IndexBlockSize)
	{
		if (ibBuf->Magic != INDEX_BLOCK_MAGIC)
		{
			NTFS_TRACE("Index Block parse error: Magic mismatch\n");
			return FALSE;
		}

		// Patch US
		WORD* usnaddr = (WORD*)((BYTE*)ibBuf + ibBuf->OffsetOfUS);
		WORD usn = *usnaddr;
		WORD* usarray = usnaddr + 1;
		if (!PatchUS((WORD*)ibBuf, sectors, usn, usarray))
		{
			NTFS_TRACE("Index Block parse error: Update Sequence Number\n");
			return FALSE;
		}

		INDEX_ENTRY* ie;
		ie = (INDEX_ENTRY*)((BYTE*)(&(ibBuf->EntryOffset)) + ibBuf->EntryOffset);

		DWORD ieTotal = ie->Size;

		while (ieTotal <= ibBuf->TotalEntrySize)
		{
			CIndexEntry* ieClass = new CIndexEntry(ie);
			ibClass.InsertEntry(ieClass);

			if (ie->Flags & INDEX_ENTRY_FLAG_LAST)
			{
				NTFS_TRACE("Last Index Entry\n");
				break;
			}

			ie = (INDEX_ENTRY*)((BYTE*)ie + ie->Size);	// Pick next
			ieTotal += ie->Size;
		}

		return TRUE;
	}
	else
		return FALSE;
}


template <class TYPE_RESIDENT>
BOOL CAttr_Bitmap<TYPE_RESIDENT>::ReadData(const ULONGLONG& offset, void* bufv, DWORD bufLen, DWORD* actual) const
{
	return FALSE;
}

template <class TYPE_RESIDENT>
BOOL CAttr_Bitmap<TYPE_RESIDENT>::IsNonResident() const
{
	return FALSE;
}

template <class TYPE_RESIDENT>
BOOL CAttr_Bitmap<TYPE_RESIDENT>::IsDataRunOK() const
{
	return FALSE;
}

template <class TYPE_RESIDENT>
ULONGLONG CAttr_Bitmap<TYPE_RESIDENT>::GetDataSize(ULONGLONG* allocSize) const
{
	return 0;
}

template <class TYPE_RESIDENT>
CAttr_Bitmap<TYPE_RESIDENT>::CAttr_Bitmap(const ATTR_HEADER_COMMON* ahc, const CFileRecord* fr) : TYPE_RESIDENT(ahc, fr)
{
	NTFS_TRACE1("Attribute: Bitmap (%sResident)\n", IsNonResident() ? "Non" : "");

	CurrentCluster = -1;

	if (IsDataRunOK())
	{
		BitmapSize = GetDataSize();

		if (IsNonResident())
			BitmapBuf = new BYTE[_ClusterSize];
		else
		{
			BitmapBuf = new BYTE[(DWORD)BitmapSize];

			DWORD len;
			if (!(ReadData(0, BitmapBuf, (DWORD)BitmapSize, &len)
				&& len == (DWORD)BitmapSize))
			{
				BitmapBuf = NULL;
				NTFS_TRACE("Read Resident Bitmap data failed\n");
			}
			else
			{
				NTFS_TRACE1("%u bytes of resident Bitmap data read\n", len);
			}
		}
	}
	else
	{
		BitmapSize = 0;
		BitmapBuf = 0;
	}
}

template <class TYPE_RESIDENT>
CAttr_Bitmap<TYPE_RESIDENT>::~CAttr_Bitmap()
{
	if (BitmapBuf)
		delete BitmapBuf;

	NTFS_TRACE("CAttr_Bitmap deleted\n");
}

// Verify if a single cluster is free
template <class TYPE_RESIDENT>
BOOL CAttr_Bitmap<TYPE_RESIDENT>::IsClusterFree(const ULONGLONG& cluster) const
{
	if (!IsDataRunOK() || !BitmapBuf)
		return FALSE;

	if (IsNonResident())
	{
		LONGLONG idx = (LONGLONG)cluster >> 3;
		DWORD clusterSize = ((CNTFSVolume*)Volume)->GetClusterSize();

		LONGLONG clusterOffset = idx / clusterSize;
		cluster -= (clusterOffset * clusterSize * 8);

		// Read one cluster of data if buffer mismatch
		if (CurrentCluster != clusterOffset)
		{
			DWORD len;
			if (ReadData(clusterOffset, BitmapBuf, clusterSize, &len) && len == clusterSize)
			{
				CurrentCluster = clusterOffset;
			}
			else
			{
				CurrentCluster = -1;
				return FALSE;
			}
		}
	}

	// All the Bitmap data is already in BitmapBuf
	DWORD idx = (DWORD)(cluster >> 3);
	if (IsNonResident() == FALSE)
	{
		if (idx >= BitmapSize)
			return TRUE;	// Resident data bounds check error
	}

	BYTE fac = (BYTE)(cluster % 8);

	return ((BitmapBuf[idx] & (1 << fac)) == 0);
}

template <class TYPE_RESIDENT>
BOOL CAttr_AttrList<TYPE_RESIDENT>::ReadData(const ULONGLONG& offset, void* bufv, DWORD bufLen, DWORD* actual) const
{
	return FALSE;
}

template <class TYPE_RESIDENT>
CAttr_AttrList<TYPE_RESIDENT>::CAttr_AttrList(const ATTR_HEADER_COMMON* ahc, const CFileRecord* fr) : TYPE_RESIDENT(ahc, fr)
{
	NTFS_TRACE("Attribute: Attribute List\n");
	if (fr->FileReference == (ULONGLONG)-1)
		return;

	ULONGLONG offset = 0;
	DWORD len;
	ATTR_ATTRIBUTE_LIST alRecord;

	while (ReadData(offset, &alRecord, sizeof(ATTR_ATTRIBUTE_LIST), &len) &&
		len == sizeof(ATTR_ATTRIBUTE_LIST))
	{
		if (ATTR_INDEX(alRecord.AttrType) > ATTR_NUMS)
		{
			NTFS_TRACE("Attribute List parse error1\n");
			break;
		}

		NTFS_TRACE1("Attribute List: 0x%04x\n", alRecord.AttrType);

		ULONGLONG recordRef = alRecord.BaseRef & 0x0000FFFFFFFFFFFFUL;
		if (recordRef != fr->FileReference)	// Skip contained attributes
		{
			DWORD am = ATTR_MASK(alRecord.AttrType);
			if (am & fr->AttrMask)	// Skip unwanted attributes
			{
				CFileRecord* frnew = new CFileRecord(fr->Volume);
				FileRecordList.InsertEntry(frnew);

				frnew->AttrMask = am;
				if (!frnew->ParseFileRecord(recordRef))
				{
					NTFS_TRACE("Attribute List parse error2\n");
					break;
				}
				frnew->ParseAttrs();

				// Insert new found AttrList to fr->AttrList
				const CAttrBase* ab = (CAttrBase*)frnew->FindFirstAttr(alRecord.AttrType);
				while (ab)
				{
					CAttrList* al = (CAttrList*)&fr->AttrList[ATTR_INDEX(alRecord.AttrType)];
					al->InsertEntry((CAttrBase*)ab);
					ab = frnew->FindNextAttr(alRecord.AttrType);
				}

				// Throw away frnew->AttrList entries to prevent free twice (fr will delete them)
				frnew->AttrList[ATTR_INDEX(alRecord.AttrType)].ThrowAll();
			}
		}

		offset += alRecord.RecordSize;
	}
}

template <class TYPE_RESIDENT>
CAttr_AttrList<TYPE_RESIDENT>::~CAttr_AttrList()
{
	NTFS_TRACE("CAttr_AttrList deleted\n");
}


CAttr_IndexRoot::CAttr_IndexRoot(const ATTR_HEADER_COMMON* ahc, const CFileRecord* fr) : CAttrResident(ahc, fr)
{
	NTFS_TRACE("Attribute: Index Root\n");

	IndexRoot = (ATTR_INDEX_ROOT*)AttrBody;

	if (IsFileName())
	{
		ParseIndexEntries();
	}
	else
	{
		NTFS_TRACE("Index View not supported\n");
	}
}

CAttr_IndexRoot::~CAttr_IndexRoot()
{
	NTFS_TRACE("CAttr_IndexRoot deleted\n");
}

// Get all the index entries
void CAttr_IndexRoot::ParseIndexEntries()
{
	INDEX_ENTRY* ie;
	ie = (INDEX_ENTRY*)((BYTE*)(&(IndexRoot->EntryOffset)) + IndexRoot->EntryOffset);

	DWORD ieTotal = ie->Size;

	while (ieTotal <= IndexRoot->TotalEntrySize)
	{
		CIndexEntry* ieClass = new CIndexEntry(ie);
		InsertEntry(ieClass);

		if (ie->Flags & INDEX_ENTRY_FLAG_LAST)
		{
			NTFS_TRACE("Last Index Entry\n");
			break;
		}

		ie = (INDEX_ENTRY*)((BYTE*)ie + ie->Size);	// Pick next
		ieTotal += ie->Size;
	}
}

// Check if this IndexRoot contains FileName or IndexView
BOOL CAttr_IndexRoot::IsFileName() const
{
	return (IndexRoot->AttrType == ATTR_TYPE_FILE_NAME);
}

