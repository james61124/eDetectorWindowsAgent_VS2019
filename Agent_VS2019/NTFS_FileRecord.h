//#pragma once
#ifndef	__NTFS_FILERECORD_H_CYB70289
#define	__NTFS_FILERECORD_H_CYB70289

//#include "NTFS_Common.h"

#include <windows.h>
#include "NTFS_Common.h"
//#include "NTFS_Attribute.h"




///////////////////////////////////////
// NTFS Volume forward declaration
///////////////////////////////////////
class CNTFSVolume
{
public:
	CNTFSVolume(_TCHAR volume);
	virtual ~CNTFSVolume();

	friend class CFileRecord;
	friend class CAttrBase;

private:
	WORD SectorSize;
	DWORD ClusterSize;
	DWORD FileRecordSize;
	DWORD IndexBlockSize;
	ULONGLONG MFTAddr;
	HANDLE hVolume;
	BOOL VolumeOK;
	ATTR_RAW_CALLBACK AttrRawCallBack[ATTR_NUMS];
	WORD Version;

	// MFT file records ($MFT file itself) may be fragmented
	// Get $MFT Data attribute to translate FileRecord to correct disk offset
	CFileRecord* MFTRecord;		// $MFT File Record
	const CAttrBase* MFTData;	// $MFT Data Attribute

	BOOL OpenVolume(_TCHAR volume);

public:
	BOOL IsVolumeOK() const;
	WORD GetVersion() const;
	ULONGLONG GetRecordsCount() const;

	DWORD GetSectorSize() const;
	DWORD GetClusterSize() const;
	DWORD GetFileRecordSize() const;
	DWORD GetIndexBlockSize() const;
	ULONGLONG GetMFTAddr() const;

	BOOL InstallAttrRawCB(DWORD attrType, ATTR_RAW_CALLBACK cb);
	void ClearAttrRawCB();
};	// CNTFSVolume


////////////////////////////////////////////
// List to hold Attributes of the same type
////////////////////////////////////////////
typedef class CSList<CAttrBase> CAttrList;

// It seems VC6.0 doesn't support template class friends
#if	_MSC_VER <= 1200
class CAttrResident;
class CAttrNonResident;
template <class TYPE_RESIDENT> class CAttr_AttrList;
#endif

////////////////////////////////
// Process a single File Record
////////////////////////////////
class CFileRecord
{
public:
	CFileRecord(const CNTFSVolume* volume);
	virtual ~CFileRecord();

	friend class CAttrBase;
#if	_MSC_VER <= 1200
	// Walk around VC6.0 compiler defect
	friend class CAttr_AttrList<CAttrResident>;
	friend class CAttr_AttrList<CAttrNonResident>;
#else
	template <class TYPE_RESIDENT> friend class CAttr_AttrList;		// Won't compiler in VC6.0, why?
	//template <class TYPE_RESIDENT> class CAttr_AttkrList;
#endif

//private:
	const CNTFSVolume* Volume;
	FILE_RECORD_HEADER* FileRecord;
	ULONGLONG FileReference;
	ATTR_RAW_CALLBACK AttrRawCallBack[ATTR_NUMS];
	DWORD AttrMask;
	CAttrList AttrList[ATTR_NUMS];	// Attributes

	void ClearAttrs();
	BOOL PatchUS(WORD* sector, int sectors, WORD usn, WORD* usarray);
	void UserCallBack(DWORD attType, ATTR_HEADER_COMMON* ahc, BOOL* bDiscard);
	CAttrBase* AllocAttr(ATTR_HEADER_COMMON* ahc, BOOL* bUnhandled);
	BOOL ParseAttr(ATTR_HEADER_COMMON* ahc);
	FILE_RECORD_HEADER* ReadFileRecord(ULONGLONG& fileRef);
	BOOL VisitIndexBlock(const ULONGLONG& vcn, const _TCHAR* fileName, CIndexEntry& ieFound) const;
	void TraverseSubNode(const ULONGLONG& vcn, SUBENTRY_CALLBACK seCallBack) const;

//public:
	BOOL ParseFileRecord(ULONGLONG fileRef);
	BOOL ParseAttrs();
	BOOL ParseFileAttrs();
	int FindAttrTypeCount(DWORD pAttrType);
	BOOL InstallAttrRawCB(DWORD attrType, ATTR_RAW_CALLBACK cb);
	void ClearAttrRawCB();

	void SetAttrMask(DWORD mask);
	void TraverseAttrs(ATTRS_CALLBACK attrCallBack, void* context);
	const CAttrBase* FindFirstAttr(DWORD attrType) const;
	const CAttrBase* FindRecoveryFirstAttr(DWORD attrType) const; // 11202012 debug add
	const CAttrBase* FindNextAttr(DWORD attrType) const;

	int GetFileName(_TCHAR* buf, DWORD bufLen) const;
	ULONGLONG GetFileSize() const;
	ULONGLONG GetParentRef() const;
	void GetFileTime(FILETIME* writeTm, FILETIME* createTm = NULL, FILETIME* accessTm = NULL) const;
	void GetFileCreateTime(FILETIME* createTm) const;
	void GetFileWriteTime(FILETIME* writeTm) const;
	void GetFileAccessTime(FILETIME* accessTm) const;
	void GetEntryModifiedTime(FILETIME* entrymodTm) const;

	void TraverseSubEntries(SUBENTRY_CALLBACK seCallBack) const;
	const BOOL FindSubEntry(const _TCHAR* fileName, CIndexEntry& ieFound) const;
	const CAttrBase* FindStream(_TCHAR* name = NULL);
	const CAttrBase* FindRecoveryStream(_TCHAR* name = NULL); //11202012 Debug add

	BOOL IsDeleted() const;
	BOOL IsDirectory() const;
	BOOL IsReadOnly() const;
	BOOL IsHidden() const;
	BOOL IsSystem() const;
	BOOL IsCompressed() const;
	BOOL IsEncrypted() const;
	BOOL IsSparse() const;
};	// CFileRecord



// add 

typedef struct tagDataRun_Entry
{
	LONGLONG			LCN;		// -1 to indicate sparse data
	ULONGLONG			Clusters;
	ULONGLONG			StartVCN;
	ULONGLONG			LastVCN;
} DataRun_Entry;
typedef class CSList<DataRun_Entry> CDataRunList;

////////////////////////////////////
// List to hold Index Entry objects
////////////////////////////////////
class CIndexEntry;
typedef class CSList<CIndexEntry> CIndexEntryList;


////////////////////////////////
// Attributes base class
////////////////////////////////
class CAttrBase
{
public:
	CAttrBase(const ATTR_HEADER_COMMON* ahc, const CFileRecord* fr);
	//CAttrBase(const ATTR_HEADER_COMMON* ahc);
	virtual ~CAttrBase();

protected:
	const ATTR_HEADER_COMMON* AttrHeader;
	WORD _SectorSize;
	DWORD _ClusterSize;
	DWORD _IndexBlockSize;
	HANDLE _hVolume;
	const CFileRecord* FileRecord;

public:
	const ATTR_HEADER_COMMON* GetAttrHeader() const;
	DWORD GetAttrType() const;
	DWORD GetAttrTotalSize() const;
	BOOL IsNonResident() const;
	WORD GetAttrFlags() const;
	int GetAttrName(char* buf, DWORD bufLen) const;
	int GetAttrName(wchar_t* buf, DWORD bufLen) const;
	BOOL IsUnNamed() const;

protected:
	virtual BOOL IsDataRunOK() const = 0;

public:
	virtual ULONGLONG GetDataSize(ULONGLONG* allocSize = NULL) const = 0;
	virtual ULONGLONG GetAllocSize(ULONGLONG* allocSize = NULL) const = 0; //0709-2013
	virtual ULONGLONG GetComSize(ULONGLONG* allocSize = NULL) const = 0;//0715-2013
	virtual DWORD GetClusterSize() const = 0;
	virtual BOOL ReadData(const ULONGLONG& offset, void* bufv, DWORD bufLen, DWORD* actural) const = 0;
	virtual BOOL ReadCompressedData(const ULONGLONG& offset, void* bufv, DWORD bufLen, DWORD* actural) const = 0; //0709-2013
	virtual BOOL ReadIniSizeData(const ULONGLONG& offset, void* bufv, DWORD bufLen, DWORD* actural) const = 0; //0715-2013
	virtual BOOL ReadRecoveryData(const ULONGLONG& offset, void* bufv, DWORD bufLen, DWORD* actural, ULONGLONG RealSize) const = 0; //11202012
	virtual BOOL GetVCNSize() const = 0; //20121212
	virtual BOOL CheckCompressed(/*ULONGLONG fileid*/) const = 0; //20121212
	virtual BOOL CompressedLessReal(ULONGLONG fileid) const = 0; //0715-2013
};	// CAttrBase


////////////////////////////////
// Resident Attributes
////////////////////////////////
class CAttrResident : public CAttrBase
{
public:
	CAttrResident(const ATTR_HEADER_COMMON* ahc, const CFileRecord* fr);
	virtual ~CAttrResident();

protected:
	const ATTR_HEADER_RESIDENT* AttrHeaderR;
	const void* AttrBody;	// Points to Resident Data
	DWORD AttrBodySize;		// Attribute Data Size

	virtual BOOL IsDataRunOK() const;

public:
	virtual ULONGLONG GetDataSize(ULONGLONG* allocSize = NULL) const;
	virtual ULONGLONG GetAllocSize(ULONGLONG* allocSize = NULL) const; //0709-2013
	virtual ULONGLONG GetComSize(ULONGLONG* allocSize = NULL) const;
	virtual DWORD GetClusterSize() const;
	virtual BOOL ReadData(const ULONGLONG& offset, void* bufv, DWORD bufLen, DWORD* actural) const;
	virtual BOOL ReadCompressedData(const ULONGLONG& offset, void* bufv, DWORD bufLen, DWORD* actural) const; //0709-2013
	virtual BOOL ReadIniSizeData(const ULONGLONG& offset, void* bufv, DWORD bufLen, DWORD* actural) const; //0715-2013
	virtual BOOL ReadRecoveryData(const ULONGLONG& offset, void* bufv, DWORD bufLen, DWORD* actural, ULONGLONG RealSize) const; //20121212
	virtual BOOL GetVCNSize() const; //20121212
	virtual BOOL CheckCompressed(/*ULONGLONG fileid*/) const; //20121212
	virtual BOOL CompressedLessReal(ULONGLONG fileid) const; //0715-2013
};	// CAttrResident



//0715-2013
////////////////////////////////
// NonResident Attributes
////////////////////////////////
class CAttrNonResident : public CAttrBase
{
public:
	CAttrNonResident(const ATTR_HEADER_COMMON* ahc, const CFileRecord* fr);
	virtual ~CAttrNonResident();

protected:
	ATTR_HEADER_NON_RESIDENT* AttrHeaderNR;
	CDataRunList DataRunList;

private:
	BOOL bDataRunOK;
	BYTE* UnalignedBuf;	// Buffer to hold not cluster aligned data
	BOOL PickData(const BYTE** dataRun, LONGLONG* length, LONGLONG* LCNOffset);
	BOOL ParseDataRun();
	BOOL ReadClusters(void* buf, DWORD clusters, LONGLONG lcn);
	BOOL ReadVirtualClusters(ULONGLONG vcn, DWORD clusters,
		void* bufv, DWORD bufLen, DWORD* actural);
	BOOL ReadRecoveryVirtualClusters(ULONGLONG vcn, DWORD clusters,
		void* bufv, DWORD bufLen, DWORD* actural);  //20121212

protected:
	virtual BOOL IsDataRunOK() const;

public:
	virtual ULONGLONG GetDataSize(ULONGLONG* allocSize = NULL) const;
	virtual ULONGLONG GetAllocSize(ULONGLONG* allocSize = NULL) const; //0709-2013
	virtual ULONGLONG GetComSize(ULONGLONG* allocSize = NULL) const; //0715-2013
	virtual DWORD GetClusterSize() const;
	virtual BOOL ReadData(const ULONGLONG& offset, void* bufv, DWORD bufLen, DWORD* actural) const;
	virtual BOOL ReadCompressedData(const ULONGLONG& offset, void* bufv, DWORD bufLen, DWORD* actural) const; //0709-2013
	virtual BOOL ReadIniSizeData(const ULONGLONG& offset, void* bufv, DWORD bufLen, DWORD* actural) const; //0715-2013
	virtual BOOL ReadRecoveryData(const ULONGLONG& offset, void* bufv, DWORD bufLen, DWORD* actural, ULONGLONG RealSize) const; //20121212
	virtual BOOL GetVCNSize() const; //20121212
	virtual BOOL CheckCompressed(/*ULONGLONG fileid*/) const; //20121212
	virtual BOOL CompressedLessReal(ULONGLONG fileid) const; //0715-2013


};	// CAttrNonResident

///////////////////////////////////
// Attribute: Standard Information
///////////////////////////////////
class CAttr_StdInfo : public CAttrResident
{
public:
	CAttr_StdInfo(const ATTR_HEADER_COMMON* ahc, const CFileRecord* fr);
	virtual ~CAttr_StdInfo();

private:
	const ATTR_STANDARD_INFORMATION* StdInfo;
	const ATTR_FILE_NAME* StdFile;

public:
	void GetFileTime(FILETIME* writeTm, FILETIME* createTm = NULL, FILETIME* accessTm = NULL) const;
	void GetFileCreateTime(FILETIME* createTm) const;
	void GetFileFileCreateTime(FILETIME* createTm) const;
	void GetFileWriteTime(FILETIME* writeTm) const;
	void GetFileFileWriteTime(FILETIME* writeTm) const;
	void GetFileAccessTime(FILETIME* accessTm) const;
	void GetFileFileAccessTime(FILETIME* accessTm) const;
	//void GetEntryModifiedTime(FILETIME *accessTm ) const;
	void GetEntryModifiedTime(FILETIME* entrymodTm) const;
	void GetFileEntryModifiedTime(FILETIME* entrymodTm) const;

	DWORD GetFilePermission() const;
	BOOL IsReadOnly() const;
	BOOL IsHidden() const;
	BOOL IsSystem() const;
	BOOL IsCompressed() const;
	BOOL IsEncrypted() const;
	BOOL IsSparse() const;

	static void UTC2Local(const ULONGLONG& ultm, FILETIME* lftm);
};	// CAttr_StdInfo


////////////////////////////////////////
// FileName helper class
// used by FileName and IndexEntry
////////////////////////////////////////
class CFileName
{
public:
	CFileName(ATTR_FILE_NAME* fn = NULL);
	virtual ~CFileName();

protected:
	const ATTR_FILE_NAME* FileName;	// May be NULL for an IndexEntry
	wchar_t* FileNameWUC;	// Uppercase Unicode File Name, used to compare file names
	int FileNameLength;
	BOOL IsCopy;

	void SetFileName(ATTR_FILE_NAME* fn);
	void CopyFileName(const CFileName* fn, const ATTR_FILE_NAME* afn);

private:
	void GetFileNameWUC();

public:
	int Compare(const wchar_t* fn) const;
	int Compare(const char* fn) const;

	ULONGLONG GetFileSize() const;
	ULONGLONG GetFileAllocSize() const;
	DWORD GetFilePermission() const;
	BOOL IsReadOnly() const;
	BOOL IsHidden() const;
	BOOL IsSystem() const;
	BOOL IsDirectory() const;
	BOOL IsCompressed() const;
	BOOL IsEncrypted() const;
	BOOL IsSparse() const;

	int GetFileName(char* buf, DWORD bufLen) const;
	int GetFileName(wchar_t* buf, DWORD bufLen) const;
	BOOL HasName() const;
	BOOL IsWin32Name() const;

	void GetFileTime(FILETIME* writeTm, FILETIME* createTm = NULL, FILETIME* accessTm = NULL) const;
	void GetFileCreateTime(FILETIME* createTm) const;
	void GetFileWriteTime(FILETIME* writeTm) const;
	void GetFileAccessTime(FILETIME* accessTm) const;
	ULONGLONG GetParentRef() const;
};	// CFileName

////////////////////////////////
// Attribute: File Name
////////////////////////////////
class CAttr_FileName : public CAttrResident, public CFileName
{
public:
	CAttr_FileName(const ATTR_HEADER_COMMON* ahc, const CFileRecord* fr) : CAttrResident(ahc, fr)
	{
		NTFS_TRACE("Attribute: File Name\n");

		SetFileName((ATTR_FILE_NAME*)AttrBody);
	}

	virtual ~CAttr_FileName()
	{
		NTFS_TRACE("CAttr_FileName deleted\n");
	}

private:
	// File permission and time in $FILE_NAME only updates when the filename changes
	// So hide these functions to prevent user from getting the error information
	// Standard Information and IndexEntry keeps the most recent file time and permission infomation
	void GetFileTime(FILETIME* writeTm, FILETIME* createTm = NULL, FILETIME* accessTm = NULL) const {}
	void GetFileCreateTime(FILETIME* createTm) const {}
	void GetFileWriteTime(FILETIME* writeTm) const {}
	void GetFileAccessTime(FILETIME* accessTm) const {}
	DWORD GetFilePermission() {}
	BOOL IsReadOnly() const {}
	BOOL IsHidden() const {}
	BOOL IsSystem() const {}
	BOOL IsCompressed() const {}
	BOOL IsEncrypted() const {}
	BOOL IsSparse() const {}
};	// CAttr_FileName


//////////////////////////////////
// Attribute: Volume Information
//////////////////////////////////
class CAttr_VolInfo : public CAttrResident
{
public:
	CAttr_VolInfo(const ATTR_HEADER_COMMON* ahc, const CFileRecord* fr) : CAttrResident(ahc, fr)
	{
		NTFS_TRACE("Attribute: Volume Information\n");

		VolInfo = (ATTR_VOLUME_INFORMATION*)AttrBody;
	}

	virtual ~CAttr_VolInfo()
	{
		NTFS_TRACE("CAttr_VolInfo deleted\n");
	}

private:
	const ATTR_VOLUME_INFORMATION* VolInfo;

public:
	// Get NTFS Volume Version
	WORD GetVersion()
	{
		return MAKEWORD(VolInfo->MinorVersion, VolInfo->MajorVersion);
	}
}; // CAttr_VolInfo


///////////////////////////
// Attribute: Volume Name
///////////////////////////
class CAttr_VolName : public CAttrResident
{
public:
	CAttr_VolName(const ATTR_HEADER_COMMON* ahc, const CFileRecord* fr) : CAttrResident(ahc, fr)
	{
		NTFS_TRACE("Attribute: Volume Name\n");

		NameLength = AttrBodySize >> 1;
		VolNameU = new wchar_t[NameLength + 1];
		VolNameA = new char[NameLength + 1];

		memcpy(VolNameU, AttrBody, AttrBodySize);
		VolNameU[NameLength] = wchar_t('\0');

		int len = WideCharToMultiByte(CP_ACP, 0, VolNameU, NameLength,
			VolNameA, NameLength, NULL, NULL);
		VolNameA[NameLength] = '\0';
	}

	virtual ~CAttr_VolName()
	{
		NTFS_TRACE("CAttr_VolName deleted\n");

		delete VolNameU;
		delete VolNameA;
	}

private:
	wchar_t* VolNameU;
	char* VolNameA;
	DWORD NameLength;

public:
	// Get NTFS Volume Unicode Name
	int GetName(wchar_t* buf, DWORD len) const
	{
		if (len < NameLength)
			return -1 * NameLength;	// buffer too small

		wcsncpy_s(buf, NameLength + 2, VolNameU, NameLength + 1);
		return NameLength;
	}

	// ANSI Name
	int GetName(char* buf, DWORD len) const
	{
		if (len < NameLength)
			return -1 * NameLength;	// buffer too small

		strncpy_s(buf, sizeof(buf), VolNameA, NameLength + 1);
		return NameLength;
	}
}; // CAttr_VolInfo


/////////////////////////////////////
// Attribute: Data
/////////////////////////////////////
template <class TYPE_RESIDENT>
class CAttr_Data : public TYPE_RESIDENT
{
public:
	CAttr_Data(const ATTR_HEADER_COMMON* ahc, const CFileRecord* fr) : TYPE_RESIDENT(ahc, fr)
	{
		//NTFS_TRACE1("Attribute: Data (%sResident)\n", IsNonResident() ? "Non" : "");
	}

	virtual ~CAttr_Data()
	{
		NTFS_TRACE("CAttr_Data deleted\n");
	}
};	// CAttr_Data


/////////////////////////////
// Index Entry helper class
/////////////////////////////
class CIndexEntry : public CFileName
{
public:
	CIndexEntry()
	{
		NTFS_TRACE("Index Entry\n");

		IsDefault = TRUE;

		IndexEntry = NULL;
		SetFileName(NULL);
	}

	CIndexEntry(const INDEX_ENTRY* ie)
	{
		NTFS_TRACE("Index Entry\n");

		IsDefault = FALSE;

		_ASSERT(ie);
		IndexEntry = ie;

		if (IsSubNodePtr())
		{
			NTFS_TRACE("Points to sub-node\n");
		}

		if (ie->StreamSize)
		{
			SetFileName((ATTR_FILE_NAME*)(ie->Stream));
		}
		else
		{
			NTFS_TRACE("No FileName stream found\n");
		}
	}

	virtual ~CIndexEntry()
	{
		// Never touch *IndexEntry here if IsCopy == FALSE !
		// As the memory have been deallocated by ~CIndexBlock()

		if (IsCopy && IndexEntry)
			delete (void*)IndexEntry;

		NTFS_TRACE("CIndexEntry deleted\n");
	}

private:
	BOOL IsDefault;

protected:
	const INDEX_ENTRY* IndexEntry;

public:
	// Use with caution !
	CIndexEntry& operator = (const CIndexEntry& ieClass)
	{
		if (!IsDefault)
		{
			NTFS_TRACE("Cannot call this routine\n");
			return *this;
		}

		NTFS_TRACE("Index Entry Copied\n");

		IsCopy = TRUE;

		if (IndexEntry)
		{
			delete (void*)IndexEntry;
			IndexEntry = NULL;
		}

		const INDEX_ENTRY* ie = ieClass.IndexEntry;
		_ASSERT(ie && (ie->Size > 0));

		IndexEntry = (INDEX_ENTRY*)new BYTE[ie->Size];
		memcpy((void*)IndexEntry, ie, ie->Size);
		CopyFileName(&ieClass, (ATTR_FILE_NAME*)(IndexEntry->Stream));

		return *this;
	}

	ULONGLONG GetFileReference() const
	{
		if (IndexEntry)
			return IndexEntry->FileReference & 0x0000FFFFFFFFFFFFUL;
		else
			return (ULONGLONG)-1;
	}

	BOOL IsSubNodePtr() const
	{
		if (IndexEntry)
			return (IndexEntry->Flags & INDEX_ENTRY_FLAG_SUBNODE);
		else
			return FALSE;
	}

	ULONGLONG GetSubNodeVCN() const
	{
		if (IndexEntry)
			return *(ULONGLONG*)((BYTE*)IndexEntry + IndexEntry->Size - 8);
		else
			return (ULONGLONG)-1;
	}
};	// CIndexEntry


///////////////////////////////
// Index Block helper class
///////////////////////////////
class CIndexBlock : public CIndexEntryList
{
public:
	CIndexBlock()
	{
		NTFS_TRACE("Index Block\n");

		IndexBlock = NULL;
	}

	virtual ~CIndexBlock()
	{
		NTFS_TRACE("IndexBlock deleted\n");

		if (IndexBlock)
			delete IndexBlock;
	}

private:
	INDEX_BLOCK* IndexBlock;

public:
	INDEX_BLOCK* AllocIndexBlock(DWORD size)
	{
		// Free previous data if any
		if (GetCount() > 0)
			RemoveAll();
		if (IndexBlock)
			delete IndexBlock;

		IndexBlock = (INDEX_BLOCK*)new BYTE[size];

		return IndexBlock;
	}
};	// CIndexBlock


/////////////////////////////////////
// Attribute: Index Root (Resident)
/////////////////////////////////////
class CAttr_IndexRoot : public CAttrResident, public CIndexEntryList
{
public:
	CAttr_IndexRoot(const ATTR_HEADER_COMMON* ahc, const CFileRecord* fr);
	virtual ~CAttr_IndexRoot();

private:
	const ATTR_INDEX_ROOT* IndexRoot;

	void ParseIndexEntries();

public:
	BOOL IsFileName() const;
};	// CAttr_IndexRoot



/////////////////////////////////////////////
// Attribute: Index Allocation (NonResident)
/////////////////////////////////////////////
class CAttr_IndexAlloc : public CAttrNonResident
{
public:
	CAttr_IndexAlloc(const ATTR_HEADER_COMMON* ahc, const CFileRecord* fr);
	virtual ~CAttr_IndexAlloc();

private:
	ULONGLONG IndexBlockCount;

	BOOL PatchUS(WORD* sector, int sectors, WORD usn, WORD* usarray);

public:
	ULONGLONG GetIndexBlockCount();
	BOOL ParseIndexBlock(const ULONGLONG& vcn, CIndexBlock& ibClass);
};	// CAttr_IndexAlloc

////////////////////////////////////////////
// Attribute: Bitmap
////////////////////////////////////////////
template <class TYPE_RESIDENT>
class CAttr_Bitmap : public TYPE_RESIDENT
{
public:
	CAttr_Bitmap(const ATTR_HEADER_COMMON* ahc, const CFileRecord* fr);
	virtual ~CAttr_Bitmap();

private:
	ULONGLONG BitmapSize;	// Bitmap data size
	BYTE* BitmapBuf;		// Bitmap data buffer
	LONGLONG CurrentCluster;

public:
	BOOL IsClusterFree(const ULONGLONG& cluster) const;

protected:
	virtual BOOL ReadData(const ULONGLONG& offset, void* bufv, DWORD bufLen, DWORD* actual) const;
	virtual BOOL IsNonResident() const;
	virtual BOOL IsDataRunOK() const;
	virtual ULONGLONG GetDataSize(ULONGLONG* allocSize = NULL) const;
	DWORD _ClusterSize;
	const CNTFSVolume* Volume;
};	// CAttr_Bitmap


////////////////////////////////////////////
// List to hold external File Records
////////////////////////////////////////////
typedef CSList<CFileRecord> CFileRecordList;

////////////////////////////////////////////
// Attribute: Attribute List
////////////////////////////////////////////
template <class TYPE_RESIDENT>
class CAttr_AttrList : public TYPE_RESIDENT
{
public:
	CAttr_AttrList(const ATTR_HEADER_COMMON* ahc, const CFileRecord* fr);
	virtual ~CAttr_AttrList();

private:
	CFileRecordList FileRecordList;

protected:
	virtual BOOL ReadData(const ULONGLONG& offset, void* bufv, DWORD bufLen, DWORD* actual) const;
};	// CAttr_AttrList

#endif
