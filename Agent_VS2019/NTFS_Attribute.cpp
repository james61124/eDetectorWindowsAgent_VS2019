//#include "NTFS_Attribute.h"
//
//CAttrBase::CAttrBase(const ATTR_HEADER_COMMON* ahc, const CFileRecord* fr)
//{
//	_ASSERT(ahc);
//	_ASSERT(fr);
//
//	AttrHeader = ahc;
//	FileRecord = fr;
//
//	_SectorSize = fr->Volume->SectorSize;
//	_ClusterSize = fr->Volume->ClusterSize;
//	_IndexBlockSize = fr->Volume->IndexBlockSize;
//	_hVolume = fr->Volume->hVolume;
//}
//
//CAttrBase::~CAttrBase()
//{
//}
//
//__inline const ATTR_HEADER_COMMON* CAttrBase::GetAttrHeader() const
//{
//	return AttrHeader;
//}
//
//__inline DWORD CAttrBase::GetAttrType() const
//{
//	return AttrHeader->Type;
//}
//
//__inline DWORD CAttrBase::GetAttrTotalSize() const
//{
//	return AttrHeader->TotalSize;
//}
//
//__inline BOOL CAttrBase::IsNonResident() const
//{
//	return AttrHeader->NonResident;
//}
//
//__inline WORD CAttrBase::GetAttrFlags() const
//{
//	return AttrHeader->Flags;
//}
//
//// Get ANSI Attribute name
//// Return 0: Unnamed, <0: buffer too small, -buffersize, >0 Name length
//int CAttrBase::GetAttrName(char* buf, DWORD bufLen) const
//{
//	if (AttrHeader->NameLength)
//	{
//		if (bufLen < AttrHeader->NameLength)
//			return -1 * AttrHeader->NameLength;	// buffer too small
//
//		wchar_t* namePtr = (wchar_t*)((BYTE*)AttrHeader + AttrHeader->NameOffset);
//		int len = WideCharToMultiByte(CP_ACP, 0, namePtr, AttrHeader->NameLength,
//			buf, bufLen, NULL, NULL);
//		if (len)
//		{
//			buf[len] = '\0';
//			NTFS_TRACE1("Attribute name: %s\n", buf);
//			return len;
//		}
//		else
//		{
//			NTFS_TRACE("Unrecognized attribute name or Name buffer too small\n");
//			return -1 * AttrHeader->NameLength;
//		}
//	}
//	else
//	{
//		NTFS_TRACE("Attribute is unnamed\n");
//		return 0;
//	}
//}
//
//// Get UNICODE Attribute name
//// Return 0: Unnamed, <0: buffer too small, -buffersize, >0 Name length
//int CAttrBase::GetAttrName(wchar_t* buf, DWORD bufLen) const
//{
//	if (AttrHeader->NameLength)
//	{
//		if (bufLen < AttrHeader->NameLength)
//			return -1 * AttrHeader->NameLength;	// buffer too small
//
//		bufLen = AttrHeader->NameLength;
//		wchar_t* namePtr = (wchar_t*)((BYTE*)AttrHeader + AttrHeader->NameOffset);
//		wcsncpy_s(buf, bufLen + 1, namePtr, bufLen);
//		buf[bufLen] = '\0\0';
//
//		NTFS_TRACE("Unicode Attribute Name\n");
//		return bufLen;
//	}
//	else
//	{
//		NTFS_TRACE("Attribute is unnamed\n");
//		return 0;
//	}
//}
//
//// Verify if this attribute is unnamed
//// Useful in analyzing MultiStream files
//__inline BOOL CAttrBase::IsUnNamed() const
//{
//	return (AttrHeader->NameLength == 0);
//}
