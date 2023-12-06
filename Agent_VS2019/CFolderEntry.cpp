
#include "CFolderEntry.h"


int CFolderEntry::g_runningNum = 0;
// Analyze the Dir entry, and fill the data in the DMs
CFolderEntry::CFolderEntry(FATDirEntry aEntryToAnalyze, LFNEntry* aLFNEntries, WORD aNumLFNEntries)
:CEntry(aEntryToAnalyze, aLFNEntries, aNumLFNEntries)
{
}

CFolderEntry::CFolderEntry()
:CEntry()
{
}

CFolderEntry::~CFolderEntry(void)
{
}

void CFolderEntry::loadCount(int & retCount)
{
	DWORD dwChainedClustersSizeBytes = 0;
	//int retCount = 0;
	// First - Gets the size of the data
	if (!CVolumeAccess::getInstance()->readChainedClusters(getFirstClusterInDataChain(),NULL, &dwChainedClustersSizeBytes))
	{
		//printf("Couldn't load the folder information for \"%s\", Code: 0x%X\n", m_data.DIR_Name, GetLastError());
	}
	else if (dwChainedClustersSizeBytes == 0)
	{
		// The size is 0 if there's a corruption in the folder
		//TCHAR* name = getName();
		//_tprintf(_T("The folder \"%s\" is probably corrupted, because no data was found on this folder\n"), name);
		//delete[] name;
	}
	else
	{
		BYTE* bData = new BYTE[dwChainedClustersSizeBytes];
		if (!CVolumeAccess::getInstance()->readChainedClusters(getFirstClusterInDataChain(),bData, &dwChainedClustersSizeBytes))
		{
			printf("Couldn't load the folder's content for \"%s\", Code: 0x%X\n", m_data.DIR_Name, GetLastError());
		}
		else
		{		
			// We got all the sub-folders and files inside the bData, lets populate the lists..
			DWORD dwCurrDataPos = 0;
			// Read as long as we have more dir entries to read AND
			// We haven't passes the whole table
			while (dwChainedClustersSizeBytes-dwCurrDataPos >= sizeof(FATDirEntry) &&
					bData[dwCurrDataPos] != 0x00)
			{
				FATDirEntryUn fatCurrEntry;
				// Read the curr dir entry from bData
				memcpy(&fatCurrEntry, bData+dwCurrDataPos, sizeof(FATDirEntry));
				dwCurrDataPos += sizeof(FATDirEntry);
				// In case we're reading any special entry, like the volume id, or the "."\".." entries
				if (isSpecialEntry(fatCurrEntry))//SpecialEntry產生
				{
					//CSpecialEntry* specialEntry = new CSpecialEntry(fatCurrEntry.ShortEntry);
					//m_specialEntries.push_back(specialEntry);
				}
				else
				{
					LFNEntry* fatLFNEntries = NULL;
					WORD wNumOfLFNOrds = 0;
					// In case this is a LFN Entry - Load the LFN Entries to fatLFNEntries 
					// If the file is deleted - we'll not treat it like LFN if it was, and just
					// load each ord from the LFN as a short entry
					if (isLFNEntry(fatCurrEntry) && !isDeletedEntry(fatCurrEntry.ShortEntry))
					{
						if (!(fatCurrEntry.LongEntry.LDIR_Ord & LAST_LONG_ENTRY))
						{
							// Error! this is not a valid first lfn entry
						}
						else
						{
							// Get the last Ord, w/o the last entry mask
							wNumOfLFNOrds = fatCurrEntry.LongEntry.LDIR_Ord & (LAST_LONG_ENTRY ^ 0xFF);
							fatLFNEntries = new LFNEntry[wNumOfLFNOrds];
							fatLFNEntries[0] = fatCurrEntry.LongEntry;							
							// Read this LFN's rest of the parts 
							for (WORD wCurrOrd = 1; 
									(wCurrOrd < wNumOfLFNOrds) && 
									(dwChainedClustersSizeBytes-dwCurrDataPos >= sizeof(LFNEntry)); 
								++wCurrOrd)
							{
								memcpy(&fatLFNEntries[wCurrOrd], bData+dwCurrDataPos, sizeof(LFNEntry));
								dwCurrDataPos+=sizeof(LFNEntry);
							}

						}
						
						// The next entry, after the LFNs, must be the short file entry
						// We are making sure that the fatCurrEntry holds the short file entry
						memcpy(&fatCurrEntry, bData+dwCurrDataPos, sizeof(FATDirEntry));
						dwCurrDataPos+=sizeof(FATDirEntry);
					}

					if (isFolderEntry(fatCurrEntry))
					{
						//addNewSubFolder(fatCurrEntry.ShortEntry, fatLFNEntries, wNumOfLFNOrds);
						CFolderEntry* newEntry = new CFolderEntry(fatCurrEntry.ShortEntry, fatLFNEntries, wNumOfLFNOrds);
						
						if (!newEntry->isDeleted())
						{	
							SYSTEMTIME CT;
							SYSTEMTIME WT;
							SYSTEMTIME AT;
							if(newEntry->getFileTime(&CT,&WT,&AT) == 0)	
							{
								retCount++;
								newEntry->loadCount(retCount);
							}
						}
						else
						{
							SYSTEMTIME CT;
							SYSTEMTIME WT;
							SYSTEMTIME AT;
							if(newEntry->getFileTime(&CT,&WT,&AT) == 0)
							{	
								retCount++;
							}
						}
						delete newEntry;
					}
					// This is a FileEntry
					else
					{
						//addNewFile(fatCurrEntry.ShortEntry, fatLFNEntries, wNumOfLFNOrds);
						CFileEntry* newEntry = new CFileEntry(fatCurrEntry.ShortEntry, fatLFNEntries, wNumOfLFNOrds);
						if (!newEntry->isDeleted())
						{
							SYSTEMTIME CT;
							SYSTEMTIME WT;
							SYSTEMTIME AT;
							if(newEntry->getFileTime(&CT,&WT,&AT) == 0)
								retCount++;
						}
						else
						{
							SYSTEMTIME CT;
							SYSTEMTIME WT;
							SYSTEMTIME AT;
							if(newEntry->getFileTime(&CT,&WT,&AT) == 0)
							{	
								retCount++;
							}
						}
						delete newEntry;
					}
				}
				
			} // while
		}
		delete[] bData;
	}
}
BOOL CFolderEntry::GetRecoverInfo(unsigned int pIndex,TCHAR * pFileName,ULONGLONG & m_FileSize)
{
	BOOL ret = FALSE;
	DWORD dwChainedClustersSizeBytes = 0;
	// First - Gets the size of the data
	if (!CVolumeAccess::getInstance()->readChainedClusters(getFirstClusterInDataChain(),NULL, &dwChainedClustersSizeBytes))
	{
		//printf("Couldn't load the folder information for \"%s\", Code: 0x%X\n", m_data.DIR_Name, GetLastError());
	}
	else if (dwChainedClustersSizeBytes == 0)
	{
		// The size is 0 if there's a corruption in the folder
		//TCHAR* name = getName();
		//_tprintf(_T("The folder \"%s\" is probably corrupted, because no data was found on this folder\n"), name);
		//delete[] name;
	}
	else
	{
		BYTE* bData = new BYTE[dwChainedClustersSizeBytes];
		if (!CVolumeAccess::getInstance()->readChainedClusters(getFirstClusterInDataChain(),bData, &dwChainedClustersSizeBytes))
		{
			printf("Couldn't load the folder's content for \"%s\", Code: 0x%X\n", m_data.DIR_Name, GetLastError());
		}
		else
		{		
			// We got all the sub-folders and files inside the bData, lets populate the lists..
			DWORD dwCurrDataPos = 0;
			wstring DeleteName;
			// Read as long as we have more dir entries to read AND
			// We haven't passes the whole table
			while (dwChainedClustersSizeBytes-dwCurrDataPos >= sizeof(FATDirEntry) &&
					bData[dwCurrDataPos] != 0x00)
			{
				FATDirEntryUn fatCurrEntry;
				// Read the curr dir entry from bData
				memcpy(&fatCurrEntry, bData+dwCurrDataPos, sizeof(FATDirEntry));
				dwCurrDataPos += sizeof(FATDirEntry);
				// In case we're reading any special entry, like the volume id, or the "."\".." entries
				if (isSpecialEntry(fatCurrEntry))//SpecialEntry產生
				{
					//CSpecialEntry* specialEntry = new CSpecialEntry(fatCurrEntry.ShortEntry);
					//m_specialEntries.push_back(specialEntry);
				}
				else
				{
					LFNEntry* fatLFNEntries = NULL;
					WORD wNumOfLFNOrds = 0;
					// In case this is a LFN Entry - Load the LFN Entries to fatLFNEntries 
					// If the file is deleted - we'll not treat it like LFN if it was, and just
					// load each ord from the LFN as a short entry
					if (isLFNEntry(fatCurrEntry) && !isDeletedEntry(fatCurrEntry.ShortEntry))
					{
						if (!(fatCurrEntry.LongEntry.LDIR_Ord & LAST_LONG_ENTRY))
						{
							// Error! this is not a valid first lfn entry
						}
						else
						{
							// Get the last Ord, w/o the last entry mask
							wNumOfLFNOrds = fatCurrEntry.LongEntry.LDIR_Ord & (LAST_LONG_ENTRY ^ 0xFF);
							fatLFNEntries = new LFNEntry[wNumOfLFNOrds];
							fatLFNEntries[0] = fatCurrEntry.LongEntry;							
							// Read this LFN's rest of the parts 
							for (WORD wCurrOrd = 1; 
									(wCurrOrd < wNumOfLFNOrds) && 
									(dwChainedClustersSizeBytes-dwCurrDataPos >= sizeof(LFNEntry)); 
								++wCurrOrd)
							{
								memcpy(&fatLFNEntries[wCurrOrd], bData+dwCurrDataPos, sizeof(LFNEntry));
								dwCurrDataPos+=sizeof(LFNEntry);
							}

						}
						
						// The next entry, after the LFNs, must be the short file entry
						// We are making sure that the fatCurrEntry holds the short file entry
						memcpy(&fatCurrEntry, bData+dwCurrDataPos, sizeof(FATDirEntry));
						dwCurrDataPos+=sizeof(FATDirEntry);
					}

					if (isFolderEntry(fatCurrEntry))
					{
						//addNewSubFolder(fatCurrEntry.ShortEntry, fatLFNEntries, wNumOfLFNOrds);
						CFolderEntry* newEntry = new CFolderEntry(fatCurrEntry.ShortEntry, fatLFNEntries, wNumOfLFNOrds);
						
						if (!newEntry->isDeleted())
						{	
							SYSTEMTIME CT;
							SYSTEMTIME WT;
							SYSTEMTIME AT;
							if(newEntry->getFileTime(&CT,&WT,&AT) == 0)	
							{
								ret = newEntry->GetRecoverInfo(pIndex,pFileName,m_FileSize);
								if(ret)
									break;
							}
							
						}
						else
						{
							//SYSTEMTIME CT;
							//SYSTEMTIME WT;
							//SYSTEMTIME AT;
							//if(newEntry->getFileTime(&CT,&WT,&AT) == 0)
							//{	
							//	retCount++;
							//}
							DeleteName.clear();
						}
						delete newEntry;
					}
					// This is a FileEntry
					else
					{
						//addNewFile(fatCurrEntry.ShortEntry, fatLFNEntries, wNumOfLFNOrds);
						CFileEntry* newEntry = new CFileEntry(fatCurrEntry.ShortEntry, fatLFNEntries, wNumOfLFNOrds);
						if (!newEntry->isDeleted())
						{
							SYSTEMTIME CT;
							SYSTEMTIME WT;
							SYSTEMTIME AT;
							if(newEntry->getFileTime(&CT,&WT,&AT) == 0)
							{
								WCHAR * wtr = newEntry->getName();

								if(!_tcsicmp(wtr,pFileName))
								{
									DWORD m_ClusterIndex = newEntry->GetTheFirstDataCluster() +5;
									if(m_ClusterIndex == pIndex)
									{
										ret = TRUE;
										m_FileSize = newEntry->getFileSize();
									}
								}
								delete [] wtr;
								if(ret)
									break;
							}
						}
						else
						{
							SYSTEMTIME CT;
							SYSTEMTIME WT;
							SYSTEMTIME AT;
							if(newEntry->getFileTime(&CT,&WT,&AT) == 0)
							{	
								if(DeleteName.empty())
								{
									WCHAR * wtr = newEntry->getName();
									if(!_tcsicmp(wtr,pFileName))
									{
										DWORD m_ClusterIndex = newEntry->GetTheFirstDataCluster() +5;
										if(m_ClusterIndex == pIndex)
										{
											ret = TRUE;
											m_FileSize = newEntry->getFileSize();
										}
									}
									delete [] wtr;
									if(ret)
										break;
								}
								else
								{
									//_tcscpy_s(m_Info.FileName,_MAX_FNAME,DeleteName.c_str());
									if(!_tcsicmp(DeleteName.c_str(),pFileName))
									{
										DWORD m_ClusterIndex = newEntry->GetTheFirstDataCluster() +5;
										if(m_ClusterIndex == pIndex)
										{
											ret = TRUE;
											m_FileSize = newEntry->getFileSize();
										}
									}
									if(ret)
										break;
								}								
								DeleteName.clear();
							}
							else
							{
								wchar_t *buf1 = new wchar_t[14];
								memcpy((char *)buf1, fatCurrEntry.LongEntry.LDIR_Name1, 10);
								memcpy((char *)buf1 + 10, fatCurrEntry.LongEntry.LDIR_Name2, 12);
								memcpy((char *)buf1 + 22, fatCurrEntry.LongEntry.LDIR_Name3, 4);
								buf1[13] = L'\0';
								wchar_t * wtr = new wchar_t[256];
								if(DeleteName.empty())
									swprintf_s(wtr,256,L"%s",buf1);
								else
									swprintf_s(wtr,256,L"%s%s",buf1,DeleteName.c_str());
								DeleteName = wtr;
								delete [] wtr;
								delete [] buf1;
							}
						}
						delete newEntry;
					}
				}				
			} // while
			DeleteName.clear();
		}
		delete[] bData;
	}
	return ret;
}
BOOL CFolderEntry::FileRecover(void *argv,char* WorkStr,unsigned int pIndex,unsigned long pFileSize,char* pMAC,char* pIP)
{
	BOOL ret = FALSE;
	//TransportData * m_Client = (TransportData *)argv;

	////	HANDLE hf = CreateFile(newEntry->getName(), GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL, NULL);
	//if(pFileSize != 0 && pIndex>= 5)
	//{
	//	DWORD fClusterSize = CVolumeAccess::getInstance()->getClusterSize();
	//	BYTE * fData  = new BYTE[fClusterSize];
	//	BYTE * SendData  = new BYTE[BUFSIZE64];
	//	DWORD fCluster = (DWORD)pIndex-5;
	//	unsigned int ClusterSizeCount = 0;
	//	int counter = 0;
	//	while(counter*fClusterSize < pFileSize)
	//		counter++;
	//	for(int i = 0; i < counter; i++)
	//	{
	//		CVolumeAccess::getInstance()->readBytesFromDeviceCluster(fData,fClusterSize,fCluster+i);
	//		if(i < counter-1)
	//		{
	//			//WriteFile(hf,fData,fClusterSize,&resize,NULL);			
	//			for(unsigned int j = 0 ; j<fClusterSize;j++)
	//			{
	//				SendData[ClusterSizeCount+j] = fData[j];
	//			}
	//			ClusterSizeCount += fClusterSize;

	//			if(ClusterSizeCount >= BUFSIZE64)
	//			{
	//				int Sendret;
	//				Sendret = m_Client->SendDataBufToServer(pMAC,pIP,WorkStr,SendData);
	//				if(Sendret == 0 || Sendret == -1)
	//				{
	//					break;
	//				}
	//				ClusterSizeCount = 0;
	//				memset(SendData,'\x0',BUFSIZE64);
	//			}
	//		}
	//		else if(i == counter - 1)
	//		{
	//			//WriteFile(hf,fData,filesize-i*fClusterSize,&resize,NULL);
	//			for(unsigned int j = 0 ; j<(pFileSize-i*fClusterSize);j++)
	//			{
	//				SendData[ClusterSizeCount+j] = fData[j];
	//			}
	//			int Sendret;
	//			Sendret = m_Client->SendDataBufToServer(pMAC,pIP,WorkStr,SendData);
	//			if(Sendret == 0 || Sendret == -1)
	//			{
	//				break;
	//			}
	//			ret = TRUE;
	//		}
	//	}
	//	delete [] fData;
	//	delete [] SendData;
	//}
	return ret;
}
BOOL CFolderEntry::FileHashAndSignature(unsigned int pIndex,unsigned long pFileSize,TCHAR * m_FileName,TCHAR* HashStr,TCHAR* SignatureStr)
{
	BOOL ret = FALSE;
	BOOL IsSignature = FALSE;
	//	HANDLE hf = CreateFile(newEntry->getName(), GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL, NULL);
	if(pFileSize != 0)
	{
		HCRYPTPROV hProv = 0;
		HCRYPTHASH hHash = 0;
		BYTE rgbHash[16];
		DWORD cbHash = 0;
		CHAR rgbDigits[] = "0123456789abcdef";
		if (!CryptAcquireContext(&hProv,NULL, NULL,PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		{
			return FALSE;
		}
		if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
		{
			CryptReleaseContext(hProv, 0);
			return FALSE;
		}
		DWORD fClusterSize = CVolumeAccess::getInstance()->getClusterSize();
		BYTE * fData  = new BYTE[fClusterSize];
		//BYTE * SendData  = new BYTE[BUFSIZE64];
		DWORD fCluster = (DWORD)pIndex;
		//unsigned int ClusterSizeCount = 0;
		int counter = 0;
		while(counter*fClusterSize < pFileSize)
			counter++;
		for(int i = 0; i < counter; i++)
		{
			CVolumeAccess::getInstance()->readBytesFromDeviceCluster(fData,fClusterSize,fCluster+i);
			if(i < counter-1)
			{
				if(!IsSignature)
					IsSignature = IsPESignature(fData,(unsigned int)fClusterSize);
				if (!CryptHashData(hHash, fData, (unsigned int)fClusterSize, 0))
				{
					CryptReleaseContext(hProv, 0);
					CryptDestroyHash(hHash);	
					break;
				}
			}
			else if(i == counter - 1)
			{
				//WriteFile(hf,fData,filesize-i*fClusterSize,&resize,NULL);
				if(!IsSignature)
					IsSignature = IsPESignature(fData,(unsigned int)(pFileSize-i*fClusterSize));
				if (!CryptHashData(hHash, fData, (unsigned int)(pFileSize-i*fClusterSize), 0))
				{
					CryptReleaseContext(hProv, 0);
					CryptDestroyHash(hHash);	
					break;
				}
				ret = TRUE;
			}
		}
		delete [] fData;
		if(ret)
		{
			if(IsSignature)
			{
				if(IsPEExt(m_FileName))
					lstrcpy(SignatureStr,_T("Match"));
				else
					lstrcpy(SignatureStr,_T("Bad Signature"));
			}
			else
			{
				if(IsPEExt(m_FileName))
					lstrcpy(SignatureStr,_T("Not PE Format"));
				else
					lstrcpy(SignatureStr,_T("Match"));
			}
			cbHash = 16;
			if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
			{
				for (DWORD i = 0; i < cbHash; i++)
				{
					TCHAR* cstr = new TCHAR[10];
					swprintf_s(cstr,10,_T("%c%c"),rgbDigits[rgbHash[i] >> 4],rgbDigits[rgbHash[i] & 0xf]);
					lstrcat(HashStr,cstr);
					delete [] cstr;
				}
			}
			else
			{
				ret = FALSE;
			}
			CryptDestroyHash(hHash);
			CryptReleaseContext(hProv, 0);
		}
	}
	return ret;
}
bool CFolderEntry::load(void *argv, TCHAR* FileName,char* pMAC,char* pIP,DWORD FatherID,char * SendStr,unsigned int & pProgressCount,unsigned int & pCount,DWORD & pLastCluster,vector<DeleteFATFileInfo>* pDelInfo,clock_t & pStartTime)
{
	std::wofstream outFile(FileName, std::ios::app);
	DWORD dwChainedClustersSizeBytes = 0;
	// First - Gets the size of the data
	if (!CVolumeAccess::getInstance()->readChainedClusters(getFirstClusterInDataChain(),NULL, &dwChainedClustersSizeBytes))
	{
		printf("Couldn't load the folder information for \"%s\", Code: 0x%X\n", m_data.DIR_Name, GetLastError());
		log.logger("Error", "Couldn't load the folder information");
	}
	else if (dwChainedClustersSizeBytes == 0)
	{
		log.logger("Error", "The size is 0");
		// The size is 0 if there's a corruption in the folder
		//TCHAR* name = getName();
		//_tprintf(_T("The folder \"%s\" is probably corrupted, because no data was found on this folder\n"), name);
		//delete[] name;
	}
	else
	{
		BYTE* bData = new BYTE[dwChainedClustersSizeBytes];
		if (!CVolumeAccess::getInstance()->readChainedClusters(getFirstClusterInDataChain(),bData, &dwChainedClustersSizeBytes))
		{
			printf("Couldn't load the folder's content for \"%s\", Code: 0x%X\n", m_data.DIR_Name, GetLastError());
			log.logger("Error", "Couldn't load the folder's content");
		}
		else
		{	
			// We got all the sub-folders and files inside the bData, lets populate the lists..
			DWORD dwCurrDataPos = 0;
			wstring DeleteName;
			// Read as long as we have more dir entries to read AND
			// We haven't passes the whole table
			while (dwChainedClustersSizeBytes-dwCurrDataPos >= sizeof(FATDirEntry) && bData[dwCurrDataPos] != 0x00) {
				//printf("bData[dwCurrDataPos]-%x\n",bData[dwCurrDataPos]);
				FATDirEntryUn fatCurrEntry;
				
				// Read the curr dir entry from bData
				memcpy(&fatCurrEntry, bData+dwCurrDataPos, sizeof(FATDirEntry));
				dwCurrDataPos += sizeof(FATDirEntry);

				// In case we're reading any special entry, like the volume id, or the "."\".." entries
				if (isSpecialEntry(fatCurrEntry))//SpecialEntry產生
				{
					//CSpecialEntry* specialEntry = new CSpecialEntry(fatCurrEntry.ShortEntry);
					//m_specialEntries.push_back(specialEntry);
				}
				else
				{
					LFNEntry* fatLFNEntries = NULL;
					WORD wNumOfLFNOrds = 0;

					// In case this is a LFN Entry - Load the LFN Entries to fatLFNEntries 
					// If the file is deleted - we'll not treat it like LFN if it was, and just
					// load each ord from the LFN as a short entry
					if (isLFNEntry(fatCurrEntry) && !isDeletedEntry(fatCurrEntry.ShortEntry))
					{
						if (!(fatCurrEntry.LongEntry.LDIR_Ord & LAST_LONG_ENTRY))
						{
							// Error! this is not a valid first lfn entry
						}
						else
						{
							// Get the last Ord, w/o the last entry mask
							wNumOfLFNOrds = fatCurrEntry.LongEntry.LDIR_Ord & (LAST_LONG_ENTRY ^ 0xFF);

							//printf("fatCurrEntry.LongEntry.LDIR_Ord-%x\n",fatCurrEntry.LongEntry.LDIR_Ord);
							fatLFNEntries = new LFNEntry[wNumOfLFNOrds];
							fatLFNEntries[0] = fatCurrEntry.LongEntry;
							
							//printf("sizeof(LFNEntry)-%u\n",sizeof(LFNEntry));
							// Read this LFN's rest of the parts 
							for (WORD wCurrOrd = 1; 
									(wCurrOrd < wNumOfLFNOrds) && 
									(dwChainedClustersSizeBytes-dwCurrDataPos >= sizeof(LFNEntry)); 
								++wCurrOrd)
							{
								memcpy(&fatLFNEntries[wCurrOrd], bData+dwCurrDataPos, sizeof(LFNEntry));
								dwCurrDataPos+=sizeof(LFNEntry);
							}

						}
						
						// The next entry, after the LFNs, must be the short file entry
						// We are making sure that the fatCurrEntry holds the short file entry
						memcpy(&fatCurrEntry, bData+dwCurrDataPos, sizeof(FATDirEntry));
						dwCurrDataPos+=sizeof(FATDirEntry);
					}

					if (isFolderEntry(fatCurrEntry))
					{
						//addNewSubFolder(fatCurrEntry.ShortEntry, fatLFNEntries, wNumOfLFNOrds);
						CFolderEntry* newEntry = new CFolderEntry(fatCurrEntry.ShortEntry, fatLFNEntries, wNumOfLFNOrds);
						
						if (!newEntry->isDeleted())
						{	
							SYSTEMTIME CT;
							SYSTEMTIME WT;
							SYSTEMTIME AT;
							if(newEntry->getFileTime(&CT,&WT,&AT) == 0)
							{	
								

								wchar_t *wstr = new wchar_t[1024];
								WCHAR * wtr = newEntry->getName();
								//DWORD FirstCluster = newEntry->GetTheFirstDataCluster()+5;
								DWORD FirstCluster = pLastCluster;

								wchar_t* create_time = SystemTimeToUnixTime(CT);
								wchar_t* write_time = SystemTimeToUnixTime(WT);
								wchar_t* access_time = SystemTimeToUnixTime(AT);
								swprintf_s(wstr, 1024, L"%s|0|2|%s|%s|%s|null,null|0|%lu|%lu\n",
									wtr, create_time, write_time, access_time, FatherID, FirstCluster);

								//swprintf_s(wstr,1024,L"%lu|%s|%lu|0|2|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|null,null,null|0|1\n", FirstCluster,wtr,
								////swprintf_s(wstr, 1024, L"%lu|%s|%lu|0|2|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|null,null,null|0|1\n", pLastCluster, wtr,
								//	FatherID,CT.wYear,CT.wMonth,CT.wDay,CT.wHour,CT.wMinute,CT.wSecond,
								//	WT.wYear,WT.wMonth,WT.wDay,WT.wHour,WT.wMinute,WT.wSecond,
								//	AT.wYear,AT.wMonth,AT.wDay,AT.wHour,AT.wMinute,AT.wSecond);
								char* m_DataStr = CStringToCharArray(wstr,CP_UTF8);
								strcat_s(SendStr,DATASTRINGMESSAGELEN,m_DataStr);
								//if(pLastCluster<FirstCluster) pLastCluster = FirstCluster;
								pLastCluster++;
								pProgressCount++;
								pCount++;
								if((pCount % 60)==0 && pCount>=60)
								{
									//int ret = m_Client->SendDataMsgToServer(pMAC,pIP,"GiveExplorerData",SendStr);
									int ret = 1;
									if (outFile.good()) outFile << SendStr;
									if(ret == 0 || ret == -1)
									{
										delete [] m_DataStr;
										delete [] wtr;
										delete [] wstr;
										return false;
									}
									memset(SendStr,'\0',DATASTRINGMESSAGELEN);
								}
								clock_t endTime = clock();
								if((endTime-pStartTime) > 300000)
								{
									char * ProgressStr = new char[10];
									sprintf_s(ProgressStr,10,"%u",pProgressCount);
									//strcat_s(SendStr,DATASTRINGMESSAGELEN,ProgressStr);
									if (outFile.good()) outFile << SendStr;
									int ret = 1;
									//int ret = m_Client->SendDataMsgToServer(pMAC,pIP,"GiveExplorerData",SendStr);
									if(ret == 0 || ret == -1)
									{
										delete [] ProgressStr;
										delete [] m_DataStr;
										delete [] wtr;
										delete [] wstr;
										return false;
									}
									pStartTime = clock();
									pCount = 0;
									memset(SendStr,'\0',DATASTRINGMESSAGELEN);
									delete [] ProgressStr;
								}
								else
								{
									if((pCount % 60)==0 && pCount>=60)
									{
										char * ProgressStr = new char[10];
										sprintf_s(ProgressStr,10,"%u",pProgressCount);
										//strcat_s(SendStr,DATASTRINGMESSAGELEN,ProgressStr);
										//int ret = m_Client->SendDataMsgToServer(pMAC,pIP,"GiveExplorerData",SendStr);
										if (outFile.good()) outFile << SendStr;
										int ret = 1;
										if(ret == 0 || ret == -1)
										{
											delete [] ProgressStr;
											delete [] m_DataStr;
											delete [] wtr;
											delete [] wstr;
											return false;
										}
										pStartTime = clock();
										pCount = 0;
										memset(SendStr,'\0',DATASTRINGMESSAGELEN);
										delete [] ProgressStr;
									}
								}
								delete [] m_DataStr;
								delete [] wtr;
								delete [] wstr;

								//if(!newEntry->load(argv, pMAC,pIP,FirstCluster,SendStr,pProgressCount,pCount,pLastCluster,pDelInfo,pStartTime)) return false;
								if (!newEntry->load(argv, FileName, pMAC, pIP, pLastCluster-1, SendStr, pProgressCount, pCount, pLastCluster, pDelInfo, pStartTime)) return false;
							}
						}
						else
						{
							SYSTEMTIME CT;
							SYSTEMTIME WT;
							SYSTEMTIME AT;
							if(newEntry->getFileTime(&CT,&WT,&AT) == 0)
							{	
								DeleteFATFileInfo m_Info;
								if(DeleteName.empty())
								{
									WCHAR * wtr = newEntry->getName();
									_tcscpy_s(m_Info.FileName,_MAX_FNAME,wtr);
									delete [] wtr;
								}
								else
									_tcscpy_s(m_Info.FileName,_MAX_FNAME,DeleteName.c_str());

								//m_Info.FirstDataCluster = newEntry->GetTheFirstDataCluster();
								m_Info.FirstDataCluster = pLastCluster;
								pLastCluster++;

								m_Info.isDirectory = 2;
								m_Info.ParentFirstDataCluster = FatherID;
								m_Info.CT = CT;
								m_Info.WT = WT;
								m_Info.AT = AT;
								m_Info.FileSize = 0;
								pDelInfo->push_back(m_Info);
								DeleteName.clear();
							}
						}
						delete newEntry;
					}
					// This is a FileEntry
					else
					{
						CFileEntry* newEntry = new CFileEntry(fatCurrEntry.ShortEntry, fatLFNEntries, wNumOfLFNOrds);
						if (!newEntry->isDeleted())
						{
							SYSTEMTIME CT;
							SYSTEMTIME WT;
							SYSTEMTIME AT;
							if(newEntry->getFileTime(&CT,&WT,&AT) == 0)
							{	
								wchar_t *wstr = new wchar_t[1024];
								WCHAR * wtr = newEntry->getName();
								TCHAR* m_MD5Str = new TCHAR[50];
								memset(m_MD5Str,'\0',50);
								TCHAR * Signaturestr = new TCHAR[20];
								memset(Signaturestr,'\0',20);
								//DWORD FirstCluster = newEntry->GetTheFirstDataCluster()+5;
								DWORD FirstCluster = pLastCluster;
								wchar_t* create_time = SystemTimeToUnixTime(CT);
								wchar_t* write_time = SystemTimeToUnixTime(WT);
								wchar_t* access_time = SystemTimeToUnixTime(AT);

								/*wchar_t* create_time = SystemTimeToUnixTime((*it).CT);
								wchar_t* write_time = SystemTimeToUnixTime((*it).WT);
								wchar_t* access_time = SystemTimeToUnixTime((*it).AT);
								swprintf_s(wstr, 1024, L"%s|1|%d|%s|%s|%s|%s,%s|%lu|%lu|%lu\n",
									(*it).FileName, (*it).isDirectory
									, create_time, write_time, access_time, m_MD5Str, Signaturestr, (*it).FileSize, (*it).ParentFirstDataCluster, LastCluster);*/


								if(FileHashAndSignature(newEntry->GetTheFirstDataCluster(),newEntry->getFileSize(),wtr,m_MD5Str,Signaturestr))
								{
									swprintf_s(wstr, 1024, L"%s|0|0|%s|%s|%s|%s,%s|%lu|%lu|%lu\n",
										wtr, create_time, write_time, access_time, m_MD5Str, Signaturestr, newEntry->getFileSize(), FatherID, FirstCluster);

									//swprintf_s(wstr,1024,L"%lu|%s|%lu|0|0|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%s,%s,null|%lu|1\n",FirstCluster,wtr,
									//	//swprintf_s(wstr, 1024, L"%lu|%s|%lu|0|0|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%s,%s,null|%lu|1\n", pLastCluster, wtr,
									//	FatherID,CT.wYear,CT.wMonth,CT.wDay,CT.wHour,CT.wMinute,CT.wSecond,
									//	WT.wYear,WT.wMonth,WT.wDay,WT.wHour,WT.wMinute,WT.wSecond,
									//	AT.wYear,AT.wMonth,AT.wDay,AT.wHour,AT.wMinute,AT.wSecond,m_MD5Str,Signaturestr,newEntry->getFileSize());
								}
								else
								{
									swprintf_s(wstr, 1024, L"%s|0|0|%s|%s|%s|null,null|%lu|%lu|%lu\n",
										wtr, create_time, write_time, access_time, newEntry->getFileSize(), FatherID, FirstCluster);

									//swprintf_s(wstr,1024,L"%lu|%s|%lu|0|0|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|null,null,null|%lu|1\n",FirstCluster,wtr,
									//	//swprintf_s(wstr, 1024, L"%lu|%s|%lu|0|0|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%s,%s,null|%lu|1\n", pLastCluster, wtr,
									//	FatherID,CT.wYear,CT.wMonth,CT.wDay,CT.wHour,CT.wMinute,CT.wSecond,
									//	WT.wYear,WT.wMonth,WT.wDay,WT.wHour,WT.wMinute,WT.wSecond,
									//	AT.wYear,AT.wMonth,AT.wDay,AT.wHour,AT.wMinute,AT.wSecond,newEntry->getFileSize());
								}

								delete [] Signaturestr;
								delete [] m_MD5Str;
								char* m_DataStr = CStringToCharArray(wstr,CP_UTF8);
								strcat_s(SendStr,DATASTRINGMESSAGELEN,m_DataStr);
								//if(pLastCluster<FirstCluster) pLastCluster = FirstCluster;
								pLastCluster++;
								pProgressCount++;
								pCount++;
								clock_t endTime = clock();
								if((endTime-pStartTime) > 300000)
								{
									char * ProgressStr = new char[10];
									sprintf_s(ProgressStr,10,"%u",pProgressCount);
									strcat_s(SendStr,DATASTRINGMESSAGELEN,ProgressStr);
									if (outFile.good()) outFile << SendStr;
									int ret = 1;
									//int ret = m_Client->SendDataMsgToServer(pMAC,pIP,"GiveExplorerData",SendStr);
									if(ret == 0 || ret == -1)
									{
										delete [] ProgressStr;
										delete [] m_DataStr;
										delete [] wtr;
										delete [] wstr;
										return false;
									}
									pStartTime = clock();
									pCount = 0;
									memset(SendStr,'\0',DATASTRINGMESSAGELEN);
									delete [] ProgressStr;
								}
								else
								{
									if((pCount % 60)==0 && pCount>=60)
									{
										char * ProgressStr = new char[10];
										sprintf_s(ProgressStr,10,"%u",pProgressCount);
										//strcat_s(SendStr,DATASTRINGMESSAGELEN,ProgressStr);
										if (outFile.good()) outFile << SendStr;
										int ret = 1;
										//int ret = m_Client->SendDataMsgToServer(pMAC,pIP,"GiveExplorerData",SendStr);
										if(ret == 0 || ret == -1)
										{
											delete [] ProgressStr;
											delete [] m_DataStr;
											delete [] wtr;
											delete [] wstr;
											return false;
										}
										pStartTime = clock();
										pCount = 0;
										memset(SendStr,'\0',DATASTRINGMESSAGELEN);
										delete [] ProgressStr;
									}
								}
								delete [] m_DataStr;
								delete [] wtr;
								delete [] wstr;
							}
						}
						else
						{
							SYSTEMTIME CT;
							SYSTEMTIME WT;
							SYSTEMTIME AT;
							if(newEntry->getFileTime(&CT,&WT,&AT) == 0)
							{	
								DeleteFATFileInfo m_Info;
								if(DeleteName.empty())
								{
									WCHAR * wtr = newEntry->getName();
									_tcscpy_s(m_Info.FileName,_MAX_FNAME,wtr);
									delete [] wtr;
								}
								else
									_tcscpy_s(m_Info.FileName,_MAX_FNAME,DeleteName.c_str());

								//m_Info.FirstDataCluster = newEntry->GetTheFirstDataCluster();

								m_Info.FirstDataCluster = pLastCluster;
								pLastCluster++;

								m_Info.isDirectory = 0;
								m_Info.ParentFirstDataCluster = FatherID;
								m_Info.CT = CT;
								m_Info.WT = WT;
								m_Info.AT = AT;
								m_Info.FileSize = newEntry->getFileSize();
								pDelInfo->push_back(m_Info);
								
								DeleteName.clear();
							}
							else
							{
								wchar_t *buf1 = new wchar_t[14];
								memcpy((char *)buf1, fatCurrEntry.LongEntry.LDIR_Name1, 10);
								memcpy((char *)buf1 + 10, fatCurrEntry.LongEntry.LDIR_Name2, 12);
								memcpy((char *)buf1 + 22, fatCurrEntry.LongEntry.LDIR_Name3, 4);
								buf1[13] = L'\0';
								wchar_t * wtr = new wchar_t[256];
								if(DeleteName.empty())
									swprintf_s(wtr,256,L"%s",buf1);
								else
									swprintf_s(wtr,256,L"%s%s",buf1,DeleteName.c_str());
								DeleteName = wtr;
								delete [] wtr;
								delete [] buf1;
							}
						}
						delete newEntry;
					}
				}
				
			} // while
			DeleteName.clear();
		}
		delete[] bData;
	}
	//outFile.close();
	return true;
}
bool CFolderEntry::LoadScanExplorer(void *argv,char* pMAC,char* pIP,char * SendStr,unsigned int & pProgressCount,unsigned int & pCount,DWORD & pLastCluster,vector<DeleteFATFileInfo>* pDelInfo,clock_t & pStartTime,ScanExplorerInfo * pInfo,TCHAR* pFilePath)
{
	//TransportData * m_Client = (TransportData *)argv;
	//DWORD dwChainedClustersSizeBytes = 0;
	//// First - Gets the size of the data
	//if (!CVolumeAccess::getInstance()->readChainedClusters(getFirstClusterInDataChain(),NULL, &dwChainedClustersSizeBytes))
	//{
	//	printf("Couldn't load the folder information for \"%s\", Code: 0x%X\n", m_data.DIR_Name, GetLastError());
	//}
	//else if (dwChainedClustersSizeBytes == 0)
	//{
	//	// The size is 0 if there's a corruption in the folder
	//	//TCHAR* name = getName();
	//	//_tprintf(_T("The folder \"%s\" is probably corrupted, because no data was found on this folder\n"), name);
	//	//delete[] name;
	//}
	//else
	//{
	//	BYTE* bData = new BYTE[dwChainedClustersSizeBytes];
	//	if (!CVolumeAccess::getInstance()->readChainedClusters(getFirstClusterInDataChain(),bData, &dwChainedClustersSizeBytes))
	//	{
	//		printf("Couldn't load the folder's content for \"%s\", Code: 0x%X\n", m_data.DIR_Name, GetLastError());
	//	}
	//	else
	//	{		
	//		// We got all the sub-folders and files inside the bData, lets populate the lists..
	//		DWORD dwCurrDataPos = 0;
	//		wstring DeleteName;
	//		// Read as long as we have more dir entries to read AND
	//		// We haven't passes the whole table
	//		while (dwChainedClustersSizeBytes-dwCurrDataPos >= sizeof(FATDirEntry) &&
	//				bData[dwCurrDataPos] != 0x00)
	//		{//printf("bData[dwCurrDataPos]-%x\n",bData[dwCurrDataPos]);

	//			FATDirEntryUn fatCurrEntry;
	//			
	//			// Read the curr dir entry from bData
	//			memcpy(&fatCurrEntry, bData+dwCurrDataPos, sizeof(FATDirEntry));
	//			dwCurrDataPos += sizeof(FATDirEntry);

	//			// In case we're reading any special entry, like the volume id, or the "."\".." entries
	//			if (isSpecialEntry(fatCurrEntry))//SpecialEntry產生
	//			{
	//				//CSpecialEntry* specialEntry = new CSpecialEntry(fatCurrEntry.ShortEntry);
	//				//m_specialEntries.push_back(specialEntry);
	//			}
	//			else
	//			{
	//				LFNEntry* fatLFNEntries = NULL;
	//				WORD wNumOfLFNOrds = 0;

	//				// In case this is a LFN Entry - Load the LFN Entries to fatLFNEntries 
	//				// If the file is deleted - we'll not treat it like LFN if it was, and just
	//				// load each ord from the LFN as a short entry
	//				if (isLFNEntry(fatCurrEntry) && !isDeletedEntry(fatCurrEntry.ShortEntry))
	//				{
	//					if (!(fatCurrEntry.LongEntry.LDIR_Ord & LAST_LONG_ENTRY))
	//					{
	//						// Error! this is not a valid first lfn entry
	//					}
	//					else
	//					{
	//						// Get the last Ord, w/o the last entry mask
	//						wNumOfLFNOrds = fatCurrEntry.LongEntry.LDIR_Ord & (LAST_LONG_ENTRY ^ 0xFF);

	//						//printf("fatCurrEntry.LongEntry.LDIR_Ord-%x\n",fatCurrEntry.LongEntry.LDIR_Ord);
	//						fatLFNEntries = new LFNEntry[wNumOfLFNOrds];
	//						fatLFNEntries[0] = fatCurrEntry.LongEntry;
	//						
	//						//printf("sizeof(LFNEntry)-%u\n",sizeof(LFNEntry));
	//						// Read this LFN's rest of the parts 
	//						for (WORD wCurrOrd = 1; 
	//								(wCurrOrd < wNumOfLFNOrds) && 
	//								(dwChainedClustersSizeBytes-dwCurrDataPos >= sizeof(LFNEntry)); 
	//							++wCurrOrd)
	//						{
	//							memcpy(&fatLFNEntries[wCurrOrd], bData+dwCurrDataPos, sizeof(LFNEntry));
	//							dwCurrDataPos+=sizeof(LFNEntry);
	//						}

	//					}
	//					
	//					// The next entry, after the LFNs, must be the short file entry
	//					// We are making sure that the fatCurrEntry holds the short file entry
	//					memcpy(&fatCurrEntry, bData+dwCurrDataPos, sizeof(FATDirEntry));
	//					dwCurrDataPos+=sizeof(FATDirEntry);
	//				}

	//				if (isFolderEntry(fatCurrEntry))
	//				{
	//					//addNewSubFolder(fatCurrEntry.ShortEntry, fatLFNEntries, wNumOfLFNOrds);
	//					CFolderEntry* newEntry = new CFolderEntry(fatCurrEntry.ShortEntry, fatLFNEntries, wNumOfLFNOrds);
	//					
	//					if (!newEntry->isDeleted())
	//					{	
	//						SYSTEMTIME CT;
	//						SYSTEMTIME WT;
	//						SYSTEMTIME AT;
	//						if(newEntry->getFileTime(&CT,&WT,&AT) == 0)
	//						{	WCHAR * wtr = newEntry->getName();
	//							pProgressCount++;
	//							TCHAR * NewFilePath = new TCHAR[MAX_PATH_EX];
	//							swprintf_s(NewFilePath,MAX_PATH_EX,_T("%s%s\\"),pFilePath,wtr);

	//							if(!newEntry->LoadScanExplorer(argv,pMAC,pIP,SendStr,pProgressCount,pCount,pLastCluster,pDelInfo,pStartTime,pInfo,NewFilePath))
	//							{	
	//								delete [] NewFilePath;
	//								delete [] wtr;
	//								return false;
	//							}
	//							delete [] NewFilePath;
	//							delete [] wtr;
	//						}
	//					}
	//					else
	//					{
	//						SYSTEMTIME CT;
	//						SYSTEMTIME WT;
	//						SYSTEMTIME AT;
	//						if(newEntry->getFileTime(&CT,&WT,&AT) == 0)
	//						{	
	//							pProgressCount++;
	//						}
	//					}
	//					delete newEntry;
	//				}
	//				// This is a FileEntry
	//				else
	//				{
	//					CFileEntry* newEntry = new CFileEntry(fatCurrEntry.ShortEntry, fatLFNEntries, wNumOfLFNOrds);
	//					if (!newEntry->isDeleted())
	//					{
	//						SYSTEMTIME CT;
	//						SYSTEMTIME WT;
	//						SYSTEMTIME AT;
	//						if(newEntry->getFileTime(&CT,&WT,&AT) == 0)
	//						{	
	//							if(newEntry->getFileSize() <= pInfo->MAXSize && newEntry->getFileSize() >0)
	//							{
	//								WCHAR * wtr = newEntry->getName();
	//								if(!lstrcmp(pInfo->KeywordStr,_T("*")))
	//								{
	//									wchar_t *wstr = new wchar_t[1024];
	//									TCHAR* m_MD5Str = new TCHAR[50];
	//									memset(m_MD5Str,'\0',50);
	//									TCHAR * Signaturestr = new TCHAR[20];
	//									memset(Signaturestr,'\0',20);
	//									TCHAR * NewFilePath = new TCHAR[MAX_PATH_EX];
	//									swprintf_s(NewFilePath,MAX_PATH_EX,_T("%s%s"),pFilePath,wtr);
	//									DWORD FirstCluster = newEntry->GetTheFirstDataCluster()+5;
	//									if(FileHashAndSignature(newEntry->GetTheFirstDataCluster(),newEntry->getFileSize(),wtr,m_MD5Str,Signaturestr))
	//									{
	//										swprintf_s(wstr,1024,L"%c|0|%lu|%s|%s|%s|0\n",pInfo->Drive,FirstCluster,m_MD5Str,wtr,NewFilePath);
	//									}
	//									else
	//									{
	//										swprintf_s(wstr,1024,L"%c|0|%lu|null|%s|%s|0\n",pInfo->Drive,FirstCluster,wtr,NewFilePath);
	//									}
	//									pProgressCount++;
	//									pCount++;
	//									delete [] NewFilePath;
	//									delete [] Signaturestr;
	//									delete [] m_MD5Str;

	//									char* m_DataStr = CStringToCharArray(wstr,CP_UTF8);
	//									strcat_s(SendStr,DATASTRINGMESSAGELEN,m_DataStr);
	//									if(pLastCluster<FirstCluster)
	//										pLastCluster = FirstCluster;
	//									
	//									clock_t endTime = clock();
	//									if((endTime-pStartTime) > 300000)
	//									{
	//										char * ProgressStr = new char[10];
	//										sprintf_s(ProgressStr,10,"%u",pProgressCount);
	//										strcat_s(SendStr,DATASTRINGMESSAGELEN,ProgressStr);
	//										int ret = m_Client->SendDataMsgToServer(pMAC,pIP,"ScanExplorerData",SendStr);
	//										if(ret == 0 || ret == -1)
	//										{
	//											delete [] ProgressStr;
	//											delete [] m_DataStr;
	//											delete [] wtr;
	//											delete [] wstr;
	//											return false;
	//										}
	//										pStartTime = clock();
	//										pCount = 0;
	//										memset(SendStr,'\0',DATASTRINGMESSAGELEN);
	//										delete [] ProgressStr;
	//									}
	//									else
	//									{
	//										if((pCount % 60)==0 && pCount>=60)
	//										{
	//											char * ProgressStr = new char[10];
	//											sprintf_s(ProgressStr,10,"%u",pProgressCount);
	//											strcat_s(SendStr,DATASTRINGMESSAGELEN,ProgressStr);
	//											int ret = m_Client->SendDataMsgToServer(pMAC,pIP,"ScanExplorerData",SendStr);
	//											if(ret == 0 || ret == -1)
	//											{
	//												delete [] ProgressStr;
	//												delete [] m_DataStr;
	//												delete [] wtr;
	//												delete [] wstr;
	//												return false;
	//											}
	//											pStartTime = clock();
	//											pCount = 0;
	//											memset(SendStr,'\0',DATASTRINGMESSAGELEN);
	//											delete [] ProgressStr;
	//										}
	//									}
	//									delete [] m_DataStr;
	//									delete [] wtr;
	//									delete [] wstr;
	//								}
	//								else
	//								{
	//									if(MatchKeyword(pInfo->KeywordStr,wtr))
	//									{
	//										wchar_t *wstr = new wchar_t[1024];
	//										TCHAR* m_MD5Str = new TCHAR[50];
	//										memset(m_MD5Str,'\0',50);
	//										TCHAR * Signaturestr = new TCHAR[20];
	//										memset(Signaturestr,'\0',20);
	//										TCHAR * NewFilePath = new TCHAR[MAX_PATH_EX];
	//										swprintf_s(NewFilePath,MAX_PATH_EX,_T("%s%s"),pFilePath,wtr);
	//										DWORD FirstCluster = newEntry->GetTheFirstDataCluster()+5;
	//										if(FileHashAndSignature(newEntry->GetTheFirstDataCluster(),newEntry->getFileSize(),wtr,m_MD5Str,Signaturestr))
	//										{
	//											swprintf_s(wstr,1024,L"%c|0|%lu|%s|%s|%s|0\n",pInfo->Drive,FirstCluster,m_MD5Str,wtr,NewFilePath);
	//										}
	//										else
	//										{
	//											swprintf_s(wstr,1024,L"%c|0|%lu|null|%s|%s|0\n",pInfo->Drive,FirstCluster,wtr,NewFilePath);
	//										}
	//										pProgressCount++;
	//										pCount++;
	//										delete [] NewFilePath;
	//										delete [] Signaturestr;
	//										delete [] m_MD5Str;

	//										char* m_DataStr = CStringToCharArray(wstr,CP_UTF8);
	//										strcat_s(SendStr,DATASTRINGMESSAGELEN,m_DataStr);
	//										if(pLastCluster<FirstCluster)
	//											pLastCluster = FirstCluster;
	//									
	//										clock_t endTime = clock();
	//										if((endTime-pStartTime) > 300000)
	//										{
	//											char * ProgressStr = new char[10];
	//											sprintf_s(ProgressStr,10,"%u",pProgressCount);
	//											strcat_s(SendStr,DATASTRINGMESSAGELEN,ProgressStr);
	//											int ret = m_Client->SendDataMsgToServer(pMAC,pIP,"ScanExplorerData",SendStr);
	//											if(ret == 0 || ret == -1)
	//											{
	//												delete [] ProgressStr;
	//												delete [] m_DataStr;
	//												delete [] wtr;
	//												delete [] wstr;
	//												return false;
	//											}
	//											pStartTime = clock();
	//											pCount = 0;
	//											memset(SendStr,'\0',DATASTRINGMESSAGELEN);
	//											delete [] ProgressStr;
	//										}
	//										else
	//										{
	//											if((pCount % 60)==0 && pCount>=60)
	//											{
	//												char * ProgressStr = new char[10];
	//												sprintf_s(ProgressStr,10,"%u",pProgressCount);
	//												strcat_s(SendStr,DATASTRINGMESSAGELEN,ProgressStr);
	//												int ret = m_Client->SendDataMsgToServer(pMAC,pIP,"ScanExplorerData",SendStr);
	//												if(ret == 0 || ret == -1)
	//												{
	//													delete [] ProgressStr;
	//													delete [] m_DataStr;
	//													delete [] wtr;
	//													delete [] wstr;
	//													return false;
	//												}
	//												pStartTime = clock();
	//												pCount = 0;
	//												memset(SendStr,'\0',DATASTRINGMESSAGELEN);
	//												delete [] ProgressStr;
	//											}
	//										}
	//										delete [] m_DataStr;
	//										delete [] wtr;
	//										delete [] wstr;
	//									}
	//								}						
	//							}
	//						}
	//					}
	//					else
	//					{
	//						SYSTEMTIME CT;
	//						SYSTEMTIME WT;
	//						SYSTEMTIME AT;
	//						if(newEntry->getFileTime(&CT,&WT,&AT) == 0)
	//						{	
	//							DeleteFATFileInfo m_Info = {0};
	//							if(DeleteName.empty())
	//							{
	//								WCHAR * wtr = newEntry->getName();
	//								_tcscpy_s(m_Info.FileName,_MAX_FNAME,wtr);
	//								delete [] wtr;
	//							}
	//							else
	//								_tcscpy_s(m_Info.FileName,_MAX_FNAME,DeleteName.c_str());

	//							swprintf_s(m_Info.FilePath,MAX_PATH_EX,_T("%s%s"),pFilePath,m_Info.FileName);
	//							m_Info.FirstDataCluster = newEntry->GetTheFirstDataCluster();
	//							m_Info.isDirectory = 0;
	//							m_Info.FileSize = newEntry->getFileSize();
	//							pDelInfo->push_back(m_Info);
	//							DeleteName.clear();
	//						}
	//						else
	//						{
	//							wchar_t *buf1 = new wchar_t[14];
	//							memcpy((char *)buf1, fatCurrEntry.LongEntry.LDIR_Name1, 10);
	//							memcpy((char *)buf1 + 10, fatCurrEntry.LongEntry.LDIR_Name2, 12);
	//							memcpy((char *)buf1 + 22, fatCurrEntry.LongEntry.LDIR_Name3, 4);
	//							buf1[13] = L'\0';
	//							wchar_t * wtr = new wchar_t[256];
	//							if(DeleteName.empty())
	//								swprintf_s(wtr,256,L"%s",buf1);
	//							else
	//								swprintf_s(wtr,256,L"%s%s",buf1,DeleteName.c_str());
	//							DeleteName = wtr;
	//							delete [] wtr;
	//							delete [] buf1;
	//						}
	//					}
	//					delete newEntry;
	//				}
	//			}
	//			
	//		} // while
	//		DeleteName.clear();
	//	}
	//	delete[] bData;
	//}
	return true;
}
DWORD CFolderEntry::getFirstClusterInDataChain()
{
	// Gets the first cluster number
	DWORD dwFirstCluster = 0x00000000;
	dwFirstCluster |= m_data.DIR_FstClusHi;
	dwFirstCluster <<= 16;
	dwFirstCluster |= m_data.DIR_FstClusLo;

	return dwFirstCluster;
}
