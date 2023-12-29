#include "DumpProcess.h"


DumpProcess::DumpProcess(Info* infoInstance, SocketSend* socketSendInstance, int pid) {
	info = infoInstance;
	socketsend = socketSendInstance;

	filename = new TCHAR[MAX_PATH_EX];
	GetMyPath(filename);
	_tcscat_s(filename, MAX_PATH_EX, DumpProcess_txt_filename);
	DeleteFile(filename);

	zip_filename = new TCHAR[MAX_PATH_EX];
	GetMyPath(zip_filename);
	_tcscat_s(zip_filename, MAX_PATH_EX, DumpProcess_zip_filename);
	DeleteFile(zip_filename);

	outFile.open(filename, std::ios::app);
	if (!outFile.is_open()) log.logger("Error", "DumpProcess.txt open failed");

	*hz = CreateZip(zip_filename, 0);
	if (hz == 0) log.logger("Error", "Failed to create DumpProcess.zip");

	ProcessID = pid;

}

void DumpProcess::DoTask() {

	MemProcess* m_MemPro = new MemProcess;
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, ProcessID);
	if (!hProc) {
		log.logger("Error", "process not found or doesn't have enough permission");
	}

#ifndef _M_IX86
	SIZE_T ptype = m_MemPro->Process32or64(hProc);
	if (!ptype) {
		log.logger("Error", "IsWow64Process failed.");
		CloseHandle(hProc);
		return;
	}
	SIZE_T startmem = 0;
	SIZE_T maxmem = 0x7FFF0000;
	if (ptype == 64) maxmem = 0x7FFFFFEFFFF;
#else
	SIZE_T ptype = 32;
	SIZE_T startmem = 0;
	SIZE_T maxmem = 0x7FFF0000;
#endif
	int count = 0;
	wchar_t lastfilename[MAX_PATH];
	while (startmem < maxmem) {
		MEMORY_BASIC_INFORMATION mbi;
		SIZE_T size = VirtualQueryEx(hProc, (LPVOID)startmem, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
		if (!size) {
			CloseHandle(hProc);
			return;
		}
		TCHAR* output = new TCHAR[_MAX_FNAME];
		TCHAR* m_FileName = new TCHAR[_MAX_FNAME];
#ifndef _M_IX86
		if (startmem, ptype == 64) swprintf_s(output, _MAX_FNAME, _T("%016I64X-%016I64X.bin"), startmem, (SIZE_T)mbi.BaseAddress + mbi.RegionSize);
		else swprintf_s(output, _MAX_FNAME, _T("%08I64X-%08I64X.bin"), startmem, (SIZE_T)mbi.BaseAddress + mbi.RegionSize);
#else
		swprintf_s(output, _MAX_FNAME, _T("%08I64X-%08I64X.bin"), startmem, (SIZE_T)mbi.BaseAddress + mbi.RegionSize);
#endif
		if (mbi.State == MEM_COMMIT)
		{
			char* buffer = new char[mbi.RegionSize];
			SIZE_T nread = 0;
			ReadProcessMemory(hProc, mbi.BaseAddress, buffer, mbi.RegionSize, &nread);
			swprintf_s(m_FileName, _MAX_FNAME, _T("%.3d_%s"), count, output);
			if (nread == mbi.RegionSize)
			{
				bool typeok = false;

				// check permission
				/*if (pInfo->ReadMode)
				{
					if (((mbi.AllocationProtect & PAGE_READONLY) ||
						(mbi.AllocationProtect & PAGE_READWRITE) ||
						(mbi.AllocationProtect & PAGE_WRITECOPY) ||
						(mbi.AllocationProtect & PAGE_EXECUTE_READ) ||
						(mbi.AllocationProtect & PAGE_EXECUTE_READWRITE) ||
						(mbi.AllocationProtect & PAGE_EXECUTE_WRITECOPY))
						)
					{
						typeok = true;
					}
				}
				if (pInfo->WriteMode)
				{
					if (((mbi.AllocationProtect & PAGE_READWRITE) ||
						(mbi.AllocationProtect & PAGE_WRITECOPY) ||
						(mbi.AllocationProtect & PAGE_EXECUTE_READWRITE) ||
						(mbi.AllocationProtect & PAGE_EXECUTE_WRITECOPY))
						)
					{
						typeok = true;
					}
				}
				if (pInfo->ExecuteMode)
				{
					if (((mbi.AllocationProtect & PAGE_EXECUTE) ||
						(mbi.AllocationProtect & PAGE_EXECUTE_READ) ||
						(mbi.AllocationProtect & PAGE_EXECUTE_READWRITE) ||
						(mbi.AllocationProtect & PAGE_EXECUTE_WRITECOPY))
						)
					{
						typeok = true;
					}
				}*/

				typeok = true;
				if (typeok) {
					if (m_MemPro->GetProcessMappedFileName(hProc, mbi.BaseAddress, lastfilename))
						swprintf_s(m_FileName, _MAX_FNAME, _T("%s"), lastfilename);
					char* cFileName = CStringToCharArray(m_FileName, CP_UTF8);
					double precentage = (double)100 * startmem / maxmem;
					unsigned int m_Progress = (unsigned int)precentage;
					int Sendret = 1;
					char* InfoStr = new char[MAX_PATH_EX];
#ifndef _M_IX86
					sprintf_s(InfoStr, MAX_PATH_EX, "%llu|%u|%s", mbi.RegionSize, m_Progress, cFileName);
#else
					sprintf_s(InfoStr, MAX_PATH_EX, "%lu|%u|%s", mbi.RegionSize, m_Progress, cFileName);
#endif

					TCHAR* DumpProcess_txt = new TCHAR[MAX_PATH_EX];
					GetMyPath(DumpProcess_txt);
					_tcscat_s(DumpProcess_txt, MAX_PATH_EX, m_FileName);
					std::wofstream DumpProcessFile;
					DumpProcessFile.open(DumpProcess_txt, std::ios::app);
					if (!DumpProcessFile.is_open()) log.logger("Error", "DumpProcess.bin open failed");
					
					// InfoStr useless ?
					BYTE* TmpBuffer1 = new BYTE[STRDATAPACKETSIZE];
					memset(TmpBuffer1, '\x0', STRDATAPACKETSIZE);
					memcpy(TmpBuffer1, InfoStr, strlen(InfoStr));
					delete[] TmpBuffer1;
					delete[] InfoStr;

					if (mbi.RegionSize > STRDATAPACKETSIZE) {
						SIZE_T tmplen = mbi.RegionSize;
						for (SIZE_T i = 0; i < mbi.RegionSize; i += STRDATAPACKETSIZE) {
							BYTE* TmpBuffer = new BYTE[STRDATAPACKETSIZE];
							memset(TmpBuffer, '\x00', STRDATAPACKETSIZE);
							if (tmplen < STRDATAPACKETSIZE) memcpy(TmpBuffer, buffer + i, tmplen);
							else {
								memcpy(TmpBuffer, buffer + i, STRDATAPACKETSIZE);
								tmplen -= STRDATAPACKETSIZE;
							}

							char* charBuffer = reinterpret_cast<char*>(TmpBuffer);
							if (DumpProcessFile.good()) DumpProcessFile << charBuffer;
							else log.logger("Error", "write to DumpProcessFile failed.");
							delete[] TmpBuffer;
						}
					}
					else {
						BYTE* TmpBuffer = new BYTE[STRDATAPACKETSIZE];
						memset(TmpBuffer, '\x00', STRDATAPACKETSIZE);
						memcpy(TmpBuffer, buffer, mbi.RegionSize);

						char* charBuffer = reinterpret_cast<char*>(TmpBuffer);
						if (DumpProcessFile.good()) DumpProcessFile << charBuffer;
						else log.logger("Error", "write to DumpProcessFile failed.");
						delete[] TmpBuffer;
					}
					delete[] cFileName;
					count++;

					DumpProcessFile.close();
					if (ZipAdd(*hz, m_FileName, DumpProcess_txt) != 0) {
						int bufferSize = WideCharToMultiByte(CP_UTF8, 0, DumpProcess_txt, -1, nullptr, 0, nullptr, nullptr);
						char* buffer = new char[bufferSize];
						WideCharToMultiByte(CP_UTF8, 0, DumpProcess_txt, -1, buffer, bufferSize, nullptr, nullptr);
						std::string result(buffer);

						string LogMsg = "failed to add " + result + " to zip";
						log.logger("Error", LogMsg);
						continue;
					}
					DeleteFile(DumpProcess_txt);

				}
			}
		}
		startmem = (SIZE_T)mbi.BaseAddress + (SIZE_T)mbi.RegionSize;
		delete[] m_FileName;
		delete[] output;
	}
	CloseHandle(hProc);

	// send zip file
	SendFileToServer("DumpProcess", zip_filename, info->tcpSocket);
	DeleteFile(zip_filename);
	CloseZip(*hz);
}