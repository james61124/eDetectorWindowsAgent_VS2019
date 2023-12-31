#pragma once
#include <iostream>
#include <cstring>
#include <thread>
#include <vector>
#include <mutex>
#include <WinSock2.h>
#include <fstream>
#include <queue>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <tchar.h>
#include "GlobalFunction.h"

class Log{
public:

	//Log();
	//Log(Info* infoInstance, SocketSend* socketSendInstance);
	//void DoTask() override;

	std::queue<std::string>MsgQueue;
	std::mutex queueMutex;

	void logger(const std::string& level, const std::string& message);
	void HandleLogClientConnection(SOCKET clientSocket);
	void LogServer();
	void WriteToLogFile();
	void EnqueueMessage(const std::string& message);
	bool DequeueMessage(std::string& message);
	std::string GetTime();
};