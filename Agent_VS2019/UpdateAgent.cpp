#include "UpdateAgent.h"

UpdateAgent::UpdateAgent(Info* infoInstance, SocketSend* socketSendInstance) {
	info = infoInstance;
	socketsend = socketSendInstance;
}
void UpdateAgent::DoTask() {
	char* null = new char[1];
	strcpy_s(null, 1, "");

	TCHAR* AgentNewVersion_exe = new TCHAR[MAX_PATH_EX];
	GetMyPath(AgentNewVersion_exe);
	_tcscat_s(AgentNewVersion_exe, MAX_PATH_EX, _T("\\ClientAgent.exe"));
	DeleteFile(AgentNewVersion_exe);

	SendMessagePacketToServer("ReadyUpdateAgent", null);
	//ReadyUpdateAgent(null);

	int fileSize = GiveUpdateInfo();
	std::thread AgentReceiveThread([&]() { AgentReceive(fileSize); });
	if (!fileSize) {
		log.logger("Error", "Error receiving New Agent Info");
	}
	//SendACK(null);
	SendMessagePacketToServer("DataRight", null);
	AgentReceiveThread.join();
	//SendACK(null);
	SendMessagePacketToServer("DataRight", null);

	log.logger("Info", "start update agent");

	RunProcess(AgentNewVersion_exe, NULL, FALSE, FALSE);

}
void UpdateAgent::WriteNewAgentToFile(char* buffer, int totalReceivedSize) {
	char* null = new char[1];
	strcpy_s(null, 1, "");
	TCHAR* AgentNewVersion_exe = new TCHAR[MAX_PATH_EX];
	GetMyPath(AgentNewVersion_exe);
	_tcscat_s(AgentNewVersion_exe, MAX_PATH_EX, _T("\\ClientAgent.exe"));
	std::ofstream outFile(AgentNewVersion_exe, std::ios::app | std::ios::binary);
	if (!outFile.is_open()) {
		log.logger("Error", "ClientAgent.exe open failed");
	}
	if (outFile.good()) {
		outFile.write(buffer, totalReceivedSize);
	}
	else {
		log.logger("Error", "Error write data into NewAgent");
	}
	outFile.close();
	//SendACK(null);
	SendMessagePacketToServer("DataRight", null);

}
void UpdateAgent::AgentReceive(int fileSize) {
	int alreadyReceived = 0;
	while (true) {

		uint64_t receivedSize = 0;
		int totalReceivedSize = 0;
		char* buffer = new char[STRDATAPACKETSIZE];

		while (totalReceivedSize < STRDATAPACKETSIZE) {
			char* tmpbuffer = new char[STRDATAPACKETSIZE];
			int bytesRead = recv(*info->tcpSocket, tmpbuffer, STRDATAPACKETSIZE, 0);
			if (bytesRead == -1) {
				log.logger("Error", "UpdateAgent Error receiving data");
				return;
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(500));
			memcpy(buffer + totalReceivedSize, tmpbuffer, bytesRead);
			totalReceivedSize += bytesRead;
			alreadyReceived += bytesRead;

		}
		alreadyReceived -= 100;

		SetKeys(BIT128, AESKey);
		DecryptBuffer((BYTE*)buffer, STRDATAPACKETSIZE);
		StrDataPacket* udata;
		udata = (StrDataPacket*)buffer;

		std::string Task(udata->DoWorking);
		std::string TaskMsg(udata->csMsg);
		std::string LogMsg = "Receive: " + Task;
		log.logger("Info", LogMsg);

		if (!strcmp(udata->DoWorking, "GiveUpdate")) {
			if (alreadyReceived > fileSize) {
				WriteNewAgentToFile(udata->csMsg, fileSize % 65436);
			}
			else {
				WriteNewAgentToFile(udata->csMsg, STRDATAPACKETSIZE - 100);
			}

		}
		else {
			break;
		}

		delete[] buffer;

	}
}

//int UpdateAgent::ReadyUpdateAgent(char* buff) {
//	char* functionName = new char[24];
//	strcpy_s(functionName, 24, "ReadyUpdateAgent");
//	printf("%s\n", buff);
//	return socketsend->SendMessageToServer(functionName, buff);
//}
//int UpdateAgent::SendACK(char* buff) {
//	char* functionName = new char[24];
//	strcpy_s(functionName, 24, "DataRight");
//	printf("%s\n", buff);
//	return socketsend->SendMessageToServer(functionName, buff);
//}
int UpdateAgent::GiveUpdateInfo() {
	char buff[STRPACKETSIZE];
	int ret = recv(*info->tcpSocket, buff, sizeof(buff), 0);

	if (ret == SOCKET_ERROR) {
		std::cerr << "Error receiving ACK: " << WSAGetLastError() << std::endl;
		return 0;
	}

	SetKeys(BIT128, AESKey);
	DecryptBuffer((BYTE*)buff, STRPACKETSIZE);

	StrPacket* udata;
	udata = (StrPacket*)buff;
	std::string Task(udata->DoWorking);
	std::string TaskMsg(udata->csMsg);
	std::string LogMsg = "Receive: " + Task + " " + TaskMsg;
	log.logger("Info", LogMsg);

	if (!strcmp(udata->DoWorking, "GiveUpdateInfo")) {
		return std::stoi(TaskMsg);
	}
	else {
		return 0;
	}
}
int UpdateAgent::GiveUpdateEnd() {
	char buff[STRPACKETSIZE];
	int ret = recv(*info->tcpSocket, buff, sizeof(buff), 0);

	if (ret == SOCKET_ERROR) {
		std::cerr << "Error receiving ACK: " << WSAGetLastError() << std::endl;
		return 0;
	}

	SetKeys(BIT128, AESKey);
	DecryptBuffer((BYTE*)buff, STRPACKETSIZE);

	StrPacket* udata;
	udata = (StrPacket*)buff;

	if (!strcmp(udata->DoWorking, "GiveUpdateEnd")) {
		return 1;
	}
	else {
		return 0;
	}
}
