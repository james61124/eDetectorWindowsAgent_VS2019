#include "socket_send.h"

SocketSend::SocketSend(Info* infoInstance) {
	info = infoInstance;
}

int SocketSend::SendDataToServer(char* Work, char* Mgs) {
	StrDataPacket GetServerMessage;
	strcpy_s(GetServerMessage.MAC, sizeof(GetServerMessage.MAC), info->MAC);
	strcpy_s(GetServerMessage.IP, sizeof(GetServerMessage.IP), info->IP);
	strcpy_s(GetServerMessage.UUID, sizeof(GetServerMessage.UUID), info->UUID);
	strcpy_s(GetServerMessage.DoWorking, sizeof(GetServerMessage.DoWorking), Work);
	strcpy_s(GetServerMessage.csMsg, sizeof(GetServerMessage.csMsg), Mgs);

	char* buff = (char*)&GetServerMessage;
	SetKeys(BIT128, AESKey);
	EncryptBuffer((BYTE*)buff, STRDATAPACKETSIZE);
	int ret = sendTCP(buff, STRDATAPACKETSIZE);
	return ret;
}

int SocketSend::SendMessageToServer(char* Work, char* Mgs) {
	StrPacket GetServerMessage;
	strcpy_s(GetServerMessage.MAC, sizeof(GetServerMessage.MAC), info->MAC);
	strcpy_s(GetServerMessage.IP, sizeof(GetServerMessage.IP), info->IP);
	strcpy_s(GetServerMessage.UUID, sizeof(GetServerMessage.UUID), info->UUID);

	char WorkNew[sizeof(Work)+1];
	strncpy_s(WorkNew, sizeof(WorkNew), Work, sizeof(Work));
	WorkNew[sizeof(WorkNew) - 1] = '\0';
	strcpy_s(GetServerMessage.DoWorking, sizeof(GetServerMessage.DoWorking), Work);
	strcpy_s(GetServerMessage.csMsg, sizeof(GetServerMessage.csMsg), Mgs);

	char* buff = (char*)&GetServerMessage;
	SetKeys(BIT128, AESKey);
	EncryptBuffer((BYTE*)buff, STRPACKETSIZE);
	int ret = sendTCP(buff, STRPACKETSIZE);
	printf("send %s\n", Work);
	//if (!ret) printf("send %s\n", GetServerMessage.DoWorking);
	//else printf("send function:%d %s %s %s %s\n", sizeof(GetServerMessage.MAC), Work, GetServerMessage.DoWorking, Mgs, GetServerMessage.csMsg);
	return ret;
}

bool SocketSend::sendTCP(char* data, long len) {
	int ret = send(*(info->tcpSocket), data, strlen(data), 0);
	if (ret) {

		std::cerr << "Error sending data: " << WSAGetLastError() << std::endl;
	}
	else {
		std::cout << "Data sent successfully." << std::endl;
	}

	return ret;
}