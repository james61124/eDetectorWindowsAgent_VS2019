#include "socket_send.h"

SocketSend::SocketSend() {}

SocketSend::SocketSend(Info* infoInstance) {
	info = infoInstance;
}

int SocketSend::SendDataToServer(char* Work, char* Mgs, SOCKET* tcpSocket) {

	StrDataPacket GetServerMessage;
	strcpy_s(GetServerMessage.MAC, sizeof(GetServerMessage.MAC), info->MAC);
	strcpy_s(GetServerMessage.IP, sizeof(GetServerMessage.IP), info->IP);
	strcpy_s(GetServerMessage.UUID, sizeof(GetServerMessage.UUID), info->UUID);

	//strcpy_s(GetServerMessage.MAC, sizeof(GetServerMessage.MAC), "0.0.0.0");
	//strcpy_s(GetServerMessage.IP, sizeof(GetServerMessage.IP), "0.0.0.0");
	//strcpy_s(GetServerMessage.UUID, sizeof(GetServerMessage.UUID), "5c28d30aedfd4329bf04d895838d59df");

	char WorkNew[24];
	strcpy_s(WorkNew, sizeof(WorkNew), Work);
	WorkNew[strlen(Work)] = '\0';

	strcpy_s(GetServerMessage.DoWorking, sizeof(GetServerMessage.DoWorking), WorkNew);
	memcpy(GetServerMessage.csMsg, Mgs, sizeof(GetServerMessage.csMsg));

	char* buff = (char*)&GetServerMessage;

	SetKeys(BIT128, AESKey);
	EncryptBuffer((BYTE*)buff, STRDATAPACKETSIZE);

	if (sendTCP(buff, STRDATAPACKETSIZE, tcpSocket)) {
		printf("Send Data Packet: %s\n", Work);
	}
	else {
		std::cerr << "Error sending data packet: " << WSAGetLastError() << std::endl;
	}
	

	return receiveTCP(tcpSocket);
	

	//delete[] Work;
	//delete[] Mgs;

	//return ret;
}

int SocketSend::SendMessageToServer(char* Work, char* Mgs, SOCKET* tcpSocket) {
	StrPacket GetServerMessage;
	strcpy_s(GetServerMessage.MAC, sizeof(GetServerMessage.MAC), info->MAC);
	strcpy_s(GetServerMessage.IP, sizeof(GetServerMessage.IP), info->IP);
	strcpy_s(GetServerMessage.UUID, sizeof(GetServerMessage.UUID), info->UUID);

	//strcpy_s(GetServerMessage.MAC, sizeof(GetServerMessage.MAC), "0.0.0.0");
	//strcpy_s(GetServerMessage.IP, sizeof(GetServerMessage.IP), "0.0.0.0");
	//strcpy_s(GetServerMessage.UUID, sizeof(GetServerMessage.UUID), "5c28d30aedfd4329bf04d895838d59df");

	//char* WorkNew = new char[24];
	char WorkNew[24];
	strcpy_s(WorkNew, sizeof(WorkNew), Work);
	WorkNew[strlen(Work)] = '\0';
	//printf("sizeof newwork %d %s", sizeof(WorkNew), WorkNew);
	

	strcpy_s(GetServerMessage.DoWorking, sizeof(GetServerMessage.DoWorking), WorkNew);
	strcpy_s(GetServerMessage.csMsg, sizeof(GetServerMessage.csMsg), Mgs);

	char* buff = (char*)&GetServerMessage;

	SetKeys(BIT128, AESKey);
	EncryptBuffer((BYTE*)buff, STRPACKETSIZE);

	int ret = sendTCP(buff, STRPACKETSIZE, tcpSocket);

	//std::string LogMessage = "send -> " + std::string(Work) + " : " + std::string(Mgs) + "\n";
	//tool.log(LogMessage);
	printf("Send Message Packet: %s\n", Work);

	delete[] Work;
	delete[] Mgs;
	//if (!ret) printf("send %s\n", GetServerMessage.DoWorking);
	//else printf("send function:%d %s %s %s %s\n", sizeof(GetServerMessage.MAC), Work, GetServerMessage.DoWorking, Mgs, GetServerMessage.csMsg);
	return ret;
}

bool SocketSend::sendTCP(char* data, long len, SOCKET* tcpSocket) {
	//printf("data\n");
	//for (int i = 100; i < 200; ++i) {
	//	printf("%02X ", data[i]);
	//	if ((i + 1) % 16 == 0)
	//		printf("\n");
	//}
	//printf("\n");

	int ret = send(*tcpSocket, data, len, 0);
	if (ret == -1) {
		std::cerr << "Error sending data: " << WSAGetLastError() << std::endl;
	}
	else {
		//std::cout << "Data sent successfully." << std::endl;
	}

	return ret;
}

int SocketSend::receiveTCP(SOCKET* tcpSocket) {
	while (true) {
		char buff[STRPACKETSIZE];
		int ret = recv(*tcpSocket, buff, sizeof(buff), 0);

		if (ret == SOCKET_ERROR) {
			std::cerr << "Error receiving ACK: " << WSAGetLastError() << std::endl;
			return 0;
		}

		SetKeys(BIT128, AESKey);
		DecryptBuffer((BYTE*)buff, STRPACKETSIZE);

		StrPacket* udata;
		udata = (StrPacket*)buff;

		printf("task receive %s\n", udata->DoWorking);
		if (!strcmp(udata->DoWorking, "DataRight")) {
			return 1;
		}
		else {
			return 0;
		}
	}
	

	return 1;


}