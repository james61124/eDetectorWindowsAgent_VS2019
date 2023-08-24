#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "Log.h"

void Log::logger(const std::string& level, const std::string& message) {
    WSADATA wsData;
    if (WSAStartup(MAKEWORD(2, 2), &wsData) != 0) {
        std::cerr << "Failed to initialize Winsock." << std::endl;
        return;
    }

    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "Error creating client socket." << std::endl;
        WSACleanup();
        return;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(12345);
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Error connecting to server." << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return;
    }

    std::string timestamp = GetTime();
    std::string MsgToSend = timestamp + " [" + level + "] " + message;

    if (send(clientSocket, MsgToSend.c_str(), MsgToSend.length(), 0) == SOCKET_ERROR) {
        std::cerr << "Error sending message." << std::endl;
    }

    closesocket(clientSocket);
    WSACleanup();
}

void Log::HandleLogClientConnection(SOCKET clientSocket) {

    char buffer[1024];
    int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (bytesReceived > 0) {
        std::string message(buffer, bytesReceived);
        EnqueueMessage(message);
        //MsgQueue.push(message);
    }
    closesocket(clientSocket);
}

void Log::WriteToLogFile() {
    std::ofstream outputFile("log.txt", std::ios::app);
    while (true) {
        if (!MsgQueue.empty()) {
            if (outputFile.is_open()) {
                std::string message;
                DequeueMessage(message);
                outputFile << message << std::endl;
            }
            else {
                std::cerr << "Error opening file for writing." << std::endl;
            }
        }
    }
    outputFile.close();
}

void Log::LogServer() {
    std::remove("log.txt");

    WSADATA wsData;
    if (WSAStartup(MAKEWORD(2, 2), &wsData) != 0) {
        std::cerr << "Failed to initialize Winsock." << std::endl;
        return;
    }

    SOCKET listeningSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listeningSocket == INVALID_SOCKET) {
        std::cerr << "Error creating listening socket." << std::endl;
        WSACleanup();
        return;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(12345);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listeningSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Error binding socket." << std::endl;
        closesocket(listeningSocket);
        WSACleanup();
        return;
    }

    if (listen(listeningSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Error listening on socket." << std::endl;
        closesocket(listeningSocket);
        WSACleanup();
        return;
    }

    std::thread LogThread([&]() { WriteToLogFile(); });
    LogThread.detach();

    
    while (true) {
        sockaddr_in clientAddr;
        int clientAddrSize = sizeof(clientAddr);
        SOCKET clientSocket = accept(listeningSocket, (sockaddr*)&clientAddr, &clientAddrSize);
        if (clientSocket != INVALID_SOCKET) {
            std::cout << "New client connected." << std::endl;
            std::thread LogReceiveThread([&]() { HandleLogClientConnection(clientSocket); });
            LogReceiveThread.detach();
        }
        else {
            std::cerr << "Error accepting client connection." << std::endl;
        }
    }

    closesocket(listeningSocket);
    WSACleanup();
}



void Log::EnqueueMessage(const std::string& message) {
    std::lock_guard<std::mutex> lock(queueMutex);
    MsgQueue.push(message);
}

bool Log::DequeueMessage(std::string& message) {
    std::lock_guard<std::mutex> lock(queueMutex);
    if (!MsgQueue.empty()) {
        message = MsgQueue.front();
        MsgQueue.pop();
        return true;
    }
    return false;
}

std::string Log::GetTime() {
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    std::time_t timeT = std::chrono::system_clock::to_time_t(now);
    std::tm localTm;
    localtime_s(&localTm, &timeT);

    std::ostringstream formattedTime;
    formattedTime << std::put_time(&localTm, "%Y-%m-%d %H:%M:%S");

    return formattedTime.str();
}