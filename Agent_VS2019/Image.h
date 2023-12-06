#pragma once

#include "AllTask.h"

namespace fs = std::filesystem;

struct ImageType {
    char path[512];
    char APPTYPE[512];
    char filename[512];
};

class Image : public AllTask {
public:

    Image(Info* infoInstance, SocketSend* socketSendInstance, char* input_cmd);
    void DoTask() override;

    void SearchForFile(std::filesystem::path root, std::filesystem::path directory, std::filesystem::path::const_iterator start, std::filesystem::path::const_iterator finish, const std::string& targetFile, HZIP* hz);
    std::string ToUpper(const std::string& str);

    char* cmd;
};
