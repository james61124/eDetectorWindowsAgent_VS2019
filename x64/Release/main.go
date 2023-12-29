package main

import (
	"github.com/gin-gonic/gin"
	"os"
	"os/exec"
	"log"
	"net/http"
	"path/filepath"
	"fmt"
	"github.com/google/uuid"
)

type GenerateExeRequest struct {
	IP          string `json:"ip"`
	Port        string `json:"port"`
	DetectPort  string `json:"detect_port"`
	Version  string `json:"version"`
}

func main() {
	router := gin.Default()

	router.POST("/agent", func(c *gin.Context) {
		var request GenerateExeRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		fmt.Printf("%s %s %s %s ", request.IP, request.Port, request.DetectPort, request.Version)
		exeFile := generateExe(request.IP, request.Port, request.DetectPort, request.Version)

		c.Writer.Header().Set("Content-Disposition", "attachment; filename=example.exe")
		c.Writer.Header().Set("Content-Type", "application/octet-stream")
		c.File(exeFile)

		err := os.Remove(exeFile)
		if err != nil {
			fmt.Println("Error deleting file:", err)
			return
		}
	})

	router.Run(":8080")
}

func generateUniqueFileName() string {
	newUUID := uuid.New()
	uniqueFileName := newUUID.String()

	return uniqueFileName
}

func generateExe(ip string, port string, detectPort string, version string) string {

	exeDir := filepath.Dir("./")
	generateExeDir := filepath.Dir("./")

	oldExePath := filepath.Join(exeDir, "Agent.exe")
	generateExePath := filepath.Join(generateExeDir, "AgentGenerator.exe")

	newName := generateUniqueFileName()
	newExePath := filepath.Join(exeDir, newName)

	err := os.Rename(oldExePath, newExePath)
	if err != nil {
		fmt.Println("Error renaming file:", err)
	}
	
	// generateExePath := "C:/james/eDetectorWindowsAgent_VS2019/x64/Release/AgentGenerator.exe"
	// generateExePath := filepath.Join(exeDir, "AgentGenerator.exe")
	
	// run AgentGenerator.exe
	if _, err := os.Stat(generateExePath); err != nil {
		log.Fatalf("Failed to find AgentGenerator.exe: %v", err)
	}
	cmd := exec.Command("./AgentGenerator.exe", ip, port, detectPort, version)

	if err := cmd.Run(); err != nil {
		log.Fatalf("Failed to run command: %v", err)
	} else {
		fmt.Println("Command executed successfully")
	}

	// 檢查 Agent.exe 是否已生成
	if _, err := os.Stat(newExePath); err != nil {
		log.Fatalf("Failed to generate Agent.exe: %v", err)
	}

	return newExePath
}