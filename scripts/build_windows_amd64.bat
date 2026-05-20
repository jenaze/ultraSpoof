@echo off
setlocal
cd /d "%~dp0.."
set CGO_ENABLED=0

set GOOS=windows
set GOARCH=amd64
go build -trimpath -ldflags="-s -w" -o ultraSpoof.exe .\cmd\ultraSpoof
if errorlevel 1 exit /b 1
echo built: .\ultraSpoof.exe (windows/amd64)

set GOOS=linux
set GOARCH=amd64
go build -trimpath -ldflags="-s -w" -o ultraSpoof .\cmd\ultraSpoof
if errorlevel 1 exit /b 1
echo built: .\ultraSpoof (linux/amd64)

@REM set GOOS=linux
@REM set GOARCH=arm64
@REM go build -trimpath -ldflags="-s -w" -o ultraSpoof_linux_arm64 .\cmd\ultraSpoof
@REM if errorlevel 1 exit /b 1
@REM echo built: .\ultraSpoof_linux_arm64 (linux/arm64)
