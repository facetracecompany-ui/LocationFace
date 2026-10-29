@echo off
cd /d %~dp0
go build -ldflags "-H=windowsgui -s -w" -o locationface.exe .

