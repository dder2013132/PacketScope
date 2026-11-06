@echo off
cd /d "%~dp0"

call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64

if errorlevel 1 exit /b 1

cl /nologo /W4 /utf-8 /std:c17 /Zi ^
/I"C:\Dev\npcap-sdk-1.17\Include" ^
/I"include" ^
/Fe:PacketScope.exe src\main.c src\capture.c src\parser.c ^
/link /LIBPATH:"C:\Dev\npcap-sdk-1.17\Lib\x64" wpcap.lib

if errorlevel 1 exit /b 1

echo BUILD SUCCESS!