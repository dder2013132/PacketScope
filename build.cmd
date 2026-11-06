@echo off
cd /d "%~dp0"

call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64

if errorlevel 1 exit /b 1

if /I "%~1"=="console" goto BUILD_CONSOLE
if /I "%~1"=="gui" goto BUILD_GUI

echo ERROR: Choose console or gui
exit /b 1

:BUILD_CONSOLE
echo Building PacketScope Console...

cl /nologo /W4 /utf-8 /std:c17 /Zi ^
/I"C:\Dev\npcap-sdk-1.17\Include" ^
/I"include" ^
/Fe:PacketScope.exe src\main.c src\capture.c src\parser.c ^
/link /LIBPATH:"C:\Dev\npcap-sdk-1.17\Lib\x64" wpcap.lib

if errorlevel 1 exit /b 1
goto BUILD_SUCCESS

:BUILD_GUI
echo Building PacketScope GUI...

cl /nologo /W4 /utf-8 /std:c17 /Zi ^
/I"C:\Dev\npcap-sdk-1.17\Include" ^
/I"include" ^
/Fe:PacketScopeGUI.exe src\gui_main.c src\gui.c src\capture.c ^
/link /LIBPATH:"C:\Dev\npcap-sdk-1.17\Lib\x64" wpcap.lib user32.lib

if errorlevel 1 exit /b 1
goto BUILD_SUCCESS

:BUILD_SUCCESS
echo BUILD SUCCESS!
exit /b 0