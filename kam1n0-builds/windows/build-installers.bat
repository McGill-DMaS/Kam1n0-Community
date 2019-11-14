@echo off

call "D:\Program Files (x86)\Microsoft Visual Studio\2017\Community\Common7\Tools\VsDevCmd.bat"

SET KAM_DIST=%~dp0bins\server
SET KAM_IDA_DIST=%~dp0bins\ida-plugin

devenv %~dp0installer-src-32-64\Kam1n0WinInstaller3264.sln /rebuild Release

if errorlevel 0 (
    rd /s /q %~dp0\bins\installer\
	mkdir %~dp0\bins\installer\
	xcopy /s %~dp0installer-src-32-64\PluginInstaller\bin\Release\Kam1n0-IDA-Plugin.exe %~dp0\bins\installer\
	xcopy /s %~dp0installer-src-32-64\ServerInstaller\bin\Release\Kam1n0-Server.exe %~dp0\bins\installer\
) else (
	echo installer build failure.
        exit /b 1
)
	
