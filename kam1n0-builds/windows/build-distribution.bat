@echo off

rd /s /q %~dp0\bins

mkdir %~dp0\bins\
mkdir %~dp0\bins\server\
mkdir %~dp0\bins\ida-plugin\

cd /D %~dp0\..\..\kam1n0
echo %~dp0\..\..\kam1n0


::initialize error flag to undefined
set hasErrors=0

call mvn -DskipTests clean
echo Exit Code = %ERRORLEVEL%
if not "%ERRORLEVEL%" == "0" exit /b 1

call mvn -DskipTests package
echo Exit Code = %ERRORLEVEL%
if not "%ERRORLEVEL%" == "0" exit /b 1


if errorlevel 0  (
    cd %~dp0
    echo maven build succeeded
    xcopy /s %~dp0\..\..\kam1n0\build-bins %~dp0\bins\server
    xcopy %~dp0\bins-additional %~dp0\bins\server
    xcopy /s %~dp0\..\..\kam1n0-clients\ida-plugin %~dp0\bins\ida-plugin
	del /s /q /f %~dp0\bins\server\lib\*.so 
    echo Distribution build completed. Please find windows distribution on %~dp0\bins\.
    exit /b 0
) else (
    echo maven build failure. 
	cd %~dp0
    exit /b 1
)
