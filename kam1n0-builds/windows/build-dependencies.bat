@echo off


SET SYM=%~dp0\..\..\kam1n0\kam1n0-symbolic\
call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvars64.bat"

cd /D %SYM%
echo %SYM%

echo "Building LibVex..."
make -s -f vex-make-any
echo Exit Code = %ERRORLEVEL%
if not "%ERRORLEVEL%" == "0" (
	cd /D %~dp0
	exit /b 1
)

echo "Building z3..."
cd /D %SYM%
call z3-build.bat
echo Exit Code = %ERRORLEVEL%
if not "%ERRORLEVEL%" == "0" (
	cd /D %~dp0
	exit /b 1
)

exit /b 0
