@echo off
setlocal 

for %%i in ("python.exe") do set PY_ENV_EXE=%%~$PATH:i 
FOR %%a IN ("%PY_ENV_EXE:~0,-1%") DO SET PY_ENV_HOME=%%~dpa
echo hello
echo %PY_ENV_HOME%
echo %PY_ENV_EXE%


SET PYTHON_EXE=%PY_ENV_EXE%
SET PYTHON_PIPY=%PY_ENV_HOME%\Scripts\pip.exe
echo %PYTHON_EXE%
echo %PYTHON_PIPY%

if not exist %PYTHON_PIPY% (
    echo "%PYTHON_EXE%" get-pip.py --no-index --find-links=.
	"%PYTHON_EXE%" get-pip.py --no-index --find-links=.
)

if exist %PYTHON_PIPY% (
	"%PYTHON_EXE%" -c "import sys; sys.exit(64) if sys.maxsize > 2**32 else sys.exit(32)"
	if errorlevel 64 (
		echo "%PYTHON_PIPY%" install cefpython3-66.1-py2.py3-none-win_amd64.whl
		"%PYTHON_PIPY%" install cefpython3-66.1-py2.py3-none-win_amd64.whl
	)
	if errorlevel 32  (
		echo "%PYTHON_PIPY%" install cefpython3-66.1-py2.py3-none-win32.whl
		"%PYTHON_PIPY%" install cefpython3-66.1-py2.py3-none-win32.whl
	)
)



