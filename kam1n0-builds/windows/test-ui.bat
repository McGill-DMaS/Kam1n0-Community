@echo off

cd /D %~dp0\..\..\kam1n0
echo %~dp0\..\..\kam1n0

::download chromedriver from http://chromedriver.chromium.org/
::need to set webdriver.chrome.driver in env vars

call mvn -DskipTests clean
call mvn -DskipTests package
call mvn -DskipTests package
call mvn -DforkMode=never test

