@echo off

cd z3
RD /s /q build
python scripts/mk_make.py -x -s --java
cd build
where nmake
nmake /S /F Makefile
copy /Y libz3.dll ..\\..\\..\\kam1n0-resources\\bin\\lib\\libz3.dll
copy /Y libz3java.dll ..\\..\\..\\kam1n0-resources\\bin\\lib\\libz3java.dll
mvn install:install-file -Dfile=com.microsoft.z3.jar -DgroupId=com.microsoft -DartifactId=z3 -Dversion=0.0.1 -Dpackaging=jar -DlocalRepositoryPath=..\local-m2-repo
