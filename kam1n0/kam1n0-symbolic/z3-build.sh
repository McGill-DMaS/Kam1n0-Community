#!/bin/sh
echo $(pwd)
cd z3
rm -rf build
python scripts/mk_make.py -s --java
cd build
make -s
cp libz3.so ../../../kam1n0-resources/bin/lib/liblibz3.so
cp libz3java.so ../../../kam1n0-resources/bin/lib/liblibz3java.so
mvn install:install-file -Dfile=com.microsoft.z3.jar -DgroupId=com.microsoft -DartifactId=z3 -Dversion=0.0.1 -Dpackaging=jar -DlocalRepositoryPath=../local-m2-repo
