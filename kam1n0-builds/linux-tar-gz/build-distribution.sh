#!/bin/sh

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
rm -rf $DIR/bins

mkdir $DIR/bins/
mkdir $DIR/bins/server/
mkdir $DIR/bins/ida-plugin/

cd $DIR/../../kam1n0
echo $DIR/../../kam1n0


mvn -DskipTests clean 
echo Exit Code = $?
if [ ! $? -eq 0 ]; then
    cd $DIR
    echo maven build failure. 
    return 1
fi


mvn -DskipTests package
mvn -DskipTests package
echo Exit Code = $?
if [ ! $? -eq 0 ]; then
    cd $DIR
    echo maven build failure. 
    return 1
fi


cd $DIR
echo maven build succeeded
cp -r $DIR/../../kam1n0/build-bins/* $DIR/bins/server
cp -r $DIR/../../kam1n0-clients/ida-plugin/* $DIR/bins/ida-plugin
cd $DIR/bins/
tar -czvf Kam1n0-Server.tar.gz server/
tar -czvf Kam1n0-IDA-Plugin.tar.gz ida-plugin/
# rm -rf $DIR/bins/server/
# rm -rf $DIR/bins/ida-plugin/
# cd $DIR
# echo Distribution build completed. Please find linux distribution on $DIR/bins/.
