#!/bin/sh


DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SYM=$DIR/../../kam1n0/kam1n0-symbolic/

cd $SYM
echo $SYM


echo "Building LibVex..."
make -s -f vex-make-any
echo Exit Code = $?
if [ ! $? -eq 0 ]; then
    cd $DIR
    return 1
fi

echo "Building z3..."
cd $SYM
source z3-build.sh
echo Exit Code = $?
if [ ! $? -eq 0 ]; then
    cd $DIR
    return 1
fi

cd $DIR
return 0