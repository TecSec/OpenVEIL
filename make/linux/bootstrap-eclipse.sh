#!/bin/bash

processors=(X64)
pushd $(dirname "${0}") > /dev/null
CUR_PATH=$(pwd -L)
popd
# CUR_PATH=$(dirname "$(readlink -f $0)" )
if [ "$1" == "" ]; then
    configurations=(Release Debug)
else
    configurations=($1)
fi

if !([ -d ../../../build ]); then mkdir ../../../build; fi

cd ../../..

for i in ${configurations[@]}; do
    for j in ${processors[@]}; do
        dir="$(echo ${i}-${j} | tr '[:upper:]' '[:lower:]')";

	if !([ -d build/opaqueveil-eclipse-${dir} ]); then mkdir build/opaqueveil-eclipse-${dir}; fi
	cd build/opaqueveil-eclipse-${dir}
	cmake -DFORCE_${j}=1 -DCMAKE_INSTALL_PREFIX:PATH=~/local -DCMAKE_BUILD_TYPE=${i} -G "Eclipse CDT4 - Unix Makefiles" ${CUR_PATH}/../..
	cd ../..
    done
done

#cd build/debug
#make
#cd ../..

