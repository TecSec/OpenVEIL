#!/bin/bash

#
# This file is the property of TecSec, Inc. (c) 2017 TecSec, Inc.
# All rights are reserved to TecSec.
#
# This product is protected by one or more of the following
# U.S. patents, as well as pending U.S. patent applications and foreign patents:
# 5,369,702; 5,369,707; 5,375,169; 5,410,599; 5,432,851; 5,440,290; 5,680,452;
# 5,787,173; 5,898,781; 6,075,865; 6,229,445; 6,266,417; 6,490,680; 6,542,608;
# 6,549,623; 6,606,386; 6,608,901; 6,684,330; 6,694,433; 6,754,820; 6,845,453;
# 6,868,598; 7,016,495; 7,069,448; 7,079,653; 7,089,417; 7,095,851; 7,095,852;
# 7,111,173; 7,131,009; 7,178,030; 7,212,632; 7,490,240; 7,539,855; 7,738,660;
# 7,817,800; 7,974,410; 8,077,870; 8,083,808; 8,285,991; 8,308,820; 8,712,046.
#
# Written by Roger Butler

processors=(X64)
if [ "$1" == "" ]; then
    configurations=(Release Debug)
else
    configurations=($1)
fi

if !([ -d ../../build ]); then mkdir ../../build; fi

cd ../..

for i in ${configurations[@]}; do
    for j in ${processors[@]}; do
        dir="$(echo ${i}-${j} | tr '[:upper:]' '[:lower:]')";

	if !([ -d build/${dir} ]); then mkdir build/${dir}; fi

	cd build/${dir}
	cmake -DFORCE_${j}=1 -DCMAKE_INSTALL_PREFIX:PATH=~/tecsec -DCMAKE_BUILD_TYPE=${i} -G "Ninja" ../../
	cd ../..
    done
done

#cd build/debug
#make
#cd ../..

