#!/bin/bash

#
# This file is the property of TecSec, Inc. (c) 2018 TecSec, Inc.
# All rights are reserved to TecSec.
#
# Licensed Technology is protected by U.S. copyright laws and international 
# treaty provisions, as well as by issued U.S. patents and U.S. trade secret 
# law. Licensee shall not copy the printed materials included in the Licensed 
# Technology. TecSec owns all title and intellectual property in and to the 
# total software product, including but not limited to any elements incorporated 
# therein. No rights to ownership of any intellectual property are transferred 
# by this Agreement.
#
#  This product is protected by one or more of the following U.S. patents, as 
#  well as pending U.S. patent applications and foreign patents;  
#  6,490,680; 6,542,608; 6,549,623; 6,606,386; 6,608,901; 6,684,330; 6,694,433; 
#  6,754,820; 6,694,433; 6,754,820; 6,845,453; 7,016,495; 7,079,653; 7,089,417; 
#  7,095,851; 7,095,852; 7,111,173; 7,131,009; 7,490,240; 7,539,855;7,738,660; 
#  7,817,800; 7,974,410; 8,077,870; 8,285,991; 8,712,046. 
#
# Written by Roger Butler, TecSec, Inc

processors=(ARM)
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

