#	Copyright (c) 2017, TecSec, Inc.
#
#	Redistribution and use in source and binary forms, with or without
#	modification, are permitted provided that the following conditions are met:
#	
#		* Redistributions of source code must retain the above copyright
#		  notice, this list of conditions and the following disclaimer.
#		* Redistributions in binary form must reproduce the above copyright
#		  notice, this list of conditions and the following disclaimer in the
#		  documentation and/or other materials provided with the distribution.
#		* Neither the name of TecSec nor the names of the contributors may be
#		  used to endorse or promote products derived from this software 
#		  without specific prior written permission.
#		 
#	ALTERNATIVELY, provided that this notice is retained in full, this product
#	may be distributed under the terms of the GNU General Public License (GPL),
#	in which case the provisions of the GPL apply INSTEAD OF those given above.
#		 
#	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
#	ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
#	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#	DISCLAIMED.  IN NO EVENT SHALL TECSEC BE LIABLE FOR ANY 
#	DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
#	(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
#	LOSS OF USE, DATA OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
#	ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Written by Roger Butler


IF(WIN32)
	SET(GMOCK_ROOT c:/GoogleTest/${TS_TOOLSET}_${TS_X_PLATFORM})
	SET(GTEST_ROOT c:/GoogleTest/${TS_TOOLSET}_${TS_X_PLATFORM})
	SET(ZLIB_ROOT S:/ThirdParty/redist)
	SET(BZ2_ROOT S:/ThirdParty/redist)
	SET(HARU_ROOT S:/ThirdParty/redist)
	SET(BOOST_ROOT S:/ThirdParty/redist)
ENDIF(WIN32)

IF(NOT EXISTS "${PUBLIC_SOURCE_TOP_DIR}/ThirdParty/bzip2")
		find_package(BZ2)
ENDIF(NOT EXISTS "${PUBLIC_SOURCE_TOP_DIR}/ThirdParty/bzip2")

IF(NOT EXISTS "${PUBLIC_SOURCE_TOP_DIR}/ThirdParty/zlib")
		find_package(ZLIB)
ENDIF(NOT EXISTS "${PUBLIC_SOURCE_TOP_DIR}/ThirdParty/zlib")
	
find_package(Haru)
#~ find_package(Threads)
find_package(GMock)
find_package(GTest)
# find_package(Boost)
set(wxWidgets_EXCLUDE_COMMON_LIBRARIES ON)
find_package(wxWidgets COMPONENTS core base adv )


if(ZLIB_FOUND)
		include_directories($<TARGET_PROPERTY:ZLIB,INTERFACE_INCLUDE_DIRECTORIES>)
endif(ZLIB_FOUND)
if(BZ2_FOUND)
		include_directories($<TARGET_PROPERTY:BZ2,INTERFACE_INCLUDE_DIRECTORIES>)
endif(BZ2_FOUND)
if(HARU_FOUND)
		include_directories($<TARGET_PROPERTY:HARU,INTERFACE_INCLUDE_DIRECTORIES>)
endif(HARU_FOUND)
if(GTEST_FOUND)
		include_directories($<TARGET_PROPERTY:GTEST,INTERFACE_INCLUDE_DIRECTORIES>)
endif(GTEST_FOUND)
if(GMOCK_FOUND)
		include_directories($<TARGET_PROPERTY:GMOCK,INTERFACE_INCLUDE_DIRECTORIES>)
endif(GMOCK_FOUND)
if(Boost_FOUND)
		include_directories(${Boost_INCLUDE_DIRS})
endif(Boost_FOUND)

