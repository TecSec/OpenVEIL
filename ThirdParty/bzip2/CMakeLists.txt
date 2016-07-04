#	Copyright (c) 2016, TecSec, Inc.
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
#  Written by Roger Butler

cmake_minimum_required(VERSION 2.4.4)
set(CMAKE_ALLOW_LOOSE_LOOP_CONSTRUCTS ON)

if(NOT SuperProject)
project(bz2 C)
endif()

set(VERSION "1.2.8")

if(MSVC)
    set(CMAKE_DEBUG_POSTFIX "d")
    add_definitions(-D_CRT_SECURE_NO_DEPRECATE)
    add_definitions(-D_CRT_NONSTDC_NO_DEPRECATE)
    add_definitions(-D_CRT_NONSTDC_NO_WARNINGS)
    include_directories(${CMAKE_CURRENT_SOURCE_DIR})
    
add_definitions(-DWINDOWS)
add_definitions(-DXP_WIN)
add_definitions("-DZLIB_WINAPI")

IF(NOT SuperProject)
set(CMAKE_C_FLAGS "-Zi -nologo -W3 -Gm- -EHsc -Gd -arch:SSE2 -fp:precise -Zc:wchar_t -Zc:forScope ")
set(CMAKE_C_FLAGS_DEBUG         "-MDd -RTC1 -Od -GS -D_DEBUG")
set(CMAKE_C_FLAGS_RELEASE       "-MD -Ox -Oi -Ot -GL -GS- -Gy -D_RELEASE")
set(CMAKE_C_FLAGS_DEBUGSTATIC   "-MTd -RTC1 -Od -GS -D_DEBUG -D_STATIC_MSVCRT -D_STATIC_TSFRAMEWORK")
set(CMAKE_C_FLAGS_RELEASESTATIC "-MT -Ox -Oi -Ot -GL -GS- -Gy -D_RELEASE -D_STATIC_MSVCRT -D_STATIC_TSFRAMEWORK")

set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -W4 -WX /Yu\"StdAfx.h\"")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")
set(CMAKE_CXX_FLAGS_DEBUGSTATIC "${CMAKE_C_FLAGS_DEBUGSTATIC}")
set(CMAKE_CXX_FLAGS_RELEASESTATIC "${CMAKE_C_FLAGS_RELEASESTATIC}")
ENDIF(NOT SuperProject) 
endif()

IF(NOT SuperProject)
# determine the CPP compiler platform
if(CMAKE_CL_64)
    set(TS_X_PLATFORM "x64")
    set(TS_PLATFORM "x64")
    set(TS_OS_PLATFORM "amd64")
    set(TS_64BIT_PATH_PART_INSTALLER "64")
	set(TS_LIB_DIR_SUFFIX "64")
else(CMAKE_CL_64)
    set(TS_X_PLATFORM "x86")
    set(TS_PLATFORM "win32")
    set(TS_OS_PLATFORM "x86")
    set(TS_64BIT_PATH_PART_INSTALLER "")
	set(TS_LIB_DIR_SUFFIX "")
endif(CMAKE_CL_64)

set(TS_TOOLSET "OTHER")
if(WIN32)
  if(CMAKE_VS_PLATFORM_TOOLSET STREQUAL "v120")
    set(TS_TOOLSET "vc12")
    set(TS_VS_VERSION "VS2013")
    set(MSVC2013 1)
    set(TS_FRAMEWORK_NODOT v451)
    set(TS_FRAMEWORK v4.5.1)
  elseif(CMAKE_VS_PLATFORM_TOOLSET STREQUAL "v110")
    set(TS_TOOLSET "vc11")
    set(TS_VS_VERSION "VS2012")
    set(MSVC2012 1)
    set(TS_FRAMEWORK_NODOT v45)
    set(TS_FRAMEWORK v4.5)
  elseif(CMAKE_VS_PLATFORM_TOOLSET STREQUAL "v100")
    set(TS_TOOLSET "vc10")
    set(TS_VS_VERSION "VS2010")
    set(MSVC2010 1)
    set(TS_FRAMEWORK_NODOT v40)
    set(TS_FRAMEWORK v4.0)
  else()
    set(TS_TOOLSET "vc10")
    set(TS_VS_VERSION "VS2010")
    set(MSVC2010 1)
    set(TS_FRAMEWORK_NODOT v40)
    set(TS_FRAMEWORK v4.0)
  endif()
endif(WIN32)
set(CMAKE_INSTALL_PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/../../redist/)

set(INSTALL_BIN_DIR "${CMAKE_INSTALL_PREFIX}/bin${TS_LIB_DIR_SUFFIX}" CACHE PATH "Installation directory for executables")
set(INSTALL_LIB_DIR "${CMAKE_INSTALL_PREFIX}/lib${TS_LIB_DIR_SUFFIX}" CACHE PATH "Installation directory for libraries")
set(INSTALL_INC_DIR "${CMAKE_INSTALL_PREFIX}/include" CACHE PATH "Installation directory for headers")
set(INSTALL_MAN_DIR "${CMAKE_INSTALL_PREFIX}/share/man" CACHE PATH "Installation directory for manual pages")
set(INSTALL_PKGCONFIG_DIR "${CMAKE_INSTALL_PREFIX}/share/pkgconfig" CACHE PATH "Installation directory for pkgconfig (.pc) files")

macro(add_uninstall)
# add the uninstall support
IF("${CMAKEMODULESPATH}" STREQUAL "")
    SET(CMAKEMODULESPATH ${CMAKE_CURRENT_SOURCE_DIR}/cmakemodules)
ENDIF()
CONFIGURE_FILE(
 "${CMAKEMODULESPATH}/uninstall.cmake.in"
 "${CMAKE_CURRENT_BINARY_DIR}/uninstall.cmake"
 IMMEDIATE @ONLY)
 
ADD_CUSTOM_TARGET(uninstall
 "${CMAKE_COMMAND}" -P "${CMAKE_CURRENT_BINARY_DIR}/uninstall.cmake")
set_target_properties(uninstall PROPERTIES FOLDER "CMakePredefinedTargets")
endmacro()

ENDIF(NOT SuperProject)


INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})

if(CMAKE_COMPILER_IS_GNUCC)
	if (NOT MINGW)
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
	endif(NOT MINGW)
endif()
	
set(CppSources 
    blocksort.c
#    bzip2.c
    #bzip2recover.c
    bzlib.c
    compress.c
    crctable.c
    decompress.c
#    dlltest.c
    huffman.c
#    mk251.c
    randtable.c
#    spewG.c
#    unzcrash.c
    )

add_library(bz2Static STATIC 
    ${CppSources} 
    bzlib.h
    bzlib_private.h
    )

set_target_properties(bz2Static PROPERTIES FOLDER "ThirdParty\\bzip2")

IF(NOT SuperProject)
add_library(bz2 SHARED 
    ${CppSources} 
    bzlib.h
    bzlib_private.h
    
    libbz2.def
    )

set_target_properties(bz2 PROPERTIES FOLDER "ThirdParty\\bzip2")

file(GLOB BZ2_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/*.h")
install(FILES ${BZ2_HEADERS} DESTINATION include/bz2)
install(TARGETS bz2 bz2Static
        RUNTIME DESTINATION "${INSTALL_BIN_DIR}"
        ARCHIVE DESTINATION "${INSTALL_LIB_DIR}"
        LIBRARY DESTINATION "${INSTALL_LIB_DIR}" )
add_uninstall()
ENDIF(NOT SuperProject)		