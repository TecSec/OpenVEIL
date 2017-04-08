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

# if (CMAKE_CONFIGURATION_TYPES)
  # set (CMAKE_CONFIGURATION_TYPES Debug Release RelWithDebInfo)
  # set (CMAKE_CONFIGURATION_TYPES "${CMAKE_CONFIGURATION_TYPES}" CACHE STRING
    # "Reset the configurations for TSFramework" FORCE)
# endif()

set (PUBLIC_SOURCE_TOP_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set (PUBLIC_BINARY_TOP_DIR ${CMAKE_CURRENT_BINARY_DIR})

if(WIN32)
  STRING(REPLACE "/" "\\" NATIVE_PUBLIC_SOURCE_TOP_DIR ${PUBLIC_SOURCE_TOP_DIR})
  STRING(REPLACE "/" "\\" NATIVE_PUBLIC_BINARY_TOP_DIR ${PUBLIC_BINARY_TOP_DIR})
else()
  SET(NATIVE_PUBLIC_SOURCE_TOP_DIR ${PUBLIC_SOURCE_TOP_DIR})
  SET(NATIVE_PUBLIC_BINARY_TOP_DIR ${PUBLIC_BINARY_TOP_DIR})
endif()

set(TECSEC_TOOLS_DIR ${PUBLIC_SOURCE_TOP_DIR}/../utils)
set(CMAKE_DEBUG_POSTFIX "_d")

if(APPLE)
  set(CMAKE_MACOSX_RPATH 1)
endif()

if(MSVC_IDE)
    set(TS_CONFIG "${TS_VS_CONFIG}")
else()
	set(TS_CONFIG ${CMAKE_BUILD_TYPE})
endif()
string(TOUPPER "${TS_CONFIG}" TS_CONFIG)

# determine the CPP compiler platform
if(FORCE_X86)
    set(TS_X_PLATFORM "x86")
    set(TS_PLATFORM "win32")
    set(TS_OS_PLATFORM "x86")
    set(TS_64BIT_PATH_PART_INSTALLER "")
    set(TS_LIB_DIR_SUFFIX "")
elseif(FORCE_X64)
    set(TS_X_PLATFORM "x64")
    set(TS_PLATFORM "x64")
    set(TS_OS_PLATFORM "amd64")
    set(TS_64BIT_PATH_PART_INSTALLER "64")
    set(TS_LIB_DIR_SUFFIX "64")
elseif(FORCE_ARM)
    set(TS_X_PLATFORM "ARM")
    set(TS_PLATFORM "ARM")
    set(TS_OS_PLATFORM "arm")
    set(TS_64BIT_PATH_PART_INSTALLER "")
    set(TS_LIB_DIR_SUFFIX "")
elseif(CMAKE_CL_64)
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
endif(FORCE_X86)

set(TS_TOOLSET "OTHER")
if(APPLE)
  set(TS_TOOLSET "MAC")
elseif(CMAKE_COMPILER_IS_GNUCC AND TS_X_PLATFORM STREQUAL "x86" AND MINGW)
  set(TS_TOOLSET "gcc_${CMAKE_CXX_COMPILER_VERSION}_i686$ENV{TS_GCC_THREAD}")
elseif(CMAKE_COMPILER_IS_GNUCC)
  set(TS_TOOLSET "gcc_${CMAKE_CXX_COMPILER_VERSION}$ENV{TS_GCC_THREAD}")
  if(ANDROID)
	set(TS_TOOLSET ${TS_TOOLSET}-Android${ANDROID_NATIVE_API_LEVEL}-${CMAKE_ANDROID_ARCH})
  endif(ANDROID)
elseif(WIN32)
  if(CMAKE_VS_PLATFORM_TOOLSET STREQUAL "v141")
    set(TS_TOOLSET "vc15")
  	set(TS_TOOLSET_NUMBER "141")
    set(TS_VS_VERSION "VS2017")
    set(MSVC2017 1)
    set(TS_FRAMEWORK_NODOT v451)
    set(TS_FRAMEWORK v4.5.1)
  elseif(CMAKE_VS_PLATFORM_TOOLSET STREQUAL "v140")
    set(TS_TOOLSET "vc14")
	set(TS_TOOLSET_NUMBER "140")
    set(TS_VS_VERSION "VS2015")
    set(MSVC2015 1)
    set(TS_FRAMEWORK_NODOT v451)
    set(TS_FRAMEWORK v4.5.1)
  elseif(CMAKE_VS_PLATFORM_TOOLSET STREQUAL "v120")
    set(TS_TOOLSET "vc12")
	set(TS_TOOLSET_NUMBER "120")
    set(TS_VS_VERSION "VS2013")
    set(MSVC2013 1)
    set(TS_FRAMEWORK_NODOT v451)
    set(TS_FRAMEWORK v4.5.1)
  elseif(CMAKE_VS_PLATFORM_TOOLSET STREQUAL "v110")
    set(TS_TOOLSET "vc11")
	set(TS_TOOLSET_NUMBER "110")
    set(TS_VS_VERSION "VS2012")
    set(MSVC2012 1)
    set(TS_FRAMEWORK_NODOT v45)
    set(TS_FRAMEWORK v4.5)
  elseif(CMAKE_VS_PLATFORM_TOOLSET STREQUAL "v100")
    set(TS_TOOLSET "vc10")
	set(TS_TOOLSET_NUMBER "100")
    set(TS_VS_VERSION "VS2010")
    set(MSVC2010 1)
    set(TS_FRAMEWORK_NODOT v40)
    set(TS_FRAMEWORK v4.0)
  elseif(MSVC10)
    set(TS_TOOLSET "vc10")
	set(TS_TOOLSET_NUMBER "100")
    set(TS_VS_VERSION "VS2010")
    set(MSVC2010 1)
    set(TS_FRAMEWORK_NODOT v40)
    set(TS_FRAMEWORK v4.0)
  elseif(MSVC15)
    set(TS_TOOLSET "vc15")
	  set(TS_TOOLSET_NUMBER "141")
    set(TS_VS_VERSION "VS2017")
    set(MSVC2017 1)
    set(TS_FRAMEWORK_NODOT v451)
    set(TS_FRAMEWORK v4.5.1)
  elseif(MSVC14)
    set(TS_TOOLSET "vc14")
	set(TS_TOOLSET_NUMBER "140")
    set(TS_VS_VERSION "VS2015")
    set(MSVC2015 1)
    set(TS_FRAMEWORK_NODOT v451)
    set(TS_FRAMEWORK v4.5.1)
  elseif(MSVC12)
    set(TS_TOOLSET "vc12")
	set(TS_TOOLSET_NUMBER "120")
    set(TS_VS_VERSION "VS2013")
    set(MSVC2013 1)
    set(TS_FRAMEWORK_NODOT v451)
    set(TS_FRAMEWORK v4.5.1)
  elseif(MSVC11)
    set(TS_TOOLSET "vc11")
	set(TS_TOOLSET_NUMBER "110")
    set(TS_VS_VERSION "VS2012")
    set(MSVC2012 1)
    set(TS_FRAMEWORK_NODOT v45)
    set(TS_FRAMEWORK v4.5)
  else()
    set(TS_TOOLSET "vc10")
    set(TS_TOOLSET_NUMBER "100")
    set(TS_VS_VERSION "VS2010")
    set(MSVC2010 1)
    set(TS_FRAMEWORK_NODOT v40)
    set(TS_FRAMEWORK v4.0)
  endif()
endif(APPLE)

add_definitions(-DTS_TOOLSET_CONFIG="core/${TS_TOOLSET}/compilerconfig.h")

if(MSVC_IDE)
  set(TS_VS_CONFIGURATION "${TS_VS_CONFIG}")
else()
  set(TS_VS_CONFIGURATION ${CMAKE_BUILD_TYPE})
endif()

# if(MSVC)
  # set (SDK_PARENT c:/TecSec)
# else()
  # set (SDK_PARENT /usr/TecSec)
# endif()

# if(WIN32)
    # STRING(REPLACE "/" "\\" NATIVE_SDK_PARENT ${SDK_PARENT})
    # #STRING(REPLACE "/" "\\" NATIVE_SDK_ROOT ${SDK_ROOT})
# else()
    # set(NATIVE_SDK_PARENT ${SDK_PARENT})
    # #set(NATIVE_SDK_ROOT ${SDK_ROOT})
# endif()

IF(BUILD_SXS)
    SET(SxSPart _SxS)
ELSE(BUILD_SXS)
    SET(SxSPart "")
ENDIF(BUILD_SXS)

IF (NOT CMAKE_BUILD_TYPE)
SET(CMAKE_BUILD_TYPE "Debug" CACHE STRING  "build type determining compiler flags" FORCE )
ENDIF (NOT CMAKE_BUILD_TYPE)

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG -D_DEBUG")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -D_RELEASE")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} -D_RELEASE")

if (UNIX)
	if (NOT CMAKE_INSTALL_PREFIX)
		SET(CMAKE_INSTALL_PREFIX "/usr/local")
	ENDIF(NOT CMAKE_INSTALL_PREFIX)
endif(UNIX)

include(machineBitSize)

MESSAGE(STATUS "Machine type: ${MACHINETYPE}")

# ----------------------------------------------------------------
if(CMAKE_COMPILER_IS_GNUCC)
include(compiler_tecsec_gnucc)
endif() #CMAKE_COMPILER_IS_GNUCC

# ----------------------------------------------------------------
if ("${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin")
include (compiler_tecsec_darwin)
endif () # Darwin

# ----------------------------------------------------------------
IF(WIN32 AND NOT CMAKE_COMPILER_IS_GNUCC)
include(compiler_tecsec_msvc)
endif () # WIN32 AND NOT CMAKE_COMPILER_IS_GNUCC

# ----------------------------------------------------------------
if ("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")

add_definitions(-DLINUX)
add_definitions(-DXP_UNIX)

if(NOT MINGW)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
endif(NOT MINGW)

# This link describes all of the various feature flags such as largefiles
# and posix vs gnu vs bsd.
#     http://www.gnu.org/s/libc/manual/html_node/Feature-Test-Macros.html
#
# I added _GNU_SOURCE go get declarations for qsort_r() on Linux.
#
# _GNU_SOURCE causes the definition of strerror_r() to change, see sg_error.c
#
add_definitions(-D_GNU_SOURCE)

# TODO this should probably call getconf LFS_CFLAGS instead
#
# TODO _GNU_SOURCE also turns on the LFS stuff, so we may not 
# TODO need to explicitly set them below.
add_definitions(-D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64) 

set(SG_OS_LIBS uuid pthread dl m)

endif () # "${CMAKE_SYSTEM_NAME}" STREQUAL "Linux"

# IF(WIN32)
# 	SET(GMOCK_ROOT c:/GoogleTest/${TS_TOOLSET}_${TS_X_PLATFORM})
# 	SET(GTEST_ROOT c:/GoogleTest/${TS_TOOLSET}_${TS_X_PLATFORM})
# 	SET(ZLIB_ROOT S:/ThirdParty/redist)
# 	SET(BZ2_ROOT S:/ThirdParty/redist)
# 	SET(HARU_ROOT S:/ThirdParty/redist)
# 	SET(BOOST_ROOT S:/ThirdParty/redist)
# ENDIF(WIN32)

# IF(IS_OPAQUEVEIL)
# 	IF(NOT EXISTS "${PUBLIC_SOURCE_TOP_DIR}/ThirdParty/bzip2")
# 		find_package(BZ2)
# 	ENDIF(NOT EXISTS "${PUBLIC_SOURCE_TOP_DIR}/ThirdParty/bzip2")

# 	IF(NOT EXISTS "${PUBLIC_SOURCE_TOP_DIR}/ThirdParty/zlib")
# 		find_package(ZLIB)
# 	ENDIF(NOT EXISTS "${PUBLIC_SOURCE_TOP_DIR}/ThirdParty/zlib")
	
# 	find_package(Haru)
# 	#~ find_package(Threads)
# 	find_package(GMock)
# 	find_package(GTest)
# 	# find_package(Boost)
	
# 	if(ZLIB_FOUND)
# 		include_directories($<TARGET_PROPERTY:ZLIB,INTERFACE_INCLUDE_DIRECTORIES>)
# 	endif(ZLIB_FOUND)
# 	if(BZ2_FOUND)
# 		include_directories($<TARGET_PROPERTY:BZ2,INTERFACE_INCLUDE_DIRECTORIES>)
# 	endif(BZ2_FOUND)
# 	if(HARU_FOUND)
# 		include_directories($<TARGET_PROPERTY:HARU,INTERFACE_INCLUDE_DIRECTORIES>)
# 	endif(HARU_FOUND)
# 	if(GTEST_FOUND)
# 		include_directories($<TARGET_PROPERTY:GTEST,INTERFACE_INCLUDE_DIRECTORIES>)
# 	endif(GTEST_FOUND)
# 	if(GMOCK_FOUND)
# 		include_directories($<TARGET_PROPERTY:GMOCK,INTERFACE_INCLUDE_DIRECTORIES>)
# 	endif(GMOCK_FOUND)
# 	if(Boost_FOUND)
# 		include_directories(${Boost_INCLUDE_DIRS})
# 	endif(Boost_FOUND)
# ENDIF(IS_OPAQUEVEIL)

include (tecsec_base_macros)

if(MSVC)
	# Remove the /Fd option so that precompiled headers work
	string(REPLACE "/Fd<TARGET_COMPILE_PDB>" "" CMAKE_C_COMPILE_OBJECT "${CMAKE_C_COMPILE_OBJECT}")
	string(REPLACE "/Fd<TARGET_COMPILE_PDB>" "" CMAKE_CXX_COMPILE_OBJECT "${CMAKE_CXX_COMPILE_OBJECT}")
endif(MSVC)

include (tecsec_installdirs)
