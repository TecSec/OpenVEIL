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

LIST(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmakemodules)
if(POLICY CMP0005)
    cmake_policy(SET CMP0005 NEW)
endif()
if(POLICY CMP0048)
    cmake_policy(SET CMP0048 NEW)
endif()
if(POLICY CMP0058)
    cmake_policy(SET CMP0058 NEW)
endif()

set(VEILCORENAME VEIL)
string(TOUPPER ${VEILCORENAME} VEILCORENAME_U)
string(TOLOWER ${VEILCORENAME} VEILCORENAME_L)

set(TS_VS_CONFIG ${CMAKE_BUILD_TYPE})
set (CMAKE_CONFIGURATION_TYPES ${CMAKE_BUILD_TYPE})
set (CMAKE_CONFIGURATION_TYPES "${CMAKE_CONFIGURATION_TYPES}" CACHE STRING "Reset the configurations" FORCE )
mark_as_advanced(CMAKE_CONFIGURATION_TYPES)

set(CMAKE_OSX_DEPLOYMENT_TARGET 10.11)
set(CMAKE_OSX_ARCHITECTURES "Universal")

set(DEBUG_TSALG ON)
#if(APPLE)
	set(wxWidgets_USE_STATIC OFF)
#endif(APPLE)


set(SuperProject ON)

#
# Set up the project name and look for the compiler configuration
#
# set(TS_MODULE_BIN OpenVEIL)
set(TS_MODULE_INCLUDE OpenVEIL)
project(OpenVEIL LANGUAGES C CXX)
IF(WIN32)
	cmake_minimum_required(VERSION 3.2)
	set_property(GLOBAL PROPERTY USE_FOLDERS On)
ELSE()
    cmake_minimum_required(VERSION 3.2)
ENDIF()

#
# Include the TecSec macros and variables.  Look for the OpaqueVEIL, OpenVEIL and VEILCrypto
#
include(tecsec_configure_env)
include(tecsec_ConfigureTSALG)
if(APPLE)
    set(SDK_FOLDER ${CRYPTO_INSTALL_BASE_DIR})
    set(TS_INSTALL_PREFIX /usr/local)
else()
    set(SDK_FOLDER ${CRYPTO_INSTALL_BASE_DIR})
    set(TS_INSTALL_PREFIX ${CRYPTO_INSTALL_PREFIX})
endif(APPLE)
include(tecsec_packages)
IF(MSVC)
	# include(compiler_tecsec_msvc.noWarnings)
ENDIF(MSVC)
set(NO_PCH OFF)
if(MINGW)
    set(NO_PCH ON)
endif(MINGW)
include(precompiled.header)
include (tecsec_installdirs)


#
# Configure some of the Linux SO parameters
#
if(APPLE)
    SET(CMAKE_SKIP_BUILD_RPATH FALSE)
    SET(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
    SET(CMAKE_INSTALL_RPATH "$ORIGIN;${SHLIB_DIR};~/local")
    SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
elseif(UNIX)
    SET(CMAKE_SKIP_BUILD_RPATH FALSE)
    SET(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
    SET(CMAKE_INSTALL_RPATH "$ORIGIN;${SHLIB_DIR};~/local")
    SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH FALSE)
endif(APPLE)


#####################################################################
## Start Options
#####################################################################

set(${VEILCORENAME_U}_MAJOR_VERSION 7)
set(${VEILCORENAME_U}_MINOR_VERSION 0)
set(${VEILCORENAME_U}_REVISION_VERSION 51)
set(${VEILCORENAME_U}_BUILD_VERSION 0)
set(OSX_FRAMEWORK_VERSION A)

#####################################################################
## End Options
#####################################################################
set(VEIL_COPYRIGHT "Copyright (C) 2017 TecSec, Inc.  All Rights Reserved Worldwide.")

set(${VEILCORENAME_U}_VERSION "${${VEILCORENAME_U}_MAJOR_VERSION}.${${VEILCORENAME_U}_MINOR_VERSION}.${${VEILCORENAME_U}_REVISION_VERSION}")
set(${VEILCORENAME_U}_VERSION_COMMA "${${VEILCORENAME_U}_MAJOR_VERSION},${${VEILCORENAME_U}_MINOR_VERSION},${${VEILCORENAME_U}_REVISION_VERSION}")
set(${VEILCORENAME_U}_SO_VERSION "${${VEILCORENAME_U}_MAJOR_VERSION}")

set(VEILCORE_VERSION ${${VEILCORENAME_U}_VERSION})
set(VEILCORE_VERSION_COMMA ${${VEILCORENAME_U}_VERSION_COMMA})

set(ENABLE_NASM OFF)
ENABLE_LANGUAGE(ASM_NASM)
if(CMAKE_ASM_NASM_COMPILER_WORKS)
	set(ENABLE_NASM ON)
endif(CMAKE_ASM_NASM_COMPILER_WORKS)

# set(ENABLE_MASM OFF)
# ENABLE_LANGUAGE(ASM_MASM)
# if(CMAKE_ASM_MASM_COMPILER_WORKS)
# 	set(ENABLE_MASM ON)
# endif(CMAKE_ASM_MASM_COMPILER_WORKS)

IF(WIN32)
    set(GTEST_ROOT c:/GoogleTest/${TS_TOOLSET}_${TS_X_PLATFORM})
ENDIF(WIN32)

find_package(GTest)

if(GTEST_FOUND)
	# enable_testing()
endif()

include(summary)

#
# Place the output into these folders
#
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${PUBLIC_BINARY_TOP_DIR}/lib")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PUBLIC_BINARY_TOP_DIR}/bin")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PUBLIC_BINARY_TOP_DIR}/bin")
set(CMAKE_PDB_OUTPUT_DIRECTORY "${PUBLIC_BINARY_TOP_DIR}/pdb")
set(OSX_FRAMEWORK_FOLDER "/Library/Frameworks")
set(OSX_SDK_DIR "{PUBLIC_BINARY_TOP_DIR}/sdk")

set(EXTRA_FILE_OUTPUT ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
if (MSVC_IDE)
	set(EXTRA_FILE_OUTPUT ${EXTRA_FILE_OUTPUT}/${CMAKE_BUILD_TYPE})
endif(MSVC_IDE)

# look for system header files needed

if(ANDROID)
message(STATUS "ANDROID BUILD")
endif()
FOREACH(KEYWORD "__inline__" "__inline" "inline")
  IF(NOT DEFINED C_INLINE)
    TRY_COMPILE(C_HAS_${KEYWORD} "${CMAKE_CURRENT_BINARY_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/SolutionItems/test_inline.c" COMPILE_DEFINITIONS "-Dinline=${KEYWORD}")
    IF(C_HAS_${KEYWORD})
      MESSAGE(STATUS "Inline found as ${KEYWORD}")
      SET(C_INLINE TRUE)
      SET(TS_INLINE ${KEYWORD})
    ENDIF()
  ENDIF()
ENDFOREACH(KEYWORD)
IF(NOT DEFINED C_INLINE)
  MESSAGE(STATUS "Inline not found")
  SET(TS_INLINE "")
ENDIF()

find_package(PCSC)

if (PCSC_FOUND AND NOT APPLE)
	get_property(_tmp TARGET pcsc PROPERTY INTERFACE_INCLUDE_DIRECTORIES)
	if(NOT ("${_tmp}" STREQUAL ""))
		include_directories(${_tmp})
		set(CMAKE_REQUIRED_INCLUDES ${CMAKE_REQUIRED_INCLUDES} ${_tmp})
	endif(NOT ("${_tmp}" STREQUAL ""))
	get_property(_tmp TARGET pcsc PROPERTY DLOPEN_SONAME)
	set(PCSC_SO_NAME, ${_tmp})
	message(STATUS 	"set(PCSC_SO_NAME, ${_tmp})")
endif()

INCLUDE(CheckIncludeFiles)
INCLUDE(CheckIncludeFileCXX)
INCLUDE(${CMAKE_ROOT}/Modules/CheckIncludeFile.cmake)
INCLUDE(${CMAKE_ROOT}/Modules/CheckTypeSize.cmake)
INCLUDE(${CMAKE_ROOT}/Modules/CheckFunctionExists.cmake)
INCLUDE(${CMAKE_ROOT}/Modules/CheckCXXSourceCompiles.cmake)
INCLUDE(${CMAKE_ROOT}/Modules/TestBigEndian.cmake)
INCLUDE(${CMAKE_ROOT}/Modules/CheckSymbolExists.cmake)

set(CMAKE_EXTRA_INCLUDE_FILES "${CMAKE_EXTRA_INCLUDE_FILES} stdlib.h")

CHECK_INCLUDE_FILES(stdio.h HAVE_STDIO_H)
CHECK_INCLUDE_FILES(string.h HAVE_STRING_H)
CHECK_INCLUDE_FILES(stdlib.h HAVE_STDLIB_H)
CHECK_INCLUDE_FILES(stdint.h HAVE_STDINT_H)
CHECK_INCLUDE_FILES(stdarg.h HAVE_STDARG_H)
CHECK_INCLUDE_FILES(stdint.h HAVE_STDINT_H)
CHECK_INCLUDE_FILES(stddef.h HAVE_STDDEF_H)
CHECK_INCLUDE_FILES(ctype.h HAVE_CTYPE_H)
CHECK_INCLUDE_FILES(errno.h HAVE_ERRNO_H)
CHECK_INCLUDE_FILES(limits.h HAVE_LIMITS_H)
CHECK_INCLUDE_FILES(process.h HAVE_PROCESS_H)
CHECK_INCLUDE_FILES(pthread.h HAVE_PTHREAD_H)
CHECK_INCLUDE_FILES(math.h HAVE_MATH_H)
CHECK_INCLUDE_FILES(windows.h HAVE_WINDOWS_H)
CHECK_INCLUDE_FILES(basetsd.h HAVE_BASETSD_H)
CHECK_INCLUDE_FILES(sys/types.h HAVE_SYS_TYPES_H)
CHECK_INCLUDE_FILES(sys/endian.h HAVE_SYS_ENDIAN_H)
CHECK_INCLUDE_FILES(sys/stat.h HAVE_SYS_STAT_H)
CHECK_INCLUDE_FILES(sys/time.h HAVE_SYS_TIME_H)
CHECK_INCLUDE_FILES(sys/timeb.h HAVE_SYS_TIMEB_H)
CHECK_INCLUDE_FILES(unistd.h HAVE_UNISTD_H)
CHECK_INCLUDE_FILES(crtdbg.h HAVE_CRTDBG_H)
CHECK_INCLUDE_FILES(wchar.h HAVE_WCHAR_H)
CHECK_INCLUDE_FILES(memory.h HAVE_MEMORY_H)
CHECK_INCLUDE_FILES(tchar.h HAVE_TCHAR_H)
CHECK_INCLUDE_FILES(time.h HAVE_TIME_H)
CHECK_INCLUDE_FILES(io.h HAVE_IO_H)
CHECK_INCLUDE_FILES(pwd.h HAVE_PWD_H)
CHECK_INCLUDE_FILES(cpuid.h HAVE_CPUID_H)
#CHECK_INCLUDE_FILES(uuid/uuid.h HAVE_UUID_UUID_H)
CHECK_INCLUDE_FILES(dlfcn.h HAVE_DLFCN_H)
CHECK_INCLUDE_FILES(glob.h HAVE_GLOB_H)
CHECK_INCLUDE_FILES(dirent.h HAVE_DIRENT_H)
CHECK_INCLUDE_FILES(syslog.h HAVE_SYSLOG_H)
CHECK_INCLUDE_FILES(fcntl.h HAVE_FCNTL_H)
CHECK_INCLUDE_FILES(sys/wait.h HAVE_SYS_WAIT_H)
CHECK_INCLUDE_FILES(sys/ioctl.h HAVE_SYS_IOCTL_H)
CHECK_INCLUDE_FILES(sys/resource.h HAVE_SYS_RESOURCE_H)
CHECK_INCLUDE_FILES(sys/socket.h HAVE_SYS_SOCKET_H)
CHECK_INCLUDE_FILES(netinet/in.h HAVE_NETINET_IN_H)
CHECK_INCLUDE_FILES(netdb.h HAVE_NETDB_H)
CHECK_INCLUDE_FILES(arpa/inet.h HAVE_ARPA_INET_H)
CHECK_INCLUDE_FILES(gio/gio.h HAVE_GIO_GIO_H)
CHECK_INCLUDE_FILES(magic.h HAVE_MAGIC_H)
CHECK_INCLUDE_FILES(pcsclite.h HAVE_PCSCLITE_H)
CHECK_INCLUDE_FILES(PCSC/pcsclite.h HAVE_PCSC_PCSCLITE_H)
CHECK_INCLUDE_FILES(winscard.h HAVE_WINSCARD_H)
CHECK_INCLUDE_FILES(PCSC/winscard.h HAVE_PCSC_WINSCARD_H)
CHECK_INCLUDE_FILES(direct.h HAVE_DIRECT_H)
CHECK_INCLUDE_FILES(wmmintrin.h HAVE_WMMINTRIN_H)
CHECK_INCLUDE_FILES(smmintrin.h HAVE_SMMINTRIN_H)
CHECK_INCLUDE_FILES(emmintrin.h HAVE_EMMINTRIN_H)
CHECK_INCLUDE_FILES(tmmintrin.h HAVE_TMMINTRIN_H)
CHECK_INCLUDE_FILES(xmmintrin.h HAVE_XMMINTRIN_H)
CHECK_INCLUDE_FILES(intrin.h HAVE_INTRIN_H)
CHECK_INCLUDE_FILES(sal.h HAVE_SAL_H)
if(NOT TS_INTERNAL_SD_DAEMON)
CHECK_INCLUDE_FILES(systemd/sd-daemon.h HAVE_SD_DAEMON_H)
endif(NOT TS_INTERNAL_SD_DAEMON)
CHECK_INCLUDE_FILE_CXX(string HAVE_CPP_STRING)
CHECK_INCLUDE_FILE_CXX(cstddef HAVE_CPP_CSTDDEF)
CHECK_INCLUDE_FILE_CXX(map HAVE_CPP_MAP)
CHECK_INCLUDE_FILE_CXX(list HAVE_CPP_LIST)
CHECK_INCLUDE_FILE_CXX(forward_list HAVE_CPP_FORWARD_LIST)
CHECK_INCLUDE_FILE_CXX(deque HAVE_CPP_DEQUE)
CHECK_INCLUDE_FILE_CXX(vector HAVE_CPP_VECTOR)
CHECK_INCLUDE_FILE_CXX(memory HAVE_CPP_MEMORY)
CHECK_INCLUDE_FILE_CXX(functional HAVE_CPP_FUNCTIONAL)
CHECK_INCLUDE_FILE_CXX(iostream HAVE_CPP_IOSTREAM)
CHECK_INCLUDE_FILE_CXX(ostream HAVE_CPP_OSTREAM)
CHECK_INCLUDE_FILE_CXX(regex HAVE_CPP_REGEX)
CHECK_INCLUDE_FILE_CXX(climits HAVE_CPP_CLIMITS)
CHECK_INCLUDE_FILE_CXX(mutex HAVE_CPP_MUTEX)

if(HAVE_ERRNO_H)
CHECK_CXX_SOURCE_COMPILES("
    #include <errno.h>
	int main(void)
	{
	  errno_t h = 9;
	  return h;
	}
	" HAVE_ERRNO_T
	)
endif()

#CHECK_TYPE_SIZE("nullptr_t" SIZEOF_NULLPTR_T BUILTIN_TYPES_ONLY LANGUAGE CXX)
CHECK_CXX_SOURCE_COMPILES("
	int main(void)
	{
	  byte* ch = 0;
	  return *ch;
	}
	" HAVE_BYTE
	)
CHECK_CXX_SOURCE_COMPILES("
	int main(void)
	{
	  char* ch = nullptr;
	  return *ch;
	}
	" HAVE_NULLPTR
	)
CHECK_CXX_SOURCE_COMPILES("
	int main(void)
	{
	  long long int ch = 0;
	  return (int)ch;
	}
	" HAVE_LONG_LONG_INT
	)
CHECK_CXX_SOURCE_COMPILES("
	int main(void)
	{
	  long long ch = 0;
	  return (int)ch;
	}
	" HAVE_LONG_LONG
	)
CHECK_CXX_SOURCE_COMPILES("
	int main(void)
	{
	  __int64 ch = 0;
	  return (int)ch;
	}
	" HAVE___INT64
	)
CHECK_CXX_SOURCE_COMPILES("
        int __cdecl test() { return 1; }
	int main(void)
	{
	  return test();
	}
	" HAVE___CDECL
	)
CHECK_CXX_SOURCE_COMPILES("
        int __stdcall test() { return 1; }
	int main(void)
	{
	  return test();
	}
	" HAVE___STDCALL
	)
CHECK_CXX_SOURCE_COMPILES("
        #include <stdio.h>
        #include <stdlib.h>
	int main(void)
	{
	  return (int)atoll(\"8\");
	}
	" HAVE_ATOLL
	)
CHECK_CXX_SOURCE_COMPILES("
        #include <stdio.h>
        #include <stdlib.h>
	int main(void)
	{
	  return (int)strtoll(\"8\", 0, 10);
	}
	" HAVE_STRTOLL
	)
CHECK_CXX_SOURCE_COMPILES("
        #include <stdio.h>
        #include <stdlib.h>
	int main(void)
	{
	  return (int)atoq(\"8\");
	}
	" HAVE_ATOQ
	)
CHECK_CXX_SOURCE_COMPILES("
        #include <stdio.h>
        #include <stdlib.h>
	int main(void)
	{
	  char buff[50];
	  return (int)_i64toa_s(4,buff,sizeof(buff)/sizeof(buff[0]),10);
	}
	" HAVE__I64TOA_S
	)
CHECK_CXX_SOURCE_COMPILES("
        #include <stdio.h>
        #include <stdlib.h>
	int main(void)
	{
	  return (int)_atoi64(\"99\");
	}
	" HAVE__ATOI64
	)
CHECK_FUNCTION_EXISTS(_atoi64, HAVE__ATOI64)


if(HAVE_WINDOWS_H)
CHECK_CXX_SOURCE_COMPILES("
    #include <windows.h>
	int main(void)
	{
	  IUnknown* ch = 0;
	  return (int)ch;
	}
	" HAVE_IUNKNOWN
	)
CHECK_CXX_SOURCE_COMPILES("
        #include <windows.h>
	int main(void)
	{
	  return (int)IsBadReadPtr(\"8\", 1);
	}
	" HAVE_ISBADREADPTR
	)
CHECK_CXX_SOURCE_COMPILES("
        #include <windows.h>
	int main(void)
	{
	LARGE_INTEGER li;
	  return (int)QueryPerformanceCounter(&li);
	}
	" HAVE_QUERYPERFORMANCECOUNTER
	)
CHECK_CXX_SOURCE_COMPILES("
        #include <windows.h>
	int main(void)
	{
	  long value = 0;
	  return InterlockedIncrement(&value);
	}
	" HAVE_INTERLOCKED_INCREMENT
	)
CHECK_CXX_SOURCE_COMPILES("
        #include <windows.h>
	int main(void)
	{
	  BSTR value = 0;
	  return *value;
	}
	" HAVE_BSTR
	)
CHECK_CXX_SOURCE_COMPILES("
	#include <windows.h>
	int main(void)
	{
	  CRITICAL_SECTION ch;

	  return (&ch == 0) ? 1 : 0;
	}
	" HAVE_CRITICAL_SECTION
	)

endif()

# look for system functions
include(CheckFunctionExists)
CHECK_FUNCTION_EXISTS(printf HAVE_PRINTF)
CHECK_FUNCTION_EXISTS(sprintf HAVE_SPRINTF)
CHECK_FUNCTION_EXISTS(vsnprintf HAVE_VSNPRINTF)
CHECK_FUNCTION_EXISTS(sprintf_s HAVE_SPRINTF_S)
CHECK_FUNCTION_EXISTS(vsprintf_s HAVE_VSPRINTF_S)
CHECK_FUNCTION_EXISTS(_vsnprintf_s HAVE__VSNPRINTF_S)
CHECK_FUNCTION_EXISTS(_snprintf_s HAVE__SNPRINTF_S)
CHECK_FUNCTION_EXISTS(vsnprintf_s HAVE_VSNPRINTF_S)
CHECK_FUNCTION_EXISTS(_vsnwprintf_s HAVE__VSNWPRINTF_S)
CHECK_FUNCTION_EXISTS(_snprintf HAVE__SNPRINTF)
CHECK_FUNCTION_EXISTS(snprintf HAVE_SNPRINTF)
CHECK_FUNCTION_EXISTS(sleep HAVE_sleep)
CHECK_FUNCTION_EXISTS(Sleep HAVE_Sleep)
CHECK_FUNCTION_EXISTS(_fseeki64 HAVE__FSEEKI64)
CHECK_FUNCTION_EXISTS(fseeko64 HAVE_FSEEKO64)
CHECK_FUNCTION_EXISTS(_getcwd HAVE__GETCWD)
CHECK_FUNCTION_EXISTS(getcwd HAVE_GETCWD)
CHECK_FUNCTION_EXISTS(_chdir HAVE__CHDIR)
CHECK_FUNCTION_EXISTS(chdir HAVE_CHDIR)
CHECK_FUNCTION_EXISTS(_unlink HAVE__UNLINK)
CHECK_FUNCTION_EXISTS(unlink HAVE_UNLINK)
CHECK_FUNCTION_EXISTS(getpeereid HAVE_GETPEEREID)

CHECK_FUNCTION_EXISTS(strlen HAVE_STRLEN)
CHECK_FUNCTION_EXISTS(strnicmp HAVE_STRNICMP)
CHECK_FUNCTION_EXISTS(strncasecmp HAVE_STRNCASECMP)
CHECK_FUNCTION_EXISTS(_strncasecmp HAVE__STRNCASECMP)
CHECK_FUNCTION_EXISTS(_strnicmp HAVE__STRNICMP)
CHECK_FUNCTION_EXISTS(stricmp HAVE_STRICMP)
CHECK_FUNCTION_EXISTS(strcasecmp HAVE_STRCASECMP)
CHECK_FUNCTION_EXISTS(_strcasecmp HAVE__STRCASECMP)
CHECK_FUNCTION_EXISTS(_stricmp HAVE__STRICMP)
CHECK_FUNCTION_EXISTS(strtok HAVE_STRTOK)
CHECK_FUNCTION_EXISTS(strtok_s HAVE_STRTOK_S)
CHECK_FUNCTION_EXISTS(strtok_r HAVE_STRTOK_R)
CHECK_FUNCTION_EXISTS(strupr HAVE_STRUPR)
CHECK_FUNCTION_EXISTS(_strupr HAVE__STRUPR)
CHECK_FUNCTION_EXISTS(_strupr_s HAVE__STRUPR_S)
CHECK_FUNCTION_EXISTS(strstr HAVE_STRSTR)

CHECK_FUNCTION_EXISTS(strncpy_s HAVE_STRNCPY_S)
CHECK_FUNCTION_EXISTS(strncpy HAVE_STRNCPY)
CHECK_FUNCTION_EXISTS(strcpy_s HAVE_STRCPY_S)
CHECK_FUNCTION_EXISTS(strcpy HAVE_STRCPY)
CHECK_FUNCTION_EXISTS(strcat_s HAVE_STRCAT_S)
CHECK_FUNCTION_EXISTS(strcat HAVE_STRCAT)
CHECK_FUNCTION_EXISTS(gettimeofday HAVE_GETTIMEOFDAY)

CHECK_FUNCTION_EXISTS(fopen HAVE_FOPEN)
CHECK_FUNCTION_EXISTS(fopen_s HAVE_FOPEN_S)
CHECK_FUNCTION_EXISTS(fclose HAVE_FCLOSE)
CHECK_FUNCTION_EXISTS(feof HAVE_FEOF)
CHECK_FUNCTION_EXISTS(fgets HAVE_FGETS)
CHECK_FUNCTION_EXISTS(gets_s HAVE_GETS_S)
CHECK_FUNCTION_EXISTS(gets HAVE_GETS)
CHECK_FUNCTION_EXISTS(fread HAVE_FREAD)
CHECK_FUNCTION_EXISTS(fwrite HAVE_FWRITE)
CHECK_FUNCTION_EXISTS(_ftelli64 HAVE__FTELLI64)
CHECK_FUNCTION_EXISTS(ftello64 HAVE_FTELLO64)
CHECK_FUNCTION_EXISTS(ftell HAVE_FTELL)
CHECK_FUNCTION_EXISTS(htonl HAVE_HTONL)
CHECK_FUNCTION_EXISTS(getpwnam HAVE_GETPWNAM)
CHECK_FUNCTION_EXISTS(getpwnam_r HAVE_GETPWNAM_R)

if(HAVE_WINDOWS_H)
    set(HAVE_INT_PTR 1)
else()
    # TODO:  Need a good test for INT_PTR here
endif()

set(symheaders "stdio.h")
if(HAVE_LIMITS_H)
set(symheaders "${symheaders};limits.h")
endif()
if(HAVE_MATH_H)
set(symheaders "${symheaders};math.h")
endif()
if(HAVE_WINDOWS_H)
set(symheaders "${symheaders};windows.h")
endif()

CHECK_SYMBOL_EXISTS(INT_MAX "${symheaders}" HAVE_SYM_INT_MAX)
CHECK_SYMBOL_EXISTS(MAXINT "${symheaders}" HAVE_SYM_MAXINT)
CHECK_SYMBOL_EXISTS(INT_MIN "${symheaders}" HAVE_SYM_INT_MIN)
CHECK_SYMBOL_EXISTS(UNREFERENCED_PARAMETER "${symheaders}" HAVE_SYM_UNREFERENCED_PARAMETER)
CHECK_SYMBOL_EXISTS(FALSE "${symheaders}" HAVE_SYM_FALSE)
CHECK_SYMBOL_EXISTS(MAX_PATH "${symheaders}" HAVE_SYM_MAX_PATH)

if(CMAKE_COMPILER_IS_GNUCC)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wdeclaration-after-statement -Wstrict-prototypes")
endif()

#if (NOT DEFINED HAVE_CONSTEXPR)
	TRY_COMPILE(HAVE_CONSTEXPR "${CMAKE_CURRENT_BINARY_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/SolutionItems/test_constexpr.cpp" )
	if(HAVE_CONSTEXPR)
		MESSAGE(STATUS "constexpr supported")
	else()
		MESSAGE(STATUS "constexpr NOT supported")
	endif()
#endif()

if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    set(PROJECT_POSTFIX _d)
else()
    set(PROJECT_POSTFIX )
endif()

set(HAVE_SMARTCARD 0)
if(HAVE_WINDOWS_H)
    set(HAVE_SMARTCARD 1)
elseif(TARGET pcsc)
    set(HAVE_SMARTCARD 1)
elseif(APPLE)
    set(HAVE_SMARTCARD 1)
endif(HAVE_WINDOWS_H)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/SolutionItems/compilerconfig.h.in ${CMAKE_CURRENT_BINARY_DIR}/core/${TS_TOOLSET}/compilerconfig.h)
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/SolutionItems/compilerconfig_c.h.in ${CMAKE_CURRENT_BINARY_DIR}/core/${TS_TOOLSET}/compilerconfig_c.h)

ImportTarget(TSALG)

add_definitions(-DWFMO)

include_directories(
	${CMAKE_CURRENT_BINARY_DIR} 
    ${CMAKE_CURRENT_BINARY_DIR}/core
	${CMAKE_CURRENT_SOURCE_DIR}/include 
	${CMAKE_CURRENT_SOURCE_DIR}/SolutionItems
	)

if(IS_OPAQUEVEIL)
	# added for installer
	CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/SolutionItems/${VEILCORENAME_L}info.txt.in ${CMAKE_CURRENT_BINARY_DIR}/${VEILCORENAME_L}info.txt)
	if(UNIX)
	    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/install.sh.in ${CMAKE_CURRENT_BINARY_DIR}/install.sh @ONLY)
	    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/installtools.sh.in ${CMAKE_CURRENT_BINARY_DIR}/installtools.sh @ONLY)
	    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/stage.sh.in ${CMAKE_CURRENT_BINARY_DIR}/stage.sh @ONLY)
	endif(UNIX)
endif(IS_OPAQUEVEIL)

IF(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/ThirdParty/bzip2")
	include_directories(${CMAKE_CURRENT_SOURCE_DIR}/ThirdParty/bzip2)
ENDIF(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/ThirdParty/bzip2")
if(NOT ANDROID)
	IF(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/ThirdParty/zlib")
		include_directories(${CMAKE_CURRENT_SOURCE_DIR}/ThirdParty/zlib)
		include_directories(${CMAKE_CURRENT_BINARY_DIR}/ThirdParty/zlib)
	ENDIF(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/ThirdParty/zlib")
ELSE()
	set(CMAKE_INSTALL_DO_STRIP ON)
ENDIF()

set(OVHeaders
	${CMAKE_CURRENT_SOURCE_DIR}/include/${VEILCORENAME}.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/VEILCmsHeader.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/VEILFileSupport.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/VEILSmartCard.h
)
IF(WIN32)
	set(OVHeaders ${OVHeaders}
		${CMAKE_CURRENT_SOURCE_DIR}/include/VEILWinAPI.h
	)
ENDIF(WIN32)

set(VEILCoreHeaders
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/VEILCore.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsmod_extension.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/HttpHeader.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/HttpChannel.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/UrlParser.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/CkmFileReader.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/CkmFileStreams.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/CkmFileWriter.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/CkmMemoryFifoStream.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/CkmMemoryStream.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/CkmReadAppendFile.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/CkmReadWriteFile.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/xp_console.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/SimpleOpt.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsThread.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/IPreferenceChangeNotify.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsJsonPreferencesBase.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/BasicVEILPreferences.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/ChangeTracker.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsAttributeMap.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/pem.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/nargv.h

	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsDebug.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsDebugStream.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsLog.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsTraceStream.h

	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsPreferencesBase.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsXmlError.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsXmlNode.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsXmlParser.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsXmlParserCallback.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsAppConfig.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/IPropertyMap.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/INotifyPropertyChange.h
	
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/IVeilUtilities.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/IOutputCollector.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/IVeilToolCommand.h

	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsCryptoStringBase.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsCryptoString.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsCryptoData.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/CryptoContainerWrapper.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/CryptoInterfaces.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/CryptoExceptions.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/FipsState.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsCryptoDate.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/TlvDocument.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/TlvNode.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/json.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsTlvSerializer.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/CryptoUtf16.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsDistinguishedName.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/xp_sharedlib.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/xp_file.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/CryptoIterators.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/CryptoStringFuncs.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/CryptoLocks.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/CryptoEvent.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/Endian.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsCertificateParser.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsCertificateBuilder.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsCertificateExtension.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsCertificateNamePart.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/standardLayoutList.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/pevents.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/CkmSymmetricAlgorithmImpl.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/cryptolocator.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/cryptolocatorwriter.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/VEILCrypto.h
    )
set(VEILCoreHeadersCompiler
    ${CMAKE_CURRENT_BINARY_DIR}/core/${TS_TOOLSET}/compilerconfig.h
    ${CMAKE_CURRENT_BINARY_DIR}/core/${TS_TOOLSET}/compilerconfig_c.h

)

set(VEILCmsHeaders
	${CMAKE_CURRENT_SOURCE_DIR}/include/CmsHeader/CmsHeaderExtensionOIDs.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/CmsHeader/CmsHeaderInterfaces.h
)

set(VEILSmartCardHeaders
	${CMAKE_CURRENT_SOURCE_DIR}/include/VEILSmartCard/tsWinscardExports.h
)
set(VEILCoreHelpHeaders
	${CMAKE_CURRENT_SOURCE_DIR}/include/help/FileVEILHelp.h
)

IF(WIN32)
	set(OVWinAPIHeaders
		${CMAKE_CURRENT_SOURCE_DIR}/include/WinAPI/htmlhelp.h
	)
ENDIF(WIN32)

if (wxWidgets_FOUND)
	INCLUDE_DIRECTORIES(${wxWidgets_INCLUDE_DIRS})
	LINK_DIRECTORIES(${wxWidgets_LIBRARY_DIRS})
	set(VersionLines)
	set(VersionLines "${VersionLines}const int VEILWXWINDOWS_MAJOR = ${${VEILCORENAME_U}_MAJOR_VERSION};\n")
	set(VersionLines "${VersionLines}const int VEILWXWINDOWS_MINOR = ${${VEILCORENAME_U}_MINOR_VERSION};\n")
	set(VersionLines "${VersionLines}const int VEILWXWINDOWS_REVISION = ${${VEILCORENAME_U}_REVISION_VERSION};\n")
	set(VersionLines "${VersionLines}const int VEILWXWINDOWS_BUILD = ${${VEILCORENAME_U}_BUILD_VERSION};\n")
	set(VersionLines "${VersionLines}\n")
	set(VersionLines "${VersionLines}#define VEILWXWINDOWS_FULL_VERSION \"${${VEILCORENAME_U}_VERSION}\"\n")
	set(VersionLines "${VersionLines}#define VEILWXWINDOWS_FULL_VERSION_COMMAS \"${VEILCORE_VERSION_COMMA}\"\n")
	set(VersionLines "${VersionLines}\n")
	set(VersionLines "${VersionLines}#define VEILWXWINDOWS_VERSION \"${VEILCORE_VERSION}\"\n")
	set(VersionLines "${VersionLines}#define VEILWXWINDOWS_SO_VERSION \"${${VEILCORENAME_U}_SO_VERSION}\"\n")
	set(VersionLines "${VersionLines}\n")
	set(VersionLines "${VersionLines}#define VEIL_COPYRIGHT \"${VEIL_COPYRIGHT}\"\n")
	set(VersionLines "${VersionLines}\n")

	file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/VEILwxWidgetsVersion.h "${VersionLines}")
	set(OVHeaders ${OVHeaders}
		${PUBLIC_SOURCE_TOP_DIR}/include/VEILwxWidgets.h
		${CMAKE_CURRENT_BINARY_DIR}/VEILwxWidgetsVersion.h
	)
	set(OVWxWinHeaders
        ${PUBLIC_SOURCE_TOP_DIR}/include/VEILWxWidgets/wxhtmlhelp.h
		)
endif (wxWidgets_FOUND)

set(GEN_EXPORTS_XASN
    ${PUBLIC_BINARY_TOP_DIR}/core/CryptoAsn1.export
    ${PUBLIC_BINARY_TOP_DIR}/core/PKIX.export
    ${PUBLIC_BINARY_TOP_DIR}/core/PKIX_Cert.export
    ${PUBLIC_BINARY_TOP_DIR}/core/PKIX_OCSP.export
)
set(GEN_HEADERS_XASN
    ${PUBLIC_BINARY_TOP_DIR}/core/CryptoAsn1.h
    ${PUBLIC_BINARY_TOP_DIR}/core/PKIX.h
    ${PUBLIC_BINARY_TOP_DIR}/core/PKIX_Cert.h
    ${PUBLIC_BINARY_TOP_DIR}/core/PKIX_OCSP.h
    ${PUBLIC_BINARY_TOP_DIR}/Asn1CkmHeader.h
    ${PUBLIC_BINARY_TOP_DIR}/TokenPacket.h
    ${PUBLIC_BINARY_TOP_DIR}/CTSProfile.h
    ${PUBLIC_BINARY_TOP_DIR}/Asn1CkmHeader.export
    ${PUBLIC_BINARY_TOP_DIR}/TokenPacket.export
    ${PUBLIC_BINARY_TOP_DIR}/CTSProfile.export
)
set (VEILCoreHeaders ${VEILCoreHeaders} ${GEN_EXPORTS_XASN} ${GEN_HEADERS_XASN})
CONFIGURE_FILE(VEILApiVersion.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/VEILApiVersion.cmake)

if (NOT APPLE)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/VEILApiVersion.cmake DESTINATION ${INCLUDE_DIR})
    install(FILES ${OVHeaders} DESTINATION ${INCLUDE_DIR})
    install(FILES ${VEILCoreHeaders} DESTINATION ${INCLUDE_DIR}/core)
    install(FILES ${VEILCoreHeadersCompiler} DESTINATION ${INCLUDE_DIR}/core/${TS_TOOLSET})
    install(FILES ${VEILCmsHeaders} DESTINATION ${INCLUDE_DIR}/CmsHeader)
    install(FILES ${VEILCoreHelpHeaders} DESTINATION ${INCLUDE_DIR}/Help)
    install(FILES ${VEILSmartCardHeaders} DESTINATION ${INCLUDE_DIR}/VEILSmartCard)
    IF(WIN32)
    install(FILES ${OVWinAPIHeaders} DESTINATION ${INCLUDE_DIR}/WinAPI)
    ENDIF(WIN32)
    if(wxWidgets_FOUND)
        install(FILES ${OVWxWinHeaders} DESTINATION ${INCLUDE_DIR}/VEILWxWidgets)
    endif()
endif()

if(UNIX)
	string(REPLACE ";" " " VEILHeaders_str "${OVHeaders} ${PUBLIC_BINARY_TOP_DIR}/Asn1CkmHeader.h ${PUBLIC_BINARY_TOP_DIR}/TokenPacket.h ${PUBLIC_BINARY_TOP_DIR}/CTSProfile.h ${PUBLIC_BINARY_TOP_DIR}/VEILssmAsn.h")
	string(REPLACE ";" " " VEILCoreHeaders_str "${VEILCoreHeaders}")
	string(REPLACE ";" " " VEILCmsHeaders_str "${VEILCmsHeaders}")
	string(REPLACE ";" " " VEILSmartCardHeaders_str "${VEILSmartCardHeaders}")
	# configure_file(${CMAKE_CURRENT_SOURCE_DIR}/stagesdk.sh.in ${CMAKE_CURRENT_BINARY_DIR}/stagesdk.sh @ONLY)
	# configure_file(${CMAKE_CURRENT_SOURCE_DIR}/installsdk.sh.in ${CMAKE_CURRENT_BINARY_DIR}/installsdk.sh @ONLY)
	# install(FILES ${CMAKE_CURRENT_BINARY_DIR}/install.sh ${CMAKE_CURRENT_BINARY_DIR}/installtools.sh ${CMAKE_CURRENT_BINARY_DIR}/installsdk.sh ${CMAKE_CURRENT_BINARY_DIR}/stage.sh ${CMAKE_CURRENT_BINARY_DIR}/stagesdk.sh DESTINATION ${BIN_DIR} PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)
endif(UNIX)

add_subdirectory(ThirdParty)
add_subdirectory(VEILCore)
add_subdirectory(VEILCmsHeader)
add_subdirectory(VEILFileSupport)
IF(WIN32)
	add_subdirectory(VEILWinAPI)
ENDIF(WIN32)
if (wxWidgets_FOUND)
	add_subdirectory(VEILWxWidgets)
	add_subdirectory(TextVEIL)
endif (wxWidgets_FOUND)
IF(HAVE_SMARTCARD)
	add_subdirectory(VEILSmartCard)
ENDIF(HAVE_SMARTCARD)
add_subdirectory(FileVEIL)
add_subdirectory(veiltool)
if(GTEST_FOUND)
	add_subdirectory(unittests)
endif(GTEST_FOUND)

if(WIN32)
	CopyImportTargetBinaries(TSALG ${BIN_DIR})
	if (wxWidgets_FOUND)
	    CopyImportTargetBinaries(WxWidgets ${BIN_DIR})
	endif (wxWidgets_FOUND)
endif(WIN32)

if(APPLE)
    CONFIGURE_FILE(README.md ${CMAKE_CURRENT_BINARY_DIR}/bin/README.md COPYONLY)
    CONFIGURE_FILE(LICENSE.md ${CMAKE_CURRENT_BINARY_DIR}/bin/LICENSE.md COPYONLY)


    CONFIGURE_FILE(SolutionItems/BuildFrameworks.VEILCore.cmake.osx.in ${CMAKE_CURRENT_BINARY_DIR}/bin/BuildFrameworks.VEILCore.cmake @ONLY)
    CONFIGURE_FILE(SolutionItems/VEILCore.list.osx.in ${CMAKE_CURRENT_BINARY_DIR}/bin/VEILCore.list @ONLY)
    CONFIGURE_FILE(SolutionItems/VEILCoreSDK.list.osx.in ${CMAKE_CURRENT_BINARY_DIR}/bin/VEILCoreSDK.list @ONLY)

    add_custom_target(CopyFrameworkVEILCore ALL
        WORKING_DIRECTORY
            ${CMAKE_CURRENT_BINARY_DIR}/bin
        COMMAND 
            ${CMAKE_COMMAND} -P BuildFrameworks.VEILCore.cmake
    )
    add_dependencies(CopyFrameworkVEILCore VEILCore ) # VEILWxWidgets


    CONFIGURE_FILE(SolutionItems/BuildFrameworks.VEILCmsHeader.cmake.osx.in ${CMAKE_CURRENT_BINARY_DIR}/bin/BuildFrameworks.VEILCmsHeader.cmake @ONLY)
    CONFIGURE_FILE(SolutionItems/VEILCmsHeader.list.osx.in ${CMAKE_CURRENT_BINARY_DIR}/bin/VEILCmsHeader.list @ONLY)
    CONFIGURE_FILE(SolutionItems/VEILCmsHeaderSDK.list.osx.in ${CMAKE_CURRENT_BINARY_DIR}/bin/VEILCmsHeaderSDK.list @ONLY)

    add_custom_target(CopyFrameworkVEILCmsHeader ALL
        WORKING_DIRECTORY
            ${CMAKE_CURRENT_BINARY_DIR}/bin
        COMMAND 
            ${CMAKE_COMMAND} -P BuildFrameworks.VEILCmsHeader.cmake
    )
    add_dependencies(CopyFrameworkVEILCmsHeader CopyFrameworkVEILCore VEILCmsHeader ) # VEILWxWidgets


    CONFIGURE_FILE(SolutionItems/BuildFrameworks.VEILSmartCard.cmake.osx.in ${CMAKE_CURRENT_BINARY_DIR}/bin/BuildFrameworks.VEILSmartCard.cmake @ONLY)
    CONFIGURE_FILE(SolutionItems/VEILSmartCard.list.osx.in ${CMAKE_CURRENT_BINARY_DIR}/bin/VEILSmartCard.list @ONLY)
    CONFIGURE_FILE(SolutionItems/VEILSmartCardSDK.list.osx.in ${CMAKE_CURRENT_BINARY_DIR}/bin/VEILSmartCardSDK.list @ONLY)

    add_custom_target(CopyFrameworkVEILSmartCard ALL
        WORKING_DIRECTORY
            ${CMAKE_CURRENT_BINARY_DIR}/bin
        COMMAND 
            ${CMAKE_COMMAND} -P BuildFrameworks.VEILSmartCard.cmake
    )
    add_dependencies(CopyFrameworkVEILSmartCard CopyFrameworkVEILCore VEILSmartCard ) # VEILWxWidgets


    CONFIGURE_FILE(SolutionItems/BuildFrameworks.VEILFileSupport.cmake.osx.in ${CMAKE_CURRENT_BINARY_DIR}/bin/BuildFrameworks.VEILFileSupport.cmake @ONLY)
    CONFIGURE_FILE(SolutionItems/VEILFileSupport.list.osx.in ${CMAKE_CURRENT_BINARY_DIR}/bin/VEILFileSupport.list @ONLY)
    CONFIGURE_FILE(SolutionItems/VEILFileSupportSDK.list.osx.in ${CMAKE_CURRENT_BINARY_DIR}/bin/VEILFileSupportSDK.list @ONLY)

    add_custom_target(CopyFrameworkVEILFileSupport ALL
        WORKING_DIRECTORY
            ${CMAKE_CURRENT_BINARY_DIR}/bin
        COMMAND 
            ${CMAKE_COMMAND} -P BuildFrameworks.VEILFileSupport.cmake
    )
    add_dependencies(CopyFrameworkVEILFileSupport CopyFrameworkVEILCore VEILFileSupport ) # VEILWxWidgets
    
    
    if (wxWidgets_FOUND)
        CONFIGURE_FILE(SolutionItems/BuildFrameworks.VEILWxWidgets.cmake.osx.in ${CMAKE_CURRENT_BINARY_DIR}/bin/BuildFrameworks.VEILWxWidgets.cmake @ONLY)
        CONFIGURE_FILE(SolutionItems/VEILWxWidgets.list.osx.in ${CMAKE_CURRENT_BINARY_DIR}/bin/VEILWxWidgets.list @ONLY)
        CONFIGURE_FILE(SolutionItems/VEILWxWidgetsSDK.list.osx.in ${CMAKE_CURRENT_BINARY_DIR}/bin/VEILWxWidgetsSDK.list @ONLY)

        add_custom_target(CopyFrameworkVEILWxWidgets ALL
            WORKING_DIRECTORY
                ${CMAKE_CURRENT_BINARY_DIR}/bin
            COMMAND 
                ${CMAKE_COMMAND} -P BuildFrameworks.VEILWxWidgets.cmake
        )
        add_dependencies(CopyFrameworkVEILWxWidgets CopyFrameworkVEILCore VEILWxWidgets ) # VEILWxWidgets
    endif (wxWidgets_FOUND)

endif(APPLE)

summary()
add_uninstall()

# DumpAllVariables()
