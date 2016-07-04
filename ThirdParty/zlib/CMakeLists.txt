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
# This file is a merge of the TecSec CMakeLists.txt template and the original zLib file.
#
cmake_minimum_required(VERSION 2.4.4)
set(CMAKE_ALLOW_LOOSE_LOOP_CONSTRUCTS ON)

if(NOT SuperProject)
project(zlib C)
endif()

set(VERSION "1.2.8")

option(ASM686 "Enable building i686 assembly implementation")
option(AMD64 "Enable building amd64 assembly implementation")

include(CheckTypeSize)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckCSourceCompiles)
enable_testing()

check_include_file(sys/types.h HAVE_SYS_TYPES_H)
check_include_file(stdint.h    HAVE_STDINT_H)
check_include_file(stddef.h    HAVE_STDDEF_H)

#
# Check to see if we have large file support
#
set(CMAKE_REQUIRED_DEFINITIONS -D_LARGEFILE64_SOURCE=1)
# We add these other definitions here because CheckTypeSize.cmake
# in CMake 2.4.x does not automatically do so and we want
# compatibility with CMake 2.4.x.
if(HAVE_SYS_TYPES_H)
    list(APPEND CMAKE_REQUIRED_DEFINITIONS -DHAVE_SYS_TYPES_H)
endif()
if(HAVE_STDINT_H)
    list(APPEND CMAKE_REQUIRED_DEFINITIONS -DHAVE_STDINT_H)
endif()
if(HAVE_STDDEF_H)
    list(APPEND CMAKE_REQUIRED_DEFINITIONS -DHAVE_STDDEF_H)
endif()
check_type_size(off64_t OFF64_T)
if(HAVE_OFF64_T)
   add_definitions(-D_LARGEFILE64_SOURCE=1)
endif()
set(CMAKE_REQUIRED_DEFINITIONS) # clear variable

#
# Check for fseeko
#
check_function_exists(fseeko HAVE_FSEEKO)
if(NOT HAVE_FSEEKO)
    add_definitions(-DNO_FSEEKO)
endif()

#
# Check for unistd.h
#
check_include_file(unistd.h Z_HAVE_UNISTD_H)

if(MSVC)
    set(CMAKE_DEBUG_POSTFIX "d")
    add_definitions(-D_CRT_SECURE_NO_DEPRECATE)
    add_definitions(-D_CRT_NONSTDC_NO_DEPRECATE)
    include_directories(${CMAKE_CURRENT_SOURCE_DIR})
    
	add_definitions(-DWINDOWS)
	add_definitions(-DXP_WIN)
	# add_definitions("-DZLIB_WINAPI")

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
ELSE(NOT SuperProject)
	set(SKIP_INSTALL_ALL ON)
ENDIF(NOT SuperProject)
endif()

if(NOT CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_CURRENT_BINARY_DIR)
    # If we're doing an out of source build and the user has a zconf.h
    # in their source tree...
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/zconf.h)
        message(STATUS "Renaming")
        message(STATUS "    ${CMAKE_CURRENT_SOURCE_DIR}/zconf.h")
        message(STATUS "to 'zconf.h.included' because this file is included with zlib")
        message(STATUS "but CMake generates it automatically in the build directory.")
        file(RENAME ${CMAKE_CURRENT_SOURCE_DIR}/zconf.h ${CMAKE_CURRENT_SOURCE_DIR}/zconf.h.included)
  endif()
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
ENDIF(NOT SuperProject)

set(INSTALL_BIN_DIR "${CMAKE_INSTALL_PREFIX}/bin${TS_LIB_DIR_SUFFIX}" CACHE PATH "Installation directory for executables")
set(INSTALL_LIB_DIR "${CMAKE_INSTALL_PREFIX}/lib${TS_LIB_DIR_SUFFIX}" CACHE PATH "Installation directory for libraries")
set(INSTALL_INC_DIR "${CMAKE_INSTALL_PREFIX}/include" CACHE PATH "Installation directory for headers")
set(INSTALL_MAN_DIR "${CMAKE_INSTALL_PREFIX}/share/man" CACHE PATH "Installation directory for manual pages")
set(INSTALL_PKGCONFIG_DIR "${CMAKE_INSTALL_PREFIX}/share/pkgconfig" CACHE PATH "Installation directory for pkgconfig (.pc) files")

IF(NOT SuperProject)
# macro(CopyFile source dest)
    # ADD_CUSTOM_COMMAND(
        # OUTPUT
            # ${dest}
        # DEPENDS
            # ${source}
        # COMMAND ${CMAKE_COMMAND} -E copy_if_different ${source} ${dest}
    # )
# endmacro()
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

set(ZLIB_PC ${CMAKE_CURRENT_BINARY_DIR}/zlib.pc)
configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/zlib.pc.cmakein
		${ZLIB_PC} @ONLY)
configure_file(	${CMAKE_CURRENT_SOURCE_DIR}/zconf.h.cmakein
		${CMAKE_CURRENT_BINARY_DIR}/zconf.h @ONLY)
if(SuperProject)
configure_file(	${CMAKE_CURRENT_SOURCE_DIR}/zconf.h.cmakein
		${PUBLIC_BINARY_TOP_DIR}/zconf.h @ONLY)
endif(SuperProject)
include_directories(${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_SOURCE_DIR})


#============================================================================
# zlib
#============================================================================

set(ZLIB_PUBLIC_HDRS
    ${CMAKE_CURRENT_BINARY_DIR}/zconf.h
    zlib.h
)
set(ZLIB_PRIVATE_HDRS
    crc32.h
    deflate.h
    gzguts.h
    inffast.h
    inffixed.h
    inflate.h
    inftrees.h
    trees.h
    zutil.h
)
set(ZLIB_SRCS
    adler32.c
    compress.c
    crc32.c
    deflate.c
    gzclose.c
    gzlib.c
    gzread.c
    gzwrite.c
    inflate.c
    infback.c
    inftrees.c
    inffast.c
    trees.c
    uncompr.c
    zutil.c
)

IF(NOT SuperProject)
if(WIN32)
    set(ZLIB_DLL_SRCS
        win32/zlib1.rc # If present will override custom build rule below.
    )
endif()
ENDIF(NOT SuperProject)

if(CMAKE_COMPILER_IS_GNUCC)
    if(ASM686)
        set(ZLIB_ASMS contrib/asm686/match.S)
    elseif (AMD64)
        set(ZLIB_ASMS contrib/amd64/amd64-match.S)
    endif ()

	if(ZLIB_ASMS)
		add_definitions(-DASMV)
		set_source_files_properties(${ZLIB_ASMS} PROPERTIES LANGUAGE C COMPILE_FLAGS -DNO_UNDERLINE)
	endif()
	if(NOT MINGW)
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
	endif(NOT MINGW)
endif()

if(MSVC)
    if(ASM686)
		ENABLE_LANGUAGE(ASM_MASM)
        set(ZLIB_ASMS
			contrib/masmx86/inffas32.asm
			contrib/masmx86/match686.asm
		)
    elseif (AMD64)
		ENABLE_LANGUAGE(ASM_MASM)
        set(ZLIB_ASMS
			contrib/masmx64/gvmat64.asm
			contrib/masmx64/inffasx64.asm
		)
    endif()

	if(ZLIB_ASMS)
		add_definitions(-DASMV -DASMINF)
	endif()
endif()

# parse the full version number from zlib.h and include in ZLIB_FULL_VERSION
file(READ ${CMAKE_CURRENT_SOURCE_DIR}/zlib.h _zlib_h_contents)
string(REGEX REPLACE ".*#define[ \t]+ZLIB_VERSION[ \t]+\"([-0-9A-Za-z.]+)\".*"
    "\\1" ZLIB_FULL_VERSION ${_zlib_h_contents})

if(MINGW)
    # This gets us DLL resource information when compiling on MinGW.
    if(NOT CMAKE_RC_COMPILER)
        set(CMAKE_RC_COMPILER windres.exe)
    endif()

    add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/zlib1rc.obj
                       COMMAND ${CMAKE_RC_COMPILER}
                            -D GCC_WINDRES
                            -I ${CMAKE_CURRENT_SOURCE_DIR}
                            -I ${CMAKE_CURRENT_BINARY_DIR}
                            -o ${CMAKE_CURRENT_BINARY_DIR}/zlib1rc.obj
                            -i ${CMAKE_CURRENT_SOURCE_DIR}/win32/zlib1.rc)
    set(ZLIB_DLL_SRCS ${CMAKE_CURRENT_BINARY_DIR}/zlib1rc.obj)
endif(MINGW)

IF(NOT SuperProject)
add_library(zdll SHARED ${ZLIB_SRCS} ${ZLIB_ASMS} ${ZLIB_DLL_SRCS} ${ZLIB_PUBLIC_HDRS} ${ZLIB_PRIVATE_HDRS})
set_target_properties(zdll PROPERTIES DEFINE_SYMBOL ZLIB_DLL)
set_target_properties(zdll PROPERTIES FOLDER "ThirdParty\\zlib")
set(ZLIB_SHARED_LIBRARY_${TS_CONFIG} ${CMAKE_CURRENT_BINARY_DIR} PARENT_SCOPE)
ENDIF(NOT SuperProject)

add_library(zlib STATIC ${ZLIB_SRCS} ${ZLIB_ASMS} ${ZLIB_PUBLIC_HDRS} ${ZLIB_PRIVATE_HDRS})
set_target_properties(zlib PROPERTIES SOVERSION 1)
set_target_properties(zlib PROPERTIES FOLDER "ThirdParty\\zlib")
set(ZLIB_STATIC_LIBRARY_${TS_CONFIG} ${CMAKE_CURRENT_BINARY_DIR} PARENT_SCOPE)

IF(NOT SuperProject)
	if(NOT CYGWIN)
		# This property causes shared libraries on Linux to have the full version
		# encoded into their final filename.  We disable this on Cygwin because
		# it causes cygz-${ZLIB_FULL_VERSION}.dll to be created when cygz.dll
		# seems to be the default.
		#
		# This has no effect with MSVC, on that platform the version info for
		# the DLL comes from the resource file win32/zlib1.rc
		set_target_properties(zdll PROPERTIES VERSION ${ZLIB_FULL_VERSION})
	endif()

	if(UNIX)
		# On unix-like platforms the library is almost always called libz
	   set_target_properties(zdll zlib PROPERTIES OUTPUT_NAME z)
	#   if(NOT APPLE)
	#     set_target_properties(zdll PROPERTIES LINK_FLAGS "-Wl,--version-script,\"${CMAKE_CURRENT_SOURCE_DIR}/zdll.map\"")
	#   endif()
	elseif(BUILD_SHARED_LIBS AND WIN32)
		# Creates zlib1.dll when building shared library version
		set_target_properties(zdll PROPERTIES SUFFIX "1.dll")
	endif()

	if(NOT SKIP_INSTALL_LIBRARIES AND NOT SKIP_INSTALL_ALL )
		install(TARGETS zdll zlib
			RUNTIME DESTINATION "${INSTALL_BIN_DIR}"
			ARCHIVE DESTINATION "${INSTALL_LIB_DIR}"
			LIBRARY DESTINATION "${INSTALL_LIB_DIR}" )
	endif()
	if(NOT SKIP_INSTALL_HEADERS AND NOT SKIP_INSTALL_ALL )
		install(FILES ${ZLIB_PUBLIC_HDRS} DESTINATION "${INSTALL_INC_DIR}")
	endif()
	if(NOT SKIP_INSTALL_FILES AND NOT SKIP_INSTALL_ALL )
		install(FILES zlib.3 DESTINATION "${INSTALL_MAN_DIR}/man3")
	endif()
	if(NOT SKIP_INSTALL_FILES AND NOT SKIP_INSTALL_ALL )
		install(FILES ${ZLIB_PC} DESTINATION "${INSTALL_PKGCONFIG_DIR}")
	endif()
ELSE(NOT SuperProject)
	if(UNIX)
	   set_target_properties(zlib PROPERTIES OUTPUT_NAME z)
	endif(UNIX)
	if(NOT SKIP_INSTALL_LIBRARIES AND NOT SKIP_INSTALL_ALL )
		install(TARGETS zlib
			RUNTIME DESTINATION "${INSTALL_BIN_DIR}"
			ARCHIVE DESTINATION "${INSTALL_LIB_DIR}"
			LIBRARY DESTINATION "${INSTALL_LIB_DIR}" )
	endif()
ENDIF(NOT SuperProject)

#============================================================================
# Example binaries
#============================================================================

IF(NOT SuperProject)
add_executable(example test/example.c)
target_link_libraries(example zdll)
add_test(example example)

add_executable(minigzip test/minigzip.c)
target_link_libraries(minigzip zdll)

if(HAVE_OFF64_T)
    add_executable(example64 test/example.c)
    target_link_libraries(example64 zdll)
    set_target_properties(example64 PROPERTIES COMPILE_FLAGS "-D_FILE_OFFSET_BITS=64")
    add_test(example64 example64)

    add_executable(minigzip64 test/minigzip.c)
    target_link_libraries(minigzip64 zdll)
    set_target_properties(minigzip64 PROPERTIES COMPILE_FLAGS "-D_FILE_OFFSET_BITS=64")
endif()


add_uninstall()
ENDIF(NOT SuperProject)