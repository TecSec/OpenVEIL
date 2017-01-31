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

include (CheckIncludeFiles)
include (CheckLibraryExists)
include (CheckSymbolExists)

find_path(BZ2_INCLUDE_DIR bzlib.h
    HINTS
        $ENV{BZ2_ROOT}/include
        $ENV{BZ2_ROOT}/include/bz2
        ${BZ2_ROOT}/include
        ${BZ2_ROOT}/include/bz2
)
mark_as_advanced(BZ2_INCLUDE_DIR)

# if (NOT BZ2_LIBRARIES)
    find_library(BZ2_SHARED_LIBRARY_RELEASE NAMES bz2 bzip2 HINTS $ENV{BZ2_ROOT}/lib${TS_LIB_DIR_SUFFIX} ${BZ2_ROOT}/lib${TS_LIB_DIR_SUFFIX} /lib${TS_LIB_DIR_SUFFIX})
    find_library(BZ2_SHARED_LIBRARY_RELWITHDEBINFO NAMES bz2 bzip2 HINTS $ENV{BZ2_ROOT}/lib${TS_LIB_DIR_SUFFIX} ${BZ2_ROOT}/lib${TS_LIB_DIR_SUFFIX} /lib${TS_LIB_DIR_SUFFIX})
    find_library(BZ2_STATIC_LIBRARY_RELEASE NAMES bz2Static bzip2Static HINTS $ENV{BZ2_ROOT}/lib${TS_LIB_DIR_SUFFIX} ${BZ2_ROOT}/lib${TS_LIB_DIR_SUFFIX} /lib${TS_LIB_DIR_SUFFIX})
    find_library(BZ2_STATIC_LIBRARY_RELWITHDEBINFO NAMES bz2Static bzip2Static HINTS $ENV{BZ2_ROOT}/lib${TS_LIB_DIR_SUFFIX} ${BZ2_ROOT}/lib${TS_LIB_DIR_SUFFIX} /lib${TS_LIB_DIR_SUFFIX})
    find_library(BZ2_SHARED_LIBRARY_DEBUG NAMES bz2d bzip2d HINTS $ENV{BZ2_ROOT}/lib${TS_LIB_DIR_SUFFIX} ${BZ2_ROOT}/lib${TS_LIB_DIR_SUFFIX} /lib${TS_LIB_DIR_SUFFIX})
    find_library(BZ2_STATIC_LIBRARY_DEBUG NAMES bz2Staticd bzip2Staticd HINTS $ENV{BZ2_ROOT}/lib${TS_LIB_DIR_SUFFIX} ${BZ2_ROOT}/lib${TS_LIB_DIR_SUFFIX} /lib${TS_LIB_DIR_SUFFIX})
IF(WIN32)
	SET(_tmp ${CMAKE_FIND_LIBRARY_SUFFIXES})
	SET(CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_SHARED_LIBRARY_SUFFIX})
    find_library(BZ2_SHARED_SO_RELEASE NAMES bz2 bzip2 HINTS $ENV{BZ2_ROOT}/bin ${BZ2_ROOT}/bin)
    find_library(BZ2_SHARED_SO_RELWITHDEBINFO NAMES bz2 bzip2 HINTS $ENV{BZ2_ROOT}/bin ${BZ2_ROOT}/bin)
    find_library(BZ2_SHARED_SO_DEBUG NAMES bz2d bzip2d HINTS $ENV{BZ2_ROOT}/bin ${BZ2_ROOT}/bin)
	SET(CMAKE_FIND_LIBRARY_SUFFIXES ${_tmp})
endif(WIN32)
# endif ()

if (BZ2_INCLUDE_DIR AND EXISTS "${BZ2_INCLUDE_DIR}/bzlib.h")
    file(STRINGS "${BZ2_INCLUDE_DIR}/bzlib.h" BZLIB_H REGEX "bzip2/libbzip2 version [0-9]+\\.[^ ]+ of [0-9]+ ")
    string(REGEX REPLACE ".* bzip2/libbzip2 version ([0-9]+\\.[^ ]+) of [0-9]+ .*" "\\1" BZIP2_VERSION_STRING "${BZLIB_H}")
endif ()

# handle the QUIETLY and REQUIRED arguments and set BZip2_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
IF(WIN32)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(BZ2
                                  REQUIRED_VARS BZ2_SHARED_LIBRARY_RELEASE BZ2_STATIC_LIBRARY_RELEASE BZ2_SHARED_LIBRARY_DEBUG BZ2_STATIC_LIBRARY_DEBUG BZ2_INCLUDE_DIR
                                  VERSION_VAR BZ2_VERSION_STRING)
ELSE(WIN32)
set(BZ2_SHARED_LIBRARY_DEBUG ${BZ2_SHARED_LIBRARY_RELEASE})
FIND_PACKAGE_HANDLE_STANDARD_ARGS(BZ2
                                  REQUIRED_VARS BZ2_SHARED_LIBRARY_RELEASE BZ2_INCLUDE_DIR
                                  VERSION_VAR BZ2_VERSION_STRING)
ENDIF(WIN32)

if (BZ2_FOUND)
   include(CheckLibraryExists)
   include(CMakePushCheckState)
   cmake_push_check_state()
   set(CMAKE_REQUIRED_QUIET ${BZ2_FIND_QUIETLY})
   CHECK_LIBRARY_EXISTS("${BZIP2_LIBRARIES}" BZ2_bzCompressInit "" BZIP2_NEED_PREFIX)
   cmake_pop_check_state()

    if(NOT TARGET BZ2)
		if(WIN32)
		  add_library(BZ2 SHARED IMPORTED)
		  set_property(TARGET BZ2 PROPERTY IMPORTED_LOCATION_DEBUG "${BZ2_SHARED_SO_DEBUG}")
		  set_property(TARGET BZ2 PROPERTY IMPORTED_LOCATION_RELEASE "${BZ2_SHARED_SO_RELEASE}")
		  set_property(TARGET BZ2 PROPERTY IMPORTED_LOCATION_RELWITHDEBINFO "${BZ2_SHARED_SO_RELWITHDEBINFO}")
		  set_property(TARGET BZ2 PROPERTY IMPORTED_IMPLIB_DEBUG "${BZ2_SHARED_LIBRARY_DEBUG}")
		  set_property(TARGET BZ2 PROPERTY IMPORTED_IMPLIB_RELEASE "${BZ2_SHARED_LIBRARY_RELEASE}")
		  set_property(TARGET BZ2 PROPERTY IMPORTED_IMPLIB_RELWITHDEBINFO "${BZ2_SHARED_LIBRARY_RELWITHDEBINFO}")
		  set_property(TARGET BZ2 PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${BZ2_INCLUDE_DIRS}")
		else(WIN32)
		  add_library(BZ2 SHARED IMPORTED)
		  set_target_properties(BZ2 PROPERTIES
			IMPORTED_LOCATION_DEBUG "${BZ2_SHARED_LIBRARY_DEBUG}"
			IMPORTED_LOCATION_RELEASE "${BZ2_SHARED_LIBRARY_RELEASE}"
			IMPORTED_LOCATION_RELWITHDEBINFO "${BZ2_SHARED_LIBRARY_RELWITHDEBINFO}"
			INTERFACE_INCLUDE_DIRECTORIES "${BZ2_INCLUDE_DIRS}")
		endif(WIN32)
    endif()
   
    if(NOT TARGET BZ2_STATIC)
      add_library(BZ2_STATIC UNKNOWN IMPORTED)
      set_target_properties(BZ2_STATIC PROPERTIES
        IMPORTED_LOCATION_DEBUG "${BZ2_STATIC_LIBRARY_DEBUG}"
        IMPORTED_LOCATION_RELEASE "${BZ2_STATIC_LIBRARY_RELEASE}"
        IMPORTED_LOCATION_RELWITHDEBINFO "${BZ2_STATIC_LIBRARY_RELWITHDEBINFO}"
        INTERFACE_INCLUDE_DIRECTORIES "${BZ2_INCLUDE_DIR}")
    endif()
endif ()

mark_as_advanced(BZ2_INCLUDE_DIR)
