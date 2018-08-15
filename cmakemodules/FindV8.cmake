#	Copyright (c) 2018, TecSec, Inc.
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

set(v8_include_hints
    $ENV{V8_ROOT}
    ${V8_ROOT}
    ${CMAKE_SOURCE_DIR}/../../other/v8
    ${CMAKE_SOURCE_DIR}/../../otherhtml/v8
)
find_path(V8_INCLUDE_DIR v8.h
    HINTS
        ${v8_include_hints}
    PATH_SUFFIXES
        include
)
mark_as_advanced(V8_INCLUDE_DIR)

#MESSAGE(STATUS "V8_INCLUDE_DIR = ${V8_INCLUDE_DIR}")
# if (NOT V8_LIBRARIES)

IF(WIN32)
    set(v8_lib_hints
        ${V8_INCLUDE_DIR}/..
    )
    set(v8_bin_hints
        ${V8_INCLUDE_DIR}/..
    )
    find_library(V8_SHARED_LIBRARY_RELEASE  NAMES v8               HINTS ${v8_lib_hints} PATH_SUFFIXES out.gn/ts_release_${TS_X_PLATFORM}/obj)
    find_library(V8_STATIC_LIBRARY_RELEASE  NAMES v8_monolith      HINTS ${v8_lib_hints} PATH_SUFFIXES out.gn/ts_release_${TS_X_PLATFORM}/obj)
    find_library(V8_STATIC_LIBRARY_RELEASE2 NAMES v8_libbase       HINTS ${v8_lib_hints} PATH_SUFFIXES out.gn/ts_release_${TS_X_PLATFORM}/obj)
    find_library(V8_STATIC_LIBRARY_RELEASE3 NAMES v8_libplatform   HINTS ${v8_lib_hints} PATH_SUFFIXES out.gn/ts_release_${TS_X_PLATFORM}/obj)

    find_library(V8_SHARED_LIBRARY_DEBUG    NAMES v8               HINTS ${v8_lib_hints} PATH_SUFFIXES out.gn/ts_debug_${TS_X_PLATFORM}/obj)
    find_library(V8_STATIC_LIBRARY_DEBUG    NAMES v8_monolith      HINTS ${v8_lib_hints} PATH_SUFFIXES out.gn/ts_debug_${TS_X_PLATFORM}/obj)
    find_library(V8_STATIC_LIBRARY_DEBUG2   NAMES v8_libbase       HINTS ${v8_lib_hints} PATH_SUFFIXES out.gn/ts_debug_${TS_X_PLATFORM}/obj)
    find_library(V8_STATIC_LIBRARY_DEBUG3   NAMES v8_libplatform   HINTS ${v8_lib_hints} PATH_SUFFIXES out.gn/ts_debug_${TS_X_PLATFORM}/obj)

    # if (NOT V8_STATIC_LIBRARY_DEBUG)
    #     set(V8_STATIC_LIBRARY_DEBUG ${V8_STATIC_LIBRARY_RELEASE})
    # endif()
    # MARK_AS_ADVANCED(V8_STATIC_LIBRARY_DEBUG)

    # if (NOT V8_STATIC_LIBRARY_DEBUG2)
    #     set(V8_STATIC_LIBRARY_DEBUG2 ${V8_STATIC_LIBRARY_RELEASE2})
    # endif()
    # MARK_AS_ADVANCED(V8_STATIC_LIBRARY_DEBUG2)

    # if (NOT V8_STATIC_LIBRARY_DEBUG3)
    #     set(V8_STATIC_LIBRARY_DEBUG3 ${V8_STATIC_LIBRARY_RELEASE3})
    # endif()
    # MARK_AS_ADVANCED(V8_STATIC_LIBRARY_DEBUG3)



    SET(_tmp ${CMAKE_FIND_LIBRARY_SUFFIXES})
	SET(CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_SHARED_LIBRARY_SUFFIX})
    find_library(V8_SHARED_SO_RELEASE NAMES v8 HINTS   ${v8_bin_hints} PATH_SUFFIXES out.gn/ts_release_${TS_X_PLATFORM}/obj)
    find_library(V8_SHARED_SO_DEBUG   NAMES v8_d HINTS ${v8_bin_hints} PATH_SUFFIXES out.gn/ts_debug_${TS_X_PLATFORM}/obj)
    SET(CMAKE_FIND_LIBRARY_SUFFIXES ${_tmp})
else()
    set(v8_lib_hints
        ${V8_INCLUDE_DIR}/..
    )
    find_library(V8_SHARED_LIBRARY_RELEASE NAMES v8 HINTS            ${v8_lib_hints} PATH_SUFFIXES out.gn/ts_release_${TS_X_PLATFORM}/obj)
    find_library(V8_STATIC_LIBRARY_RELEASE NAMES v8_monolith HINTS   ${v8_lib_hints} PATH_SUFFIXES out.gn/ts_release_${TS_X_PLATFORM}/obj)
    find_library(V8_STATIC_LIBRARY_RELEASE2 NAMES v8_libbase       HINTS ${v8_lib_hints} PATH_SUFFIXES out.gn/ts_release_${TS_X_PLATFORM}/obj)
    find_library(V8_STATIC_LIBRARY_RELEASE3 NAMES v8_libplatform   HINTS ${v8_lib_hints} PATH_SUFFIXES out.gn/ts_release_${TS_X_PLATFORM}/obj)
    
    find_library(V8_SHARED_LIBRARY_DEBUG   NAMES v8_d HINTS          ${v8_lib_hints} PATH_SUFFIXES out.gn/ts_debug_${TS_X_PLATFORM}/obj)
    find_library(V8_STATIC_LIBRARY_DEBUG   NAMES v8_monolith_d HINTS ${v8_lib_hints} PATH_SUFFIXES out.gn/ts_debug_${TS_X_PLATFORM}/obj)
    find_library(V8_STATIC_LIBRARY_DEBUG2   NAMES v8_libbase       HINTS ${v8_lib_hints} PATH_SUFFIXES out.gn/ts_debug_${TS_X_PLATFORM}/obj)
    find_library(V8_STATIC_LIBRARY_DEBUG3   NAMES v8_libplatform   HINTS ${v8_lib_hints} PATH_SUFFIXES out.gn/ts_debug_${TS_X_PLATFORM}/obj)

endif(WIN32)
# MESSAGE(STATUS "
# V8_SHARED_LIBRARY_RELEASE  = ${V8_SHARED_LIBRARY_RELEASE}
# V8_STATIC_LIBRARY_RELEASE  = ${V8_STATIC_LIBRARY_RELEASE}
# V8_STATIC_LIBRARY_RELEASE2 = ${V8_STATIC_LIBRARY_RELEASE2}
# V8_STATIC_LIBRARY_RELEASE3 = ${V8_STATIC_LIBRARY_RELEASE3}
# V8_SHARED_LIBRARY_DEBUG    = ${V8_SHARED_LIBRARY_DEBUG}
# V8_STATIC_LIBRARY_DEBUG    = ${V8_STATIC_LIBRARY_DEBUG}
# V8_STATIC_LIBRARY_DEBUG2   = ${V8_STATIC_LIBRARY_DEBUG2}
# V8_STATIC_LIBRARY_DEBUG3   = ${V8_STATIC_LIBRARY_DEBUG3}")


# endif ()

# if (BZ2_INCLUDE_DIR AND EXISTS "${V8_INCLUDE_DIR}/v8.h")
#     file(STRINGS "${V8_INCLUDE_DIR}/bzlib.h" BZLIB_H REGEX "bzip2/libbzip2 version [0-9]+\\.[^ ]+ of [0-9]+ ")
#     string(REGEX REPLACE ".* bzip2/libbzip2 version ([0-9]+\\.[^ ]+) of [0-9]+ .*" "\\1" BZIP2_VERSION_STRING "${BZLIB_H}")
# endif ()

# handle the QUIETLY and REQUIRED arguments and set BZip2_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
IF(WIN32)
    FIND_PACKAGE_HANDLE_STANDARD_ARGS(V8
                                  REQUIRED_VARS V8_STATIC_LIBRARY_RELEASE V8_STATIC_LIBRARY_RELEASE2 V8_STATIC_LIBRARY_RELEASE3
                                  V8_STATIC_LIBRARY_DEBUG V8_STATIC_LIBRARY_DEBUG2 V8_STATIC_LIBRARY_DEBUG3
                                  V8_INCLUDE_DIR
                                  # V8_SHARED_LIBRARY_RELEASE V8_SHARED_LIBRARY_DEBUG V8_STATIC_LIBRARY_DEBUG 
                                  # VERSION_VAR V8_VERSION_STRING
                                  )
ELSE(WIN32)
    set(V8_SHARED_LIBRARY_DEBUG ${V8_SHARED_LIBRARY_RELEASE})
    FIND_PACKAGE_HANDLE_STANDARD_ARGS(V8
                                  REQUIRED_VARS V8_STATIC_LIBRARY_RELEASE V8_INCLUDE_DIR
                                  VERSION_VAR V8_VERSION_STRING)
ENDIF(WIN32)

if (V8_FOUND)
   include(CheckLibraryExists)
   include(CMakePushCheckState)
#    cmake_push_check_state()
#    set(CMAKE_REQUIRED_QUIET ${V8_FIND_QUIETLY})
#    CHECK_LIBRARY_EXISTS("${BZIP2_LIBRARIES}" BZ2_bzCompressInit "" BZIP2_NEED_PREFIX)
#    cmake_pop_check_state()

    if(NOT TARGET V8)
		if(WIN32)
            add_library(V8 UNKNOWN IMPORTED)
            set_target_properties(V8 PROPERTIES
                IMPORTED_LOCATION_DEBUG "${V8_STATIC_LIBRARY_DEBUG}"
                IMPORTED_LOCATION_RELEASE "${V8_STATIC_LIBRARY_RELEASE}"
                INTERFACE_INCLUDE_DIRECTORIES "${V8_INCLUDE_DIR};${V8_INCLUDE_DIR}/..;${V8_INCLUDE_DIR}/libplatform")
        else(WIN32)
		  add_library(V8 SHARED IMPORTED)
		  set_target_properties(V8 PROPERTIES
			IMPORTED_LOCATION_DEBUG "${V8_SHARED_LIBRARY_DEBUG}"
			IMPORTED_LOCATION_RELEASE "${V8_SHARED_LIBRARY_RELEASE}"
			IMPORTED_LOCATION_RELWITHDEBINFO "${V8_SHARED_LIBRARY_RELWITHDEBINFO}"
			INTERFACE_INCLUDE_DIRECTORIES "${V8_INCLUDE_DIRS};${V8_INCLUDE_DIR}/..;${V8_INCLUDE_DIR}/libplatform")
		endif(WIN32)
    endif()
    if(NOT TARGET V8_BASE)
        if(WIN32)
            add_library(V8_BASE UNKNOWN IMPORTED)
            set_target_properties(V8_BASE PROPERTIES
                IMPORTED_LOCATION_DEBUG "${V8_STATIC_LIBRARY_DEBUG2}"
                IMPORTED_LOCATION_RELEASE "${V8_STATIC_LIBRARY_RELEASE2}"
                INTERFACE_INCLUDE_DIRECTORIES "${V8_INCLUDE_DIR};${V8_INCLUDE_DIR}/..;${V8_INCLUDE_DIR}/libplatform")
        else(WIN32)
        endif(WIN32)
    endif()
    if(NOT TARGET V8_PLATFORM)
        if(WIN32)
            add_library(V8_PLATFORM UNKNOWN IMPORTED)
            set_target_properties(V8_PLATFORM PROPERTIES
                IMPORTED_LOCATION_DEBUG "${V8_STATIC_LIBRARY_DEBUG3}"
                IMPORTED_LOCATION_RELEASE "${V8_STATIC_LIBRARY_RELEASE3}"
                INTERFACE_INCLUDE_DIRECTORIES "${V8_INCLUDE_DIR};${V8_INCLUDE_DIR}/..;${V8_INCLUDE_DIR}/libplatform")
        else(WIN32)
        endif(WIN32)
    endif()
endif ()

mark_as_advanced(V8_INCLUDE_DIR)
