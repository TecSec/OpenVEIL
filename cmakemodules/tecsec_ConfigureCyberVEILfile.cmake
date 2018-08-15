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

if(APPLE)

  set(CyberVEILfile_NAME "CyberVEILfile")
	FIND_LIBRARY(CyberVEILfile_LIBRARY ${CyberVEILfile_NAME})
	MARK_AS_ADVANCED(CyberVEILfile_LIBRARY)

	FIND_LIBRARY(CyberVEILfile_D_LIBRARY ${CyberVEILfile_NAME}_d)
  if (NOT CyberVEILfile_D_LIBRARY)
  	set(CyberVEILfile_D_LIBRARY ${CyberVEILfile_LIBRARY})
  endif()
	MARK_AS_ADVANCED(CyberVEILfile_D_LIBRARY)

  set(CYBERVEILFILE_ROOT_DIR ${CyberVEILfile_LIBRARY})


  if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    set(CyberVEILfile_TARGET ${CyberVEILfile_D_LIBRARY})
  else()
    set(CyberVEILfile_TARGET ${CyberVEILfile_LIBRARY})
  endif()

  message(STATUS "CyberVEILfile target:  ${CyberVEILfile_TARGET}")
  #add_definitions(-framework ${CyberVEIL_NAME})

  #  TODO:  Need lots of stuff here
  if(NOT TARGET CyberVEILfile)
    add_library(CyberVEILfile SHARED IMPORTED)
    set_target_properties(CyberVEILfile PROPERTIES
        IMPORTED_LOCATION_DEBUG "${CyberVEILfile_TARGET}"
        IMPORTED_LOCATION_RELEASE "${CyberVEILfile_TARGET}"
        INTERFACE_INCLUDE_DIRECTORIES "${CyberVEILfile_TARGET}/Headers"
        )
  endif()

else()
  set(__path_suffixes 
    TecSec/VEIL_7-0
    TecSec/VEIL_7
    TecSec/VEIL
    VEIL_7-0
    VEIL_7
    VEIL
  )
  if(WIN32)
    GET_FILENAME_COMPONENT(__regPath [HKEY_CURRENT_USER\\SOFTWARE\\TecSec\\VEILSDK\\CyberVEIL\\SdkDir] ABSOLUTE)

    set(__paths 
        ENV CyberVEIL_ROOT
        ENV CyberVEIL
        C:/
        C:/TecSec
        D:/
        ENV ProgramFiles\(x86\)
        ENV ProgramFiles
        $ENV{HOMEDRIVE}$ENV{HOMEPATH}/AppData/Local/TecSec/VEILSDK
    )
    if(__regPath)
      set(__paths __regPath ${__paths})
    endif(__regPath)
  else()
    set(__paths
      /usr
      /usr/local
      ~/local 
    )
  endif(WIN32)

  set(INCLUDE_PART include/TecSec/CyberVEIL)

  find_path(CYBERVEIL_ROOT_DIR
    NAMES 
    ${INCLUDE_PART}/CyberVEILfile.h
    PATHS
    ${__paths}
    PATH_SUFFIXES
    ${__path_suffixes}
    DOC 
    "CyberVEILfile base/installation directory"
    )

  if (CYBERVEIL_ROOT_DIR)
    if(NOT EXISTS ${CYBERVEIL_ROOT_DIR}/CyberVEIL.cmake)
      unset(CYBERVEIL_ROOT_DIR CACHE)
      find_path(CYBERVEIL_ROOT_DIR
        NAMES 
          ${INCLUDE_PART}/CyberVEILfile.h
        PATHS
          ${__paths}
        PATH_SUFFIXES
          ${__path_suffixes}
        DOC 
      "CyberVEILfile base/installation directory"
        )
    endif()
  endif()

  if(WIN32)
    set(BIN_PART bin${TS_LIB_DIR_SUFFIX})
    set(LIB_PART lib${TS_LIB_DIR_SUFFIX})
  else()
    set(BIN_PART bin)
    set(LIB_PART lib)
  endif(WIN32)


  if (CYBERVEIL_ROOT_DIR)
    
    if(DEBUG_CyberVEIL)
      message(STATUS "Looking for CyberVEILfile at:  ${CYBERVEIL_ROOT_DIR}/CyberVEIL.cmake")
    endif()

    set(CyberVEIL_ROOT_BIN_RELEASE "")
    set(CyberVEIL_ROOT_BIN_DEBUG "")
    set(CyberVEIL_ROOT_LIB_RELEASE "")
    set(CyberVEIL_ROOT_LIB_DEBUG "")

    if(UNIX)
      if (EXISTS "${CYBERVEIL_ROOT_DIR}/${LIB_PART}/${CMAKE_SHARED_LIBRARY_PREFIX}CyberVEILfile_${TS_X_PLATFORM}_d${CMAKE_SHARED_LIBRARY_SUFFIX}")
        set(CyberVEIL_ROOT_LIB_DEBUG "${CYBERVEIL_ROOT_DIR}/${LIB_PART}")
        set(CyberVEIL_ROOT_BIN_DEBUG "${CYBERVEIL_ROOT_DIR}/${BIN_PART}")
        set(__debugSuffix "_d")
      elseif(EXISTS "${CYBERVEIL_ROOT_DIR}/${LIB_PART}/${CMAKE_SHARED_LIBRARY_PREFIX}CyberVEILfile_${TS_X_PLATFORM}_d${CMAKE_SHARED_LIBRARY_SUFFIX}")
        set(CyberVEIL_ROOT_LIB_DEBUG "${CYBERVEIL_ROOT_DIR}/${LIB_PART}")
        set(CyberVEIL_ROOT_BIN_DEBUG "${CYBERVEIL_ROOT_DIR}/${BIN_PART}")
        set(__debugSuffix "_d")
      else()
        set(__debugSuffix "")
        set(CyberVEIL_ROOT_LIB_DEBUG "${CYBERVEIL_ROOT_DIR}/${LIB_PART}")
        set(CyberVEIL_ROOT_BIN_DEBUG "${CYBERVEIL_ROOT_DIR}/${BIN_PART}")
      endif()

      if(EXISTS "${CYBERVEIL_ROOT_DIR}/${LIB_PART}/${CMAKE_SHARED_LIBRARY_PREFIX}CyberVEILfile_${TS_X_PLATFORM}${CMAKE_SHARED_LIBRARY_SUFFIX}")
        set(CyberVEIL_ROOT_LIB_RELEASE "${CYBERVEIL_ROOT_DIR}/${LIB_PART}")
        set(CyberVEIL_ROOT_BIN_RELEASE "${CYBERVEIL_ROOT_DIR}/${BIN_PART}")
        set(__releaseSuffix "")
      else()
        set(__releaseSuffix "${__debugSuffix}")
        set(CyberVEIL_ROOT_LIB_RELEASE "${CyberVEIL_ROOT_LIB_DEBUG}")
        set(CyberVEIL_ROOT_BIN_RELEASE "${CyberVEIL_ROOT_BIN_DEBUG}")
      endif()

      set(CyberVEIL_SHLIB_DEBUG ${CyberVEIL_ROOT_LIB_DEBUG})
      set(CyberVEIL_SHLIB_RELEASE ${CyberVEIL_ROOT_LIB_RELEASE})
    else()
      if (EXISTS "${CYBERVEIL_ROOT_DIR}/${BIN_PART}_d/${CMAKE_SHARED_LIBRARY_PREFIX}CyberVEILfile_${TS_X_PLATFORM}_d${CMAKE_SHARED_LIBRARY_SUFFIX}")
        set(CyberVEIL_ROOT_BIN_DEBUG "${CYBERVEIL_ROOT_DIR}/${BIN_PART}_d")
        set(CyberVEIL_ROOT_LIB_DEBUG "${CYBERVEIL_ROOT_DIR}/${LIB_PART}")
        set(__debugSuffix "_d")
      elseif(EXISTS "${CYBERVEIL_ROOT_DIR}/${BIN_PART}/${CMAKE_SHARED_LIBRARY_PREFIX}CyberVEILfile_${TS_X_PLATFORM}_d${CMAKE_SHARED_LIBRARY_SUFFIX}")
        set(CyberVEIL_ROOT_BIN_DEBUG "${CYBERVEIL_ROOT_DIR}/${BIN_PART}")
        set(CyberVEIL_ROOT_LIB_DEBUG "${CYBERVEIL_ROOT_DIR}/${LIB_PART}")
        set(__debugSuffix "_d")
      else()
        set(__debugSuffix "")
        set(CyberVEIL_ROOT_BIN_DEBUG "${CYBERVEIL_ROOT_DIR}/${BIN_PART}")
        set(CyberVEIL_ROOT_LIB_DEBUG "${CYBERVEIL_ROOT_DIR}/${LIB_PART}")
      endif()

      if(EXISTS "${CYBERVEIL_ROOT_DIR}/${BIN_PART}/${CMAKE_SHARED_LIBRARY_PREFIX}CyberVEILfile_${TS_X_PLATFORM}${CMAKE_SHARED_LIBRARY_SUFFIX}")
        set(CyberVEIL_ROOT_BIN_RELEASE "${CYBERVEIL_ROOT_DIR}/${BIN_PART}")
        set(CyberVEIL_ROOT_LIB_RELEASE "${CYBERVEIL_ROOT_DIR}/${LIB_PART}")
        set(__releaseSuffix "")
      else()
        set(__releaseSuffix "${__debugSuffix}")
        set(CyberVEIL_ROOT_LIB_RELEASE "${CyberVEIL_ROOT_LIB_DEBUG}")
        set(CyberVEIL_ROOT_BIN_RELEASE "${CyberVEIL_ROOT_BIN_DEBUG}")
      endif()
      set(CyberVEIL_SHLIB_DEBUG ${CyberVEIL_ROOT_BIN_DEBUG})
      set(CyberVEIL_SHLIB_RELEASE ${CyberVEIL_ROOT_BIN_RELEASE})
    endif()
      
    set(CRYPTO_INSTALL_PREFIX "${CYBERVEIL_ROOT_DIR}")
    set(CRYPTO_BIN_DIR "${CyberVEIL_ROOT_BIN_RELEASE}")
    set(CRYPTO_INCLUDE_DIR "${CYBERVEIL_ROOT_DIR}/${INCLUDE_PART}")
    set(CRYPTO_LIB_DIR "${CyberVEIL_ROOT_LIB_RELEASE}")
    if(UNIX)
      set(CRYPTO_SHLIB_DIR "${CRYPTO_LIB_DIR}")
    else()
      set(CRYPTO_SHLIB_DIR "${CRYPTO_BIN_DIR}")
    endif()

    if(NOT TARGET CyberVEILfile)
      if(WIN32 AND MINGW AND EXISTS ${CyberVEIL_SHLIB_RELEASE}/CyberVEILfile_${TS_X_PLATFORM}${__releaseSuffix}.dll)
        add_library(CyberVEILfile SHARED IMPORTED)
        set_target_properties(CyberVEILfile PROPERTIES
          IMPORTED_LOCATION_DEBUG "${CyberVEIL_SHLIB_DEBUG}/CyberVEILfile_${TS_X_PLATFORM}${__debugSuffix}.dll"
          IMPORTED_LOCATION_RELEASE "${CyberVEIL_SHLIB_RELEASE}/CyberVEILfile_${TS_X_PLATFORM}${__releaseSuffix}.dll"
          IMPORTED_IMPLIB_DEBUG "${CyberVEIL_ROOT_LIB_DEBUG}/CyberVEILfile_${TS_X_PLATFORM}${__debugSuffix}.lib"
          IMPORTED_IMPLIB_RELEASE "${CyberVEIL_ROOT_LIB_RELEASE}/CyberVEILfile_${TS_X_PLATFORM}${__releaseSuffix}.lib"
          INTERFACE_INCLUDE_DIRECTORIES "${CRYPTO_INCLUDE_DIR}"
          INTERFACE_INCLUDE_DIRECTORIES_DEBUG "${CRYPTO_INCLUDE_DIR}"
          INTERFACE_INCLUDE_DIRECTORIES_RELEASE "${CRYPTO_INCLUDE_DIR}"
          INTERFACE_BIN_MODULES_DEBUG "${CyberVEIL_SHLIB_DEBUG}/CyberVEILfile_${TS_X_PLATFORM}${__debugSuffix}.dll"
          INTERFACE_BIN_MODULES_RELEASE "${CyberVEIL_SHLIB_RELEASE}/CyberVEILfile_${TS_X_PLATFORM}${__releaseSuffix}.dll"
        )
      elseif(EXISTS ${CyberVEIL_SHLIB_RELEASE}/${CMAKE_SHARED_LIBRARY_PREFIX}CyberVEILfile_${TS_X_PLATFORM}${__releaseSuffix}${CMAKE_SHARED_LIBRARY_SUFFIX})
        add_library(CyberVEILfile SHARED IMPORTED)
        set_target_properties(CyberVEILfile PROPERTIES
          IMPORTED_LOCATION_DEBUG "${CyberVEIL_SHLIB_DEBUG}/${CMAKE_SHARED_LIBRARY_PREFIX}CyberVEILfile_${TS_X_PLATFORM}${__debugSuffix}${CMAKE_SHARED_LIBRARY_SUFFIX}"
          IMPORTED_LOCATION_RELEASE "${CyberVEIL_SHLIB_RELEASE}/${CMAKE_SHARED_LIBRARY_PREFIX}CyberVEILfile_${TS_X_PLATFORM}${__releaseSuffix}${CMAKE_SHARED_LIBRARY_SUFFIX}"
          IMPORTED_IMPLIB_DEBUG "${CyberVEIL_ROOT_LIB_DEBUG}/${CMAKE_STATIC_LIBRARY_PREFIX}CyberVEILfile_${TS_X_PLATFORM}${__debugSuffix}${CMAKE_STATIC_LIBRARY_SUFFIX}"
          IMPORTED_IMPLIB_RELEASE "${CyberVEIL_ROOT_LIB_RELEASE}/${CMAKE_STATIC_LIBRARY_PREFIX}CyberVEILfile_${TS_X_PLATFORM}${__releaseSuffix}${CMAKE_STATIC_LIBRARY_SUFFIX}"
          INTERFACE_INCLUDE_DIRECTORIES "${CRYPTO_INCLUDE_DIR}"
          INTERFACE_INCLUDE_DIRECTORIES_DEBUG "${CRYPTO_INCLUDE_DIR}"
          INTERFACE_INCLUDE_DIRECTORIES_RELEASE "${CRYPTO_INCLUDE_DIR}"
          INTERFACE_BIN_MODULES_DEBUG "${CyberVEIL_SHLIB_DEBUG}/${CMAKE_SHARED_LIBRARY_PREFIX}CyberVEILfile_${TS_X_PLATFORM}${__debugSuffix}${CMAKE_SHARED_LIBRARY_SUFFIX}"
          INTERFACE_BIN_MODULES_RELEASE "${CyberVEIL_SHLIB_RELEASE}/${CMAKE_SHARED_LIBRARY_PREFIX}CyberVEILfile_${TS_X_PLATFORM}${__releaseSuffix}${CMAKE_SHARED_LIBRARY_SUFFIX}"
        )
      else()
        message(FATAL_ERROR "CyberVEILfile not found")
      endif()
    endif()
    if(NOT TARGET CyberVEILfile_s)
      if(EXISTS ${CyberVEIL_ROOT_LIB_RELEASE}/${CMAKE_STATIC_LIBRARY_PREFIX}CyberVEILfile_${TS_X_PLATFORM}_static${__releaseSuffix}${CMAKE_STATIC_LIBRARY_SUFFIX})
        add_library(CyberVEILfile_s STATIC IMPORTED)
        set_target_properties(CyberVEILfile_s PROPERTIES
          IMPORTED_LOCATION_DEBUG "${CyberVEIL_ROOT_LIB_DEBUG}/${CMAKE_STATIC_LIBRARY_PREFIX}CyberVEILfile_${TS_X_PLATFORM}_static${__debugSuffix}${CMAKE_STATIC_LIBRARY_SUFFIX}"
          IMPORTED_LOCATION_RELEASE "${CyberVEIL_ROOT_LIB_RELEASE}/${CMAKE_STATIC_LIBRARY_PREFIX}CyberVEILfile_${TS_X_PLATFORM}_static${__releaseSuffix}${CMAKE_STATIC_LIBRARY_SUFFIX}"
          INTERFACE_INCLUDE_DIRECTORIES "${CRYPTO_INCLUDE_DIR}"
          INTERFACE_INCLUDE_DIRECTORIES_DEBUG "${CRYPTO_INCLUDE_DIR}"
          INTERFACE_INCLUDE_DIRECTORIES_RELEASE "${CRYPTO_INCLUDE_DIR}"
        )
      else()
        #message(FATAL_ERROR "CyberVEILfile_s not found")
      endif()
    endif()

  else ()
    message(FATAL_ERROR "CyberVEILfile could not be found.")
  endif(CYBERVEIL_ROOT_DIR)
endif(APPLE)

