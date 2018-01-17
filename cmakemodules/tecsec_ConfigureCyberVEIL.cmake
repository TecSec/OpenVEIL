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

  set(CyberVEIL_NAME "CyberVEIL")
	FIND_LIBRARY(CyberVEIL_LIBRARY ${CyberVEIL_NAME})
	MARK_AS_ADVANCED(CyberVEIL_LIBRARY)

	FIND_LIBRARY(CyberVEIL_D_LIBRARY ${CyberVEIL_NAME}_d)
  if (NOT CyberVEIL_D_LIBRARY)
  	set(CyberVEIL_D_LIBRARY ${CyberVEIL_LIBRARY})
  endif()
	MARK_AS_ADVANCED(CyberVEIL_D_LIBRARY)

  set(CYBERVEIL_ROOT_DIR ${CyberVEIL_LIBRARY})


  if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    set(CyberVEIL_TARGET ${CyberVEIL_D_LIBRARY})
  else()
    set(CyberVEIL_TARGET ${CyberVEIL_LIBRARY})
  endif()

  include(${CyberVEIL_TARGET}/CyberVEIL.cmake)

  message(STATUS "CyberVEIL target:  ${CyberVEIL_TARGET}  Version: ${CRYPTO_VERSION}")
  #add_definitions(-framework ${CyberVEIL_NAME})

  #  TODO:  Need lots of stuff here
  if(NOT TARGET CyberVEIL)
    add_library(CyberVEIL SHARED IMPORTED)
    set_target_properties(CyberVEIL PROPERTIES
        IMPORTED_LOCATION_DEBUG "${CyberVEIL_TARGET}"
        IMPORTED_LOCATION_RELEASE "${CyberVEIL_TARGET}"
        INTERFACE_INCLUDE_DIRECTORIES "${CyberVEIL_TARGET}/Headers"
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
      ${INCLUDE_PART}/CyberVEIL.h
      PATHS
      ${__paths}
      PATH_SUFFIXES
      ${__path_suffixes}
      DOC 
      "CyberVEIL base/installation directory"
      )

    if (CYBERVEIL_ROOT_DIR)
      if(NOT EXISTS ${CYBERVEIL_ROOT_DIR}/CyberVEIL.cmake)
        unset(CYBERVEIL_ROOT_DIR CACHE)
        find_path(CYBERVEIL_ROOT_DIR
          NAMES 
            ${INCLUDE_PART}/CyberVEIL.h
          PATHS
            ${__paths}
          PATH_SUFFIXES
            ${__path_suffixes}
          DOC 
        "CyberVEIL base/installation directory"
          )
      endif()
    endif()

  if(APPLE)
	  set(BIN_PART bin)
	  set(LIB_PART lib)
  elseif(WIN32)
    set(BIN_PART bin${TS_LIB_DIR_SUFFIX})
    set(LIB_PART lib${TS_LIB_DIR_SUFFIX})
  else()
    set(BIN_PART bin)
    set(LIB_PART lib)
  endif(APPLE)


  if (CYBERVEIL_ROOT_DIR)
    
    if(DEBUG_CyberVEIL)
      message(STATUS "Looking for CyberVEIL at:  ${CYBERVEIL_ROOT_DIR}/CyberVEIL.cmake")
    endif()

    # Build the values needed for program development here
    if(EXISTS ${CYBERVEIL_ROOT_DIR}/CyberVEIL.cmake)
      include(${CYBERVEIL_ROOT_DIR}/CyberVEIL.cmake)

      set(CyberVEIL_ROOT_BIN_RELEASE "")
      set(CyberVEIL_ROOT_BIN_DEBUG "")
      set(CyberVEIL_ROOT_LIB_RELEASE "")
      set(CyberVEIL_ROOT_LIB_DEBUG "")

      if(UNIX)
        if (EXISTS "${CYBERVEIL_ROOT_DIR}/${LIB_PART}/${CMAKE_SHARED_LIBRARY_PREFIX}CyberVEIL_d${CMAKE_SHARED_LIBRARY_SUFFIX}")
          set(CyberVEIL_ROOT_LIB_DEBUG "${CYBERVEIL_ROOT_DIR}/${LIB_PART}")
          set(CyberVEIL_ROOT_BIN_DEBUG "${CYBERVEIL_ROOT_DIR}/${BIN_PART}")
          set(__debugSuffix "_d")
        elseif(EXISTS "${CYBERVEIL_ROOT_DIR}/${LIB_PART}/${CMAKE_SHARED_LIBRARY_PREFIX}CyberVEIL_d${CMAKE_SHARED_LIBRARY_SUFFIX}")
          set(CyberVEIL_ROOT_LIB_DEBUG "${CYBERVEIL_ROOT_DIR}/${LIB_PART}")
          set(CyberVEIL_ROOT_BIN_DEBUG "${CYBERVEIL_ROOT_DIR}/${BIN_PART}")
          set(__debugSuffix "_d")
        else()
          set(__debugSuffix "")
          set(CyberVEIL_ROOT_LIB_DEBUG "${CYBERVEIL_ROOT_DIR}/${LIB_PART}")
          set(CyberVEIL_ROOT_BIN_DEBUG "${CYBERVEIL_ROOT_DIR}/${BIN_PART}")
        endif()

        if(EXISTS "${CYBERVEIL_ROOT_DIR}/${LIB_PART}/${CMAKE_SHARED_LIBRARY_PREFIX}CyberVEIL${CMAKE_SHARED_LIBRARY_SUFFIX}")
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
        if (EXISTS "${CYBERVEIL_ROOT_DIR}/${BIN_PART}_d/${CMAKE_SHARED_LIBRARY_PREFIX}CyberVEIL_d${CMAKE_SHARED_LIBRARY_SUFFIX}")
          set(CyberVEIL_ROOT_BIN_DEBUG "${CYBERVEIL_ROOT_DIR}/${BIN_PART}_d")
          set(CyberVEIL_ROOT_LIB_DEBUG "${CYBERVEIL_ROOT_DIR}/${LIB_PART}")
          set(__debugSuffix "_d")
        elseif(EXISTS "${CYBERVEIL_ROOT_DIR}/${BIN_PART}/${CMAKE_SHARED_LIBRARY_PREFIX}CyberVEIL_d${CMAKE_SHARED_LIBRARY_SUFFIX}")
          set(CyberVEIL_ROOT_BIN_DEBUG "${CYBERVEIL_ROOT_DIR}/${BIN_PART}")
          set(CyberVEIL_ROOT_LIB_DEBUG "${CYBERVEIL_ROOT_DIR}/${LIB_PART}")
          set(__debugSuffix "_d")
        else()
          set(__debugSuffix "")
          set(CyberVEIL_ROOT_BIN_DEBUG "${CYBERVEIL_ROOT_DIR}/${BIN_PART}")
          set(CyberVEIL_ROOT_LIB_DEBUG "${CYBERVEIL_ROOT_DIR}/${LIB_PART}")
        endif()

        if(EXISTS "${CYBERVEIL_ROOT_DIR}/${BIN_PART}/${CMAKE_SHARED_LIBRARY_PREFIX}CyberVEIL${CMAKE_SHARED_LIBRARY_SUFFIX}")
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

      if(DEBUG_CYBERVEIL)
        message(STATUS "CRYPTO_INSTALL_PREFIX           = ${CRYPTO_INSTALL_PREFIX}")
        message(STATUS "CRYPTO_BIN_DIR                  = ${CRYPTO_BIN_DIR}")
        message(STATUS "CRYPTO_INCLUDE_DIR              = ${CRYPTO_INCLUDE_DIR}")
        message(STATUS "CRYPTO_LIB_DIR                  = ${CRYPTO_LIB_DIR}")
        message(STATUS "CRYPTO_SHLIB_DIR                = ${CRYPTO_SHLIB_DIR}")

        message(STATUS "__debugSuffix                   = ${__debugSuffix}")
        message(STATUS "CyberVEIL_ROOT_LIB_DEBUG        = ${CyberVEIL_ROOT_LIB_DEBUG}")
        message(STATUS "CyberVEIL_ROOT_BIN_DEBUG        = ${CyberVEIL_ROOT_BIN_DEBUG}")
        message(STATUS "__releaseSuffix                 = ${__releaseSuffix}")
        message(STATUS "CyberVEIL_ROOT_LIB_RELEASE      = ${CyberVEIL_ROOT_LIB_RELEASE}")
        message(STATUS "CyberVEIL_ROOT_BIN_RELEASE      = ${CyberVEIL_ROOT_BIN_RELEASE}")
        message(STATUS "CyberVEIL_SHLIB_DEBUG           = ${CyberVEIL_SHLIB_DEBUG}")
        message(STATUS "CyberVEIL_SHLIB_RELEASE         = ${CyberVEIL_SHLIB_RELEASE}")


      endif(DEBUG_CYBERVEIL)


      if(NOT TARGET CyberVEIL)
        if(WIN32 AND MINGW AND EXISTS ${CyberVEIL_SHLIB_RELEASE}/CyberVEIL${__releaseSuffix}.dll)
          add_library(CyberVEIL SHARED IMPORTED)
          set_target_properties(CyberVEIL PROPERTIES
            IMPORTED_LOCATION_DEBUG "${CyberVEIL_SHLIB_DEBUG}/CyberVEIL${__debugSuffix}.dll"
            IMPORTED_LOCATION_RELEASE "${CyberVEIL_SHLIB_RELEASE}/CyberVEIL${__releaseSuffix}.dll"
            IMPORTED_IMPLIB_DEBUG "${CyberVEIL_ROOT_LIB_DEBUG}/CyberVEIL${__debugSuffix}.lib"
            IMPORTED_IMPLIB_RELEASE "${CyberVEIL_ROOT_LIB_RELEASE}/CyberVEIL${__releaseSuffix}.lib"
            INTERFACE_INCLUDE_DIRECTORIES "${CRYPTO_INCLUDE_DIR}"
            INTERFACE_INCLUDE_DIRECTORIES_DEBUG "${CRYPTO_INCLUDE_DIR}"
            INTERFACE_INCLUDE_DIRECTORIES_RELEASE "${CRYPTO_INCLUDE_DIR}"
            INTERFACE_BIN_MODULES_DEBUG "${CyberVEIL_SHLIB_DEBUG}/CyberVEIL${__debugSuffix}.dll"
            INTERFACE_BIN_MODULES_RELEASE "${CyberVEIL_SHLIB_RELEASE}/CyberVEIL${__releaseSuffix}.dll"
          )
        elseif(EXISTS ${CyberVEIL_SHLIB_RELEASE}/${CMAKE_SHARED_LIBRARY_PREFIX}CyberVEIL${__releaseSuffix}${CMAKE_SHARED_LIBRARY_SUFFIX})
          add_library(CyberVEIL SHARED IMPORTED)
          set_target_properties(CyberVEIL PROPERTIES
            IMPORTED_LOCATION_DEBUG "${CyberVEIL_SHLIB_DEBUG}/${CMAKE_SHARED_LIBRARY_PREFIX}CyberVEIL${__debugSuffix}${CMAKE_SHARED_LIBRARY_SUFFIX}"
            IMPORTED_LOCATION_RELEASE "${CyberVEIL_SHLIB_RELEASE}/${CMAKE_SHARED_LIBRARY_PREFIX}CyberVEIL${__releaseSuffix}${CMAKE_SHARED_LIBRARY_SUFFIX}"
            IMPORTED_IMPLIB_DEBUG "${CyberVEIL_ROOT_LIB_DEBUG}/${CMAKE_STATIC_LIBRARY_PREFIX}CyberVEIL${__debugSuffix}${CMAKE_STATIC_LIBRARY_SUFFIX}"
            IMPORTED_IMPLIB_RELEASE "${CyberVEIL_ROOT_LIB_RELEASE}/${CMAKE_STATIC_LIBRARY_PREFIX}CyberVEIL${__releaseSuffix}${CMAKE_STATIC_LIBRARY_SUFFIX}"
            INTERFACE_INCLUDE_DIRECTORIES "${CRYPTO_INCLUDE_DIR}"
            INTERFACE_INCLUDE_DIRECTORIES_DEBUG "${CRYPTO_INCLUDE_DIR}"
            INTERFACE_INCLUDE_DIRECTORIES_RELEASE "${CRYPTO_INCLUDE_DIR}"
            INTERFACE_BIN_MODULES_DEBUG "${CyberVEIL_SHLIB_DEBUG}/${CMAKE_SHARED_LIBRARY_PREFIX}CyberVEIL${__debugSuffix}${CMAKE_SHARED_LIBRARY_SUFFIX}"
            INTERFACE_BIN_MODULES_RELEASE "${CyberVEIL_SHLIB_RELEASE}/${CMAKE_SHARED_LIBRARY_PREFIX}CyberVEIL${__releaseSuffix}${CMAKE_SHARED_LIBRARY_SUFFIX}"
          )
        else()
          message(FATAL_ERROR "CyberVEIL not found")
        endif()
      endif()
      if(NOT TARGET SQLite.cyberveil.db)
        if(WIN32 AND MINGW AND EXISTS ${CyberVEIL_SHLIB_RELEASE}/SQLite.cyberveil.db.dll)
          add_library(SQLite.cyberveil.db SHARED IMPORTED)
          set_target_properties(SQLite.cyberveil.db PROPERTIES
            IMPORTED_LOCATION_DEBUG "${CyberVEIL_SHLIB_DEBUG}/SQLite.cyberveil.db.dll"
            IMPORTED_LOCATION_RELEASE "${CyberVEIL_SHLIB_RELEASE}/SQLite.cyberveil.db.dll"
            INTERFACE_BIN_MODULES_DEBUG "${CyberVEIL_SHLIB_DEBUG}/SQLite.cyberveil.db.dll"
            INTERFACE_BIN_MODULES_RELEASE "${CyberVEIL_SHLIB_RELEASE}/SQLite.cyberveil.db.dll"
          )
        elseif(EXISTS ${CyberVEIL_SHLIB_RELEASE}/${CMAKE_SHARED_LIBRARY_PREFIX}SQLite.cyberveil.db${CMAKE_SHARED_LIBRARY_SUFFIX})
          add_library(SQLite.cyberveil.db SHARED IMPORTED)
          set_target_properties(SQLite.cyberveil.db PROPERTIES
            IMPORTED_LOCATION_DEBUG "${CyberVEIL_SHLIB_DEBUG}/${CMAKE_SHARED_LIBRARY_PREFIX}SQLite.cyberveil.db${CMAKE_SHARED_LIBRARY_SUFFIX}"
            IMPORTED_LOCATION_RELEASE "${CyberVEIL_SHLIB_RELEASE}/${CMAKE_SHARED_LIBRARY_PREFIX}SQLite.cyberveil.db${CMAKE_SHARED_LIBRARY_SUFFIX}"
            INTERFACE_BIN_MODULES_DEBUG "${CyberVEIL_SHLIB_DEBUG}/${CMAKE_SHARED_LIBRARY_PREFIX}SQLite.cyberveil.db${CMAKE_SHARED_LIBRARY_SUFFIX}"
            INTERFACE_BIN_MODULES_RELEASE "${CyberVEIL_SHLIB_RELEASE}/${CMAKE_SHARED_LIBRARY_PREFIX}SQLite.cyberveil.db${CMAKE_SHARED_LIBRARY_SUFFIX}"
          )
        else()
          message(FATAL_ERROR "SQLite.cyberveil.db not found")
        endif()
      endif()
      if(NOT TARGET ODBC.cyberveil.db)
      if(WIN32 AND MINGW AND EXISTS ${CyberVEIL_SHLIB_RELEASE}/ODBC.cyberveil.db.dll)
        add_library(ODBC.cyberveil.db SHARED IMPORTED)
        set_target_properties(ODBC.cyberveil.db PROPERTIES
          IMPORTED_LOCATION_DEBUG "${CyberVEIL_SHLIB_DEBUG}/ODBC.cyberveil.db.dll"
          IMPORTED_LOCATION_RELEASE "${CyberVEIL_SHLIB_RELEASE}/ODBC.cyberveil.db.dll"
          INTERFACE_BIN_MODULES_DEBUG "${CyberVEIL_SHLIB_DEBUG}/ODBC.cyberveil.db.dll"
          INTERFACE_BIN_MODULES_RELEASE "${CyberVEIL_SHLIB_RELEASE}/ODBC.cyberveil.db.dll"
        )
      elseif(EXISTS ${CyberVEIL_SHLIB_RELEASE}/${CMAKE_SHARED_LIBRARY_PREFIX}ODBC.cyberveil.db${CMAKE_SHARED_LIBRARY_SUFFIX})
        add_library(ODBC.cyberveil.db SHARED IMPORTED)
        set_target_properties(ODBC.cyberveil.db PROPERTIES
          IMPORTED_LOCATION_DEBUG "${CyberVEIL_SHLIB_DEBUG}/${CMAKE_SHARED_LIBRARY_PREFIX}ODBC.cyberveil.db${CMAKE_SHARED_LIBRARY_SUFFIX}"
          IMPORTED_LOCATION_RELEASE "${CyberVEIL_SHLIB_RELEASE}/${CMAKE_SHARED_LIBRARY_PREFIX}ODBC.cyberveil.db${CMAKE_SHARED_LIBRARY_SUFFIX}"
          INTERFACE_BIN_MODULES_DEBUG "${CyberVEIL_SHLIB_DEBUG}/${CMAKE_SHARED_LIBRARY_PREFIX}ODBC.cyberveil.db${CMAKE_SHARED_LIBRARY_SUFFIX}"
          INTERFACE_BIN_MODULES_RELEASE "${CyberVEIL_SHLIB_RELEASE}/${CMAKE_SHARED_LIBRARY_PREFIX}ODBC.cyberveil.db${CMAKE_SHARED_LIBRARY_SUFFIX}"
        )
      else()
        message(FATAL_ERROR "ODBC.cyberveil.db not found")
      endif()
    endif()
      if(NOT TARGET CyberVEIL_s)
        if(EXISTS ${CyberVEIL_ROOT_LIB_RELEASE}/${CMAKE_STATIC_LIBRARY_PREFIX}CyberVEIL_static${__releaseSuffix}${CMAKE_STATIC_LIBRARY_SUFFIX})
          add_library(CyberVEIL_s STATIC IMPORTED)
          set_target_properties(CyberVEIL_s PROPERTIES
            IMPORTED_LOCATION_DEBUG "${CyberVEIL_ROOT_LIB_DEBUG}/${CMAKE_STATIC_LIBRARY_PREFIX}CyberVEIL_static${__debugSuffix}${CMAKE_STATIC_LIBRARY_SUFFIX}"
            IMPORTED_LOCATION_RELEASE "${CyberVEIL_ROOT_LIB_RELEASE}/${CMAKE_STATIC_LIBRARY_PREFIX}CyberVEIL_static${__releaseSuffix}${CMAKE_STATIC_LIBRARY_SUFFIX}"
            INTERFACE_INCLUDE_DIRECTORIES "${CRYPTO_INCLUDE_DIR}"
            INTERFACE_INCLUDE_DIRECTORIES_DEBUG "${CRYPTO_INCLUDE_DIR}"
            INTERFACE_INCLUDE_DIRECTORIES_RELEASE "${CRYPTO_INCLUDE_DIR}"
          )
        else()
          #message(FATAL_ERROR "CyberVEIL_s not found")
        endif()
      endif()
    else ()
      message(FATAL_ERROR "CyberVEIL.cmake could not be found.")
    endif()

  else ()
    message(FATAL_ERROR "CyberVEIL could not be found.")
  endif(CYBERVEIL_ROOT_DIR)
endif(APPLE)

