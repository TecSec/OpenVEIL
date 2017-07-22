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

if(APPLE)

  set(TSALG_NAME "TSALG")
	FIND_LIBRARY(TSALG_LIBRARY ${TSALG_NAME})
	FIND_LIBRARY(TS_SUP_LIBRARY ts_sup_dll)
	MARK_AS_ADVANCED(TSALG_LIBRARY)
	MARK_AS_ADVANCED(TS_SUP_LIBRARY)

	FIND_LIBRARY(TSALG_D_LIBRARY ${TSALG_NAME}_d)
  FIND_LIBRARY(TS_SUP_D_LIBRARY ts_sup_dll_d)
  if (NOT TSALG_D_LIBRARY)
  	set(TSALG_D_LIBRARY ${TSALG_LIBRARY})
  	set(TS_SUP_D_LIBRARY ${TS_SUP_LIBRARY})
  endif()
	MARK_AS_ADVANCED(TSALG_D_LIBRARY)
	MARK_AS_ADVANCED(TS_SUP_D_LIBRARY)

  set(TSALG_ROOT_DIR ${TSALG_LIBRARY})


  if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    set(TSALG_TARGET ${TSALG_D_LIBRARY} ${TS_SUP_D_LIBRARY})
  else()
    set(TSALG_TARGET ${TSALG_LIBRARY} ${TS_SUP_LIBRARY})
  endif()

  include(${TSALG_TARGET}/TSALG.cmake)

  message(STATUS "Crypto target:  ${TSALG_TARGET}  Version: ${CRYPTO_VERSION}")
  #add_definitions(-framework ${TSALG_NAME})

  #  TODO:  Need lots of stuff here
  if(NOT TARGET TSALG)
    add_library(TSALG SHARED IMPORTED)
    set_target_properties(TSALG PROPERTIES
        IMPORTED_LOCATION_DEBUG "${TSALG_TARGET}"
        IMPORTED_LOCATION_RELEASE "${TSALG_TARGET}"
        INTERFACE_INCLUDE_DIRECTORIES "${TSALG_TARGET}/Headers"
        )
    add_library(TS_SUP_DLL SHARED IMPORTED)
    set_target_properties(TS_SUP_DLL PROPERTIES
        IMPORTED_LOCATION_DEBUG "${TS_SUP_TARGET}"
        IMPORTED_LOCATION_RELEASE "${TS_SUP_TARGET}"
        INTERFACE_INCLUDE_DIRECTORIES "${TS_SUP_TARGET}/Headers"
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
    GET_FILENAME_COMPONENT(__regPath [HKEY_CURRENT_USER\\SOFTWARE\\TecSec\\VEILSDK\\TSALG\\SdkDir] ABSOLUTE)

    set(__paths 
        ENV TSALG_ROOT
        ENV TSALG
        C:/
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

  if(UNIX)
    set(INCLUDE_PART include/TecSec/Crypto)
  else()
    set(INCLUDE_PART include/TecSec/Crypto)
  endif()

    find_path(TSALG_ROOT_DIR
      NAMES 
      ${INCLUDE_PART}/TSALG.h
      PATHS
      ${__paths}
      PATH_SUFFIXES
      ${__path_suffixes}
      DOC 
      "TSALG base/installation directory"
      )

    if (TSALG_ROOT_DIR)
      if(NOT EXISTS ${TSALG_ROOT_DIR}/${INCLUDE_PART}/TSALG.cmake)
        unset(TSALG_ROOT_DIR CACHE)
        find_path(TSALG_ROOT_DIR
          NAMES 
            ${INCLUDE_PART}/TSALG.h
          PATHS
            ${__paths}
          PATH_SUFFIXES
            ${__path_suffixes}
          DOC 
        "TSALG base/installation directory"
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


  if (TSALG_ROOT_DIR)
    
    if(DEBUG_TSALG)
      message(STATUS "Looking for TSALG at:  ${TSALG_ROOT_DIR}/${INCLUDE_PART}/TSALG.cmake")
    endif()

    # Build the values needed for program development here
    if(EXISTS ${TSALG_ROOT_DIR}/${INCLUDE_PART}/TSALG.cmake)
      include(${TSALG_ROOT_DIR}/${INCLUDE_PART}/TSALG.cmake)

      set(TSALG_ROOT_BIN_RELEASE "")
      set(TSALG_ROOT_BIN_DEBUG "")
      set(TSALG_ROOT_LIB_RELEASE "")
      set(TSALG_ROOT_LIB_DEBUG "")

      if(UNIX)
        if (EXISTS "${TSALG_ROOT_DIR}/${LIB_PART}/${CMAKE_SHARED_LIBRARY_PREFIX}TSALG_d${CMAKE_SHARED_LIBRARY_SUFFIX}")
          set(TSALG_ROOT_LIB_DEBUG "${TSALG_ROOT_DIR}/${LIB_PART}")
          set(TSALG_ROOT_BIN_DEBUG "${TSALG_ROOT_DIR}/${BIN_PART}")
          set(__debugSuffix "_d")
        elseif(EXISTS "${TSALG_ROOT_DIR}/${LIB_PART}/${CMAKE_SHARED_LIBRARY_PREFIX}TSALG_d${CMAKE_SHARED_LIBRARY_SUFFIX}")
          set(TSALG_ROOT_LIB_DEBUG "${TSALG_ROOT_DIR}/${LIB_PART}")
          set(TSALG_ROOT_BIN_DEBUG "${TSALG_ROOT_DIR}/${BIN_PART}")
          set(__debugSuffix "_d")
        else()
          set(__debugSuffix "")
          set(TSALG_ROOT_LIB_DEBUG "${TSALG_ROOT_DIR}/${LIB_PART}")
          set(TSALG_ROOT_BIN_DEBUG "${TSALG_ROOT_DIR}/${BIN_PART}")
        endif()

        if(EXISTS "${TSALG_ROOT_DIR}/${LIB_PART}/${CMAKE_SHARED_LIBRARY_PREFIX}TSALG${CMAKE_SHARED_LIBRARY_SUFFIX}")
          set(TSALG_ROOT_LIB_RELEASE "${TSALG_ROOT_DIR}/${LIB_PART}")
          set(TSALG_ROOT_BIN_RELEASE "${TSALG_ROOT_DIR}/${BIN_PART}")
          set(__releaseSuffix "")
        else()
          set(__releaseSuffix "${__debugSuffix}")
          set(TSALG_ROOT_LIB_RELEASE "${TSALG_ROOT_LIB_DEBUG}")
          set(TSALG_ROOT_BIN_RELEASE "${TSALG_ROOT_BIN_DEBUG}")
        endif()

        set(TSALG_SHLIB_DEBUG ${TSALG_ROOT_LIB_DEBUG})
        set(TSALG_SHLIB_RELEASE ${TSALG_ROOT_LIB_RELEASE})
      else()
        if (EXISTS "${TSALG_ROOT_DIR}/${BIN_PART}_d/${TS_TOOLSET}/${CMAKE_SHARED_LIBRARY_PREFIX}TSALG_d${CMAKE_SHARED_LIBRARY_SUFFIX}")
          set(TSALG_ROOT_BIN_DEBUG "${TSALG_ROOT_DIR}/${BIN_PART}_d/${TS_TOOLSET}")
          set(TSALG_ROOT_LIB_DEBUG "${TSALG_ROOT_DIR}/${LIB_PART}/${TS_TOOLSET}")
          set(__debugSuffix "_d")
        elseif(EXISTS "${TSALG_ROOT_DIR}/${BIN_PART}/${TS_TOOLSET}/${CMAKE_SHARED_LIBRARY_PREFIX}TSALG_d${CMAKE_SHARED_LIBRARY_SUFFIX}")
          set(TSALG_ROOT_BIN_DEBUG "${TSALG_ROOT_DIR}/${BIN_PART}/${TS_TOOLSET}")
          set(TSALG_ROOT_LIB_DEBUG "${TSALG_ROOT_DIR}/${LIB_PART}/${TS_TOOLSET}")
          set(__debugSuffix "_d")
        else()
          set(__debugSuffix "")
          set(TSALG_ROOT_BIN_DEBUG "${TSALG_ROOT_DIR}/${BIN_PART}/${TS_TOOLSET}")
          set(TSALG_ROOT_LIB_DEBUG "${TSALG_ROOT_DIR}/${LIB_PART}/${TS_TOOLSET}")
        endif()

        if(EXISTS "${TSALG_ROOT_DIR}/${BIN_PART}/${TS_TOOLSET}/${CMAKE_SHARED_LIBRARY_PREFIX}TSALG${CMAKE_SHARED_LIBRARY_SUFFIX}")
          set(TSALG_ROOT_BIN_RELEASE "${TSALG_ROOT_DIR}/${BIN_PART}/${TS_TOOLSET}")
          set(TSALG_ROOT_LIB_RELEASE "${TSALG_ROOT_DIR}/${LIB_PART}/${TS_TOOLSET}")
          set(__releaseSuffix "")
        else()
          set(__releaseSuffix "${__debugSuffix}")
          set(TSALG_ROOT_LIB_RELEASE "${TSALG_ROOT_LIB_DEBUG}/${TS_TOOLSET}")
          set(TSALG_ROOT_BIN_RELEASE "${TSALG_ROOT_BIN_DEBUG}/${TS_TOOLSET}")
        endif()
        set(TSALG_SHLIB_DEBUG ${TSALG_ROOT_BIN_DEBUG})
        set(TSALG_SHLIB_RELEASE ${TSALG_ROOT_BIN_RELEASE})
      endif()
      




      set(CRYPTO_INSTALL_PREFIX "${TSALG_ROOT_DIR}")
      set(CRYPTO_BIN_DIR "${TSALG_ROOT_BIN_RELEASE}")
      set(CRYPTO_INCLUDE_DIR "${TSALG_ROOT_DIR}/${INCLUDE_PART}")
      set(CRYPTO_LIB_DIR "${TSALG_ROOT_LIB_RELEASE}")
      if(UNIX)
        set(CRYPTO_SHLIB_DIR "${CRYPTO_LIB_DIR}")
      else()
        set(CRYPTO_SHLIB_DIR "${CRYPTO_BIN_DIR}")
      endif()

      if(DEBUG_TSALG)
        message(STATUS "CRYPTO_INSTALL_PREFIX       = ${CRYPTO_INSTALL_PREFIX}")
        message(STATUS "CRYPTO_BIN_DIR              = ${CRYPTO_BIN_DIR}")
        message(STATUS "CRYPTO_INCLUDE_DIR          = ${CRYPTO_INCLUDE_DIR}")
        message(STATUS "CRYPTO_LIB_DIR              = ${CRYPTO_LIB_DIR}")
        message(STATUS "CRYPTO_SHLIB_DIR            = ${CRYPTO_SHLIB_DIR}")

        message(STATUS "__debugSuffix               = ${__debugSuffix}")
        message(STATUS "TSALG_ROOT_LIB_DEBUG        = ${TSALG_ROOT_LIB_DEBUG}")
        message(STATUS "TSALG_ROOT_BIN_DEBUG        = ${TSALG_ROOT_BIN_DEBUG}")
        message(STATUS "__releaseSuffix             = ${__releaseSuffix}")
        message(STATUS "TSALG_ROOT_LIB_RELEASE      = ${TSALG_ROOT_LIB_RELEASE}")
        message(STATUS "TSALG_ROOT_BIN_RELEASE      = ${TSALG_ROOT_BIN_RELEASE}")
        message(STATUS "TSALG_SHLIB_DEBUG           = ${TSALG_SHLIB_DEBUG}")
        message(STATUS "TSALG_SHLIB_RELEASE         = ${TSALG_SHLIB_RELEASE}")


      endif(DEBUG_TSALG)


      if(NOT TARGET TSALG)
      if(WIN32 AND MINGW AND EXISTS ${TSALG_SHLIB_RELEASE}/TSALG${__releaseSuffix}.dll)
        add_library(TSALG SHARED IMPORTED)
        set_target_properties(TSALG PROPERTIES
        IMPORTED_LOCATION_DEBUG "${TSALG_SHLIB_DEBUG}/TSALG${__debugSuffix}.dll"
        IMPORTED_LOCATION_RELEASE "${TSALG_SHLIB_RELEASE}/TSALG${__releaseSuffix}.dll"
        IMPORTED_IMPLIB_DEBUG "${TSALG_ROOT_LIB_DEBUG}/TSALG${__debugSuffix}.lib"
        IMPORTED_IMPLIB_RELEASE "${TSALG_ROOT_LIB_RELEASE}/TSALG${__releaseSuffix}.lib"
        INTERFACE_INCLUDE_DIRECTORIES "${CRYPTO_INCLUDE_DIR}"
        INTERFACE_INCLUDE_DIRECTORIES_DEBUG "${CRYPTO_INCLUDE_DIR}"
        INTERFACE_INCLUDE_DIRECTORIES_RELEASE "${CRYPTO_INCLUDE_DIR}"
        INTERFACE_BIN_MODULES_DEBUG "${TSALG_SHLIB_DEBUG}/TSALG${__debugSuffix}.dll"
        INTERFACE_BIN_MODULES_RELEASE "${TSALG_SHLIB_RELEASE}/TSALG${__releaseSuffix}.dll"
        )
          add_library(TS_SUP_DLL SHARED IMPORTED)
          set_target_properties(TS_SUP_DLL PROPERTIES
            IMPORTED_LOCATION_DEBUG "${TSALG_SHLIB_DEBUG}/ts_sup_dll${__debugSuffix}.dll"
            IMPORTED_LOCATION_RELEASE "${TSALG_SHLIB_RELEASE}/ts_sup_dll${__releaseSuffix}.dll"
            IMPORTED_IMPLIB_DEBUG "${TSALG_ROOT_LIB_DEBUG}/ts_sup_dll${__debugSuffix}.lib"
            IMPORTED_IMPLIB_RELEASE "${TSALG_ROOT_LIB_RELEASE}/ts_sup_dll${__releaseSuffix}.lib"
            INTERFACE_INCLUDE_DIRECTORIES "${CRYPTO_INCLUDE_DIR}"
            INTERFACE_INCLUDE_DIRECTORIES_DEBUG "${CRYPTO_INCLUDE_DIR}"
            INTERFACE_INCLUDE_DIRECTORIES_RELEASE "${CRYPTO_INCLUDE_DIR}"
            INTERFACE_BIN_MODULES_DEBUG "${TSALG_SHLIB_DEBUG}/ts_sup_dll${__debugSuffix}.dll"
            INTERFACE_BIN_MODULES_RELEASE "${TSALG_SHLIB_RELEASE}/ts_sup_dll${__releaseSuffix}.dll"
          )

      elseif(EXISTS ${TSALG_SHLIB_RELEASE}/${CMAKE_SHARED_LIBRARY_PREFIX}TSALG${__releaseSuffix}${CMAKE_SHARED_LIBRARY_SUFFIX})
        add_library(TSALG SHARED IMPORTED)
        set_target_properties(TSALG PROPERTIES
        IMPORTED_LOCATION_DEBUG "${TSALG_SHLIB_DEBUG}/${CMAKE_SHARED_LIBRARY_PREFIX}TSALG${__debugSuffix}${CMAKE_SHARED_LIBRARY_SUFFIX}"
        IMPORTED_LOCATION_RELEASE "${TSALG_SHLIB_RELEASE}/${CMAKE_SHARED_LIBRARY_PREFIX}TSALG${__releaseSuffix}${CMAKE_SHARED_LIBRARY_SUFFIX}"
        IMPORTED_IMPLIB_DEBUG "${TSALG_ROOT_LIB_DEBUG}/${CMAKE_STATIC_LIBRARY_PREFIX}TSALG${__debugSuffix}${CMAKE_STATIC_LIBRARY_SUFFIX}"
        IMPORTED_IMPLIB_RELEASE "${TSALG_ROOT_LIB_RELEASE}/${CMAKE_STATIC_LIBRARY_PREFIX}TSALG${__releaseSuffix}${CMAKE_STATIC_LIBRARY_SUFFIX}"
        INTERFACE_INCLUDE_DIRECTORIES "${CRYPTO_INCLUDE_DIR}"
        INTERFACE_INCLUDE_DIRECTORIES_DEBUG "${CRYPTO_INCLUDE_DIR}"
        INTERFACE_INCLUDE_DIRECTORIES_RELEASE "${CRYPTO_INCLUDE_DIR}"
        INTERFACE_BIN_MODULES_DEBUG "${TSALG_SHLIB_DEBUG}/${CMAKE_SHARED_LIBRARY_PREFIX}TSALG${__debugSuffix}${CMAKE_SHARED_LIBRARY_SUFFIX}"
        INTERFACE_BIN_MODULES_RELEASE "${TSALG_SHLIB_RELEASE}/${CMAKE_SHARED_LIBRARY_PREFIX}TSALG${__releaseSuffix}${CMAKE_SHARED_LIBRARY_SUFFIX}"
        )
          add_library(TS_SUP_DLL SHARED IMPORTED)
          set_target_properties(TS_SUP_DLL PROPERTIES
            IMPORTED_LOCATION_DEBUG "${TSALG_SHLIB_DEBUG}/${CMAKE_SHARED_LIBRARY_PREFIX}ts_sup_dll${__debugSuffix}${CMAKE_SHARED_LIBRARY_SUFFIX}"
            IMPORTED_LOCATION_RELEASE "${TSALG_SHLIB_RELEASE}/${CMAKE_SHARED_LIBRARY_PREFIX}ts_sup_dll${__releaseSuffix}${CMAKE_SHARED_LIBRARY_SUFFIX}"
            IMPORTED_IMPLIB_DEBUG "${TSALG_ROOT_LIB_DEBUG}/${CMAKE_STATIC_LIBRARY_PREFIX}ts_sup_dll${__debugSuffix}${CMAKE_STATIC_LIBRARY_SUFFIX}"
            IMPORTED_IMPLIB_RELEASE "${TSALG_ROOT_LIB_RELEASE}/${CMAKE_STATIC_LIBRARY_PREFIX}ts_sup_dll${__releaseSuffix}${CMAKE_STATIC_LIBRARY_SUFFIX}"
            INTERFACE_INCLUDE_DIRECTORIES "${CRYPTO_INCLUDE_DIR}"
            INTERFACE_INCLUDE_DIRECTORIES_DEBUG "${CRYPTO_INCLUDE_DIR}"
            INTERFACE_INCLUDE_DIRECTORIES_RELEASE "${CRYPTO_INCLUDE_DIR}"
            INTERFACE_BIN_MODULES_DEBUG "${TSALG_SHLIB_DEBUG}/${CMAKE_SHARED_LIBRARY_PREFIX}ts_sup_dll${__debugSuffix}${CMAKE_SHARED_LIBRARY_SUFFIX}"
            INTERFACE_BIN_MODULES_RELEASE "${TSALG_SHLIB_RELEASE}/${CMAKE_SHARED_LIBRARY_PREFIX}ts_sup_dll${__releaseSuffix}${CMAKE_SHARED_LIBRARY_SUFFIX}"
          )
      else()
        message(FATAL_ERROR "TSALG not found")
      endif()
      endif()
      if(NOT TARGET TSALG_s)
        if(EXISTS ${TSALG_ROOT_LIB_RELEASE}/${CMAKE_STATIC_LIBRARY_PREFIX}TSALG_static${__releaseSuffix}${CMAKE_STATIC_LIBRARY_SUFFIX})
          add_library(TSALG_s STATIC IMPORTED)
          set_target_properties(TSALG_s PROPERTIES
          IMPORTED_LOCATION_DEBUG "${TSALG_ROOT_LIB_DEBUG}/${CMAKE_STATIC_LIBRARY_PREFIX}TSALG_static${__debugSuffix}${CMAKE_STATIC_LIBRARY_SUFFIX}"
          IMPORTED_LOCATION_RELEASE "${TSALG_ROOT_LIB_RELEASE}/${CMAKE_STATIC_LIBRARY_PREFIX}TSALG_static${__releaseSuffix}${CMAKE_STATIC_LIBRARY_SUFFIX}"
          INTERFACE_INCLUDE_DIRECTORIES "${CRYPTO_INCLUDE_DIR}"
          INTERFACE_INCLUDE_DIRECTORIES_DEBUG "${CRYPTO_INCLUDE_DIR}"
          INTERFACE_INCLUDE_DIRECTORIES_RELEASE "${CRYPTO_INCLUDE_DIR}"
          )
          add_library(TS_SUP_STATIC STATIC IMPORTED)
          set_target_properties(TS_SUP_STATIC PROPERTIES
            IMPORTED_LOCATION_DEBUG "${TSALG_ROOT_LIB_DEBUG}/${CMAKE_STATIC_LIBRARY_PREFIX}ts_sup_static${__debugSuffix}${CMAKE_STATIC_LIBRARY_SUFFIX}"
            IMPORTED_LOCATION_RELEASE "${TSALG_ROOT_LIB_RELEASE}/${CMAKE_STATIC_LIBRARY_PREFIX}ts_sup_static${__releaseSuffix}${CMAKE_STATIC_LIBRARY_SUFFIX}"
            INTERFACE_INCLUDE_DIRECTORIES "${CRYPTO_INCLUDE_DIR}"
            INTERFACE_INCLUDE_DIRECTORIES_DEBUG "${CRYPTO_INCLUDE_DIR}"
            INTERFACE_INCLUDE_DIRECTORIES_RELEASE "${CRYPTO_INCLUDE_DIR}"
          )
        else()
          #message(FATAL_ERROR "TSALG_s not found")
        endif()
      endif()
    else ()
      message(FATAL_ERROR "TSALG.cmake could not be found.")
    endif()

  else ()
    message(FATAL_ERROR "TSALG could not be found.")
  endif(TSALG_ROOT_DIR)
endif(APPLE)

