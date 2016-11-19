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
# Written by Roger Butler

if(APPLE)

  set(VEILCRYPTO_NAME "VEILCrypto")
	FIND_LIBRARY(VEILCRYPTO_LIBRARY ${VEILCRYPTO_NAME})
	MARK_AS_ADVANCED(VEILCRYPTO_LIBRARY)
  if (NOT VEILCRYPTO_LIBRARY)
  	message(FATAL "VEILCrypto not found")
  else()
  	message(STATUS "VEILCrypto at ${VEILCRYPTO_LIBRARY}")
  endif()

	FIND_LIBRARY(VEILCRYPTO_D_LIBRARY ${VEILCRYPTO_NAME}_d)
  if (NOT VEILCRYPTO_D_LIBRARY)
  	set(VEILCRYPTO_D_LIBRARY ${VEILCRYPTO_LIBRARY})
  endif()
	MARK_AS_ADVANCED(VEILCRYPTO_D_LIBRARY)
	message(STATUS "VEILCrypto_d at ${VEILCRYPTO_D_LIBRARY}")

  set(VEILCRYPTO_ROOT_DIR ${VEILCRYPTO_LIBRARY})


  if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    set(VEILCRYPTO_TARGET ${VEILCRYPTO_D_LIBRARY})
  else()
    set(VEILCRYPTO_TARGET ${VEILCRYPTO_LIBRARY})
  endif()

  message(STATUS "Crypto target:  ${VEILCRYPTO_TARGET}")
  #add_definitions(-framework ${VEILCRYPTO_NAME})

  #  TODO:  Need lots of stuff here

else()
  set(__path_suffixes 
	TecSec/CRYPTO_7-0/${TS_TOOLSET}
	TecSec/CRYPTO_7/${TS_TOOLSET}
	TecSec/CRYPTO/${TS_TOOLSET}
	CRYPTO_7-0/${TS_TOOLSET}
	CRYPTO_7/${TS_TOOLSET}
	CRYPTO/${TS_TOOLSET}
	${TS_TOOLSET}
	TecSec/CRYPTO_7-0
	TecSec/CRYPTO_7
	TecSec/CRYPTO
	CRYPTO_7-0
	CRYPTO_7
	CRYPTO
  )
  if(WIN32)
  set(__paths 
      ENV VEILCrypto_ROOT
      ENV VEILCrypto
      C:/
      D:/
      ENV ProgramFiles\(x86\)
      ENV ProgramFiles
  )
  elseif(APPLE)
  set(__paths
      ENV VEILCrypto_ROOT
      ENV VEILCrypto
      /usr/local
      /usr
      ~/work/local
  )
  else()
  message(FATAL_ERROR "The search process for VEILCrypto for this environment has not been configured.")
  endif(WIN32)

  if(UNIX)
  set(INCLUDE_PART include/TecSec)
  else()
  set(INCLUDE_PART include)
  endif()

  find_path(VEILCRYPTO_ROOT_DIR
    NAMES 
      ${INCLUDE_PART}/VEILCrypto.h
    PATHS
      ${__paths}
    PATH_SUFFIXES
		${__path_suffixes}
    DOC 
		"VEILCrypto base/installation directory"
    )

  if (VEILCRYPTO_ROOT_DIR)
    if(NOT EXISTS ${VEILCRYPTO_ROOT_DIR}/VEILCrypto.cmake)
      unset(VEILCRYPTO_ROOT_DIR CACHE)
      find_path(VEILCRYPTO_ROOT_DIR
        NAMES 
            ${INCLUDE_PART}/VEILCrypto.h
        PATHS
          ${__paths}
    PATH_SUFFIXES
          ${__path_suffixes}
        DOC 
			"VEILCrypto base/installation directory"
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
  set(BIN_PART bin${TS_LIB_DIR_SUFFIX})
  set(LIB_PART lib${TS_LIB_DIR_SUFFIX})
  endif(APPLE)


  if (VEILCRYPTO_ROOT_DIR)

  if(DEBUG_VEILCRYPTO)
    message(STATUS "Looking for VEILCrypto at:  ${VEILCRYPTO_ROOT_DIR}/${BIN_PART}/VEILCrypto.cmake")
  endif()

  # Build the values needed for program development here
  if(EXISTS ${VEILCRYPTO_ROOT_DIR}/VEILCrypto.cmake)
    include(${VEILCRYPTO_ROOT_DIR}/VEILCrypto.cmake)

    set(VEILCRYPTO_ROOT_BIN_RELEASE "")
    set(VEILCRYPTO_ROOT_BIN_DEBUG "")
    set(VEILCRYPTO_ROOT_LIB_RELEASE "")
    set(VEILCRYPTO_ROOT_LIB_DEBUG "")

    if(UNIX)
        if (EXISTS "${VEILCRYPTO_ROOT_DIR}/${LIB_PART}_d/${CMAKE_SHARED_LIBRARY_PREFIX}VEILCrypto_d${CMAKE_SHARED_LIBRARY_SUFFIX}")
        set(VEILCRYPTO_ROOT_LIB_DEBUG "${VEILCRYPTO_ROOT_DIR}/${LIB_PART}_d")
        set(VEILCRYPTO_ROOT_BIN_DEBUG "${VEILCRYPTO_ROOT_DIR}/${BIN_PART}_d")
        set(__debugSuffix "_d")
        elseif(EXISTS "${VEILCRYPTO_ROOT_DIR}/${LIB_PART}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILCrypto_d${CMAKE_SHARED_LIBRARY_SUFFIX}")
        set(VEILCRYPTO_ROOT_LIB_DEBUG "${VEILCRYPTO_ROOT_DIR}/${LIB_PART}")
        set(VEILCRYPTO_ROOT_BIN_DEBUG "${VEILCRYPTO_ROOT_DIR}/${BIN_PART}")
        set(__debugSuffix "_d")
      else()
        set(__debugSuffix "")
        set(VEILCRYPTO_ROOT_LIB_DEBUG "${VEILCRYPTO_ROOT_DIR}/${LIB_PART}")
        set(VEILCRYPTO_ROOT_BIN_DEBUG "${VEILCRYPTO_ROOT_DIR}/${BIN_PART}")
    endif()

        if(EXISTS "${VEILCRYPTO_ROOT_DIR}/${LIB_PART}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILCrypto${CMAKE_SHARED_LIBRARY_SUFFIX}")
        set(VEILCRYPTO_ROOT_LIB_RELEASE "${VEILCRYPTO_ROOT_DIR}/${LIB_PART}")
        set(VEILCRYPTO_ROOT_BIN_RELEASE "${VEILCRYPTO_ROOT_DIR}/${BIN_PART}")
        set(__releaseSuffix "")
      else()
        set(__releaseSuffix "${__debugSuffix}")
        set(VEILCRYPTO_ROOT_LIB_RELEASE "${VEILCRYPTO_ROOT_LIB_DEBUG}")
        set(VEILCRYPTO_ROOT_BIN_RELEASE "${VEILCRYPTO_ROOT_BIN_DEBUG}")
      endif()

      set(VEILCRYPTO_SHLIB_DEBUG ${VEILCRYPTO_ROOT_LIB_DEBUG})
      set(VEILCRYPTO_SHLIB_RELEASE ${VEILCRYPTO_ROOT_LIB_RELEASE})
    else()
        if (EXISTS "${VEILCRYPTO_ROOT_DIR}/${BIN_PART}_d/${CMAKE_SHARED_LIBRARY_PREFIX}VEILCrypto_d${CMAKE_SHARED_LIBRARY_SUFFIX}")
        set(VEILCRYPTO_ROOT_BIN_DEBUG "${VEILCRYPTO_ROOT_DIR}/${BIN_PART}_d")
        set(VEILCRYPTO_ROOT_LIB_DEBUG "${VEILCRYPTO_ROOT_DIR}/${LIB_PART}_d")
        set(__debugSuffix "_d")
        elseif(EXISTS "${VEILCRYPTO_ROOT_DIR}/${BIN_PART}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILCrypto_d${CMAKE_SHARED_LIBRARY_SUFFIX}")
        set(VEILCRYPTO_ROOT_BIN_DEBUG "${VEILCRYPTO_ROOT_DIR}/${BIN_PART}")
        set(VEILCRYPTO_ROOT_LIB_DEBUG "${VEILCRYPTO_ROOT_DIR}/${LIB_PART}")
        set(__debugSuffix "_d")
      else()
        set(__debugSuffix "")
        set(VEILCRYPTO_ROOT_BIN_DEBUG "${VEILCRYPTO_ROOT_DIR}/${BIN_PART}")
        set(VEILCRYPTO_ROOT_LIB_DEBUG "${VEILCRYPTO_ROOT_DIR}/${LIB_PART}")
      endif()

        if(EXISTS "${VEILCRYPTO_ROOT_DIR}/${BIN_PART}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILCrypto${CMAKE_SHARED_LIBRARY_SUFFIX}")
        set(VEILCRYPTO_ROOT_BIN_RELEASE "${VEILCRYPTO_ROOT_DIR}/${BIN_PART}")
        set(VEILCRYPTO_ROOT_LIB_RELEASE "${VEILCRYPTO_ROOT_DIR}/${LIB_PART}")
        set(__releaseSuffix "")
      else()
        set(__releaseSuffix "${__debugSuffix}")
        set(VEILCRYPTO_ROOT_LIB_RELEASE "${VEILCRYPTO_ROOT_LIB_DEBUG}")
        set(VEILCRYPTO_ROOT_BIN_RELEASE "${VEILCRYPTO_ROOT_BIN_DEBUG}")
      endif()
      set(VEILCRYPTO_SHLIB_DEBUG ${VEILCRYPTO_ROOT_BIN_DEBUG})
      set(VEILCRYPTO_SHLIB_RELEASE ${VEILCRYPTO_ROOT_BIN_RELEASE})
    endif()
    




    set(CRYPTO_INSTALL_PREFIX "${VEILCRYPTO_ROOT_DIR}")
    set(CRYPTO_BIN_DIR "${VEILCRYPTO_ROOT_BIN_RELEASE}")
    set(CRYPTO_INCLUDE_DIR "${VEILCRYPTO_ROOT_DIR}/${INCLUDE_PART}")
    set(CRYPTO_LIB_DIR "${VEILCRYPTO_ROOT_LIB_RELEASE}")
    if(UNIX)
      set(CRYPTO_SHLIB_DIR "${CRYPTO_LIB_DIR}")
    else()
    set(CRYPTO_SHLIB_DIR "${CRYPTO_BIN_DIR}")
    endif()

    if(DEBUG_VEILCRYPTO)
      message(STATUS "CRYPTO_INSTALL_PREFIX = ${CRYPTO_INSTALL_PREFIX}")
      message(STATUS "CRYPTO_BIN_DIR        = ${CRYPTO_BIN_DIR}")
      message(STATUS "CRYPTO_INCLUDE_DIR    = ${CRYPTO_INCLUDE_DIR}")
      message(STATUS "CRYPTO_LIB_DIR        = ${CRYPTO_LIB_DIR}")
      message(STATUS "CRYPTO_SHLIB_DIR      = ${CRYPTO_SHLIB_DIR}")

      message(STATUS "__debugSuffix               = ${__debugSuffix}")
      message(STATUS "VEILCRYPTO_ROOT_LIB_DEBUG   = ${VEILCRYPTO_ROOT_LIB_DEBUG}")
      message(STATUS "VEILCRYPTO_ROOT_BIN_DEBUG   = ${VEILCRYPTO_ROOT_BIN_DEBUG}")
      message(STATUS "__releaseSuffix             = ${__releaseSuffix}")
      message(STATUS "VEILCRYPTO_ROOT_LIB_RELEASE = ${VEILCRYPTO_ROOT_LIB_RELEASE}")
      message(STATUS "VEILCRYPTO_ROOT_BIN_RELEASE = ${VEILCRYPTO_ROOT_BIN_RELEASE}")
      message(STATUS "VEILCRYPTO_SHLIB_DEBUG      = ${VEILCRYPTO_SHLIB_DEBUG}")
      message(STATUS "VEILCRYPTO_SHLIB_RELEASE    = ${VEILCRYPTO_SHLIB_RELEASE}")


    endif(DEBUG_VEILCRYPTO)
    if (MINGW)
      set(IMPLIB_SUFFIX_PREFIX ".dll")
    else()
      set(IMPLIB_SUFFIX_PREFIX "")
    endif(MINGW)

    IF(${TS_X_PLATFORM} STREQUAL "x86")
        set(BIGNUM_INCLUDE_DIR ${CRYPTO_INCLUDE_DIR}/VEILCrypto/base32Library)
    ELSE(${TS_X_PLATFORM} STREQUAL "x86")
        set(BIGNUM_INCLUDE_DIR ${CRYPTO_INCLUDE_DIR}/VEILCrypto/base64Library)
    ENDIF(${TS_X_PLATFORM} STREQUAL "x86")


      if(NOT TARGET VEILCrypto)
      if(EXISTS ${VEILCRYPTO_SHLIB_RELEASE}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILCrypto${__releaseSuffix}${CMAKE_SHARED_LIBRARY_SUFFIX})
        add_library(VEILCrypto SHARED IMPORTED)
        set_target_properties(VEILCrypto PROPERTIES
        IMPORTED_LOCATION_DEBUG "${VEILCRYPTO_SHLIB_DEBUG}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILCrypto${__debugSuffix}${CMAKE_SHARED_LIBRARY_SUFFIX}"
        IMPORTED_LOCATION_RELEASE "${VEILCRYPTO_SHLIB_RELEASE}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILCrypto${__releaseSuffix}${CMAKE_SHARED_LIBRARY_SUFFIX}"
        IMPORTED_IMPLIB_DEBUG "${VEILCRYPTO_ROOT_LIB_DEBUG}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILCrypto${__debugSuffix}${IMPLIB_SUFFIX_PREFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}"
        IMPORTED_IMPLIB_RELEASE "${VEILCRYPTO_ROOT_LIB_RELEASE}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILCrypto${__releaseSuffix}${IMPLIB_SUFFIX_PREFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}"
        INTERFACE_INCLUDE_DIRECTORIES "${CRYPTO_INCLUDE_DIR};${BIGNUM_INCLUDE_DIR}"
        INTERFACE_INCLUDE_DIRECTORIES_DEBUG "${CRYPTO_INCLUDE_DIR};${BIGNUM_INCLUDE_DIR}"
        INTERFACE_INCLUDE_DIRECTORIES_RELEASE "${CRYPTO_INCLUDE_DIR};${BIGNUM_INCLUDE_DIR}"
        INTERFACE_BIN_MODULES_DEBUG "${VEILCRYPTO_SHLIB_DEBUG}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILCrypto${__debugSuffix}${CMAKE_SHARED_LIBRARY_SUFFIX}"
        INTERFACE_BIN_MODULES_RELEASE "${VEILCRYPTO_SHLIB_RELEASE}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILCrypto${__releaseSuffix}${CMAKE_SHARED_LIBRARY_SUFFIX}"
      )
    else()
        message(FATAL_ERROR "VEILCrypto not found")
      endif()
    endif()
        
    if(NOT TARGET xml2Asn1CodeGen)
      if(EXISTS ${VEILCRYPTO_ROOT_BIN_RELEASE}/xml2Asn1CodeGen${CMAKE_EXECUTABLE_SUFFIX})
      # message(STATUS "xml2Asn1CodeGen located at ${CRYPTO_BIN_DIR}/xml2Asn1CodeGen${DEBUG_POSTFIX}${CMAKE_EXECUTABLE_SUFFIX}")
      add_executable(xml2Asn1CodeGen IMPORTED)
      set_target_properties(xml2Asn1CodeGen PROPERTIES
          IMPORTED_LOCATION_DEBUG "${VEILCRYPTO_ROOT_BIN_RELEASE}/xml2Asn1CodeGen${CMAKE_EXECUTABLE_SUFFIX}"
          IMPORTED_LOCATION_RELEASE "${VEILCRYPTO_ROOT_BIN_RELEASE}/xml2Asn1CodeGen${CMAKE_EXECUTABLE_SUFFIX}"
          INTERFACE_BIN_MODULES_DEBUG "${VEILCRYPTO_ROOT_BIN_RELEASE}/xml2Asn1CodeGen${CMAKE_EXECUTABLE_SUFFIX}"
          INTERFACE_BIN_MODULES_RELEASE "${VEILCRYPTO_ROOT_BIN_RELEASE}/xml2Asn1CodeGen${CMAKE_EXECUTABLE_SUFFIX}"
      )
    else()
      message(FATAL_ERROR "xml2Asn1CodeGen not found")
    endif()
    endif()

    if(NOT TARGET tsschemagen)
      if(EXISTS ${VEILCRYPTO_ROOT_BIN_RELEASE}/tsschemagen${CMAKE_EXECUTABLE_SUFFIX})
      add_executable(tsschemagen IMPORTED)
      set_target_properties(tsschemagen PROPERTIES
          IMPORTED_LOCATION_DEBUG "${VEILCRYPTO_ROOT_BIN_RELEASE}/tsschemagen${CMAKE_EXECUTABLE_SUFFIX}"
          IMPORTED_LOCATION_RELEASE "${VEILCRYPTO_ROOT_BIN_RELEASE}/tsschemagen${CMAKE_EXECUTABLE_SUFFIX}"
          INTERFACE_BIN_MODULES_DEBUG "${VEILCRYPTO_ROOT_BIN_RELEASE}/tsschemagen${CMAKE_EXECUTABLE_SUFFIX}"
          INTERFACE_BIN_MODULES_RELEASE "${VEILCRYPTO_ROOT_BIN_RELEASE}/tsschemagen${CMAKE_EXECUTABLE_SUFFIX}"
      )
    endif()
    endif()

    if(NOT TARGET Utf16ToUtf8)
      if(EXISTS ${VEILCRYPTO_ROOT_BIN_RELEASE}/Utf16ToUtf8${CMAKE_EXECUTABLE_SUFFIX})
      add_executable(Utf16ToUtf8 IMPORTED)
      set_target_properties(Utf16ToUtf8 PROPERTIES
          IMPORTED_LOCATION_DEBUG "${VEILCRYPTO_ROOT_BIN_RELEASE}/Utf16ToUtf8${CMAKE_EXECUTABLE_SUFFIX}"
          IMPORTED_LOCATION_RELEASE "${VEILCRYPTO_ROOT_BIN_RELEASE}/Utf16ToUtf8${CMAKE_EXECUTABLE_SUFFIX}"
          INTERFACE_BIN_MODULES_DEBUG "${VEILCRYPTO_ROOT_BIN_RELEASE}/Utf16ToUtf8${CMAKE_EXECUTABLE_SUFFIX}"
          INTERFACE_BIN_MODULES_RELEASE "${VEILCRYPTO_ROOT_BIN_RELEASE}/Utf16ToUtf8${CMAKE_EXECUTABLE_SUFFIX}"
      )
    endif()
    endif()

  else ()
    message(FATAL_ERROR "VEILCrypto.cmake could not be found.")
  endif()

  else ()
  message(FATAL_ERROR "VEILCrypto could not be found.")
  endif(VEILCRYPTO_ROOT_DIR)
endif(APPLE)

