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

set(__paths 
      ENV VEILCrypto_ROOT
      ENV VEILCrypto
      C:/
      D:/
      ENV ProgramFiles\(x86\)
      ENV ProgramFiles
)
if(WIN32)
  find_path(VEILCRYPTO_ROOT_DIR
    NAMES 
      include/VEILCryptoCore.h
    PATHS
      ${__paths}
    PATH_SUFFIXES
		  TecSec/CRYPTO_7-0/${TS_TOOLSET}
		  TecSec/CRYPTO_7/${TS_TOOLSET}
		  TecSec/CRYPTO/${TS_TOOLSET}
		  CRYPTO_7-0/${TS_TOOLSET}
		  CRYPTO_7/${TS_TOOLSET}
		  CRYPTO/${TS_TOOLSET}
      ${TS_TOOLSET}
    DOC "VEILCrypto base/installation directory"
    )
  if (VEILCRYPTO_ROOT_DIR)
    if(NOT EXISTS ${VEILCRYPTO_ROOT_DIR}/VEILCrypto.cmake)
      unset(VEILCRYPTO_ROOT_DIR CACHE)
      find_path(VEILCRYPTO_ROOT_DIR
        NAMES 
          include/VEILCryptoCore.h
        PATHS
          ${__paths}
    PATH_SUFFIXES
		  TecSec/CRYPTO_7-0/${TS_TOOLSET}
		  TecSec/CRYPTO_7/${TS_TOOLSET}
		  TecSec/CRYPTO/${TS_TOOLSET}
		  CRYPTO_7-0/${TS_TOOLSET}
		  CRYPTO_7/${TS_TOOLSET}
		  CRYPTO/${TS_TOOLSET}
      ${TS_TOOLSET}
    DOC "VEILCrypto base/installation directory"
    )
    endif()
  endif()    
else()
  message(FATAL_ERROR "The search process for VEILCrypto for this environment has not been configured.")
endif(WIN32)



if (VEILCRYPTO_ROOT_DIR)

  if(DEBUG_VEILCRYPTO)
    message(STATUS "Looking for VEILCrypto at:  ${VEILCRYPTO_ROOT_DIR}/bin${TS_LIB_DIR_SUFFIX}${EXE_DLL_POSTFIX}/VEILCrypto.cmake")
  endif()

  # Build the values needed for program development here
  if(EXISTS ${VEILCRYPTO_ROOT_DIR}/VEILCrypto.cmake)
    include(${VEILCRYPTO_ROOT_DIR}/VEILCrypto.cmake)

    set(__suffix "${EXE_DLL_POSTFIX}")
    if(EXE_DLL_POSTFIX STREQUAL "d" AND NOT IS_DIRECTORY "${VEILCRYPTO_ROOT_DIR}/bin${TS_LIB_DIR_SUFFIX}${EXE_DLL_POSTFIX}")
      set(__suffix "")
    endif()

    set(CRYPTO_INSTALL_PREFIX "${VEILCRYPTO_ROOT_DIR}")
    set(CRYPTO_BIN_DIR "${VEILCRYPTO_ROOT_DIR}/bin${TS_LIB_DIR_SUFFIX}${__suffix}")
    set(CRYPTO_INCLUDE_DIR "${VEILCRYPTO_ROOT_DIR}/include")
    set(CRYPTO_LIB_DIR "${VEILCRYPTO_ROOT_DIR}/lib${TS_LIB_DIR_SUFFIX}${__suffix}")
    set(CRYPTO_SHLIB_DIR "${CRYPTO_BIN_DIR}")

    if(DEBUG_VEILCRYPTO)
      message(STATUS "CRYPTO_INSTALL_PREFIX = ${CRYPTO_INSTALL_PREFIX}")
      message(STATUS "CRYPTO_BIN_DIR        = ${CRYPTO_BIN_DIR}")
      message(STATUS "CRYPTO_INCLUDE_DIR    = ${CRYPTO_INCLUDE_DIR}")
      message(STATUS "CRYPTO_LIB_DIR        = ${CRYPTO_LIB_DIR}")
      message(STATUS "CRYPTO_SHLIB_DIR      = ${CRYPTO_SHLIB_DIR}")
    endif(DEBUG_VEILCRYPTO)

    if(WIN32)
      if (MSYS OR MINGW)
        set(_cryptocore_implib "${CRYPTO_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILCryptoCore${__suffix}.dll${CMAKE_STATIC_LIBRARY_SUFFIX}")
      else(MSYS OR MINGW)
        set(_cryptocore_implib "${CRYPTO_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILCryptoCore${__suffix}${CMAKE_STATIC_LIBRARY_SUFFIX}")
      endif(MSYS OR MINGW)
      set(_enhancedcrypto_implib "${CRYPTO_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILEnhancedCrypto${__suffix}${CMAKE_STATIC_LIBRARY_SUFFIX}")
      set(_cryptocore_bin_modules "${CRYPTO_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILCryptoCore${__suffix}${CMAKE_SHARED_LIBRARY_SUFFIX}")
      set(_enhancedcrypto_bin_modules "${CRYPTO_SHLIB_DIR}/VEILEnhancedCrypto${__suffix}.crypto")
    elseif(ANDROID)
      set(_cryptocore_implib "${CRYPTO_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILCryptoCore${__suffix}${CMAKE_STATIC_LIBRARY_SUFFIX}")
      set(_cryptocore_bin_modules "${CRYPTO_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILCryptoCore${__suffix}${CMAKE_SHARED_LIBRARY_SUFFIX}")

      set(_enhancedcrypto_implib "${CRYPTO_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILEnhancedCrypto${__suffix}${CMAKE_STATIC_LIBRARY_SUFFIX}")
      set(_enhancedcrypto_bin_modules "${CRYPTO_SHLIB_DIR}/VEILEnhancedCrypto${__suffix}.crypto")

    else(WIN32)
      set(_cryptocore_implib "${CRYPTO_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILCryptoCore${__suffix}${CMAKE_STATIC_LIBRARY_SUFFIX}")
      set(_cryptocore_bin_modules "${CRYPTO_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILCryptoCore${__suffix}${CMAKE_SHARED_LIBRARY_SUFFIX}.${CRYPTO_VERSION};${CRYPTO_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILCryptoCore${__suffix}${CMAKE_SHARED_LIBRARY_SUFFIX}.${CRYPTO_SO_VERSION}")

      set(_enhancedcrypto_implib "${CRYPTO_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILEnhancedCrypto${__suffix}${CMAKE_STATIC_LIBRARY_SUFFIX}")
      set(_enhancedcrypto_bin_modules "${SHLIBCRYPTO_SHLIB_DIR_DIR}/VEILEnhancedCrypto${__suffix}.crypto.${CRYPTO_VERSION}")
    endif(WIN32)
    IF(${TS_X_PLATFORM} STREQUAL "x86")
      set(BIGNUM_INCLUDE_DIR ${CRYPTO_INCLUDE_DIR}/VEILCryptoCore/base32Library)
    ELSE(${TS_X_PLATFORM} STREQUAL "x86")
      set(BIGNUM_INCLUDE_DIR ${CRYPTO_INCLUDE_DIR}/VEILCryptoCore/base64Library)
    ENDIF(${TS_X_PLATFORM} STREQUAL "x86")


    if(NOT TARGET VEILCryptoCore AND EXISTS ${CRYPTO_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILCryptoCore${__suffix}${CMAKE_SHARED_LIBRARY_SUFFIX})
      add_library(VEILCryptoCore SHARED IMPORTED)
      set_target_properties(VEILCryptoCore PROPERTIES
        IMPORTED_LOCATION_${TS_CONFIG} "${CRYPTO_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILCryptoCore${__suffix}${CMAKE_SHARED_LIBRARY_SUFFIX}"
        IMPORTED_IMPLIB_${TS_CONFIG} "${_cryptocore_implib}"
        INTERFACE_INCLUDE_DIRECTORIES "${CRYPTO_INCLUDE_DIR};${BIGNUM_INCLUDE_DIR}"
        INTERFACE_INCLUDE_DIRECTORIES_${TS_CONFIG} "${CRYPTO_INCLUDE_DIR};${BIGNUM_INCLUDE_DIR}"
        INTERFACE_BIN_MODULES_${TS_CONFIG} "${_cryptocore_bin_modules}"
      )
    else()
      message(FATAL_ERROR "VEILCryptoCore not found")
    endif()
        
    if(NOT TARGET VEILEnhancedCrypto AND EXISTS ${CRYPTO_SHLIB_DIR}/VEILEnhancedCrypto${__suffix}.crypto)
      add_library(VEILEnhancedCrypto SHARED IMPORTED)
      set_target_properties(VEILEnhancedCrypto PROPERTIES
        IMPORTED_LOCATION_${TS_CONFIG} "${CRYPTO_SHLIB_DIR}/VEILEnhancedCrypto${__suffix}.crypto"
        IMPORTED_IMPLIB_${TS_CONFIG} "${_enhancedcrypto_implib}"
        INTERFACE_INCLUDE_DIRECTORIES "${CRYPTO_INCLUDE_DIR}"
        INTERFACE_INCLUDE_DIRECTORIES_${TS_CONFIG} "${CRYPTO_INCLUDE_DIR}"
        INTERFACE_BIN_MODULES_${TS_CONFIG} "${_enhancedcrypto_bin_modules}"
      )
    endif()
        
    if(NOT TARGET xml2Asn1CodeGen AND EXISTS ${CRYPTO_BIN_DIR}/xml2Asn1CodeGen${DEBUG_POSTFIX}${CMAKE_EXECUTABLE_SUFFIX})
      # message(STATUS "xml2Asn1CodeGen located at ${CRYPTO_BIN_DIR}/xml2Asn1CodeGen${DEBUG_POSTFIX}${CMAKE_EXECUTABLE_SUFFIX}")
      add_executable(xml2Asn1CodeGen IMPORTED)
      set_target_properties(xml2Asn1CodeGen PROPERTIES
        IMPORTED_LOCATION_${TS_CONFIG} "${CRYPTO_BIN_DIR}/xml2Asn1CodeGen${DEBUG_POSTFIX}${CMAKE_EXECUTABLE_SUFFIX}"
        INTERFACE_BIN_MODULES_${TS_CONFIG} "${CRYPTO_BIN_DIR}/xml2Asn1CodeGen${DEBUG_POSTFIX}${CMAKE_EXECUTABLE_SUFFIX}"
      )
    else()
      message(FATAL_ERROR "xml2Asn1CodeGen not found")
    endif()

    if(NOT TARGET tsschemagen AND EXISTS ${CRYPTO_BIN_DIR}/tsschemagen${DEBUG_POSTFIX}${CMAKE_EXECUTABLE_SUFFIX})
      add_executable(tsschemagen IMPORTED)
      set_target_properties(tsschemagen PROPERTIES
        IMPORTED_LOCATION_${TS_CONFIG} "${CRYPTO_BIN_DIR}/tsschemagen${DEBUG_POSTFIX}${CMAKE_EXECUTABLE_SUFFIX}"
        INTERFACE_BIN_MODULES_${TS_CONFIG} "${CRYPTO_BIN_DIR}/tsschemagen${DEBUG_POSTFIX}${CMAKE_EXECUTABLE_SUFFIX}"
      )
    endif()

    if(NOT TARGET Utf16ToUtf8 AND EXISTS ${CRYPTO_BIN_DIR}/Utf16ToUtf8${DEBUG_POSTFIX}${CMAKE_EXECUTABLE_SUFFIX})
      add_executable(Utf16ToUtf8 IMPORTED)
      set_target_properties(Utf16ToUtf8 PROPERTIES
        IMPORTED_LOCATION_${TS_CONFIG} "${CRYPTO_BIN_DIR}/Utf16ToUtf8${DEBUG_POSTFIX}${CMAKE_EXECUTABLE_SUFFIX}"
        INTERFACE_BIN_MODULES_${TS_CONFIG} "${CRYPTO_BIN_DIR}/Utf16ToUtf8${DEBUG_POSTFIX}${CMAKE_EXECUTABLE_SUFFIX}"
      )
    endif()
  else ()
    message(FATAL_ERROR "VEILCrypto.cmake could not be found.")
  endif()

else ()
  message(FATAL_ERROR "VEILCrypto could not be found.")
endif(VEILCRYPTO_ROOT_DIR)


