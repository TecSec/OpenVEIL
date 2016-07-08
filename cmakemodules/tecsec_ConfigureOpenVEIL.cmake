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

include(tecsec_ConfigureVEILCrypto)

set(__paths 
      ENV VEIL_ROOT
      ENV VEIL
      C:/
      D:/
      ENV ProgramFiles\(x86\)
      ENV ProgramFiles
)
if(WIN32)
  find_path(VEIL_ROOT_DIR
    NAMES 
      include/VEIL.h
    PATHS
      ${__paths}
    PATH_SUFFIXES
		  TecSec/VEIL_7-0/${TS_TOOLSET}
		  TecSec/VEIL_7/${TS_TOOLSET}
		  TecSec/VEIL/${TS_TOOLSET}
		  VEIL_7-0/${TS_TOOLSET}
		  VEIL_7/${TS_TOOLSET}
		  VEIL/${TS_TOOLSET}
      ${TS_TOOLSET}
    DOC "VEIL base/installation directory"
    )
  if (VEIL_ROOT_DIR)
    if(NOT EXISTS ${VEIL_ROOT_DIR}/VEILApiVersion.cmake)
      unset(VEIL_ROOT_DIR CACHE)
      find_path(VEIL_ROOT_DIR
        NAMES 
          include/VEIL.h
        PATHS
          ${__paths}
    PATH_SUFFIXES
		  TecSec/VEIL_7-0/${TS_TOOLSET}
		  TecSec/VEIL_7/${TS_TOOLSET}
		  TecSec/VEIL/${TS_TOOLSET}
		  VEIL_7-0/${TS_TOOLSET}
		  VEIL_7/${TS_TOOLSET}
		  VEIL/${TS_TOOLSET}
      ${TS_TOOLSET}
    DOC "VEIL base/installation directory"
    )
    endif()
  endif()    
else()
  message(FATAL_ERROR "The search process for VEIL for this environment has not been configured.")
endif(WIN32)



if (VEIL_ROOT_DIR)

  if(DEBUG_TECSEC_SDK)
    message(STATUS "Looking for VEIL at:  ${VEIL_ROOT_DIR}/bin${TS_LIB_DIR_SUFFIX}${EXE_DLL_POSTFIX}/VEILApiVersion.cmake")
  endif(DEBUG_TECSEC_SDK)

  # Build the values needed for program development here
  if(EXISTS ${VEIL_ROOT_DIR}/VEILApiVersion.cmake)
    include(${VEIL_ROOT_DIR}/VEILApiVersion.cmake)

    set(VEIL_INSTALL_PREFIX "${VEIL_ROOT_DIR}")
    set(VEIL_BIN_DIR "${VEIL_ROOT_DIR}/bin${TS_LIB_DIR_SUFFIX}${EXE_DLL_POSTFIX}")
    set(VEIL_INCLUDE_DIR "${VEIL_ROOT_DIR}/include")
    set(VEIL_LIB_DIR "${VEIL_ROOT_DIR}/lib${TS_LIB_DIR_SUFFIX}${EXE_DLL_POSTFIX}")
    set(VEIL_SHLIB_DIR "${VEIL_BIN_DIR}")

    if(DEBUG_TECSEC_SDK)
      message(STATUS "VEIL_INSTALL_PREFIX = ${VEIL_INSTALL_PREFIX}")
      message(STATUS "VEIL_BIN_DIR        = ${VEIL_BIN_DIR}")
      message(STATUS "VEIL_INCLUDE_DIR    = ${VEIL_INCLUDE_DIR}")
      message(STATUS "VEIL_LIB_DIR        = ${VEIL_LIB_DIR}")
      message(STATUS "VEIL_SHLIB_DIR      = ${VEIL_SHLIB_DIR}")
    endif(DEBUG_TECSEC_SDK)

    if(WIN32)
      if (MSYS OR MINGW)
        set(_core_implib "${VEIL_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILCore${EXE_DLL_POSTFIX}.dll${CMAKE_STATIC_LIBRARY_SUFFIX}")
        set(_header_implib "${VEIL_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILCmsHeader${EXE_DLL_POSTFIX}.dll${CMAKE_STATIC_LIBRARY_SUFFIX}")
        set(_fs_implib "${VEIL_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILFileSupport${EXE_DLL_POSTFIX}.dll${CMAKE_STATIC_LIBRARY_SUFFIX}")
        set(_scard_implib "${VEIL_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILSmartCard${EXE_DLL_POSTFIX}.dll${CMAKE_STATIC_LIBRARY_SUFFIX}")
        set(_server_implib "${VEIL_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILServerSupport${EXE_DLL_POSTFIX}.dll${CMAKE_STATIC_LIBRARY_SUFFIX}")
        set(_winapi_implib "${VEIL_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILWinAPI${EXE_DLL_POSTFIX}.dll${CMAKE_STATIC_LIBRARY_SUFFIX}")
        set(_wxwidgets_implib "${VEIL_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILWxWidgets${EXE_DLL_POSTFIX}.dll${CMAKE_STATIC_LIBRARY_SUFFIX}")
      else(MSYS OR MINGW)
        set(_core_implib "${VEIL_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILCore${EXE_DLL_POSTFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}")
        set(_header_implib "${VEIL_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILCmsHeader${EXE_DLL_POSTFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}")
        set(_fs_implib "${VEIL_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILFileSupport${EXE_DLL_POSTFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}")
        set(_scard_implib "${VEIL_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILSmartCard${EXE_DLL_POSTFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}")
        set(_server_implib "${VEIL_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILServerSupport${EXE_DLL_POSTFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}")
        set(_winapi_implib "${VEIL_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILWinAPI${EXE_DLL_POSTFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}")
        set(_wxwidgets_implib "${VEIL_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILWxWidgets${EXE_DLL_POSTFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}")
      endif(MSYS OR MINGW)
      set(_core_bin_modules "${VEIL_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILCore${EXE_DLL_POSTFIX}${CMAKE_SHARED_LIBRARY_SUFFIX}")
      set(_header_bin_modules "${VEIL_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILCmsHeader${EXE_DLL_POSTFIX}${CMAKE_SHARED_LIBRARY_SUFFIX}")
      set(_fs_bin_modules "${VEIL_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILFileSupport${EXE_DLL_POSTFIX}${CMAKE_SHARED_LIBRARY_SUFFIX}")
      set(_scard_bin_modules "${VEIL_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILSmartCard${EXE_DLL_POSTFIX}${CMAKE_SHARED_LIBRARY_SUFFIX}")
      set(_server_bin_modules "${VEIL_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILServerSupport${EXE_DLL_POSTFIX}${CMAKE_SHARED_LIBRARY_SUFFIX}")
      set(_winapi_bin_modules "${VEIL_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILWinAPI${EXE_DLL_POSTFIX}${CMAKE_SHARED_LIBRARY_SUFFIX}")
      set(_wxwidgets_bin_modules "${VEIL_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILWxWidgets${EXE_DLL_POSTFIX}${CMAKE_SHARED_LIBRARY_SUFFIX}")
    elseif(ANDROID)
      set(_core_implib "${VEIL_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILCore${EXE_DLL_POSTFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}")
      set(_core_bin_modules "${VEIL_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILCore${EXE_DLL_POSTFIX}${CMAKE_SHARED_LIBRARY_SUFFIX}")
      set(_header_implib "${VEIL_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILCmsHeader${EXE_DLL_POSTFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}")
      set(_header_bin_modules "${VEIL_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILCmsHeader${EXE_DLL_POSTFIX}${CMAKE_SHARED_LIBRARY_SUFFIX}")
      set(_fs_implib "${VEIL_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILFileSupport${EXE_DLL_POSTFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}")
      set(_fs_bin_modules "${VEIL_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILFileSupport${EXE_DLL_POSTFIX}${CMAKE_SHARED_LIBRARY_SUFFIX}")
      set(_scard_implib "${VEIL_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILSmartCard${EXE_DLL_POSTFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}")
      set(_scard_bin_modules "${VEIL_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILSmartCard${EXE_DLL_POSTFIX}${CMAKE_SHARED_LIBRARY_SUFFIX}")
      set(_server_implib "${VEIL_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILServerSupport${EXE_DLL_POSTFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}")
      set(_server_bin_modules "${VEIL_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILServerSupport${EXE_DLL_POSTFIX}${CMAKE_SHARED_LIBRARY_SUFFIX}")
    else(WIN32)
      set(_core_implib "${VEIL_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILCore${EXE_DLL_POSTFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}")
      set(_core_bin_modules "${VEIL_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILCore${EXE_DLL_POSTFIX}${CMAKE_SHARED_LIBRARY_SUFFIX}.${VEIL_VERSION};${VEIL_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILCore${EXE_DLL_POSTFIX}${CMAKE_SHARED_LIBRARY_SUFFIX}.${VEIL_SO_VERSION}")
      set(_header_implib "${VEIL_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILCmsHeader${EXE_DLL_POSTFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}")
      set(_header_bin_modules "${VEIL_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILCmsHeader${EXE_DLL_POSTFIX}${CMAKE_SHARED_LIBRARY_SUFFIX}.${VEIL_VERSION};${VEIL_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILCmsHeader${EXE_DLL_POSTFIX}${CMAKE_SHARED_LIBRARY_SUFFIX}.${VEIL_SO_VERSION}")
      set(_fs_implib "${VEIL_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILFileSupport${EXE_DLL_POSTFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}")
      set(_fs_bin_modules "${VEIL_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILFileSupport${EXE_DLL_POSTFIX}${CMAKE_SHARED_LIBRARY_SUFFIX}.${VEIL_VERSION};${VEIL_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILFileSupport${EXE_DLL_POSTFIX}${CMAKE_SHARED_LIBRARY_SUFFIX}.${VEIL_SO_VERSION}")
      set(_scard_implib "${VEIL_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILSmartCard${EXE_DLL_POSTFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}")
      set(_scard_bin_modules "${VEIL_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILSmartCard${EXE_DLL_POSTFIX}${CMAKE_SHARED_LIBRARY_SUFFIX}.${VEIL_VERSION};${VEIL_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILSmartCard${EXE_DLL_POSTFIX}${CMAKE_SHARED_LIBRARY_SUFFIX}.${VEIL_SO_VERSION}")
      set(_server_implib "${VEIL_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILServerSupport${EXE_DLL_POSTFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}")
      set(_server_bin_modules "${VEIL_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILServerSupport${EXE_DLL_POSTFIX}${CMAKE_SHARED_LIBRARY_SUFFIX}.${VEIL_VERSION};${VEIL_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILServerSupport${EXE_DLL_POSTFIX}${CMAKE_SHARED_LIBRARY_SUFFIX}.${VEIL_SO_VERSION}")
      set(_wxwidgets_implib "${VEIL_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}VEILWxWidgets${EXE_DLL_POSTFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}")
      set(_wxwidgets_bin_modules "${VEIL_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILWxWidgets${EXE_DLL_POSTFIX}${CMAKE_SHARED_LIBRARY_SUFFIX}")
    endif(WIN32)


    if(NOT TARGET VEILCore)
      add_library(VEILCore SHARED IMPORTED)
      set_target_properties(VEILCore PROPERTIES
        IMPORTED_LOCATION_${TS_CONFIG} "${VEIL_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILCore${EXE_DLL_POSTFIX}${CMAKE_SHARED_LIBRARY_SUFFIX}"
        IMPORTED_IMPLIB_${TS_CONFIG} "${_core_implib}"
        INTERFACE_INCLUDE_DIRECTORIES "${VEIL_INCLUDE_DIR}"
        INTERFACE_INCLUDE_DIRECTORIES_${TS_CONFIG} "${VEIL_INCLUDE_DIR}"
        INTERFACE_TOOLS_${TS_CONFIG} "${VEIL_BIN_DIR}/veil${DEBUG_POSTFIX}${CMAKE_EXECUTABLE_SUFFIX};${VEIL_BIN_DIR}/veilfile${DEBUG_POSTFIX}${CMAKE_EXECUTABLE_SUFFIX}"
            INTERFACE_BIN_MODULES_${TS_CONFIG} "${_core_bin_modules}"
      )
    endif()
        
    if(NOT TARGET VEILCmsHeader)
      add_library(VEILCmsHeader SHARED IMPORTED)
      set_target_properties(VEILCmsHeader PROPERTIES
        IMPORTED_LOCATION_${TS_CONFIG} "${VEIL_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILVEILCmsHeader${EXE_DLL_POSTFIX}${CMAKE_SHARED_LIBRARY_SUFFIX}"
        IMPORTED_IMPLIB_${TS_CONFIG} "${_header_implib}"
        INTERFACE_INCLUDE_DIRECTORIES "${VEIL_INCLUDE_DIR}"
        INTERFACE_INCLUDE_DIRECTORIES_${TS_CONFIG} "${VEIL_INCLUDE_DIR}"
            INTERFACE_BIN_MODULES_${TS_CONFIG} "${_header_bin_modules}"
      )
    endif()
        
    if(NOT TARGET VEILFileSupport)
      add_library(VEILFileSupport SHARED IMPORTED)
      set_target_properties(VEILFileSupport PROPERTIES
        IMPORTED_LOCATION_${TS_CONFIG} "${VEIL_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILVEILFileSupport${EXE_DLL_POSTFIX}${CMAKE_SHARED_LIBRARY_SUFFIX}"
        IMPORTED_IMPLIB_${TS_CONFIG} "${_fs_implib}"
        INTERFACE_INCLUDE_DIRECTORIES "${VEIL_INCLUDE_DIR}"
        INTERFACE_INCLUDE_DIRECTORIES_${TS_CONFIG} "${VEIL_INCLUDE_DIR}"
            INTERFACE_BIN_MODULES_${TS_CONFIG} "${_fs_bin_modules}"
      )
    endif()
        
    if(NOT TARGET VEILSmartCard)
            add_library(VEILSmartCard SHARED IMPORTED)
            set_target_properties(VEILSmartCard PROPERTIES
                IMPORTED_LOCATION_${TS_CONFIG} "${VEIL_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILSmartCard${EXE_DLL_POSTFIX}${CMAKE_SHARED_LIBRARY_SUFFIX}"
            IMPORTED_IMPLIB_${TS_CONFIG} "${_scard_implib}"
                INTERFACE_INCLUDE_DIRECTORIES "${VEIL_INCLUDE_DIR}"
                INTERFACE_INCLUDE_DIRECTORIES_${TS_CONFIG} "${VEIL_INCLUDE_DIR}"
            INTERFACE_BIN_MODULES_${TS_CONFIG} "${_scard_bin_modules}"
            )
    endif()

    IF(WIN32)
      if(NOT TARGET VEILWinAPI)
          add_library(VEILWinAPI SHARED IMPORTED)
          set_target_properties(VEILWinAPI PROPERTIES
            IMPORTED_LOCATION_${TS_CONFIG} "${VEIL_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILWinAPI${EXE_DLL_POSTFIX}${CMAKE_SHARED_LIBRARY_SUFFIX}"
          IMPORTED_IMPLIB_${TS_CONFIG} "${_winapi_implib}"
            INTERFACE_INCLUDE_DIRECTORIES "${VEIL_INCLUDE_DIR}"
            INTERFACE_INCLUDE_DIRECTORIES_${TS_CONFIG} "${VEIL_INCLUDE_DIR}"
          INTERFACE_BIN_MODULES_${TS_CONFIG} "${_winapi_bin_modules}"
          )
      endif()
    endif()

    if(NOT TARGET VEILWxWidgets)
            add_library(VEILWxWidgets SHARED IMPORTED)
            set_target_properties(VEILWxWidgets PROPERTIES
                IMPORTED_LOCATION_${TS_CONFIG} "${VEIL_SHLIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}VEILWxWidgets${EXE_DLL_POSTFIX}${CMAKE_SHARED_LIBRARY_SUFFIX}"
            IMPORTED_IMPLIB_${TS_CONFIG} "${_wxwidgets_implib}"
                INTERFACE_INCLUDE_DIRECTORIES "${VEIL_INCLUDE_DIR}"
                INTERFACE_INCLUDE_DIRECTORIES_${TS_CONFIG} "${VEIL_INCLUDE_DIR}"
            INTERFACE_BIN_MODULES_${TS_CONFIG} "${_wxwidgets_bin_modules}"
            )
    endif()

    if(NOT TARGET xml2Asn1CodeGen)
      add_executable(xml2Asn1CodeGen IMPORTED)
      set_target_properties(xml2Asn1CodeGen PROPERTIES
        IMPORTED_LOCATION_${TS_CONFIG} "${VEIL_BIN_DIR}/xml2Asn1CodeGen${DEBUG_POSTFIX}${CMAKE_EXECUTABLE_SUFFIX}"
            INTERFACE_BIN_MODULES_${TS_CONFIG} "${VEIL_BIN_DIR}/xml2Asn1CodeGen${DEBUG_POSTFIX}${CMAKE_EXECUTABLE_SUFFIX}"
      )
    endif()

    if(NOT TARGET file2hex)
      add_executable(file2hex IMPORTED)
      set_target_properties(file2hex PROPERTIES
        IMPORTED_LOCATION_${TS_CONFIG} "${VEIL_BIN_DIR}/file2hex${DEBUG_POSTFIX}${CMAKE_EXECUTABLE_SUFFIX}"
            INTERFACE_BIN_MODULES_${TS_CONFIG} "${VEIL_BIN_DIR}/file2hex${DEBUG_POSTFIX}${CMAKE_EXECUTABLE_SUFFIX}"
      )
    endif()

    if(NOT TARGET filetob64)
      add_executable(filetob64 IMPORTED)
      set_target_properties(filetob64 PROPERTIES
        IMPORTED_LOCATION_${TS_CONFIG} "${VEIL_BIN_DIR}/filetob64${DEBUG_POSTFIX}${CMAKE_EXECUTABLE_SUFFIX}"
            INTERFACE_BIN_MODULES_${TS_CONFIG} "${VEIL_BIN_DIR}/filetob64${DEBUG_POSTFIX}${CMAKE_EXECUTABLE_SUFFIX}"
      )
    endif()

    if(NOT TARGET hex2file)
      add_executable(hex2file IMPORTED)
      set_target_properties(hex2file PROPERTIES
        IMPORTED_LOCATION_${TS_CONFIG} "${VEIL_BIN_DIR}/hex2file${DEBUG_POSTFIX}${CMAKE_EXECUTABLE_SUFFIX}"
            INTERFACE_BIN_MODULES_${TS_CONFIG} "${VEIL_BIN_DIR}/hex2file${DEBUG_POSTFIX}${CMAKE_EXECUTABLE_SUFFIX}"
      )
    endif()

    if(NOT TARGET OID2Hex)
      add_executable(OID2Hex IMPORTED)
      set_target_properties(OID2Hex PROPERTIES
        IMPORTED_LOCATION_${TS_CONFIG} "${VEIL_BIN_DIR}/OID2Hex${DEBUG_POSTFIX}${CMAKE_EXECUTABLE_SUFFIX}"
            INTERFACE_BIN_MODULES_${TS_CONFIG} "${VEIL_BIN_DIR}/OID2Hex${DEBUG_POSTFIX}${CMAKE_EXECUTABLE_SUFFIX}"
      )
    endif()

    if(NOT TARGET b64Tofile)
      add_executable(b64Tofile IMPORTED)
      set_target_properties(b64Tofile PROPERTIES
        IMPORTED_LOCATION_${TS_CONFIG} "${VEIL_BIN_DIR}/b64Tofile${DEBUG_POSTFIX}${CMAKE_EXECUTABLE_SUFFIX}"
            INTERFACE_BIN_MODULES_${TS_CONFIG} "${VEIL_BIN_DIR}/b64Tofile${DEBUG_POSTFIX}${CMAKE_EXECUTABLE_SUFFIX}"
      )
    endif()

    IF(WIN32)
      if(NOT TARGET Com2H)
        add_executable(Com2H IMPORTED)
        set_target_properties(Com2H PROPERTIES
          IMPORTED_LOCATION_${TS_CONFIG} "${VEIL_BIN_DIR}/Com2H${DEBUG_POSTFIX}${CMAKE_EXECUTABLE_SUFFIX}"
          INTERFACE_BIN_MODULES_${TS_CONFIG} "${VEIL_BIN_DIR}/Com2H${DEBUG_POSTFIX}${CMAKE_EXECUTABLE_SUFFIX}"
        )
      endif()
    ENDIF(WIN32)
  else ()
    message(FATAL_ERROR "VEILApiVersion.cmake could not be found.")
  endif()

else ()
  message(FATAL_ERROR "VEILApiVersion could not be found.")
endif(VEIL_ROOT_DIR)


