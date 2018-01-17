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

# =======================================================================
# print summary of configuration to screen
# =======================================================================

macro(summary)
set(_output_results "
Summary of CMake build system results for the TecSec component

Configuration options:
   HOST PLATFORM:                  ${CMAKE_HOST_SYSTEM_PROCESSOR}
   TS_X_PLATFORM:                  ${TS_X_PLATFORM}
   TS_TOOLSET:                     ${TS_TOOLSET}
   CMAKE_VS_PLATFORM_TOOLSET:      ${CMAKE_VS_PLATFORM_TOOLSET}
   TS_VS_CONFIGURATION:            ${TS_VS_CONFIGURATION}
   Postfix for DLLS...             ${CMAKE_${TS_CONFIG}_POSTFIX}

Other important CMake variables:
   CMAKE_SYSTEM_NAME:  ${CMAKE_SYSTEM_NAME}
   UNIX:               ${UNIX}
   WIN32:              ${WIN32}
   APPLE:              ${APPLE}
   MSVC_IDE:           ${MSVC_IDE}
   MSVC:               ${MSVC} (MSVC_VERSION:  ${MSVC_VERSION})
   MINGW:              ${MINGW}
   MSYS:               ${MSYS}
   CYGWIN:             ${CYGWIN}

Compilation Options:
   CMAKE_BUILD_TYPE:               ${CMAKE_BUILD_TYPE}
   CMAKE_C_COMPILER:               ${CMAKE_C_COMPILER}
   CMAKE_C_FLAGS:                  ${CMAKE_C_FLAGS}
   CMAKE_C_FLAGS_DEBUG:            ${CMAKE_C_FLAGS_DEBUG}
   CMAKE_C_FLAGS_RELEASE:          ${CMAKE_C_FLAGS_RELEASE}
   CMAKE_CXX_FLAGS:                ${CMAKE_CXX_FLAGS}
   CMAKE_CXX_FLAGS_DEBUG:          ${CMAKE_CXX_FLAGS_DEBUG}
   CMAKE_CXX_FLAGS_RELEASE:        ${CMAKE_CXX_FLAGS_RELEASE}
   CMAKE_EXECUTABLE_SUFFIX:        ${CMAKE_EXECUTABLE_SUFFIX}
   CMAKE_SHARED_MODULE_PREFIX:     ${CMAKE_SHARED_MODULE_PREFIX}
   CMAKE_SHARED_MODULE_SUFFIX:     ${CMAKE_SHARED_MODULE_SUFFIX}

Build Paths:
   CMAKE_INSTALL_PREFIX:           ${CMAKE_INSTALL_PREFIX}
   CMAKE_INSTALL_EXEC_PREFIX       ${CMAKE_INSTALL_EXEC_PREFIX}
   CMAKE_INSTALL_BINDIR            ${CMAKE_INSTALL_BINDIR}
   CMAKE_INSTALL_LIBDIR            ${CMAKE_INSTALL_LIBDIR}
   CMAKE_INSTALL_INCLUDEDIR        ${CMAKE_INSTALL_INCLUDEDIR}
   CRYPTO_INSTALL_PREFIX           ${CRYPTO_INSTALL_PREFIX} (VERSION: ${CRYPTO_VERSION})
   SOURCE_DIR:                     ${SOURCE_DIR}
   BUILD_DIR:                      ${BUILD_DIR}
   CMAKE_ARCHIVE_OUTPUT_DIRECTORY: ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}
   CMAKE_LIBRARY_OUTPUT_DIRECTORY: ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}
   CMAKE_RUNTIME_OUTPUT_DIRECTORY: ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}

Install Paths:
   TS_INSTALL_PREFIX:              ${TS_INSTALL_PREFIX}
   DATA_DIR:                       ${DATA_DIR}
   INCLUDE_DIR:                    ${INCLUDE_DIR}
   ALLBIN_DIR:                     ${ALLBIN_DIR}
   BIN_DIR:                        ${BIN_DIR}
   LIB_DIR:                        ${LIB_DIR}
   SHLIB_DIR:                      ${SHLIB_DIR}
   DOC_DIR:                        ${DOC_DIR}
   INFO_DIR:                       ${INFO_DIR}
   MAN_DIR:                        ${MAN_DIR}

Optional libraries:")
if (BZ2_FOUND)
set(_output_results "${_output_results}
   BZ2                FOUND ${BZ2_VERSION_STRING}")
else()
set(_output_results "${_output_results}
   BZ2                missing")
endif(BZ2_FOUND)
if (ZLIB_FOUND)
set(_output_results "${_output_results}
   ZLIB               FOUND ${ZLIB_VERSION_STRING}")
else()
set(_output_results "${_output_results}
   ZLIB               missing")
endif(ZLIB_FOUND)
if (HARU_FOUND)
set(_output_results "${_output_results}
   HARU               FOUND ${HARU_VERSION_STRING}")
else()
set(_output_results "${_output_results}
   HARU               missing")
endif(HARU_FOUND)
if (wxWidgets_FOUND)
set(_output_results "${_output_results}
   wxWidgets          FOUND ${wxWidgets_VERSION_STRING}")
else()
set(_output_results "${_output_results}
   wxWidgets          missing")
endif(wxWidgets_FOUND)
if (GMOCK_FOUND)
set(_output_results "${_output_results}
   GMOCK              FOUND")
else()
set(_output_results "${_output_results}
   GMOCK              missing")
endif(GMOCK_FOUND)
if (GTEST_FOUND)
set(_output_results "${_output_results}
   GTEST              FOUND")
else()
set(_output_results "${_output_results}
   GTEST              missing")
endif(GTEST_FOUND)
if (PNG_FOUND)
set(_output_results "${_output_results}
   PNG                FOUND")
else()
set(_output_results "${_output_results}
   PNG                missing")
endif(PNG_FOUND)

message("${_output_results}
")
endmacro(summary)
