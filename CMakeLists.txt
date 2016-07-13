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

IF(WIN32)
	cmake_minimum_required(VERSION 3.2.0)
	set_property(GLOBAL PROPERTY USE_FOLDERS On)
ELSE()
	cmake_minimum_required(VERSION 3.2.0)
ENDIF()
cmake_policy(SET CMP0048 NEW)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmakemodules")

set(VEILCORENAME VEIL)
string(TOUPPER ${VEILCORENAME} VEILCORENAME_U)
string(TOLOWER ${VEILCORENAME} VEILCORENAME_L)

set(CMAKE_BUILD_TYPE ${TS_VS_CONFIG} CACHE STRING "The configuration build type")
if (CMAKE_CONFIGURATION_TYPES)
  set (CMAKE_CONFIGURATION_TYPES ${TS_VS_CONFIG})
  set (CMAKE_CONFIGURATION_TYPES "${CMAKE_CONFIGURATION_TYPES}" CACHE STRING "Reset the configurations for ${VEILCORENAME}" )
endif()

#####################################################################
## Start Options
#####################################################################

if(WIN32)
	if(NOT "$ENV{VEIL_ROOT}" STREQUAL "")
		set(OPENVEIL_SDK_FOLDER "$ENV{VEIL_ROOT}" CACHE PATH "The install location for OpenVEIL")
	else()
		set(OPENVEIL_SDK_FOLDER "c:/TecSec/VEIL" CACHE PATH "The install location for OpenVEIL")
	endif()
else()
	set(OPENVEIL_SDK_FOLDER "~/local/VEIL" CACHE PATH "The install location for OpenVEIL")
endif()

set(${VEILCORENAME_U}_MAJOR_VERSION 7)
set(${VEILCORENAME_U}_MINOR_VERSION 0)
set(${VEILCORENAME_U}_REVISION_VERSION 34)
set(${VEILCORENAME_U}_BUILD_VERSION 0)

option(TS_INTERNAL_SD_DAEMON "Enable the reference copy of sd_daemon code within VEIL (More portable)." ON)
option(TS_SUPPORT_MESSAGE_QUEUE "Enable message queue support in the internal sd-daemon" ON)

#####################################################################
## End Options
#####################################################################

project(${VEILCORENAME} LANGUAGES C CXX VERSION ${${VEILCORENAME_U}_MAJOR_VERSION}.${${VEILCORENAME_U}_MINOR_VERSION}.${${VEILCORENAME_U}_REVISION_VERSION}.${${VEILCORENAME_U}_BUILD_VERSION})

if(UNIX)
    SET(CMAKE_SKIP_BUILD_RPATH FALSE)
    SET(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
    SET(CMAKE_INSTALL_RPATH "$ORIGIN")
    SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH FALSE)
endif(UNIX)

set(VEIL_COPYRIGHT "Copyright (C) 2016 TecSec, Inc.  All Rights Reserved Worldwide.")

set(${VEILCORENAME_U}_VERSION "${${VEILCORENAME_U}_MAJOR_VERSION}.${${VEILCORENAME_U}_MINOR_VERSION}.${${VEILCORENAME_U}_REVISION_VERSION}")
set(${VEILCORENAME_U}_VERSION_COMMA "${${VEILCORENAME_U}_MAJOR_VERSION},${${VEILCORENAME_U}_MINOR_VERSION},${${VEILCORENAME_U}_REVISION_VERSION}")
set(${VEILCORENAME_U}_SO_VERSION "${${VEILCORENAME_U}_MAJOR_VERSION}")

set(VEILCORE_VERSION ${${VEILCORENAME_U}_VERSION})
set(VEILCORE_VERSION_COMMA ${${VEILCORENAME_U}_VERSION_COMMA})

set(SuperProject ON)

include(tecsec_configure_env)
include(tecsec_ConfigureVEILCrypto)
# get_filename_component(__tmp ${VEILCRYPTO_ROOT_DIR} DIRECTORY)
# string(FIND ${__tmp} "/" __tmpPos REVERSE)
# string(SUBSTRING ${__tmp} 0 ${__tmpPos} __tmp)
set(SDK_FOLDER ${OPENVEIL_SDK_FOLDER})
set(TS_INSTALL_PREFIX ${SDK_FOLDER}/${TS_TOOLSET})
include (tecsec_installdirs)
include(tecsec_packages)
IF(MSVC)
	# include(compiler_tecsec_msvc.noWarnings)
ENDIF(MSVC)
include(precompiled.header)

# Place the output into these folders
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${PUBLIC_BINARY_TOP_DIR}/lib")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PUBLIC_BINARY_TOP_DIR}/bin")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PUBLIC_BINARY_TOP_DIR}/bin")

set(CMAKE_INSTALL_PREFIX ${TS_INSTALL_PREFIX} CACHE STRING "Base install path" FORCE)
set(NO_PCH OFF)
if(MINGW)
    set(NO_PCH ON)
endif(MINGW)

include(summary)

if(CMAKE_COMPILER_IS_GNUCC)
	set(CMAKE_C_FLAGS "")
endif()

find_package(PCSC)

if (PCSC_FOUND)
	get_property(_tmp TARGET pcsc PROPERTY INTERFACE_INCLUDE_DIRECTORIES)
	if(NOT ("${_tmp}" STREQUAL ""))
		include_directories(${_tmp})
		set(CMAKE_REQUIRED_INCLUDES ${CMAKE_REQUIRED_INCLUDES} ${_tmp})
	endif(NOT ("${_tmp}" STREQUAL ""))
	get_property(_tmp TARGET pcsc PROPERTY DLOPEN_SONAME)
	set(PCSC_SO_NAME, ${_tmp})
message(STATUS 	"set(PCSC_SO_NAME, ${_tmp})")
endif()

INCLUDE(CheckIncludeFiles)
INCLUDE(CheckIncludeFileCXX)
INCLUDE(${CMAKE_ROOT}/Modules/CheckIncludeFile.cmake)
INCLUDE(${CMAKE_ROOT}/Modules/CheckTypeSize.cmake)
INCLUDE(${CMAKE_ROOT}/Modules/CheckFunctionExists.cmake)
INCLUDE(${CMAKE_ROOT}/Modules/CheckCXXSourceCompiles.cmake)
INCLUDE(${CMAKE_ROOT}/Modules/TestBigEndian.cmake)
INCLUDE(${CMAKE_ROOT}/Modules/CheckSymbolExists.cmake)

set(CMAKE_EXTRA_INCLUDE_FILES "${CMAKE_EXTRA_INCLUDE_FILES} stdlib.h")

CHECK_INCLUDE_FILES(windows.h HAVE_WINDOWS_H)
CHECK_INCLUDE_FILES(pcsclite.h HAVE_PCSCLITE_H)



if(CMAKE_COMPILER_IS_GNUCC)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wdeclaration-after-statement -Wstrict-prototypes")
endif()

set(HAVE_SMARTCARD 0)
if(HAVE_WINDOWS_H)
    set(HAVE_SMARTCARD 1)
elseif(TARGET pcsc)
    set(HAVE_SMARTCARD 1)
endif(HAVE_WINDOWS_H)

ImportTarget(VEILCryptoCore)
if(TARGET VEILEnhancedCrypto)
	ImportTarget(VEILEnhancedCrypto)
endif(TARGET VEILEnhancedCrypto)

include_directories(
	${CMAKE_CURRENT_BINARY_DIR} 
	${CMAKE_CURRENT_SOURCE_DIR}/include 
	${CMAKE_CURRENT_SOURCE_DIR}/SolutionItems
	)

if(IS_OPAQUEVEIL)
	# added for installer
	CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/SolutionItems/${VEILCORENAME_L}info.txt.in ${CMAKE_CURRENT_BINARY_DIR}/${VEILCORENAME_L}info.txt)
	if(UNIX)
	    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/install.sh.in ${CMAKE_CURRENT_BINARY_DIR}/install.sh @ONLY)
	    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/installtools.sh.in ${CMAKE_CURRENT_BINARY_DIR}/installtools.sh @ONLY)
	    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/stage.sh.in ${CMAKE_CURRENT_BINARY_DIR}/stage.sh @ONLY)
	endif(UNIX)
endif(IS_OPAQUEVEIL)

IF(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/ThirdParty/bzip2")
	include_directories(${CMAKE_CURRENT_SOURCE_DIR}/ThirdParty/bzip2)
ENDIF(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/ThirdParty/bzip2")
if(NOT ANDROID)
	IF(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/ThirdParty/zlib")
		include_directories(${CMAKE_CURRENT_SOURCE_DIR}/ThirdParty/zlib)
		include_directories(${CMAKE_CURRENT_BINARY_DIR}/ThirdParty/zlib)
	ENDIF(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/ThirdParty/zlib")
ELSE()
	set(CMAKE_INSTALL_DO_STRIP ON)
ENDIF()

set(OVHeaders
	${CMAKE_CURRENT_SOURCE_DIR}/include/${VEILCORENAME}.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/VEILCmsHeader.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/VEILFileSupport.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/VEILSmartCard.h
)
IF(WIN32)
	set(OVHeaders ${OVHeaders}
		${CMAKE_CURRENT_SOURCE_DIR}/include/VEILWinAPI.h
	)
ENDIF(WIN32)

set(VEILCoreHeaders
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/VEILCore.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsmod_extension.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/HttpHeader.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/HttpChannel.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/UrlParser.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/CkmFileReader.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/CkmFileStreams.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/CkmFileWriter.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/CkmMemoryFifoStream.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/CkmMemoryStream.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/CkmReadAppendFile.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/CkmReadWriteFile.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/xp_console.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/SimpleOpt.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsThread.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/IPreferenceChangeNotify.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsJsonPreferencesBase.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/BasicVEILPreferences.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/ChangeTracker.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsAttributeMap.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/pem.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/nargv.h

	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsDebug.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsDebugStream.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsLog.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsTraceStream.h

	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsPreferencesBase.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsXmlError.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsXmlNode.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsXmlParser.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsXmlParserCallback.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsAppConfig.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/IPropertyMap.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/INotifyPropertyChange.h
	# ${CMAKE_CURRENT_SOURCE_DIR}/include/core/sd-daemon.h
	
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/IVeilUtilities.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/IOutputCollector.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/core/IVeilToolCommand.h

)

set(VEILCmsHeaders
	${CMAKE_CURRENT_SOURCE_DIR}/include/CmsHeader/CmsHeaderExtensionOIDs.h
	${CMAKE_CURRENT_SOURCE_DIR}/include/CmsHeader/CmsHeaderInterfaces.h
)

set(VEILSmartCardHeaders
	${CMAKE_CURRENT_SOURCE_DIR}/include/VEILSmartCard/tsWinscardExports.h
)
set(VEILCoreHelpHeaders
	${CMAKE_CURRENT_SOURCE_DIR}/include/help/FileVEILHelp.h
)

IF(WIN32)
	set(OVWinAPIHeaders
		${CMAKE_CURRENT_SOURCE_DIR}/include/WinAPI/htmlhelp.h
	)
ENDIF(WIN32)

if (wxWidgets_FOUND)
	INCLUDE_DIRECTORIES(${wxWidgets_INCLUDE_DIRS})
	LINK_DIRECTORIES(${wxWidgets_LIBRARY_DIRS})
	set(VersionLines)
	set(VersionLines "${VersionLines}const int VEILWXWINDOWS_MAJOR = ${${VEILCORENAME_U}_MAJOR_VERSION};\n")
	set(VersionLines "${VersionLines}const int VEILWXWINDOWS_MINOR = ${${VEILCORENAME_U}_MINOR_VERSION};\n")
	set(VersionLines "${VersionLines}const int VEILWXWINDOWS_REVISION = ${${VEILCORENAME_U}_REVISION_VERSION};\n")
	set(VersionLines "${VersionLines}const int VEILWXWINDOWS_BUILD = ${${VEILCORENAME_U}_BUILD_VERSION};\n")
	set(VersionLines "${VersionLines}\n")
	set(VersionLines "${VersionLines}#define VEILWXWINDOWS_FULL_VERSION \"${${VEILCORENAME_U}_VERSION}\"\n")
	set(VersionLines "${VersionLines}#define VEILWXWINDOWS_FULL_VERSION_COMMAS \"${VEILCORE_VERSION_COMMA}\"\n")
	set(VersionLines "${VersionLines}\n")
	set(VersionLines "${VersionLines}#define VEILWXWINDOWS_VERSION \"${VEILCORE_VERSION}\"\n")
	set(VersionLines "${VersionLines}#define VEILWXWINDOWS_SO_VERSION \"${${VEILCORENAME_U}_SO_VERSION}\"\n")
	set(VersionLines "${VersionLines}\n")
	set(VersionLines "${VersionLines}#define VEIL_COPYRIGHT \"${VEIL_COPYRIGHT}\"\n")
	set(VersionLines "${VersionLines}\n")

	file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/VEILwxWidgetsVersion.h "${VersionLines}")
	set(OVHeaders ${OVHeaders}
		${PUBLIC_SOURCE_TOP_DIR}/include/VEILwxWidgets.h
		${CMAKE_CURRENT_BINARY_DIR}/VEILwxWidgetsVersion.h
	)
	set(OVWxWinHeaders
		${PUBLIC_SOURCE_TOP_DIR}/include/VeilWxWidgets/wxhtmlhelp.h
		)
endif (wxWidgets_FOUND)

CopyImportTargetBinaries(VEILCryptoCore ${BIN_DIR})
if(TARGET VEILEnhancedCrypto)
	CopyImportTargetBinaries(VEILEnhancedCrypto ${BIN_DIR})
endif(TARGET VEILEnhancedCrypto)

CONFIGURE_FILE(VEILApiVersion.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/VEILApiVersion.cmake)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/VEILApiVersion.cmake DESTINATION ${BIN_DIR}/..)
install(FILES ${OVHeaders} DESTINATION ${INCLUDE_DIR})
install(FILES ${VEILCoreHeaders} DESTINATION ${INCLUDE_DIR}/core)
install(FILES ${VEILCmsHeaders} DESTINATION ${INCLUDE_DIR}/CmsHeader)
install(FILES ${VEILCoreHelpHeaders} DESTINATION ${INCLUDE_DIR}/Help)

if(UNIX)
	string(REPLACE ";" " " VEILHeaders_str "${OVHeaders} ${PUBLIC_BINARY_TOP_DIR}/Asn1CkmHeader.h ${PUBLIC_BINARY_TOP_DIR}/TokenPacket.h ${PUBLIC_BINARY_TOP_DIR}/CTSProfile.h ${PUBLIC_BINARY_TOP_DIR}/VEILssmAsn.h")
	string(REPLACE ";" " " VEILCoreHeaders_str "${VEILCoreHeaders}")
	string(REPLACE ";" " " VEILCmsHeaders_str "${VEILCmsHeaders}")
	string(REPLACE ";" " " VEILSmartCardHeaders_str "${VEILSmartCardHeaders}")
	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/stagesdk.sh.in ${CMAKE_CURRENT_BINARY_DIR}/stagesdk.sh @ONLY)
	configure_file(${CMAKE_CURRENT_SOURCE_DIR}/installsdk.sh.in ${CMAKE_CURRENT_BINARY_DIR}/installsdk.sh @ONLY)
	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/install.sh ${CMAKE_CURRENT_BINARY_DIR}/installtools.sh ${CMAKE_CURRENT_BINARY_DIR}/installsdk.sh ${CMAKE_CURRENT_BINARY_DIR}/stage.sh ${CMAKE_CURRENT_BINARY_DIR}/stagesdk.sh DESTINATION ${BIN_DIR} PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)
endif(UNIX)
install(FILES ${VEILSmartCardHeaders} DESTINATION ${INCLUDE_DIR}/VEILSmartCard)
IF(WIN32)
install(FILES ${OVWinAPIHeaders} DESTINATION ${INCLUDE_DIR}/WinAPI)
ENDIF(WIN32)
if(wxWidgets_FOUND)
	install(FILES ${OVWxWinHeaders} DESTINATION ${INCLUDE_DIR}/VEILWxWidgets)
endif()

add_subdirectory(BuildTools)
add_subdirectory(ThirdParty)
add_subdirectory(VEILCore)
add_subdirectory(VEILCmsHeader)
add_subdirectory(VEILFileSupport)
IF(WIN32)
	add_subdirectory(VEILWinAPI)
ENDIF(WIN32)
if (wxWidgets_FOUND)
	add_subdirectory(VEILWxWidgets)
	add_subdirectory(TextVEIL)
endif (wxWidgets_FOUND)
IF(HAVE_SMARTCARD)
	add_subdirectory(VEILSmartCard)
ENDIF(HAVE_SMARTCARD)
add_subdirectory(FileVEIL)
add_subdirectory(veiltool)

summary()
add_uninstall()

# DumpAllVariables()
