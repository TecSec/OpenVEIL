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

#
# This section is used to set the basic configuration for CMAKE
#
LIST(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmakemodules)
if(POLICY CMP0005)
    cmake_policy(SET CMP0005 NEW)
endif()
if(POLICY CMP0048)
    cmake_policy(SET CMP0048 NEW)
endif()
if(POLICY CMP0058)
    cmake_policy(SET CMP0058 NEW)
endif()

set(VEILCORENAME VEIL)
string(TOUPPER ${VEILCORENAME} VEILCORENAME_U)
string(TOLOWER ${VEILCORENAME} VEILCORENAME_L)

set(TS_VS_CONFIG ${CMAKE_BUILD_TYPE})
set (CMAKE_CONFIGURATION_TYPES ${CMAKE_BUILD_TYPE})
set (CMAKE_CONFIGURATION_TYPES "${CMAKE_CONFIGURATION_TYPES}" CACHE STRING "Reset the configurations" FORCE )
mark_as_advanced(CMAKE_CONFIGURATION_TYPES)

set(CMAKE_OSX_DEPLOYMENT_TARGET 10.11)
set(CMAKE_OSX_ARCHITECTURES "Universal")

set(DEBUG_CYBERVEIL ON)
#if(APPLE)
	set(wxWidgets_USE_STATIC OFF)
#endif(APPLE)


set(SuperProject ON)

#
# Set up the project name and look for the compiler configuration
#
# set(TS_MODULE_BIN OpenVEIL)
set(TS_MODULE_INCLUDE OpenVEIL)
project(OpenVEIL LANGUAGES C CXX)
IF(WIN32)
    cmake_minimum_required(VERSION 3.2)
    set_property(GLOBAL PROPERTY USE_FOLDERS On)
ELSE()
    cmake_minimum_required(VERSION 3.2)
ENDIF()

#
# Include the TecSec macros and variables.  Look for the OpaqueVEIL, OpenVEIL and VEILCrypto
#
include(tecsec_configure_env)
include(tecsec_ConfigureCyberVEIL)
if(APPLE)
    set(SDK_FOLDER ${CRYPTO_INSTALL_BASE_DIR})
    set(TS_INSTALL_PREFIX /usr/local)
else()
    set(SDK_FOLDER ${CRYPTO_INSTALL_BASE_DIR})
    set(TS_INSTALL_PREFIX ${CRYPTO_INSTALL_PREFIX})
endif(APPLE)
include(tecsec_packages)
IF(MSVC)
    # include(compiler_tecsec_msvc.noWarnings)
ENDIF(MSVC)
set(NO_PCH OFF)
if(MINGW)
    set(NO_PCH ON)
endif(MINGW)
include(precompiled.header)
include (tecsec_installdirs)

#
# Configure some of the Linux SO parameters
#
if(APPLE)
    SET(CMAKE_SKIP_BUILD_RPATH FALSE)
    SET(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
    SET(CMAKE_INSTALL_RPATH "$ORIGIN;${SHLIB_DIR};~/local")
    SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
elseif(UNIX)
    SET(CMAKE_SKIP_BUILD_RPATH FALSE)
    SET(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
    SET(CMAKE_INSTALL_RPATH "$ORIGIN;${SHLIB_DIR};~/local")
    SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH FALSE)
endif(APPLE)


#####################################################################
## Start Options
#####################################################################

## SET VERSION HERE
set(${VEILCORENAME_U}_MAJOR_VERSION 7)
set(${VEILCORENAME_U}_MINOR_VERSION 0)
set(${VEILCORENAME_U}_REVISION_VERSION 70)
set(${VEILCORENAME_U}_BUILD_VERSION 0)
set(OSX_FRAMEWORK_VERSION A)

#####################################################################
## End Options
#####################################################################
set(VEIL_COPYRIGHT "Copyright (C) 2018 TecSec, Inc.  All Rights Reserved Worldwide.")

set(${VEILCORENAME_U}_VERSION "${${VEILCORENAME_U}_MAJOR_VERSION}.${${VEILCORENAME_U}_MINOR_VERSION}.${${VEILCORENAME_U}_REVISION_VERSION}")
set(${VEILCORENAME_U}_VERSION_COMMA "${${VEILCORENAME_U}_MAJOR_VERSION},${${VEILCORENAME_U}_MINOR_VERSION},${${VEILCORENAME_U}_REVISION_VERSION}")
set(${VEILCORENAME_U}_SO_VERSION "${${VEILCORENAME_U}_MAJOR_VERSION}")

set(VEILCORE_VERSION ${${VEILCORENAME_U}_VERSION})
set(VEILCORE_VERSION_COMMA ${${VEILCORENAME_U}_VERSION_COMMA})

set(ENABLE_NASM OFF)
ENABLE_LANGUAGE(ASM_NASM)
if(CMAKE_ASM_NASM_COMPILER_WORKS)
    set(ENABLE_NASM ON)
endif(CMAKE_ASM_NASM_COMPILER_WORKS)

# set(ENABLE_MASM OFF)
# ENABLE_LANGUAGE(ASM_MASM)
# if(CMAKE_ASM_MASM_COMPILER_WORKS)
# 	set(ENABLE_MASM ON)
# endif(CMAKE_ASM_MASM_COMPILER_WORKS)

IF(WIN32)
    set(GTEST_ROOT c:/GoogleTest/${TS_TOOLSET}_${TS_X_PLATFORM})
ENDIF(WIN32)

find_package(GTest)

if(GTEST_FOUND)
    # enable_testing()
endif()

include(summary)

#
# Place the output into these folders
#
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${PUBLIC_BINARY_TOP_DIR}/lib")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PUBLIC_BINARY_TOP_DIR}/bin")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PUBLIC_BINARY_TOP_DIR}/bin")
set(CMAKE_PDB_OUTPUT_DIRECTORY "${PUBLIC_BINARY_TOP_DIR}/pdb")
set(OSX_FRAMEWORK_FOLDER "/Library/Frameworks")
set(OSX_SDK_DIR "{PUBLIC_BINARY_TOP_DIR}/sdk")

set(EXTRA_FILE_OUTPUT ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
if (MSVC_IDE)
    set(EXTRA_FILE_OUTPUT ${EXTRA_FILE_OUTPUT}/${CMAKE_BUILD_TYPE})
endif(MSVC_IDE)

# look for system header files needed

if(ANDROID)
message(STATUS "ANDROID BUILD")
endif()
FOREACH(KEYWORD "__inline__" "__inline" "inline")
  IF(NOT DEFINED C_INLINE)
    TRY_COMPILE(C_HAS_${KEYWORD} "${CMAKE_CURRENT_BINARY_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/SolutionItems/test_inline.c" COMPILE_DEFINITIONS "-Dinline=${KEYWORD}")
    IF(C_HAS_${KEYWORD})
      MESSAGE(STATUS "Inline found as ${KEYWORD}")
      SET(C_INLINE TRUE)
      SET(TS_INLINE ${KEYWORD})
    ENDIF()
  ENDIF()
ENDFOREACH(KEYWORD)
IF(NOT DEFINED C_INLINE)
  MESSAGE(STATUS "Inline not found")
  SET(TS_INLINE "")
ENDIF()

find_package(PCSC)

if (PCSC_FOUND AND NOT APPLE)
    get_property(_tmp TARGET pcsc PROPERTY INTERFACE_INCLUDE_DIRECTORIES)
    if(NOT ("${_tmp}" STREQUAL ""))
        include_directories(${_tmp})
        set(CMAKE_REQUIRED_INCLUDES ${CMAKE_REQUIRED_INCLUDES} ${_tmp})
    endif(NOT ("${_tmp}" STREQUAL ""))
    get_property(_tmp TARGET pcsc PROPERTY DLOPEN_SONAME)
    set(PCSC_SO_NAME, ${_tmp})
    message(STATUS 	"set(PCSC_SO_NAME, ${_tmp})")
endif()

if(CMAKE_COMPILER_IS_GNUCC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wdeclaration-after-statement -Wstrict-prototypes")
endif()

#if (NOT DEFINED HAVE_CONSTEXPR)
    TRY_COMPILE(HAVE_CONSTEXPR "${CMAKE_CURRENT_BINARY_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/SolutionItems/test_constexpr.cpp" )
    if(HAVE_CONSTEXPR)
        MESSAGE(STATUS "constexpr supported")
    else()
        MESSAGE(STATUS "constexpr NOT supported")
    endif()
#endif()

if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    set(PROJECT_POSTFIX _d)
else()
    set(PROJECT_POSTFIX )
endif()

set(HAVE_SMARTCARD 0)
if(WIN32)
    set(HAVE_SMARTCARD 1)
elseif(TARGET pcsc)
    set(HAVE_SMARTCARD 1)
elseif(APPLE)
    set(HAVE_SMARTCARD 1)
endif(WIN32)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/SolutionItems/compilerconfig.h.in ${CMAKE_CURRENT_BINARY_DIR}/core/${TS_TOOLSET}/compilerconfig.h)
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/SolutionItems/compilerconfig_c.h.in ${CMAKE_CURRENT_BINARY_DIR}/core/${TS_TOOLSET}/compilerconfig_c.h)

ImportTarget(CyberVEIL)

add_definitions(-DWFMO)
add_definitions(-D_CYBERVEILCPP_HEADER_ONLY)

include_directories(
    ${CMAKE_CURRENT_BINARY_DIR} 
    ${CMAKE_CURRENT_BINARY_DIR}/core
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

if(NOT ANDROID)
ELSE()
    set(CMAKE_INSTALL_DO_STRIP ON)
ENDIF()

set(OVHeaders
    ${CMAKE_CURRENT_SOURCE_DIR}/include/${VEILCORENAME}.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/VEILCmsHeader.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/VEILFileSupport.h
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

    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsXmlError.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsXmlNode.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsXmlParser.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsXmlParserCallback.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsAppConfig.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/IPropertyMap.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/INotifyPropertyChange.h
    
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/IVeilUtilities.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/IOutputCollector.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/IVeilToolCommand.h

    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsCryptoStringBase.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsCryptoString.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsCryptoData.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/CryptoContainerWrapper.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/CryptoInterfaces.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/CryptoExceptions.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/FipsState.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsCryptoDate.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/TlvDocument.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/TlvNode.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/json.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsTlvSerializer.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/CryptoUtf16.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsDistinguishedName.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/xp_sharedlib.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/xp_file.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/CryptoIterators.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/CryptoLocks.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/CryptoEvent.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/Endian.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsCertificateParser.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsCertificateBuilder.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsCertificateExtension.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/tsCertificateNamePart.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/standardLayoutList.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/pevents.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/CkmSymmetricAlgorithmImpl.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/cryptolocator.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/cryptolocatorwriter.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/core/VEILCrypto.h
    )
set(VEILCoreHeadersCompiler
    ${CMAKE_CURRENT_BINARY_DIR}/core/${TS_TOOLSET}/compilerconfig.h
    ${CMAKE_CURRENT_BINARY_DIR}/core/${TS_TOOLSET}/compilerconfig_c.h

)

set(VEILCmsHeaders
    ${CMAKE_CURRENT_SOURCE_DIR}/include/CmsHeader/CmsHeaderExtensionOIDs.h
    ${CMAKE_CURRENT_SOURCE_DIR}/include/CmsHeader/CmsHeaderInterfaces.h
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

set(GEN_EXPORTS_XASN
    ${PUBLIC_BINARY_TOP_DIR}/core/CryptoAsn1.export
    ${PUBLIC_BINARY_TOP_DIR}/core/PKIX.export
    ${PUBLIC_BINARY_TOP_DIR}/core/PKIX_Cert.export
    ${PUBLIC_BINARY_TOP_DIR}/core/PKIX_OCSP.export
)
set(GEN_HEADERS_XASN
    ${PUBLIC_BINARY_TOP_DIR}/core/CryptoAsn1.h
    ${PUBLIC_BINARY_TOP_DIR}/core/PKIX.h
    ${PUBLIC_BINARY_TOP_DIR}/core/PKIX_Cert.h
    ${PUBLIC_BINARY_TOP_DIR}/core/PKIX_OCSP.h
    ${PUBLIC_BINARY_TOP_DIR}/Asn1CkmHeader.h
    ${PUBLIC_BINARY_TOP_DIR}/TokenPacket.h
    ${PUBLIC_BINARY_TOP_DIR}/CTSProfile.h
    ${PUBLIC_BINARY_TOP_DIR}/Asn1CkmHeader.export
    ${PUBLIC_BINARY_TOP_DIR}/TokenPacket.export
    ${PUBLIC_BINARY_TOP_DIR}/CTSProfile.export
)
set (VEILCoreHeaders ${VEILCoreHeaders} ${GEN_EXPORTS_XASN} ${GEN_HEADERS_XASN})
CONFIGURE_FILE(VEILApiVersion.cmake.in ${CMAKE_CURRENT_BINARY_DIR}/VEILApiVersion.cmake)

if (NOT APPLE)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/VEILApiVersion.cmake DESTINATION ${INCLUDE_DIR})
    install(FILES ${OVHeaders} DESTINATION ${INCLUDE_DIR})
    install(FILES ${VEILCoreHeaders} DESTINATION ${INCLUDE_DIR}/core)
    install(FILES ${VEILCoreHeadersCompiler} DESTINATION ${INCLUDE_DIR}/core/${TS_TOOLSET})
    install(FILES ${VEILCmsHeaders} DESTINATION ${INCLUDE_DIR}/CmsHeader)
    install(FILES ${VEILCoreHelpHeaders} DESTINATION ${INCLUDE_DIR}/Help)
    IF(WIN32)
    install(FILES ${OVWinAPIHeaders} DESTINATION ${INCLUDE_DIR}/WinAPI)
    ENDIF(WIN32)
    if(wxWidgets_FOUND)
        install(FILES ${OVWxWinHeaders} DESTINATION ${INCLUDE_DIR}/VEILWxWidgets)
    endif()
endif()

if(UNIX)
    string(REPLACE ";" " " VEILHeaders_str "${OVHeaders} ${PUBLIC_BINARY_TOP_DIR}/Asn1CkmHeader.h ${PUBLIC_BINARY_TOP_DIR}/TokenPacket.h ${PUBLIC_BINARY_TOP_DIR}/CTSProfile.h ${PUBLIC_BINARY_TOP_DIR}/VEILssmAsn.h")
    string(REPLACE ";" " " VEILCoreHeaders_str "${VEILCoreHeaders}")
    string(REPLACE ";" " " VEILCmsHeaders_str "${VEILCmsHeaders}")
    # configure_file(${CMAKE_CURRENT_SOURCE_DIR}/stagesdk.sh.in ${CMAKE_CURRENT_BINARY_DIR}/stagesdk.sh @ONLY)
    # configure_file(${CMAKE_CURRENT_SOURCE_DIR}/installsdk.sh.in ${CMAKE_CURRENT_BINARY_DIR}/installsdk.sh @ONLY)
    # install(FILES ${CMAKE_CURRENT_BINARY_DIR}/install.sh ${CMAKE_CURRENT_BINARY_DIR}/installtools.sh ${CMAKE_CURRENT_BINARY_DIR}/installsdk.sh ${CMAKE_CURRENT_BINARY_DIR}/stage.sh ${CMAKE_CURRENT_BINARY_DIR}/stagesdk.sh DESTINATION ${BIN_DIR} PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)
endif(UNIX)

add_subdirectory(VEILCore)
add_subdirectory(VEILCmsHeader)
add_subdirectory(VEILFileSupport)
IF(WIN32)
    add_subdirectory(VEILWinAPI)
ENDIF(WIN32)
if (wxWidgets_FOUND)
    add_subdirectory(VeilWxWidgets)
    add_subdirectory(TextVEIL)
endif (wxWidgets_FOUND)
add_subdirectory(FileVEIL)
add_subdirectory(veiltool)
if(GTEST_FOUND)
    add_subdirectory(unittests)
endif(GTEST_FOUND)

if(WIN32)
    CopyImportTargetBinaries(CyberVEIL ${BIN_DIR})
	if (wxWidgets_FOUND)
	    CopyImportTargetBinaries(WxWidgets ${BIN_DIR})
	endif (wxWidgets_FOUND)
endif(WIN32)

if(APPLE)
    CONFIGURE_FILE(README.md ${CMAKE_CURRENT_BINARY_DIR}/bin/README.md COPYONLY)
    CONFIGURE_FILE(LICENSE.md ${CMAKE_CURRENT_BINARY_DIR}/bin/LICENSE.md COPYONLY)


    CONFIGURE_FILE(SolutionItems/BuildFrameworks.VEILCore.cmake.osx.in ${CMAKE_CURRENT_BINARY_DIR}/bin/BuildFrameworks.VEILCore.cmake @ONLY)
    CONFIGURE_FILE(SolutionItems/VEILCore.list.osx.in ${CMAKE_CURRENT_BINARY_DIR}/bin/VEILCore.list @ONLY)
    CONFIGURE_FILE(SolutionItems/VEILCoreSDK.list.osx.in ${CMAKE_CURRENT_BINARY_DIR}/bin/VEILCoreSDK.list @ONLY)

    add_custom_target(CopyFrameworkVEILCore ALL
        WORKING_DIRECTORY
            ${CMAKE_CURRENT_BINARY_DIR}/bin
        COMMAND 
            ${CMAKE_COMMAND} -P BuildFrameworks.VEILCore.cmake
    )
    add_dependencies(CopyFrameworkVEILCore VEILCore ) # VEILWxWidgets


    CONFIGURE_FILE(SolutionItems/BuildFrameworks.VEILCmsHeader.cmake.osx.in ${CMAKE_CURRENT_BINARY_DIR}/bin/BuildFrameworks.VEILCmsHeader.cmake @ONLY)
    CONFIGURE_FILE(SolutionItems/VEILCmsHeader.list.osx.in ${CMAKE_CURRENT_BINARY_DIR}/bin/VEILCmsHeader.list @ONLY)
    CONFIGURE_FILE(SolutionItems/VEILCmsHeaderSDK.list.osx.in ${CMAKE_CURRENT_BINARY_DIR}/bin/VEILCmsHeaderSDK.list @ONLY)

    add_custom_target(CopyFrameworkVEILCmsHeader ALL
        WORKING_DIRECTORY
            ${CMAKE_CURRENT_BINARY_DIR}/bin
        COMMAND 
            ${CMAKE_COMMAND} -P BuildFrameworks.VEILCmsHeader.cmake
    )
    add_dependencies(CopyFrameworkVEILCmsHeader CopyFrameworkVEILCore VEILCmsHeader ) # VEILWxWidgets


    CONFIGURE_FILE(SolutionItems/BuildFrameworks.VEILFileSupport.cmake.osx.in ${CMAKE_CURRENT_BINARY_DIR}/bin/BuildFrameworks.VEILFileSupport.cmake @ONLY)
    CONFIGURE_FILE(SolutionItems/VEILFileSupport.list.osx.in ${CMAKE_CURRENT_BINARY_DIR}/bin/VEILFileSupport.list @ONLY)
    CONFIGURE_FILE(SolutionItems/VEILFileSupportSDK.list.osx.in ${CMAKE_CURRENT_BINARY_DIR}/bin/VEILFileSupportSDK.list @ONLY)

    add_custom_target(CopyFrameworkVEILFileSupport ALL
        WORKING_DIRECTORY
            ${CMAKE_CURRENT_BINARY_DIR}/bin
        COMMAND 
            ${CMAKE_COMMAND} -P BuildFrameworks.VEILFileSupport.cmake
    )
    add_dependencies(CopyFrameworkVEILFileSupport CopyFrameworkVEILCore VEILFileSupport ) # VEILWxWidgets
    
    
    if (wxWidgets_FOUND)
        CONFIGURE_FILE(SolutionItems/BuildFrameworks.VEILWxWidgets.cmake.osx.in ${CMAKE_CURRENT_BINARY_DIR}/bin/BuildFrameworks.VEILWxWidgets.cmake @ONLY)
        CONFIGURE_FILE(SolutionItems/VEILWxWidgets.list.osx.in ${CMAKE_CURRENT_BINARY_DIR}/bin/VEILWxWidgets.list @ONLY)
        CONFIGURE_FILE(SolutionItems/VEILWxWidgetsSDK.list.osx.in ${CMAKE_CURRENT_BINARY_DIR}/bin/VEILWxWidgetsSDK.list @ONLY)

        add_custom_target(CopyFrameworkVEILWxWidgets ALL
            WORKING_DIRECTORY
                ${CMAKE_CURRENT_BINARY_DIR}/bin
            COMMAND 
                ${CMAKE_COMMAND} -P BuildFrameworks.VEILWxWidgets.cmake
        )
        add_dependencies(CopyFrameworkVEILWxWidgets CopyFrameworkVEILCore VEILWxWidgets ) # VEILWxWidgets


        CONFIGURE_FILE(SolutionItems/BuildFrameworks.OpenVEIL.cmake.osx.in ${CMAKE_CURRENT_BINARY_DIR}/bin/BuildFrameworks.OpenVEIL.cmake @ONLY)
        CONFIGURE_FILE(SolutionItems/OpenVEIL.list.osx.in ${CMAKE_CURRENT_BINARY_DIR}/bin/OpenVEIL.list @ONLY)
        CONFIGURE_FILE(SolutionItems/OpenVEILSDK.list.osx.in ${CMAKE_CURRENT_BINARY_DIR}/bin/OpenVEILSDK.list @ONLY)

        add_custom_target(CopyFrameworkOpenVEIL ALL
            WORKING_DIRECTORY
                ${CMAKE_CURRENT_BINARY_DIR}/bin
            COMMAND 
                ${CMAKE_COMMAND} -P BuildFrameworks.OpenVEIL.cmake
        )
        add_dependencies(CopyFrameworkOpenVEIL CopyFrameworkVEILCore CopyFrameworkVEILWxWidgets  CopyFrameworkVEILFileSupport CopyFrameworkVEILCmsHeader) # VEILWxWidgets

    endif (wxWidgets_FOUND)

endif(APPLE)

summary()
add_uninstall()

# DumpAllVariables()
