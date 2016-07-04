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


add_definitions("-DDLL_FRAMEWORK_USONLY")
add_definitions("-DWFMO")

add_custom_command(
	OUTPUT
		${CMAKE_CURRENT_BINARY_DIR}/Asn1CkmHeader.cpp
		${PUBLIC_BINARY_TOP_DIR}/Asn1CkmHeader.h
		${PUBLIC_BINARY_TOP_DIR}/Asn1CkmHeader.export
	DEPENDS
		${CMAKE_CURRENT_SOURCE_DIR}/Asn1CkmHeader.xasn
		xml2Asn1CodeGen
	COMMAND
		xml2Asn1CodeGen -o=${CMAKE_CURRENT_BINARY_DIR} -e=${CRYPTO_INCLUDE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/Asn1CkmHeader.xasn
	COMMAND
		${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/Asn1CkmHeader.h ${PUBLIC_BINARY_TOP_DIR}/Asn1CkmHeader.h
	COMMAND
		${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/Asn1CkmHeader.export ${PUBLIC_BINARY_TOP_DIR}/Asn1CkmHeader.export
	)

add_custom_command(
	OUTPUT
		${CMAKE_CURRENT_BINARY_DIR}/TokenPacket.cpp
		${CMAKE_CURRENT_BINARY_DIR}/CTSProfile.cpp
		${PUBLIC_BINARY_TOP_DIR}/TokenPacket.h
		${PUBLIC_BINARY_TOP_DIR}/CTSProfile.h
		${PUBLIC_BINARY_TOP_DIR}/TokenPacket.export
		${PUBLIC_BINARY_TOP_DIR}/CTSProfile.export
	DEPENDS
		${CMAKE_CURRENT_SOURCE_DIR}/TokenPacket.xasn
		xml2Asn1CodeGen
	COMMAND
		xml2Asn1CodeGen -o=${CMAKE_CURRENT_BINARY_DIR} -e=${CRYPTO_INCLUDE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/TokenPacket.xasn
	COMMAND
		${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/TokenPacket.h ${PUBLIC_BINARY_TOP_DIR}/TokenPacket.h
	COMMAND
		${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/CTSProfile.h ${PUBLIC_BINARY_TOP_DIR}/CTSProfile.h
	COMMAND
		${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/TokenPacket.export ${PUBLIC_BINARY_TOP_DIR}/TokenPacket.export
	COMMAND
		${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/CTSProfile.export ${PUBLIC_BINARY_TOP_DIR}/CTSProfile.export
	)

INCLUDE_DIRECTORIES(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}
    )

set(VEILCoreSource
	pem.cpp
	servicelocator.cpp

	TcpMsgProcessor.cpp
	VEILCore.cpp
	HttpHeader.cpp
	TcpConnection.h
	TcpConnection.cpp
	TcpChannel.h
	TcpChannel.cpp
	HttpChannel.cpp
	UrlParser.cpp
	CkmFileReader.cpp
	CkmFileWriter.cpp
	CkmMemoryFifoStream.cpp
	CkmMemoryStream.cpp
	CkmReadAppendFile.cpp
	CkmReadWriteFile.cpp
	KeyVEILConnector.cpp
	Token.cpp
	Favorite.cpp
	xp_console.cpp
	KeyVEILSession.cpp

	CkmSymmetricAlgorithmImpl.h
	stdafx.cpp
	tsAttributeMap.cpp
	CkmChangeMonitorImpl.cpp
	CkmChangeMonitorImpl.h
	tsThread.cpp
	tsJsonPreferencesBase.cpp
	BasicVEILPreferences.cpp

	tsLog.cpp
	tsTraceStream.cpp
	tsDebug.cpp
	tsDebugStream.cpp
	PluginModuleManager.cpp
	PluginModule.cpp
	nargv.cpp


)
set(VEILCoreSource ${VEILCoreSource}

	tsXmlHelper.cpp
	tsXmlError.cpp
	tsXmlNode.cpp
	tsPreferencesBase.cpp
	tsAppConfig.cpp
	tsXmlParser.cpp
	tsSignal.cpp
	PropertyChangedEventArgs.cpp
	NotifyPropertyChange.cpp
	PropertyMap.cpp

	Asn1CkmHeader.xasn
	TokenPacket.xasn
	)
if(UNIX)
	set(VEILCoreSource ${VEILCoreSource}
		sd-daemon.c
	)
endif(UNIX)

set(GEN_HEADERS_XASN
	${PUBLIC_BINARY_TOP_DIR}/Asn1CkmHeader.h
	${PUBLIC_BINARY_TOP_DIR}/TokenPacket.h
	${PUBLIC_BINARY_TOP_DIR}/CTSProfile.h
	${PUBLIC_BINARY_TOP_DIR}/Asn1CkmHeader.export
	${PUBLIC_BINARY_TOP_DIR}/TokenPacket.export
	${PUBLIC_BINARY_TOP_DIR}/CTSProfile.export
)
set(GEN_SOURCE_XASN 
	${CMAKE_CURRENT_BINARY_DIR}/Asn1CkmHeader.cpp
	${CMAKE_CURRENT_BINARY_DIR}/TokenPacket.cpp
	${CMAKE_CURRENT_BINARY_DIR}/CTSProfile.cpp
)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/VEILCore.rc.in ${CMAKE_CURRENT_BINARY_DIR}/VEILCore.rc)

if(WIN32)
    set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/VEILCore.rc PROPERTIES COMPILE_DEFINITIONS RC_COMPILED)
endif(WIN32)

add_library(VEILCore SHARED
    ${CMAKE_CURRENT_BINARY_DIR}/VEILCore.rc
	stdafx.h
	targetver.h
	resource.h

	${CMAKE_CURRENT_SOURCE_DIR}/VEILCore.rc.in

    ${VEILCoreSource}
	${OVHeaders}
	${VEILCoreHeaders}
	${GEN_HEADERS_XASN}
    ${GEN_SOURCE_XASN}
)
Source_Group(CryptoInterface FILES 	
 	ServerAuthenticationCalculatorPbkdf.cpp 
	TunnelInitiator.cpp TunnelResponder.cpp TunnelEncryptor.cpp TunnelDecryptor.cpp CkmAuthentication.cpp
)
Source_Group(Generated FILES ${GEN_HEADERS_XASN} ${GEN_SOURCE_XASN})

target_include_directories(VEILCore INTERFACE $<BUILD_INTERFACE:${PUBLIC_SOURCE_TOP_DIR}/include> $<INSTALL_INTERFACE:${TS_MODULE}/include>)
add_definitions("-DVEILCORE_EXPORTS")

TARGET_LINK_LIBRARIES(VEILCore VEILCryptoCore)
IF(MSVC)
	set_target_properties(VEILCore PROPERTIES LINK_FLAGS "-PDBSTRIPPED:${CMAKE_PDB_OUTPUT_DIRECTORY}/VEILCore.pdb")
ENDIF(MSVC)


if(ANDROID)
	TARGET_LINK_LIBRARIES(VEILCore z)
else(ANDROID)
	TARGET_LINK_LIBRARIES(VEILCore zlib)
endif(ANDROID)
if(UNIX AND NOT ANDROID AND TS_SUPPORT_MESSAGE_QUEUE AND TS_INTERNAL_SD_DAEMON)
    target_link_libraries(VEILCore rt)
endif(UNIX AND NOT ANDROID AND TS_SUPPORT_MESSAGE_QUEUE AND TS_INTERNAL_SD_DAEMON)

if(ANDROID)
	set_target_properties(VEILCore PROPERTIES COTIRE_ADD_UNITY_BUILD FALSE)
endif()
add_precompiled_header(VEILCore stdafx.h FORCEINCLUDE SOURCE_CXX stdafx.cpp)

if(WIN32)
	TARGET_LINK_LIBRARIES(VEILCore ws2_32)
	# add_dependencies(VEILCore Configure.TSFrameworkVersion.h)
ENDIF(WIN32)

set_target_properties(VEILCore PROPERTIES FOLDER "Modules")
if(NOT ANDROID)
	set_target_properties(VEILCore PROPERTIES VERSION ${${VEILCORENAME_U}_VERSION} SOVERSION ${${VEILCORENAME_U}_SO_VERSION})
else()
	# set_target_properties(VEILCore PROPERTIES ANDROID_ARCH "x86")
endif()
set_target_properties(VEILCore PROPERTIES OUTPUT_NAME ${VEILCORENAME}Core)
if(UNIX AND CMAKE_OBJCOPY)
	add_custom_command(TARGET VEILCore POST_BUILD 
		COMMAND ${CMAKE_OBJCOPY} --only-keep-debug $<TARGET_FILE:VEILCore> $<TARGET_FILE_DIR:VEILCore>/$<TARGET_FILE_NAME:VEILCore>.dbg 
		COMMAND ${CMAKE_OBJCOPY} --strip-debug $<TARGET_FILE:VEILCore>
		)
endif()

install(TARGETS VEILCore ARCHIVE DESTINATION ${LIB_DIR} LIBRARY DESTINATION ${SHLIB_DIR} RUNTIME DESTINATION ${BIN_DIR} )

install(FILES ${GEN_HEADERS_XASN} DESTINATION ${INCLUDE_DIR})
