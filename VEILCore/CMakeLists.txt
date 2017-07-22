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
	add_definitions(-D__DARWIN__)
elseif(WIN32)
	add_definitions(-D__WINDOWS__)
elseif(UNIX)
	add_definitions(-D__LINUX__)
else()
	message(FATAL "Unknown environment")
endif()

if(APPLE)
    FIND_LIBRARY(Security_LIBRARY Security)
    MARK_AS_ADVANCED(Security_LIBRARY)
    message(STATUS "Security at ${Security_LIBRARY}")
    FIND_LIBRARY(ApplicationServices_LIBRARY ApplicationServices)
    MARK_AS_ADVANCED(ApplicationServices_LIBRARY)
    message(STATUS "ApplicationServices at ${ApplicationServices_LIBRARY}")
endif(APPLE)

add_definitions("-DDLL_FRAMEWORK_USONLY")
add_definitions("-DWFMO")

if(MINGW)
	string(REPLACE "/" "\\" xmlCodeGen ${CRYPTO_BIN_DIR}/xml2Asn1CodeGen${CMAKE_EXECUTABLE_SUFFIX})
	# message(STATUS "CodeGen Path ${xmlCodeGen}")
    elseif(APPLE)
	set(xmlCodeGen /usr/local/bin/xml2Asn1CodeGen)
else()
	set(xmlCodeGen ${CRYPTO_BIN_DIR}/xml2Asn1CodeGen${CMAKE_EXECUTABLE_SUFFIX})
endif()

add_custom_command(
	OUTPUT
		${CMAKE_CURRENT_BINARY_DIR}/CryptoAsn1.cpp
		${PUBLIC_BINARY_TOP_DIR}/core/CryptoAsn1.h
		${PUBLIC_BINARY_TOP_DIR}/core/CryptoAsn1.export
	DEPENDS
		${CMAKE_CURRENT_SOURCE_DIR}/CryptoAsn1.xasn
	COMMAND
		${xmlCodeGen} -o=${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/CryptoAsn1.xasn
	COMMAND
		${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/CryptoAsn1.export ${PUBLIC_BINARY_TOP_DIR}/core/CryptoAsn1.export
	COMMAND
		${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/CryptoAsn1.h ${PUBLIC_BINARY_TOP_DIR}/core/CryptoAsn1.h
	)

add_custom_command(
	OUTPUT
		${CMAKE_CURRENT_BINARY_DIR}/PKIX.cpp
		${PUBLIC_BINARY_TOP_DIR}/core/PKIX.h
		${PUBLIC_BINARY_TOP_DIR}/core/PKIX.export
		${CMAKE_CURRENT_BINARY_DIR}/PKIX_Cert.cpp
		${PUBLIC_BINARY_TOP_DIR}/core/PKIX_Cert.h
		${PUBLIC_BINARY_TOP_DIR}/core/PKIX_Cert.export
		${CMAKE_CURRENT_BINARY_DIR}/PKIX_OCSP.cpp
		${PUBLIC_BINARY_TOP_DIR}/core/PKIX_OCSP.h
		${PUBLIC_BINARY_TOP_DIR}/core/PKIX_OCSP.export
	DEPENDS
		${CMAKE_CURRENT_SOURCE_DIR}/pkix.xasn
		${PUBLIC_BINARY_TOP_DIR}/core/CryptoAsn1.export
	COMMAND
		${xmlCodeGen} -o=${CMAKE_CURRENT_BINARY_DIR} -e=${PUBLIC_BINARY_TOP_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/pkix.xasn
	COMMAND
		${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/PKIX.export ${PUBLIC_BINARY_TOP_DIR}/core/PKIX.export
	COMMAND
		${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/PKIX_Cert.export ${PUBLIC_BINARY_TOP_DIR}/core/PKIX_Cert.export
	COMMAND
		${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/PKIX_OCSP.export ${PUBLIC_BINARY_TOP_DIR}/core/PKIX_OCSP.export
	COMMAND
		${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/PKIX.h ${PUBLIC_BINARY_TOP_DIR}/core/PKIX.h
	COMMAND
		${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/PKIX_Cert.h ${PUBLIC_BINARY_TOP_DIR}/core/PKIX_Cert.h
	COMMAND
		${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/PKIX_OCSP.h ${PUBLIC_BINARY_TOP_DIR}/core/PKIX_OCSP.h
	)

add_custom_command(
	OUTPUT
		${CMAKE_CURRENT_BINARY_DIR}/Asn1CkmHeader.cpp
		${PUBLIC_BINARY_TOP_DIR}/Asn1CkmHeader.h
		${PUBLIC_BINARY_TOP_DIR}/Asn1CkmHeader.export
	DEPENDS
		${PUBLIC_BINARY_TOP_DIR}/core/CryptoAsn1.export
		${CMAKE_CURRENT_SOURCE_DIR}/Asn1CkmHeader.xasn
	COMMAND
		${xmlCodeGen} -o=${CMAKE_CURRENT_BINARY_DIR} -e=${CRYPTO_INCLUDE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/Asn1CkmHeader.xasn
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
		${PUBLIC_BINARY_TOP_DIR}/core/CryptoAsn1.export
	COMMAND
		${xmlCodeGen} -o=${CMAKE_CURRENT_BINARY_DIR} -e=${CRYPTO_INCLUDE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/TokenPacket.xasn
	COMMAND
		${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/TokenPacket.h ${PUBLIC_BINARY_TOP_DIR}/TokenPacket.h
	COMMAND
		${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/CTSProfile.h ${PUBLIC_BINARY_TOP_DIR}/CTSProfile.h
	COMMAND
		${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/TokenPacket.export ${PUBLIC_BINARY_TOP_DIR}/TokenPacket.export
	COMMAND
		${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/CTSProfile.export ${PUBLIC_BINARY_TOP_DIR}/CTSProfile.export
	)
add_custom_target(VEILCoreCodeGen ALL
	BYPRODUCTS
		${CMAKE_CURRENT_BINARY_DIR}/CryptoAsn1.cpp
		${PUBLIC_BINARY_TOP_DIR}/core/CryptoAsn1.h
		${PUBLIC_BINARY_TOP_DIR}/core/CryptoAsn1.export
		${CMAKE_CURRENT_BINARY_DIR}/PKIX.cpp
		${PUBLIC_BINARY_TOP_DIR}/core/PKIX.h
		${PUBLIC_BINARY_TOP_DIR}/core/PKIX.export
		${CMAKE_CURRENT_BINARY_DIR}/PKIX_Cert.cpp
		${PUBLIC_BINARY_TOP_DIR}/core/PKIX_Cert.h
		${PUBLIC_BINARY_TOP_DIR}/core/PKIX_Cert.export
		${CMAKE_CURRENT_BINARY_DIR}/PKIX_OCSP.cpp
		${PUBLIC_BINARY_TOP_DIR}/core/PKIX_OCSP.h
		${PUBLIC_BINARY_TOP_DIR}/core/PKIX_OCSP.export
		${CMAKE_CURRENT_BINARY_DIR}/Asn1CkmHeader.cpp
		${PUBLIC_BINARY_TOP_DIR}/Asn1CkmHeader.h
		${PUBLIC_BINARY_TOP_DIR}/Asn1CkmHeader.export
		${CMAKE_CURRENT_BINARY_DIR}/TokenPacket.cpp
		${CMAKE_CURRENT_BINARY_DIR}/CTSProfile.cpp
		${PUBLIC_BINARY_TOP_DIR}/TokenPacket.h
		${PUBLIC_BINARY_TOP_DIR}/CTSProfile.h
		${PUBLIC_BINARY_TOP_DIR}/TokenPacket.export
		${PUBLIC_BINARY_TOP_DIR}/CTSProfile.export

	SOURCES
		${CMAKE_CURRENT_SOURCE_DIR}/CryptoAsn1.xasn
		${CMAKE_CURRENT_SOURCE_DIR}/pkix.xasn
		${CMAKE_CURRENT_SOURCE_DIR}/Asn1CkmHeader.xasn
		${CMAKE_CURRENT_SOURCE_DIR}/TokenPacket.xasn

	COMMAND
		echo Building ASN1 files
)
INCLUDE_DIRECTORIES(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}
    )

set(CryptoInterfaceSource
    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface/Hash.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface/XOF.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface/MAC_Handler.cpp

    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface/SymmetricWithModes.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface/SymmetricStream.cpp 
    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface/AEAD.cpp 

    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface/PbKdfImpl.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface/KDF.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface/KeyWrap.cpp

    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface/Prime_Probable.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface/Prime_Provable.cpp

    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface/DhParametersImpl.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface/DhKeyImpl.cpp
    
    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface/Key_Rsa.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface/Rsa_OAEP.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface/Sign_Rsa.cpp

    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface/Key_ECC.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface/Sign_Ecc.cpp

    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface/TunnelInitiator.cpp 
    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface/CkmAuthentication.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface/ServerAuthenticationCalculatorPbkdf.cpp

	# CryptoInterface/Hash_SHA3_XOF.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface/XTS.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface/KASImpl.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface/RSASVEImpl.cpp 
    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface/KTSOAEP.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface/KTSKEMKWS.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface/RSA_KEM_KWS.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface/RSAKAS1.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoInterface/RSAKAS2.cpp

)
set(algorithmSourceSSL
    ${CMAKE_CURRENT_SOURCE_DIR}/SSL/TLSClientHandshakeProtocol.cpp 
)

set(VEILCoreSource
    ${CMAKE_CURRENT_SOURCE_DIR}/pem.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/servicelocator.cpp

    ${CMAKE_CURRENT_SOURCE_DIR}/FipsState.cpp 
    ${CMAKE_CURRENT_SOURCE_DIR}/tsCryptoStringBase.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/tsCryptoString.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/tsCryptoData.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoLocator.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/RWLock.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoLocks.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoEvent.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/VEILCrypto.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoStringFuncs.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Endian.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/TlvDocument.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/TlvNode.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoAsn1.xasn
    ${CMAKE_CURRENT_SOURCE_DIR}/pkix.xasn
    ${CMAKE_CURRENT_SOURCE_DIR}/tsTlvSerializer.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/json.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/tsCryptoDate.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ConvertUTF.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/ConvertUTF.h
    ${CMAKE_CURRENT_SOURCE_DIR}/CryptoUtf16.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/tsDistinguishedName.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/xp_file.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/xp_filelist.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/xp_sharedLib.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/tsCertificateParser.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/tsCertificateBuilder.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/tsCertificateExtension.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/tsCertificateNamePart.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CertificateValidator.cpp

    ${CMAKE_CURRENT_SOURCE_DIR}/TcpMsgProcessor.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/VEILCore.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/HttpHeader.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/TcpConnection.h
    ${CMAKE_CURRENT_SOURCE_DIR}/TcpConnection.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/UdpConnection.h
    ${CMAKE_CURRENT_SOURCE_DIR}/UdpConnection.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/TcpChannel.h
    ${CMAKE_CURRENT_SOURCE_DIR}/TcpChannel.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/HttpChannel.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/JsonChannel.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/UrlParser.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CkmFileReader.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CkmFileWriter.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CkmMemoryFifoStream.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CkmMemoryStream.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CkmReadAppendFile.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CkmReadWriteFile.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/KeyVEILConnector.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Token.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/Favorite.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/xp_console.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/KeyVEILSession.cpp

    ${CMAKE_CURRENT_SOURCE_DIR}/CkmSymmetricAlgorithmImpl.h
    ${CMAKE_CURRENT_SOURCE_DIR}/tsAttributeMap.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CkmChangeMonitorImpl.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/CkmChangeMonitorImpl.h
    ${CMAKE_CURRENT_SOURCE_DIR}/tsThread.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/tsJsonPreferencesBase.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/BasicVEILPreferences.cpp

    ${CMAKE_CURRENT_SOURCE_DIR}/tsLog.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/tsTraceStream.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/tsDebug.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/tsDebugStream.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/PluginModuleManager.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/PluginModule.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/nargv.cpp

)
set(VEILCoreSource ${VEILCoreSource}

    ${CMAKE_CURRENT_SOURCE_DIR}/tsXmlHelper.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/tsXmlError.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/tsXmlNode.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/tsPreferencesBase.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/tsAppConfig.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/tsXmlParser.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/tsSignal.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/PropertyChangedEventArgs.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/NotifyPropertyChange.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/PropertyMap.cpp

    ${CMAKE_CURRENT_SOURCE_DIR}/Asn1CkmHeader.xasn
    ${CMAKE_CURRENT_SOURCE_DIR}/TokenPacket.xasn
	)
set(GEN_SOURCE_XASN 
    ${CMAKE_CURRENT_BINARY_DIR}/CryptoAsn1.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/PKIX.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/PKIX_Cert.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/PKIX_OCSP.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/Asn1CkmHeader.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/TokenPacket.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/CTSProfile.cpp
)
set(GEN_EXPORTS_XASN
	${PUBLIC_BINARY_TOP_DIR}/core/CryptoAsn1.export
	${PUBLIC_BINARY_TOP_DIR}/core/PKIX.export
	${PUBLIC_BINARY_TOP_DIR}/core/PKIX_Cert.export
	${PUBLIC_BINARY_TOP_DIR}/core/PKIX_OCSP.export
    ${PUBLIC_BINARY_TOP_DIR}/Asn1CkmHeader.export
    ${PUBLIC_BINARY_TOP_DIR}/TokenPacket.export
    ${PUBLIC_BINARY_TOP_DIR}/CTSProfile.export
    )
set(GEN_HEADERS_XASN
	${PUBLIC_BINARY_TOP_DIR}/core/CryptoAsn1.h
	${PUBLIC_BINARY_TOP_DIR}/core/PKIX.h
	${PUBLIC_BINARY_TOP_DIR}/core/PKIX_Cert.h
	${PUBLIC_BINARY_TOP_DIR}/core/PKIX_OCSP.h
	${PUBLIC_BINARY_TOP_DIR}/Asn1CkmHeader.h
	${PUBLIC_BINARY_TOP_DIR}/TokenPacket.h
	${PUBLIC_BINARY_TOP_DIR}/CTSProfile.h
    )
IF(UNIX)
	set(VEILCoreSource ${VEILCoreSource}
        ${CMAKE_CURRENT_SOURCE_DIR}/pevents.cpp
	)
ENDIF(UNIX)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/VEILCore.rc.in ${CMAKE_CURRENT_BINARY_DIR}/VEILCore.rc)

if(WIN32)
    set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/VEILCore.rc PROPERTIES COMPILE_DEFINITIONS RC_COMPILED)
endif(WIN32)

set(VEILCoreSource
    ${CMAKE_CURRENT_SOURCE_DIR}/include/targetver.h
    ${CMAKE_CURRENT_SOURCE_DIR}/resource.h
    ${VEILCoreSource}
	${OVHeaders}
	${VEILCoreHeaders}
	${GEN_HEADERS_XASN}
	${GEN_EXPORTS_XASN}
    ${GEN_SOURCE_XASN}
	${algorithmSourceSSL}
	${CryptoInterfaceSource}
    )
add_library(VEILCore SHARED
    ${CMAKE_CURRENT_BINARY_DIR}/VEILCore.rc
    ${CMAKE_CURRENT_SOURCE_DIR}/VEILCore.rc.in
    ${VEILCoreSource}
    ${CMAKE_CURRENT_SOURCE_DIR}/include/stdafx.h
    ${CMAKE_CURRENT_SOURCE_DIR}/stdafx.cpp
)
# add_dependencies(VEILCore VEILCoreCodeGen)
Source_Group(CryptoInterface FILES 	
    ${CMAKE_CURRENT_SOURCE_DIR}/ServerAuthenticationCalculatorPbkdf.cpp 
    ${CMAKE_CURRENT_SOURCE_DIR}/TunnelInitiator.cpp ${CMAKE_CURRENT_SOURCE_DIR}/TunnelResponder.cpp ${CMAKE_CURRENT_SOURCE_DIR}/TunnelEncryptor.cpp ${CMAKE_CURRENT_SOURCE_DIR}/TunnelDecryptor.cpp ${CMAKE_CURRENT_SOURCE_DIR}/CkmAuthentication.cpp
)
Source_Group(Generated FILES ${GEN_HEADERS_XASN} ${GEN_SOURCE_XASN} ${GEN_EXPORTS_XASN})
Source_Group(CryptoSupport\\SSL FILES
	${algorithmSourceSSL}
)
Source_Group(CryptoInterfaces FILES
	${CryptoInterfaceSource}
)

target_include_directories(VEILCore INTERFACE $<BUILD_INTERFACE:${PUBLIC_SOURCE_TOP_DIR}/include> $<INSTALL_INTERFACE:${TS_MODULE}/include>)
add_definitions("-DVEILCORE_EXPORTS")

if(APPLE)
    TARGET_LINK_LIBRARIES(VEILCore ${TSALG_TARGET} ${Security_LIBRARY} ${TSALG_TARGET} ${VEILCore_TARGET} ${ApplicationServices_LIBRARY})
else()
    TARGET_LINK_LIBRARIES(VEILCore TSALG TS_SUP_DLL)
endif(APPLE)
IF(MSVC AND DEFINED CMAKE_PDB_OUTPUT_DIRECTORY)
	set_target_properties(VEILCore PROPERTIES LINK_FLAGS "-PDBSTRIPPED:${CMAKE_PDB_OUTPUT_DIRECTORY}/VEILCore.pdb")
ENDIF(MSVC AND DEFINED CMAKE_PDB_OUTPUT_DIRECTORY)


if(ANDROID)
	TARGET_LINK_LIBRARIES(VEILCore z)
else(ANDROID)
	TARGET_LINK_LIBRARIES(VEILCore zlib)
endif(ANDROID)

# if(ANDROID)
	set_target_properties(VEILCore PROPERTIES COTIRE_ADD_UNITY_BUILD FALSE)
# endif()
if(WIN32)
	add_precompiled_header(VEILCore stdafx.h FORCEINCLUDE SOURCE_CXX stdafx.cpp)
else()
	# add_precompiled_header(VEILCore include/stdafx.h FORCEINCLUDE SOURCE_CXX stdafx.cpp)
endif(WIN32)
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

if(APPLE)
     set_target_properties(VEILCore PROPERTIES 
        FRAMEWORK TRUE
        FRAMEWORK_VERSION ${OSX_FRAMEWORK_VERSION}
        MACOSX_FRAMEWORK_IDENTIFIER com.tecsec.VEILCore
        MACOSX_FRAMEWORK_ICON_FILE CKM_Lock_Icon.icns
 #		MACOSX_FRAMEWORK_NAME
        MACOSX_FRAMEWORK_BUNDLE_VERSION ${VEIL_VERSION}
        MACOSX_FRAMEWORK_SHORT_VERSION_STRING ${VEIL_VERSION}
        # MACOSX_FRAMEWORK_INFO_PLIST Info.plist
        PUBLIC_HEADER VEIL.h
        # XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "iPhone Developer"
        )
else()
    install(TARGETS VEILCore ARCHIVE DESTINATION ${LIB_DIR} LIBRARY DESTINATION ${SHLIB_DIR} RUNTIME DESTINATION ${BIN_DIR} )
    install(FILES ${GEN_HEADERS_XASN} ${GEN_EXPORTS_XASN} DESTINATION ${INCLUDE_DIR}/core)
endif()

if(WIN32)
    add_subdirectory(static)
endif(WIN32)
