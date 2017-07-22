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

INCLUDE_DIRECTORIES(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    )

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
        ${CMAKE_CURRENT_BINARY_DIR}/CodeGenTemplates.cpp
        ${CMAKE_CURRENT_BINARY_DIR}/CodeGenTemplates.h
        ${PUBLIC_BINARY_TOP_DIR}/CodeGenTemplates.h
        ${PUBLIC_BINARY_TOP_DIR}/CodeGenTemplates.export

        ${CMAKE_CURRENT_BINARY_DIR}/TestCryptoAsn1.cpp
        ${CMAKE_CURRENT_BINARY_DIR}/TestCryptoAsn1.h
        ${PUBLIC_BINARY_TOP_DIR}/TestCryptoAsn1.h
        ${PUBLIC_BINARY_TOP_DIR}/TestCryptoAsn1.export

        ${CMAKE_CURRENT_BINARY_DIR}/TestAsn1CkmHeader.cpp
        ${CMAKE_CURRENT_BINARY_DIR}/TestAsn1CkmHeader.h
        ${PUBLIC_BINARY_TOP_DIR}/TestAsn1CkmHeader.h
        ${PUBLIC_BINARY_TOP_DIR}/TestAsn1CkmHeader.export
    DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/CodeGenTemplates.xasn
    COMMAND
        ${xmlCodeGen} -o=${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/CodeGenTemplates.xasn
    COMMAND
        ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/CodeGenTemplates.h ${PUBLIC_BINARY_TOP_DIR}/CodeGenTemplates.h
    COMMAND
        ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/CodeGenTemplates.export ${PUBLIC_BINARY_TOP_DIR}/CodeGenTemplates.export
    COMMAND
        ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/TestCryptoAsn1.h ${PUBLIC_BINARY_TOP_DIR}/TestCryptoAsn1.h
    COMMAND
        ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/TestCryptoAsn1.export ${PUBLIC_BINARY_TOP_DIR}/TestCryptoAsn1.export
    COMMAND
        ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/TestAsn1CkmHeader.h ${PUBLIC_BINARY_TOP_DIR}/TestAsn1CkmHeader.h
    COMMAND
        ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/TestAsn1CkmHeader.export ${PUBLIC_BINARY_TOP_DIR}/TestAsn1CkmHeader.export
    )

add_custom_command(
    OUTPUT
        ${CMAKE_CURRENT_BINARY_DIR}/Asn1ParserTest.inl
        ${CMAKE_CURRENT_BINARY_DIR}/Asn1ParserTest.h
        ${CMAKE_CURRENT_BINARY_DIR}/ParserTest2.inl
        ${CMAKE_CURRENT_BINARY_DIR}/ParserTest2.h
        ${PUBLIC_BINARY_TOP_DIR}/Asn1ParserTest.h
        ${PUBLIC_BINARY_TOP_DIR}/ParserTest2.h
    DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/Asn1ParserTest.xasn
    COMMAND
        ${xmlCodeGen} -o=${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/Asn1ParserTest.xasn
    COMMAND
        ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/Asn1ParserTest.h ${PUBLIC_BINARY_TOP_DIR}/Asn1ParserTest.h
    COMMAND
        ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/Asn1ParserTest.export ${PUBLIC_BINARY_TOP_DIR}/Asn1ParserTest.export
    COMMAND
        ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/ParserTest2.h ${PUBLIC_BINARY_TOP_DIR}/ParserTest2.h
    COMMAND
        ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/ParserTest2.export ${PUBLIC_BINARY_TOP_DIR}/ParserTest2.export
    )
add_custom_command(
    OUTPUT
        ${CMAKE_CURRENT_BINARY_DIR}/Asn1ParserTestImport.inl
        ${CMAKE_CURRENT_BINARY_DIR}/Asn1ParserTestImport.h
        ${PUBLIC_BINARY_TOP_DIR}/Asn1ParserTestImport.h
    DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/Asn1ParserTestImport.xasn
		${PUBLIC_BINARY_TOP_DIR}/Asn1ParserTest.h
    COMMAND
        ${xmlCodeGen} -o=${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/Asn1ParserTestImport.xasn
    COMMAND
        ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/Asn1ParserTestImport.h ${PUBLIC_BINARY_TOP_DIR}/Asn1ParserTestImport.h
    )

if(WIN32)
    CopyImportTargetBinariesToBuildFolder(TSALG ${EXTRA_FILE_OUTPUT})
    CopyImportTargetBinariesToBuildFolder(GTEST ${EXTRA_FILE_OUTPUT})
    CopyImportTargetBinariesToBuildFolder(GTEST_MAIN ${EXTRA_FILE_OUTPUT})
endif(WIN32)

add_executable(CryptoTests 
    targetver.h
    stdafx.h
    stdafx.cpp

	unittest1.cpp
	tsCryptoStringTests.cpp
    TlvSerializerTests.cpp
    OCSPTests.cpp
    TlvSerializerImportTests.cpp
    testBaseCurve25519.cpp
	
    ${CMAKE_CURRENT_BINARY_DIR}/CodeGenTemplates.cpp
    ${PUBLIC_BINARY_TOP_DIR}/CodeGenTemplates.h
    ${CMAKE_CURRENT_SOURCE_DIR}/CodeGenTemplates.xasn
    
    ${CMAKE_CURRENT_BINARY_DIR}/Asn1ParserTest.inl
    ${PUBLIC_BINARY_TOP_DIR}/Asn1ParserTest.h
    ${CMAKE_CURRENT_BINARY_DIR}/ParserTest2.inl
    ${PUBLIC_BINARY_TOP_DIR}/ParserTest2.h    
    ${CMAKE_CURRENT_SOURCE_DIR}/Asn1ParserTest.xasn
            
    ${CMAKE_CURRENT_BINARY_DIR}/Asn1ParserTestImport.inl
    ${PUBLIC_BINARY_TOP_DIR}/Asn1ParserTestImport.h
    ${CMAKE_CURRENT_SOURCE_DIR}/Asn1ParserTestImport.xasn

    ${CMAKE_CURRENT_BINARY_DIR}/TestCryptoAsn1.cpp
    ${PUBLIC_BINARY_TOP_DIR}/TestCryptoAsn1.h
    ${PUBLIC_BINARY_TOP_DIR}/TestCryptoAsn1.export

    ${CMAKE_CURRENT_BINARY_DIR}/TestAsn1CkmHeader.cpp
    ${PUBLIC_BINARY_TOP_DIR}/TestAsn1CkmHeader.h
    ${PUBLIC_BINARY_TOP_DIR}/TestAsn1CkmHeader.export

    ${soFilesToCopy}
    )

if(ANDROID)
	set_target_properties(CryptoTests PROPERTIES COTIRE_ADD_UNITY_BUILD FALSE)
endif()
add_precompiled_header(CryptoTests stdafx.h FORCEINCLUDE SOURCE_CXX stdafx.cpp)
# add_dependencies(CryptoTests Generate_KeyVEILData_Code )
set_target_properties(CryptoTests PROPERTIES FOLDER "UnitTests")
TARGET_LINK_LIBRARIES(CryptoTests
	VEILCore
    GTEST
    TS_SUP_DLL
	)

install(TARGETS CryptoTests ARCHIVE DESTINATION ${LIB_DIR} LIBRARY DESTINATION ${SHLIB_DIR} RUNTIME DESTINATION ${BIN_DIR})
