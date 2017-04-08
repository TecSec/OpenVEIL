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
    )


CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/VEILFileSupport.rc.in ${CMAKE_CURRENT_BINARY_DIR}/VEILFileSupport.rc)

set(CppSources
    ${CMAKE_CURRENT_SOURCE_DIR}/FilePrimitives.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/FileVEILFileList.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/VEILFileSupportFactory.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/VEILFileSupport.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/FileOperations.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/CryptoHelperImpl.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/EncryptProcessor.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/Compressor.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/targetver.h
    ${CMAKE_CURRENT_SOURCE_DIR}/FileVEILFileList.h
    ${CMAKE_CURRENT_SOURCE_DIR}/VEILFileSupportFactory.h
    ${CMAKE_CURRENT_SOURCE_DIR}/FileOperations.h
    ${CMAKE_CURRENT_SOURCE_DIR}/resource.h
    )

add_library(VEILFileSupport SHARED
    stdafx.h
    stdafx.cpp

    ${CppSources}
    VEILFileSupport.rc.in
	${CMAKE_CURRENT_BINARY_DIR}/VEILFileSupport.rc
    VEILFileSupport.def
    )
if(ANDROID)
	set_target_properties(VEILFileSupport PROPERTIES COTIRE_ADD_UNITY_BUILD FALSE)
endif()
add_precompiled_header(VEILFileSupport stdafx.h FORCEINCLUDE SOURCE_CXX stdafx.cpp)

set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/VEILFileSupport.rc PROPERTIES COMPILE_DEFINITIONS RC_COMPILED)
set_target_properties(VEILFileSupport PROPERTIES FOLDER "Modules")
if(NOT ANDROID)
	set_target_properties(VEILFileSupport PROPERTIES VERSION ${${VEILCORENAME_U}_VERSION} SOVERSION ${${VEILCORENAME_U}_SO_VERSION})
endif()
if(ANDROID)
	TARGET_LINK_LIBRARIES(VEILFileSupport 
		VEILCore 
		VEILCmsHeader 
		z 
		bz2Static
		)
else()
	target_link_libraries(VEILFileSupport
		VEILCore
		VEILCmsHeader
		zlib
		bz2Static
		)
endif()

if(WIN32)
    target_link_libraries(VEILFileSupport
        urlmon
        )
endif()
if(UNIX AND CMAKE_OBJCOPY)
	add_custom_command(TARGET VEILFileSupport POST_BUILD 
		COMMAND ${CMAKE_OBJCOPY} --only-keep-debug $<TARGET_FILE:VEILFileSupport> $<TARGET_FILE_DIR:VEILFileSupport>/$<TARGET_FILE_NAME:VEILFileSupport>.dbg 
		COMMAND ${CMAKE_OBJCOPY} --strip-debug $<TARGET_FILE:VEILFileSupport>
		)
endif()

if(APPLE)
     set_target_properties(VEILFileSupport PROPERTIES 
 		FRAMEWORK TRUE
 		FRAMEWORK_VERSION ${OSX_FRAMEWORK_VERSION}
 		MACOSX_FRAMEWORK_IDENTIFIER com.tecsec.VEILFileSupport
 		MACOSX_FRAMEWORK_ICON_FILE CKM_Lock_Icon.icns
 #		MACOSX_FRAMEWORK_NAME
 		MACOSX_FRAMEWORK_BUNDLE_VERSION ${VEIL_VERSION}
 		MACOSX_FRAMEWORK_SHORT_VERSION_STRING ${VEIL_VERSION}
 		# MACOSX_FRAMEWORK_INFO_PLIST Info.plist
 		PUBLIC_HEADER VEILFileSupport.h
 		# XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "iPhone Developer"
 		)
else()
    install(TARGETS VEILFileSupport ARCHIVE DESTINATION ${LIB_DIR} LIBRARY DESTINATION ${SHLIB_DIR} RUNTIME DESTINATION ${BIN_DIR})
endif()



if(WIN32)
    add_subdirectory(static)
endif(WIN32)
