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
#  Written by Roger Butler

INCLUDE_DIRECTORIES(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}
    )


# source_group("Generated" FILES )

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/CmsHeader.rc.in ${CMAKE_CURRENT_BINARY_DIR}/CmsHeader.rc)

set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/CmsHeader.rc PROPERTIES COMPILE_DEFINITIONS RC_COMPILED)

set(VEILCmsHeaderSource
    ${CMAKE_CURRENT_SOURCE_DIR}/targetver.h
    ${CMAKE_CURRENT_SOURCE_DIR}/resource.h
	${CMAKE_CURRENT_SOURCE_DIR}/CmsHeaderAndGroupImpl.h
	${CMAKE_CURRENT_SOURCE_DIR}/CmsHeaderAttributeImpl.h
	${CMAKE_CURRENT_SOURCE_DIR}/CmsHeaderExtensionImpl.h
	${CMAKE_CURRENT_SOURCE_DIR}/CmsHeaderFiefdomImpl.h
	${CMAKE_CURRENT_SOURCE_DIR}/CmsHeaderImpl.h
    ${CMAKE_CURRENT_SOURCE_DIR}/CmsHeader.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/CmsHeaderAndGroupImpl.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/CmsHeaderAttributeImpl.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/CmsHeaderExtensionImpl.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/CmsHeaderFiefdomImpl.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/CmsHeaderImpl.cpp
	${OVCmsHeaders}
	)

add_library(VEILCmsHeader SHARED
    stdafx.h
    stdafx.cpp
    CmsHeader.rc.in
	${CMAKE_CURRENT_BINARY_DIR}/CmsHeader.rc
	${VEILCmsHeaderSource}
)

target_include_directories(VEILCmsHeader INTERFACE $<BUILD_INTERFACE:${PUBLIC_SOURCE_TOP_DIR}/include> $<INSTALL_INTERFACE:${TS_MODULE}/include>)

if(WIN32)
	# add_dependencies(VEILCmsHeader Configure.TSFrameworkVersion.h)
ENDIF(WIN32)
if(ANDROID)
	set_target_properties(VEILCmsHeader PROPERTIES COTIRE_ADD_UNITY_BUILD FALSE)
endif()
add_precompiled_header(VEILCmsHeader stdafx.h FORCEINCLUDE SOURCE_CXX stdafx.cpp)

TARGET_LINK_LIBRARIES(VEILCmsHeader VEILCore)
set_target_properties(VEILCmsHeader PROPERTIES FOLDER "Modules")
if(NOT ANDROID)
	set_target_properties(VEILCmsHeader PROPERTIES VERSION ${${VEILCORENAME_U}_VERSION} SOVERSION ${${VEILCORENAME_U}_SO_VERSION})
endif()
if(UNIX AND CMAKE_OBJCOPY)
	add_custom_command(TARGET VEILCmsHeader POST_BUILD 
		COMMAND ${CMAKE_OBJCOPY} --only-keep-debug $<TARGET_FILE:VEILCmsHeader> $<TARGET_FILE_DIR:VEILCmsHeader>/$<TARGET_FILE_NAME:VEILCmsHeader>.dbg 
		COMMAND ${CMAKE_OBJCOPY} --strip-debug $<TARGET_FILE:VEILCmsHeader>
		)
endif()


if(APPLE)
     set_target_properties(VEILCmsHeader PROPERTIES 
 		FRAMEWORK TRUE
 		FRAMEWORK_VERSION ${OSX_FRAMEWORK_VERSION}
 		MACOSX_FRAMEWORK_IDENTIFIER com.tecsec.VEILCmsHeader
 		MACOSX_FRAMEWORK_ICON_FILE CKM_Lock_Icon.icns
 #		MACOSX_FRAMEWORK_NAME
 		MACOSX_FRAMEWORK_BUNDLE_VERSION ${VEIL_VERSION}
 		MACOSX_FRAMEWORK_SHORT_VERSION_STRING ${VEIL_VERSION}
 		# MACOSX_FRAMEWORK_INFO_PLIST Info.plist
 		PUBLIC_HEADER VEILCmsHeader.h
 		# XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "iPhone Developer"
 		)
else()
	install(TARGETS VEILCmsHeader ARCHIVE DESTINATION ${LIB_DIR} LIBRARY DESTINATION ${SHLIB_DIR} RUNTIME DESTINATION ${BIN_DIR})
endif()


if(WIN32)
    add_subdirectory(static)
endif(WIN32)
