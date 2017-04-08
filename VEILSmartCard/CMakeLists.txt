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
	FIND_LIBRARY(PCSC_LIBRARY PCSC)
	MARK_AS_ADVANCED(PCSC_LIBRARY)
	message(STATUS "PCSC at ${PCSC_LIBRARY}")
endif(APPLE)

INCLUDE_DIRECTORIES(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}
    )


# source_group("Generated" FILES )
set(CkmSmartCardCppSources
    ${CMAKE_CURRENT_SOURCE_DIR}/CkmSmartCard.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/tsWinscardSupport.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/CkmWinscardEventImpl.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/SmartCardConnection.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/SmartCardInformation.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/SmartCardLink.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/CkmWinscardMonitorImpl.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/CkmWinscardReaderImpl.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/CkmWinscardConnectionImpl.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/CkmWinscardContextImpl.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/targetver.h
	${CMAKE_CURRENT_SOURCE_DIR}/tsWinscardSupport.h
	${CMAKE_CURRENT_SOURCE_DIR}/CkmWinscardEventImpl.h
	${CMAKE_CURRENT_SOURCE_DIR}/CkmWinscardMonitorImpl.h
	${CMAKE_CURRENT_SOURCE_DIR}/CkmWinscardReaderImpl.h
	${CMAKE_CURRENT_SOURCE_DIR}/CkmWinscardConnectionImpl.h
	${CMAKE_CURRENT_SOURCE_DIR}/CkmWinscardContextImpl.h
    ${CMAKE_CURRENT_SOURCE_DIR}/resource.h
)

set_source_files_properties(${CMAKE_CURRENT_SOURCE_DIR}/CkmSmartCard.rc PROPERTIES COMPILE_DEFINITIONS RC_COMPILED)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/CkmSmartCard.rc.in ${CMAKE_CURRENT_BINARY_DIR}/CkmSmartCard.rc)

set(VEILSmartCardSource
    ${CkmSmartCardCppSources}
	${VEILSmartCardHeaders}
	)

add_library(VEILSmartCard SHARED
    stdafx.h
    stdafx.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/CkmSmartCard.rc
    CkmSmartCard.rc.in
	${VEILSmartCardSource}
)

target_include_directories(VEILSmartCard INTERFACE $<BUILD_INTERFACE:${PUBLIC_SOURCE_TOP_DIR}/include> $<INSTALL_INTERFACE:${TS_MODULE}/include>)

if(WIN32)
	# add_dependencies(VEILSmartCard Configure.TSFrameworkVersion.h)
ENDIF(WIN32)
#if(APPLE)
#    set_target_properties(VEILSmartCard PROPERTIES COMPILE_FLAGS ${PCSC_FLAGS})
#endif(APPLE)
if(ANDROID)
	set_target_properties(VEILSmartCard PROPERTIES COTIRE_ADD_UNITY_BUILD FALSE)
endif()
add_precompiled_header(VEILSmartCard stdafx.h FORCEINCLUDE SOURCE_CXX stdafx.cpp)
TARGET_LINK_LIBRARIES(VEILSmartCard VEILCore)
if(WIN32)
	TARGET_LINK_LIBRARIES(VEILSmartCard winscard)
elseif(APPLE)
	TARGET_LINK_LIBRARIES(VEILSmartCard ${PCSC_LIBRARY})
else()
	TARGET_LINK_LIBRARIES(VEILSmartCard pcsc)
endif(WIN32)
set_target_properties(VEILSmartCard PROPERTIES FOLDER "Modules" VERSION ${${VEILCORENAME_U}_VERSION} SOVERSION ${${VEILCORENAME_U}_SO_VERSION})
if(UNIX AND CMAKE_OBJCOPY)
	add_custom_command(TARGET VEILSmartCard POST_BUILD 
		COMMAND ${CMAKE_OBJCOPY} --only-keep-debug $<TARGET_FILE:VEILSmartCard> $<TARGET_FILE_DIR:VEILSmartCard>/$<TARGET_FILE_NAME:VEILSmartCard>.dbg 
		COMMAND ${CMAKE_OBJCOPY} --strip-debug $<TARGET_FILE:VEILSmartCard>
		)
endif()
set_target_properties(VEILSmartCard PROPERTIES OUTPUT_NAME ${VEILCORENAME}SmartCard)

if(APPLE)
     set_target_properties(VEILSmartCard PROPERTIES 
 		FRAMEWORK TRUE
 		FRAMEWORK_VERSION ${OSX_FRAMEWORK_VERSION}
 		MACOSX_FRAMEWORK_IDENTIFIER com.tecsec.VEILSmartCard
 		MACOSX_FRAMEWORK_ICON_FILE CKM_Lock_Icon.icns
 #		MACOSX_FRAMEWORK_NAME
 		MACOSX_FRAMEWORK_BUNDLE_VERSION ${VEIL_VERSION}
 		MACOSX_FRAMEWORK_SHORT_VERSION_STRING ${VEIL_VERSION}
 		# MACOSX_FRAMEWORK_INFO_PLIST Info.plist
 		PUBLIC_HEADER VEILSmartCard.h
 		# XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "iPhone Developer"
 		)
else()
	install(TARGETS VEILSmartCard ARCHIVE DESTINATION ${LIB_DIR} LIBRARY DESTINATION ${SHLIB_DIR} RUNTIME DESTINATION ${BIN_DIR})
endif()


if(WIN32)
    add_subdirectory(static)
endif(WIN32)
