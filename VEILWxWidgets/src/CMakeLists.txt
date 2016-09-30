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

INCLUDE_DIRECTORIES(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}
    )

add_definitions(-DUNICODE -D_UNICODE)

if(WIN32)
	add_definitions(-D_CRT_SECURE_NO_WARNINGS=1)
endif(WIN32)

# source_group("Generated" FILES )
set(CppSources
    stdafx.cpp
	VEILWxWidgets.cpp
	About.cpp
	KeyVEILLogin.cpp
	AudienceSelector.cpp
	TokenLogin.cpp
	TokenSelector.cpp
	FavoriteName.cpp
	AttributeSelectorGrid.cpp
	GeneralSettingsHandler.cpp
	PropertySheet.cpp
	VEILFileSettingsPage.cpp
	# TSList.h
	# TSList.cpp
	# TSGrid.h
	# TSGrid.cpp
	# ProgressDlg.cpp
)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/VEILWxWidgets.rc.in ${CMAKE_CURRENT_BINARY_DIR}/VEILWxWidgets.rc)

set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/VEILWxWidgets.rc PROPERTIES COMPILE_DEFINITIONS RC_COMPILED)

CopyImportTargetBinariesToBuildFolder(WxWidgets ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${TS_VS_CONFIG})

add_library(VEILWxWidgets SHARED
    VEILWxWidgets.rc.in
	${CMAKE_CURRENT_BINARY_DIR}/VEILWxWidgets.rc
    targetver.h
    stdafx.h
	tecseclogo.xpm
	readwrit.xpm

    ${CppSources}
	${OVWxWinHeaders}

	${soFilesToCopy}
)

target_include_directories(VEILWxWidgets INTERFACE $<BUILD_INTERFACE:${PUBLIC_SOURCE_TOP_DIR}/include> $<INSTALL_INTERFACE:${TS_MODULE}/include>)

if(ANDROID)
	set_target_properties(VEILWxWidgets PROPERTIES COTIRE_ADD_UNITY_BUILD FALSE)
endif()
add_precompiled_header(VEILWxWidgets stdafx.h FORCEINCLUDE SOURCE_CXX stdafx.cpp)
TARGET_LINK_LIBRARIES(VEILWxWidgets VEILCore VEILCmsHeader ${wxWidgets_LIBRARIES})
IF(WIN32)
	TARGET_LINK_LIBRARIES(VEILWxWidgets Version.lib)
ENDIF(WIN32)
set_target_properties(VEILWxWidgets PROPERTIES 
	FOLDER "Modules" 
	VERSION ${${VEILCORENAME_U}_VERSION} 
	SOVERSION ${${VEILCORENAME_U}_SO_VERSION} 
	COMPILE_DEFINITIONS VEILWXWIDGETSDEF
	)
if(UNIX AND CMAKE_OBJCOPY)
	add_custom_command(TARGET VEILWxWidgets POST_BUILD 
		COMMAND ${CMAKE_OBJCOPY} --only-keep-debug $<TARGET_FILE:VEILWxWidgets> $<TARGET_FILE_DIR:VEILWxWidgets>/$<TARGET_FILE_NAME:VEILWxWidgets>.dbg 
		COMMAND ${CMAKE_OBJCOPY} --strip-debug $<TARGET_FILE:VEILWxWidgets>
		)
endif()

install(TARGETS VEILWxWidgets ARCHIVE DESTINATION ${LIB_DIR} LIBRARY DESTINATION ${SHLIB_DIR} RUNTIME DESTINATION ${BIN_DIR})
