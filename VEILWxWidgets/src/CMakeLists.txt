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

INCLUDE_DIRECTORIES(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}
    ${wxWidgets_INCLUDE_DIRS}
    )

set(wxFlags )
if(APPLE)
    set(wxFlags ${wxWidgets_DEFINITIONS})
elseif(WIN32)
    set(wxFlags "_UNICODE;UNICODE;_CRT_SECURE_NO_WARNINGS=1;__WXMSW__")
else()
	set(wxFlags ${wxWidgets_DEFINITIONS})
endif(APPLE)

# source_group("Generated" FILES )
set(CppSources
    ${CMAKE_CURRENT_SOURCE_DIR}/VEILWxWidgets.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/WxHelpRegistry.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/AttributeSelectorGridWrapper.h
    ${CMAKE_CURRENT_SOURCE_DIR}/AttributeSelectorGridWrapper.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/audienceselector2.h
    ${CMAKE_CURRENT_SOURCE_DIR}/audienceselector2.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/audienceselector2Wrapper.h
    ${CMAKE_CURRENT_SOURCE_DIR}/audienceselector2Wrapper.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/attributeselectorgrid.h
	${CMAKE_CURRENT_SOURCE_DIR}/AttributeSelectorGrid.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/groupeditorwizardpage.h
	${CMAKE_CURRENT_SOURCE_DIR}/groupeditorwizardpage.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/keyveilwizardpage.h
	${CMAKE_CURRENT_SOURCE_DIR}/keyveilwizardpage.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/saveselectionwizardpage.h
	${CMAKE_CURRENT_SOURCE_DIR}/saveselectionwizardpage.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/tokenselectionwizardpage.h
	${CMAKE_CURRENT_SOURCE_DIR}/tokenselectionwizardpage.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/favoriteselectionpage.h
	${CMAKE_CURRENT_SOURCE_DIR}/favoriteselectionpage.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/favoritemanagerdlg.h
    ${CMAKE_CURRENT_SOURCE_DIR}/favoritemanagerdlg.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/FavoriteManagerWrapper.h
	${CMAKE_CURRENT_SOURCE_DIR}/FavoriteManagerWrapper.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/tokenlogindlg.h
	${CMAKE_CURRENT_SOURCE_DIR}/tokenlogindlg.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/TokenLogin.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/keyveillogindlg.h
	${CMAKE_CURRENT_SOURCE_DIR}/keyveillogindlg.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/KeyVEILLogin.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/favoritenamedlg.h
	${CMAKE_CURRENT_SOURCE_DIR}/favoritenamedlg.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/FavoriteName.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/tokenselectordlg.h
	${CMAKE_CURRENT_SOURCE_DIR}/tokenselectordlg.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/TokenSelector.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/aboutckm.h
	${CMAKE_CURRENT_SOURCE_DIR}/aboutckm.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/About.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/audienceselectordlg.h
	${CMAKE_CURRENT_SOURCE_DIR}/audienceselectordlg.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/AudienceSelector.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/propertysheetdlg.h
	${CMAKE_CURRENT_SOURCE_DIR}/propertysheetdlg.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/GeneralSettingsHandler.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/PropertySheet.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/VEILFileSettingsPage.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/ProgressDlgWrapper.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/progressdlg.h
	${CMAKE_CURRENT_SOURCE_DIR}/ProgressDlg.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/EnterPinDlgWrapper.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/enterpindlg.h
	${CMAKE_CURRENT_SOURCE_DIR}/enterpindlg.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/targetver.h
    ${CMAKE_CURRENT_SOURCE_DIR}/tecseclogo.xpm
    ${CMAKE_CURRENT_SOURCE_DIR}/readwrit.xpm
	${CMAKE_CURRENT_SOURCE_DIR}/ChangeNameDlgWrapper.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/changenamedlg.h
	${CMAKE_CURRENT_SOURCE_DIR}/changenamedlg.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/veilfilepropertypage.h
	${CMAKE_CURRENT_SOURCE_DIR}/veilfilepropertypage.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/generalsettingspropertypage.h
	${CMAKE_CURRENT_SOURCE_DIR}/generalsettingspropertypage.cpp
)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/VEILWxWidgets.rc.in ${CMAKE_CURRENT_BINARY_DIR}/VEILWxWidgets.rc)

set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/VEILWxWidgets.rc PROPERTIES COMPILE_DEFINITIONS RC_COMPILED)

CopyImportTargetBinariesToBuildFolder(WxWidgets ${EXTRA_FILE_OUTPUT})

add_library(VEILWxWidgets SHARED
    VEILWxWidgets.rc.in
    ${CMAKE_CURRENT_BINARY_DIR}/VEILWxWidgets.rc
    stdafx.cpp
    stdafx.h

    ${CppSources}
    ${OVWxWinHeaders}

    ${soFilesToCopy}
)
set_target_properties(VEILWxWidgets PROPERTIES COMPILE_DEFINITIONS "${wxFlags};WXUSINGDLL;VEILWXWIDGETSDEF")

Source_Group(AudienceSelector2 FILES 	
    audienceselector2.h
    audienceselector2.cpp
    audienceselector2Wrapper.h
    audienceselector2Wrapper.cpp
	groupeditorwizardpage.h
	groupeditorwizardpage.cpp
	keyveilwizardpage.h
	keyveilwizardpage.cpp
	saveselectionwizardpage.h
	saveselectionwizardpage.cpp
	tokenselectionwizardpage.h
	tokenselectionwizardpage.cpp
	favoriteselectionpage.h
	favoriteselectionpage.cpp
)
Source_Group(FavoriteManager FILES 	
    favoritemanagerdlg.h
    favoritemanagerdlg.cpp
	FavoriteManagerWrapper.h
	FavoriteManagerWrapper.cpp
)
Source_Group(TokenLogin FILES 	
	tokenlogindlg.h
	tokenlogindlg.cpp
    TokenLogin.cpp
)
Source_Group(KeyVEILLogin FILES 	
	keyveillogindlg.h
	keyveillogindlg.cpp
    KeyVEILLogin.cpp
)
Source_Group(FavoriteName FILES 	
	favoritenamedlg.h
	favoritenamedlg.cpp
	FavoriteName.cpp
)
Source_Group(TokenSelector FILES 	
	tokenselectordlg.h
	tokenselectordlg.cpp
	TokenSelector.cpp
)
Source_Group(AboutCkm FILES 	
	aboutckm.h
	aboutckm.cpp
    About.cpp
)
Source_Group(AudienceSelector FILES 	
	audienceselectordlg.h
	audienceselectordlg.cpp
    AudienceSelector.cpp
)
Source_Group(PropertySheets FILES 	
	propertysheetdlg.h
	propertysheetdlg.cpp
    GeneralSettingsHandler.cpp
    PropertySheet.cpp
    VEILFileSettingsPage.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/veilfilepropertypage.h
	${CMAKE_CURRENT_SOURCE_DIR}/veilfilepropertypage.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/generalsettingspropertypage.h
	${CMAKE_CURRENT_SOURCE_DIR}/generalsettingspropertypage.cpp
)
Source_Group(ProgressDialog FILES 	
	ProgressDlgWrapper.cpp
	progressdlg.h
	progressdlg.cpp
)
Source_Group(EnterPin FILES 	
	EnterPinDlgWrapper.cpp
	enterpindlg.h
	enterpindlg.cpp
)
Source_Group(ChangeName FILES 	
	${CMAKE_CURRENT_SOURCE_DIR}/ChangeNameDlgWrapper.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/changenamedlg.h
	${CMAKE_CURRENT_SOURCE_DIR}/changenamedlg.cpp
)

target_include_directories(VEILWxWidgets INTERFACE $<BUILD_INTERFACE:${PUBLIC_SOURCE_TOP_DIR}/include> $<INSTALL_INTERFACE:${TS_MODULE}/include>)

if(ANDROID)
    set_target_properties(VEILWxWidgets PROPERTIES COTIRE_ADD_UNITY_BUILD FALSE)
endif()
add_precompiled_header(VEILWxWidgets stdafx.h FORCEINCLUDE SOURCE_CXX stdafx.cpp)
if(WIN32)
	TARGET_LINK_LIBRARIES(VEILWxWidgets VEILCore CyberVEIL VEILCmsHeader ${WxWidgets_Targets})
elseif(APPLE)
	TARGET_LINK_LIBRARIES(VEILWxWidgets VEILCore ${CyberVEIL_TARGET} VEILCmsHeader ${wxWidgets_LIBRARIES})
else()
	TARGET_LINK_LIBRARIES(VEILWxWidgets VEILCore CyberVEIL VEILCmsHeader ${wxWidgets_LIBRARIES})
endif()
IF(WIN32)
    TARGET_LINK_LIBRARIES(VEILWxWidgets Version.lib)
ENDIF(WIN32)
set_target_properties(VEILWxWidgets PROPERTIES 
    FOLDER "Modules" 
    VERSION ${${VEILCORENAME_U}_VERSION} 
    SOVERSION ${${VEILCORENAME_U}_SO_VERSION} 
    )
if(UNIX AND CMAKE_OBJCOPY)
    add_custom_command(TARGET VEILWxWidgets POST_BUILD 
        COMMAND ${CMAKE_OBJCOPY} --only-keep-debug $<TARGET_FILE:VEILWxWidgets> $<TARGET_FILE_DIR:VEILWxWidgets>/$<TARGET_FILE_NAME:VEILWxWidgets>.dbg 
        COMMAND ${CMAKE_OBJCOPY} --strip-debug $<TARGET_FILE:VEILWxWidgets>
        )
endif()

if(APPLE)
     set_target_properties(VEILWxWidgets PROPERTIES 
        FRAMEWORK TRUE
        FRAMEWORK_VERSION ${OSX_FRAMEWORK_VERSION}
        MACOSX_FRAMEWORK_IDENTIFIER com.tecsec.VEILWxWidgets
        MACOSX_FRAMEWORK_ICON_FILE CKM_Lock_Icon.icns
 #		MACOSX_FRAMEWORK_NAME
        MACOSX_FRAMEWORK_BUNDLE_VERSION ${VEIL_VERSION}
        MACOSX_FRAMEWORK_SHORT_VERSION_STRING ${VEIL_VERSION}
        # MACOSX_FRAMEWORK_INFO_PLIST Info.plist
        PUBLIC_HEADER VEILwxWidgets.h
        # XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "iPhone Developer"
        )
else()
    install(TARGETS VEILWxWidgets ARCHIVE DESTINATION ${LIB_DIR} LIBRARY DESTINATION ${SHLIB_DIR} RUNTIME DESTINATION ${BIN_DIR})
endif()



if(WIN32)
	add_subdirectory(static)
endif(WIN32)