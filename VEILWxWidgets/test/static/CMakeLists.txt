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

if(MSVC)
	set(CMAKE_C_FLAGS_DEBUG         "${CMAKE_C_FLAGS_DEBUGSTATIC}")
	set(CMAKE_C_FLAGS_RELEASE       "${CMAKE_C_FLAGS_RELEASESTATIC}")
	set(CMAKE_CXX_FLAGS_DEBUG       "${CMAKE_CXX_FLAGS_DEBUGSTATIC}")
	set(CMAKE_CXX_FLAGS_RELEASE     "${CMAKE_CXX_FLAGS_RELEASESTATIC}")
endif(MSVC)

#set(BUILD_SHARED_LIBS OFF)
#set(wxWidgets_EXCLUDE_COMMON_LIBRARIES ON)
#find_package(wxWidgets COMPONENTS core base adv html )

add_executable(VEILwxWinApiSample_s WIN32
	stdafx.h
	stdafx.cpp
	${VEILwxWinApiSampleSource}
)
if(ANDROID)
	set_target_properties(VEILwxWinApiSample_s PROPERTIES COTIRE_ADD_UNITY_BUILD FALSE)
endif()
add_precompiled_header(VEILwxWinApiSample_s stdafx.h FORCEINCLUDE SOURCE_CXX stdafx.cpp)
TARGET_LINK_LIBRARIES(VEILwxWinApiSample_s VEILCore_s VEILWxWidgets_s TSALG_s VEILCmsHeader_s)
if(WIN32)
	TARGET_LINK_LIBRARIES(VEILwxWinApiSample_s ws2_32 Comctl32 Rpcrt4)
else()
endif()
if (${CMAKE_BUILD_TYPE} STREQUAL "Debug")
	if (${TS_X_PLATFORM} STREQUAL "x64")
		TARGET_LINK_LIBRARIES(VEILwxWinApiSample_s ${wxWidgets_ROOT_DIR}/lib/${TS_TOOLSET}0_x64_lib/wxzlibd.lib ${wxWidgets_ROOT_DIR}/lib/${TS_TOOLSET}0_x64_lib/wxbase31ud.lib ${wxWidgets_ROOT_DIR}/lib/${TS_TOOLSET}0_x64_lib/wxmsw31ud_core.lib ${wxWidgets_ROOT_DIR}/lib/${TS_TOOLSET}0_x64_lib/wxmsw31ud_adv.lib ${wxWidgets_ROOT_DIR}/lib/${TS_TOOLSET}0_x64_lib/wxmsw31ud_html.lib ${wxWidgets_ROOT_DIR}/lib/${TS_TOOLSET}0_x64_lib/wxpngd.lib ${wxWidgets_ROOT_DIR}/lib/${TS_TOOLSET}0_x64_lib/wxjpegd.lib )
	else()
		TARGET_LINK_LIBRARIES(VEILwxWinApiSample_s ${wxWidgets_ROOT_DIR}/lib/${TS_TOOLSET}0_lib/wxzlibd.lib ${wxWidgets_ROOT_DIR}/lib/${TS_TOOLSET}0_lib/wxbase31ud.lib ${wxWidgets_ROOT_DIR}/lib/${TS_TOOLSET}0_lib/wxmsw31ud_core.lib ${wxWidgets_ROOT_DIR}/lib/${TS_TOOLSET}0_lib/wxmsw31ud_adv.lib ${wxWidgets_ROOT_DIR}/lib/${TS_TOOLSET}0_lib/wxmsw31ud_html.lib ${wxWidgets_ROOT_DIR}/lib/${TS_TOOLSET}0_lib/wxpngd.lib ${wxWidgets_ROOT_DIR}/lib/${TS_TOOLSET}0_lib/wxjpegd.lib)
	endif()
else()
	if (${TS_X_PLATFORM} STREQUAL "x64")
		TARGET_LINK_LIBRARIES(VEILwxWinApiSample_s ${wxWidgets_ROOT_DIR}/lib/${TS_TOOLSET}0_x64_lib/wxzlib.lib ${wxWidgets_ROOT_DIR}/lib/${TS_TOOLSET}0_x64_lib/wxbase31u.lib ${wxWidgets_ROOT_DIR}/lib/${TS_TOOLSET}0_x64_lib/wxmsw31u_core.lib ${wxWidgets_ROOT_DIR}/lib/${TS_TOOLSET}0_x64_lib/wxmsw31u_adv.lib ${wxWidgets_ROOT_DIR}/lib/${TS_TOOLSET}0_x64_lib/wxmsw31u_html.lib ${wxWidgets_ROOT_DIR}/lib/${TS_TOOLSET}0_x64_lib/wxpng.lib ${wxWidgets_ROOT_DIR}/lib/${TS_TOOLSET}0_x64_lib/wxjpeg.lib )
	else()
		TARGET_LINK_LIBRARIES(VEILwxWinApiSample_s ${wxWidgets_ROOT_DIR}/lib/${TS_TOOLSET}0_lib/wxzlib.lib ${wxWidgets_ROOT_DIR}/lib/${TS_TOOLSET}0_lib/wxbase31u.lib ${wxWidgets_ROOT_DIR}/lib/${TS_TOOLSET}0_lib/wxmsw31u_core.lib ${wxWidgets_ROOT_DIR}/lib/${TS_TOOLSET}0_lib/wxmsw31u_adv.lib ${wxWidgets_ROOT_DIR}/lib/${TS_TOOLSET}0_lib/wxmsw31u_html.lib ${wxWidgets_ROOT_DIR}/lib/${TS_TOOLSET}0_lib/wxpng.lib ${wxWidgets_ROOT_DIR}/lib/${TS_TOOLSET}0_lib/wxjpeg.lib)
	endif()
endif()
set_target_properties(VEILwxWinApiSample_s PROPERTIES FOLDER "Modules/Static" VERSION ${VEIL_VERSION} SOVERSION ${VEIL_SO_VERSION} COMPILE_DEFINITIONS OPAQUEVEILWXWIDGETSDEF)
set_target_properties(VEILwxWinApiSample_s PROPERTIES COMPILE_DEFINITIONS "VEILCORE_STATIC;VEILWXWIDGETS_STATIC;_STATIC_TSALG;VEILCMSHEADER_STATIC;VEILFILESUPPORT_STATIC")

install(TARGETS VEILwxWinApiSample_s ARCHIVE DESTINATION ${LIB_DIR} LIBRARY DESTINATION ${SHLIB_DIR} RUNTIME DESTINATION ${BIN_DIR})
