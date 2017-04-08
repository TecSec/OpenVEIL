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

if(APPLE)
    add_definitions(-D_FILE_OFFSET_BITS=64 -DWXUSINGDLL -D__WXMAC__ -D__WXOSX__ -D__WXOSX_COCOA__)
elseif(WIN32)
    add_definitions(-DWXUSINGDLL)
	add_definitions(-D_UNICODE)
	add_definitions(-DUNICODE)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS=1 -D__WXMSW__)
else()
    add_definitions(-D_FILE_OFFSET_BITS=64 -DWXUSINGDLL)
endif(APPLE)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/TextVEIL.rc.in ${CMAKE_CURRENT_BINARY_DIR}/TextVEIL.rc @ONLY)

set(CppSources
    TextVEIL.cpp
    stdafx.cpp
	)
add_executable(TextVEIL WIN32
	targetver.h 
	stdafx.h 
	${CppSources} 
	${CMAKE_CURRENT_SOURCE_DIR}/TextVEIL.rc.in 
	${CMAKE_CURRENT_BINARY_DIR}/TextVEIL.rc 
	)
add_precompiled_header(TextVEIL stdafx.h FORCEINCLUDE SOURCE_CXX stdafx.cpp)

set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/TextVEIL.rc PROPERTIES COMPILE_DEFINITIONS RC_COMPILED)
set_target_properties(TextVEIL PROPERTIES FOLDER "Tools")
TARGET_LINK_LIBRARIES(TextVEIL 
	VEILCore
	VEILCmsHeader
	VEILFileSupport
	VEILWxWidgets
	)
if(UNIX)
    set_target_properties(TextVEIL PROPERTIES OUTPUT_NAME_DEBUG TextVEIL.debug)
endif(UNIX)

install(TARGETS TextVEIL RUNTIME DESTINATION ${BIN_DIR})
