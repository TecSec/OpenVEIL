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
	${CMAKE_CURRENT_SOURCE_DIR}/../../
    )

set(CMAKE_DEBUG_POSTFIX "")

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/smartcard.rc.in ${CMAKE_CURRENT_BINARY_DIR}/smartcard.rc @ONLY)

add_library(smartcard SHARED 
    targetver.h 
    stdafx.h 
	stdafx.cpp
    smartcard.cpp
	ChangeActPassword.cpp
	SmartCardInfoTool.cpp
	ListAidTool.cpp
	AddAidTool.cpp
	RemoveAidTool.cpp
	SmartCardMonitorTool.cpp
    
    smartcard.rc.in
	${CMAKE_CURRENT_BINARY_DIR}/smartcard.rc
    )
add_precompiled_header(smartcard stdafx.h FORCEINCLUDE SOURCE_CXX stdafx.cpp)
set_source_files_properties(smartcard.rc PROPERTIES COMPILE_DEFINITIONS RC_COMPILED)
set_target_properties(smartcard PROPERTIES FOLDER "Tools/veilExtensions")
TARGET_LINK_LIBRARIES(smartcard VEILCore VEILSmartCard)
set_target_properties(smartcard PROPERTIES 
	SUFFIX ".veil"  
	)
if(NOT MSVC)
	set_target_properties(smartcard PROPERTIES PREFIX "")
endif(NOT MSVC)

install(TARGETS smartcard LIBRARY DESTINATION ${SHLIB_DIR} RUNTIME DESTINATION ${BIN_DIR})
