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

#
# Determine the bitness of the machine
if (APPLE)
	EXECUTE_PROCESS(COMMAND sysctl -n hw.cpu64bit_capable RESULT_VARIABLE error_code OUTPUT_VARIABLE SYSCTL_OUTPUT)
	STRING(REGEX REPLACE "\n" "" OSX_64BIT "${SYSCTL_OUTPUT}")
	if (OSX_64BIT)
		MESSAGE(STATUS "Build universal binary - yes")
		SET(MACHINETYPE "universal")
	else()
		MESSAGE(STATUS "Build universal binary - no")
		SET(MACHINETYPE "i386")
	endif()
ELSEIF("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
	EXECUTE_PROCESS(COMMAND /bin/uname -m RESULT_VARIABLE error_code OUTPUT_VARIABLE UNAME_OUTPUT)
	IF (error_code)
		MESSAGE(FATAL_ERROR "Unable to determine machine archtecture")
	ENDIF(error_code)
	
	STRING(REGEX REPLACE "\n" "" MACHINETYPE "${UNAME_OUTPUT}")
	
	MESSAGE(STATUS "Machine Type: ${MACHINETYPE}")
	
	EXECUTE_PROCESS(COMMAND /usr/bin/lsb_release -s -i RESULT_VARIABLE error_code OUTPUT_VARIABLE LSB_OUTPUT)
	IF (NOT error_code)
		STRING(REGEX REPLACE "\n" "" LINUX_VENDOR "${LSB_OUTPUT}")
		EXECUTE_PROCESS(COMMAND /usr/bin/lsb_release -s -c RESULT_VARIABLE ec OUTPUT_VARIABLE LSB_CODENAME)
		IF (NOT ec)
			STRING(REGEX REPLACE "\n" "" LINUX_CODENAME "${LSB_OUTPUT}")
		ENDIF(NOT ec)
	ELSE()
		SET(LINUX_VENDOR "Unknown")
	ENDIF()
ELSEIF(WIN32)
	EXECUTE_PROCESS(COMMAND cl.exe RESULT_VARIABLE error_code OUTPUT_VARIABLE CL_OUTPUT ERROR_VARIABLE CL_ERR)
	
	STRING(REGEX MATCH ".*x64.*" WIN64 "${CL_ERR}")
	
	IF(WIN64 STREQUAL "")
		SET(MACHINETYPE "x86")
	ELSE()
		SET(MACHINETYPE "amd64")
	ENDIF()
ENDIF(APPLE)
