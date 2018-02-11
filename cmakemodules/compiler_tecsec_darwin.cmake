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

add_definitions(-DMAC)

# the following two lines are needed for spidermonkey
add_definitions(-DXP_UNIX)
#add_definitions(-DDARWIN)

## CMAKE_OSX_ARCHITECTURES is a built-in variable that lets you list
## the chips that you want to compile for.  If you list more than
## one value, you get a universal binary.  Each listed value will be
## converted into a '-arch v' argument to GCC.  This was useful when
## the choices when set to "i386;ppc", but not so much when set
## to "i386;x86_64".
##
## From what I can tell, when -arch is set we don't need -m32 or -m64.
## Warning: If you mix -m32, -m64 and one or more -arch arguments,
## you don't always get what you expect.  (Use /usr/bin/file on a
## generated .o or exe to confirm.)
##
if(OSX_64BIT)
	SET(CMAKE_OSX_ARCHITECTURES "x86_64")
else()
	SET(CMAKE_OSX_ARCHITECTURES "i386")	
endif()
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS}  -fvisibility=hidden -msse4.1 -maes -Wall -Wextra -Wdeclaration-after-statement -std=c11 -Wno-unused-parameter -fno-strict-aliasing")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1y -msse -msse4.1 -maes -fvisibility-ms-compat")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -D_DEBUG -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -D_RELEASE -DNDEBUG -O3")

## These are noise for now. Hide them from the basic display in the
## GUI tools.
mark_as_advanced(CMAKE_OSX_DEPLOYMENT_TARGET)
mark_as_advanced(CMAKE_OSX_SYSROOT)
mark_as_advanced(CMAKE_INSTALL_PREFIX)

