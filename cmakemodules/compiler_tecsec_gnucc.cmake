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


# TODO should we add -Wconversion to make this more like the MSFT compiler?
# TODO or -Wsign-conversion ?

# TODO would -Wunreachable-code make this more like the MSFT compiler?

# TODO how about -Wmissing-prototypes ??  this would make the compiler VERY
# TODO fussy, but it might catch some interesting problems

# TODO I would love to add 
# TODO -Wdisallowed-function-list=strcpy,sprintf,etc
# TODO but gcc on the Mac is at version 4.0 and this
# TODO option was added in some later version.

execute_process(COMMAND ${CMAKE_C_COMPILER} -dumpversion
                OUTPUT_VARIABLE GCC_VERSION)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden")
if(MACHINETYPE MATCHES "arm")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -marm -mlittle-endian -mfpu=neon")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -marm -DNEON -mlittle-endian")
    set(LINK_FLAGS "${LINK_FLAGS}")
elseif(TS_X_PLATFORM STREQUAL "x64")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m64 -msse4.1 -maes")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m64 -msse4.1 -maes")
    set(LINK_FLAGS "${LINK_FLAGS} -m64")
elseif(ANDROID)
elseif(TS_X_PLATFORM STREQUAL "x86")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32 -msse -msse4.1 -maes -march=i686")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32 -msse -msse4.1 -maes -march=i686")
    set(LINK_FLAGS "${LINK_FLAGS} -m32")
else()
  error(Missing processor type)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wdeclaration-after-statement -std=c11 -Wno-unused-parameter")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-invalid-offsetof")

# the apple_unicode code violates the strict-aliasing rules
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-strict-aliasing")

#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsigned-char")

# Add -Wunused when using gcc 4.6 so we get the same errors as when building
# with cdbs (Common Debian Build System)
if (GCC_VERSION VERSION_GREATER 4.6 OR GCC_VERSION VERSION_EQUAL 4.6)
	#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused -std=c++11")
	#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wunused -std=c++11 -fno-implicit-templates")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wunused -std=c++11")
else()
	#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunused -std=c++0x")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wunused -std=c++0x")
endif()

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -D_DEBUG -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -D_RELEASE -DNDEBUG -O3")
if(MINGW)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -D_DEBUG -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -D_RELEASE -DNDEBUG -O3")
else(MINGW)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -D_DEBUG -DDEBUG -fPIC")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -D_RELEASE -DNDEBUG -fPIC -O3")
endif(MINGW)

OPTION(SG_GCOV "Compile everything with -fprofile-arcs -ftest-coverage for gcov" OFF)

#if(SG_GCOV)
#    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
#    SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fprofile-arcs -ftest-coverage")
#endif()

OPTION(SG_GPROF "Compile everything with -pg for gprof" OFF)

#if(SG_GPROF)
#    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pg")
#    SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pg")
#endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${TS_CONFIG}}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${TS_CONFIG}}")
if(ANDROID)
	LINK_LIBRARIES(dl)
else(ANDROID)
	if(NOT MINGW)
		LINK_LIBRARIES(pthread dl)
	endif(NOT MINGW)
endif(ANDROID)

