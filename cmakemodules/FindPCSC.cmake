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

include(FindPkgConfig)

function (get_soname SONAME OBJFILE)
  find_program(CMAKE_OBJDUMP names objdump DOC "The objdump program")
  execute_process(
	COMMAND objdump -p "${OBJFILE}"
   	COMMAND sed -n -es/^[[:space:]]*SONAME[[:space:]]*//p
	RESULT_VARIABLE STATUS
	OUTPUT_VARIABLE SONAME_OUT
	ERROR_QUIET
  )
  STRING(REPLACE "\n" "" SONAME_OUT "${SONAME_OUT}")
#  get_filename_component(_tmp ${OBJFILE} DIRECTORY)
  if (STATUS EQUAL 0)
    set(${SONAME} "${SONAME_OUT}" PARENT_SCOPE)
  else()
    set(${SONAME} "" PARENT_SCOPE)
  endif()
endfunction()


if (PKG_CONFIG_FOUND)
	pkg_check_modules(PCSC libpcsclite)
else()
	set(PCSC_INCLUDE_DIRS ${PCSC_INCLUDE_DIRS} /usr/local/include /usr/include)
	set(PCSC_LIBRARY_DIRS ${PCSC_LIBRARY_DIRS} /usr/local/lib /usr/lib)
endif()

find_path(PCSC_INCLUDE_DIR pcsclite.h winscard.h PATHS ${PCSC_INCLUDE_DIRS} PATH_SUFFIXES PCSC)

if(APPLE)
    FIND_PACKAGE_HANDLE_STANDARD_ARGS(PCSC DEFAULT_MSG PCSC_INCLUDE_DIR)
		set(PCSC_FLAGS "-framework PCSC")
else()
    find_library(PCSC_LIBRARY pcsclite PATHS ${PCSC_LIBRARY_DIRS})

    FIND_PACKAGE_HANDLE_STANDARD_ARGS(PCSC DEFAULT_MSG PCSC_INCLUDE_DIR PCSC_LIBRARY)
endif()

mark_as_advanced(PCSC_INCLUDE_DIR PCSC_LIBRARY PCSC_FLAGS)

if(PCSC_FOUND AND NOT APPLE)
    if(NOT TARGET pcsc)
	if(UNIX)
		get_soname(PCSC_SO_NAME ${PCSC_LIBRARY})
		find_library(PCSC_LIBRARY_SO ${PCSC_SO_NAME} PATHS ${PCSC_LIBRARY_DIRS})
		add_library(pcsc SHARED IMPORTED)
		set_target_properties(pcsc PROPERTIES
			IMPORTED_LOCATION "${PCSC_LIBRARY}"
			INTERFACE_INCLUDE_DIRECTORIES "${PCSC_INCLUDE_DIR}"
			IMPORTED_SONAME "${PCSC_SO_NAME}"
			DLOPEN_SONAME "${PCSC_SO_NAME}"
		)
	endif(UNIX)
    endif()
endif(PCSC_FOUND AND NOT APPLE)
