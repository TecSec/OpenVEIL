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


Find_Path(WIX_ROOT_DIR 
	NAMES
		bin/candle.exe
		bin/light.exe
	PATHS
		"${WIX_ROOT_DIR}"
		"$ENV{WIX}"
		"$ENV{WIX_ROOT_DIR}"
		"$ENV{ProgramFiles}/WiX Installer XML"
)

set(WIX_FOUND OFF)
if(WIX_ROOT_DIR)
	set(WIX_FOUND ON)
endif(WIX_ROOT_DIR)

if(NOT WIX_FOUND)
	if(NOT WIX_OPTIONAL)
		message(FATAL_ERROR "WiX is required and was not found.")
	else()
		message(STATUS "WiX NOT found")
	endif(NOT WIX_OPTIONAL)
else()
	if(NOT TARGET Wix_Candle AND EXISTS ${WIX_ROOT_DIR}/bin/candle.exe)
		add_executable(Wix_Candle IMPORTED)
		set_target_properties(Wix_Candle PROPERTIES
			IMPORTED_LOCATION "${WIX_ROOT_DIR}/bin/candle.exe"
		)
	endif(NOT TARGET Wix_Candle AND EXISTS ${WIX_ROOT_DIR}/bin/candle.exe)

	if(NOT TARGET Wix_Light AND EXISTS ${WIX_ROOT_DIR}/bin/light.exe)
		add_executable(Wix_Light IMPORTED)
		set_target_properties(Wix_Light PROPERTIES
			IMPORTED_LOCATION "${WIX_ROOT_DIR}/bin/light.exe"
		)
	endif(NOT TARGET Wix_Light AND EXISTS ${WIX_ROOT_DIR}/bin/light.exe)
	set(WIX_INCLUDE_DIRS "${WIX_ROOT_DIR}/bin")
endif(NOT WIX_FOUND)

MARK_AS_ADVANCED(WIX_ROOT_DIR)

# macro(Wix_Compile _sourceFiles _objFiles _extraDependencies)
# 	foreach(__tmp ${${_sourceFiles}})
# 		get_filename_component(_tmp_file ${__tmp} ABSOLUTE)
# 		get_filename_component(_basename ${_tmp_file} NAME_WE)
#
# 		if(NOT EXISTS ${_tmp_file})
# 			message(FATAL_ERROR "Could not find the file ${_tmp_file}")
# 		endif()
#
# 		set(_outputFilename ${_basename}.wixobj)
# 		add_custom_command(
# 			OUTPUT
# 				${_outputFilename}
# 			COMMAND
# 				Wix_Candle ${WIX_CANDLE_FLAGS} "${_tmp_file}"
# 			DEPENDS
# 				${_tmp_file} ${${_extraDependencies}}
# 			COMMENT
# 				"Compiling ${_tmp_file} -> ${_outputFilename}"
# 		)
# 		set(${_objFiles} ${${_objFiles}} ${CMAKE_CURRENT_BINARY_DIR}/${_outputFilename})
# 	endforeach()
# endmacro()
#
# macro(Wix_Compile_All _output_FileName _source_files _dependencies)
# 	add_custom_command(
# 		OUTPUT
# 			${_output_FileName}
# 		COMMAND
# 			Wix_Candle ${WIX_CANDLE_FLAGS} -out "${_output_FileName}" ${${_source_files}}
# 		DEPENDS
# 			${${_source_files}} ${${_dependencies}}
# 		COMMENT
# 			"Compiling ${${_source_files}} -> ${_output_FileName}"
# 	)
# endmacro()
#
# macro(Wix_Link _output_FileName _source_files localizations)
# 	set(__flags "")
# 	foreach(__tmp ${${localizations}})
# 		set(__flags ${__flags} -loc "${__tmp}")
# 	endforeach()
#
# 	add_custom_command(
# 		OUTPUT
# 			${_output_FileName}
# 		COMMAND
# 			Wix_Light ${WIX_LIGHT_FLAGS} ${__flags} -out "${_output_FileName}" ${${_source_files}}
# 		DEPENDS
# 			${${_source_files}}
# 		COMMENT
# 			"Linking ${${_source_files}} ->${_output_FileName}"
# 	)
# endmacro()

function(wix_include_directories)
    set(WIX_INCLUDE_DIRS ${WIX_INCLUDE_DIRS} ${ARGN} PARENT_SCOPE)
endfunction()

function(wix_add_definition)
    set(WIX_DEFINITIONS ${WIX_DEFINITIONS} ${ARGN} PARENT_SCOPE)
endfunction()

function(wix_add_variable)
    set(WIX_VARIABLES ${WIX_VARIABLES} ${ARGN} PARENT_SCOPE)
endfunction()

function(add_wix_target)
    set(objs )
    set(extflags )
    set(compileflags )
    set(linkflags )

    set(options NOPDB FIPS PEDANTIC TRACE VERBOSE NOLOGO)
    set(singleArgOptions TARGET OUTPUT TYPE COMPRESS ARCH)
    set(multiArgOptions WIXEXTENSION SOURCE DEPENDS LOCAL OTHERSOURCE SOURCEFILES NOWARN ISERROR ICE)
    cmake_parse_arguments(WIX_OPTION "${options}" "${singleArgOptions}" "${multiArgOptions}" ${ARGN})

    string(REPLACE "." "_" WIX_OPTION_TARGET ${WIX_OPTION_TARGET})

    if(DEBUG_WIX)
        message(STATUS "add_wix_target(ARGN) ->
        Target:  ${WIX_OPTION_TARGET}
        Output:  ${WIX_OPTION_OUTPUT}
        Type:    ${WIX_OPTION_TYPE}
        Exts:    ${WIX_OPTION_WIXEXTENSION}
        Source:  ${WIX_OPTION_SOURCE}
        Depends: ${WIX_OPTION_DEPENDS}
        Local:   ${WIX_OPTION_LOCAL}
        Other:   ${WIX_OPTION_OTHERSOURCE}
        ")
    endif(DEBUG_WIX)

    #
    # Candle (compile) processing
    #
    foreach (extension ${WIX_OPTION_WIXEXTENSION})
        set(extflags ${extflags} -ext ${extension}.dll)
    endforeach()
    if (DEFINED WIX_OPTION_COMPRESS)
        set(linkflags ${linkflags} -dcl:${WIX_OPTION_COMPRESS})
    endif()
    if (DEFINED WIX_OPTION_ARCH)
        set(compileflags ${compileflags} -arch ${WIX_OPTION_ARCH})
    endif()
    if (WIX_OPTION_FIPS)
        set(compileflags ${compileflags} -fips)
    endif()
    foreach(inc ${WIX_INCLUDE_DIRS})
        set(compileflags ${compileflags} -I"${inc}")
    endforeach()
    foreach(def ${WIX_DEFINITIONS})
        set(compileflags ${compileflags} -d${def})
    endforeach()
    if(WIX_OPTION_PEDANTIC)
        set(compileflags ${compileflags} -pedantic)
    endif()
    if(WIX_OPTION_TRACE)
        set(compileflags ${compileflags} -trace)
    endif()
    if(WIX_OPTION_VERBOSE)
        set(compileflags ${compileflags} -verbose)
    endif()
    if(WIX_OPTION_NOLOGO)
        set(compileflags ${compileflags} -nologo)
    endif()
    foreach(warn ${WIX_INCLUDE_NOWARN})
        set(compileflags ${compileflags} -sw${warn})
    endforeach()
    foreach(err ${WIX_INCLUDE_ISERROR})
        set(compileflags ${compileflags} -wx${warn})
    endforeach()

    foreach(source ${WIX_OPTION_SOURCE})
		get_filename_component(_tmp_file ${source} ABSOLUTE)
		get_filename_component(_basename ${_tmp_file} NAME_WE)

		if(NOT EXISTS ${_tmp_file})
			message(FATAL_ERROR "Could not find the file ${_tmp_file}")
		endif()

		set(_outputFilename ${_basename}.wixobj)
		add_custom_command(
			OUTPUT
				${_outputFilename}
			COMMAND
				Wix_Candle ${WIX_CANDLE_FLAGS} ${compileflags} ${extflags} "${_tmp_file}"
			DEPENDS
				${_tmp_file} ${WIX_OPTION_DEPENDS} Wix_Compile ${WIX_OPTION_SOURCEFILES}
			COMMENT
				"Compiling ${_tmp_file} -> ${_outputFilename}"
		)
		set(objs ${objs} ${CMAKE_CURRENT_BINARY_DIR}/${_outputFilename})
    endforeach()


    #
    # Light (link) processing
    #
	set(__flags ${linkflags})
	foreach(__tmp ${WIX_OPTION_LOCAL})
		set(__flags ${__flags} -loc "${__tmp}")
	endforeach()
	foreach(__tmp ${WIX_VARIABLES})
		set(__flags ${__flags} -d${__tmp})
	endforeach()
    if(WIX_OPTION_NOPDB)
        set(__flags ${__flags} -spdb)
    else()
        set(__flags ${__flags} -pdbout "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/pdb/${WIX_OPTION_TARGET}.wixpdb")
    endif()
    if(WIX_OPTION_NOLOGO)
        set(__flags ${__flags} -nologo)
    endif()
    if(WIX_OPTION_PEDANTIC)
        set(__flags ${__flags} -pedantic)
    endif()
    foreach(warn ${WIX_INCLUDE_NOWARN})
        set(__flags ${__flags} -sw${warn})
    endforeach()
    foreach(err ${WIX_INCLUDE_ISERROR})
        set(__flags ${__flags} -wx${warn})
    endforeach()
    if(WIX_OPTION_VERBOSE)
        set(__flags ${__flags} -verbose)
    endif()
    foreach(ice ${WIX_INCLUDE_ICE})
        set(__flags ${__flags} -ice:${warn})
    endforeach()

	add_custom_command(
		OUTPUT
			${WIX_OPTION_OUTPUT}
		COMMAND
			Wix_Light ${WIX_LIGHT_FLAGS} ${__flags} ${extflags} -out "${WIX_OPTION_OUTPUT}" ${objs}
		DEPENDS
            ${objs} ${OTHERSOURCE} ${WIX_OPTION_LOCAL} Wix_Link 
		COMMENT
			"Linking ${objs} -> ${WIX_OPTION_OUTPUT}"
	)

    #
    # Tie it all together with a target
    #
    add_custom_target(${WIX_OPTION_TARGET} ALL
        DEPENDS
            ${WIX_OPTION_SOURCE} ${WIX_OPTION_DEPENDS}
        SOURCES
            ${WIX_OPTION_SOURCE} ${WIX_OPTION_LOCAL} ${OTHERSOURCE} ${objs} ${WIX_OPTION_OUTPUT}
        BYPRODUCTS
            ${WIX_OPTION_OUTPUT}
            ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/pdb/${WIX_OPTION_TARGET}.wixpdb
        COMMAND
            echo Building ${WIX_OPTION_TARGET}
    )
endfunction()

