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

macro(ConfigureExe target)
    set_target_properties(${target} PROPERTIES DEBUG_POSTFIX "_d")
endmacro()
macro(CopyFile source dest)
    ADD_CUSTOM_COMMAND(
        OUTPUT
            ${dest}
        DEPENDS
            ${source}
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${source} ${dest}
    )
endmacro()
macro(SignThenCopy source destination)
    ADD_CUSTOM_COMMAND(
        OUTPUT ${destination}
        DEPENDS ${source}
        COMMAND signtool.exe sign ${TSF_CERT_SPEC} "${source}"
        COMMAND ${CMAKE_COMMAND} -E copy ${source} ${destination}
    )
endmacro()
macro(StrongSignThenCopy source destination)
    ADD_CUSTOM_COMMAND(
        OUTPUT ${destination}
        DEPENDS ${source}
        COMMAND sn.exe -R "${source}" "${PUBLIC_SOURCE_TOP_DIR}/SolutionItems/${TSF_KEY_FILE}"
        COMMAND signtool.exe sign ${TSF_CERT_SPEC} "${source}"
        COMMAND ${CMAKE_COMMAND} -E copy ${source} ${destination}
    )
endmacro()

macro(CopyTlbHeadersToSDK idlName)
    ADD_CUSTOM_COMMAND(
        OUTPUT ${SDK_ROOT_VS}/include/${TS_X_PLATFORM}/${idlName}_h.h ${SDK_ROOT_VS}/include/${TS_X_PLATFORM}/${idlName}_i.h
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${idlName}_h.h ${CMAKE_CURRENT_BINARY_DIR}/${idlName}_i.h
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/${idlName}_h.h ${SDK_ROOT_VS}/include/${TS_X_PLATFORM}/
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/${idlName}_i.h ${SDK_ROOT_VS}/include/${TS_X_PLATFORM}/
        )
endmacro()
macro(CopyTlbToSDK idlName)
    ADD_CUSTOM_COMMAND(
        OUTPUT ${SDK_ROOT_VS}/include/${TS_X_PLATFORM}/${idlName}.tlb
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${idlName}.tlb
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_BINARY_DIR}/${idlName}.tlb ${SDK_ROOT_VS}/include/${TS_X_PLATFORM}/
        )
endmacro()
macro(CopyToSDKInclude filename destName)
    ADD_CUSTOM_COMMAND(
        OUTPUT ${SDK_ROOT_VS}/include/${destName}
        DEPENDS ${filename}
        COMMAND ${CMAKE_COMMAND} -E copy ${filename} ${SDK_ROOT_VS}/include/${destName}
        )
endmacro()
macro(CopyToSDKInstallerInclude filename destName)
    ADD_CUSTOM_COMMAND(
        OUTPUT ${SDK_ROOT_VS}/${TS_MODULE}/installer/include/${destName}
        DEPENDS ${filename}
        COMMAND ${CMAKE_COMMAND} -E copy ${filename} ${SDK_ROOT_VS}/${TS_MODULE}/installer/include/${destName}
        )
endmacro()
macro(DumpAllVariables)
    get_cmake_property(_variableNames VARIABLES)
    foreach(_variableName ${_variableNames})
        message(STATUS "${_variableName}=${${_variableName}}")
    endforeach()
endmacro()
macro(DumpAllTargetVariables targetName)
    get_target_property(_variableNames ${targetName} VARIABLES)
    foreach(_variableName ${_variableNames})
        message(STATUS "tgt: ${_variableName}=${${_variableName}}")
    endforeach()
endmacro()


IF(BUILD_SXS)
macro(MakeManifest manifestBaseFilename)
    file(TO_NATIVE_PATH "${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${manifestBaseFilename}.manifest" _maniPath)
    CopyFile(${CMAKE_CURRENT_BINARY_DIR}/${manifestBaseFilename}.manifest ${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${manifestBaseFilename}.manifest)
    ADD_CUSTOM_COMMAND(
        OUTPUT
            ${SDK_ROOT_VS}/bin/${TS_X_PLATFORM}/${manifestBaseFilename}.manifest
            ${SDK_ROOT_VS}/policy/${TS_X_PLATFORM}/${manifestBaseFilename}.manifest
            ${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${manifestBaseFilename}.cdf
        DEPENDS            
            ${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${manifestBaseFilename}.manifest
            ${ARGN}
        COMMAND mt.exe -nologo -manifest "${_maniPath}" -makecdfs
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${manifestBaseFilename}.manifest ${SDK_ROOT_VS}/bin/${TS_X_PLATFORM}/${manifestBaseFilename}.manifest
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${manifestBaseFilename}.manifest ${SDK_ROOT_VS}/policy/${TS_X_PLATFORM}/${manifestBaseFilename}.manifest
        COMMAND ${CMAKE_COMMAND} -E remove "${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${manifestBaseFilename}.cdf"
        COMMAND ${CMAKE_COMMAND} -E rename "${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${manifestBaseFilename}.manifest.cdf" "${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${manifestBaseFilename}.cdf"
    )
endmacro()

macro(MakeManifestCatalog manifestBaseFilename)
    file(TO_NATIVE_PATH "${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${manifestBaseFilename}.cdf" _cdfPath)
    ADD_CUSTOM_COMMAND(
        OUTPUT
            ${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${manifestBaseFilename}.cat
        DEPENDS
            ${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${manifestBaseFilename}.cdf
        COMMAND MakeCat.Exe "${_cdfPath}"
        COMMAND signtool.exe sign ${TSF_CERT_SPEC} "${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${manifestBaseFilename}.cat"
    )
    CopyFile(${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${manifestBaseFilename}.cat ${SDK_ROOT_VS}/policy/${TS_X_PLATFORM}/${manifestBaseFilename}.cat)
endmacro()

macro(MakePolicyManifest policyBaseFilename)
    file(TO_NATIVE_PATH "${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${policyBaseFilename}.manifest" _maniPath)
    CopyFile(${CMAKE_CURRENT_BINARY_DIR}/${policyBaseFilename}.manifest ${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${policyBaseFilename}.manifest)
    ADD_CUSTOM_COMMAND(
        OUTPUT
            ${SDK_ROOT_VS}/policy/${TS_X_PLATFORM}/${policyBaseFilename}.manifest
            ${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${policyBaseFilename}.cdf
        DEPENDS            
            ${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${policyBaseFilename}.manifest
            ${ARGN}
        COMMAND mt.exe -nologo -manifest "${_maniPath}" -makecdfs 
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${policyBaseFilename}.manifest ${SDK_ROOT_VS}/policy/${TS_X_PLATFORM}/${policyBaseFilename}.manifest
        COMMAND ${CMAKE_COMMAND} -E remove "${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${policyBaseFilename}.cdf"
        COMMAND ${CMAKE_COMMAND} -E rename "${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${policyBaseFilename}.manifest.cdf" "${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${policyBaseFilename}.cdf"
    )
endmacro()

macro(MakePolicyCatalog policyBaseFilename)
    file(TO_NATIVE_PATH "${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${policyBaseFilename}.cdf" _cdfPath)

    ADD_CUSTOM_COMMAND(
        OUTPUT
            ${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${policyBaseFilename}.cat
        DEPENDS
            ${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${policyBaseFilename}.cdf
        COMMAND MakeCat.Exe "${_cdfPath}"
        COMMAND signtool.exe sign ${TSF_CERT_SPEC} "${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${policyBaseFilename}.cat"
    )

    CopyFile(${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${policyBaseFilename}.cat ${SDK_ROOT_VS}/policy/${TS_X_PLATFORM}/${policyBaseFilename}.cat)
endmacro()
ENDIF(BUILD_SXS)

macro(SignBinary sourcePath signedPath filename dest)
    ADD_CUSTOM_COMMAND(
        OUTPUT
            ${signedPath}/${filename}
        DEPENDS
            ${sourcePath}/${filename}
        COMMAND ${CMAKE_COMMAND} -E echo Signing file ${sourcePath}/${filename}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${signedPath}
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${sourcePath}/${filename} ${signedPath}/${filename}
        COMMAND signtool.exe sign ${TSF_CERT_SPEC} "${signedPath}/${filename}"
    )
    CopyFile(${signedPath}/${filename} ${dest}/${filename})
endmacro()

IF(WIN32)
macro(BuildTLB_sdk idlName)
    ADD_CUSTOM_COMMAND(
        OUTPUT 
            ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_h.h
            ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_i.h 
            # ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_p.c
            ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}.tlb 
        DEPENDS ${idlName}.idl
		COMMAND
		    ${CMAKE_COMMAND} -E make_directory ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/
        COMMAND 
			midl /D "_DEBUG" /W1 /nologo /char signed /env ${TS_PLATFORM} /Oicf /I ${CMAKE_CURRENT_SOURCE_DIR}/../include /I ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/ ${TS_MIDL_INCLUDES} /h "${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_h.h" /iid "${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_i.h" /proxy "${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_p.c" /tlb "${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}.tlb" /robust ${CMAKE_CURRENT_SOURCE_DIR}/${idlName}.idl
        )
	install(
		FILES 
			${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}.tlb
			${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_h.h
			${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_i.h
			# ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_p.c
		DESTINATION 
			${TS_MODULE}/include/${TS_X_PLATFORM}
	)
	install(
		FILES 
			${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}.tlb
			${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_h.h
			${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_i.h
			# ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_p.c
		DESTINATION 
			${TS_MODULE}/installer/include/
	)
    add_custom_target(Generate_${idlName}_TLB ALL
        SOURCES
            ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_h.h
            ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_i.h 
            # ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_p.c
            ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}.tlb 
        DEPENDS
             ${ARGN}
        )
endmacro()
macro(BuildTLB_app idlName)
    ADD_CUSTOM_COMMAND(
        OUTPUT 
            ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_h.h
            ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_i.h 
            # ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_p.c
            ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}.tlb 
        DEPENDS ${idlName}.idl
		COMMAND
		    ${CMAKE_COMMAND} -E make_directory ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/
        COMMAND 
			midl /D "_DEBUG" /W1 /nologo /char signed /env ${TS_PLATFORM} /Oicf /I ${CMAKE_CURRENT_SOURCE_DIR}/../include/ /I ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/ ${TS_MIDL_INCLUDES} /h "${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_h.h" /iid "${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_i.h" /proxy "${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_p.c" /tlb "${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}.tlb" /robust ${CMAKE_CURRENT_SOURCE_DIR}/${idlName}.idl
        )
	install(
		FILES 
			${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}.tlb
			${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_h.h
			${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_i.h
			# ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_p.c
		DESTINATION
			${TS_MODULE}/include/${TS_X_PLATFORM}
	)
    add_custom_target(Generate_${idlName}_TLB ALL
        SOURCES
            ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_h.h
            ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_i.h 
            # ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_p.c
            ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}.tlb 
        DEPENDS
             ${ARGN}
        )
endmacro()
macro(BuildTLBInBinary idlName)
    ADD_CUSTOM_COMMAND(
        OUTPUT 
            ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_h.h
            ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_i.h 
            # ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_p.c
            ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}.tlb 
        DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${idlName}.idl
		COMMAND
		    ${CMAKE_COMMAND} -E make_directory ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/
        COMMAND midl /D "_DEBUG" /W1 /nologo /char signed /env ${TS_PLATFORM} /Oicf /I ${CMAKE_CURRENT_SOURCE_DIR}/../include/ /I ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/ ${TS_MIDL_INCLUDES} /h "${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_h.h" /iid "${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_i.h" /proxy "${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_p.c" /tlb "${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}.tlb" /robust ${CMAKE_CURRENT_BINARY_DIR}/${idlName}.idl
        )
	install(
		FILES
			${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}.tlb
			${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_h.h
			${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_i.h
			# ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_p.c
		DESTINATION
			${TS_MODULE}/include/${TS_X_PLATFORM}
	)
	install(
		FILES
			${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}.tlb
			${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_h.h
			${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_i.h
			# ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_p.c
		DESTINATION
			${TS_MODULE}/installer/include/${TS_X_PLATFORM}
	)
		
    add_custom_target(Generate_${idlName}_TLB ALL
        SOURCES
            ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_h.h
            ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_i.h 
            # ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_p.c
            ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}.tlb 
        DEPENDS
             ${ARGN}
        )
endmacro()
macro(BuildTLBNoLib idlName)
    ADD_CUSTOM_COMMAND(
        OUTPUT 
            ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_h.h
            ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_i.h 
            # ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_p.c
        DEPENDS ${idlName}.idl
		COMMAND
		    ${CMAKE_COMMAND} -E make_directory ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/
        COMMAND 
			midl /D "_DEBUG" /W1 /nologo /char signed /env ${TS_PLATFORM} /Oicf /I ${CMAKE_CURRENT_SOURCE_DIR}/../include/ /I ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/ ${TS_MIDL_INCLUDES} /h "${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_h.h" /iid "${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_i.h" /proxy "${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_p.c" /tlb "${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}.tlb" /robust ${CMAKE_CURRENT_SOURCE_DIR}/${idlName}.idl
        )
	install(
		FILES
			${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_h.h
			${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_i.h
			# ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_p.c
		DESTINATION
			${TS_MODULE}/include/${TS_X_PLATFORM}
	)
	install(
		FILES
			${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_h.h
			${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_i.h
			# ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_p.c
		DESTINATION
			${TS_MODULE}/installer/include/${TS_X_PLATFORM}
	)
    add_custom_target(Generate_${idlName}_TLB ALL
        SOURCES
            ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_h.h
            ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_i.h 
            # ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_p.c
        DEPENDS
             ${ARGN}
        )
endmacro()
macro(BuildTypeTLB_sdk idlName)
    ADD_CUSTOM_COMMAND(
        OUTPUT 
            ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_h.h
            ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_i.h 
            # ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_p.c
        DEPENDS ${idlName}.idl
        COMMAND midl /D "_DEBUG" /W1 /nologo /char signed /notlb /env ${TS_PLATFORM} /Oicf /I ${CMAKE_CURRENT_SOURCE_DIR}/../include/ /I ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/ ${TS_MIDL_INCLUDES} /h "${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_h.h" /iid "${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_i.h" /proxy "${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_p.c" /robust ${CMAKE_CURRENT_SOURCE_DIR}/${idlName}.idl
        )
	install(
		FILES
			${CMAKE_CURRENT_SOURCE_DIR}/${idlName}.idl
			${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_h.h
			${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_i.h
			# ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_p.c
		DESTINATION
			${TS_MODULE}/include/${TS_X_PLATFORM}
	)
	install(
		FILES
			${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_h.h
			${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_i.h
			# ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_p.c
		DESTINATION
			${TS_MODULE}/installer/include/${TS_X_PLATFORM}
	)
    add_custom_target(Generate_${idlName}_TLB ALL
        SOURCES
            ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_h.h
            ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_i.h 
            # ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_p.c
        DEPENDS
             ${ARGN}
        )
endmacro()
macro(BuildTypeTLB_app idlName)
    ADD_CUSTOM_COMMAND(
        OUTPUT 
            ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_h.h
            ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_i.h 
            # ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_p.c
        DEPENDS ${idlName}.idl
        COMMAND midl /D "_DEBUG" /W1 /nologo /char signed /notlb /env ${TS_PLATFORM} /Oicf /I ${CMAKE_CURRENT_SOURCE_DIR}/../include/ /I ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/ ${TS_MIDL_INCLUDES} /h "${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_h.h" /iid "${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_i.h" /proxy "${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_p.c" /robust ${CMAKE_CURRENT_SOURCE_DIR}/${idlName}.idl
        )
	install(
		FILES
			${CMAKE_CURRENT_SOURCE_DIR}/${idlName}.idl
			${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_h.h
			${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_i.h
			# ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_p.c
		DESTINATION
			${TS_MODULE}/include/${TS_X_PLATFORM}
	)
    add_custom_target(Generate_${idlName}_TLB ALL
        SOURCES
            ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_h.h
            ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_i.h 
            # ${PUBLIC_BINARY_TOP_DIR}/include/${TS_VS_CONFIGURATION}/${idlName}_p.c
        DEPENDS
             ${ARGN}
        )
endmacro()

macro(Tlb2TypesDll idlName asmName namespace Product dependency configName)
    # Copy the required manifest and config files
    configure_file(${PUBLIC_SOURCE_TOP_DIR}/SolutionItems/${asmName}.manifest.in ${CMAKE_CURRENT_BINARY_DIR}/${asmName}.manifest)
    configure_file(${PUBLIC_SOURCE_TOP_DIR}/SolutionItems/policy.${asmName}.config.in ${CMAKE_CURRENT_BINARY_DIR}/${TSF_POLICYFILENAME}.${asmName}.config)
    
    # Create the .net TYPES dll
    ADD_CUSTOM_COMMAND(
        OUTPUT 
            ${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${asmName}.dll 
        DEPENDS 
            ${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${idlName}.tlb
        COMMAND 
            tlbimp.exe -nologo /out:${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${asmName}.dll /namespace:${namespace} /delaysign /keyfile:${PUBLIC_SOURCE_TOP_DIR}/SolutionItems/${TSF_KEY_FILE} /primary /machine:${TS_X_PLATFORM} /asmversion:"${TSF_FULL_VERSION}" ${ARGN} /productversion:"${TSF_FULL_VERSION}" ${SDK_ROOT_VS}/include/${TS_X_PLATFORM}/${idlName}.tlb /company:"TecSec Inc" "/copyright:Copyright (c) 2013 TecSec, Inc. All rights reserved" /product:"${Product}"
        COMMAND 
            mt.exe -nologo -manifest "${CMAKE_CURRENT_BINARY_DIR}/${asmName}.manifest" -hashupdate -outputresource:${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${asmName}.dll\;2 
        )
    StrongSignThenCopy(${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${asmName}.dll ${SDK_ROOT_VS}/bin/${TS_X_PLATFORM}/${asmName}.dll)
    CopyFile(${SDK_ROOT_VS}/bin/${TS_X_PLATFORM}/${asmName}.dll ${SDK_ROOT_VS}/assembly/${TS_X_PLATFORM}/${asmName}.dll)
    

    # create the policy dll for the .net component
    CopyFile(${CMAKE_CURRENT_BINARY_DIR}/${TSF_POLICYFILENAME}.${asmName}.config ${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${TSF_POLICYFILENAME}.${asmName}.config)
    ADD_CUSTOM_COMMAND(
        OUTPUT 
            ${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${TSF_POLICYFILENAME}.${asmName}.dll
        DEPENDS 
            # ${SDK_ROOT_VS}/Assembly/${TS_X_PLATFORM}/${asmName}.dll
            ${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${TSF_POLICYFILENAME}.${asmName}.config
        COMMAND 
            al /linkresource:${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${TSF_POLICYFILENAME}.${asmName}.config /out:${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${TSF_POLICYFILENAME}.${asmName}.dll /keyfile:${PUBLIC_SOURCE_TOP_DIR}/SolutionItems/${TSF_KEY_FILE} /v:${TSF_FULL_VERSION}
        )
    SignThenCopy(${CMAKE_CURRENT_BINARY_DIR}/${TS_VS_CONFIGURATION}/${TSF_POLICYFILENAME}.${asmName}.dll "${SDK_ROOT_VS}/policy/${TS_X_PLATFORM}/${TSF_POLICYFILENAME}.${asmName}.dll")
    
    # Put it all together as a VS project
    add_custom_target(Generate_${asmName} ALL
        SOURCES
            ${SDK_ROOT_VS}/bin/${TS_X_PLATFORM}/${asmName}.dll
            ${SDK_ROOT_VS}/assembly/${TS_X_PLATFORM}/${asmName}.dll
            ${SDK_ROOT_VS}/policy/${TS_X_PLATFORM}/${TSF_POLICYFILENAME}.${asmName}.dll
        DEPENDS
            Generate_${idlName}_TLB  ${dependency}
        )
endmacro()
ENDIF(WIN32)

set(SDK_FRAMEWORK_BINARIES
    ${CMAKE_SHARED_MODULE_PREFIX}TSFramework${CMAKE_SHARED_MODULE_SUFFIX}
	)
IF(BUILD_SXS)
set(SDK_FRAMEWORK_BINARIES ${SDK_FRAMEWORK_BINARIES}
    TSFramework-${TS_TOOLSET}-${TS_X_PLATFORM}-assembly.manifest
    )
ENDIF(BUILD_SXS)
set(SDK_CRYPTO_BINARIES
    ${SDK_FRAMEWORK_BINARIES}

    ${CMAKE_SHARED_MODULE_PREFIX}TSCryptoSupport${CMAKE_SHARED_MODULE_SUFFIX}
    ${CMAKE_SHARED_MODULE_PREFIX}CkmCrypto2${CMAKE_SHARED_MODULE_SUFFIX}
    ${CMAKE_SHARED_MODULE_PREFIX}CkmCrypto_Fips${CMAKE_SHARED_MODULE_SUFFIX}
	)
IF(BUILD_SXS)
set(SDK_CRYPTO_BINARIES ${SDK_CRYPTO_BINARIES}
    TSCkmCrypto2-${TS_TOOLSET}-${TS_X_PLATFORM}-assembly.manifest
    TSCkmCrypto_Fips-${TS_TOOLSET}-${TS_X_PLATFORM}-assembly.manifest
    TSCryptoSupport-${TS_TOOLSET}-${TS_X_PLATFORM}-assembly.manifest
    )
ENDIF(BUILD_SXS)
set(SDK_RUNTIME_BINARIES
    ${SDK_CRYPTO_BINARIES}
    
    ${CMAKE_SHARED_MODULE_PREFIX}BsiCore${CMAKE_SHARED_MODULE_SUFFIX}
    ${CMAKE_SHARED_MODULE_PREFIX}CkmEBClient${CMAKE_SHARED_MODULE_SUFFIX}
    ${CMAKE_SHARED_MODULE_PREFIX}CkmHeader${CMAKE_SHARED_MODULE_SUFFIX}
    ${CMAKE_SHARED_MODULE_PREFIX}CkmFileSupport${CMAKE_SHARED_MODULE_SUFFIX}
    ${CMAKE_SHARED_MODULE_PREFIX}CkmKeyGen${CMAKE_SHARED_MODULE_SUFFIX}
    ${CMAKE_SHARED_MODULE_PREFIX}CkmUI${CMAKE_SHARED_MODULE_SUFFIX}
    ${CMAKE_SHARED_MODULE_PREFIX}CkmDatastore${CMAKE_SHARED_MODULE_SUFFIX}
    ${CMAKE_SHARED_MODULE_PREFIX}CkmWinscard${CMAKE_SHARED_MODULE_SUFFIX}
    ${CMAKE_SHARED_MODULE_PREFIX}Ckm_Pkcs11${CMAKE_SHARED_MODULE_SUFFIX}
    ${CMAKE_SHARED_MODULE_PREFIX}TSAppCommon${CMAKE_SHARED_MODULE_SUFFIX}
    ${CMAKE_SHARED_MODULE_PREFIX}TSCkmLoader${CMAKE_SHARED_MODULE_SUFFIX}
    )
IF(BUILD_SXS)
set(SDK_RUNTIME_BINARIES
    ${SDK_RUNTIME_BINARIES}
   
    TSAppCommon-${TS_TOOLSET}-${TS_X_PLATFORM}-assembly.manifest
    TSCkmUI-${TS_TOOLSET}-${TS_X_PLATFORM}-assembly.manifest
    TSCkmLoader-${TS_TOOLSET}-${TS_X_PLATFORM}-assembly.manifest
    )
ENDIF(BUILD_SXS)
	
set(GMOCK_BINARIES
    ${CMAKE_SHARED_MODULE_PREFIX}gmock.dll
    ${CMAKE_SHARED_MODULE_PREFIX}gmock_main.dll
    ${CMAKE_SHARED_MODULE_PREFIX}gtest.dll
    ${CMAKE_SHARED_MODULE_PREFIX}gtest_main.dll
    )
macro(CopySdkFrameworkBinaries folder name)
	set(__list "")
    foreach(_file ${SDK_FRAMEWORK_BINARIES})
        CopyFile(${SDK_ROOT_VS}/bin/${TS_X_PLATFORM}/${_file} ${folder}/${_file})
		set(__list ${__list} ${folder}/${_file})
    endforeach()
    add_custom_target(Start_AppFolders_${name}
        SOURCES
            ${__list}
        DEPENDS
            ${name}
            ${ARGN}
        COMMAND
            ${CMAKE_COMMAND} -E echo Creating the application output folders
        )    
endmacro()
macro(CopySdkFrameworkBinariesAndGmock folder name)
	set(__list "")
    foreach(_file ${SDK_FRAMEWORK_BINARIES})
        CopyFile(${SDK_ROOT_VS}/bin/${TS_X_PLATFORM}/${_file} ${folder}/${_file})
		set(__list ${__list} ${folder}/${_file})
    endforeach()
    foreach(_file ${GMOCK_BINARIES})
        CopyFile(${PUBLIC_SOURCE_TOP_DIR}/../thirdparty/${TS_VS_CONFIGURATION}/${_file} ${folder}/${_file})
		set(__list ${__list} ${folder}/${_file})
    endforeach()
    add_custom_target(Start_AppFolders_${name}
        SOURCES
            ${__list}
        DEPENDS
            ${name}
            ${ARGN}
        COMMAND
            ${CMAKE_COMMAND} -E echo Creating the application output folders
        )    
endmacro()
macro(CopySdkCryptoBinaries folder name)
	set(__list "")
    foreach(_file ${SDK_CRYPTO_BINARIES})
        CopyFile(${SDK_ROOT_VS}/bin/${TS_X_PLATFORM}/${_file} ${folder}/${_file})
		set(__list ${__list} ${folder}/${_file})
    endforeach()
    add_custom_target(Start_AppFolders_${name}
        SOURCES
            ${__list}
            
        DEPENDS
            ${name}
            ${ARGN}
        COMMAND
            echo Creating the application output folders
        )    
endmacro()
macro(CopySdkCryptoBinariesAndGmock folder name)
	set(__list "")
    foreach(_file ${SDK_CRYPTO_BINARIES})
        CopyFile(${SDK_ROOT_VS}/bin/${TS_X_PLATFORM}/${_file} ${folder}/${_file})
		set(__list ${__list} ${folder}/${_file})
    endforeach()
    foreach(_file ${GMOCK_BINARIES})
        CopyFile(${PUBLIC_SOURCE_TOP_DIR}/../thirdparty/${TS_VS_CONFIGURATION}/${_file} ${folder}/${_file})
		set(__list ${__list} ${folder}/${_file})
    endforeach()
    add_custom_target(Start_AppFolders_${name}
        SOURCES
            ${__list}
        DEPENDS
            ${name}
            ${ARGN}
        COMMAND
            echo Creating the application output folders
        )    
endmacro()
macro(CopySdkRuntimeBinaries folder name)
	set(__list "")
    foreach(_file ${SDK_RUNTIME_BINARIES})
        CopyFile(${SDK_ROOT_VS}/bin/${TS_X_PLATFORM}/${_file} ${folder}/${_file})
		set(__list ${__list} ${folder}/${_file})
    endforeach()
    add_custom_target(Start_AppFolders_${name}
        SOURCES
            ${__list}
            
        DEPENDS
            ${name}
            ${ARGN}
        COMMAND
            echo Creating the application output folders
        )    
endmacro()
macro(CopySdkRuntimeBinariesAndGmock folder name)
	set(__list "")
    foreach(_file ${SDK_RUNTIME_BINARIES})
        CopyFile(${SDK_ROOT_VS}/bin/${TS_X_PLATFORM}/${_file} ${folder}/${_file})
		set(__list ${__list} ${folder}/${_file})
    endforeach()
    foreach(_file ${GMOCK_BINARIES})
        CopyFile(${PUBLIC_SOURCE_TOP_DIR}/../thirdparty/${TS_VS_CONFIGURATION}/${_file} ${folder}/${_file})
		set(__list ${__list} ${folder}/${_file})
    endforeach()
    add_custom_target(Start_AppFolders_${name}
        SOURCES
            ${__list}
        DEPENDS
            ${name}
            ${ARGN}
        COMMAND
            echo Creating the application output folders
        ) 
endmacro()
macro(CopySdkRteBinariesToWeb name folder)
	set(__list "")
    foreach(_file ${SDK_RUNTIME_BINARIES})
        CopyFile(${SDK_ROOT_VS}/bin/${TS_X_PLATFORM}/${_file} ${APP_TEST_ROOT_VS}/${folder}/${TS_X_PLATFORM}-${TS_TOOLSET}/Web/bin/${_file})
		set(__list ${__list} ${APP_TEST_ROOT_VS}/${folder}/${TS_X_PLATFORM}-${TS_TOOLSET}/Web/bin/${_file})
    endforeach()
    add_custom_target(Start_AppFolders.Web.${name}
        SOURCES
			${__list}

		COMMAND
            echo Creating the application output folders
        )    
        set_target_properties(Start_AppFolders.Web.${name} PROPERTIES FOLDER "Finish")
endmacro()

macro(Minify source dest)
if(APPLE)
	GET_FILENAME_COMPONENT(__destFile ${dest} NAME)
	GET_FILENAME_COMPONENT(__destPath ${dest} DIRECTORY)
	ADD_CUSTOM_COMMAND(
		OUTPUT
			${dest}
		DEPENDS
			${source}
		COMMAND
			${CMAKE_COMMAND} -E copy_if_different ${source} ${dest}
	)
else()
	GET_FILENAME_COMPONENT(__destFile ${dest} NAME)
	GET_FILENAME_COMPONENT(__destPath ${dest} DIRECTORY)
	ADD_CUSTOM_COMMAND(
		OUTPUT
			${dest}
		DEPENDS
			${source}
		COMMAND
			${CMAKE_COMMAND} -E copy_if_different ${source} ${dest}.tmp.js
#		COMMAND 
#			${CMAKE_COMMAND} -E chdir ${__destPath} java -jar s:/devsup/utils/yuicompressor-2.4.8.jar -o "${__destFile}" "${dest}.tmp.js"
                COMMAND
                        java.exe -jar ${yuicompressor} -o "${__destFile}" "${dest}.tmp.js" WORKING_DIRECTORY ${__destPath}
		COMMAND
			${CMAKE_COMMAND} -E remove ${dest}.tmp.js
	)
    endif(APPLE)
endmacro()
macro(add_uninstall)
    # add the uninstall support
    set(_tmp_sysroot ${CMAKE_SYSROOT})
    set(CMAKE_SYSROOT "")
    find_file(UNINSTALL_HELPER uninstall.cmake.in HINTS ${CMAKE_MODULE_PATH})
    set(CMAKE_SYSROOT ${_tmp_sysroot})
    if("${UNINSTALL_HELPER}" STREQUAL "UNINSTALL_HELPER-NOTFOUND")
        MESSAGE(FATAL "The file uninstall.cmake.in could not be found.")
    else()
        CONFIGURE_FILE("${UNINSTALL_HELPER}" "${CMAKE_CURRENT_BINARY_DIR}/uninstall.cmake" IMMEDIATE @ONLY)
        
        ADD_CUSTOM_TARGET(uninstall "${CMAKE_COMMAND}" -P "${CMAKE_CURRENT_BINARY_DIR}/uninstall.cmake")
        set_target_properties(uninstall PROPERTIES FOLDER "CMakePredefinedTargets")
    endif()
endmacro()

macro(ImportTarget target)
if(TARGET ${target})
	#include_directories($<TARGET_PROPERTY:${target},INTERFACE_INCLUDE_DIRECTORIES_$<UPPER_CASE:$<CONFIG>>>)
	get_property(_tmp TARGET ${target} PROPERTY INTERFACE_INCLUDE_DIRECTORIES_${TS_CONFIG})
	if(NOT ("${_tmp}" STREQUAL ""))
		include_directories(${_tmp})
	endif(NOT ("${_tmp}" STREQUAL ""))
	get_property(_tmp TARGET ${target} PROPERTY INTERFACE_MIDL_INCLUDE_${TS_CONFIG})
	if(NOT "${_tmp}" STREQUAL "")
		list(APPEND TS_MIDL_INCLUDES "-I" "${_tmp}")
	endif(NOT "${_tmp}" STREQUAL "")
    if(APPLE)
    	get_property(_tmp TARGET ${target} PROPERTY INTERFACE_BIN_MODULES_${TS_CONFIG})
        #  need something here
    endif(APPLE)
endif(TARGET ${target})
endmacro()
macro(CopyImportTargetBinaries target dest)
	get_property(_tmp TARGET ${target} PROPERTY INTERFACE_BIN_MODULES_${TS_CONFIG})
	install(FILES ${_tmp} DESTINATION ${dest})
endmacro()
macro(CopyImportTargetBinariesToBuildFolder target dest)
	get_property(_tmp TARGET ${target} PROPERTY INTERFACE_BIN_MODULES_${TS_CONFIG})
    foreach(_file ${_tmp})
        GET_FILENAME_COMPONENT(__destFile ${_file} NAME)
        add_custom_command(
            OUTPUT 
                ${dest}/${__destFile}
            COMMAND 
                ${CMAKE_COMMAND} -E copy_if_different ${_file} ${dest}/${__destFile}
            DEPENDS
                ${_file}
        )
        LIST(APPEND soFilesToCopy "${dest}/${__destFile}")
    endforeach()
endmacro()
macro(CopyImportTargetTools target dest)
	get_property(_tmp TARGET ${target} PROPERTY INTERFACE_TOOLS_${TS_CONFIG})
	if(NOT("${_tmp}" STREQUAL ""))
		install(FILES ${_tmp} DESTINATION ${dest})
	endif(NOT("${_tmp}" STREQUAL ""))
endmacro()
