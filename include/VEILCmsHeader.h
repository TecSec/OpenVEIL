//	Copyright (c) 2016, TecSec, Inc.
//
//	Redistribution and use in source and binary forms, with or without
//	modification, are permitted provided that the following conditions are met:
//	
//		* Redistributions of source code must retain the above copyright
//		  notice, this list of conditions and the following disclaimer.
//		* Redistributions in binary form must reproduce the above copyright
//		  notice, this list of conditions and the following disclaimer in the
//		  documentation and/or other materials provided with the distribution.
//		* Neither the name of TecSec nor the names of the contributors may be
//		  used to endorse or promote products derived from this software 
//		  without specific prior written permission.
//		 
//	ALTERNATIVELY, provided that this notice is retained in full, this product
//	may be distributed under the terms of the GNU General Public License (GPL),
//	in which case the provisions of the GPL apply INSTEAD OF those given above.
//		 
//	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
//	ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//	DISCLAIMED.  IN NO EVENT SHALL TECSEC BE LIABLE FOR ANY 
//	DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//	(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
//	LOSS OF USE, DATA OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
//	ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Written by Roger Butler

#ifndef __CMSHEADER_H__
#define __CMSHEADER_H__

#pragma once

#include "compilerconfig.h"

#include "VEIL.h"

#ifdef _WIN32
	#ifdef _STATIC_RUNTIME_LOADER
		#define CMSHEADER_EXPORT
		#define CMSHEADER_TEMPLATE_EXTERN extern
	#else
		#if !defined(CMSHEADERDEF) && !defined(DOXYGEN)
			#define CMSHEADER_EXPORT  __declspec(dllimport)
			#define CMSHEADER_TEMPLATE_EXTERN extern
		#else
			/// <summary>A macro that defines extern syntax for templates.</summary>
			#define CMSHEADER_TEMPLATE_EXTERN
			/// <summary>A macro that defines the export modifiers for the AppPlatform components.</summary>
			#define CMSHEADER_EXPORT __declspec(dllexport)
		#endif
	#endif
#else
	#if !defined(CMSHEADERDEF) && !defined(DOXYGEN)
		#define CMSHEADER_EXPORT
		#define CMSHEADER_TEMPLATE_EXTERN extern
	#else
		#define CMSHEADER_EXPORT EXPORT_SYMBOL
		#define CMSHEADER_TEMPLATE_EXTERN
	#endif
#endif // _WIN32

extern bool CMSHEADER_EXPORT InitializeCmsHeader();

#include "CmsHeader/CmsHeaderInterfaces.h"
#include "CmsHeader/CmsHeaderExtensionOIDs.h"

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Extracts a header from the beginning of a data stream.</summary>
///
/// <param name="data">		   The data to process.</param>
/// <param name="dataLength">  Length of the data to process.</param>
/// <param name="headerLength">[out] The length of the header in the data stream.</param>
/// <param name="pVal">		   [out] The new header object.</param>
///
/// <returns>S_OK for success or a standard COM error for failure.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
bool CMSHEADER_EXPORT ExtractHeaderFromStream(const BYTE *data, int dataLength, int *headerLength, std::shared_ptr<tsmod::IObject>& pVal);
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Extracts a header from the beginning of a data stream.</summary>
///
/// <param name="data">		   The data to process.</param>
/// <param name="dataLength">  Length of the data to process.</param>
/// <param name="headerLength">[out] The length of the header in the data stream.</param>
///
/// <returns>S_OK for success or a standard COM error for failure.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
bool CMSHEADER_EXPORT ExtractHeaderLength(const BYTE *data, int dataLength, int *headerLength);

#endif // __CMSHEADER_H__
