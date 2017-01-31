//	Copyright (c) 2017, TecSec, Inc.
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

//////////////////////////////////////////////////////////////////////////////////
/// \file AppCommon\CkmHeaderExtensionOIDs.h
/// \brief Some common CKM Header OIDs in byte array form.
//////////////////////////////////////////////////////////////////////////////////

#ifndef CKMHEADEREXTENSIONOIDS_H_INCLUDED
#define CKMHEADEREXTENSIONOIDS_H_INCLUDED

static const BYTE IVEC_HEADER_EXTENSION_OID[]          = {0x67, 0x2A, 0x09, 0x0A, 0x03, 0x00, 0x02, 0x02, 0x01};	///< The ivec extension oid[]
static const BYTE CKM_SECRYPTM__EXTENSION_OID[]        = {0x67, 0x2A, 0x09, 0x0A, 0x03, 0x00, 0x02, 0x02, 0x02};	///< The SecryptM extension oid[]
static const BYTE FILELENGTH_HEADER_EXTENSION_OID[]    = {0x67, 0x2A, 0x09, 0x0A, 0x03, 0x00, 0x02, 0x02, 0x03};	///< The File length extension oid[]
static const BYTE FILEHASH_HEADER_EXTENSION_OID[]      = {0x67, 0x2A, 0x09, 0x0A, 0x03, 0x00, 0x02, 0x02, 0x04};	///< The File hash extension oid[]
static const BYTE FILENAME_HEADER_EXTENSION_OID[]      = {0x67, 0x2A, 0x09, 0x0A, 0x03, 0x00, 0x02, 0x02, 0x05};	///< The File name extension oid[]
static const BYTE FAVORITENAME_HEADER_EXTENSION_OID[]  = {0x67, 0x2A, 0x09, 0x0A, 0x03, 0x00, 0x02, 0x02, 0x06};	///< The Favorite name extension oid[]
static const BYTE SIGNATURE_HEADER_EXTENSION_OID[]     = {0x67, 0x2A, 0x09, 0x0A, 0x03, 0x00, 0x02, 0x02, 0x07};	///< The Signature extension oid[]
static const BYTE BLOCKSIZE_HEADER_EXTENSION_OID[]     = {0x67, 0x2A, 0x09, 0x0A, 0x03, 0x00, 0x02, 0x02, 0x08};	///< The Block size extension oid[]
static const BYTE PAD_HEADER_EXTENSION_OID[]           = {0x67, 0x2A, 0x09, 0x0A, 0x03, 0x00, 0x02, 0x02, 0x09};	///< The header padding extension oid[]
static const BYTE THIRD_PARTY_HEADER_EXTENSION_OID[]   = {0x67, 0x2A, 0x09, 0x0A, 0x03, 0x00, 0x02, 0x02, 0x0A};	///< The third party base extension oid[]


#endif // CKMHEADEREXTENSIONOIDS_H_INCLUDED
