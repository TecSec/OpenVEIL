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

////////////////////////////////////////////////////////////////////////////////////////////////////
/// \file   Endian.h
///
/// \brief  Declares the endian conversion macros and functions.
////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef __TS_ENDIAN_H__
#define __TS_ENDIAN_H__


#ifndef _ENDIAN_MACROS_ONLY_
namespace tscrypto {
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Cross platform Host to Network short conversion</summary>
	///
	/// <param name="s">The unsigned short to process.</param>
	///
	/// <returns>the unsigned short in network byte order</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	uint16_t VEILCORE_API XP_htons(uint16_t s);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Cross platform Host to Network long conversion</summary>
	///
	/// <param name="l">The unsigned long to process.</param>
	///
	/// <returns>the unsigned long in network byte order</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	uint32_t  VEILCORE_API XP_htonl(uint32_t l);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>The cross platform Network to Host short conversion</summary>
	///
	/// <param name="s">The unsigned short to process.</param>
	///
	/// <returns>the unsigned short in host byte order</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	uint16_t VEILCORE_API XP_ntohs(uint16_t s);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>The cross platform Network to Host long conversion</summary>
	///
	/// <param name="l">The unsigned long to process.</param>
	///
	/// <returns>the unsigned long in host byte order</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	uint32_t  VEILCORE_API XP_ntohl(uint32_t l);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Cross platform byte swapper for long values</summary>
	///
	/// <param name="l">The unsigned long to process.</param>
	///
	/// <returns>the unsigned long in swapped byte order</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	uint32_t  VEILCORE_API XP_swapEndianLong(uint32_t l);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Cross platform byte swapper for short values</summary>
	///
	/// <param name="s">The unsigned short to process.</param>
	///
	/// <returns>the unsigned short in swapped byte order</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	uint16_t VEILCORE_API XP_swapEndianShort(uint16_t s);
}
#endif // _ENDIAN_MACROS_ONLY_

#endif //__ENDIAN_H__

