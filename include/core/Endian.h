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

/* Byte Order */
#ifndef TS_BYTE_ORDER
#define TS_LITTLE_ENDIAN   1234    /*!< \brief least-significant byte first (vax) */
#define TS_BIG_ENDIAN      4321    /*!< \brief most-significant byte first (IBM, net) */
#define TS_PDP_ENDIAN      3412    /*!< \brief LSB first in word, MSW first in long (pdp) */

/* The _WIN32 define is listed here so that all existing projects don't have to be
 * modified to state the architecture.  Since Microsoft has dropped support
 * for the alpha on NT/2000 then we have no worries.
 */
#if defined(_WIN32) || defined(vax) || defined(ns32000) || defined(sun386) || defined(i386) || \
    defined(MIPSEL) || defined(_MIPSEL) || defined(BIT_ZERO_ON_RIGHT) || \
    defined(__alpha__) || defined(__alpha) || \
    (defined(__Lynx__) && defined(__x86__)) || defined(__ORDER_LITTLE_ENDIAN__)
#define TS_BYTE_ORDER      TS_LITTLE_ENDIAN
#elif defined(sel) || defined(pyr) || defined(mc68000) || defined(sparc) || \
    defined(is68k) || defined(tahoe) || defined(ibm032) || defined(ibm370) || \
    defined(MIPSEB) || defined(_MIPSEB) || defined(_IBMR2) || defined(DGUX) ||\
    defined(apollo) || defined(__convex__) || defined(_CRAY) || \
    defined(RISC6000) || defined(_IBMESA) || defined(aiws) || \
    defined(__hppa) || defined(__hp9000) || \
    defined(__hp9000s300) || defined(__hp9000s700) || \
    defined (BIT_ZERO_ON_LEFT) || defined(m68k) || \
    (defined(__Lynx__) && \
     (defined(__68k__) || defined(__sparc__) || defined(__powerpc__))) || \
    WORDS_BIGENDIAN || defined(__ORDER_BIG_ENDIAN__)
#define TS_BYTE_ORDER      TS_BIG_ENDIAN
#else
#error Unknown Platform
#endif
#endif /* TS_BYTE_ORDER */

//#if defined(_TS_LITTLE_ENDIAN)
//	#undef TS_LITTLE_ENDIAN
//	#undef TS_BIG_ENDIAN
//	#define TS_LITTLE_ENDIAN _LITTLE_ENDIAN
//	#define TS_BIG_ENDIAN _BIG_ENDIAN
//#endif

#if (TS_BYTE_ORDER == TS_LITTLE_ENDIAN)
#define IsLittleEndianMachine
#undef IsBigEndianMachine
//#ifndef _M_IX86
//#define _M_IX86 1
//#endif
#define	ALIGN32	0	 /*!< \brief need dword alignment? (no for Pentium) */
#define	Bswap(x) (x) /*!< \brief NOP for little-endian machines */
#define ADDR_XOR 0   /*!< \brief NOP for little-endian machines */
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that defines 2 byte big endian conversion</summary>
///
/// <remarks>This macro is a code block and therefore cannot be used like a function.</remarks>
/// 
/// <param name="x">2 bytes to process</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define TS_BIG_ENDIAN2(x) { BYTE * y=(BYTE *)&x; BYTE temp=*y; *y= *(y+1); *(y+1) = temp; }
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that defines 2 byte little endian conversion</summary>
///
/// <remarks>This macro is a code block and therefore cannot be used like a function.</remarks>
/// 
/// <param name="x">2 bytes to process</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define TS_LITTLE_ENDIAN2(x)
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that defines 4 byte big endian conversion</summary>
///
/// <remarks>This macro is a code block and therefore cannot be used like a function.</remarks>
/// 
/// <param name="x">4 bytes to process</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define TS_BIG_ENDIAN4(x) { BYTE * y=(BYTE *)&x; BYTE temp=*y; *y= *(y+3); *(y+3) = temp; temp = *(y+1); *(y+1) = *(y+2); *(y+2) = temp; }
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that defines 8 byte big endian conversion</summary>
///
/// <remarks>This macro is a code block and therefore cannot be used like a function.</remarks>
/// 
/// <param name="x">8 bytes to process</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define TS_BIG_ENDIAN8(x) { BYTE * y=(BYTE *)&x; BYTE temp; temp = *y;     *y     = *(y+7); *(y+7) = temp; temp = *(y+1); *(y+1) = *(y+6); *(y+6) = temp; temp = *(y+2); *(y+2) = *(y+5); *(y+5) = temp; temp = *(y+3); *(y+3) = *(y+4); *(y+4) = temp; }
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that defines 4 byte little endian conversion</summary>
///
/// <remarks>This macro is a code block and therefore cannot be used like a function.</remarks>
/// 
/// <param name="x">4 bytes to process</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define TS_LITTLE_ENDIAN4(x)

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that defines 2 byte big endian conversion as a function</summary>
///
/// <param name="x">2 bytes to process</param>
/// 
/// <returns>the big endian converted value</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define _TS_BIG_ENDIAN2(x) ((((x) >> 8) & 0xFF) | ((((x) & 0xff) << 8)))
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that defines a 2 byte little endian conversion as a function</summary>
///
/// <param name="x">2 bytes to process</param>
/// 
/// <returns>the little endian converted value</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define _TS_LITTLE_ENDIAN2(x) (x)
#ifdef __cplusplus
extern "C"
#endif
TS_INLINE unsigned long _TS_BIG_ENDIAN4(unsigned long x) { TS_BIG_ENDIAN4(x); return x; }
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that defines a 4 byte little endian conversion as a function</summary>
///
/// <param name="x">4 bytes to process</param>
/// 
/// <returns>the little endian converted value</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define _TS_LITTLE_ENDIAN4(x) (x)
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that will reverse the byte order of a 2 byte entity regardless of the byte order of the machine</summary>
///
/// <param name="x">2 bytes to process.</param>
/// 
/// <returns>the swapped value</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define _REVERSE16(x) _TS_BIG_ENDIAN2(x)
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that will reverse the byte order of a 4 byte entity regardless of the byte order of the machine</summary>
///
/// <param name="x">4 bytes to process.</param>
/// 
/// <returns>the swapped value</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define _REVERSE32(x) _TS_BIG_ENDIAN4(x)

#elif (TS_BYTE_ORDER == TS_BIG_ENDIAN)
#undef IsLittleEndianMachine
#define IsBigEndianMachine

#define ALIGN32  1 /* (assume need alignment for non-Intel) */
#define Bswap(x) ((ROR(x,8) & 0xFF00FF00) | (ROL(x,8) & 0x00FF00FF))
#define ADDR_XOR 3 /* convert byte address in dword */
#define TS_BIG_ENDIAN2(x)
#define TS_LITTLE_ENDIAN2(x) { BYTE * y=(BYTE *)&x; BYTE temp=*y; *y= *(y+1); *(y+1) = temp; }
#define TS_BIG_ENDIAN4(x)
#define TS_BIG_ENDIAN8(x)
#define TS_LITTLE_ENDIAN4(x) { BYTE * y=(BYTE *)&x; BYTE temp=*y; *y= *(y+3); *(y+3) = temp; temp = *(y+1); *(y+1) = *(y+2); *(y+2) = temp; }

#define _TS_BIG_ENDIAN2(x) (x)
#define _TS_LITTLE_ENDIAN2(x) ((((x) >> 8) & 0xFF) | ((((x) & 0xff) << 8)))
#define _TS_BIG_ENDIAN4(x) (x)
#define _TS_LITTLE_ENDIAN4(x) ((ROR(x,8) & 0xFF00FF00) | (ROL(x,8) & 0x00FF00FF))
#define _REVERSE16(x) _TS_LITTLE_ENDIAN2(x)
#define _REVERSE32(x) _TS_LITTLE_ENDIAN4(x)

#else
#error Unknown Byte Order
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that will reverse the byte order of a 2 byte entity regardless of the byte order of the machine</summary>
///
/// <remarks>This macro is a code block and therefore cannot be used like a function.</remarks>
///
/// <param name="x">2 bytes to process.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define SWAP_SHORT(x) { BYTE * y=(BYTE *)&x; BYTE temp=*y; *y= *(y+1); *(y+1) = temp; }
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that will reverse the byte order of a 2 byte entity regardless of the byte order of the machine</summary>
///
/// <remarks>This macro is a code block and therefore cannot be used like a function.</remarks>
///
/// <param name="x">4 bytes to process.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define SWAP_LONG(x) { BYTE * y=(BYTE *)&x; BYTE temp=*y; *y= *(y+3); *(y+3) = temp; temp = *(y+1); *(y+1) = *(y+2); *(y+2) = temp; }

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

