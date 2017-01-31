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
/// \file   Endian.cpp
///
/// \brief  Implements the endian class.
////////////////////////////////////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//#ifdef _WIN32
//    #include <windows.h>
//#endif




/* byte ordering routines */

////////////////////////////////////////////////////////////////////////////////////////////////////
/// \fn extern unsigned short XP_htons(unsigned short s)
///
/// \brief  Xp htons.
///
/// \author Rogerb
/// \date   12/4/2010
///
/// \param  s   The.
///
/// \return .
////////////////////////////////////////////////////////////////////////////////////////////////////
extern uint16_t tscrypto::XP_htons(uint16_t s)
{
#ifdef HAVE_HTONL
    return htons(s);
#else
    return _TS_BIG_ENDIAN2(s);
#endif // HAVE_HTONL
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// \fn extern unsigned long XP_htonl(unsigned long l)
///
/// \brief  Xp htonl.
///
/// \author Rogerb
/// \date   12/4/2010
///
/// \param  l   The.
///
/// \return .
////////////////////////////////////////////////////////////////////////////////////////////////////
extern uint32_t tscrypto::XP_htonl(uint32_t l)
{
#ifdef HAVE_HTONL
    return htonl(l);
#else
	TS_BIG_ENDIAN4(l);
    return l;
#endif // HAVE_HTONL
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// \fn extern unsigned short XP_ntohs(unsigned short s)
///
/// \brief  Xp ntohs.
///
/// \author Rogerb
/// \date   12/4/2010
///
/// \param  s   The.
///
/// \return .
////////////////////////////////////////////////////////////////////////////////////////////////////
extern uint16_t tscrypto::XP_ntohs(uint16_t s)
{
#ifdef HAVE_HTONL
    return ntohs(s);
#else
    return _TS_BIG_ENDIAN2(s);
#endif // HAVE_HTONL
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// \fn extern unsigned long XP_ntohl(unsigned long l)
///
/// \brief  Xp ntohl.
///
/// \author Rogerb
/// \date   12/4/2010
///
/// \param  l   The.
///
/// \return .
////////////////////////////////////////////////////////////////////////////////////////////////////
extern uint32_t tscrypto::XP_ntohl(uint32_t l)
{
#ifdef HAVE_HTONL
    return ntohl(l);
#else
	TS_BIG_ENDIAN4(l);
    return l;
#endif // HAVE_HTONL
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// \fn extern unsigned long XP_swapEndianLong(unsigned long l)
///
/// \brief  Xp swap endian long.
///
/// \author Rogerb
/// \date   12/4/2010
///
/// \param  l   The.
///
/// \return .
////////////////////////////////////////////////////////////////////////////////////////////////////
extern uint32_t tscrypto::XP_swapEndianLong(uint32_t l)
{
    SWAP_LONG(l);
    return l;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// \fn extern unsigned short XP_swapEndianShort(unsigned short s)
///
/// \brief  Xp swap endian short.
///
/// \author Rogerb
/// \date   12/4/2010
///
/// \param  s   The.
///
/// \return .
////////////////////////////////////////////////////////////////////////////////////////////////////
extern uint16_t tscrypto::XP_swapEndianShort(uint16_t s)
{
    SWAP_SHORT(s);
    return s;
}

//
//void TSSwapBytes(BYTE *data, size_t len)
//{
//    if ( len > 0 )
//    {
//        BYTE tmp;
//        size_t i;
//
//        for (i = 0; i < (len >> 1); i++)
//        {
//            tmp = data[i];
//            data[i] = data[len - i - 1];
//            data[len - i - 1] = tmp;
//        }
//    }
//}
//
//void TSSwapBytes(tsCryptoData &data)
//{
//	data.reverse();
//}
//
//#if (BYTE_ORDER == LITTLE_ENDIAN)
//void TSMakeBigEndian(BYTE *data, size_t len)
//{
//    TSSwapBytes(data, len);
//}
//#else
//void TSMakeBigEndian(BYTE * /*data*/, size_t /*len*/)
//{
//}
//#endif
//
//void TSMakeBigEndian(tsCryptoData &data)
//{
//    TSMakeBigEndian(data.rawData(), data.size());
//}
//
//#if (BYTE_ORDER != LITTLE_ENDIAN)
//void TSMakeLittleEndian(__attribute__((unused)) BYTE *data, __attribute__((unused)) size_t len)
//{
//    TSSwapBytes(data, len);
//}
//#else
//void TSMakeLittleEndian(BYTE * /*data*/, size_t /*len*/)
//{
//}
//#endif
//
//void TSMakeLittleEndian(tsCryptoData &data)
//{
//    TSMakeLittleEndian(data.rawData(), data.size());
//}
