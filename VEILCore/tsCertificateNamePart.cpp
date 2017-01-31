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
/// \file AppCommon\tsCertificateNamePart.cpp
/// \brief Holds data about one segment of an issuer or subject name for a certificate.
//////////////////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#if 0
#include "tsCertificateNamePart.h"

static struct NamePartListItem
{
    NamePartType type;
    const char *name;
    uint32_t oidLen;
    BYTE oid[20];
} NamePartXref[]=
{
    {CommonName, "CN", 3, {85, 4, 3}  }
    {Surname, "sn", 3, {85, 4, 4}  }
    {Country, "C", 3, {85, 4, 6}  }
    {locality, "L", 3, {85, 4, 7}  }
    {state, "ST", 3, {85, 4, 8}  }
    {OrgName, "O", 3, {85, 4, 10}  }
    {OrgUnit, "OU", 3, {85, 4, 11}  }
    {Title, "title", 3, {85, 4, 12}  }
    {Name, "name", 3, {85, 4, 41}  }
    {givenName, "givenName", 3, {85, 4, 42}  }
    {Initials, "initials", 3, {85, 4, 43}  }
    {Suffix, "generationQualifier", 3, {85, 4, 44}  }
    {dnQualifier, "dnQualifier", 3, {85, 4, 46}  }
};

tsCertificateNamePart::tsCertificateNamePart()
{
    //ctor
}

tsCertificateNamePart::~tsCertificateNamePart()
{
    //dtor
}
//void *tsCertificateNamePart::operator new(size_t bytes) 
//{ 
//    return CryptoSupportAllocator(bytes); 
//}
//
//void tsCertificateNamePart::operator delete(void *ptr) 
//{ 
//    return CryptoSupportDeallocator(ptr); 
//}

 // TODO:  Implement me and then add this support to tsCertificateBuilder
#endif
