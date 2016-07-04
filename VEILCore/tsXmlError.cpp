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


// tsXmlError.cpp: implementation of the CtsXmlError class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

tsXmlError::tsXmlError() :
    m_number (0)
{

}

tsXmlError::~tsXmlError()
{

}

//void *tsXmlError::operator new(size_t bytes) 
//{ 
//    return FrameworkAllocator(bytes); 
//}
//
//void tsXmlError::operator delete(void *ptr) 
//{ 
//    return FrameworkDeallocator(ptr); 
//}

const tscrypto::tsCryptoString &tsXmlError::Description() const
{
    return m_description;
}

void tsXmlError::Description(const tscrypto::tsCryptoString &desc)
{
    m_description = desc;
}

const tscrypto::tsCryptoString &tsXmlError::Component() const
{
    return m_component;
}

void tsXmlError::Component(const tscrypto::tsCryptoString &comp)
{
    m_component = comp;
}

const tscrypto::tsCryptoString &tsXmlError::Method() const
{
    return m_method;
}

void tsXmlError::Method(const tscrypto::tsCryptoString &meth)
{
    m_method = meth;
}

int32_t tsXmlError::Number() const
{
    return m_number;
}

void tsXmlError::Number(int32_t num)
{
    m_number = num;
}

void tsXmlError::ToXML(tscrypto::tsCryptoString &appendToXML, bool useAttributes) const
{
    if (useAttributes)
    {
        appendToXML += "<Error ";
        TSAddToXML(appendToXML, "Number", tscrypto::tsCryptoString().append(m_number));
        TSAddToXML(appendToXML, "Component", m_component);
        TSAddToXML(appendToXML, "Method", m_method);
        TSAddToXML(appendToXML, "Value", m_description);
        appendToXML += "/>";
    }
    else
    {
        appendToXML += "<Error><NumberAtt>";
        appendToXML.append(m_number);
        appendToXML += "</NumberAtt><ComponentAtt>";
	    appendToXML += m_component;
        appendToXML += "</ComponentAtt><MethodAtt>";
	    appendToXML += m_method;
        appendToXML += "</MethodAtt><ValueAtt>";
	    appendToXML += m_description;
        appendToXML += "</ValueAtt></Error>";
    }
}
