//	Copyright (c) 2018, TecSec, Inc.
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

#include "stdafx.h"

class CmsHeaderAttributeImpl : public ICmsHeaderAttribute, public tsmod::IObject
{
public:
	CmsHeaderAttributeImpl(void);
	virtual ~CmsHeaderAttributeImpl(void);

	// ICmsHeaderAttribute
	virtual tscrypto::tsCryptoData GetAttributeId();
	virtual bool SetAttributeId(const tscrypto::tsCryptoData &id);
	virtual int GetKeyVersion();
	virtual bool SetKeyVersion(int setTo);
	virtual int GetCryptoGroupNumber();
	virtual bool SetCryptoGroupNumber(int setTo);
	virtual tscrypto::tsCryptoData GetSignature();
	virtual bool SetSignature(const tscrypto::tsCryptoData &setTo);

private:
    tscrypto::tsCryptoData m_id;
	int m_version;
	int m_cryptoGroupNumber;
	tscrypto::tsCryptoData m_signature;
};

CmsHeaderAttributeImpl::CmsHeaderAttributeImpl(void) :
    m_version(0),
	m_cryptoGroupNumber(0)
{
}

CmsHeaderAttributeImpl::~CmsHeaderAttributeImpl(void)
{
}

tscrypto::tsCryptoData CmsHeaderAttributeImpl::GetAttributeId()
{
    return m_id;
}

bool CmsHeaderAttributeImpl::SetAttributeId(const tscrypto::tsCryptoData &id)
{
    m_id = id;
    return true;
}

int CmsHeaderAttributeImpl::GetKeyVersion()
{
    return m_version;
}

bool CmsHeaderAttributeImpl::SetKeyVersion(int setTo)
{
    m_version = setTo;
    return true;
}

int CmsHeaderAttributeImpl::GetCryptoGroupNumber()
{
	return m_cryptoGroupNumber;
}

bool CmsHeaderAttributeImpl::SetCryptoGroupNumber(int setTo)
{
	m_cryptoGroupNumber = setTo;
    return true;
}

tscrypto::tsCryptoData CmsHeaderAttributeImpl::GetSignature()
{
    return m_signature;
}

bool CmsHeaderAttributeImpl::SetSignature(const tscrypto::tsCryptoData &setTo)
{
    m_signature = setTo;
    return true;
}

std::shared_ptr<ICmsHeaderAttribute> CreateHeaderAttribute()
{
	return ::TopServiceLocator()->Finish<ICmsHeaderAttribute>(new CmsHeaderAttributeImpl());
}