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

class CmsHeaderCryptoGroupImpl : public ICmsHeaderCryptoGroup, public tsmod::IObject
{
public:
	CmsHeaderCryptoGroupImpl(const tscrypto::tsCryptoData& domId);
	virtual ~CmsHeaderCryptoGroupImpl(void);

	// ICmsHeaderCryptoGroup
	virtual tscrypto::tsCryptoData GetCryptoGroupId();
	virtual int  GetCurrentMaintenanceLevel();
	virtual bool SetCurrentMaintenanceLevel(int setTo);
	virtual tscrypto::tsCryptoData GetEphemeralPublic();
	virtual bool SetEphemeralPublic(const tscrypto::tsCryptoData &key);

private:
    tscrypto::tsCryptoData m_cryptoGroupId;
	int m_CML;
	tscrypto::tsCryptoData m_ephemeralPublic;
};

CmsHeaderCryptoGroupImpl::CmsHeaderCryptoGroupImpl(const tscrypto::tsCryptoData& domId) :
	m_cryptoGroupId(domId),
    m_CML(0)
{
}


CmsHeaderCryptoGroupImpl::~CmsHeaderCryptoGroupImpl(void)
{
}

// ICmsHeaderCryptoGroup
tscrypto::tsCryptoData CmsHeaderCryptoGroupImpl::GetCryptoGroupId()
{
	return m_cryptoGroupId;
}

int  CmsHeaderCryptoGroupImpl::GetCurrentMaintenanceLevel()
{
    return m_CML;
}

bool CmsHeaderCryptoGroupImpl::SetCurrentMaintenanceLevel(int setTo)
{
    m_CML = setTo;
    return true;
}

tscrypto::tsCryptoData CmsHeaderCryptoGroupImpl::GetEphemeralPublic()
{
    return m_ephemeralPublic;
}

bool CmsHeaderCryptoGroupImpl::SetEphemeralPublic(const tscrypto::tsCryptoData &key)
{
    m_ephemeralPublic = key;
    return true;
}


std::shared_ptr<ICmsHeaderCryptoGroup> CreateCryptoGroupHeaderObject(const tscrypto::tsCryptoData& domId)
{
	return ::TopServiceLocator()->Finish<ICmsHeaderCryptoGroup>(new CmsHeaderCryptoGroupImpl(domId));
}
