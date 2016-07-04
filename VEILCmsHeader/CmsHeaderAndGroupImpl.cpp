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

#include "stdafx.h"
#include <stdexcept>

class CmsHeaderAttributeGroupImpl : public ICmsHeaderAttributeGroup, public tsmod::IObject
{
public:
	CmsHeaderAttributeGroupImpl(void);
	virtual ~CmsHeaderAttributeGroupImpl(void);

	// ICmsHeaderAccessGroup
	virtual AndGroupType GetAndGroupType();

	// ICmsHeaderAttributeGroup
	virtual size_t GetAttributeCount() const;
	virtual const uint32_t& GetAttributeIndex(size_t position) const;
	virtual bool RemoveAttributeIndex(size_t position);
	virtual bool AddAttributeIndex(uint32_t  indexInAttributeList);
	virtual tscrypto::tsCryptoData GetEncryptedRandom();
	virtual bool SetEncryptedRandom(const tscrypto::tsCryptoData &setTo);
	bool SetAttributeIndex(size_t position, uint32_t setTo);

private:
	std::vector<uint32_t> m_attrIndexList;
	tscrypto::tsCryptoData m_encryptedRandom;
};

std::shared_ptr<ICmsHeaderAccessGroup> CreateHeaderAccessGroup(AndGroupType type)
{
    switch (type)
    {
	case ag_Attrs:
		return ::TopServiceLocator()->Finish<ICmsHeaderAccessGroup>(new CmsHeaderAttributeGroupImpl);
    default:
        return nullptr;
    }
}

//
//
//
//

CmsHeaderAttributeGroupImpl::CmsHeaderAttributeGroupImpl(void)
{
}

CmsHeaderAttributeGroupImpl::~CmsHeaderAttributeGroupImpl(void)
{
}

AndGroupType CmsHeaderAttributeGroupImpl::GetAndGroupType()
{
    return ag_Attrs;
}

size_t CmsHeaderAttributeGroupImpl::GetAttributeCount() const
{
    return m_attrIndexList.size();
}

const uint32_t& CmsHeaderAttributeGroupImpl::GetAttributeIndex(size_t position) const
{
    if (position >= (int)GetAttributeCount())
        throw new std::range_error("position out of range");

    return m_attrIndexList[position];
}

bool CmsHeaderAttributeGroupImpl::SetAttributeIndex(size_t position, uint32_t setTo)
{
    if (position >= (int)GetAttributeCount())
        return false;

    m_attrIndexList[position] = setTo;
	return true;
}
bool CmsHeaderAttributeGroupImpl::RemoveAttributeIndex(size_t position)
{
    if (position >= (int)GetAttributeCount())
        return false;
	auto it = m_attrIndexList.begin();
	std::advance(it, position);
    m_attrIndexList.erase(it);
    return true;
}

bool CmsHeaderAttributeGroupImpl::AddAttributeIndex(uint32_t  indexInAttributeList)
{
	m_attrIndexList.push_back(indexInAttributeList);
    return true;
}

tscrypto::tsCryptoData CmsHeaderAttributeGroupImpl::GetEncryptedRandom()
{
    return m_encryptedRandom;
}

bool CmsHeaderAttributeGroupImpl::SetEncryptedRandom(const tscrypto::tsCryptoData &setTo)
{
    m_encryptedRandom = setTo;
    return true;
}

