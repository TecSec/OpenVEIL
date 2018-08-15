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

using namespace tscrypto;

class AEAD : public TSName, public MAC2, public CCM_GCM, public tscrypto::ICryptoObject, public tscrypto::IInitializableObject, public AlgorithmInfo
{
public:
    AEAD();
    virtual ~AEAD(void);

    // CCM
    virtual bool initialize(const tsCryptoData &key) override;
    virtual bool finish() override;
    virtual bool encryptMessage(const tsCryptoData &nonce, const tsCryptoData &header, tsCryptoData &data, size_t requiredTagLength, tsCryptoData &tag) override;
    virtual bool decryptMessage(const tsCryptoData &nonce, const tsCryptoData &header, tsCryptoData &data, const tsCryptoData &tag) override;
    virtual bool startMessage(const tsCryptoData &ivec, uint64_t headerLength, uint64_t messageLength, size_t tagLength) override;
    virtual bool authenticateHeader(const tsCryptoData &header) override;
    virtual bool encrypt(tsCryptoData &data) override;
    virtual bool decrypt(tsCryptoData &data) override;
    virtual bool computeTag(size_t requiredTagLength, tsCryptoData &tag) override;
    virtual bool requiresKey() const override;
    virtual size_t minimumKeySizeInBits() const override;
    virtual size_t maximumKeySizeInBits() const override;
    virtual size_t keySizeIncrementInBits() const override;

    // MAC2
    virtual bool update(const tsCryptoData &data) override;
    virtual bool finish(tsCryptoData &digest) override;
    virtual size_t GetBlockSize() override;
    virtual size_t GetDigestSize() override;
    virtual bool isUsableKey(const tsCryptoData &key) override;
    virtual size_t get_MacLengthInBytes() const override;
    virtual bool set_MacLengthInBytes(size_t setTo) override;
    virtual tsCryptoData get_Nonce() const override;
    virtual bool set_Nonce(const tsCryptoData &setTo) override;

    // AlgorithmInfo
    virtual tsCryptoString AlgorithmName() const override;
    virtual tsCryptoString AlgorithmOID() const override;
    virtual TS_ALG_ID AlgorithmID() const override;

    // tscrypto::IInitializableObject
    virtual bool InitializeWithFullName(const tscrypto::tsCryptoStringBase& fullName) override
    {
        return PrepareClass(fullName);
    }

private:
    SmartCryptoWorkspace m_context;
    const TSIAead* desc;

    tsCryptoString m_baseName;

    // Variables used in the "MessageAuthenticationCode" interface functions
    tsCryptoData m_macData;
    size_t m_tagLen;
    tsCryptoData m_nonce;
    size_t m_keySizeInBits;

    bool PrepareClass(const tsCryptoStringBase& fullName)
    {
        tsCryptoString algorithm(fullName);
        tsCryptoStringList parts;

        m_context.reset();
        desc = TSLookup(TSIAead, algorithm.c_str());
        if (desc == nullptr)
        {
            parts = algorithm.split('-');
            if (parts->size() > 2)
            {
                tsCryptoString name;
                name << parts->at(0) << "-" << parts->at(1);
                desc = TSLookup(TSIAead, name.c_str());
            }
            if (desc == nullptr)
            {
                tsCryptoString name;
                name << parts->at(0) << "-AES";
                desc = TSLookup(TSIAead, name.c_str());
            }
        }
        SetName(algorithm);

        if (desc == nullptr)
            return false;

        m_baseName = GetName();

        return true;
    }
};

tscrypto::ICryptoObject* CreateAEAD()
{
    return dynamic_cast<tscrypto::ICryptoObject*>(new AEAD());
}

AEAD::AEAD() :
    m_tagLen (16),
    m_keySizeInBits(0),
    desc(nullptr)
{
    PrepareClass("GCM-AES");
}

AEAD::~AEAD(void)
{
    m_context.reset();
    desc = nullptr;
}

bool AEAD::initialize(const tsCryptoData &key)
{
    if (!gFipsState.operational())
        return false;
    if (desc == nullptr)
        return false;
    if (key.size() != 16 && key.size() != 24 && key.size() != 32)
        return false;
    if (!isUsableKey(key))
        return false;

    m_keySizeInBits = (int)key.size() * 8;
    m_macData.clear();
    m_tagLen = 16;
    m_nonce.clear();

    m_context.reset();
    m_context = desc->def;

    tsCryptoString name(m_baseName);
    name += "-";
    name.append((key.size() * 8));
    SetName(name);

    return desc->init(m_context, key.c_str(), (uint32_t)key.size());
}

bool AEAD::finish()
{
    m_macData.clear();
    m_tagLen = 16;
    m_nonce.clear();
    m_keySizeInBits = 0;

    if (!gFipsState.operational())
        return false;
    if (desc == nullptr)
        return false;
    if (m_context.empty())
        return false;

    bool retVal = desc->finish(m_context);
    m_context.reset();
    return retVal;
}

bool AEAD::encryptMessage(const tsCryptoData &ivec, const tsCryptoData &header, tsCryptoData &data, size_t requiredTagLength, tsCryptoData &tag)
{
    if (!gFipsState.operational())
        return false;
    if (desc == nullptr)
        return false;
    if (requiredTagLength < desc->minimumTagSize || requiredTagLength > desc->maximumTagSize)
        return false;
    if (desc->tagSizeIncrement > 1 && (requiredTagLength & (desc->tagSizeIncrement - 1)) != 0)
        return false;
    if (m_context.empty())
        return false;

    tag.clear();
    tag.resize(requiredTagLength);

    bool retVal = desc->encryptMessage(m_context, ivec.c_str(), (uint32_t)ivec.size(), header.c_str(), (uint32_t)header.size(), data.rawData(), (uint32_t)data.size(), (uint32_t)requiredTagLength, tag.rawData());

    if (!retVal)
    {
        data.clear();
        tag.clear();
    }
    return retVal;
}

bool AEAD::decryptMessage(const tsCryptoData &ivec, const tsCryptoData &header, tsCryptoData &data, const tsCryptoData &tag)
{
    if (!gFipsState.operational())
        return false;
    if (desc == nullptr)
        return false;
    if (m_context.empty())
        return false;

    bool retVal = desc->decryptMessage(m_context, ivec.c_str(), (uint32_t)ivec.size(), header.c_str(), (uint32_t)header.size(), data.rawData(), (uint32_t)data.size(), tag.c_str(), (uint32_t)tag.size());

    if (!retVal)
    {
        data.clear();
    }
    return retVal;
}

bool AEAD::startMessage(const tsCryptoData &ivec, uint64_t headerLength, uint64_t messageLength, size_t tagLength)
{
    if (!gFipsState.operational())
        return false;
    if (desc == nullptr)
        return false;
    if (m_context.empty())
        return false;

    bool retVal = desc->startMessage(m_context, ivec.c_str(), (uint32_t)ivec.size(), headerLength, messageLength, (uint32_t)tagLength);

    return retVal;
}

bool AEAD::authenticateHeader(const tsCryptoData &header)
{
    if (!gFipsState.operational())
        return false;
    if (desc == nullptr)
        return false;
    if (m_context.empty())
        return false;

    bool retVal = desc->authenticateHeader(m_context, header.c_str(), (uint32_t)header.size());

    return retVal;
}

bool AEAD::encrypt(tsCryptoData &data)
{
    if (!gFipsState.operational())
        return false;
    if (desc == nullptr)
        return false;
    if (m_context.empty())
        return false;

    bool retVal = desc->encrypt(m_context, data.rawData(), (uint32_t)data.size());

    if (!retVal)
    {
        data.clear();
    }
    return retVal;
}

bool AEAD::decrypt(tsCryptoData &data)
{
    if (!gFipsState.operational())
        return false;
    if (desc == nullptr)
        return false;
    if (m_context.empty())
        return false;

    bool retVal = desc->decrypt(m_context, data.rawData(), (uint32_t)data.size());

    if (!retVal)
    {
        data.clear();
    }
    return retVal;
}

bool AEAD::computeTag(size_t requiredTagLength, tsCryptoData &tag)
{
    if (!gFipsState.operational())
        return false;
    if (desc == nullptr)
        return false;
    if (requiredTagLength < 1 || requiredTagLength > 16)
        return false;
    if (m_context.empty())
        return false;

    tag.resize(requiredTagLength);

    bool retVal = desc->computeTag(m_context, (uint32_t)requiredTagLength, tag.rawData());

    if (!retVal)
    {
        tag.clear();
    }
    return retVal;
}

#if 0
bool AEAD::runTests(bool runDetailedTests)
{
    bool testPassed = false;

    if (!gFipsState.operational())
        return false;
    if (desc == nullptr)
        return false;

    std::shared_ptr<TSExtensibleSelfTest> exSelfTest = std::dynamic_pointer_cast<TSExtensibleSelfTest>(CryptoFactory(&m_baseName.c_str()[4]));

    if (!exSelfTest)
        exSelfTest.reset();

    if (!!exSelfTest)
    {
        testPassed = exSelfTest->RunSelfTestsFor("CCM", _me.lock(), runDetailedTests);
    }

    if (!testPassed)
    {
        gFipsState.testFailed();
        return false;
    }
    return true;
}
#endif // 0

tsCryptoString AEAD::AlgorithmName() const
{
    return GetName();
}

tsCryptoString AEAD::AlgorithmOID() const
{
    return LookUpAlgOID(GetName());
}

TS_ALG_ID AEAD::AlgorithmID() const
{
    return LookUpAlgID(GetName());
}

bool AEAD::update(const tsCryptoData &data)
{
    if (!gFipsState.operational())
        return false;
    if (desc == nullptr)
        return false;

    m_macData += data;
    return true;
}

bool AEAD::finish(tsCryptoData &digest)
{
    if (!gFipsState.operational())
        return false;
    if (desc == nullptr)
        return false;

    tsCryptoData tmp;

    return encryptMessage(m_nonce, m_macData, tmp, m_tagLen, digest);
}

size_t AEAD::GetBlockSize()
{
    if (!gFipsState.operational())
        return false;
    if (desc == nullptr)
        return false;

    return 16;
}

size_t AEAD::GetDigestSize()
{
    if (!gFipsState.operational())
        return false;
    if (desc == nullptr)
        return false;

    return desc->maximumTagSize;
}

bool AEAD::isUsableKey(const tsCryptoData &key)
{
    if (!gFipsState.operational())
        return false;
    if (desc == nullptr)
        return false;

    for (uint32_t i = desc->minimumKeySize; i <= desc->maximumKeySize; i += desc->keySizeIncrement)
    {
        if (key.size() * 8 == i)
            return true;
    }
    return false;
}

size_t AEAD::get_MacLengthInBytes() const
{
    if (!gFipsState.operational())
        return false;
    if (desc == nullptr)
        return false;

    return m_tagLen;
}

bool AEAD::set_MacLengthInBytes(size_t setTo)
{
    if (!gFipsState.operational())
        return false;
    if (desc == nullptr)
        return false;

    if (setTo < 4 || setTo > 16 || (setTo & 1) != 0)
        return false;

    m_tagLen = setTo;
    return true;
}

tsCryptoData AEAD::get_Nonce() const
{
    if (!gFipsState.operational())
        return tsCryptoData();
    if (desc == nullptr)
        return tsCryptoData();

    return m_nonce;
}

bool AEAD::set_Nonce(const tsCryptoData &setTo)
{
    if (!gFipsState.operational())
        return false;
    if (desc == nullptr)
        return false;

    m_nonce = setTo;
    return true;
}

bool AEAD::requiresKey() const
{
    return true;
}

size_t AEAD::minimumKeySizeInBits() const
{
    if (desc == nullptr)
        return 0;

    return m_keySizeInBits == 0 ? desc->minimumKeySize : m_keySizeInBits;
}

size_t AEAD::maximumKeySizeInBits() const
{
    if (desc == nullptr)
        return 0;

    return m_keySizeInBits == 0 ? desc->maximumKeySize : m_keySizeInBits;
}

size_t AEAD:: keySizeIncrementInBits() const
{
    if (desc == nullptr)
        return 0;

    return m_keySizeInBits == 0 ? desc->keySizeIncrement : 0;
}
