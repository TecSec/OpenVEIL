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

class KTSOAEP : public KtsOaep, public TSName, public Selftest, public tscrypto::ICryptoObject, public tscrypto::IInitializableObject, public AlgorithmInfo
{
public:
    KTSOAEP(const tsCryptoStringBase& algorithm);
    virtual ~KTSOAEP(void);

    // Selftests
    virtual bool runTests(bool runDetailedTests) override;

    // AlgorithmInfo
    virtual tsCryptoString AlgorithmName() const override;
    virtual tsCryptoString AlgorithmOID() const override;
    virtual TS_ALG_ID AlgorithmID() const override;

    // KtsOaep
	virtual bool GenerateBasic(std::shared_ptr<RsaKey> key, const tsCryptoData &keyData, const tsCryptoData &additionalInput, tsCryptoData &outputData) override;
	virtual bool RecoverBasic(std::shared_ptr<RsaKey> key, const tsCryptoData &cipherData, const tsCryptoData &additionalInput, tsCryptoData &keyData) override;

	virtual bool GenerateKeyConfirmation(std::shared_ptr<RsaKey> key, const tsCryptoData &keyData, const tsCryptoData &additionalInput, tsCryptoData &outputData, size_t macKeyLengthInBits) override;
	virtual bool RecoverKeyConfirmation(std::shared_ptr<RsaKey> key, const tsCryptoData &cipherData, const tsCryptoData &additionalInput, size_t macKeyLengthInBits, size_t macTagLength, const tsCryptoStringBase& macName, const tsCryptoData &IDu, const tsCryptoData &IDv, const tsCryptoData &Text, tsCryptoData &keyData, tsCryptoData &macTag) override;
    virtual bool ValidateKeyConfirmation(const tsCryptoStringBase& macName, const tsCryptoData &IDu, const tsCryptoData &IDv, const tsCryptoData &Text, const tsCryptoData &macTag) override;

	virtual bool RecoverKeyConfirmation_Raw(std::shared_ptr<RsaKey> key, const tsCryptoData &cipherData, const tsCryptoData &additionalInput, size_t macKeyLengthInBits, size_t macTagLength, const tsCryptoStringBase& macName, const tsCryptoData &macData, tsCryptoData &keyData, tsCryptoData &macTag) override;
    virtual bool ValidateKeyConfirmation_Raw(const tsCryptoStringBase& macName, const tsCryptoData &macData, const tsCryptoData &macTag) override;

	// tscrypto::IInitializableObject
	virtual bool InitializeWithFullName(const tscrypto::tsCryptoStringBase& fullName) override
	{
		tsCryptoString algorithm(fullName);

		SetName(algorithm);
		if (!(m_alg = std::dynamic_pointer_cast<RsaOAEP>(CryptoFactory("RSA-OAEP"))))
		{
			return false;
		}
		return true;
	}

private:
	std::shared_ptr<RsaOAEP> m_alg;
    tsCryptoData m_macKey;
    tsCryptoData m_C;

    void Clear();
};

tscrypto::ICryptoObject* CreateKtsOaep(const tsCryptoStringBase& algorithm)
{
	return dynamic_cast<tscrypto::ICryptoObject*>(new KTSOAEP(algorithm));
}

KTSOAEP::KTSOAEP(const tsCryptoStringBase& algorithmName)
{
}

KTSOAEP::~KTSOAEP(void)
{
}

bool KTSOAEP::runTests(bool /*runDetailedTests*/)
{
    if (!gFipsState.operational())
        return false;
    // TODO:  See if tests are needed here
    return true;
}

tsCryptoString KTSOAEP::AlgorithmName() const
{
    return GetName();
}

tsCryptoString KTSOAEP::AlgorithmOID() const
{
    return LookUpAlgOID(GetName());
}

TS_ALG_ID KTSOAEP::AlgorithmID() const
{
    return LookUpAlgID(GetName());
}

bool KTSOAEP::GenerateBasic(std::shared_ptr<RsaKey> key, const tsCryptoData &keyData, const tsCryptoData &additionalInput, tsCryptoData &outputData)
{
    if (!gFipsState.operational())
        return false;
    Clear();

    if (!m_alg)
        return false;

    return m_alg->Generate(key, keyData, additionalInput, outputData);
}

bool KTSOAEP::RecoverBasic(std::shared_ptr<RsaKey> key, const tsCryptoData &cipherData, const tsCryptoData &additionalInput, tsCryptoData &keyData)
{
    if (!gFipsState.operational())
        return false;
    Clear();

    if (!m_alg)
        return false;

    return m_alg->Recover(key, cipherData, additionalInput, keyData);
}

bool KTSOAEP::GenerateKeyConfirmation(std::shared_ptr<RsaKey> key, const tsCryptoData &keyData, const tsCryptoData &additionalInput, tsCryptoData &outputData, size_t macKeyLengthInBits)
{
    if (!gFipsState.operational())
        return false;
    if (!m_alg)
        return false;

	if (!GenerateRandom(m_macKey, (macKeyLengthInBits + 7) / 8))
    {
        Clear();
        return false;
    }

    tsCryptoData data;

    data.append(m_macKey).append(keyData);

    if (!m_alg->Generate(key, data, additionalInput, outputData))
    {
        Clear();
        outputData.clear();
        return false;
    }
    m_C = outputData;
    return true;
}

bool KTSOAEP::RecoverKeyConfirmation(std::shared_ptr<RsaKey> key, const tsCryptoData &cipherData, const tsCryptoData &additionalInput, size_t macKeyLengthInBits, size_t macTagLength,
	const tsCryptoStringBase& macName, const tsCryptoData &IDu, const tsCryptoData &IDv, const tsCryptoData &Text, tsCryptoData &keyData, tsCryptoData &macTag)
{
    if (!gFipsState.operational())
        return false;
    if (!m_alg)
        return false;

    tsCryptoData otherData;

    otherData.append("KC_1_V").append(IDv).append(IDu).append(cipherData).append(Text);

    return RecoverKeyConfirmation_Raw(key, cipherData, additionalInput, macKeyLengthInBits, macTagLength, macName, otherData, keyData, macTag);
}

bool KTSOAEP::ValidateKeyConfirmation(const tsCryptoStringBase& macName, const tsCryptoData &IDu, const tsCryptoData &IDv, const tsCryptoData &Text, const tsCryptoData &macTag)
{
    if (!gFipsState.operational())
        return false;
    if (!m_alg || m_C.size() == 0)
        return false;

    tsCryptoData otherData;

    otherData.append("KC_1_V").append(IDv).append(IDu).append(m_C).append(Text);

    return ValidateKeyConfirmation_Raw(macName, otherData, macTag);
}

bool KTSOAEP::RecoverKeyConfirmation_Raw(std::shared_ptr<RsaKey> key, const tsCryptoData &cipherData, const tsCryptoData &additionalInput, size_t macKeyLengthInBits, size_t macTagLength,
	const tsCryptoStringBase& macName, const tsCryptoData &macData, tsCryptoData &keyData, tsCryptoData &macTag)
{
    if (!gFipsState.operational())
        return false;
    if (!m_alg)
        return false;

    tsCryptoData data;
    std::shared_ptr<MessageAuthenticationCode> mac;
    tsCryptoData macOutput;

    if (!m_alg->Recover(key, cipherData, additionalInput, data))
    {
        Clear();
        return false;
    }

    m_macKey = data.substring(0, (macKeyLengthInBits + 7) / 8);
    data.erase(0, m_macKey.size());

	if (!(mac = std::dynamic_pointer_cast<MessageAuthenticationCode>(CryptoFactory(macName))))
    {
        Clear();
        return false;
    }

    if (!mac->initialize(m_macKey) || !mac->update(macData) || !mac->finish(macOutput))
    {
        Clear();
        return false;
    }
    if (macOutput.size() > macTagLength)
        macOutput.resize(macTagLength);
    keyData = data;
    macTag = macOutput;
    return true;
}

bool KTSOAEP::ValidateKeyConfirmation_Raw(const tsCryptoStringBase& macName, const tsCryptoData &macData, const tsCryptoData &macTag)
{
    if (!gFipsState.operational())
        return false;
    if (!m_alg || m_macKey.size() == 0)
        return false;

    std::shared_ptr<MessageAuthenticationCode> mac;
    tsCryptoData macOutput;

	if (!(mac = std::dynamic_pointer_cast<MessageAuthenticationCode>(CryptoFactory(macName))))
    {
        Clear();
        return false;
    }

    if (!mac->initialize(m_macKey) || !mac->update(macData) || !mac->finish(macOutput))
    {
        Clear();
        return false;
    }
    if (macOutput.size() > macTag.size())
        macOutput.resize(macTag.size());

    if (macOutput != macTag)
    {
        Clear();
        return false;
    }
    return true;
}

void KTSOAEP::Clear()
{
    m_macKey.clear();
    m_C.clear();
}

