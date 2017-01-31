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


#include "stdafx.h"
#include "TSALG.h"

using namespace tscrypto;

class RSAKAS1 : public RsaKAS1, public TSName, public Selftest, public tscrypto::ICryptoObject, public tscrypto::IInitializableObject, public AlgorithmInfo
{
public:
    RSAKAS1(const tsCryptoStringBase& algorithm);
    virtual ~RSAKAS1(void);

    // Selftests
    virtual bool runTests(bool runDetailedTests) override;

    // AlgorithmInfo
    virtual tsCryptoString AlgorithmName() const override;
    virtual tsCryptoString AlgorithmOID() const override;
    virtual TS_ALG_ID AlgorithmID() const override;

    // RsaKAS1
    virtual bool initialize(const tsCryptoData &IDu, const tsCryptoData &IDv, bool hasText, const tsCryptoData &Text, size_t macKeyLengthInBits, const tsCryptoStringBase& MACAlgorithmName) override;
    virtual bool finish() override;
	virtual bool GenerateFirstPart(std::shared_ptr<RsaKey> key, tsCryptoData &partOneToRecipient) override;
	virtual bool RecoverPartOne(std::shared_ptr<RsaKey> key, const tsCryptoData &partOneFromOriginator, tsCryptoData &nonceToOriginator) override;
    virtual bool ComputeSecretForOriginator(const tsCryptoData &nonce, const tsCryptoStringBase& KDFname, size_t secretBitLength, tsCryptoData &secret) override;
    virtual bool ComputeSecretForRecipient(const tsCryptoStringBase& KDFname, size_t secretBitLength, tsCryptoData &secret) override;
    virtual bool ComputeSecretAndValidateMac(const tsCryptoData &nonce, const tsCryptoStringBase& KDFname, size_t secretBitLength, const tsCryptoData &macTag, tsCryptoData &secret) override;
    virtual bool ComputeSecretAndMac(const tsCryptoData &nonce, const tsCryptoStringBase& KDFname, size_t secretBitLength, tsCryptoData &secret, tsCryptoData &macTag) override;
    virtual bool ComputeSecret_Raw(const tsCryptoData &otherInfo, const tsCryptoStringBase& KDFname, size_t secretBitLength, tsCryptoData &secret) override;
    virtual bool ComputeSecretAndValidateMac_Raw(const tsCryptoData &otherInfo, const tsCryptoStringBase& KDFname, size_t secretBitLength, const tsCryptoData &macTag, tsCryptoData &secret) override;
    virtual bool ComputeSecretAndMac_Raw(const tsCryptoData &otherInfo, const tsCryptoStringBase& KDFname, size_t secretBitLength, tsCryptoData &secret, tsCryptoData &macTag) override;

	// tscrypto::IInitializableObject
	virtual bool InitializeWithFullName(const tscrypto::tsCryptoStringBase& fullName) override
	{
		tsCryptoString algorithm(fullName);

		SetName(algorithm);
		return true;
	}

private:
    tsCryptoData m_IDu;
    tsCryptoData m_IDv;
    bool m_hasText;
    tsCryptoData m_Text;
    size_t m_macKeyLengthInBits;
	std::shared_ptr<MessageAuthenticationCode> m_mac;
    tsCryptoData m_Z;
    tsCryptoData m_C;
    tsCryptoData m_nonce;
};

tscrypto::ICryptoObject* CreateRsaKAS1(const tsCryptoStringBase& algorithm)
{
	return dynamic_cast<tscrypto::ICryptoObject*>(new RSAKAS1(algorithm));
}

RSAKAS1::RSAKAS1(const tsCryptoStringBase& algorithm) :
    m_hasText(false),
    m_macKeyLengthInBits(0)
{
}

RSAKAS1::~RSAKAS1(void)
{
}

bool RSAKAS1::runTests(bool /*runDetailedTests*/)
{
    if (!gFipsState.operational())
        return false;
    // TODO:  See if tests are needed here
    return true;
}

tsCryptoString RSAKAS1::AlgorithmName() const
{
    return GetName();
}

tsCryptoString RSAKAS1::AlgorithmOID() const
{
    return LookUpAlgOID(GetName());
}

TS_ALG_ID RSAKAS1::AlgorithmID() const
{
    return LookUpAlgID(GetName());
}

bool RSAKAS1::initialize(const tsCryptoData &IDu, const tsCryptoData &IDv, bool hasText, const tsCryptoData &Text, size_t macKeyLengthInBits, const tsCryptoStringBase& MACAlgorithmName)
{
    if (!gFipsState.operational())
        return false;

    finish();

    m_IDu = IDu;
    m_IDv = IDv;
    m_hasText = hasText;
    m_Text = Text;
    m_macKeyLengthInBits = macKeyLengthInBits;

    if (MACAlgorithmName.size() == 0)
    {
        if (macKeyLengthInBits != 0)
            return false;
        return true;
    }
	if (!(m_mac = std::dynamic_pointer_cast<MessageAuthenticationCode>(CryptoFactory(MACAlgorithmName))))
        return false;
    return true;
}

bool RSAKAS1::finish()
{
    if (!gFipsState.operational())
        return false;
    m_IDu.clear();
    m_IDv.clear();
    m_hasText = false;
    m_Text.clear();
    m_macKeyLengthInBits = 0;
    m_mac.reset();
    m_Z.clear();
    m_C.clear();
    m_nonce.clear();

    return true;
}

bool RSAKAS1::GenerateFirstPart(std::shared_ptr<RsaKey> key, tsCryptoData &partOneToRecipient)
{
    if (!gFipsState.operational())
        return false;
    std::shared_ptr<RsaSVE> sve;

	if (!(sve = std::dynamic_pointer_cast<RsaSVE>(CryptoFactory("RSASVE"))))
    {
		finish();
        return false;
    }

    if (!sve->Generate(key, m_Z, m_C))
    {
		finish();
        return false;
    }
    partOneToRecipient = m_C;
    return true;
}

bool RSAKAS1::RecoverPartOne(std::shared_ptr<RsaKey> key, const tsCryptoData &partOneFromOriginator, tsCryptoData &nonceToOriginator)
{
    if (!gFipsState.operational())
        return false;
    std::shared_ptr<RsaSVE> sve;

	if (!(sve = std::dynamic_pointer_cast<RsaSVE>(CryptoFactory("RSASVE"))))
    {
		finish();
        return false;
    }

    if (!sve->Recover(key, partOneFromOriginator, m_Z))
    {
		finish();
        return false;
    }
    m_C = partOneFromOriginator;

	if (!GenerateRandom(m_nonce, 32))
    {
		finish();
        return false;
    }

    nonceToOriginator = m_nonce;
    return true;
}

bool RSAKAS1::ComputeSecretForOriginator(const tsCryptoData &nonce, const tsCryptoStringBase& KDFname, size_t secretBitLength, tsCryptoData &secret)
{
    if (!gFipsState.operational())
        return false;
    tsCryptoData otherInfo;

    m_nonce = nonce;
    otherInfo += m_IDu;
    otherInfo += m_IDv;
    otherInfo += m_nonce;
    if (m_hasText)
        otherInfo += m_Text;

    if (!ComputeSecret_Raw(otherInfo, KDFname, secretBitLength, secret))
    {
		finish();
        return false;
    }
    return true;
}

bool RSAKAS1::ComputeSecretForRecipient(const tsCryptoStringBase& KDFname, size_t secretBitLength, tsCryptoData &secret)
{
    if (!gFipsState.operational())
        return false;
    tsCryptoData otherInfo;

    otherInfo += m_IDu;
    otherInfo += m_IDv;
    otherInfo += m_nonce;
    if (m_hasText)
        otherInfo += m_Text;

    if (!ComputeSecret_Raw(otherInfo, KDFname, secretBitLength, secret))
    {
		finish();
        return false;
    }
    return true;
}

bool RSAKAS1::ComputeSecretAndValidateMac(const tsCryptoData &nonce, const tsCryptoStringBase& KDFname, size_t secretBitLength, const tsCryptoData &macTag, tsCryptoData &secret)
{
    if (!gFipsState.operational())
        return false;
    tsCryptoData otherInfo;

    secret.clear();
    if (m_macKeyLengthInBits == 0 || !m_mac)
    {
		finish();
        return false;
    }

    m_nonce = nonce;
    otherInfo += m_IDu;
    otherInfo += m_IDv;
    otherInfo += m_nonce;
    if (m_hasText)
        otherInfo += m_Text;

    if (!ComputeSecretAndValidateMac_Raw(otherInfo, KDFname, secretBitLength, macTag, secret))
    {
        secret.clear();
		finish();
        return false;
    }
    return true;
}

bool RSAKAS1::ComputeSecretAndMac(const tsCryptoData &nonce, const tsCryptoStringBase& KDFname, size_t secretBitLength, tsCryptoData &secret, tsCryptoData &macTag)
{
    if (!gFipsState.operational())
        return false;
    tsCryptoData otherInfo;

    secret.clear();
    if (m_macKeyLengthInBits == 0 || !m_mac)
    {
		finish();
        return false;
    }

    m_nonce = nonce;
    otherInfo += m_IDu;
    otherInfo += m_IDv;
    otherInfo += m_nonce;
    if (m_hasText)
        otherInfo += m_Text;

    if (!ComputeSecretAndMac_Raw(otherInfo, KDFname, secretBitLength, secret, macTag))
    {
        secret.clear();
		finish();
        return false;
    }
    return true;
}

bool RSAKAS1::ComputeSecret_Raw(const tsCryptoData &otherInfo, const tsCryptoStringBase& KDFname, size_t secretBitLength, tsCryptoData &secret)
{
    if (!gFipsState.operational())
        return false;
    std::shared_ptr<KeyDerivationFunction> kdf;

	if (!(kdf = std::dynamic_pointer_cast<KeyDerivationFunction>(CryptoFactory(KDFname))))
    {
		finish();
        return false;
    }

    if (!kdf->initialize() || !kdf->Derive_SP800_56A_Counter(m_Z, otherInfo, secretBitLength, secret))
    {
        secret.clear();
		finish();
        return false;
    }
    return true;
}

bool RSAKAS1::ComputeSecretAndValidateMac_Raw(const tsCryptoData &otherInfo, const tsCryptoStringBase& KDFname, size_t secretBitLength, const tsCryptoData &macTag, tsCryptoData &secret)
{
    if (!gFipsState.operational())
        return false;
    tsCryptoData mac;
    tsCryptoData mySecret;

    secret.clear();
    if (!ComputeSecretAndMac_Raw(otherInfo, KDFname, secretBitLength, mac, mySecret))
    {
		finish();
        return false;
    }
    if (mac != macTag)
    {
        secret.clear();
		finish();
        return false;
    }
    secret = mySecret;
    return true;
}

bool RSAKAS1::ComputeSecretAndMac_Raw(const tsCryptoData &otherInfo, const tsCryptoStringBase& KDFname, size_t secretBitLength, tsCryptoData &secret, tsCryptoData &macTag)
{
    if (!gFipsState.operational())
        return false;
    tsCryptoData macKey;
    tsCryptoData macData("KC_1_V", tsCryptoData::ASCII);
    tsCryptoData mac;
    tsCryptoData mySecret;

    secret.clear();
    if (m_macKeyLengthInBits == 0 || !m_mac)
    {
		finish();
        return false;
    }

    if (!ComputeSecret_Raw(otherInfo, KDFname, (((secretBitLength + 7) / 8) * 8) + (((m_macKeyLengthInBits + 7) / 8) * 8), mySecret))
    {
		finish();
        return false;
    }

    macKey = mySecret.substring(0, (m_macKeyLengthInBits + 7) / 8);
    mySecret.erase(0, macKey.size());

    macData += m_IDu;
    macData += m_IDv;
    macData += m_nonce;
    macData += m_C;
    if (m_hasText)
        macData += m_Text;

	if (!m_mac->initialize(macKey) || !m_mac->update(macData) || !m_mac->finish(mac))
    {
        secret.clear();
		finish();
        return false;
    }
    macTag = mac;
    secret = mySecret;
    return true;
}

