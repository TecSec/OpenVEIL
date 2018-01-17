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

class RSAKAS2 : public RsaKAS2, public TSName, public Selftest, public tscrypto::ICryptoObject, public tscrypto::IInitializableObject, public AlgorithmInfo
{
public:
    RSAKAS2(const tsCryptoStringBase& algorithm);
    virtual ~RSAKAS2(void);

    // Selftests
    virtual bool runTests(bool runDetailedTests) override;

    // AlgorithmInfo
    virtual tsCryptoString AlgorithmName() const override;
    virtual tsCryptoString AlgorithmOID() const override;
    virtual TS_ALG_ID AlgorithmID() const override;

    // RsaKAS2
    virtual bool initialize(size_t secretLengthInBits, const tsCryptoStringBase& kdfName, const tsCryptoData &IDu, const tsCryptoData &IDv) override;
    virtual bool initializeForConfirmation(size_t secretLengthInBits, const tsCryptoStringBase& kdfName, const tsCryptoData &IDu, const tsCryptoData &IDv, bool forBilateral, const tsCryptoStringBase& macName, size_t macLengthInBytes, size_t macKeyLengthInBits) override;
	virtual bool finish() override;

	virtual bool GenerateFirstPart(std::shared_ptr<RsaKey> keyPartyV, tsCryptoData &partOneToRecipient) override;
	virtual bool GenerateSecondPart(std::shared_ptr<RsaKey> keyPartyU, std::shared_ptr<RsaKey> keyPartyV, const tsCryptoData &partOneToRecipient, tsCryptoData &partTwoToOriginator) override;
	virtual bool ReceiveSecondPart(std::shared_ptr<RsaKey> keyPartyU, const tsCryptoData &partTwoFromRecipient) override;

    virtual bool GenerateOriginatorMac(const tsCryptoData &optionalData, tsCryptoData &macTag) override;
    virtual bool GenerateRecipientMac(const tsCryptoData &optionalData, tsCryptoData &macTag) override;
    virtual bool ValidateOriginatorMac(const tsCryptoData &optionalData, const tsCryptoData &macTag) override;
    virtual bool ValidateRecipientMac(const tsCryptoData &optionalData, const tsCryptoData &macTag) override;
    virtual tsCryptoData GetSecret(const tsCryptoData &optionalData) override;

    virtual bool GenerateOriginatorMac_Raw(const tsCryptoData &otherData, tsCryptoData &macTag) override;
    virtual bool GenerateRecipientMac_Raw(const tsCryptoData &otherData, tsCryptoData &macTag) override;
    virtual bool ValidateOriginatorMac_Raw(const tsCryptoData &otherData, const tsCryptoData &macTag) override;
    virtual bool ValidateRecipientMac_Raw(const tsCryptoData &otherData, const tsCryptoData &macTag) override;
    virtual tsCryptoData GetSecret_Raw(const tsCryptoData &otherData) override;

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
    tsCryptoData m_Zu, m_Zv;
    tsCryptoData m_Cu, m_Cv;
	std::shared_ptr<KeyDerivationFunction> m_kdf;
	std::shared_ptr<MessageAuthenticationCode> m_mac;
	std::shared_ptr<RsaSVE> m_sve;
    size_t m_secretLengthInBits;
    size_t m_macKeyLengthInBits;
    size_t m_macTagLengthInBytes;
    bool m_forBilateral;
    bool m_validatedOriginator;
    bool m_validatedRecipient;

    tsCryptoData m_secret;
    tsCryptoData m_macKey;

    bool GenerateKeys(const tsCryptoData &optionalData);
    bool GenerateKeys_Raw(const tsCryptoData &otherData);
};

RSAKAS2::RSAKAS2(const tsCryptoStringBase& algorithm) :
    m_secretLengthInBits(0),
    m_macKeyLengthInBits(0),
    m_macTagLengthInBytes(0),
    m_forBilateral(false),
    m_validatedOriginator(false),
    m_validatedRecipient(false)
{
}

tscrypto::ICryptoObject* CreateRsaKAS2(const tsCryptoStringBase& algorithm)
{
	return dynamic_cast<tscrypto::ICryptoObject*>(new RSAKAS2(algorithm));
}

RSAKAS2::~RSAKAS2(void)
{
}

bool RSAKAS2::runTests(bool /*runDetailedTests*/)
{
    if (!gFipsState.operational())
        return false;
    // TODO:  See if tests are needed here
    return true;
}

tsCryptoString RSAKAS2::AlgorithmName() const
{
    return GetName();
}

tsCryptoString RSAKAS2::AlgorithmOID() const
{
    return LookUpAlgOID(GetName());
}

TS_ALG_ID RSAKAS2::AlgorithmID() const
{
    return LookUpAlgID(GetName());
}

bool RSAKAS2::initialize(size_t secretLengthInBits, const tsCryptoStringBase& kdfName, const tsCryptoData &IDu, const tsCryptoData &IDv)
{
    if (!gFipsState.operational())
        return false;

    finish();

    m_secretLengthInBits = secretLengthInBits;
    m_IDu = IDu;
    m_IDv = IDv;

    if (!(m_kdf = std::dynamic_pointer_cast<KeyDerivationFunction>(CryptoFactory(kdfName))) ||
		!m_kdf->initialize())
    {
        finish();
        return false;
    }
	if (!(m_sve = std::dynamic_pointer_cast<RsaSVE>(CryptoFactory("RSASVE"))))
    {
        finish();
        return false;
    }
    return true;
}

bool RSAKAS2::initializeForConfirmation(size_t secretLengthInBits, const tsCryptoStringBase& kdfName, const tsCryptoData &IDu, const tsCryptoData &IDv, bool forBilateral, const tsCryptoStringBase& macName, size_t macLengthInBytes, size_t macKeyLengthInBits)
{
    if (!gFipsState.operational())
        return false;

    finish();

    m_secretLengthInBits = secretLengthInBits;
    m_IDu = IDu;
    m_IDv = IDv;
    m_macKeyLengthInBits = macKeyLengthInBits;
    m_macTagLengthInBytes = macLengthInBytes;
    m_forBilateral = forBilateral;

	if (!(m_kdf = std::dynamic_pointer_cast<KeyDerivationFunction>(CryptoFactory(kdfName))) ||
		!m_kdf->initialize() ||
		!(m_mac = std::dynamic_pointer_cast<MessageAuthenticationCode>(CryptoFactory(macName))) ||
		!(m_sve = std::dynamic_pointer_cast<RsaSVE>(CryptoFactory("RSASVE"))))
    {
        finish();
        return false;
    }

    return true;
}

bool RSAKAS2::finish()
{
    if (!gFipsState.operational())
        return false;
    m_IDu.clear();
    m_IDv.clear();
    m_Zu.clear();
    m_Zv.clear();
    m_Cu.clear();
    m_Cv.clear();
    m_kdf.reset();
    m_mac.reset();
    m_sve.reset();
    m_secretLengthInBits = 0;
    m_macKeyLengthInBits = 0;
    m_macTagLengthInBytes = 0;
    m_forBilateral = false;
    m_validatedOriginator = false;
    m_validatedRecipient = false;

    m_secret.clear();
    m_macKey.clear();

    return true;
}

bool RSAKAS2::GenerateFirstPart(std::shared_ptr<RsaKey> keyPartyV, tsCryptoData &partOneToRecipient)
{
    if (!gFipsState.operational())
        return false;
    if (!m_kdf || !m_sve)
        return false;

    if (!m_sve->Generate(keyPartyV, m_Zu, m_Cu))
    {
        finish();
        return false;
    }
    partOneToRecipient = m_Cu;
    return true;
}

bool RSAKAS2::GenerateSecondPart(std::shared_ptr<RsaKey> keyPartyU, std::shared_ptr<RsaKey> keyPartyV, const tsCryptoData &partOneToRecipient, tsCryptoData &partTwoToOriginator)
{
    if (!gFipsState.operational())
        return false;
    if (!m_kdf || !m_sve)
        return false;

    m_Cu = partOneToRecipient;
    if (!m_sve->Recover(keyPartyV, m_Cu, m_Zu) || !m_sve->Generate(keyPartyU, m_Zv, m_Cv))
    {
        finish();
        return false;
    }
    partTwoToOriginator = m_Cv;
    return true;
}

bool RSAKAS2::ReceiveSecondPart(std::shared_ptr<RsaKey> keyPartyU, const tsCryptoData &partTwoFromRecipient)
{
    if (!gFipsState.operational())
        return false;
    if (!m_kdf || !m_sve)
        return false;

    m_Cv = partTwoFromRecipient;
    if (!m_sve->Recover(keyPartyU, m_Cv, m_Zv))
    {
        finish();
        return false;
    }
    return true;
}

bool RSAKAS2::GenerateOriginatorMac(const tsCryptoData &optionalData, tsCryptoData &macTag)
{
    if (!gFipsState.operational())
        return false;
    tsCryptoData otherData;

    if (!m_kdf || !m_sve || !m_mac || m_Cu.size() == 0 || m_Cv.size() == 0 || m_IDu.size() == 0 || m_IDv.size() == 0)
        return false;

    if (m_forBilateral)
    {
        otherData = "KC_2_U";
    }
    else
    {
        otherData = "KC_1_U";
    }
    otherData.append(m_IDu).append(m_IDv).append(m_Cu).append(m_Cv).append(optionalData);
    return GenerateOriginatorMac_Raw(otherData, macTag);
}

bool RSAKAS2::GenerateRecipientMac(const tsCryptoData &optionalData, tsCryptoData &macTag)
{
    if (!gFipsState.operational())
        return false;
    tsCryptoData otherData;

    if (!m_kdf || !m_sve || !m_mac || m_Cu.size() == 0 || m_Cv.size() == 0 || m_IDu.size() == 0 || m_IDv.size() == 0)
        return false;

    if (m_forBilateral)
    {
        otherData = "KC_2_V";
    }
    else
    {
        otherData = "KC_1_V";
    }
    otherData.append(m_IDv).append(m_IDu).append(m_Cv).append(m_Cu).append(optionalData);
    return GenerateRecipientMac_Raw(otherData, macTag);
}

bool RSAKAS2::ValidateOriginatorMac(const tsCryptoData &optionalData, const tsCryptoData &macTag)
{
    if (!gFipsState.operational())
        return false;
    tsCryptoData mac;

    if (!m_kdf || !m_sve)
        return false;

    if (!GenerateOriginatorMac(optionalData, mac) || mac != macTag)
    {
        m_validatedOriginator = false;
        finish();
        return false;
    }
    m_validatedOriginator = true;
    return true;
}

bool RSAKAS2::ValidateRecipientMac(const tsCryptoData &optionalData, const tsCryptoData &macTag)
{
    if (!gFipsState.operational())
        return false;
    tsCryptoData mac;

    if (!m_kdf || !m_sve)
        return false;

    if (!GenerateRecipientMac(optionalData, mac) || mac != macTag)
    {
        finish();
        return false;
    }
    m_validatedRecipient = true;
    return true;
}

tsCryptoData RSAKAS2::GetSecret(const tsCryptoData &optionalData)
{
    if (!m_kdf || !m_sve)
        return tsCryptoData();

    if (!!m_mac)
    {
        if (!m_validatedOriginator || !m_validatedRecipient)
            return tsCryptoData();
    }

    if (!GenerateKeys(optionalData))
    {
        finish();
        return tsCryptoData();
    }
    return m_secret;
}

bool RSAKAS2::GenerateOriginatorMac_Raw(const tsCryptoData &otherData, tsCryptoData &macTag)
{
    if (!gFipsState.operational())
        return false;
    tsCryptoData mac;

    if (!m_kdf || !m_sve)
        return false;

    if (!GenerateKeys_Raw(otherData))
    {
        finish();
        return false;
    }
    if (!m_mac->initialize(m_macKey) || !m_mac->update(otherData) || !m_mac->finish(mac))
    {
        finish();
        return false;
    }
    m_validatedOriginator = true;
    if (!m_forBilateral)
        m_validatedRecipient = true;

    macTag = mac;
    if (macTag.size() > m_macTagLengthInBytes)
    {
        macTag.resize(m_macTagLengthInBytes);
    }
    return true;
}

bool RSAKAS2::GenerateRecipientMac_Raw(const tsCryptoData &otherData, tsCryptoData &macTag)
{
    if (!gFipsState.operational())
        return false;
    tsCryptoData mac;

    if (!m_kdf || !m_sve)
        return false;

    if (!GenerateKeys_Raw(otherData))
    {
        finish();
        return false;
    }
    if (!m_mac->initialize(m_macKey) || !m_mac->update(otherData) || !m_mac->finish(mac))
    {
        finish();
        return false;
    }

    m_validatedRecipient = true;
    if (!m_forBilateral)
        m_validatedOriginator = true;

    macTag = mac;
    if (macTag.size() > m_macTagLengthInBytes)
    {
        macTag.resize(m_macTagLengthInBytes);
    }
    return true;
}

bool RSAKAS2::ValidateOriginatorMac_Raw(const tsCryptoData &otherData, const tsCryptoData &macTag)
{
    if (!gFipsState.operational())
        return false;
    tsCryptoData mac;

    if (!m_kdf || !m_sve)
        return false;

    if (!GenerateOriginatorMac_Raw(otherData, mac))
    {
        finish();
        return false;
    }
    m_validatedOriginator = false;
    if (mac != macTag)
    {
        finish();
        return false;
    }
    m_validatedOriginator = true;
    return true;
}

bool RSAKAS2::ValidateRecipientMac_Raw(const tsCryptoData &otherData, const tsCryptoData &macTag)
{
    if (!gFipsState.operational())
        return false;
    tsCryptoData mac;

    if (!m_kdf || !m_sve)
        return false;

    if (!GenerateRecipientMac_Raw(otherData, mac))
    {
        finish();
        return false;
    }
    m_validatedRecipient = false;
    if (mac != macTag)
    {
        finish();
        return false;
    }
    m_validatedRecipient = true;
    return true;
}

tsCryptoData RSAKAS2::GetSecret_Raw(const tsCryptoData &otherData)
{
    if (!m_kdf || !m_sve)
        return tsCryptoData();

    if (!!m_mac)
    {
        if (!m_validatedOriginator || !m_validatedRecipient)
            return tsCryptoData();
    }

    if (!GenerateKeys_Raw(otherData))
    {
        finish();
        return tsCryptoData();
    }
    return m_secret;
}

bool RSAKAS2::GenerateKeys(const tsCryptoData &optionalData)
{
    if (!gFipsState.operational())
        return false;
    tsCryptoData otherData;

    otherData.append(m_IDu).append(m_IDv).append(optionalData);
    return GenerateKeys_Raw(otherData);
}

bool RSAKAS2::GenerateKeys_Raw(const tsCryptoData &otherData)
{
    if (!gFipsState.operational())
        return false;
    if (!m_kdf || m_Zu.size() == 0 || m_Zv.size() == 0)
        return false;

    if (m_secret.size() > 0)
        return true;

    tsCryptoData Z;
    tsCryptoData output;

    Z.append(m_Zu).append(m_Zv);

    if (!!m_mac)
    {
        if (!m_kdf->Derive_SP800_56A_Counter(Z, otherData, (((m_secretLengthInBits + 7) / 8) * 8) + (((m_macKeyLengthInBits + 7) / 8) * 8), output))
        {
            finish();
            return false;
        }
        m_macKey = output.substring(0, (m_macKeyLengthInBits + 7) / 8);
        output.erase(0, m_macKey.size());
        m_secret = output;
    }
    else
    {
        if (!m_kdf->Derive_SP800_56A_Counter(Z, otherData, m_secretLengthInBits, output))
        {
            finish();
            return false;
        }
        m_secret = output;
    }
    return true;
}

