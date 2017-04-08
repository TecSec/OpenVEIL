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

using namespace tscrypto;

class KeyWrap_RFC3217 : public TSName, public Selftest,
	public KeyTransport, public tscrypto::ICryptoObject, public tscrypto::IInitializableObject, public AlgorithmInfo
{
public:
    KeyWrap_RFC3217(const tsCryptoStringBase& algorithm);
    virtual ~KeyWrap_RFC3217(void);

    // KeyTransport
    virtual bool initializeWithSymmetricKey(const tsCryptoData &key) override;
	virtual bool initializeWithAsymmetricKey(std::shared_ptr<tscrypto::ICryptoObject> key);
    virtual bool Wrap(const tsCryptoData &inputData, const tsCryptoData &pad, tsCryptoData &outputData) override;
    virtual bool Unwrap(const tsCryptoData &inputData, const tsCryptoData &pad, tsCryptoData &outputData) override;
    virtual bool CanWrap(const tsCryptoData &keyToWrap) override;
    virtual bool CanUnwrap(const tsCryptoData &keyToUnwrap) override;
	virtual size_t minimumKeySizeInBits() const override;
	virtual size_t maximumKeySizeInBits() const override;
	virtual size_t keySizeIncrementInBits() const override;

    // Selftest
    virtual bool runTests(bool runDetailedTests) override;

    // AlgorithmInfo
    virtual tsCryptoString AlgorithmName() const override;
    virtual tsCryptoString AlgorithmOID() const override;
    virtual TS_ALG_ID AlgorithmID() const override;

	// tscrypto::IInitializableObject
	virtual bool InitializeWithFullName(const tscrypto::tsCryptoStringBase& fullName) override
	{
		tsCryptoString algorithm(fullName);

		SetName(algorithm);
		if (algorithm.size() > 9)
		{
			if (!(m_cipher = std::dynamic_pointer_cast<Symmetric>(CryptoFactory(&algorithm.c_str()[8]))))
			{
				return false;
			}
		}
		else
		{
			if (!(m_cipher = std::dynamic_pointer_cast<Symmetric>(CryptoFactory("TDES"))))
			{
				return false;
			}
			SetName("KEYWRAP-TDES");
		}
		if (!!m_cipher && m_cipher->getBlockSize() != 8)
			m_cipher.reset();

		if (!(m_hasher = std::dynamic_pointer_cast<Hash>(CryptoFactory("SHA1"))))
		{
			m_cipher.reset();
			return false;
		}
		return true;
	}

private:
	std::shared_ptr<Symmetric> m_cipher;
	std::shared_ptr<Hash> m_hasher;
    tsCryptoData m_key;
};

tscrypto::ICryptoObject* CreateKeyWrapRFC3217(const tsCryptoStringBase& algorithm)
{
	return dynamic_cast<tscrypto::ICryptoObject*>(new KeyWrap_RFC3217(algorithm));
}

KeyWrap_RFC3217::KeyWrap_RFC3217(const tsCryptoStringBase& algorithm)
{
}

KeyWrap_RFC3217::~KeyWrap_RFC3217(void)
{
}

bool KeyWrap_RFC3217::initializeWithSymmetricKey(const tsCryptoData &key)
{
    if (!gFipsState.operational())
        return false;
    if (!m_cipher || !m_hasher)
        return false;

    if (!m_cipher->isUsableKey(key))
        return false;

    m_key = key;

    return true;
}

bool KeyWrap_RFC3217::initializeWithAsymmetricKey(std::shared_ptr<tscrypto::ICryptoObject> /*key*/)
{
    return false; // not supported for RFC 3217
}

bool KeyWrap_RFC3217::Wrap(const tsCryptoData &inputData, const tsCryptoData & /*pad*/, tsCryptoData &outputData)
{
    if (!gFipsState.operational())
        return false;
    if (!m_cipher || !m_hasher)
        return false;
    if (!m_cipher->isUsableKey(m_key))
        return false;
    if (inputData.size() != 24) // only supporting TDes wrapping in this module
        return false;

    tsCryptoData CEK(inputData);
    tsCryptoData ICV;
    tsCryptoData CEKICV;
    tsCryptoData IV;
    tsCryptoData TEMP1;
    tsCryptoData TEMP2;
    tsCryptoData TEMP3;
	tsCryptoData finalData;

    //The Triple-DES key wrap algorithm encrypts a Triple-DES key with a Triple-DES key-encryption key. The Triple-DES key wrap algorithm is:

    // 1. Set odd parity for each of the DES key octets comprising the Three-Key Triple-DES key that is to be wrapped, call the result CEK.
    FixTDESParityBits(CEK);

    // 2. Compute an 8 octet key checksum value on CEK as described above in Section 2, call the result ICV.
    if (!m_hasher->initialize() || !m_hasher->update(CEK) || !m_hasher->finish(ICV))
        return false;

    ICV.resize(8);

    //   3. Let CEKICV = CEK || ICV.
    CEKICV.append(CEK).append(ICV);

    //   4. Generate 8 octets at random, call the result IV.
	std::shared_ptr<Random> prng = std::dynamic_pointer_cast<Random>(CryptoFactory("Random"));

	if (!prng || !prng->Initialize(256, true, tsCryptoData(), tsCryptoData()) || !prng->Generate(64, 112, false, tsCryptoData("RFC3217 Key Wrap", tsCryptoData::ASCII), IV))
        return false;

    //   5. Encrypt CEKICV in CBC mode using the key-encryption key.  Use the
    //      random value generated in the previous step as the initialization
    //      vector (IV).  Call the ciphertext TEMP1.
    if (!m_cipher->init(true, _SymmetricMode::CKM_SymMode_CBC, m_key, IV) ||
        !m_cipher->update(CEKICV, TEMP1))
    {
        m_cipher->finish(finalData);
        return false;
    }
    m_cipher->finish(finalData);

    //   6. Let TEMP2 = IV || TEMP1.
    TEMP2.append(IV).append(TEMP1);

    //   7. Reverse the order of the octets in TEMP2.  That is, the most
    //      significant (first) octet is swapped with the least significant
    //      (last) octet, and so on.  Call the result TEMP3.
    TEMP3 = TEMP2;
    TEMP3.reverse();

    //   8. Encrypt TEMP3 in CBC mode using the key-encryption key.  Use an
    //      initialization vector (IV) of 0x4adda22c79e82105.  The ciphertext
    //      is 40 octets long.
    static BYTE iv2[] = {0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05};
    IV.assign(iv2, sizeof(iv2));

    outputData.clear();
    if (!m_cipher->init(true, _SymmetricMode::CKM_SymMode_CBC, m_key, IV) ||
        !m_cipher->update(TEMP3, outputData))
    {
        outputData.clear();
        m_cipher->finish(finalData);
        return false;
    }
    m_cipher->finish(finalData);
    return true;
}

bool KeyWrap_RFC3217::Unwrap(const tsCryptoData &inputData, const tsCryptoData & /*pad*/, tsCryptoData &outputData)
{
    tsCryptoData CEK;
    tsCryptoData ICVcomputed;
    tsCryptoData ICV;
    tsCryptoData CEKICV;
    tsCryptoData IV;
    tsCryptoData TEMP1;
    tsCryptoData TEMP2;
    tsCryptoData TEMP3;
	tsCryptoData finalData;

    if (!gFipsState.operational())
        return false;
    if (!m_cipher || !m_hasher)
        return false;
    if (!m_cipher->isUsableKey(m_key))
        return false;

    //The Triple-DES key unwrap algorithm decrypts a Triple-DES key using a Triple-DES key-encryption key. The Triple-DES key unwrap algorithm is:

    //1 If the wrapped key is not 40 octets, then error.
    if (inputData.size() != 40) // Only supporting TDES wrapping in this module
        return false;

    //2. Decrypt the wrapped key in CBC mode using the key-encryption key. Use an initialization vector (IV) of 0x4adda22c79e82105. Call the output TEMP3.
    static BYTE iv2[] = {0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05};

    IV.assign(iv2, sizeof(iv2));
    if (!m_cipher->init(false, _SymmetricMode::CKM_SymMode_CBC, m_key, IV) ||
        !m_cipher->update(inputData, TEMP3))
    {
        m_cipher->finish(finalData);
        return false;
    }
    m_cipher->finish(finalData);

    //3 Reverse the order of the octets in TEMP3. That is, the most
    //significant (first) octet is swapped with the least significant (last) octet, and so on. Call the result TEMP2.
    TEMP2 = TEMP3;
    TEMP2.reverse();

    //4 Decompose TEMP2 into IV and TEMP1. IV is the most significant
    //(first) 8 octets, and TEMP1 is the least significant (last) 32 octets.
    IV = TEMP2;
    IV.resize(8);
    TEMP1 = TEMP2;
    TEMP1.erase(0, 8);

    //5 Decrypt TEMP1 in CBC mode using the key-encryption key. Use the
    //IV value from the previous step as the initialization vector. Call the ciphertext CEKICV.
    if (!m_cipher->init(false, _SymmetricMode::CKM_SymMode_CBC, m_key, IV) ||
        !m_cipher->update(TEMP1, CEKICV))
    {
        m_cipher->finish(finalData);
        return false;
    }
    m_cipher->finish(finalData);

    //6 Decompose CEKICV into CEK and ICV. CEK is the most significant
    //(first) 24 octets, and ICV is the least significant (last) 8 octets.
    CEK = CEKICV;
    CEK.resize(24);
    ICV = CEKICV;
    ICV.erase(0, 24);

    //7 Compute an 8 octet key checksum value on CEK as described above in
    //Section 2. If the computed key checksum value does not match the decrypted key checksum value, ICV, then error.
    if (!m_hasher->initialize() || !m_hasher->update(CEK) || !m_hasher->finish(ICVcomputed))
        return false;
    ICVcomputed.resize(8);
    if (ICV != ICVcomputed)
        return false;

    //8 Check for odd parity each of the DES key octets comprising CEK.
    //If parity is incorrect, then error.
    if (!CheckTDESParityBits(CEK))
        return false;

    //9 Use CEK as a Triple-DES key.
    outputData = CEK;
    return true;
}

bool KeyWrap_RFC3217::CanWrap(const tsCryptoData &keyToWrap)
{
    return (keyToWrap.size() == 24);
}

bool KeyWrap_RFC3217::CanUnwrap(const tsCryptoData &keyToUnwrap)
{
    return (keyToUnwrap.size() == 40);
}

bool KeyWrap_RFC3217::runTests(bool runDetailedTests)
{
    if (!gFipsState.operational())
        return false;
    if (!m_cipher)
        return false;

	std::shared_ptr<TSExtensibleSelfTest> exSelfTest;
	exSelfTest = std::dynamic_pointer_cast<TSExtensibleSelfTest>(m_cipher);
	if (!exSelfTest)
		exSelfTest.reset();

	if (!!exSelfTest)
	{
		if (!exSelfTest->RunSelfTestsFor("KEYWRAP-RFC3217", _me.lock(), runDetailedTests))
		{
			gFipsState.testFailed();
			return false;
		}
		return true;
	}
    return false;
}

tsCryptoString KeyWrap_RFC3217::AlgorithmName() const
{
    return GetName();
}

tsCryptoString KeyWrap_RFC3217::AlgorithmOID() const
{
    return LookUpAlgOID(GetName());
}

TS_ALG_ID KeyWrap_RFC3217::AlgorithmID() const
{
    return LookUpAlgID(GetName());
}

size_t KeyWrap_RFC3217::minimumKeySizeInBits() const
{
	if (!m_cipher)
		return 64;
	return m_cipher->minimumKeySizeInBits();
}

size_t KeyWrap_RFC3217::maximumKeySizeInBits() const
{
	if (!m_cipher)
		return 192;
	return m_cipher->maximumKeySizeInBits();
}

size_t KeyWrap_RFC3217::keySizeIncrementInBits() const
{
	if (!m_cipher)
		return 64;
	return m_cipher->keySizeIncrementInBits();
}

