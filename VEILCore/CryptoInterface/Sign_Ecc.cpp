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

class Sign_Ecc : public Signer, public TSName, public Selftest, public tscrypto::ICryptoObject, public tscrypto::IInitializableObject, public AlgorithmInfo
{
public:
    Sign_Ecc(const tsCryptoStringBase& algorithm);
    virtual ~Sign_Ecc(void);

    // Signer
	virtual bool initialize(std::shared_ptr<AsymmetricKey> key) override;
    virtual bool signHash(const tsCryptoData &hashData, tsCryptoData &signature) override;
    virtual bool update(const tsCryptoData &data) override;
    virtual bool sign(tsCryptoData &signature) override;
    virtual bool verifyHash(const tsCryptoData &hashData, const tsCryptoData &signature) override;
    virtual bool verify(const tsCryptoData &signature) override;
	virtual bool finish() override;
	virtual size_t GetHashBlockSize() override
	{
		if (!m_hasher)
			return 0;
		return m_hasher->GetBlockSize();
	}
	virtual size_t GetHashDigestSize() override
	{
		if (!m_hasher)
			return 0;
		return m_hasher->GetDigestSize();
	}

    // Selftests
    virtual bool runTests(bool runDetailedTests) override;

    // AlgorithmInfo
    virtual tsCryptoString AlgorithmName() const override;
    virtual tsCryptoString AlgorithmOID() const override;
    virtual TS_ALG_ID AlgorithmID() const override;

	// tscrypto::IInitializableObject
	virtual bool InitializeWithFullName(const tscrypto::tsCryptoStringBase& fullName) override
	{
		tsCryptoString algorithm(fullName);
		tsCryptoStringList parts = tsCryptoString(algorithm).split('-');

		SetName(algorithm);

		if (parts->size() < 3)
			SetName((GetName() + tsCryptoString("-SHA256")).c_str());

		if (TsStrLen(GetName()) > strlen("SIGN-ECC") && TsStrniCmp(GetName(), ("SIGN-ECC"), 8) == 0)
		{
			m_isEcc = true;
			if (!(m_hasher = std::dynamic_pointer_cast<Hash>(CryptoFactory(&GetName()[9]))))
			{
				return false;
			}
		}
		else if (TsStrLen(GetName()) > strlen("SIGN-DSA") && TsStrniCmp(GetName(), ("SIGN-DSA"), 8) == 0)
		{
			if (!(m_hasher = std::dynamic_pointer_cast<Hash>(CryptoFactory(&GetName()[9]))))
			{
				return false;
			}
		}
		return true;
	}

private:
	std::shared_ptr<Hash> m_hasher;
	std::shared_ptr<DhEccPrimitives> m_prims;
	bool m_isEcc;
    uint32_t m_keySize;
};

Sign_Ecc::Sign_Ecc(const tsCryptoStringBase& algorithm) :
	m_isEcc(false),
    m_keySize(0)
{
}

Sign_Ecc::~Sign_Ecc(void)
{
}

tscrypto::ICryptoObject* CreateEccSigner(const tsCryptoStringBase& algorithm)
{
	return dynamic_cast<tscrypto::ICryptoObject*>(new Sign_Ecc(algorithm));
}

bool Sign_Ecc::runTests(bool runDetailedTests)
{
    if (!gFipsState.operational())
        return false;
	// TODO:  Implement me
	//std::shared_ptr<TSExtensibleSelfTest> exSelfTest = std::dynamic_pointer_cast<TSExtensibleSelfTest>(m_hasher);
	//
	//if (!!exSelfTest)
	//{
	//	if (!exSelfTest->RunSelfTestsFor(m_isEcc ? "SIGN-ECC" : "SIGN-DSA", _me.lock(), runDetailedTests))
	//	{
	//		gFipsState.testFailed();
	//		return false;
	//	}
	//	return true;
	//}
    return true;
}

tsCryptoString Sign_Ecc::AlgorithmName() const
{
    return GetName();
}

tsCryptoString Sign_Ecc::AlgorithmOID() const
{
    return LookUpAlgOID(GetName());
}

TS_ALG_ID Sign_Ecc::AlgorithmID() const
{
    return LookUpAlgID(GetName());
}

bool Sign_Ecc::initialize(std::shared_ptr<AsymmetricKey> key)
{
    if (!gFipsState.operational())
        return false;
    m_prims.reset();

    if (!m_hasher)
        return false;

    if (!key || !(m_prims = std::dynamic_pointer_cast<DhEccPrimitives>(key)))
        return false;

    m_keySize = (uint32_t)key->KeySize();

    if (!!m_hasher)
    {
        if (!m_hasher->initialize())
            return false;
    }
    return true;
}

bool Sign_Ecc::signHash(const tsCryptoData &hashData, tsCryptoData &signature)
{
    if (!gFipsState.operational())
        return false;
    tsCryptoData r, s;

    if (!m_prims)
        return false;

    if (!m_prims->SignUsingData(hashData, r, s))
        return false;

    // Pack the signature here
	std::shared_ptr<TlvDocument> doc = TlvDocument::Create();

	while (r.size() > 0 && r[0] == 0)
		r.erase(0, 1);
	while (s.size() > 0 && r[0] == 0)
		s.erase(0, 1);
    if ((r[0] & 0x80) != 0)
        r.insert(0, (uint8_t)0);
    if ((s[0] & 0x80) != 0)
        s.insert(0, (uint8_t)0);
    doc->DocumentElement()->Tag(TlvNode::Tlv_Sequence);
    doc->DocumentElement()->Type(TlvNode::Type_Universal);
    doc->DocumentElement()->AppendChild(doc->CreateNumberNode(r));
    doc->DocumentElement()->AppendChild(doc->CreateNumberNode(s));
    signature = doc->SaveTlv();

    return true;
}

bool Sign_Ecc::update(const tsCryptoData &data)
{
    if (!gFipsState.operational())
        return false;
    if (!m_hasher)
        return false;

    return m_hasher->update(data);
}

bool Sign_Ecc::sign(tsCryptoData &signature)
{
    if (!gFipsState.operational())
        return false;
    tsCryptoData hashData;

    if (!m_hasher || !m_prims)
        return false;

	if (!m_hasher->finish(hashData))
        return false;

    return signHash(hashData, signature);
}

bool Sign_Ecc::verifyHash(const tsCryptoData &hashData, const tsCryptoData &signature)
{
    if (!gFipsState.operational())
        return false;
    tsCryptoData r, s;
    uint32_t keyByteSize = (m_keySize + 7) / 8;

    if (!m_prims)
        return false;

    // Unpack the signature here

	std::shared_ptr<TlvDocument> doc = TlvDocument::Create();

    if (!doc->LoadTlv(signature))
        return false;

    if (doc->DocumentElement()->Tag() != TlvNode::Tlv_Sequence || doc->DocumentElement()->Type() != TlvNode::Type_Universal ||
        !doc->DocumentElement()->IsConstructed() || doc->DocumentElement()->Children()->size() != 2 ||
        doc->DocumentElement()->Children()->at(0)->Tag() != TlvNode::Tlv_Number || doc->DocumentElement()->Children()->at(0)->Type() != TlvNode::Type_Universal ||
        doc->DocumentElement()->Children()->at(0)->IsConstructed() ||
        doc->DocumentElement()->Children()->at(1)->Tag() != TlvNode::Tlv_Number || doc->DocumentElement()->Children()->at(1)->Type() != TlvNode::Type_Universal ||
        doc->DocumentElement()->Children()->at(1)->IsConstructed() )
    {
        return false;
    }

    r = doc->DocumentElement()->Children()->at(0)->InnerData();
    s = doc->DocumentElement()->Children()->at(1)->InnerData();

    if (r.size() > 1 && r[0] == 0 && (r[1] & 0x80) != 0)
    {
        r.erase(0, 1);
    }
    if (s.size() > 1 && s[0] == 0 && (s[1] & 0x80) != 0)
    {
        s.erase(0, 1);
    }
    if (r.size() < keyByteSize)
        r.padLeft(keyByteSize);
    if (s.size() < keyByteSize)
        s.padLeft(keyByteSize);
    if (!m_prims->VerifySignatureForData(hashData, r, s))
        return false;

    return true;
}

bool Sign_Ecc::verify(const tsCryptoData &signature)
{
    if (!gFipsState.operational())
        return false;
    tsCryptoData hashData;

    if (!m_prims)
        return false;

	if (!m_hasher->finish(hashData))
        return false;

    return verifyHash(hashData, signature);
}

bool Sign_Ecc::finish()
{
    if (!gFipsState.operational())
        return false;
    tsCryptoData dummy;

    m_prims.reset();
    if (!!m_hasher)
		m_hasher->finish(dummy);
    return true;
}

