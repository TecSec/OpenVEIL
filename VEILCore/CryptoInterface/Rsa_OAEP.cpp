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

static bool isZero(const uint8_t* data, size_t dataLen)
{
	uint8_t c = 0;
	for (size_t i = 0; i < dataLen; i++)
	{
		c |= data[i];
	}
	return c == 0;
}
static bool isOne(const uint8_t* data, size_t dataLen)
{
	for (size_t i = 0; i < dataLen - 1; i++)
	{
		if (data[i] != 0)
			return false;
	}
	return data[dataLen - 1] == 1;
}

static bool isGreaterOrEqual(const tsCryptoData& in_left, const tsCryptoData& in_right)
{
	tsCryptoData left(in_left);
	tsCryptoData right(in_right);

	while (left.size() > 0 && left.front() == 0)
		left.erase(0, 1);
	while (right.size() > 0 && right.front() == 0)
		right.erase(0, 1);

	if (left.size() < right.size())
		return false;
	if (left.size() > right.size())
		return true;
	return memcmp(left.c_str(), right.c_str(), left.size()) >= 0;
}

class RSA_OAEP : public RsaOAEP, public TSName, public Selftest, public tscrypto::ICryptoObject, public tscrypto::IInitializableObject, public AlgorithmInfo
{
public:
    RSA_OAEP()
	{
	}
	virtual ~RSA_OAEP(void)
	{
	}

    // Selftests
    virtual bool runTests(bool runDetailedTests) override
	{
		bool testPassed = false;

		if (!gFipsState.operational())
			return false;
		if (!m_hasher)
			return false;

		// TODO:  Implement me
		//std::shared_ptr<TSExtensibleSelfTest> exSelfTest = std::dynamic_pointer_cast<TSExtensibleSelfTest>(m_hasher);
		//
		//if (!!exSelfTest)
		//{
		//	testPassed = exSelfTest->RunSelfTestsFor("RSA-OAEP", _me.lock(), runDetailedTests);
		//}
		//if (!testPassed)
		//{
		//	gFipsState.testFailed();
		//	return false;
		//}
		return true;
	}

    // AlgorithmInfo
    virtual tsCryptoString AlgorithmName() const override
	{
		return GetName();
	}
	virtual tsCryptoString AlgorithmOID() const override
	{
		return LookUpAlgOID(GetName());
	}
	virtual TS_ALG_ID AlgorithmID() const override
	{
		return LookUpAlgID(GetName());
	}

    // RsaOAEP
    virtual bool Generate(std::shared_ptr<RsaKey> key, const tsCryptoData &keyData, const tsCryptoData &additionalInput, tsCryptoData &outputData) override
	{
		if (!gFipsState.operational())
			return false;
		//    BigInteger n;
		std::shared_ptr<RsaPrimitives> prims;
		size_t nLen;
		tsCryptoData HA;
		tsCryptoData PS;
		tsCryptoData DB;
		tsCryptoData mgfSeed;
		tsCryptoData dbMask;
		tsCryptoData maskedDB;
		tsCryptoData mgfSeedMask;
		tsCryptoData maskedMGFSeed;
		tsCryptoData EM;
		tsCryptoData cipherText;

		if (!key || !m_hasher || !(prims = std::dynamic_pointer_cast<RsaPrimitives>(key)))
			return false;

		//n = key->get_PublicModulus();
		//nLen = (n.BitLength() + 7) / 8;
		nLen = (uint32_t)key->get_PublicModulus().size();

		if (keyData.size() > nLen - 2 * m_hasher->GetDigestSize() - 2)
			return false;

		if (!m_hasher->initialize() || !m_hasher->update(additionalInput) || !m_hasher->finish(HA))
			return false;

		PS.resize(nLen - 2 * m_hasher->GetDigestSize() - 2 - keyData.size());

		DB.append(HA).append(PS).append((uint8_t)1).append(keyData);

		if (!GenerateRandom(mgfSeed, m_hasher->GetDigestSize()))
			return false;

		dbMask = MGF(mgfSeed, nLen - m_hasher->GetDigestSize() - 1);

		maskedDB = dbMask;
		maskedDB.XOR(DB);

		mgfSeedMask = MGF(maskedDB, m_hasher->GetDigestSize());

		maskedMGFSeed = mgfSeed;
		maskedMGFSeed.XOR(mgfSeedMask);

		EM.append((uint8_t)0).append(maskedMGFSeed).append(maskedDB);

		if (!prims->EncryptPrimitive(EM, cipherText))
		{
			cipherText.clear();
			return false;
		}
		outputData = cipherText;
		outputData.truncOrPadLeft(nLen);
		return true;
	}
	virtual bool Recover(std::shared_ptr<RsaKey> key, const tsCryptoData &cipherData, const tsCryptoData &additionalInput, tsCryptoData &keyData) override
	{
		if (!gFipsState.operational())
			return false;
		tsCryptoData n;
		std::shared_ptr<RsaPrimitives> prims;
		uint32_t nLen;
		tsCryptoData EM;
		tsCryptoData HA;
		tsCryptoData HAprime;
		tsCryptoData DB;
		tsCryptoData mgfSeed;
		tsCryptoData dbMask;
		tsCryptoData maskedDB;
		tsCryptoData mgfSeedMask;
		tsCryptoData maskedMGFSeed;
		tsCryptoData X;

		keyData.clear();

		if (!key || !m_hasher || !(prims = std::dynamic_pointer_cast<RsaPrimitives>(key)))
			return false;

		n = key->get_PublicModulus();

		nLen = (uint32_t)(key->KeySize() + 7) / 8;

		if (nLen < 2 * m_hasher->GetDigestSize() + 2 || cipherData.size() != nLen || isZero(cipherData.c_str(), cipherData.size()) || isOne(cipherData.c_str(), cipherData.size()) || 
			isGreaterOrEqual(cipherData, n))
			return false;

		if (!prims->DecryptPrimitive(cipherData, EM))
		{
			return false;
		}

		if (EM.size() < nLen)
			EM.truncOrPadLeft(nLen);

		if (!m_hasher->initialize() || !m_hasher->update(additionalInput) || !m_hasher->finish(HA))
			return false;

		if (EM[0] != 0)
			return false;

		EM.erase(0, 1);

		maskedMGFSeed = EM;
		maskedMGFSeed.resize(m_hasher->GetDigestSize());

		maskedDB = EM;
		maskedDB.erase(0, maskedMGFSeed.size());

		mgfSeedMask = MGF(maskedDB, m_hasher->GetDigestSize());

		mgfSeed = maskedMGFSeed;
		mgfSeed.XOR(mgfSeedMask);

		dbMask = MGF(mgfSeed, nLen - m_hasher->GetDigestSize() - 1);

		DB = maskedDB;
		DB.XOR(dbMask);

		HAprime = DB;
		HAprime.resize(m_hasher->GetDigestSize());

		X = DB;
		X.erase(0, HAprime.size());

		if (HA != HAprime)
			return false;

		while (X.size() > 0 && X[0] == 0)
			X.erase(0, 1);

		if (X[0] != 1)
			return false;

		X.erase(0, 1);

		keyData = X;
		return true;
	}

	// tscrypto::IInitializableObject
	virtual bool InitializeWithFullName(const tscrypto::tsCryptoStringBase& fullName) override
	{
		tsCryptoString algorithm(fullName);

		SetName(algorithm);
		if (algorithm.size() < 10)
		{
			tsCryptoString tmp = GetName();
			tmp += "-SHA1";
			SetName(tmp);
		}
		if (!(m_hasher = std::dynamic_pointer_cast<Hash>(CryptoFactory(&GetName().c_str()[9]))))
		{
			return false;
		}
		return true;
	}

private:
	std::shared_ptr<Hash> m_hasher;

    tsCryptoData MGF(const tsCryptoData &seed, size_t maskLenInBytes)
	{
		tsCryptoData data(seed);
		tsCryptoData tmp;
		tsCryptoData output;

		data.resize(data.size() + 4);

		while (tmp.size() < maskLenInBytes)
		{
			if (!m_hasher->initialize() || !m_hasher->update(data) || !m_hasher->finish(output))
			{
				return tsCryptoData();
			}
			tmp += output;
			if (tmp.size() < maskLenInBytes)
			{
				data.increment();
			}
		}
		if (tmp.size() > maskLenInBytes)
			tmp.resize(maskLenInBytes);
		return tmp;
	}
};

tscrypto::ICryptoObject* CreateRsaOAEP()
{
	return dynamic_cast<tscrypto::ICryptoObject*>(new RSA_OAEP);
}

