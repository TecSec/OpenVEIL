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
#include "core/CkmSymmetricAlgorithmImpl.h"

using namespace tscrypto;

class SymmetricStream : public TSName, public CkmSymmetricAlgorithmImpl, public tscrypto::ICryptoObject, public tscrypto::IInitializableObject, public AlgorithmInfo
{
public:
	SymmetricStream() :
		m_keySizeInBits(0)
	{
		SetName("CHACHA20");
		desc = findSymmetricAlgorithm("CHACHA20");
	}
	virtual ~SymmetricStream(void)
	{
	}

	// Symmetric
	virtual size_t getBlockSize() override
	{
		return desc->blockSize;
	}
	virtual bool createKey(size_t keyLengthInBits, tsCryptoData &key) override
	{
		if (!gFipsState.operational())
			return false;
		if (keyLengthInBits < minimumKeySizeInBits() || keyLengthInBits > maximumKeySizeInBits() || (keyLengthInBits & 7) != 0)
			return false;

		key.resize((keyLengthInBits + 7) / 8);
		if (!internalGenerateRandomBits(key.rawData(), (uint32_t)keyLengthInBits, true, nullptr, 0))
			return false;

		return true;
	}
	virtual bool createIVEC(tsCryptoData &ivec) override
	{
		if (!gFipsState.operational())
			return false;

		ivec.resize(getIVECSizeForMode(_SymmetricMode::CKM_SymMode_CTR));
		if (!internalGenerateRandomBits(ivec.rawData(), (uint32_t)(getIVECSizeForMode(_SymmetricMode::CKM_SymMode_CTR) * 8), false, nullptr, 0))
			return false;

		return true;
	}
	virtual bool init(bool forEncrypt, SymmetricMode mode, const tsCryptoData &key, const tsCryptoData &ivec) override
	{
		if (!gFipsState.operational() || desc == nullptr)
			return false;
		if (ivec.size() != desc->ivecSize)
			return false;
		if (!isUsableKey(key))
			return false;

		m_mode = _SymmetricMode::CKM_SymMode_CTR;
		m_keySizeInBits = (int)key.size() * 8;
		m_key = key;

		m_context.clear();
		m_context.resize(desc->getWorkspaceSize(desc));
		return desc->init(desc, m_context.rawData(), forEncrypt, key.c_str(), (uint32_t)key.size(), ivec.c_str(), (uint32_t)ivec.size(), 0);
	}
	virtual bool update(const tsCryptoData &in_Data, tsCryptoData &out_Data) override
	{
		if (!gFipsState.operational())
			return false;
		if (m_context.empty())
			return false;

		size_t dataToProcess = in_Data.size();

		if (out_Data.size() != dataToProcess)
			out_Data.resize(dataToProcess);

		if (dataToProcess == 0)
			return true;

		return desc->update(desc, m_context.rawData(), in_Data.c_str(), (uint32_t)in_Data.size(), out_Data.rawData());
	}
	virtual bool finish(tsCryptoData &out_Data) override
	{
		out_Data.clear();

		if (!gFipsState.operational())
			return false;
		if (m_context.empty())
			return false;

		m_context.clear();
		m_keySizeInBits = 0;
		return true;
	}
	virtual bool getIVEC(tsCryptoData &ivec) override
	{
		if (!gFipsState.operational())
			return false;
		if (m_context.empty() || desc == nullptr)
			return false;
		ivec.clear();
		ivec.resize(desc->ivecSize);
		return desc->getIvec(desc, m_context.rawData(), ivec.rawData());
	}
	virtual bool setIVEC(const tsCryptoData &ivec) override
	{
		if (!gFipsState.operational())
			return false;
		if (m_context.empty() || desc == nullptr)
			return false;
		if (ivec.size() != desc->ivecSize)
			return false;
		return desc->setIvec(desc, m_context.rawData(), ivec.c_str());
	}
	virtual bool supportsBlockLength(size_t in_blockLength) override
	{
		if (!gFipsState.operational())
			return false;
		return true;
	}
	virtual bool supportsKeyLength(size_t in_keyLength) override
	{
		if (!gFipsState.operational())
			return false;
		return desc->supportsKeyLength(desc, (uint32_t)in_keyLength);
	}
	virtual bool isUsableKey(const tsCryptoData &key) override
	{
		if (!gFipsState.operational())
			return false;
		return desc->isUsableKey(desc, key.c_str(), (uint32_t)key.size());
	}
	virtual bool bytesToKey(size_t keyBitStrength, const tsCryptoData &data, tsCryptoData &key) override
	{
		size_t byteLength = (keyBitStrength + 7) / 8;
		tsCryptoData tmp(data);

		if (!gFipsState.operational())
			return false;
		if (!supportsKeyLength(keyBitStrength))
			return false;
		tmp.resize(byteLength);
		key = tmp;
		return true;
	}
	virtual uint64_t getBlockCount() const override
	{
		if (!gFipsState.operational())
			return 0;
		return desc->getBlockCount(desc, m_context.c_str());
	}
	virtual void setBlockCount(uint64_t setTo) override
	{
		desc->setBlockCount(desc, m_context.rawData(), setTo);
	}
	virtual void registerCounterModeIncrementor(std::shared_ptr<CounterModeIncrementor> pObj) override
	{
		m_incrementer.reset();
		if (!!pObj)
			m_incrementer = pObj;
	}
	virtual size_t getIVECSizeForMode(SymmetricMode mode) override
	{
		return desc->ivecSize;
	}
	virtual size_t minimumKeySizeInBits() const override
	{
		return m_keySizeInBits == 0 ? desc->minimumKeySize : m_keySizeInBits;
	}
	virtual size_t maximumKeySizeInBits() const override
	{
		return m_keySizeInBits == 0 ? desc->maximumKeySize : m_keySizeInBits;
	}
	virtual size_t keySizeIncrementInBits() const override
	{
		return m_keySizeInBits == 0 ? desc->keySizeIncrement : 0;
	}
	virtual size_t currentKeySizeInBits() const override
	{
		return m_keySizeInBits;
	}

#if 0
	bool testBlock(int ptLen, int blockNumber, const char* key, const char* ivec, const char* ctData)
	{
		tsCryptoData pt, ct, ct2;
		uint8_t b;

		pt.clear();
		pt.resize(ptLen);

		if (!init(true, _SymmetricMode::CKM_SymMode_CTR, tsCryptoData(key, tsCryptoData::HEX), tsCryptoData(ivec, tsCryptoData::HEX)))
		{
			return false;
		}
		setBlockCount(blockNumber);
		if (!update(pt, ct) || !finish(ct2))
		{
			return false;
		}
		ct.append(ct2);
		if (tsCryptoData(ctData, tsCryptoData::HEX) != ct)
		{
			return false;
		}
		if (!init(false, _SymmetricMode::CKM_SymMode_CTR, tsCryptoData(key, tsCryptoData::HEX), tsCryptoData(ivec, tsCryptoData::HEX)))
		{
			return false;
		}
		setBlockCount(blockNumber);
		if (!update(ct, pt) || !finish(ct2))
		{
			return false;
		}
		pt.append(ct2);
		b = 0;
		for (size_t j = 0; j < pt.size(); j++)
			b |= pt[j];
		if (pt.size() != ptLen || b != 0)
		{
			return false;
		}
		return true;
	}

	// Selftests
	virtual bool runTests(bool runDetailedTests) override
	{
		static struct {
			const char* key;
			const char* ivec;
			int block1;
			const char* ct1;
			int ptLen;
		} gTests[] = {
			{ "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "000000090000004a00000000", 
				1, "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e", 64 },
		};

		if (!gFipsState.operational())
			return false;

		for (size_t i = 0; i < sizeof(gTests) / sizeof(gTests[0]); i++)
		{
			if (!testBlock(gTests[i].ptLen, gTests[i].block1, gTests[i].key, gTests[i].ivec, gTests[i].ct1))
			{
				gFipsState.testFailed();
				return false;
			}
		}
		return true;
	}
#endif // 0

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

	// tscrypto::IInitializableObject
	virtual bool InitializeWithFullName(const tscrypto::tsCryptoStringBase& fullName) override
	{
		SetName(fullName);
		m_context.clear();

		desc = findSymmetricAlgorithm(fullName.c_str());

		m_mode = (_SymmetricMode::CKM_SymMode_CTR);
		return true;
	}
	virtual bool reserved1(uint8_t* data)
	{
		return false;
	}

private:
	const SymmetricAlgorithmDescriptor* desc;
	tsCryptoData m_context;
	tsCryptoData m_key;
	std::shared_ptr<CounterModeIncrementor> m_incrementer;
	int m_keySizeInBits;
};

tscrypto::ICryptoObject* CreateSymmetricStream()
{
	return dynamic_cast<tscrypto::ICryptoObject*>(new SymmetricStream);
}
