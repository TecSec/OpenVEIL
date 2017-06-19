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
#if defined(_WIN32) && (!defined(MINGW) || defined(_WIN64))
#include <intrin.h>
#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>
#endif // _WIN32

#include "core/CkmSymmetricAlgorithmImpl.h"

using namespace tscrypto;

class SymmetricWithModes : public TSName, public CkmSymmetricAlgorithmImpl, public tscrypto::ICryptoObject, public tscrypto::IInitializableObject, public AlgorithmInfo
{
public:
	SymmetricWithModes() :
		m_forEncrypt(true),
		m_keySizeInBits(0),
		m_baseAlgName("AES")
	{
		desc = findSymmetricAlgorithm(m_baseAlgName.c_str());
	}
	virtual ~SymmetricWithModes(void)
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
		if (keyLengthInBits != 128 && keyLengthInBits != 192 && keyLengthInBits != 256)
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

		ivec.resize(getBlockSize());
		if (!internalGenerateRandomBits(ivec.rawData(), (uint32_t)(getBlockSize() * 8), true, nullptr, 0))
			return false;

		return true;
	}
	virtual bool init(bool forEncrypt, SymmetricMode mode, const tsCryptoData &key, const tsCryptoData &ivec) override
	{
		if (!gFipsState.operational())
			return false;

		if (mode != _SymmetricMode::CKM_SymMode_CBC && mode != _SymmetricMode::CKM_SymMode_ECB && mode != _SymmetricMode::CKM_SymMode_OFB &&
			mode != _SymmetricMode::CKM_SymMode_CFB8 && mode != _SymmetricMode::CKM_SymMode_CFBfull && mode != _SymmetricMode::CKM_SymMode_CTR)
			return false;

		switch (mode)
		{
		case _SymmetricMode::CKM_SymMode_Default:
			break;
		case _SymmetricMode::CKM_SymMode_ECB:
			desc = findSymmetricAlgorithm((m_baseAlgName).c_str());
			break;
		case _SymmetricMode::CKM_SymMode_CBC:
			desc = findSymmetricAlgorithm((m_baseAlgName + "-CBC").c_str());
			break;
		case _SymmetricMode::CKM_SymMode_OFB:
			desc = findSymmetricAlgorithm((m_baseAlgName + "-OFB").c_str());
			break;
		case _SymmetricMode::CKM_SymMode_CFB8:
			desc = findSymmetricAlgorithm((m_baseAlgName + "-CFB8").c_str());
			break;
		case _SymmetricMode::CKM_SymMode_CFBfull:
			desc = findSymmetricAlgorithm((m_baseAlgName + "-CFBFULL").c_str());
			break;
		case _SymmetricMode::CKM_SymMode_CTR:
			desc = findSymmetricAlgorithm((m_baseAlgName + "-CTR").c_str());
			break;
		default:
			return false;
		}
		if (desc == nullptr)
			return false;
		if (!isUsableKey(key))
			return false;

		m_context.reset();
		m_context = desc;
		if (mode == _SymmetricMode::CKM_SymMode_CBC || mode == _SymmetricMode::CKM_SymMode_OFB || mode == _SymmetricMode::CKM_SymMode_CFB8 || 
			mode == _SymmetricMode::CKM_SymMode_CFBfull || mode == _SymmetricMode::CKM_SymMode_CTR)
		{
			if (ivec.size() != desc->ivecSize)
				return false;
			if (!setIVEC(ivec))
				return false;
		}
		m_mode = mode;
		m_lastBlock.clear();
		m_keySizeInBits = (int)key.size() * 8;

		tsCryptoString name(m_baseAlgName + "-");
		name.append((key.size() * 8));
		name += "-";
		switch (mode)
		{
		case _SymmetricMode::CKM_SymMode_CBC:
			name += "CBC";
			break;
		case _SymmetricMode::CKM_SymMode_ECB:
			name += "ECB";
			break;
		case _SymmetricMode::CKM_SymMode_OFB:
			name += "OFB";
			break;
		case _SymmetricMode::CKM_SymMode_CFB8:
			name += "CFB8";
			break;
		case _SymmetricMode::CKM_SymMode_CFBfull:
			name += "CFBfull";
			break;
		case _SymmetricMode::CKM_SymMode_CTR:
			name += "CTR";
			break;
		}
		SetName(name);

		m_forEncrypt = forEncrypt;
		return desc->init(desc, m_context, forEncrypt, key.c_str(), (uint32_t)key.size(), ivec.c_str(), (uint32_t)ivec.size(), 0);
	}
	virtual bool update(const tsCryptoData &in_Data, tsCryptoData &out_Data) override
	{
		if (!gFipsState.operational())
			return false;
		if (m_context.empty())
			return false;

		if (in_Data.size() == 0)
		{
			out_Data.clear();
			return true;
		}
		size_t dataToProcess = in_Data.size();

		if (out_Data.c_str() != in_Data.c_str())
		{
			out_Data.clear();
			out_Data = in_Data;
		}

		if (NeedsPadding())
		{
			if (m_lastBlock.size() > 0)
				out_Data.insert(0, m_lastBlock);

			size_t needed = out_Data.size() % getBlockSize();

			if (needed == 0 && out_Data.size() > 0)
				needed = getBlockSize();
			m_lastBlock.assign(&out_Data.c_str()[out_Data.size() - needed], needed);
			out_Data.resize(out_Data.size() - needed);
			dataToProcess = out_Data.size();
		}

		if (dataToProcess == 0)
			return true;

		return desc->update(desc, m_context, out_Data.c_str(), (uint32_t)out_Data.size(), out_Data.rawData());
	}
	virtual bool finish(tsCryptoData &out_Data) override
	{
		out_Data.clear();

		if (!gFipsState.operational())
			return false;
		if (m_context.empty())
			return false;

		if (m_lastBlock.size() > 0 || NeedsPadding())
		{
			out_Data = m_lastBlock;
			m_lastBlock.clear();
			if (m_forEncrypt)
				PadData(out_Data);
			if (!desc->update(desc, m_context, out_Data.c_str(), (uint32_t)out_Data.size(), out_Data.rawData()))
				return false;
			if (!m_forEncrypt)
			{
				if (!UnpadData(out_Data))
					return false;
			}
		}

		m_context.reset();
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
		return desc->getIvec(desc, m_context, ivec.rawData());
	}
	virtual bool setIVEC(const tsCryptoData &ivec) override
	{
		if (!gFipsState.operational())
			return false;
		if (m_context.empty() || desc == nullptr)
			return false;
		if (ivec.size() != 0 && ivec.size() != desc->ivecSize)
			return false;
		return desc->setIvec(desc, m_context, ivec.c_str());
	}
	virtual bool supportsBlockLength(size_t in_blockLength) override
	{
		if (!gFipsState.operational() || desc == nullptr)
			return false;
		return in_blockLength == getBlockSize();
	}
	virtual bool supportsKeyLength(size_t in_keyLength) override
	{
		if (!gFipsState.operational() || desc == nullptr)
			return false;
		return desc->supportsKeyLength(desc, (uint32_t)in_keyLength);
	}
	virtual bool isUsableKey(const tsCryptoData &key) override
	{
		if (!gFipsState.operational() || desc == nullptr)
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
		if (!gFipsState.operational() || desc == nullptr)
			return 0;
		return desc->getBlockCount(desc, m_context);
	}
	virtual void setBlockCount(uint64_t setTo) override
	{
		if (!gFipsState.operational() || desc == nullptr)
			return ;
		desc->setBlockCount(desc, m_context, setTo);
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
	virtual bool reserved1(uint8_t* data) override
	{
		return false;
	}
	virtual size_t currentKeySizeInBits() const override
	{
		return m_keySizeInBits;
	}

#if 0
	// Selftests
	virtual bool runTests(bool runDetailedTests) override
	{
		static uint8_t key[] = { 0x80, 0x81, 0x82, 0x83, 0x85, 0x86, 0x87, 0x88, 0x8A, 0x8B, 0x8C, 0x8D, 0x8F, 0x90, 0x91, 0x92, 0x94, 0x95, 0x96, 0x97, 0x99, 0x9A, 0x9B, 0x9C, 0x9E, 0x9F, 0xA0, 0xA1, 0xA3, 0xA4, 0xA5, 0xA6, };
		static uint8_t data[] = { 0xA8, 0xA9, 0xAA, 0xAB, 0x5C, 0x5F, 0x5E, 0x51, 0xAE, 0xAF, 0xA8, 0xA9, 0x3D, 0x22, 0x23, 0x20 };
		static uint8_t cipher[] = { 0xB4, 0xFB, 0xD6, 0x5B, 0x33, 0xF7, 0x0D, 0x8C, 0xF7, 0xF1, 0x11, 0x1A, 0xC4, 0x64, 0x9C, 0x36 };
		tsCryptoData results;
		tsCryptoData finalData;
		static const char *ctrKey = "2b7e151628aed2a6abf7158809cf4f3c";
		static const char *ctrIv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
		static const char *ctrPlaintext = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
		static const char *ctrCiphertext = "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee";
		static const char *cfbfullKey = "50932af0ea47c247c556f5d5ecaec421";
		static const char *cfbfullIv = "31281ce609ccef719db1a07d58239cd8";
		static const char *cfbfullPlaintext = "0a7ae511fdd91e55a2099784cd29a77b9396cf747b86af8665062e79ac7d4eda";
		static const char *cfbfullCiphertext = "0a21769de450f63222d8d08ba3f4e45766725875e4b78d10a302510f08f556ac";
		//static const char *cfbfullIv = "0a21769de450f63222d8d08ba3f4e457";
		//static const char *cfbfullPlaintext = "916b9f2dc845c3acbe271e381e1af719";
		//static const char *cfbfullCiphertext = "66725875e4b78d10a302510f08f556ac";

		if (!gFipsState.operational())
			return false;

		// first encrypt
		if (!init(true, _SymmetricMode::CKM_SymMode_ECB, tsCryptoData(key, sizeof(key)), tsCryptoData()) ||
			!update(tsCryptoData(data, sizeof(data)), results))
		{
			finish(finalData);
			gFipsState.testFailed();
			return false;
		}
		finish(finalData);
		if (results.size() != sizeof(cipher) || memcmp(results.c_str(), cipher, sizeof(cipher)) != 0)
		{
			gFipsState.testFailed();
			return false;
		}

		// then decrypt
		if (!init(false, _SymmetricMode::CKM_SymMode_ECB, tsCryptoData(key, sizeof(key)), tsCryptoData()) ||
			!update(results, results))
		{
			finish(finalData);
			gFipsState.testFailed();
			return false;
		}
		finish(finalData);
		if (results.size() != sizeof(data) || memcmp(results.c_str(), data, sizeof(data)) != 0)
		{
			gFipsState.testFailed();
			return false;
		}


		// first encrypt
		if (!init(true, _SymmetricMode::CKM_SymMode_CFBfull, tsCryptoData(cfbfullKey, tsCryptoData::HEX), tsCryptoData(cfbfullIv, tsCryptoData::HEX)) ||
			!update(tsCryptoData(cfbfullPlaintext, tsCryptoData::HEX), results))
		{
			finish(finalData);
			gFipsState.testFailed();
			return false;
		}
		finish(finalData);
		if (results != tsCryptoData(cfbfullCiphertext, tsCryptoData::HEX))
		{
			gFipsState.testFailed();
			return false;
		}

		// then decrypt
		if (!init(false, _SymmetricMode::CKM_SymMode_CFBfull, tsCryptoData(cfbfullKey, tsCryptoData::HEX), tsCryptoData(cfbfullIv, tsCryptoData::HEX)) ||
			!update(results, results))
		{
			finish(finalData);
			gFipsState.testFailed();
			return false;
		}
		finish(finalData);
		if (results != tsCryptoData(cfbfullPlaintext, tsCryptoData::HEX))
		{
			gFipsState.testFailed();
			return false;
		}

		if (runDetailedTests)
		{
			tsCryptoData key1;
			tsCryptoData iv;
			tsCryptoData pt, pt1, pt2;
			tsCryptoData ct;
			tsCryptoData tmp1, tmp2;

			key1.FromHexString(ctrKey);
			iv.FromHexString(ctrIv);
			pt.FromHexString(ctrPlaintext);
			ct.FromHexString(ctrCiphertext);

			if (!init(true, _SymmetricMode::CKM_SymMode_CTR, key1, iv) ||
				!update(pt, results))
			{
				finish(finalData);
				gFipsState.testFailed();
				return false;
			}
			finish(finalData);
			if (results.size() != ct.size() || memcmp(results.c_str(), ct.c_str(), ct.size()) != 0)
			{
				gFipsState.testFailed();
				return false;
			}
			pt1 = pt.left(3);
			pt2 = pt.substring(3, 9999);
			if (!init(true, _SymmetricMode::CKM_SymMode_CTR, key1, iv) ||
				!update(pt1, results) || !update(pt2, tmp1))
			{
				finish(finalData);
				gFipsState.testFailed();
				return false;
			}
			results += tmp1;
			finish(finalData);
			if (results.size() != ct.size() || memcmp(results.c_str(), ct.c_str(), ct.size()) != 0)
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

#if 0
	// TSExtensibleSelfTest
	virtual bool RunSelfTestsFor(const tsCryptoStringBase& baseProtocolName, std::shared_ptr<tscrypto::ICryptoObject> baseProtocol, bool runDetailedTests) override
	{
		if (!gFipsState.operational())
			return false;
		if (!baseProtocol || baseProtocolName.size() == 0)
		{
			gFipsState.testFailed();
			return false;
		}

		if (baseProtocolName == "CCM")
		{
			std::shared_ptr<CCM_GCM> alg = std::dynamic_pointer_cast<CCM_GCM>(baseProtocol);

			if (!alg)
			{
				gFipsState.testFailed();
				return false;
			}

			if (!fipsTestsForCCM(alg, runDetailedTests))
			{
				gFipsState.testFailed();
				return false;
			}
			return true;
		}
		else if (baseProtocolName == "GCM")
		{
			std::shared_ptr<CCM_GCM> alg = std::dynamic_pointer_cast<CCM_GCM>(baseProtocol);

			if (!alg)
			{
				gFipsState.testFailed();
				return false;
			}

			if (!fipsTestsForGCM(alg, runDetailedTests))
			{
				gFipsState.testFailed();
				return false;
			}
			return true;
		}
		//else if (baseProtocolName == "XTS")
		//{
		//	std::shared_ptr<XTS> alg = std::dynamic_pointer_cast<XTS>(baseProtocol);

		//	if (!alg)
		//	{
		//		gFipsState.testFailed();
		//		return false;
		//	}

		//	if (!fipsTestsForXTS(alg, runDetailedTests))
		//	{
		//		gFipsState.testFailed();
		//		return false;
		//	}
		//	return true;
		//}
		else if (baseProtocolName == "KEYWRAP-RFC3394")
		{
			std::shared_ptr<KeyTransport> kw = std::dynamic_pointer_cast<KeyTransport>(baseProtocol);

			if (!kw)
			{
				gFipsState.testFailed();
				return false;
			}

			static const uint8_t key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
			static const uint8_t data192[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
			static const uint8_t wData192192[] = { 0x03, 0x1d, 0x33, 0x26, 0x4e, 0x15, 0xd3, 0x32, 0x68, 0xf2, 0x4e, 0xc2, 0x60, 0x74, 0x3e, 0xdc, 0xe1, 0xc6, 0xc7, 0xdd, 0xee, 0x72, 0x5a, 0x93, 0x6b, 0xa8, 0x14, 0x91, 0x5c, 0x67, 0x62, 0xd2 };
			tsCryptoData outputData;

			if (!kw->initializeWithSymmetricKey(tsCryptoData(key, sizeof(key))) ||
				!kw->Wrap(tsCryptoData(data192, sizeof(data192)), tsCryptoData(), outputData) ||
				outputData.size() != sizeof(wData192192) ||
				memcmp(wData192192, outputData.c_str(), sizeof(wData192192)) != 0)
			{
				gFipsState.testFailed();
				return false;
			}
			if (!kw->initializeWithSymmetricKey(tsCryptoData(key, sizeof(key))) ||
				!kw->Unwrap(outputData, tsCryptoData(), outputData) ||
				outputData.size() != sizeof(data192) ||
				memcmp(data192, outputData.c_str(), sizeof(data192)) != 0)
			{
				gFipsState.testFailed();
				return false;
			}
			return true;
		}
		else if (baseProtocolName == "CMAC")
		{
			std::shared_ptr<MessageAuthenticationCode> cm = std::dynamic_pointer_cast<MessageAuthenticationCode>(baseProtocol);

			if (!cm)
			{
				gFipsState.testFailed();
				return false;
			}

			if (!fips_test_cmac_aes(cm, runDetailedTests))
			{
				gFipsState.testFailed();
				return false;
			}
			return true;
		}
		if (baseProtocolName == "KDF-CMAC")
		{
			std::shared_ptr<KeyDerivationFunction> kdf = std::dynamic_pointer_cast<KeyDerivationFunction>(baseProtocol);

			if (!kdf)
			{
				gFipsState.testFailed();
				return false;
			}

			if (!fips_test_kdf_cmac_aes(kdf, runDetailedTests))
			{
				gFipsState.testFailed();
				return false;
			}
			return true;
		}
		return false; // TODO:  Implement me
	}
#endif // 0

	// tscrypto::IInitializableObject
	virtual bool InitializeWithFullName(const tscrypto::tsCryptoStringBase& fullName) override
	{
		tsCryptoString algorithm(fullName);
		tsCryptoStringList parts = algorithm.split("-");

		SetName(algorithm);

		m_baseAlgName = parts->front();

		m_context.reset();

		m_mode = (_SymmetricMode::CKM_SymMode_ECB);
		if (parts->size() > 1)
		{
			// Initialize the algorithm with parameters from the name
			tsCryptoString name(algorithm);
			tsCryptoData IVEC, KEY;

			if (parts->size() > 2)
			{
				if (TsStriCmp(parts->at(2).c_str(), ("CBC")) == 0)
				{
					m_mode = _SymmetricMode::CKM_SymMode_CBC;
					desc = findSymmetricAlgorithm((m_baseAlgName + "-CBC").c_str());
				}
				else if (TsStriCmp(parts->at(2).c_str(), ("ECB")) == 0)
				{
					m_mode = _SymmetricMode::CKM_SymMode_ECB;
					desc = findSymmetricAlgorithm((m_baseAlgName).c_str());
				}
				else if (TsStriCmp(parts->at(2).c_str(), ("CFB8")) == 0)
				{
					m_mode = _SymmetricMode::CKM_SymMode_CFB8;
					desc = findSymmetricAlgorithm((m_baseAlgName + "-CFB8").c_str());
				}
				else if (TsStriCmp(parts->at(2).c_str(), ("CFBfull")) == 0)
				{
					m_mode = _SymmetricMode::CKM_SymMode_CFBfull;
					desc = findSymmetricAlgorithm((m_baseAlgName + "-CFBFULL").c_str());
				}
				else if (TsStriCmp(parts->at(2).c_str(), ("CTR")) == 0)
				{
					m_mode = _SymmetricMode::CKM_SymMode_CTR;
					desc = findSymmetricAlgorithm((m_baseAlgName + "-CTR").c_str());
				}
				else if (TsStriCmp(parts->at(2).c_str(), ("OFB")) == 0)
				{
					m_mode = _SymmetricMode::CKM_SymMode_OFB;
					desc = findSymmetricAlgorithm((m_baseAlgName + "-OFB").c_str());
				}
			}
			if (desc == nullptr)
			{
				return false;
			}
			m_context = desc;

			if (m_mode != _SymmetricMode::CKM_SymMode_ECB)
			{
				createIVEC(IVEC);
			}
			if (parts->size() > 1)
			{
				int keySize = TsStrToInt(parts->at(1).c_str());

				if (desc->supportsKeyLength(desc, keySize))
				{
					createKey(keySize, KEY);

					if (KEY.size() > 0)
					{
						init(true, m_mode, KEY, IVEC);
					}
				}
			}
		}
		else
		{
			m_mode = _SymmetricMode::CKM_SymMode_ECB;
			desc = findSymmetricAlgorithm((m_baseAlgName).c_str());
			if (desc == nullptr)
			{
				return false;
			}
			m_context = desc;
		}
		return true;
	}

protected:
#if 0
	bool fips_test_cmac_aes(std::shared_ptr<MessageAuthenticationCode>& cm, bool runDetailed)
	{
		tsCryptoData data;
		tsCryptoData key;
		tsCryptoData digest;
		uint32_t i;
		static BYTE data1[1] = { 0 };
		static BYTE data2[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
		static BYTE data3[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11 };
		static BYTE data4[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };

		// 128 bit key values
		static BYTE key1[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
		static BYTE mac1[] = { 0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46 };
		static BYTE mac2[] = { 0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c };
		static BYTE mac3[] = { 0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30, 0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27 };
		static BYTE mac4[] = { 0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92, 0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe };

		// 192 bit key values
		static BYTE key2[] = { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
		static BYTE mac5[] = { 0xd1, 0x7d, 0xdf, 0x46, 0xad, 0xaa, 0xcd, 0xe5, 0x31, 0xca, 0xc4, 0x83, 0xde, 0x7a, 0x93, 0x67 };
		static BYTE mac6[] = { 0x9e, 0x99, 0xa7, 0xbf, 0x31, 0xe7, 0x10, 0x90, 0x06, 0x62, 0xf6, 0x5e, 0x61, 0x7c, 0x51, 0x84 };
		static BYTE mac7[] = { 0x8a, 0x1d, 0xe5, 0xbe, 0x2e, 0xb3, 0x1a, 0xad, 0x08, 0x9a, 0x82, 0xe6, 0xee, 0x90, 0x8b, 0x0e };
		static BYTE mac8[] = { 0xa1, 0xd5, 0xdf, 0x0e, 0xed, 0x79, 0x0f, 0x79, 0x4d, 0x77, 0x58, 0x96, 0x59, 0xf3, 0x9a, 0x11 };

		// 256 bit key values
		static BYTE key3[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
		static BYTE mac9[] = { 0x02, 0x89, 0x62, 0xf6, 0x1b, 0x7b, 0xf8, 0x9e, 0xfc, 0x6b, 0x55, 0x1f, 0x46, 0x67, 0xd9, 0x83 };
		static BYTE mac10[] = { 0x28, 0xa7, 0x02, 0x3f, 0x45, 0x2e, 0x8f, 0x82, 0xbd, 0x4b, 0xf2, 0x8d, 0x8c, 0x37, 0xc3, 0x5c };
		static BYTE mac11[] = { 0xaa, 0xf3, 0xd8, 0xf1, 0xde, 0x56, 0x40, 0xc2, 0x32, 0xf5, 0xb1, 0x69, 0xb9, 0xc9, 0x11, 0xe6 };
		static BYTE mac12[] = { 0xe1, 0x99, 0x21, 0x90, 0x54, 0x9f, 0x6e, 0xd5, 0x69, 0x6a, 0x2c, 0x05, 0x6c, 0x31, 0x54, 0x10 };

		struct tagCmacData
		{
			const unsigned char *key;
			int keyLength;
			const unsigned char *data;
			int dataLength;
			const unsigned char *cmac;
		};
		static struct tagCmacData
		CmacData[] = {
			// 128 bit key
				{ key1, sizeof(key1), data1, 0,             mac1 },
				{ key1, sizeof(key1), data2, sizeof(data2), mac2 },
				{ key1, sizeof(key1), data3, sizeof(data3), mac3 },
				{ key1, sizeof(key1), data4, sizeof(data4), mac4 },

			// 192 bit key
				{ key2, sizeof(key2), data1, 0,             mac5 },
				{ key2, sizeof(key2), data2, sizeof(data2), mac6 },
				{ key2, sizeof(key2), data3, sizeof(data3), mac7 },
				{ key2, sizeof(key2), data4, sizeof(data4), mac8 },

			// 256 bit key
				{ key3, sizeof(key3), data1, 0,             mac9 },
				{ key3, sizeof(key3), data2, sizeof(data2), mac10 },
				{ key3, sizeof(key3), data3, sizeof(data3), mac11 },
				{ key3, sizeof(key3), data4, sizeof(data4), mac12 },
		};

		for (i = 0; i < (runDetailed ? sizeof(CmacData) / sizeof(CmacData[0]) : 2); i++)
		{
			data.assign(CmacData[i].data, CmacData[i].dataLength);
			key.assign(CmacData[i].key, CmacData[i].keyLength);

			if (!cm->initialize(key) || !cm->update(data) || !cm->finish(digest))
			{
				gFipsState.testFailed();
				return false;
			}
			if (digest.size() != cm->GetDigestSize() || 0 != memcmp(digest.c_str(), CmacData[i].cmac, digest.size()))
			{
				gFipsState.testFailed();
				return false;
			}
		}
		return true;
	}
	bool fips_test_kdf_cmac_aes(std::shared_ptr<KeyDerivationFunction>& kdf, bool runDetailed)
	{
		MY_UNREFERENCED_PARAMETER(runDetailed);

		if (!gFipsState.operational())
			return false;
		tsCryptoData results;

		if (!kdf->initializeWithKey(tsCryptoData("c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558", tsCryptoData::HEX)) ||
			!kdf->Derive_SCP03(4, 520, tsCryptoData("3f852ef8bcb5ed12ac7058325f56e6099aab1a1c", tsCryptoData::HEX), results) ||
			!kdf->finish() ||
			tsCryptoData("F29317337100DB6A1B45D003224BCBB9C648E1051F1A3990AFD585F3642E34F5E788F28AA51E38BA6BBABC3F293D0FCFA13C6F63E05A0CC3ABEEE7AA70D7CE2689", tsCryptoData::HEX) != results)
		{
			gFipsState.testFailed();
			return false;
		}

		return true;
	}
	//bool fipsTestsForXTS(std::shared_ptr<XTS>& alg, bool runDetailedTests);
	bool fipsTestsForCCM(std::shared_ptr<CCM_GCM>& alg, bool runDetailedTests)
	{
		const tsCryptoData key("404142434445464748494a4b4c4d4e4f", tsCryptoData::HEX);
		const tsCryptoData ivec("10111213141516", tsCryptoData::HEX);
		const tsCryptoData header("0001020304050607", tsCryptoData::HEX);
		const tsCryptoData plaintext("20212223", tsCryptoData::HEX);
		const tsCryptoData ciphertext("7162015b", tsCryptoData::HEX);
		const tsCryptoData tag("4dac255d", tsCryptoData::HEX);
		tsCryptoData resultTag;
		tsCryptoData data;

		if (!gFipsState.operational())
			return false;

		data = plaintext;
		if (!alg->initialize(key) ||
			!alg->encryptMessage(ivec, header, data, 4, resultTag) ||
			!alg->finish() ||
			data != ciphertext || resultTag != tag)
		{
			gFipsState.testFailed();
			return false;
		}
		if (!alg->initialize(key) ||
			!alg->decryptMessage(ivec, header, data, tag) ||
			!alg->finish() ||
			data != plaintext)
		{
			gFipsState.testFailed();
			return false;
		}
		return true;
	}
	bool fipsTestsForGCM(std::shared_ptr<CCM_GCM>& alg, bool runDetailedTests)
	{
		const tsCryptoData Key("9bb94d7ed19d811fcb263eabfc52f8d7", tsCryptoData::HEX);
		const tsCryptoData IV("5323d5b830cff263a7a2da2f", tsCryptoData::HEX);
		const tsCryptoData PT("f4fc684c78177720d78628200849e6a5", tsCryptoData::HEX);
		const tsCryptoData AAD("7a63d4e4f508f78ebd6bd750e6973d6a", tsCryptoData::HEX);
		const tsCryptoData CT("c81cfe31cbe2003d83cdacaf9109fad2", tsCryptoData::HEX);
		const tsCryptoData Tag("4c31e377b237345a6dc16d63dae6e4fe", tsCryptoData::HEX);

		tsCryptoData resultTag;
		tsCryptoData data;

		if (!gFipsState.operational())
			return false;

		data = PT;
		if (!alg->initialize(Key) ||
			!alg->encryptMessage(IV, AAD, data, (uint32_t)Tag.size(), resultTag) ||
			!alg->finish() ||
			data != CT || resultTag != Tag)
		{
			gFipsState.testFailed();
			return false;
		}
		if (!alg->initialize(Key) ||
			!alg->decryptMessage(IV, AAD, data, Tag) ||
			!alg->finish() ||
			data != PT)
		{
			gFipsState.testFailed();
			return false;
		}
		return true;
	}
#endif // 0

private:
	const SymmetricAlgorithmDescriptor* desc;
	tsCryptoString m_baseAlgName;
    SmartCryptoWorkspace m_context;
	std::shared_ptr<CounterModeIncrementor> m_incrementer;
	tsCryptoData m_lastBlock;
	bool m_forEncrypt;
	int m_keySizeInBits;
};

tscrypto::ICryptoObject* CreateSymmetricWithModes()
{
	return dynamic_cast<tscrypto::ICryptoObject*>(new SymmetricWithModes());
}
