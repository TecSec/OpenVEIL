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

class XTSImpl : public XTS, public TSName, public tscrypto::ICryptoObject, public tscrypto::IInitializableObject, public AlgorithmInfo
{
public:
	XTSImpl() :
		m_keySizeInBits(0),
		desc(nullptr)
	{
		PrepareClass("XTS-AES");
	}    
	virtual ~XTSImpl(void)
	{
		m_context.clear();
		desc = nullptr;
	}

    // XTS
    virtual bool initialize(const tsCryptoData &key, bool forEncrypt) override
	{
		tsCryptoData tmp;

		if (!gFipsState.operational() || desc == nullptr)
			return false;
		if (key.size() != 32 && key.size() != 48 && key.size() != 64)
			return false;

		m_keySizeInBits = (int)key.size() * 8;

		m_context.clear();
		m_context.resize(desc->getWorkspaceSize(desc));
		m_forEncrypt = forEncrypt;

		tsCryptoString name(m_baseName);
		name += "-";
		name.append((key.size() * 8));
		SetName(name);

		return desc->init(desc, m_context.rawData(), key.c_str(), (uint32_t)key.size());
	}
	virtual bool update(tsCryptoData &sector, size_t sectorSizeInBits, const tsCryptoData &sectorAddress) override
	{
		if (!gFipsState.operational())
			return false;
		if (desc == nullptr)
			return false;
		if (sector.size() < 16 || sector.size() != ((sectorSizeInBits + 7) / 8) || sectorSizeInBits > 1024 * 1024 * desc->blockSizeInBytes)
			return false;
		if (m_context.empty())
			return false;

		if (sectorAddress.size() != desc->blockSizeInBytes)
			return false;

		if (sector.size() < desc->blockSizeInBytes)
		{
			return false;
		}
		bool retVal;
		if (m_forEncrypt)
		{
			retVal = desc->encrypt(desc, m_context.rawData(), sector.rawData(), (unsigned int)sectorSizeInBits, sectorAddress.c_str());
		}
		else
		{
			retVal = desc->decrypt(desc, m_context.rawData(), sector.rawData(), (unsigned int)sectorSizeInBits, sectorAddress.c_str());
		}
		if (!retVal)
		{
			sector.clear();
		}
		return retVal;
	}
	virtual bool updateByAddress(tsCryptoData &sector, size_t sectorSizeInBits, uint64_t sectorAddress) override
	{
		tsCryptoData iv((uint8_t*)&sectorAddress, sizeof(sectorAddress));

		if (!gFipsState.operational())
			return false;
		if (desc == nullptr)
			return false;
		if (m_context.empty())
			return false;


		if (sectorSizeInBits > 1024 * 1024 * desc->blockSizeInBytes)
			return false;

#if BYTE_ORDER != LITTLE_ENDIAN
		iv.Reverse();
#endif
		iv.resize(16);
		return update(sector, sectorSizeInBits, iv);
	}
	virtual bool finish() override
	{
		if (!gFipsState.operational())
			return false;
		if (desc == nullptr)
			return false;
		if (m_context.empty())
			return false;

		bool retVal = desc->finish(desc, m_context.rawData());
		m_context.clear();
		m_keySizeInBits = 0;
		return retVal;
	}
	virtual size_t minimumKeySizeInBits() const override
	{
		if (desc == nullptr)
			return 0;

		return m_keySizeInBits == 0 ? desc->minimumKeySize : m_keySizeInBits;
	}
	virtual size_t maximumKeySizeInBits() const override
	{
		if (desc == nullptr)
			return 0;

		return m_keySizeInBits == 0 ? desc->maximumKeySize : m_keySizeInBits;
	}
	virtual size_t keySizeIncrementInBits() const override
	{
		if (desc == nullptr)
			return 0;

		return m_keySizeInBits == 0 ? desc->keySizeIncrement : 0;
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

	// tscrypto::IInitializableObject
	virtual bool InitializeWithFullName(const tscrypto::tsCryptoStringBase& fullName) override
	{
		return PrepareClass(fullName);
	}

#if 0
protected:
	bool fipsTestsForAESXTS(std::shared_ptr<XTS> alg, bool /*runDetailedTests*/)
	{
		tsCryptoData key("97098b465a44ca75e7a1c2dbfc40b7a61a20e32c6d9dbfda80726fee10541bab475463ca07c1c1e4496173321468d1ab3fad8ad91fcdc62abe07bff8ef961b6b", tsCryptoData::HEX);
		tsCryptoData ivec("15601e2e358510a09ddca4ea1751f43c", tsCryptoData::HEX);
		tsCryptoData pt("d19cfb383baf872e6f121687451de15c", tsCryptoData::HEX);
		tsCryptoData ct("eb22269b14905027dc73c4a40f938069", tsCryptoData::HEX);
		tsCryptoData results;
	
		results = pt;
		if (!alg->initialize(key, true) || !alg->update(results, 128, ivec) || !alg->finish() || results != ct)
		{
			gFipsState.testFailed();
			return false;
		}
		if (!alg->initialize(key, false) || !alg->update(results, 128, ivec) || !alg->finish() || results != pt)
		{
			gFipsState.testFailed();
			return false;
		}
		return true;
	}
#endif // 0

private:
    tsCryptoData m_context;
	const XTS_Descriptor* desc;
    bool m_forEncrypt;
    tsCryptoString m_baseName;
	int m_keySizeInBits;

	bool PrepareClass(const tsCryptoStringBase& fullName)
	{
		tsCryptoString algorithm(fullName);
		tsCryptoString alg;
		tsCryptoStringList parts;

		desc = nullptr;
		m_context.clear();
		SetName(algorithm);
		parts = algorithm.split('-');
		if (parts->size() == 1)
			parts->push_back("AES");
		alg = "XTS-" + parts->at(1);

		desc = findXtsAlgorithm(alg.c_str());
		if (desc == nullptr)
			return false;

		m_baseName = GetName();

		return true;
	}
};

tscrypto::ICryptoObject* CreateXTS()
{
	return dynamic_cast<tscrypto::ICryptoObject*>(new XTSImpl);
}

#if 0
bool XTS_AES::runTests(bool runDetailedTests)
{
	bool testPassed = false;

	if (!gFipsState.operational())
		return false;
	if (desc == nullptr)
		return false;

	if (TsStrStr(GetName(), "AES") != nullptr)
	{
		fipsTestsForAESXTS(std::dynamic_pointer_cast<tscrypto::XTS>(_me.lock()), runDetailedTests);
	}
	else
	{
		std::shared_ptr<TSExtensibleSelfTest> exSelfTest = std::dynamic_pointer_cast<TSExtensibleSelfTest>(CryptoFactory(&m_baseName.c_str()[4]));

		if (!exSelfTest)
			exSelfTest.reset();

		if (!!exSelfTest)
		{
			testPassed = exSelfTest->RunSelfTestsFor("XTS", _me.lock(), runDetailedTests);
		}

		if (!testPassed)
		{
			gFipsState.testFailed();
			return false;
		}
	}
	return true;
}
#endif // 0
