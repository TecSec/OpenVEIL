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

class KDF : public KeyDerivationFunction, public TSName, public tscrypto::ICryptoObject, public tscrypto::IInitializableObject, public AlgorithmInfo
{
public:
	KDF()
	{
		desc = findKdfAlgorithm("KDF");
		if (desc != nullptr)
			workspace.resize(desc->getWorkspaceSize(desc));
		macDesc = findMacAlgorithm("SHA512");
		if (macDesc != nullptr)
			macWorkspace.resize(macDesc->getWorkspaceSize(macDesc));
	}
	virtual ~KDF(void)
	{
	}

    // KeyDerivationFunction
    virtual bool initialize() override
	{
		if (!gFipsState.operational() || desc == nullptr || macDesc == nullptr)
			return false;

		if (!desc->configure(desc, workspace.rawData(), macDesc, macWorkspace.rawData()))
			return false;
		return desc->init(desc, workspace.rawData());
	}
	virtual bool initializeWithKey(const tsCryptoData &key) override
	{
		if (!gFipsState.operational() || desc == nullptr || macDesc == nullptr)
			return false;

		if (!desc->configure(desc, workspace.rawData(), macDesc, macWorkspace.rawData()))
			return false;
		return desc->initWithKey(desc, workspace.rawData(), key.c_str(), (uint32_t)key.size());
	}
	virtual bool Derive_X9_63_Counter(const tsCryptoData &Z, const tsCryptoData &otherInfo, size_t outputBitLength, tsCryptoData &output) override
	{
		if (!gFipsState.operational() || desc == nullptr || macDesc == nullptr)
			return false;

		output.resize((outputBitLength + 7) / 8);
		bool retVal = desc->derive_X9_63_Counter(desc, workspace.rawData(), Z.c_str(), (uint32_t)Z.size(), otherInfo.c_str(), (uint32_t)otherInfo.size(), (uint32_t)outputBitLength, output.rawData());
		if (!retVal)
			output.clear();
		return retVal;
	}
	virtual bool Derive_SP800_108_Counter(bool containsBitLength, size_t bytesOfBitLength, bool containsLabel, int32_t counterLocation, size_t counterByteLength, const tsCryptoData &Label,
		const tsCryptoData &Context, size_t outputBitLength, tsCryptoData &output) override
	{
		if (!gFipsState.operational() || desc == nullptr || macDesc == nullptr)
			return false;

		output.resize((outputBitLength + 7) / 8);
		bool retVal = desc->derive_SP800_108_Counter(desc, workspace.rawData(), containsBitLength, (uint32_t)bytesOfBitLength, containsLabel, counterLocation, (uint32_t)counterByteLength,
			Label.c_str(), (uint32_t)Label.size(), Context.c_str(), (uint32_t)Context.size(), (uint32_t)outputBitLength, output.rawData());
		if (!retVal)
			output.clear();
		return retVal;
	}
	virtual bool Derive_SP800_108_Feedback(Kdf_feedbackCounterLocation counterLocation, uint32_t counterByteLength, bool containsBitLength, uint32_t bytesOfBitLength, bool containsLabel, const tsCryptoData &feedbackIV, const tsCryptoStringBase &Label, const tsCryptoData &Context, size_t outputBitLength, tsCryptoData &output) override
	{
		if (!gFipsState.operational() || desc == nullptr || macDesc == nullptr)
			return false;

		output.resize((outputBitLength + 7) / 8);
		bool retVal = desc->derive_SP800_108_Feedback(desc, workspace.rawData(), (kdf_feedbackCounterLocation)counterLocation, counterByteLength, containsBitLength, bytesOfBitLength, containsLabel, feedbackIV.c_str(), (uint32_t)feedbackIV.size(), (uint8_t*)Label.c_str(), (uint32_t)Label.size(),
			Context.c_str(), (uint32_t)Context.size(), (uint32_t)outputBitLength, output.rawData());
		if (!retVal)
			output.clear();
		return retVal;
	}
	virtual bool Derive_SP800_56A_Counter(const tsCryptoData &Z, const tsCryptoData &otherInfo, size_t outputBitLength, tsCryptoData &output) override
	{
		if (!gFipsState.operational() || desc == nullptr || macDesc == nullptr)
			return false;

		output.resize((outputBitLength + 7) / 8);
		bool retVal = desc->derive_SP800_56A_Counter(desc, workspace.rawData(), Z.c_str(), (uint32_t)Z.size(), otherInfo.c_str(), (uint32_t)otherInfo.size(),
			(uint32_t)outputBitLength, output.rawData());
		if (!retVal)
			output.clear();
		return retVal;
	}
	virtual bool Derive_SP800_56A_Feedback(bool includeCounter, const tsCryptoData &feedbackIV, const tsCryptoData &Z, const tsCryptoData &otherInfo, size_t outputBitLength, tsCryptoData &output) override
	{
		if (!gFipsState.operational() || desc == nullptr || macDesc == nullptr)
			return false;

		output.resize((outputBitLength + 7) / 8);
		bool retVal = desc->derive_SP800_56A_Feedback(desc, workspace.rawData(), includeCounter, feedbackIV.c_str(), (uint32_t)feedbackIV.size(), Z.c_str(), (uint32_t)Z.size(),
			otherInfo.c_str(), (uint32_t)otherInfo.size(), (uint32_t)outputBitLength, output.rawData());
		if (!retVal)
			output.clear();
		return retVal;
	}
	virtual bool Derive_SCP03(uint8_t type, size_t outputBitLength, const tsCryptoData &Context, tsCryptoData &output) override
	{
		if (!gFipsState.operational() || desc == nullptr || macDesc == nullptr)
			return false;

		output.resize((outputBitLength + 7) / 8);
		bool retVal = desc->derive_SCP03(desc, workspace.rawData(), type, (uint32_t)outputBitLength, Context.c_str(), (uint32_t)Context.size(), output.rawData());
		if (!retVal)
			output.clear();
		return retVal;
	}
	virtual bool Derive_Raw(bool includeCounter, bool useFeedback, const tsCryptoData &feedbackIV, const tsCryptoData &Context, size_t counterLength, size_t counterStart,
		size_t feedbackPosition, size_t outputBitLength, tsCryptoData &output) override
	{
		if (!gFipsState.operational() || desc == nullptr || macDesc == nullptr)
			return false;

		output.resize((outputBitLength + 7) / 8);
		bool retVal = desc->derive_Raw(desc, workspace.rawData(), includeCounter, useFeedback, feedbackIV.c_str(), (uint32_t)feedbackIV.size(), Context.c_str(), (uint32_t)Context.size(), 
			(uint32_t)counterLength, (uint32_t)counterStart, (uint32_t)feedbackPosition, (uint32_t)outputBitLength, output.rawData());
		if (!retVal)
			output.clear();
		return retVal;
	}
	virtual bool finish() override
	{
		if (!gFipsState.operational() || desc == nullptr || macDesc == nullptr)
			return false;

		return desc->finish(desc, workspace.rawData());
	}
	virtual size_t GetBlockSize() override
	{
		if (desc == nullptr || macDesc == nullptr)
			return 0;
		return macDesc->getBlockSize(macDesc);
	}
	virtual size_t GetDigestSize() override
	{
		if (desc == nullptr || macDesc == nullptr)
			return 0;
		return macDesc->getDigestSize(macDesc);
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
		tsCryptoString algorithm(fullName);

		SetName(algorithm);
		macWorkspace.clear();
		macDesc = nullptr;
		if (algorithm.size() < 5)
		{
			macDesc = findMacAlgorithm("SHA512");
			SetName("KDF-SHA512");
		}
		else
		{
			tsCryptoString name = &algorithm.c_str()[4];

			if (TsStrniCmp(name, "HASH-", 5) == 0)
				name.erase(0, 5);

			name.ToUpper().Replace("SHA3-", "SHA3_");
			macDesc = findMacAlgorithm(name.c_str());
		}
		if (macDesc == nullptr)
		{
			return false;
		}
		macWorkspace.resize(macDesc->getWorkspaceSize(macDesc));
		return true;
	}

private:
	const KDF_Descriptor* desc;
	tsCryptoData workspace;
	const MAC_Descriptor* macDesc;
	tsCryptoData macWorkspace;
};

tscrypto::ICryptoObject* CreateKDF()
{
	return dynamic_cast<tscrypto::ICryptoObject*>(new KDF);
}

#if 0
bool KDF::runTests(bool runDetailedTests)
{
    bool testPassed = false;

    if (!gFipsState.operational())
        return false;
    if (!m_prf)
        return false;

	std::shared_ptr<TSExtensibleSelfTest> exSelfTest = std::dynamic_pointer_cast<TSExtensibleSelfTest>(m_prf);

	if (!m_prf || !exSelfTest)
		exSelfTest.reset();

	if (!!exSelfTest)
	{
		testPassed = exSelfTest->RunSelfTestsFor("KDF", _me.lock(), runDetailedTests);
	}

    if (!testPassed)
    {
        gFipsState.testFailed();
        return false;
    }
    return true;
}
#endif // 0
