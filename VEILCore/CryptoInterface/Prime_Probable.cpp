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

class Prime_Probable :
     public ProbablePrime,
     public TSName,
	 public tscrypto::ICryptoObject, 
	 public tscrypto::IInitializableObject, 
	 public AlgorithmInfo
{
public:
	Prime_Probable()
	{
		SetName("PRIME-PROBABLE");
		desc = findProbablePrimeAlgorithm("FIPS186-3-PROBABLE-PRIME");
	}
	virtual ~Prime_Probable(void)
	{
	}

    // Prime
    virtual bool GeneratePrime(size_t bitLength, size_t rounds, bool strongPrime, tsCryptoData &prime) override
	{
		if (!gFipsState.operational() || desc == nullptr)
			return false;

		prime.resize((bitLength + 7) / 8);
		bool retVal = desc->generatePrime(desc, (uint32_t)bitLength, (uint32_t)rounds, strongPrime, prime.rawData());
		if (!retVal)
			prime.clear();
		return retVal;
	}
	virtual bool ComputeRounds(bool forRSA, size_t primebitLength, size_t subprimebitLength, bool use100Probability, size_t &subprimeRounds, size_t &primeRounds, bool &useStrong) override
	{
		uint32_t subRound, round;
		ts_bool UseStrong;

		if (!gFipsState.operational() || desc == nullptr)
			return false;

		bool retVal = desc->computeRounds(desc, forRSA, (uint32_t)primebitLength, (uint32_t)subprimebitLength, use100Probability, &subRound, &round, &UseStrong);

		if (retVal)
		{
			subprimeRounds = subRound;
			primeRounds = round;
			useStrong = UseStrong;
		}

		return retVal;
	}
	virtual bool IsComposite(size_t rounds, bool strongPrime, const tsCryptoData &candidate) override
	{
		if (!gFipsState.operational() || desc == nullptr)
			return false;
		return desc->isComposite(desc, (uint32_t)rounds, strongPrime, candidate.c_str(), (uint32_t)candidate.size());
	}
	virtual bool IsCompositeAndNotPowerOfAPrime(size_t rounds, bool strongPrime, const tsCryptoData &candidate) override
	{
		if (!gFipsState.operational() || desc == nullptr)
			return false;
		return desc->isCompositeAndNotPowerOfAPrime(desc, (uint32_t)rounds, strongPrime, candidate.c_str(), (uint32_t)candidate.size());
	}
	virtual bool NextPrime(size_t rounds, bool strongPrime, tsCryptoData &value) override
	{
		if (!gFipsState.operational() || desc == nullptr)
			return false;
		if (value.size() == 0)
			return false;

		value[value.size() - 1] |= 1; // force to be odd
		return desc->nextPrime(desc, (uint32_t)rounds, strongPrime, value.rawData(), (uint32_t)value.size());
	}
	virtual bool ComputeCompositePrime(size_t primeLengthInBits, size_t primeRounds, const tsCryptoData &r1, const tsCryptoData &r2, const tsCryptoData &exponent, tsCryptoData &X, 
		tsCryptoData &prime) override
	{
		uint32_t XLen = 0;
		uint32_t primeLen = 0;

		if (!gFipsState.operational() || desc == nullptr)
			return false;

		if (!desc->computeCompositePrime(desc, (uint32_t)primeLengthInBits, (uint32_t)primeRounds, r1.c_str(), (uint32_t)r1.size(), r2.c_str(), (uint32_t)r2.size(), exponent.c_str(), (uint32_t)exponent.size(),
			NULL, &XLen, NULL, &primeLen))
		{
			return false;
		}
		prime.resize(primeLen);
		X.resize(XLen);
		if (!desc->computeCompositePrime(desc, (uint32_t)primeLengthInBits, (uint32_t)primeRounds, r1.c_str(), (uint32_t)r1.size(), r2.c_str(), (uint32_t)r2.size(), exponent.c_str(), (uint32_t)exponent.size(),
			X.rawData(), &XLen, prime.rawData(), &primeLen))
		{
			prime.clear();
			X.clear();
			return false;
		}
		prime.resize(primeLen);
		X.resize(XLen);
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

	// tscrypto::IInitializableObject
	virtual bool InitializeWithFullName(const tscrypto::tsCryptoStringBase& fullName) override
	{
		tsCryptoString algorithm(fullName);

		SetName(algorithm);
		return true;
	}
protected:
	const ProbablePrimeDescriptor* desc;
};
tscrypto::ICryptoObject* CreateProbablePrime()
{
	return dynamic_cast<tscrypto::ICryptoObject*>(new Prime_Probable);
}

#if 0
bool Prime_Probable::runTests(bool runDetailedTests)
{
    if (!gFipsState.operational())
        return false;
	RsaNumber n = 20003;
	RsaNumber a = 1236;

    if (InnerJacobi(n, a) != 1)
    {
        gFipsState.testFailed();
        return false;
    }

    if (FindNegOneJacobi(RsaNumber(tsCryptoData("CD04262D", tsCryptoData::HEX))) != 5)
    {
        gFipsState.testFailed();
        return false;
    }

    if (runDetailedTests)
    {
        if (!IsComposite(32, true, tsCryptoData("c8387fd38fa33ddcea6a9de1b2d55410663502dbc225655a9310cceac9f4cf1bce653ec916d794077c286ad48c57bd26a965bf7596b048fd51d6a41715e1b519B", tsCryptoData::HEX)))
        {
            gFipsState.testFailed();
            return false;
        }
        if (IsComposite(32, true, tsCryptoData("1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", tsCryptoData::HEX)))
        {
            gFipsState.testFailed();
            return false;
        }
        if (IsComposite(32, true, tsCryptoData("c8387fd38fa33ddcea6a9de1b2d55410663502dbc225655a9310cceac9f4cf1bce653ec916d794077c286ad48c57bd26a965bf7596b048fd51d6a41715e1b517", tsCryptoData::HEX)))
        {
            gFipsState.testFailed();
            return false;
        }
    }

    return true;
}
#endif // 0

