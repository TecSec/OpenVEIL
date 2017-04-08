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


class Prime_Provable :
    public ProvablePrime,
    public TSName,
	public tscrypto::ICryptoObject, 
	public tscrypto::IInitializableObject, 
	public AlgorithmInfo
{
public:
	Prime_Provable()
	{
		SetName("PRIME-PROVABLE");
		desc = findProvablePrimeAlgorithm("FIPS186-3-PROVABLE-PRIME");
	}
	virtual ~Prime_Provable(void)
	{
	}

    // ProvablePrime
    virtual bool GeneratePrime(size_t bitLength, const tsCryptoStringBase& hashName, const tsCryptoData &seed, tsCryptoData &prime, size_t &prime_gen_counter, size_t strength, tsCryptoData &primeSeed) override
	{
		const HASH_Descriptor* hasher;
		tsCryptoData hashWorkspace;
		uint32_t primeLen, counter = (uint32_t)prime_gen_counter;

		if (!gFipsState.operational() || desc == nullptr)
			return false;

		hasher = findHashAlgorithm(hashName.c_str());
		if (hasher == nullptr)
			return false;
		hashWorkspace.resize(hasher->getWorkspaceSize(hasher));

		primeLen = (uint32_t)(bitLength + 7) / 8;
		prime.resize(primeLen);
		primeSeed = seed;
		bool retVal = desc->generatePrime(desc, hasher, hashWorkspace.rawData(), (uint32_t)bitLength, primeSeed.rawData(), (uint32_t)primeSeed.size(), prime.rawData(), &primeLen, &counter, (uint32_t)strength);
		prime_gen_counter = counter;
		prime.resize(primeLen);
		if (!retVal)
		{
			prime.clear();
			primeSeed.clear();
		}
		return retVal;
	}
    virtual bool ConstructPrimeFromFactors(size_t bitLength, const tsCryptoStringBase& hashName, size_t p1BitLength, size_t p2BitLength, tsCryptoData &firstSeed, const tsCryptoData &exponent, 
		tsCryptoData &p1, tsCryptoData &p2, tsCryptoData &p, tsCryptoData &pSeed, size_t &counter, size_t strength) override
	{
		const HASH_Descriptor* hasher;
		tsCryptoData hashWorkspace;
		uint32_t count = (uint32_t)counter;
		uint32_t primeLen = (uint32_t)(bitLength + 7) / 8;
		uint32_t p1Len = (uint32_t)(p1BitLength + 7) / 8;
		uint32_t p2Len = (uint32_t)(p2BitLength + 7) / 8;
		
		if (!gFipsState.operational() || desc == nullptr)
			return false;

		hasher = findHashAlgorithm(hashName.c_str());
		if (hasher == nullptr)
			return false;
		hashWorkspace.resize(hasher->getWorkspaceSize(hasher));

		p.resize(primeLen);
		p1.resize(p1Len);
		p2.resize(p2Len);

		bool retVal = desc->constructPrimeFromFactors(desc, hasher, hashWorkspace.rawData(), (uint32_t)bitLength, (uint32_t)p1BitLength, (uint32_t)p2BitLength, 
			firstSeed.rawData(), (uint32_t)firstSeed.size(), exponent.c_str(), (uint32_t)exponent.size(), p1.rawData(), &p1Len, p2.rawData(), &p2Len, p.rawData(), &primeLen, &count, (uint32_t)strength);
		counter = count;
		p.resize(primeLen);
		p1.resize(p1Len);
		p2.resize(p2Len);

		if (!retVal)
		{
			p.clear();
			p1.clear();
			p2.clear();
		}
		return retVal;
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
	const ProvablePrimeDescriptor* desc;
};

tscrypto::ICryptoObject* CreateProvablePrime()
{
	return dynamic_cast<tscrypto::ICryptoObject*>(new Prime_Provable());
}


