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

class PbKdfImpl : public PbKdf, public TSName, public tscrypto::ICryptoObject, public tscrypto::IInitializableObject, public AlgorithmInfo
{
public:
    PbKdfImpl(const tsCryptoStringBase& algorithm)
	{
		SetName(algorithm);
		desc = findPbkdfAlgorithm("PBKDF");
	}
	virtual ~PbKdfImpl(void)
	{
	}

    // AlgorithmInfo
    virtual tsCryptoString  AlgorithmName() const override
	{
		return GetName();
	}
	virtual tsCryptoString  AlgorithmOID() const override
	{
		return LookUpAlgOID(GetName());
	}
	virtual TS_ALG_ID AlgorithmID() const override
	{
		return LookUpAlgID(GetName());
	}

    // Pbkdf
    virtual bool PKCS5_PBKDF2(const tsCryptoStringBase& hmacName, const tsCryptoData &password, const tsCryptoData &salt, size_t counter, tsCryptoData &key, size_t keyLenNeeded) const override
	{
		const MAC_Descriptor* macDesc = nullptr;
		SmartCryptoWorkspace macWorkspace;

		if (!gFipsState.operational() || desc == nullptr)
		{
			return false;
		}

		if (TsStrniCmp(hmacName.c_str(), "HMAC-", 5) != 0)
		{
			macDesc = findMacAlgorithm(("HMAC-" + hmacName).c_str());
		}
		if (macDesc == nullptr)
		{
			macDesc = findMacAlgorithm(hmacName.c_str());
		}
		if (macDesc == nullptr)
			return false;
		macWorkspace = macDesc;

		key.clear();

		if (password.size() == 0)
		{
			return false;
		}

		key.resize(keyLenNeeded);

		bool retVal = desc->PKCS5_PBKDF2(desc, macDesc, macWorkspace, password.c_str(), (uint32_t)password.size(), salt.c_str(), (uint32_t)salt.size(), (uint32_t)counter, key.rawData(), (uint32_t)keyLenNeeded);

		if (!retVal)
			key.clear();
		return retVal;
	}
	virtual bool PKCS5_PBKDF2_With_Mac(const tsCryptoStringBase& hmacName, const tsCryptoData &password, const tsCryptoData &salt, size_t counter, tsCryptoData &key, size_t keyLenNeeded, 
		tsCryptoData &mac) const override
	{
		const MAC_Descriptor* macDesc = nullptr;
		SmartCryptoWorkspace macWorkspace;

		if (!gFipsState.operational() || desc == nullptr)
		{
			return false;
		}

		if (TsStrniCmp(hmacName.c_str(), "HMAC-", 5) != 0)
		{
			macDesc = findMacAlgorithm(("HMAC-" + hmacName).c_str());
		}
		if (macDesc == nullptr)
		{
			macDesc = findMacAlgorithm(hmacName.c_str());
		}
		if (macDesc == nullptr)
			return false;
		macWorkspace = macDesc;

		key.clear();

		if (password.size() == 0)
		{
			return false;
		}

		key.resize(keyLenNeeded);
		mac.resize(macDesc->getDigestSize(macDesc));

		bool retVal = desc->PKCS5_PBKDF2_With_Mac(desc, macDesc, macWorkspace, password.c_str(), (uint32_t)password.size(), salt.c_str(), (uint32_t)salt.size(), (uint32_t)counter, key.rawData(), (uint32_t)keyLenNeeded, mac.rawData(), (uint32_t)mac.size());

		if (!retVal)
		{
			key.clear();
			mac.clear();
		}
		return retVal;
	}
	virtual bool Pkcs12Pbkdf_Ascii(const tsCryptoStringBase& hashAlg, const tsCryptoStringBase& password, uint8_t id, const tsCryptoData& salt, size_t iter, size_t outputLengthInBits, 
		tsCryptoData& Key) const override
	{
		const HASH_Descriptor* hasher;
		SmartCryptoWorkspace hashWorkspace;

		if (!gFipsState.operational() || desc == nullptr)
			return false;

		hasher = findHashAlgorithm(hashAlg.c_str());
		if (hasher == nullptr)
			return false;
		hashWorkspace = hasher;

		Key.clear();
		Key.resize((outputLengthInBits + 7) / 8);

		bool retVal = desc->Pkcs12Pbkdf_Ascii(desc, hasher, hashWorkspace, password.c_str(), id, salt.c_str(), (uint32_t)salt.size(), (uint32_t)iter, (uint32_t)outputLengthInBits, Key.rawData());
		if (!retVal)
			Key.clear();
		return retVal;
	}
	virtual bool PBKDF1(const tsCryptoStringBase& hashName, const tsCryptoStringBase & password, const tsCryptoData & iv, int keyLenInBytes, tsCryptoData& Key) const override
	{
		const HASH_Descriptor* hasher;
        SmartCryptoWorkspace hashWorkspace;

		if (!gFipsState.operational() || desc == nullptr)
			return false;

		hasher = findHashAlgorithm(hashName.c_str());
		if (hasher == nullptr)
			return false;
		hashWorkspace = hasher;

		Key.clear();
		Key.resize(keyLenInBytes);
		bool retVal = desc->PBKDF1(desc, hasher, hashWorkspace, password.c_str(), iv.c_str(), (uint32_t)iv.size(), keyLenInBytes, Key.rawData());
		if (!retVal)
			Key.clear();
		return retVal;
	}

	// tscrypto::IInitializableObject
	virtual bool InitializeWithFullName(const tscrypto::tsCryptoStringBase& fullName) override
	{
		SetName(fullName);
		return true;
	}

protected:
	const PBKDF_Descriptor* desc;
};

tscrypto::ICryptoObject* CreatePbkdf()
{
	return dynamic_cast<tscrypto::ICryptoObject*>(new PbKdfImpl("KDF-PBKDF2"));
}

