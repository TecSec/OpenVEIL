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

class XOFImpl : public AlgorithmInfo, public XOF, public TSName, public tscrypto::ICryptoObject, public tscrypto::IInitializableObject
{
public:
	XOFImpl() :
		bitSize(256),
		outputSize(512)
	{
		desc = findXofAlgorithm("SHAKE256");
		SetName("SHAKE256");
	}
	virtual ~XOFImpl(void)
	{
	}

	virtual bool initialize() override
	{
		if (!gFipsState.operational() || desc == nullptr)
			return false;
		context.reset();
		context = desc;
		return desc->init(desc, context);
	}
	virtual bool update(const tsCryptoData &data) override
	{
		if (!gFipsState.operational() || desc == nullptr)
			return false;
		if (context.empty())
			return false;
		return desc->update(desc, context, data.c_str(), (uint32_t)data.size());
	}
	virtual bool finish(tsCryptoData &digest) override
	{
		if (!gFipsState.operational() || desc == nullptr)
			return false;
		digest.resize((outputSize + 7) / 8);
		if (context.empty())
			return false;
		bool retVal = desc->finish(desc, context, digest.rawData(), (uint32_t)digest.size());
		context.reset();
		return retVal;
	}
	virtual size_t GetBlockSize() override
	{
		return desc->blockSize;
	}
	virtual size_t GetDigestSize() override
	{
		return outputSize / 8;
	}
	virtual size_t minimumKeySizeInBits() const override
	{
		return desc->minimumKeySize;
	}
	virtual size_t maximumKeySizeInBits() const override
	{
		return desc->maximumKeySize;
	}
	virtual size_t keySizeIncrementInBits() const override
	{
		return desc->keySizeIncrement;
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
		algorithm.ToUpper();
		tsCryptoStringList parts = algorithm.split('-');

		desc = findXofAlgorithm(fullName.c_str());
		if (desc != nullptr)
		{
			bitSize = desc->digestSize * 8;
		}
		else
			return false;

		if (parts->size() > 1)
		{
			outputSize = TsStrToInt(parts->at(1).c_str());
		}
		if (outputSize < 16)
			outputSize = bitSize * 2;

		algorithm = parts->at(0);

		SetName(algorithm);

		context.reset();
		return true;
	}

protected:

private:
	SmartCryptoWorkspace context;
	const HASH_Descriptor *desc;
	int bitSize;
	int outputSize;
};

tscrypto::ICryptoObject* CreateXOF()
{
	return dynamic_cast<tscrypto::ICryptoObject*>(new XOFImpl);
}

