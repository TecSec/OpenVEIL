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

static bool isZero(const uint8_t* data, size_t dataLen)
{
	uint8_t c = 0;
	for (size_t i = 0; i < dataLen; i++)
	{
		c |= data[i];
	}
	return c == 0;
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

class RSASVEImpl : public RsaSVE, public TSName, public Selftest, public tscrypto::ICryptoObject, public tscrypto::IInitializableObject, public AlgorithmInfo
{
public:
    RSASVEImpl(const tsCryptoStringBase& algorithm);
    virtual ~RSASVEImpl(void);

    // Selftests
    virtual bool runTests(bool runDetailedTests) override;

    // AlgorithmInfo
    virtual tsCryptoString AlgorithmName() const override;
    virtual tsCryptoString AlgorithmOID() const override;
    virtual TS_ALG_ID AlgorithmID() const override;

    // RsaSVE
	virtual bool Generate(std::shared_ptr<RsaKey> key, tsCryptoData &Z, tsCryptoData &cipherText) override;
	virtual bool Recover(std::shared_ptr<RsaKey> key, const tsCryptoData &cipherText, tsCryptoData &Z) override;

	// tscrypto::IInitializableObject
	virtual bool InitializeWithFullName(const tscrypto::tsCryptoStringBase& fullName) override
	{
		tsCryptoString algorithm(fullName);

		SetName(algorithm);
		return true;
	}
};

RSASVEImpl::RSASVEImpl(const tsCryptoStringBase& algorithm)
{
}

RSASVEImpl::~RSASVEImpl(void)
{
}

tscrypto::ICryptoObject* CreateRsaSve(const tsCryptoStringBase& algorithm)
{
	return dynamic_cast<tscrypto::ICryptoObject*>(new RSASVEImpl(algorithm));
}

bool RSASVEImpl::runTests(bool runDetailedTests)
{
	if (!gFipsState.operational())
        return false;

	if (runDetailedTests)
	{
		std::shared_ptr<RsaKey> key;
		tsCryptoData e("10001", tsCryptoData::HEX);
		tsCryptoData m("647586ba587b09aa555d1b8da4cdf5c6e777e08859379ca45789019f2041e708", tsCryptoData::HEX);
		tsCryptoData n("ed501261d702f1c27dddda89387a2018cae145ad1f542c6d4dea2444932778b957c503275bcc0cbd18582cba5216370e1416141a48bc67242d38222c03bb55c57d04fa4d3bcb2f07754e4e8b23432ea761ddb0df7aa1d4b21de580235766aa43e04aae46f3fc0c2db75c3d63edb303ea1d3f1c6f72a85f64f10f1222872a6e9f", tsCryptoData::HEX);
		tsCryptoData s("686a44f3f199b1e024c7fc2aea6749eab4b618d739c422dae0685c13b8df6253a8e7a9a60a774cf160e8a1e548f2e15b0db4192e4e941659b7e37e708e7be50b9f542d25c9b7ef6a158c3a0a3d18e6095239cd16948c561270c37c2dff6698440a4002df152f53ca5deadd5af7afa72c62f79cbf3c6057cca20694564d5f4911", tsCryptoData::HEX);

		if (!(key = std::dynamic_pointer_cast<RsaKey>(CryptoFactory("Key-Rsa"))) ||
			!key->set_Exponent(tsCryptoData("010001", tsCryptoData::HEX)) ||
			!key->set_PublicModulus(tsCryptoData("a8b3b284af8eb50b387034a860f146c4919f318763cd6c5598c8ae4811a1e0abc4c7e0b082d693a5e7fced675cf4668512772c0cbc64a742c6c630f533c8cc72f62ae833c40bf25842e984bb78bdbf97c0107d55bdb662f5c4e0fab9845cb5148ef7392dd3aaff93ae1e6b667bb3d4247616d4f5ba10d4cfd226de88d39f16fb", tsCryptoData::HEX)) ||
			!key->set_p(tsCryptoData("d32737e7267ffe1341b2d5c0d150a81b586fb3132bed2f8d5262864a9cb9f30af38be448598d413a172efb802c21acf1c11c520c2f26a471dcad212eac7ca39d", tsCryptoData::HEX)) ||
			!key->set_q(tsCryptoData("cc8853d1d54da630fac004f471f281c7b8982d8224a490edbeb33d3e3d5cc93c4765703d1dd791642f1f116a0dd852be2419b2af72bfe9a030e860b0288b5d77", tsCryptoData::HEX)) ||
			!key->set_dp(tsCryptoData("0e12bf1718e9cef5599ba1c3882fe8046a90874eefce8f2ccc20e4f2741fb0a33a3848aec9c9305fbecbd2d76819967d4671acc6431e4037968db37878e695c1", tsCryptoData::HEX)) ||
			!key->set_dq(tsCryptoData("95297b0f95a2fa67d00707d609dfd4fc05c89dafc2ef6d6ea55bec771ea333734d9251e79082ecda866efef13c459e1a631386b7e354c899f5f112ca85d71583", tsCryptoData::HEX)) ||
			!key->set_qInv(tsCryptoData("4f456c502493bdc0ed2ab756a3a6ed4d67352a697d4216e93212b127a63d5411ce6fa98d5dbefd73263e3728142743818166ed7dd63687dd2a8ca1d2f4fbd8e1", tsCryptoData::HEX)))
		{
			gFipsState.testFailed();
			return false;
		}
		key->Clear();

		key->set_PublicModulus(n);
		key->set_Exponent(e);

	}
    return true;
}

tsCryptoString RSASVEImpl::AlgorithmName() const
{
    return GetName();
}

tsCryptoString RSASVEImpl::AlgorithmOID() const
{
    return LookUpAlgOID(GetName());
}

TS_ALG_ID RSASVEImpl::AlgorithmID() const
{
    return LookUpAlgID(GetName());
}

bool RSASVEImpl::Generate(std::shared_ptr<RsaKey> key, tsCryptoData &Z, tsCryptoData &cipherText)
{
    if (!gFipsState.operational())
        return false;
    std::shared_ptr<RsaPrimitives> prims;

    Z.clear();
    cipherText.clear();

    if (!key || !(prims = std::dynamic_pointer_cast<RsaPrimitives>(key)))
        return false;

	tsCryptoData z;
	size_t modLen = (key->KeySize() + 7) / 8;
	tsCryptoData n;
	n = key->get_PublicModulus();

    do
    {
		if (!TSGenerateRandom(z, modLen))
			return false;
    }
	while (isZero(z.c_str(), z.size()) || isGreaterOrEqual(z, n));

    if (!prims->EncryptPrimitive(z, cipherText))
    {
        cipherText.clear();
        return false;
    }
    Z = z;
    return true;
}

bool RSASVEImpl::Recover(std::shared_ptr<RsaKey> key, const tsCryptoData &cipherText, tsCryptoData &Z)
{
    if (!gFipsState.operational())
        return false;
	tsCryptoData n;
    std::shared_ptr<RsaPrimitives> prims;

    Z.clear();

    if (!key || !(prims = std::dynamic_pointer_cast<RsaPrimitives>(key)))
        return false;

    n = key->get_PublicModulus();

	if (isZero(cipherText.c_str(), cipherText.size()) || isGreaterOrEqual(cipherText, n))
        return false;

    if (!prims->DecryptPrimitive(cipherText, Z))
    {
        Z.clear();
        return false;
    }

    return true;
}

