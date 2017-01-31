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

class RSA_KEM_KWS : public RsaKemKws, public TSName, public Selftest, public tscrypto::ICryptoObject, public tscrypto::IInitializableObject, public AlgorithmInfo
{
public:
    RSA_KEM_KWS(const tsCryptoStringBase& algorithm);
    virtual ~RSA_KEM_KWS(void);

    // Selftests
    virtual bool runTests(bool runDetailedTests) override;

    // AlgorithmInfo
    virtual tsCryptoString AlgorithmName() const override;
    virtual tsCryptoString AlgorithmOID() const override;
    virtual TS_ALG_ID AlgorithmID() const override;

    // RsaKemKws
	virtual bool Wrap(std::shared_ptr<RsaKey> key, const tsCryptoStringBase& KDFname, const tsCryptoData &kdfOtherInfo, const tsCryptoStringBase& KeyWrapName, size_t kwkBits, const tsCryptoData &keyData, const tsCryptoData &additionalInfo, tsCryptoData &cipherText) override;
	virtual bool Unwrap(std::shared_ptr<RsaKey> key, const tsCryptoStringBase& KDFname, const tsCryptoData &kdfOtherInfo, const tsCryptoStringBase& KeyWrapName, size_t kwkBits, const tsCryptoData &cipherText, const tsCryptoData &additionalInfo, tsCryptoData &keyData) override;

	// tscrypto::IInitializableObject
	virtual bool InitializeWithFullName(const tscrypto::tsCryptoStringBase& fullName) override
	{
		tsCryptoString algorithm(fullName);

		SetName(algorithm);
		return true;
	}

};

tscrypto::ICryptoObject* CreateRsaKemKws(const tsCryptoStringBase& algorithm)
{
	return dynamic_cast<tscrypto::ICryptoObject*>(new RSA_KEM_KWS(algorithm));
}

RSA_KEM_KWS::RSA_KEM_KWS(const tsCryptoStringBase& algorithm)
{
    SetName(algorithm);
}

RSA_KEM_KWS::~RSA_KEM_KWS(void)
{
}

bool RSA_KEM_KWS::runTests(bool /*runDetailedTests*/)
{
    if (!gFipsState.operational())
        return false;
    // TODO:  See if tests are needed here
    return true;
}

tsCryptoString RSA_KEM_KWS::AlgorithmName() const
{
    return GetName();
}

tsCryptoString RSA_KEM_KWS::AlgorithmOID() const
{
    return LookUpAlgOID(GetName());
}

TS_ALG_ID RSA_KEM_KWS::AlgorithmID() const
{
    return LookUpAlgID(GetName());
}

bool RSA_KEM_KWS::Wrap(std::shared_ptr<RsaKey> key, const tsCryptoStringBase& KDFname, const tsCryptoData &kdfOtherInfo, const tsCryptoStringBase& KeyWrapName, size_t kwkBits, const tsCryptoData &keyData, const tsCryptoData &additionalInfo, tsCryptoData &cipherText)
{
    if (!gFipsState.operational())
        return false;
//    BigInteger n;
    std::shared_ptr<RsaPrimitives> prims;
    //uint32_t nLen;
    std::shared_ptr<KeyDerivationFunction> kdf;
    std::shared_ptr<KeyTransport> transport;
    std::shared_ptr<RsaSVE> sve;
    tsCryptoData Z, c0, kwk, c1;

    cipherText.clear();

    if (!key || !(prims = std::dynamic_pointer_cast<RsaPrimitives>(key)))
        return false;

    //n = key->get_PublicModulus();
    //nLen = (n.BitLength() + 7) / 8;
	//nLen = (uint32_t)key->get_PublicModulus().size();

    if (KDFname.size() == 0 || KeyWrapName.size() == 0)
        return false;

    if (!(kdf = std::dynamic_pointer_cast<KeyDerivationFunction>(CryptoFactory(KDFname))))
        return false;
	if (!(transport = std::dynamic_pointer_cast<KeyTransport>(CryptoFactory(KeyWrapName))))
        return false;
	if (!(sve = std::dynamic_pointer_cast<RsaSVE>(CryptoFactory("RSASVE"))))
        return false;

    if (!transport->CanWrap(keyData))
        return false;

    if (!sve->Generate(key, Z, c0))
        return false;

    if (!kdf->Derive_SP800_56A_Counter(Z, kdfOtherInfo, kwkBits, kwk))
        return false;

    if (!transport->initializeWithSymmetricKey(kwk) || !transport->Wrap(keyData, additionalInfo, c1))
        return false;

    cipherText.append(c0).append(c1);
    return true;
}

bool RSA_KEM_KWS::Unwrap(std::shared_ptr<RsaKey> key, const tsCryptoStringBase& KDFname, const tsCryptoData &kdfOtherInfo, const tsCryptoStringBase& KeyWrapName, size_t kwkBits, const tsCryptoData &cipherText, const tsCryptoData &additionalInfo, tsCryptoData &keyData)
{
    if (!gFipsState.operational())
        return false;
//    BigInteger n;
    std::shared_ptr<RsaPrimitives> prims;
    uint32_t nLen;
    std::shared_ptr<KeyDerivationFunction> kdf;
    std::shared_ptr<KeyTransport> transport;
    std::shared_ptr<RsaSVE> sve;
    tsCryptoData Z, c0, kwk, c1, plaintext;

    keyData.clear();

    if (!key || !(prims = std::dynamic_pointer_cast<RsaPrimitives>(key)))
        return false;

    //n = key->get_PublicModulus();
    //nLen = (n.BitLength() + 7) / 8;
	nLen = (uint32_t)key->get_PublicModulus().size();

    if (KDFname.size() == 0 || KeyWrapName.size() == 0)
        return false;

	if (!(kdf = std::dynamic_pointer_cast<KeyDerivationFunction>(CryptoFactory(KDFname))))
        return false;
	if (!(transport = std::dynamic_pointer_cast<KeyTransport>(CryptoFactory(KeyWrapName))))
        return false;
	if (!(sve = std::dynamic_pointer_cast<RsaSVE>(CryptoFactory("RSASVE"))))
        return false;

    if (cipherText.size() <= nLen || !transport->CanUnwrap(cipherText))
        return false;

    c0 = cipherText.substring(0, nLen);
    c1 = cipherText.right(cipherText.size() - nLen);

    if (!sve->Recover(key, c0, Z))
        return false;

    if (!kdf->Derive_SP800_56A_Counter(Z, kdfOtherInfo, kwkBits, kwk))
        return false;

    if (!transport->initializeWithSymmetricKey(kwk) || !transport->Unwrap(c1, additionalInfo, plaintext))
        return false;

    keyData = plaintext;
    return true;
}

