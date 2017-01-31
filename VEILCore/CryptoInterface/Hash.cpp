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

class Hash_Alg :
    public MessageAuthenticationCode,
   	public TSName,
    public AlgorithmInfo, 
	public Hash,
	public tscrypto::ICryptoObject,
	public tscrypto::IInitializableObject
{
public:
	Hash_Alg(const tsCryptoStringBase& algorithm);
    virtual ~Hash_Alg(void);

    virtual bool initialize() override;
    virtual bool update(const tsCryptoData &data) override;
    virtual bool finish(tsCryptoData &digest) override;
    virtual size_t GetBlockSize() override;
    virtual size_t GetDigestSize() override;

    // MessageAuthenticationCode extra functions
    virtual bool initialize(const tsCryptoData &key) override;
    virtual bool isUsableKey(const tsCryptoData &key) override;
    virtual bool requiresKey() const override;
	virtual size_t minimumKeySizeInBits() const override;
	virtual size_t maximumKeySizeInBits() const override;
	virtual size_t keySizeIncrementInBits() const override;

    // AlgorithmInfo
    virtual tsCryptoString AlgorithmName() const override;
    virtual tsCryptoString AlgorithmOID() const override;
    virtual TS_ALG_ID AlgorithmID() const override;

	// tscrypto::IInitializableObject
	virtual bool InitializeWithFullName(const tscrypto::tsCryptoStringBase& fullName) override
	{
		tsCryptoString algName(fullName);

		if (TsStrniCmp(algName, "HASH-", 5) == 0)
			algName.erase(0, 5);
		algName.ToUpper();
		desc = findHashAlgorithm(algName.c_str());
		if (desc == nullptr)
		{
			tsCryptoStringList parts = tsCryptoString(fullName).split("-");
			desc = findHashAlgorithm(parts->back().c_str());
		}
		if (desc != nullptr)
		{
			context.clear();
			context.resize(desc->getWorkspaceSize(desc));
		}
		SetName(fullName);
		context.clear();
		return true;
	}
private:
    tsCryptoData context;
	const HASH_Descriptor* desc;
};

tscrypto::ICryptoObject* CreateHash()
{
	return dynamic_cast<tscrypto::ICryptoObject*>(new Hash_Alg("SHA1"));
}
Hash_Alg::Hash_Alg(const tsCryptoStringBase& algorithm)
{
	tsCryptoStringList parts = tsCryptoString(algorithm).split("-");
	desc = findHashAlgorithm(parts->back().c_str());
	if (desc != nullptr)
	{
		context.resize(desc->getWorkspaceSize(desc));
	}
	SetName(algorithm);
	context.clear();
}

Hash_Alg::~Hash_Alg(void)
{
	context.clear();
}

bool Hash_Alg::initialize()
{
    if (!gFipsState.operational())
        return false;
	context.clear();
	context.resize(desc->getWorkspaceSize(desc));
    return desc->init(desc, context.rawData());
}

bool Hash_Alg::update(const tsCryptoData &data)
{
    if (!gFipsState.operational())
        return false;
	if (desc == nullptr)
		return false;
	if (data.size() > 0)
    {
		return desc->update(desc, context.rawData(), data.c_str(), (uint32_t)data.size());
    }
    return true;
}

bool Hash_Alg::finish(tsCryptoData &digest)
{
    if (!gFipsState.operational() || desc == nullptr)
        return false;
    digest.resize(desc->digestSize);
	if (!context.empty())
	{
		if (!desc->finish(desc, context.rawData(), digest.rawData(), (uint32_t)digest.size()))
		{
			digest.clear();
			return false;
		}
	}
    return true;
}

#if 0
bool Hash_Alg::fips_test_sha1_hmac(std::shared_ptr<MessageAuthenticationCode> hm, bool runDetailed)
{
    tsCryptoData data;
    tsCryptoData key;
    tsCryptoData digest;
    uint32_t i;
    static BYTE key1[20]  = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    static BYTE data1[8]  = {'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e'};
    static BYTE hmac1[20] = {0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00};
    static BYTE key2[4]   = {'J', 'e', 'f', 'e'};
    static BYTE data2[28] = {'w', 'h', 'a', 't', ' ', 'd', 'o', ' ', 'y', 'a', ' ', 'w', 'a', 'n', 't', ' ', 'f', 'o', 'r', ' ', 'n', 'o', 't', 'h', 'i', 'n', 'g', '?'};
    static BYTE hmac2[20] = {0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2, 0xd2, 0x74, 0x16, 0xd5, 0xf1, 0x84, 0xdf, 0x9c, 0x25, 0x9a, 0x7c, 0x79};
    static BYTE key3[20]  = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};
    static BYTE data3[50] = {0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                             0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                             0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd};
    static BYTE hmac3[20] = {0x12, 0x5d, 0x73, 0x42, 0xb9, 0xac, 0x11, 0xcd, 0x91, 0xa3, 0x9a, 0xf4, 0x8a, 0xa1, 0x7b, 0x4f, 0x63, 0xf1, 0x75, 0xd3};
    static BYTE key4[25]  = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19};
    static BYTE data4[50] = {0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
                             0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
                             0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd};
    static BYTE hmac4[20] = {0x4c, 0x90, 0x07, 0xf4, 0x02, 0x62, 0x50, 0xc6, 0xbc, 0x84, 0x14, 0xf9, 0xbf, 0x50, 0xc8, 0x6c, 0x2d, 0x72, 0x35, 0xda};
    static BYTE key5[20]  = {0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c};
    static BYTE data5[20] = {'T', 'e', 's', 't', ' ', 'W', 'i', 't', 'h', ' ', 'T', 'r', 'u', 'n', 'c', 'a', 't', 'i', 'o', 'n'};
    static BYTE hmac5[20] = {0x4c, 0x1a, 0x03, 0x42, 0x4b, 0x55, 0xe0, 0x7f, 0xe7, 0xf2, 0x7b, 0xe1, 0xd5, 0x8b, 0xb9, 0x32, 0x4a, 0x9a, 0x5a, 0x04};
    static BYTE key6[80]  = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                             0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                             0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                             0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};
    static BYTE data6[54] = {'T', 'e', 's', 't', ' ', 'U', 's', 'i', 'n', 'g', ' ', 'L', 'a', 'r', 'g', 'e', 'r', ' ', 'T', 'h', 'a', 'n', ' ', 'B', 'l', 'o', 'c', 'k', '-', 'S', 'i', 'z', 'e', ' ', 'K', 'e', 'y', ' ', '-', ' ', 'H', 'a', 's', 'h', ' ', 'K', 'e', 'y', ' ', 'F', 'i', 'r', 's', 't'};
    static BYTE hmac6[20] = {0xaa, 0x4a, 0xe5, 0xe1, 0x52, 0x72, 0xd0, 0x0e, 0x95, 0x70, 0x56, 0x37, 0xce, 0x8a, 0x3b, 0x55, 0xed, 0x40, 0x21, 0x12};
    static BYTE data7[73] = {'T', 'e', 's', 't', ' ', 'U', 's', 'i', 'n', 'g', ' ', 'L', 'a', 'r', 'g', 'e', 'r', ' ', 'T', 'h', 'a', 'n', ' ', 'B', 'l', 'o', 'c', 'k', '-', 'S', 'i', 'z', 'e', ' ', 'K', 'e', 'y', ' ', 'a', 'n', 'd', ' ', 'L', 'a', 'r', 'g', 'e', 'r', ' ', 'T', 'h', 'a', 'n', ' ', 'O', 'n', 'e', ' ', 'B', 'l', 'o', 'c', 'k', '-', 'S', 'i', 'z', 'e', ' ', 'D', 'a', 't', 'a'};
    static BYTE hmac7[20] = {0xe8, 0xe9, 0x9d, 0x0f, 0x45, 0x23, 0x7d, 0x78, 0x6d, 0x6b, 0xba, 0xa7, 0x96, 0x5c, 0x78, 0x08, 0xbb, 0xff, 0x1a, 0x91};

    struct tagSHAHmacData
    {
        const unsigned char *key;
        int keyLength;
        const unsigned char *data;
        int dataLength;
        const unsigned char *hmac;
    };
    static struct tagSHAHmacData
    SHA1HmacData[] = {
        {key1, sizeof(key1), data1, sizeof(data1), hmac1},
        {key2, sizeof(key2), data2, sizeof(data2), hmac2},
        {key3, sizeof(key3), data3, sizeof(data3), hmac3},
        {key4, sizeof(key4), data4, sizeof(data4), hmac4},
        {key5, sizeof(key5), data5, sizeof(data5), hmac5},
        {key6, sizeof(key6), data6, sizeof(data6), hmac6},
        {key6, sizeof(key6), data7, sizeof(data7), hmac7},
    };

    for ( i = 0; i < (runDetailed ? sizeof(SHA1HmacData) / sizeof(SHA1HmacData[0]) : 2); i++ )
    {
        data.assign(SHA1HmacData[i].data, SHA1HmacData[i].dataLength);
        key.assign(SHA1HmacData[i].key,SHA1HmacData[i].keyLength);

        if (!hm->initialize(key) || !hm->update(data) || !hm->finish(digest))
        {
            gFipsState.testFailed();
            return false;
        }
        if (digest.size() != hm->GetDigestSize() || 0 != memcmp(digest.c_str(), SHA1HmacData[i].hmac, digest.size()))
        {
            gFipsState.testFailed();
            return false;
        }
    }
    return true;
}

bool Hash_Sha1::fips_test_sign_rsa_x9_31_sha1(std::shared_ptr<Signer> sign, bool runDetailedTests)
{
	UNREFERENCED_PARAMETER(runDetailedTests);

    if (!gFipsState.operational())
        return false;

	std::shared_ptr<RsaKey> rsa;

	// Perform a verify operation
	if (!(rsa = std::dynamic_pointer_cast<RsaKey>(CryptoFactory("KEY-RSA")))||
		!rsa->set_Exponent(tsCryptoData("baeb99", tsCryptoData::HEX)) ||
		!rsa->set_PublicModulus(tsCryptoData("a053a72131f84672054369d2c58545f7af49629e3ae2813b69720d4535f8f5e3b461d2300e0172b439efc9f01308ca36c5a8cf0735858fe6629be5290f8208bfb260119eb68e9be55aae9763c522a94e9b8367f5eda2982aad4c3786e36bd36effe1fcf089ea158b3a4df7fc9f81fbb2328a1c2430746afd3dc3b8f01ae77dc3", tsCryptoData::HEX)) ||
		!sign->initialize(std::dynamic_pointer_cast<AsymmetricKey>(rsa)) ||
		!sign->update(tsCryptoData("540c5aff97a7a02b5ac934bef4403f8a000b532fb0615a3b65f6cd967c79271e6a61988e0be9fda4375910839788dc56b69f75365b1fe54e1726693c1aeedebb4a96767f9725af6188cc86bc1a6be717cb576904f25b384751fc523bed01f7721e335a9ce2629daa76a8fc3328f2491667bb98611c1b3b713d01f15b9ebc5a8b", tsCryptoData::HEX)) ||
		!sign->verify(tsCryptoData("190842ccf36cd49fabcdb798873f1fa048cbbb63a4b4c5578c2fbe9b297226dba4e82241f4101c53e0137f62735b0e19580c64fd803b81e70424f1948709d7b57f60d79a83fd4c8a37cc7644d4841bf3f55cb26db3069b38993626937c91523ca6af968427107fc9f1487bcd1cb97301b9977ed6c9229afea1107f4012b0665b", tsCryptoData::HEX)))
	{
		gFipsState.testFailed();
		return false;
	}
	return true;
}

bool Hash_Sha1::fips_test_sign_rsa_pkcs_sha1(std::shared_ptr<Signer> sign, bool runDetailedTests)
{
	UNREFERENCED_PARAMETER(runDetailedTests);

    if (!gFipsState.operational())
        return false;

	std::shared_ptr<RsaKey> rsa;

	// Perform a verify operation
	if (!(rsa = std::dynamic_pointer_cast<RsaKey>(CryptoFactory("KEY-RSA"))) ||
		!rsa->set_Exponent(tsCryptoData("fe3fa1", tsCryptoData::HEX)) ||
		!rsa->set_PublicModulus(tsCryptoData("dd07f43534adefb5407cc163aacc7abe9f93cb749643eaec22a3ef16e77813d77df20e84a755088872fde21d3d3192f9a78d726ef3d0daa9d6bc19daf6822eb834fbf837ed03d0f84a7fc7709be382e880e77ba3ce3d91ca1cbf567fc2e62169843489188a128ec853079e7942e6590508ea2faab1cf87b860b21b9546442455", tsCryptoData::HEX)) ||
		!sign->initialize(std::dynamic_pointer_cast<AsymmetricKey>(rsa)) ||
		!sign->update(tsCryptoData("73ef115a1dec6d91e1aa51c5e11708ead45b2419fb0313d9565ff39e1928a78f5a662b8c0c91247030f7bc934a5dac9412e99a556d40a6469beb40e7b2ff3c884bfd28537bf7dd8d05f45419cd96bb3e90fac8aad3e04eb6190c0eeb59eccfc5af7ab1b85264be71c66ac25e53085c70b5565620152c32b0388905b3f73689cf", tsCryptoData::HEX)) ||
		!sign->verify(tsCryptoData("25493b7d70cc07e9269a248632c2c89c8514fe8298ed84319ec664f01db980e24bbb59eea5867316792fec36cbe9ee9d3c69346b992377f35c08d19de0d6dd37482074cf5d3c5cd2b54d09a3ed296187f4ee5b30926a7aa794c88a2c0f9d09f721436e5a9bd4fef62e20e43095faee7f5f1e6ce87705c27aa5cdb08d50bd2cf0", tsCryptoData::HEX)))
	{
		gFipsState.testFailed();
		return false;
	}
	return true;
}

bool Hash_Sha1::fips_test_sign_rsa_pss_sha1(std::shared_ptr<Signer> sign, bool runDetailedTests)
{
	UNREFERENCED_PARAMETER(runDetailedTests);

    if (!gFipsState.operational())
        return false;

	std::shared_ptr<RsaKey> rsa;

	// Perform a verify operation
	if (!(rsa = std::dynamic_pointer_cast<RsaKey>(CryptoFactory("KEY-RSA"))) ||
		!rsa->set_Exponent(tsCryptoData("7df7cb", tsCryptoData::HEX)) ||
		!rsa->set_PublicModulus(tsCryptoData("cee1643a42cd3802e82bfad93e8a06ef89fe5e25f01492c9e8988cf05f2ebbaf9f57c9288a9067616c4cf60412aca8538aed597c7ddae4018bff6a7cbf33ffb5598163bf298a46a47037c437dd825cf7d777ba45a3e9f11a51493428e7f6ab1d7c6d684a926aa141fdd49284080f05f4c576f0e09c5e3ec61827181d669e95fd", tsCryptoData::HEX)) ||
		!sign->initialize(std::dynamic_pointer_cast<AsymmetricKey>(rsa)) ||
		!sign->update(tsCryptoData("e95bd0c2ec9c6d09fa0a9d4eee25af303e947db426bcaa8203912752fdacfca1e89f45a86c857a8e64ddf4dd8598ad334070483ae97c51d91801c5ac508cd5b2de3de7460466de5157559bbd666dc32d9c7cc3eb684812219a6bb64d11610aef93e0be84fc671fb89b1a99d8d9cd7a861b5ff8b0ea4976c35276031b875624bf", tsCryptoData::HEX)) ||
		!sign->verify(tsCryptoData("34587b8edd078b37595caae8642a30d5810565c7e9cba31b265df47c02896acff71b9cd08c4c6e2a736d90cd4dd93ea4130fdb380787516eee6fc1ea024ef7557947093fe1c6a303233e18d0f42ebeabe884b7e19a66ec7ea3ab9c6225195644f2904561fddf454a8eaaadbcc839d3bf6ddaf6d7436f049ad0ec37381ac051b9", tsCryptoData::HEX)))
	{
		gFipsState.testFailed();
		return false;
	}
	return true;
}

bool Hash_Sha1::fips_test_kdf_sha1(std::shared_ptr<KeyDerivationFunction> kdf, bool runDetailedTests)
{
	UNREFERENCED_PARAMETER(runDetailedTests);

    if (!gFipsState.operational())
        return false;

	// TODO:  Find a real test (this one created by this code)
    tsCryptoData results;

	if (!kdf->initializeWithKey(tsCryptoData("8723b723aa398f94af2b61c06cd99de01ef6497b", tsCryptoData::HEX)) ||
        !kdf->Derive_SP800_56A_Counter(tsCryptoData("8aece231d69ab033c9efe824c398da94777b260887c609a34c0206e4abcce0f5709356a7dbb92b8b0d387ccb4945d3b8a5490972205e72531f961b3d", tsCryptoData::HEX),
			tsCryptoData("3c9efe824c398da94777b260887c609a34c0206e4", tsCryptoData::HEX), 128, results) ||
        !kdf->finish() ||
        tsCryptoData("6503f718852b96038b1d36f1c21db1e4", tsCryptoData::HEX) != results)
    {
        gFipsState.testFailed();
        return false;
    }

    return true;
}

bool Hash_Sha1::fips_test_kdf_hmac_sha1(std::shared_ptr<KeyDerivationFunction> kdf, bool runDetailedTests)
{
	UNREFERENCED_PARAMETER(runDetailedTests);

    if (!gFipsState.operational())
        return false;
    tsCryptoData results;

	if (!kdf->initializeWithKey(tsCryptoData("8723b723aa398f94af2b61c06cd99de01ef6497b", tsCryptoData::HEX)) ||
        !kdf->Derive_SP800_108_Counter(false, 0, false, true, 1, tsCryptoData(), tsCryptoData("8aece231d69ab033c9efe824c398da94777b260887c609a34c0206e4abcce0f5709356a7dbb92b8b0d387ccb4945d3b8a5490972205e72531f961b3d", tsCryptoData::HEX), 128, results) ||
        !kdf->finish() ||
        tsCryptoData("7596a2c6e19c8f5f52e1e7c6380fa5e5", tsCryptoData::HEX) != results)
    {
        gFipsState.testFailed();
        return false;
    }

    return true;
}

bool Hash_Sha1::fips_test_rsa_oaep_sha1(std::shared_ptr<RsaOAEP> rsa, bool runDetailedTests)
{
    if (!gFipsState.operational())
        return false;
    tsCryptoData results;

	if (runDetailedTests)
	{
		std::shared_ptr<RsaKey> key;

		// TODO:  Need real test data here (generated by this code)
		if (!(key = std::dynamic_pointer_cast<RsaKey>(CryptoFactory("KEY-RSA"))) ||
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
		if (!rsa->Recover(key, tsCryptoData("49aca9067b616bc3f39bb0fa6b4c399ee264352042f0cdd9539a4802b75d8d4ad0e3a40eaedc3d584c5c2355f9148e66aa12a8b0669ea96a926503d188daa967e3535bb28550f656d91c0553d3647127a63d1d068a31fa39d989529e2b55ebad075fa7895a3befa538e7687d206c7aa0dc18ae3e559ee5808f7e800593ebcd9c", tsCryptoData::HEX), tsCryptoData("18b776ea21069d69776a33e96bad48e1dda0a5ef", tsCryptoData::HEX), results) ||
			results != tsCryptoData("6628194e12073db03ba94cda9ef9532397d50dba79b987004afefe34", tsCryptoData::HEX) )
		{
			gFipsState.testFailed();
			return false;
		}

		// From RSA tests
		if (!rsa->Recover(key, tsCryptoData("354fe67b4a126d5d35fe36c777791a3f7ba13def484e2d3908aff722fad468fb21696de95d0be911c2d3174f8afcc201035f7b6d8e69402de5451618c21a535fa9d7bfc5b8dd9fc243f8cf927db31322d6e881eaa91a996170e657a05a266426d98c88003f8477c1227094a0d9fa1e8c4024309ce1ecccb5210035d47ac72e8a", tsCryptoData::HEX), tsCryptoData(), results) ||
			results != tsCryptoData("6628194e12073db03ba94cda9ef9532397d50dba79b987004afefe34", tsCryptoData::HEX) )
		{
			gFipsState.testFailed();
			return false;
		}
		return true;
	}
	return true; // Only performing extended tests
}

bool Hash_Sha1::fips_test_sign_ecc(std::shared_ptr<Signer> sign, bool runDetailedTests)
{
	UNREFERENCED_PARAMETER(runDetailedTests);

    if (!gFipsState.operational())
        return false;

#ifdef SUPPORT_ECC_P192
	std::shared_ptr<EccKey> ecc;

	// Perform a verify operation
	if (FAILED(CreateAlgorithm("KEY-P192", __uuidof(EccKey), &ecc))||
		!ecc->set_Point(tsCryptoData("04ff78e337847d947df2911da234b0d4bebf408903c08bb6942fe38d0db7f7c371adb10c726b1811317f5dfd0feb9ebfcf", tsCryptoData::HEX)) ||
		!sign->initialize(ecc) ||
		!sign->update(tsCryptoData("33e84fb5259fc0df6bc1c0ed5ed01c7fed90d3af9c0433a2cd98405c3ea055d9d4010e59972e64fbfd571a8d6bdd59a3f90897e676fcbdaface988d5e4832fc3adb247cdda8ae4c4ca7d02c7eccf235d814b39c1a435c57d887f413a023fbcd74761c4b8f6998861599c3e43e890c3d50ec181e730959634ecc233369ebe413e", tsCryptoData::HEX)) ||
		!sign->verify(tsCryptoData("303402181806e6daca26b14f211938bc8659fc487ff9a458e3ab71160218df587e9ba12e17aea7fd52b11df74d665857c5a93e12290d  ", tsCryptoData::HEX)))
	{
		gFipsState.testFailed();
		return false;
	}
#else
	UNREFERENCED_PARAMETER(sign);
#endif
	return true;
}

bool Hash_Sha1::fips_test_sign_dsa(std::shared_ptr<Signer> sign, bool runDetailedTests)
{
	UNREFERENCED_PARAMETER(runDetailedTests);

    if (!gFipsState.operational())
        return false;

	std::shared_ptr<DhParameters> params;
	std::shared_ptr<DhKey> dh;

	// Perform a verify operation
	if (!(dh = std::dynamic_pointer_cast<DhKey>(CryptoFactory("KEY-DH"))) ||
		!(params = std::dynamic_pointer_cast<DhParameters>(CryptoFactory("PARAMETERSET-DH"))) ||
		!params->set_prime(tsCryptoData("913f79890754ef120b19792a7ffd56dcd3b4098f6c8eb64a80d849c52208e2d725c2844f7ab781fe7464e85a7b5b6acd2b4e6622cb980b9b3c9b109dbd2e52d8c97126fa8ebf0b46501cffd1c7d6aeadca294093c762a808153cf1e9093372f862c8bf41476f45bfe25ab055a33b20063fb99de1a866747c8a2bc2606ef1a98f", tsCryptoData::HEX)) ||
		!params->set_subprime(tsCryptoData("ba6004ab5b9f309b6afa02802328cef63920c8a5", tsCryptoData::HEX)) ||
		!params->set_generator(tsCryptoData("633730cef2827ec0a28b7a3a512858c8782a4fb2c2f7b061cf9a9624fe08f0b85f77c6f6cf1c44594078b12130d56e26bd2c74da6ad6836c7d22baba1e26299e3862b63fa846600498cad2a011c6265bc45f81c542212094d01fbdc279febc6f400c18342dc224e631cbcfbcebcddbc6881e1f607d8ddc4e003eede4d276c503", tsCryptoData::HEX)) ||
		!dh->set_DomainParameters(params) ||
		!dh->set_PublicKey(tsCryptoData("6f2f0523427d9ab6f37c2eb436f46ca7ba060d28271a80a3e3edc0a9f93cbdf6ceaeaaf9cf5767549693fe12edcb603d07ad52766decc65867a62e9d4da2eafdfba9a86ef2a78fe1157018ba245c31e67dc6912521589581e68198a91363b7509ef1c35492b19c268beb11cc616a74c25e463ad801c12626ca0462f8c626d22b", tsCryptoData::HEX)) ||
		!sign->initialize(std::dynamic_pointer_cast<AsymmetricKey>(dh)) ||
		!sign->update(tsCryptoData("517051a4cbe243413d71889fd1539420d4d1d4f28ed32b44b0acfd5f634aa78f4f4b27150ff39fdb08b0c3564a64ad192f02ee49e4da0c6efeb3f5b302d568875878ebab9117ce8b1c57b36dbbd529de2afc3866388beb5cb73268de55c0a4428b1d93544bff54d26e3f660c326c1dbe40e279cba968ded00a03213c9c9c578f", tsCryptoData::HEX)) ||
		!sign->verify(tsCryptoData("302C02146fbe3f2e9cafa6cd0b4048e7350a2a7309c88522021493c113b2bfd0f1a38d9f97956176aab0c91e5675", tsCryptoData::HEX)))
	{
		gFipsState.testFailed();
		return false;
	}
	return true;
}

bool Hash_Sha1::RunSelfTestsFor(const tsCryptoStringBase& baseProtocolName, std::shared_ptr<tscrypto::ICryptoObject> baseProtocol, bool runDetailedTests)
{
    if (!gFipsState.operational())
        return false;
	if (!baseProtocol || baseProtocolName.size() == 0)
	{
		gFipsState.testFailed();
		return false;
	}

	if (TsStrCmp(baseProtocolName, ("HMAC")) == 0)
	{
		std::shared_ptr<MessageAuthenticationCode> hm;

		hm = std::dynamic_pointer_cast<MessageAuthenticationCode>(baseProtocol);
		if (!hm)
		{
			gFipsState.testFailed();
			return false;
		}
		if (!fips_test_sha1_hmac(hm, runDetailedTests))
		{
			gFipsState.testFailed();
			return false;
		}
		return true;
	}
	else if (TsStrCmp(baseProtocolName, ("KDF-HMAC")) == 0)
	{
		std::shared_ptr<KeyDerivationFunction> kdf;

		kdf = std::dynamic_pointer_cast<KeyDerivationFunction>(baseProtocol);
		if (!kdf)
		{
			gFipsState.testFailed();
			return false;
		}
		if (!fips_test_kdf_hmac_sha1(kdf, runDetailedTests))
		{
			gFipsState.testFailed();
			return false;
		}
		return true;
	}
	else if (TsStrCmp(baseProtocolName, ("KDF")) == 0)
	{
		std::shared_ptr<KeyDerivationFunction> kdf;

		kdf = std::dynamic_pointer_cast<KeyDerivationFunction>(baseProtocol);
		if (!kdf)
		{
			gFipsState.testFailed();
			return false;
		}
		if (!fips_test_kdf_sha1(kdf, runDetailedTests))
		{
			gFipsState.testFailed();
			return false;
		}
		return true;
	}
	else if (TsStrCmp(baseProtocolName, ("SIGN-RSA-PKCS")) == 0)
	{
		std::shared_ptr<Signer> sign;

		sign = std::dynamic_pointer_cast<Signer>(baseProtocol);
		if (!sign)
		{
			gFipsState.testFailed();
			return false;
		}
		if (!fips_test_sign_rsa_pkcs_sha1(sign, runDetailedTests))
		{
			gFipsState.testFailed();
			return false;
		}
		return true;
	}
	else if (TsStrCmp(baseProtocolName, ("SIGN-RSA-X9.31")) == 0)
	{
		std::shared_ptr<Signer> sign;

		sign = std::dynamic_pointer_cast<Signer>(baseProtocol);
		if (!sign)
		{
			gFipsState.testFailed();
			return false;
		}
		if (!fips_test_sign_rsa_x9_31_sha1(sign, runDetailedTests))
		{
			gFipsState.testFailed();
			return false;
		}
		return true;
	}
	else if (TsStrCmp(baseProtocolName, ("SIGN-RSA-PSS")) == 0)
	{
		std::shared_ptr<Signer> sign;

		sign = std::dynamic_pointer_cast<Signer>(baseProtocol);
		if (!sign)
		{
			gFipsState.testFailed();
			return false;
		}
		if (!fips_test_sign_rsa_pss_sha1(sign, runDetailedTests))
		{
			gFipsState.testFailed();
			return false;
		}
		return true;
	}
	else if (TsStrCmp(baseProtocolName, ("RSA-OAEP")) == 0)
	{
		std::shared_ptr<RsaOAEP> rsa;

		rsa = std::dynamic_pointer_cast<RsaOAEP>(baseProtocol);
		if (!rsa)
		{
			gFipsState.testFailed();
			return false;
		}
		if (!fips_test_rsa_oaep_sha1(rsa, runDetailedTests))
		{
			gFipsState.testFailed();
			return false;
		}
		return true;
	}
	else if (TsStrCmp(baseProtocolName, ("SIGN-ECC")) == 0)
	{
		std::shared_ptr<Signer> sign;

		sign = std::dynamic_pointer_cast<Signer>(baseProtocol);
		if (!sign)
		{
			gFipsState.testFailed();
			return false;
		}
		if (!fips_test_sign_ecc(sign, runDetailedTests))
		{
			gFipsState.testFailed();
			return false;
		}
		return true;
	}
	else if (TsStrCmp(baseProtocolName, ("SIGN-DSA")) == 0)
	{
		std::shared_ptr<Signer> sign;

		sign = std::dynamic_pointer_cast<Signer>(baseProtocol);
		if (!sign)
		{
			gFipsState.testFailed();
			return false;
		}
		if (!fips_test_sign_dsa(sign, runDetailedTests))
		{
			gFipsState.testFailed();
			return false;
		}
		return true;
	}

	return false;
}

bool Hash_Sha1::runTests(bool /*runDetailedTests*/)
{
    static BYTE testA[]   = "abc";
    static BYTE testB[]   = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    static BYTE resultA[] = {0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D};
    static BYTE resultB[] = {0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E, 0xBA, 0xAE, 0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5, 0xE5, 0x46, 0x70, 0xF1};
    //static BYTE resultC[] = {0x34, 0xAA, 0x97, 0x3C, 0xD4, 0xC4, 0xDA, 0xA4, 0xF6, 0x1E, 0xEB, 0x2B, 0xDB, 0xAD, 0x27, 0x31, 0x65, 0x34, 0x01, 0x6F};
    tsCryptoData output;
//    BYTE *buffC;

    typedef struct block_sha_struct
    {
        BYTE * data ;
        int datalen ;
        BYTE * result ;
    } block_sha ;

    static block_sha blocks_sha[] =
    {
        { testA,   3, resultA },
        { testB,  56, resultB }
    };

    tsCryptoData outputb;
    int i ;
    block_sha temp ;

    if (!gFipsState.operational())
        return false;

    for ( i=0; i < sizeof(blocks_sha) / sizeof(blocks_sha[0]); i++ )
    {
        temp = blocks_sha[i] ;

        if ( !initialize() ||
             !update(tsCryptoData(temp.data, temp.datalen)) ||
             !finish(outputb))
        {
            gFipsState.testFailed();
            return false;
        }

        if (outputb.size() != SHA1_Descriptor.digestSize || memcmp(outputb.c_str(), temp.result, outputb.size()) != 0)
        {
            gFipsState.testFailed();
            return false;
        }
    }

    return true;
}
#endif // 0

size_t Hash_Alg::GetBlockSize()
{
	if (desc == nullptr)
		return 0;
    return desc->blockSize;
}

size_t Hash_Alg::GetDigestSize()
{
	if (desc == nullptr)
		return 0;
	return desc->digestSize;
}

tsCryptoString Hash_Alg::AlgorithmName() const
{
    return GetName();
}

tsCryptoString Hash_Alg::AlgorithmOID() const
{
    return LookUpAlgOID(GetName());
}

TS_ALG_ID Hash_Alg::AlgorithmID() const
{
    return LookUpAlgID(GetName());
}

bool Hash_Alg::initialize(const tsCryptoData &key)
{
    if (!initialize())
        return false;

    return update(key);
}

bool Hash_Alg::isUsableKey(const tsCryptoData & /*key*/)
{
    return true;
}

bool Hash_Alg::requiresKey() const
{
    return false;
}

size_t Hash_Alg::minimumKeySizeInBits() const
{
	if (desc == nullptr)
		return 0;
	return desc->minimumKeySize;
}

size_t Hash_Alg::maximumKeySizeInBits() const
{
	if (desc == nullptr)
		return 0;
	return (size_t)desc->maximumKeySize;
}

size_t Hash_Alg::keySizeIncrementInBits() const
{
	if (desc == nullptr)
		return 0;
	return desc->keySizeIncrement;
}
