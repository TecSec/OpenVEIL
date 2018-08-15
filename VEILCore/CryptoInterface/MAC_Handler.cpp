//	Copyright (c) 2018, TecSec, Inc.
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

class MAC_Handler : public TSName, public MessageAuthenticationCode, public tscrypto::ICryptoObject, public tscrypto::IInitializableObject, public AlgorithmInfo
{
public:
    MAC_Handler()
    {
        desc = TSLookup(TSIMac, "HMAC-SHA512");
    }
    virtual ~MAC_Handler(void)
    {
    }

    // MessageAuthenticationCode
    virtual bool initialize(const tsCryptoData &key) override
    {
        if (!gFipsState.operational() || desc == nullptr)
            return false;

        context = desc->def;

        return desc->init(context, key.c_str(), (uint32_t)key.size());
    }
    virtual bool update(const tsCryptoData &data) override
    {
        if (!gFipsState.operational() || desc == nullptr || context.empty())
            return false;

        if (data.size() > 0)
        {
            return desc->update(context, data.c_str(), (uint32_t)data.size());
        }
        return true;
    }
    virtual bool finish(tsCryptoData &digest) override
    {
        if (!gFipsState.operational() || desc == nullptr || context.empty())
            return false;

        digest.clear();
        digest.resize(desc->getDigestSize(desc));
        bool retVal = desc->finish(context, digest.rawData(), (uint32_t)digest.size());
        if (!retVal)
            digest.clear();
        context.reset();
        return retVal;
    }
    virtual size_t GetBlockSize() override
    {
        if (desc == nullptr)
            return 0;
        return desc->getBlockSize(desc);
    }
    virtual size_t GetDigestSize() override
    {
        if (desc == nullptr)
            return 0;
        return desc->getDigestSize(desc);
    }
    virtual bool isUsableKey(const tsCryptoData &key) override
    {
        return desc != nullptr && desc->isUsableKey(desc, key.c_str(), (uint32_t)key.size());
    }
    virtual bool requiresKey() const override
    {
        if (desc == nullptr)
            return false;
        return desc->getMinimumKeySize(desc) > 0;
    }
    virtual size_t minimumKeySizeInBits() const override
    {
        if (desc == nullptr)
            return 0;
        return desc->getMaximumKeySize(desc);
    }
    virtual size_t maximumKeySizeInBits() const override
    {
        if (desc == nullptr)
            return 0;
        return desc->getMaximumKeySize(desc);
    }
    virtual size_t keySizeIncrementInBits() const override
    {
        if (desc == nullptr)
            return 0;
        return desc->getKeySizeIncrement(desc);
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

        context.reset();
        desc = nullptr;
        if (tsStrniCmp(algorithm.c_str(), "HMAC", 4) == 0)
        {
            if (algorithm.size() <= 5)
            {
                algorithm = "HMAC-SHA512";
            }
            else if (tsStriCmp(algorithm.c_str(), "HMAC-SHA3") == 0)
            {
                algorithm += "-512";
            }
            tsCryptoString algName(algorithm);

            algName.ToUpper().Replace("SHA3-", "SHA3_");

            SetName(algorithm);
            desc = TSLookup(TSIMac, algName.c_str());
        }
        else if (tsStrniCmp(algorithm.c_str(), "CMAC", 4) == 0)
        {
            if (algorithm.size() < 6)
            {
                SetName("CMAC-AES");
                desc = TSLookup(TSIMac, "CMAC-AES");
                if (desc == nullptr)
                {
                    return false;
                }
                SetName("CMAC-AES");
            }
            else
            {
                tsCryptoString name = "CMAC-";
                name << &algorithm[5];
                desc = TSLookup(TSIMac, name.c_str());
                if (desc == nullptr)
                {
                    tsCryptoStringList parts = name.split("-");
                    bool foundIt = false;
                    while (parts->size() > 2)
                    {
                        tsCryptoString tmp;
                        parts->pop_back();

                        for (tsCryptoString& s : *parts)
                        {
                            if (!tmp.empty())
                                tmp << "-";
                            tmp << s;
                            desc = TSLookup(TSIMac, tmp.c_str());
                            if (desc != nullptr)
                            {
                                foundIt = true;
                                break;
                            }
                        }
                    }
                    if (!foundIt)
                        return false;
                }
                SetName(name);
            }
        }
        else if (tsStrniCmp(algorithm.c_str(), "POLY1305", 8) == 0)
        {
            algorithm = "POLY1305";
            SetName("POLY1305");
            desc = TSLookup(TSIMac, "POLY1305");
        }
        
        if (desc == nullptr)
            return false;
        return true;
    }

private:
    SmartCryptoWorkspace context;
    const TSIMac* desc;
};

tscrypto::ICryptoObject* CreateMAC()
{
    return dynamic_cast<tscrypto::ICryptoObject*>(new MAC_Handler());
}

#if 0
bool HMAC::RunSelfTestsFor(const tsCryptoStringBase& baseProtocolName, std::shared_ptr<tscrypto::ICryptoObject> baseProtocol, bool runDetailedTests)
{
    if (!gFipsState.operational())
        return false;
    if (!baseProtocol || baseProtocolName.size() == 0)
    {
        gFipsState.testFailed();
        return false;
    }

    if (desc->underlyingHash == nullptr)
        return false;

    std::shared_ptr<Hash> hasher = std::dynamic_pointer_cast<Hash>(CryptoFactory(desc->underlyingHash->name));

    if (baseProtocolName == "KDF")
    {
        std::shared_ptr<TSExtensibleSelfTest> exSelfTest = std::dynamic_pointer_cast<TSExtensibleSelfTest>(hasher);

        if (!!exSelfTest)
        {
            if (!exSelfTest->RunSelfTestsFor("KDF-HMAC", baseProtocol, runDetailedTests))
            {
                gFipsState.testFailed();
                return false;
            }
            return true;
        }
        else
        {
            gFipsState.testFailed();
            return false;
        }
    }


    gFipsState.testFailed();
    return false;
}

bool HMAC::runTests(bool runDetailedTests)
{
    bool testPassed = false;

    if (!gFipsState.operational())
        return false;

    if (desc->underlyingHash == nullptr)
        return false;

    std::shared_ptr<Hash> hasher = std::dynamic_pointer_cast<Hash>(CryptoFactory(desc->underlyingHash->name));
    
    if (!hasher)
        return false;

    std::shared_ptr<TSExtensibleSelfTest> exSelfTest = std::dynamic_pointer_cast<TSExtensibleSelfTest>(hasher);

    if (!!exSelfTest)
    {
        testPassed = exSelfTest->RunSelfTestsFor("HMAC", _me.lock(), runDetailedTests);
    }
    if (!testPassed)
    {
        gFipsState.testFailed();
        return false;
    }
    return true;
}
#endif // 0

