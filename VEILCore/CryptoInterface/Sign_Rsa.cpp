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

class Sign_Rsa : public Signer, public TSName, public tscrypto::ICryptoObject, public tscrypto::IInitializableObject, public AlgorithmInfo
{
public:
    Sign_Rsa() :
        signDesc(nullptr)
    {
    }
    virtual ~Sign_Rsa(void)
    {
    }

    // Signer
    virtual bool initialize(std::shared_ptr<AsymmetricKey> key) override
    {
        std::shared_ptr<TSALG_Access> access;

        if (!gFipsState.operational() || signDesc == nullptr)
            return false;
        m_key.reset();

        if (!key || !(m_key = std::dynamic_pointer_cast<RsaKey>(key)) || !(access = std::dynamic_pointer_cast<TSALG_Access>(key)))
            return false;

        workspace = signDesc->def;

        return signDesc->init(workspace, access->getKeyPair(), hashName.c_str());
    }
    virtual bool signHash(const tsCryptoData &hashData, tsCryptoData &signature) override
    {
        if (!gFipsState.operational() || signDesc == nullptr || workspace.empty())
            return false;
        uint32_t len;

        signature.clear();

        if (!signDesc->signHash(workspace, hashData.c_str(), (uint32_t)hashData.size(), nullptr, &len))
            return false;

        signature.resize(len);
        if (!signDesc->signHash(workspace, hashData.c_str(), (uint32_t)hashData.size(), signature.rawData(), &len))
        {
            signature.clear();
            return false;
        }
        signature.resize(len);
        return true;
    }
    virtual bool update(const tsCryptoData &data) override
    {
        if (!gFipsState.operational() || signDesc == nullptr || workspace.empty())
            return false;

        return signDesc->update(workspace, data.c_str(), (uint32_t)data.size());
    }
    virtual bool sign(tsCryptoData &signature) override
    {
        if (!gFipsState.operational() || signDesc == nullptr || workspace.empty())
            return false;

        uint32_t len;
        signature.clear();

        if (!signDesc->sign(workspace, nullptr, &len))
            return false;

        signature.resize(len);
        if (!signDesc->sign(workspace, signature.rawData(), &len))
        {
            signature.clear();
            return false;
        }
        signature.resize(len);
        return true;
    }
    virtual bool verifyHash(const tsCryptoData &hashData, const tsCryptoData &signature) override
    {
        if (!gFipsState.operational() || signDesc == nullptr || workspace.empty())
            return false;

        return signDesc->verifyHash(workspace, hashData.c_str(), (uint32_t)hashData.size(), signature.c_str(), (uint32_t)signature.size());
    }
    virtual bool verify(const tsCryptoData &signature) override
    {
        if (!gFipsState.operational() || signDesc == nullptr || workspace.empty())
            return false;

        return signDesc->verify(workspace, signature.c_str(), (uint32_t)signature.size());
    }
    virtual bool finish() override
    {
        if (!gFipsState.operational() || signDesc == nullptr)
            return false;
        if (workspace.empty())
            return true;

        signDesc->finish(workspace);
        workspace.reset();
        return true;
    }
    virtual size_t GetHashBlockSize() override
    {
        const TSIHash* hash = TSLookup(TSIHash, hashName.c_str());
        if (hash == nullptr)
            return 0;
        return hash->blockSize;
    }
    virtual size_t GetHashDigestSize() override
    {
        const TSIHash* hash = TSLookup(TSIHash, hashName.c_str());
        if (hash == nullptr)
            return 0;
        return hash->digestSize;
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
        tsCryptoStringList parts = tsCryptoString(algorithm).split('-');

        SetName(algorithm);

        if (parts->size() == 2)
        {
            // Default to PKCS-SHA1
            SetName((GetName() + tsCryptoString("-PKCS-SHA1")).c_str());
            parts = tsCryptoString(GetName()).split('-');
        }

        if (parts->size() >= 3)
        {
            tsCryptoString name("RSA_");
            name += parts->at(2);

            signDesc = TSLookup(TSIRsaSigner, name.c_str());
            if (signDesc == nullptr)
            {
                return false;
            }
        }

        if (parts->size() == 5)
        {
            hashName = (parts->at(3) + "-" + parts->at(4)).c_str();
        }
        else if (parts->size() == 4)
        {
            hashName = parts->at(3).c_str();
        }
        return true;
    }

private:
    const TSIRsaSigner* signDesc;
    SmartCryptoWorkspace workspace;
    tsCryptoString hashName;
    SmartCryptoWorkspace hashWorkspace;
    std::shared_ptr<RsaKey> m_key;
};

tscrypto::ICryptoObject* CreateRsaSigner()
{
    return dynamic_cast<tscrypto::ICryptoObject*>(new Sign_Rsa);
}

