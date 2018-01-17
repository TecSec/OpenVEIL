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

class KeyWrapImpl : public TSName, public KeyTransport, public tscrypto::ICryptoObject, public tscrypto::IInitializableObject, public AlgorithmInfo
{
public:
    KeyWrapImpl() : desc(nullptr)
    {
    }
    virtual ~KeyWrapImpl(void)
    {
    }

    // KeyTransport
    virtual bool initializeWithSymmetricKey(const tsCryptoData &key) override
    {
        if (!gFipsState.operational() || desc == nullptr || workspace.empty())
            return false;

        if (!desc->isUsableKey(desc, key.c_str(), (uint32_t)key.size()))
            return false;

        tsCryptoString name;
        tsCryptoStringList parts = tsCryptoString(GetName()).split('-');
        name = parts->at(0).c_str();
        if (parts->size() > 1)
            name.append("-").append(parts->at(1).c_str());
        if (parts->size() > 2)
            name.append("-").append(parts->at(2).c_str());
        name += "-";
        name.append((key.size() * 8));
        SetName(name);
        return desc->init(desc, workspace, key.c_str(), (uint32_t)key.size());
    }
    virtual bool initializeWithAsymmetricKey(std::shared_ptr<tscrypto::ICryptoObject>& key)
    {
        if (!gFipsState.operational())
            return false;
        return false; // not supported for RFC 3394
    }
    virtual bool Wrap(const tsCryptoData &inputData, const tsCryptoData &pad, tsCryptoData &outputData) override
    {
        uint32_t len;
        uint32_t inLen = (uint32_t)inputData.size();

        if (!gFipsState.operational() || desc == nullptr || workspace.empty())
            return false;

        if (!desc->wrap(desc, workspace, inputData.c_str(), inLen, pad.c_str(), (uint32_t)pad.size(), nullptr, &len))
            return false;

        outputData.resize(len);

        if (!desc->wrap(desc, workspace, inputData.c_str(), inLen, pad.c_str(), (uint32_t)pad.size(), outputData.rawData(), &len))
        {
            outputData.clear();
            return false;
        }

        outputData.resize(len);

        return true;
    }
    virtual bool Unwrap(const tsCryptoData &inputData, const tsCryptoData &pad, tsCryptoData &outputData) override
    {
        uint32_t len;
        uint32_t inLen = (uint32_t)inputData.size();

        if (!gFipsState.operational() || desc == nullptr || workspace.empty())
            return false;

        if (!desc->unwrap(desc, workspace, inputData.c_str(), inLen, pad.c_str(), (uint32_t)pad.size(), nullptr, &len))
            return false;

        outputData.resize(len);

        if (!desc->unwrap(desc, workspace, inputData.c_str(), inLen, pad.c_str(), (uint32_t)pad.size(), outputData.rawData(), &len))
        {
            outputData.clear();
            return false;
        }

        outputData.resize(len);

        return true;
    }
    virtual bool CanWrap(const tsCryptoData &keyToWrap) override
    {
        if (desc == nullptr || workspace.empty())
            return false;

        return desc->canWrap(desc, workspace, keyToWrap.c_str(), (uint32_t)keyToWrap.size());
    }
    virtual bool CanUnwrap(const tsCryptoData &keyToUnwrap) override
    {
        if (desc == nullptr || workspace.empty())
            return false;

        return desc->canUnwrap(desc, workspace, keyToUnwrap.c_str(), (uint32_t)keyToUnwrap.size());
    }
    virtual size_t minimumKeySizeInBits() const override
    {
        if (desc == nullptr)
            return 128;
        return desc->getMinimumKeySize(desc);
    }
    virtual size_t maximumKeySizeInBits() const override
    {
        if (desc == nullptr)
            return 256;
        return desc->getMaximumKeySize(desc);
    }
    virtual size_t keySizeIncrementInBits() const override
    {
        if (desc == nullptr)
            return 64;
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
        tsCryptoString tmp;
        bool padIt = false;
        bool invert = false;

        SetName(algorithm);

        algorithm.ToUpper().Replace("-RFC3394", "");

        tsCryptoStringList parts = algorithm.split("-");

        tmp = parts->front();
        padIt = (tmp == "KEYWRAP_PAD" || tmp == "KEYWRAP_PAD_INV" || tmp == "KWP" || tmp == "KWP_INV");
        invert = (tmp == "KEYWRAP_INV" || tmp == "KEYWRAP_PAD_INV" || tmp == "KW_INV" || tmp == "KWP_INV" || tmp == "TKW_INV");

        algorithm = "KW";
        if (padIt)
            algorithm << "P";
        if (invert)
            algorithm << "_INV";
        algorithm << "-";

        if (parts->size() == 1)
        {
            if (parts->front() == "KEYWRAP")
                algorithm << "AES";
            else
                algorithm << parts->front();
        }
        else if (parts->size() >= 2)
        {
            algorithm << parts->at(1);
        }

        desc = tsFindKeyTransportAlgorithm(algorithm.c_str());
        if (desc == nullptr)
        {
            algorithm.insert(0, "T");
            desc = tsFindKeyTransportAlgorithm(algorithm.c_str());
        }
        if (desc == nullptr)
            return false;
        workspace = desc;
        SetName(algorithm);
        return true;
    }

private:
    const TSKeyTransportDescriptor* desc;
    SmartCryptoWorkspace workspace;
};

tscrypto::ICryptoObject* CreateKeyWrap()
{
    return dynamic_cast<tscrypto::ICryptoObject*>(new KeyWrapImpl);
}
