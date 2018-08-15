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

#define MAX_KEY_SIZE_BYTES 512

class DhKeyImpl : public DhKey, public TSName, 
                  public DhEccPrimitives, 
                  public tscrypto::ICryptoObject, public tscrypto::IInitializableObject, public AlgorithmInfo, public TSALG_Access
{
public:
    DhKeyImpl(const tsCryptoStringBase& algorithm) :
        desc(nullptr),
        reason(tskvf_NoFailure)
    {
        desc = TSLookup(TSIDh, "DH");
        SetName(algorithm);
    }
    virtual ~DhKeyImpl(void)
    {
        desc = nullptr;
        dhKey.reset();
    }

    // AssymetricKey
    virtual void Clear() override
    {
        reason = tskvf_NoFailure;
        if (desc != nullptr && dhKey != nullptr)
        {
            desc->clearKey(dhKey);
        }
    }
    virtual size_t KeySize() const override
    {
        if (!gFipsState.operational() || desc == nullptr || dhKey == nullptr)
            return 0;
        return desc->getPrimeSize(dhKey);
    }
    virtual bool IsPublicLoaded() const override
    {
        if (!gFipsState.operational() || desc == nullptr || dhKey == nullptr)
            return false;
        return desc->hasPublicKey(dhKey);
    }
    virtual bool IsPrivateLoaded() const override
    {
        if (!gFipsState.operational() || desc == nullptr || dhKey == nullptr)
            return false;
        return desc->hasPrivateKey(dhKey);
    }
    virtual bool IsPublicVerified() const override
    {
        if (!gFipsState.operational() || desc == nullptr || dhKey == nullptr)
            return false;
        return desc->publicIsValidated(dhKey);
    }
    virtual bool IsPrivateVerified() const override
    {
        if (!gFipsState.operational() || desc == nullptr || dhKey == nullptr)
            return false;
        return desc->privateIsValidated(dhKey);
    }
    virtual bool HasPublicKey() const override
    {
        if (!gFipsState.operational() || desc == nullptr || dhKey == nullptr)
            return false;
        return desc->hasPublicKey(dhKey);
    }
    virtual bool HasPrivateKey() const override
    {
        if (!gFipsState.operational() || desc == nullptr || dhKey == nullptr)
            return false;
        return desc->hasPrivateKey(dhKey);
    }
    virtual bool ValidateKeys() override
    {
        if (!gFipsState.operational() || desc == nullptr || dhKey == nullptr)
            return false;
        return desc->validateKeys(dhKey, &reason);
    }
    virtual bool KeysAreCompatible(std::shared_ptr<AsymmetricKey> secondKey) const override
    {
        if (!gFipsState.operational() || desc == nullptr || dhKey == nullptr)
            return false;
        std::shared_ptr<TSALG_Access> ts = std::dynamic_pointer_cast<TSALG_Access>(secondKey);

        if (!ts)
            return false;

        return desc->keysAreCompatible(dhKey, ts->getKeyPair());
    }
    virtual bool generateKeyPair(bool forSignature) override
    {
        if (!gFipsState.operational() || desc == nullptr || dhKey == nullptr)
            return false;

        return desc->generateKeyPair(dhKey);
    }
    virtual bool CanComputeZ() const override
    {
        if (!gFipsState.operational() || desc == nullptr || dhKey == nullptr)
            return false;
        return desc->canComputeZ;
    }
    virtual bool ComputeZ(std::shared_ptr<AsymmetricKey> secondKey, tsCryptoData &Z) const override
    {
        uint32_t len = MAX_KEY_SIZE_BYTES;
        ts_bool retVal;
        std::shared_ptr<TSALG_Access> ts = std::dynamic_pointer_cast<TSALG_Access>(secondKey);
        if (!gFipsState.operational() || desc == nullptr || dhKey == nullptr || !ts)
            return false;
        
        Z.clear();
        Z.resize(len);
        retVal = desc->computeZ(dhKey, ts->getKeyPair(), Z.rawData(), &len);
        if (!retVal)
            len = 0;
        Z.resize(len);
        return retVal;
    }
    virtual ValidationFailureType ValidationFailureReason() const override
    {
        return reason;
    }
    virtual tsCryptoData toByteArray() const override
    {
        std::shared_ptr<TlvDocument> doc = TlvDocument::Create();
        std::shared_ptr<TlvNode> sequence;
        std::shared_ptr<DhParameters> params;

        doc->DocumentElement()->Tag(TlvNode::Tlv_Sequence);
        doc->DocumentElement()->Type(0);
        doc->DocumentElement()->AppendChild(sequence = doc->CreateSequence());
        sequence->AppendChild(doc->CreateOIDNode(tsCryptoData(id_TECSEC_DH_KEY_OID, tsCryptoData::OID)));
        doc->DocumentElement()->AppendChild(MakeIntegerNode(get_PrivateKey(), doc));
        doc->DocumentElement()->AppendChild(MakeIntegerNode(get_PublicKey(), doc));
        if (!(params = get_DomainParameters()))
        {
            std::shared_ptr<TlvNode> tmp;

            doc->DocumentElement()->AppendChild(tmp = doc->CreateSequence());
            tmp->OuterData(params->toByteArray());
        }
        return doc->SaveTlv();
    }
    virtual bool fromByteArray(const tsCryptoData &data) override
    {
        if (!gFipsState.operational())
            return false;
        std::shared_ptr<TlvDocument> doc = TlvDocument::Create();
        std::shared_ptr<DhParameters> params;
        std::shared_ptr<TlvNode> top;
        tsCryptoData priv, pub;

        Clear();

        if (!doc->LoadTlv(data))
            return false;

        top = doc->DocumentElement();

        if (top->Tag() != TlvNode::Tlv_Sequence || top->Type() != 0 || !top->IsConstructed() || top->Children()->size() < 3 || !IsSequenceOID(top->ChildAt(0), tsCryptoData(id_TECSEC_DH_KEY_OID, tsCryptoData::OID)))
            return false;

        if (top->ChildAt(1)->Tag() != TlvNode::Tlv_Number || top->ChildAt(1)->Type() != TlvNode::Type_Universal)
            return false;
        priv = AdjustASN1Number(top->ChildAt(1)->InnerData());

        if (top->ChildAt(2)->Tag() != TlvNode::Tlv_Number || top->ChildAt(2)->Type() != TlvNode::Type_Universal)
            return false;
        pub = AdjustASN1Number(top->ChildAt(2)->InnerData());

        if (top->ChildCount() > 3)
        {
            // We have fiefdom parameters
            if (top->ChildAt(3)->Tag() != TlvNode::Tlv_Sequence || top->ChildAt(3)->Type() != TlvNode::Type_Universal)
                return false;

            if (!(params = std::dynamic_pointer_cast<DhParameters>(CryptoFactory("PARAMETERSET-DH"))))
                return false;

            if (!params->fromByteArray(top->ChildAt(3)->OuterData()) || !set_DomainParameters(params))
                return false;
        }

        if (!set_PrivateKey(priv) || !set_PublicKey(pub))
            return false;
        return true;
    }
    virtual size_t minimumKeySizeInBits() const override
    {
        if (desc == nullptr)
            return 0;
        return desc->minimumKeySizeInBits(desc);
    }
    virtual size_t maximumKeySizeInBits() const override
    {
        if (desc == nullptr)
            return 0;
        return desc->maximumKeySizeInBits(desc);
    }
    virtual size_t keySizeIncrementInBits() const override
    {
        if (desc == nullptr)
            return 0;
        return desc->keySizeIncrementInBits(desc);
    }
    virtual std::shared_ptr<AsymmetricKey> generateNewKeyPair(bool forSignature) const override
    {
        std::shared_ptr<AsymmetricKey> key = std::dynamic_pointer_cast<AsymmetricKey>(CryptoFactory(GetName()));
        std::shared_ptr<DhKey> dh = std::dynamic_pointer_cast<DhKey>(key);

        if (!!key)
        {
            dh->set_DomainParameters(get_DomainParameters());
            if (!key->generateKeyPair())
            {
                key.reset();
            }
        }
        return key;
    }
    virtual bool signatureKey() const override 
    { 
        return true; 
    }
    virtual bool encryptionKey() const override 
    { 
        return true; 
    }
    virtual bool prehashSignatures() const override 
    { 
        return true; 
    }
    virtual void set_signatureKey(bool /*setTo*/) override 
    {
    }
    virtual void set_encryptionKey(bool /*setTo*/) override 
    {
    }

    // DhKey
    virtual std::shared_ptr<DhParameters> get_DomainParameters() const override
    {
        return dhParams;
    }
    virtual bool set_DomainParameters(std::shared_ptr<DhParameters> setTo) override
    {
        std::shared_ptr<TSALG_Access> ts = std::dynamic_pointer_cast<TSALG_Access>(setTo);

        if (!gFipsState.operational())
            return false;
        dhKey.reset();
        dhParams = setTo;
        if (!!dhParams && !!ts)
        {
            dhKey = tsCreateWorkspace(desc);
            desc->setParameterset(dhKey, ts->getKeyPair());
            return dhKey != nullptr;
        }
        return true;
    }
    virtual tsCryptoData get_PrivateKey() const override
    {
        tsCryptoData tmp;
        uint32_t len = MAX_KEY_SIZE_BYTES;

        if (desc == nullptr || dhKey == nullptr)
            return tsCryptoData();

        tmp.resize(len);
        if (!desc->exportPrivateKey(dhKey, tmp.rawData(), &len))
            return tsCryptoData();
        tmp.resize(len);
        return tmp;
    }
    virtual bool set_PrivateKey(const tsCryptoData &data) override
    {
        if (!gFipsState.operational() || desc == nullptr || dhParams == nullptr)
            return false;

        if (data.size() == 0)
            return false;
        return desc->addPrivateKey(dhKey, data.c_str(), (uint32_t)data.size());;
    }
    virtual tsCryptoData get_PublicKey() const override
    {
        tsCryptoData tmp;
        uint32_t len = MAX_KEY_SIZE_BYTES;

        if (desc == nullptr || dhKey == nullptr)
            return tsCryptoData();

        tmp.resize(len);
        if (!desc->exportPublicKey(dhKey, tmp.rawData(), &len))
            return tsCryptoData();
        tmp.resize(len);
        return tmp;
    }
    virtual bool set_PublicKey(const tsCryptoData &data) override
    {
        if (!gFipsState.operational() || desc == nullptr || dhParams == nullptr)
            return false;

        if (data.size() == 0)
            return false;
        return desc->addPublicKey(dhKey, data.c_str(), (uint32_t)data.size());;
    }

    // DhEccPrimitives
    virtual bool SignUsingData(const tsCryptoData &data, tsCryptoData &r, tsCryptoData &s) const override
    {
        uint32_t Rlen = MAX_KEY_SIZE_BYTES;
        uint32_t Slen = MAX_KEY_SIZE_BYTES;
        ts_bool retVal;
        if (!gFipsState.operational() || desc == nullptr || dhKey == nullptr)
            return false;

        r.resize(Rlen);
        s.resize(Slen);

        retVal = desc->signUsingData(dhKey, data.c_str(), (uint32_t)data.size(), r.rawData(), &Rlen, s.rawData(), &Slen);
        if (!retVal)
        {
            Rlen = 0;
            Slen = 0;
        }
        r.resize(Rlen);
        s.resize(Slen);
        return retVal;
    }
    virtual bool VerifySignatureForData(const tsCryptoData &data, const tsCryptoData &r, const tsCryptoData &s) const override
    {
        if (!gFipsState.operational() || desc == nullptr || dhKey == nullptr)
            return false;

        return desc->verifySignatureForData(dhKey, data.c_str(), (uint32_t)data.size(), r.c_str(), (uint32_t)r.size(), s.c_str(), (uint32_t)s.size());
    }
    virtual bool DH(const tsCryptoData &publicKey, tsCryptoData &Z) const override
    {
        Z.clear();
        if (!gFipsState.operational() || desc == nullptr || dhKey == nullptr)
            return false;

        std::shared_ptr<DhKey> key = ServiceLocator()->get_instance<DhKey>("KEY-DH");
        if (!key || !key->set_DomainParameters(dhParams) || !key->set_PublicKey(publicKey))
            return false;
        return ComputeZ(key, Z);
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
        SetName(fullName);

        return true;
    }

    // Inherited via TSALG_Access
    virtual const TSICyberVEILObject * Descriptor() const override
    {
        return desc->def.primary;
    }
    virtual TSWORKSPACE getKeyPair() const override
    {
        return dhKey;
    }
    virtual TSWORKSPACE getWorkspace() const override
    {
        return nullptr;
    }
    virtual TSWORKSPACE detachFromKeyPair() override
    {
        return (TSWORKSPACE)dhKey.detach();
    }
    virtual TSWORKSPACE cloneKeyPair() const override
    {
        if (desc == nullptr || dhKey == nullptr)
            return nullptr;
        return tsClone(dhKey);
    }

private:
    const TSIDh* desc;
    SmartCryptoWorkspace dhKey;
    TSKeyValidationFailureType reason;
    std::shared_ptr<tscrypto::DhParameters> dhParams;
};

tscrypto::ICryptoObject* CreateDhKey(const tsCryptoStringBase& algorithm)
{
    return dynamic_cast<tscrypto::ICryptoObject*>(new DhKeyImpl(algorithm));
}

//bool DhKeyImpl::RunSelfTestsFor(const tsCryptoStringBase& baseProtocolName, std::shared_ptr<tscrypto::ICryptoObject> baseProtocol, bool runDetailedTests)
//{
//	UNREFERENCED_PARAMETER(runDetailedTests);
//
//    if (!gFipsState.operational())
//        return false;
//	if (!baseProtocol || baseProtocolName.size() == 0)
//	{
//		gFipsState.testFailed();
//		return false;
//	}
//
//
//	return false; // TODO:  Implement me
//}
//
//bool DhKeyImpl::runTests(bool runDetailedTests)
//{
//    if (!gFipsState.operational())
//        return false;
//
//	if (runDetailedTests)
//	{
//		tsCryptoData p("a1206b626225bdbb2b6242ccb0f3d3ef542c8752fbbb0c79a6f85477d7b67e7389493ce1bbb9045186b36995be1dfb9290073e54593c47e092a942ff9c72ea94b1f345d37aac79120a5a56f0afb28a38dc8f62b91cbd0c646333ba271cda1b385b423e8b9e544601f79a2a7e01f0b73d5bdb733ae2e4ef7b934672e9b99a4c8d", tsCryptoData::HEX);
//		tsCryptoData q("b027f53b8a7f1bb772b1a4ad98c880c573f3d0ef", tsCryptoData::HEX);
//		tsCryptoData g("10cc4864d3b4ffd050e9a416c1083bc24f38094e7218bf589ab57b49b64b3267ebd58032cf637b2b6f4b13922ffbb73e7cd938b1e45b98d01b2ecb603f280d5969b242c76c94f7bda82097556b76ac70e6633cc9ec177229dc0d3c8b68941cd9a5b4edb799d168a8fee6ed7effb2390390aab156cd5099b145346dd40e7c3b3f", tsCryptoData::HEX);
//		tsCryptoData x("ae3672814689dd95c6cb477ad73d64e954387662", tsCryptoData::HEX);
//		tsCryptoData y("9c6be048965683f9dad750448198781cd661da7d4cd335bd8f6409f5b664c84c9aabdff7b7fe4167d7ff5f02762a72be737d9a6d22ef5f4bf8bf8964105e8eae6a0181c1bfeb59ab1485b47693cded4313fd6efea1cc1497d8acdfe45641a1d897209955528df3a59bb41703a15215f4bdf9ff317abe7081eff424724b20d543", tsCryptoData::HEX);
//		std::shared_ptr<DhParameters> params;
//
//		if (!(params = std::dynamic_pointer_cast<DhParameters>(CryptoFactory("PARAMETERSET-DH"))) ||
//			!params->set_prime(p) || !params->set_subprime(q) || !params->set_generator(g) ||
//			!set_DomainParameters(params) || !set_PublicKey(y) || !set_PrivateKey(x) ||
//			!ValidateKeys())
//		{
//			gFipsState.testFailed();
//			return false;
//		}
//		return true;
//	}
//
//    return true;
//}

