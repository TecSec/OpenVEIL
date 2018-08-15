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
#include "PKIX.h"
#include "CryptoAsn1.h"

using namespace tscrypto;

class Key_Rsa : public RsaKeyGenerationParameters, public RsaPrimitives, public TSName,
    public TSExtensibleSelfTest, public tscrypto::ICryptoObject, public tscrypto::IInitializableObject, public AlgorithmInfo, public TSALG_Access
{
public:
    Key_Rsa() :
        m_validationReason(tskvf_NoFailure),
        desc(nullptr)
    {
        desc = TSLookup(TSIRsa, "RSA");
        if (desc != nullptr)
            keyPair = tsCreateWorkspace(desc);
    }
    virtual ~Key_Rsa(void)
    {
        keyPair.reset();
    }

    // AssymetricKey
    virtual void Clear() override
    {
        if (desc != nullptr && keyPair != nullptr)
            desc->clearKey(keyPair);
        m_validationReason = tskvf_NoFailure;
    }
    virtual size_t KeySize() const override
    {
        if (desc == nullptr || keyPair == nullptr)
            return 0;
        return desc->exportKeySize(keyPair);
    }
    virtual bool IsPublicLoaded() const override
    {
        if (desc == nullptr || keyPair == nullptr)
            return false;
        return desc->hasPublicKey(keyPair);
    }
    virtual bool IsPrivateLoaded() const override
    {
        if (desc == nullptr || keyPair == nullptr)
            return false;
        return desc->hasPrivateKey(keyPair);
    }
    virtual bool IsPublicVerified() const override
    {
        if (desc == nullptr || keyPair == nullptr)
            return false;
        return desc->publicIsValidated(keyPair);
    }
    virtual bool IsPrivateVerified() const override
    {
        if (desc == nullptr || keyPair == nullptr)
            return false;
        return desc->privateIsValidated(keyPair);
    }
    virtual bool HasPublicKey() const override
    {
        return IsPublicLoaded();
    }
    virtual bool HasPrivateKey() const override
    {
        return IsPrivateLoaded();
    }
    virtual bool ValidateKeys() override
    {
        if (desc == nullptr || keyPair == nullptr)
            return false;
        return desc->validateKeys(keyPair, false, &m_validationReason);
    }
    virtual bool KeysAreCompatible(std::shared_ptr<AsymmetricKey> secondKey) const override
    {
        std::shared_ptr<RsaKey> rsa = std::dynamic_pointer_cast<RsaKey>(secondKey);

        return (!!rsa);
    }
    virtual bool generateKeyPair(bool forSignature) override
    {
        return generateKeyPair(_RSA_Key_Gen_Type::rsakg_Probable_Composite, "SHA256", 2048, forSignature);
    }
    virtual bool CanComputeZ() const override
    {
        return false;
    }
    virtual bool ComputeZ(std::shared_ptr<AsymmetricKey> secondKey, tsCryptoData &Z) const override
    {
        return false;
    }
    virtual ValidationFailureType ValidationFailureReason() const override
    {
        if (!gFipsState.operational())
            return _ValidationFailureType::vf_Internal;
        return (ValidationFailureType)m_validationReason; // TODO: Ensure that these two types match
    }
    virtual tsCryptoData toByteArray() const override
    {
        if (IsPublicLoaded() && !IsPrivateLoaded())
        {
            std::shared_ptr<TlvDocument> blobDoc = TlvDocument::Create();

            blobDoc->DocumentElement()->Tag(0x10);
            blobDoc->DocumentElement()->Type(0);

            std::shared_ptr<TlvNode> alg = blobDoc->CreateTlvNode(0x10, 0);
            std::shared_ptr<TlvNode> oid = blobDoc->CreateTlvNode(0x06, 0);
            std::shared_ptr<TlvNode> nullNode = blobDoc->CreateTlvNode(0x05, 0);

            blobDoc->DocumentElement()->AppendChild(alg);
            oid->InnerData(tsCryptoData(id_RSA_ENCRYPT_OID, tsCryptoData::OID)); //RsaEncryption
            alg->AppendChild(oid);
            alg->AppendChild(nullNode);


            std::shared_ptr<TlvDocument> keyDoc = TlvDocument::Create();
            keyDoc->DocumentElement()->Tag(0x10);
            keyDoc->DocumentElement()->Type(0);

            keyDoc->DocumentElement()->AppendChild(MakeIntegerNode(get_PublicModulus(), keyDoc));
            keyDoc->DocumentElement()->AppendChild(MakeIntegerNode(get_Exponent(), keyDoc));

            blobDoc->DocumentElement()->AppendChild(MakeBitString(keyDoc->SaveTlv(), 0, blobDoc));
            return blobDoc->SaveTlv();
        }
        else if (IsPrivateLoaded())
        {
            // SEQUENCE(0x30) {
            //   Alg(0x30) {
            //     OID (6) =  "2.23.42.9.10.3.0.7.7.2"
            //     Params(5) = <<null>>
            //   }
            //   BitString(3) = "SEQUENCE(0x30) {Int(2) = Modulus, Int(2) = exponent, Int(2) = d, Int(2) = p, Int(2) = q, Int(2) = dp, Int(2) = dq, Int(2) = qInv}"
            //   [opt]SEQUENCE(0x30) {
            //     OCTET STRING(4) = seed
            //     Int(2) = counter
            //   }
            // }
            //
            std::shared_ptr<TlvDocument> blobDoc = TlvDocument::Create();

            blobDoc->DocumentElement()->Tag(0x10);
            blobDoc->DocumentElement()->Type(0);

            std::shared_ptr<TlvNode> alg = blobDoc->CreateTlvNode(0x10, 0);
            std::shared_ptr<TlvNode> oid = blobDoc->CreateTlvNode(0x06, 0);
            std::shared_ptr<TlvNode> nullNode = blobDoc->CreateTlvNode(0x05, 0);

            blobDoc->DocumentElement()->AppendChild(alg);
            oid->InnerData(tsCryptoData(id_TECSEC_RSA_PRIVATE_KEY_BLOB_OID, tsCryptoData::OID)); //TecSec Private RSA Key Blob
            alg->AppendChild(oid);
            alg->AppendChild(nullNode);


            std::shared_ptr<TlvDocument> keyDoc = TlvDocument::Create();
            keyDoc->DocumentElement()->Tag(0x10);
            keyDoc->DocumentElement()->Type(0);

            keyDoc->DocumentElement()->AppendChild(MakeIntegerNode(get_PublicModulus(), keyDoc));
            keyDoc->DocumentElement()->AppendChild(MakeIntegerNode(get_Exponent(), keyDoc));
            keyDoc->DocumentElement()->AppendChild(MakeIntegerNode(get_PrivateExponent(), keyDoc));
            keyDoc->DocumentElement()->AppendChild(MakeIntegerNode(get_p(), keyDoc));
            keyDoc->DocumentElement()->AppendChild(MakeIntegerNode(get_q(), keyDoc));
            keyDoc->DocumentElement()->AppendChild(MakeIntegerNode(get_dp(), keyDoc));
            keyDoc->DocumentElement()->AppendChild(MakeIntegerNode(get_dq(), keyDoc));
            keyDoc->DocumentElement()->AppendChild(MakeIntegerNode(get_qInv(), keyDoc));

            blobDoc->DocumentElement()->AppendChild(MakeBitString(keyDoc->SaveTlv(), 0, blobDoc));
            return blobDoc->SaveTlv();
        }
        else
        {
            return tsCryptoData();
        }
    }
    virtual bool fromByteArray(const tsCryptoData &data) override
    {
        if (!gFipsState.operational())
            return false;
        std::shared_ptr<TlvDocument> doc = TlvDocument::Create();
        std::shared_ptr<TlvNode> top;
        tsCryptoData n, e, p, q, dp, dq, qInv, d;
        std::shared_ptr<TlvDocument> innerDoc = TlvDocument::Create();

        Clear();

        // First try the pkcs 8 / RFC 3279 private key
        for (;;)
        {
            tscrypto::_POD_Pkcs8RSAPrivateKey key;

            if (key.Decode(data))
            {
                if (key.get_version() == 0)
                {
                    set_Exponent(key.get_publicExponent());
                    set_PublicModulus(key.get_modulus());
                    if (key.get_exponent1().size() > 0)
                    {
                        set_p(key.get_prime1());
                        set_q(key.get_prime2());
                        set_dp(key.get_exponent1());
                        set_dq(key.get_exponent2());
                        set_qInv(key.get_coefficient());
                    }
                    else
                        set_PrivateExponent(key.get_privateExponent());
                    return true;
                }
            }
            break;
        }

        // Ok, now try the pkcs 8 / RFC 3279 public key
        for (;;)
        {
            tscrypto::_POD_Pkcs8PublicKey key;

            if (!key.Decode(data))
            {
                if (key.get_pubKeyAlgorithm().get_oid().ToOIDString() == id_RSA_ENCRYPT_OID)
                {
                    tscrypto::_POD_RsaPublicKeyPart part;

                    if (!part.Decode(key.get_keyValue().bits()))
                    {
                        break;
                    }
                    set_Exponent(part.get_exponent());
                    set_PublicModulus(part.get_n());
                    return true;
                }
            }
            break;
        }


        if (!doc->LoadTlv(data))
            return false;

        top = doc->DocumentElement();

        if (top->Tag() == TlvNode::Tlv_Sequence && top->Type() == TlvNode::Type_Universal && top->IsConstructed() && top->Children()->size() == 3 && top->Children()->at(0)->IsNumber(0) && top->Children()->at(1)->IsSequence() && top->Children()->at(2)->Tag() == TlvNode::Tlv_Octet)
        {
            if (top->ChildAt(1)->ChildCount() == 2 && top->ChildAt(1)->ChildAt(0)->IsOIDNode(tsCryptoData(id_RSA_ENCRYPT_OID, tsCryptoData::OID)))
            {
                tscrypto::_POD_Pkcs8RSAPrivateKey privkey;
                tscrypto::_POD_Pkcs8PublicKey pubkey;

                if (privkey.Decode(top->ChildAt(2)->InnerData()))
                {
                    if (privkey.get_version() == 0)
                    {
                        set_Exponent(privkey.get_publicExponent());
                        set_PublicModulus(privkey.get_modulus());
                        if (privkey.get_exponent1().size() > 0)
                        {
                            set_p(privkey.get_prime1());
                            set_q(privkey.get_prime2());
                            set_dp(privkey.get_exponent1());
                            set_dq(privkey.get_exponent2());
                            set_qInv(privkey.get_coefficient());
                        }
                        else
                            set_PrivateExponent(privkey.get_privateExponent());
                        return true;
                    }
                }

                if (!pubkey.Decode(top->ChildAt(2)->InnerData()))
                {
                    if (pubkey.get_pubKeyAlgorithm().get_oid().ToOIDString() == id_RSA_ENCRYPT_OID)
                    {
                        tscrypto::_POD_RsaPublicKeyPart part;

                        if (part.Decode(pubkey.get_keyValue().bits()))
                        {
                            set_Exponent(part.get_exponent());
                            set_PublicModulus(part.get_n());
                            return true;
                        }
                    }
                }
            }
        }

        if (top->Tag() != TlvNode::Tlv_Sequence || top->Type() != 0 || !top->IsConstructed() || top->Children()->size() != 2 || top->Children()->at(1)->Tag() != TlvNode::Tlv_BitString)
            return false;

        if (!innerDoc->LoadTlv(AdjustBitString(top->Children()->at(1)->InnerData())))
        {
            return false;
        }

        if (IsSequenceOID(top->ChildAt(0), tsCryptoData(id_RSA_ENCRYPT_OID, tsCryptoData::OID)))
        {
            // Public key only
            // RSA Public key blob
            top = innerDoc->DocumentElement();

            if (top->Tag() != 0x10 || top->Type() != 0 || !top->IsConstructed() || top->Children()->size() != 2)
                return false;

            n = AdjustASN1Number(top->Children()->at(0)->InnerData());
            e = AdjustASN1Number(top->Children()->at(1)->InnerData());
            if (!set_Exponent(e) || !set_PublicModulus(n))
                return false;

            if (!IsPublicLoaded())
                return false;
            return true;
        }
        else if (IsSequenceOID(top->ChildAt(0), tsCryptoData(id_TECSEC_RSA_PRIVATE_KEY_BLOB_OID, tsCryptoData::OID)))
        {
            // Private key
            top = innerDoc->DocumentElement();

            if (top->Tag() != 0x10 || top->Type() != 0 || !top->IsConstructed() || top->Children()->size() != 8)
                return false;

            n = AdjustASN1Number(top->Children()->at(0)->InnerData());
            e = AdjustASN1Number(top->Children()->at(1)->InnerData());
            d = AdjustASN1Number(top->Children()->at(2)->InnerData());
            p = AdjustASN1Number(top->Children()->at(3)->InnerData());
            q = AdjustASN1Number(top->Children()->at(4)->InnerData());
            dp = AdjustASN1Number(top->Children()->at(5)->InnerData());
            dq = AdjustASN1Number(top->Children()->at(6)->InnerData());
            qInv = AdjustASN1Number(top->Children()->at(7)->InnerData());
            if (!set_Exponent(e) || !set_PublicModulus(n))
                return false;

            if (p.size() == q.size() && p.size() > 0)
            {
                if (!set_p(p) || !set_q(q) || !set_dp(dp) || !set_dq(dq) || !set_qInv(qInv))
                    return false;
            }
            else
            {
                if (!set_PrivateExponent(d))
                    return false;
            }
            if (!IsPublicLoaded() || !IsPrivateLoaded())
                return false;
            return true;
        }
        else
            return false;
    }
    virtual size_t minimumKeySizeInBits() const override
    {
        if (desc == nullptr)
            return 0;
        return desc->minimumKeyBitSize;
    }
    virtual size_t maximumKeySizeInBits() const override
    {
        if (desc == nullptr)
            return 0;
        return desc->maximumKeyBitSize;
    }
    virtual size_t keySizeIncrementInBits() const override
    {
        if (desc == nullptr)
            return 0;
        return desc->keySizeIncrement;
    }
    virtual std::shared_ptr<AsymmetricKey> generateNewKeyPair(bool forSignature) const override
    {
        std::shared_ptr<AsymmetricKey> key = std::dynamic_pointer_cast<AsymmetricKey>(CryptoFactory(GetName()));
        std::shared_ptr<RsaKey> rsa = std::dynamic_pointer_cast<RsaKey>(key);

        if (!!key && !!rsa)
        {
            if (!rsa->generateKeyPair(_RSA_Key_Gen_Type::rsakg_Probable_Composite, "SHA256", KeySize(), forSignature))
            {
                key.reset();
            }
        }
        else
        {
            key.reset();
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

    // RsaPrimitives
    virtual bool EncryptPrimitive(const tsCryptoData &inputData, tsCryptoData &outputData) const override
    {
        if (!gFipsState.operational() || desc == nullptr || keyPair == nullptr)
            return false;

        uint32_t len;

        if (!desc->encryptPrimitive(keyPair, inputData.c_str(), (uint32_t)inputData.size(), nullptr, &len))
            return false;

        outputData.resize(len);

        if (!desc->encryptPrimitive(keyPair, inputData.c_str(), (uint32_t)inputData.size(), outputData.rawData(), &len))
        {
            outputData.clear();
            return false;
        }
        outputData.resize(len);
        return true;
    }
    virtual bool DecryptPrimitive(const tsCryptoData &inputData, tsCryptoData &outputData) const override
    {
        if (!gFipsState.operational() || desc == nullptr || keyPair == nullptr)
            return false;

        uint32_t len;

        if (!desc->decryptPrimitive(keyPair, inputData.c_str(), (uint32_t)inputData.size(), nullptr, &len))
            return false;

        outputData.resize(len);

        if (!desc->decryptPrimitive(keyPair, inputData.c_str(), (uint32_t)inputData.size(), outputData.rawData(), &len))
        {
            outputData.clear();
            return false;
        }
        outputData.resize(len);
        return true;
    }

    // RsaKey
    virtual tsCryptoData get_PublicModulus() const override
    {
        if (!tsCryptoOK() || desc == nullptr || keyPair == nullptr)
            return tsCryptoData();

        tsCryptoData tmp;
        uint32_t len;
        if (!desc->exportPublicModulus(keyPair, nullptr, &len))
            return tsCryptoData();
        tmp.resize(len);
        if (!desc->exportPublicModulus(keyPair, tmp.rawData(), &len))
            return tsCryptoData();
        tmp.resize(len);
        return tmp;
    }
    virtual bool set_PublicModulus(const tsCryptoData &data) override
    {
        if (!gFipsState.operational() || desc == nullptr || keyPair == nullptr)
            return false;
        if (!desc->addPublicModulus(keyPair, data.c_str(), (uint32_t)data.size()))
        {
            return false;
        }
        return true;
    }
    virtual tsCryptoData get_Exponent() const override
    {
        if (!tsCryptoOK() || desc == nullptr || keyPair == nullptr)
            return tsCryptoData();

        tsCryptoData tmp;
        uint32_t len;
        if (!desc->exportPublicExponent(keyPair, nullptr, &len))
            return tsCryptoData();
        tmp.resize(len);
        if (!desc->exportPublicExponent(keyPair, tmp.rawData(), &len))
            return tsCryptoData();
        tmp.resize(len);
        return tmp;
    }
    virtual bool set_Exponent(const tsCryptoData &data) override
    {
        if (!gFipsState.operational() || desc == nullptr || keyPair == nullptr)
            return false;
        if (!desc->addPublicExponent(keyPair, data.c_str(), (uint32_t)data.size()))
        {
            return false;
        }
        return true;
    }
    virtual tsCryptoData get_PrivateExponent() const override
    {
        if (!tsCryptoOK() || desc == nullptr || keyPair == nullptr)
            return tsCryptoData();

        tsCryptoData tmp;
        uint32_t len;
        if (!desc->exportPrivateExponent(keyPair, nullptr, &len))
            return tsCryptoData();
        tmp.resize(len);
        if (!desc->exportPrivateExponent(keyPair, tmp.rawData(), &len))
            return tsCryptoData();
        tmp.resize(len);
        return tmp;
    }
    virtual bool set_PrivateExponent(const tsCryptoData &data) override
    {
        if (!gFipsState.operational() || desc == nullptr || keyPair == nullptr)
            return false;
        if (!desc->addPrivateKey(keyPair, data.c_str(), (uint32_t)data.size()))
        {
            return false;
        }
        return true;
    }
    virtual tsCryptoData get_p() const override
    {
        if (!tsCryptoOK() || desc == nullptr || keyPair == nullptr)
            return tsCryptoData();

        tsCryptoData p, q, dp, dq, qInv;
        uint32_t Plen, Qlen, DPlen, DQlen, QINVlen;
        if (!desc->exportPrivateCrt(keyPair, nullptr, &Plen, nullptr, &Qlen, nullptr, &DPlen, nullptr, &DQlen, nullptr, &QINVlen))
            return tsCryptoData();
        p.resize(Plen);
        q.resize(Qlen);
        dp.resize(DPlen);
        dq.resize(DQlen);
        qInv.resize(QINVlen);
        if (!desc->exportPrivateCrt(keyPair, p.rawData(), &Plen, q.rawData(), &Qlen, dp.rawData(), &DPlen, dq.rawData(), &DQlen, qInv.rawData(), &QINVlen))
            return tsCryptoData();
        p.resize(Plen);
        q.resize(Qlen);
        dp.resize(DPlen);
        dq.resize(DQlen);
        qInv.resize(QINVlen);
        return p;
    }
    virtual bool set_p(const tsCryptoData &data) override
    {
        if (!gFipsState.operational() || desc == nullptr || keyPair == nullptr)
            return false;
        if (!desc->addPrivateCrtP(keyPair, data.c_str(), (uint32_t)data.size()))
        {
            return false;
        }
        return true;
    }
    virtual tsCryptoData get_q() const override
    {
        if (!tsCryptoOK() || desc == nullptr || keyPair == nullptr)
            return tsCryptoData();

        tsCryptoData p, q, dp, dq, qInv;
        uint32_t Plen, Qlen, DPlen, DQlen, QINVlen;
        if (!desc->exportPrivateCrt(keyPair, nullptr, &Plen, nullptr, &Qlen, nullptr, &DPlen, nullptr, &DQlen, nullptr, &QINVlen))
            return tsCryptoData();
        p.resize(Plen);
        q.resize(Qlen);
        dp.resize(DPlen);
        dq.resize(DQlen);
        qInv.resize(QINVlen);
        if (!desc->exportPrivateCrt(keyPair, p.rawData(), &Plen, q.rawData(), &Qlen, dp.rawData(), &DPlen, dq.rawData(), &DQlen, qInv.rawData(), &QINVlen))
            return tsCryptoData();
        p.resize(Plen);
        q.resize(Qlen);
        dp.resize(DPlen);
        dq.resize(DQlen);
        qInv.resize(QINVlen);
        return q;
    }
    virtual bool set_q(const tsCryptoData &data) override
    {
        if (!gFipsState.operational() || desc == nullptr || keyPair == nullptr)
            return false;
        if (!desc->addPrivateCrtQ(keyPair, data.c_str(), (uint32_t)data.size()))
        {
            return false;
        }
        return true;
    }
    virtual tsCryptoData get_dp() const override
    {
        if (!tsCryptoOK() || desc == nullptr || keyPair == nullptr)
            return tsCryptoData();

        tsCryptoData p, q, dp, dq, qInv;
        uint32_t Plen, Qlen, DPlen, DQlen, QINVlen;
        if (!desc->exportPrivateCrt(keyPair, nullptr, &Plen, nullptr, &Qlen, nullptr, &DPlen, nullptr, &DQlen, nullptr, &QINVlen))
            return tsCryptoData();
        p.resize(Plen);
        q.resize(Qlen);
        dp.resize(DPlen);
        dq.resize(DQlen);
        qInv.resize(QINVlen);
        if (!desc->exportPrivateCrt(keyPair, p.rawData(), &Plen, q.rawData(), &Qlen, dp.rawData(), &DPlen, dq.rawData(), &DQlen, qInv.rawData(), &QINVlen))
            return tsCryptoData();
        p.resize(Plen);
        q.resize(Qlen);
        dp.resize(DPlen);
        dq.resize(DQlen);
        qInv.resize(QINVlen);
        return dp;
    }
    virtual bool set_dp(const tsCryptoData &data) override
    {
        if (!gFipsState.operational() || desc == nullptr || keyPair == nullptr)
            return false;
        if (!desc->addPrivateCrtDP(keyPair, data.c_str(), (uint32_t)data.size()))
        {
            return false;
        }
        return true;
    }
    virtual tsCryptoData get_dq() const override
    {
        if (!tsCryptoOK() || desc == nullptr || keyPair == nullptr)
            return tsCryptoData();

        tsCryptoData p, q, dp, dq, qInv;
        uint32_t Plen, Qlen, DPlen, DQlen, QINVlen;
        if (!desc->exportPrivateCrt(keyPair, nullptr, &Plen, nullptr, &Qlen, nullptr, &DPlen, nullptr, &DQlen, nullptr, &QINVlen))
            return tsCryptoData();
        p.resize(Plen);
        q.resize(Qlen);
        dp.resize(DPlen);
        dq.resize(DQlen);
        qInv.resize(QINVlen);
        if (!desc->exportPrivateCrt(keyPair, p.rawData(), &Plen, q.rawData(), &Qlen, dp.rawData(), &DPlen, dq.rawData(), &DQlen, qInv.rawData(), &QINVlen))
            return tsCryptoData();
        p.resize(Plen);
        q.resize(Qlen);
        dp.resize(DPlen);
        dq.resize(DQlen);
        qInv.resize(QINVlen);
        return dq;
    }
    virtual bool set_dq(const tsCryptoData &data) override
    {
        if (!gFipsState.operational() || desc == nullptr || keyPair == nullptr)
            return false;
        if (!desc->addPrivateCrtDQ(keyPair, data.c_str(), (uint32_t)data.size()))
        {
            return false;
        }
        return true;
    }
    virtual tsCryptoData get_qInv() const override
    {
        if (!tsCryptoOK() || desc == nullptr || keyPair == nullptr)
            return tsCryptoData();

        tsCryptoData p, q, dp, dq, qInv;
        uint32_t Plen, Qlen, DPlen, DQlen, QINVlen;
        if (!desc->exportPrivateCrt(keyPair, nullptr, &Plen, nullptr, &Qlen, nullptr, &DPlen, nullptr, &DQlen, nullptr, &QINVlen))
            return tsCryptoData();
        p.resize(Plen);
        q.resize(Qlen);
        dp.resize(DPlen);
        dq.resize(DQlen);
        qInv.resize(QINVlen);
        if (!desc->exportPrivateCrt(keyPair, p.rawData(), &Plen, q.rawData(), &Qlen, dp.rawData(), &DPlen, dq.rawData(), &DQlen, qInv.rawData(), &QINVlen))
            return tsCryptoData();
        p.resize(Plen);
        q.resize(Qlen);
        dp.resize(DPlen);
        dq.resize(DQlen);
        qInv.resize(QINVlen);
        return qInv;
    }
    virtual bool set_qInv(const tsCryptoData &data) override
    {
        if (!gFipsState.operational() || desc == nullptr || keyPair == nullptr)
            return false;
        if (!desc->addPrivateCrtQINV(keyPair, data.c_str(), (uint32_t)data.size()))
        {
            return false;
        }
        return true;
    }
    virtual bool generateKeyPair(RSA_Key_Gen_Type primeType, const tsCryptoStringBase& hashName, size_t keyLengthInBits, bool forSignature) override
    {
        const TSIHash* hasher;
        SmartCryptoWorkspace hashWorkspace;

        if (!gFipsState.operational() || desc == nullptr)
            return false;

        if (keyPair == nullptr)
            keyPair = tsCreateWorkspace(desc);
        if (keyPair == nullptr)
            return false;

        hasher = TSLookup(TSIHash, hashName.c_str());
        if (hasher == nullptr)
            return false;
        hashWorkspace = hasher->def;

        return desc->generateKeyPair(keyPair, (TSRsaKeyGenType)primeType, (uint32_t)keyLengthInBits, hashWorkspace, false) &&
            ValidateKeys();
    }
    virtual bool reserved1() override
    {
        return false;
    }
    virtual bool reserved2() override
    {
        return false;
    }
    virtual bool reserved3() override
    {
        return false;
    }

    // RsaKeyGenerationParameters
    virtual tsCryptoData get_Seed() const override
    {
        if (!tsCryptoOK() || desc == nullptr || keyPair == nullptr)
            return tsCryptoData();

        tsCryptoData tmp;
        uint32_t len;
        if (!desc->getSeed(keyPair, nullptr, &len))
            return tsCryptoData();
        tmp.resize(len);
        if (!desc->getSeed(keyPair, tmp.rawData(), &len))
            return tsCryptoData();
        tmp.resize(len);
        return tmp;
    }
    virtual bool set_Seed(const tsCryptoData &data) override
    {
        if (!gFipsState.operational() || desc == nullptr || keyPair == nullptr)
            return false;
        if (!desc->setSeed(keyPair, data.c_str(), (uint32_t)data.size()))
        {
            return false;
        }
        return true;
    }
    virtual tsCryptoData get_p1() const override
    {
        if (!tsCryptoOK() || desc == nullptr || keyPair == nullptr)
            return tsCryptoData();

        tsCryptoData tmp;
        uint32_t len;
        if (!desc->getP1(keyPair, nullptr, &len))
            return tsCryptoData();
        tmp.resize(len);
        if (!desc->getP1(keyPair, tmp.rawData(), &len))
            return tsCryptoData();
        tmp.resize(len);
        return tmp;
    }
    virtual bool set_p1(const tsCryptoData &data) override
    {
        if (!gFipsState.operational() || desc == nullptr || keyPair == nullptr)
            return false;
        if (!desc->setP1(keyPair, data.c_str(), (uint32_t)data.size()))
        {
            return false;
        }
        return true;
    }
    virtual tsCryptoData get_p2() const override
    {
        if (!tsCryptoOK() || desc == nullptr || keyPair == nullptr)
            return tsCryptoData();

        tsCryptoData tmp;
        uint32_t len;
        if (!desc->getP2(keyPair, nullptr, &len))
            return tsCryptoData();
        tmp.resize(len);
        if (!desc->getP2(keyPair, tmp.rawData(), &len))
            return tsCryptoData();
        tmp.resize(len);
        return tmp;
    }
    virtual bool set_p2(const tsCryptoData &data) override
    {
        if (!gFipsState.operational() || desc == nullptr || keyPair == nullptr)
            return false;
        if (!desc->setP2(keyPair, data.c_str(), (uint32_t)data.size()))
        {
            return false;
        }
        return true;
    }
    virtual tsCryptoData get_q1() const override
    {
        if (!tsCryptoOK() || desc == nullptr || keyPair == nullptr)
            return tsCryptoData();

        tsCryptoData tmp;
        uint32_t len;
        if (!desc->getQ1(keyPair, nullptr, &len))
            return tsCryptoData();
        tmp.resize(len);
        if (!desc->getQ1(keyPair, tmp.rawData(), &len))
            return tsCryptoData();
        tmp.resize(len);
        return tmp;
    }
    virtual bool set_q1(const tsCryptoData &data) override
    {
        if (!gFipsState.operational() || desc == nullptr || keyPair == nullptr)
            return false;
        if (!desc->setQ1(keyPair, data.c_str(), (uint32_t)data.size()))
        {
            return false;
        }
        return true;
    }
    virtual tsCryptoData get_q2() const override
    {
        if (!tsCryptoOK() || desc == nullptr || keyPair == nullptr)
            return tsCryptoData();

        tsCryptoData tmp;
        uint32_t len;
        if (!desc->getQ2(keyPair, nullptr, &len))
            return tsCryptoData();
        tmp.resize(len);
        if (!desc->getQ2(keyPair, tmp.rawData(), &len))
            return tsCryptoData();
        tmp.resize(len);
        return tmp;
    }
    virtual bool set_q2(const tsCryptoData &data) override
    {
        if (!gFipsState.operational() || desc == nullptr || keyPair == nullptr)
            return false;
        if (!desc->setQ2(keyPair, data.c_str(), (uint32_t)data.size()))
        {
            return false;
        }
        return true;
    }
    virtual tsCryptoData get_Xp1() const override
    {
        if (!tsCryptoOK() || desc == nullptr || keyPair == nullptr)
            return tsCryptoData();

        tsCryptoData tmp;
        uint32_t len;
        if (!desc->getXp1(keyPair, nullptr, &len))
            return tsCryptoData();
        tmp.resize(len);
        if (!desc->getXp1(keyPair, tmp.rawData(), &len))
            return tsCryptoData();
        tmp.resize(len);
        return tmp;
    }
    virtual bool set_Xp1(const tsCryptoData &data) override
    {
        if (!gFipsState.operational() || desc == nullptr || keyPair == nullptr)
            return false;
        if (!desc->setXp1(keyPair, data.c_str(), (uint32_t)data.size()))
        {
            return false;
        }
        return true;
    }
    virtual tsCryptoData get_Xp2() const override
    {
        if (!tsCryptoOK() || desc == nullptr || keyPair == nullptr)
            return tsCryptoData();

        tsCryptoData tmp;
        uint32_t len;
        if (!desc->getXp2(keyPair, nullptr, &len))
            return tsCryptoData();
        tmp.resize(len);
        if (!desc->getXp2(keyPair, tmp.rawData(), &len))
            return tsCryptoData();
        tmp.resize(len);
        return tmp;
    }
    virtual bool set_Xp2(const tsCryptoData &data) override
    {
        if (!gFipsState.operational() || desc == nullptr || keyPair == nullptr)
            return false;
        if (!desc->setXp2(keyPair, data.c_str(), (uint32_t)data.size()))
        {
            return false;
        }
        return true;
    }
    virtual tsCryptoData get_Xq1() const override
    {
        if (!tsCryptoOK() || desc == nullptr || keyPair == nullptr)
            return tsCryptoData();

        tsCryptoData tmp;
        uint32_t len;
        if (!desc->getXq1(keyPair, nullptr, &len))
            return tsCryptoData();
        tmp.resize(len);
        if (!desc->getXq1(keyPair, tmp.rawData(), &len))
            return tsCryptoData();
        tmp.resize(len);
        return tmp;
    }
    virtual bool set_Xq1(const tsCryptoData &data) override
    {
        if (!gFipsState.operational() || desc == nullptr || keyPair == nullptr)
            return false;
        if (!desc->setXq1(keyPair, data.c_str(), (uint32_t)data.size()))
        {
            return false;
        }
        return true;
    }
    virtual tsCryptoData get_Xq2() const override
    {
        if (!tsCryptoOK() || desc == nullptr || keyPair == nullptr)
            return tsCryptoData();

        tsCryptoData tmp;
        uint32_t len;
        if (!desc->getXq2(keyPair, nullptr, &len))
            return tsCryptoData();
        tmp.resize(len);
        if (!desc->getXq2(keyPair, tmp.rawData(), &len))
            return tsCryptoData();
        tmp.resize(len);
        return tmp;
    }
    virtual bool set_Xq2(const tsCryptoData &data) override
    {
        if (!gFipsState.operational() || desc == nullptr || keyPair == nullptr)
            return false;
        if (!desc->setXq2(keyPair, data.c_str(), (uint32_t)data.size()))
        {
            return false;
        }
        return true;
    }
    virtual tsCryptoData get_Xp() const override
    {
        if (!tsCryptoOK() || desc == nullptr || keyPair == nullptr)
            return tsCryptoData();

        tsCryptoData tmp;
        uint32_t len;
        if (!desc->getXp(keyPair, nullptr, &len))
            return tsCryptoData();
        tmp.resize(len);
        if (!desc->getXp(keyPair, tmp.rawData(), &len))
            return tsCryptoData();
        tmp.resize(len);
        return tmp;
    }
    virtual bool set_Xp(const tsCryptoData &data) override
    {
        if (!gFipsState.operational() || desc == nullptr || keyPair == nullptr)
            return false;
        if (!desc->setXp(keyPair, data.c_str(), (uint32_t)data.size()))
        {
            return false;
        }
        return true;
    }
    virtual tsCryptoData get_Xq() const override
    {
        if (!tsCryptoOK() || desc == nullptr || keyPair == nullptr)
            return tsCryptoData();

        tsCryptoData tmp;
        uint32_t len;
        if (!desc->getXq(keyPair, nullptr, &len))
            return tsCryptoData();
        tmp.resize(len);
        if (!desc->getXq(keyPair, tmp.rawData(), &len))
            return tsCryptoData();
        tmp.resize(len);
        return tmp;
    }
    virtual bool set_Xq(const tsCryptoData &data) override
    {
        if (!gFipsState.operational() || desc == nullptr || keyPair == nullptr)
            return false;
        if (!desc->setXq(keyPair, data.c_str(), (uint32_t)data.size()))
        {
            return false;
        }
        return true;
    }
    virtual size_t get_bitlength1() const override
    {
        if (!tsCryptoOK() || desc == nullptr || keyPair == nullptr)
            return 0;

        return desc->getBitlength1(keyPair);
    }
    virtual bool set_bitlength1(size_t setTo) override
    {
        if (!gFipsState.operational() || desc == nullptr || keyPair == nullptr)
            return false;
        if (!desc->setBitlength1(keyPair, (uint32_t)setTo))
        {
            return false;
        }
        return true;
    }
    virtual size_t get_bitlength2() const override
    {
        if (!tsCryptoOK() || desc == nullptr || keyPair == nullptr)
            return 0;

        return desc->getBitlength2(keyPair);
    }
    virtual bool set_bitlength2(size_t setTo) override
    {
        if (!gFipsState.operational() || desc == nullptr || keyPair == nullptr)
            return false;
        if (!desc->setBitlength2(keyPair, (uint32_t)setTo))
        {
            return false;
        }
        return true;
    }
    virtual size_t get_bitlength3() const override
    {
        if (!tsCryptoOK() || desc == nullptr || keyPair == nullptr)
            return 0;

        return desc->getBitlength3(keyPair);
    }
    virtual bool set_bitlength3(size_t setTo) override
    {
        if (!gFipsState.operational() || desc == nullptr || keyPair == nullptr)
            return false;
        if (!desc->setBitlength3(keyPair, (uint32_t)setTo))
        {
            return false;
        }
        return true;
    }
    virtual size_t get_bitlength4() const override
    {
        if (!tsCryptoOK() || desc == nullptr || keyPair == nullptr)
            return 0;

        return desc->getBitlength4(keyPair);
    }
    virtual bool set_bitlength4(size_t setTo) override
    {
        if (!gFipsState.operational() || desc == nullptr || keyPair == nullptr)
            return false;
        if (!desc->setBitlength4(keyPair, (uint32_t)setTo))
        {
            return false;
        }
        return true;
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

    // TSExtensibleSelfTest
    virtual bool RunSelfTestsFor(const tsCryptoStringBase& baseProtocolName, std::shared_ptr<tscrypto::ICryptoObject> baseProtocol, bool runDetailedTests) override
    {
        UNREFERENCED_PARAMETER(runDetailedTests);

        if (!gFipsState.operational())
            return false;
        if (!baseProtocol || baseProtocolName.size() == 0)
        {
            gFipsState.testFailed();
            return false;
        }

        return false; // TODO:  Implement me
    }

    // tscrypto::IInitializableObject
    virtual bool InitializeWithFullName(const tscrypto::tsCryptoStringBase& fullName) override
    {
        tsCryptoString algorithm(fullName);

        SetName(algorithm);
        return true;
    }

private:
    TSKeyValidationFailureType m_validationReason;
    const TSIRsa* desc;
    SmartCryptoWorkspace keyPair;

    // Inherited via TSALG_Access
    virtual const TSICyberVEILObject * Descriptor() const override
    {
        return desc->def.primary;
    }
    virtual TSWORKSPACE getKeyPair() const override
    {
        return keyPair;
    }
    virtual TSWORKSPACE getWorkspace() const override
    {
        return nullptr;
    }
    virtual TSWORKSPACE detachFromKeyPair() override
    {
        return keyPair.detach();
    }
    virtual TSWORKSPACE cloneKeyPair() const override
    {
        if (desc == nullptr || keyPair == nullptr)
            return nullptr;
        return tsClone(keyPair);
    }
};

tscrypto::ICryptoObject* CreateRsaKey()
{
    return dynamic_cast<tscrypto::ICryptoObject*>(new Key_Rsa);
}
