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
#include "CryptoAsn1.h"

class Key_ECC : public EccKey, public TSName, public DhEccPrimitives, public tscrypto::ICryptoObject, public tscrypto::IInitializableObject, public AlgorithmInfo, public TSALG_Access
{
public:
	Key_ECC() : m_validationReason(kvf_NoFailure)
	{
		desc = findEccAlgorithm("ECC-P256");
	}
	virtual ~Key_ECC(void)
	{
        keyPair.reset();
	}

	// AssymetricKey
	virtual void Clear() override
	{
		if (desc != nullptr && keyPair != nullptr)
		{
			desc->clearKey(desc, keyPair);
			keyPair.reset();
		}
		m_validationReason = kvf_NoFailure;
	}
	virtual size_t KeySize() const override
	{
		if (desc == nullptr)
			return 0;
		return desc->keySizeInBits;
	}
	virtual bool IsPublicLoaded() const override
	{
		if (desc == nullptr)
			return false;
		return desc->hasPublicKey(desc, keyPair);
	}
	virtual bool IsPrivateLoaded() const override
	{
		if (desc == nullptr)
			return false;
		return desc->hasPrivateKey(desc, keyPair);
	}
	virtual bool IsPublicVerified() const override
	{
		if (desc == nullptr)
			return false;
		return desc->publicIsValidated(desc, keyPair);
	}
	virtual bool IsPrivateVerified() const override
	{
		if (desc == nullptr)
			return false;
		return desc->privateIsValidated(desc, keyPair);
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
		if (desc == nullptr)
			return false;
		return desc->validateKeys(desc, keyPair, &m_validationReason);
	}
	virtual bool KeysAreCompatible(std::shared_ptr<AsymmetricKey> secondKey) const override
	{
		if (!gFipsState.operational())
			return false;
		std::shared_ptr<EccKey> ecc = std::dynamic_pointer_cast<EccKey>(secondKey);

		if (!ecc)
			return false;

		return (ecc->get_curveName() == get_curveName());
	}
	virtual bool generateKeyPair(bool forSignature) override
	{
		if (!gFipsState.operational() || desc == nullptr)
			return false;

		Clear();
		if (forSignature)
			desc = desc->signingDescriptor;
		else
			desc = desc->encryptionDescriptor;
		keyPair = desc->createKeyStructure(desc);
		if (keyPair == nullptr)
			return false;
		if (!desc->generateKeyPair(desc, keyPair))
		{
			Clear();
			return false;
		}
		return true;
	}
	virtual bool CanComputeZ() const override
	{
		if (desc == nullptr)
			return false;

		return desc->canComputeZ;
	}
	virtual bool ComputeZ(std::shared_ptr<AsymmetricKey> secondKey, tsCryptoData &Z) const override
	{
		if (!gFipsState.operational() || desc == nullptr || keyPair == nullptr || !KeysAreCompatible(secondKey))
			return false;
		std::shared_ptr<Key_ECC> ecc = std::dynamic_pointer_cast<Key_ECC>(secondKey);

		Z.clear();
		if (!ecc)
			return false;

		if (HasPrivateKey())
		{
			if (!ecc->HasPublicKey())
				return false;
			return DH(ecc->get_Point(), Z);
		}
		else
		{
			std::shared_ptr<DhEccPrimitives> prims = std::dynamic_pointer_cast<DhEccPrimitives>(secondKey);

			if (!prims || !ecc->HasPrivateKey() || !HasPublicKey())
				return false;

			return prims->DH(get_Point(), Z);
		}
	}
	virtual ValidationFailureType ValidationFailureReason() const override
	{
		return (ValidationFailureType)m_validationReason; // TODO:  Make sure that these two definitions match
	}
	virtual tsCryptoData toByteArray() const override
	{
		if (desc == nullptr || keyPair == nullptr)
			return tsCryptoData();

		if (IsPublicLoaded() && !IsPrivateLoaded())
		{
			std::shared_ptr<TlvDocument> blobDoc = TlvDocument::Create();

			blobDoc->DocumentElement()->Tag(0x10);
			blobDoc->DocumentElement()->Type(0);

			std::shared_ptr<TlvNode> alg = blobDoc->CreateTlvNode(0x10, 0);

			blobDoc->DocumentElement()->AppendChild(alg);
			alg->AppendChild(blobDoc->CreateOIDNode(tsCryptoData(EC_PUBLIC_KEY_OID, tsCryptoData::OID)));
			alg->AppendChild(blobDoc->CreateOIDNode(tsCryptoData(AlgorithmOID(), tsCryptoData::OID)));

			std::shared_ptr<TlvDocument> keyDoc = TlvDocument::Create();
			keyDoc->DocumentElement()->Tag(0x10);
			keyDoc->DocumentElement()->Type(0);

			keyDoc->DocumentElement()->AppendChild(MakeIntegerNode(get_Point(), keyDoc));

			blobDoc->DocumentElement()->AppendChild(MakeBitString(keyDoc->SaveTlv(), 0, blobDoc));
			return blobDoc->SaveTlv();
		}
		else if (IsPrivateLoaded())
		{
			std::shared_ptr<TlvDocument> blobDoc = TlvDocument::Create();

			blobDoc->DocumentElement()->Tag(0x10);
			blobDoc->DocumentElement()->Type(0);

			std::shared_ptr<TlvNode> alg = blobDoc->CreateSequence();

			blobDoc->DocumentElement()->AppendChild(alg);
			alg->AppendChild(blobDoc->CreateOIDNode(tsCryptoData(TECSEC_ECC_PRIVATE_KEY_BLOB, tsCryptoData::OID)));
			alg->AppendChild(blobDoc->CreateOIDNode(tsCryptoData(AlgorithmOID(), tsCryptoData::OID)));

			std::shared_ptr<TlvDocument> keyDoc = TlvDocument::Create();
			keyDoc->DocumentElement()->Tag(0x10);
			keyDoc->DocumentElement()->Type(0);

			keyDoc->DocumentElement()->AppendChild(MakeIntegerNode(get_Point(), keyDoc));
			keyDoc->DocumentElement()->AppendChild(MakeIntegerNode(get_PrivateValue(), keyDoc));

			blobDoc->DocumentElement()->AppendChild(MakeBitString(keyDoc->SaveTlv(), 0, blobDoc));
			return blobDoc->SaveTlv();
		}
		else
		{
			throw tscrypto::not_ready("No keys loaded");
		}
	}
	virtual bool fromByteArray(const tsCryptoData &data) override
	{
		if (!gFipsState.operational() || desc == nullptr)
			return false;

		std::shared_ptr<TlvDocument> doc = TlvDocument::Create();
		std::shared_ptr<TlvNode> top;
		tsCryptoData point, privateKey;
		std::shared_ptr<TlvDocument> innerDoc = TlvDocument::Create();
		tsCryptoData curve;

		Clear();

		// First check the RFC 3279 / pkcs 8 definition for ECC Public keys.
		for (;;)
		{
			tscrypto::_POD_Pkcs8PublicKey pkcs8Key;

			if (pkcs8Key.Decode(data))
			{
				if (pkcs8Key.get_pubKeyAlgorithm().get_oid().ToOIDString() == RSA_ENCRYPT_OID)
				{
					break;
				}
				else if (pkcs8Key.get_pubKeyAlgorithm().get_oid().ToOIDString() == EC_PUBLIC_KEY_OID)
				{
					if (pkcs8Key.get_pubKeyAlgorithm().exists_Parameter() &&
						pkcs8Key.get_pubKeyAlgorithm().get_Parameter()->type == TlvNode::Tlv_Sequence)
					{
						tscrypto::_POD_EccPublicKeyParameter param;

						if (!param.Decode(pkcs8Key.get_pubKeyAlgorithm().get_Parameter()->value))
						{
							break;
						}
						switch (param.get_EcpkParameters().get_selectedItem())
						{
						case tscrypto::_POD_EccPublicKeyParameter_EcpkParameters::Choice_namedCurve:
						{
							tsCryptoString curvename = OIDtoAlgName(param.get_EcpkParameters().get_namedCurve().ToOIDString());
							tsCryptoString eccName = curvename;

							eccName.Replace("KEY-", "ECC-");
							if (TsStrniCmp(eccName.c_str(), "NUMSP", 5) == 0)
								eccName.insert(0, "ECC-");
							if (TsStrniCmp(eccName.c_str(), "X", 1) == 0)
								eccName.Replace("X", "ECC-CURVE", 1);
							if (TsStrniCmp(eccName.c_str(), "ED", 2) == 0)
								eccName.insert(0, "ECC-").Replace("_PH", "");

							desc = findEccAlgorithm(eccName.c_str());
							if (desc == nullptr)
								return false;
							SetName(curvename);
							keyPair = desc->createKeyStructure(desc);
						}
							break;
						// TODO:  Implement me - Search through ECC list to find a matching curve
						//case tscrypto::_POD_EccPublicKeyParameter_EcpkParameters::Choice_ecParameters:
						//	if (param.get_EcpkParameters().get_ecParameters().get_fieldId().get_fieldType().ToOIDString() != "1.2.840.10045.1.1")
						//	{
						//		tsCryptoString oid;
						//		tscrypto::_POD_ECParameters& params = param.get_EcpkParameters().get_ecParameters();
						//
						//
						//		if (!EccCurve::GetCurveOIDByParameters(params.get_fieldId().get_parameters(), params.get_curve().get_a(), params.get_curve().get_b(), params.get_base(),
						//			params.get_order(), params.exists_cofactor() ? (int)params.get_cofactor().ToUint64() : 1, oid))
						//		{
						//			break;
						//		}
						//		if (!(ecc = std::dynamic_pointer_cast<EccKey>(CryptoFactory(oid))))
						//			break;
						//	}
						//	break;
						default:
							break;
						}

						return set_Point(pkcs8Key.get_keyValue().bits());
					}
					else
					{
						break;
					}
				}
				else
				{
					break;
				}
			}
			break;
		}

		// Now try ECC Private Keys (pkcs 8 / RFC 3279)
		for (;;)
		{
			tscrypto::_POD_Pkcs8EccPrivateKey key;

			if (!key.Decode(data))
			{
				if (!key.exists_curve())
				{
					break;
				}
				else
				{
					tsCryptoString curvename = OIDtoAlgName(key.get_curve()->get_parameters().ToOIDString());
					tsCryptoString eccName = curvename;

					eccName.Replace("KEY-", "ECC-");
					if (TsStrniCmp(eccName.c_str(), "NUMSP", 5) == 0)
						eccName.insert(0, "ECC-");
					if (TsStrniCmp(eccName.c_str(), "X", 1) == 0)
						eccName.Replace("X", "ECC-CURVE", 1);
					if (TsStrniCmp(eccName.c_str(), "ED", 2) == 0)
						eccName.insert(0, "ECC-").Replace("_PH", "");

					desc = findEccAlgorithm(eccName.c_str());
					if (desc == nullptr)
						break;
					SetName(curvename);
					keyPair = desc->createKeyStructure(desc);

					if (key.exists_publicKey())
					{
						set_Point(key.get_publicKey()->get_value().bits());
					}
					set_PrivateValue(key.get_privateKey());
					return true;
				}
			}
			break;
		}


		// OK, now try the TecSec internal formats
		if (!doc->LoadTlv(data))
			return false;

		top = doc->DocumentElement();

		if (top->Tag() != TlvNode::Tlv_Sequence || top->Type() != 0 || !top->IsConstructed() || top->Children()->size() != 2 || top->Children()->at(1)->Tag() != TlvNode::Tlv_BitString)
			return false;

		if (top->ChildAt(0)->ChildCount() != 2 || top->ChildAt(0)->ChildAt(1)->Tag() != TlvNode::Tlv_OID)
		{
			return false;
		}
		curve = top->ChildAt(0)->ChildAt(1)->InnerData();

		if (curve.ToOIDString() != tsCryptoString(AlgorithmOID()))
		{
			tsCryptoString curvename = OIDtoAlgName(curve.ToOIDString());
			tsCryptoString eccName = curvename;

			eccName.Replace("KEY-", "ECC-");
			if (TsStrniCmp(eccName.c_str(), "NUMSP", 5) == 0)
				eccName.insert(0, "ECC-");
			if (TsStrniCmp(eccName.c_str(), "X", 1) == 0)
				eccName.Replace("X", "ECC-CURVE", 1);
			if (TsStrniCmp(eccName.c_str(), "ED", 2) == 0)
				eccName.insert(0, "ECC-").Replace("_PH", "");

			desc = findEccAlgorithm(eccName.c_str());
			if (desc == nullptr)
				return false;
			SetName(curvename);
			keyPair = desc->createKeyStructure(desc);
		}

		if (!innerDoc->LoadTlv(AdjustBitString(top->Children()->at(1)->InnerData())))
		{
			return false;
		}

		if (IsSequenceOID(top->ChildAt(0), tsCryptoData(EC_PUBLIC_KEY_OID, tsCryptoData::OID)))
		{
			// Public key only
			// ECC Public key blob
			top = innerDoc->DocumentElement();

			if (top->Tag() != 0x10 || top->Type() != 0 || !top->IsConstructed() || top->Children()->size() != 1)
				return false;

			point = AdjustASN1Number(top->Children()->at(0)->InnerData());
			if (!set_Point(point))
				return false;

			if (!IsPublicLoaded())
				return false;
			return true;
		}
		else if (IsSequenceOID(top->ChildAt(0), tsCryptoData(TECSEC_ECC_PRIVATE_KEY_BLOB, tsCryptoData::OID)))
		{
			// Private key
			top = innerDoc->DocumentElement();

			if (top->Tag() != 0x10 || top->Type() != 0 || !top->IsConstructed() || top->Children()->size() != 2)
				return false;

			point = AdjustASN1Number(top->Children()->at(0)->InnerData());
			privateKey = AdjustASN1Number(top->Children()->at(1)->InnerData());

			if (!set_PrivateValue(privateKey))
				return false;
			if (!IsPrivateLoaded())
				return false;
			if (point.size() > 0)
			{
				if (!set_Point(point))
					return false;
				if (!IsPublicLoaded())
					return false;
			}
			return true;
		}
		else
			return false;
	}
	virtual size_t minimumKeySizeInBits() const override
	{
		return KeySize();
	}
	virtual size_t maximumKeySizeInBits() const override
	{
		return KeySize();
	}
	virtual size_t keySizeIncrementInBits() const override
	{
		return 0;
	}
	virtual std::shared_ptr<AsymmetricKey> generateNewKeyPair(bool forSignature) const override
	{
		std::shared_ptr<AsymmetricKey> key = std::dynamic_pointer_cast<AsymmetricKey>(CryptoFactory(GetName()));

		if (!!key)
		{
			if (!key->generateKeyPair(forSignature))
			{
				key.reset();
			}
		}
		return key;
	}
	virtual bool signatureKey() const override 
	{ 
		if (desc == nullptr)
			return false;
		return desc->canSign;
	}
	virtual bool encryptionKey() const override 
	{ 
		if (desc == nullptr)
			return false;
		return desc->canComputeZ;
	}
	virtual bool prehashSignatures() const override 
	{ 
		if (desc == nullptr)
			return false;
		return desc->prehash_signatures;
	}
	virtual void set_signatureKey(bool setTo) override 
	{
        if (setTo && !signatureKey())
        {
            if (desc != nullptr && desc->signingDescriptor != nullptr)
            {
                tsCryptoData data = toByteArray();
                keyPair.reset();
                desc = desc->signingDescriptor;
                keyPair = desc->createKeyStructure(desc);
                fromByteArray(data);
            }
        }
	}
	virtual void set_encryptionKey(bool /*setTo*/) override 
	{
        if (!encryptionKey())
        {
            if (desc != nullptr && desc->encryptionDescriptor != nullptr)
            {
                tsCryptoData data = toByteArray();
                keyPair.reset();
                desc = desc->encryptionDescriptor;
                keyPair = desc->createKeyStructure(desc);
                fromByteArray(data);
            }
        }
	}

	// EccKey
	virtual tsCryptoString get_curveName() const override
	{
		if (desc == nullptr)
			return "";
		return desc->curve_name;
	}
	virtual tsCryptoData get_PrivateValue() const override
	{
		int i;
		int count;
		tsCryptoData tmp;
		uint32_t len;

		if (desc == nullptr || keyPair == nullptr || !desc->exportPrivateKey(desc, keyPair, nullptr, &len))
			throw tscrypto::not_ready("No curve");

		tmp.resize(len);
		if (!desc->exportPrivateKey(desc, keyPair, tmp.rawData(), &len))
			throw tscrypto::not_ready("No curve");

		tmp.resize(len);

		count = (int)tmp.size();
		for (i = 0; i < count; i++)
		{
			if (tmp[i] != 0)
			{
				if (i > 0)
					tmp.erase(0, i);
				break;
			}
		}
		if (i >= count && tmp.size() == (size_t)count)
			tmp.clear();
		if (tmp.size() == 0)
			return tmp;
		return tmp.padLeft((KeySize() + 7) / 8);
	}
	virtual bool set_PrivateValue(const tsCryptoData &data) override
	{
		if (!gFipsState.operational() || desc == nullptr)
			return false;

		if (keyPair == nullptr)
			keyPair = desc->createKeyStructure(desc);
		if (keyPair == nullptr)
			return false;

		return desc->addPrivateKey(desc, keyPair, data.c_str(), (uint32_t)data.size());
	}
	virtual tsCryptoData get_PublicX() const override
	{
		tsCryptoData tmp;
		uint32_t len = 0;

		if (desc == nullptr || keyPair == nullptr || !desc->exportPublicX(desc, keyPair, nullptr, &len))
			throw tscrypto::not_ready("No curve");

		tmp.resize(len);
		if (!desc->exportPublicX(desc, keyPair, tmp.rawData(), &len))
			tmp.clear();
		else
			tmp.resize(len);
		return tmp;
	}
	virtual tsCryptoData get_PublicY() const override
	{
		tsCryptoData tmp;
		uint32_t len = 0;

		if (desc == nullptr || keyPair == nullptr || !desc->exportPublicY(desc, keyPair, nullptr, &len))
			throw tscrypto::not_ready("No curve");

		tmp.resize(len);
		if (!desc->exportPublicY(desc, keyPair, tmp.rawData(), &len))
			tmp.clear();
		else
			tmp.resize(len);
		return tmp;
	}
	virtual tsCryptoData get_Point() const override
	{
		tsCryptoData tmp;
		uint32_t len = 0;

		if (desc == nullptr || keyPair == nullptr || !desc->exportPublicPoint(desc, keyPair, nullptr, &len))
			throw tscrypto::not_ready("No curve");

		tmp.resize(len);
		if (!desc->exportPublicPoint(desc, keyPair, tmp.rawData(), &len))
			tmp.clear();
		else
			tmp.resize(len);
		return tmp;
	}
	virtual bool set_Point(const tsCryptoData &data) override
	{
		if (!gFipsState.operational() || desc == nullptr)
			return false;

		if (keyPair == nullptr)
			keyPair = desc->createKeyStructure(desc);
		if (keyPair == nullptr)
			return false;

		return desc->addPublicPoint(desc, keyPair, data.c_str(), (uint32_t)data.size());
	}

	// DhEccPrimitives
	virtual bool SignUsingData(const tsCryptoData &data, tsCryptoData &r, tsCryptoData &s) const override
	{
		uint32_t rLen, sLen;

		if (!gFipsState.operational() || !HasPrivateKey() || !desc->canSign)
			return false;

		if (!desc->signUsingData(desc, keyPair, data.c_str(), (uint32_t)data.size(), nullptr, &rLen, nullptr, &sLen))
			return false;

		r.resize(rLen);
		s.resize(sLen);

		if (!desc->signUsingData(desc, keyPair, data.c_str(), (uint32_t)data.size(), r.rawData(), &rLen, s.rawData(), &sLen))
			return false;

		r.resize(rLen);
		s.resize(sLen);

		uint32_t size = (uint32_t)(KeySize() + 7) / 8;

		r.truncOrPadLeft(size);
		s.truncOrPadLeft(size);

		return true;
	}
	virtual bool VerifySignatureForData(const tsCryptoData &data, const tsCryptoData &r, const tsCryptoData &s) const override
	{
        uint32_t keySizeInBytes;

		if (!gFipsState.operational() || !HasPublicKey() || !desc->canSign)
			return false;

        keySizeInBytes = (desc->keySizeInBits + 7) / 8;
        if (r.size() != keySizeInBytes || s.size() != keySizeInBytes)
        {
            tsCryptoData r1(r), s1(s);

            if (r1.size() < keySizeInBytes)
                r1.padLeft(keySizeInBytes);
            if (s1.size() < keySizeInBytes)
                s1.padLeft(keySizeInBytes);
            return desc->verifySignatureForData(desc, keyPair, data.c_str(), (uint32_t)data.size(), r1.c_str(), (uint32_t)r1.size(), s1.c_str(), (uint32_t)s1.size());
        }
        else
		return desc->verifySignatureForData(desc, keyPair, data.c_str(), (uint32_t)data.size(), r.c_str(), (uint32_t)r.size(), s.c_str(), (uint32_t)s.size());
	}
	virtual bool DH(const tsCryptoData &publicPoint, tsCryptoData &Z) const override
	{
        SmartCryptoKey secondKey;
		uint32_t len;
		bool retVal;

		if (!gFipsState.operational() || !HasPrivateKey() || !desc->canComputeZ)
			return false;

		secondKey = desc->createKeyStructure(desc);
		if (secondKey == nullptr || !desc->addPublicPoint(desc, secondKey, publicPoint.c_str(), (uint32_t)publicPoint.size()) ||
			!desc->computeZ(desc, keyPair, secondKey, nullptr, &len))
		{
			return false;
		}
		Z.clear();
		Z.resize(len);
		retVal = desc->computeZ(desc, keyPair, secondKey, Z.rawData(), &len);
		Z.resize(len);
		if (!retVal)
			Z.clear();
		return retVal;
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

		SetName(algorithm);
		algorithm.ToUpper();
		algorithm.Replace("KEY-", "ECC-");
		if (TsStrniCmp(algorithm.c_str(), "NUMSP", 5) == 0)
			algorithm.insert(0, "ECC-");
		if (TsStrniCmp(algorithm.c_str(), "X", 1) == 0)
			algorithm.Replace("X", "ECC-CURVE", 1);
		if (TsStrniCmp(algorithm.c_str(), "ED", 2) == 0)
			algorithm.insert(0, "ECC-");
		algorithm.Replace("X25519", "CURVE25519").Replace("_PH", "");
		keyPair.reset();
		desc = findEccAlgorithm(algorithm.c_str());
		if (desc == nullptr)
			return false;
		return true;
	}

private:
	const EccDescriptor* desc;
	SmartCryptoKey keyPair;
	tsalg_keyValidationFailureType m_validationReason;

	// Inherited via TSALG_Access
	virtual const TSALG_Base_Descriptor * Descriptor() const override
	{
		return desc;
	}
	virtual CRYPTO_ASYMKEY getKeyPair() const override
	{
		return keyPair;
	}
	virtual CRYPTO_WORKSPACE getWorkspace() const override
	{
		return nullptr;
	}
	virtual CRYPTO_ASYMKEY detachFromKeyPair() override
	{
		return keyPair.detach();
	}
	virtual CRYPTO_ASYMKEY cloneKeyPair() const override
	{
		if (desc == nullptr || keyPair == nullptr)
			return nullptr;
		return desc->cloneKey(desc, keyPair);
	}
};

tscrypto::ICryptoObject* CreateEccKey()
{
	return dynamic_cast<tscrypto::ICryptoObject*>(new Key_ECC);
}

#if 0
bool Key_ECC::RunSelfTestsFor(const tsCryptoStringBase& baseProtocolName, std::shared_ptr<tscrypto::ICryptoObject> baseProtocol, bool runDetailedTests)
{
	MY_UNREFERENCED_PARAMETER(runDetailedTests);

	if (!gFipsState.operational())
		return false;
	if (!baseProtocol || baseProtocolName.size() == 0)
	{
		gFipsState.testFailed();
		return false;
	}


	return false; // TODO:  Implement me
}

bool Key_ECC::runTests(bool runDetailedTests)
{
	if (!gFipsState.operational())
		return false;
	if (!m_curve)
		return false;

	if (runDetailedTests)
	{
		tsCryptoData priv;
		tsCryptoData pub;
		// size_t keySize;

		// keySize = this->KeySize();
		if (TsStriCmp(m_curve->FiefdomName(), "P256") == 0)
		{
			priv.FromHexString("5b7051fff0d3ce5d0204d6f37943a02efa08e0a4a642af7074e9d83417a53b9e");
			pub.FromHexString("04b8ef6632fbd2ef543b76172a004518c84b7820e26a71e3b1f60adee0089ca04f8e85306b8286c2aba784f62b7358bb5bfb438b0260964bca8d529c3cde76d79e");
		}
		else if (TsStriCmp(m_curve->FiefdomName(), "P256K1") == 0)
		{
			priv.FromHexString("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFAEABB739ABD2280EEFF497A3340D9050");
			pub.FromHexString("04A6B594B38FB3E77C6EDF78161FADE2041F4E09FD8497DB776E546C41567FEB3C71444009192228730CD8237A490FEBA2AFE3D27D7CC1136BC97E439D13330D55");
		}
#ifdef SUPPORT_ECC_P192
		else if (TsStriCmp(m_curve->FiefdomName(), "P192") == 0)
		{
			priv.FromHexString("2d9ec4777dfb9574f462ed75d73b42af903737dcbf11e4c2");
			pub.FromHexString("0491d81f1a28781cf36bb36b897928aa69191abd27e18e939e6b998ee85184766a52b95599db97de6473ec3c49ea57681a");
		}
#endif
#ifdef SUPPORT_ECC_P224
		else if (TsStriCmp(m_curve->FiefdomName(), "P224") == 0)
		{
			priv.FromHexString("39ea58076e7ad4dca54b47aa23b624d95a891e7ac6df4eff27423d19");
			pub.FromHexString("0479cc5b4766ae35882c9bc7086f4d52a202dc33fcee3ab41fc136f885de28ed702a493ca93ad1b6848634533a748c07a7a8c76801b58907c9");
		}
#endif
#ifndef CRYPTO_EXPORT
		else if (TsStriCmp(m_curve->FiefdomName(), "P384") == 0)
		{
			priv.FromHexString("0fc41b0054443796e70e5d70e478305ebc2ae4330b37b3ef0b63e45c0605b4c4bc5b4bd70c694b0aa6cf9023a6e8eedf");
			pub.FromHexString("0428bb8e61aa113b1bc2431e67252bf291716b6fab918b1843076fa579ee99967ca3d44d1bf0de65b30e10c41a875cc9cdb527052afd45cb89d0cd56586dd76760793ce582b6e57aa49caacf637c5cbb39d02e6b02f8505c111c61752a4948e40f");
		}
		else if (TsStriCmp(m_curve->FiefdomName(), "P521") == 0)
		{
			priv.FromHexString("000001be08d2795e35e8398f25a4f6c3b3a2a5462523c78c16ddf1ab39b94331d6ee8cf0f84b2f5ad14cdc386ee2e5a1d3ce1a799d3d6f7f84a24f88c716a4b8ba517898");
			pub.FromHexString("040055d5d01c074eb2e6fc5fbf4b95c482596ff7f6830d0826952872d363acadad06daf282394e4025058baf514e1e0f6cdad4175570bb9ec0e94319e8c6c0c84cee86 013f8daaeb4bdccff9df8135ee1431d3d434a0e4c65f0768bedc40203076c33f28e2177565d47d02788112fc8e695e97012e694bd2c269aab0f41b726f2f61b83c87");
		}
#endif
		else
		{
			gFipsState.testFailed();
			return false;
		}
		if (!set_Point(pub) || !set_PrivateValue(priv) || !ValidateKeys())
		{
			gFipsState.testFailed();
			return false;
		}
		return true;
	}

	return true;
}
#endif // 0
