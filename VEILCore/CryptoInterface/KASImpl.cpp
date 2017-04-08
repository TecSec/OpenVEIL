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

class KASImpl : public KAS, public TSName, public tscrypto::ICryptoObject, public tscrypto::IInitializableObject, public AlgorithmInfo
{
public:
    KASImpl() : desc(nullptr), kdfDesc(nullptr), macDesc(nullptr)
	{
		desc = findDHKeyAgreementAlgorithm("KAS");
		if (desc)
			workspace.resize(desc->getWorkspaceSize(desc));
		kdfDesc = findKdfAlgorithm("KDF");
		if (kdfDesc != nullptr)
			kdfWorkspace.resize(kdfDesc->getWorkspaceSize(kdfDesc));

		SetName("KAS");
	}
    virtual ~KASImpl(void)
	{
		clear();
		if (kdfDesc != nullptr && !kdfWorkspace.empty())
		{
			kdfDesc->finish(kdfDesc, kdfWorkspace.rawData());
			kdfWorkspace.clear();
		}
		if (desc != nullptr && !workspace.empty())
		{
			desc->finish(desc, workspace.rawData());
			workspace.clear();
		}
		if (kdfMacDesc != nullptr && !kdfMacWorkspace.empty())
		{
			uint8_t tmp[64];

			kdfMacDesc->finish(kdfMacDesc, kdfMacWorkspace.rawData(), tmp, kdfMacDesc->getDigestSize(kdfMacDesc));
			kdfMacWorkspace.clear();
		}
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


    // KAS
    virtual void clear() override
	{
		finish();
	}
	virtual tsCryptoString get_KdfName() const override
	{
		if (kdfDesc == nullptr || kdfMacDesc == nullptr)
			return "";

		return kdfDesc->name + tsCryptoString("-") + kdfMacDesc->name;
	}
	virtual bool set_KdfName(const tsCryptoStringBase& name) override
	{
		tsCryptoString Name(name);
		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;

		if (kdfMacDesc != nullptr && !kdfMacWorkspace.empty())
		{
			uint8_t tmp[64];

			kdfMacDesc->finish(kdfMacDesc, kdfMacWorkspace.rawData(), tmp, kdfMacDesc->getDigestSize(kdfMacDesc));
		}
		kdfMacWorkspace.clear();

		if (TsStrniCmp(Name, "KDF-", 4) == 0)
			Name.erase(0, 4);

		kdfMacDesc = findMacAlgorithm(Name.c_str());
		if (kdfMacDesc == nullptr)
			return false;
		kdfMacWorkspace.resize(kdfMacDesc->getWorkspaceSize(kdfMacDesc));
		if (!kdfDesc->configure(kdfDesc, kdfWorkspace.rawData(), kdfMacDesc, kdfMacWorkspace.rawData()))
			return false;
		return true;
	}
    virtual tsCryptoData get_IDu() const override
	{
		if (desc == nullptr || workspace.empty())
			return tsCryptoData();

		uint32_t len;
		tsCryptoData tmp;

		if (!desc->getIDu(desc, workspace.rawData(), NULL, &len))
			return tsCryptoData();
		tmp.resize(len);
		if (!desc->getIDu(desc, workspace.rawData(), tmp.rawData(), &len))
			return tsCryptoData();
		tmp.resize(len);
		return tmp;
	}
	virtual bool set_IDu(const tsCryptoData &data) override
	{
		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;
		return desc->setIDu(desc, workspace.rawData(), data.c_str(), (uint32_t)data.size());
	}
	virtual tsCryptoData get_IDv() const override
	{
		if (desc == nullptr || workspace.empty())
			return tsCryptoData();

		uint32_t len;
		tsCryptoData tmp;

		if (!desc->getIDv(desc, workspace.rawData(), NULL, &len))
			return tsCryptoData();
		tmp.resize(len);
		if (!desc->getIDv(desc, workspace.rawData(), tmp.rawData(), &len))
			return tsCryptoData();
		tmp.resize(len);
		return tmp;
	}
	virtual bool set_IDv(const tsCryptoData &data) override
	{
		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;
		return desc->setIDv(desc, workspace.rawData(), data.c_str(), (uint32_t)data.size());
	}
	virtual size_t get_KcKeyLengthInBits() const override
	{
		if (desc == nullptr || workspace.empty())
			return 0;

		return desc->getKcKeyLengthInBits(desc, workspace.rawData());
	}
	virtual bool set_KcKeyLengthInBits(size_t setTo) override
	{
		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;
		return desc->setKcKeyLengthInBits(desc, workspace.rawData(), (uint32_t)setTo);
	}
	virtual tsCryptoString get_KcAlgorithmName() const override
	{
		if (macDesc == nullptr || macWorkspace.empty())
			return "";
		return macDesc->name;
	}
	virtual bool set_KcAlgorithmName(const tsCryptoStringBase& name) override
	{
		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;
		if (macDesc != nullptr && !macWorkspace.empty())
		{
			uint8_t tmp[64];
			macDesc->finish(macDesc, macWorkspace.rawData(), tmp, macDesc->getDigestSize(macDesc));
			macWorkspace.clear();
		}
		macDesc = findMacAlgorithm(name.c_str());
		if (macDesc == nullptr)
			return false;
		macWorkspace.resize(macDesc->getWorkspaceSize(macDesc));
		if (!desc->configure(desc, workspace.rawData(), kdfDesc, kdfWorkspace.rawData(), macDesc, macWorkspace.rawData()))
			return false;
		return true;
	}
	virtual tsCryptoData get_KcSuffixU() const override
	{
		if (desc == nullptr || workspace.empty())
			return tsCryptoData();

		uint32_t len;
		tsCryptoData tmp;

		if (!desc->getKcSuffixU(desc, workspace.rawData(), NULL, &len))
			return tsCryptoData();
		tmp.resize(len);
		if (!desc->getKcSuffixU(desc, workspace.rawData(), tmp.rawData(), &len))
			return tsCryptoData();
		tmp.resize(len);
		return tmp;
	}
	virtual bool set_KcSuffixU(const tsCryptoData &data) override
	{
		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;
		return desc->setKcSuffixU(desc, workspace.rawData(), data.c_str(), (uint32_t)data.size());
	}
	virtual tsCryptoData get_KcSuffixV() const override
	{
		if (desc == nullptr || workspace.empty())
			return tsCryptoData();

		uint32_t len;
		tsCryptoData tmp;

		if (!desc->getKcSuffixV(desc, workspace.rawData(), NULL, &len))
			return tsCryptoData();
		tmp.resize(len);
		if (!desc->getKcSuffixV(desc, workspace.rawData(), tmp.rawData(), &len))
			return tsCryptoData();
		tmp.resize(len);
		return tmp;
	}
	virtual bool set_KcSuffixV(const tsCryptoData &data) override
	{
		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;
		return desc->setKcSuffixV(desc, workspace.rawData(), data.c_str(), (uint32_t)data.size());
	}
	virtual size_t get_KcLengthInBits() const override
	{
		if (desc == nullptr || workspace.empty())
			return 0;

		return desc->getKcLengthInBits(desc, workspace.rawData());
	}
	virtual bool set_KcLengthInBits(size_t setTo) override
	{
		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;
		return desc->setKcLengthInBits(desc, workspace.rawData(), (uint32_t)setTo);
	}
	virtual tsCryptoData get_OtherInfoPrefix() const override
	{
		if (desc == nullptr || workspace.empty())
			return tsCryptoData();

		uint32_t len;
		tsCryptoData tmp;

		if (!desc->getOtherInfoPrefix(desc, workspace.rawData(), NULL, &len))
			return tsCryptoData();
		tmp.resize(len);
		if (!desc->getOtherInfoPrefix(desc, workspace.rawData(), tmp.rawData(), &len))
			return tsCryptoData();
		tmp.resize(len);
		return tmp;
	}
	virtual bool set_OtherInfoPrefix(const tsCryptoData &data) override
	{
		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;
		return desc->setOtherInfoPrefix(desc, workspace.rawData(), data.c_str(), (uint32_t)data.size());
	}
	virtual tsCryptoData get_OtherInfoSuffix() const override
	{
		if (desc == nullptr || workspace.empty())
			return tsCryptoData();

		uint32_t len;
		tsCryptoData tmp;

		if (!desc->getOtherInfoSuffix(desc, workspace.rawData(), NULL, &len))
			return tsCryptoData();
		tmp.resize(len);
		if (!desc->getOtherInfoSuffix(desc, workspace.rawData(), tmp.rawData(), &len))
			return tsCryptoData();
		tmp.resize(len);
		return tmp;
	}
	virtual bool set_OtherInfoSuffix(const tsCryptoData &data) override
	{
		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;
		return desc->setOtherInfoSuffix(desc, workspace.rawData(), data.c_str(), (uint32_t)data.size());
	}
	virtual tsCryptoData get_CCMNonce() const override
	{
		if (desc == nullptr || workspace.empty())
			return tsCryptoData();

		uint32_t len;
		tsCryptoData tmp;

		if (!desc->getCCMNonce(desc, workspace.rawData(), NULL, &len))
			return tsCryptoData();
		tmp.resize(len);
		if (!desc->getCCMNonce(desc, workspace.rawData(), tmp.rawData(), &len))
			return tsCryptoData();
		tmp.resize(len);
		return tmp;
	}
	virtual bool set_CCMNonce(const tsCryptoData &data) override
	{
		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;
		return desc->setCCMNonce(desc, workspace.rawData(), data.c_str(), (uint32_t)data.size());
	}
	virtual bool computeCCMNonce(size_t nonceBitLength, tsCryptoData &nonce) override
	{
		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;
		tsCryptoData tmp;

		tmp.resize((nonceBitLength + 7) / 8);
		if (!internalGenerateRandomBits(tmp.rawData(), (uint32_t)nonceBitLength, true, (uint8_t*)"KAS Nonce", 9))
			return false;

		if (!desc->setCCMNonce(desc, workspace.rawData(), tmp.c_str(), (uint32_t)tmp.size()))
			return false;
		return true;
	}
	virtual size_t get_CCMTagLengthInBytes() const override
	{
		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;
		return desc->getCCMTagLengthInBytes(desc, workspace.rawData());
	}
	virtual bool set_CCMTagLengthInBytes(size_t setTo) override
	{
		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;
		if (setTo < 4 || setTo > 16 || (setTo & 1) != 0)
			return false;
		return desc->setCCMTagLengthInBytes(desc, workspace.rawData(), (uint32_t)setTo);
	}
	virtual tsCryptoData get_NonceU() const override
	{
		if (desc == nullptr || workspace.empty())
			return tsCryptoData();

		uint32_t len;
		tsCryptoData tmp;

		if (!desc->getNonceU(desc, workspace.rawData(), NULL, &len))
			return tsCryptoData();
		tmp.resize(len);
		if (!desc->getNonceU(desc, workspace.rawData(), tmp.rawData(), &len))
			return tsCryptoData();
		tmp.resize(len);
		return tmp;
	}
	virtual bool set_NonceU(const tsCryptoData &data) override
	{
		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;
		return desc->setNonceU(desc, workspace.rawData(), data.c_str(), (uint32_t)data.size());
	}
	virtual bool computeNonceU(size_t nonceBitLength, tsCryptoData &nonce) override
	{
		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;
		tsCryptoData tmp;

		tmp.resize((nonceBitLength + 7) / 8);
		if (!internalGenerateRandomBits(tmp.rawData(), (uint32_t)nonceBitLength, true, (uint8_t*)"KAS Nonce", 9))
			return false;

		if (!desc->setNonceU(desc, workspace.rawData(), tmp.c_str(), (uint32_t)tmp.size()))
			return false;
		return true;
	}
	virtual tsCryptoData get_NonceV() const override
	{
		if (desc == nullptr || workspace.empty())
			return tsCryptoData();

		uint32_t len;
		tsCryptoData tmp;

		if (!desc->getNonceV(desc, workspace.rawData(), NULL, &len))
			return tsCryptoData();
		tmp.resize(len);
		if (!desc->getNonceV(desc, workspace.rawData(), tmp.rawData(), &len))
			return tsCryptoData();
		tmp.resize(len);
		return tmp;
	}
	virtual bool set_NonceV(const tsCryptoData &data) override
	{
		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;
		return desc->setNonceV(desc, workspace.rawData(), data.c_str(), (uint32_t)data.size());
	}
	virtual bool computeNonceV(size_t nonceBitLength, tsCryptoData &nonce) override
	{
		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;
		tsCryptoData tmp;

		tmp.resize((nonceBitLength + 7) / 8);
		if (!internalGenerateRandomBits(tmp.rawData(), (uint32_t)nonceBitLength, true, (uint8_t*)"KAS Nonce", 9))
			return false;

		if (!desc->setNonceV(desc, workspace.rawData(), tmp.c_str(), (uint32_t)tmp.size()))
			return false;
		return true;
	}
	virtual bool initialize(bool isPartyU, size_t kmLengthInBits, /*IN*/ std::shared_ptr<AsymmetricKey> staticKey, /*INOUT*/ std::shared_ptr<AsymmetricKey> ephemeralKey) override
	{
		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;

		std::shared_ptr<EccKey> eccStatic = std::dynamic_pointer_cast<EccKey>(staticKey);
		std::shared_ptr<EccKey> eccEphemeral = std::dynamic_pointer_cast<EccKey>(ephemeralKey);
		std::shared_ptr<DhKey> dhStatic = std::dynamic_pointer_cast<DhKey>(staticKey);
		std::shared_ptr<DhKey> dhEphemeral = std::dynamic_pointer_cast<DhKey>(ephemeralKey);
		std::shared_ptr<TSALG_Access> accStatic = std::dynamic_pointer_cast<TSALG_Access>(staticKey);
		std::shared_ptr<TSALG_Access> accEphemeral = std::dynamic_pointer_cast<TSALG_Access>(ephemeralKey);
		const void* staticDesc = nullptr;
		void* staticKeyPair = nullptr;
		const void* ephemeralDesc = nullptr;
		void* ephemeralKeyPair = nullptr;

		if (!!accStatic)
		{
			staticDesc = accStatic->Descriptor();
			staticKeyPair = accStatic->getKeyPair();
		}
		if (!!accEphemeral)
		{
			ephemeralDesc = accEphemeral->Descriptor();
			ephemeralKeyPair = accEphemeral->getKeyPair();
		}
		if (staticDesc == nullptr)
			staticDesc = ephemeralDesc;

		if (!!eccStatic || !!eccEphemeral)
		{
			return desc->init_ecc(desc, workspace.rawData(), isPartyU, (uint32_t)kmLengthInBits, (const EccDescriptor*)staticDesc, staticKeyPair, ephemeralKeyPair);
		}
		else if (!!dhStatic || !!dhEphemeral)
		{
			return desc->init_dh(desc, workspace.rawData(), isPartyU, (uint32_t)kmLengthInBits, (const DH_Descriptor*)staticDesc, staticKeyPair, ephemeralKeyPair);
		}
		else
			return false;
	}
	virtual bool finish() override
	{
		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;
		return desc->finish(desc, workspace.rawData());
	}
	virtual bool setKCDirection(bool bilateral, bool unilateralFromMe) override
	{
		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;

		return desc->setKCDirection(desc, workspace.rawData(), bilateral, unilateralFromMe);
	}
	virtual bool computeZ(std::shared_ptr<AsymmetricKey> otherStaticKey, std::shared_ptr<AsymmetricKey> otherEphemeral) override
	{
		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;

		std::shared_ptr<TSALG_Access> accStatic = std::dynamic_pointer_cast<TSALG_Access>(otherStaticKey);
		std::shared_ptr<TSALG_Access> accEphemeral = std::dynamic_pointer_cast<TSALG_Access>(otherEphemeral);
		void* staticKeyPair = nullptr;
		void* ephemeralKeyPair = nullptr;

		if (!!accStatic)
		{
			staticKeyPair = accStatic->getKeyPair();
		}
		if (!!accEphemeral)
		{
			ephemeralKeyPair = accEphemeral->getKeyPair();
		}

		return desc->computeZ(desc, workspace.rawData(), staticKeyPair, ephemeralKeyPair);
	}
	virtual bool computeMac(tsCryptoData &mac) override
	{
		uint32_t len;

		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;

		if (!desc->computeMac(desc, workspace.rawData(), nullptr, &len))
			return false;
		mac.resize(len);
		if (!desc->computeMac(desc, workspace.rawData(), mac.rawData(), &len))
		{
			mac.resize(len);
			return false;
		}
		mac.resize(len);
		return true;
	}
	virtual bool verifyMac(const tsCryptoData &mac) override
	{
		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;

		return desc->verifyMac(desc, workspace.rawData(), mac.c_str(), (uint32_t)mac.size());
	}
	virtual bool retrieveKeyingMaterial(tsCryptoData &keyingMaterial) override
	{
		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;
		uint32_t len;

		keyingMaterial.clear();
		if (!desc->retrieveKeyingMaterial(desc, workspace.rawData(), NULL, &len))
			return false;
		keyingMaterial.resize(len);
		if (!desc->retrieveKeyingMaterial(desc, workspace.rawData(), keyingMaterial.rawData(), &len))
			return false;
		keyingMaterial.resize(len);
		return true;
	}
	virtual bool get_Z(tsCryptoData &data) override
	{
		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;

		uint32_t len;

		data.clear();
		if (!desc->getZ(desc, workspace.rawData(), NULL, &len))
			return false;
		data.resize(len);
		if (!desc->getZ(desc, workspace.rawData(), data.rawData(), &len))
			return false;
		data.resize(len);
		return true;
	}
	virtual bool get_MacData(tsCryptoData &data) override
	{
		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;

		uint32_t len;

		data.clear();
		if (!desc->getMacData(desc, workspace.rawData(), NULL, &len))
			return false;
		data.resize(len);
		if (!desc->getMacData(desc, workspace.rawData(), data.rawData(), &len))
			return false;
		data.resize(len);
		return true;
	}
	virtual bool get_OtherMacData(tsCryptoData &data) override
	{
		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;

		uint32_t len;

		data.clear();
		if (!desc->getOtherMacData(desc, workspace.rawData(), NULL, &len))
			return false;
		data.resize(len);
		if (!desc->getOtherMacData(desc, workspace.rawData(), data.rawData(), &len))
			return false;
		data.resize(len);
		return true;
	}
	virtual bool get_OtherInfo(tsCryptoData &data) override
	{
		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;

		uint32_t len;

		data.clear();
		if (!desc->getOtherInfo(desc, workspace.rawData(), NULL, &len))
			return false;
		data.resize(len);
		if (!desc->getOtherInfo(desc, workspace.rawData(), data.rawData(), &len))
			return false;
		data.resize(len);
		return true;
	}
	virtual bool computeZForOtherInfo(const tsCryptoData &otherInfo, std::shared_ptr<AsymmetricKey> otherStaticKey, std::shared_ptr<AsymmetricKey> otherEphemeral) override
	{
		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;

		std::shared_ptr<TSALG_Access> accStatic = std::dynamic_pointer_cast<TSALG_Access>(otherStaticKey);
		std::shared_ptr<TSALG_Access> accEphemeral = std::dynamic_pointer_cast<TSALG_Access>(otherEphemeral);
		void* staticKeyPair = nullptr;
		void* ephemeralKeyPair = nullptr;

		if (!!accStatic)
		{
			staticKeyPair = accStatic->getKeyPair();
		}
		if (!!accEphemeral)
		{
			ephemeralKeyPair = accEphemeral->getKeyPair();
		}

		return desc->computeZForOtherInfo(desc, workspace.rawData(), otherInfo.c_str(), (uint32_t)otherInfo.size(), staticKeyPair, ephemeralKeyPair);
	}
	virtual bool get_DKM(tsCryptoData &data) override
	{
		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;

		uint32_t len;

		data.clear();
		if (!desc->getDKM(desc, workspace.rawData(), NULL, &len))
			return false;
		data.resize(len);
		if (!desc->getDKM(desc, workspace.rawData(), data.rawData(), &len))
			return false;
		data.resize(len);
		return true;
	}
	virtual bool computeMacForData(const tsCryptoData &data, tsCryptoData &mac) override
	{
		if (!gFipsState.operational() || desc == nullptr || workspace.empty())
			return false;

		uint32_t len;

		mac.clear();
		if (!desc->computeMacForData(desc, workspace.rawData(), data.c_str(), (uint32_t)data.size(), NULL, &len))
			return false;
		mac.resize(len);
		if (!desc->computeMacForData(desc, workspace.rawData(), data.c_str(), (uint32_t)data.size(), mac.rawData(), &len))
			return false;
		mac.resize(len);
		return true;
	}

	// tscrypto::IInitializableObject
	virtual bool InitializeWithFullName(const tscrypto::tsCryptoStringBase& fullName) override
	{
		tsCryptoString algorithm(fullName);

		SetName(algorithm);
		return true;
	}

private:
	const DHKeyAgreement_Descriptor* desc;
	mutable tsCryptoData workspace;
	const KDF_Descriptor* kdfDesc;
	tsCryptoData kdfWorkspace;
	const MAC_Descriptor* kdfMacDesc;
	tsCryptoData kdfMacWorkspace;
	const MAC_Descriptor* macDesc;
	tsCryptoData macWorkspace;


 //   tsCryptoString m_kdfName;
 //   tsCryptoData m_IDu;
 //   tsCryptoData m_IDv;
 //   size_t m_macKeyLengthInBits;
 //   size_t m_macLengthInBits;
 //   tsCryptoString m_MACAlgorithmName;
 //   tsCryptoData m_KcSuffixU;
 //   tsCryptoData m_KcSuffixV;
 //   tsCryptoData m_OtherInfoPrefix;
 //   tsCryptoData m_OtherInfoSuffix;
 //   tsCryptoData m_NonceU;
 //   tsCryptoData m_NonceV;

 //   bool m_isPartyU;
 //   size_t m_kmLengthInBits;
	//std::shared_ptr<AsymmetricKey> m_myStaticKey;
	//std::shared_ptr<AsymmetricKey> m_myEphemeralKey;
	//std::shared_ptr<AsymmetricKey> m_ephemU;
	//std::shared_ptr<AsymmetricKey> m_ephemV;
	//std::shared_ptr<KeyDerivationFunction> m_kdf;
	//std::shared_ptr<MessageAuthenticationCode> m_mac;
 //   tsCryptoData m_generatedKey;
 //   tsCryptoData m_macKey;
 //   bool m_bilateral;
 //   bool m_unilateralFromMe;
 //   tsCryptoData m_Z;
 //   size_t m_eCount;
 //   size_t m_sCount;
 //   tsCryptoData m_ccmNonce;
 //   size_t m_ccmTagLen;
};

tscrypto::ICryptoObject* CreateKAS()
{
	return dynamic_cast<tscrypto::ICryptoObject*>(new KASImpl);
}
