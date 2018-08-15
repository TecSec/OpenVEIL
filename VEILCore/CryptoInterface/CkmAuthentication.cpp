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
#include "CryptoAsn1.h"

using namespace tscrypto;


class CkmAuthenticationImpl : public AuthenticationResponder, public AuthenticationInitiator, public TSName, public Selftest, public tscrypto::ICryptoObject, 
	public tscrypto::IInitializableObject, public AlgorithmInfo
{
public:
	CkmAuthenticationImpl(const tsCryptoStringBase& algorithm)
	{
		SetName(algorithm);
	}
	virtual ~CkmAuthenticationImpl(void)
	{
	}

	// Selftests
	virtual bool runTests(bool runDetailedTests) override
	{
		UNREFERENCED_PARAMETER(runDetailedTests);
		if (!gFipsState.operational())
			return false;

		// TODO:  Need tests here

		return true;
	}

	// AlgorithmInfo
	virtual tsCryptoString  AlgorithmName() const override
	{
		return GetName();
	}
	virtual tsCryptoString  AlgorithmOID() const override
	{
		return LookUpAlgOID(GetName());
	}
	virtual TS_ALG_ID AlgorithmID() const override
	{
		return LookUpAlgID(GetName());
	}

	// AuthenticationResponder
	virtual bool computeResponderValues(const tsCryptoData& responderParameters, const tsCryptoData& storedKey, authenticationResponderKeyHandler* keyAccess, 
		tsCryptoData& responderMITMProof, tsCryptoData& sessionKey) override
	{
		const TSICkmAuth *resp = TSLookup(TSICkmAuth, "CKMAUTH");
		SmartCryptoWorkspace workspace;
		uint32_t mitmLen;
		uint32_t sessionKeyLen;

		if (resp == nullptr || keyAccess == nullptr)
			return false;

		workspace = resp->def;

		if (!resp->configure(workspace, keyAccess, (keyAccess->keyServer() ? &getKey : nullptr),
			(keyAccess->keyServer() ? nullptr : &computeZ), hashName.c_str(), macName.c_str(), translateKeyWrapName().c_str(), "KDF", macName.c_str(), _usesMITM))
		{
			return false;
		}

		if (!resp->computeResponderValues(workspace, responderParameters.c_str(), (uint32_t)responderParameters.size(), storedKey.c_str(), (uint32_t)storedKey.size(), 
			nullptr, &mitmLen, nullptr, &sessionKeyLen))
		{
			responderMITMProof.clear();
			sessionKey.clear();
			return false;
		}
		responderMITMProof.resize(mitmLen);
		sessionKey.resize(sessionKeyLen);
		if (!resp->computeResponderValues(workspace, responderParameters.c_str(), (uint32_t)responderParameters.size(), storedKey.c_str(), (uint32_t)storedKey.size(), 
			responderMITMProof.rawData(), &mitmLen, sessionKey.rawData(), &sessionKeyLen))
		{
			responderMITMProof.clear();
			sessionKey.clear();
			return false;
		}
		responderMITMProof.resize(mitmLen);
		sessionKey.resize(sessionKeyLen);
		return true;
	}

	// AuthenticationInitiator
	virtual bool computeInitiatorValues(const tsCryptoData& initiatorParameters, const tsCryptoData& authenticationInformation, tsCryptoData& responderParameters, 
		tsCryptoData& responderMITMProof, tsCryptoData& sessionKey) override
	{
		const TSICkmAuth* init = TSLookup(TSICkmAuth, "CKMAUTH");
		const TSIEcc* pkDesc = nullptr;
		SmartCryptoWorkspace workspace;
		SmartCryptoWorkspace respKeyPair;
		uint32_t responderParamLen;
		uint32_t mitmLen;
		uint32_t sessionKeyLen;
		TSCkmAuthInitiatorParameters initParams;

		if (init == nullptr)
			return false;

		workspace = init->def;

        memset(&initParams, 0, sizeof(initParams));
        if (!tsDecodeCkmAuthInitiatorParameters(initiatorParameters.data(), (uint32_t)initiatorParameters.size(), &initParams, nullptr, nullptr) ||
			!init->configure(workspace, nullptr, &getKey, nullptr, hashName.c_str(), macName.c_str(), translateKeyWrapName().c_str(), "KDF", macName.c_str(), _usesMITM))
		{
            tsFreeCkmAuthInitiatorParameters(&initParams, nullptr, nullptr);
			return false;
		}

		pkDesc = findResponderDescriptor(initParams);
		if (pkDesc == nullptr || (respKeyPair = tsCreateWorkspace(pkDesc)) == nullptr ||
			!pkDesc->addPublicPoint(respKeyPair, tsGetBufferDataPtr(initParams.responderPublicKey), tsBufferUsed(initParams.responderPublicKey)))
		{
            tsFreeCkmAuthInitiatorParameters(&initParams, nullptr, nullptr);
			return false;
		}

		if (!init->setInitiatorParameters_PBKDF(workspace, respKeyPair, tsGetBufferDataPtr(initParams.oidInfo), tsBufferUsed(initParams.oidInfo), 
			tsGetBufferDataPtr(initParams.nonce), tsBufferUsed(initParams.nonce), tsGetBufferDataPtr(initParams.authParameters.pbkdf.salt), tsBufferUsed(initParams.authParameters.pbkdf.salt), 
            initParams.keySizeInBits, initParams.authParameters.pbkdf.iterationCount, ts_false, "PBKDF", macName.c_str()))
		{
            tsFreeCkmAuthInitiatorParameters(&initParams, nullptr, nullptr);
			return false;
		}
        tsFreeCkmAuthInitiatorParameters(&initParams, nullptr, nullptr);

		if (!init->computeInitiatorValues(workspace, authenticationInformation.c_str(), (uint32_t)authenticationInformation.size(), nullptr, &responderParamLen, nullptr, &mitmLen,
			nullptr, &sessionKeyLen))
		{
			responderParameters.clear();
			responderMITMProof.clear();
			sessionKey.clear();
			return false;
		}
		responderParameters.resize(responderParamLen);
		responderMITMProof.resize(mitmLen);
		sessionKey.resize(sessionKeyLen);
		if (!init->computeInitiatorValues(workspace, authenticationInformation.c_str(), (uint32_t)authenticationInformation.size(), responderParameters.rawData(), 
			&responderParamLen, responderMITMProof.rawData(), &mitmLen, sessionKey.rawData(), &sessionKeyLen))
		{
			responderParameters.clear();
			responderMITMProof.clear();
			sessionKey.clear();
			return false;
		}
		responderParameters.resize(responderParamLen);
		responderMITMProof.resize(mitmLen);
		sessionKey.resize(sessionKeyLen);
		return true;
	}
	virtual bool testInitiatorValues(const tsCryptoData& initiatorParameters, const tsCryptoData& authenticationInformation, const tsCryptoData& KGK, const tsCryptoData& ephPriv, 
		const tsCryptoData& ephPub, const tsCryptoData& responderParameters, const tsCryptoData& responderMITMProof, const tsCryptoData& sessionKey) override
	{
		const TSICkmAuth* init = TSLookup(TSICkmAuth, "CKMAUTH");
		const TSIEcc* pkDesc = nullptr;
		SmartCryptoWorkspace workspace;
		SmartCryptoWorkspace respKeyPair;
		SmartCryptoWorkspace ephKeyPair;
		TSCkmAuthInitiatorParameters initParams;
		TSCkmAuthResponderParameters respParams;

        memset(&initParams, 0, sizeof(initParams));
        memset(&respParams, 0, sizeof(respParams));
		if (init == nullptr)
			return false;

		workspace = init->def;

        if (!tsDecodeCkmAuthInitiatorParameters(initiatorParameters.data(), (uint32_t)initiatorParameters.size(), &initParams, nullptr, nullptr) ||
            !tsDecodeCkmAuthResponderParameters(responderParameters.data(), (uint32_t)responderParameters.size(), &respParams, nullptr, nullptr) ||
			!init->configure(workspace, nullptr, &getKey, nullptr, hashName.c_str(), macName.c_str(), translateKeyWrapName().c_str(), "KDF", macName.c_str(), _usesMITM))
		{
            tsFreeCkmAuthInitiatorParameters(&initParams, nullptr, nullptr);
            tsFreeCkmAuthResponderParameters(&respParams, nullptr, nullptr);
			return false;
		}

		pkDesc = findResponderDescriptor(initParams);
		if (pkDesc == nullptr || (respKeyPair = tsCreateWorkspace(pkDesc)) == nullptr || (ephKeyPair = tsCreateWorkspace(pkDesc)) == nullptr ||
			!pkDesc->addPublicPoint(respKeyPair, tsGetBufferDataPtr(initParams.responderPublicKey), tsBufferUsed(initParams.responderPublicKey)) ||
			!pkDesc->addPublicPoint(ephKeyPair, ephPub.c_str(), (uint32_t)ephPub.size()) ||
			!pkDesc->addPrivateKey(ephKeyPair, ephPriv.c_str(), (uint32_t)ephPriv.size())
			)
		{
            tsFreeCkmAuthInitiatorParameters(&initParams, nullptr, nullptr);
            tsFreeCkmAuthResponderParameters(&respParams, nullptr, nullptr);
			return false;
		}

		TSPbkdfParameters& pbParams = initParams.authParameters.pbkdf;

		if (!init->setInitiatorParameters_PBKDF(workspace, respKeyPair, tsGetBufferDataPtr(initParams.oidInfo), tsBufferUsed(initParams.oidInfo),
			tsGetBufferDataPtr(initParams.nonce), tsBufferUsed(initParams.nonce), tsGetBufferDataPtr(pbParams.salt), tsBufferUsed(pbParams.salt), initParams.keySizeInBits,
			pbParams.iterationCount, ts_false, "PBKDF", macName.c_str()))
		{
            tsFreeCkmAuthInitiatorParameters(&initParams, nullptr, nullptr);
            tsFreeCkmAuthResponderParameters(&respParams, nullptr, nullptr);
			return false;
		}

		if (!init->testInitiatorValues(workspace, authenticationInformation.c_str(), (uint32_t)authenticationInformation.size(), KGK.c_str(), (uint32_t)KGK.size(),
			ephKeyPair, tsGetBufferDataPtr(respParams.eKGK), tsBufferUsed(respParams.eKGK), tsGetBufferDataPtr(respParams.initiatorAuthProof), tsBufferUsed(respParams.initiatorAuthProof),
			tsGetBufferDataPtr(respParams.initiatorMITMProof), tsBufferUsed(respParams.initiatorMITMProof), responderMITMProof.c_str(), (uint32_t)responderMITMProof.size(), 
			sessionKey.c_str(), (uint32_t)sessionKey.size()))
		{
            tsFreeCkmAuthInitiatorParameters(&initParams, nullptr, nullptr);
            tsFreeCkmAuthResponderParameters(&respParams, nullptr, nullptr);
			return false;
		}
        tsFreeCkmAuthInitiatorParameters(&initParams, nullptr, nullptr);
        tsFreeCkmAuthResponderParameters(&respParams, nullptr, nullptr);
		return true;
	}

	// tscrypto::IInitializableObject
	virtual bool InitializeWithFullName(const tscrypto::tsCryptoStringBase& fullName) override
	{
		SetName(fullName);

		tsCryptoStringList parts = tsCryptoString(fullName).split(";");

		if (parts->size() < 2)
			parts->push_back("SHA512");
		if (parts->size() < 3)
			parts->push_back("HMAC-SHA512");
		if (parts->size() < 4)
			parts->push_back("KEYWRAP-RFC3394");
		if (parts->size() < 5)
			parts->push_back("MITM");

		hashName = parts->at(1);
		macName = parts->at(2);
		keyTransportName = parts->at(3);
		_usesMITM = tsStriCmp(parts->at(4).c_str(), "NO-MITM") != 0;
		return true;
	}
private:
	tsCryptoString hashName;
	tsCryptoString macName;
	tsCryptoString keyTransportName;
	bool _usesMITM;

	tsCryptoString translateKeyWrapName()
	{
		tsCryptoString tmp = keyTransportName;
		tsCryptoString tmp1 = OIDtoAlgName(tmp);
		
		if (!tmp1.empty())
			tmp = tmp1;

		tmp.ToUpper();
		tmp.Replace("KEYWRAP", "KW").Replace("RFC3394", "");
		if (tmp.size() == 3)
			tmp.append("AES");
		return tmp;
	}
	static ts_bool getKey(void* keyParams, const uint8_t* keyId, uint32_t keyIdLen, TSWORKSPACE* keyPair)
	{
		authenticationResponderKeyHandler* keyAccess = (authenticationResponderKeyHandler*)keyParams;
		tsCryptoString keyType;
		tsCryptoData id(keyId, keyIdLen);

		if (keyAccess == nullptr || keyPair == nullptr)
			return ts_false;

		keyType = keyAccess->getKeyType(id);

		tsCryptoData data = keyAccess->getKey(id);

		if (data.empty())
		{
			return ts_false;
		}
		*keyPair = TSCreate(TSIEcc, keyType.c_str());
		if (*keyPair == nullptr)
		{
			return ts_false;
		}
        return tsSetCryptoKeyValues(*keyPair, NULL, 0, data.c_str(), (uint32_t)data.size());
	}
	static ts_bool computeZ(void* keyParams, const uint8_t* keyId, uint32_t keyIdLen, const uint8_t* ephemPublic, uint32_t ephemPublicLen, uint8_t *secret, uint32_t* secretLen)
	{
		authenticationResponderKeyHandler* keyAccess = (authenticationResponderKeyHandler*)keyParams;
		tsCryptoData id(keyId, keyIdLen);

		if (keyAccess == nullptr || secretLen == nullptr)
			return ts_false;

		tsCryptoData data = keyAccess->computeZ(id, tsCryptoData(ephemPublic, ephemPublicLen));

		if (data.empty())
			return ts_false;

		if (secret == nullptr)
		{
			*secretLen = (uint32_t)data.size();
			return ts_true;
		}
		if (*secretLen < (uint32_t)data.size())
		{
			*secretLen = (uint32_t)data.size();
			return ts_false;
		}
		*secretLen = (uint32_t)data.size();
		memcpy(secret, data.c_str(), data.size());
		return ts_true;
	}
	const TSIEcc* findResponderDescriptor(const TSCkmAuthInitiatorParameters& params)
	{
		const TSIEcc* desc = nullptr;
		tsCryptoString tmp;

		if (params.responderPublicKeyOIDExists)
		{
			tmp = OIDtoAlgName(tsCryptoData(params.responderPublicKeyOID).ToOIDString());
		}
		else
		{
			if (tsBufferUsed(params.responderPublicKey) > 1 && tsGetBufferDataPtr(params.responderPublicKey)[0] == 4)
			{
				switch (tsBufferUsed(params.responderPublicKey))
				{
#ifdef SUPPORT_ECC_P192
				case 49: // p192
					tmp = "ECC-P192";
					break;
#endif
#ifdef SUPPORT_ECC_P224
				case 57: // p224
					tmp = "ECC-P224";
					break;
#endif
				case 65: // p256
					tmp = "ECC-P256";
					break;
				case 97: // p384
					tmp = "ECC-P384";
					break;
				case 133: // p521
					tmp = "ECC-P521";
					break;
				default:
					return nullptr;
				}
			}
			else
			{
				return nullptr;
			}
		}
		if (tmp == "KEY-SECP256R1")
			tmp = "KEY-P256";
		else if (tmp == "KEY-SECP384R1")
			tmp = "KEY-P384";
		else if (tmp == "KEY-SECP521R1")
			tmp = "KEY-P521";
		else if (tmp == "KEY=SECP25K1")
			tmp = "KEY-P256K1";
		tmp.Replace("KEY-", "ECC-");
		return TSLookup(TSIEcc, tmp.c_str());
	}
};

tscrypto::ICryptoObject* CreateCkmAuthentication(const tsCryptoStringBase& algorithm)
{
	return dynamic_cast<tscrypto::ICryptoObject*>(new CkmAuthenticationImpl(algorithm));
}


