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

class ServerAuthenticationCalculatorPbkdfImpl : public ServerAuthenticationCalculator, public TSName, public Selftest, public tscrypto::ICryptoObject, public tscrypto::IInitializableObject, public AlgorithmInfo
{
public:
    ServerAuthenticationCalculatorPbkdfImpl(const tsCryptoStringBase& algorithm)
    {
        calc = TSLookup(TSICkmAuthCalc, "CKMAUTH-CALC");
        macName = "HMAC-SHA512";
        hashName = "SHA512";
        workspace = calc->def;
        _pbkdfHashAlg = "HMAC-SHA512";
    }
    virtual ~ServerAuthenticationCalculatorPbkdfImpl(void)
    {
    }

    // Selftests
    virtual bool runTests(bool runDetailedTests) override
    {
        UNREFERENCED_PARAMETER(runDetailedTests);
        if (!gFipsState.operational())
            return false;

        // TODO:  Need tests here (hard to do since random seed is generated...)

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

    // ServerAuthenticationCalculator
    virtual bool computeServerAuthenticationParameters(const tsCryptoData& authInfo, tsCryptoData& authenticationParameters, tsCryptoData& storedKey) override
    {
        tsCryptoData seed;
        int iterCount = 4096;
        uint32_t storedKeyLen = 1024, authOutputLen = 1500;

        if (!gFipsState.operational() || calc == nullptr || macName.empty() || _pbkdfHashAlg.empty())
            return false;

        if (tsStriCmp(_pbkdfHashAlg.c_str(), "SHA1") != 0 || tsStriCmp(_pbkdfHashAlg.c_str(), "HMAC-SHA1") != 0)
            iterCount = 1000;

        if (!TSGenerateRandom(seed, 32))
            return false;

        if (!calc->init_pbkdf(workspace, _pbkdfHashAlg.c_str(), iterCount, seed.c_str(), (uint32_t)seed.size()))
        {
            return false;
        }

        storedKey.resize(storedKeyLen);
        authenticationParameters.resize(authOutputLen);
        if (!calc->computeServerAuth(workspace, macName.c_str(), hashName.c_str(), authInfo.c_str(), (uint32_t)authInfo.size(), authenticationParameters.rawData(), &authOutputLen, storedKey.rawData(), &storedKeyLen))
        {
            storedKey.clear();
            authenticationParameters.clear();
            return false;
        }
        storedKey.resize(storedKeyLen);
        authenticationParameters.resize(authOutputLen);
        return true;
    }
    virtual bool validateServerAuthenticationParameters(const tsCryptoData& authInfo, const tsCryptoData& authenticationParameters, const tsCryptoData& storedKey) override
    {
        TSCkmAuthServerParameters params;
        tsCryptoData salt;
        bool retVal;

        if (!gFipsState.operational())
            return false;

        memset(&params, 0, sizeof(params));

        if (!tsDecodeCkmAuthServerParameters(authenticationParameters.data(), (uint32_t)authenticationParameters.size(), &params, nullptr, nullptr))
        {
            tsFreeCkmAuthServerParameters(&params, nullptr, nullptr);
            return false;
        }


        salt = params.pbkdf.salt;
        retVal = 
            calc->init_pbkdf(workspace, _pbkdfHashAlg.c_str(), params.pbkdf.iterationCount, salt.c_str(), (uint32_t)salt.size()) &&
            calc->validateServerAuth(workspace, macName.c_str(), hashName.c_str(), authInfo.c_str(), (uint32_t)authInfo.size(), storedKey.c_str(), (uint32_t)storedKey.size());
        tsFreeCkmAuthServerParameters(&params, nullptr, nullptr);
        return retVal;
    }

    // tscrypto::IInitializableObject
    virtual bool InitializeWithFullName(const tscrypto::tsCryptoStringBase& fullName) override
    {
        tsCryptoString algorithm(fullName);
        tsCryptoString tmp(algorithm);

        SetName(algorithm);

        while (tmp.size() > 0 && tmp[0] != '-')
            tmp.DeleteAt(0, 1);
        if (tmp[0] == '-')
            tmp.DeleteAt(0, 1);

        if (tsStrniCmp(tmp.c_str(), "PBKDF2-", 7) != 0)
            return false;
        tmp.DeleteAt(0, 7);
        this->_pbkdfHashAlg = "HMAC-" + tmp;

        hashName = tmp;
        macName = "HMAC-" + tmp;
        return true;
    }

private:
    const TSICkmAuthCalc *calc;
    tsCryptoString macName;
    tsCryptoString hashName;
    SmartCryptoWorkspace workspace;
    tsCryptoString _pbkdfHashAlg;
};


// Uses SHA512 for the KDFs.  Uses the indicated PBKDF sha for the PBKDF
tscrypto::ICryptoObject* CreateServerAuthenticationCalculator(const tsCryptoStringBase& algorithm)
{
    return dynamic_cast<tscrypto::ICryptoObject*>(new ServerAuthenticationCalculatorPbkdfImpl(algorithm));
}


