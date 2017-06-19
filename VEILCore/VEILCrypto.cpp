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
#ifdef _WIN32
#include "shlwapi.h"
#include "shlobj.h"
#endif // _WIN32
#include "CryptoAsn1.h"

#ifndef MIN
#   define MIN(a,b) ((a)<(b)?(a):(b))
#endif // MIN

using namespace tscrypto;
using namespace tscrypto::_TS_ALG_ID;
using namespace tscrypto::_CryptoAlgType;
//using namespace BigNum;


bool tscrypto::gPersistAnyfieldAsObject = true; //  Supported as of Crypto 7.0.1 and VEIL 7.0.34

static bool Check_CPU_support_AES();
static bool Check_CPU_support_SSE();
static bool Check_CPU_support_SSE2();

static bool loadCryptoModules();


static std::shared_ptr<tscrypto::ICryptoLocator> g_CryptoLocator;
static std::shared_ptr<tscrypto::ICryptoLocator> g_CryptoTestLocator;
FipsState tscrypto::gFipsState;
static std::vector<std::function<bool()> > gInitializers;
static std::vector<std::function<bool()> > gInitialInitializers;
static std::deque<std::function<bool()> > gTerminators;
static XP_MODULE hDllModule = XP_MODULE_INVALID;

static std::vector<std::function<bool(TS_ALG_ID AlgID, size_t& pVal)>> gKeySizeFuncs;
static std::vector<std::function<bool(TS_ALG_ID AlgID, SymmetricMode& pVal)>> gModeFuncs;
static std::vector<std::function<bool(TS_ALG_ID AlgID, KeyType& pVal)>> gKeyTypeFuncs;
static std::vector<std::function<bool(TS_ALG_ID AlgID, size_t& pVal)>> gBlockSizeFuncs;
static std::vector<std::function<bool(TS_ALG_ID AlgID, size_t& pVal)>> gIVECSizeFuncs;
static std::vector<std::function<tsCryptoString(TS_ALG_ID signAlgorithm)>> gSignNameFuncs;

typedef struct moduleInfo
{
    moduleInfo(const tsCryptoString& name, XP_MODULE mod) : filename(name), module(mod) {}
    moduleInfo(const moduleInfo& obj) = delete;
    moduleInfo(moduleInfo&& obj) : filename(std::move(obj.filename)), module(obj.module)
    {
        obj.module = XP_MODULE_INVALID;
    }
    moduleInfo& operator=(const moduleInfo& obj) = delete;
    moduleInfo& operator=(moduleInfo&& obj)
    {
        if (this != &obj)
        {
            filename = std::move(obj.filename);
            module = obj.module;
            obj.module = XP_MODULE_INVALID;
        }
        return *this;
    }
    ~moduleInfo() {
        if (module != XP_MODULE_INVALID)
            xp_FreeSharedLib(module);
        module = XP_MODULE_INVALID;
        filename.clear();
    }
    tsCryptoString filename;
    XP_MODULE module;
} moduleInfo;
static std::vector<moduleInfo> moduleList;

// from servicelocator.cpp
//#ifdef _DEBUG
//std::list<std::weak_ptr<tscrypto::ICryptoObject> > gAllocatedObjects;
//TSAutoCriticalSection gAllocatedObjectsListLock;
//#endif


// from EccCurve.cpp
//std::vector<std::shared_ptr<BigNum::EccCurve> > gDomains;

// From this file
bool tscrypto::gCpuSupportsAES = Check_CPU_support_AES();
bool tscrypto::gCpuSupportsSSE = Check_CPU_support_SSE();
bool tscrypto::gCpuSupportsSSE2 = Check_CPU_support_SSE2();


static void RunCryptoInitializers();


extern tscrypto::ICryptoObject* CreateAlgorithmListManager();
extern tscrypto::ICryptoObject* CreateHash();
extern tscrypto::ICryptoObject* CreateMAC();

extern tscrypto::ICryptoObject* CreateSymmetricWithModes();
extern tscrypto::ICryptoObject* CreateAEAD();
extern tscrypto::ICryptoObject* CreatePbkdf();
extern tscrypto::ICryptoObject* CreateKDF();
extern tscrypto::ICryptoObject* CreateKeyWrap();
extern tscrypto::ICryptoObject* CreateProbablePrime();
extern tscrypto::ICryptoObject* CreateProvablePrime();
extern tscrypto::ICryptoObject* CreateDhKey(const tsCryptoStringBase& algorithm);
extern tscrypto::ICryptoObject* CreateDhParameters(const tsCryptoStringBase& algorithm);
extern tscrypto::ICryptoObject* CreateRsaKey();
extern tscrypto::ICryptoObject* CreateRsaOAEP();
extern tscrypto::ICryptoObject* CreateEccKey();
extern tscrypto::ICryptoObject* CreateRsaSigner();
extern tscrypto::ICryptoObject* CreateEccSigner(const tsCryptoStringBase& algorithm);
extern tscrypto::ICryptoObject* CreateServerAuthenticationCalculator(const tsCryptoStringBase& algorithm);
extern tscrypto::ICryptoObject* CreateTunnelInitiator(const tsCryptoStringBase& algorithm);
extern tscrypto::ICryptoObject* CreateCkmAuthentication(const tsCryptoStringBase& algorithm);
extern tscrypto::ICryptoObject* CreateSslHandshake_Client();
extern tscrypto::ICryptoObject* CreateCertificateIssuer();

extern tscrypto::ICryptoObject *CreateXOF();
extern tscrypto::ICryptoObject *CreateSymmetricStream();
extern tscrypto::ICryptoObject *CreateXTS();
extern tscrypto::ICryptoObject *CreateKAS();
extern tscrypto::ICryptoObject *CreateRsaSve(const tsCryptoStringBase &algorithm);
extern tscrypto::ICryptoObject *CreateKtsOaep(const tsCryptoStringBase &algorithm);
extern tscrypto::ICryptoObject *CreateKtsKemKws(const tsCryptoStringBase &algorithm);
extern tscrypto::ICryptoObject *CreateRsaKAS1(const tsCryptoStringBase &algorithm);
extern tscrypto::ICryptoObject *CreateRsaKAS2(const tsCryptoStringBase &algorithm);
extern tscrypto::ICryptoObject *CreateRsaKemKws(const tsCryptoStringBase &algorithm);


std::shared_ptr<tscrypto::ICryptoLocator> tscrypto::CryptoLocator()
{
    if (!g_CryptoLocator)
    {
        //		LOG(FrameworkInfo1, "Initializing the system");
        g_CryptoLocator = tscrypto::CreateCryptoLocator();
        std::shared_ptr<tscrypto::ICryptoLocatorWriter> cryptoWriter = std::dynamic_pointer_cast<tscrypto::ICryptoLocatorWriter>(g_CryptoLocator);
        cryptoWriter->SetAsRoot();
        //
        cryptoWriter->AddSingletonClass("AlgorithmListManager", CreateAlgorithmListManager);

        //if (!tscrypto::InitializeCInterface())
        //{
        //	g_CryptoLocator.reset();
        //	return nullptr;
        //}

        //initializeBaseEccCurves();
		cryptoWriter->AddClass("SHA256", CreateHash);
		cryptoWriter->AddClass("SHA384", CreateHash);
		cryptoWriter->AddClass("SHA512", CreateHash);
		cryptoWriter->AddClass("SHA3-224", CreateHash);
		cryptoWriter->AddClass("SHA3-256", CreateHash);
		cryptoWriter->AddClass("SHA3-384", CreateHash);
		cryptoWriter->AddClass("SHA3-512", CreateHash);
		cryptoWriter->AddClass("HASH", CreateHash);
        cryptoWriter->AddClass("SHA1", CreateHash);
        cryptoWriter->AddClass("SHA224", CreateHash);
        cryptoWriter->AddClass("MD5", CreateHash);
        cryptoWriter->AddClass("RIPEMD160", CreateHash);
        cryptoWriter->AddClass("HMAC", CreateMAC);

		cryptoWriter->AddClass("DES", CreateSymmetricWithModes);
		cryptoWriter->AddClass("TDES", CreateSymmetricWithModes);
        cryptoWriter->AddClass("DES-EDE3", CreateSymmetricWithModes);
        cryptoWriter->AddClass("XTEA", CreateSymmetricWithModes);
        cryptoWriter->AddClass("BLOWFISH", CreateSymmetricWithModes);
        cryptoWriter->AddClass("RC2", CreateSymmetricWithModes);
        cryptoWriter->AddClass("RC4", CreateSymmetricStream);
        cryptoWriter->AddClass("AES", CreateSymmetricWithModes);
        cryptoWriter->AddClass("GCM", CreateAEAD);
        cryptoWriter->AddClass("GCM-AES", CreateAEAD);
        cryptoWriter->AddClass("CCM", CreateAEAD);
        cryptoWriter->AddClass("CCM-AES", CreateAEAD);
        cryptoWriter->AddClass("CMAC", CreateMAC);
        cryptoWriter->AddClass("KDF-PBKDF2", CreatePbkdf);
        cryptoWriter->AddClass("KDF", CreateKDF);

		cryptoWriter->AddClass("KEYWRAP", CreateKeyWrap);
		cryptoWriter->AddClass("KEYWRAP_PAD", CreateKeyWrap);
		cryptoWriter->AddClass("KEYWRAP_INV", CreateKeyWrap);
		cryptoWriter->AddClass("KEYWRAP_PAD_INV", CreateKeyWrap);
		cryptoWriter->AddClass("KW", CreateKeyWrap);
		cryptoWriter->AddClass("KWP", CreateKeyWrap);
		cryptoWriter->AddClass("KW_INV", CreateKeyWrap);
		cryptoWriter->AddClass("KWP_INV", CreateKeyWrap);
		cryptoWriter->AddClass("TKW", CreateKeyWrap);
		cryptoWriter->AddClass("TKW_INV", CreateKeyWrap);

        cryptoWriter->AddClass("PRIME-PROBABLE", CreateProbablePrime);
        cryptoWriter->AddClass("PRIME-PROVABLE", CreateProvablePrime);
        cryptoWriter->AddClass("KEY-DH", []()->tscrypto::ICryptoObject* {return CreateDhKey("KEY-DH"); });
        cryptoWriter->AddClass("KEY-DSA", []()->tscrypto::ICryptoObject* {return CreateDhKey("KEY-DSA"); });
        cryptoWriter->AddClass("PARAMETERSET-DH", []()->tscrypto::ICryptoObject* {return CreateDhParameters("PARAMETERSET-DH"); });

        cryptoWriter->AddClass("KEY-RSA", CreateRsaKey);
        cryptoWriter->AddClass("RSA-OAEP", CreateRsaOAEP);
        cryptoWriter->AddClass("SIGN-RSA", CreateRsaSigner);

        cryptoWriter->AddClass("KEY", CreateEccKey);
		cryptoWriter->AddClass("KEY-P256", CreateEccKey);
		cryptoWriter->AddClass("KEY-P256K1", CreateEccKey);
		cryptoWriter->AddClass("KEY-P384", CreateEccKey);
        cryptoWriter->AddClass("KEY-P521", CreateEccKey);
        cryptoWriter->AddClass("SIGN-ECC", []()->tscrypto::ICryptoObject* {return CreateEccSigner("SIGN-ECC"); });
        cryptoWriter->AddClass("SIGN-ECC-SHA256", []()->tscrypto::ICryptoObject* {return CreateEccSigner("SIGN-ECC-SHA256"); });
        cryptoWriter->AddClass("SIGN-ECC-SHA384", []()->tscrypto::ICryptoObject* {return CreateEccSigner("SIGN-ECC-SHA384"); });
        cryptoWriter->AddClass("SIGN-ECC-SHA512", []()->tscrypto::ICryptoObject* {return CreateEccSigner("SIGN-ECC-SHA512"); });
        cryptoWriter->AddClass("SIGN-ECC-SHA1", []()->tscrypto::ICryptoObject* {return CreateEccSigner("SIGN-ECC-SHA1"); });
        cryptoWriter->AddClass("SIGN-ECC-SHA224", []()->tscrypto::ICryptoObject* {return CreateEccSigner("SIGN-ECC-SHA224"); });
        cryptoWriter->AddClass("SIGN-DSA", []()->tscrypto::ICryptoObject* {return CreateEccSigner("SIGN-DSA"); });
        cryptoWriter->AddClass("SIGN-DSA-SHA1", []()->tscrypto::ICryptoObject* {return CreateEccSigner("SIGN-DSA-SHA1"); });
        cryptoWriter->AddClass("SIGN-DSA-SHA224", []()->tscrypto::ICryptoObject* {return CreateEccSigner("SIGN-DSA-SHA224"); });
        cryptoWriter->AddClass("SIGN-DSA-SHA256", []()->tscrypto::ICryptoObject* {return CreateEccSigner("SIGN-DSA-SHA256"); });
        cryptoWriter->AddClass("SIGN-DSA-SHA384", []()->tscrypto::ICryptoObject* {return CreateEccSigner("SIGN-DSA-SHA384"); });
        cryptoWriter->AddClass("SIGN-DSA-SHA512", []()->tscrypto::ICryptoObject* {return CreateEccSigner("SIGN-DSA-SHA512"); });
		cryptoWriter->AddClass("X25519", CreateEccKey);
		cryptoWriter->AddClass("ED25519", CreateEccKey);
		cryptoWriter->AddClass("ED25519_PH", CreateEccKey);
		cryptoWriter->AddClass("KEY-X25519", CreateEccKey);
		cryptoWriter->AddClass("KEY-ED25519", CreateEccKey);
		cryptoWriter->AddClass("KEY-ED25519_PH", CreateEccKey);

#ifndef MINGW
        cryptoWriter->AddClass("numsp256d1", CreateEccKey);
        cryptoWriter->AddClass("numsp384d1", CreateEccKey);
        cryptoWriter->AddClass("numsp512d1", CreateEccKey);
        cryptoWriter->AddClass("numsp256t1", CreateEccKey);
        cryptoWriter->AddClass("numsp384t1", CreateEccKey);
        cryptoWriter->AddClass("numsp512t1", CreateEccKey);
		cryptoWriter->AddClass("KEY-numsp256d1", CreateEccKey);
		cryptoWriter->AddClass("KEY-numsp384d1", CreateEccKey);
		cryptoWriter->AddClass("KEY-numsp512d1", CreateEccKey);
		cryptoWriter->AddClass("KEY-numsp256t1", CreateEccKey);
		cryptoWriter->AddClass("KEY-numsp384t1", CreateEccKey);
		cryptoWriter->AddClass("KEY-numsp512t1", CreateEccKey);
#endif



        cryptoWriter->AddClass("SHAKE128", CreateXOF);
        cryptoWriter->AddClass("SHAKE256", CreateXOF);
        cryptoWriter->AddClass("POLY1305", CreateMAC);
        cryptoWriter->AddClass("SALSA20", CreateSymmetricStream);
        cryptoWriter->AddClass("XSALSA20", CreateSymmetricStream);
        cryptoWriter->AddClass("SALSA20_POLY1305", CreateAEAD);
        cryptoWriter->AddClass("CHACHA20", CreateSymmetricStream);
        cryptoWriter->AddClass("CHACHA20_IETF", CreateSymmetricStream);
        cryptoWriter->AddClass("CHACHA20_POLY1305", CreateAEAD);
        cryptoWriter->AddClass("CAMELLIA", CreateSymmetricWithModes);
        cryptoWriter->AddClass("ARIA", CreateSymmetricWithModes);
        cryptoWriter->AddClass("SEED", CreateSymmetricWithModes);
        cryptoWriter->AddClass("XTS", CreateXTS);
        //cryptoWriter->AddClass("SIGN-ECC-SHA3", []()->tscrypto::ICryptoObject* {return CreateEccSigner("SIGN-ECC-SHA3"); });
        //cryptoWriter->AddClass("SIGN-DSA-SHA3", []()->tscrypto::ICryptoObject* {return CreateEccSigner("SIGN-DSA-SHA3"); });
        cryptoWriter->AddClass("KAS", CreateKAS);

        cryptoWriter->AddClass("RSASVE", []()->tscrypto::ICryptoObject* {return CreateRsaSve("RSASVE"); });
        cryptoWriter->AddClass("KTS-OAEP", []()->tscrypto::ICryptoObject* {return CreateKtsOaep("KTS-OAEP"); });
        cryptoWriter->AddClass("KTS-KEM-KWS", []()->tscrypto::ICryptoObject* {return CreateKtsKemKws("KTS-KWM-KWS"); });
        cryptoWriter->AddClass("RSAKAS1", []()->tscrypto::ICryptoObject* {return CreateRsaKAS1("RSAKAS1"); });
        cryptoWriter->AddClass("RSAKAS2", []()->tscrypto::ICryptoObject* {return CreateRsaKAS2("RSAKAS2"); });
        cryptoWriter->AddClass("RSA-KEM-KWS", []()->tscrypto::ICryptoObject* {return CreateRsaKemKws("RSA-KEM-KWS"); });


        //cryptoWriter->AddClass("PROTOCOL_SSL_SERVER", CreateSslHandshake_Server);
        cryptoWriter->AddClass("PROTOCOL_SSL_CLIENT", CreateSslHandshake_Client);
        cryptoWriter->AddClass("CKMAUTH_CALCULATOR-PBKDF2-SHA3", []()->tscrypto::ICryptoObject* {return CreateServerAuthenticationCalculator("CKMAUTH_CALCULATOR-PBKDF2-SHA3-512"); });
        cryptoWriter->AddClass("CKMAUTH_CALCULATOR-PBKDF2", []()->tscrypto::ICryptoObject* {return CreateServerAuthenticationCalculator("CKMAUTH_CALCULATOR-PBKDF2-SHA512"); });

        cryptoWriter->AddClass("TUNNEL-INITIATOR", []()->tscrypto::ICryptoObject* {return CreateTunnelInitiator("TUNNEL-INITIATOR"); });
        cryptoWriter->AddClass("CKMAUTH", []()->tscrypto::ICryptoObject* {return CreateCkmAuthentication("CKMAUTH"); });
        cryptoWriter->AddClass("CertificateIssuer", CreateCertificateIssuer);


        //		g_CryptoLocator->AddClass("PROTOCOL_SSL_SERVER", CreateSslHandshake_Server);
        //		g_CryptoLocator->AddClass("PROTOCOL_SSL_CLIENT", CreateSslHandshake_Client);
        //
        //		cryptoWriter->AddClass("CKMAUTH_CALCULATOR-PBKDF2", []()->tscrypto::ICryptoObject* {return CreateServerAuthenticationCalculator("CKMAUTH_CALCULATOR-PBKDF2-SHA512"); });
        //		cryptoWriter->AddClass("TUNNEL-INITIATOR", []()->tscrypto::ICryptoObject* {return CreateTunnelInitiator("TUNNEL-INITIATOR"); });
        //		cryptoWriter->AddClass("CKMAUTH", []()->tscrypto::ICryptoObject* {return CreateCkmAuthentication("CKMAUTH"); });
        //
        //
        g_CryptoTestLocator = std::dynamic_pointer_cast<tscrypto::ICryptoLocator>(g_CryptoLocator->newInstance());
        cryptoWriter->AddSingletonObject("CryptoTest", std::dynamic_pointer_cast<tscrypto::ICryptoObject>(g_CryptoTestLocator));
        std::shared_ptr<tscrypto::ICryptoLocatorWriter> cryptoTestWriter = std::dynamic_pointer_cast<tscrypto::ICryptoLocatorWriter>(g_CryptoTestLocator);


        cryptoTestWriter->AddClass("RSA-OAEP", CreateRsaOAEP);
        cryptoTestWriter->AddClass("SIGN-ECC", []()->tscrypto::ICryptoObject* {return CreateEccSigner("SIGN-ECC"); });
        cryptoTestWriter->AddClass("SIGN-DSA", []()->tscrypto::ICryptoObject* {return CreateEccSigner("SIGN-DSA"); });

        cryptoTestWriter->AddClass("TUNNEL-INITIATOR", []()->tscrypto::ICryptoObject* {return CreateTunnelInitiator("TUNNEL-INITIATOR"); });
        cryptoTestWriter->AddClass("CKMAUTH", []()->tscrypto::ICryptoObject* {return CreateCkmAuthentication("CKMAUTH"); });

        cryptoTestWriter->AddClass("RSASVE", []() -> tscrypto::ICryptoObject * { return CreateRsaSve("RSASVE"); });
        cryptoTestWriter->AddClass("KTS-OAEP", []() -> tscrypto::ICryptoObject * { return CreateKtsOaep("KTS-OAEP"); });
        cryptoTestWriter->AddClass("KTS-KEM-KWS", []() -> tscrypto::ICryptoObject * { return CreateKtsKemKws("KTS-KEM-KWS"); });
        cryptoTestWriter->AddClass("RSAKAS1", []() -> tscrypto::ICryptoObject * { return CreateRsaKAS1("RSAKAS1"); });
        cryptoTestWriter->AddClass("RSAKAS2", []() -> tscrypto::ICryptoObject * { return CreateRsaKAS2("RSAKAS2"); });
        cryptoTestWriter->AddClass("RSA-KEM-KWS", []() -> tscrypto::ICryptoObject * { return CreateRsaKemKws("RSA-KEM-KWS"); });

        //		cryptoTestWriter->AddClass("TUNNEL-INITIATOR", []()->tscrypto::ICryptoObject* {return CreateTunnelInitiator("TUNNEL-INITIATOR"); });
        //		cryptoTestWriter->AddClass("CKMAUTH", []()->tscrypto::ICryptoObject* {return CreateCkmAuthentication("CKMAUTH"); });
        //
        //
        tscrypto::AddCryptoTerminationFunction([cryptoWriter, cryptoTestWriter]() ->bool {
            cryptoWriter->DeleteClass("AlgorithmListManager");
            cryptoWriter->DeleteClass("CkmEntropy");
            cryptoWriter->DeleteClass("CryptoTest");
            cryptoWriter->DeleteClass("TlsCipherSuiteProcessor");
            //cryptoWriter->DeleteClass("PROTOCOL_SSL_SERVER");
            cryptoWriter->DeleteClass("CertificateIssuer");

            cryptoWriter->DeleteClass("SHAKE128");
            cryptoWriter->DeleteClass("SHAKE256");
            cryptoWriter->DeleteClass("HASH");
            cryptoWriter->DeleteClass("POLY1305");
            cryptoWriter->DeleteClass("SALSA20");
            cryptoWriter->DeleteClass("XSALSA20");
            cryptoWriter->DeleteClass("SALSA20_POLY1305");
            cryptoWriter->DeleteClass("CHACHA20");
            cryptoWriter->DeleteClass("CHACHA20_POLY1305");
            cryptoWriter->DeleteClass("CAMELLIA");
            cryptoWriter->DeleteClass("CAMELLIA-256");
            cryptoWriter->DeleteClass("CAMELLIA-192");
            cryptoWriter->DeleteClass("CAMELLIA-128");
            cryptoWriter->DeleteClass("CAMELLIA-256-CBC");
            cryptoWriter->DeleteClass("CAMELLIA-256-ECB");
            cryptoWriter->DeleteClass("CAMELLIA-256-CFB8");
            cryptoWriter->DeleteClass("CAMELLIA-256-CFBfull");
            cryptoWriter->DeleteClass("CAMELLIA-256-CTR");
            cryptoWriter->DeleteClass("CAMELLIA-256-OFB");
            cryptoWriter->DeleteClass("CAMELLIA-192-CBC");
            cryptoWriter->DeleteClass("CAMELLIA-192-ECB");
            cryptoWriter->DeleteClass("CAMELLIA-192-CFB8");
            cryptoWriter->DeleteClass("CAMELLIA-192-CFBfull");
            cryptoWriter->DeleteClass("CAMELLIA-192-CTR");
            cryptoWriter->DeleteClass("CAMELLIA-192-OFB");
            cryptoWriter->DeleteClass("CAMELLIA-128-CBC");
            cryptoWriter->DeleteClass("CAMELLIA-128-ECB");
            cryptoWriter->DeleteClass("CAMELLIA-128-CFB8");
            cryptoWriter->DeleteClass("CAMELLIA-128-CFBfull");
            cryptoWriter->DeleteClass("CAMELLIA-128-CTR");
            cryptoWriter->DeleteClass("CAMELLIA-128-OFB");
            cryptoWriter->DeleteClass("ARIA");
            cryptoWriter->DeleteClass("ARIA-256");
            cryptoWriter->DeleteClass("ARIA-192");
            cryptoWriter->DeleteClass("ARIA-128");
            cryptoWriter->DeleteClass("ARIA-256-CBC");
            cryptoWriter->DeleteClass("ARIA-256-ECB");
            cryptoWriter->DeleteClass("ARIA-256-CFB8");
            cryptoWriter->DeleteClass("ARIA-256-CFBfull");
            cryptoWriter->DeleteClass("ARIA-256-CTR");
            cryptoWriter->DeleteClass("ARIA-256-OFB");
            cryptoWriter->DeleteClass("ARIA-192-CBC");
            cryptoWriter->DeleteClass("ARIA-192-ECB");
            cryptoWriter->DeleteClass("ARIA-192-CFB8");
            cryptoWriter->DeleteClass("ARIA-192-CFBfull");
            cryptoWriter->DeleteClass("ARIA-192-CTR");
            cryptoWriter->DeleteClass("ARIA-192-OFB");
            cryptoWriter->DeleteClass("ARIA-128-CBC");
            cryptoWriter->DeleteClass("ARIA-128-ECB");
            cryptoWriter->DeleteClass("ARIA-128-CFB8");
            cryptoWriter->DeleteClass("ARIA-128-CFBfull");
            cryptoWriter->DeleteClass("ARIA-128-CTR");
            cryptoWriter->DeleteClass("ARIA-128-OFB");
            cryptoWriter->DeleteClass("SEED");
            cryptoWriter->DeleteClass("SEED-128");
            cryptoWriter->DeleteClass("SEED-128-CBC");
            cryptoWriter->DeleteClass("SEED-128-ECB");
            cryptoWriter->DeleteClass("SEED-128-CFB8");
            cryptoWriter->DeleteClass("SEED-128-CFBfull");
            cryptoWriter->DeleteClass("SEED-128-CTR");
            cryptoWriter->DeleteClass("SEED-128-OFB");
            cryptoWriter->DeleteClass("XTS");
            cryptoWriter->DeleteClass("XTS-AES");
            cryptoWriter->DeleteClass("XTS-AES-256");
            cryptoWriter->DeleteClass("XTS-AES-192");
            cryptoWriter->DeleteClass("XTS-AES-128");
            cryptoWriter->DeleteClass("XTS-CAMELLIA");
            cryptoWriter->DeleteClass("XTS-CAMELLIA-256");
            cryptoWriter->DeleteClass("XTS-CAMELLIA-192");
            cryptoWriter->DeleteClass("XTS-CAMELLIA-128");
            cryptoWriter->DeleteClass("XTS-ARIA");
            cryptoWriter->DeleteClass("XTS-ARIA-256");
            cryptoWriter->DeleteClass("XTS-ARIA-192");
            cryptoWriter->DeleteClass("XTS-ARIA-128");
            cryptoWriter->DeleteClass("XTS-SEED");
            cryptoWriter->DeleteClass("XTS-SEED-128");
            cryptoWriter->DeleteClass("X25519");
            cryptoWriter->DeleteClass("ED25519");
            cryptoWriter->DeleteClass("ED25519_PH");
            cryptoWriter->DeleteClass("KEY-X25519");
            cryptoWriter->DeleteClass("KEY-ED25519");
            cryptoWriter->DeleteClass("KEY-ED25519_PH");
            cryptoWriter->DeleteClass("numsp256d1");
            cryptoWriter->DeleteClass("numsp384d1");
            cryptoWriter->DeleteClass("numsp512d1");
            cryptoWriter->DeleteClass("numsp256t1");
            cryptoWriter->DeleteClass("numsp384t1");
            cryptoWriter->DeleteClass("numsp512t1");
            cryptoWriter->DeleteClass("KEY-numsp256d1");
            cryptoWriter->DeleteClass("KEY-numsp384d1");
            cryptoWriter->DeleteClass("KEY-numsp512d1");
            cryptoWriter->DeleteClass("KEY-numsp256t1");
            cryptoWriter->DeleteClass("KEY-numsp384t1");
            cryptoWriter->DeleteClass("KEY-numsp512t1");
            cryptoWriter->DeleteClass("KAS");
            cryptoWriter->DeleteClass("RSASVE");
            cryptoWriter->DeleteClass("KTS-OAEP");
            cryptoWriter->DeleteClass("KTS-KEM-KWS");
            cryptoWriter->DeleteClass("RSAKAS1");
            cryptoWriter->DeleteClass("RSAKAS2");
            cryptoWriter->DeleteClass("RSA-KEM-KWS");
			cryptoWriter->DeleteClass("KEYWRAP");
			cryptoWriter->DeleteClass("KEYWRAP_PAD");
			cryptoWriter->DeleteClass("KEYWRAP_INV");
			cryptoWriter->DeleteClass("KEYWRAP_PAD_INV");
			cryptoWriter->DeleteClass("KW");
			cryptoWriter->DeleteClass("KWP");
			cryptoWriter->DeleteClass("KW_INV");
			cryptoWriter->DeleteClass("KWP_INV");
			cryptoWriter->DeleteClass("TKW");
			cryptoWriter->DeleteClass("TKW_INV");

            cryptoTestWriter->DeleteClass("SHAKE128");
            cryptoTestWriter->DeleteClass("POLY1305");
            cryptoTestWriter->DeleteClass("SALSA20");
            cryptoTestWriter->DeleteClass("XSALSA20");
            cryptoTestWriter->DeleteClass("SALSA20_POLY1305");
            cryptoTestWriter->DeleteClass("CHACHA20");
            cryptoTestWriter->DeleteClass("CHACHA20_POLY1305");
            cryptoTestWriter->DeleteClass("CAMELLIA");
            cryptoTestWriter->DeleteClass("ARIA");
            cryptoTestWriter->DeleteClass("SEED");
            cryptoTestWriter->DeleteClass("XTS-AES");
            cryptoTestWriter->DeleteClass("XTS-CAMELLIA");
            cryptoTestWriter->DeleteClass("XTS-ARIA");
            cryptoTestWriter->DeleteClass("XTS-SEED");
            cryptoTestWriter->DeleteClass("X25519");
            cryptoTestWriter->DeleteClass("KAS");
            cryptoTestWriter->DeleteClass("RSASVE");
            cryptoTestWriter->DeleteClass("KTS-OAEP");
            cryptoTestWriter->DeleteClass("KTS-KEM-KWS");
            cryptoTestWriter->DeleteClass("RSAKAS1");
            cryptoTestWriter->DeleteClass("RSAKAS2");
            cryptoTestWriter->DeleteClass("RSA-KEM-KWS");


            //
            //			g_CryptoLocator->DeleteClass("PROTOCOL_SSL_SERVER");
            //			g_CryptoLocator->DeleteClass("CertificateIssuer");
            //			g_CryptoLocator->DeleteClass("TlsCipherSuiteProcessor");
            g_CryptoTestLocator.reset();
            g_CryptoLocator.reset();
            return true;
        });
        if (!loadCryptoModules())
        {
            tscrypto::TerminateCryptoSystem();
            throw tscrypto::crypto_failure();
        }
        tscrypto::AddCryptoTerminationFunction([]() ->bool {
            gKeySizeFuncs.clear();
            gModeFuncs.clear();
            gKeyTypeFuncs.clear();
            gBlockSizeFuncs.clear();
            gIVECSizeFuncs.clear();
            gSignNameFuncs.clear();
            return true;
        });
        // Now run the crypto self-tests
        if (!gFipsState.selfTest())
        {
            throw tscrypto::crypto_failure();
        }
        RunCryptoInitializers();
    }

    return g_CryptoLocator;
}

bool tscrypto::HasCryptoLocator()
{
    return !!g_CryptoLocator;
}

void RunCryptoInitializers()
{
	if (gInitialInitializers.empty())
		gInitialInitializers = gInitializers;
    for (auto func : gInitializers)
    {
        func();
    }
    gInitializers.clear();
}
void tscrypto::AddCryptoInitializationFunction(std::function<bool()> func)
{
    gInitializers.push_back(func);
}
void tscrypto::AddCryptoTerminationFunction(std::function<bool()> func)
{
    gTerminators.push_back(func);
}
void tscrypto::TerminateCryptoSystem()
{
    std::shared_ptr<tscrypto::ICryptoLocator> saved = g_CryptoLocator;

    while (gTerminators.size() > 0)
    {
        std::function<bool()> func = gTerminators.back();
        gTerminators.pop_back();
        func();
    }
	gInitialInitializers = gInitialInitializers;
}

static bool Check_CPU_support_AES()
{
#if defined(ANDROID)
    return false;
#elif defined(HAVE_CPUID_H)
    unsigned int vals[4];

    __cpuid(1, vals[0], vals[1], vals[2], vals[3]);

    return (vals[2] & 0x2000000) != 0;
#else
    int vals[4];

    __cpuid(vals, 1);

    return (vals[2] & 0x2000000) != 0;
#endif // HAVE_CPUID_H
}
static bool Check_CPU_support_SSE()
{
#if defined(ANDROID)
    return false;
#elif defined(HAVE_CPUID_H)
    int vals[4];

    __cpuid(1, vals[0], vals[1], vals[2], vals[3]);

    return (vals[3] & 0x2000000) != 0;
#else
    int vals[4];

    __cpuid(vals, 1);

    return (vals[3] & 0x2000000) != 0;
#endif // HAVE_CPUID_H
}
static bool Check_CPU_support_SSE2()
{
#if defined(ANDROID)
    return false;
#elif defined(HAVE_CPUID_H)
    int vals[4];

    __cpuid(1, vals[0], vals[1], vals[2], vals[3]);

    return (vals[3] & 0x4000000) != 0;
#else
    int vals[4];

    __cpuid(vals, 1);

    return (vals[3] & 0x4000000) != 0;
#endif // HAVE_CPUID_H
}

void tscrypto::XP_Sleep(uint32_t milliseconds)
{
#ifdef _WIN32
    Sleep(milliseconds);
#else
    usleep(milliseconds * 1000);
#endif
}

typedef struct AlgNameToIds
{
    const char *algName;
    const char *algOid;
    TS_ALG_ID algId;
    CryptoAlgType type;
} AlgNameToIds;

static AlgNameToIds _nameIdList[] = {
    {"Sha1", SHA1_OID, TS_ALG_SHA1, cat_Digest},
    {"Sha224", NIST_SHA224_OID, TS_ALG_SHA224, cat_Digest},
    {"Sha256", NIST_SHA256_OID, TS_ALG_SHA256, cat_Digest},
    {"Sha384", NIST_SHA384_OID, TS_ALG_SHA384, cat_Digest},
    {"Sha512", NIST_SHA512_OID, TS_ALG_SHA512, cat_Digest},
    {"MD5", MD5_OID, TS_ALG_MD5, cat_Digest},
    {"RIPEMD160", RIPEMD160_OID, TS_ALG_RIPEMD160, cat_Digest},
    {"HMAC-SHA1", RSADSI_HMAC_SHA1_OID, TS_ALG_HMAC_SHA1, cat_MAC},
    {"HMAC-SHA224", RSADSI_HMAC_SHA224_OID, TS_ALG_HMAC_SHA224, cat_MAC},
    {"HMAC-SHA256", RSADSI_HMAC_SHA256_OID, TS_ALG_HMAC_SHA256, cat_MAC},
    {"HMAC-SHA384", RSADSI_HMAC_SHA384_OID, TS_ALG_HMAC_SHA384, cat_MAC},
    {"HMAC-SHA512", RSADSI_HMAC_SHA512_OID, TS_ALG_HMAC_SHA512, cat_MAC},
    {"HMAC-MD5", HMAC_MD5, TS_ALG_HMAC_MD5, cat_MAC},
    {"HMAC-RIPEMD160", HMAC_RIPEMD160_OID, TS_ALG_HMAC_RIPEMD160, cat_MAC},

    {"TDES", ANSI_X9_52_DES_3EDE_CBC, TS_ALG_DES3_THREEKEY_CBC,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"TDES-64-CBC", TECSEC_DES_CBC, TS_ALG_DES_CBC,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"TDES-64-CFB8", TECSEC_DES_CFB8, TS_ALG_DES_CFB8,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"TDES-64-CFBfull", TECSEC_DES_CFB64, TS_ALG_DES_CFB64,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"TDES-64-CTR", TECSEC_DES_CTR, TS_ALG_DES_CTR,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"TDES-64-ECB", TECSEC_DES_ECB, TS_ALG_DES_ECB,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"TDES-64-OFB", TECSEC_DES_OFB, TS_ALG_DES_OFB,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"TDES-128-CBC", ANSI_X9_52_DES_3EDE_CBC, TS_ALG_DES3_TWOKEY_CBC,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"TDES-128-CFB8", TECSEC_TDES_TWOKEY_CFB8, TS_ALG_DES3_TWOKEY_CFB8,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"TDES-128-CFBfull", TECSEC_TDES_TWOKEY_CFB64, TS_ALG_DES3_TWOKEY_CFB64,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"TDES-128-CTR", TECSEC_TDES_TWOKEY_CTR, TS_ALG_DES3_TWOKEY_CTR,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"TDES-128-ECB", ANSI_X9_52_DES_3EDE_ECB, TS_ALG_DES3_TWOKEY_ECB,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"TDES-128-OFB", TECSEC_TDES_TWOKEY_OFB, TS_ALG_DES3_TWOKEY_OFB,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"TDES-192-CBC", ANSI_X9_52_DES_3EDE_CBC, TS_ALG_DES3_THREEKEY_CBC,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"TDES-192-CFB8", TECSEC_TDES_THREEKEY_CFB8, TS_ALG_DES3_THREEKEY_CFB8,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"TDES-192-CFBfull", TECSEC_TDES_THREEKEY_CFB64, TS_ALG_DES3_THREEKEY_CFB64,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"TDES-192-CTR", TECSEC_TDES_THREEKEY_CTR, TS_ALG_DES3_THREEKEY_CTR,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"TDES-192-ECB", ANSI_X9_52_DES_3EDE_ECB, TS_ALG_DES3_THREEKEY_ECB,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"TDES-192-OFB", TECSEC_TDES_THREEKEY_OFB, TS_ALG_DES3_THREEKEY_OFB,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"BLOWFISH", TECSEC_BLOWFISH_CBC_OID, TS_ALG_BLOWFISH_CBC,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"BLOWFISH-CBC", TECSEC_BLOWFISH_CBC_OID, TS_ALG_BLOWFISH_CBC,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"BLOWFISH-ECB", TECSEC_BLOWFISH_ECB_OID, TS_ALG_BLOWFISH_ECB,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"RC2", RC2_CBC_OID, TS_ALG_RC2_CBC,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"RC2-40-CBC", RC2_CBC_OID, TS_ALG_RC2_CBC,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"RC2-40-CFB8", TECSEC_RC2_40_CFB8, TS_ALG_RC2_CFB8,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"RC2-40-CFBfull", TECSEC_RC2_40_CFB64, TS_ALG_RC2_CFB64,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"RC2-40-CTR", TECSEC_RC2_40_CTR, TS_ALG_RC2_CTR,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"RC2-40-ECB", RC2_ECB_OID, TS_ALG_RC2_ECB,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"RC2-40-OFB", TECSEC_RC2_40_OFB, TS_ALG_RC2_OFB,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},

    {"RC2-128-CBC", TECSEC_RC2_128_CBC, TS_ALG_RC2_128_CBC,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"RC2-128-CFB8", TECSEC_RC2_128_CFB8, TS_ALG_RC2_128_CFB8,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"RC2-128-CFBfull", TECSEC_RC2_128_CFB64, TS_ALG_RC2_128_CFB64,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"RC2-128-CTR", TECSEC_RC2_128_CTR, TS_ALG_RC2_128_CTR,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"RC2-128-ECB", TECSEC_RC2_128_ECB, TS_ALG_RC2_128_ECB,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"RC2-128-OFB", TECSEC_RC2_128_OFB, TS_ALG_RC2_128_OFB,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"ARCFOUR", RC4_OID, TS_ALG_RC4,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_StreamCipher)},
    {"AES", NIST_AES_256_CBC_OID, TS_ALG_AES_CBC_256,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"AES-256-CBC", NIST_AES_256_CBC_OID, TS_ALG_AES_CBC_256,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"AES-256-ECB", NIST_AES_256_ECB_OID, TS_ALG_AES_ECB_256,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"AES-256-CFB8", NIST_AES_256_CFB_OID, TS_ALG_AES_CFB8_256,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"AES-256-CFBfull", NIST_AES_256_CFB_OID, TS_ALG_AES_CFB128_256,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"AES-256-CTR", TECSEC_AES_256_CTR_OID, TS_ALG_AES_CTR_256,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"AES-256-OFB", NIST_AES_256_OFB_OID, TS_ALG_AES_OFB_256,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"AES-192-CBC", NIST_AES_192_CBC_OID, TS_ALG_AES_CBC_192,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"AES-192-ECB", NIST_AES_192_ECB_OID, TS_ALG_AES_ECB_192,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"AES-192-CFB8", NIST_AES_192_CFB_OID, TS_ALG_AES_CFB8_192,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"AES-192-CFBfull", NIST_AES_192_CFB_OID, TS_ALG_AES_CFB128_192,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"AES-192-CTR", TECSEC_AES_192_CTR_OID, TS_ALG_AES_CTR_192,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"AES-192-OFB", NIST_AES_192_OFB_OID, TS_ALG_AES_OFB_192,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"AES-128-CBC", NIST_AES_128_CBC_OID, TS_ALG_AES_CBC_128,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"AES-128-ECB", NIST_AES_128_ECB_OID, TS_ALG_AES_ECB_128,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"AES-128-CFB8", NIST_AES_128_CFB_OID, TS_ALG_AES_CFB8_128,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"AES-128-CFBfull", NIST_AES_128_CFB_OID, TS_ALG_AES_CFB8_128,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"AES-128-CTR", TECSEC_AES_128_CTR_OID, TS_ALG_AES_CTR_128,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"AES-128-OFB", NIST_AES_128_OFB_OID, TS_ALG_AES_OFB_128,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"CCM-AES", NIST_AES_256_CCM_OID, TS_ALG_AES_CCM_256,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_AEAD)},
    {"CCM-AES-256", NIST_AES_256_CCM_OID, TS_ALG_AES_CCM_256,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_AEAD)},
    {"CCM-AES-192", NIST_AES_192_CCM_OID, TS_ALG_AES_CCM_192,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_AEAD)},
    {"CCM-AES-128", NIST_AES_128_CCM_OID, TS_ALG_AES_CCM_128,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_AEAD)},
    {"GCM-AES", NIST_AES_256_GCM_OID, TS_ALG_AES_GCM_256,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_AEAD)},
    {"GCM-AES-256", NIST_AES_256_GCM_OID, TS_ALG_AES_GCM_256,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_AEAD)},
    {"GCM-AES-192", NIST_AES_192_GCM_OID, TS_ALG_AES_GCM_192,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_AEAD)},
    {"GCM-AES-128", NIST_AES_128_GCM_OID, TS_ALG_AES_GCM_128,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_AEAD)},

    {"CMAC-AES", TECSEC_CMAC_AES256_OID, TS_ALG_CMAC_AES256,
     (CryptoAlgType)(cat_Symmetric | cat_MAC)},
    {"CMAC-AES-256", TECSEC_CMAC_AES256_OID, TS_ALG_CMAC_AES256,
     (CryptoAlgType)(cat_Symmetric | cat_MAC)},
    {"CMAC-AES-192", TECSEC_CMAC_AES192_OID, TS_ALG_CMAC_AES192,
     (CryptoAlgType)(cat_Symmetric | cat_MAC)},
    {"CMAC-AES-128", TECSEC_CMAC_AES128_OID, TS_ALG_CMAC_AES128,
     (CryptoAlgType)(cat_Symmetric | cat_MAC)},
    {"CMAC-TDES", TECSEC_CMAC_TDES_OID, TS_ALG_CMAC_TDES,
     (CryptoAlgType)(cat_Symmetric | cat_MAC)},
    {"CMAC-TDES-64", TECSEC_CMAC_TDES_OID, TS_ALG_CMAC_TDES,
     (CryptoAlgType)(cat_Symmetric | cat_MAC)},
    {"CMAC-TDES-128", TECSEC_CMAC_TDES_OID, TS_ALG_CMAC_TDES,
     (CryptoAlgType)(cat_Symmetric | cat_MAC)},
    {"CMAC-TDES-192", TECSEC_CMAC_TDES_OID, TS_ALG_CMAC_TDES,
     (CryptoAlgType)(cat_Symmetric | cat_MAC)},
    {"CMAC-BLOWFISH", TECSEC_CMAC_BLOWFISH_OID, TS_ALG_CMAC_BLOWFISH,
     (CryptoAlgType)(cat_Symmetric | cat_MAC)},
    {"CMAC-BLOWFISH-64", TECSEC_CMAC_BLOWFISH_OID, TS_ALG_CMAC_BLOWFISH,
     (CryptoAlgType)(cat_Symmetric | cat_MAC)},
    {"CMAC-BLOWFISH-128", TECSEC_CMAC_BLOWFISH_OID, TS_ALG_CMAC_BLOWFISH,
     (CryptoAlgType)(cat_Symmetric | cat_MAC)},
    {"CMAC-BLOWFISH-192", TECSEC_CMAC_BLOWFISH_OID, TS_ALG_CMAC_BLOWFISH,
     (CryptoAlgType)(cat_Symmetric | cat_MAC)},
    {"CMAC-XTEA", TECSEC_CMAC_XTEA_OID, TS_ALG_CMAC_XTEA,
     (CryptoAlgType)(cat_Symmetric | cat_MAC)},

    {"KDF-PBKDF2", TECSEC_KDF_PBKDF2_OID, TS_ALG_PBKDF2, cat_PbKdf},
    {"KDF-CMAC-AES", TECSEC_KDF_CMAC_AES_OID, TS_ALG_KDF_CMAC_AES, cat_KDF},
    {"KDF-CMAC-TDES", TECSEC_KDF_CMAC_TDES_OID, TS_ALG_KDF_CMAC_TDES, cat_KDF},
    {"KDF-CMAC-BLOWFISH", TECSEC_KDF_CMAC_BLOWFISH_OID,
     TS_ALG_KDF_CMAC_BLOWFISH, cat_KDF},
    {"KDF-CMAC-XTEA", TECSEC_KDF_CMAC_XTEA_OID, TS_ALG_KDF_CMAC_XTEA, cat_KDF},
    {"KDF-HMAC-MD5", TECSEC_KDF_HMAC_MD5_OID, TS_ALG_KDF_HMAC_MD5, cat_KDF},
    {"KDF-HMAC-Sha1", TECSEC_KDF_HMAC_SHA1_OID, TS_ALG_KDF_HMAC_SHA1, cat_KDF},
    {"KDF-HMAC-Sha224", TECSEC_KDF_HMAC_SHA224_OID, TS_ALG_KDF_HMAC_SHA224,
     cat_KDF},
    {"KDF-HMAC-Sha256", TECSEC_KDF_HMAC_SHA256_OID, TS_ALG_KDF_HMAC_SHA256,
     cat_KDF},
    {"KDF-HMAC-Sha384", TECSEC_KDF_HMAC_SHA384_OID, TS_ALG_KDF_HMAC_SHA384,
     cat_KDF},
    {"KDF-HMAC-Sha512", TECSEC_KDF_HMAC_SHA512_OID, TS_ALG_KDF_HMAC_SHA512,
     cat_KDF},
    {"KDF-MD5", TECSEC_KDF_HASH_MD5_OID, TS_ALG_KDF_HASH_MD5, cat_KDF},
    {"KDF-Sha1", TECSEC_KDF_HASH_SHA1_OID, TS_ALG_KDF_HASH_SHA1, cat_KDF},
    {"KDF-Sha224", TECSEC_KDF_HASH_SHA224_OID, TS_ALG_KDF_HASH_SHA224, cat_KDF},
    {"KDF-Sha256", TECSEC_KDF_HASH_SHA256_OID, TS_ALG_KDF_HASH_SHA256, cat_KDF},
    {"KDF-Sha384", TECSEC_KDF_HASH_SHA384_OID, TS_ALG_KDF_HASH_SHA384, cat_KDF},
    {"KDF-Sha512", TECSEC_KDF_HASH_SHA512_OID, TS_ALG_KDF_HASH_SHA512, cat_KDF},
    {"KDF-HMAC-RIPEMD160", TECSEC_KDF_HMAC_RIPEMD160_OID,
     TS_ALG_KDF_HMAC_RIPEMD160, cat_KDF},
    {"KDF-RIPEMD160", TECSEC_KDF_HASH_RIPEMD160_OID, TS_ALG_KDF_HASH_RIPEMD160,
     cat_KDF},

    {"KEYWRAP-AES", NIST_AES_256_wrap_OID, TS_ALG_KEYWRAP_AES256, cat_KeyTransport},
    {"KEYWRAP-RFC3394-AES", NIST_AES_256_wrap_OID, TS_ALG_KEYWRAP_AES256, cat_KeyTransport},
    {"KEYWRAP-RFC3394-AES-256", NIST_AES_256_wrap_OID, TS_ALG_KEYWRAP_AES256, cat_KeyTransport},
    {"KEYWRAP-RFC3394-AES-192", NIST_AES_192_wrap_OID, TS_ALG_KEYWRAP_AES192, cat_KeyTransport},
    {"KEYWRAP-RFC3394-AES-128", NIST_AES_128_wrap_OID, TS_ALG_KEYWRAP_AES128, cat_KeyTransport},
    {"KEYWRAP-TDES", TDES_KEYWRAP_OID, TS_ALG_KEYWRAP_TDES, cat_KeyTransport},
	{"KEYWRAP-BLOWFISH", TECSEC_KEYWRAP_BLOWFISH_OID, TS_ALG_KEYWRAP_BLOWFISH, cat_KeyTransport},
    {"KEYWRAP-XTEA", TECSEC_KEYWRAP_XTEA_OID, TS_ALG_KEYWRAP_XTEA, cat_KeyTransport},
	{"KEYWRAP-CAMELLIA", TECSEC_KEYWRAP_CAMELLIA_OID, TS_ALG_KEYWRAP_CAMELLIA256, cat_KeyTransport },
	{"KEYWRAP-ARIA", ARIA_256_KW_OID, TS_ALG_KEYWRAP_ARIA256, cat_KeyTransport },
	{"KEYWRAP-SEED", TECSEC_SEED_128_KW_OID, TS_ALG_KEYWRAP_SEED128, cat_KeyTransport },

    {"KW-AES", NIST_AES_256_wrap_OID, TS_ALG_KEYWRAP_AES256, cat_KeyTransport},
    {"TKW-TDES", TDES_KEYWRAP_OID, TS_ALG_KEYWRAP_TDES, cat_KeyTransport},
	{"TKW-BLOWFISH", TECSEC_KEYWRAP_BLOWFISH_OID, TS_ALG_KEYWRAP_BLOWFISH, cat_KeyTransport},
    {"KW-XTEA", TECSEC_KEYWRAP_XTEA_OID, TS_ALG_KEYWRAP_XTEA, cat_KeyTransport},
	{"KW-CAMELLIA", TECSEC_KEYWRAP_CAMELLIA256_OID, TS_ALG_KEYWRAP_CAMELLIA256, cat_KeyTransport },
	{"KW-ARIA", ARIA_256_KW_OID, TS_ALG_KEYWRAP_ARIA256, cat_KeyTransport },
	{"KW-SEED", TECSEC_SEED_128_KW_OID, TS_ALG_KEYWRAP_SEED128, cat_KeyTransport },

    {"PRIME-PROVABLE", TECSEC_PROVABLE_PRIME_OID, TS_ALG_PROVABLE_PRIME,
     cat_Prime},
    {"PRIME-PROBABLE", TECSEC_PROBABLE_PRIME_OID, TS_ALG_PROBABLE_PRIME,
     cat_Prime},
    {"PRIME-X9.31", TECSEC_PROBABLE_X9_31_PRIME_OID,
     TS_ALG_PROBABLE_X9_31_PRIME, cat_Prime},
    {"PARAMETERSET-DH", TECSEC_DH_PARAMETERS, TS_ALG_DH_PARAMETERS,
     cat_Asymmetric},
    {"KEY-DH", TECSEC_DH_KEY, TS_ALG_DH_KEY, cat_Asymmetric},
    {"KEY-DSA", TECSEC_DH_KEY, TS_ALG_DH_KEY, cat_Asymmetric},
    {"KEY-RSA", TECSEC_RSA_PRIVATE_KEY_BLOB, TS_ALG_RSA, cat_Asymmetric},
    {"KEY-RSA-X9.31", TECSEC_RSA_PRIVATE_KEY_BLOB, TS_ALG_RSA_X9_31_KEY,
     cat_Asymmetric},
    {"ENCODE-RSA-X9.31", TECSEC_RSA_X9_31_ENCODE, TS_ALG_RSA_X9_31_ENCODE,
     cat_Encoder},
    {"ENCODE-RSA-PSS", TECSEC_RSA_PSS_ENCODE, TS_ALG_RSA_PSS_ENCODE,
     cat_Encoder},
    {"ENCODE-RSA-PKCS", TECSEC_RSA_PKCS_ENCODE, TS_ALG_RSA_PKCS_v15,
     cat_Encoder},
    //{"ENCODE-RSA-ENCRYPT-PKCS", TECSEC_RSA_PKCS_ENCRYPT_ENCODE, TS_ALG_RSA,
    // cat_Encoder},
    {"RSA-OAEP-SHA1", TECSEC_RSA_OAEP_SHA1, TS_ALG_RSA_OAEP_SHA1, cat_Sign},
    {"RSA-OAEP-SHA224", TECSEC_RSA_OAEP_SHA224, TS_ALG_RSA_OAEP_SHA224,
     cat_Sign},
    {"RSA-OAEP-SHA256", TECSEC_RSA_OAEP_SHA256, TS_ALG_RSA_OAEP_SHA256,
     cat_Sign},
    {"RSA-OAEP-SHA384", TECSEC_RSA_OAEP_SHA384, TS_ALG_RSA_OAEP_SHA384,
     cat_Sign},
    {"RSA-OAEP-SHA512", TECSEC_RSA_OAEP_SHA512, TS_ALG_RSA_OAEP_SHA512,
     cat_Sign},
    {"SIGN-RSA-X9.31-SHA1", TECSEC_RSA_X9_31_SHA1, TS_ALG_RSA_X9_31_SHA1,
     cat_Sign},
    {"SIGN-RSA-X9.31-SHA224", TECSEC_RSA_X9_31_SHA224, TS_ALG_RSA_X9_31_SHA224,
     cat_Sign},
    {"SIGN-RSA-X9.31-SHA256", TECSEC_RSA_X9_31_SHA256, TS_ALG_RSA_X9_31_SHA256,
     cat_Sign},
    {"SIGN-RSA-X9.31-SHA384", TECSEC_RSA_X9_31_SHA384, TS_ALG_RSA_X9_31_SHA384,
     cat_Sign},
    {"SIGN-RSA-X9.31-SHA512", TECSEC_RSA_X9_31_SHA512, TS_ALG_RSA_X9_31_SHA512,
     cat_Sign},
    {"SIGN-RSA-PKCS", RSA_ENCRYPT_OID, TS_ALG_RSA_PKCS, cat_Sign},
    {"SIGN-RSA-PKCS-MD5", RSADSI_MD5, TS_ALG_RSA_MD5_v15, cat_Sign},
    {"SIGN-RSA-PKCS-SHA1", RSA_SHA1_SIGN_OID, TS_ALG_RSA_SHA1_v15, cat_Sign},
    {"SIGN-RSA-PKCS-SHA224", RSA_SHA224_SIGN_OID, TS_ALG_RSA_SHA224_v15,
     cat_Sign},
    {"SIGN-RSA-PKCS-SHA256", RSA_SHA256_SIGN_OID, TS_ALG_RSA_SHA256_v15,
     cat_Sign},
    {"SIGN-RSA-PKCS-SHA384", RSA_SHA384_SIGN_OID, TS_ALG_RSA_SHA384_v15,
     cat_Sign},
    {"SIGN-RSA-PKCS-SHA512", RSA_SHA512_SIGN_OID, TS_ALG_RSA_SHA512_v15,
     cat_Sign},
    {"SIGN-RSA-PSS-SHA1", RSASSA_PSS_OID, TS_ALG_RSA_PSS_SHA1, cat_Sign},
    {"SIGN-RSA-PSS-SHA224", RSASSA_PSS_OID, TS_ALG_RSA_PSS_SHA224, cat_Sign},
    {"SIGN-RSA-PSS-SHA256", RSASSA_PSS_OID, TS_ALG_RSA_PSS_SHA256, cat_Sign},
    {"SIGN-RSA-PSS-SHA384", RSASSA_PSS_OID, TS_ALG_RSA_PSS_SHA384, cat_Sign},
    {"SIGN-RSA-PSS-SHA512", RSASSA_PSS_OID, TS_ALG_RSA_PSS_SHA512, cat_Sign},

    #ifdef SUPPORT_ECC_P192
    //	{ "KEY-P192", NIST_P192_CURVE_OID, TS_ALG_ECC_P192 },
    #endif // SUPPORT_ECC_P192
    #ifdef SUPPORT_ECC_P224
    //	{ "KEY-P224", NIST_P224_CURVE_OID, TS_ALG_ECC_P224 },
    #endif // SUPPORT_ECC_P224
    {"KEY-P256", SECP256R1_CURVE_OID, TS_ALG_ECC_P256, cat_Asymmetric},
    {"KEY-P256K1", SECP256K1_OID, TS_ALG_ECC_P256K1, cat_Asymmetric },
    {"KEY-P384", SECP384R1_CURVE_OID, TS_ALG_ECC_P384, cat_Asymmetric},
    {"KEY-P521", SECP521R1_CURVE_OID, TS_ALG_ECC_P521, cat_Asymmetric},
    {"SIGN-ECC-SHA1", ECDSA_SHA1_OID, TS_ALG_ECC_SHA1, cat_Sign},
    {"SIGN-ECC-SHA224", ECDSA_SHA224_OID, TS_ALG_ECC_SHA224, cat_Sign},
    {"SIGN-ECC-SHA256", ECDSA_SHA256_OID, TS_ALG_ECC_SHA256, cat_Sign},
    {"SIGN-ECC-SHA384", ECDSA_SHA384_OID, TS_ALG_ECC_SHA384, cat_Sign},
    {"SIGN-ECC-SHA512", ECDSA_SHA512_OID, TS_ALG_ECC_SHA512, cat_Sign},
    {"SIGN-DSA-SHA1", DSA_SHA1_OID, TS_ALG_DSA_SHA1, cat_Sign},
    {"SIGN-DSA-SHA224", NIST_DSA_SHA224_OID, TS_ALG_DSA_SHA224, cat_Sign},
    {"SIGN-DSA-SHA256", NIST_DSA_SHA256_OID, TS_ALG_DSA_SHA256, cat_Sign},
    {"SIGN-DSA-SHA384", TECSEC_DSA_SIGN_SHA384, TS_ALG_DSA_SHA384, cat_Sign},
    {"SIGN-DSA-SHA512", TECSEC_DSA_SIGN_SHA512, TS_ALG_DSA_SHA512, cat_Sign},

    { "X25519", id_X25519, TS_ALG_X25519, cat_Asymmetric },
    { "ED25519", id_X25519, TS_ALG_X25519, cat_Asymmetric },
    { "ED25519_PH", id_X25519_PH, TS_ALG_X25519_PH, cat_Asymmetric },
    { "KEY-X25519", id_X25519, TS_ALG_X25519, cat_Asymmetric },
    { "KEY-ED25519", id_X25519, TS_ALG_X25519, cat_Asymmetric },
    { "KEY-ED25519_PH", id_X25519_PH, TS_ALG_X25519_PH, cat_Asymmetric },
    //{ "X448", id_X448, TS_ALG_X448, cat_Asymmetric },
    //{ "X448_PH", id_X448_PH, TS_ALG_X448_PH, cat_Asymmetric },

#ifndef MINGW
    { "NUMSP256D1", TECSEC_NUMSP256D1, TS_ALG_NUMSP256D1, cat_Asymmetric },
    { "NUMSP384D1", TECSEC_NUMSP384D1, TS_ALG_NUMSP384D1, cat_Asymmetric },
    { "NUMSP512D1", TECSEC_NUMSP512D1, TS_ALG_NUMSP512D1, cat_Asymmetric },
    { "NUMSP256T1", TECSEC_NUMSP256T1, TS_ALG_NUMSP256T1, cat_Asymmetric },
    { "NUMSP384T1", TECSEC_NUMSP384T1, TS_ALG_NUMSP384T1, cat_Asymmetric },
    { "NUMSP512T1", TECSEC_NUMSP512T1, TS_ALG_NUMSP512T1, cat_Asymmetric },
    { "KEY-NUMSP256D1", TECSEC_NUMSP256D1, TS_ALG_NUMSP256D1, cat_Asymmetric },
    { "KEY-NUMSP384D1", TECSEC_NUMSP384D1, TS_ALG_NUMSP384D1, cat_Asymmetric },
    { "KEY-NUMSP512D1", TECSEC_NUMSP512D1, TS_ALG_NUMSP512D1, cat_Asymmetric },
    { "KEY-NUMSP256T1", TECSEC_NUMSP256T1, TS_ALG_NUMSP256T1, cat_Asymmetric },
    { "KEY-NUMSP384T1", TECSEC_NUMSP384T1, TS_ALG_NUMSP384T1, cat_Asymmetric },
    { "KEY-NUMSP512T1", TECSEC_NUMSP512T1, TS_ALG_NUMSP512T1, cat_Asymmetric },
#endif

    {"CKMAUTH", TECSEC_CKMAUTH_OID, TS_ALG_CKMAUTH, cat_CkmAuth},
    {"CKMAUTH_CALCULATOR-PBKDF2-SHA1", TECSEC_CKMAUTH_PBKDF_SHA1_OID,
     TS_ALG_CKMAUTH_PBKDF_SHA1, cat_CkmAuth},
    {"CKMAUTH_CALCULATOR-PBKDF2-SHA224", TECSEC_CKMAUTH_PBKDF_SHA224_OID,
     TS_ALG_CKMAUTH_PBKDF_SHA224, (CryptoAlgType)(cat_CkmAuth | cat_PbKdf)},
    {"CKMAUTH_CALCULATOR-PBKDF2-SHA256", TECSEC_CKMAUTH_PBKDF_SHA256_OID,
     TS_ALG_CKMAUTH_PBKDF_SHA256, (CryptoAlgType)(cat_CkmAuth | cat_PbKdf)},
    {"CKMAUTH_CALCULATOR-PBKDF2-SHA384", TECSEC_CKMAUTH_PBKDF_SHA384_OID,
     TS_ALG_CKMAUTH_PBKDF_SHA384, (CryptoAlgType)(cat_CkmAuth | cat_PbKdf)},
    {"CKMAUTH_CALCULATOR-PBKDF2-SHA512", TECSEC_CKMAUTH_PBKDF_SHA512_OID,
     TS_ALG_CKMAUTH_PBKDF_SHA512, (CryptoAlgType)(cat_CkmAuth | cat_PbKdf)},
    {"SHA3-512", NIST_SHA3_512_OID, TS_ALG_SHA3_512, cat_Digest},
    {"SHA3-224", NIST_SHA3_224_OID, TS_ALG_SHA3_224, cat_Digest},
    {"SHA3-256", NIST_SHA3_256_OID, TS_ALG_SHA3_256, cat_Digest},
    {"SHA3-384", NIST_SHA3_384_OID, TS_ALG_SHA3_384, cat_Digest},
    {"SHAKE128", NIST_SHAKE128_OID, TS_ALG_SHAKE128,
     (CryptoAlgType)(cat_Digest | cat_XOF)},
    {"SHAKE256", NIST_SHAKE256_OID, TS_ALG_SHAKE256,
     (CryptoAlgType)(cat_Digest | cat_XOF)},
    {"HMAC-SHA3-224", NIST_HMAC_SHA3_224_OID, TS_ALG_HMAC_SHA3_224, cat_MAC},
    {"HMAC-SHA3-256", NIST_HMAC_SHA3_256_OID, TS_ALG_HMAC_SHA3_256, cat_MAC},
    {"HMAC-SHA3-384", NIST_HMAC_SHA3_384_OID, TS_ALG_HMAC_SHA3_384, cat_MAC},
    {"HMAC-SHA3-512", NIST_HMAC_SHA3_512_OID, TS_ALG_HMAC_SHA3_512, cat_MAC},

    {"KDF-HMAC-SHA3-224", TECSEC_KDF_HMAC_SHA3_224_OID,
     TS_ALG_KDF_HMAC_SHA3_224, cat_KDF},
    {"KDF-HMAC-SHA3-256", TECSEC_KDF_HMAC_SHA3_256_OID,
     TS_ALG_KDF_HMAC_SHA3_256, cat_KDF},
    {"KDF-HMAC-SHA3-384", TECSEC_KDF_HMAC_SHA3_384_OID,
     TS_ALG_KDF_HMAC_SHA3_384, cat_KDF},
    {"KDF-HMAC-SHA3-512", TECSEC_KDF_HMAC_SHA3_512_OID,
     TS_ALG_KDF_HMAC_SHA3_512, cat_KDF},
    {"KDF-SHA3-224", TECSEC_KDF_HASH_SHA3_224_OID, TS_ALG_KDF_HASH_SHA3_224,
     cat_KDF},
    {"KDF-SHA3-256", TECSEC_KDF_HASH_SHA3_256_OID, TS_ALG_KDF_HASH_SHA3_256,
     cat_KDF},
    {"KDF-SHA3-384", TECSEC_KDF_HASH_SHA3_384_OID, TS_ALG_KDF_HASH_SHA3_384,
     cat_KDF},
    {"KDF-SHA3-512", TECSEC_KDF_HASH_SHA3_512_OID, TS_ALG_KDF_HASH_SHA3_512,
     cat_KDF},

    {"POLY1305", TECSEC_POLY1305, TS_ALG_POLY1305, (CryptoAlgType)(cat_MAC)},
    {"SALSA20", TECSEC_SALSA20, TS_ALG_SALSA20,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_StreamCipher)},
    {"XSALSA20", TECSEC_XSALSA20, TS_ALG_XSALSA20,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_StreamCipher)},
    {"SALSA20_POLY1305", TECSEC_SALSA20_POLY1305_OID, TS_ALG_SALSA20_POLY1305,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_AEAD)},
    {"CHACHA20", TECSEC_CHACHA20, TS_ALG_CHACHA20,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_StreamCipher)},
    {"CHACHA20_POLY1305", TECSEC_CHACHA20_POLY1305_OID,
     TS_ALG_CHACHA20_POLY1305,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_AEAD)},
    {"CAMELLIA", CAMELLIA_256_CBC_OID, TS_ALG_CAMELLIA_CBC_256,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"CAMELLIA-256-CBC", CAMELLIA_256_CBC_OID, TS_ALG_CAMELLIA_CBC_256,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"CAMELLIA-256-ECB", CAMELLIA_256_ECB_OID, TS_ALG_CAMELLIA_ECB_256,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"CAMELLIA-256-CFB8", CAMELLIA_256_CFB_OID, TS_ALG_CAMELLIA_CFB8_256,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"CAMELLIA-256-CFBfull", CAMELLIA_256_CFB_OID, TS_ALG_CAMELLIA_CFB128_256,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"CAMELLIA-256-CTR", CAMELLIA_256_CTR_OID, TS_ALG_CAMELLIA_CTR_256,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"CAMELLIA-256-OFB", CAMELLIA_256_OFB_OID, TS_ALG_CAMELLIA_OFB_256,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"CAMELLIA-192-CBC", CAMELLIA_192_CBC_OID, TS_ALG_CAMELLIA_CBC_192,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"CAMELLIA-192-ECB", CAMELLIA_192_ECB_OID, TS_ALG_CAMELLIA_ECB_192,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"CAMELLIA-192-CFB8", CAMELLIA_192_CFB_OID, TS_ALG_CAMELLIA_CFB8_192,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"CAMELLIA-192-CFBfull", CAMELLIA_192_CFB_OID, TS_ALG_CAMELLIA_CFB128_192,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"CAMELLIA-192-CTR", CAMELLIA_192_CTR_OID, TS_ALG_CAMELLIA_CTR_192,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"CAMELLIA-192-OFB", CAMELLIA_192_OFB_OID, TS_ALG_CAMELLIA_OFB_192,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"CAMELLIA-128-CBC", CAMELLIA_128_CBC_OID, TS_ALG_CAMELLIA_CBC_128,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"CAMELLIA-128-ECB", CAMELLIA_128_ECB_OID, TS_ALG_CAMELLIA_ECB_128,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"CAMELLIA-128-CFB8", CAMELLIA_128_CFB_OID, TS_ALG_CAMELLIA_CFB8_128,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"CAMELLIA-128-CFBfull", CAMELLIA_128_CFB_OID, TS_ALG_CAMELLIA_CFB8_128,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"CAMELLIA-128-CTR", CAMELLIA_128_CTR_OID, TS_ALG_CAMELLIA_CTR_128,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"CAMELLIA-128-OFB", CAMELLIA_128_OFB_OID, TS_ALG_CAMELLIA_OFB_128,
     (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"CMAC-CAMELLIA", CAMELLIA_256_CMAC_OID, TS_ALG_CMAC_CAMELLIA256,
     (CryptoAlgType)(cat_Symmetric | cat_MAC)},
    {"CMAC-CAMELLIA-256", CAMELLIA_256_CMAC_OID, TS_ALG_CMAC_CAMELLIA256,
     (CryptoAlgType)(cat_Symmetric | cat_MAC)},
    {"CMAC-CAMELLIA-192", CAMELLIA_192_CMAC_OID, TS_ALG_CMAC_CAMELLIA192,
     (CryptoAlgType)(cat_Symmetric | cat_MAC)},
    {"CMAC-CAMELLIA-128", CAMELLIA_128_CMAC_OID, TS_ALG_CMAC_CAMELLIA128,
     (CryptoAlgType)(cat_Symmetric | cat_MAC)},
    {"KDF-CMAC-CAMELLIA", TECSEC_KDF_CMAC_CAMELLIA_OID,
     TS_ALG_KDF_CMAC_CAMELLIA, cat_KDF},
    // {"GCM-CAMELLIA", CAMELLIA_256_GCM_OID, TS_ALG_CAMELLIA_GCM_256, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_AEAD)},
    // {"GCM-CAMELLIA-256", CAMELLIA_256_GCM_OID, TS_ALG_CAMELLIA_GCM_256, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_AEAD)},
    // {"GCM-CAMELLIA-192", CAMELLIA_192_GCM_OID, TS_ALG_CAMELLIA_GCM_192, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_AEAD)},
    // {"GCM-CAMELLIA-128", CAMELLIA_128_GCM_OID, TS_ALG_CAMELLIA_GCM_128, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_AEAD)},
    // { "CCM-CAMELLIA", CAMELLIA_256_CCM_OID, TS_ALG_CAMELLIA_CCM_256, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_AEAD) },
    // { "CCM-CAMELLIA-256", CAMELLIA_256_CCM_OID, TS_ALG_CAMELLIA_CCM_256, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_AEAD) },
    // { "CCM-CAMELLIA-192", CAMELLIA_192_CCM_OID, TS_ALG_CAMELLIA_CCM_192, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_AEAD) },
    // { "CCM-CAMELLIA-128", CAMELLIA_128_CCM_OID, TS_ALG_CAMELLIA_CCM_128, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_AEAD) },
    {"ARIA", ARIA_256_CBC_OID, TS_ALG_ARIA_CBC_256, (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"ARIA-256-CBC", ARIA_256_CBC_OID, TS_ALG_ARIA_CBC_256, (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"ARIA-256-ECB", ARIA_256_ECB_OID, TS_ALG_ARIA_ECB_256, (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"ARIA-256-CFB8", TECSEC_ARIA_256_CFB8_OID, TS_ALG_ARIA_CFB8_256, (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"ARIA-256-CFBfull", ARIA_256_CFB_OID, TS_ALG_ARIA_CFB128_256, (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"ARIA-256-CTR", ARIA_256_CTR_OID, TS_ALG_ARIA_CTR_256, (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"ARIA-256-OFB", ARIA_256_OFB_OID, TS_ALG_ARIA_OFB_256, (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"ARIA-192-CBC", ARIA_192_CBC_OID, TS_ALG_ARIA_CBC_192, (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"ARIA-192-ECB", ARIA_192_ECB_OID, TS_ALG_ARIA_ECB_192, (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"ARIA-192-CFB8", TECSEC_ARIA_192_CFB8_OID, TS_ALG_ARIA_CFB8_192, (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"ARIA-192-CFBfull", ARIA_192_CFB_OID, TS_ALG_ARIA_CFB128_192, (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"ARIA-192-CTR", ARIA_192_CTR_OID, TS_ALG_ARIA_CTR_192, (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"ARIA-192-OFB", ARIA_192_OFB_OID, TS_ALG_ARIA_OFB_192, (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"ARIA-128-CBC", ARIA_128_CBC_OID, TS_ALG_ARIA_CBC_128, (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"ARIA-128-ECB", ARIA_128_ECB_OID, TS_ALG_ARIA_ECB_128, (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"ARIA-128-CFB8", TECSEC_ARIA_128_CFB8_OID, TS_ALG_ARIA_CFB8_128, (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"ARIA-128-CFBfull", ARIA_128_CFB_OID, TS_ALG_ARIA_CFB8_128, (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"ARIA-128-CTR", ARIA_128_CTR_OID, TS_ALG_ARIA_CTR_128, (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"ARIA-128-OFB", ARIA_128_OFB_OID, TS_ALG_ARIA_OFB_128, (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"CMAC-ARIA", ARIA_256_CMAC_OID, TS_ALG_CMAC_ARIA256, (CryptoAlgType)(cat_Symmetric | cat_MAC)},
    {"CMAC-ARIA-256", ARIA_256_CMAC_OID, TS_ALG_CMAC_ARIA256, (CryptoAlgType)(cat_Symmetric | cat_MAC)},
    {"CMAC-ARIA-192", ARIA_192_CMAC_OID, TS_ALG_CMAC_ARIA192, (CryptoAlgType)(cat_Symmetric | cat_MAC)},
    {"CMAC-ARIA-128", ARIA_128_CMAC_OID, TS_ALG_CMAC_ARIA128, (CryptoAlgType)(cat_Symmetric | cat_MAC)},
    {"KDF-CMAC-ARIA", TECSEC_KDF_CMAC_ARIA_OID, TS_ALG_KDF_CMAC_ARIA, cat_KDF},
    // {"CCM-ARIA", ARIA_256_CCM_OID, TS_ALG_ARIA_CCM_256, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_AEAD)},
    // {"CCM-ARIA-256", ARIA_256_CCM_OID, TS_ALG_ARIA_CCM_256, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_AEAD)},
    // {"CCM-ARIA-192", ARIA_192_CCM_OID, TS_ALG_ARIA_CCM_192, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_AEAD)},
    // {"CCM-ARIA-128", ARIA_128_CCM_OID, TS_ALG_ARIA_CCM_128, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_AEAD)},
    // {"GCM-ARIA", ARIA_256_GCM_OID, TS_ALG_ARIA_GCM_256, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_AEAD)},
    // {"GCM-ARIA-256", ARIA_256_GCM_OID, TS_ALG_ARIA_GCM_256, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_AEAD)},
    // {"GCM-ARIA-192", ARIA_192_GCM_OID, TS_ALG_ARIA_GCM_192, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_AEAD)},
    // {"GCM-ARIA-128", ARIA_128_GCM_OID, TS_ALG_ARIA_GCM_128, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_AEAD)},
    {"SEED", SEED_128_CBC_OID, TS_ALG_SEED_CBC_128, (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"SEED-128-CBC", SEED_128_CBC_OID, TS_ALG_SEED_CBC_128, (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"SEED-128-ECB", SEED_128_ECB_OID, TS_ALG_SEED_ECB_128, (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"SEED-128-CFB8", TECSEC_SEED_128_CFB8_OID, TS_ALG_SEED_CFB8_128, (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"SEED-128-CFBfull", SEED_128_CFB_OID, TS_ALG_SEED_CFB8_128, (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"SEED-128-CTR", TECSEC_SEED_128_CTR_OID, TS_ALG_SEED_CTR_128, (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"SEED-128-OFB", SEED_128_OFB_OID, TS_ALG_SEED_OFB_128, (CryptoAlgType)(cat_Symmetric | cat_Encrypt)},
    {"CMAC-SEED", SEED_128_CMAC_OID, TS_ALG_CMAC_SEED128, (CryptoAlgType)(cat_Symmetric | cat_MAC)},
    {"CMAC-SEED-128", SEED_128_CMAC_OID, TS_ALG_CMAC_SEED128, (CryptoAlgType)(cat_Symmetric | cat_MAC)},
    {"KDF-CMAC-SEED", TECSEC_KDF_CMAC_SEED_OID, TS_ALG_KDF_CMAC_SEED, cat_KDF},
    // {"CCM-SEED", TECSEC_SEED_128_CCM_OID, TS_ALG_SEED_CCM_128, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_AEAD)},
    // {"CCM-SEED-128", TECSEC_SEED_128_CCM_OID, TS_ALG_SEED_CCM_128, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_AEAD)},
    // {"GCM-SEED", TECSEC_SEED_128_GCM_OID, TS_ALG_SEED_GCM_128, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_AEAD)},
    // {"GCM-SEED-128", TECSEC_SEED_128_GCM_OID, TS_ALG_SEED_GCM_128, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_AEAD)},
    {"XTS-AES", XTS_AES_256_OID, TS_ALG_AES_XTS_256, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_XTS)},
    {"XTS-AES-256", XTS_AES_256_OID, TS_ALG_AES_XTS_256, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_XTS)},
    {"XTS-AES-192", TECSEC_AES_192_XTS_OID, TS_ALG_AES_XTS_192, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_XTS)},
    {"XTS-AES-128", XTS_AES_128_OID, TS_ALG_AES_XTS_128, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_XTS)},
    // {"XTS-CAMELLIA", TECSEC_CAMELLIA_256_XTS_OID, TS_ALG_CAMELLIA_XTS_256, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_XTS)},
    // {"XTS-CAMELLIA-256", TECSEC_CAMELLIA_256_XTS_OID, TS_ALG_CAMELLIA_XTS_256, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_XTS)},
    // {"XTS-CAMELLIA-192", TECSEC_CAMELLIA_192_XTS_OID, TS_ALG_CAMELLIA_XTS_192, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_XTS)},
    // {"XTS-CAMELLIA-128", TECSEC_CAMELLIA_128_XTS_OID, TS_ALG_CAMELLIA_XTS_128, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_XTS)},
    // {"XTS-ARIA", TECSEC_ARIA_256_XTS_OID, TS_ALG_ARIA_XTS_256, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_XTS)},
    // {"XTS-ARIA-256", TECSEC_ARIA_256_XTS_OID, TS_ALG_ARIA_XTS_256, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_XTS)},
    // {"XTS-ARIA-192", TECSEC_ARIA_192_XTS_OID, TS_ALG_ARIA_XTS_192, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_XTS)},
    // {"XTS-ARIA-128", TECSEC_ARIA_128_XTS_OID, TS_ALG_ARIA_XTS_128, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_XTS)},
    // {"XTS-SEED", TECSEC_SEED_128_XTS_OID, TS_ALG_SEED_XTS_128, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_XTS)},
    // {"XTS-SEED-128", TECSEC_SEED_128_XTS_OID, TS_ALG_SEED_XTS_128, (CryptoAlgType)(cat_Symmetric | cat_Encrypt | cat_XTS)},

    {"SIGN-RSA-X9.31-SHA3-224", TECSEC_RSA_X9_31_SHA3_224,
     TS_ALG_RSA_X9_31_SHA3_224, cat_Sign},
    {"SIGN-RSA-X9.31-SHA3-256", TECSEC_RSA_X9_31_SHA3_256,
     TS_ALG_RSA_X9_31_SHA3_256, cat_Sign},
    {"SIGN-RSA-X9.31-SHA3-384", TECSEC_RSA_X9_31_SHA3_384,
     TS_ALG_RSA_X9_31_SHA3_384, cat_Sign},
    {"SIGN-RSA-X9.31-SHA3-512", TECSEC_RSA_X9_31_SHA3_512,
     TS_ALG_RSA_X9_31_SHA3_512, cat_Sign},
    {"SIGN-RSA-PKCS-SHA3-224", NIST_RSA_PKCS_SHA3_224,
     TS_ALG_RSA_PKCS_SHA3_224, cat_Sign},
    {"SIGN-RSA-PKCS-SHA3-256", NIST_RSA_PKCS_SHA3_256,
     TS_ALG_RSA_PKCS_SHA3_256, cat_Sign},
    {"SIGN-RSA-PKCS-SHA3-384", NIST_RSA_PKCS_SHA3_384,
     TS_ALG_RSA_PKCS_SHA3_384, cat_Sign},
    {"SIGN-RSA-PKCS-SHA3-512", NIST_RSA_PKCS_SHA3_512,
     TS_ALG_RSA_PKCS_SHA3_512, cat_Sign},
    {"SIGN-RSA-PSS-SHA3-224", RSASSA_PSS_OID, TS_ALG_RSA_PSS_SHA3_224,
     cat_Sign},
    {"SIGN-RSA-PSS-SHA3-256", RSASSA_PSS_OID, TS_ALG_RSA_PSS_SHA3_256,
     cat_Sign},
    {"SIGN-RSA-PSS-SHA3-384", RSASSA_PSS_OID, TS_ALG_RSA_PSS_SHA3_384,
     cat_Sign},
    {"SIGN-RSA-PSS-SHA3-512", RSASSA_PSS_OID, TS_ALG_RSA_PSS_SHA3_512,
     cat_Sign},
    {"SIGN-ECC-SHA3-224", NIST_ECDSA_SHA3_224_OID, TS_ALG_ECC_SHA3_224,
     cat_Sign},
    {"SIGN-ECC-SHA3-256", NIST_ECDSA_SHA3_256_OID, TS_ALG_ECC_SHA3_256,
     cat_Sign},
    {"SIGN-ECC-SHA3-384", NIST_ECDSA_SHA3_384_OID, TS_ALG_ECC_SHA3_384,
     cat_Sign},
    {"SIGN-ECC-SHA3-512", NIST_ECDSA_SHA3_512_OID, TS_ALG_ECC_SHA3_512,
     cat_Sign},
    {"SIGN-DSA-SHA3-224", NIST_DSA_SHA3_224_OID, TS_ALG_DSA_SHA3_224,
     cat_Sign},
    {"SIGN-DSA-SHA3-256", NIST_DSA_SHA3_256_OID, TS_ALG_DSA_SHA3_256,
     cat_Sign},
    {"SIGN-DSA-SHA3-384", NIST_DSA_SHA3_384_OID, TS_ALG_DSA_SHA3_384,
     cat_Sign},
    {"SIGN-DSA-SHA3-512", NIST_DSA_SHA3_512_OID, TS_ALG_DSA_SHA3_512,
     cat_Sign},
    {"KAS", TECSEC_DH_ECDH_KAS, TS_ALG_DH_ECDH_KAS, cat_KeyAgreement},
    {"RSASVE", TECSEC_RSASVE, TS_ALG_RSASVE, cat_KeyTransport},
    {"RSA-KEM-KWS", TECSEC_RSA_KEM_KWS, TS_ALG_RSA_KEM_KWS, cat_KeyTransport},
    {"RSAKAS1", TECSEC_RSA_KAS1, TS_ALG_RSA_KAS1, cat_KeyAgreement},
    {"RSAKAS2", TECSEC_RSA_KAS2, TS_ALG_RSA_KAS2, cat_KeyAgreement},
    {"KTS-OAEP", TECSEC_RSA_KTS_OAEP, TS_ALG_RSA_KTS_OAEP, cat_KeyTransport},
    {"KTS-KEM-KWS", TECSEC_RSA_KTS_KEM_KWS, TS_ALG_RSA_KTS_KEM_KWS,
     cat_KeyTransport},

    {"CKM7CRYPTOGROUP-P256-SHA512", TECSEC_CKM7_CRYPTOGROUP_P256_SHA512,
     TS_ALG_CKM7_CRYPTOGROUP_P256_SHA512, cat_CryptoGroup},
    {"CKM7CRYPTOGROUP-P384-SHA512", TECSEC_CKM7_CRYPTOGROUP_P384_SHA512,
     TS_ALG_CKM7_CRYPTOGROUP_P384_SHA512, cat_CryptoGroup},
    {"CKM7CRYPTOGROUP-P521-SHA512", TECSEC_CKM7_CRYPTOGROUP_P521_SHA512,
     TS_ALG_CKM7_CRYPTOGROUP_P521_SHA512, cat_CryptoGroup},
    {"CKM7CRYPTOGROUP-X25519-SHA512", TECSEC_CKM7_CRYPTOGROUP_X25519_SHA512,
     TS_ALG_CKM7_CRYPTOGROUP_X25519_SHA512, cat_CryptoGroup},
    { "CKM7CRYPTOGROUP-P256K1-SHA512", TECSEC_CKM7_CRYPTOGROUP_P256K1_SHA512, TS_ALG_CKM7_CRYPTOGROUP_P256K1_SHA512, cat_CryptoGroup},

#ifndef MINGW
    { "CKM7CRYPTOGROUP-NUMSP256D1-SHA512", TECSEC_CKM7_CRYPTOGROUP_NUMSP256D1_SHA512, TS_ALG_CKM7_CRYPTOGROUP_NUMSP256D1_SHA512, cat_CryptoGroup },
    { "CKM7CRYPTOGROUP-NUMSP384D1-SHA512", TECSEC_CKM7_CRYPTOGROUP_NUMSP384D1_SHA512, TS_ALG_CKM7_CRYPTOGROUP_NUMSP384D1_SHA512, cat_CryptoGroup },
    { "CKM7CRYPTOGROUP-NUMSP512D1-SHA512", TECSEC_CKM7_CRYPTOGROUP_NUMSP512D1_SHA512, TS_ALG_CKM7_CRYPTOGROUP_NUMSP512D1_SHA512, cat_CryptoGroup },
    { "CKM7CRYPTOGROUP-NUMSP256T1-SHA512", TECSEC_CKM7_CRYPTOGROUP_NUMSP256T1_SHA512, TS_ALG_CKM7_CRYPTOGROUP_NUMSP256T1_SHA512, cat_CryptoGroup },
    { "CKM7CRYPTOGROUP-NUMSP384T1-SHA512", TECSEC_CKM7_CRYPTOGROUP_NUMSP384T1_SHA512, TS_ALG_CKM7_CRYPTOGROUP_NUMSP384T1_SHA512, cat_CryptoGroup },
    { "CKM7CRYPTOGROUP-NUMSP512T1-SHA512", TECSEC_CKM7_CRYPTOGROUP_NUMSP512T1_SHA512, TS_ALG_CKM7_CRYPTOGROUP_NUMSP512T1_SHA512, cat_CryptoGroup},
#endif 

    {"CKM7ATTRIBUTE-SYM", TECSEC_CKM7_ATTR_SYM, TS_ALG_CKM7_ATTRIBUTE_SYM,
     cat_Attribute},
    {"CKM7ATTRIBUTE-P256", TECSEC_CKM7_ATTR_P256, TS_ALG_CKM7_ATTRIBUTE_P256,
     cat_Attribute},
    {"CKM7ATTRIBUTE-P384", TECSEC_CKM7_ATTR_P384, TS_ALG_CKM7_ATTRIBUTE_P384,
     cat_Attribute},
    {"CKM7ATTRIBUTE-P521", TECSEC_CKM7_ATTR_P521, TS_ALG_CKM7_ATTRIBUTE_P521,
     cat_Attribute},
    {"CKM7ATTRIBUTE-X25519", TECSEC_CKM7_ATTR_X25519,
     TS_ALG_CKM7_ATTRIBUTE_X25519, cat_Attribute},
    { "CKM7ATTRIBUTE-P256K1", TECSEC_CKM7_ATTR_P256K1, TS_ALG_CKM7_ATTRIBUTE_P256K1, cat_Attribute},

    { "CKM7ATTRIBUTE-NUMSP256D1", TECSEC_CKM7_ATTR_NUMSP256D1, TS_ALG_CKM7_ATTRIBUTE_NUMSP256D1, cat_Attribute },
    { "CKM7ATTRIBUTE-NUMSP384D1", TECSEC_CKM7_ATTR_NUMSP384D1, TS_ALG_CKM7_ATTRIBUTE_NUMSP384D1, cat_Attribute },
    { "CKM7ATTRIBUTE-NUMSP512D1", TECSEC_CKM7_ATTR_NUMSP512D1, TS_ALG_CKM7_ATTRIBUTE_NUMSP512D1, cat_Attribute },
    { "CKM7ATTRIBUTE-NUMSP256T1", TECSEC_CKM7_ATTR_NUMSP256T1, TS_ALG_CKM7_ATTRIBUTE_NUMSP256T1, cat_Attribute },
    { "CKM7ATTRIBUTE-NUMSP384T1", TECSEC_CKM7_ATTR_NUMSP384T1, TS_ALG_CKM7_ATTRIBUTE_NUMSP384T1, cat_Attribute },
    { "CKM7ATTRIBUTE-NUMSP512T1", TECSEC_CKM7_ATTR_NUMSP512T1, TS_ALG_CKM7_ATTRIBUTE_NUMSP512T1, cat_Attribute},

    {"CKM7COMBINER", TECSEC_CKM7_OID, TS_ALG_CKM7, cat_Combiner},
    {"CKMAUTH_CALCULATOR-PBKDF2-SHA3-224", TECSEC_CKMAUTH_PBKDF_SHA3_224_OID,
     TS_ALG_CKMAUTH_PBKDF_SHA3_224, (CryptoAlgType)(cat_CkmAuth | cat_PbKdf)},
    {"CKMAUTH_CALCULATOR-PBKDF2-SHA3-256", TECSEC_CKMAUTH_PBKDF_SHA3_256_OID,
     TS_ALG_CKMAUTH_PBKDF_SHA3_256, (CryptoAlgType)(cat_CkmAuth | cat_PbKdf)},
    {"CKMAUTH_CALCULATOR-PBKDF2-SHA3-384", TECSEC_CKMAUTH_PBKDF_SHA3_384_OID,
     TS_ALG_CKMAUTH_PBKDF_SHA3_384, (CryptoAlgType)(cat_CkmAuth | cat_PbKdf)},
    {"CKMAUTH_CALCULATOR-PBKDF2-SHA3-512", TECSEC_CKMAUTH_PBKDF_SHA3_512_OID,
     TS_ALG_CKMAUTH_PBKDF_SHA3_512, (CryptoAlgType)(cat_CkmAuth | cat_PbKdf)},
};

class AlgorithmList : public tscrypto::IAlgorithmList, public tscrypto::ICryptoObject
{
public:
    AlgorithmList(std::shared_ptr<IAlgorithmListManager> mgr) : _mgr(mgr), _currentIndex(-1)
    {}
    virtual ~AlgorithmList()
    {}

    void AddIndex(size_t value)
    {
        _indexes.push_back(value);
    }

    // Inherited via IAlgorithmList
    virtual size_t count() const override
    {
        return _indexes.size();
    }
    virtual bool next() override
    {
        _currentIndex++;

        if (_currentIndex >= (ptrdiff_t)count())
        {
            _currentIndex = count();
            return false;
        }
        return true;
    }
    virtual bool restart() override
    {
        _currentIndex = -1;
        return true;
    }
    virtual TS_ALG_ID algId() const override
    {
        if (_currentIndex >= (ptrdiff_t)count())
            return TS_ALG_INVALID;
        return _mgr->algId(_indexes[_currentIndex]);
    }
    virtual tsCryptoString oid() const override
    {
        if (_currentIndex >= (ptrdiff_t)count())
            return "";
        return _mgr->oid(_indexes[_currentIndex]);
    }
    virtual tsCryptoString name() const override
    {
        if (_currentIndex >= (ptrdiff_t)count())
            return "";
        return _mgr->name(_indexes[_currentIndex]);
    }
    virtual CryptoAlgType algFlags() const override
    {
        if (_currentIndex >= (ptrdiff_t)count())
            return (CryptoAlgType)0;
        return _mgr->algFlags(_indexes[_currentIndex]);
    }
    virtual TS_ALG_ID algId(size_t index) const override
    {
        if (index >= count())
            return TS_ALG_INVALID;
        return _mgr->algId(_indexes[index]);
    }
    virtual tsCryptoString oid(size_t index) const override
    {
        if (index >= count())
            return "";
        return _mgr->oid(_indexes[index]);
    }
    virtual tsCryptoString name(size_t index) const override
    {
        if (index >= count())
            return "";
        return _mgr->name(_indexes[index]);
    }
    virtual CryptoAlgType algFlags(size_t index) const override
    {
        if (index >= count())
            return (CryptoAlgType)0;
        return _mgr->algFlags(_indexes[index]);
    }

protected:
    std::shared_ptr<IAlgorithmListManager> _mgr;
    std::vector<size_t> _indexes;
    ptrdiff_t _currentIndex;
};

class AlgorithmListManager : public IAlgorithmListManagerWriter, public tscrypto::ICryptoObject
{
public:
    AlgorithmListManager()
    {
        // Prepopulate with the built in entries
        for (size_t i = 0; i < sizeof(_nameIdList) / sizeof(_nameIdList[0]); i++)
        {
            _algs.push_back(AlgNameToIdsForList(_nameIdList[i].algName, _nameIdList[i].algOid, _nameIdList[i].algId, _nameIdList[i].type));
        }
    }
    virtual ~AlgorithmListManager() {}

    // Inherited via IAlgorithmListManager
    virtual TS_ALG_ID algId(size_t index) const override
    {
        return _algs[index].algId;
    }
    virtual tsCryptoString oid(size_t index) const override
    {
        return _algs[index].algOid;
    }
    virtual tsCryptoString name(size_t index) const override
    {
        return _algs[index].algName;
    }
    virtual CryptoAlgType algFlags(size_t index) const override
    {
        return _algs[index].type;
    }
    virtual void RemoveAlgorithmById(TS_ALG_ID algId) override
    {
        _algs.erase(std::remove_if(_algs.begin(), _algs.end(), [algId](AlgNameToIdsForList& entry) {
            return entry.algId == algId;
        }), _algs.end());
    }
    virtual void RemoveAlgorithmByOid(const tsCryptoStringBase & oid) override
    {
        _algs.erase(std::remove_if(_algs.begin(), _algs.end(), [oid](AlgNameToIdsForList& entry) {
            return entry.algOid == oid;
        }), _algs.end());
    }
    virtual void RemoveAlgorithmByOid(const tsCryptoData & oid) override
    {
        tsCryptoString oidStr = oid.ToOIDString();
        _algs.erase(std::remove_if(_algs.begin(), _algs.end(), [oidStr](AlgNameToIdsForList& entry) {
            return entry.algOid == oidStr;
        }), _algs.end());
    }
    virtual void RemoveAlgorithmByName(const tsCryptoStringBase & name) override
    {
        _algs.erase(std::remove_if(_algs.begin(), _algs.end(), [name](AlgNameToIdsForList& entry) {
            return entry.algName == name;
        }), _algs.end());
    }
    virtual bool AddAlgorithm(TS_ALG_ID algId, const tsCryptoStringBase & oid, const tsCryptoStringBase & name, CryptoAlgType algFlags) override
    {
        RemoveAlgorithmById(algId);
        _algs.push_back(AlgNameToIdsForList(name, oid, algId, algFlags));
        return true;
    }
    virtual size_t size() const override
    {
        return _algs.size();
    }
    virtual std::shared_ptr<tscrypto::IAlgorithmList> GetAlgorithmList(CryptoAlgType flags, bool matchAllFlags) override
    {
        std::shared_ptr<AlgorithmList> algList = CryptoLocator()->Finish<AlgorithmList>(new AlgorithmList(std::dynamic_pointer_cast<IAlgorithmListManager>(_me.lock())));

        if (flags == (CryptoAlgType)0)
        {
            // Match all
            for (size_t i = 0; i < size(); i++)
            {
                algList->AddIndex(i);
            }
        }
        else
        {
            for (size_t i = 0; i < size(); i++)
            {
                if (matchAllFlags)
                {
                    if ((_algs[i].type & flags) == flags)
                    {
                        algList->AddIndex(i);
                    }
                }
                else
                {
                    if ((_algs[i].type & flags) != (CryptoAlgType)0)
                    {
                        algList->AddIndex(i);
                    }
                }
            }
        }
        return std::dynamic_pointer_cast<tscrypto::IAlgorithmList>(algList);
    }
    virtual TS_ALG_ID LookUpAlgID(const tsCryptoStringBase& algName) const override
    {
        tsCryptoString tmpAlgName(algName);

        for (int i = 0; i < (int)size(); i++)
        {
            if (TsStriCmp(_algs[i].algName, tmpAlgName) == 0)
            {
                return _algs[i].algId;
            }
        }
        return TS_ALG_INVALID;
    }
    virtual tsCryptoString LookUpAlgOID(const tsCryptoStringBase& algName) const override
    {
        tsCryptoString id;
        tsCryptoString tmpAlgName(algName);

        for (int i = 0; i < (int)size(); i++)
        {
            if (TsStriCmp(_algs[i].algName, tmpAlgName) == 0)
            {
                return _algs[i].algOid;
            }
        }
        return "";
    }
    virtual tsCryptoString OIDtoAlgName(const tsCryptoStringBase& oid) const override
    {
        tsCryptoString name;
        tsCryptoString tmpOid(oid);

        for (int i = 0; i < (int)size(); i++)
        {
            if (TsStriCmp(_algs[i].algOid, tmpOid) == 0)
            {
                return _algs[i].algName;
            }
        }
        return "";
    }
    virtual TS_ALG_ID OIDtoID(const tsCryptoStringBase& OID) const override
    {
        tsCryptoString tmpOid(OID);

        for (int i = 0; i < (int)size(); i++)
        {
            if (TsStriCmp(_algs[i].algOid, tmpOid) == 0)
            {
                return _algs[i].algId;
            }
        }
        return TS_ALG_INVALID;
    }
    virtual tsCryptoString IDtoOID(TS_ALG_ID id) const override
    {
        tsCryptoString oid;
        for (int i = 0; i < (int)size(); i++)
        {
            if (_algs[i].algId == id)
            {
                return _algs[i].algOid;
            }
        }
        return "";
    }


protected:
    typedef struct AlgNameToIdsForList
    {
        AlgNameToIdsForList(const tsCryptoString& name, const tsCryptoString& oid, TS_ALG_ID alg, CryptoAlgType tp) :
            algName(name), algOid(oid), algId(alg), type(tp)
        {}
        AlgNameToIdsForList(const AlgNameToIdsForList& obj) :
            algName(obj.algName), algOid(obj.algOid), algId(obj.algId), type(obj.type)
        {
        }
        AlgNameToIdsForList(AlgNameToIdsForList&& obj) :
            algName(std::move(obj.algName)), algOid(std::move(obj.algOid)), algId(obj.algId), type(obj.type)
        {
            obj.algId = TS_ALG_INVALID;
            obj.type = (CryptoAlgType)0;
        }
        AlgNameToIdsForList& operator=(const AlgNameToIdsForList& obj)
        {
            if (this != &obj)
            {
                algName = obj.algName;
                algOid = obj.algOid;
                algId = obj.algId;
                type = obj.type;
            }
            return *this;
        }
        AlgNameToIdsForList& operator=(AlgNameToIdsForList&& obj)
        {
            if (this != &obj)
            {
                algName = std::move(obj.algName);
                algOid = std::move(obj.algOid);
                algId = obj.algId;
                type = obj.type;
                obj.algId = TS_ALG_ID(0);
                obj.type = CryptoAlgType(0);
            }
            return *this;
        }
        tsCryptoString algName;
        tsCryptoString algOid;
        TS_ALG_ID algId;
        CryptoAlgType type;
    } AlgNameToIdsForList;
    std::vector<AlgNameToIdsForList> _algs;
};

tscrypto::ICryptoObject* CreateAlgorithmListManager()
{
    return dynamic_cast<tscrypto::ICryptoObject*>(new AlgorithmListManager());
}

std::shared_ptr<tscrypto::IAlgorithmList> tscrypto::GetAlgorithmList(CryptoAlgType flags, bool matchAllFlags)
{
    std::shared_ptr<IAlgorithmListManager> mgr = ::CryptoLocator()->get_instance<IAlgorithmListManager>("AlgorithmListManager");

    return mgr->GetAlgorithmList(flags, matchAllFlags);
}

TS_ALG_ID tscrypto::LookUpAlgID(const tsCryptoStringBase& algName)
{
    std::shared_ptr<IAlgorithmListManager> mgr = ::CryptoLocator()->get_instance<IAlgorithmListManager>("AlgorithmListManager");

    return mgr->LookUpAlgID(algName);
}

tsCryptoString tscrypto::LookUpAlgOID(const tsCryptoStringBase& algName)
{
    std::shared_ptr<IAlgorithmListManager> mgr = ::CryptoLocator()->get_instance<IAlgorithmListManager>("AlgorithmListManager");

    return mgr->LookUpAlgOID(algName);
}

tsCryptoString tscrypto::OIDtoAlgName(const tsCryptoStringBase& oid)
{
    std::shared_ptr<IAlgorithmListManager> mgr = ::CryptoLocator()->get_instance<IAlgorithmListManager>("AlgorithmListManager");

    return mgr->OIDtoAlgName(oid);
}

TS_ALG_ID tscrypto::OIDtoID(const tsCryptoStringBase& OID)
{
    std::shared_ptr<IAlgorithmListManager> mgr = ::CryptoLocator()->get_instance<IAlgorithmListManager>("AlgorithmListManager");

    return mgr->OIDtoID(OID);
}

tsCryptoString tscrypto::IDtoOID(TS_ALG_ID id)
{
    std::shared_ptr<IAlgorithmListManager> mgr = ::CryptoLocator()->get_instance<IAlgorithmListManager>("AlgorithmListManager");

    return mgr->IDtoOID(id);
}

std::shared_ptr<tscrypto::ICryptoObject> tscrypto::CryptoFactory(const tsCryptoStringBase& nameOrOID)
{
    std::shared_ptr<tscrypto::ICryptoObject> obj;
    tsCryptoString name(nameOrOID);

    // First remove any parameters
    tsCryptoStringList parts = name.split(";", 2);
    name = parts->at(0);

    if (name[0] >= '0' && name[0] <= '9')
    {
        name = OIDtoAlgName(name);
    }
    // If there are any parameters, add them back here
    if (parts->size() > 1)
        name.append(";").append(parts->at(1));

    if (!HasCryptoLocator())
        tscrypto::CryptoLocator();
    if (!HasCryptoLocator())
        return nullptr;

    if (!(obj = g_CryptoLocator->try_get_instance<tscrypto::ICryptoObject>(name)))
    {
        return nullptr;
    }
    else
        return obj;
}
std::shared_ptr<tscrypto::ICryptoObject> tscrypto::CryptoFactory(TS_ALG_ID alg)
{
    return (CryptoFactory(IDtoOID(alg)));
}
tsCryptoString tscrypto::GetAlgorithmNameByIndex(size_t index)
{
    std::shared_ptr<IAlgorithmListManager> mgr = ::CryptoLocator()->get_instance<IAlgorithmListManager>("AlgorithmListManager");

    if (index >= mgr->size())
    {
        return "";
    }
    return mgr->name(index);
}

std::shared_ptr<tscrypto::ICryptoObject> tscrypto::ConstructAlgorithmByIndex(size_t index)
{
    //    int algCount = 0, algOffset = 0;

    if (index >= GetAlgorithmCount())
    {
        return nullptr;
    }

    tsCryptoString algName = GetAlgorithmNameByIndex(index);
    std::shared_ptr<tscrypto::ICryptoObject> obj;

    do {
        obj = CryptoFactory(algName);
        if (!obj)
        {
            size_t posi = algName.rfind('-');

            if (posi == tsCryptoString::npos)
                return nullptr;
            algName.resize(posi);
        }
    } while (algName.size() > 0 && !obj);
    return obj;
}

size_t  tscrypto::GetAlgorithmCount()
{
    std::shared_ptr<IAlgorithmListManager> mgr = ::CryptoLocator()->get_instance<IAlgorithmListManager>("AlgorithmListManager");

    return mgr->size();
}

std::shared_ptr<TlvNode> tscrypto::MakeBitString(const tsCryptoData &data, uint8_t unusedBits, std::shared_ptr<TlvDocument>& doc)
{
    std::shared_ptr<TlvNode> node = doc->CreateTlvNode(0x03, 0);

    if (data.size() == 0)
    {
        node->InnerData(tsCryptoData((uint8_t)0));
        return node;
    }
    tsCryptoData data1(data);

    data1.insert(0, unusedBits);
    node->InnerData(data1);
    return node;
}

std::shared_ptr<TlvNode> tscrypto::MakeIntegerNode(const tsCryptoData &data, std::shared_ptr<TlvDocument>& doc)
{
    std::shared_ptr<TlvNode> node = doc->CreateTlvNode(0x02, 0);

    if (data.size() == 0)
    {
        node->InnerData(tsCryptoData((uint8_t)0));
        return node;
    }
    tsCryptoData data1(data);
    if ((data[0] & 0x80) != 0)
    {
        data1.insert(0, (uint8_t)0);
    }
    node->InnerData(data1);
    return node;
}

tsCryptoData tscrypto::AdjustASN1Number(tsCryptoData data)
{
    if ((data.size() > 1 && data[0] == 0 && (data[1] & 0x80) != 0) || (data.size() == 1 && data[0] == 0))
        data.erase(0, 1);
    return data;
}

tsCryptoData tscrypto::AdjustBitString(tsCryptoData data)
{
    if (data.size() < 1)
        return data;

    uint8_t unused = data[0];
    data.erase(0, 1);

    if (unused > 7)
    {
        data.resize(data.size() - (unused / 8));
    }
    return data;
}

bool tscrypto::IsSequenceOID(const std::shared_ptr<TlvNode>& node, const tsCryptoData &oid)
{
    if (!node || node->Tag() != TlvNode::Tlv_Sequence || node->Type() != TlvNode::Type_Universal || !node->IsConstructed() || node->ChildCount() < 1 || node->ChildCount() > 2)
        return false;
    std::shared_ptr<TlvNode> node1 = node->ChildAt(0);
    if (node1->Tag() != TlvNode::Tlv_OID || node1->Type() != TlvNode::Type_Universal || node1->InnerData() != oid)
        return false;
    return true;
}

void tscrypto::TSGuidToString(const GUID &id, tscrypto::tsCryptoStringBase &out)  // taken from RTE guid_functions.cpp
{
    unsigned char * pStr;

    pStr = (unsigned char *)&id;
    out.Format("{%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        pStr[3], pStr[2], pStr[1], pStr[0], pStr[5], pStr[4], pStr[7], pStr[6], pStr[8], pStr[9],
        pStr[10], pStr[11], pStr[12], pStr[13], pStr[14], pStr[15]);
    return;
}

tsCryptoString tscrypto::TSGuidToString(const GUID &id)
{
    tscrypto::tsCryptoString tmp;

    tscrypto::TSGuidToString(id, tmp);
    return tmp;
}


void tscrypto::AddKeySizeFunction(std::function<bool(TS_ALG_ID AlgID, size_t& pVal)> fn)
{
    gKeySizeFuncs.push_back(fn);
}
void tscrypto::AddAlg2ModeFunction(std::function<bool(TS_ALG_ID AlgID, SymmetricMode& pVal)> fn)
{
    gModeFuncs.push_back(fn);
}
void tscrypto::AddAlg2KeyTypeFunction(std::function<bool(TS_ALG_ID AlgID, KeyType& pVal)> fn)
{
    gKeyTypeFuncs.push_back(fn);
}
void tscrypto::AddBlockSizeFunction(std::function<bool(TS_ALG_ID AlgID, size_t& pVal)> fn)
{
    gBlockSizeFuncs.push_back(fn);
}
void tscrypto::AddIVECSizeFunction(std::function<bool(TS_ALG_ID AlgID, size_t& pVal)> fn)
{
    gIVECSizeFuncs.push_back(fn);
}
void tscrypto::AddSignNameFunction(std::function<tsCryptoString(TS_ALG_ID signAlgorithm)> fn)
{
    gSignNameFuncs.push_back(fn);
}

size_t tscrypto::CryptoKeySize(TS_ALG_ID AlgID)
{
    for (auto& fn : gKeySizeFuncs)
    {
        size_t size;

        if (fn(AlgID, size))
            return size;
    }
    switch (AlgID)
    {
    case TS_ALG_DES_CBC:
    case TS_ALG_DES_ECB:
    case TS_ALG_DES_CTR:
        return 64;

    case TS_ALG_DES3_TWOKEY_CBC:
    case TS_ALG_DES3_TWOKEY_ECB:
    case TS_ALG_DES3_TWOKEY_CTR:
    case TS_ALG_DES3_TWOKEY_OFB:
    case TS_ALG_DES3_TWOKEY_CFB8:
    case TS_ALG_DES3_TWOKEY_CFB64:
        return 128;

    case TS_ALG_DES3_THREEKEY_CBC:
    case TS_ALG_DES3_THREEKEY_ECB:
    case TS_ALG_DES3_THREEKEY_CTR:
    case TS_ALG_DES3_THREEKEY_OFB:
    case TS_ALG_DES3_THREEKEY_CFB8:
    case TS_ALG_DES3_THREEKEY_CFB64:
    case TS_ALG_CMAC_TDES:
    case TS_ALG_KEYWRAP_TDES:
        return 192;

    case TS_ALG_AES_CBC_256:
    case TS_ALG_AES_ECB_256:
    case TS_ALG_AES_CTR:
    case TS_ALG_TSAES_CBC_256:
    case TS_ALG_TSAES_ECB_256:
    case TS_ALG_AES_OFB_256:
    case TS_ALG_TSAES_OFB_256:
    case TS_ALG_AES_CFB8_256:
    case TS_ALG_TSAES_CFB8_256:
    case TS_ALG_AES_CFB128_256:
    case TS_ALG_TSAES_CFB128_256:
    case TS_ALG_TSAES_CTR_256:
    case TS_ALG_AES_CCM_256:
    case TS_ALG_TSAES_CCM_256:
    case TS_ALG_AES_GCM_256:
    case TS_ALG_TSAES_GCM_256:
    case TS_ALG_CMAC_AES256:
    case TS_ALG_CMAC_TSAES256:
    case TS_ALG_KEYWRAP_AES256:
    case TS_ALG_KEYWRAP_TSAES256:
    case TS_ALG_AES_XTS_256:
    case TS_ALG_CAMELLIA_CBC_256:
    case TS_ALG_CAMELLIA_ECB_256:
    case TS_ALG_CAMELLIA_CTR:
    case TS_ALG_CAMELLIA_OFB_256:
    case TS_ALG_CAMELLIA_CFB8_256:
    case TS_ALG_CAMELLIA_CFB128_256:
    case TS_ALG_CAMELLIA_CCM_256:
    case TS_ALG_CAMELLIA_GCM_256:
    case TS_ALG_CAMELLIA_XTS_256:
    case TS_ALG_CMAC_CAMELLIA256:
    case TS_ALG_KEYWRAP_CAMELLIA256:

    case TS_ALG_ARIA_CBC_256:
    case TS_ALG_ARIA_ECB_256:
    case TS_ALG_ARIA_CTR:
    case TS_ALG_ARIA_OFB_256:
    case TS_ALG_ARIA_CFB8_256:
    case TS_ALG_ARIA_CFB128_256:
    case TS_ALG_ARIA_CCM_256:
    case TS_ALG_ARIA_GCM_256:
    case TS_ALG_ARIA_XTS_256:
    case TS_ALG_CMAC_ARIA256:
    case TS_ALG_KEYWRAP_ARIA256:
    case TS_ALG_SALSA20:
    case TS_ALG_XSALSA20:
    case TS_ALG_CHACHA20:
    case TS_ALG_CHACHA20_POLY1305:
        return 256;

    case TS_ALG_AES_CBC_192:
    case TS_ALG_AES_ECB_192:
    case TS_ALG_AES_CTR_192:
    case TS_ALG_TSAES_CBC_192:
    case TS_ALG_TSAES_ECB_192:
    case TS_ALG_AES_OFB_192:
    case TS_ALG_TSAES_OFB_192:
    case TS_ALG_AES_CFB8_192:
    case TS_ALG_TSAES_CFB8_192:
    case TS_ALG_AES_CFB128_192:
    case TS_ALG_TSAES_CFB128_192:
    case TS_ALG_TSAES_CTR_192:
    case TS_ALG_AES_CCM_192:
    case TS_ALG_TSAES_CCM_192:
    case TS_ALG_AES_GCM_192:
    case TS_ALG_TSAES_GCM_192:
    case TS_ALG_CMAC_AES192:
    case TS_ALG_CMAC_TSAES192:
    case TS_ALG_KEYWRAP_AES192:
    case TS_ALG_KEYWRAP_TSAES192:

    case TS_ALG_AES_XTS_192:
    case TS_ALG_CAMELLIA_CBC_192:
    case TS_ALG_CAMELLIA_ECB_192:
    case TS_ALG_CAMELLIA_CTR_192:
    case TS_ALG_CAMELLIA_OFB_192:
    case TS_ALG_CAMELLIA_CFB8_192:
    case TS_ALG_CAMELLIA_CFB128_192:
    case TS_ALG_CAMELLIA_CCM_192:
    case TS_ALG_CAMELLIA_GCM_192:
    case TS_ALG_CAMELLIA_XTS_192:
    case TS_ALG_CMAC_CAMELLIA192:
    case TS_ALG_KEYWRAP_CAMELLIA192:

    case TS_ALG_ARIA_CBC_192:
    case TS_ALG_ARIA_ECB_192:
    case TS_ALG_ARIA_CTR_192:
    case TS_ALG_ARIA_OFB_192:
    case TS_ALG_ARIA_CFB8_192:
    case TS_ALG_ARIA_CFB128_192:
    case TS_ALG_ARIA_CCM_192:
    case TS_ALG_ARIA_GCM_192:
    case TS_ALG_ARIA_XTS_192:
    case TS_ALG_CMAC_ARIA192:
    case TS_ALG_KEYWRAP_ARIA192:
        return 192;

    case TS_ALG_AES_CBC_128:
    case TS_ALG_AES_ECB_128:
    case TS_ALG_AES_CTR_128:
    case TS_ALG_TSAES_CBC_128:
    case TS_ALG_TSAES_ECB_128:
    case TS_ALG_AES_OFB_128:
    case TS_ALG_TSAES_OFB_128:
    case TS_ALG_AES_CFB8_128:
    case TS_ALG_TSAES_CFB8_128:
    case TS_ALG_AES_CFB128_128:
    case TS_ALG_TSAES_CFB128_128:
    case TS_ALG_TSAES_CTR_128:
    case TS_ALG_AES_CCM_128:
    case TS_ALG_TSAES_CCM_128:
    case TS_ALG_AES_GCM_128:
    case TS_ALG_TSAES_GCM_128:
    case TS_ALG_CMAC_AES128:
    case TS_ALG_CMAC_TSAES128:
    case TS_ALG_KEYWRAP_AES128:
    case TS_ALG_KEYWRAP_TSAES128:

    case TS_ALG_AES_XTS_128:

    case TS_ALG_CAMELLIA_CBC_128:
    case TS_ALG_CAMELLIA_ECB_128:
    case TS_ALG_CAMELLIA_CTR_128:
    case TS_ALG_CAMELLIA_OFB_128:
    case TS_ALG_CAMELLIA_CFB8_128:
    case TS_ALG_CAMELLIA_CFB128_128:
    case TS_ALG_CAMELLIA_CCM_128:
    case TS_ALG_CAMELLIA_GCM_128:
    case TS_ALG_CAMELLIA_XTS_128:
    case TS_ALG_CMAC_CAMELLIA128:
    case TS_ALG_KEYWRAP_CAMELLIA128:

    case TS_ALG_ARIA_CBC_128:
    case TS_ALG_ARIA_ECB_128:
    case TS_ALG_ARIA_CTR_128:
    case TS_ALG_ARIA_OFB_128:
    case TS_ALG_ARIA_CFB8_128:
    case TS_ALG_ARIA_CFB128_128:
    case TS_ALG_ARIA_CCM_128:
    case TS_ALG_ARIA_GCM_128:
    case TS_ALG_ARIA_XTS_128:
    case TS_ALG_CMAC_ARIA128:
    case TS_ALG_KEYWRAP_ARIA128:

    case TS_ALG_SEED_CBC_128:
    case TS_ALG_SEED_ECB_128:
    case TS_ALG_SEED_CTR_128:
    case TS_ALG_SEED_OFB_128:
    case TS_ALG_SEED_CFB8_128:
    case TS_ALG_SEED_CFB128_128:
    case TS_ALG_SEED_CCM_128:
    case TS_ALG_SEED_GCM_128:
    case TS_ALG_SEED_XTS_128:
    case TS_ALG_CMAC_SEED128:
    case TS_ALG_KEYWRAP_SEED128:
        return 128;

    case TS_ALG_RC2_ECB:
    case TS_ALG_RC2_CBC:
    case TS_ALG_RC2_CTR:
    case TS_ALG_RC2_OFB:
    case TS_ALG_RC2_CFB8:
    case TS_ALG_RC2_CFB64:
    case TS_ALG_RC2_128_ECB:
    case TS_ALG_RC2_128_CBC:
    case TS_ALG_RC2_128_CTR:
    case TS_ALG_RC2_128_OFB:
    case TS_ALG_RC2_128_CFB8:
    case TS_ALG_RC2_128_CFB64:
        return 128 * 8;

    case TS_ALG_RC4:
        return 256 * 8;
        //case TS_ALG_PSQUARED               :
        //    keySize = 449;
        //    break;

    default:
        return 0;
    }
}

SymmetricMode tscrypto::Alg2Mode(TS_ALG_ID AlgID)
{
    for (auto& fn : gModeFuncs)
    {
        SymmetricMode mode;

        if (fn(AlgID, mode))
            return mode;
    }
    switch (AlgID)
    {
    case TS_ALG_AES_GCM_256:
    case TS_ALG_TSAES_GCM_256:
    case TS_ALG_AES_GCM_192:
    case TS_ALG_TSAES_GCM_192:
    case TS_ALG_AES_GCM_128:
    case TS_ALG_TSAES_GCM_128:

    case TS_ALG_CAMELLIA_GCM_256:
    case TS_ALG_CAMELLIA_GCM_192:
    case TS_ALG_CAMELLIA_GCM_128:

    case TS_ALG_CHACHA20_POLY1305:
    case TS_ALG_ARIA_GCM_256:
    case TS_ALG_ARIA_GCM_192:
    case TS_ALG_ARIA_GCM_128:

    case TS_ALG_SEED_GCM_128:
        return _SymmetricMode::CKM_SymMode_GCM;

    case TS_ALG_AES_CCM_256:
    case TS_ALG_TSAES_CCM_256:
    case TS_ALG_AES_CCM_192:
    case TS_ALG_TSAES_CCM_192:
    case TS_ALG_AES_CCM_128:
    case TS_ALG_TSAES_CCM_128:

    case TS_ALG_CAMELLIA_CCM_256:
    case TS_ALG_CAMELLIA_CCM_192:
    case TS_ALG_CAMELLIA_CCM_128:

    case TS_ALG_ARIA_CCM_256:
    case TS_ALG_ARIA_CCM_192:
    case TS_ALG_ARIA_CCM_128:

    case TS_ALG_SEED_CCM_128:
        return _SymmetricMode::CKM_SymMode_CCM;

    case TS_ALG_AES_XTS_256:
    case TS_ALG_AES_XTS_192:
    case TS_ALG_AES_XTS_128:

    case TS_ALG_CAMELLIA_XTS_256:
    case TS_ALG_CAMELLIA_XTS_192:
    case TS_ALG_CAMELLIA_XTS_128:

    case TS_ALG_ARIA_XTS_256:
    case TS_ALG_ARIA_XTS_192:
    case TS_ALG_ARIA_XTS_128:

    case TS_ALG_SEED_XTS_128:
        return _SymmetricMode::CKM_SymMode_XTS;

    case TS_ALG_DES_CBC:
    case TS_ALG_DES3_TWOKEY_CBC:
    case TS_ALG_DES3_THREEKEY_CBC:
    case TS_ALG_CMAC_TDES:
    case TS_ALG_CMAC_BLOWFISH:
    case TS_ALG_CMAC_XTEA:
    case TS_ALG_AES_CBC_256:
    case TS_ALG_TSAES_CBC_256:
    case TS_ALG_AES_CBC_192:
    case TS_ALG_TSAES_CBC_192:
    case TS_ALG_AES_CBC_128:
    case TS_ALG_CMAC_AES256:
    case TS_ALG_CMAC_TSAES256:
    case TS_ALG_CMAC_AES192:
    case TS_ALG_CMAC_TSAES192:
    case TS_ALG_CMAC_AES128:
    case TS_ALG_CMAC_TSAES128:
    case TS_ALG_RC2_CBC:
    case TS_ALG_TSAES_CBC_128:
    case TS_ALG_BLOWFISH_CBC:
    case TS_ALG_XTEA_CBC:
    case TS_ALG_RC2_128_CBC:

    case TS_ALG_CAMELLIA_CBC_256:
    case TS_ALG_CAMELLIA_CBC_192:
    case TS_ALG_CAMELLIA_CBC_128:
    case TS_ALG_CMAC_CAMELLIA256:
    case TS_ALG_CMAC_CAMELLIA192:
    case TS_ALG_CMAC_CAMELLIA128:

    case TS_ALG_ARIA_CBC_256:
    case TS_ALG_ARIA_CBC_192:
    case TS_ALG_ARIA_CBC_128:
    case TS_ALG_CMAC_ARIA256:
    case TS_ALG_CMAC_ARIA192:
    case TS_ALG_CMAC_ARIA128:

    case TS_ALG_SEED_CBC_128:
    case TS_ALG_CMAC_SEED128:
        return _SymmetricMode::CKM_SymMode_CBC;

    case TS_ALG_DES_ECB:
    case TS_ALG_DES3_TWOKEY_ECB:
    case TS_ALG_DES3_THREEKEY_ECB:
    case TS_ALG_KEYWRAP_TDES:
    case TS_ALG_KEYWRAP_BLOWFISH:
    case TS_ALG_KEYWRAP_XTEA:
    case TS_ALG_TSAES_ECB_256:
    case TS_ALG_KEYWRAP_AES256:
    case TS_ALG_KEYWRAP_TSAES256:
    case TS_ALG_KEYWRAP_AES192:
    case TS_ALG_KEYWRAP_TSAES192:
    case TS_ALG_AES_ECB_128:
    case TS_ALG_KEYWRAP_AES128:
    case TS_ALG_KEYWRAP_TSAES128:
    case TS_ALG_TSAES_ECB_128:
    case TS_ALG_AES_ECB_192:
    case TS_ALG_TSAES_ECB_192:
    case TS_ALG_RC4:
    case TS_ALG_RC2_ECB:
    case TS_ALG_RC2_128_ECB:
    case TS_ALG_AES_ECB_256:
    case TS_ALG_BLOWFISH_ECB:
    case TS_ALG_XTEA_ECB:

    case TS_ALG_SALSA20:
    case TS_ALG_XSALSA20:
    case TS_ALG_CHACHA20:

    case TS_ALG_KEYWRAP_CAMELLIA256:
    case TS_ALG_KEYWRAP_CAMELLIA192:
    case TS_ALG_KEYWRAP_CAMELLIA128:
    case TS_ALG_CAMELLIA_ECB_128:
    case TS_ALG_CAMELLIA_ECB_192:
    case TS_ALG_CAMELLIA_ECB_256:

    case TS_ALG_KEYWRAP_ARIA256:
    case TS_ALG_KEYWRAP_ARIA192:
    case TS_ALG_KEYWRAP_ARIA128:
    case TS_ALG_ARIA_ECB_128:
    case TS_ALG_ARIA_ECB_192:
    case TS_ALG_ARIA_ECB_256:

    case TS_ALG_KEYWRAP_SEED128:
    case TS_ALG_SEED_ECB_128:
        return _SymmetricMode::CKM_SymMode_ECB;

    case TS_ALG_DES_CTR:
    case TS_ALG_DES3_TWOKEY_CTR:
    case TS_ALG_DES3_THREEKEY_CTR:
    case TS_ALG_AES_CTR:
    case TS_ALG_TSAES_CTR_256:
    case TS_ALG_AES_CTR_192:
    case TS_ALG_TSAES_CTR_192:
    case TS_ALG_AES_CTR_128:
    case TS_ALG_TSAES_CTR_128:
    case TS_ALG_RC2_CTR:
    case TS_ALG_RC2_128_CTR:

    case TS_ALG_CAMELLIA_CTR:
    case TS_ALG_CAMELLIA_CTR_192:
    case TS_ALG_CAMELLIA_CTR_128:

    case TS_ALG_ARIA_CTR:
    case TS_ALG_ARIA_CTR_192:
    case TS_ALG_ARIA_CTR_128:

    case TS_ALG_SEED_CTR_128:
        return _SymmetricMode::CKM_SymMode_CTR;

    case TS_ALG_DES3_TWOKEY_OFB:
    case TS_ALG_DES3_THREEKEY_OFB:
    case TS_ALG_AES_OFB_256:
    case TS_ALG_TSAES_OFB_256:
    case TS_ALG_AES_OFB_192:
    case TS_ALG_TSAES_OFB_192:
    case TS_ALG_AES_OFB_128:
    case TS_ALG_TSAES_OFB_128:

    case TS_ALG_CAMELLIA_OFB_256:
    case TS_ALG_CAMELLIA_OFB_192:
    case TS_ALG_CAMELLIA_OFB_128:

    case TS_ALG_ARIA_OFB_256:
    case TS_ALG_ARIA_OFB_192:
    case TS_ALG_ARIA_OFB_128:

    case TS_ALG_SEED_OFB_128:

    case TS_ALG_RC2_OFB:
    case TS_ALG_RC2_128_OFB:
        return _SymmetricMode::CKM_SymMode_OFB;

    case TS_ALG_DES3_TWOKEY_CFB8:
    case TS_ALG_DES3_THREEKEY_CFB8:
    case TS_ALG_AES_CFB8_256:
    case TS_ALG_TSAES_CFB8_256:
    case TS_ALG_AES_CFB8_192:
    case TS_ALG_TSAES_CFB8_192:
    case TS_ALG_AES_CFB8_128:
    case TS_ALG_TSAES_CFB8_128:

    case TS_ALG_CAMELLIA_CFB8_256:
    case TS_ALG_CAMELLIA_CFB8_192:
    case TS_ALG_CAMELLIA_CFB8_128:

    case TS_ALG_ARIA_CFB8_256:
    case TS_ALG_ARIA_CFB8_192:
    case TS_ALG_ARIA_CFB8_128:

    case TS_ALG_SEED_CFB8_128:

    case TS_ALG_RC2_CFB8:
    case TS_ALG_RC2_128_CFB8:

        return _SymmetricMode::CKM_SymMode_CFB8;

    case TS_ALG_DES3_TWOKEY_CFB64:
    case TS_ALG_DES3_THREEKEY_CFB64:
    case TS_ALG_AES_CFB128_256:
    case TS_ALG_TSAES_CFB128_256:
    case TS_ALG_AES_CFB128_192:
    case TS_ALG_TSAES_CFB128_192:
    case TS_ALG_AES_CFB128_128:
    case TS_ALG_TSAES_CFB128_128:

    case TS_ALG_CAMELLIA_CFB128_256:
    case TS_ALG_CAMELLIA_CFB128_192:
    case TS_ALG_CAMELLIA_CFB128_128:

    case TS_ALG_ARIA_CFB128_256:
    case TS_ALG_ARIA_CFB128_192:
    case TS_ALG_ARIA_CFB128_128:

    case TS_ALG_SEED_CFB128_128:
    case TS_ALG_RC2_CFB64:
    case TS_ALG_RC2_128_CFB64:
        return _SymmetricMode::CKM_SymMode_CFBfull;

    case TS_ALG_PSQUARED:
    default:
        return _SymmetricMode::CKM_SymMode_ECB;
    }
}

KeyType tscrypto::Alg2KeyType(TS_ALG_ID AlgID)
{
    for (auto& fn : gKeyTypeFuncs)
    {
        KeyType type;

        if (fn(AlgID, type))
            return type;
    }
    switch (AlgID)
    {
    case TS_ALG_BLOWFISH_CBC:
    case TS_ALG_BLOWFISH_ECB:
    case TS_ALG_CMAC_BLOWFISH:
    case TS_ALG_KEYWRAP_BLOWFISH:
        return _KeyType::kt_BLOWFISH;

    case TS_ALG_XTEA_CBC:
    case TS_ALG_XTEA_ECB:
    case TS_ALG_CMAC_XTEA:
    case TS_ALG_KEYWRAP_XTEA:
        return _KeyType::kt_XTEA;

    case TS_ALG_DES_CBC:
    case TS_ALG_DES_ECB:
    case TS_ALG_DES_CTR:
        return _KeyType::kt_DES;

    case TS_ALG_DES3_TWOKEY_CBC:
    case TS_ALG_DES3_TWOKEY_ECB:
    case TS_ALG_DES3_TWOKEY_CTR:
    case TS_ALG_DES3_TWOKEY_OFB:
    case TS_ALG_DES3_TWOKEY_CFB8:
    case TS_ALG_DES3_TWOKEY_CFB64:
        return _KeyType::kt_DES2;

    case TS_ALG_DES3_THREEKEY_CBC:
    case TS_ALG_DES3_THREEKEY_ECB:
    case TS_ALG_DES3_THREEKEY_CTR:
    case TS_ALG_DES3_THREEKEY_OFB:
    case TS_ALG_DES3_THREEKEY_CFB8:
    case TS_ALG_DES3_THREEKEY_CFB64:
    case TS_ALG_CMAC_TDES:
    case TS_ALG_KEYWRAP_TDES:
        return _KeyType::kt_DES3;

    case TS_ALG_AES_CBC_256:
    case TS_ALG_AES_ECB_256:
    case TS_ALG_AES_CTR:
    case TS_ALG_TSAES_CBC_256:
    case TS_ALG_TSAES_ECB_256:
    case TS_ALG_AES_OFB_256:
    case TS_ALG_TSAES_OFB_256:
    case TS_ALG_AES_CFB8_256:
    case TS_ALG_TSAES_CFB8_256:
    case TS_ALG_AES_CFB128_256:
    case TS_ALG_TSAES_CFB128_256:
    case TS_ALG_TSAES_CTR_256:
    case TS_ALG_AES_CCM_256:
    case TS_ALG_TSAES_CCM_256:
    case TS_ALG_AES_GCM_256:
    case TS_ALG_TSAES_GCM_256:
    case TS_ALG_CMAC_AES256:
    case TS_ALG_CMAC_TSAES256:
    case TS_ALG_KEYWRAP_AES256:
    case TS_ALG_KEYWRAP_TSAES256:
    case TS_ALG_AES_CBC_192:
    case TS_ALG_AES_ECB_192:
    case TS_ALG_AES_CTR_192:
    case TS_ALG_TSAES_CBC_192:
    case TS_ALG_TSAES_ECB_192:
    case TS_ALG_AES_OFB_192:
    case TS_ALG_TSAES_OFB_192:
    case TS_ALG_AES_CFB8_192:
    case TS_ALG_TSAES_CFB8_192:
    case TS_ALG_AES_CFB128_192:
    case TS_ALG_TSAES_CFB128_192:
    case TS_ALG_TSAES_CTR_192:
    case TS_ALG_AES_CCM_192:
    case TS_ALG_TSAES_CCM_192:
    case TS_ALG_AES_GCM_192:
    case TS_ALG_TSAES_GCM_192:
    case TS_ALG_CMAC_AES192:
    case TS_ALG_CMAC_TSAES192:
    case TS_ALG_KEYWRAP_AES192:
    case TS_ALG_KEYWRAP_TSAES192:
    case TS_ALG_AES_CBC_128:
    case TS_ALG_AES_ECB_128:
    case TS_ALG_AES_CTR_128:
    case TS_ALG_TSAES_CBC_128:
    case TS_ALG_TSAES_ECB_128:
    case TS_ALG_AES_OFB_128:
    case TS_ALG_TSAES_OFB_128:
    case TS_ALG_AES_CFB8_128:
    case TS_ALG_TSAES_CFB8_128:
    case TS_ALG_AES_CFB128_128:
    case TS_ALG_TSAES_CFB128_128:
    case TS_ALG_TSAES_CTR_128:
    case TS_ALG_AES_CCM_128:
    case TS_ALG_TSAES_CCM_128:
    case TS_ALG_AES_GCM_128:
    case TS_ALG_TSAES_GCM_128:
    case TS_ALG_CMAC_AES128:
    case TS_ALG_CMAC_TSAES128:
    case TS_ALG_KEYWRAP_AES128:
    case TS_ALG_KEYWRAP_TSAES128:
    case TS_ALG_AES_XTS_256:
    case TS_ALG_AES_XTS_192:
    case TS_ALG_AES_XTS_128:
        return _KeyType::kt_AES;

    case TS_ALG_CAMELLIA_CBC_256:
    case TS_ALG_CAMELLIA_ECB_256:
    case TS_ALG_CAMELLIA_CTR:
    case TS_ALG_CAMELLIA_OFB_256:
    case TS_ALG_CAMELLIA_CFB8_256:
    case TS_ALG_CAMELLIA_CFB128_256:
    case TS_ALG_CAMELLIA_CCM_256:
    case TS_ALG_CAMELLIA_GCM_256:
    case TS_ALG_CAMELLIA_XTS_256:
    case TS_ALG_CMAC_CAMELLIA256:
    case TS_ALG_KEYWRAP_CAMELLIA256:
    case TS_ALG_CAMELLIA_CBC_192:
    case TS_ALG_CAMELLIA_ECB_192:
    case TS_ALG_CAMELLIA_CTR_192:
    case TS_ALG_CAMELLIA_OFB_192:
    case TS_ALG_CAMELLIA_CFB8_192:
    case TS_ALG_CAMELLIA_CFB128_192:
    case TS_ALG_CAMELLIA_CCM_192:
    case TS_ALG_CAMELLIA_GCM_192:
    case TS_ALG_CAMELLIA_XTS_192:
    case TS_ALG_CMAC_CAMELLIA192:
    case TS_ALG_KEYWRAP_CAMELLIA192:
    case TS_ALG_CAMELLIA_CBC_128:
    case TS_ALG_CAMELLIA_ECB_128:
    case TS_ALG_CAMELLIA_CTR_128:
    case TS_ALG_CAMELLIA_OFB_128:
    case TS_ALG_CAMELLIA_CFB8_128:
    case TS_ALG_CAMELLIA_CFB128_128:
    case TS_ALG_CAMELLIA_CCM_128:
    case TS_ALG_CAMELLIA_GCM_128:
    case TS_ALG_CAMELLIA_XTS_128:
    case TS_ALG_CMAC_CAMELLIA128:
    case TS_ALG_KEYWRAP_CAMELLIA128:
        return _KeyType::kt_CAMELLIA;

    case TS_ALG_ARIA_CBC_256:
    case TS_ALG_ARIA_ECB_256:
    case TS_ALG_ARIA_CTR:
    case TS_ALG_ARIA_OFB_256:
    case TS_ALG_ARIA_CFB8_256:
    case TS_ALG_ARIA_CFB128_256:
    case TS_ALG_ARIA_CCM_256:
    case TS_ALG_ARIA_GCM_256:
    case TS_ALG_ARIA_XTS_256:
    case TS_ALG_CMAC_ARIA256:
    case TS_ALG_KEYWRAP_ARIA256:
    case TS_ALG_ARIA_CBC_192:
    case TS_ALG_ARIA_ECB_192:
    case TS_ALG_ARIA_CTR_192:
    case TS_ALG_ARIA_OFB_192:
    case TS_ALG_ARIA_CFB8_192:
    case TS_ALG_ARIA_CFB128_192:
    case TS_ALG_ARIA_CCM_192:
    case TS_ALG_ARIA_GCM_192:
    case TS_ALG_ARIA_XTS_192:
    case TS_ALG_CMAC_ARIA192:
    case TS_ALG_KEYWRAP_ARIA192:
    case TS_ALG_ARIA_CBC_128:
    case TS_ALG_ARIA_ECB_128:
    case TS_ALG_ARIA_CTR_128:
    case TS_ALG_ARIA_OFB_128:
    case TS_ALG_ARIA_CFB8_128:
    case TS_ALG_ARIA_CFB128_128:
    case TS_ALG_ARIA_CCM_128:
    case TS_ALG_ARIA_GCM_128:
    case TS_ALG_ARIA_XTS_128:
    case TS_ALG_CMAC_ARIA128:
    case TS_ALG_KEYWRAP_ARIA128:
        return _KeyType::kt_ARIA;

    case TS_ALG_SEED_CBC_128:
    case TS_ALG_SEED_ECB_128:
    case TS_ALG_SEED_CTR_128:
    case TS_ALG_SEED_OFB_128:
    case TS_ALG_SEED_CFB8_128:
    case TS_ALG_SEED_CFB128_128:
    case TS_ALG_SEED_CCM_128:
    case TS_ALG_SEED_GCM_128:
    case TS_ALG_SEED_XTS_128:
    case TS_ALG_CMAC_SEED128:
    case TS_ALG_KEYWRAP_SEED128:
        return _KeyType::kt_SEED;

    case TS_ALG_RC2_CBC:
    case TS_ALG_RC2_ECB:
    case TS_ALG_RC2_CTR:
    case TS_ALG_RC2_OFB:
    case TS_ALG_RC2_CFB8:
    case TS_ALG_RC2_CFB64:
    case TS_ALG_RC2_128_CBC:
    case TS_ALG_RC2_128_ECB:
    case TS_ALG_RC2_128_CTR:
    case TS_ALG_RC2_128_OFB:
    case TS_ALG_RC2_128_CFB8:
    case TS_ALG_RC2_128_CFB64:
        return _KeyType::kt_RC2;

    case TS_ALG_RC4:
        return _KeyType::kt_RC4;

    case TS_ALG_SALSA20:
    case TS_ALG_XSALSA20:
        return _KeyType::kt_SALSA20;

    case TS_ALG_CHACHA20:
    case TS_ALG_CHACHA20_POLY1305:
        return _KeyType::kt_ChaCha20;

        //case TS_ALG_PSQUARED               :
        //    keySize = 449;
        //    break;

    default:
        return _KeyType::kt_UNKNOWN;
    }
}

size_t tscrypto::CryptoBlockSize(TS_ALG_ID AlgID)
{
    for (auto& fn : gBlockSizeFuncs)
    {
        size_t size;

        if (fn(AlgID, size))
            return size;
    }
    switch (AlgID)
    {
    case TS_ALG_DES_CBC:
    case TS_ALG_DES_ECB:
    case TS_ALG_DES3_TWOKEY_CBC:
    case TS_ALG_DES3_TWOKEY_ECB:
    case TS_ALG_DES3_TWOKEY_OFB:
    case TS_ALG_DES3_TWOKEY_CFB64:
    case TS_ALG_DES3_THREEKEY_CBC:
    case TS_ALG_DES3_THREEKEY_ECB:
    case TS_ALG_DES3_THREEKEY_CFB64:
    case TS_ALG_CMAC_TDES:
    case TS_ALG_KEYWRAP_TDES:
    case TS_ALG_BLOWFISH_CBC:
    case TS_ALG_BLOWFISH_ECB:
    case TS_ALG_CMAC_BLOWFISH:
    case TS_ALG_KEYWRAP_BLOWFISH:
    case TS_ALG_XTEA_CBC:
    case TS_ALG_XTEA_ECB:
    case TS_ALG_CMAC_XTEA:
    case TS_ALG_KEYWRAP_XTEA:
    case TS_ALG_RC2_CBC:
    case TS_ALG_RC2_ECB:
    case TS_ALG_RC2_CFB64:
    case TS_ALG_RC2_128_CBC:
    case TS_ALG_RC2_128_ECB:
    case TS_ALG_RC2_128_CFB64:
        return 8;

    case TS_ALG_AES_CBC_256:
    case TS_ALG_AES_ECB_256:
    case TS_ALG_TSAES_CBC_256:
    case TS_ALG_TSAES_ECB_256:
    case TS_ALG_AES_OFB_256:
    case TS_ALG_TSAES_OFB_256:
    case TS_ALG_AES_CFB128_256:
    case TS_ALG_TSAES_CFB128_256:
    case TS_ALG_AES_XTS_256:
    case TS_ALG_CMAC_AES256:
    case TS_ALG_CMAC_TSAES256:
    case TS_ALG_KEYWRAP_AES256:
    case TS_ALG_KEYWRAP_TSAES256:
    case TS_ALG_AES_CBC_192:
    case TS_ALG_AES_ECB_192:
    case TS_ALG_TSAES_CBC_192:
    case TS_ALG_TSAES_ECB_192:
    case TS_ALG_AES_OFB_192:
    case TS_ALG_TSAES_OFB_192:
    case TS_ALG_AES_CFB128_192:
    case TS_ALG_TSAES_CFB128_192:
    case TS_ALG_AES_XTS_192:
    case TS_ALG_CMAC_AES192:
    case TS_ALG_CMAC_TSAES192:
    case TS_ALG_KEYWRAP_AES192:
    case TS_ALG_KEYWRAP_TSAES192:
    case TS_ALG_AES_CBC_128:
    case TS_ALG_AES_ECB_128:
    case TS_ALG_TSAES_CBC_128:
    case TS_ALG_TSAES_ECB_128:
    case TS_ALG_AES_OFB_128:
    case TS_ALG_TSAES_OFB_128:
    case TS_ALG_AES_CFB128_128:
    case TS_ALG_TSAES_CFB128_128:
    case TS_ALG_AES_XTS_128:
    case TS_ALG_CMAC_AES128:
    case TS_ALG_CMAC_TSAES128:
    case TS_ALG_KEYWRAP_AES128:
    case TS_ALG_KEYWRAP_TSAES128:

    case TS_ALG_CAMELLIA_CBC_256:
    case TS_ALG_CAMELLIA_ECB_256:
    case TS_ALG_CAMELLIA_OFB_256:
    case TS_ALG_CAMELLIA_CFB128_256:
    case TS_ALG_CAMELLIA_XTS_256:
    case TS_ALG_CAMELLIA_CBC_192:
    case TS_ALG_CAMELLIA_ECB_192:
    case TS_ALG_CAMELLIA_OFB_192:
    case TS_ALG_CAMELLIA_CFB128_192:
    case TS_ALG_CAMELLIA_XTS_192:
    case TS_ALG_CAMELLIA_CBC_128:
    case TS_ALG_CAMELLIA_ECB_128:
    case TS_ALG_CAMELLIA_OFB_128:
    case TS_ALG_CAMELLIA_CFB128_128:
    case TS_ALG_CAMELLIA_XTS_128:
    case TS_ALG_CMAC_CAMELLIA256:
    case TS_ALG_CMAC_CAMELLIA192:
    case TS_ALG_CMAC_CAMELLIA128:
    case TS_ALG_KEYWRAP_CAMELLIA256:
    case TS_ALG_KEYWRAP_CAMELLIA192:
    case TS_ALG_KEYWRAP_CAMELLIA128:

    case TS_ALG_ARIA_CBC_256:
    case TS_ALG_ARIA_ECB_256:
    case TS_ALG_ARIA_OFB_256:
    case TS_ALG_ARIA_CFB128_256:
    case TS_ALG_ARIA_XTS_256:
    case TS_ALG_ARIA_CBC_192:
    case TS_ALG_ARIA_ECB_192:
    case TS_ALG_ARIA_OFB_192:
    case TS_ALG_ARIA_CFB128_192:
    case TS_ALG_ARIA_XTS_192:
    case TS_ALG_ARIA_CBC_128:
    case TS_ALG_ARIA_ECB_128:
    case TS_ALG_ARIA_OFB_128:
    case TS_ALG_ARIA_CFB128_128:
    case TS_ALG_ARIA_XTS_128:
    case TS_ALG_CMAC_ARIA256:
    case TS_ALG_CMAC_ARIA192:
    case TS_ALG_CMAC_ARIA128:
    case TS_ALG_KEYWRAP_ARIA256:
    case TS_ALG_KEYWRAP_ARIA192:
    case TS_ALG_KEYWRAP_ARIA128:

    case TS_ALG_SEED_CBC_128:
    case TS_ALG_SEED_ECB_128:
    case TS_ALG_SEED_OFB_128:
    case TS_ALG_SEED_CFB128_128:
    case TS_ALG_SEED_XTS_128:
    case TS_ALG_CMAC_SEED128:
    case TS_ALG_KEYWRAP_SEED128:
        return 16;

    case TS_ALG_DES_CTR:
    case TS_ALG_DES3_TWOKEY_CTR:
    case TS_ALG_DES3_TWOKEY_CFB8:
    case TS_ALG_DES3_THREEKEY_CTR:
    case TS_ALG_DES3_THREEKEY_OFB:
    case TS_ALG_DES3_THREEKEY_CFB8:
    case TS_ALG_AES_CCM_256:
    case TS_ALG_TSAES_CCM_256:
    case TS_ALG_AES_GCM_256:
    case TS_ALG_TSAES_GCM_256:
    case TS_ALG_AES_CCM_192:
    case TS_ALG_TSAES_CCM_192:
    case TS_ALG_AES_GCM_192:
    case TS_ALG_TSAES_GCM_192:
    case TS_ALG_AES_CCM_128:
    case TS_ALG_TSAES_CCM_128:
    case TS_ALG_AES_GCM_128:
    case TS_ALG_TSAES_GCM_128:
    case TS_ALG_AES_CTR:
    case TS_ALG_AES_CFB8_256:
    case TS_ALG_TSAES_CFB8_256:
    case TS_ALG_TSAES_CTR_256:
    case TS_ALG_AES_CTR_192:
    case TS_ALG_AES_CFB8_192:
    case TS_ALG_TSAES_CFB8_192:
    case TS_ALG_TSAES_CTR_192:
    case TS_ALG_AES_CTR_128:
    case TS_ALG_AES_CFB8_128:
    case TS_ALG_TSAES_CFB8_128:
    case TS_ALG_TSAES_CTR_128:
    case TS_ALG_RC4:
    case TS_ALG_SALSA20:
    case TS_ALG_XSALSA20:
    case TS_ALG_CHACHA20:

    case TS_ALG_CAMELLIA_CCM_256:
    case TS_ALG_CAMELLIA_GCM_256:
    case TS_ALG_CAMELLIA_CCM_192:
    case TS_ALG_CAMELLIA_GCM_192:
    case TS_ALG_CAMELLIA_CCM_128:
    case TS_ALG_CAMELLIA_GCM_128:
    case TS_ALG_CAMELLIA_CTR:
    case TS_ALG_CAMELLIA_CFB8_256:
    case TS_ALG_CAMELLIA_CTR_192:
    case TS_ALG_CAMELLIA_CFB8_192:
    case TS_ALG_CAMELLIA_CTR_128:
    case TS_ALG_CAMELLIA_CFB8_128:

    case TS_ALG_ARIA_CCM_256:
    case TS_ALG_ARIA_GCM_256:
    case TS_ALG_ARIA_CCM_192:
    case TS_ALG_ARIA_GCM_192:
    case TS_ALG_ARIA_CCM_128:
    case TS_ALG_ARIA_GCM_128:
    case TS_ALG_ARIA_CTR:
    case TS_ALG_ARIA_CFB8_256:
    case TS_ALG_ARIA_CTR_192:
    case TS_ALG_ARIA_CFB8_192:
    case TS_ALG_ARIA_CTR_128:
    case TS_ALG_ARIA_CFB8_128:

    case TS_ALG_SEED_CCM_128:
    case TS_ALG_SEED_GCM_128:
    case TS_ALG_SEED_CTR_128:
    case TS_ALG_SEED_CFB8_128:

    case TS_ALG_RC2_OFB:
    case TS_ALG_RC2_CFB8:
    case TS_ALG_RC2_CTR:
    case TS_ALG_RC2_128_OFB:
    case TS_ALG_RC2_128_CFB8:
    case TS_ALG_RC2_128_CTR:

    case TS_ALG_CHACHA20_POLY1305:
        return 1;

    default:
    {
        std::shared_ptr<Symmetric> sym;

        if (!(sym = std::dynamic_pointer_cast<Symmetric>(CryptoFactory(AlgID))))
            return 0;

        return sym->getBlockSize();
    }
    }
}

size_t tscrypto::CryptoIVECSize(TS_ALG_ID AlgID)
{
    for (auto& fn : gIVECSizeFuncs)
    {
        size_t size;

        if (fn(AlgID, size))
            return size;
    }

    SymmetricMode mode = Alg2Mode(AlgID);

    switch (mode)
    {
    case _SymmetricMode::CKM_SymMode_ECB:
        return 0;
    case _SymmetricMode::CKM_SymMode_CBC:
    case _SymmetricMode::CKM_SymMode_CFB8:
    case _SymmetricMode::CKM_SymMode_CFBfull:
    case _SymmetricMode::CKM_SymMode_CTR:
    case _SymmetricMode::CKM_SymMode_OFB:
        return CryptoBlockSize(AlgID);
    case _SymmetricMode::CKM_SymMode_CCM:
        return 13;
    case _SymmetricMode::CKM_SymMode_GCM:
        return 12;
    case _SymmetricMode::CKM_SymMode_XTS:
        return 0;
    default:
        return 0;
    }
}

bool tscrypto::CryptoOperational()
{
    return gFipsState.operational();
}

void tscrypto::CryptoTestFailed()
{
    gFipsState.testFailed();
}

bool tscrypto::GenerateRandom(tsCryptoData& data, size_t lenInBytes)
{
	data.resize(lenInBytes);
	return internalGenerateRandomBits(data.rawData(), (uint32_t)(lenInBytes * 8), true, nullptr, 0);
}

bool tscrypto::GenerateRandom(uint8_t* data, size_t lenInBytes)
{
	return internalGenerateRandomBits(data, (uint32_t)(lenInBytes * 8), true, nullptr, 0);
}
#ifdef __cplusplus
extern "C"
#endif
bool generateARandomKeyValue(unsigned int length, unsigned char *data)
{
    return GenerateRandom(data, length);
}

bool tscrypto::TSHash(const tsCryptoData &data, HashDigest &hash, TS_ALG_ID AlgID)
{
    CryptoContext ctx;

    if (!TSIncrementalHashStart(ctx, AlgID) ||
        !TSIncrementalHash(data, ctx) ||
        !TSIncrementalHashFinish(ctx, hash))
        return false;
    return true;
}
bool tscrypto::TSHash(const tsCryptoData &data, HashDigest &hash, const char* AlgID)
{
    CryptoContext ctx;

    if (!TSIncrementalHashStart(ctx, AlgID) ||
        !TSIncrementalHash(data, ctx) ||
        !TSIncrementalHashFinish(ctx, hash))
        return false;
    return true;
}
bool tscrypto::TSHash(const uint8_t* data, size_t inLen, uint8_t* hash, size_t hashLen, TS_ALG_ID AlgID)
{
    tsCryptoData in(data, inLen);
    tsCryptoData h;

    if (hash == nullptr || !TSHash(in, h, AlgID))
        return false;
    memmove(hash, h.c_str(), MIN(h.size(), hashLen));
    return true;
}
bool tscrypto::TSHash(const uint8_t* data, size_t inLen, uint8_t* hash, size_t hashLen, const char* AlgID)
{
    tsCryptoData in(data, inLen);
    tsCryptoData h;

    if (hash == nullptr || !TSHash(in, h, AlgID))
        return false;
    memmove(hash, h.c_str(), MIN(h.size(), hashLen));
    return true;
}

bool tscrypto::TSIncrementalHashStart(CryptoContext &ctx, TS_ALG_ID AlgID)
{
    std::shared_ptr<Hash> hashAlg;

    if (!(hashAlg = std::dynamic_pointer_cast<Hash>(CryptoFactory(AlgID))))
        return false;

    if (!hashAlg->initialize())
        return false;

    ctx = std::dynamic_pointer_cast<tscrypto::ICryptoObject>(hashAlg);

    return true;
}

bool tscrypto::TSIncrementalHashStart(CryptoContext &ctx, const char* AlgID)
{
    std::shared_ptr<Hash> hashAlg;

    if (!(hashAlg = std::dynamic_pointer_cast<Hash>(CryptoFactory(AlgID))))
        return false;

    if (!hashAlg->initialize())
        return false;

    ctx = std::dynamic_pointer_cast<tscrypto::ICryptoObject>(hashAlg);

    return true;
}

bool tscrypto::TSIncrementalHash(const tsCryptoData &data, CryptoContext &ctx)
{
    std::shared_ptr<Hash> hashAlg;

    hashAlg = ctx.get<Hash>();
    if (!hashAlg)
        return false;

    if (data.size() < 1)
        return true;

    if (!hashAlg->update(data))
        return false;
    return true;
}
bool tscrypto::TSIncrementalHash(const uint8_t* data, size_t dataLen, CryptoContext &ctx)
{
    tsCryptoData dt(data, dataLen);

    return TSIncrementalHash(dt, ctx);
}
bool tscrypto::TSIncrementalHashFinish(CryptoContext &ctx, HashDigest &hash)
{
    std::shared_ptr<Hash> hashAlg;

    hashAlg = ctx.get<Hash>();
    if (!hashAlg)
        return false;

    if (!hashAlg->finish(hash))
        return false;

    return true;
}
bool tscrypto::TSIncrementalHashFinish(CryptoContext &ctx, uint8_t* hash, size_t hashLen)
{
    tsCryptoData h;

    if (hash == nullptr || !TSIncrementalHashFinish(ctx, h))
        return false;
    memmove(hash, h.c_str(), MIN(hashLen, h.size()));
    return true;
}

bool tscrypto::TSCreatePBEKeyAndMac(const tsCryptoStringBase& hmacName, const tsCryptoStringBase &Password, const tsCryptoData &seed,
    size_t Count, size_t KeyLen,
    tsCryptoData &Key, tsCryptoData &Mac)
{
    std::shared_ptr<PbKdf> pbkdf;

    if (!(pbkdf = std::dynamic_pointer_cast<PbKdf>(CryptoFactory("KDF-PBKDF2"))))
        return false;

    if (!pbkdf->PKCS5_PBKDF2_With_Mac(hmacName, tsCryptoData(Password), seed, Count, Key, (uint16_t)KeyLen, Mac))
        return false;
    return true;
}

bool tscrypto::TSCreatePBEKey(const tsCryptoStringBase& hmacName, const tsCryptoStringBase &Password, const tsCryptoData &seed,
    size_t Count, size_t KeyLen,
    tsCryptoData &Key)
{
    std::shared_ptr<PbKdf> pbkdf;

    if (!(pbkdf = std::dynamic_pointer_cast<PbKdf>(CryptoFactory("KDF-PBKDF2"))))
        return false;

    if (!pbkdf->PKCS5_PBKDF2(hmacName, tsCryptoData(Password), seed, Count, Key, (uint16_t)KeyLen))
        return false;
    return true;
}

bool tscrypto::SP800_108_Counter(const tsCryptoData &key, const tsCryptoData &Label, const tsCryptoData &Context,
    int bitSize, tsCryptoData &outputData, bool containsBitLength, int bytesOfBitLength, int32_t counterLocation, int counterByteLength,
    const tsCryptoStringBase &algorithm)
{
    std::shared_ptr<KeyDerivationFunction> kdf;

    if (!(kdf = std::dynamic_pointer_cast<KeyDerivationFunction>(CryptoFactory(algorithm))))
        return false;

    if (!kdf->initializeWithKey(key) || !kdf->Derive_SP800_108_Counter(containsBitLength, bytesOfBitLength, Label.size() > 0, counterLocation, counterByteLength,
        Label, Context, bitSize, outputData))
        return false;
    return true;
}

bool tscrypto::TSGenerateECCKeysByAlg(TS_ALG_ID alg, std::shared_ptr<EccKey>& keyPair)
{
    std::shared_ptr<EccKey> eccAlg;

    if (!(eccAlg = std::dynamic_pointer_cast<EccKey>(CryptoFactory(alg))))
    {
        return false;
    }
    if (!eccAlg->generateKeyPair())
        return false;
    keyPair = eccAlg;
    return true;
}
bool tscrypto::TSGenerateECCKeysByName(const tsCryptoStringBase& algName, std::shared_ptr<EccKey>& keyPair)
{
    std::shared_ptr<EccKey> eccAlg;

    if (!(eccAlg = std::dynamic_pointer_cast<EccKey>(CryptoFactory(algName))))
    {
        return false;
    }
    if (!eccAlg->generateKeyPair())
        return false;
    keyPair = eccAlg;
    return true;
}
bool tscrypto::TSGenerateECCKeysBySize(size_t bitSize, std::shared_ptr<EccKey>& keyPair)
{
    tsCryptoData oid;

    switch (bitSize)
    {
#ifdef SUPPORT_ECC_P192
    case 192:
        oid = tsCryptoData(NIST_P192_CURVE_OID, tsCryptoData::OID);
        break;
#endif
#ifdef SUPPORT_ECC_P224
    case 224:
        oid = tsCryptoData(NIST_P224_CURVE_OID, tsCryptoData::OID);
        break;
#endif
    case 255:
        oid = tsCryptoData(id_X25519, tsCryptoData::HEX);
        break;
    case 256:
        oid = tsCryptoData(SECP256R1_CURVE_OID, tsCryptoData::OID);
        break;
    case 384:
        oid = tsCryptoData(SECP384R1_CURVE_OID, tsCryptoData::OID);
        break;
    case 448:
        oid = tsCryptoData(id_X448, tsCryptoData::HEX);
        break;
    case 521:
        oid = tsCryptoData(SECP521R1_CURVE_OID, tsCryptoData::OID);
        break;
    default:
        return false;
    }
    if (!TSBuildEccKey(oid, keyPair))
        return false;

    if (!keyPair->generateKeyPair())
        return false;
    return true;
}

bool tscrypto::TSGenerateECCKeysBySize(size_t bitSize, tsCryptoData &PublicKey, tsCryptoData &PrivateKey)
{
    std::shared_ptr<EccKey> eccAlg;

    if (!TSGenerateECCKeysBySize(bitSize, eccAlg))
        return false;

    //
    // Build the public key blob (based on ECC Cert public key)
    //
    PrivateKey = eccAlg->toByteArray();
    PublicKey = eccAlg->get_Point();
    eccAlg->Clear();
    eccAlg->set_Point(PublicKey);
    if (!eccAlg->ValidateKeys())
        return false;
    PublicKey = eccAlg->toByteArray();

    return true;
}

bool tscrypto::TSBuildEccKey(const tsCryptoStringBase& keyName, std::shared_ptr<EccKey>& key)
{
    std::shared_ptr<EccKey> eccAlg;

    if (!(eccAlg = std::dynamic_pointer_cast<EccKey>(CryptoFactory(keyName))))
    {
        return false;
    }
    key = eccAlg;
    return true;
}

bool tscrypto::TSBuildEccKey(const tsCryptoData &keyOID, std::shared_ptr<EccKey>& key)
{
    std::shared_ptr<EccKey> eccAlg;

    if (!(eccAlg = std::dynamic_pointer_cast<EccKey>(CryptoFactory(keyOID.ToOIDString()))))
    {
        return false;
    }
    key = eccAlg;
    return true;
}

bool tscrypto::TSBuildECCKeyFromBlob(const tsCryptoData &blob, std::shared_ptr<EccKey>& key)
{
    std::shared_ptr<EccKey> eccAlg;
    tsCryptoString oidStr;

    if (!TSBuildEccKey(tsCryptoString("X25519"), eccAlg))
        return false;

    if (!eccAlg->fromByteArray(blob))
    {
        if (!TSBuildEccKey(tsCryptoString("KEY-P256"), eccAlg))
            return false;
        if (!eccAlg->fromByteArray(blob))
        {
            if (!TSBuildEccKey(tsCryptoString("KEY-P256"), eccAlg))
                return false;
            if (!eccAlg->fromByteArray(blob))
            {
                if (!TSBuildEccKey(tsCryptoString("NUMSP256D1"), eccAlg))
                    return false;
                if (!eccAlg->fromByteArray(blob))
                    return false;
            }
        }
    }

    key = eccAlg;
    return true;
}

bool tscrypto::TSHMACStart(TS_ALG_ID algorithm, const tsCryptoData &key, CryptoContext &ctx)
{
    std::shared_ptr<MessageAuthenticationCode> hashAlg;

    hashAlg = std::dynamic_pointer_cast<MessageAuthenticationCode>(CryptoFactory(algorithm));
    if (!hashAlg)
        return false;

    ctx = std::dynamic_pointer_cast<tscrypto::ICryptoObject>(hashAlg);

    if (!hashAlg->initialize(key))
        return false;

    return true;
}

bool tscrypto::TSHMACStart(const char* algorithm, const tsCryptoData &key, CryptoContext &ctx)
{
    std::shared_ptr<MessageAuthenticationCode> hashAlg;

    hashAlg = std::dynamic_pointer_cast<MessageAuthenticationCode>(CryptoFactory(algorithm));
    if (!hashAlg)
        return false;

    ctx = std::dynamic_pointer_cast<tscrypto::ICryptoObject>(hashAlg);

    if (!hashAlg->initialize(key))
        return false;

    return true;
}

bool tscrypto::TSHMACUpdate(const tsCryptoData &data, CryptoContext &ctx)
{
    std::shared_ptr<MessageAuthenticationCode> hashAlg;

    hashAlg = ctx.get<MessageAuthenticationCode>();
    if (!hashAlg)
        return false;

    if (!hashAlg->update(data))
        return false;

    return true;
}

bool tscrypto::TSHMACFinish(tsCryptoData &hmac, CryptoContext &ctx)
{
    std::shared_ptr<MessageAuthenticationCode> hashAlg;

    hashAlg = ctx.get<MessageAuthenticationCode>();
    if (!hashAlg)
        return false;

    if (!hashAlg->finish(hmac))
        return false;

    return true;
}

bool tscrypto::TSHMAC(TS_ALG_ID algorithm, const tsCryptoData &key, const tsCryptoData &data, tsCryptoData &hmac)
{
    CryptoContext Context;

    if (!TSHMACStart(algorithm, key, Context))
    {
        return false;
    }

    if (!TSHMACUpdate(data, Context))
    {
        return false;
    }

    if (!TSHMACFinish(hmac, Context))
    {
        return false;
    }

    return true;
}
bool tscrypto::TSHMAC(const char* algorithm, const tsCryptoData &key, const tsCryptoData &data, tsCryptoData &hmac)
{
    CryptoContext Context;

    if (!TSHMACStart(algorithm, key, Context))
    {
        return false;
    }

    if (!TSHMACUpdate(data, Context))
    {
        return false;
    }

    if (!TSHMACFinish(hmac, Context))
    {
        return false;
    }

    return true;
}

bool tscrypto::TSBuildECCKeyFromPoint(const tsCryptoData &point, std::shared_ptr<EccKey>& key)
{
    if (point.size() == 0 || (point[0] != 4 && point.size() != 32 && point.size() != 56))
        return false;

    switch (point.size())
    {
#ifdef SUPPORT_ECC_P192
    case 49: // p192
        if (!tsCrypto::TSBuildEccKey(tsCryptoString("KEY-P192"), key))
            return false;
        break;
#endif
#ifdef SUPPORT_ECC_P224
    case 57: // p224
        if (!tsCrypto::TSBuildEccKey(tsCryptoString("KEY-P224"), key))
            return false;
        break;
#endif
    case 32:
        if (!TSBuildEccKey(tsCryptoString("X25519"), key))
            return false;
        break;
    case 56:
        if (!TSBuildEccKey(tsCryptoString("X448"), key))
            return false;
        break;
    case 65: // p256
        if (!TSBuildEccKey(tsCryptoString("KEY-P256"), key))
            return false;
        break;
    case 97: // p384
        if (!TSBuildEccKey(tsCryptoString("KEY-P384"), key))
            return false;
        break;
    case 133: // p521
        if (!TSBuildEccKey(tsCryptoString("KEY-P521"), key))
            return false;
        break;
    default:
        return false;
    }
    if (!key->set_Point(point))
    {
        key.reset();
        return false;
    }
    return true;
}

bool tscrypto::TSBuildECCKeyFromPrivateValue(const tsCryptoData &value, std::shared_ptr<EccKey>& key, bool preferEdwards)
{
    switch (value.size())
    {
#ifdef SUPPORT_ECC_P192
    case 24: // p192
        if (!tsCrypto::TSBuildEccKey(tsCryptoString("KEY-P192"), key))
            return false;
        break;
#endif
#ifdef SUPPORT_ECC_P224
    case 28: // p224
        if (!tsCrypto::TSBuildEccKey(tsCryptoString("KEY-P224"), key))
            return false;
        break;
#endif
    case 56: // X448
    case 112: // X448 EdDSA
        if (!TSBuildEccKey(tsCryptoString("X448"), key))
            return false;
        break;
    case 64: // X25519 EdDSA
        if (!TSBuildEccKey(tsCryptoString("X25519"), key))
            return false;
        break;
    case 32: // p256 or X25519
        if (preferEdwards)
        {
            if (!TSBuildEccKey(tsCryptoString("X25519"), key))
                return false;
        }
        else
        {
            if (!TSBuildEccKey(tsCryptoString("KEY-P256"), key))
                return false;
        }
        break;
    case 48: // p384
        if (!TSBuildEccKey(tsCryptoString("KEY-P384"), key))
            return false;
        break;
    case 66: // p521
        if (!TSBuildEccKey(tsCryptoString("KEY-P521"), key))
            return false;
        break;
    default:
        return false;
    }
    if (!key->set_PrivateValue(value))
    {
        key.reset();
        return false;
    }
    return true;
}

bool tscrypto::TSBuildDhKey(std::shared_ptr<DhKey>& key)
{
    std::shared_ptr<DhKey> dhAlg;

    if (!(dhAlg = std::dynamic_pointer_cast<DhKey>(CryptoFactory("KEY-DH"))))
    {
        return false;
    }
    key = dhAlg;
    return true;
}

bool tscrypto::TSBuildDhParams(std::shared_ptr<DhParameters>& params)
{
    std::shared_ptr<DhParameters> dhAlg;

    if (!(dhAlg = std::dynamic_pointer_cast<DhParameters>(CryptoFactory("PARAMETERSET-DH"))))
    {
        return false;
    }
    params = dhAlg;
    return true;
}

bool tscrypto::TSBuildDhParamsFromBlob(const tsCryptoData &blob, std::shared_ptr<DhParameters>& params)
{
    std::shared_ptr<DhParameters> dhAlg;

    if (!(dhAlg = std::dynamic_pointer_cast<DhParameters>(CryptoFactory("PARAMETERSET-DH"))))
    {
        return false;
    }
    if (!dhAlg->fromByteArray(blob))
        return false;

    params = dhAlg;
    return true;
}

bool tscrypto::TSBuildDhKeyFromBlob(const tsCryptoData &blob, std::shared_ptr<DhKey>& key)
{
    std::shared_ptr<DhKey> dhAlg;
    tsCryptoString oidStr;

    if (!TSBuildDhKey(dhAlg))
        return false;

    if (!dhAlg->fromByteArray(blob))
        return false;

    key = dhAlg;
    return true;
}
std::shared_ptr<AsymmetricKey> tscrypto::TSBuildAsymmetricKeyFromBlob(const tsCryptoData& blob)
{
    std::shared_ptr<AsymmetricKey> key;
    std::shared_ptr<EccKey> ecc;
    std::shared_ptr<RsaKey> rsa;
    std::shared_ptr<DhKey> dh;

    if (!TSBuildECCKeyFromBlob(blob, ecc))
    {
        if (!TSBuildRSAKeyFromBlob(blob, rsa))
        {
            if (!TSBuildDhKeyFromBlob(blob, dh))
            {
                return nullptr;
            }
            else
            {
                key = std::dynamic_pointer_cast<AsymmetricKey>(dh);
            }
        }
        else
        {
            key = std::dynamic_pointer_cast<AsymmetricKey>(rsa);
        }
    }
    else
    {
        key = std::dynamic_pointer_cast<AsymmetricKey>(ecc);
    }
    return key;
}

tsCryptoData tscrypto::TSBuildRSAPublicKeyBlob(const tsCryptoData &modulus, const tsCryptoData &exponent)
{
    // SEQUENCE(0x30) {
    //   Alg(0x30) {
    //     OID (6) =  "1.2.840.113549.1.1.1"
    //     Params(5) = <<null>>
    //   }
    //   BitString(3) = "SEQUENCE(0x30) {Int(2) = Modulus, Int(2) = exponent}"
    // }
    //
    std::shared_ptr<TlvDocument> blobDoc = TlvDocument::Create();

    blobDoc->DocumentElement()->Tag(0x10);
    blobDoc->DocumentElement()->Type(0);

    std::shared_ptr<TlvNode> alg = blobDoc->CreateTlvNode(0x10, 0);
    std::shared_ptr<TlvNode> oid = blobDoc->CreateTlvNode(0x06, 0);
    std::shared_ptr<TlvNode> nullNode = blobDoc->CreateTlvNode(0x05, 0);

    blobDoc->DocumentElement()->AppendChild(alg);
    oid->InnerData(tsCryptoData(RSA_ENCRYPT_OID, tsCryptoData::OID)); //RsaEncryption
    alg->AppendChild(oid);
    alg->AppendChild(nullNode);

    std::shared_ptr<TlvDocument> keyDoc = TlvDocument::Create();
    keyDoc->DocumentElement()->Tag(0x10);
    keyDoc->DocumentElement()->Type(0);

    keyDoc->DocumentElement()->AppendChild(MakeIntegerNode(modulus, keyDoc));
    keyDoc->DocumentElement()->AppendChild(MakeIntegerNode(exponent, keyDoc));

    blobDoc->DocumentElement()->AppendChild(MakeBitString(keyDoc->SaveTlv(), 0, blobDoc));
    return blobDoc->SaveTlv();
}

tsCryptoData tscrypto::TSBuildRSAPrivateKeyBlob(const tsCryptoData &modulus, const tsCryptoData &exponent, const tsCryptoData &d, const tsCryptoData &p, const tsCryptoData &q, const tsCryptoData &dp, const tsCryptoData &dq, const tsCryptoData &qInv)
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
    oid->InnerData(tsCryptoData(TECSEC_RSA_PRIVATE_KEY_BLOB, tsCryptoData::OID)); //TecSec Private RSA Key Blob
    alg->AppendChild(oid);
    alg->AppendChild(nullNode);

    std::shared_ptr<TlvDocument> keyDoc = TlvDocument::Create();
    keyDoc->DocumentElement()->Tag(0x10);
    keyDoc->DocumentElement()->Type(0);
    keyDoc->DocumentElement()->AppendChild(MakeIntegerNode(modulus, keyDoc));
    keyDoc->DocumentElement()->AppendChild(MakeIntegerNode(exponent, keyDoc));
    keyDoc->DocumentElement()->AppendChild(MakeIntegerNode(d, keyDoc));
    keyDoc->DocumentElement()->AppendChild(MakeIntegerNode(p, keyDoc));
    keyDoc->DocumentElement()->AppendChild(MakeIntegerNode(q, keyDoc));
    keyDoc->DocumentElement()->AppendChild(MakeIntegerNode(dp, keyDoc));
    keyDoc->DocumentElement()->AppendChild(MakeIntegerNode(dq, keyDoc));
    keyDoc->DocumentElement()->AppendChild(MakeIntegerNode(qInv, keyDoc));

    blobDoc->DocumentElement()->AppendChild(MakeBitString(keyDoc->SaveTlv(), 0, blobDoc));
    return blobDoc->SaveTlv();
}

bool tscrypto::TSBuildRSAKey(std::shared_ptr<RsaKey>& key)
{
    std::shared_ptr<RsaKey> rsaAlg;

    if (!(rsaAlg = std::dynamic_pointer_cast<RsaKey>(CryptoFactory("KEY-RSA"))))
    {
        return false;
    }
    key = rsaAlg;
    return true;
}
bool tscrypto::TSBuildRSAKeyFromBlob(const tsCryptoData &blob, std::shared_ptr<RsaKey>& key)
{
    std::shared_ptr<RsaKey> rsaAlg;
    tsCryptoString oidStr;

    if (!TSBuildRSAKey(rsaAlg))
        return false;

    std::shared_ptr<TlvDocument> doc = TlvDocument::Create();

    if (!doc->LoadTlv(blob))
        return false;

    std::shared_ptr<TlvNode> top = doc->DocumentElement();

    if (!top->IsConstructed() || top->Children()->size() != 2 || top->Children()->at(0)->Tag() != 0x10 || !top->Children()->at(0)->IsConstructed() ||
        top->Children()->at(1)->Tag() != TlvNode::Tlv_BitString)
    {
        return false;
    }

    std::shared_ptr<TlvNode> alg = top->Children()->at(0);
    tsCryptoData keyValueData = AdjustBitString(top->Children()->at(1)->InnerData());

    std::shared_ptr<TlvDocument> innerdoc = TlvDocument::Create();

    if (alg->Children()->size() != 2 || alg->Children()->at(0)->Tag() != TlvNode::Tlv_OID || alg->Children()->at(0)->Type() != 0 || !innerdoc->LoadTlv(keyValueData))
    {
        return false;
    }
    oidStr = alg->Children()->at(0)->InnerData().ToOIDString();
    if (TsStrCmp(oidStr, tsCryptoString(RSA_ENCRYPT_OID)) == 0)
    {
        tsCryptoData e, n;

        // RSA Public key blob
        top = innerdoc->DocumentElement();

        if (top->Tag() != 0x10 || top->Type() != 0 || !top->IsConstructed() || top->Children()->size() != 2)
            return false;

        n = AdjustASN1Number(top->Children()->at(0)->InnerData());
        e = AdjustASN1Number(top->Children()->at(1)->InnerData());
        if (!rsaAlg->set_Exponent(e) || !rsaAlg->set_PublicModulus(n))
            return false;

        if (!rsaAlg->IsPublicLoaded())
            return false;
    }
    else if (TsStrCmp(oidStr, tsCryptoString(TECSEC_RSA_PRIVATE_KEY_BLOB)) == 0)
    {
        tsCryptoData e, n, d, p, q, dp, dq, qInv;

        // RSA Public key blob
        top = innerdoc->DocumentElement();

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
        if (!rsaAlg->set_Exponent(e) || !rsaAlg->set_PublicModulus(n))
            return false;

        if (p.size() == q.size() && p.size() > 0)
        {
            if (!rsaAlg->set_p(p) || !rsaAlg->set_q(q) || !rsaAlg->set_dp(dp) || !rsaAlg->set_dq(dq) || !rsaAlg->set_qInv(qInv))
                return false;
        }
        else
        {
            if (!rsaAlg->set_PrivateExponent(d))
                return false;
        }
        if (!rsaAlg->IsPublicLoaded() || !rsaAlg->IsPrivateLoaded())
            return false;
    }
    else
    {
        return false;
    }
    key = rsaAlg;
    return true;
}

bool tscrypto::TSGetRsaModulus(const tsCryptoData &blob, tsCryptoData &modulus)
{
    std::shared_ptr<RsaKey> key;

    modulus.clear();
    if (!TSBuildRSAKeyFromBlob(blob, key))
        return false;
    modulus = key->get_PublicModulus();
    return true;
}

bool tscrypto::TSGetRsaExponent(const tsCryptoData &blob, tsCryptoData &exponent)
{
    std::shared_ptr<RsaKey> key;

    exponent.clear();
    if (!TSBuildRSAKeyFromBlob(blob, key))
        return false;
    exponent = key->get_Exponent();
    return true;
}

bool tscrypto::TSGetRsaPublicComponents(const tsCryptoData &blob, tsCryptoData &modulus, tsCryptoData &exponent)
{
    std::shared_ptr<RsaKey> key;

    modulus.clear();
    exponent.clear();
    if (!TSBuildRSAKeyFromBlob(blob, key))
        return false;
    modulus = key->get_PublicModulus();
    exponent = key->get_Exponent();
    return true;
}

bool tscrypto::TSGenerateRSAKeys(size_t bitSize, std::shared_ptr<RsaKey> &rsa)
{
    std::shared_ptr<RsaKey> rsaAlg;

    if (!TSBuildRSAKey(rsaAlg))
        return false;

    if (!rsaAlg->generateKeyPair(_RSA_Key_Gen_Type::rsakg_Probable_Composite, "SHA512", bitSize))
        return false;

    rsa = rsaAlg;
    return true;
}
bool tscrypto::TSGenerateRSAKeys(size_t bitSize, tsCryptoData &PublicKey, tsCryptoData &PrivateKey)
{
    std::shared_ptr<RsaKey> rsaAlg;

    if (!TSGenerateRSAKeys(bitSize, rsaAlg))
        return false;

    //
    // Build the public key blob (based on RSA Cert public key)
    //
    PublicKey = TSBuildRSAPublicKeyBlob(rsaAlg->get_PublicModulus(), rsaAlg->get_Exponent());
    PrivateKey = TSBuildRSAPrivateKeyBlob(rsaAlg->get_PublicModulus(), rsaAlg->get_Exponent(), rsaAlg->get_PrivateExponent(), rsaAlg->get_p(), rsaAlg->get_q(), rsaAlg->get_dp(), rsaAlg->get_dq(), rsaAlg->get_qInv());

    return true;
}
bool tscrypto::TSRSAPKCS11Sign(const tsCryptoData &RSAPrivate, const BYTE *value, size_t valueLen, tsCryptoData &signature, TS_ALG_ID signAlgorithm)
{
    return TSRSAPKCS11Sign(RSAPrivate, tsCryptoData(value, valueLen), signature, signAlgorithm);
}

bool tscrypto::TSSignData(std::shared_ptr<AsymmetricKey> key, const tsCryptoData& data, tsCryptoData& signature, const char* signAlgSuffix)
{
    std::shared_ptr<RsaKey> rsakey;
    std::shared_ptr<EccKey> ecckey;
    std::shared_ptr<DhKey> dhkey;
    std::shared_ptr<Signer> signer;
    tsCryptoString signerName;

    rsakey = std::dynamic_pointer_cast<RsaKey>(key);
    ecckey = std::dynamic_pointer_cast<EccKey>(key);
    dhkey = std::dynamic_pointer_cast<DhKey>(key);

    if (!!ecckey)
    {
        signerName = "SIGN-ECC";

        if (signAlgSuffix == nullptr || signAlgSuffix[0] == 0)
        {
            switch (ecckey->KeySize())
            {
            case 255:
                signerName << "-SHA512";
                break;
            case 448:
                signerName << "-SHAKE256";
                break;
            case 256:
                signerName << "-SHA256";
                break;
            case 384:
                signerName << "-SHA384";
                break;
            case 521:
                signerName << "-SHA512";
                break;
            }
        }
        else
            signerName << "-" << signAlgSuffix;
    }
    else if (!!rsakey)
    {
        signerName = "SIGN-RSA";

        if (signAlgSuffix == nullptr || signAlgSuffix[0] == 0)
        {
            signerName << "-PKCS-SHA1";
        }
        else
            signerName << "-" << signAlgSuffix;
    }
    else if (!!dhkey)
    {
        signerName = "SIGN-DSA";

        if (signAlgSuffix == nullptr || signAlgSuffix[0] == 0)
        {
            signerName << "-SHA1";
        }
        else
            signerName << "-" << signAlgSuffix;
    }
    else
        return false;

    signer = std::dynamic_pointer_cast<Signer>(CryptoFactory(signerName));

    if (!signer || !signer->initialize(key) || !signer->update(data) || !signer->sign(signature))
        return false;
    return true;
}

bool tscrypto::TSVerifyData(std::shared_ptr<AsymmetricKey> key, const tsCryptoData& data, const tsCryptoData& signature, const char* signAlgSuffix)
{
    std::shared_ptr<RsaKey> rsakey;
    std::shared_ptr<EccKey> ecckey;
    std::shared_ptr<DhKey> dhkey;
    std::shared_ptr<Signer> signer;
    tsCryptoString signerName;

    rsakey = std::dynamic_pointer_cast<RsaKey>(key);
    ecckey = std::dynamic_pointer_cast<EccKey>(key);
    dhkey = std::dynamic_pointer_cast<DhKey>(key);

    if (!!ecckey)
    {
        signerName = "SIGN-ECC";

        if (signAlgSuffix == nullptr || signAlgSuffix[0] == 0)
        {
            switch (ecckey->KeySize())
            {
            case 255:
                signerName << "-SHA512";
                break;
            case 448:
                signerName << "-SHAKE256";
                break;
            case 256:
                signerName << "-SHA256";
                break;
            case 384:
                signerName << "-SHA384";
                break;
            case 521:
                signerName << "-SHA512";
                break;
            }
        }
        else
            signerName << "-" << signAlgSuffix;
    }
    else if (!!rsakey)
    {
        signerName = "SIGN-RSA";

        if (signAlgSuffix == nullptr || signAlgSuffix[0] == 0)
        {
            signerName << "-PKCS-SHA1";
        }
        else
            signerName << "-" << signAlgSuffix;
    }
    else if (!!dhkey)
    {
        signerName = "SIGN-DSA";

        if (signAlgSuffix == nullptr || signAlgSuffix[0] == 0)
        {
            signerName << "-SHA1";
        }
        else
            signerName << "-" << signAlgSuffix;
    }
    else
        return false;

    signer = std::dynamic_pointer_cast<Signer>(CryptoFactory(signerName));

    if (!signer || !signer->initialize(key) || !signer->update(data) || !signer->verify(signature))
        return false;
    return true;
}

bool tscrypto::TSSignHash(std::shared_ptr<AsymmetricKey> key, const tsCryptoData& hash, tsCryptoData& signature, const char* signAlgSuffix)
{
    std::shared_ptr<RsaKey> rsakey;
    std::shared_ptr<EccKey> ecckey;
    std::shared_ptr<DhKey> dhkey;
    std::shared_ptr<Signer> signer;
    tsCryptoString signerName;

    rsakey = std::dynamic_pointer_cast<RsaKey>(key);
    ecckey = std::dynamic_pointer_cast<EccKey>(key);
    dhkey = std::dynamic_pointer_cast<DhKey>(key);

    if (!!ecckey)
    {
        signerName = "SIGN-ECC";

        if (signAlgSuffix == nullptr || signAlgSuffix[0] == 0)
        {
            switch (ecckey->KeySize())
            {
            case 255:
                signerName << "-SHA512";
                break;
            case 448:
                signerName << "-SHAKE256";
                break;
            case 256:
                signerName << "-SHA256";
                break;
            case 384:
                signerName << "-SHA384";
                break;
            case 521:
                signerName << "-SHA512";
                break;
            }
        }
        else
            signerName << "-" << signAlgSuffix;
    }
    else if (!!rsakey)
    {
        signerName = "SIGN-RSA";

        if (signAlgSuffix == nullptr || signAlgSuffix[0] == 0)
        {
            signerName << "-PKCS-SHA1";
        }
        else
            signerName << "-" << signAlgSuffix;
    }
    else if (!!dhkey)
    {
        signerName = "SIGN-DSA";

        if (signAlgSuffix == nullptr || signAlgSuffix[0] == 0)
        {
            signerName << "-SHA1";
        }
        else
            signerName << "-" << signAlgSuffix;
    }
    else
        return false;

    signer = std::dynamic_pointer_cast<Signer>(CryptoFactory(signerName));

    if (!signer || !signer->initialize(key) || !signer->signHash(hash, signature))
        return false;
    return true;
}
bool tscrypto::TSVerifyHash(std::shared_ptr<AsymmetricKey> key, const tsCryptoData& hash, const tsCryptoData& signature, const char* signAlgSuffix)
{
    std::shared_ptr<RsaKey> rsakey;
    std::shared_ptr<EccKey> ecckey;
    std::shared_ptr<DhKey> dhkey;
    std::shared_ptr<Signer> signer;
    tsCryptoString signerName;

    rsakey = std::dynamic_pointer_cast<RsaKey>(key);
    ecckey = std::dynamic_pointer_cast<EccKey>(key);
    dhkey = std::dynamic_pointer_cast<DhKey>(key);

    if (!!ecckey)
    {
        signerName = "SIGN-ECC";

        if (signAlgSuffix == nullptr || signAlgSuffix[0] == 0)
        {
            switch (ecckey->KeySize())
            {
            case 255:
                signerName << "-SHA512";
                break;
            case 448:
                signerName << "-SHAKE256";
                break;
            case 256:
                signerName << "-SHA256";
                break;
            case 384:
                signerName << "-SHA384";
                break;
            case 521:
                signerName << "-SHA512";
                break;
            }
        }
        else
            signerName << "-" << signAlgSuffix;
    }
    else if (!!rsakey)
    {
        signerName = "SIGN-RSA";

        if (signAlgSuffix == nullptr || signAlgSuffix[0] == 0)
        {
            signerName << "-PKCS-SHA1";
        }
        else
            signerName << "-" << signAlgSuffix;
    }
    else if (!!dhkey)
    {
        signerName = "SIGN-DSA";

        if (signAlgSuffix == nullptr || signAlgSuffix[0] == 0)
        {
            signerName << "-SHA1";
        }
        else
            signerName << "-" << signAlgSuffix;
    }
    else
        return false;

    signer = std::dynamic_pointer_cast<Signer>(CryptoFactory(signerName));

    if (!signer || !signer->initialize(key) || !signer->verifyHash(hash, signature))
        return false;
    return true;
}

static tsCryptoString GetSignAlgName(TS_ALG_ID signAlgorithm)
{
    tsCryptoString name;
    
    for (auto& fn : gSignNameFuncs)
    {
        name = fn(signAlgorithm);
        if (!name.empty())
            return name;
    }

    switch (signAlgorithm)
    {
    case TS_ALG_RSA_PKCS_v15:
        name = "SIGN-RSA-PKCS";
        break;
    case TS_ALG_RSA_SHA1_v15:
        name = "SIGN-RSA-PKCS-SHA1";
        break;
    case TS_ALG_RSA_MD5_v15:
        name = "SIGN-RSA-PKCS-MD5";
        break;
    case TS_ALG_RSA_SHA256_v15:
        name = "SIGN-RSA-PKCS-SHA256";
        break;
    case TS_ALG_RSA_SHA384_v15:
        name = "SIGN-RSA-PKCS-SHA384";
        break;
    case TS_ALG_RSA_SHA512_v15:
        name = "SIGN-RSA-PKCS-SHA512";
        break;
    case TS_ALG_RSA_SHA224_v15:
        name = "SIGN-RSA-PKCS-SHA224";
        break;
    case TS_ALG_RSA:
        name = "SIGN-RSA-PKCS";
        break;
    case TS_ALG_RSA_PSS_ENCODE:
        name = "SIGN-RSA-PSS-SHA1";
        break;
    case TS_ALG_RSA_X9_31_ENCODE:
        name = "SIGN-RSA-X9.31-SHA1";
        break;
    case TS_ALG_RSA_X9_31_SHA1:
        name = "SIGN-RSA-X9.31-SHA1";
        break;
    case TS_ALG_RSA_X9_31_SHA224:
        name = "SIGN-RSA-X9.31-SHA224";
        break;
    case TS_ALG_RSA_X9_31_SHA256:
        name = "SIGN-RSA-X9.31-SHA256";
        break;
    case TS_ALG_RSA_X9_31_SHA384:
        name = "SIGN-RSA-X9.31-SHA384";
        break;
    case TS_ALG_RSA_X9_31_SHA512:
        name = "SIGN-RSA-X9.31-SHA512";
        break;
    case TS_ALG_RSA_PSS_SHA1:
        name = "SIGN-RSA-PSS-SHA1";
        break;
    case TS_ALG_RSA_PSS_SHA224:
        name = "SIGN-RSA-PSS-SHA224";
        break;
    case TS_ALG_RSA_PSS_SHA256:
        name = "SIGN-RSA-PSS-SHA256";
        break;
    case TS_ALG_RSA_PSS_SHA384:
        name = "SIGN-RSA-PSS-SHA384";
        break;
    case TS_ALG_RSA_PSS_SHA512:
        name = "SIGN-RSA-PSS-SHA512";
        break;
    case TS_ALG_RSA_PKCS_SHA3_256:
        name = "SIGN-RSA-PKCS-SHA3-256";
        break;
    case TS_ALG_RSA_PKCS_SHA3_384:
        name = "SIGN-RSA-PKCS-SHA3-384";
        break;
    case TS_ALG_RSA_PKCS_SHA3_512:
        name = "SIGN-RSA-PKCS-SHA3-512";
        break;
    case TS_ALG_RSA_PKCS_SHA3_224:
        name = "SIGN-RSA-PKCS-SHA3-224";
        break;
    case TS_ALG_RSA_X9_31_SHA3_224:
        name = "SIGN-RSA-X9.31-SHA3-224";
        break;
    case TS_ALG_RSA_X9_31_SHA3_256:
        name = "SIGN-RSA-X9.31-SHA3-256";
        break;
    case TS_ALG_RSA_X9_31_SHA3_384:
        name = "SIGN-RSA-X9.31-SHA3-384";
        break;
    case TS_ALG_RSA_X9_31_SHA3_512:
        name = "SIGN-RSA-X9.31-SHA3-512";
        break;
    case TS_ALG_RSA_PSS_SHA3_224:
        name = "SIGN-RSA-PSS-SHA3-224";
        break;
    case TS_ALG_RSA_PSS_SHA3_256:
        name = "SIGN-RSA-PSS-SHA3-256";
        break;
    case TS_ALG_RSA_PSS_SHA3_384:
        name = "SIGN-RSA-PSS-SHA3-384";
        break;
    case TS_ALG_RSA_PSS_SHA3_512:
        name = "SIGN-RSA-PSS-SHA3-512";
        break;
    default:
        name = "SIGN-RSA-PKCS";
    }
    return name;
}

bool tscrypto::TSRSAPKCS11Sign(const tsCryptoData &RSAPrivate, const tsCryptoData &value, tsCryptoData &signature, TS_ALG_ID signAlgorithm)
{
    tsCryptoString name;

    if (value.size() == 0)
        return false;

    std::shared_ptr<RsaKey> rsaAlg;
    std::shared_ptr<Signer> signer;

    if (!TSBuildRSAKeyFromBlob(RSAPrivate, rsaAlg))
        return false;

    name = GetSignAlgName(signAlgorithm);

    if (!(signer = std::dynamic_pointer_cast<Signer>(CryptoFactory(name))))
    {
        return false;
    }

    if (!signer->initialize(std::dynamic_pointer_cast<AsymmetricKey>(rsaAlg)) || !signer->signHash(value, signature))
    {
        return false;
    }
    return true;
}
bool tscrypto::TSRSAPKCS11Verify(const tsCryptoData &RSAPublic, const BYTE *value, const uint32_t valueLen, const tsCryptoData &signature, TS_ALG_ID signAlgorithm)
{
    return TSRSAPKCS11Verify(RSAPublic, tsCryptoData(value, valueLen), signature, signAlgorithm);
}

bool tscrypto::TSRSAPKCS11Verify(const tsCryptoData &RSAPublic, const tsCryptoData &value, const tsCryptoData &signature, TS_ALG_ID signAlgorithm)
{
    tsCryptoString name;

    if (value.size() == 0)
        return false;

    std::shared_ptr<RsaKey> rsaAlg;
    std::shared_ptr<Signer> signer;

    name = GetSignAlgName(signAlgorithm);

    if (!TSBuildRSAKeyFromBlob(RSAPublic, rsaAlg))
        return false;

    if (!(signer = std::dynamic_pointer_cast<Signer>(CryptoFactory(name.c_str()))))
    {
        return false;
    }

    if (!signer->initialize(std::dynamic_pointer_cast<AsymmetricKey>(rsaAlg)) || !signer->verifyHash(value, signature))
    {
        return false;
    }
    return true;
}

//bool tscrypto::TSRSAEncrypt(const tsCryptoData &PubKey, const tsCryptoData &indata, tsCryptoData &OutData)
//{
//    if (indata.size() <= 0)
//        return false;
//
//    std::shared_ptr<RsaKey> rsaAlg;
//    std::shared_ptr<RsaPrimitives> prims;
//    tsCryptoData tmp;
//
//    if (!TSBuildRSAKeyFromBlob(PubKey, rsaAlg) || !(prims = std::dynamic_pointer_cast<RsaPrimitives>(rsaAlg)))
//        return false;
//
//    if (!TSRSAEncodeEncrypt_v1_5(rsaAlg->KeySize(), indata, tmp))
//        return false;
//
//    if (!prims->EncryptPrimitive(tmp, OutData))
//        return false;
//
//    return true;
//}
//
//bool tscrypto::TSRSAEncrypt(std::shared_ptr<RsaKey> PubKey, const tsCryptoData &indata, tsCryptoData &OutData)
//{
//    if (indata.size() <= 0)
//        return false;
//
//    std::shared_ptr<RsaPrimitives> prims;
//    tsCryptoData tmp;
//
//    if (!(prims = std::dynamic_pointer_cast<RsaPrimitives>(PubKey)))
//        return false;
//
//    if (!TSRSAEncodeEncrypt_v1_5(PubKey->KeySize(), indata, tmp))
//        return false;
//
//    if (!prims->EncryptPrimitive(tmp, OutData))
//        return false;
//
//    return true;
//}
//
//bool tscrypto::TSRSADecrypt(const tsCryptoData &PrivKey, const tsCryptoData &indata, tsCryptoData &OutData)
//{
//    if (indata.size() <= 0)
//        return false;
//
//    std::shared_ptr<RsaKey> rsaAlg;
//    std::shared_ptr<RsaPrimitives> prims;
//    tsCryptoData tmp;
//
//    if (!TSBuildRSAKeyFromBlob(PrivKey, rsaAlg) || !(prims = std::dynamic_pointer_cast<RsaPrimitives>(rsaAlg)))
//        return false;
//
//    if (!prims->DecryptPrimitive(indata, tmp))
//        return false;
//
//    if (tmp[0] == 2)
//    {
//        // We have a case here where the encryption could have been padded incorrectly. Tweek the values and try a "special" decode.
//        tmp.insert(0, (uint8_t)0);
//        return TSRSADecodeEncrypt_v1_5(rsaAlg->KeySize() + 8, tmp, OutData);
//    }
//    return TSRSADecodeEncrypt_v1_5(rsaAlg->KeySize(), tmp, OutData);
//}
//
//bool tscrypto::TSRSADecrypt(std::shared_ptr<RsaKey>  PrivKey, const tsCryptoData &indata, tsCryptoData &OutData)
//{
//    if (indata.size() <= 0)
//        return false;
//
//    std::shared_ptr<RsaPrimitives> prims;
//    tsCryptoData tmp;
//
//    if (!(prims = std::dynamic_pointer_cast<RsaPrimitives>(PrivKey)))
//        return false;
//
//    if (!prims->DecryptPrimitive(indata, tmp))
//        return false;
//
//    if (tmp[0] == 2)
//    {
//        // We have a case here where the encryption could have been padded incorrectly. Tweek the values and try a "special" decode.
//        tmp.insert(0, (uint8_t)0);
//        return TSRSADecodeEncrypt_v1_5(PrivKey->KeySize() + 8, tmp, OutData);
//    }
//    return TSRSADecodeEncrypt_v1_5(PrivKey->KeySize(), tmp, OutData);
//}
//
//bool tscrypto::TSReverseRSAEncrypt(const tsCryptoData &PrivKey, const tsCryptoData &indata, tsCryptoData &OutData)
//{
//    if (indata.size() <= 0)
//        return false;
//
//    std::shared_ptr<RsaKey> rsaAlg;
//    std::shared_ptr<RsaPrimitives> prims;
//    tsCryptoData tmp;
//
//    if (!TSBuildRSAKeyFromBlob(PrivKey, rsaAlg) || !(prims = std::dynamic_pointer_cast<RsaPrimitives>(rsaAlg)))
//    {
//        return false;
//    }
//
//    if (!TSRSAEncodeEncrypt_v1_5(rsaAlg->KeySize(), indata, tmp))
//        return false;
//
//    if (!prims->DecryptPrimitive(tmp, OutData))
//        return false;
//    return true;
//}
//
//bool tscrypto::TSReverseRSADecrypt(const tsCryptoData &PubKey, const tsCryptoData &indata, tsCryptoData &OutData)
//{
//    if (indata.size() <= 0)
//        return false;
//
//    std::shared_ptr<RsaKey> rsaAlg;
//    std::shared_ptr<RsaPrimitives> prims;
//
//    if (!TSBuildRSAKeyFromBlob(PubKey, rsaAlg) || !(prims = std::dynamic_pointer_cast<RsaPrimitives>(rsaAlg)))
//        return false;
//
//    tsCryptoData tmp;
//
//    if (!prims->EncryptPrimitive(indata, tmp))
//        return false;
//
//    if (tmp[0] == 2)
//    {
//        // We have a case here where the encryption could have been padded incorrectly. Tweek the values and try a "special" decode.
//        tmp.insert(0, (uint8_t)0);
//        return TSRSADecodeEncrypt_v1_5(rsaAlg->KeySize() + 8, tmp, OutData);
//    }
//    return TSRSADecodeEncrypt_v1_5(rsaAlg->KeySize(), tmp, OutData);
//}

size_t tscrypto::TSGetRsaKeySize(const tsCryptoData &blob)
{
    if (blob.size() == 0)
        return 0;

    std::shared_ptr<RsaKey> rsaAlg;

    if (!TSBuildRSAKeyFromBlob(blob, rsaAlg))
        return 0;

    return rsaAlg->KeySize();
}
//bool tscrypto::TSRSADecodeEncrypt_v1_5(size_t keyBitSize, const tsCryptoData &encodedMessage, tsCryptoData &msg)
//{
//    std::shared_ptr<EncryptionEncoder> encoder;
//
//    msg.clear();
//    if (!(encoder = std::dynamic_pointer_cast<EncryptionEncoder>(CryptoFactory("ENCODE-RSA-ENCRYPT-PKCS"))))
//        return false;
//
//    if (!encoder->Decode(keyBitSize, encodedMessage, msg))
//        return false;
//    return true;
//}
//
//bool tscrypto::TSRSAEncodeEncrypt_v1_5(size_t keyBitSize, const tsCryptoData &msg, tsCryptoData &encoded_msg)
//{
//    std::shared_ptr<EncryptionEncoder> encoder;
//
//    encoded_msg.clear();
//    if (!(encoder = std::dynamic_pointer_cast<EncryptionEncoder>(CryptoFactory("ENCODE-RSA-ENCRYPT-PKCS"))))
//        return false;
//
//    if (!encoder->Encode(keyBitSize, msg, encoded_msg))
//        return false;
//    return true;
//}
//
//bool tscrypto::TSRSADecodeSign_v1_5(TS_ALG_ID hashAlgorithm, size_t keyBitSize, const tsCryptoData &hashData, const tsCryptoData &encodedMessage, tsCryptoData &msg)
//{
//    std::shared_ptr<SignatureEncoder> encoder;
//    std::shared_ptr<Hash> hasher;
//
//    hasher = std::dynamic_pointer_cast<Hash>(CryptoFactory(hashAlgorithm));
//
//    if (!(encoder = std::dynamic_pointer_cast<SignatureEncoder>(CryptoFactory("ENCODE-RSA-PKCS"))))
//        return false;
//
//    msg.clear();
//    if (!encoder->Decode(keyBitSize, hasher, hashData, encodedMessage, msg))
//        return false;
//    return true;
//}

//bool tscrypto::TSRSAEncodeSign_v1_5(TS_ALG_ID hashAlgorithm, size_t keyBitSize, const tsCryptoData &msg, tsCryptoData &encoded_msg)
//{
//    std::shared_ptr<SignatureEncoder> encoder;
//    std::shared_ptr<Hash> hasher;
//
//    hasher = std::dynamic_pointer_cast<Hash>(CryptoFactory(hashAlgorithm));
//
//    if (!(encoder = std::dynamic_pointer_cast<SignatureEncoder>(CryptoFactory("ENCODE-RSA-PKCS"))))
//        return false;
//
//    encoded_msg.clear();
//    if (!encoder->Encode(keyBitSize, hasher, msg, encoded_msg))
//        return false;
//    return true;
//}

static bool HexToUint8(const char *str, int len, uint8_t &value)
{
    value = 0;

    for (int i = 0; i < len; i++)
    {
        if (str[i] >= '0' && str[i] <= '9')
        {
            value = (uint8_t)((value << 4) | (str[i] - '0'));
        }
        else if (str[i] >= 'A' && str[i] <= 'F')
        {
            value = (uint8_t)((value << 4) | (str[i] - 'A' + 10));
        }
        else if (str[i] >= 'a' && str[i] <= 'f')
        {
            value = (uint8_t)((value << 4) | (str[i] - 'a' + 10));
        }
        else
            return false;
    }
    return true;
}

static bool HexToUint16(const char *str, int len, uint16_t &value)
{
    uint8_t tmp;

    value = 0;

    switch (len)
    {
    case 4:
        if (!HexToUint8(str, 2, tmp))
            return false;
        value = tmp;
        str += 2;
        if (!HexToUint8(str, 2, tmp))
            return false;
        value = (value << 8) | tmp;
        break;
    case 3:
        if (!HexToUint8(str, 1, tmp))
            return false;
        value = tmp;
        str += 1;
        if (!HexToUint8(str, 2, tmp))
            return false;
        value = (value << 8) | tmp;
        break;
    case 2:
        if (!HexToUint8(str, 2, tmp))
            return false;
        value = tmp;
        break;
    case 1:
        if (!HexToUint8(str, 1, tmp))
            return false;
        value = tmp;
        break;
    default:
        return false;
    }
    return true;
}

static bool HexToUint32(const char *str, int len, uint32_t &value)
{
    uint16_t tmp;
    int sublen;

    value = 0;

    if (len > 8 || len < 1)
        return false;

    if (len > 4)
    {
        sublen = len - 4;

        if (!HexToUint16(str, sublen, tmp))
            return false;
        value = tmp;
        str += sublen;
        len -= sublen;
    }
    if (!HexToUint16(str, len, tmp))
        return false;
    value = (value << 16) | tmp;
    return true;
}

GUID tscrypto::TSStringToGuid(const tscrypto::tsCryptoStringBase &strGuid)
{
    GUID id;

    tscrypto::TSStringToGuid(strGuid, id);
    return id;
}

void tscrypto::TSStringToGuid(const tscrypto::tsCryptoStringBase &strGuid, GUID &id)
{
    const char *p;
    uint32_t l1;
    uint16_t w1, w2, w3;
    uint8_t b1, b2, b3, b4, b5, b6;
    static GUID nullGuid = { 0, };

    id = nullGuid;
    if (strGuid.size() < 38 || strGuid.c_at(0) != '{' || strGuid.c_at(37) != '}' ||
        strGuid.c_at(9) != '-' || strGuid.c_at(14) != '-' || strGuid.c_at(19) != '-' ||
        strGuid.c_at(24) != '-')
    {
        return;
    }
    p = strGuid.c_str();
    if (!HexToUint32(&p[1], 8, l1) ||
        !HexToUint16(&p[10], 4, w1) ||
        !HexToUint16(&p[15], 4, w2) ||
        !HexToUint16(&p[20], 4, w3) ||
        !HexToUint8(&p[25], 2, b1) ||
        !HexToUint8(&p[27], 2, b2) ||
        !HexToUint8(&p[29], 2, b3) ||
        !HexToUint8(&p[31], 2, b4) ||
        !HexToUint8(&p[33], 2, b5) ||
        !HexToUint8(&p[35], 2, b6))
        return;
    id.Data1 = l1;
    id.Data2 = w1;
    id.Data3 = w2;
    id.Data4[0] = (unsigned char)(w3 >> 8);
    id.Data4[1] = (unsigned char)(w3);
    id.Data4[2] = b1;
    id.Data4[3] = b2;
    id.Data4[4] = b3;
    id.Data4[5] = b4;
    id.Data4[6] = b5;
    id.Data4[7] = b6;
}

void tscrypto::xor8(const uint8_t* src, const uint8_t* second, uint8_t* dest)
{
    const uint64_t* a = (const uint64_t*)src;
    const uint64_t* b = (const uint64_t*)second;
    uint64_t* c = (uint64_t*)dest;
    *c = *a ^ *b;
}
void tscrypto::xor16(const uint8_t* src, const uint8_t* second, uint8_t* dest)
{
    const uint64_t* a = (const uint64_t*)src;
    const uint64_t* b = (const uint64_t*)second;
    uint64_t* c = (uint64_t*)dest;
    c[0] = a[0] ^ b[0];
    c[1] = a[1] ^ b[1];
}
void tscrypto::xor32(const uint8_t* src, const uint8_t* second, uint8_t* dest)
{
    const uint64_t* a = (const uint64_t*)src;
    const uint64_t* b = (const uint64_t*)second;
    uint64_t* c = (uint64_t*)dest;
    c[0] = a[0] ^ b[0];
    c[1] = a[1] ^ b[1];
    c[2] = a[2] ^ b[2];
    c[3] = a[3] ^ b[3];
}

bool loadCryptoModules()
{
    tsCryptoString moduleName, dir, file, ext;
    typedef bool(*initFn)();

    xp_GetModuleFileName(hDllModule, moduleName);
    xp_SplitPath(moduleName, dir, file, ext);

//printf("Searching for modules %s\n", (dir + "*.crypto").c_str());
#ifdef _DEBUG
    XP_FileListHandle list = xp_GetFileListHandle(dir + "*_d.crypto");
#else
    XP_FileListHandle list = xp_GetFileListHandle(dir + "*.crypto");
#endif
    if (!!list)
    {
        for (auto& filename : *list)
        {
            XP_MODULE module;

//printf("  Loading module:  %s\n", filename.c_str());
            // TODO:  Authenticate the module
            // TODO:  Validate the license
            if (xp_LoadSharedLib(filename, &module) == 0)
            {
                tsCryptoString tmp;
                xp_SplitPath(filename, tmp, file, ext);

//printf("module loaded\n");
                ext = tmp + filename;
                moduleList.push_back(moduleInfo(ext, module));

                AddCryptoTerminationFunction([ext]() {
                    moduleList.erase(std::remove_if(moduleList.begin(), moduleList.end(), [ext](moduleInfo& info) {
                        return info.filename == ext;
                    }), moduleList.end());
                    return true;
                });

#ifdef _DEBUG
                if (file.size() > 2 && file[file.size() - 1] == 'd' && file[file.size() - 2] == '_')
                    file.resize(file.size() - 2);
#endif
                initFn func = (initFn)xp_GetProcAddress(module, ("Initialize_" + file).c_str());
                if (func != nullptr)
                {
                    if (!(*func)())
                    {
                        moduleList.erase(std::remove_if(moduleList.begin(), moduleList.end(), [ext](moduleInfo& info) {
                            return info.filename == ext;
                        }), moduleList.end());
                    }
                    else
                    {
//printf ("module initialized\n");
                    }
                }
                else
                {
                    moduleList.erase(std::remove_if(moduleList.begin(), moduleList.end(), [ext](moduleInfo& info) {
                        return info.filename == ext;
                    }), moduleList.end());
                }
            }
        }
    }
    return true;
}

//tsCryptoStringList CreatetsCryptoStringList()
//{
//	return CreateContainer<tsCryptoString>();
//}
//
//HttpAttributeList CreateHttpAttributeList()
//{
//	return CreateContainer<HttpAttribute>();
//}
//TSNamedBinarySectionList CreateTSNamedBinarySectionList()
//{
//	return CreateContainer<TSNamedBinarySection>();
//}
//
//tsTraceStream httpData("HTTPDATA", DEBUG_LEVEL_DEBUG);
//tsTraceStream httpLog("HTTPLOG", DEBUG_LEVEL_INFORMATION);
//tsTraceStream FrameworkError("Error", DEBUG_LEVEL_ERROR);
//tsDebugStream FrameworkInfo1("Info1", DEBUG_LEVEL_DEBUG);
//tsDebugStream FrameworkInternal("Internal", DEBUG_LEVEL_TRACE);
//tsDebugStream FrameworkDevOnly("DevOnly", DEBUG_LEVEL_DEV_ONLY);
//tsDebugStream FrameworkLocks("Locks", DEBUG_LEVEL_DEBUG);
//tsTraceStream gMetaError("MetaError", DEBUG_LEVEL_ERROR);
//tsDebugStream gMetaDebug("MetaDebug", DEBUG_LEVEL_DEBUG);
//tsDebugStream gMetaTrace("MetaTrace", DEBUG_LEVEL_TRACE);
//tsDebugStream CallTrace("CallTrace", DEBUG_LEVEL_DEBUG);
//tsTraceStream gLoaderError("LoadErr", DEBUG_LEVEL_ERROR);
//tsDebugStream gLoaderTrace("Loader", DEBUG_LEVEL_TRACE);
//tsDebugStream gDebugAuth("AUTH", DEBUG_LEVEL_SENSITIVE);
//tsTraceStream gTunnel("TUNNEL", DEBUG_LEVEL_DEV_ONLY);
//tsTraceStream gTunnelError("TUNNEL", DEBUG_LEVEL_ERROR);
//tsTraceStream CkmError("CkmError", DEBUG_LEVEL_ERROR);
//tsDebugStream CkmInfo1("CkmInfo1", DEBUG_LEVEL_DEBUG);
//tsDebugStream CkmInfo2("CkmInfo2", DEBUG_LEVEL_DEBUG);
//tsDebugStream CkmDevOnly("CkmDevOnly", DEBUG_LEVEL_DEV_ONLY);
//tsDebugStream CkmCrypto("CkmCrypto", DEBUG_LEVEL_SENSITIVE);
//tsDebugStream DebugInfo1("Info1", DEBUG_LEVEL_DEBUG);
//tsDebugStream DebugInfo2("Info2", DEBUG_LEVEL_DEBUG);
//tsDebugStream DebugInfo3("Info3", DEBUG_LEVEL_DEBUG);
//tsDebugStream DebugConfig("Config", DEBUG_LEVEL_DEBUG);
//tsDebugStream DebugToken("Token", DEBUG_LEVEL_DEBUG);
//tsDebugStream DebugCrypto("Crypto", DEBUG_LEVEL_SENSITIVE);
//tsDebugStream DebugPki("Pki", DEBUG_LEVEL_DEBUG);
//tsDebugStream DebugInternal("Internal", DEBUG_LEVEL_DEV_ONLY);
//tsDebugStream DebugDevOnly("Dev", DEBUG_LEVEL_DEV_ONLY);
//tsDebugStream DebugFile("File", DEBUG_LEVEL_DEBUG);
//tsDebugStream DebugNetwork("Network", DEBUG_LEVEL_DEBUG);
//tsDebugStream DebugUI("UI", DEBUG_LEVEL_DEBUG);
//tsTraceStream DebugError("Error", DEBUG_LEVEL_ERROR);
//tsTraceStream DebugFatal("Fatal", DEBUG_LEVEL_FATAL_ERROR);
//tsDebugStream DebugLocks("Locks", DEBUG_LEVEL_DEBUG);
//tsDebugStream gSql("SQL", DEBUG_LEVEL_INFORMATION);
//
////tsDebugStream AuditInfo("Info", 1, AUDIT_INFO, false);
////tsDebugStream AuditLoginFailure("Failure", 1, AUDIT_LOGIN, false);
////tsDebugStream AuditLoginSuccess("Success", 1, AUDIT_LOGIN, false);
////tsDebugStream AuditLogout("Success", 1, AUDIT_LOGOUT, false);
////tsDebugStream AuditEncryptFailure("Failure", 1, AUDIT_ENCRYPT, false);
////tsDebugStream AuditEncryptSuccess("Success", 1, AUDIT_ENCRYPT, false);
////tsDebugStream AuditDecryptFailure("Failure", 1, AUDIT_DECRYPT, false);
////tsDebugStream AuditDecryptSuccess("Success", 1, AUDIT_DECRYPT, false);
////tsDebugStream AuditSignFailure("Failure", 1, AUDIT_SIGN, false);
////tsDebugStream AuditSignSuccess("Success", 1, AUDIT_SIGN, false);
////tsDebugStream AuditVerifyFailure("Failure", 1, AUDIT_VERIFY, false);
////tsDebugStream AuditVerifySuccess("Success", 1, AUDIT_VERIFY, false);
////tsDebugStream AuditHashFailure("Failure", 1, AUDIT_HASH, false);
////tsDebugStream AuditHashSuccess("Success", 1, AUDIT_HASH, false);
//
//extern HIDDEN tsCryptoString localGetErrorString(int errorNumber);
//
//
//
////std::shared_ptr<tscrypto::IServiceLocator> topServiceLocator()
////{
////	return ServiceLocator();
////}
////
////std::shared_ptr<tscrypto::IServiceLocator> rootServiceLocator()
////{
////	std::shared_ptr<tscrypto::IServiceLocator> p = ServiceLocator();
////
////	while (p->Creator().use_count() > 0)
////		p = p->Creator();
////	return p;
////}
//
//HIDDEN tsCryptoString localGetErrorString(int errorNumber)
//{
//	return "%s";
//}
//
//tsCryptoString ToXml(const char* src, const char* nullValue)
//{
//	if (src == nullptr || *src == 0)
//		return nullValue;
//	tsCryptoString tmp;
//	TSPatchValueForXML(tsCryptoString(src), tmp);
//	return tmp;
//}
//tsCryptoString ToXml(const tsCryptoString &src, const char* nullValue)
//{
//	if (src.size() == 0)
//		return nullValue;
//	tsCryptoString tmp;
//	TSPatchValueForXML(src, tmp);
//	return tmp;
//}
//tsCryptoString ToXml(const GUID &src, const char* nullValue)
//{
//	if (src == GUID_NULL)
//		return nullValue;
//	tsCryptoString tmp;
//	TSPatchValueForXML(TSGuidToString(src), tmp);
//	return tmp;
//}
//tsCryptoString ToXml(bool src, const char* nullValue)
//{
//	return ToXml(src ? "true" : "false");
//}
//tsCryptoString ToXml(int src, const char* nullValue)
//{
//	tsCryptoString tmp;
//	tmp << src;
//	return tmp;
//}
//tsCryptoString ToXml(double src, const char* nullValue)
//{
//	tsCryptoString tmp;
//	tmp << src;
//	return tmp;
//}
//tsCryptoString ToXml(const tsDate &src, const char* nullValue)
//{
//	if (src.GetStatus() != tsDate::valid)
//		return nullValue;
//	return ToXml(src.ToString());
//}
void tscrypto::TSPatchValueForXML(const tsCryptoStringBase &value, tsCryptoStringBase &out)
{
    size_t count;
    size_t i;
    char val;

    out.resize(0);
    count = value.size();
    for (i = 0; i < count; i++)
    {
        val = value.data()[i];
        if (val == '<')
            out += "&lt;";
        else if (val == '>')
            out += "&gt;";
        else if (val == '&')
            out += "&amp;";
        else if (val == '"')
            out += "&quot;";
        else if (val == '\'')
            out += "&apos;";
        else
            out += val;
    }
}

void* tscrypto::cryptoNew(size_t size)
{
    return std::malloc(size);
}
void tscrypto::cryptoDelete(void* ptr)
{
    if (ptr != nullptr)
    {
        std::free(ptr);
    }
}
