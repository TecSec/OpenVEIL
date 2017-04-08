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
#include "gtest/gtest.h"
#include "CodeGenTemplates.h"
#include "TestAsn1CkmHeader.h"
#include "core/CryptoAsn1.h"

using namespace tscrypto;

#pragma warning(push)
#pragma warning(disable: 6326)

#define TEST_JSON

static const uint8_t oid1[] = { 0x67, 0x2A, 0x09, 0x0A, 0x03, 0x00, 0x07, 0x09, 0x00 };
static const uint8_t oid2[] = { 0x67, 0x2A, 0x09, 0x0A, 0x03, 0x00, 0x07, 0x09, 0x32 };
static const uint8_t oid3[] = { 0x67, 0x2A, 0x09, 0x0A, 0x03, 0x00, 0x0B, 0x04 };
static const uint8_t oid4[] = { 0x67, 0x2A, 0x09, 0x0A, 0x03, 0x00, 0x0B };

TEST(Crypto, SelfTest) 
{
	EXPECT_TRUE(gFipsState.detailedSelfTest());
}

TEST(Crypto, CreateAlgs)
{
	EXPECT_TRUE(!!CryptoFactory("DRBG-SHA512"));
	EXPECT_TRUE(!!CryptoFactory("Sha1"));
	EXPECT_TRUE(!!CryptoFactory("Sha224"));
	EXPECT_TRUE(!!CryptoFactory("Sha256"));
	EXPECT_TRUE(!!CryptoFactory("Sha384"));
	EXPECT_TRUE(!!CryptoFactory("Sha512"));
	EXPECT_TRUE(!!CryptoFactory("MD5"));
	EXPECT_TRUE(!!CryptoFactory("RIPEMD160"));
	EXPECT_TRUE(!!CryptoFactory("HMAC-SHA1"));
	EXPECT_TRUE(!!CryptoFactory("HMAC-SHA224"));
	EXPECT_TRUE(!!CryptoFactory("HMAC-SHA256"));
	EXPECT_TRUE(!!CryptoFactory("HMAC-SHA384"));
	EXPECT_TRUE(!!CryptoFactory("HMAC-SHA512"));
	EXPECT_TRUE(!!CryptoFactory("HMAC-MD5"));
	EXPECT_TRUE(!!CryptoFactory("HMAC-RIPEMD160"));
	EXPECT_TRUE(!!CryptoFactory("TDES"));
	EXPECT_TRUE(!!CryptoFactory("TDES-64-CBC"));
	EXPECT_TRUE(!!CryptoFactory("TDES-64-CFB8"));
	EXPECT_TRUE(!!CryptoFactory("TDES-64-CFBfull"));
	EXPECT_TRUE(!!CryptoFactory("TDES-64-CTR"));
	EXPECT_TRUE(!!CryptoFactory("TDES-64-ECB"));
	EXPECT_TRUE(!!CryptoFactory("TDES-64-OFB"));
	EXPECT_TRUE(!!CryptoFactory("TDES-128-CBC"));
	EXPECT_TRUE(!!CryptoFactory("TDES-128-CFB8"));
	EXPECT_TRUE(!!CryptoFactory("TDES-128-CFBfull"));
	EXPECT_TRUE(!!CryptoFactory("TDES-128-CTR"));
	EXPECT_TRUE(!!CryptoFactory("TDES-128-ECB"));
	EXPECT_TRUE(!!CryptoFactory("TDES-128-OFB"));
	EXPECT_TRUE(!!CryptoFactory("TDES-192-CBC"));
	EXPECT_TRUE(!!CryptoFactory("TDES-192-CFB8"));
	EXPECT_TRUE(!!CryptoFactory("TDES-192-CFBfull"));
	EXPECT_TRUE(!!CryptoFactory("TDES-192-CTR"));
	EXPECT_TRUE(!!CryptoFactory("TDES-192-ECB"));
	EXPECT_TRUE(!!CryptoFactory("TDES-192-OFB"));
	EXPECT_TRUE(!!CryptoFactory("BLOWFISH"));
	EXPECT_TRUE(!!CryptoFactory("BLOWFISH-CBC"));
	EXPECT_TRUE(!!CryptoFactory("BLOWFISH-ECB"));
	EXPECT_TRUE(!!CryptoFactory("RC2"));
	EXPECT_TRUE(!!CryptoFactory("RC2-40-CBC"));
	EXPECT_TRUE(!!CryptoFactory("RC2-40-CFB8"));
	EXPECT_TRUE(!!CryptoFactory("RC2-40-CFBfull"));
	EXPECT_TRUE(!!CryptoFactory("RC2-40-CTR"));
	EXPECT_TRUE(!!CryptoFactory("RC2-40-ECB"));
	EXPECT_TRUE(!!CryptoFactory("RC2-40-OFB"));
	EXPECT_TRUE(!!CryptoFactory("RC2-128-CBC"));
	EXPECT_TRUE(!!CryptoFactory("RC2-128-CFB8"));
	EXPECT_TRUE(!!CryptoFactory("RC2-128-CFBfull"));
	EXPECT_TRUE(!!CryptoFactory("RC2-128-CTR"));
	EXPECT_TRUE(!!CryptoFactory("RC2-128-ECB"));
	EXPECT_TRUE(!!CryptoFactory("RC2-128-OFB"));
	EXPECT_TRUE(!!CryptoFactory("RC4"));
	EXPECT_TRUE(!!CryptoFactory("AES"));
	EXPECT_TRUE(!!CryptoFactory("AES-256-CBC"));
	EXPECT_TRUE(!!CryptoFactory("AES-256-ECB"));
	EXPECT_TRUE(!!CryptoFactory("AES-256-CFB8"));
	EXPECT_TRUE(!!CryptoFactory("AES-256-CFBfull"));
	EXPECT_TRUE(!!CryptoFactory("AES-256-CTR"));
	EXPECT_TRUE(!!CryptoFactory("AES-256-OFB"));
	EXPECT_TRUE(!!CryptoFactory("AES-192-CBC"));
	EXPECT_TRUE(!!CryptoFactory("AES-192-ECB"));
	EXPECT_TRUE(!!CryptoFactory("AES-192-CFB8"));
	EXPECT_TRUE(!!CryptoFactory("AES-192-CFBfull"));
	EXPECT_TRUE(!!CryptoFactory("AES-192-CTR"));
	EXPECT_TRUE(!!CryptoFactory("AES-192-OFB"));
	EXPECT_TRUE(!!CryptoFactory("AES-128-CBC"));
	EXPECT_TRUE(!!CryptoFactory("AES-128-ECB"));
	EXPECT_TRUE(!!CryptoFactory("AES-128-CFB8"));
	EXPECT_TRUE(!!CryptoFactory("AES-128-CFBfull"));
	EXPECT_TRUE(!!CryptoFactory("AES-128-CTR"));
	EXPECT_TRUE(!!CryptoFactory("AES-128-OFB"));
	EXPECT_TRUE(!!CryptoFactory("CCM-AES"));
	EXPECT_TRUE(!!CryptoFactory("CCM-AES-256"));
	EXPECT_TRUE(!!CryptoFactory("CCM-AES-192"));
	EXPECT_TRUE(!!CryptoFactory("CCM-AES-128"));
	EXPECT_TRUE(!!CryptoFactory("GCM-AES"));
	EXPECT_TRUE(!!CryptoFactory("GCM-AES-256"));
	EXPECT_TRUE(!!CryptoFactory("GCM-AES-192"));
	EXPECT_TRUE(!!CryptoFactory("GCM-AES-128"));
	EXPECT_TRUE(!!CryptoFactory("CMAC-AES"));
	EXPECT_TRUE(!!CryptoFactory("CMAC-AES-256"));
	EXPECT_TRUE(!!CryptoFactory("CMAC-AES-192"));
	EXPECT_TRUE(!!CryptoFactory("CMAC-AES-128"));
	EXPECT_TRUE(!!CryptoFactory("CMAC-TDES"));
	EXPECT_TRUE(!!CryptoFactory("CMAC-TDES-64"));
	EXPECT_TRUE(!!CryptoFactory("CMAC-TDES-128"));
	EXPECT_TRUE(!!CryptoFactory("CMAC-TDES-192"));
	EXPECT_TRUE(!!CryptoFactory("CMAC-BLOWFISH"));
	EXPECT_TRUE(!!CryptoFactory("CMAC-BLOWFISH-64"));
	EXPECT_TRUE(!!CryptoFactory("CMAC-BLOWFISH-128"));
	EXPECT_TRUE(!!CryptoFactory("CMAC-BLOWFISH-192"));
	EXPECT_TRUE(!!CryptoFactory("CMAC-XTEA"));
	EXPECT_TRUE(!!CryptoFactory("KDF-PBKDF2"));
	EXPECT_TRUE(!!CryptoFactory("KDF-CMAC-AES"));
	EXPECT_TRUE(!!CryptoFactory("KDF-CMAC-TDES"));
	EXPECT_TRUE(!!CryptoFactory("KDF-CMAC-BLOWFISH"));
	EXPECT_TRUE(!!CryptoFactory("KDF-CMAC-XTEA"));
	EXPECT_TRUE(!!CryptoFactory("KDF-HMAC-MD5"));
	EXPECT_TRUE(!!CryptoFactory("KDF-HMAC-Sha1"));
	EXPECT_TRUE(!!CryptoFactory("KDF-HMAC-Sha224"));
	EXPECT_TRUE(!!CryptoFactory("KDF-HMAC-Sha256"));
	EXPECT_TRUE(!!CryptoFactory("KDF-HMAC-Sha384"));
	EXPECT_TRUE(!!CryptoFactory("KDF-HMAC-Sha512"));
	EXPECT_TRUE(!!CryptoFactory("KDF-MD5"));
	EXPECT_TRUE(!!CryptoFactory("KDF-Sha1"));
	EXPECT_TRUE(!!CryptoFactory("KDF-Sha224"));
	EXPECT_TRUE(!!CryptoFactory("KDF-Sha256"));
	EXPECT_TRUE(!!CryptoFactory("KDF-Sha384"));
	EXPECT_TRUE(!!CryptoFactory("KDF-Sha512"));
	EXPECT_TRUE(!!CryptoFactory("KDF-HMAC-RIPEMD160"));
	EXPECT_TRUE(!!CryptoFactory("KDF-RIPEMD160"));
	EXPECT_TRUE(!!CryptoFactory("KEYWRAP-AES"));
	EXPECT_TRUE(!!CryptoFactory("KEYWRAP-RFC3394-AES"));
	EXPECT_TRUE(!!CryptoFactory("KEYWRAP-RFC3394-AES-256"));
	EXPECT_TRUE(!!CryptoFactory("KEYWRAP-RFC3394-AES-192"));
	EXPECT_TRUE(!!CryptoFactory("KEYWRAP-RFC3394-AES-128"));
	EXPECT_TRUE(!!CryptoFactory("KEYWRAP-TDES"));
	EXPECT_TRUE(!!CryptoFactory("KEYWRAP-BLOWFISH"));
	EXPECT_TRUE(!!CryptoFactory("KEYWRAP-XTEA"));
	EXPECT_TRUE(!!CryptoFactory("PRIME-PROVABLE"));
	EXPECT_TRUE(!!CryptoFactory("PRIME-PROBABLE"));
//	EXPECT_TRUE(!!CryptoFactory("PRIME-X9.31"));
//	EXPECT_TRUE(!!CryptoFactory("PARAMETERSET-DH"));
//	EXPECT_TRUE(!!CryptoFactory("KEY-DH"));
//	EXPECT_TRUE(!!CryptoFactory("KEY-DSA"));
	EXPECT_TRUE(!!CryptoFactory("KEY-RSA"));
//	EXPECT_TRUE(!!CryptoFactory("KEY-RSA-X9.31"));
//	EXPECT_TRUE(!!CryptoFactory("ENCODE-RSA-X9.31"));
//	EXPECT_TRUE(!!CryptoFactory("ENCODE-RSA-PSS"));
//	EXPECT_TRUE(!!CryptoFactory("ENCODE-RSA-PKCS"));
	EXPECT_TRUE(!!CryptoFactory("ENCODE-RSA-ENCRYPT-PKCS"));
	EXPECT_TRUE(!!CryptoFactory("RSA-OAEP-SHA1"));
	EXPECT_TRUE(!!CryptoFactory("RSA-OAEP-SHA224"));
	EXPECT_TRUE(!!CryptoFactory("RSA-OAEP-SHA256"));
	EXPECT_TRUE(!!CryptoFactory("RSA-OAEP-SHA384"));
	EXPECT_TRUE(!!CryptoFactory("RSA-OAEP-SHA512"));
	//EXPECT_TRUE(!!CryptoFactory("SIGN-RSA-X9.31-SHA1"));
	//EXPECT_TRUE(!!CryptoFactory("SIGN-RSA-X9.31-SHA224"));
	//EXPECT_TRUE(!!CryptoFactory("SIGN-RSA-X9.31-SHA256"));
	//EXPECT_TRUE(!!CryptoFactory("SIGN-RSA-X9.31-SHA384"));
	//EXPECT_TRUE(!!CryptoFactory("SIGN-RSA-X9.31-SHA512"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-RSA-PKCS"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-RSA-PKCS-MD5"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-RSA-PKCS-SHA1"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-RSA-PKCS-SHA224"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-RSA-PKCS-SHA256"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-RSA-PKCS-SHA384"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-RSA-PKCS-SHA512"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-RSA-PSS-SHA1"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-RSA-PSS-SHA224"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-RSA-PSS-SHA256"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-RSA-PSS-SHA384"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-RSA-PSS-SHA512"));
	EXPECT_TRUE(!!CryptoFactory("KEY-P256"));
	EXPECT_TRUE(!!CryptoFactory("KEY-P384"));
	EXPECT_TRUE(!!CryptoFactory("KEY-P521"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-ECC-SHA1"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-ECC-SHA224"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-ECC-SHA256"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-ECC-SHA384"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-ECC-SHA512"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-DSA-SHA1"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-DSA-SHA224"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-DSA-SHA256"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-DSA-SHA384"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-DSA-SHA512"));
	EXPECT_TRUE(!!CryptoFactory("X25519"));
	//EXPECT_TRUE(!!CryptoFactory("X25519_PH"));
	EXPECT_TRUE(!!CryptoFactory("NUMSP256D1"));
	EXPECT_TRUE(!!CryptoFactory("NUMSP384D1"));
	EXPECT_TRUE(!!CryptoFactory("NUMSP512D1"));
	EXPECT_TRUE(!!CryptoFactory("NUMSP256T1"));
	EXPECT_TRUE(!!CryptoFactory("NUMSP384T1"));
	EXPECT_TRUE(!!CryptoFactory("NUMSP512T1"));
	EXPECT_TRUE(!!CryptoFactory("CKMAUTH"));
	EXPECT_TRUE(!!CryptoFactory("CKMAUTH_CALCULATOR-PBKDF2-SHA1"));
	EXPECT_TRUE(!!CryptoFactory("CKMAUTH_CALCULATOR-PBKDF2-SHA224"));
	EXPECT_TRUE(!!CryptoFactory("CKMAUTH_CALCULATOR-PBKDF2-SHA256"));
	EXPECT_TRUE(!!CryptoFactory("CKMAUTH_CALCULATOR-PBKDF2-SHA384"));
	EXPECT_TRUE(!!CryptoFactory("CKMAUTH_CALCULATOR-PBKDF2-SHA512"));
	EXPECT_TRUE(!!CryptoFactory("SHA3-512"));
	EXPECT_TRUE(!!CryptoFactory("SHA3-224"));
	EXPECT_TRUE(!!CryptoFactory("SHA3-256"));
	EXPECT_TRUE(!!CryptoFactory("SHA3-384"));
	EXPECT_TRUE(!!CryptoFactory("SHAKE128"));
	EXPECT_TRUE(!!CryptoFactory("SHAKE256"));
	EXPECT_TRUE(!!CryptoFactory("HMAC-SHA3-224"));
	EXPECT_TRUE(!!CryptoFactory("HMAC-SHA3-256"));
	EXPECT_TRUE(!!CryptoFactory("HMAC-SHA3-384"));
	EXPECT_TRUE(!!CryptoFactory("HMAC-SHA3-512"));
	EXPECT_TRUE(!!CryptoFactory("KDF-HMAC-SHA3-224"));
	EXPECT_TRUE(!!CryptoFactory("KDF-HMAC-SHA3-256"));
	EXPECT_TRUE(!!CryptoFactory("KDF-HMAC-SHA3-384"));
	EXPECT_TRUE(!!CryptoFactory("KDF-HMAC-SHA3-512"));
	EXPECT_TRUE(!!CryptoFactory("KDF-SHA3-224"));
	EXPECT_TRUE(!!CryptoFactory("KDF-SHA3-256"));
	EXPECT_TRUE(!!CryptoFactory("KDF-SHA3-384"));
	EXPECT_TRUE(!!CryptoFactory("KDF-SHA3-512"));
	EXPECT_TRUE(!!CryptoFactory("POLY1305"));
	EXPECT_TRUE(!!CryptoFactory("SALSA20"));
	EXPECT_TRUE(!!CryptoFactory("XSALSA20"));
	EXPECT_TRUE(!!CryptoFactory("SALSA20_POLY1305"));
	EXPECT_TRUE(!!CryptoFactory("CHACHA20"));
	EXPECT_TRUE(!!CryptoFactory("CHACHA20_POLY1305"));
	EXPECT_TRUE(!!CryptoFactory("CAMELLIA"));
	EXPECT_TRUE(!!CryptoFactory("CAMELLIA-256-CBC"));
	EXPECT_TRUE(!!CryptoFactory("CAMELLIA-256-ECB"));
	EXPECT_TRUE(!!CryptoFactory("CAMELLIA-256-CFB8"));
	EXPECT_TRUE(!!CryptoFactory("CAMELLIA-256-CFBfull"));
	EXPECT_TRUE(!!CryptoFactory("CAMELLIA-256-CTR"));
	EXPECT_TRUE(!!CryptoFactory("CAMELLIA-256-OFB"));
	EXPECT_TRUE(!!CryptoFactory("CAMELLIA-192-CBC"));
	EXPECT_TRUE(!!CryptoFactory("CAMELLIA-192-ECB"));
	EXPECT_TRUE(!!CryptoFactory("CAMELLIA-192-CFB8"));
	EXPECT_TRUE(!!CryptoFactory("CAMELLIA-192-CFBfull"));
	EXPECT_TRUE(!!CryptoFactory("CAMELLIA-192-CTR"));
	EXPECT_TRUE(!!CryptoFactory("CAMELLIA-192-OFB"));
	EXPECT_TRUE(!!CryptoFactory("CAMELLIA-128-CBC"));
	EXPECT_TRUE(!!CryptoFactory("CAMELLIA-128-ECB"));
	EXPECT_TRUE(!!CryptoFactory("CAMELLIA-128-CFB8"));
	EXPECT_TRUE(!!CryptoFactory("CAMELLIA-128-CFBfull"));
	EXPECT_TRUE(!!CryptoFactory("CAMELLIA-128-CTR"));
	EXPECT_TRUE(!!CryptoFactory("CAMELLIA-128-OFB"));
	EXPECT_TRUE(!!CryptoFactory("CMAC-CAMELLIA"));
	EXPECT_TRUE(!!CryptoFactory("CMAC-CAMELLIA-256"));
	EXPECT_TRUE(!!CryptoFactory("CMAC-CAMELLIA-192"));
	EXPECT_TRUE(!!CryptoFactory("CMAC-CAMELLIA-128"));
	EXPECT_TRUE(!!CryptoFactory("KEYWRAP-CAMELLIA"));
	EXPECT_TRUE(!!CryptoFactory("KEYWRAP-RFC3394-CAMELLIA"));
	EXPECT_TRUE(!!CryptoFactory("KEYWRAP-RFC3394-CAMELLIA-256"));
	EXPECT_TRUE(!!CryptoFactory("KEYWRAP-RFC3394-CAMELLIA-192"));
	EXPECT_TRUE(!!CryptoFactory("KEYWRAP-RFC3394-CAMELLIA-128"));
	EXPECT_TRUE(!!CryptoFactory("KDF-CMAC-CAMELLIA"));
	EXPECT_TRUE(!!CryptoFactory("CCM-CAMELLIA"));
	EXPECT_TRUE(!!CryptoFactory("CCM-CAMELLIA-256"));
	EXPECT_TRUE(!!CryptoFactory("CCM-CAMELLIA-192"));
	EXPECT_TRUE(!!CryptoFactory("CCM-CAMELLIA-128"));
	EXPECT_TRUE(!!CryptoFactory("GCM-CAMELLIA"));
	EXPECT_TRUE(!!CryptoFactory("GCM-CAMELLIA-256"));
	EXPECT_TRUE(!!CryptoFactory("GCM-CAMELLIA-192"));
	EXPECT_TRUE(!!CryptoFactory("GCM-CAMELLIA-128"));
	EXPECT_TRUE(!!CryptoFactory("ARIA"));
	EXPECT_TRUE(!!CryptoFactory("ARIA-256-CBC"));
	EXPECT_TRUE(!!CryptoFactory("ARIA-256-ECB"));
	EXPECT_TRUE(!!CryptoFactory("ARIA-256-CFB8"));
	EXPECT_TRUE(!!CryptoFactory("ARIA-256-CFBfull"));
	EXPECT_TRUE(!!CryptoFactory("ARIA-256-CTR"));
	EXPECT_TRUE(!!CryptoFactory("ARIA-256-OFB"));
	EXPECT_TRUE(!!CryptoFactory("ARIA-192-CBC"));
	EXPECT_TRUE(!!CryptoFactory("ARIA-192-ECB"));
	EXPECT_TRUE(!!CryptoFactory("ARIA-192-CFB8"));
	EXPECT_TRUE(!!CryptoFactory("ARIA-192-CFBfull"));
	EXPECT_TRUE(!!CryptoFactory("ARIA-192-CTR"));
	EXPECT_TRUE(!!CryptoFactory("ARIA-192-OFB"));
	EXPECT_TRUE(!!CryptoFactory("ARIA-128-CBC"));
	EXPECT_TRUE(!!CryptoFactory("ARIA-128-ECB"));
	EXPECT_TRUE(!!CryptoFactory("ARIA-128-CFB8"));
	EXPECT_TRUE(!!CryptoFactory("ARIA-128-CFBfull"));
	EXPECT_TRUE(!!CryptoFactory("ARIA-128-CTR"));
	EXPECT_TRUE(!!CryptoFactory("ARIA-128-OFB"));
	EXPECT_TRUE(!!CryptoFactory("CMAC-ARIA"));
	EXPECT_TRUE(!!CryptoFactory("CMAC-ARIA-256"));
	EXPECT_TRUE(!!CryptoFactory("CMAC-ARIA-192"));
	EXPECT_TRUE(!!CryptoFactory("CMAC-ARIA-128"));
	EXPECT_TRUE(!!CryptoFactory("KEYWRAP-ARIA"));
	EXPECT_TRUE(!!CryptoFactory("KEYWRAP-RFC3394-ARIA"));
	EXPECT_TRUE(!!CryptoFactory("KEYWRAP-RFC3394-ARIA-256"));
	EXPECT_TRUE(!!CryptoFactory("KEYWRAP-RFC3394-ARIA-192"));
	EXPECT_TRUE(!!CryptoFactory("KEYWRAP-RFC3394-ARIA-128"));
	EXPECT_TRUE(!!CryptoFactory("KDF-CMAC-ARIA"));
	EXPECT_TRUE(!!CryptoFactory("CCM-ARIA"));
	EXPECT_TRUE(!!CryptoFactory("CCM-ARIA-256"));
	EXPECT_TRUE(!!CryptoFactory("CCM-ARIA-192"));
	EXPECT_TRUE(!!CryptoFactory("CCM-ARIA-128"));
	EXPECT_TRUE(!!CryptoFactory("GCM-ARIA"));
	EXPECT_TRUE(!!CryptoFactory("GCM-ARIA-256"));
	EXPECT_TRUE(!!CryptoFactory("GCM-ARIA-192"));
	EXPECT_TRUE(!!CryptoFactory("GCM-ARIA-128"));
	EXPECT_TRUE(!!CryptoFactory("SEED"));
	EXPECT_TRUE(!!CryptoFactory("SEED-128-CBC"));
	EXPECT_TRUE(!!CryptoFactory("SEED-128-ECB"));
	EXPECT_TRUE(!!CryptoFactory("SEED-128-CFB8"));
	EXPECT_TRUE(!!CryptoFactory("SEED-128-CFBfull"));
	EXPECT_TRUE(!!CryptoFactory("SEED-128-CTR"));
	EXPECT_TRUE(!!CryptoFactory("SEED-128-OFB"));
	EXPECT_TRUE(!!CryptoFactory("CMAC-SEED"));
	EXPECT_TRUE(!!CryptoFactory("CMAC-SEED-128"));
	EXPECT_TRUE(!!CryptoFactory("KEYWRAP-SEED"));
	EXPECT_TRUE(!!CryptoFactory("KEYWRAP-RFC3394-SEED"));
	EXPECT_TRUE(!!CryptoFactory("KEYWRAP-RFC3394-SEED-128"));
	EXPECT_TRUE(!!CryptoFactory("KDF-CMAC-SEED"));
	EXPECT_TRUE(!!CryptoFactory("CCM-SEED"));
	EXPECT_TRUE(!!CryptoFactory("CCM-SEED-128"));
	EXPECT_TRUE(!!CryptoFactory("GCM-SEED"));
	EXPECT_TRUE(!!CryptoFactory("GCM-SEED-128"));
	EXPECT_TRUE(!!CryptoFactory("XTS-AES"));
	EXPECT_TRUE(!!CryptoFactory("XTS-AES-256"));
	EXPECT_TRUE(!!CryptoFactory("XTS-AES-192"));
	EXPECT_TRUE(!!CryptoFactory("XTS-AES-128"));
	EXPECT_TRUE(!!CryptoFactory("XTS-CAMELLIA"));
	EXPECT_TRUE(!!CryptoFactory("XTS-CAMELLIA-256"));
	EXPECT_TRUE(!!CryptoFactory("XTS-CAMELLIA-192"));
	EXPECT_TRUE(!!CryptoFactory("XTS-CAMELLIA-128"));
	EXPECT_TRUE(!!CryptoFactory("XTS-ARIA"));
	EXPECT_TRUE(!!CryptoFactory("XTS-ARIA-256"));
	EXPECT_TRUE(!!CryptoFactory("XTS-ARIA-192"));
	EXPECT_TRUE(!!CryptoFactory("XTS-ARIA-128"));
	EXPECT_TRUE(!!CryptoFactory("XTS-SEED"));
	EXPECT_TRUE(!!CryptoFactory("XTS-SEED-128"));
	EXPECT_TRUE(!!CryptoFactory("KEY-P256K1"));
	//EXPECT_TRUE(!!CryptoFactory("SIGN-RSA-X9.31-SHA3-224"));
	//EXPECT_TRUE(!!CryptoFactory("SIGN-RSA-X9.31-SHA3-256"));
	//EXPECT_TRUE(!!CryptoFactory("SIGN-RSA-X9.31-SHA3-384"));
	//EXPECT_TRUE(!!CryptoFactory("SIGN-RSA-X9.31-SHA3-512"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-RSA-PKCS-SHA3-224"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-RSA-PKCS-SHA3-256"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-RSA-PKCS-SHA3-384"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-RSA-PKCS-SHA3-512"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-RSA-PSS-SHA3-224"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-RSA-PSS-SHA3-256"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-RSA-PSS-SHA3-384"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-RSA-PSS-SHA3-512"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-ECC-SHA3-224"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-ECC-SHA3-256"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-ECC-SHA3-384"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-ECC-SHA3-512"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-DSA-SHA3-224"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-DSA-SHA3-256"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-DSA-SHA3-384"));
	EXPECT_TRUE(!!CryptoFactory("SIGN-DSA-SHA3-512"));
	EXPECT_TRUE(!!CryptoFactory("KAS"));
	EXPECT_TRUE(!!CryptoFactory("RSASVE"));
	EXPECT_TRUE(!!CryptoFactory("RSA-KEM-KWS"));
	EXPECT_TRUE(!!CryptoFactory("RSAKAS1"));
	EXPECT_TRUE(!!CryptoFactory("RSAKAS2"));
	EXPECT_TRUE(!!CryptoFactory("KTS-OAEP"));
	EXPECT_TRUE(!!CryptoFactory("KTS-KEM-KWS"));
	//EXPECT_TRUE(!!CryptoFactory("CKM7CRYPTOGROUP-P256-SHA512"));
	//EXPECT_TRUE(!!CryptoFactory("CKM7CRYPTOGROUP-P384-SHA512"));
	//EXPECT_TRUE(!!CryptoFactory("CKM7CRYPTOGROUP-P521-SHA512"));
	//EXPECT_TRUE(!!CryptoFactory("CKM7CRYPTOGROUP-X25519-SHA512"));
	//EXPECT_TRUE(!!CryptoFactory("CKM7CRYPTOGROUP-P256K1-SHA512"));
	//EXPECT_TRUE(!!CryptoFactory("CKM7CRYPTOGROUP-NUMSP256D1-SHA512"));
	//EXPECT_TRUE(!!CryptoFactory("CKM7CRYPTOGROUP-NUMSP384D1-SHA512"));
	//EXPECT_TRUE(!!CryptoFactory("CKM7CRYPTOGROUP-NUMSP512D1-SHA512"));
	//EXPECT_TRUE(!!CryptoFactory("CKM7CRYPTOGROUP-NUMSP256T1-SHA512"));
	//EXPECT_TRUE(!!CryptoFactory("CKM7CRYPTOGROUP-NUMSP384T1-SHA512"));
	//EXPECT_TRUE(!!CryptoFactory("CKM7CRYPTOGROUP-NUMSP512T1-SHA512"));
	//EXPECT_TRUE(!!CryptoFactory("CKM7ATTRIBUTE-SYM"));
	//EXPECT_TRUE(!!CryptoFactory("CKM7ATTRIBUTE-P256"));
	//EXPECT_TRUE(!!CryptoFactory("CKM7ATTRIBUTE-P384"));
	//EXPECT_TRUE(!!CryptoFactory("CKM7ATTRIBUTE-P521"));
	//EXPECT_TRUE(!!CryptoFactory("CKM7ATTRIBUTE-X25519"));
	//EXPECT_TRUE(!!CryptoFactory("CKM7ATTRIBUTE-P256K1"));
	//EXPECT_TRUE(!!CryptoFactory("CKM7ATTRIBUTE-NUMSP256D1"));
	//EXPECT_TRUE(!!CryptoFactory("CKM7ATTRIBUTE-NUMSP384D1"));
	//EXPECT_TRUE(!!CryptoFactory("CKM7ATTRIBUTE-NUMSP512D1"));
	//EXPECT_TRUE(!!CryptoFactory("CKM7ATTRIBUTE-NUMSP256T1"));
	//EXPECT_TRUE(!!CryptoFactory("CKM7ATTRIBUTE-NUMSP384T1"));
	//EXPECT_TRUE(!!CryptoFactory("CKM7ATTRIBUTE-NUMSP512T1"));
	//EXPECT_TRUE(!!CryptoFactory("CKM7COMBINER"));
	EXPECT_TRUE(!!CryptoFactory("CKMAUTH_CALCULATOR-PBKDF2-SHA3-224"));
	EXPECT_TRUE(!!CryptoFactory("CKMAUTH_CALCULATOR-PBKDF2-SHA3-256"));
	EXPECT_TRUE(!!CryptoFactory("CKMAUTH_CALCULATOR-PBKDF2-SHA3-384"));
	EXPECT_TRUE(!!CryptoFactory("CKMAUTH_CALCULATOR-PBKDF2-SHA3-512"));
}

//TEST(Crypto, testAllPublishedAlgs)
//{
//	size_t count = GetAlgorithmCount();
//
//	for (size_t i = 0; i < count; i++)
//	{
//		tscrypto::tsCryptoString name = GetAlgorithmNameByIndex(i);
//		std::shared_ptr<Selftest> test = std::dynamic_pointer_cast<Selftest>(ConstructAlgorithmByIndex(i));
//		std::shared_ptr<AlgorithmInfo> info = std::dynamic_pointer_cast<AlgorithmInfo>(test);
//
//		EXPECT_TRUE(!!test) << "Algorithm " << name.c_str() << " does not support testing";
//		if (!!test)
//		{
//			tscrypto::tsCryptoString name(info->AlgorithmName());
//			tscrypto::tsCryptoString oid(info->AlgorithmOID());
//			tscrypto::tsCryptoString id;
//			id << info->AlgorithmID();
//			name.resize(35, ' ');
//			oid.resize(27, ' ');
//			id.resize(4, ' ');
//
//			EXPECT_TRUE(test->runTests(true)) << "Algorithm " << name.c_str() << " FAILED";
//		}
//	}
//}
TEST(Crypto, TDES_CFB8_MMT_Issue_c)
{
	const SymmetricAlgorithmDescriptor *desc = findSymmetricAlgorithm("TDES-CFB8");
	tsCryptoData key1(std::initializer_list<uint8_t>{0x10, 0x04, 0x67, 0x83, 0x97, 0x91, 0xab, 0x3d});
	tsCryptoData iv1(std::initializer_list<uint8_t>{0xc0, 0x59, 0xed, 0x45, 0x76, 0xec, 0x5c, 0xc4});
	tsCryptoData ct1(std::initializer_list<uint8_t>{0x25});
	tsCryptoData pt1(std::initializer_list<uint8_t>{0x48});
	tsCryptoData outData;
	tsCryptoData context;

	ASSERT_NE(nullptr, desc);

	context.resize(desc->getWorkspaceSize(desc));
	// First encrypt and make sure it works
	outData.clear();
	outData.resize(pt1.size());
	EXPECT_TRUE(desc->init(desc, context.rawData(), true, key1.c_str(), (uint32_t)key1.size(), iv1.c_str(), (uint32_t)iv1.size(), 0));
	EXPECT_TRUE(desc->update(desc, context.rawData(), pt1.c_str(), (uint32_t)ct1.size(), outData.rawData()));
	EXPECT_TRUE(desc->finish(desc, context.rawData()));
	EXPECT_STREQ(ct1.ToHexStringWithSpaces().c_str(), outData.ToHexStringWithSpaces().c_str());

	// Now see if the decrypt works
	outData.clear();
	outData.resize(ct1.size());
	EXPECT_TRUE(desc->init(desc, context.rawData(), false, key1.c_str(), (uint32_t)key1.size(), iv1.c_str(), (uint32_t)iv1.size(), 0));
	EXPECT_TRUE(desc->update(desc, context.rawData(), ct1.c_str(), (uint32_t)ct1.size(), outData.rawData()));
	EXPECT_TRUE(desc->finish(desc, context.rawData()));
	EXPECT_STREQ(pt1.ToHexStringWithSpaces().c_str(), outData.ToHexStringWithSpaces().c_str());
}


TEST(Asn1CodeGenTests, Decode_Encode_round_trip) {
	tscrypto::tsCryptoData inData("30 81 a6 06 0a 67 2a 09 0a 03 00 09 05 16 01 04 48 df 20 de a8 27 76 1a 89 0d c5 62 18 32 20 20 b9 6c 1e 33 e8 52 d3 d3 73 86 02 fd 31 cc d5 0d 6c 5b 81 88 a3 77 54 cb 98 7f 5d 93 89 db d7 17 a1 cb b9 cd 80 60 9e 79 bc 53 87 26 e6 e3 3e 64 b2 60 29 4c 79 aa f7 8e 9d a0 30 04 20 2b 30 66 8a fe a3 5e d5 ab bc 48 33 bd 0b 6f 53 92 51 e8 ef 42 28 e9 b5 16 49 ce 63 59 6b b8 9f 02 02 03 e8 06 08 2a 86 48 86 f7 0d 02 0b 02 01 00 02 01 00 18 00 02 01 00 18 00 18 0f 32 30 31 36 31 31 30 39 31 35 35 36 32 30 5a", tscrypto::tsCryptoData::HEX);
	TEST::_POD_TokenAuthentication ta;

	EXPECT_EQ(true, ta.Decode(inData));
	ta.set_VERSION(0);
	EXPECT_EQ(inData, ta.Encode());
}

TEST(Asn1CodeGenTests, Decode_Encode_round_trip_auto_upgrade) {
	tscrypto::tsCryptoData inData("30 81 a6 06 0a 67 2a 09 0a 03 00 09 05 16 01 04 48 df 20 de a8 27 76 1a 89 0d c5 62 18 32 20 20 b9 6c 1e 33 e8 52 d3 d3 73 86 02 fd 31 cc d5 0d 6c 5b 81 88 a3 77 54 cb 98 7f 5d 93 89 db d7 17 a1 cb b9 cd 80 60 9e 79 bc 53 87 26 e6 e3 3e 64 b2 60 29 4c 79 aa f7 8e 9d a0 30 04 20 2b 30 66 8a fe a3 5e d5 ab bc 48 33 bd 0b 6f 53 92 51 e8 ef 42 28 e9 b5 16 49 ce 63 59 6b b8 9f 02 02 03 e8 06 08 2a 86 48 86 f7 0d 02 0b 02 01 00 02 01 00 18 00 02 01 00 18 00 18 0f 32 30 31 36 31 31 30 39 31 35 35 36 32 30 5a", tscrypto::tsCryptoData::HEX);
	tscrypto::tsCryptoData outData("30 81 a9 06 0a 67 2a 09 0a 03 00 09 05 16 02 01 01 01 04 48 df 20 de a8 27 76 1a 89 0d c5 62 18 32 20 20 b9 6c 1e 33 e8 52 d3 d3 73 86 02 fd 31 cc d5 0d 6c 5b 81 88 a3 77 54 cb 98 7f 5d 93 89 db d7 17 a1 cb b9 cd 80 60 9e 79 bc 53 87 26 e6 e3 3e 64 b2 60 29 4c 79 aa f7 8e 9d a0 30 04 20 2b 30 66 8a fe a3 5e d5 ab bc 48 33 bd 0b 6f 53 92 51 e8 ef 42 28 e9 b5 16 49 ce 63 59 6b b8 9f 02 02 03 e8 06 08 2a 86 48 86 f7 0d 02 0b 0A 01 00 02 01 00 18 00 02 01 00 18 00 18 0f 32 30 31 36 31 31 30 39 31 35 35 36 32 30 5a", tscrypto::tsCryptoData::HEX);
	TEST::_POD_TokenAuthentication ta;

	EXPECT_EQ(true, ta.Decode(inData));
	EXPECT_NE(inData, ta.Encode());
}


static const char* TEST_HEADER1 = "30 82 02 61 06 06 2A 86 48 CE 4C 04 02 01 00 02 01 07 81 10 DE 5C AC 8A B1 E3 16 44 B9 72 AF 4E 91 3A 9D 08 18 0F 32 30 31 33 30 39 32 30 30 32 31 31 34 34 5A 30 0D 06 09 60 86 48 01 65 03 04 01 2E 05 00 A2 82 01 CD 30 6C 06 09 67 2A 09 0A 03 00 02 02 06 01 01 FF 04 5C 30 5A 30 58 04 10 D7 F7 F6 6C 84 C8 73 48 91 0D CD 0A D6 BF 21 13 02 01 00 04 41 04 D9 67 6A C7 93 87 78 C7 D4 55 53 24 2E BF 42 FF B1 74 72 75 1F A8 8B 63 0F 93 24 D2 E1 8F C3 74 C3 3B 55 B4 15 B2 89 52 6B 1F 25 BD BD AB 96 E8 E0 B8 9F E4 40 05 45 0E 32 3F 74 85 3B A7 FF 81 30 75 06 09 67 2A 09 0A 03 00 02 02 09 01 01 FF 04 65 30 63 30 61 04 10 AF 01 48 6C 4B 54 30 42 88 AB 7E 9F 36 F3 BA FE 02 01 00 02 01 00 04 47 30 45 02 21 00 B5 12 85 6B FA 70 4F 88 43 5A 90 53 1A 08 AE 40 B9 5B 98 43 80 B9 BC 92 FC FC B8 7B AE 7F 12 FE 02 20 2B 1B B2 27 B9 DC 66 4C 13 DA 23 A1 0B 47 40 44 DB B4 D5 57 E8 06 D9 6D 05 D4 9B E3 1B BD A3 0A 30 1D 06 09 67 2A 09 0A 03 00 02 02 08 04 10 D7 F7 F6 6C 84 C8 73 48 91 0D CD 0A D6 BF 21 13 30 43 06 09 67 2A 09 0A 03 00 02 02 07 01 01 FF 04 33 30 31 A3 2F 30 03 02 01 00 04 28 50 A7 36 34 A9 5A 65 A3 83 98 7E 74 CF 76 C0 46 80 A6 31 0D 18 68 05 44 E2 34 D9 F1 3D C6 69 27 AA 2A B9 5B EB 4C 7E BA 30 1E 06 09 67 2A 09 0A 03 00 02 02 0B 04 11 30 0F 06 09 67 2A 09 0A 03 00 07 01 02 02 02 01 00 30 15 06 09 67 2A 09 0A 03 00 02 02 03 04 08 FF FF FF FF FF FF FF FF 30 1C 06 09 67 2A 09 0A 03 00 02 02 01 01 01 FF 04 0C 8E 41 AB 11 7B 26 CA 98 56 7F 7E 8A 30 18 06 09 67 2A 09 0A 03 00 02 02 10 04 0B 30 09 02 03 4C 4B 40 02 02 20 02 30 13 06 09 67 2A 09 0A 03 00 02 02 05 04 06 4D 65 6D 6F 72 79 A3 0C 06 08 2A 86 48 86 F7 0D 02 0B 05 00 84 40 88 FE B3 A2 EC 3B F2 A1 86 88 1C 01 12 E0 B2 A6 50 21 05 14 A2 14 BA 4B F7 37 FB 06 39 7F DD 75 C2 B4 E4 10 FF A0 CF 62 E3 A1 3F 15 38 28 DC C1 E9 4D 15 20 8E D4 19 DE 02 66 B5 9A AD F8 63 23";
static const char* TEST_SIGNABLE1 = "30 82 02 1F 06 06 2A 86 48 CE 4C 04 02 01 00 02 01 07 81 10 DE 5C AC 8A B1 E3 16 44 B9 72 AF 4E 91 3A 9D 08 18 0F 32 30 31 33 30 39 32 30 30 32 31 31 34 34 5A 30 0D 06 09 60 86 48 01 65 03 04 01 2E 05 00 A2 82 01 CD 30 6C 06 09 67 2A 09 0A 03 00 02 02 06 01 01 FF 04 5C 30 5A 30 58 04 10 D7 F7 F6 6C 84 C8 73 48 91 0D CD 0A D6 BF 21 13 02 01 00 04 41 04 D9 67 6A C7 93 87 78 C7 D4 55 53 24 2E BF 42 FF B1 74 72 75 1F A8 8B 63 0F 93 24 D2 E1 8F C3 74 C3 3B 55 B4 15 B2 89 52 6B 1F 25 BD BD AB 96 E8 E0 B8 9F E4 40 05 45 0E 32 3F 74 85 3B A7 FF 81 30 75 06 09 67 2A 09 0A 03 00 02 02 09 01 01 FF 04 65 30 63 30 61 04 10 AF 01 48 6C 4B 54 30 42 88 AB 7E 9F 36 F3 BA FE 02 01 00 02 01 00 04 47 30 45 02 21 00 B5 12 85 6B FA 70 4F 88 43 5A 90 53 1A 08 AE 40 B9 5B 98 43 80 B9 BC 92 FC FC B8 7B AE 7F 12 FE 02 20 2B 1B B2 27 B9 DC 66 4C 13 DA 23 A1 0B 47 40 44 DB B4 D5 57 E8 06 D9 6D 05 D4 9B E3 1B BD A3 0A 30 1D 06 09 67 2A 09 0A 03 00 02 02 08 04 10 D7 F7 F6 6C 84 C8 73 48 91 0D CD 0A D6 BF 21 13 30 43 06 09 67 2A 09 0A 03 00 02 02 07 01 01 FF 04 33 30 31 A3 2F 30 03 02 01 00 04 28 50 A7 36 34 A9 5A 65 A3 83 98 7E 74 CF 76 C0 46 80 A6 31 0D 18 68 05 44 E2 34 D9 F1 3D C6 69 27 AA 2A B9 5B EB 4C 7E BA 30 1E 06 09 67 2A 09 0A 03 00 02 02 0B 04 11 30 0F 06 09 67 2A 09 0A 03 00 07 01 02 02 02 01 00 30 15 06 09 67 2A 09 0A 03 00 02 02 03 04 08 FF FF FF FF FF FF FF FF 30 1C 06 09 67 2A 09 0A 03 00 02 02 01 01 01 FF 04 0C 8E 41 AB 11 7B 26 CA 98 56 7F 7E 8A 30 18 06 09 67 2A 09 0A 03 00 02 02 10 04 0B 30 09 02 03 4C 4B 40 02 02 20 02 30 13 06 09 67 2A 09 0A 03 00 02 02 05 04 06 4D 65 6D 6F 72 79 A3 0C 06 08 2A 86 48 86 F7 0D 02 0B 05 00";
static const char* TEST_HEADER2 = "30 82 01 ec 06 06 2a 86 48 ce 4c 04 02 01 00 02 01 07 81 10 25 0f 4e 30 e1 cb 84 4e 86 45 d7 0a c4 78 d7 ee 18 0f 32 30 31 34 30 32 31 30 31 38 30 35 30 33 5a 02 01 65 a2 82 01 72 30 1d 06 09 67 2a 09 0a 03 00 02 02 08 04 10 ca b7 f4 e3 fa bb db 46 8e 2f f6 84 91 6c a6 c0 30 1e 06 09 67 2a 09 0a 03 00 02 02 0b 04 11 30 0f 06 09 67 2a 09 0a 03 00 07 01 01 02 02 02 00 30 6e 06 09 67 2a 09 0a 03 00 02 02 06 01 01 ff 04 5e 30 5c 30 5a 30 58 04 10 83 cb 7e dc b2 45 12 43 ba 2a a0 10 aa 3b 5b 54 02 01 00 04 41 04 fb e0 b2 a1 fc 9a 9c b8 7a 60 48 9f ab 37 60 19 42 67 bc e5 58 00 9b 1d ef bf 05 73 6d d6 5f ff 03 02 28 83 16 0d d0 ee 09 33 95 13 9f e7 e3 df 1a a7 40 a4 d3 18 5e 8e bd 78 4e 01 30 57 64 52 30 78 06 09 67 2a 09 0a 03 00 02 02 09 01 01 ff 04 68 30 66 30 64 30 62 04 10 ca b7 f4 e3 fa bb db 46 8e 2f f6 84 91 6c a6 c0 02 01 00 02 01 00 04 48 30 46 02 21 00 d8 c0 7f 5d 20 d0 48 d2 69 59 71 38 d6 85 84 e5 98 db c5 8e 46 1f a1 41 ac ae 20 a5 95 94 ec fd 02 21 00 95 4d 3a 22 9c 3a 24 34 24 44 ac e4 5b 6b fc 72 b8 82 46 69 69 96 13 0e dc 2c f2 e3 d4 c9 eb 90 30 47 06 09 67 2a 09 0a 03 00 02 02 07 01 01 ff 04 37 30 35 30 33 a3 31 30 05 a0 03 80 01 00 04 28 2d e6 c8 b8 e0 ac 04 45 80 ae a9 d1 36 df 6d 59 9f e2 62 09 e8 e0 83 00 63 ba ab ee df 1f 1a 71 55 35 ec 8b e4 00 2e bc 84 40 27 fb 97 2c c2 65 2d 87 ad 20 37 1d 72 ff 15 f4 20 f8 0e 4a a0 c6 7e 75 8d 13 ec 37 09 69 b9 0d 30 c3 04 55 eb 8e 6a 2b ce c7 ab ee 87 5a 4a 36 7d 6b 03 7a 87 7d 0a 89 01 ac 5a f6 04 91 09 75";

static const char* TEST_HEADER3 = "30 82 03 71 06 06 2A 86 48 CE 4C 04 02 01 00 02 01 07 81 10 51 8D CA 0F B7 6D 2E 45 88 21 47 D7 DC 6F B5 E9 18 0F 32 30 31 36 30 35 31 33 31 35 33 33 34 38 5A 02 01 65 80 01 01 86 10 E7 DD FF 4C 61 F0 C0 48 A6 48 6B F0 FC E8 8A 70 A2 82 02 CC 30 1D 06 09 67 2A 09 0A 03 00 02 02 08 04 10 70 56 34 12 99 99 99 99 99 99 99 99 99 99 02 56 30 6E 06 09 67 2A 09 0A 03 00 02 02 06 01 01 FF 04 5E 30 5C 30 5A 30 58 04 10 70 56 34 12 99 99 99 99 99 99 99 99 99 99 92 56 02 01 00 04 41 04 86 3A 8B 98 12 26 C9 BD 03 4F D0 3C C2 6C A4 8E 19 95 96 95 89 76 9B 52 95 C5 E3 E1 EB F4 3B 0D BB 3C 35 DF C9 17 00 9D A2 B8 32 26 73 FD 69 CA 5E 41 EE 89 43 5E 1A EC 7A 20 7A 85 C5 B0 73 73 30 43 06 09 67 2A 09 0A 03 00 02 02 07 01 01 FF 04 33 30 31 A3 2F 30 03 02 01 03 04 28 28 21 C4 8F 20 06 E4 F2 94 90 62 D2 F9 8A F8 7E 3C B3 AC 4B 9D 08 EB E8 10 A8 D3 7C 23 B9 33 CF AB 4D 2D 3E 97 27 11 00 30 81 C8 06 09 67 2A 09 0A 03 00 02 02 09 01 01 FF 04 81 B7 30 81 B4 30 81 B1 30 18 04 10 36 81 31 FE 6F 3E 62 49 BA 5D A3 F8 00 00 00 01 02 01 00 02 01 00 30 18 04 10 36 81 31 FE 6F 3E 62 49 BA 5D A3 F8 00 00 00 02 02 01 00 02 01 00 30 18 04 10 36 81 31 FE 6F 3E 62 49 BA 5D A3 F8 00 00 00 03 02 01 00 02 01 00 30 61 04 10 36 81 31 FE 6F 3E 62 49 BA 5D A3 F8 00 00 00 04 02 01 00 02 01 00 04 47 30 45 02 20 11 48 B4 91 F3 EE D7 91 CF FD F5 91 DD A5 E9 49 5F 4D 68 6C 0D 9B 55 CD 22 71 41 49 1F 23 20 A5 02 21 00 B1 6B 5D 1B 06 21 81 3E CD BB CF D8 7F 89 0E 29 61 55 EE FC D8 FA EE F9 39 A1 75 4D D5 B8 CC 4D 30 1E 06 09 67 2A 09 0A 03 00 02 02 0B 04 11 30 0F 06 09 67 2A 09 0A 03 00 07 01 02 02 02 01 60 30 60 06 09 67 2A 09 0A 03 00 02 02 04 04 53 30 51 30 0D 06 09 60 86 48 01 65 03 04 02 03 00 00 04 40 EC 2F 03 8E 4C 6E D0 AF 0F 86 6D 47 72 8C 0D 27 F2 64 4D D7 D9 F8 DD 6B AB 94 3F F4 93 AA 58 9A A8 43 F9 63 7E 90 EE 16 52 89 F1 E9 BB 12 D4 36 BF 45 FF 6F 0A E9 AD 2A 7D 27 D0 66 95 FC 8C 2E 30 0E 06 09 67 2A 09 0A 03 00 02 02 03 04 01 56 30 51 06 09 67 2A 09 0A 03 00 02 02 0A 01 01 FF 04 41 04 F1 90 FF FE 7F 9E 0C F6 DA CC 83 54 A0 7F AF F8 E4 6A 4C 1E B8 76 02 04 90 98 F8 6A 9D 02 4D 52 F5 B4 6F 32 1F 67 74 E3 95 EE 6C E2 B4 E5 43 EB 03 7F BD 94 AA 9E 12 71 66 5C 36 94 3B 7C A6 41 30 18 06 09 67 2A 09 0A 03 00 02 02 10 04 0B 30 09 02 03 4C 4B 40 02 02 20 02 30 17 06 09 67 2A 09 0A 03 00 02 02 11 04 0A 74 65 78 74 2F 70 6C 61 69 6E 30 13 06 09 67 2A 09 0A 03 00 02 02 05 04 06 4D 65 6D 6F 72 79 A3 0C 06 08 2A 86 48 CE 3D 04 03 02 00 00 84 48 30 46 02 21 00 86 CC 48 90 6F B8 0E 85 75 DD 8E 7B 9D 58 50 6A FA BD 8D 5C A7 8E A8 84 CB 57 12 A8 2C 18 FB 56 02 21 00 AC C6 90 5D 33 87 DA 08 FD B7 52 20 41 82 50 F9 B3 97 78 85 53 11 10 24 92 2F 74 62 C4 5B 44 7C";

TEST(TestAsn1CkmHeader, Decode_Encode_round_trip)
{
	tscryptotest::CMS::_POD_CmsHeaderData header;
	tscrypto::tsCryptoData output;

	EXPECT_EQ(true, header.Decode(tscrypto::tsCryptoData(TEST_HEADER1, tscrypto::tsCryptoData::HEX)));
	EXPECT_EQ(true, header.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData(TEST_HEADER1, tscrypto::tsCryptoData::HEX), output);
}

TEST(TestAsn1CkmHeader, Decode_Encode2_round_trip)
{
	tscryptotest::CMS::_POD_CmsHeaderData header;
	tscrypto::tsCryptoData output;

	EXPECT_EQ(true, header.Decode(tscrypto::tsCryptoData(TEST_HEADER2, tscrypto::tsCryptoData::HEX)));
	EXPECT_EQ(true, header.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData(TEST_HEADER2, tscrypto::tsCryptoData::HEX), output);
}

TEST(TestAsn1CkmHeader, Decode_part)
{
	tscryptotest::CMS::_POD_CmsHeaderData header;
	tscrypto::tsCryptoData output;

	EXPECT_EQ(true, header.Decode(tscrypto::tsCryptoData(TEST_HEADER1, tscrypto::tsCryptoData::HEX)));

	EXPECT_EQ(true, header.Encode_Signable(output));
	EXPECT_EQ(tscrypto::tsCryptoData(TEST_SIGNABLE1, tscrypto::tsCryptoData::HEX), output);

	//Asn1Test::TP_MiniHeader mh;
	//tscrypto::tsCryptoData output;

	//setupMiniHeader(mh);

	//EXPECT_EQ(true, mh.Encode(output));
	//EXPECT_EQ(tscrypto::tsCryptoData("30 81 FE 02 01 07 02 01 03 04 10 FD 0A 29 73 35 93 46 46 9F 96 55 CB 28 19 0C F7 18 0F 32 30 31 34 30 31 30 31 31 32 33 31 34 39 5A 80 2B 04 91 28 34 79 27 34 98 27 49 82 79 48 72 09 37 40 17 04 71 90 82 37 49 82 37 49 82 73 45 91 30 94 10 97 43 98 27 34 97 23 09 54 01 01 FF 01 01 00 02 02 02 00 04 34 B9 38 74 50 92 38 4A 75 09 23 74 59 02 37 45 92 73 45 97 23 F5 71 A9 23 47 59 03 81 74 59 B2 34 75 98 27 39 45 72 93 04 75 09 23 74 E5 97 34 9F 57 23 49 85 A2 66 30 64 A3 38 30 1F 04 10 29 7F 53 39 FF FE D3 4D 91 9C 08 68 FA BB B6 A6 02 01 59 80 08 30 06 02 01 00 02 01 00 30 15 04 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 01 00 04 28 54 78 94 39 78 34 57 85 43 78 95 43 89 74 53 78 45 38 79 54 37 89 45 38 97 54 37 89 45 32 78 54 87 94 58 97 89 75 49 54", tscrypto::tsCryptoData::HEX), output);

	//mh.clear();
	////EXPECT_EQ(mh.Decode(output), true);
	////EXPECT_EQ(true, checkMiniHeader(mh));
	//EXPECT_EQ(true, mh.Decode(tscrypto::tsCryptoData("30 81 FE 02 01 07 02 01 03 04 10 FD 0A 29 73 35 93 46 46 9F 96 55 CB 28 19 0C F7 18 0F 32 30 31 34 30 31 30 31 31 32 33 31 34 39 5A 80 2B 04 91 28 34 79 27 34 98 27 49 82 79 48 72 09 37 40 17 04 71 90 82 37 49 82 37 49 82 73 45 91 30 94 10 97 43 98 27 34 97 23 09 54 01 01 FF 01 01 00 02 02 02 00 04 34 B9 38 74 50 92 38 4A 75 09 23 74 59 02 37 45 92 73 45 97 23 F5 71 A9 23 47 59 03 81 74 59 B2 34 75 98 27 39 45 72 93 04 75 09 23 74 E5 97 34 9F 57 23 49 85 A2 66 30 64 A3 38 30 1F 04 10 29 7F 53 39 FF FE D3 4D 91 9C 08 68 FA BB B6 A6 02 01 59 80 08 30 06 02 01 00 02 01 00 30 15 04 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 01 00 04 28 54 78 94 39 78 34 57 85 43 78 95 43 89 74 53 78 45 38 79 54 37 89 45 38 97 54 37 89 45 32 78 54 87 94 58 97 89 75 49 54", tscrypto::tsCryptoData::HEX)));
	//EXPECT_EQ(true, checkMiniHeader(mh));
}

TEST(CKMAUTH, Calc)
{
	tsCryptoData servData, storedKey;
	std::shared_ptr<tscrypto::ServerAuthenticationCalculator> calc = std::dynamic_pointer_cast<tscrypto::ServerAuthenticationCalculator>(CryptoFactory("CKMAUTH_CALCULATOR-PBKDF2-SHA512"));

	EXPECT_TRUE(calc->validateServerAuthenticationParameters(tsCryptoData("This is my Password", tsCryptoData::ASCII), tsCryptoData("30670609672a090a0300070932020100a057020100020203e804409b05f45ca75a99572959184c9f35cf30f672f278c71a5b24b3e61ad23549a6bf2b02922a74bfe2926a681b0e5d75dfb848485b7160343f520bf664db2d7ce287300c06082a864886f70d020b0500", tsCryptoData::HEX), tsCryptoData("9e8edc4641030c2f74872421269a134a8bb21cb41e765d4f3d510daf0699b469ab255a827719d81f57eee08507229c5b08fef665cbc7ea65ba4b93da3ceb02e4", tsCryptoData::HEX)));


	EXPECT_TRUE(calc->computeServerAuthenticationParameters(tsCryptoData("This is my Password", tsCryptoData::ASCII), servData, storedKey));
	EXPECT_FALSE(servData == tsCryptoData("9e8edc4641030c2f74872421269a134a8bb21cb41e765d4f3d510daf0699b469ab255a827719d81f57eee08507229c5b08fef665cbc7ea65ba4b93da3ceb02e4", tsCryptoData::HEX));
	EXPECT_TRUE(calc->validateServerAuthenticationParameters(tsCryptoData("This is my Password", tsCryptoData::ASCII), servData, storedKey));
}
TEST(CKMAUTH, TestInitiatorValues)
{
	std::shared_ptr<AuthenticationInitiator> init = std::dynamic_pointer_cast<AuthenticationInitiator>(CryptoFactory("CKMAUTH"));
	tsCryptoData eccPrivKey("00AC8A29AA54FA24B68630F358451BCB3A74434467ACA1DD4168B50C4F070C40217D87700BC7C064F41E6F61E262937822C030359519A30C61E07F4DFD6CC25ECD5A", tsCryptoData::HEX);
	tsCryptoData eccPubKey("040059B683072B9C91B62136E16FAC66F10D926FFD394F506A6B59B4473449C032B1A93719B1834D605333A387E6A6B4267FFC86EF701C9E516B29DE66D464CDD5423101B0EB0403387F313AF3E14AC3D3A0035AAA00D7B645EEFA0EBD2DED80C2310342787CEE8655AFDCA0F6033B606D3E3040D4A7F3D909398D9C497F90BAAFC0C7AB72", tsCryptoData::HEX);
	tsCryptoData ephPrivKey("00C9BC4731DB042FFCBBEE269E783A50FFF70E8FE4ECC3429637F8C7AA90BB79FE6FF614EE52402C8BD8562ED093401BD27CBF44780101C3D21D7CBC819FD25BC115", tsCryptoData::HEX);
	tsCryptoData ephPubKey("0401A35C0D4D5DF19368D9529B040F8338C6E9EC4FB2FBD3721BCBD70B13AA481D58A13EF7A7CD396EECEE9BF0AA0A21F90AE92C3C3C407E8AF8E8782BA6C57F2C917C0054B4BB27E640FEE45391631FED4743A0D3A885594B36C4D4ADE7CAE2A9D23AF6F2C103303E892E7BAACD39399BC147389ED4E0907669BE6499DDCBE1E559561C73", tsCryptoData::HEX);
	tsCryptoData KGK("0207ed83518ba5762a672a7deff00c582c6a4eee48eecd6a1d055dd212396277", tsCryptoData::HEX);
	_POD_CkmAuthInitiatorParameters initParams;
	_POD_CkmAuthServerParameters servAuthParams;

	EXPECT_TRUE(servAuthParams.Decode(tsCryptoData("30670609672a090a0300070932020100a057020100020203e804409b05f45ca75a99572959184c9f35cf30f672f278c71a5b24b3e61ad23549a6bf2b02922a74bfe2926a681b0e5d75dfb848485b7160343f520bf664db2d7ce287300c06082a864886f70d020b0500", tsCryptoData::HEX)));
	initParams.set_authParameters(servAuthParams);
	initParams.set_keySizeInBits(512);
	initParams.set_nonce(tsCryptoData("7eee08507229c52f74872421269a134a8bb08fef665cbc7ea65bb21cb41e765d", tsCryptoData::HEX));
	initParams.set_oidInfo(tsCryptoData("03e804409b05f45ca75a99572959184c9f35cf30f672f278c71a5b24b3e61ad23549a6bf2b02922a74bfe2", tsCryptoData::HEX));
	initParams.set_responderPublicKey(eccPubKey);

	EXPECT_TRUE(init->testInitiatorValues(initParams.Encode(), tsCryptoData("This is my Password", tsCryptoData::ASCII), KGK, ephPrivKey, ephPubKey, 
		tsCryptoData("308201970609672A090A03000709340201000481850401A35C0D4D5DF19368D9529B040F8338C6E9EC4FB2FBD3721BCBD70B13AA481D58A13EF7A7CD396EECEE9BF0AA0A21F90AE92C3C3C407E8AF8E8782BA6C57F2C917C0054B4BB27E640FEE45391631FED4743A0D3A885594B36C4D4ADE7CAE2A9D23AF6F2C103303E892E7BAACD39399BC147389ED4E0907669BE6499DDCBE1E559561C7304284EDDDA6C8DE47F2C353A4A4DC76DAE1CCCC652D1AE0000DC2A27B6287FC7BC3959D6A7BABC5E0767042B03E804409B05F45CA75A99572959184C9F35CF30F672F278C71A5B24B3E61AD23549A6BF2B02922A74BFE204207EEE08507229C52F74872421269A134A8BB08FEF665CBC7EA65BB21CB41E765D02020200044062ABBEC12271B5DDA0022C20BD2DB46C551A9904C584A45550402EDB7CB4FF07044A65219D8573EE5FE269885E7D260502BCFFD5E2AC2A3D3B5632A83B3E403B0440037E727F8129D8ED14961CC4CFE8ED46CD09181B5EB2A5B4D367D675AB728E9EF00DA5AB458C9F891BFAEAF0C8C1F4B77FAB6F38A800FC559144D6C5F6258C06", tsCryptoData::HEX), 
		tsCryptoData("3792b415b1dc301aee972602d8554c6dc069ec1f70a47ed89db22d630077c75bdd6baa114829d3c8f3e34f0dd307b74e7064f2a6dd9b9aed0cfc56c50e9a67be", tsCryptoData::HEX), 
		tsCryptoData("cc6918670e7967f1c1c53cf0364690a58fd14742122245095d3b14e4b0a3772983857da23c6763cdc3701cd4a4caef21b1b7161c45b064b5a603e5a34e487ede", tsCryptoData::HEX)));
}


TEST(TestSerializers, AlgorithmID)
{
	_POD_AlgorithmIdentifier pid;

	pid.set_oid(TECSEC_AES_192_GCM_OID);
	pid.set_Parameter();
	pid.get_Parameter()->tag = 5;
	EXPECT_STRCASEEQ("300D0609672A090A030007021A0500", pid.Encode().ToHexString().c_str());
	pid.clear();
	EXPECT_STREQ("", pid.get_oid().ToOIDString().c_str());

	EXPECT_TRUE(pid.Decode(tsCryptoData("300D0609672A090A030007021A0500", tsCryptoData::HEX)));
	EXPECT_STREQ(TECSEC_AES_192_GCM_OID, pid.get_oid().ToOIDString().c_str());
}

TEST(TestSerializers, CkmTunnelLogout)
{
	_POD_CkmTunnelLogout obj;

	EXPECT_STRCASEEQ("300D0608672A090A03000B06020100", obj.Encode().ToHexString().c_str());
	obj.clear();

	EXPECT_TRUE(obj.Decode(tsCryptoData("300D0608672A090A03000B06020100", tsCryptoData::HEX)));
}

TEST(TestSerializers, CkmTunnelError)
{
	_POD_CkmTunnelError obj;

	obj.set_Message("My error message goes here");
	EXPECT_STRCASEEQ("30290608672A090A03000B050201000C1A4D79206572726F72206D65737361676520676F65732068657265", obj.Encode().ToHexString().c_str());
	obj.clear();
	EXPECT_STREQ("", obj.get_Message().c_str());

	EXPECT_TRUE(obj.Decode(tsCryptoData("30290608672A090A03000B050201000C1A4D79206572726F72206D65737361676520676F65732068657265", tsCryptoData::HEX)));
	EXPECT_STREQ("My error message goes here", obj.get_Message().c_str());
}

TEST(TestSerializers, CkmTunnelInitLogin)
{
	_POD_CkmTunnelInitLogin obj;

	obj.set_username("Super D Duper User");
	EXPECT_STRCASEEQ("30210608672A090A03000B010201000C12537570657220442044757065722055736572", obj.Encode().ToHexString().c_str());
	obj.clear();
	EXPECT_STREQ("", obj.get_username().c_str());

	EXPECT_TRUE(obj.Decode(tsCryptoData("30210608672A090A03000B010201000C12537570657220442044757065722055736572", tsCryptoData::HEX)));
	EXPECT_STREQ("Super D Duper User", obj.get_username().c_str());
}

TEST(TestSerializers, CkmAuthResponderParameters)
{
	_POD_CkmAuthResponderParameters obj;

	obj.set_eKGK(tsCryptoData("eKGK", tsCryptoData::ASCII));
	obj.set_ephemeralPublic(tsCryptoData("ephemeralPublic", tsCryptoData::ASCII));
	obj.set_initiatorAuthProof(tsCryptoData("initiatorAuthProof", tsCryptoData::ASCII));
	obj.set_initiatorMITMProof(tsCryptoData("initiatorMITMProof", tsCryptoData::ASCII));
	obj.set_keySizeInBits(1234);
	obj.set_nonce(tsCryptoData("nonce", tsCryptoData::ASCII));
	obj.set_oidInfo(tsCryptoData("oidInfo", tsCryptoData::ASCII));

	EXPECT_STRCASEEQ("30610609672A090A0300070934020100040F657068656D6572616C5075626C69630404654B474B04076F6964496E666F04056E6F6E6365020204D20412696E69746961746F724D49544D50726F6F660412696E69746961746F724175746850726F6F66", obj.Encode().ToHexString().c_str());
	obj.clear();
	EXPECT_EQ(0, obj.get_keySizeInBits());

	EXPECT_TRUE(obj.Decode(tsCryptoData("30610609672A090A0300070934020100040F657068656D6572616C5075626C69630404654B474B04076F6964496E666F04056E6F6E6365020204D20412696E69746961746F724D49544D50726F6F660412696E69746961746F724175746850726F6F66", tsCryptoData::HEX)));
	EXPECT_STREQ("eKGK", obj.get_eKGK().ToUtf8String().c_str());
	EXPECT_STREQ("ephemeralPublic", obj.get_ephemeralPublic().ToUtf8String().c_str());
	EXPECT_STREQ("initiatorAuthProof", obj.get_initiatorAuthProof().ToUtf8String().c_str());
	EXPECT_STREQ("initiatorMITMProof", obj.get_initiatorMITMProof().ToUtf8String().c_str());
	EXPECT_EQ(1234, obj.get_keySizeInBits());
	EXPECT_STREQ("nonce", obj.get_nonce().ToUtf8String().c_str());
	EXPECT_STREQ("oidInfo", obj.get_oidInfo().ToUtf8String().c_str());
}

TEST(TestSerializers, PBKDF_Parameters)
{
	_POD_PBKDF_Parameters obj;

	obj.set_IterationCount(9876);
	obj.set_Salt(tsCryptoData("This is my salt value", tsCryptoData::ASCII));
	obj.get_hmacAlgorithm().set_oid(NIST_HMAC_SHA3_224_OID);
	obj.get_hmacAlgorithm().set_Parameter();
	obj.get_hmacAlgorithm().get_Parameter()->tag = 5;

	EXPECT_STRCASEEQ("302D02010002022694041554686973206973206D792073616C742076616C7565300D060960864801650304020D0500", obj.Encode().ToHexString().c_str());
	obj.clear();
	EXPECT_EQ(0, obj.get_IterationCount());

	EXPECT_TRUE(obj.Decode(tsCryptoData("302D02010002022694041554686973206973206D792073616C742076616C7565300D060960864801650304020D0500", tsCryptoData::HEX)));
	EXPECT_STREQ("This is my salt value", obj.get_Salt().ToUtf8String().c_str());
	EXPECT_STREQ(NIST_HMAC_SHA3_224_OID, obj.get_hmacAlgorithm().get_oid().ToOIDString().c_str());
	EXPECT_EQ(9876, obj.get_IterationCount());
}

TEST(TestSerializers, CkmAuthServerParameters)
{
	_POD_CkmAuthServerParameters obj;

	obj.set_Expired(true);
	obj.set_hashName("hashName");
	obj.set_kdfMacName("kdfMacName");
	obj.set_kdfName("kdf");
	obj.set_keyWrapName("KeyWrap");
	obj.set_macName("Mu mac");
	obj.set_useMITM(true);
	obj.get_params().set_selectedItem(_POD_CkmAuthServerParameters_params::Choice_Pbkdf);

	obj.get_params().get_Pbkdf().set_IterationCount(4958);
	obj.get_params().get_Pbkdf().set_Salt(tsCryptoData("This is a salt value", tsCryptoData::ASCII));
	obj.get_params().get_Pbkdf().get_hmacAlgorithm().set_oid(NIST_HMAC_SHA3_512_OID);
	obj.get_params().get_Pbkdf().get_hmacAlgorithm().set_Parameter();
	obj.get_params().get_Pbkdf().get_hmacAlgorithm().get_Parameter()->tag = 5;


	EXPECT_STRCASEEQ("306E0609672A090A0300070932020100A02C0201000202135E04145468697320697320612073616C742076616C7565300D060960864801650304021005008101FF8208686173684E616D6583064D75206D616384074B65795772617085036B6466860A6B64664D61634E616D658701FF", obj.Encode().ToHexString().c_str());
	obj.clear();
	EXPECT_EQ(0, obj.get_params().get_Pbkdf().get_IterationCount());
	EXPECT_FALSE(obj.get_Expired());
	EXPECT_FALSE(obj.get_useMITM());

	EXPECT_TRUE(obj.Decode(tsCryptoData("306E0609672A090A0300070932020100A02C0201000202135E04145468697320697320612073616C742076616C7565300D060960864801650304021005008101FF8208686173684E616D6583064D75206D616384074B65795772617085036B6466860A6B64664D61634E616D658701FF", tsCryptoData::HEX)));
	EXPECT_STREQ("This is a salt value", obj.get_params().get_Pbkdf().get_Salt().ToUtf8String().c_str());
	EXPECT_STREQ(NIST_HMAC_SHA3_512_OID, obj.get_params().get_Pbkdf().get_hmacAlgorithm().get_oid().ToOIDString().c_str());
	EXPECT_EQ(4958, obj.get_params().get_Pbkdf().get_IterationCount());

	EXPECT_TRUE(obj.get_Expired());
	EXPECT_TRUE(obj.get_useMITM());
	EXPECT_STREQ("hashName", obj.get_hashName()->c_str());
	EXPECT_STREQ("kdfMacName", obj.get_kdfMacName()->c_str());
	EXPECT_STREQ("kdf", obj.get_kdfName()->c_str());
	EXPECT_STREQ("KeyWrap", obj.get_keyWrapName()->c_str());
	EXPECT_STREQ("Mu mac", obj.get_macName()->c_str());

}

TEST(TestSerializers, CkmAuthInitiatorParameters)
{
	_POD_CkmAuthInitiatorParameters obj;
	_POD_CkmAuthServerParameters obj1;

	obj1.set_Expired(true);
	obj1.set_hashName("hashName");
	obj1.set_kdfMacName("kdfMacName");
	obj1.set_kdfName("kdf");
	obj1.set_keyWrapName("KeyWrap");
	obj1.set_macName("Mu mac");
	obj1.set_useMITM(true);
	obj1.get_params().set_selectedItem(_POD_CkmAuthServerParameters_params::Choice_Pbkdf);

	obj1.get_params().get_Pbkdf().set_IterationCount(4958);
	obj1.get_params().get_Pbkdf().set_Salt(tsCryptoData("This is a salt value", tsCryptoData::ASCII));
	obj1.get_params().get_Pbkdf().get_hmacAlgorithm().set_oid(NIST_HMAC_SHA3_512_OID);
	obj1.get_params().get_Pbkdf().get_hmacAlgorithm().set_Parameter();
	obj1.get_params().get_Pbkdf().get_hmacAlgorithm().get_Parameter()->tag = 5;

	obj.set_authParameters(obj1);
	obj.set_keySizeInBits(2311);
	obj.set_nonce(tsCryptoData("nonce", tsCryptoData::ASCII));
	obj.set_oidInfo(tsCryptoData("oidInfo", tsCryptoData::ASCII));
	obj.set_responderPublicKey(tsCryptoData("responderPublicKey", tsCryptoData::ASCII));
	obj.set_responderPublicKeyOID(tsCryptoData("responderPublicKeyOID", tsCryptoData::ASCII));

	EXPECT_STRCASEEQ("3081BD0609672A090A03000709330201000412726573706F6E6465725075626C69634B657904076F6964496E666F04056E6F6E636502020907306E0609672A090A0300070932020100A02C0201000202135E04145468697320697320612073616C742076616C7565300D060960864801650304021005008101FF8208686173684E616D6583064D75206D616384074B65795772617085036B6466860A6B64664D61634E616D658701FF8015726573706F6E6465725075626C69634B65794F4944", obj.Encode().ToHexString().c_str());
	obj.clear();
	EXPECT_EQ(0, obj.get_keySizeInBits());
	EXPECT_EQ(0, obj.get_authParameters().get_params().get_Pbkdf().get_IterationCount());
	EXPECT_FALSE(obj.get_authParameters().get_Expired());
	EXPECT_FALSE(obj.get_authParameters().get_useMITM());

	EXPECT_TRUE(obj.Decode(tsCryptoData("3081BD0609672A090A03000709330201000412726573706F6E6465725075626C69634B657904076F6964496E666F04056E6F6E636502020907306E0609672A090A0300070932020100A02C0201000202135E04145468697320697320612073616C742076616C7565300D060960864801650304021005008101FF8208686173684E616D6583064D75206D616384074B65795772617085036B6466860A6B64664D61634E616D658701FF8015726573706F6E6465725075626C69634B65794F4944", tsCryptoData::HEX)));

	EXPECT_STREQ("nonce", obj.get_nonce().ToUtf8String().c_str());
	EXPECT_STREQ("oidInfo", obj.get_oidInfo().ToUtf8String().c_str());
	EXPECT_STREQ("responderPublicKey", obj.get_responderPublicKey().ToUtf8String().c_str());
	EXPECT_STREQ("responderPublicKeyOID", obj.get_responderPublicKeyOID()->ToUtf8String().c_str());
	EXPECT_EQ(2311, obj.get_keySizeInBits());

	EXPECT_STREQ("This is a salt value", obj.get_authParameters().get_params().get_Pbkdf().get_Salt().ToUtf8String().c_str());
	EXPECT_STREQ(NIST_HMAC_SHA3_512_OID, obj.get_authParameters().get_params().get_Pbkdf().get_hmacAlgorithm().get_oid().ToOIDString().c_str());
	EXPECT_EQ(4958, obj.get_authParameters().get_params().get_Pbkdf().get_IterationCount());

	EXPECT_TRUE(obj.get_authParameters().get_Expired());
	EXPECT_TRUE(obj.get_authParameters().get_useMITM());
	EXPECT_STREQ("hashName", obj.get_authParameters().get_hashName()->c_str());
	EXPECT_STREQ("kdfMacName", obj.get_authParameters().get_kdfMacName()->c_str());
	EXPECT_STREQ("kdf", obj.get_authParameters().get_kdfName()->c_str());
	EXPECT_STREQ("KeyWrap", obj.get_authParameters().get_keyWrapName()->c_str());
	EXPECT_STREQ("Mu mac", obj.get_authParameters().get_macName()->c_str());

}

TEST(TestSerializers, CkmTunnelInitLoginResponse)
{
	_POD_CkmTunnelInitLoginResponse obj;
	_POD_CkmAuthInitiatorParameters obj2;
	_POD_CkmAuthServerParameters obj1;

	obj1.set_Expired(true);
	obj1.set_hashName("hashName");
	obj1.set_kdfMacName("kdfMacName");
	obj1.set_kdfName("kdf");
	obj1.set_keyWrapName("KeyWrap");
	obj1.set_macName("Mu mac");
	obj1.set_useMITM(true);
	obj1.get_params().set_selectedItem(_POD_CkmAuthServerParameters_params::Choice_Pbkdf);

	obj1.get_params().get_Pbkdf().set_IterationCount(4958);
	obj1.get_params().get_Pbkdf().set_Salt(tsCryptoData("This is a salt value", tsCryptoData::ASCII));
	obj1.get_params().get_Pbkdf().get_hmacAlgorithm().set_oid(NIST_HMAC_SHA3_512_OID);
	obj1.get_params().get_Pbkdf().get_hmacAlgorithm().set_Parameter();
	obj1.get_params().get_Pbkdf().get_hmacAlgorithm().get_Parameter()->tag = 5;

	obj2.set_authParameters(obj1);
	obj2.set_keySizeInBits(2311);
	obj2.set_nonce(tsCryptoData("nonce", tsCryptoData::ASCII));
	obj2.set_oidInfo(tsCryptoData("oidInfo", tsCryptoData::ASCII));
	obj2.set_responderPublicKey(tsCryptoData("responderPublicKey", tsCryptoData::ASCII));
	obj2.set_responderPublicKeyOID(tsCryptoData("responderPublicKeyOID", tsCryptoData::ASCII));

	obj.set_AuthenticationInformation(obj2);
	obj.set_MessageEncryptionAlg();
	obj.get_MessageEncryptionAlg()->set_oid(tsCryptoData(oid2, sizeof(oid2)));
	obj.get_MessageEncryptionAlg()->set_Parameter();
	obj.get_MessageEncryptionAlg()->get_Parameter()->tag = 4;
	obj.set_MessageKeyBitSize(256);
	obj.set_MessageMacAlg();
	obj.get_MessageMacAlg()->set_oid(tsCryptoData(oid3, sizeof(oid3)));
	obj.get_MessageMacAlg()->set_Parameter();
	obj.get_MessageMacAlg()->get_Parameter()->tag = 2;


	EXPECT_STRCASEEQ("3081EE0608672A090A03000B020201003081BD0609672A090A03000709330201000412726573706F6E6465725075626C69634B657904076F6964496E666F04056E6F6E636502020907306E0609672A090A0300070932020100A02C0201000202135E04145468697320697320612073616C742076616C7565300D060960864801650304021005008101FF8208686173684E616D6583064D75206D616384074B65795772617085036B6466860A6B64664D61634E616D658701FF8015726573706F6E6465725075626C69634B65794F494402020100A00D0609672A090A03000709320400A10C0608672A090A03000B040200", obj.Encode().ToHexString().c_str());
	obj.clear();
	EXPECT_EQ(0, obj.get_MessageKeyBitSize());
	EXPECT_EQ(0, obj.get_AuthenticationInformation().get_keySizeInBits());
	EXPECT_EQ(0, obj.get_AuthenticationInformation().get_authParameters().get_params().get_Pbkdf().get_IterationCount());
	EXPECT_FALSE(obj.get_AuthenticationInformation().get_authParameters().get_Expired());
	EXPECT_FALSE(obj.get_AuthenticationInformation().get_authParameters().get_useMITM());

	EXPECT_TRUE(obj.Decode(tsCryptoData("3081EE0608672A090A03000B020201003081BD0609672A090A03000709330201000412726573706F6E6465725075626C69634B657904076F6964496E666F04056E6F6E636502020907306E0609672A090A0300070932020100A02C0201000202135E04145468697320697320612073616C742076616C7565300D060960864801650304021005008101FF8208686173684E616D6583064D75206D616384074B65795772617085036B6466860A6B64664D61634E616D658701FF8015726573706F6E6465725075626C69634B65794F494402020100A00D0609672A090A03000709320400A10C0608672A090A03000B040200", tsCryptoData::HEX)));

	EXPECT_EQ(256, obj.get_MessageKeyBitSize());
	EXPECT_STREQ("2.23.42.9.10.3.0.7.9.50", obj.get_MessageEncryptionAlg()->get_oid().ToOIDString().c_str());
	EXPECT_EQ(4, obj.get_MessageEncryptionAlg()->get_Parameter()->tag);

	EXPECT_STREQ("2.23.42.9.10.3.0.11.4", obj.get_MessageMacAlg()->get_oid().ToOIDString().c_str());
	EXPECT_EQ(2, obj.get_MessageMacAlg()->get_Parameter()->tag);

	EXPECT_STREQ("nonce", obj.get_AuthenticationInformation().get_nonce().ToUtf8String().c_str());
	EXPECT_STREQ("oidInfo", obj.get_AuthenticationInformation().get_oidInfo().ToUtf8String().c_str());
	EXPECT_STREQ("responderPublicKey", obj.get_AuthenticationInformation().get_responderPublicKey().ToUtf8String().c_str());
	EXPECT_STREQ("responderPublicKeyOID", obj.get_AuthenticationInformation().get_responderPublicKeyOID()->ToUtf8String().c_str());
	EXPECT_EQ(2311, obj.get_AuthenticationInformation().get_keySizeInBits());

	EXPECT_STREQ("This is a salt value", obj.get_AuthenticationInformation().get_authParameters().get_params().get_Pbkdf().get_Salt().ToUtf8String().c_str());
	EXPECT_STREQ(NIST_HMAC_SHA3_512_OID, obj.get_AuthenticationInformation().get_authParameters().get_params().get_Pbkdf().get_hmacAlgorithm().get_oid().ToOIDString().c_str());
	EXPECT_EQ(4958, obj.get_AuthenticationInformation().get_authParameters().get_params().get_Pbkdf().get_IterationCount());

	EXPECT_TRUE(obj.get_AuthenticationInformation().get_authParameters().get_Expired());
	EXPECT_TRUE(obj.get_AuthenticationInformation().get_authParameters().get_useMITM());
	EXPECT_STREQ("hashName", obj.get_AuthenticationInformation().get_authParameters().get_hashName()->c_str());
	EXPECT_STREQ("kdfMacName", obj.get_AuthenticationInformation().get_authParameters().get_kdfMacName()->c_str());
	EXPECT_STREQ("kdf", obj.get_AuthenticationInformation().get_authParameters().get_kdfName()->c_str());
	EXPECT_STREQ("KeyWrap", obj.get_AuthenticationInformation().get_authParameters().get_keyWrapName()->c_str());
	EXPECT_STREQ("Mu mac", obj.get_AuthenticationInformation().get_authParameters().get_macName()->c_str());

}

TEST(TestSerializers, CkmTunnelFinishLogin)
{
	_POD_CkmTunnelFinishLogin obj;

	obj.get_AuthenticationInformation().set_eKGK(tsCryptoData("eKGK", tsCryptoData::ASCII));
	obj.get_AuthenticationInformation().set_ephemeralPublic(tsCryptoData("ephemeralPublic", tsCryptoData::ASCII));
	obj.get_AuthenticationInformation().set_initiatorAuthProof(tsCryptoData("initiatorAuthProof", tsCryptoData::ASCII));
	obj.get_AuthenticationInformation().set_initiatorMITMProof(tsCryptoData("initiatorMITMProof", tsCryptoData::ASCII));
	obj.get_AuthenticationInformation().set_keySizeInBits(1234);
	obj.get_AuthenticationInformation().set_nonce(tsCryptoData("nonce", tsCryptoData::ASCII));
	obj.get_AuthenticationInformation().set_oidInfo(tsCryptoData("oidInfo", tsCryptoData::ASCII));

	EXPECT_STRCASEEQ("30700608672A090A03000B0302010030610609672A090A0300070934020100040F657068656D6572616C5075626C69630404654B474B04076F6964496E666F04056E6F6E6365020204D20412696E69746961746F724D49544D50726F6F660412696E69746961746F724175746850726F6F66", obj.Encode().ToHexString().c_str());
	obj.clear();
	EXPECT_EQ(0, obj.get_AuthenticationInformation().get_keySizeInBits());

	EXPECT_TRUE(obj.Decode(tsCryptoData("30700608672A090A03000B0302010030610609672A090A0300070934020100040F657068656D6572616C5075626C69630404654B474B04076F6964496E666F04056E6F6E6365020204D20412696E69746961746F724D49544D50726F6F660412696E69746961746F724175746850726F6F66", tsCryptoData::HEX)));
	EXPECT_STREQ("eKGK", obj.get_AuthenticationInformation().get_eKGK().ToUtf8String().c_str());
	EXPECT_STREQ("ephemeralPublic", obj.get_AuthenticationInformation().get_ephemeralPublic().ToUtf8String().c_str());
	EXPECT_STREQ("initiatorAuthProof", obj.get_AuthenticationInformation().get_initiatorAuthProof().ToUtf8String().c_str());
	EXPECT_STREQ("initiatorMITMProof", obj.get_AuthenticationInformation().get_initiatorMITMProof().ToUtf8String().c_str());
	EXPECT_EQ(1234, obj.get_AuthenticationInformation().get_keySizeInBits());
	EXPECT_STREQ("nonce", obj.get_AuthenticationInformation().get_nonce().ToUtf8String().c_str());
	EXPECT_STREQ("oidInfo", obj.get_AuthenticationInformation().get_oidInfo().ToUtf8String().c_str());
}

TEST(TestSerializers, CkmTunnelFinishResponse)
{
	_POD_CkmTunnelFinishResponse obj;

	obj.set_ResponderProof(tsCryptoData("My error message goes here", tsCryptoData::ASCII));
	EXPECT_STRCASEEQ("30290608672A090A03000B04020100041A4D79206572726F72206D65737361676520676F65732068657265", obj.Encode().ToHexString().c_str());
	obj.clear();
	EXPECT_STREQ("", obj.get_ResponderProof().ToUtf8String().c_str());

	EXPECT_TRUE(obj.Decode(tsCryptoData("30290608672A090A03000B04020100041A4D79206572726F72206D65737361676520676F65732068657265", tsCryptoData::HEX)));
	EXPECT_STREQ("My error message goes here", obj.get_ResponderProof().ToUtf8String().c_str());
}

class authKeyTestHarness : public authenticationResponderKeyHandler
{
public:
	authKeyTestHarness(const tsCryptoData privKey) : _privKey(privKey)
	{
	}

protected:
	tsCryptoData _privKey;

	// Inherited via authenticationResponderKeyHandler
	virtual bool keyServer() override
	{
		return true;
	}
	virtual tsCryptoData getKey(const tsCryptoData & keyId) override
	{
		return _privKey;
	}
	virtual tsCryptoData computeZ(const tsCryptoData & keyId, const tsCryptoData & ephemeralPublic) override
	{
		return tsCryptoData();
	}
	virtual tsCryptoString getKeyType(const tsCryptoData & keyId) override
	{
		return "ECC-P521";
	}
};

TEST(CKMAUTH, TestResponderValues)
{
	std::shared_ptr<AuthenticationResponder> resp = std::dynamic_pointer_cast<AuthenticationResponder>(CryptoFactory("CKMAUTH"));
	tsCryptoData eccPrivKey("00AC8A29AA54FA24B68630F358451BCB3A74434467ACA1DD4168B50C4F070C40217D87700BC7C064F41E6F61E262937822C030359519A30C61E07F4DFD6CC25ECD5A", tsCryptoData::HEX);
	tsCryptoData eccPubKey("040059B683072B9C91B62136E16FAC66F10D926FFD394F506A6B59B4473449C032B1A93719B1834D605333A387E6A6B4267FFC86EF701C9E516B29DE66D464CDD5423101B0EB0403387F313AF3E14AC3D3A0035AAA00D7B645EEFA0EBD2DED80C2310342787CEE8655AFDCA0F6033B606D3E3040D4A7F3D909398D9C497F90BAAFC0C7AB72", tsCryptoData::HEX);
	tsCryptoData ephPrivKey("00C9BC4731DB042FFCBBEE269E783A50FFF70E8FE4ECC3429637F8C7AA90BB79FE6FF614EE52402C8BD8562ED093401BD27CBF44780101C3D21D7CBC819FD25BC115", tsCryptoData::HEX);
	tsCryptoData ephPubKey("0401A35C0D4D5DF19368D9529B040F8338C6E9EC4FB2FBD3721BCBD70B13AA481D58A13EF7A7CD396EECEE9BF0AA0A21F90AE92C3C3C407E8AF8E8782BA6C57F2C917C0054B4BB27E640FEE45391631FED4743A0D3A885594B36C4D4ADE7CAE2A9D23AF6F2C103303E892E7BAACD39399BC147389ED4E0907669BE6499DDCBE1E559561C73", tsCryptoData::HEX);
	tsCryptoData KGK("0207ed83518ba5762a672a7deff00c582c6a4eee48eecd6a1d055dd212396277", tsCryptoData::HEX);
	_POD_CkmAuthInitiatorParameters initParams;
	_POD_CkmAuthServerParameters servAuthParams;
	tsCryptoData respParams, respMITM, sessionKey;
	authKeyTestHarness harness(eccPrivKey);

	EXPECT_TRUE(servAuthParams.Decode(tsCryptoData("30670609672a090a0300070932020100a057020100020203e804409b05f45ca75a99572959184c9f35cf30f672f278c71a5b24b3e61ad23549a6bf2b02922a74bfe2926a681b0e5d75dfb848485b7160343f520bf664db2d7ce287300c06082a864886f70d020b0500", tsCryptoData::HEX)));
	initParams.set_authParameters(servAuthParams);
	initParams.set_keySizeInBits(512);
	initParams.set_nonce(tsCryptoData("7eee08507229c52f74872421269a134a8bb08fef665cbc7ea65bb21cb41e765d", tsCryptoData::HEX));
	initParams.set_oidInfo(tsCryptoData("03e804409b05f45ca75a99572959184c9f35cf30f672f278c71a5b24b3e61ad23549a6bf2b02922a74bfe2", tsCryptoData::HEX));
	initParams.set_responderPublicKey(eccPubKey);

	EXPECT_TRUE(resp->computeResponderValues(tsCryptoData("308201970609672A090A03000709340201000481850401A35C0D4D5DF19368D9529B040F8338C6E9EC4FB2FBD3721BCBD70B13AA481D58A13EF7A7CD396EECEE9BF0AA0A21F90AE92C3C3C407E8AF8E8782BA6C57F2C917C0054B4BB27E640FEE45391631FED4743A0D3A885594B36C4D4ADE7CAE2A9D23AF6F2C103303E892E7BAACD39399BC147389ED4E0907669BE6499DDCBE1E559561C7304284EDDDA6C8DE47F2C353A4A4DC76DAE1CCCC652D1AE0000DC2A27B6287FC7BC3959D6A7BABC5E0767042B03E804409B05F45CA75A99572959184C9F35CF30F672F278C71A5B24B3E61AD23549A6BF2B02922A74BFE204207EEE08507229C52F74872421269A134A8BB08FEF665CBC7EA65BB21CB41E765D02020200044062ABBEC12271B5DDA0022C20BD2DB46C551A9904C584A45550402EDB7CB4FF07044A65219D8573EE5FE269885E7D260502BCFFD5E2AC2A3D3B5632A83B3E403B0440037E727F8129D8ED14961CC4CFE8ED46CD09181B5EB2A5B4D367D675AB728E9EF00DA5AB458C9F891BFAEAF0C8C1F4B77FAB6F38A800FC559144D6C5F6258C06", tsCryptoData::HEX), 
		tsCryptoData("9e8edc4641030c2f74872421269a134a8bb21cb41e765d4f3d510daf0699b469ab255a827719d81f57eee08507229c5b08fef665cbc7ea65ba4b93da3ceb02e4", tsCryptoData::HEX), 
		&harness, respMITM, sessionKey));
	EXPECT_STRCASEEQ("3792b415b1dc301aee972602d8554c6dc069ec1f70a47ed89db22d630077c75bdd6baa114829d3c8f3e34f0dd307b74e7064f2a6dd9b9aed0cfc56c50e9a67be", respMITM.ToHexString().c_str());
	EXPECT_STRCASEEQ("cc6918670e7967f1c1c53cf0364690a58fd14742122245095d3b14e4b0a3772983857da23c6763cdc3701cd4a4caef21b1b7161c45b064b5a603e5a34e487ede", sessionKey.ToHexString().c_str());
}

TEST(CKMAUTH, AuthTest)
{
	std::shared_ptr<AuthenticationInitiator> init = std::dynamic_pointer_cast<AuthenticationInitiator>(CryptoFactory("CKMAUTH"));
	std::shared_ptr<AuthenticationResponder> resp = std::dynamic_pointer_cast<AuthenticationResponder>(CryptoFactory("CKMAUTH"));
	_POD_CkmAuthInitiatorParameters initParams;
	_POD_CkmAuthServerParameters servAuthParams;
	tsCryptoData eccPrivKey("00AC8A29AA54FA24B68630F358451BCB3A74434467ACA1DD4168B50C4F070C40217D87700BC7C064F41E6F61E262937822C030359519A30C61E07F4DFD6CC25ECD5A", tsCryptoData::HEX);
	tsCryptoData eccPubKey("040059B683072B9C91B62136E16FAC66F10D926FFD394F506A6B59B4473449C032B1A93719B1834D605333A387E6A6B4267FFC86EF701C9E516B29DE66D464CDD5423101B0EB0403387F313AF3E14AC3D3A0035AAA00D7B645EEFA0EBD2DED80C2310342787CEE8655AFDCA0F6033B606D3E3040D4A7F3D909398D9C497F90BAAFC0C7AB72", tsCryptoData::HEX);
	tsCryptoData respParams, respMITM, sessionKey;
	tsCryptoData respMITM2, sessionKey2;
	authKeyTestHarness harness(eccPrivKey);

	EXPECT_TRUE(servAuthParams.Decode(tsCryptoData("30670609672a090a0300070932020100a057020100020203e804409b05f45ca75a99572959184c9f35cf30f672f278c71a5b24b3e61ad23549a6bf2b02922a74bfe2926a681b0e5d75dfb848485b7160343f520bf664db2d7ce287300c06082a864886f70d020b0500", tsCryptoData::HEX)));
	initParams.set_authParameters(servAuthParams);
	initParams.set_keySizeInBits(512);
	initParams.set_nonce(tsCryptoData("7eee08507229c52f74872421269a134a8bb08fef665cbc7ea65bb21cb41e765d", tsCryptoData::HEX));
	initParams.set_oidInfo(tsCryptoData("03e804409b05f45ca75a99572959184c9f35cf30f672f278c71a5b24b3e61ad23549a6bf2b02922a74bfe2", tsCryptoData::HEX));
	initParams.set_responderPublicKey(eccPubKey);
	EXPECT_TRUE(init->computeInitiatorValues(initParams.Encode(), tsCryptoData("This is my Password", tsCryptoData::ASCII), respParams, respMITM, sessionKey));

	EXPECT_TRUE(resp->computeResponderValues(respParams, tsCryptoData("9e8edc4641030c2f74872421269a134a8bb21cb41e765d4f3d510daf0699b469ab255a827719d81f57eee08507229c5b08fef665cbc7ea65ba4b93da3ceb02e4", tsCryptoData::HEX), 
		&harness, respMITM2, sessionKey2));
	EXPECT_STRCASEEQ(respMITM.ToHexString().c_str(), respMITM2.ToHexString().c_str());
	EXPECT_STRCASEEQ(sessionKey.ToHexString().c_str(), sessionKey2.ToHexString().c_str());
	EXPECT_STRCASENE("3792b415b1dc301aee972602d8554c6dc069ec1f70a47ed89db22d630077c75bdd6baa114829d3c8f3e34f0dd307b74e7064f2a6dd9b9aed0cfc56c50e9a67be", respMITM2.ToHexString().c_str());
	EXPECT_STRCASENE("cc6918670e7967f1c1c53cf0364690a58fd14742122245095d3b14e4b0a3772983857da23c6763cdc3701cd4a4caef21b1b7161c45b064b5a603e5a34e487ede", sessionKey2.ToHexString().c_str());
}
#ifdef TEST_JSON
TEST(TestAsn1CkmHeader, Json) {
	tscryptotest::CMS::_POD_CmsHeaderData header;
	tscryptotest::CMS::_POD_CmsHeaderData header2;
	tscrypto::tsCryptoData output;
	tscrypto::tsCryptoString json;

	EXPECT_EQ(true, header.Decode(tscrypto::tsCryptoData(TEST_HEADER3, tscrypto::tsCryptoData::HEX)));
	json = header.toJSON().ToJSON();
	EXPECT_EQ(true, header2.fromJSON(json));
	EXPECT_EQ(true, header2.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData(TEST_HEADER3, tscrypto::tsCryptoData::HEX), output);
}
#endif // TEST_JSON

class myEnv : public ::testing::Environment{
public:
	virtual ~myEnv()
	{}
	virtual void SetUp() override
	{
		tscrypto::CryptoLocator();
	}
	virtual void TearDown() override
	{
		tscrypto::TerminateCryptoSystem();
	}
};


GTEST_API_ int main(int argc, char **argv) {

#ifdef _DEBUG
  //_CrtSetBreakAlloc(176);
  //_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF | _CRTDBG_CHECK_ALWAYS_DF | _CRTDBG_DELAY_FREE_MEM_DF); //   _CRTDBG_CHECK_EVERY_128_DF |  | |  
  //_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF); //   _CRTDBG_CHECK_EVERY_128_DF |  | |  
#endif


  AddGlobalTestEnvironment(new myEnv);
  testing::InitGoogleTest(&argc, argv);
  int retVal = RUN_ALL_TESTS();

//   if (_heapchk() != _HEAPOK)
// 	  printf("HEAP ERROR\n");
//   return retVal;
}

#ifdef MINGW
int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) 
{
	int argc = 1;
	char* argv[] = {(char*)"test.exe"};

	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
#endif

#pragma warning(pop)
