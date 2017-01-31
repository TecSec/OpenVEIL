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

//////////////////////////////////////////////////////////////////////////////////
/// \file tsCertificateBuilder.h
/// \brief Parses and creates PKI certificates.
//////////////////////////////////////////////////////////////////////////////////

#ifndef TSCERTIFICATEBUILDER_H
#define TSCERTIFICATEBUILDER_H

namespace tscrypto
{
    struct VEILCORE_API CA_Certificate_Extension
	{
		static void* operator new(std::size_t count) {
			return tscrypto::cryptoNew(count);
		}
		static void* operator new[](std::size_t count) {
			return tscrypto::cryptoNew(count);
		}
			static void operator delete(void* ptr) {
			tscrypto::cryptoDelete(ptr);
		}
		static void operator delete[](void* ptr) {
			tscrypto::cryptoDelete(ptr);
		}

		tsCryptoString oid;
		bool critical;
		tsCryptoData contents;
	};

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4231)
	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API tscrypto::ICryptoContainerWrapper<CA_Certificate_Extension>;
	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::shared_ptr<tscrypto::ICryptoContainerWrapper<CA_Certificate_Extension>>;
#pragma warning(pop)
#endif // _MSC_VER

	typedef std::shared_ptr<tscrypto::ICryptoContainerWrapper<CA_Certificate_Extension>> CAExtensionList;

	extern VEILCORE_API CAExtensionList CreateCAExtensionList();

	class VEILCORE_API CA_Certificate_Request
	{
	public:
		static void* operator new(std::size_t count) {
			return tscrypto::cryptoNew(count);
		}
		static void* operator new[](std::size_t count) {
			return tscrypto::cryptoNew(count);
		}
			static void operator delete(void* ptr) {
			tscrypto::cryptoDelete(ptr);
		}
		static void operator delete[](void* ptr) {
			tscrypto::cryptoDelete(ptr);
		}

		typedef enum {
			digitialSignature = 0x80,
			nonRepudiation = 0x40,
			keyEncipherment = 0x20,
			dataEncipherment = 0x10,
			keyAgreement = 0x08,
			keyCertSign = 0x04,
			CRLSign = 0x02,
			encipherOnly = 0x01,
			decipherOnly = 0x8000,
		} KeyUsageFlags;

		CA_Certificate_Request()
		{
			extendedKeyUsage = CreateTsCryptoStringList();
			extensions = CreateCAExtensionList();
		}
		~CA_Certificate_Request()
		{
			extendedKeyUsage.reset();
			extensions.reset();
		}

		tsCryptoString dn;
		tsCryptoString email;
		tsCryptoString loginName;
		tsCryptoString templateName;
		tsCryptoData kek;
		CAExtensionList extensions;
		tsCryptoStringList extendedKeyUsage;
		KeyUsageFlags keyUsage;
		int days;
	};

	class VEILCORE_API CA_Crypto_Info
	{
	public:
		static void* operator new(std::size_t count) {
			return tscrypto::cryptoNew(count);
		}
		static void* operator new[](std::size_t count) {
			return tscrypto::cryptoNew(count);
		}
			static void operator delete(void* ptr) {
			tscrypto::cryptoDelete(ptr);
		}
		static void operator delete[](void* ptr) {
			tscrypto::cryptoDelete(ptr);
		}

		CA_Crypto_Info()
		{
			crlPoints = CreateTsCryptoStringList();
			authAccess = CreateTsCryptoStringList();
		}
		~CA_Crypto_Info()
		{
			crlPoints.reset();
			authAccess.reset();
		}
		tsCryptoData CA_PrivateKey;
		tsCryptoData rootCert;
		tsCryptoData pivSigningKey;

		tsCryptoStringList crlPoints;
		tsCryptoStringList authAccess;

		tscrypto::TS_ALG_ID signatureHash;
		tscrypto::TS_ALG_ID keyType;

		int64_t nextSerialNumber;
		int64_t issuerSerialNumber;
		int issuerDays;
		int memberDays;
	};

	class VEILCORE_API ICertificateIssuer
	{
	public:
		typedef enum {
			X509_v1,	///< X509 v1 certificate
			X509_v2,	///< X509 v2 certificate
			X509_v3		///< X509 v3 certificate with attributes
		} CertificateVersion;
		/// <summary>Defines the certificate algorithm.</summary>
		//typedef enum { // TODO:  Document this better and convert this into the TS_ALG_ID form or OID form.
		//	UnknownAlg,
		//	RsaEncryption,
		//	RsaMd2,
		//	RsaMd5,
		//	RsaSha1,
		//	RsaSha256,
		//	RsaSha384,
		//	RsaSha512,
		//	DsaSha1,
		//	DsaSha224,
		//	DsaSha256,
		//	DsaSha384,
		//	DsaSha512,
		//	DhPublicNumber,
		//	CkmEncryption,
		//	EccSha1,
		//	EccSha256,
		//	EccSha384,
		//	EccSha512,
		//} CertificateAlgorithm;

		virtual ~ICertificateIssuer() {}
		virtual void setIssuerInformation(const tsCryptoStringBase& issuer) = 0;
		virtual tsCryptoString getIssuerInformation() = 0;
		virtual void setCryptoInformation(const CA_Crypto_Info& issuer) = 0;
		virtual CA_Crypto_Info getCryptoInformation() = 0;
		virtual void NewCA(const char *keyType, int optKeySize, tscrypto::TS_ALG_ID hash = tscrypto::_TS_ALG_ID::TS_ALG_INVALID) = 0;
		virtual void NewCA(std::shared_ptr<tscrypto::AsymmetricKey> key, tscrypto::TS_ALG_ID hash = tscrypto::_TS_ALG_ID::TS_ALG_INVALID) = 0;
		virtual void CreatePivSigningCert(tsCryptoData& certData, tsCryptoData& keyPair) = 0;
		virtual void CreateMemberCertAndKey(CA_Certificate_Request& member, const char *keyType, int optKeySize, tsCryptoData& certData, tsCryptoData& keyPair) = 0;
		virtual tsCryptoData CreateMemberCert(CA_Certificate_Request& member, const tsCryptoData& publicKey) = 0;
		virtual tsCryptoData CreateMemberCert(CA_Certificate_Request& member, std::shared_ptr<tscrypto::AsymmetricKey> publicKey) = 0;
		virtual void setDhParameters(std::shared_ptr<tscrypto::DhParameters> setTo) = 0;
		virtual std::shared_ptr<tscrypto::DhParameters> getDhParameters() = 0;
	};
}

#endif // TSCERTIFICATEBUILDER_H
