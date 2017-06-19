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
/// \file tsCertificateParser.h
/// \brief This file defines an object that parses X.509 certificates.
//////////////////////////////////////////////////////////////////////////////////

/*! \defgroup HighLevelHelpers High Level Helpers
 * @{
 */

 #ifndef __TSCERTIFICATEPARSER_H__
 #define __TSCERTIFICATEPARSER_H__
 
#pragma once

namespace tscrypto
{
	/// <summary>an object that parses X.509 certificates.</summary>
	class VEILCORE_API  tsCertificateParser
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

		/// <summary>Default constructor.</summary>
		tsCertificateParser();
		tsCertificateParser(const tsCertificateParser& obj);
		tsCertificateParser(tsCertificateParser&& obj);
		/// <summary>Destructor.</summary>
		~tsCertificateParser();

		tsCertificateParser& operator=(const tsCertificateParser& obj);
		tsCertificateParser& operator=(tsCertificateParser&& obj);
		bool operator==(const tsCertificateParser& obj) const;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Parses a certificate.</summary>
		///
		/// <param name="certData">The certificate.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
        bool LoadCertificate(const tscrypto::tsCryptoData &certData);
		/// <summary>Clears this object to its blank/initial state.</summary>
		void Clear();
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the version of this certificate.</summary>
		///
		/// <returns>the version of this certificate.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		ICertificateIssuer::CertificateVersion Version() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the encoded serial number.</summary>
		///
		/// <returns>the encoded serial number.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
        const tscrypto::tsCryptoData &EncodedSerialNumber() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the serial number.</summary>
		///
		/// <returns>the serial number.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
        const tscrypto::tsCryptoData &SerialNumber() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the algorithm BLOB node.</summary>
		///
		/// <returns>the algorithm BLOB node.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		const std::shared_ptr<tscrypto::TlvNode> AlgorithmBlob() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the algorithm oid.</summary>
		///
		/// <returns>the algorithm oid.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
        const tscrypto::tsCryptoData &AlgorithmOID() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the algorithm parameters node.</summary>
		///
		/// <returns>the algorithm parameters node.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		const std::shared_ptr<tscrypto::TlvNode> AlgorithmParameters() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the issuer node.</summary>
		///
		/// <returns>the issuer node.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		const std::shared_ptr<tscrypto::TlvNode> Issuer() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the issuance date.</summary>
		///
		/// <returns>the issuance date.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
        const tscrypto::tsCryptoString &IssuanceDate() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the expiration date.</summary>
		///
		/// <returns>the expiration date.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
        const tscrypto::tsCryptoString &ExpirationDate() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the subject node.</summary>
		///
		/// <returns>the subject node.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		const std::shared_ptr<tscrypto::TlvNode> Subject() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the public key algorithm BLOB.</summary>
		///
		/// <returns>the public key algorithm BLOB.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
        const tscrypto::tsCryptoData &PublicKeyAlgorithmBlob() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the public key algorithm.</summary>
		///
		/// <returns>the public key algorithm.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
        const tscrypto::tsCryptoData &PublicKeyAlgorithm() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the public key algorithm parameters node.</summary>
		///
		/// <returns>the public key algorithm parameters node.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		const std::shared_ptr<tscrypto::TlvNode> PublicKeyAlgorithmParameters() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the public key.</summary>
		///
		/// <returns>the public key.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
        const tscrypto::tsCryptoData &PublicKey() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the RSA modulus.</summary>
		///
		/// <returns>the RSA modulus.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
        const tscrypto::tsCryptoData &Modulus() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the RSA exponent.</summary>
		///
		/// <returns>the RSA exponent.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
        const tscrypto::tsCryptoData &Exponent() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the issuer unique number node.</summary>
		///
		/// <returns>the issuer unique number node.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		const std::shared_ptr<tscrypto::TlvNode> IssuerUniqueNumber() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the subject unique number node.</summary>
		///
		/// <returns>the subject unique number node.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		const std::shared_ptr<tscrypto::TlvNode> SubjectUniqueNumber() const;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the extension count.</summary>
		///
		/// <returns>the extension count.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		size_t ExtensionCount() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the extension at 'index'.</summary>
		///
		/// <param name="index">Zero-based index of the extension to get.</param>
		///
		/// <returns>The extension object.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		const tsCertificateExtension *Extension(size_t index) const;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the signature algorithm BLOB node.</summary>
		///
		/// <returns>the signature algorithm BLOB node.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		const std::shared_ptr<tscrypto::TlvNode> SignatureAlgorithmBlob() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the signature algorithm oid.</summary>
		///
		/// <returns>the signature algorithm oid.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
        const tscrypto::tsCryptoData &SignatureAlgorithmOID() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the signature algorithm parameters node.</summary>
		///
		/// <returns>the signature algorithm parameters node.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		const std::shared_ptr<tscrypto::TlvNode> SignatureAlgorithmParameters() const;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the certificate signature.</summary>
		///
		/// <returns>the certificate signature.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
        const tscrypto::tsCryptoData &CertificateSignature() const;

		//////////////////////////////////////////////////////////////////////////////////////////////////////
		///// <summary>Object allocation operator.</summary>
		/////
		///// <param name="bytes">The number of bytes to allocate.</param>
		/////
		///// <returns>The allocated object.</returns>
		//////////////////////////////////////////////////////////////////////////////////////////////////////
		//void *operator new(size_t bytes);
		//////////////////////////////////////////////////////////////////////////////////////////////////////
		///// <summary>Object de-allocation operator.</summary>
		/////
		///// <param name="ptr">[in,out] If non-null, the pointer to delete.</param>
		//////////////////////////////////////////////////////////////////////////////////////////////////////
		//void operator delete(void *ptr);

        const tscrypto::tsCryptoData SubjectKeyIdentifier() const;
        const tscrypto::tsCryptoData SubjectKeyIdentifierValue() const;
        const tscrypto::tsCryptoData IssuerKeyIdentifier() const;
        tscrypto::tsCryptoData asRawData() const;
        tscrypto::tsCryptoString asBase64() const;
        tscrypto::tsCryptoString SubjectName() const;
        tscrypto::tsCryptoString IssuerName() const;
		std::shared_ptr<tscrypto::AsymmetricKey> getPublicKeyObject() const;
        tscrypto::tsCryptoData getExtensionValue(const char* oid) const;
		CA_Certificate_Request::KeyUsageFlags GetKeyUsage() const;
        tscrypto::tsCryptoDate ValidFrom() const;
        tscrypto::tsCryptoDate ValidTo() const;
        std::shared_ptr<tscrypto::AsymmetricKey> PublicKeyObject(bool forSigning) const;
        bool VerifySignature(std::shared_ptr<tscrypto::AsymmetricKey> parentCertKey) const;
        bool IsCACert() const;
        bool getBasicConstraintInfo(bool& isCA, int32_t& maxNumberIntermediaries) const;

	private:
		std::shared_ptr<tscrypto::TlvDocument> m_doc;
		ICertificateIssuer::CertificateVersion m_version;
		tsCryptoData m_serialNumber;
		tsCryptoData m_encodedSerialNumber;
		std::shared_ptr<tscrypto::TlvNode> m_algorithmBlob;
		tsCryptoData m_algorithmOID;
		std::shared_ptr<tscrypto::TlvNode> m_algorithmParameters;
		std::shared_ptr<tscrypto::TlvNode> m_issuer;
		tsCryptoString   m_start;
		tsCryptoString   m_end;
		std::shared_ptr<tscrypto::TlvNode> m_subject;
		tsCryptoData m_modulus;
		tsCryptoData m_exponent;
		tsCryptoData m_pubKeyAlgorithmBlob;
		tsCryptoData m_pubKeyAlgorithm;
		std::shared_ptr<tscrypto::TlvNode> m_pubKeyAlgorithmParameters;
		tsCryptoData m_publicKey;
		std::shared_ptr<tscrypto::TlvNode> m_issuerUniqueNumber;
		std::shared_ptr<tscrypto::TlvNode> m_subjectUniqueNumber;
		tsCertificateExtensionList m_extensionList;
		std::shared_ptr<tscrypto::TlvNode> m_signatureAlgorithmBlob;
		tsCryptoData m_signatureAlgorithmOID;
		std::shared_ptr<tscrypto::TlvNode> m_signatureAlgorithmParameters;
		tsCryptoData m_certificateSignature;
		tsCryptoData m_originalData;
        tsCryptoData m_signablePart;

		tsCryptoData UnpackNumber(const tsCryptoData& number) const;
	};
}

#endif // __TSCERTIFICATEPARSER_H__

/*! @} */