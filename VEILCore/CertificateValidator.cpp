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

static const struct tag_AlgInfo
{
    const char* oid;
    TSSslHashAlgorithm hashAlg;
    TSSslSignatureAlgorithm sigAlg;
} gAlgs[] =
{
    { id_RSA_SHA1_SIGN_OID, tsSslhash_sha1, tsSslsign_rsa },
    { id_RSA_SHA224_SIGN_OID,tsSslhash_sha224,tsSslsign_rsa },
    { id_RSA_SHA256_SIGN_OID,tsSslhash_sha256, tsSslsign_rsa },
    { id_RSA_SHA384_SIGN_OID,tsSslhash_sha384,tsSslsign_rsa },
    { id_RSA_SHA512_SIGN_OID,tsSslhash_sha512,tsSslsign_rsa },
    { id_ECDSA_SHA1_OID,tsSslhash_sha1,tsSslsign_ecdsa },
    { id_ECDSA_SHA224_OID,tsSslhash_sha224,tsSslsign_ecdsa },
    { id_ECDSA_SHA256_OID,tsSslhash_sha256,tsSslsign_ecdsa },
    { id_ECDSA_SHA384_OID,tsSslhash_sha384,tsSslsign_ecdsa },
    { id_ECDSA_SHA512_OID,tsSslhash_sha512,tsSslsign_ecdsa },
    { id_DSA_SHA1_OID,tsSslhash_sha1,tsSslsign_dsa },
    { id_NIST_DSA_SHA224_OID,tsSslhash_sha224,tsSslsign_dsa },
    { id_NIST_DSA_SHA256_OID,tsSslhash_sha256,tsSslsign_dsa },
    { id_DSA_PARAMETER_SET_OID,tsSslhash_sha1,tsSslsign_dsa },
};

static const struct tag_AlgInfo* getAlgInfo(const char* oid)
{
    for (size_t i = 0; i < sizeof(gAlgs) / sizeof(gAlgs[0]); i++)
    {
        if (tsStrCmp(oid, gAlgs[i].oid) == 0)
            return &gAlgs[i];
    }
    return nullptr;
}

VEILCORE_API bool tscrypto::GetCertificateSignatureInfo(const tscrypto::tsCryptoString& oid, TSSslHashAlgorithm& hashAlg, TSSslSignatureAlgorithm& sigAlg)
{
    const struct tag_AlgInfo* alg = getAlgInfo(oid.c_str());

    if (alg == nullptr)
        return false;

    hashAlg = alg->hashAlg;
    sigAlg = alg->sigAlg;
    return true;
}
VEILCORE_API bool tscrypto::GetCertificateSignatureInfo(const tscrypto::tsCryptoData& oid, TSSslHashAlgorithm& hashAlg, TSSslSignatureAlgorithm& sigAlg)
{
    const struct tag_AlgInfo* alg = getAlgInfo(oid.ToOIDString().c_str());

    if (alg == nullptr)
        return false;

    hashAlg = alg->hashAlg;
    sigAlg = alg->sigAlg;
    return true;
}

class tsCertificateValidator : public ICertificateValidator, public tsmod::IObject, public tsmod::IInitializableObject
{
public:
    tsCertificateValidator()
    {
    }
    virtual ~tsCertificateValidator()
    {
    }

protected:
    std::shared_ptr<IPropertyMap> _parameters;
    std::shared_ptr<ICertificateValidatorOptions> _options;
    std::shared_ptr<ICertificateRevocationChecker> _revoker;

    virtual bool GetCertificateSignatureInfo(const tscrypto::tsCertificateParser& cert, TSSslHashAlgorithm& hashAlg, TSSslSignatureAlgorithm& sigAlg) override
    {
        tsCryptoString oid = cert.SignatureAlgorithmOID().ToOIDString();

        return tscrypto::GetCertificateSignatureInfo(oid, hashAlg, sigAlg);
    }
    virtual bool GetCertificateSignatureInfo(const tscrypto::tsCryptoData& cert, TSSslHashAlgorithm& hashAlg, TSSslSignatureAlgorithm& sigAlg) override
    {
        tsCertificateParser parser;

        if (!parser.LoadCertificate(cert))
            return false;
        return GetCertificateSignatureInfo(parser, hashAlg, sigAlg);
    }

    virtual TSSslAlertDescription basicCertValidation(const tscrypto::tsCertificateParser& cert, std::shared_ptr<tscrypto::AsymmetricKey> priorKey, bool sslCert, TSSslCipher cipher) override
    {
        TSSslHashAlgorithm hashAlg;
        TSSslSignatureAlgorithm sigAlg;

        if (!GetCertificateSignatureInfo(cert, hashAlg, sigAlg))
            return tsSslalert_bad_certificate;
        if (cipher != tsTLS_NULL_WITH_NULL_NULL && !_options->CertSignatureTypeOkForCipher(hashAlg, sigAlg, sslCert, cipher))
            return tsSslalert_bad_certificate;
        if (!!priorKey && !cert.VerifySignature(priorKey))
            return tsSslalert_bad_certificate;
        if (cert.ValidFrom() > tsCryptoDate::Now() || cert.ValidTo() < tsCryptoDate::Now())
            return tsSslalert_certificate_expired;

        if (!!_revoker)
        {
            if (_revoker->IsRevoked(cert))
                return tsSslalert_certificate_revoked;
        }
        return tsSslalert_no_error;
    }
    virtual TSSslAlertDescription basicCertValidation(const tscrypto::tsCryptoData& cert, std::shared_ptr<tscrypto::AsymmetricKey> priorKey, bool sslCert, TSSslCipher cipher) override
    {
        tsCertificateParser parser;

        if (!parser.LoadCertificate(cert))
            return tsSslalert_bad_certificate;
        return basicCertValidation(parser, priorKey, sslCert, cipher);
    }

    virtual bool IsSelfSigned(const tscrypto::tsCertificateParser& cert) override
    {
        return cert.IssuerName() == cert.SubjectName();
    }
    virtual bool IsSelfSigned(const tscrypto::tsCryptoData& cert) override
    {
        tsCertificateParser parser;

        if (!parser.LoadCertificate(cert))
            return false;

        return IsSelfSigned(parser);
    }

    virtual TSSslAlertDescription ValidateCertificate(const tscrypto::tsCryptoDataList& certificates, TSSslCipher cipher) override
    {
        bool first = true;
        //int32_t startAt;
        TSSslAlertDescription retVal;
        std::shared_ptr<tscrypto::AsymmetricKey> priorKey;
        std::shared_ptr<ICertificateRetriever> retriever;
        std::vector<tsCertificateParser> certs;
        bool trustedRootFound = false;
        bool trustedIntermediaryFound = false;

        if (!certificates || certificates->size() == 0)
            return tsSslalert_bad_certificate;

        retriever = _options->getCertificateRetriever();

        if (!retriever)
            return tsSslalert_certificate_unknown;

        for (const auto& it : *certificates)
        {
            tsCertificateParser certParser;

            if (!certParser.LoadCertificate(it))
            {
                return tsSslalert_bad_certificate;
            }
            certs.push_back(certParser);
            if (certs.size() > 1)
            {
                if (retriever->isTrustedRootCert(certParser))
                {
                    trustedRootFound = true;
                    break;
                }
                else if (retriever->isTrustedIntermediaryCert(certParser))
                {
                    trustedIntermediaryFound = true;
                    break;
                }
            }
        }

        if (!trustedRootFound && !trustedIntermediaryFound && !IsSelfSigned(certs.back()))
        {
            tscrypto::tsCryptoDataList trustList = CreateTsCryptoDataList();
            // If the trusted root/intermediary is not found then retrieve the chain.
            if (!retriever->getTrustChainForCert(certs.back(), trustList, trustedRootFound, trustedIntermediaryFound))
            {
                return tsSslalert_bad_certificate;
            }
            for (const auto& it : *trustList)
            {
                tsCertificateParser certParser;

                if (!certParser.LoadCertificate(it))
                {
                    return tsSslalert_bad_certificate;
                }
                certs.push_back(certParser);
            }
        }
        if (!trustedRootFound && !trustedIntermediaryFound)
        {
            if (!IsSelfSigned(certs.back()))
            {
                return tsSslalert_bad_certificate;
            }
            else
            {
                if (!_options->allowSelfSignedCerts())
                    return tsSslalert_bad_certificate;
                else
                {
                    priorKey = certs.back().getPublicKeyObject();
                    trustedRootFound = true;
                }
            }
        }

        // At this point we have the cert chain and it terminates on a trusted entity.
        for (int i = (int)certs.size() - 1; i >= 0; i--)
        {
            const tsCertificateParser& cert = certs.at(i);

            retVal = basicCertValidation(cert, priorKey, (i == 0), cipher);
            if (retVal != tsSslalert_no_error)
                return retVal;

            if (i > 0)
            {
                TSSslHashAlgorithm hashAlg;
                TSSslSignatureAlgorithm sigAlg;

                if ((cert.GetKeyUsage() & CA_Certificate_Request::digitialSignature) == 0 || (cert.GetKeyUsage() & CA_Certificate_Request::keyCertSign) == 0)
                    return tsSslalert_bad_certificate;

                if (!GetCertificateSignatureInfo(cert, hashAlg, sigAlg))
                    return tsSslalert_bad_certificate;

                if (!_options->CertSignatureTypeOkForCipher(hashAlg, sigAlg, false, cipher))
                    return tsSslalert_bad_certificate;

                 priorKey = cert.getPublicKeyObject();
                 if (!_options->KeySizeOkForCipher(hashAlg, sigAlg, (uint32_t)priorKey->KeySize(), false, cipher))
                     return tsSslalert_bad_certificate;
            }
            if (trustedRootFound)
            {
                bool isCA = false;
                int maxIntermediaries = 1000000;

                if (!cert.getBasicConstraintInfo(isCA, maxIntermediaries) || !isCA)
                    return tsSslalert_bad_certificate;

                if (maxIntermediaries + 2 > certs.size())
                    return tsSslalert_bad_certificate;
                trustedRootFound = false; // clear the flag for the reset of the testing
            }
            else if (i > 0)
            {
                bool isCA = false;
                int maxIntermediaries = 1000000;

                if (cert.getBasicConstraintInfo(isCA, maxIntermediaries) && isCA)
                    return tsSslalert_unsupported_certificate;
            }
        }

        // Validate the flags for the sslCert
        const TSTlsSupportDescriptor* supDesc = (const TSTlsSupportDescriptor*)tsFindCkmAlgorithm("TLS-SUPPORT");

        if (supDesc == nullptr)
            return tsSslalert_certificate_unknown;

        const char* info = supDesc->keyExchange(cipher);

        if (info != nullptr)
        {
            if (tsStriCmp(info, "RSA") == 0)
            {
                if ((certs.front().GetKeyUsage() & CA_Certificate_Request::digitialSignature) == 0 && (certs.front().GetKeyUsage() & CA_Certificate_Request::dataEncipherment) == 0)
                    return tsSslalert_bad_certificate;
            }
            else if (tsStriCmp(info, "DSA") == 0)
            {
                if ((certs.front().GetKeyUsage() & CA_Certificate_Request::digitialSignature) == 0)
                    return tsSslalert_bad_certificate;
            }
            else if (tsStriCmp(info, "ECDSA") == 0)
            {
                if ((certs.front().GetKeyUsage() & CA_Certificate_Request::digitialSignature) == 0)
                    return tsSslalert_bad_certificate;
            }
            else if (tsStriCmp(info, "DH") == 0)
            {
                if ((certs.front().GetKeyUsage() & CA_Certificate_Request::dataEncipherment) == 0)
                    return tsSslalert_bad_certificate;
            }
            else if (tsStriCmp(info, "ECDH") == 0)
            {
                if ((certs.front().GetKeyUsage() & CA_Certificate_Request::dataEncipherment) == 0)
                    return tsSslalert_bad_certificate;
            }
            else 
            {
                return tsSslalert_bad_certificate;
            }
        }
        else
        {
            return tsSslalert_bad_certificate;
        }

        return tsSslalert_no_error;

        //tsSslalert_no_error = 1024,
        //sslalert_no_certificate_RESERVED = 41,
        //tsSslalert_bad_certificate = 42,
        //tsSslalert_unsupported_certificate = 43,
        //tsSslalert_certificate_revoked = 44,
        //tsSslalert_certificate_expired = 45,
        //tsSslalert_certificate_unknown = 46,

    }

    // Inherited via IInitializableObject
    virtual bool InitializeWithFullName(const tscrypto::tsCryptoStringBase & fullName) override
    {
        _parameters = ServiceLocator()->get_instance<IPropertyMap>("PropertyMap");
        _parameters->parseUrlQueryString(fullName);

        // Parameters are all upper case
        if (!_parameters->hasItem("OPTIONS"))
            _parameters->AddItem("OPTIONS", "/CERTIFICATEOPTIONS");

        tsCryptoString optionsName = _parameters->item("OPTIONS");

        optionsName.Replace("^", "?").Replace("$", "&");

        if (!(_options = ServiceLocator()->try_get_instance<ICertificateValidatorOptions>(optionsName)))
            return false;

        _revoker = _options->getRevocationChecker();

        return true;
    }
};

tsmod::IObject* CreateCertificateValidator()
{
    return dynamic_cast<tsmod::IObject*>(new tsCertificateValidator);
}

class BasicCertOptions : public tscrypto::ICertificateValidatorOptions, public tsmod::IObject, public tsmod::IInitializableObject
{
public:
    BasicCertOptions() : _selfSigned(false)
    {
    }
    virtual ~BasicCertOptions()
    {
    }

protected:
    std::shared_ptr<ICertificateRetriever> _retriever;
    std::shared_ptr<ICertificateRevocationChecker> _checker;
    bool _selfSigned;

    // Inherited via IInitializableObject
    virtual bool InitializeWithFullName(const tscrypto::tsCryptoStringBase & fullName) override
    {
        std::shared_ptr<IPropertyMap> _parameters = ServiceLocator()->get_instance<IPropertyMap>("PropertyMap");
        _parameters->parseUrlQueryString(fullName);

        // Parameters are all upper case
        if (!_parameters->hasItem("RETRIEVER"))
            _parameters->AddItem("RETRIEVER", "/CERTIFICATE_RETRIEVER");

        if (_parameters->hasItem("CHECKER"))
        {
            _checker = ServiceLocator()->try_get_instance<ICertificateRevocationChecker>(_parameters->item("CHECKER"));
            if (!_checker)
                return false;
        }

        _selfSigned = _parameters->itemAsBoolean("SELFSIGNED", false);

        _retriever = ServiceLocator()->try_get_instance<ICertificateRetriever>(_parameters->item("RETRIEVER"));
        return !!_retriever;
    }

    // Inherited via ICertificateValidatorOptions
    virtual bool allowSelfSignedCerts() const override
    {
        return _selfSigned;
    }

    virtual std::shared_ptr<ICertificateRevocationChecker> getRevocationChecker() override
    {
        return _checker;
    }

    virtual std::shared_ptr<ICertificateRetriever> getCertificateRetriever() override
    {
        return _retriever;
    }

    virtual bool CertSignatureTypeOkForCipher(TSSslHashAlgorithm hashAlg, TSSslSignatureAlgorithm sigAlg, bool sslCert, TSSslCipher cipher) override
    {
        return true;
    }

    virtual bool KeySizeOkForCipher(TSSslHashAlgorithm hashAlg, TSSslSignatureAlgorithm sigAlg, uint32_t keySize, bool sslCert, TSSslCipher cipher) override
    {
        return true;
    }
};

tsmod::IObject* CreateBasicCertificateOptions()
{
    return dynamic_cast<tsmod::IObject*>(new tsCertificateValidator);
}
