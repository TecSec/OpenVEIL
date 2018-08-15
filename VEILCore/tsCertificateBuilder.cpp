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
#include "PKIX_Cert.h"

using namespace tscrypto;
using namespace tscrypto::PKIX;
using namespace tscrypto::PKIX::Cert;

CAExtensionList tscrypto::CreateCAExtensionList()
{
    return CreateContainer<CA_Certificate_Extension>();
}

class CertificateIssuer : public ICertificateIssuer, public tscrypto::ICryptoObject
{
private:
    tsDistinguishedName _issuer;
    CA_Crypto_Info _crypto;
    std::shared_ptr<DhParameters> _dhParams;
public:
    CertificateIssuer()
    {
        _crypto.signatureHash = TS_ALG_SHA256;
        _crypto.keyType = TS_ALG_ECC_P384;
        _crypto.nextSerialNumber = 1;
        _crypto.issuerDays = 1460;
        _crypto.memberDays = 365;
    }
    virtual void setIssuerInformation(const tsCryptoStringBase& issuer)
    {
        _issuer.FromString(issuer.c_str());
    }
    virtual tsCryptoString getIssuerInformation()
    {
        return _issuer.ToString();
    }
    virtual void setCryptoInformation(const CA_Crypto_Info& issuer)
    {
        _crypto = issuer;
    }
    virtual CA_Crypto_Info getCryptoInformation()
    {
        return _crypto;
    }
    virtual void setDhParameters(std::shared_ptr<DhParameters> setTo)
    {
        _dhParams = setTo;
    }
    virtual std::shared_ptr<DhParameters> getDhParameters()
    {
        return _dhParams;
    }

#pragma region Support routines
protected:
    std::shared_ptr<TlvNode> MakeBitString(const tsCryptoData& data, uint8_t unusedBits, std::shared_ptr<TlvDocument> doc)
    {
        std::shared_ptr<TlvNode> node = doc->CreateTlvNode(0x03, 0);

        if (data.size() == 0)
        {
            node->InnerData(tsCryptoData((uint8_t)0));
            return node;
        }
        tsCryptoData data1;

        data1 << unusedBits << data;
        node->InnerData(data1);
        return node;
    }

    std::shared_ptr<TlvNode> MakeIntegerNode(const tsCryptoData& data, std::shared_ptr<TlvDocument> doc)
    {
        std::shared_ptr<TlvNode> node = doc->CreateTlvNode(0x02, 0);

        if (data.size() == 0)
        {
            node->InnerData(tsCryptoData((uint8_t)0));
            return node;
        }
        if ((data[0] & 0x80) != 0)
        {
            tsCryptoData data1;

            data1 << (uint8_t)0 << data;
            node->InnerData(data1);
        }
        else
            node->InnerData(data);
        return node;
    }

    _POD_AlgorithmIdentifier BuildSignatureAlgorithm()
    {
        _POD_AlgorithmIdentifier id;
        Asn1AnyField any;

        any.tag = TlvNode::Tlv_OID;
        any.type = TlvNode::Type_Universal;

        switch (_crypto.keyType)
        {
        case TS_ALG_RSA:
            switch (_crypto.signatureHash)
            {
            case TS_ALG_SHA1:
                id.set_oid(tsCryptoData(id_RSA_SHA1_SIGN_OID, tsCryptoData::OID)); //sha1RsaWithEncryption
                break;
            case TS_ALG_SHA224:
                id.set_oid(tsCryptoData(id_RSA_SHA224_SIGN_OID, tsCryptoData::OID)); //sha224RsaWithEncryption
                break;
            case TS_ALG_SHA256:
                id.set_oid(tsCryptoData(id_RSA_SHA256_SIGN_OID, tsCryptoData::OID)); //sha256RsaWithEncryption
                break;
            case TS_ALG_SHA384:
                id.set_oid(tsCryptoData(id_RSA_SHA384_SIGN_OID, tsCryptoData::OID)); //sha384RsaWithEncryption
                break;
            case TS_ALG_SHA512:
                id.set_oid(tsCryptoData(id_RSA_SHA512_SIGN_OID, tsCryptoData::OID)); //sha512RsaWithEncryption
                break;
            default:
                throw tscrypto::Exception("Invalid hash type");
            }
            break;
        case TS_ALG_DSA:
            switch (_crypto.signatureHash)
            {
            case TS_ALG_SHA1:
                id.set_oid(tsCryptoData(id_DSA_SHA1_OID, tsCryptoData::OID)); //sha1Dsa
                break;
            case TS_ALG_SHA224:
                id.set_oid(tsCryptoData(id_NIST_DSA_SHA224_OID, tsCryptoData::OID)); //sha224Dsa
                break;
            case TS_ALG_SHA256:
                id.set_oid(tsCryptoData(id_NIST_DSA_SHA256_OID, tsCryptoData::OID)); //sha256Dsa
                break;
            case TS_ALG_SHA384:
                //id.set_oid(tsCryptoData(DSA_SHA384_OID, tsCryptoData::OID)); //sha384Dsa
                //break;
            case TS_ALG_SHA512:
                //id.set_oid(tsCryptoData(DSA_SHA512_OID, tsCryptoData::OID)); //sha512Dsa
                //break;
            default:
                throw tscrypto::Exception("Invalid hash type");
            }
            break;
        case TS_ALG_ECC_P256:
            any.value = tsCryptoData(id_SECP256R1_CURVE_OID, tsCryptoData::OID); // p256
            id.set_Parameter(any);
            switch (_crypto.signatureHash)
            {
            case TS_ALG_SHA1:
                id.set_oid(tsCryptoData(id_ECDSA_SHA1_OID, tsCryptoData::OID)); //ECDSA with SHA1
                break;
            case TS_ALG_SHA224:
                id.set_oid(tsCryptoData(id_ECDSA_SHA224_OID, tsCryptoData::OID)); //ECDSA with SHA224
                break;
            case TS_ALG_SHA256:
                id.set_oid(tsCryptoData(id_ECDSA_SHA256_OID, tsCryptoData::OID)); //ECDSA with SHA256
                break;
            case TS_ALG_SHA384:
                id.set_oid(tsCryptoData(id_ECDSA_SHA384_OID, tsCryptoData::OID)); //ECDSA with SHA384
                break;
            case TS_ALG_SHA512:
                id.set_oid(tsCryptoData(id_ECDSA_SHA512_OID, tsCryptoData::OID)); //ECDSA with SHA512
                break;
            default:
                throw tscrypto::Exception("Invalid hash type");
            }
            break;
        case TS_ALG_ECC_P384:
            
            any.value = tsCryptoData(id_SECP384R1_CURVE_OID, tsCryptoData::OID); // p384
            id.set_Parameter(any);
            switch (_crypto.signatureHash)
            {
            case TS_ALG_SHA1:
                id.set_oid(tsCryptoData(id_ECDSA_SHA1_OID, tsCryptoData::OID)); //ECDSA with SHA1
                break;
            case TS_ALG_SHA224:
                id.set_oid(tsCryptoData(id_ECDSA_SHA224_OID, tsCryptoData::OID)); //ECDSA with SHA224
                break;
            case TS_ALG_SHA256:
                id.set_oid(tsCryptoData(id_ECDSA_SHA256_OID, tsCryptoData::OID)); //ECDSA with SHA256
                break;
            case TS_ALG_SHA384:
                id.set_oid(tsCryptoData(id_ECDSA_SHA384_OID, tsCryptoData::OID)); //ECDSA with SHA384
                break;
            case TS_ALG_SHA512:
                id.set_oid(tsCryptoData(id_ECDSA_SHA512_OID, tsCryptoData::OID)); //ECDSA with SHA512
                break;
            default:
                throw tscrypto::Exception("Invalid hash type");
            }
            break;
        case TS_ALG_ECC_P521:
            any.value = tsCryptoData(id_SECP521R1_CURVE_OID, tsCryptoData::OID); // p521
            id.set_Parameter(any);
            switch (_crypto.signatureHash)
            {
            case TS_ALG_SHA1:
                id.set_oid(tsCryptoData(id_ECDSA_SHA1_OID, tsCryptoData::OID)); //ECDSA with SHA1
                break;
            case TS_ALG_SHA224:
                id.set_oid(tsCryptoData(id_ECDSA_SHA224_OID, tsCryptoData::OID)); //ECDSA with SHA224
                break;
            case TS_ALG_SHA256:
                id.set_oid(tsCryptoData(id_ECDSA_SHA256_OID, tsCryptoData::OID)); //ECDSA with SHA256
                break;
            case TS_ALG_SHA384:
                id.set_oid(tsCryptoData(id_ECDSA_SHA384_OID, tsCryptoData::OID)); //ECDSA with SHA384
                break;
            case TS_ALG_SHA512:
                id.set_oid(tsCryptoData(id_ECDSA_SHA512_OID, tsCryptoData::OID)); //ECDSA with SHA512
                break;
            default:
                throw tscrypto::Exception("Invalid hash type");
            }
            break;
        default:
            throw tscrypto::Exception("Invalid key type");
        }
        id.set_Parameter(any);
        return id;
    }

    _POD_Name BuildIssuerName()
    {
        _POD_Name name;
        name.SetFromDN(_issuer);
        return name;
    }

    _POD_Name BuildSubjectName(const CA_Certificate_Request& request)
    {
        tsDistinguishedName name;

        name.FromString(request.dn.c_str());

        if (request.email.size() > 0)
            name.Parts()->insert(name.Parts()->begin(), tsDnPart(tsCryptoData(id_emailAddress_OID, tsCryptoData::OID), request.email));

        _POD_Name nameVal;
        nameVal.SetFromDN(name);
        return nameVal;
    }

    _POD_Validity BuildValidity(int days)
    {
        _POD_Validity v;
        _POD_Time t;

        t.set_selectedItem(_POD_Time::Choice_generalTime);
        t.set_generalTime(tsCryptoDate::Now());
        v.set_notBefore(t);
        t.set_generalTime(tsCryptoDate::Now().AddInterval(days, 0, 0, 0));
        v.set_notAfter(t);
        return v;
    }

    _POD_SubjectPublicKeyInfo BuildPublicKeyInfo(std::shared_ptr<AsymmetricKey> key, CA_Certificate_Request& req, bool addDhParameters)
    {
        std::shared_ptr<DhKey> dh = std::dynamic_pointer_cast<DhKey>(key);
        std::shared_ptr<RsaKey> rsa = std::dynamic_pointer_cast<RsaKey>(key);
        std::shared_ptr<EccKey> ecc = std::dynamic_pointer_cast<EccKey>(key);
        //int keyLenInBytes = 0;
        _POD_SubjectPublicKeyInfo pki;
        _POD_AlgorithmIdentifier alg;
        Asn1Bitstring pk;
        Asn1AnyField any;

        any.tag = TlvNode::Tlv_OID;
        any.type = TlvNode::Type_Universal;

        // switch (key->KeySize())
        // {
        // case 256:
        // 	keyLenInBytes = 32;
        // 	break;
        // case 384:
        // 	keyLenInBytes = 48;
        // 	break;
        // case 1024:
        // 	keyLenInBytes = 128;
        // 	break;
        // case 2048:
        // 	keyLenInBytes = 256;
        // 	break;
        // case 3072:
        // 	keyLenInBytes = 384;
        // 	break;
        // default:
        // 	keyLenInBytes = 32;
        // 	break;
        // }

        if (!!ecc)
        {
            alg.set_oid(tsCryptoData(id_EC_PUBLIC_KEY_OID, tsCryptoData::OID)); //ECDSA Public Key
            switch (ecc->KeySize())
            {
            case 256:
                any.value = tsCryptoData(id_SECP256R1_CURVE_OID, tsCryptoData::OID); //p256
                break;
            case 384:
                any.value = tsCryptoData(id_SECP384R1_CURVE_OID, tsCryptoData::OID); //p384
                break;
            case 521:
                any.value = tsCryptoData(id_SECP521R1_CURVE_OID, tsCryptoData::OID); //p521
                break;
            }
            alg.set_Parameter(any);
            pk.bits(ecc->get_Point());
        }
        else if (!!rsa)
        {
            _POD_RsaPublicKeyPart keyPart;

            alg.set_oid(tsCryptoData(id_RSA_ENCRYPT_OID, tsCryptoData::OID));

            keyPart.set_exponent(rsa->get_Exponent());
            keyPart.set_n(rsa->get_PublicModulus());
            pk.bits(keyPart.Encode());
        }
        else if (!!dh)
        {
            std::shared_ptr<DhParameters> dhParams = dh->get_DomainParameters();

            if ((req.keyUsage & CA_Certificate_Request::keyAgreement) != 0 && (req.keyUsage & (CA_Certificate_Request::digitialSignature | CA_Certificate_Request::CRLSign | CA_Certificate_Request::keyCertSign) ) != 0)
            {
                throw tscrypto::Exception("Invalid key usage for DH/DSA");
            }


            if ((req.keyUsage & CA_Certificate_Request::keyAgreement) != 0)
            {
                alg.set_oid(tsCryptoData(id_DHPUBLICNUMBER_OID, tsCryptoData::OID));

                if (!!dhParams && addDhParameters)
                {
                    _POD_DhParameter_gMiddle params;

                    params.set_p(dhParams->get_prime());
                    params.set_g(dhParams->get_generator());
                    params.set_q(dhParams->get_subprime());

                    any.rawData(params.Encode());
                    alg.set_Parameter(any);
                }
            }
            else
            {
                alg.set_oid(tsCryptoData(id_DSA_PARAMETER_SET_OID, tsCryptoData::OID));

                if (!!dhParams && addDhParameters)
                {
                    _POD_DhParameterSet params;

                    params.set_p(dhParams->get_prime());
                    params.set_g(dhParams->get_generator());
                    params.set_q(dhParams->get_subprime());

                    any.rawData(params.Encode());
                    alg.set_Parameter(any);
                }
            }

            pk.bits(dh->get_PublicKey());
        }
        else
            throw tscrypto::Exception("Invalid public key");

        pki.set_algorithm(alg);
        pki.set_subjectPublicKey(pk);
        return pki;
    }

    _POD_CertificateExtension BuildKeyUsage(CA_Certificate_Request::KeyUsageFlags usageBits)
    {
        _POD_CertificateExtension ext;
        uint16_t flags = usageBits;
        TS_LITTLE_ENDIAN2(flags);
        tsCryptoData bFlags((uint8_t*)&flags, 2);
        if (bFlags[1] == 0)
            bFlags.resize(1);

        ext.setbits_KeyUsage(bFlags);
        return ext;
    }

    void AddPivContentSigningToRequest(CA_Certificate_Request& req)
    {
        req.extendedKeyUsage->erase(std::remove_if(req.extendedKeyUsage->begin(), req.extendedKeyUsage->end(), [](const tsCryptoString& oid) { return oid == id_CERT_PIV_CONTENT_SIGNING_OID; }), req.extendedKeyUsage->end());
        req.extendedKeyUsage->push_back(id_CERT_PIV_CONTENT_SIGNING_OID);
    }

    void AddCrl(std::shared_ptr<TlvNode> outer, const tsCryptoStringBase& value)
    {
        std::shared_ptr<TlvNode> sequence = outer->OwnerDocument().lock()->CreateSequence();
        std::shared_ptr<TlvNode> contextZero1 = outer->OwnerDocument().lock()->CreateContextNode(0);
        std::shared_ptr<TlvNode> contextZero2 = outer->OwnerDocument().lock()->CreateContextNode(0);
        std::shared_ptr<TlvNode> contextSix = outer->OwnerDocument().lock()->CreateContextNode(6);

        outer->AppendChild(sequence);
        sequence->AppendChild(contextZero1);
        contextZero1->AppendChild(contextZero2);
        contextZero2->AppendChild(contextSix);
        contextSix->InnerString(value);
    }

    void AddAuthorityAccess(std::shared_ptr<TlvNode> outer, const tsCryptoStringBase& value)
    {
        std::shared_ptr<TlvNode> sequence = outer->OwnerDocument().lock()->CreateSequence();
        std::shared_ptr<TlvNode> contextSix = outer->OwnerDocument().lock()->CreateContextNode(6);

        outer->AppendChild(sequence);
        sequence->AppendChild(outer->OwnerDocument().lock()->CreateOIDNode(tsCryptoData(id_ad_caIssuers_OID, tsCryptoData::OID)));
        sequence->AppendChild(contextSix);
        contextSix->InnerString(value);
    }

    void AddCrlExtension(CA_Certificate_Request& Member)
    {
        if (!!_crypto.crlPoints && _crypto.crlPoints->size() != 0)
        {
            //
            // Crl Distribution Points
            //
            CA_Certificate_Extension ext;
            std::shared_ptr<TlvDocument> innerDoc = TlvDocument::Create();

            innerDoc->DocumentElement()->Tag(TlvNode::Tlv_Sequence);
            innerDoc->DocumentElement()->Type(0);

            for (auto point : *_crypto.crlPoints)
            {
                AddCrl(innerDoc->DocumentElement(), point);
            }

            ext.oid = id_ce_cRLDistributionPoints_OID;
            ext.critical = false;
            ext.contents = innerDoc->SaveTlv();
            Member.extensions->erase(std::remove_if(Member.extensions->begin(), Member.extensions->end(), [](const CA_Certificate_Extension& ext) { return ext.oid == id_ce_cRLDistributionPoints_OID; }), Member.extensions->end());
            Member.extensions->push_back(ext);
        }
    }

    //void AddLoginUsage(std::shared_ptr<TlvNode> attrNode, const CA_Certificate_Request& Member)
    //{
    //	std::shared_ptr<TlvNode> sequence = attrNode->OwnerDocument().lock()->CreateTlvNode(0x10, 0);
    //	std::shared_ptr<TlvNode> appZero;
    //
    //	if (_crypto.crlPoints.size() != 0)
    //	{
    //		//
    //		// Crl Distribution Points
    //		//
    //		attrNode->AppendChild(sequence);
    //		sequence->AppendChild(sequence->OwnerDocument().lock()->CreateOIDNode(tsCryptoData(CERT_CRL_DISTRIBUTION_POINTS_OID, tsCryptoData::OID)));
    //		std::shared_ptr<TlvNode> octet = attrNode->OwnerDocument().lock()->CreateTlvNode(0x04, 0);
    //		sequence->AppendChild(octet);
    //		std::shared_ptr<TlvDocument> innerDoc = TlvDocument::Create();
    //		innerDoc->DocumentElement()->Tag(0x10);
    //		innerDoc->DocumentElement()->Type(0);
    //
    //		std::for_each(_crypto.crlPoints.begin(), _crypto.crlPoints.end(), [this, &innerDoc](const tsCryptoString& point) {
    //			AddCrl(innerDoc->DocumentElement(), point);
    //		});
    //		//AddCrl(innerDoc->DocumentElement(), "ldap:///CN=butlersoft,CN=ad-server,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=dev,DC=butlersoft,DC=com?certificateRevocationList?base?objectClass=cRLDistributionPoint");
    //		//AddCrl(innerDoc->DocumentElement(), "http://ad-server.dev.butlersloft.com/CertEnroll/butlersoft.crl");
    //
    //		octet->InnerData(innerDoc->SaveTlv());
    //	}
    //
    //	if (_crypto.authAccess.size() != 0)
    //	{
    //		//
    //		// Authority Info Access
    //		//
    //		sequence = attrNode->OwnerDocument().lock()->CreateSequence();
    //		sequence->AppendChild(sequence->OwnerDocument().lock()->CreateOIDNode(tsCryptoData(CERT_AUTHORITY_INFO_ACCESS_OID, tsCryptoData::OID)));
    //		std::shared_ptr<TlvNode> octet = attrNode->OwnerDocument().lock()->CreateTlvNode(0x04, 0);
    //		sequence->AppendChild(octet);
    //		std::shared_ptr<TlvDocument> innerDoc = TlvDocument::Create();
    //		innerDoc->DocumentElement()->Tag(0x10);
    //		innerDoc->DocumentElement()->Type(0);
    //
    //		std::for_each(_crypto.authAccess.begin(), _crypto.authAccess.end(), [this, &innerDoc](const tsCryptoString& point) {
    //			AddAuthorityAccess(innerDoc->DocumentElement(), point);
    //		});
    //		//AddAuthorityAccess(innerDoc->DocumentElement(), "ldap:///CN=butlersoft,CN=AIA,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=dev,DC=butlersoft,DC=com?cACertificate?base?objectClass=certificationAuthority");
    //		//AddAuthorityAccess(innerDoc->DocumentElement(), "http://ad-server.dev.butlersoft.ccom/CertEnroll/ad-server.dev.butlersoft.com_butlersoft.crt");
    //
    //		octet->InnerData(innerDoc->SaveTlv());
    //	}
    //
    //	//
    //	// Extended Key Usage
    //	//
    //	sequence = attrNode->OwnerDocument().lock()->CreateTlvNode(0x10, 0);
    //	attrNode->AppendChild(sequence);
    //	std::shared_ptr<TlvNode> oid = attrNode->OwnerDocument().lock()->CreateTlvNode(0x06, 0);
    //	oid->InnerData(tsCryptoData(CERT_EXTENDED_KEY_USAGE_OID, tsCryptoData::OID));
    //	sequence->AppendChild(oid);
    //	std::shared_ptr<TlvNode> octet = attrNode->OwnerDocument().lock()->CreateTlvNode(0x04, 0);
    //
    //	std::shared_ptr<TlvDocument> innerDoc = TlvDocument::Create();
    //	innerDoc->DocumentElement()->Tag(0x10);
    //	innerDoc->DocumentElement()->Type(0);
    //	innerDoc->DocumentElement()->AppendChild(innerDoc->CreateOIDNode(tsCryptoData(CERT_CLIENT_AUTHENTICATION_OID, tsCryptoData::OID)));
    //	innerDoc->DocumentElement()->AppendChild(innerDoc->CreateOIDNode(tsCryptoData(CERT_SMARTCARD_LOGIN_OID, tsCryptoData::OID))); // smart card login
    //
    //	octet->InnerData(innerDoc->SaveTlv());
    //	sequence->AppendChild(octet);
    //
    //	if (Member.loginName.size() != 0)
    //	{
    //		//
    //		// Now add the login name
    //		//
    //		sequence = attrNode->OwnerDocument().lock()->CreateTlvNode(0x10, 0);
    //
    //		attrNode->AppendChild(sequence);
    //
    //		oid = attrNode->OwnerDocument().lock()->CreateTlvNode(0x06, 0);
    //		oid->InnerData(tsCryptoData(CERT_SUBJECT_ALT_NAME_OID, tsCryptoData::OID));
    //		sequence->AppendChild(oid);
    //		octet = attrNode->OwnerDocument().lock()->CreateTlvNode(0x04, 0);
    //
    //
    //
    //		innerDoc = TlvDocument::Create();
    //		innerDoc->DocumentElement()->Tag(0x10);
    //		innerDoc->DocumentElement()->Type(0);
    //		innerDoc->DocumentElement()->AppendChild(appZero = innerDoc->CreateContextNode(0));
    //		appZero->AppendChild(innerDoc->CreateOIDNode(tsCryptoData(CERT_UPN_OID, tsCryptoData::OID)));
    //		appZero->AppendChild(innerDoc->CreateContextNode(0));
    //		appZero->Children()[1]->AppendChild(innerDoc->CreateTlvNode(0x0c, 0));
    //		appZero->Children()[1]->Children()[0]->InnerString(Member.loginName);
    //
    //		innerDoc->DocumentElement()->AppendChild(appZero = innerDoc->CreateContextNode(1));
    //		appZero->AppendChild(innerDoc->CreateTlvNode(0x16, 0));
    //		appZero->Children()[0]->InnerString(Member.email);
    //
    //
    //		octet->InnerData(innerDoc->SaveTlv());
    //		sequence->AppendChild(octet);
    //	}
    //}

    void AddLoginNameToRequest(CA_Certificate_Request& req, const CA_Certificate_Request& Member)
    {
        if (Member.loginName.size() > 0)
        {
            CA_Certificate_Extension ext;
            std::shared_ptr<TlvNode> appZero;

            std::shared_ptr<TlvDocument> innerDoc = TlvDocument::Create();
            innerDoc->DocumentElement()->Tag(0x10);
            innerDoc->DocumentElement()->Type(0);
            innerDoc->DocumentElement()->AppendChild(appZero = innerDoc->CreateContextNode(0));
            appZero->AppendChild(innerDoc->CreateOIDNode(tsCryptoData(id_CERT_UPN_OID, tsCryptoData::OID)));
            appZero->AppendChild(innerDoc->CreateContextNode(0));
            appZero->Children()->at(1)->AppendChild(innerDoc->CreateTlvNode(0x0c, 0));
            appZero->Children()->at(1)->Children()->at(0)->InnerString(Member.loginName);

            ext.oid = id_ce_subjectAltName_OID;
            ext.critical = false;
            ext.contents = innerDoc->SaveTlv();
            req.extensions->erase(std::remove_if(req.extensions->begin(), req.extensions->end(), [](const CA_Certificate_Extension& ext) { return ext.oid == id_ce_subjectAltName_OID; }), req.extensions->end());
            req.extensions->push_back(ext);
        }
        ////			sequence = attrNode->OwnerDocument().lock()->CreateTlvNode(0x10, 0);
        ////		
        ////			attrnode->AppendChild(sequence);
        ////
        ////			oid = attrNode->OwnerDocument().lock()->CreateTlvNode(0x06, 0);
        ////			oid->InnerData = new byte[]{85, 29, 17};
        ////			sequence->AppendChild(oid);
        ////			octet = attrNode->OwnerDocument().lock()->CreateTlvNode(0x04, 0);
        ////
        ////			innerDoc = new TlvDocument();
        ////			innerDoc->DocumentElement()->Tag = 0x10;
        ////			innerDoc->DocumentElement()->Type = 0;
        ////			innerDoc->DocumentElement()->AppendChild(appZero = innerDoc->CreateContextNode(0));
        ////			appZero.AppendChild(innerDoc->CreateOIDNode(new byte[]{43, 6, 1, 4, 1, 0x82, 55, 20, 2, 3}));
        ////			innerDoc->DocumentElement()->AppendChild(appZero = innerDoc->CreateContextNode(1));
        ////			appZero.AppendChild(innerDoc->CreateTlvNode(0x16, 0));
        ////			appZero.Children[0].InnerString = DatabaseHelper.GetAttribute(Member, "email", "");
        ////
        ////			octet->InnerData = innerDoc->SaveTlv();
        ////			sequence->AppendChild(octet);
    }
    _POD__ExplicitCertificateExtension BuildAttributes(const CA_Certificate_Request& Member)
    {
        _POD__ExplicitCertificateExtension extObj;

        // add the key usage
        extObj.get_extensions().add(BuildKeyUsage(Member.keyUsage));

        if (Member.extendedKeyUsage->size() > 0)
        {
            _POD_ExtKeyUsageSyntax eku;
            _POD_CertificateExtension ce;

            for (const tsCryptoString& str : *Member.extendedKeyUsage)
            {
                eku.add(tsCryptoData(str, tsCryptoData::OID));
            }
            ce.set_ExtKeyUsageSyntax(eku);
            extObj.get_extensions().add(ce);
        }
        for (auto ext : *Member.extensions)
        {
            _POD_CertificateExtension ce;

            ce.set_OID(tsCryptoData(ext.oid, tsCryptoData::OID));
            ce.set_critical(ext.critical);
            ce.set_extnValue(ext.contents);

            extObj.get_extensions().add(ce);
        }
        return extObj;
    }

    //void AddEncryptionUsage(CA_Certificate_Request& req)
    //{
    //	req.extendedKeyUsage.erase(std::remove_if(req.extendedKeyUsage.begin(), req.extendedKeyUsage.end(), [](const tsCryptoString& oid) { return oid == CERT_CLIENT_AUTHENTICATION_OID; }), req.extendedKeyUsage.end());
    //	req.extendedKeyUsage.push_back(CERT_CLIENT_AUTHENTICATION_OID);
    //	req.extendedKeyUsage.erase(std::remove_if(req.extendedKeyUsage.begin(), req.extendedKeyUsage.end(), [](const tsCryptoString& oid) { return oid == CERT_EMAIL_PROTECTION_OID; }), req.extendedKeyUsage.end());
    //	req.extendedKeyUsage.push_back(CERT_EMAIL_PROTECTION_OID);
    //	req.extendedKeyUsage.erase(std::remove_if(req.extendedKeyUsage.begin(), req.extendedKeyUsage.end(), [](const tsCryptoString& oid) { return oid == CERT_EFS_CRYPTO_OID; }), req.extendedKeyUsage.end());
    //	req.extendedKeyUsage.push_back(CERT_EFS_CRYPTO_OID);
    //}

    void AddTemplateNameToRequest(CA_Certificate_Request& Member)
    {
        if (Member.templateName.size() > 0)
        {
            CA_Certificate_Extension ext;
            std::shared_ptr<TlvDocument> innerDoc = TlvDocument::Create();

            innerDoc->DocumentElement()->Tag(TlvNode::Tlv_UTF8String);
            innerDoc->DocumentElement()->Type(0);

            innerDoc->DocumentElement()->InnerString(Member.templateName);

            ext.oid = id_CERT_CERTIFICATE_TYPE_OID;
            ext.critical = false;
            ext.contents = innerDoc->SaveTlv();
            Member.extensions->erase(std::remove_if(Member.extensions->begin(), Member.extensions->end(), [](const CA_Certificate_Extension& ext) { return ext.oid == id_CERT_CERTIFICATE_TYPE_OID; }), Member.extensions->end());
            Member.extensions->push_back(ext);
        }
    }

    void AddSubjectKeyIdentifierToRequest(CA_Certificate_Request& req, std::shared_ptr<AsymmetricKey> subjectKey)
    {
        _POD_CertificateExtension ce;
        CA_Certificate_Extension ext;
        tsCryptoData hash;
        _POD_SubjectPublicKeyInfo pki = BuildPublicKeyInfo(subjectKey, req, false);

        TSHash(pki.get_subjectPublicKey().toData(), hash, _crypto.signatureHash);
        
        ce.set_SubjectKeyIdentifier(hash);

        ext.oid = ce.get_OID().ToOIDString();
        ext.critical = false;
        ext.contents = ce.get_extnValue();
        req.extensions->erase(std::remove_if(req.extensions->begin(), req.extensions->end(), [](const CA_Certificate_Extension& ext) { return ext.oid == id_ce_subjectKeyIdentifier_OID; }), req.extensions->end());
        req.extensions->push_back(ext);
    }

    void AddAuthorityKeyIdentifierToRequest(CA_Certificate_Request& req, std::shared_ptr<AsymmetricKey> authorityKey)
    {
        _POD_CertificateExtension ce;
        CA_Certificate_Extension ext;
        tsCryptoData hash;
        _POD_SubjectPublicKeyInfo pki = BuildPublicKeyInfo(authorityKey, req, false);
        _POD_AuthorityKeyIdentifier aki;

        TSHash(pki.get_subjectPublicKey().toData(), hash, _crypto.signatureHash);

        aki.set_keyIdentifier(hash);
        ce.set_AuthorityKeyId(aki);

        ext.oid = ce.get_OID().ToOIDString();
        ext.critical = false;
        ext.contents = ce.get_extnValue();
        req.extensions->erase(std::remove_if(req.extensions->begin(), req.extensions->end(), [](const CA_Certificate_Extension& ext) { return ext.oid == id_ce_subjectKeyIdentifier_OID; }), req.extensions->end());
        req.extensions->push_back(ext);
    }

    //void AddMemberAuthCertAttributes(std::shared_ptr<TlvNode> certInfo, const CA_Certificate_Request& Member, std::shared_ptr<AsymmetricKey> rootKey)
    //{
    //	std::shared_ptr<TlvNode> attrSequence = certInfo->OwnerDocument().lock()->CreateTlvNode(0x03, 2);
    //	std::shared_ptr<TlvNode> sequence = certInfo->OwnerDocument().lock()->CreateTlvNode(0x10, 0);
    //
    //	certInfo->AppendChild(attrSequence);
    //	attrSequence->AppendChild(sequence);
    //	// add the key usage
    //	AddKeyUsage(sequence, 0xA0, 5);
    //
    //	AddTemplateName(sequence, Member);
    //	AddSubjectKeyIdentifier(sequence, rootKey);
    //	AddAuthorityAttributes(sequence, rootKey);
    //	if (Member.loginName.size() > 0)
    //		AddLoginUsage(sequence, Member);
    //}
    //
    //void AddMemberPivSigningAttributes(std::shared_ptr<TlvNode> certInfo, const CA_Certificate_Request& Member, std::shared_ptr<AsymmetricKey> rootKey)
    //{
    //	std::shared_ptr<TlvNode> attrSequence = certInfo->OwnerDocument().lock()->CreateTlvNode(0x03, 2);
    //	std::shared_ptr<TlvNode> sequence = certInfo->OwnerDocument().lock()->CreateTlvNode(0x10, 0);
    //
    //	certInfo->AppendChild(attrSequence);
    //	attrSequence->AppendChild(sequence);
    //	// add the key usage
    //	AddKeyUsage(sequence, 0xc0, 6);
    //	AddTemplateName(sequence, Member);
    //	AddLoginName(sequence, Member);
    //	AddSubjectKeyIdentifier(sequence, rootKey);
    //	AddAuthorityAttributes(sequence, rootKey);
    //}
    //
    //void AddMemberPivEncryptionAttributes(std::shared_ptr<TlvNode> certInfo, const CA_Certificate_Request& Member, std::shared_ptr<AsymmetricKey> rootKey)
    //{
    //	std::shared_ptr<TlvNode> attrSequence = certInfo->OwnerDocument().lock()->CreateTlvNode(0x03, 2);
    //	std::shared_ptr<TlvNode> sequence = certInfo->OwnerDocument().lock()->CreateTlvNode(0x10, 0);
    //
    //	certInfo->AppendChild(attrSequence);
    //	attrSequence->AppendChild(sequence);
    //	// add the key usage
    //	AddKeyUsage(sequence, 0xA0, 5);
    //	AddTemplateName(sequence, Member);
    //	AddSubjectKeyIdentifier(sequence, rootKey);
    //	AddAuthorityAttributes(sequence, rootKey);
    //}

    void AddBasicConstraintsToRequest(CA_Certificate_Request& req)
    {
        CA_Certificate_Extension ext;

        ext.oid = id_ce_basicConstraints_OID;
        ext.critical = true;
        ext.contents = tsCryptoData("30030101FF", tsCryptoData::HEX);
        req.extensions->erase(std::remove_if(req.extensions->begin(), req.extensions->end(), [](const CA_Certificate_Extension& ext) { return ext.oid == id_ce_basicConstraints_OID; }), req.extensions->end());
        req.extensions->push_back(ext);
    }

    void AddCaVersionToRequest(CA_Certificate_Request& req)
    {
        CA_Certificate_Extension ext;

        ext.oid = id_CERT_CA_VERSION_OID;
        ext.critical = false;
        ext.contents = tsCryptoData("020100", tsCryptoData::HEX);
        req.extensions->erase(std::remove_if(req.extensions->begin(), req.extensions->end(), [](const CA_Certificate_Extension& ext) { return ext.oid == id_CERT_CA_VERSION_OID; }), req.extensions->end());
        req.extensions->push_back(ext);
    }

#pragma endregion
#pragma region Generic Key Support
protected:
    std::shared_ptr<AsymmetricKey> BuildRootKey(const char *keyType, int optKeySize, TS_ALG_ID hash = TS_ALG_INVALID)
    {
        std::shared_ptr<AsymmetricKey> key;
        std::shared_ptr<RsaKey> rsakey;
        std::shared_ptr<EccKey> ecckey;
        std::shared_ptr<DhKey> dhkey;
        std::shared_ptr<AlgorithmInfo> algInfo;

        key = std::dynamic_pointer_cast<AsymmetricKey>(CryptoFactory(keyType));
        rsakey = std::dynamic_pointer_cast<RsaKey>(key);
        ecckey = std::dynamic_pointer_cast<EccKey>(key);
        dhkey = std::dynamic_pointer_cast<DhKey>(key);
        algInfo = std::dynamic_pointer_cast<AlgorithmInfo>(key);

        if (!!ecckey)
        {
            if (!ecckey->generateKeyPair())
                throw tscrypto::Exception("Unable to generate the ECC key pair");
        }
        else if (!!dhkey)
        {
            if (!!dhkey && !!_dhParams)
                dhkey->set_DomainParameters(_dhParams);
            if (!dhkey->generateKeyPair())
                throw tscrypto::Exception("Unable to generate the DH key pair");
        }
        else if (!!rsakey)
        {
            if (!rsakey->generateKeyPair(_RSA_Key_Gen_Type::rsakg_Probable_Composite, "HASH-SHA256", optKeySize))
                throw tscrypto::Exception("Unable to generate the RSA key pair");
        }
        _crypto.keyType = algInfo->AlgorithmID();
        if (hash == TS_ALG_INVALID)
        {
            switch (key->KeySize())
            {
            case 1024:
                _crypto.signatureHash = TS_ALG_SHA1;
                break;
            case 2048:
            case 3072:
                _crypto.signatureHash = TS_ALG_SHA256;
                break;
            case 192:
            case 224:
                _crypto.signatureHash = TS_ALG_SHA224;
                break;
            case 256:
                _crypto.signatureHash = TS_ALG_SHA256;
                break;
            case 384:
                _crypto.signatureHash = TS_ALG_SHA384;
                break;
            case 521:
                _crypto.signatureHash = TS_ALG_SHA512;
                break;
            default:
                throw tscrypto::ArgumentException("Invalid key type specified.");
            }
        }
        else
            _crypto.signatureHash = hash;

        _crypto.CA_PrivateKey = key->toByteArray();
        return key;
    }
    std::shared_ptr<AsymmetricKey> BuildKey(const char *keyType, int optKeySize)
    {
        std::shared_ptr<AsymmetricKey> key;
        std::shared_ptr<RsaKey> rsakey;
        std::shared_ptr<EccKey> ecckey;
        std::shared_ptr<DhKey> dhkey;
        std::shared_ptr<AlgorithmInfo> algInfo;

        key = std::dynamic_pointer_cast<AsymmetricKey>(CryptoFactory(keyType));
        rsakey = std::dynamic_pointer_cast<RsaKey>(key);
        ecckey = std::dynamic_pointer_cast<EccKey>(key);
        dhkey = std::dynamic_pointer_cast<DhKey>(key);
        algInfo = std::dynamic_pointer_cast<AlgorithmInfo>(key);

        if (!!ecckey)
        {
            if (!ecckey->generateKeyPair())
                throw tscrypto::Exception("Unable to generate the ECC key pair");
        }
        else if (!!dhkey)
        {
            if (!!dhkey && !!_dhParams)
                dhkey->set_DomainParameters(_dhParams);
            if (!dhkey->generateKeyPair())
                throw tscrypto::Exception("Unable to generate the DH key pair");
        }
        else if (!!rsakey)
        {
            if (!rsakey->generateKeyPair(_RSA_Key_Gen_Type::rsakg_Probable_Composite, "HASH-SHA256", optKeySize))
                throw tscrypto::Exception("Unable to generate the RSA key pair");
        }
        return key;
    }
    std::shared_ptr<AsymmetricKey> BuildAlgKey(uint8_t alg)
    {
        std::shared_ptr<AsymmetricKey> key;
        std::shared_ptr<RsaKey> rsakey;
        std::shared_ptr<EccKey> ecckey;
        std::shared_ptr<DhKey> dhkey;
        int keySize = 0;

        switch (alg)
        {
        case 6:
            key = std::dynamic_pointer_cast<AsymmetricKey>(CryptoFactory("KEY-RSA"));
            keySize = 1024;
            break;
        case 7:
            key = std::dynamic_pointer_cast<AsymmetricKey>(CryptoFactory("KEY-RSA"));
            keySize = 2048;
            break;
        case 0x11: // p256
            key = std::dynamic_pointer_cast<AsymmetricKey>(CryptoFactory("KEY-P256"));
            keySize = 256;
            break;
        case 0x14: // p384
            key = std::dynamic_pointer_cast<AsymmetricKey>(CryptoFactory("KEY-P384"));
            keySize = 256;
            break;
        default:
            throw tscrypto::NotImplementedException("Invalid algorithm");
        }
        rsakey = std::dynamic_pointer_cast<RsaKey>(key);
        ecckey = std::dynamic_pointer_cast<EccKey>(key);
        dhkey = std::dynamic_pointer_cast<DhKey>(key);

        if (!!ecckey)
        {
            if (!ecckey->generateKeyPair())
                throw tscrypto::Exception("Unable to generate the ECC key pair");
        }
        else if (!!dhkey)
        {
            if (!!dhkey && !!_dhParams)
                dhkey->set_DomainParameters(_dhParams);
            if (!dhkey->generateKeyPair())
                throw tscrypto::Exception("Unable to generate the DH key pair");
        }
        else if (!!rsakey)
        {
            if (!rsakey->generateKeyPair(_RSA_Key_Gen_Type::rsakg_Probable_Composite, "HASH-SHA256", keySize))
                throw tscrypto::Exception("Unable to generate the RSA key pair");
        }
        return key;
    }
    std::shared_ptr<AsymmetricKey> GetKekKey(CA_Certificate_Request& MemberNode, uint8_t alg)
    {
        std::shared_ptr<AsymmetricKey> key;

        if (MemberNode.kek.size() == 0)
        {
            key = BuildAlgKey(alg);
            if (!!key)
            {
                MemberNode.kek = key->toByteArray();
            }
        }
        else
        {
            key = TSBuildAsymmetricKeyFromBlob(MemberNode.kek);
        }

        if (!key)
            throw tscrypto::NotImplementedException("Invalid algorithm specified");
        return key;
    }
    tsCryptoData GetKekKeyPrivateBytes(CA_Certificate_Request& MemberNode, uint8_t alg)
    {
        std::shared_ptr<AsymmetricKey> key = GetKekKey(MemberNode, alg);
        std::shared_ptr<EccKey> ecc = std::dynamic_pointer_cast<EccKey>(key);

        if (!ecc)
            throw tscrypto::NotImplementedException("Invalid algorithm specified");

        return ecc->get_PrivateValue();
    }
    std::shared_ptr<AsymmetricKey> BuildPivSigningKey()
    {
        std::shared_ptr<AsymmetricKey> rootKey = GetRootKey();

        if (!rootKey)
            throw tscrypto::Exception("Unable to retrieve the issuer root key.");

        std::shared_ptr<AsymmetricKey> key = rootKey->generateNewKeyPair();
        if (!key)
            throw tscrypto::NotImplementedException("Unknown key type detected");
        _crypto.pivSigningKey = key->toByteArray();
        return key;
    }
    std::shared_ptr<AsymmetricKey> GetRootKey()
    {
        if (_crypto.CA_PrivateKey.size() == 0)
            throw tscrypto::NotImplementedException("Invalid key type detected for the CA root key");

        std::shared_ptr<AsymmetricKey> key = TSBuildAsymmetricKeyFromBlob(_crypto.CA_PrivateKey);
        std::shared_ptr<DhKey> dh = std::dynamic_pointer_cast<DhKey>(key);

        if (!key)
            throw tscrypto::NotImplementedException("Invalid key type detected for the CA root key");
        if (!!dh && !!_dhParams)
            dh->set_DomainParameters(_dhParams);
        return key;
    }
    void SignCert(_POD_Certificate& cert, std::shared_ptr<AsymmetricKey> rootKey)
    {
        std::shared_ptr<RsaKey> rsakey;
        std::shared_ptr<EccKey> ecckey;
        std::shared_ptr<DhKey> dhkey;
        std::shared_ptr<Signer> signer;
        tsCryptoString signerName;

        rsakey = std::dynamic_pointer_cast<RsaKey>(rootKey);
        ecckey = std::dynamic_pointer_cast<EccKey>(rootKey);
        dhkey = std::dynamic_pointer_cast<DhKey>(rootKey);

        if (!!ecckey)
        {
            switch (_crypto.signatureHash)
            {
            case TS_ALG_SHA1:
                signerName = "SIGN-ECC-SHA1";
                break;
            case TS_ALG_SHA224:
                signerName = "SIGN-ECC-SHA224";
                break;
            case TS_ALG_SHA256:
                signerName = "SIGN-ECC-SHA256";
                break;
            case TS_ALG_SHA384:
                signerName = "SIGN-ECC-SHA384";
                break;
            case TS_ALG_SHA512:
                signerName = "SIGN-ECC-SHA512";
                break;
            default:
                throw tscrypto::Exception("Invalid signer hash detected.");
            }
        }
        else if (!!rsakey)
        {
            switch (_crypto.signatureHash)
            {
            case TS_ALG_SHA1:
                signerName = "SIGN-RSA-PKCS-SHA1";
                break;
            case TS_ALG_SHA224:
                signerName = "SIGN-RSA-PKCS-SHA224";
                break;
            case TS_ALG_SHA256:
                signerName = "SIGN-RSA-PKCS-SHA256";
                break;
            case TS_ALG_SHA384:
                signerName = "SIGN-RSA-PKCS-SHA384";
                break;
            case TS_ALG_SHA512:
                signerName = "SIGN-RSA-PKCS-SHA512";
                break;
            default:
                throw tscrypto::Exception("Invalid signer hash detected.");
            }
        }
        else if (!!dhkey)
        {
            switch (_crypto.signatureHash)
            {
            case TS_ALG_SHA1:
                signerName = "SIGN-DSA-SHA1";
                break;
            case TS_ALG_SHA224:
                signerName = "SIGN-DSA-SHA224";
                break;
            case TS_ALG_SHA256:
                signerName = "SIGN-DSA-SHA256";
                break;
            case TS_ALG_SHA384:
                signerName = "SIGN-DSA-SHA384";
                break;
            case TS_ALG_SHA512:
                signerName = "SIGN-DSA-SHA512";
                break;
            default:
                throw tscrypto::Exception("Invalid signer hash detected.");
            }
        }
        else
            throw tscrypto::Exception("Invalid root key");

        tsCryptoData signature;

        signer = std::dynamic_pointer_cast<Signer>(CryptoFactory(signerName));

        if (!signer || !signer->initialize(rootKey) || !signer->update(cert.get_tbsCertificate().Encode()) || !signer->sign(signature))
            throw tscrypto::Exception("Unable to sign the certificate.");

        cert.get_signature().bits(signature);
    }
    uint8_t ComputeBlobType(bool publicValue, int dataLenInBytes)
    {
        if (publicValue)
        {
            switch (dataLenInBytes)
            {
            case 32:
                return 0x31;
            case 48:
                return 0x33;
            case 66:
                return 0x35;
            default:
                throw tscrypto::ArgumentException("No public key in this credential");
            }
        }
        else
        {
            switch (dataLenInBytes)
            {
            case 32:
                return 0x32;
            case 48:
                return 0x34;
            case 66:
                return 0x36;
            default:
                throw tscrypto::ArgumentException("No private key in this credential");
            }
        }
    }
    uint8_t ComputeSignerBlobType(bool publicValue, int dataLenInBytes)
    {
        if (publicValue)
        {
            switch (dataLenInBytes)
            {
            case 32:
                return 0x31;
            case 48:
                return 0x33;
            case 66:
                return 0x35;
            default:
                throw tscrypto::ArgumentException("No public verifier in this credential");
            }
        }
        else
        {
            switch (dataLenInBytes)
            {
            case 32:
                return 0x32;
            case 48:
                return 0x34;
            case 66:
                return 0x36;
            default:
                throw tscrypto::ArgumentException("No private signer in this credential");
            }
        }
    }
#pragma endregion
#pragma region Core Issuer Cert routines
protected:
    tsCryptoData BuildCertificate(CA_Certificate_Request& req, std::shared_ptr<AsymmetricKey>& certKey, std::shared_ptr<AsymmetricKey>& signingKey)
    {
        _POD_Certificate cert;
        _POD_TBSCertificate &tbs = cert.get_tbsCertificate();

        tbs.SetVersion(2);
        tsCryptoData tmp;
        tmp.assign((uint8_t*)&_crypto.nextSerialNumber, sizeof(_crypto.nextSerialNumber));
        _crypto.nextSerialNumber++;
#if BYTE_ORDER == LITTLE_ENDIAN
        tmp.reverse();
#endif
        while (tmp.size() > 1 && tmp[0] == 0)
            tmp.erase(0, 1);
        if (tmp[0] & 0x80)
            tmp.insert(0, (uint8_t)0);
        tbs.set_serialNumber(tmp);
        tbs.set_signature(BuildSignatureAlgorithm());
        tbs.set_issuer(BuildIssuerName());
        tbs.set_validity(BuildValidity(req.days));
        tbs.set_subject(BuildSubjectName(req));
        tbs.set_subjectPublicKeyInfo(BuildPublicKeyInfo(certKey, req, true));
        tbs.set_extensions(BuildAttributes(req));

        cert.set_algorithmIdentifier(BuildSignatureAlgorithm());

        SignCert(cert, signingKey);
        return cert.Encode();
    }
public:
    virtual void NewCA(const char *keyType, int optKeySize, TS_ALG_ID hash)
    {
        std::shared_ptr<AsymmetricKey> rootKey = BuildRootKey(keyType, optKeySize, hash);

        if (!rootKey)
            throw tscrypto::Exception("Unable to generate the key pair");

        _crypto.nextSerialNumber = 1;
        _crypto.issuerSerialNumber = _crypto.nextSerialNumber;

        if (_crypto.issuerDays < 365)
        {
            _crypto.issuerDays = 1460;
        }
        if (_crypto.memberDays < 10)
        {
            _crypto.memberDays = 365;
        }

        CA_Certificate_Request req;

        req.dn = _issuer.ToString();
        req.templateName = "CA";
        AddTemplateNameToRequest(req);
        req.keyUsage = (CA_Certificate_Request::KeyUsageFlags)(CA_Certificate_Request::digitialSignature | CA_Certificate_Request::keyCertSign | CA_Certificate_Request::CRLSign);
        AddBasicConstraintsToRequest(req);
        AddCaVersionToRequest(req);
        AddSubjectKeyIdentifierToRequest(req, rootKey);
        //AddAuthorityKeyIdentifierToRequest(req, rootKey);
        req.days = _crypto.issuerDays;

        _crypto.rootCert = BuildCertificate(req, rootKey, rootKey);

        std::shared_ptr<AlgorithmInfo> info = std::dynamic_pointer_cast<AlgorithmInfo>(rootKey);
        _crypto.keyType = info->AlgorithmID();
        _crypto.CA_PrivateKey = rootKey->toByteArray();
    }

    virtual void NewCA(std::shared_ptr<AsymmetricKey> key, TS_ALG_ID hash)
    {
        if (!key || !key->HasPrivateKey())
            throw tscrypto::Exception("Unable to use the specified key pair");

        _crypto.nextSerialNumber = 1;
        _crypto.issuerSerialNumber = _crypto.nextSerialNumber;

        if (_crypto.issuerDays < 365)
        {
            _crypto.issuerDays = 1460;
        }
        if (_crypto.memberDays < 10)
        {
            _crypto.memberDays = 365;
        }

        CA_Certificate_Request req;

        req.dn = _issuer.ToString();
        req.templateName = "CA";
        AddTemplateNameToRequest(req);
        req.keyUsage = (CA_Certificate_Request::KeyUsageFlags)(CA_Certificate_Request::digitialSignature | CA_Certificate_Request::keyCertSign | CA_Certificate_Request::CRLSign);
        AddBasicConstraintsToRequest(req);
        AddCaVersionToRequest(req);
        AddSubjectKeyIdentifierToRequest(req, key);
        //AddAuthorityKeyIdentifierToRequest(req, rootKey);
        req.days = _crypto.issuerDays;

        _crypto.rootCert = BuildCertificate(req, key, key);

        std::shared_ptr<AlgorithmInfo> info = std::dynamic_pointer_cast<AlgorithmInfo>(key);
        _crypto.keyType = info->AlgorithmID();
        _crypto.CA_PrivateKey = key->toByteArray();
    }
    virtual void CreatePivSigningCert(tsCryptoData& certData, tsCryptoData& keyPair)
    {
        std::shared_ptr<AsymmetricKey> pivKey = BuildPivSigningKey();
        std::shared_ptr<AsymmetricKey> rootKey = GetRootKey();

        // We will use the issuer information for the PIV subject id.
        CA_Certificate_Request pivInfo;
        tsDistinguishedName dn = _issuer;
        tsDnPart* part = dn.findPartByName("CN");

        if (part == nullptr)
        {
            dn.AddPart("CN", "Piv Signature Cert");
        }
        else
            part->Value("Piv Signature Cert");

        pivInfo.dn = dn.ToString();

        AddPivContentSigningToRequest(pivInfo);
        pivInfo.keyUsage = (CA_Certificate_Request::KeyUsageFlags)(CA_Certificate_Request::digitialSignature | CA_Certificate_Request::nonRepudiation);
        AddSubjectKeyIdentifierToRequest(pivInfo, pivKey);
        AddAuthorityKeyIdentifierToRequest(pivInfo, rootKey);
        if (pivInfo.days < 1 || pivInfo.days > _crypto.memberDays)
            pivInfo.days = _crypto.memberDays;
        AddTemplateNameToRequest(pivInfo);

        certData = BuildCertificate(pivInfo, pivKey, rootKey);

        keyPair = pivKey->toByteArray();
    }
    virtual void CreateMemberCertAndKey(CA_Certificate_Request& member, const char *keyType, int optKeySize, tsCryptoData& certData, tsCryptoData& keyPair)
    {
        std::shared_ptr<AsymmetricKey> rootKey = GetRootKey();
        std::shared_ptr<AsymmetricKey> certKey = BuildKey(keyType, optKeySize);

        keyPair = certKey->toByteArray();
        certData = CreateMemberCert(member, keyPair);
    }
    virtual tsCryptoData CreateMemberCert(CA_Certificate_Request& member, const tsCryptoData& publicKey)
    {
        std::shared_ptr<AsymmetricKey> certKey = TSBuildAsymmetricKeyFromBlob(publicKey);
        std::shared_ptr<AsymmetricKey> rootKey = GetRootKey();

        if (member.days < 1 || member.days > _crypto.memberDays)
            member.days = _crypto.memberDays;

        AddTemplateNameToRequest(member);
        AddSubjectKeyIdentifierToRequest(member, certKey);
        AddAuthorityKeyIdentifierToRequest(member, rootKey);

        return BuildCertificate(member, certKey, rootKey);
    }
    virtual tsCryptoData CreateMemberCert(CA_Certificate_Request& member, std::shared_ptr<AsymmetricKey> publicKey)
    {
        std::shared_ptr<AsymmetricKey> rootKey = GetRootKey();

        if (member.days < 1 || member.days > _crypto.memberDays)
            member.days = _crypto.memberDays;

        AddTemplateNameToRequest(member);
        AddSubjectKeyIdentifierToRequest(member, publicKey);
        AddAuthorityKeyIdentifierToRequest(member, rootKey);

        return BuildCertificate(member, publicKey, rootKey);
    }
#pragma endregion
    //#pragma region CAC Cert support
    //public:
    //	tsCryptoData CreateMemberAuthCert_asdf(const tsCryptoData& pubModulus, const tsCryptoData& pubExp, XmlDocument doc)
    //	{
    //		////XmlNode certNode;
    //		////XmlNode certsNode;
    //		////int certNumber;
    //		////int memberId = Convert.ToInt32(DatabaseHelper.GetAttribute(Member, "id", "0"));
    //		TlvDocument cert = new TlvDocument();
    //
    //		////if ( memberId == 0 )
    //		////    throw tscrypto::Exception("The member Id is not set");
    //
    //		XmlNode caRootNode = DatabaseHelper.FindNode("/cardmanager/ca", doc.DocumentElement); ;
    //
    //		object rootKey = GetRootKey(caRootNode);
    //		int keyLenInBytes = (Convert.ToInt32(DatabaseHelper.GetAttribute(caRootNode, "keysize", "256")) + 7) / 8;
    //
    //		////if (DatabaseHelper.GetAttribute(canode->ParentNode, "keytype", "RSA").ToUpper() == "RSA")
    //		////{
    //		////    RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(Convert.ToInt32(DatabaseHelper.GetAttribute(caNode, "keysize", "1024")));
    //
    //		////    XmlNode issuerNode = Utilities.FindNode("/cardmanager/ca/issuer", doc.DocumentElement);
    //		////    certsNode = Utilities.FindNode("/cardmanager/ca/certs", doc.DocumentElement);
    //
    //		////    certNumber = Convert.ToInt32(DatabaseHelper.GetAttribute(caNode, "certCount", "1"));
    //		////    Utilities.SetAttribute(caNode, "certCount", (certNumber + 1).ToString());
    //
    //		////    if (certsNode == null)
    //		////    {
    //		////        certsNode = doc.CreateElement("certs");
    //		////        canode->AppendChild(certsNode);
    //		////    }
    //		////    certNode = doc.CreateElement("cert");
    //
    //
    //		////    cert->DocumentElement()->Tag = 0x10;
    //		////    cert->DocumentElement()->TagType = 0;
    //		////    TlvNode certInfo;
    //
    //		////    certInfo = cert->CreateTlvNode(0x10, 0);
    //		////    cert->DocumentElement()->AppendChild(certInfo);
    //		////    // First we need the version information
    //		////    AddVersion(certInfo);
    //		////    // Then add the serial number
    //		////    AddSerialNumber(certInfo, certNumber);
    //		////    // Now we need the signature algorithm
    //		////    AddRsaSignatureAlgorithm(certInfo);
    //		////    // Issuer information
    //		////    AddIssuerInfo(certInfo, issuerNode);
    //		////    // Validity
    //		////    AddValidity(certInfo, Member);
    //		////    // Subject
    //		////    AddSubjectInfo(certInfo, issuerNode, DatabaseHelper.GetAttribute(Member, "name", "unknown"), DatabaseHelper.GetAttribute(Member, "email", ""));
    //		////    // Public Key Info
    //
    //		////    if (pubModulus == null || pubExp == null)
    //		////        throw tscrypto::Exception("The public key template is not recognized.");
    //
    //		////    AddPublicKeyInfo(certInfo, pubModulus, pubExp);
    //		////    // Attributes
    //		////    AddMemberAuthCertAttributes(certInfo, Member, caNode, pubModulus, pubExp);
    //		////    // Signature Algorithm
    //		////    AddRsaSignatureAlgorithm(cert->DocumentElement);
    //		////    // Signature
    //		////    byte[] dataToSign = cert->DocumentElement()->Children[0].OuterData();
    //
    //		////    //
    //		////    // Now get the root key and sign this certificate
    //		////    //
    //		SignCert(cert, keyLenInBytes, rootKey);
    //		////}
    //		////else if (DatabaseHelper.GetAttribute(canode->ParentNode, "keytype", "RSA").ToUpper() == "ECDSA")
    //		////{
    //		////    // TODO:  Implement ECDSA
    //		////    throw tscrypto::NotImplementedException();
    //		////}
    //		////else
    //		////{
    //		throw tscrypto::NotImplementedException();
    //		////}
    //		////return cert->SaveTlv();
    //	}
    //#pragma endregion
#pragma region PIV Cert Support - SmartCard
private:
    //object GetCardKeyFromCardData(const tsCryptoData& outData)
    //{
    //	TlvDocument pubKeyDoc = new TlvDocument();
    //
    //	pubKeyDoc.LoadTlv(outData);
    //	if (pubKeyDoc.DocumentElement()->Tag != 0x49 || pubKeyDoc.DocumentElement()->TagType != 1)
    //	{
    //		throw tscrypto::Exception("Unable to generate the RSA key pair for Piv Authentication (invalid public key).");
    //	}
    //
    //	byte[] modulus = null;
    //	byte[] exponent = null;
    //	byte[] ecKey = null;
    //
    //	foreach(TlvNode node in pubKeyDoc.DocumentElement()->Children)
    //	{
    //		if (node->Tag == 1 && node->TagType == 2)
    //			modulus = node->InnerData();
    //		else if (node->Tag == 2 && node->TagType == 2)
    //			exponent = node->InnerData();
    //		else if (node->Tag == 6 && node->TagType == 2)
    //			ecKey = node->InnerData();
    //		else
    //			throw tscrypto::Exception("The public key template is not recognized.");
    //	}
    //	if ((modulus == null || exponent == null) && ecKey == null)
    //		throw tscrypto::Exception("The public key template is not recognized.");
    //
    //	if (ecKey != null && (modulus != null || exponent != null))
    //		throw tscrypto::Exception("The public key template is not recognized.");
    //
    //	if (ecKey != null && (ecKey[0] != 4 || (ecKey.Length & 1) != 1))
    //	{
    //		throw tscrypto::Exception("The public key template is not recognized.");
    //	}
    //
    //	if (ecKey != null)
    //	{
    //		ecKey = Utilities.Substring(ecKey, 1, ecKey.Length - 1);
    //		int keyLen = ecKey.Length >> 1;
    //		byte[] tmp = new byte[keyLen * 3];
    //		ecKey.CopyTo(tmp, 0);
    //
    //		return tmp;
    //	}
    //	else
    //	{
    //		RSAParameters parms = new RSAParameters();
    //		parms.Modulus = modulus;
    //		parms.Exponent = exponent;
    //		RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(modulus.Length * 8);
    //		rsa.ImportParameters(parms);
    //		return rsa;
    //	}
    //}
public:
    //int KeyLenInBytesFromKey(std::shared_ptr<AsymmetricKey> key)
    //{
    //	if (key is byte[])
    //	{
    //		return (((byte[])key).Length - 8) / 3;
    //	}
    //	else if (key is byte[])
    //	{
    //		return (((byte[])key).Length / 3);
    //	}
    //	else
    //	{
    //		return (((RSACryptoServiceProvider)key).KeySize + 7) / 8;
    //	}
    //}
    //tsCryptoData CreateMemberAuthCert(GPSmartCard card, XmlDocument doc, const CA_Name_Info& Member, XmlNode token)
    //{
    //	XmlNode certNode;
    //	XmlNode certsNode;
    //	byte[] outData = null;
    //	int certNumber;
    //	TlvDocument cert = new TlvDocument();
    //	int memberId = Convert.ToInt32(DatabaseHelper.GetAttribute(Member, "id", "0"));
    //
    //	if (memberId == 0)
    //		throw tscrypto::Exception("The member Id is not set");
    //
    //	XmlNode caRootNode = DatabaseHelper.FindNode("/cardmanager/ca", doc.DocumentElement); ;
    //
    //	object rootKey = GetRootKey(caRootNode);
    //	int keyLenInBytes = (Convert.ToInt32(DatabaseHelper.GetAttribute(caRootNode, "keysize", "256")) + 7) / 8;
    //
    //
    //	XmlNode issuerNode = DatabaseHelper.FindNode("/cardmanager/ca/issuer", doc.DocumentElement);
    //	certsNode = DatabaseHelper.FindNode("/cardmanager/ca/certs", doc.DocumentElement);
    //
    //	certNumber = Convert.ToInt32(DatabaseHelper.GetAttribute(caRootNode, "certCount", "1"));
    //	DatabaseHelper.SetAttribute(caRootNode, "certCount", (certNumber + 1).ToString());
    //
    //	if (certsNode == null)
    //	{
    //		certsNode = doc.CreateElement("certs");
    //		caRootnode->AppendChild(certsNode);
    //	}
    //	certNode = doc.CreateElement("cert");
    //
    //
    //	cert->DocumentElement()->Tag = 0x10;
    //	cert->DocumentElement()->TagType = 0;
    //	std::shared_ptr<TlvNode> certInfo;
    //
    //	certInfo = cert->CreateTlvNode(0x10, 0);
    //	cert->DocumentElement()->AppendChild(certInfo);
    //	// First we need the version information
    //	AddVersion(certInfo);
    //	// Then add the serial number
    //	AddSerialNumber(certInfo, certNumber);
    //	// Now we need the signature algorithm
    //	AddSignatureAlgorithm(certInfo, keyLenInBytes, rootKey);
    //	// Issuer information
    //	AddIssuerInfo(certInfo, issuerNode);
    //	// Validity
    //	AddValidity(certInfo, Member);
    //	// Subject
    //	AddSubjectInfo(certInfo, issuerNode, DatabaseHelper.GetAttribute(Member, "name", "unknown"), DatabaseHelper.GetAttribute(Member, "email", ""));
    //
    //
    //
    //	// Public Key Info
    //	byte[] inData;
    //	byte[] algs = Utilities.HexStringToBytes(DatabaseHelper.GetAttribute(token, "keyAlgs", "0603060606"));
    //
    //	inData = new byte[]{ 0xAC, 0x03, 0x80, 0x01, algs[0] };
    //
    //	if (card.SendCommand(0x00, 0x47, 0x00, 0x9a, (byte)inData.size(), inData, 0, ref outData) != 0x9000)
    //	{
    //		throw tscrypto::Exception("Unable to generate the RSA key pair for Piv Authentication.");
    //	}
    //
    //	object cardKey = GetCardKeyFromCardData(outData);
    //
    //	AddPublicKeyInfo(certInfo, KeyLenInBytesFromKey(cardKey), cardKey);
    //	// Attributes
    //	AddMemberAuthCertAttributes(certInfo, Member, caRootNode, keyLenInBytes, rootKey);
    //	// Signature Algorithm
    //	AddSignatureAlgorithm(cert->DocumentElement(), keyLenInBytes, rootKey);
    //	// Signature
    //	byte[] dataToSign = cert->DocumentElement()->Children[0].OuterData();
    //
    //	//
    //	// Now get the root key and sign this certificate
    //	//
    //	SignCert(cert, keyLenInBytes, rootKey);
    //
    //	certnode->InnerText = Convert.ToBase64String(cert->SaveTlv());
    //	DatabaseHelper.SetAttribute(certNode, "memberid", memberId.ToString());
    //	DatabaseHelper.SetAttribute(certNode, "id", certNumber.ToString());
    //	DatabaseHelper.SetAttribute(certNode, "certtype", "PIV-Auth");
    //
    //	certsnode->AppendChild(certNode);
    //	return cert->SaveTlv();
    //}
    //tsCryptoData CreateMemberPivSigningCert(GPSmartCard card, XmlDocument doc, const CA_Name_Info& Member, XmlNode token)
    //{
    //	XmlNode certNode;
    //	XmlNode certsNode;
    //	byte[] outData = null;
    //	int certNumber;
    //	int memberId = Convert.ToInt32(DatabaseHelper.GetAttribute(Member, "id", "0"));
    //	TlvDocument cert = new TlvDocument();
//
    //	if (memberId == 0)
    //		throw tscrypto::Exception("The member Id is not set");
//
    //	XmlNode caRootNode = DatabaseHelper.FindNode("/cardmanager/ca", doc.DocumentElement); ;
//
    //	object rootKey = GetRootKey(caRootNode);
    //	int keyLenInBytes = (Convert.ToInt32(DatabaseHelper.GetAttribute(caRootNode, "keysize", "256")) + 7) / 8;
//
    //	XmlNode issuerNode = DatabaseHelper.FindNode("/cardmanager/ca/issuer", doc.DocumentElement);
    //	certsNode = DatabaseHelper.FindNode("/cardmanager/ca/certs", doc.DocumentElement);
//
    //	certNumber = Convert.ToInt32(DatabaseHelper.GetAttribute(caRootNode, "certCount", "1"));
    //	DatabaseHelper.SetAttribute(caRootNode, "certCount", (certNumber + 1).ToString());
//
    //	if (certsNode == null)
    //	{
    //		certsNode = doc.CreateElement("certs");
    //		caRootnode->AppendChild(certsNode);
    //	}
    //	certNode = doc.CreateElement("cert");
//
//
    //	cert->DocumentElement()->Tag = 0x10;
    //	cert->DocumentElement()->TagType = 0;
    //	std::shared_ptr<TlvNode> certInfo;
//
    //	certInfo = cert->CreateTlvNode(0x10, 0);
    //	cert->DocumentElement()->AppendChild(certInfo);
    //	// First we need the version information
    //	AddVersion(certInfo);
    //	// Then add the serial number
    //	AddSerialNumber(certInfo, certNumber);
    //	// Now we need the signature algorithm
    //	AddSignatureAlgorithm(certInfo, keyLenInBytes, rootKey);
    //	// Issuer information
    //	AddIssuerInfo(certInfo, issuerNode);
    //	// Validity
    //	AddValidity(certInfo, Member);
    //	// Subject
    //	AddSubjectInfo(certInfo, issuerNode, DatabaseHelper.GetAttribute(Member, "name", "unknown"), DatabaseHelper.GetAttribute(Member, "email", ""));
    //	// Public Key Info
    //	byte[] inData;
//
    //	byte[] algs = Utilities.HexStringToBytes(DatabaseHelper.GetAttribute(token, "keyAlgs", "0603060606"));
//
    //	inData = new byte[]{ 0xAC, 0x03, 0x80, 0x01, algs[2] };
//
    //	if (card.SendCommand(0x00, 0x47, 0x00, 0x9C, (byte)inData.size(), inData, 0, ref outData) != 0x9000)
    //	{
    //		throw tscrypto::Exception("Unable to generate the RSA key pair for Piv Authentication.");
    //	}
    //	object cardKey = GetCardKeyFromCardData(outData);
//
    //	AddPublicKeyInfo(certInfo, KeyLenInBytesFromKey(cardKey), cardKey);
    //	// Attributes
    //	AddMemberPivSigningAttributes(certInfo, Member, keyLenInBytes, rootKey);
    //	// Signature Algorithm
    //	AddSignatureAlgorithm(cert->DocumentElement(), keyLenInBytes, rootKey);
    //	// Signature
    //	byte[] dataToSign = cert->DocumentElement()->Children[0].OuterData();
//
    //	//
    //	// Now get the root key and sign this certificate
    //	//
    //	SignCert(cert, keyLenInBytes, rootKey);
//
    //	certnode->InnerText = Convert.ToBase64String(cert->SaveTlv());
    //	DatabaseHelper.SetAttribute(certNode, "memberid", memberId.ToString());
    //	DatabaseHelper.SetAttribute(certNode, "id", certNumber.ToString());
    //	DatabaseHelper.SetAttribute(certNode, "certtype", "PIV-Sign");
//
    //	certsnode->AppendChild(certNode);
    //	return cert->SaveTlv();
    //}
    //tsCryptoData CreateMemberPivKeyCert(GPSmartCard card, XmlDocument doc, const CA_Name_Info& Member, const tsCryptoData& kek, XmlNode token)
    //{
    //	XmlNode certNode;
    //	XmlNode certsNode;
    //	int certNumber;
    //	int memberId = Convert.ToInt32(DatabaseHelper.GetAttribute(Member, "id", "0"));
    //	byte[] algs = Utilities.HexStringToBytes(DatabaseHelper.GetAttribute(token, "keyAlgs", "0603060606"));
    //	TlvDocument cert = new TlvDocument();
//
    //	if (memberId == 0)
    //		throw tscrypto::Exception("The member Id is not set");
//
    //	XmlNode caRootNode = DatabaseHelper.FindNode("/cardmanager/ca", doc.DocumentElement); ;
//
    //	object rootKey = GetRootKey(caRootNode);
    //	object certKey = GetKekKey(caRootNode, Member, algs[3]);
    //	if (certKey is byte[])
    //	{
    //		certKey = GetKekKeyPrivateBytes(caRootNode, Member, algs[3]);
    //	}
    //	int keyLenInBytes = (Convert.ToInt32(DatabaseHelper.GetAttribute(caRootNode, "keysize", "256")) + 7) / 8;
//
    //	if (!PivUtilities.PutKeyThroughSSD(0x9d, certKey, card, Globals.gPivAID, kek))
    //	{
    //		throw tscrypto::Exception("Unable to put the Key Encryption Key into the token.");
    //	}
//
    //	XmlNode issuerNode = DatabaseHelper.FindNode("/cardmanager/ca/issuer", doc.DocumentElement);
    //	certsNode = DatabaseHelper.FindNode("/cardmanager/ca/certs", doc.DocumentElement);
//
    //	certNumber = Convert.ToInt32(DatabaseHelper.GetAttribute(caRootNode, "certCount", "1"));
    //	DatabaseHelper.SetAttribute(caRootNode, "certCount", (certNumber + 1).ToString());
//
    //	if (certsNode == null)
    //	{
    //		certsNode = doc.CreateElement("certs");
    //		caRootnode->AppendChild(certsNode);
    //	}
    //	certNode = doc.CreateElement("cert");
//
//
    //	cert->DocumentElement()->Tag = 0x10;
    //	cert->DocumentElement()->TagType = 0;
    //	std::shared_ptr<TlvNode> certInfo;
//
    //	certInfo = cert->CreateTlvNode(0x10, 0);
    //	cert->DocumentElement()->AppendChild(certInfo);
    //	// First we need the version information
    //	AddVersion(certInfo);
    //	// Then add the serial number
    //	AddSerialNumber(certInfo, certNumber);
    //	// Now we need the signature algorithm
    //	AddSignatureAlgorithm(certInfo, keyLenInBytes, rootKey);
    //	// Issuer information
    //	AddIssuerInfo(certInfo, issuerNode);
    //	// Validity
    //	AddValidity(certInfo, Member);
    //	// Subject
    //	AddSubjectInfo(certInfo, issuerNode, DatabaseHelper.GetAttribute(Member, "name", "unknown"), DatabaseHelper.GetAttribute(Member, "email", ""));
    //	// Public Key Info
    //	AddPublicKeyInfo(certInfo, KeyLenInBytesFromKey(certKey), certKey);
    //	// Attributes
    //	AddMemberPivEncryptionAttributes(certInfo, Member, KeyLenInBytesFromKey(certKey), certKey);
    //	// Signature Algorithm
    //	AddSignatureAlgorithm(cert->DocumentElement(), keyLenInBytes, rootKey);
    //	// Signature
    //	byte[] dataToSign = cert->DocumentElement()->Children[0].OuterData();
//
    //	//
    //	// Now get the root key and sign this certificate
    //	//
    //	SignCert(cert, keyLenInBytes, rootKey);
    //	certnode->InnerText = Convert.ToBase64String(cert->SaveTlv());
    //	DatabaseHelper.SetAttribute(certNode, "memberid", memberId.ToString());
    //	DatabaseHelper.SetAttribute(certNode, "id", certNumber.ToString());
    //	DatabaseHelper.SetAttribute(certNode, "certtype", "PIV-Kek");
//
    //	certsnode->AppendChild(certNode);
    //	return cert->SaveTlv();
    //}
    //tsCryptoData CreateCardAuthCert(GPSmartCard card, XmlDocument doc, const CA_Name_Info& Member, bool forBiometric, XmlNode token)
    //{
    //	XmlNode certNode;
    //	XmlNode certsNode;
    //	byte[] outData = null;
    //	int certNumber;
    //	int memberId = Convert.ToInt32(DatabaseHelper.GetAttribute(Member, "id", "0"));
    //	TlvDocument cert = new TlvDocument();
//
    //	if (memberId == 0)
    //		throw tscrypto::Exception("The member Id is not set");
//
    //	XmlNode caRootNode = DatabaseHelper.FindNode("/cardmanager/ca", doc.DocumentElement); ;
//
    //	object rootKey = GetRootKey(caRootNode);
    //	int keyLenInBytes = (Convert.ToInt32(DatabaseHelper.GetAttribute(caRootNode, "keysize", "256")) + 7) / 8;
//
    //	XmlNode issuerNode = DatabaseHelper.FindNode("/cardmanager/ca/issuer", doc.DocumentElement);
    //	certsNode = DatabaseHelper.FindNode("/cardmanager/ca/certs", doc.DocumentElement);
//
    //	certNumber = Convert.ToInt32(DatabaseHelper.GetAttribute(caRootNode, "certCount", "1"));
    //	DatabaseHelper.SetAttribute(caRootNode, "certCount", (certNumber + 1).ToString());
//
    //	if (certsNode == null)
    //	{
    //		certsNode = doc.CreateElement("certs");
    //		caRootnode->AppendChild(certsNode);
    //	}
    //	certNode = doc.CreateElement("cert");
//
//
    //	cert->DocumentElement()->Tag = 0x10;
    //	cert->DocumentElement()->TagType = 0;
    //	std::shared_ptr<TlvNode> certInfo;
//
    //	certInfo = cert->CreateTlvNode(0x10, 0);
    //	cert->DocumentElement()->AppendChild(certInfo);
    //	// First we need the version information
    //	AddVersion(certInfo);
    //	// Then add the serial number
    //	AddSerialNumber(certInfo, certNumber);
    //	// Now we need the signature algorithm
    //	AddSignatureAlgorithm(certInfo, keyLenInBytes, rootKey);
    //	// Issuer information
    //	AddIssuerInfo(certInfo, issuerNode);
    //	// Validity
    //	AddValidity(certInfo, Member);
    //	// Subject
    //	AddSubjectInfo(certInfo, issuerNode, DatabaseHelper.GetAttribute(Member, "name", "unknown"), DatabaseHelper.GetAttribute(Member, "email", ""));
    //	// Public Key Info
    //	if (forBiometric)
    //	{
    //		byte[] inData = new byte[]{ 0x80, 0x02, 0x00, 0x10, 0x41, 0x01, 0x00, 0xAC, 0x03, 0x80, 0x01, 0x06 };
//
    //		if (card.SendCommand(0x80, 0xE2, 0x80, 0x00, (byte)inData.size(), inData, 0, ref outData) != 0x9000)
    //		{
    //			throw tscrypto::Exception("Unable to generate the RSA key pair for Biometric card Authentication.");
    //		}
    //	}
    //	else
    //	{
    //		byte[] inData;
//
    //		byte[] algs = Utilities.HexStringToBytes(DatabaseHelper.GetAttribute(token, "keyAlgs", "0603060606"));
//
    //		inData = new byte[]{ 0xAC, 0x03, 0x80, 0x01, algs[4] };
//
    //		if (card.SendCommand(0x00, 0x47, 0x00, 0x9E, (byte)inData.size(), inData, 0, ref outData) != 0x9000)
    //		{
    //			throw tscrypto::Exception("Unable to generate the key pair for Piv Authentication.");
    //		}
    //	}
    //	object cardKey = GetCardKeyFromCardData(outData);
//
    //	AddPublicKeyInfo(certInfo, KeyLenInBytesFromKey(cardKey), cardKey);
    //	// Attributes
    //	AddMemberPivSigningAttributes(certInfo, Member, keyLenInBytes, rootKey);
    //	// Signature Algorithm
    //	AddSignatureAlgorithm(cert->DocumentElement(), keyLenInBytes, rootKey);
    //	// Signature
    //	byte[] dataToSign = cert->DocumentElement()->Children[0].OuterData();
//
    //	//
    //	// Now get the root key and sign this certificate
    //	//
    //	SignCert(cert, keyLenInBytes, rootKey);
//
    //	certnode->InnerText = Convert.ToBase64String(cert->SaveTlv());
    //	DatabaseHelper.SetAttribute(certNode, "memberid", memberId.ToString());
    //	DatabaseHelper.SetAttribute(certNode, "id", certNumber.ToString());
    //	if (forBiometric)
    //		DatabaseHelper.SetAttribute(certNode, "certtype", "Bio-Card");
    //	else
    //		DatabaseHelper.SetAttribute(certNode, "certtype", "PIV-Card");
//
    //	certsnode->AppendChild(certNode);
    //	return cert->SaveTlv();
    //}
    //tsCryptoData CreateCardAuthCert_Contactless(GPSmartCard card, XmlDocument doc, const CA_Name_Info& Member, XmlNode token)
    //{
    //	XmlNode certNode;
    //	XmlNode certsNode;
    //	byte[] outData = null;
    //	int certNumber;
    //	int memberId = Convert.ToInt32(DatabaseHelper.GetAttribute(Member, "id", "0"));
    //	std::shared_ptr<TlvDocument> cert = TlvDocument::Create();
//
    //	if (memberId == 0)
    //		throw tscrypto::Exception("The member Id is not set");
//
    //	XmlNode caRootNode = DatabaseHelper.FindNode("/cardmanager/ca", doc.DocumentElement); ;
//
    //	object rootKey = GetRootKey(caRootNode);
    //	int keyLenInBytes = (Convert.ToInt32(DatabaseHelper.GetAttribute(caRootNode, "keysize", "256")) + 7) / 8;
//
    //	XmlNode issuerNode = DatabaseHelper.FindNode("/cardmanager/ca/issuer", doc.DocumentElement);
    //	certsNode = DatabaseHelper.FindNode("/cardmanager/ca/certs", doc.DocumentElement);
//
    //	certNumber = Convert.ToInt32(DatabaseHelper.GetAttribute(caRootNode, "certCount", "1"));
    //	DatabaseHelper.SetAttribute(caRootNode, "certCount", (certNumber + 1).ToString());
//
    //	if (certsNode == null)
    //	{
    //		certsNode = doc.CreateElement("certs");
    //		caRootnode->AppendChild(certsNode);
    //	}
    //	certNode = doc.CreateElement("cert");
//
//
    //	cert->DocumentElement()->Tag = 0x10;
    //	cert->DocumentElement()->TagType = 0;
    //	std::shared_ptr<TlvNode> certInfo;
//
    //	certInfo = cert->CreateTlvNode(0x10, 0);
    //	cert->DocumentElement()->AppendChild(certInfo);
    //	// First we need the version information
    //	AddVersion(certInfo);
    //	// Then add the serial number
    //	AddSerialNumber(certInfo, certNumber);
    //	// Now we need the signature algorithm
    //	AddSignatureAlgorithm(certInfo, keyLenInBytes, rootKey);
    //	// Issuer information
    //	AddIssuerInfo(certInfo, issuerNode);
    //	// Validity
    //	AddValidity(certInfo, Member);
    //	// Subject
    //	AddSubjectInfo(certInfo, issuerNode, DatabaseHelper.GetAttribute(Member, "name", "unknown"), DatabaseHelper.GetAttribute(Member, "email", ""));
    //	// Public Key Info
    //	byte[] inData;
//
    //	byte[] algs = Utilities.HexStringToBytes(DatabaseHelper.GetAttribute(token, "keyAlgs", "0603060606"));
//
    //	inData = new byte[]{ 0x80, 0x01, 0x9E, 0xAC, 0x03, 0x80, 0x01, algs[4] };
//
    //	if (card.SendCommand(0x80, 0xE2, 0x80, 0x00, (byte)inData.size(), inData, 0, ref outData) != 0x9000)
    //	{
    //		throw tscrypto::Exception("Unable to generate the RSA key pair for Piv Authentication.");
    //	}
    //	object cardKey = GetCardKeyFromCardData(outData);
    //	////byte[] modulus = null;
    //	////byte[] exponent = null;
    //	////if (outData.size() > 0)
    //	////{
    //	////    TlvDocument pubKeyDoc = new TlvDocument();
//
    //	////    pubKeyDoc.LoadTlv(outData);
    //	////    if (pubKeyDoc.DocumentElement()->Tag != 0x49 || pubKeyDoc.DocumentElement()->TagType != 1)
    //	////    {
    //	////        throw tscrypto::Exception("Unable to generate the RSA key pair for Piv Authentication (invalid public key).");
    //	////    }
//
    //	////    foreach (TlvNode node in pubKeyDoc.DocumentElement()->Children)
    //	////    {
    //	////        if (node->Tag == 1 && node->TagType == 2)
    //	////            modulus = node->InnerData();
    //	////        else if (node->Tag == 2 && node->TagType == 2)
    //	////            exponent = node->InnerData();
    //	////        else
    //	////            throw tscrypto::Exception("The public key template is not recognized.");
    //	////    }
    //	////}
    //	////else
    //	////{
    //	////    // The RSA key must be > 255 bytes.  Therefore go get the parts.
    //	////    if (card.SendCommand(Globals.gPersonalizePiv, ref outData) != 0x9000 ||
    //	////        card.SendCommand(new byte[] { 0x80, 0xE2, 0x80, 0x00, 0x06, 0x82, 0x01, 0x01, 0x41, 0x01, 0x01 }, ref exponent) != 0x9000 ||
    //	////        card.SendCommand(Globals.gPersonalizePiv, ref outData) != 0x9000 ||
    //	////        card.SendCommand(new byte[] { 0x80, 0xE2, 0x80, 0x00, 0x06, 0x82, 0x01, 0x01, 0x41, 0x01, 0x02 }, ref modulus) != 0x9000 ||
    //	////        card.SendCommand(Globals.gPersonalizePiv, ref outData) != 0x9000 ||
    //	////        card.SendCommand(new byte[] { 0x80, 0xE2, 0x80, 0x00, 0x06, 0x82, 0x01, 0x01, 0x41, 0x01, 0x03 }, ref outData) != 0x9000)
    //	////    {
    //	////        throw tscrypto::Exception("Unable to retrieve the public key.");
    //	////    }
    //	////    modulus = Utilities.HexStringToBytes(Utilities.BytesToHex(modulus) + Utilities.BytesToHex(outData));
    //	////}
    //	////if (modulus == null || exponent == null)
    //	////    throw tscrypto::Exception("The public key template is not recognized.");
//
    //	AddPublicKeyInfo(certInfo, keyLenInBytes, cardKey);
    //	// Attributes
    //	AddMemberPivSigningAttributes(certInfo, Member, keyLenInBytes, rootKey);
    //	// Signature Algorithm
    //	AddSignatureAlgorithm(cert->DocumentElement(), keyLenInBytes, rootKey);
    //	// Signature
    //	byte[] dataToSign = cert->DocumentElement()->Children[0].OuterData();
//
    //	//
    //	// Now get the root key and sign this certificate
    //	//
    //	SignCert(cert, keyLenInBytes, rootKey);
//
    //	certnode->InnerText = Convert.ToBase64String(cert->SaveTlv());
    //	DatabaseHelper.SetAttribute(certNode, "memberid", memberId.ToString());
    //	DatabaseHelper.SetAttribute(certNode, "id", certNumber.ToString());
    //	DatabaseHelper.SetAttribute(certNode, "certtype", "PIV-Card");
//
    //	certsnode->AppendChild(certNode);
    //	return cert->SaveTlv();
    //}
#pragma endregion
public:
    //tsCryptoData CreateScriptCert(const tsCryptoData& pubModulus, const tsCryptoData& pubExp, XmlDocument doc, int memberID, string memberName, string memberEmail)
    //{
    //	XmlNode certNode;
    //	XmlNode certsNode;
    //	XmlNode caNode;
    //	int certNumber;
    //
    //	RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(1024);
    //
    //	XmlNode issuerNode = DatabaseHelper.FindNode("/cardmanager/ca/issuer", doc.DocumentElement);
    //	caNode = DatabaseHelper.FindNode("/cardmanager/ca", doc.DocumentElement);
    //	certsNode = DatabaseHelper.FindNode("/cardmanager/ca/certs", doc.DocumentElement);
    //
    //	certNumber = Convert.ToInt32(DatabaseHelper.GetAttribute(caNode, "certCount", "1"));
    //	DatabaseHelper.SetAttribute(caNode, "certCount", (certNumber + 1).ToString());
    //
    //	if (certsNode == null)
    //	{
    //		certsNode = doc.CreateElement("certs");
    //		canode->AppendChild(certsNode);
    //	}
    //	certNode = doc.CreateElement("cert");
    //
    //
    //	TlvDocument cert = new TlvDocument();
    //	cert->DocumentElement()->Tag = 0x10;
    //	cert->DocumentElement()->TagType = 0;
    //	std::shared_ptr<TlvNode> certInfo;
    //
    //	certInfo = cert->CreateTlvNode(0x10, 0);
    //	cert->DocumentElement()->AppendChild(certInfo);
    //	// First we need the version information
    //	AddVersion(certInfo);
    //	// Then add the serial number
    //	AddSerialNumber(certInfo, certNumber);
    //	// Now we need the signature algorithm
    //	AddSignatureAlgorithm(certInfo);
    //	// Issuer information
    //	AddIssuerInfo(certInfo, issuerNode);
    //	// Validity
    //	AddValidity(certInfo, null);
    //	// Subject
    //	AddSubjectInfo(certInfo, issuerNode, memberName, memberEmail);
    //	// Public Key Info
    //
    //	if (pubModulus == null || pubExp == null)
    //		throw tscrypto::Exception("The public key template is not recognized.");
    //
    //	AddPublicKeyInfo(certInfo, pubModulus, pubExp);
    //	// Attributes
    //	AddMemberAuthCertAttributes(certInfo, null, caNode, pubModulus, pubExp);
    //	// Signature Algorithm
    //	AddSignatureAlgorithm(cert->DocumentElement);
    //	// Signature
    //	byte[] dataToSign = cert->DocumentElement()->Children[0].OuterData();
    //
    //	//
    //	// Now get the root key and sign this certificate
    //	//
    //	XmlNode rootKey = DatabaseHelper.FindNode("/cardmanager/ca/key", doc.DocumentElement);
    //
    //	rsa.FromXmlString(rootKey.OuterXml);
    //
    //	cert->DocumentElement()->AppendChild(MakeBitString(rsa.SignData(dataToSign, new SHA1CryptoServiceProvider()), 0, cert));
    //
    //	return cert->SaveTlv();
    //}
};

tscrypto::ICryptoObject* CreateCertificateIssuer()
{
    return dynamic_cast<tscrypto::ICryptoObject*>(new CertificateIssuer());
}

