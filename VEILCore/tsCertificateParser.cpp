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

static BYTE gRsaAlgorithm[] = { 42, 0x86, 72, 0x86, 0xf7, 13, 1, 1, 1 };

namespace tsCertificateTypes
{
    typedef enum {
        Unknown,		///< Unknown
        Name,			///< The entire name
        Surname,		///< The surname
        givenName,		///< The given name
        Initials,		///< Your initials
        Suffix,			///< Your suffix
        CommonName,		///< Your common name
        locality,		///< The locality (city for example)
        state,			///< your state name
        OrgName,		///< Your organization's name
        OrgUnit,		///< The name of an organizational unit
        Title,			///< Your title
        dnQualifier,	///< The distinquished name qualifier
        Country			///< Your country
    } NamePartType;
}

// static struct NamePartListItem
// {
//     tsCertificateTypes::NamePartType type;
//     const char *name;
//     const char *oid;
// } NamePartXref[]=
// {
//     {tsCertificateTypes::CommonName,    "CN",                   "2.5.4.3"},
//     {tsCertificateTypes::Surname,       "sn",                   "2.5.4.4"},
//     {tsCertificateTypes::Country,       "C",                    "2.5.4.6"},
//     {tsCertificateTypes::locality,      "L",                    "2.5.4.7"},
//     {tsCertificateTypes::state,         "ST",                   "2.5.4.8"},
//     {tsCertificateTypes::OrgName,       "O",                    "2.5.4.10"},
//     {tsCertificateTypes::OrgUnit,       "OU",                   "2.5.4.11"},
//     {tsCertificateTypes::Title,         "title",                "2.5.4.12"},
//     {tsCertificateTypes::Name,          "name",                 "2.5.4.41"},
//     {tsCertificateTypes::givenName,     "givenName",            "2.5.4.42"},
//     {tsCertificateTypes::Initials,      "initials",             "2.5.4.43"},
//     {tsCertificateTypes::Suffix,        "generationQualifier",  "2.5.4.44"},
//     {tsCertificateTypes::dnQualifier,   "dnQualifier",          "2.5.4.46"},
// };

tsCertificateParser::tsCertificateParser()
{
	m_extensionList = CreateContainer<tsCertificateExtension>();
	m_doc = TlvDocument::Create();
    Clear();
}

tsCertificateParser::~tsCertificateParser()
{
    Clear();
}

tsCertificateParser::tsCertificateParser(const tsCertificateParser& obj)
{
	m_doc = TlvDocument::Create();
    Clear();
    if (obj.m_originalData.size() > 0)
        LoadCertificate(obj.m_originalData);
}

tsCertificateParser::tsCertificateParser(tsCertificateParser&& obj) :
    m_doc(std::move(obj.m_doc)),
    m_version(obj.m_version),
    m_serialNumber(std::move(obj.m_serialNumber)),
    m_encodedSerialNumber(std::move(obj.m_encodedSerialNumber)),
    m_algorithmBlob(obj.m_algorithmBlob),
    m_algorithmOID(std::move(obj.m_algorithmOID)),
    m_algorithmParameters(obj.m_algorithmParameters),
    m_issuer(obj.m_issuer),
    m_start(std::move(obj.m_start)),
    m_end(std::move(obj.m_end)),
    m_subject(obj.m_subject),
    m_modulus(std::move(obj.m_modulus)),
    m_exponent(std::move(obj.m_exponent)),
    m_pubKeyAlgorithmBlob(std::move(obj.m_pubKeyAlgorithmBlob)),
    m_pubKeyAlgorithm(std::move(obj.m_pubKeyAlgorithm)),
    m_pubKeyAlgorithmParameters(obj.m_pubKeyAlgorithmParameters),
    m_publicKey(std::move(obj.m_publicKey)),
    m_issuerUniqueNumber(obj.m_issuerUniqueNumber),
    m_subjectUniqueNumber(obj.m_subjectUniqueNumber),
    m_extensionList(std::move(obj.m_extensionList)),
    m_signatureAlgorithmBlob(obj.m_signatureAlgorithmBlob),
    m_signatureAlgorithmOID(std::move(obj.m_signatureAlgorithmOID)),
    m_signatureAlgorithmParameters(obj.m_signatureAlgorithmParameters),
    m_certificateSignature(std::move(obj.m_certificateSignature)),
    m_originalData(std::move(obj.m_originalData))
{
    obj.m_version = ICertificateIssuer::X509_v1;
    obj.m_algorithmBlob = nullptr;
    obj.m_algorithmParameters = nullptr;
    obj.m_issuer = nullptr;
    obj.m_subject = nullptr;
    obj.m_pubKeyAlgorithmParameters = nullptr;
    obj.m_issuerUniqueNumber = nullptr;
    obj.m_subjectUniqueNumber = nullptr;
    obj.m_signatureAlgorithmBlob = nullptr;
    obj.m_signatureAlgorithmParameters = nullptr;
}

tsCertificateParser& tsCertificateParser::operator=(const tsCertificateParser& obj)
{
    if (&obj != this)
    {
        m_doc = (obj.m_doc);
        m_version = (obj.m_version);
        m_serialNumber = (obj.m_serialNumber);
        m_encodedSerialNumber = (obj.m_encodedSerialNumber);
        m_algorithmOID = (obj.m_algorithmOID);
        m_start = (obj.m_start);
        m_end = (obj.m_end);
        m_modulus = (obj.m_modulus);
        m_exponent = (obj.m_exponent);
        m_pubKeyAlgorithmBlob = (obj.m_pubKeyAlgorithmBlob);
        m_pubKeyAlgorithm = (obj.m_pubKeyAlgorithm);
        m_publicKey = (obj.m_publicKey);
        m_extensionList = (obj.m_extensionList);
        m_signatureAlgorithmOID = (obj.m_signatureAlgorithmOID);
        m_certificateSignature = (obj.m_certificateSignature);
        m_originalData = (obj.m_originalData);
        m_algorithmBlob = (obj.m_algorithmBlob);
        m_algorithmParameters = (obj.m_algorithmParameters);
        m_issuer = (obj.m_issuer);
        m_subject = (obj.m_subject);
        m_pubKeyAlgorithmParameters = (obj.m_pubKeyAlgorithmParameters);
        m_issuerUniqueNumber = (obj.m_issuerUniqueNumber);
        m_subjectUniqueNumber = (obj.m_subjectUniqueNumber);
        m_signatureAlgorithmBlob = (obj.m_signatureAlgorithmBlob);
        m_signatureAlgorithmParameters = (obj.m_signatureAlgorithmParameters);
    }
    return *this;
}

tsCertificateParser& tsCertificateParser::operator=(tsCertificateParser&& obj)
{
    if (&obj != this)
    {
        m_doc = (std::move(obj.m_doc));
        m_version = (obj.m_version);
        m_serialNumber = (std::move(obj.m_serialNumber));
        m_encodedSerialNumber = (std::move(obj.m_encodedSerialNumber));
        m_algorithmOID = (std::move(obj.m_algorithmOID));
        m_start = (std::move(obj.m_start));
        m_end = (std::move(obj.m_end));
        m_modulus = (std::move(obj.m_modulus));
        m_exponent = (std::move(obj.m_exponent));
        m_pubKeyAlgorithmBlob = (std::move(obj.m_pubKeyAlgorithmBlob));
        m_pubKeyAlgorithm = (std::move(obj.m_pubKeyAlgorithm));
        m_publicKey = (std::move(obj.m_publicKey));
        m_extensionList = (std::move(obj.m_extensionList));
        m_signatureAlgorithmOID = (std::move(obj.m_signatureAlgorithmOID));
        m_certificateSignature = (std::move(obj.m_certificateSignature));
        m_originalData = (std::move(obj.m_originalData));
        m_algorithmBlob = (obj.m_algorithmBlob);
        m_algorithmParameters = (obj.m_algorithmParameters);
        m_issuer = (obj.m_issuer);
        m_subject = (obj.m_subject);
        m_pubKeyAlgorithmParameters = (obj.m_pubKeyAlgorithmParameters);
        m_issuerUniqueNumber = (obj.m_issuerUniqueNumber);
        m_subjectUniqueNumber = (obj.m_subjectUniqueNumber);
        m_signatureAlgorithmBlob = (obj.m_signatureAlgorithmBlob);
        m_signatureAlgorithmParameters = (obj.m_signatureAlgorithmParameters);

        obj.m_version = ICertificateIssuer::X509_v1;
        obj.m_algorithmBlob = nullptr;
        obj.m_algorithmParameters = nullptr;
        obj.m_issuer = nullptr;
        obj.m_subject = nullptr;
        obj.m_pubKeyAlgorithmParameters = nullptr;
        obj.m_issuerUniqueNumber = nullptr;
        obj.m_subjectUniqueNumber = nullptr;
        obj.m_signatureAlgorithmBlob = nullptr;
        obj.m_signatureAlgorithmParameters = nullptr;
    }
    return *this;
}

bool tsCertificateParser::operator==(const tsCertificateParser& obj) const
{
    return m_originalData == obj.m_originalData;
}


//void *tsCertificateParser::operator new(size_t bytes) 
//{ 
//    return CryptoSupportAllocator(bytes); 
//}
//
//void tsCertificateParser::operator delete(void *ptr) 
//{ 
//    return CryptoSupportDeallocator(ptr); 
//}

bool tsCertificateParser::LoadCertificate(const tsCryptoData &certData)
{
    std::shared_ptr<TlvNode> certInfo;
    std::shared_ptr<TlvNode> node1;
    std::shared_ptr<TlvNode> node2;
    std::shared_ptr<TlvNode> node3;
	int tbsOffset = 0;

    Clear();

    if (!m_doc->LoadTlv(certData))
        return false;

    if (m_doc->DocumentElement()->Tag() != 0x10 || m_doc->DocumentElement()->Type() != 0 ||
        !m_doc->DocumentElement()->IsConstructed() || m_doc->DocumentElement()->Children()->size() < 3)
    {
        Clear();
        return false;
    }
    //
    // Now extract the cert info structures
    //
    certInfo = m_doc->DocumentElement()->Children()->at(0);
    if (!certInfo || certInfo->Tag() != 0x10 || certInfo->Type() != 0 || !certInfo->IsConstructed() ||
        certInfo->Children()->size() < 6)
    {
        Clear();
        return false;
    }
    m_signablePart = certInfo->OuterData();
    //
    // Version information
    //
    node1 = certInfo->Children()->at(0);
    if (node1->Tag() != 0 || node1->Type() != 2 || !node1->IsConstructed() || node1->Children()->size() != 1)
    {
		m_version = ICertificateIssuer::X509_v2;
    }
	else
	{
    node2 = node1->Children()->at(0);
		if (node2->Tag() != TlvNode::Tlv_Number || node2->Type() != 0 || node2->IsConstructed())
    {
        Clear();
        return false;
    }
    m_version = (ICertificateIssuer::CertificateVersion)node2->InnerDataAsNumber();
		tbsOffset++;
	}
    //
    // Serial number
    //
    node1 = certInfo->Children()->at(tbsOffset++);
    if (node1->Tag() != TlvNode::Tlv_Number || node1->Type() != 0 || node1->IsConstructed())
    {
        Clear();
        return false;
    }
    m_encodedSerialNumber = node1->OuterData();
    m_serialNumber = node1->InnerData();
    if (m_serialNumber.size() > 0 && m_serialNumber[0] == 0)
        m_serialNumber.erase(0, 1);

    //
    // Signature Algorithm
    //
    node1 = certInfo->Children()->at(tbsOffset++);
    if (node1->Tag() != 0x10 || node1->Type() != 0 || !node1->IsConstructed() || node1->Children()->size() < 1)
    {
        Clear();
        return false;
    }
    m_algorithmBlob = node1;
    node3 = node1->Children()->at(0);
    if (node3->Tag() != TlvNode::Tlv_OID || node3->Type() != 0 || node3->IsConstructed())
    {
        Clear();
        return false;
    }
    m_algorithmOID = node3->InnerData();
    if (node1->Children()->size() == 2)
    {
        node3 = node1->Children()->at(1);
        m_algorithmParameters = node3;
    }

    //
    // Issuer
    //
    node1 = certInfo->Children()->at(tbsOffset++);
    m_issuer = node1; // TODO:  Implement error checked here
    if (node1->Tag() != 0x10 || node1->Type() != 0 || !node1->IsConstructed())
    {
        Clear();
        return false;
    }

    //
    // Validity
    //
    node1 = certInfo->Children()->at(tbsOffset++);
    if (node1->Tag() != 0x10 || node1->Type() != 0 || !node1->IsConstructed() || node1->Children()->size() != 2)
    {
        Clear();
        return false;
    }
    node2 = node1->Children()->at(0);
    if (node2->Tag() == TlvNode::Tlv_GeneralizedTime && node2->Type() == 0)
    {
        m_start = node2->InnerData().ToUtf8String();
    }
    else if (node2->Tag() == TlvNode::Tlv_UTCTime && node2->Type() == 0)
    {
        m_start = node2->InnerData().ToUtf8String();
        if (m_start.size() > 0 && m_start[0] >= '5')
            m_start.prepend("19");
        else
            m_start.prepend("20");
    }
    else
    {
        Clear();
        return false;
    }
    node2 = node1->Children()->at(1);
    if (node2->Tag() == TlvNode::Tlv_GeneralizedTime && node2->Type() == 0)
    {
        m_end = node2->InnerData().ToUtf8String();
    }
    else if (node2->Tag() == TlvNode::Tlv_UTCTime && node2->Type() == 0)
    {
        m_end = node2->InnerData().ToUtf8String();
        if (m_end.size() > 0 && m_end[0] >= '5')
            m_end.prepend("19");
        else
            m_end.prepend("20");
    }
    else
    {
        Clear();
        return false;
    }
    //
    // Subject
    //
    node1 = certInfo->Children()->at(tbsOffset++);
    m_subject = node1; // TODO:  Implement error checked here
    if (node1->Tag() != 0x10 || node1->Type() != 0 || !node1->IsConstructed())
    {
        Clear();
        return false;
    }

    //
    // Public key information
    //
    node1 = certInfo->Children()->at(tbsOffset++);
    if (node1->Tag() != 0x10 || node1->Type() != 0 || !node1->IsConstructed() || node1->Children()->size() != 2)
    {
        Clear();
        return false;
    }
    node2 = node1->Children()->at(0);
    if (node2->Tag() != 0x10 || node2->Type() != 0 || !node2->IsConstructed() || node2->Children()->size() < 1 ||
        node2->Children()->size() > 2)
    {
        Clear();
        return false;
    }
    m_pubKeyAlgorithmBlob = node2->OuterData();
    node3 = node2->Children()->at(0);
    if (node3->Tag() != TlvNode::Tlv_OID || node3->Type() != 0 || node3->IsConstructed())
    {
        Clear();
        return false;
    }
    m_pubKeyAlgorithm = node3->InnerData();
    if (node2->Children()->size() == 2)
    {
        node3 = node2->Children()->at(1);
        m_pubKeyAlgorithmParameters = node3;
    }


    node2 = node1->Children()->at(1);
    if (node2->Tag() != TlvNode::Tlv_BitString || node2->Type() != 0 || node2->IsConstructed())
    {
        Clear();
        return false;
    }
    m_publicKey = node2->InnerData();
    if (m_pubKeyAlgorithm.size() == sizeof(gRsaAlgorithm) && memcmp(m_pubKeyAlgorithm.c_str(), gRsaAlgorithm, sizeof(gRsaAlgorithm)) == 0)
    {
        //
        // We are using RSA keys, so parse out the modulus and exponent
        //
		std::shared_ptr<TlvDocument> doc2 = TlvDocument::Create();

        if (m_publicKey.size() > 0)
            m_publicKey.erase(0, 1);

        if (!doc2->LoadTlv(m_publicKey))
        {
            Clear();
            return false;
        }
        node2 = doc2->DocumentElement();
        if (node2->Tag() != 0x10 || node2->Type() != 0 || !node2->IsConstructed() || node2->Children()->size() != 2)
        {
            Clear();
            return false;
        }
        node3 = node2->Children()->at(0); // Modulus
        if (node3->Tag() != TlvNode::Tlv_Number || node3->Type() != 0)
        {
            Clear();
            return false;
        }
        m_modulus = node3->InnerData();
        if (m_modulus.size() > 3 && m_modulus[0] == 0 && (m_modulus[1] & 0x80) != 0)
            m_modulus.erase(0, 1);
        node3 = node2->Children()->at(1); // Exponent
        if (node3->Tag() != TlvNode::Tlv_Number || node3->Type() != 0)
        {
            Clear();
            return false;
        }
        m_exponent = node3->InnerData();
        if (m_exponent.size() > 3 && m_exponent[0] == 0 && (m_exponent[1] & 0x80) != 0)
            m_exponent.erase(0, 1);
    }

    if (m_version == ICertificateIssuer::X509_v1 && certInfo->Children()->size() > 7)
    {
        // Version 1 certs cannot have any of the extensions
        Clear();
        return false;
    }

    for (size_t i = tbsOffset; i < certInfo->Children()->size(); i++)
    {
        node1 = certInfo->Children()->at(i);

        if (!node1 || node1->Type() != 2)
        {
            Clear();
            return false;
        }
        switch (node1->Tag())
        {
        case 1:	// Issuer Unique ID
            m_issuerUniqueNumber = node1;
            break;
        case 2:	// Subject Unique ID
            m_subjectUniqueNumber = node1;
            break;
        case 3:	// Extension list
            if (m_version < ICertificateIssuer::X509_v3)
            {
                Clear();
                return false;
            }
            if (!node1->IsConstructed() || node1->Children()->size() != 1)
            {
                Clear();
                return false;
            }
            node2 = node1->Children()->at(0);
            if (!node2 || node2->Tag() != TlvNode::Tlv_Sequence || node2->Type() != TlvNode::Type_Universal ||
                !node2->IsConstructed() || node2->Children()->size() < 1)
            {
                Clear();
                return false;
            }
            else
            {
                size_t extCount = node2->Children()->size();

				for (size_t j = 0; j < extCount; j++)
                {
                    tsCertificateExtension ext;

                    if (!ext.LoadExtension(node2->ChildAt(j)))
                    {
                        Clear();
                        return false;
                    }
                    m_extensionList->push_back(ext);
                }
            }

            break;
        default:
            Clear();
            return false;
        }
    }


    node1 = m_doc->DocumentElement()->Children()->at(1);
    if (node1->Tag() != 0x10 || node1->Type() != 0 || !node1->IsConstructed() || node1->Children()->size() < 1)
    {
        Clear();
        return false;
    }
    m_signatureAlgorithmBlob = node1;
    node3 = node1->Children()->at(0);
    if (node3->Tag() != TlvNode::Tlv_OID || node3->Type() != 0 || node3->IsConstructed())
    {
        Clear();
        return false;
    }
    m_signatureAlgorithmOID = node3->InnerData();
    if (node1->Children()->size() == 2)
    {
        node3 = node1->Children()->at(1);
        m_signatureAlgorithmParameters = node3;
    }

    node1 = m_doc->DocumentElement()->Children()->at(2);
    if (node1->Tag() != TlvNode::Tlv_BitString || node1->Type() != 0 || node1->IsConstructed())
    {
        Clear();
        return false;
    }
    m_certificateSignature = node1->InnerData();
    m_originalData = certData;
    return true;
}

void tsCertificateParser::Clear()
{
    m_originalData.clear();
    m_version = ICertificateIssuer::X509_v1;
    m_serialNumber.erase();
    m_encodedSerialNumber.erase();
    m_algorithmBlob.reset();
    m_algorithmOID.erase();
    m_algorithmParameters.reset();
    m_issuer.reset();
    m_start.erase();
    m_end.erase();
    m_subject.reset();
    m_modulus.erase();
    m_exponent.erase();
    m_pubKeyAlgorithmBlob.erase();
    m_pubKeyAlgorithm.erase();
    m_pubKeyAlgorithmParameters.reset();
    m_publicKey.erase();
    m_issuerUniqueNumber.reset();
    m_subjectUniqueNumber.reset();
    m_extensionList->clear();
    m_signatureAlgorithmBlob.reset();
    m_signatureAlgorithmOID.erase();
    m_signatureAlgorithmParameters.reset();
    m_certificateSignature.erase();

    m_doc->Clear();
}

ICertificateIssuer::CertificateVersion tsCertificateParser::Version() const
{
    return m_version;
}

const tsCryptoData &tsCertificateParser::EncodedSerialNumber() const
{
    return m_encodedSerialNumber;
}

const tsCryptoData &tsCertificateParser::SerialNumber() const
{
    return m_serialNumber;
}

const std::shared_ptr<TlvNode> tsCertificateParser::AlgorithmBlob() const
{
    return m_algorithmBlob;
}

const tsCryptoData &tsCertificateParser::AlgorithmOID() const
{
    return m_algorithmOID;
}

const std::shared_ptr<TlvNode> tsCertificateParser::AlgorithmParameters() const
{
    return m_algorithmParameters;
}

const std::shared_ptr<TlvNode> tsCertificateParser::Issuer() const
{
    return m_issuer;
}

const tsCryptoString &tsCertificateParser::IssuanceDate() const
{
    return m_start;
}

const tsCryptoString &tsCertificateParser::ExpirationDate() const
{
    return m_end;
}

const std::shared_ptr<TlvNode> tsCertificateParser::Subject() const
{
    return m_subject;
}

const tsCryptoData &tsCertificateParser::PublicKeyAlgorithmBlob() const
{
    return m_pubKeyAlgorithmBlob;
}

const tsCryptoData &tsCertificateParser::PublicKeyAlgorithm() const
{
    return m_pubKeyAlgorithm;
}

const std::shared_ptr<TlvNode> tsCertificateParser::PublicKeyAlgorithmParameters() const
{
    return m_pubKeyAlgorithmParameters;
}

const tsCryptoData &tsCertificateParser::PublicKey() const
{
    return m_publicKey;
}

const tsCryptoData &tsCertificateParser::Modulus() const
{
    return m_modulus;
}

const tsCryptoData &tsCertificateParser::Exponent() const
{
    return m_exponent;
}

const std::shared_ptr<TlvNode> tsCertificateParser::IssuerUniqueNumber() const
{
    return m_issuerUniqueNumber;
}

const std::shared_ptr<TlvNode> tsCertificateParser::SubjectUniqueNumber() const
{
    return m_subjectUniqueNumber;
}

size_t tsCertificateParser::ExtensionCount() const
{
    return m_extensionList->size();
}

const tsCertificateExtension *tsCertificateParser::Extension(size_t index) const
{
    if (index >= ExtensionCount())
        return nullptr;
    return &m_extensionList->at(index);
}

const tsCryptoData tsCertificateParser::SubjectKeyIdentifier() const
{
    auto it = std::find_if(m_extensionList->begin(), m_extensionList->end(), [](const tsCertificateExtension& ext) ->bool { return ext.oidString() == "2.5.29.14"; });
    if (it == m_extensionList->end())
        return tsCryptoData();
    return it->Value();
}

const tsCryptoData tsCertificateParser::SubjectKeyIdentifierValue() const
{
	auto it = std::find_if(m_extensionList->begin(), m_extensionList->end(), [](const tsCertificateExtension& ext) ->bool { return ext.oidString() == "2.5.29.14"; });
	if (it == m_extensionList->end())
		return tsCryptoData();

	std::shared_ptr<TlvDocument> doc = TlvDocument::Create();

	if (!doc->LoadTlv(it->Value()))
		return tsCryptoData();

	return doc->DocumentElement()->InnerData();
}
const tsCryptoData tsCertificateParser::IssuerKeyIdentifier() const
{
	auto it = std::find_if(m_extensionList->begin(), m_extensionList->end(), [](const tsCertificateExtension& ext) ->bool { return ext.oidString() == "2.5.29.35"; });
    if (it == m_extensionList->end())
        return tsCryptoData();
    return it->Value();
}

const std::shared_ptr<TlvNode> tsCertificateParser::SignatureAlgorithmBlob() const
{
    return m_signatureAlgorithmBlob;
}

const tsCryptoData &tsCertificateParser::SignatureAlgorithmOID() const
{
    return m_signatureAlgorithmOID;
}

const std::shared_ptr<TlvNode> tsCertificateParser::SignatureAlgorithmParameters() const
{
    return m_signatureAlgorithmParameters;
}

const tsCryptoData &tsCertificateParser::CertificateSignature() const
{
    return m_certificateSignature;
}

tsCryptoData tsCertificateParser::asRawData() const
{
    return m_originalData;
}

tsCryptoString tsCertificateParser::asBase64() const
{
    return m_originalData.ToBase64();
}

tsCryptoString tsCertificateParser::SubjectName() const
{
	const std::shared_ptr<TlvNode> parent = Subject();
	tsDistinguishedName dn;

    if (parent != nullptr)
    {
        for (size_t i = 0; i < parent->ChildCount(); i++)
        {
			const std::shared_ptr<TlvNode> child = parent->ChildAt(i);

            if (child->Tag() == TlvNode::Tlv_Set && child->Type() == TlvNode::Type_Universal && child->ChildCount() == 1)
            {
				const std::shared_ptr<TlvNode> subchild = child->ChildAt(0);
                if (subchild->Tag() == TlvNode::Tlv_Sequence && subchild->Type() == TlvNode::Type_Universal && subchild->ChildCount() > 1)
                {
                    tsCryptoString oid = subchild->ChildAt(0)->InnerData().ToOIDString();

					dn.AddPartByOID(oid.c_str(), subchild->ChildAt(1)->InnerString().c_str());
                }
            }
        }
    }

	return dn.ToString();
}

tsCryptoString tsCertificateParser::IssuerName() const
{
	const std::shared_ptr<TlvNode> parent = Issuer();
	tsDistinguishedName dn;

    if (parent != nullptr)
    {
        for (size_t i = 0; i < parent->ChildCount(); i++)
        {
			const std::shared_ptr<TlvNode> child = parent->ChildAt(i);

            if (child->Tag() == TlvNode::Tlv_Set && child->Type() == TlvNode::Type_Universal && child->ChildCount() == 1)
            {
				const std::shared_ptr<TlvNode> subchild = child->ChildAt(0);
                if (subchild->Tag() == TlvNode::Tlv_Sequence && subchild->Type() == TlvNode::Type_Universal && subchild->ChildCount() > 1)
                {
                    tsCryptoString oid = subchild->ChildAt(0)->InnerData().ToOIDString();

					dn.AddPartByOID(oid.c_str(), subchild->ChildAt(1)->InnerString().c_str());

                }
            }
        }
    }
    return dn.ToString();
}

std::shared_ptr<AsymmetricKey> tsCertificateParser::getPublicKeyObject() const
{
	tsCryptoString oid = m_pubKeyAlgorithm.ToOIDString();

	if (oid == EC_PUBLIC_KEY_OID)
	{
		std::shared_ptr<EccKey> ecc = std::dynamic_pointer_cast<EccKey>(CryptoFactory(PublicKeyAlgorithmParameters()->InnerData().ToOIDString()));

		if (!ecc)
			return nullptr;
		ecc->set_Point(PublicKey().substring(1, PublicKey().size() - 1));
		return ecc;
	}
	if (oid == RSA_ENCRYPT_OID)
	{
		std::shared_ptr<RsaKey> rsa = std::dynamic_pointer_cast<RsaKey>(CryptoFactory("KEY-RSA"));

		if (!rsa)
			return nullptr;
		rsa->set_Exponent(Exponent());
		rsa->set_PublicModulus(Modulus());
		return rsa;
	}
	if (oid == DHPUBLICNUMBER_OID)
	{
		std::shared_ptr<DhParameters> params;
		std::shared_ptr<DhKey> key;
		tsCryptoData pubKey;
		std::shared_ptr<TlvDocument> doc = TlvDocument::Create();

		if (!m_pubKeyAlgorithmParameters || !m_pubKeyAlgorithmParameters->IsConstructed() || m_pubKeyAlgorithmParameters->ChildCount() < 3 || !TSBuildDhParams(params) || !TSBuildDhKey(key))
			return nullptr;
		if (!doc->LoadTlv(PublicKey().substring(1, PublicKey().size() - 1)) || doc->DocumentElement()->Tag() != TlvNode::Tlv_Number)
			return nullptr;
		pubKey = UnpackNumber(doc->DocumentElement()->InnerData());

		if (!params->set_prime(UnpackNumber(m_pubKeyAlgorithmParameters->ChildAt(0)->InnerData())) ||
			!params->set_subprime(UnpackNumber(m_pubKeyAlgorithmParameters->ChildAt(2)->InnerData())) ||
			!params->set_generator(UnpackNumber(m_pubKeyAlgorithmParameters->ChildAt(1)->InnerData())) ||
			!key->set_DomainParameters(params) || !key->set_PublicKey(pubKey))
		{
			return nullptr;
		}
		return key;
	}
	if (oid == DSA_PARAMETER_SET)
	{
		std::shared_ptr<DhParameters> params;
		std::shared_ptr<DhKey> key;
		tsCryptoData pubKey;
		std::shared_ptr<TlvDocument> doc = TlvDocument::Create();

		if (!m_pubKeyAlgorithmParameters || !m_pubKeyAlgorithmParameters->IsConstructed() || m_pubKeyAlgorithmParameters->ChildCount() < 3 || !TSBuildDhParams(params) || !TSBuildDhKey(key))
			return nullptr;
		if (!doc->LoadTlv(PublicKey().substring(1, PublicKey().size() - 1)) || doc->DocumentElement()->Tag() != TlvNode::Tlv_Number)
			return nullptr;
		pubKey = UnpackNumber(doc->DocumentElement()->InnerData());

		if (!params->set_prime(UnpackNumber(m_pubKeyAlgorithmParameters->ChildAt(0)->InnerData())) ||
			!params->set_subprime(UnpackNumber(m_pubKeyAlgorithmParameters->ChildAt(1)->InnerData())) ||
			!params->set_generator(UnpackNumber(m_pubKeyAlgorithmParameters->ChildAt(2)->InnerData())) ||
			!key->set_DomainParameters(params) || !key->set_PublicKey(pubKey))
		{
			return nullptr;
		}
		return key;
	}
	return nullptr;
}

tsCryptoData tsCertificateParser::UnpackNumber(const tsCryptoData& number) const
{
	tsCryptoData tmp(number);

	if (tmp.size() > 1 && tmp[0] == 0 && (tmp[1] & 0x80) != 0)
	{
		tmp.erase(0, 1);
	}
	return tmp;
}
tsCryptoData tsCertificateParser::getExtensionValue(const char* oid) const
{
	auto it = std::find_if(m_extensionList->begin(), m_extensionList->end(), [oid](const tsCertificateExtension& ext) { return ext.oidString() == oid; });
	if (it == m_extensionList->end())
		return tsCryptoData();
	return it->Value();
}

CA_Certificate_Request::KeyUsageFlags tsCertificateParser::GetKeyUsage() const
{
	tsCryptoData usage = getExtensionValue(CERT_KEY_USAGE_OID);
	CA_Certificate_Request::KeyUsageFlags tmp = (CA_Certificate_Request::KeyUsageFlags)0;

	usage.erase(0, 3);

	if (usage.size() == 1)
		tmp = (CA_Certificate_Request::KeyUsageFlags)usage[0];
	else if (usage.size() > 1)
	{
		tmp = (CA_Certificate_Request::KeyUsageFlags)(usage[0] | (256 * usage[1]));
	}
	return tmp;
}
tscrypto::tsCryptoDate tsCertificateParser::ValidFrom() const
{
    return tsCryptoDate(m_start, tsCryptoDate::Zulu);
}
tscrypto::tsCryptoDate tsCertificateParser::ValidTo() const
{
    return tsCryptoDate(m_end, tsCryptoDate::Zulu);
}
std::shared_ptr<tscrypto::AsymmetricKey> tsCertificateParser::PublicKeyObject(bool forSigning) const
{
    tsCryptoString oid = m_pubKeyAlgorithm.ToOIDString();
    tsCryptoString paramOid;
    std::shared_ptr<tscrypto::AsymmetricKey> key;

    if (m_pubKeyAlgorithmParameters->Tag() == TlvNode::Tlv_OID)
        paramOid = m_pubKeyAlgorithmParameters->InnerData().ToOIDString();

    if (oid == RSA_ENCRYPT_OID)
    {
        std::shared_ptr<tscrypto::RsaKey> rsa = std::dynamic_pointer_cast<tscrypto::RsaKey>(CryptoFactory("KEY-RSA"));
        _POD_RsaPublicKeyPart keyPart;

        if (!keyPart.Decode(m_publicKey))
            return nullptr;

        if (!rsa->set_Exponent(keyPart.get_exponent()) || !rsa->set_PublicModulus(keyPart.get_n()))
            return nullptr;
        key = rsa;
    }
    else if (oid == EC_PUBLIC_KEY_OID)
    {
        std::shared_ptr<tscrypto::EccKey> ecc;

        if (paramOid == SECP256R1_CURVE_OID)
        {
            ecc = std::dynamic_pointer_cast<tscrypto::EccKey>(CryptoFactory("KEY-P256"));
        }
        else if (paramOid == SECP384R1_CURVE_OID)
        {
            ecc = std::dynamic_pointer_cast<tscrypto::EccKey>(CryptoFactory("KEY-P384"));
        }
        else if (paramOid == SECP521R1_CURVE_OID)
        {
            ecc = std::dynamic_pointer_cast<tscrypto::EccKey>(CryptoFactory("KEY-P521"));
        }
        else if (paramOid == SECP256K1_CURVE_OID)
        {
            ecc = std::dynamic_pointer_cast<tscrypto::EccKey>(CryptoFactory("KEY-P256K1"));
        }
        else if (paramOid == CURVE_25519_OID)
        {
            if (forSigning)
            {
                ecc = std::dynamic_pointer_cast<tscrypto::EccKey>(CryptoFactory("ED25519"));
            }
            else
            {
                ecc = std::dynamic_pointer_cast<tscrypto::EccKey>(CryptoFactory("X25519"));
            }
        }
        else if (paramOid == TECSEC_NUMSP256D1)
        {
            ecc = std::dynamic_pointer_cast<tscrypto::EccKey>(CryptoFactory("numsp256d1"));
        }
        else if (paramOid == TECSEC_NUMSP256T1)
        {
            ecc = std::dynamic_pointer_cast<tscrypto::EccKey>(CryptoFactory("numsp256t1"));
        }
        else if (paramOid == TECSEC_NUMSP384D1)
        {
            ecc = std::dynamic_pointer_cast<tscrypto::EccKey>(CryptoFactory("numsp384d1"));
        }
        else if (paramOid == TECSEC_NUMSP384T1)
        {
            ecc = std::dynamic_pointer_cast<tscrypto::EccKey>(CryptoFactory("numsp384t1"));
        }
        else if (paramOid == TECSEC_NUMSP512D1)
        {
            ecc = std::dynamic_pointer_cast<tscrypto::EccKey>(CryptoFactory("numsp512d1"));
        }
        else if (paramOid == TECSEC_NUMSP512T1)
        {
            ecc = std::dynamic_pointer_cast<tscrypto::EccKey>(CryptoFactory("numsp512t1"));
        }
        else
        {
            return nullptr;
        }
        if (!ecc || !ecc->set_Point(m_publicKey))
            return nullptr;
        key = ecc;
    }
    else if (oid == DHPUBLICNUMBER_OID)
    {
        std::shared_ptr<DhParameters> dhParams = std::dynamic_pointer_cast<DhParameters>(CryptoFactory("PARAMETERSET-DH"));
        std::shared_ptr<tscrypto::DhKey> dh;
        _POD_DhParameter_gMiddle params;

        if (forSigning)
        {
            dh = std::dynamic_pointer_cast<tscrypto::DhKey>(CryptoFactory("KEY-DSA"));
        }
        else
        {
            dh = std::dynamic_pointer_cast<tscrypto::DhKey>(CryptoFactory("KEY-DH"));
        }
        if (!dh || !dhParams)
            return nullptr;

        if (!params.Decode(m_pubKeyAlgorithmParameters->OuterData()))
        {
            return nullptr;
        }
        if (!dhParams->set_prime(params.get_p()) || !dhParams->set_subprime(params.get_q()) || !dhParams->set_generator(params.get_g()))
            return nullptr;
        if (!dh->set_DomainParameters(dhParams) || !dh->set_PublicKey(m_publicKey))
            return nullptr;
        key = dh;
    }
    else if (oid == DSA_PARAMETER_SET)
    {
        std::shared_ptr<DhParameters> dhParams = std::dynamic_pointer_cast<DhParameters>(CryptoFactory("PARAMETERSET-DH"));
        std::shared_ptr<tscrypto::DhKey> dh = std::dynamic_pointer_cast<tscrypto::DhKey>(CryptoFactory("KEY-DH"));
        _POD_DhParameterSet params;

        if (!params.Decode(m_pubKeyAlgorithmParameters->OuterData()))
        {
            return nullptr;
        }
        if (!dhParams->set_prime(params.get_p()) || !dhParams->set_subprime(params.get_q()) || !dhParams->set_generator(params.get_g()))
            return nullptr;
        if (!dh->set_DomainParameters(dhParams) || !dh->set_PublicKey(m_publicKey))
            return nullptr;
        key = dh;
    }
    else
    {
        return nullptr;
    }

    return key;
}

bool tsCertificateParser::VerifySignature(std::shared_ptr<tscrypto::AsymmetricKey> parentCertKey) const
{
    std::shared_ptr<RsaKey> rsakey;
    std::shared_ptr<EccKey> ecckey;
    std::shared_ptr<DhKey> dhkey;
    std::shared_ptr<Signer> signer;
    tsCryptoString signerName;
    SSL_HashAlgorithm hashAlg;
    SSL_SignatureAlgorithm sigAlg;

    rsakey = std::dynamic_pointer_cast<RsaKey>(parentCertKey);
    ecckey = std::dynamic_pointer_cast<EccKey>(parentCertKey);
    dhkey = std::dynamic_pointer_cast<DhKey>(parentCertKey);

    if (!GetCertificateSignatureInfo(m_signatureAlgorithmOID, hashAlg, sigAlg))
        return false;

    if (!!ecckey)
    {
        if (sigAlg != sslsign_ecdsa)
            return false;

        switch (hashAlg)
        {
        case sslhash_sha1:
            signerName = "SIGN-ECC-SHA1";
            break;
        case sslhash_sha224:
            signerName = "SIGN-ECC-SHA224";
            break;
        case sslhash_sha256:
            signerName = "SIGN-ECC-SHA256";
            break;
        case sslhash_sha384:
            signerName = "SIGN-ECC-SHA384";
            break;
        case sslhash_sha512:
            signerName = "SIGN-ECC-SHA512";
            break;
        default:
            return false;
        }
    }
    else if (!!rsakey)
    {
        if (sigAlg != sslsign_rsa)
            return false;

        switch (hashAlg)
        {
        case sslhash_sha1:
            signerName = "SIGN-RSA-PKCS-SHA1";
            break;
        case sslhash_sha224:
            signerName = "SIGN-RSA-PKCS-SHA224";
            break;
        case sslhash_sha256:
            signerName = "SIGN-RSA-PKCS-SHA256";
            break;
        case sslhash_sha384:
            signerName = "SIGN-RSA-PKCS-SHA384";
            break;
        case sslhash_sha512:
            signerName = "SIGN-RSA-PKCS-SHA512";
            break;
        default:
            return false;
        }
    }
    else if (!!dhkey)
    {
        if (sigAlg != sslsign_dsa)
            return false;

        switch (hashAlg)
        {
        case sslhash_sha1:
            signerName = "SIGN-DSA-SHA1";
            break;
        case sslhash_sha224:
            signerName = "SIGN-DSA-SHA224";
            break;
        case sslhash_sha256:
            signerName = "SIGN-DSA-SHA256";
            break;
        case sslhash_sha384:
            signerName = "SIGN-DSA-SHA384";
            break;
        case sslhash_sha512:
            signerName = "SIGN-DSA-SHA512";
            break;
        default:
            return false;
        }
    }
    else
        return false;

    signer = std::dynamic_pointer_cast<Signer>(CryptoFactory(signerName));

    if (!signer || !signer->initialize(parentCertKey) || !signer->update(m_signablePart) || !signer->verify(m_certificateSignature))
        return false;
    return true;
}

bool tsCertificateParser::IsCACert() const
{
    bool isCA;
    int max;

    return getBasicConstraintInfo(isCA, max) && isCA;
}

bool tsCertificateParser::getBasicConstraintInfo(bool& isCA, int32_t& maxNumberIntermediaries) const
{
    tsCryptoData extData = getExtensionValue(CERT_BASIC_CONSTRAINTS_OID);

    isCA = false;
    maxNumberIntermediaries = 0;

    if (extData.empty())
        return false;

    PKIX::Cert::_POD_BasicConstraints data;

    if (!data.Decode(extData))
        return false;
    isCA = data.get_cA();
    if (data.exists_pathLenConstraint())
        maxNumberIntermediaries = data.get_pathLenConstraint();
    else
        maxNumberIntermediaries = 1000000;
    return true;
}