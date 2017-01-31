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

typedef struct
{
	const char *oid;
	const char *name;
} ExtNameRefList;

static const ExtNameRefList gNameList[] =
{
	{("1.3.6.1.4.1.311.20.2.1"),			("Certificate request agent")},

	{("1.3.6.1.4.1.311.10.3.1"),			("Microsoft trust list signing")},
	{("1.3.6.1.4.1.311.10.3.2"),			("Microsoft time stamping")},
	{("1.3.6.1.4.1.311.10.3.3"),			("Microsoft Server Gated Crypto (SGC)")},
	{("1.3.6.1.4.1.311.10.3.4"),			("Encrypting file system")},
	{("1.3.6.1.4.1.311.10.3.4.1"),		("File recovery")},
	{("1.3.6.1.4.1.311.10.3.5"),			("Windows hardware driver verification")},
	{("1.3.6.1.4.1.311.10.3.6"),			("Windows system component verification")},
	{("1.3.6.1.4.1.311.10.3.7"),			("OEM Windows system component verification")},
	{("1.3.6.1.4.1.311.10.3.8"),			("Embedded Windows system component verification")},
	{("1.3.6.1.4.1.311.10.3.9"),			("Root list signer")},
	{("1.3.6.1.4.1.311.10.3.10"),		("Qualified subordination")},
	{("1.3.6.1.4.1.311.10.3.11"),		("Key recovery")},
	{("1.3.6.1.4.1.311.10.3.12"),		("Document signing")},
	{("1.3.6.1.4.1.311.10.3.13"),		("Lifetime signing")},

	{("1.3.6.1.4.1.311.10.5.1"),			("Digital rights")},

	{("1.3.6.1.4.1.311.10.6.1"),			("Key pack licenses")},
	{("1.3.6.1.4.1.311.10.6.2"),			("License server verification")},

	{("1.3.6.1.4.1.311.20.2.2"),			("Smart card logon")},

	{("1.3.6.1.4.1.311.21.5"),			("Private key archival")},
	{("1.3.6.1.4.1.311.21.6"),			("Key recovery agent")},
	{("1.3.6.1.4.1.311.21.8.8123737.14982925.1133499.4404598.13301292.106.1.400"), ("Low assurance")},
	{("1.3.6.1.4.1.311.21.8.8123737.14982925.1133499.4404598.13301292.106.1.401"), ("Medium assurance")},
	{("1.3.6.1.4.1.311.21.8.8123737.14982925.1133499.4404598.13301292.106.1.402"), ("High assurance")},
	{("1.3.6.1.4.1.311.21.19"),			("Directory service email replication")},


	{("1.3.6.1.5.5.7.1.1"),				("Authority information access")},
	{("1.3.6.1.5.5.7.1.11"),				("Subject information access")},
	{("1.3.6.1.5.5.7.1.13"),				("wlan SSID")},

	{("1.3.6.1.5.5.7.3.1"),				("Server authentication")},
	{("1.3.6.1.5.5.7.3.2"),				("Client authentication")},
	{("1.3.6.1.5.5.7.3.3"),				("Code signing")},
	{("1.3.6.1.5.5.7.3.4"),				("Secure email")},
	{("1.3.6.1.5.5.7.3.5"),				("IP security end system")},
	{("1.3.6.1.5.5.7.3.6"),				("IP security tunnel termination")},
	{("1.3.6.1.5.5.7.3.7"),				("IP security user")},
	{("1.3.6.1.5.5.7.3.8"),				("Time stamping")},
	{("1.3.6.1.5.5.7.3.9"),				("OCSP sisgning")},
	{("1.3.6.1.5.5.7.3.13"),				("eap over PPP")},
	{("1.3.6.1.5.5.7.3.14"),				("eap over LAN")},

	{("1.3.6.1.5.5.7.10.7"),				("wlan SSID list")},

	{("1.3.6.1.5.5.7.48.4"),				("OCSP Nocheck")},

	{("1.3.6.1.5.5.8.2.2"),				("IP security IKE intermediate")},

	{("2.5.29.1"),						("old Authority key identifier")},
	{("2.5.29.2"),						("old Primary key attributes")},
	{("2.5.29.3"),						("Certificate policies")},
	{("2.5.29.4"),						("Primary key usage restriction")},
	{("2.5.29.9"),						("Subject directory attributes")},
	{("2.5.29.14"), 						("Subject key identifier")},
	{("2.5.29.15"),						("X.509 key usage")},
	{("2.5.29.16"),						("Private key usage period")},
	{("2.5.29.17"),						("Subject Alternative Name")},
	{("2.5.29.18"),						("Issuer Alternative Name")},
	{("2.5.29.19"),						("Basic Constraints")},		// Value of TRUE can indicate CA certificate
	{("2.5.29.20"),						("CRL Number")},
	{("2.5.29.21"),						("Reason code")},
	{("2.5.29.23"),						("Hold Instruction Code")},
	{("2.5.29.24"),						("Invalidity Date")},
	{("2.5.29.27"),						("Delta CRL indicator")},
	{("2.5.29.28"),						("Issuing Distribution Point")},
	{("2.5.29.29"),						("Certificate Issuer")},
	{("2.5.29.30"),						("Name Constraints")},
	{("2.5.29.31"),						("CRL Distribution Points")},
	{("2.5.29.32"),						("Certificate policies")},
	{("2.5.29.32.0"),					("All issuance policies")},
	{("2.5.29.33"),						("Policy Mappings")},
	{("2.5.29.35"),						("Authority Key Identifier")},
	{("2.5.29.36"),						("Policy Constraints")},
	{("2.5.29.37"),						("X.509v3 extended key usage")},
	{("2.5.29.46"),						("FreshestCRL")},
	{("2.5.29.54"),						("X.509v3 certificate extension inhibit any-policy")},

	{("2.16.840.1.113730.1.1"),			("Netscape certificate type")},

	{("2.16.840.1.113730.4.1"),			("Netscape SGC")},

};




/*
Microsoft OID...................................1.3.6.1.4.1.311

Authenticode....................................1.3.6.1.4.1.311.2
     Software Publishing (with associated encoders/decoders)
        SPC_INDIRECT_DATA_OBJID                 1.3.6.1.4.1.311.2.1.4
        SPC_STATEMENT_TYPE_OBJID                1.3.6.1.4.1.311.2.1.11
        SPC_SP_OPUS_INFO_OBJID                  1.3.6.1.4.1.311.2.1.12
        SPC_PE_IMAGE_DATA_OBJID                 1.3.6.1.4.1.311.2.1.15
        SPC_SP_AGENCY_INFO_OBJID                1.3.6.1.4.1.311.2.1.10
        SPC_MINIMAL_CRITERIA_OBJID              1.3.6.1.4.1.311.2.1.26
        SPC_FINANCIAL_CRITERIA_OBJID            1.3.6.1.4.1.311.2.1.27
        SPC_LINK_OBJID                          1.3.6.1.4.1.311.2.1.28
        SPC_HASH_INFO_OBJID                     1.3.6.1.4.1.311.2.1.29
        SPC_SIPINFO_OBJID                       1.3.6.1.4.1.311.2.1.30

     Software Publishing (with NO associated encoders/decoders)
        SPC_CERT_EXTENSIONS_OBJID               1.3.6.1.4.1.311.2.1.14
        SPC_RAW_FILE_DATA_OBJID                 1.3.6.1.4.1.311.2.1.18
        SPC_STRUCTURED_STORAGE_DATA_OBJID       1.3.6.1.4.1.311.2.1.19
        SPC_JAVA_CLASS_DATA_OBJID               1.3.6.1.4.1.311.2.1.20
        SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID     1.3.6.1.4.1.311.2.1.21
        SPC_COMMERCIAL_SP_KEY_PURPOSE_OBJID     1.3.6.1.4.1.311.2.1.22
        SPC_CAB_DATA_OBJID                      1.3.6.1.4.1.311.2.1.25
        SPC_GLUE_RDN_OBJID                      1.3.6.1.4.1.311.2.1.25

     CTL for Software Publishers Trusted CAs    1.3.6.1.4.1.311.2.2
     (sub-subtree is defined for Software Publishing trusted CAs)
        szOID_TRUSTED_CODESIGNING_CA_LIST       1.3.6.1.4.1.311.2.2.1
        szOID_TRUSTED_CLIENT_AUTH_CA_LIST       1.3.6.1.4.1.311.2.2.2
        szOID_TRUSTED_SERVER_AUTH_CA_LIST       1.3.6.1.4.1.311.2.2.3

Time Stamping...................................1.3.6.1.4.1.311.3
(with Associated encoder/decoders)
        SPC_TIME_STAMP_REQUEST_OBJID            1.3.6.1.4.1.311.3.2.1

Permissions.....................................1.3.6.1.4.1.311.4

Crypto 2.0......................................1.3.6.1.4.1.311.10
     PKCS #7 ContentType Object Identifier for Certificate Trust List (CTL)
        szOID_CTL                               1.3.6.1.4.1.311.10.1
     Sorted CTL Extension
        szOID_SORTED_CTL                        1.3.6.1.4.1.311.10.1.1

     Next Update Location extension or attribute. Value is an encoded GeneralNames
        szOID_NEXT_UPDATE_LOCATION              1.3.6.1.4.1.311.10.2

     Enhanced Key Usage (Purpose)
        Signer of CTLs
        szOID_KP_CTL_USAGE_SIGNING              1.3.6.1.4.1.311.10.3.1

        Signer of TimeStamps
        szOID_KP_TIME_STAMP_SIGNING             1.3.6.1.4.1.311.10.3.2

     Can use strong encryption in export environment
        szOID_SERVER_GATED_CRYPTO               1.3.6.1.4.1.311.10.3.3
        szOID_SERIALIZED                        1.3.6.1.4.1.311.10.3.3.1

     Can use encrypted file systems (EFS)
        szOID_EFS_CRYPTO                        1.3.6.1.4.1.311.10.3.4
        szOID_EFS_RECOVERY                      1.3.6.1.4.1.311.10.3.4.1

     Can use Windows Hardware Compatible (WHQL)
        szOID_WHQL_CRYPTO                       1.3.6.1.4.1.311.10.3.5

     Signed by the NT5 build lab
        szOID_NT5_CRYPTO                        1.3.6.1.4.1.311.10.3.6

     Signed by and OEM of WHQL
        szOID_OEM_WHQL_CRYPTO                   1.3.6.1.4.1.311.10.3.7

     Signed by the Embedded NT
        szOID_EMBEDDED_NT_CRYPTO                1.3.6.1.4.1.311.10.3.8

     Signer of a CTL containing trusted roots
        szOID_ROOT_LIST_SIGNER                  1.3.6.1.4.1.311.10.3.9

     Can sign cross-cert and subordinate CA requests with qualified
     subordination (name constraints, policy mapping, etc.)
        szOID_KP_QUALIFIED_SUBORDINATION        1.3.6.1.4.1.311.10.3.10

     Can be used to encrypt/recover escrowed keys
        szOID_KP_KEY_RECOVERY                   1.3.6.1.4.1.311.10.3.11

     Signer of documents
        szOID_KP_DOCUMENT_SIGNING               1.3.6.1.4.1.311.10.3.12

     Microsoft Attribute Object Identifiers
        szOID_YESNO_TRUST_ATTR                  1.3.6.1.4.1.311.10.4.1

     Microsoft Music
        szOID_DRM                               1.3.6.1.4.1.311.10.5.1

     Microsoft DRM EKU
        szOID_DRM_INDIVIDUALIZATION             1.3.6.1.4.1.311.10.5.2

     Microsoft Licenses
        szOID_LICENSES                          1.3.6.1.4.1.311.10.6.1
        szOID_LICENSE_SERVER                    1.3.6.1.4.1.311.10.6.2

     Microsoft CERT_RDN attribute Object Identifiers
        szOID_MICROSOFT_RDN_PREFIX              1.3.6.1.4.1.311.10.7
     Special RDN containing the KEY_ID. Its value type is CERT_RDN_OCTET_STRING.
        szOID_KEYID_RDN                         1.3.6.1.4.1.311.10.7.1

     Microsoft extension in a CTL to add or remove the certificates. The
     extension type is an INTEGER. 0 =&amp;gt; add certificate, 1 =&amp;gt; remove certificate
        szOID_REMOVE_CERTIFICATE                1.3.6.1.4.1.311.10.8.1

     Microsoft certificate extension containing cross certificate distribution
     points. ASN.1 encoded as follows:
         CrossCertDistPoints ::= SEQUENCE {
             syncDeltaTime               INTEGER (0..4294967295) OPTIONAL,
             crossCertDistPointNames     CrossCertDistPointNames
         } --#public--
              CrossCertDistPointNames ::= SEQUENCE OF GeneralNames

        szOID_CROSS_CERT_DIST_POINTS            1.3.6.1.4.1.311.10.9.1


     Microsoft CMC OIDs                         1.3.6.1.4.1.311.10.10

     Similar to szOID_CMC_ADD_EXTENSIONS. Attributes replaces Extensions.
        szOID_CMC_ADD_ATTRIBUTES                1.3.6.1.4.1.311.10.10.1

     Microsoft certificate property OIDs        1.3.6.1.4.1.311.10.11
     The OID component following the prefix contains the PROP_ID (decimal)
        szOID_CERT_PROP_ID_PREFIX               1.3.6.1.4.1.311.10.11.

     CryptUI                                    1.3.6.1.4.1.311.10.12
        szOID_ANY_APPLICATION_POLICY            1.3.6.1.4.1.311.10.12.1

Catalog.........................................1.3.6.1.4.1.311.12
        szOID_CATALOG_LIST                      1.3.6.1.4.1.311.12.1.1
        szOID_CATALOG_LIST_MEMBER               1.3.6.1.4.1.311.12.1.2
        CAT_NAMEVALUE_OBJID                     1.3.6.1.4.1.311.12.2.1
        CAT_MEMBERINFO_OBJID                    1.3.6.1.4.1.311.12.2.2

Microsoft PKCS10 OIDs...........................1.3.6.1.4.1.311.13
        szOID_RENEWAL_CERTIFICATE               1.3.6.1.4.1.311.13.1
        szOID_ENROLLMENT_NAME_VALUE_PAIR        1.3.6.1.4.1.311.13.2.1
        szOID_ENROLLMENT_CSP_PROVIDER           1.3.6.1.4.1.311.13.2.2

Microsoft Java..................................1.3.6.1.4.1.311.15

Microsoft Outlook/Exchange......................1.3.6.1.4.1.311.16
          Outlook Express                       1.3.6.1.4.1.311.16.4
          Used by OL/OLEXP to identify which certificate signed the PKCS # 7 message

Microsoft PKCS12 attributes.....................1.3.6.1.4.1.311.17
        szOID_LOCAL_MACHINE_KEYSET              1.3.6.1.4.1.311.17.1

Microsoft Hydra.................................1.3.6.1.4.1.311.18

Microsoft ISPU Test.............................1.3.6.1.4.1.311.19

Microsoft Enrollment Infrastructure..............1.3.6.1.4.1.311.20
        szOID_AUTO_ENROLL_CTL_USAGE             1.3.6.1.4.1.311.20.1
     Extension contain certificate type
        szOID_ENROLL_CERTTYPE_EXTENSION         1.3.6.1.4.1.311.20.2
        szOID_ENROLLMENT_AGENT                  1.3.6.1.4.1.311.20.2.1
        szOID_KP_SMARTCARD_LOGON                1.3.6.1.4.1.311.20.2.2
        szOID_NT_PRINCIPAL_NAME                 1.3.6.1.4.1.311.20.2.3
        szOID_CERT_MANIFOLD                     1.3.6.1.4.1.311.20.3

Microsoft CertSrv Infrastructure.................1.3.6.1.4.1.311.21
     CertSrv (with associated encoders/decoders)
        szOID_CERTSRV_CA_VERSION                1.3.6.1.4.1.311.21.1

Microsoft Directory Service.....................1.3.6.1.4.1.311.25
        szOID_NTDS_REPLICATION                  1.3.6.1.4.1.311.25.1

IIS.............................................1.3.6.1.4.1.311.30

Windows updates and service packs...............1.3.6.1.4.1.311.31
        szOID_PRODUCT_UPDATE                    1.3.6.1.4.1.311.31.1

Fonts...........................................1.3.6.1.4.1.311.40

Microsoft Licensing and Registration............1.3.6.1.4.1.311.41

Microsoft Corporate PKI (ITG)...................1.3.6.1.4.1.311.42

CAPICOM.........................................1.3.6.1.4.1.311.88
        szOID_CAPICOM                           1.3.6.1.4.1.311.88      Reserved for CAPICOM.
        szOID_CAPICOM_VERSION                   1.3.6.1.4.1.311.88.1    CAPICOM version
        szOID_CAPICOM_ATTRIBUTE                 1.3.6.1.4.1.311.88.2    CAPICOM attribute
        szOID_CAPICOM_DOCUMENT_NAME             1.3.6.1.4.1.311.88.2.1  Document type attribute
        szOID_CAPICOM_DOCUMENT_DESCRIPTION      1.3.6.1.4.1.311.88.2.2  Document description attribute
        szOID_CAPICOM_ENCRYPTED_DATA            1.3.6.1.4.1.311.88.3    CAPICOM encrypted data message.
        szOID_CAPICOM_ENCRYPTED_CONTENT         1.3.6.1.4.1.311.88.3.1  CAPICOM content of encrypted data.
Microsoft OID...................................1.3.6.1.4.1.311

Authenticode....................................1.3.6.1.4.1.311.2
     Software Publishing (with associated encoders/decoders)
        SPC_INDIRECT_DATA_OBJID                 1.3.6.1.4.1.311.2.1.4
        SPC_STATEMENT_TYPE_OBJID                1.3.6.1.4.1.311.2.1.11
        SPC_SP_OPUS_INFO_OBJID                  1.3.6.1.4.1.311.2.1.12
        SPC_PE_IMAGE_DATA_OBJID                 1.3.6.1.4.1.311.2.1.15
        SPC_SP_AGENCY_INFO_OBJID                1.3.6.1.4.1.311.2.1.10
        SPC_MINIMAL_CRITERIA_OBJID              1.3.6.1.4.1.311.2.1.26
        SPC_FINANCIAL_CRITERIA_OBJID            1.3.6.1.4.1.311.2.1.27
        SPC_LINK_OBJID                          1.3.6.1.4.1.311.2.1.28
        SPC_HASH_INFO_OBJID                     1.3.6.1.4.1.311.2.1.29
        SPC_SIPINFO_OBJID                       1.3.6.1.4.1.311.2.1.30

     Software Publishing (with NO associated encoders/decoders)
        SPC_CERT_EXTENSIONS_OBJID               1.3.6.1.4.1.311.2.1.14
        SPC_RAW_FILE_DATA_OBJID                 1.3.6.1.4.1.311.2.1.18
        SPC_STRUCTURED_STORAGE_DATA_OBJID       1.3.6.1.4.1.311.2.1.19
        SPC_JAVA_CLASS_DATA_OBJID               1.3.6.1.4.1.311.2.1.20
        SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID     1.3.6.1.4.1.311.2.1.21
        SPC_COMMERCIAL_SP_KEY_PURPOSE_OBJID     1.3.6.1.4.1.311.2.1.22
        SPC_CAB_DATA_OBJID                      1.3.6.1.4.1.311.2.1.25
        SPC_GLUE_RDN_OBJID                      1.3.6.1.4.1.311.2.1.25

     CTL for Software Publishers Trusted CAs    1.3.6.1.4.1.311.2.2
     (sub-subtree is defined for Software Publishing trusted CAs)
        szOID_TRUSTED_CODESIGNING_CA_LIST       1.3.6.1.4.1.311.2.2.1
        szOID_TRUSTED_CLIENT_AUTH_CA_LIST       1.3.6.1.4.1.311.2.2.2
        szOID_TRUSTED_SERVER_AUTH_CA_LIST       1.3.6.1.4.1.311.2.2.3

Time Stamping...................................1.3.6.1.4.1.311.3
(with Associated encoder/decoders)
        SPC_TIME_STAMP_REQUEST_OBJID            1.3.6.1.4.1.311.3.2.1

Permissions.....................................1.3.6.1.4.1.311.4

Crypto 2.0......................................1.3.6.1.4.1.311.10
     PKCS #7 ContentType Object Identifier for Certificate Trust List (CTL)
        szOID_CTL                               1.3.6.1.4.1.311.10.1
     Sorted CTL Extension
        szOID_SORTED_CTL                        1.3.6.1.4.1.311.10.1.1

     Next Update Location extension or attribute. Value is an encoded GeneralNames
        szOID_NEXT_UPDATE_LOCATION              1.3.6.1.4.1.311.10.2

     Enhanced Key Usage (Purpose)
        Signer of CTLs
        szOID_KP_CTL_USAGE_SIGNING              1.3.6.1.4.1.311.10.3.1

        Signer of TimeStamps
        szOID_KP_TIME_STAMP_SIGNING             1.3.6.1.4.1.311.10.3.2

     Can use strong encryption in export environment
        szOID_SERVER_GATED_CRYPTO               1.3.6.1.4.1.311.10.3.3
        szOID_SERIALIZED                        1.3.6.1.4.1.311.10.3.3.1

     Can use encrypted file systems (EFS)
        szOID_EFS_CRYPTO                        1.3.6.1.4.1.311.10.3.4
        szOID_EFS_RECOVERY                      1.3.6.1.4.1.311.10.3.4.1

     Can use Windows Hardware Compatible (WHQL)
        szOID_WHQL_CRYPTO                       1.3.6.1.4.1.311.10.3.5

     Signed by the NT5 build lab
        szOID_NT5_CRYPTO                        1.3.6.1.4.1.311.10.3.6

     Signed by and OEM of WHQL
        szOID_OEM_WHQL_CRYPTO                   1.3.6.1.4.1.311.10.3.7

     Signed by the Embedded NT
        szOID_EMBEDDED_NT_CRYPTO                1.3.6.1.4.1.311.10.3.8

     Signer of a CTL containing trusted roots
        szOID_ROOT_LIST_SIGNER                  1.3.6.1.4.1.311.10.3.9

     Can sign cross-cert and subordinate CA requests with qualified
     subordination (name constraints, policy mapping, etc.)
        szOID_KP_QUALIFIED_SUBORDINATION        1.3.6.1.4.1.311.10.3.10

     Can be used to encrypt/recover escrowed keys
        szOID_KP_KEY_RECOVERY                   1.3.6.1.4.1.311.10.3.11

     Signer of documents
        szOID_KP_DOCUMENT_SIGNING               1.3.6.1.4.1.311.10.3.12

     Limits the valid lifetime of the signature to the lifetime of the certificate.
        szOID_KP_LIFETIME_SIGNING               1.3.6.1.4.1.311.10.3.13
        szOID_KP_MOBILE_DEVICE_SOFTWARE         1.3.6.1.4.1.311.10.3.14

     Microsoft Attribute Object Identifiers
        szOID_YESNO_TRUST_ATTR                  1.3.6.1.4.1.311.10.4.1

     Microsoft Music
        szOID_DRM                               1.3.6.1.4.1.311.10.5.1

     Microsoft DRM EKU
        szOID_DRM_INDIVIDUALIZATION             1.3.6.1.4.1.311.10.5.2

     Microsoft Licenses
        szOID_LICENSES                          1.3.6.1.4.1.311.10.6.1
        szOID_LICENSE_SERVER                    1.3.6.1.4.1.311.10.6.2

     Microsoft CERT_RDN attribute Object Identifiers
        szOID_MICROSOFT_RDN_PREFIX              1.3.6.1.4.1.311.10.7
     Special RDN containing the KEY_ID. Its value type is CERT_RDN_OCTET_STRING.
        szOID_KEYID_RDN                         1.3.6.1.4.1.311.10.7.1

     Microsoft extension in a CTL to add or remove the certificates. The
     extension type is an INTEGER. 0 => add certificate, 1 => remove certificate
        szOID_REMOVE_CERTIFICATE                1.3.6.1.4.1.311.10.8.1

     Microsoft certificate extension containing cross certificate distribution
     points. ASN.1 encoded as follows:
         CrossCertDistPoints ::= SEQUENCE {
             syncDeltaTime               INTEGER (0..4294967295) OPTIONAL,
             crossCertDistPointNames     CrossCertDistPointNames
         } --#public--
              CrossCertDistPointNames ::= SEQUENCE OF GeneralNames

        szOID_CROSS_CERT_DIST_POINTS            1.3.6.1.4.1.311.10.9.1


     Microsoft CMC OIDs                         1.3.6.1.4.1.311.10.10

     Similar to szOID_CMC_ADD_EXTENSIONS. Attributes replaces Extensions.
        szOID_CMC_ADD_ATTRIBUTES                1.3.6.1.4.1.311.10.10.1

     Microsoft certificate property OIDs        1.3.6.1.4.1.311.10.11
     The OID component following the prefix contains the PROP_ID (decimal)
        szOID_CERT_PROP_ID_PREFIX               1.3.6.1.4.1.311.10.11.

     CryptUI                                    1.3.6.1.4.1.311.10.12
        szOID_ANY_APPLICATION_POLICY            1.3.6.1.4.1.311.10.12.1

Catalog.........................................1.3.6.1.4.1.311.12
        szOID_CATALOG_LIST                      1.3.6.1.4.1.311.12.1.1
        szOID_CATALOG_LIST_MEMBER               1.3.6.1.4.1.311.12.1.2
        CAT_NAMEVALUE_OBJID                     1.3.6.1.4.1.311.12.2.1
        CAT_MEMBERINFO_OBJID                    1.3.6.1.4.1.311.12.2.2

Microsoft PKCS10 OIDs...........................1.3.6.1.4.1.311.13
        szOID_RENEWAL_CERTIFICATE               1.3.6.1.4.1.311.13.1
        szOID_ENROLLMENT_NAME_VALUE_PAIR        1.3.6.1.4.1.311.13.2.1
        szOID_ENROLLMENT_CSP_PROVIDER           1.3.6.1.4.1.311.13.2.2
        szOID_OS_VERSION                        1.3.6.1.4.1.311.13.2.3

Microsoft Java..................................1.3.6.1.4.1.311.15

Microsoft Outlook/Exchange......................1.3.6.1.4.1.311.16
      Used by OL/OLEXP to identify which certificate signed the PKCS # 7 message
        szOID_MICROSOFT_Encryption_Key_Preference  1.3.6.1.4.1.311.16.4

Microsoft PKCS12 attributes.....................1.3.6.1.4.1.311.17
        szOID_LOCAL_MACHINE_KEYSET              1.3.6.1.4.1.311.17.1

Microsoft Hydra.................................1.3.6.1.4.1.311.18
     License Info root
        szOID_PKIX_LICENSE_INFO                 1.3.6.1.4.1.311.18.1

     Manufacturer value
        szOID_PKIX_MANUFACTURER                 1.3.6.1.4.1.311.18.2

     Manufacturer Specfic Data
        szOID_PKIX_MANUFACTURER_MS_SPECIFIC     1.3.6.1.4.1.311.18.3

     OID for Certificate Version Stamp
        szOID_PKIX_HYDRA_CERT_VERSION           1.3.6.1.4.1.311.18.4

     OID for License Server to identify licensed product.
        szOID_PKIX_LICENSED_PRODUCT_INFO        1.3.6.1.4.1.311.18.5

     OID for License Server specific info.
        szOID_PKIX_MS_LICENSE_SERVER_INFO       1.3.6.1.4.1.311.18.6

     Extension OID reserved for product policy module - only one is allowed.
        szOID_PKIS_PRODUCT_SPECIFIC_OID         1.3.6.1.4.1.311.18.7
        szOID_PKIS_TLSERVER_SPK_OID             1.3.6.1.4.1.311.18.8

Microsoft ISPU Test.............................1.3.6.1.4.1.311.19

Microsoft Enrollment Infrastructure.............1.3.6.1.4.1.311.20
        szOID_AUTO_ENROLL_CTL_USAGE             1.3.6.1.4.1.311.20.1
     Extension contain certificate type
        szOID_ENROLL_CERTTYPE_EXTENSION         1.3.6.1.4.1.311.20.2
        szOID_ENROLLMENT_AGENT                  1.3.6.1.4.1.311.20.2.1
        szOID_KP_SMARTCARD_LOGON                1.3.6.1.4.1.311.20.2.2
        szOID_NT_PRINCIPAL_NAME                 1.3.6.1.4.1.311.20.2.3
        szOID_CERT_MANIFOLD                     1.3.6.1.4.1.311.20.3

Microsoft CertSrv Infrastructure................1.3.6.1.4.1.311.21
     CertSrv (with associated encoders/decoders)
        szOID_CERTSRV_CA_VERSION                1.3.6.1.4.1.311.21.1

     Contains the sha1 hash of the previous version of the CA certificate.
        szOID_CERTSRV_PREVIOUS_CERT_HASH        1.3.6.1.4.1.311.21.2

     Delta CRLs only. Contains the base CRL Number of the corresponding base CRL.
        szOID_CRL_VIRTUAL_BASE                  1.3.6.1.4.1.311.21.3

     Contains the time when the next CRL is expected to be published. This may be sooner than the CRL's NextUpdate field.
        szOID_CRL_NEXT_PUBLISH                  1.3.6.1.4.1.311.21.4

     Enhanced Key Usage for CA encryption certificate
        szOID_KP_CA_EXCHANGE                    1.3.6.1.4.1.311.21.5

     Enhanced Key Usage for key recovery agent certificate
        szOID_KP_KEY_RECOVERY_AGENT             1.3.6.1.4.1.311.21.6

     Certificate template extension (v2)
        szOID_CERTIFICATE_TEMPLATE              1.3.6.1.4.1.311.21.7

     The root oid for all enterprise specific oids
        szOID_ENTERPRISE_OID_ROOT               1.3.6.1.4.1.311.21.8

     Dummy signing Subject RDN
        szOID_RDN_DUMMY_SIGNER                  1.3.6.1.4.1.311.21.9

     Application Policies extension -- same encoding as szOID_CERT_POLICIES
        szOID_APPLICATION_CERT_POLICIES         1.3.6.1.4.1.311.21.10

     Application Policy Mappings -- same encoding as szOID_POLICY_MAPPINGS
        szOID_APPLICATION_POLICY_MAPPINGS       1.3.6.1.4.1.311.21.11

     Application Policy Constraints -- same encoding as szOID_POLICY_CONSTRAINTS
        szOID_APPLICATION_POLICY_CONSTRAINTS    1.3.6.1.4.1.311.21.12

        szOID_ARCHIVED_KEY_ATTR                 1.3.6.1.4.1.311.21.13
        szOID_CRL_SELF_CDP                      1.3.6.1.4.1.311.21.14

     Requires all certificates below the root to have a non-empty intersecting issuance certificate policy usage.
        szOID_REQUIRE_CERT_CHAIN_POLICY         1.3.6.1.4.1.311.21.15
        szOID_ARCHIVED_KEY_CERT_HASH            1.3.6.1.4.1.311.21.16
        szOID_ISSUED_CERT_HASH                  1.3.6.1.4.1.311.21.17

     Enhanced key usage for DS email replication
        szOID_DS_EMAIL_REPLICATION              1.3.6.1.4.1.311.21.19

        szOID_REQUEST_CLIENT_INFO               1.3.6.1.4.1.311.21.20
        szOID_ENCRYPTED_KEY_HASH                1.3.6.1.4.1.311.21.21
        szOID_CERTSRV_CROSSCA_VERSION           1.3.6.1.4.1.311.21.22

Microsoft Directory Service.....................1.3.6.1.4.1.311.25
        szOID_NTDS_REPLICATION                  1.3.6.1.4.1.311.25.1

IIS.............................................1.3.6.1.4.1.311.30
        szOID_IIS_VIRTUAL_SERVER                1.3.6.1.4.1.311.30.1

Microsoft WWOps BizExt..........................1.3.6.1.4.1.311.43


Microsoft Peer Networking.......................1.3.6.1.4.1.311.44
     Subtrees for genaral use including pnrp, IM, and grouping
        szOID_PEERNET_GENERAL
        szOID_PEERNET_PNRP                      1.3.6.1.4.1.311.44.1
        szOID_PEERNET_IDENTITY                  1.3.6.1.4.1.311.44.2
        szOID_PEERNET_GROUPING                  1.3.6.1.4.1.311.44.3

     Property that contains the type of the certificate (GMC, GRC, etc.)
        szOID_PEERNET_CERT_TYPE                 1.3.6.1.4.1.311.44.0.1

     Type of the value in the 'other' name: peer name
        szOID_PEERNET_PEERNAME                  1.3.6.1.4.1.311.44.0.2

     Type : classifier
        szOID_PEERNET_CLASSIFIER                1.3.6.1.4.1.311.44.0.3

     Property containing the version of the certificate
        szOID_PEERNET_CERT_VERSION              1.3.6.1.4.1.311.44.0.4

     PNRP specific properties
        szOID_PEERNET_PNRP_ADDRESS              1.3.6.1.4.1.311.44.1.1
        szOID_PEERNET_PNRP_FLAGS                1.3.6.1.4.1.311.44.1.2
        szOID_PEERNET_PNRP_PAYLOAD              1.3.6.1.4.1.311.44.1.3
        szOID_PEERNET_PNRP_ID                   1.3.6.1.4.1.311.44.1.4

     Identity flags, placeholder
        szOID_PEERNET_IDENTITY_FLAGS            1.3.6.1.4.1.311.44.2.2

     Peer name of the group
        szOID_PEERNET_GROUPING_PEERNAME         1.3.6.1.4.1.311.44.3.1

     Group flags: placeholder
        szOID_PEERNET_GROUPING_FLAGS            1.3.6.1.4.1.311.44.3.2

     List of roles in the GMC
        szOID_PEERNET_GROUPING_ROLES            1.3.6.1.4.1.311.44.3.3

     List of classifiers in the GMC
        szOID_PEERNET_GROUPING_CLASSIFIERS      1.3.6.1.4.1.311.44.3.5

Mobile Devices Code Signing.....................1.3.6.1.4.1.311.45

CAPICOM.........................................1.3.6.1.4.1.311.88
     Reserved for CAPICOM.
        szOID_CAPICOM                           1.3.6.1.4.1.311.88

     CAPICOM version
        szOID_CAPICOM_VERSION                   1.3.6.1.4.1.311.88.1

     CAPICOM attribute
        szOID_CAPICOM_ATTRIBUTE                 1.3.6.1.4.1.311.88.2

     Document type attribute
        szOID_CAPICOM_DOCUMENT_NAME             1.3.6.1.4.1.311.88.2.1

     Document description attribute
        szOID_CAPICOM_DOCUMENT_DESCRIPTION      1.3.6.1.4.1.311.88.2.2

     CAPICOM encrypted data message.
        szOID_CAPICOM_ENCRYPTED_DATA            1.3.6.1.4.1.311.88.3

     CAPICOM content of encrypted data.
        szOID_CAPICOM_ENCRYPTED_CONTENT         1.3.6.1.4.1.311.88.3.1*/
tsCertificateExtension::tsCertificateExtension() :
	m_critical(false)
{
}

tsCertificateExtension::tsCertificateExtension(const tsCryptoData &OID, bool critical, const tsCryptoData &value) :
	m_oid(OID),
    m_value(value),
	m_critical(critical)
{
	m_oidString = m_oid.ToOIDString();
	for (int i = 0; i < (int)(sizeof(gNameList) / sizeof(gNameList[0])); i++)
	{
		if ( TsStrCmp(gNameList[i].oid, m_oidString) == 0 )
		{
			m_extName = gNameList[i].name;
			break;
		}
	}
	if ( m_extName.size() == 0 )
		m_extName = m_oidString.c_str();
}

tsCertificateExtension::tsCertificateExtension(const tsCertificateExtension &obj) :
	m_oid(obj.m_oid),
	m_value(obj.m_value),
	m_critical(obj.m_critical),
    m_oidString(obj.m_oidString),
    m_extName(obj.m_extName)
{
}

tsCertificateExtension::~tsCertificateExtension()
{
}

tsCertificateExtension &tsCertificateExtension::operator=(const tsCertificateExtension &obj)
{
	if (this != &obj)
	{
		m_oid = obj.m_oid;
		m_oidString = obj.m_oidString;
		m_extName = obj.m_extName;
		m_value = obj.m_value;
		m_critical = obj.m_critical;
	}
	return *this;
}

//void *tsCertificateExtension::operator new(size_t bytes) 
//{ 
//    return CryptoSupportAllocator(bytes); 
//}
//
//void tsCertificateExtension::operator delete(void *ptr) 
//{ 
//    return CryptoSupportDeallocator(ptr); 
//}

void tsCertificateExtension::Clear()
{
	m_value.erase();
	m_oid.erase();
	m_critical = false;
	m_oidString.erase();
	m_extName.clear();
}

bool tsCertificateExtension::LoadExtension(std::shared_ptr<TlvNode> node)
{
	std::shared_ptr<TlvNode> node1;
	int offset = 0;
//	uint32_t lastProcessed = 0;
	//int value = 0;

	Clear();

	if ( !node || node->Tag() != TlvNode::Tlv_Sequence || node->Type() != TlvNode::Type_Universal ||
		 !node->IsConstructed() || node->Children()->size() < 2 || node->Children()->size() > 3 )
	{
		Clear();
		return false;
	}

	node1 = node->Children()->at(offset++);
	if ( !node1 || node1->Tag() != TlvNode::Tlv_OID || node1->Type() != TlvNode::Type_Universal ||
		 node1->IsConstructed() )
	{
		Clear();
		return false;
	}
	m_oid = node1->InnerData();

	node1 = node->Children()->at(offset++);
	if ( !!node1 && node1->Tag() == TlvNode::Tlv_Boolean && node1->Type() == TlvNode::Type_Universal && !node1->IsConstructed() )
	{
		m_critical = (node1->InnerDataAsNumber() != 0);

		node1 = node->Children()->at(offset++);
	}
	if ( !node1 || node1->Tag() != TlvNode::Tlv_Octet || node1->Type() != TlvNode::Type_Universal ||
		 node1->IsConstructed() )
	{
		Clear();
		return false;
	}
	m_value = node1->InnerData();

	m_oidString = m_oid.ToOIDString();

	for (int i = 0; i < (int)(sizeof(gNameList) / sizeof(gNameList[0])); i++)
	{
		if ( TsStrCmp(gNameList[i].oid, m_oidString) == 0 )
		{
			m_extName = gNameList[i].name;
			break;
		}
	}
	if ( m_extName.size() == 0 )
		m_extName = m_oidString.c_str();

	return true;
}

bool tsCertificateExtension::AddToNode(std::shared_ptr<TlvNode> parent) const
{
	std::shared_ptr<TlvNode> seq, node;

    if ( !parent )
        return false;

    parent->AppendChild(seq = parent->OwnerDocument().lock()->CreateSequence());
    if ( !seq )
        return false;

    seq->AppendChild(parent->OwnerDocument().lock()->CreateOIDNode(OID()));
    if ( Critical() )
    {
        seq->AppendChild(node = parent->OwnerDocument().lock()->CreateTlvNode(TlvNode::Tlv_Boolean, TlvNode::Type_Universal));
        if ( !node )
            return false;
        node->InnerData((BYTE)1);
    }
    seq->AppendChild(parent->OwnerDocument().lock()->CreateOctetString(Value()));
    return true;
}

const tsCryptoData &tsCertificateExtension::OID() const
{
	return m_oid;
}

void tsCertificateExtension::OID(tsCryptoData &setTo)
{
	m_oid = setTo;
	m_extName.clear();
	m_oidString = m_oid.ToOIDString();
	for (int i = 0; i < (int)(sizeof(gNameList) / sizeof(gNameList[0])); i++)
	{
		if ( TsStrCmp(gNameList[i].oid, m_oidString) == 0 )
		{
			m_extName = gNameList[i].name;
			break;
		}
	}
	if ( m_extName.size() )
		m_extName = m_oidString.c_str();
}

bool tsCertificateExtension::Critical() const
{
	return m_critical;
}

void tsCertificateExtension::Critical(bool setTo)
{
	m_critical = setTo;
}

const tsCryptoData &tsCertificateExtension::Value() const
{
	return m_value;
}

void tsCertificateExtension::Value(tsCryptoData &setTo)
{
	m_value = setTo;
}

tsCryptoString tsCertificateExtension::oidString() const
{
	return m_oidString;
}

tsCryptoString tsCertificateExtension::ExtensionName() const
{
	return m_extName;
}
