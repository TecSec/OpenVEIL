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

#if 0

#ifdef _WIN32
// Modification for Authenticode KRR 10/21/2009

// 07/01/2010 KRR disabled all way too slow needs to be revisited
// 11/18/2010 KRR fixed certificate now much faster

#include <stdio.h>
#include <stdlib.h>

// for VerifyEmbeddedSignature
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <wchar.h>

#pragma comment (lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

#define ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)

typedef struct {
    LPWSTR lpszProgramName;
    LPWSTR lpszPublisherLink;
    LPWSTR lpszMoreInfoLink;
} SPROG_PUBLISHERINFO, *PSPROG_PUBLISHERINFO;

static BYTE hexCharToByte(char hex)
{
    if (hex >= 'a' && hex <= 'f')
        return (BYTE)(hex - 'a' + 10);
    if (hex >= 'A' && hex <= 'F')
        return (BYTE)(hex - 'A' + 10);
    if (hex >= '0' && hex <= '9')
        return (BYTE)(hex - '0');
    return 0;
}

static bool compareHex(const char*hex, const BYTE* data, int dataLen)
{
    BYTE c;

    while (dataLen > 0)
    {
        c = 0;
        if (hex == nullptr || hex[0] == 0 || hex[1] == 0)
            return false;
        c = (hexCharToByte(hex[0]) << 4) | hexCharToByte(hex[1]);
        if (data[0] != c)
            return false;
        dataLen--;
        data++;
        hex += 2;
    }
    return true;
}

static BOOL FindCertificateInfo(PCCERT_CONTEXT pCertContext)
{
	BOOL fReturn = FALSE;
	DWORD dwData = 0L;	// krr -> fixed compiler warning C4706:
    BYTE buffer[512];
    DWORD len;

	for(;;)
	{
        // Validate the certificate thumbprint
        len = sizeof(buffer);
        if (!CertGetCertificateContextProperty(pCertContext, CERT_SHA1_HASH_PROP_ID, buffer, &len))
        {
			printf ("  ERROR:  The signing certificate is invalid - Thumbprint missing.\n");
            break;
        }
        if (!compareHex("47d8ecb6c3cda9dc9fd65c7276d6f95f3c3c2d4b", buffer, len))
		{
			printf ("  ERROR:  The signing certificate is invalid - Thumbprint is invalid.\n");
            break;
		}

        // Validate the subject key id
        len = sizeof(buffer);
        if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_IDENTIFIER_PROP_ID, buffer, &len))
        {
			printf ("  ERROR:  The signing certificate is invalid - Subject key identifier is missing.\n");
            break;
        }
        if (!compareHex("6bcd22cefb0b4076f2b230d2508b55b21a92e1d3", buffer, len))
		{
		    printf ("  ERROR:  The signing certificate is invalid - Subject key identifier is invalid.\n");
		    break;
		}

	    // Get Issuer name size.
		if ((dwData = CertGetNameStringA(pCertContext,
											CERT_NAME_SIMPLE_DISPLAY_TYPE,
											CERT_NAME_ISSUER_FLAG,
											NULL,
											(LPSTR)buffer,
											sizeof(buffer))) == 0)
		{
			printf ("  ERROR:  The signing certificate is invalid - Issuer is missing.\n");
			break;
		}

//			if(!strstr(tsName.c_str(), "VeriSign Class 3 Code Signing 2010 CA" ) && !strstr(tsName.c_str(), "TecSec Secure Services"))
		if(strcmp((LPSTR)buffer, ("TecSec-CERTSERVER-CA")) != 0)
		{
			printf ("  ERROR:  The signing certificate is invalid - Issuer is invalid.\n");
			break;
		}

		// Get Subject name size.
		if ((dwData = CertGetNameStringA(pCertContext,
											CERT_NAME_SIMPLE_DISPLAY_TYPE,
											0,
											NULL,
											(LPSTR)buffer,
											sizeof(buffer))) == 0)
		{
			printf ("  ERROR:  The signing certificate is invalid - Subject is missing.\n");
			break;
		}

		if (strcmp((LPSTR)buffer, ("TecSec Secure Services")) != 0)
		{
			printf ("  ERROR:  The signing certificate is invalid - Subject is invalid.\n");
			break;
		}

        fReturn = TRUE;
		break; // PLEASE do not remove this break or the for loop will for... forever!
	}	// for(;;)

	return fReturn;
}

// 07/01/2010 KRR needs to revisited - too slow
// 11/18/2010 KRR fixed certificate now much faster
static int32_t VerifyEmbeddedSignature(const char *aFileName)
{
	LONG lStatus = ERROR_SUCCESS;	// 11/23/09 krr fixed compiler warning C4701 uninitialied variable
    ts_wchar tsSourceFile[MAX_PATH] = {0, };

    MultiByteToWideChar(0, 0, aFileName, (int)strlen(aFileName), tsSourceFile, sizeof(tsSourceFile) / sizeof(tsSourceFile[0]));

	WINTRUST_FILE_INFO WinTrustFileInfo;
	memset(&WinTrustFileInfo, 0, sizeof(WinTrustFileInfo));
	WinTrustFileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
	WinTrustFileInfo.pcwszFilePath = tsSourceFile;
	WinTrustFileInfo.hFile = NULL;
	WinTrustFileInfo.pgKnownSubject = NULL;

	HCERTSTORE hStore = NULL;
	HCRYPTMSG hMsg = NULL;
	PCCERT_CONTEXT pCertContext = NULL;
	BOOL fResult = FALSE;
	DWORD dwEncoding, dwContentType, dwFormatType;
	PCMSG_SIGNER_INFO pSignerInfo = NULL;
	PCMSG_SIGNER_INFO pCounterSignerInfo = NULL;
	DWORD dwSignerInfo = 0;
	CERT_INFO CertInfo;
	SPROG_PUBLISHERINFO ProgPubInfo;

	GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_DATA WinTrustData;
	SetLastError(ERROR_SUCCESS);

	//do and while(1) complains with error C4127
	for(;;)
	{
		ZeroMemory(&ProgPubInfo, sizeof(ProgPubInfo));

		fResult = CryptQueryObject(CERT_QUERY_OBJECT_FILE,
									WinTrustFileInfo.pcwszFilePath,
									CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
									CERT_QUERY_FORMAT_FLAG_BINARY,
									0,
									&dwEncoding,
									&dwContentType,
									&dwFormatType,
									&hStore,
									&hMsg,
									NULL);
		if (!fResult)
		{
			printf ("  ERROR:  The signature is missing.\n");
			break;
		}

		// Get signer information size.
		fResult = CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSignerInfo);

		if (!fResult)
		{
			printf ("  ERROR:  No signer information is found in the signature.\n");
			break;
		}

		// Allocate memory for signer information.
		pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSignerInfo);

		if (!pSignerInfo)
		{
			printf ("  ERROR:  No signer information is found in the signature.\n");
	  		fResult = FALSE;
			break;
		}

		// Get Signer Information.
		fResult = CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, (PVOID)pSignerInfo, &dwSignerInfo);

		if (!fResult)
		{
			printf ("  ERROR:  No signer information is found in the signature.\n");
			break;
		}

		// Search for the signer certificate in the temporary
		// certificate store.
		CertInfo.Issuer = pSignerInfo->Issuer;
		CertInfo.SerialNumber = pSignerInfo->SerialNumber;

		pCertContext = CertFindCertificateInStore(hStore, ENCODING, 0, CERT_FIND_SUBJECT_CERT, (PVOID)&CertInfo, NULL);

		if (!pCertContext)
		{
			printf ("  ERROR:  The root certificate was not found.\n");
			fResult = FALSE;
			break;
		}

		if(!FindCertificateInfo(pCertContext))
		{
			printf ("  ERROR:  Unable to load the root certificate.\n");
			lStatus = ERROR_INVALID_DATA;
			fResult = TRUE;
			break;
		}

		// if we got this far were good so far
		fResult = true;

		memset(&WinTrustData, 0, sizeof(WinTrustData));
		WinTrustData.cbStruct = sizeof(WinTrustData);
		WinTrustData.pPolicyCallbackData = NULL;
		WinTrustData.pSIPClientData = NULL;
		WinTrustData.dwUIChoice = WTD_UI_NONE;
		WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
		WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
		WinTrustData.dwStateAction = 0;
		WinTrustData.hWVTStateData = NULL;
		WinTrustData.pwszURLReference = NULL;
		WinTrustData.dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;
		WinTrustData.dwUIContext = 0;
		WinTrustData.pFile = &WinTrustFileInfo;

		lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);
		if (lStatus != ERROR_SUCCESS)
			printf ("  ERROR:  Unable to validate the signature [%08X].\n", GetLastError());
		break;	// PLEASE do not remove this break or the for loop will for... forever!
	}	// for(;;)

	if(!fResult)
		lStatus = GetLastError();

	// Garbage collection.
	if (ProgPubInfo.lpszProgramName != NULL)
		LocalFree(ProgPubInfo.lpszProgramName);
	if (ProgPubInfo.lpszPublisherLink != NULL)
		LocalFree(ProgPubInfo.lpszPublisherLink);
	if (ProgPubInfo.lpszMoreInfoLink != NULL)
		LocalFree(ProgPubInfo.lpszMoreInfoLink);

	if (pSignerInfo != NULL)
		LocalFree(pSignerInfo);
	if (pCounterSignerInfo != NULL)
		LocalFree(pCounterSignerInfo);
	if (pCertContext != NULL)
		CertFreeCertificateContext(pCertContext);
	if (hStore != NULL)
		CertCloseStore(hStore, 0);
	if (hMsg != NULL)
		CryptMsgClose(hMsg);

	return lStatus;
}

// 07/01/2010 KRR disabled Authenticode too slow - needs to be revisited
// 11/18/2010 KRR fixed certificate now much faster
bool AuthenticateModule(const char *aFilename)
{
#ifndef NonDebug
 	long lReturn = ERROR_SUCCESS;

	lReturn = VerifyEmbeddedSignature(aFilename);

	if(lReturn == ERROR_SUCCESS)
	{
		return true;
	} else {
		return false;
	}
#else
	UNREFERENCED_PARAMETER(aFilename);
	return true;
#endif // NonDebug
}


#else
bool AuthenticateModule(const char *aFilename)
{
    UNREFERENCED_PARAMETER(aFilename);

    // TODO:  Implement me
    return true;
}
bool AuthenticateModule(const tsAscii& aFilename)
{
    UNREFERENCED_PARAMETER(aFilename);

    // TODO:  Implement me
    return true;
}
#endif // _WIN32

#else // 0

bool AuthenticateModule(const char *aFilename)
{
    UNREFERENCED_PARAMETER(aFilename);
	
	// Handled in crypto license
	return true;
}
#endif // 0
