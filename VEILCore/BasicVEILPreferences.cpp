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

static const char *gItems[] = {
	"$.Desktop.AllowSigning",
	"$.Desktop.AllowCertificateEncryption",
	"$.Desktop.SigningCert",
	"$.Desktop.EncryptionCert",
	"$.Desktop.VerifyCerts",
	"$.Desktop.VerifyCertificateChain",
	"$.Desktop.CheckRevocation",
	"$.Desktop.AllowPasswordEncryption",
	"$.Desktop.CertificateSources",
	"$.Desktop.RequireRecovery",
	"$.Desktop.EncryptionAlgorithm",
	"$.Desktop.HashAlgorithm",
	"$.Desktop.SignHeader",
	"$.Desktop.HeaderSigningKeyAlgorithm",
	"$.KeyVEILUrl",
	"$.KeyVEILUsername",
	"$.AIDList",
	"$.KVPollTime",

	"$.FileVEIL.AlwaysOnTop",
	"$.FileVEIL.CloseAfterOperation",
	"$.FileVEIL.OverwriteExisting",
	"$.FileVEIL.DeleteAfterEncryption",
	"$.FileVEIL.DeleteAfterDecryption",
	"$.FileVEIL.DeleteAfterSigning",
	"$.FileVEIL.SecureDeletePassCount",
	"$.FileVEIL.SessionTimeout",
	"$.FileVEIL.LastDirBrowsed",
	"$.FileVEIL.CompressionType",
	"$.FileVEIL.DirBrowsedList",
};

BasicVEILPreferences::BasicVEILPreferences(JsonConfigLocation loc1, JsonConfigLocation loc2, JsonConfigLocation loc3) : tsJsonPreferencesBase(loc1, loc2, loc3)
{
	_parentSearchEntryCount = tsJsonPreferencesBase::getEntrySearchCount();
	setDefaultValues();
}


BasicVEILPreferences::~BasicVEILPreferences(void)
{
}

int BasicVEILPreferences::getEntrySearchCount() const
{
	return sizeof(gItems) / sizeof(gItems[0]) + _parentSearchEntryCount;
}

tscrypto::tsCryptoString BasicVEILPreferences::getEntrySearch(int index) const
{
	if (index < 0 || index >= getEntrySearchCount())
		return "";
	if (index < _parentSearchEntryCount)
		return tsJsonPreferencesBase::getEntrySearch(index);
	return gItems[index - _parentSearchEntryCount];
}

tscrypto::tsCryptoString BasicVEILPreferences::ConfigName()
{
	return "default";
}

JsonConfigLocation BasicVEILPreferences::DefaultSaveLocation() const
{
	return jc_User;
}


DEFINE_ENUM_PREF_CODE(BasicVEILPreferences, "$.Desktop.EncryptionAlgorithm", EncryptionAlgorithm, TS_ALG_ID, _TS_ALG_ID::TS_ALG_AES_GCM_256)
DEFINE_TEXT_PREF_CODE(BasicVEILPreferences, "$.Desktop.HeaderSigningKeyAlgorithm", HeaderSigningKeyAlgorithm, "")
DEFINE_ENUM_PREF_CODE(BasicVEILPreferences, "$.Desktop.HashAlgorithm", HashAlgorithm, TS_ALG_ID, _TS_ALG_ID::TS_ALG_SHA512)
DEFINE_BOOL_PREF_CODE(BasicVEILPreferences, "$.Desktop.SignHeader", SignHeader, true)
DEFINE_BOOL_PREF_CODE(BasicVEILPreferences, "$.Desktop.AllowSigning", AllowSigning, false)
DEFINE_BOOL_PREF_CODE(BasicVEILPreferences, "$.Desktop.AllowCertificateEncryption", AllowCertificateEncryption, false)
DEFINE_BOOL_PREF_CODE(BasicVEILPreferences, "$.Desktop.VerifyCerts", VerifyCerts, true)
DEFINE_BOOL_PREF_CODE(BasicVEILPreferences, "$.Desktop.VerifyCertificateChain", VerifyCertificateChain, true)
DEFINE_BOOL_PREF_CODE(BasicVEILPreferences, "$.Desktop.CheckRevocation", CheckRevocation, true)
DEFINE_BOOL_PREF_CODE(BasicVEILPreferences, "$.Desktop.AllowPasswordEncryption", AllowPasswordEncryption, true)
DEFINE_BOOL_PREF_CODE(BasicVEILPreferences, "$.Desktop.RequireRecovery", RequireRecovery, false)
DEFINE_DATA_PREF_CODE(BasicVEILPreferences, "$.Desktop.SigningCert", SigningCert)
DEFINE_DATA_PREF_CODE(BasicVEILPreferences, "$.Desktop.EncryptionCert", EncryptionCert)
DEFINE_TEXT_PREF_CODE(BasicVEILPreferences, "$.Desktop.CertificateSources", CertificateSources, "")
DEFINE_TEXT_PREF_CODE(BasicVEILPreferences, "$.KeyVEILUrl", KeyVEILUrl, "")
DEFINE_TEXT_PREF_CODE(BasicVEILPreferences, "$.KeyVEILUsername", KeyVEILUsername, "")
DEFINE_TEXT_PREF_CODE(BasicVEILPreferences, "$.AIDList", AIDList, "")
DEFINE_INT_PREF_CODE(BasicVEILPreferences, "$.KVPollTime", KVPollTime, 2000)

// FileVEIL settings
DEFINE_BOOL_PREF_CODE(BasicVEILPreferences, "$.FileVEIL.AlwaysOnTop", AlwaysOnTop, false)
DEFINE_BOOL_PREF_CODE(BasicVEILPreferences, "$.FileVEIL.CloseAfterOperation", CloseAfterOperation, false)
DEFINE_BOOL_PREF_CODE(BasicVEILPreferences, "$.FileVEIL.OverwriteExisting", OverwriteExisting, false)
DEFINE_BOOL_PREF_CODE(BasicVEILPreferences, "$.FileVEIL.DeleteAfterEncryption", DeleteAfterEncryption, false)
DEFINE_BOOL_PREF_CODE(BasicVEILPreferences, "$.FileVEIL.DeleteAfterDecryption", DeleteAfterDecryption, false)
DEFINE_BOOL_PREF_CODE(BasicVEILPreferences, "$.FileVEIL.DeleteAfterSigning", DeleteAfterSigning, false)
DEFINE_INT_PREF_CODE(BasicVEILPreferences, "$.FileVEIL.SecureDeletePassCount", SecureDeletePassCount, 3)
DEFINE_INT_PREF_CODE(BasicVEILPreferences, "$.FileVEIL.SessionTimeout", SessionTimeout, 300)
DEFINE_TEXT_PREF_CODE(BasicVEILPreferences, "$.FileVEIL.LastDirBrowsed", LastDirBrowsed, "")
DEFINE_ENUM_PREF_CODE(BasicVEILPreferences, "$.FileVEIL.CompressionType", CompressionType, CompressionType, ct_zLib)
DEFINE_TEXT_PREF_CODE(BasicVEILPreferences, "$.FileVEIL.DirBrowsedList", DirBrowsedList, "")

std::shared_ptr<BasicVEILPreferences> BasicVEILPreferences::Create(JsonConfigLocation loc1, JsonConfigLocation loc2, JsonConfigLocation loc3)
{
	return ::TopServiceLocator()->Finish<BasicVEILPreferences>(new BasicVEILPreferences(loc1, loc2, loc3));
}