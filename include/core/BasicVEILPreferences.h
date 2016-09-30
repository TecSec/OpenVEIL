//	Copyright (c) 2016, TecSec, Inc.
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
/// \file BasicVEILPreferences.h
/// \brief Provides access to and change monitoring for the CKM Desktop preferences.
//////////////////////////////////////////////////////////////////////////////////

#pragma once

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Provides access to and change monitoring for the CKM Desktop preferences.</summary>
///
/// <seealso cref="CKMPreferencesBase"/>
////////////////////////////////////////////////////////////////////////////////////////////////////
class VEILCORE_API BasicVEILPreferences : public tsJsonPreferencesBase
{
public:
	static std::shared_ptr<BasicVEILPreferences> Create(JsonConfigLocation location = jc_System, JsonConfigLocation loc2 = jc_User, JsonConfigLocation loc3 = jc_Public);
	static void *operator new(std::size_t count) {
		return tscrypto::cryptoNew(count);
	}
	static void *operator new[](std::size_t count) {
		return tscrypto::cryptoNew(count);
	}
		static void operator delete(void *ptr) {
		tscrypto::cryptoDelete(ptr);
	}
	static void operator delete[](void *ptr) {
		tscrypto::cryptoDelete(ptr);
	}

protected:
	/// <summary>Default constructor.</summary>
	BasicVEILPreferences(JsonConfigLocation loc1, JsonConfigLocation loc2, JsonConfigLocation loc3);
public:
	/// <summary>Destructor.</summary>
	virtual ~BasicVEILPreferences(void);

	/**
	* \brief Gets attribute entry search count.
	*
	* \return true if it succeeds, false if it fails.
	*/
	virtual int getEntrySearchCount() const;
	/**
	* \brief Gets attribute entry search.
	*
	* \param index Zero-based index of the.
	*
	* \return The attribute entry search.
	*/
	virtual tscrypto::tsCryptoString getEntrySearch(int index) const;
	virtual JsonConfigLocation DefaultSaveLocation() const;

	DECLARE_BASE_TYPE_PREF_CODE(EncryptionAlgorithm, tscrypto::TS_ALG_ID)
	DECLARE_BASE_TYPE_PREF_CODE(HashAlgorithm, tscrypto::TS_ALG_ID)
	DECLARE_BOOL_PREF_CODE(SignHeader)
	DECLARE_TEXT_PREF_CODE(HeaderSigningKeyAlgorithm)
	DECLARE_BOOL_PREF_CODE(AllowSigning)
	DECLARE_BOOL_PREF_CODE(AllowCertificateEncryption)
	DECLARE_BOOL_PREF_CODE(VerifyCerts)
	DECLARE_BOOL_PREF_CODE(VerifyCertificateChain)
	DECLARE_BOOL_PREF_CODE(CheckRevocation)
	DECLARE_BOOL_PREF_CODE(AllowPasswordEncryption)
	DECLARE_BOOL_PREF_CODE(RequireRecovery)
	DECLARE_DATA_PREF_CODE(SigningCert)
	DECLARE_DATA_PREF_CODE(EncryptionCert)
	DECLARE_TEXT_PREF_CODE(CertificateSources)
	DECLARE_TEXT_PREF_CODE(KeyVEILUrl)
	DECLARE_TEXT_PREF_CODE(KeyVEILUsername)
	DECLARE_TEXT_PREF_CODE(AIDList)
	DECLARE_INT_PREF_CODE(KVPollTime)

	// FileVEIL settings
	DECLARE_BOOL_PREF_CODE(AlwaysOnTop)
	DECLARE_BOOL_PREF_CODE(CloseAfterOperation)
	DECLARE_BOOL_PREF_CODE(OverwriteExisting)
	DECLARE_BOOL_PREF_CODE(DeleteAfterEncryption)
	DECLARE_BOOL_PREF_CODE(DeleteAfterDecryption)
	DECLARE_BOOL_PREF_CODE(DeleteAfterSigning)
	DECLARE_INT_PREF_CODE(SecureDeletePassCount)
	DECLARE_INT_PREF_CODE(SessionTimeout)
	DECLARE_TEXT_PREF_CODE(LastDirBrowsed)
	DECLARE_BASE_TYPE_PREF_CODE(CompressionType, CompressionType)

protected:

	/// <summary>Sets the default values for these options.</summary>
	//virtual void setDefaultValues();
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the configuration name.</summary>
	///
	/// <returns>the configuration name..</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual tscrypto::tsCryptoString ConfigName();

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Saves the configuration changes for the specified location.</summary>
	///
	/// <param name="location">The location.</param>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool saveConfigurationChangesForLocation(JsonConfigLocation location) { MY_UNREFERENCED_PARAMETER(location); return true; }
	//virtual bool saveConfigurationChangesForLocation(JsonConfigLocation location);
	/**
	 * \brief Loads configuration values for the specified location.
	 *
	 * \param location The location.
	 * \param config   The configuration.
	 *
	 * \return true if it succeeds, false if it fails.
	 */
	virtual bool loadValuesForLocation(JsonConfigLocation location, const tscrypto::JSONObject &config) { MY_UNREFERENCED_PARAMETER(location); MY_UNREFERENCED_PARAMETER(config); return true; }
	//virtual bool loadValuesForLocation(JsonConfigLocation location, const tscrypto::JSONObject &config);
	/**
	 * \brief Determines if we can use entries.
	 *
	 * \return true if it succeeds, false if it fails.
	 */
	virtual bool UseEntries(void) const { return true; }

private:
	int _parentSearchEntryCount;
};

