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
/// \file CKMHeader.h
/// \brief This file describes the interface to the CKM Header component.
//////////////////////////////////////////////////////////////////////////////////

/*! \defgroup CKMHEADER CKM Header Component
 * @{
 */

#ifndef __CMSHEADERINTERFACES_H__
#define __CMSHEADERINTERFACES_H__

/// <summary>Common functionality for all CMS headers.</summary>
class ICmsHeaderBase
{
public:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the combiner version.</summary>
    ///
    /// <returns>The combiner version.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual int GetCombinerVersion() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the combiner version.</summary>
    ///
    /// <param name="setTo">the combiner version.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual void SetCombinerVersion(int setTo) = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the header creation date.</summary>
    ///
    /// <returns>The header creation date.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::tsCryptoString GetCreationDate() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the header creation date.</summary>
    ///
    /// <param name="date">the header creation date.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual void SetCreationDate(const tscrypto::tsCryptoString& date) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the encryption algorithm identifier.</summary>
    ///
    /// <returns>The encryption algorithm identifier.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::TS_ALG_ID GetEncryptionAlgorithmID() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the encryption algorithm identifier.</summary>
    ///
    /// <param name="setTo">the encryption algorithm identifier.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual void SetEncryptionAlgorithmID(tscrypto::TS_ALG_ID setTo) = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the compression type.</summary>
    ///
    /// <returns>The compression type.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual CompressionType GetCompressionType() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the compression type.</summary>
    ///
    /// <param name="setTo">the compression type.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual void SetCompressionType(CompressionType setTo) = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Converts the header to an array of bytes.</summary>
    ///
    /// <returns>This object as a tscrypto::tsCryptoData.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::tsCryptoData ToBytes() = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Initializes this object from the given array of bytes.</summary>
    ///
    /// <param name="setTo">The the streamed header.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool FromBytes(const tscrypto::tsCryptoData &setTo) = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the padding type.</summary>
    ///
    /// <returns>The padding type.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::SymmetricPaddingType GetPaddingType () const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the padding type.</summary>
    ///
    /// <param name="setTo">the padding type.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual void SetPaddingType (tscrypto::SymmetricPaddingType setTo) = 0;

    /*! @brief Creates a clone of this CMS Header object
     *
     * This function is used to duplicate (clone) this CKM header into a new object.
     * @param pVal the destination for the new CKM Header interface pointer
     * @return Success or failure code
     * @retval S_OK Success
     * @retval E_POINTER pVal is NULL
     * @retval E_OUTOFMEMORY Out of memory when attempting to clone the data
     */
	virtual bool DuplicateHeader(std::shared_ptr<ICmsHeaderBase>& pVal) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Converts the header into a human readable string.</summary>
    ///
    /// <returns>The human readable string.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::tsCryptoString GetDebugString() = 0;
};

//-------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------

/// <summary>Cms header CryptoGroup.</summary>
class ICmsHeaderCryptoGroup
{
public:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the CryptoGroup's unique identifier.</summary>
    ///
    /// <returns>The CryptoGroup's unique identifier.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual GUID GetCryptoGroupGuid() = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the current maintenance level.</summary>
    ///
    /// <returns>The current maintenance level.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual int  GetCurrentMaintenanceLevel() = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the current maintenance level.</summary>
    ///
    /// <param name="setTo">The maintenance level.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetCurrentMaintenanceLevel(int setTo) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the ephemeral public key.</summary>
    ///
    /// <returns>The ephemeral public key.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::tsCryptoData GetEphemeralPublic() = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the ephemeral public key.</summary>
    ///
    /// <param name="key">The ephemeral public key.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetEphemeralPublic(const tscrypto::tsCryptoData &key) = 0;
};

/// <summary>Defines the possible set of AND groups that can be combined in CKM 7.</summary>
typedef enum
{
    ag_FullCert = 0,		///< \brief A full certificate
    ag_PartialCert = 1,		///< \brief A partial certificate (issuer and subject information)
    ag_Pin = 2,				///< \brief A pin
    ag_Attrs = 3,			///< \brief CKM7 attributes
    ag_ExternalCrypto = 4,	///< \brief External crypto system
} AndGroupType;

/// <summary>The base interface for a CKM7 header access group (AND group).</summary>
class ICmsHeaderAccessGroup 
{
public:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the group type.</summary>
    ///
    /// <returns>The group type.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual AndGroupType GetAndGroupType() = 0;
};

/// <summary>Holds attribute index information for one AND group.  The attributes are stored in ICKM7HeaderAttributeListExtension.</summary>
class ICmsHeaderAttributeGroup : public ICmsHeaderAccessGroup
{
public:
	//IMPLEMENT_GENERIC_INDEXED_BASE_ITERATORS(uint32_t, uint32_t, GetAttributeCount, GetAttributeIndex, 0);

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets number of attributes referenced in this AND group</summary>
    ///
    /// <returns>The attribute count.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual size_t GetAttributeCount() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the specified attribute index.</summary>
    ///
    /// <param name="position">The attribute index position.</param>
    ///
    /// <returns>The attribute index.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual const uint32_t& GetAttributeIndex(size_t position) const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Removes the attribute index described by position.</summary>
    ///
    /// <param name="position">The position.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool RemoveAttributeIndex(size_t position) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Adds an attribute index.</summary>
    ///
    /// <param name="indexInAttributeList">The attribute index.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool AddAttributeIndex(uint32_t  indexInAttributeList) = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the encrypted random for this AND group.</summary>
    ///
    /// <returns>The encrypted random.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::tsCryptoData GetEncryptedRandom() = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the encrypted random for this AND group.</summary>
    ///
    /// <param name="setTo">The encrypted random.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetEncryptedRandom(const tscrypto::tsCryptoData &setTo) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the specified attribute index.</summary>
	///
	/// <param name="position">The attribute index position.</param>
	///
	/// <returns>The attribute index.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool SetAttributeIndex(size_t position, uint32_t setTo) = 0;
};

/// <summary>This interface defines the base functionality needed for a CKM 7 Header Extension.</summary>
class ICmsHeaderExtension 
{
public:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the oid that defines this extension.</summary>
    ///
    /// <returns>The oid.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::tsCryptoData GetOID() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the oid that defines this extension.</summary>
    ///
    /// <param name="oid">The oid.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetOID(const tscrypto::tsCryptoData &oid) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets a flag that indicates that this extension is critical (must be understood to process this header).</summary>
    ///
    /// <returns>true if critical, false otherwise.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool GetIsCritical() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets a flag that indicates that this extension is critical (must be understood to process this header).</summary>
    ///
    /// <param name="setTo">true for critical.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetIsCritical(bool setTo) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the data held in this extension.</summary>
    ///
    /// <returns>The contents.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::tsCryptoData GetContents() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the data held in this extension.</summary>
    ///
    /// <param name="data">The data.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetContents(const tscrypto::tsCryptoData &data) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Query if this object is a known TecSec extension.</summary>
    ///
    /// <returns>true if known extension, false if not.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool IsKnownExtension() = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Converts this object to an encoded byte array.</summary>
    ///
    /// <returns>This object as a tscrypto::tsCryptoData.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::tsCryptoData ToBytes() = 0;
};

/// <summary>Defines an extension that holds an initialization vector.</summary>
class ICmsHeaderIvecExtension
{
public:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the initialization vector.</summary>
    ///
    /// <returns>The initialization vector.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::tsCryptoData GetIvec() = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the initialization vector.</summary>
    ///
    /// <param name="data">The initialization vector.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetIvec(const tscrypto::tsCryptoData &data) = 0;
};

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Defines an extension for a SecryptM encrypted file.</summary>
///
/// <remarks>Holds the padding for a SecryptM header to force the header to a given predetermined
/// size.</remarks>
////////////////////////////////////////////////////////////////////////////////////////////////////
class ICmsHeaderSecryptMExtension
{
public:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the padding.</summary>
    ///
    /// <returns>The padding.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::tsCryptoData GetPadding() = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the padding.</summary>
    ///
    /// <param name="data">The data.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetPadding(const tscrypto::tsCryptoData &data) = 0;
};
/**
 * \brief Defines an extension that holds the padded size of this header.
 */
class ICmsHeaderPaddedSizeExtension 
{
public:
	/**
	 * \brief Gets the padded size of the header.
	 *
	 * \return The padding.
	 */
	virtual uint32_t GetPaddedHeaderSize() = 0;
	/**
	 * \brief Sets the padded size of the header.
	 *
	 * \param setTo The data.
	 *
	 * \return true if it succeeds, false if it fails.
	 */
	virtual bool SetPaddedHeaderSize(uint32_t setTo) = 0;
};
/// <summary>Holds the data length.</summary>
class ICmsHeaderLengthExtension 
{
public:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the length of the data encrypted using this header.</summary>
    ///
    /// <returns>The length of the data.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual uint64_t GetLength() = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the length of the data encrypted using this header.</summary>
    ///
    /// <param name="data">The length of the data.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetLength(uint64_t data) = 0;
};

/// <summary>Holds a hash of the data.</summary>
class ICmsHeaderHashExtension 
{
public:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets hash algorithm oid.</summary>
    ///
    /// <returns>The hash algorithm oid.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::tsCryptoData GetHashAlgorithmOID() = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the hash algorithm oid.</summary>
    ///
    /// <param name="oid">The oid.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetHashAlgorithmOID(const tscrypto::tsCryptoData &oid) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the hash value.</summary>
    ///
    /// <returns>The hash value.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::tsCryptoData GetHash() = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the hash value.</summary>
    ///
    /// <param name="hash">The hash value.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetHash(const tscrypto::tsCryptoData &hash) = 0;
};

/// <summary>Holds the name of the data, could be a file name...</summary>
class ICmsHeaderNameExtension 
{
public:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the name of the data.</summary>
    ///
    /// <returns>The name of the data.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::tsCryptoString GetName() = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the name of the data.</summary>
    ///
    /// <param name="name">The name of the data.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetName(const tscrypto::tsCryptoString &name) = 0;
};

/// <summary>Holds a list of CKM 7 CryptoGroups that are to be used in the key generation process.</summary>
class ICmsHeaderCryptoGroupListExtension 
{
public:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets CryptoGroup count.</summary>
    ///
    /// <returns>The CryptoGroup count.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual size_t GetCryptoGroupCount() = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Adds a CryptoGroup to this list and returns the index of the newly added CryptoGroup.</summary>
    ///
    /// <param name="sryptoGroupGuid">Unique identifier for the CryptoGroup.</param>
    /// <param name="pVal">		 [out] The index of the newly added CryptoGroup.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool AddCryptoGroup(const GUID &cryptoGroupGuid, int *pVal) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the specified CryptoGroup.</summary>
    ///
    /// <param name="index">Zero-based index of the CryptoGroup.</param>
    /// <param name="pVal"> [out] The CryptoGroup value.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool GetCryptoGroup(size_t index, std::shared_ptr<ICmsHeaderCryptoGroup>& pVal) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Removes the CryptoGroup described by index.</summary>
    ///
    /// <param name="index">Zero-based index of the CryptoGroup to remove from the list.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool RemoveCryptoGroup(size_t index) = 0;
};

/// <summary>Holds the list of access groups (AND groups) that are used in this key generation.</summary>
class ICmsHeaderAccessGroupExtension 
{
public:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the access group count.</summary>
    ///
    /// <returns>The access group count.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual size_t GetAccessGroupCount() = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Adds an access group to to this list and returns the newly created object.</summary>
    ///
    /// <param name="type">The type of access group to create and add.</param>
    /// <param name="pVal">[out] The newly created access group.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool AddAccessGroup(AndGroupType type, std::shared_ptr<ICmsHeaderAccessGroup>& pVal) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the specified access group.</summary>
    ///
    /// <param name="index">Zero-based index of the access group.</param>
    /// <param name="pVal"> [out] The access group.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool GetAccessGroup(size_t index, std::shared_ptr<ICmsHeaderAccessGroup>& pVal) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Removes the access group described by index.</summary>
    ///
    /// <param name="index">Zero-based index of the access group to remove from the list.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool RemoveAccessGroup (size_t index) = 0;
};

/// <summary>An extension that holds the unique ID of the issuer (enterprise).</summary>
class ICmsHeaderIssuerExtension 
{
public:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets issuer unique identifier.</summary>
    ///
    /// <returns>The issuer unique identifier.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual GUID GetIssuerGuid() = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the issuer unique identifier.</summary>
    ///
    /// <param name="guid">Unique identifier.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetIssuerGuid(const GUID &guid) = 0;
};

/// <summary>Holds the purpose and size of the working key to generate.</summary>
class ICmsHeaderKeyUsageExtension 
{
public:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets key usage oid.</summary>
    ///
    /// <returns>The key usage oid.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::tsCryptoData GetKeyUsageOID() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the key usage oid.</summary>
    ///
    /// <param name="setTo">The key usage oid.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetKeyUsageOID(const tscrypto::tsCryptoData &setTo) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the working key size in bits.</summary>
    ///
    /// <returns>The working key size in bits.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual int GetKeySizeInBits() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the working key size in bits.</summary>
    ///
    /// <param name="setTo">The working key size in bits.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetKeySizeInBits(int setTo) = 0;
};

/// <summary>Holds the data block size and the encryption and hash format of the data.</summary>
class ICmsHeaderDataFormatExtension 
{
public:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the size of the plaintext block in bytes to process.</summary>
    ///
    /// <returns>The block size in bytes.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual int GetBlockSize() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the size of the plaintext block in bytes to process.</summary>
    ///
    /// <param name="setTo">The block size in bytes.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetBlockSize(int setTo) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the algorithm to use to process the data.</summary>
    ///
    /// <returns>The format algorithm. <see cref="CKMFileFormatIds"/></returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual int GetFormatAlgorithm() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the algorithm to use to process the data.</summary>
    ///
    /// <param name="setTo">The format algorithm. <see cref="CKMFileFormatIds"/></param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetFormatAlgorithm(int setTo) = 0;
};

/// <summary>Holds the MIME type of the plaintext data.</summary>
class ICmsHeaderMimeTypeExtension 
{
public:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the mime type.</summary>
    ///
    /// <returns>The mime type.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::tsCryptoString GetMimeType() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the mime type.</summary>
    ///
    /// <param name="setTo">the mime type.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetMimeType(const tscrypto::tsCryptoString &setTo) = 0;
};

/// <summary>Holds the identity and key version information for one CKM 7 attribute in this header.</summary>
class ICmsHeaderAttribute 
{
public:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets attribute unique identifier.</summary>
    ///
    /// <returns>The attribute unique identifier.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual GUID GetAttributeGUID() = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the attribute unique identifier.</summary>
    ///
    /// <param name="guid">Unique identifier.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool SetAttributeGuid(const GUID &guid) = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the attribute key version.</summary>
    ///
    /// <returns>The key version.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual int GetKeyVersion() = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the attribute key version.</summary>
    ///
    /// <param name="setTo">The set to.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetKeyVersion(int setTo) = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the CryptoGroup index number.</summary>
    ///
    /// <returns>The CryptoGroup index number.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual int GetCryptoGroupNumber() = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the CryptoGroup index number.</summary>
    ///
    /// <param name="setTo">The CryptoGroup index number.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool SetCryptoGroupNumber(int setTo) = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the optional attribute signature.</summary>
    ///
    /// <returns>The attribute signature.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::tsCryptoData GetSignature() = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the optional attribute signature.</summary>
    ///
    /// <param name="setTo">The attribute signature.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetSignature(const tscrypto::tsCryptoData &setTo) = 0;
};

/// <summary>Holds a list of attributes.</summary>
class ICmsHeaderAttributeListExtension 
{
public:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the attribute count.</summary>
    ///
    /// <returns>The attribute count.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual size_t GetAttributeCount() const = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Adds an attribute to the list and returns the attribute index.</summary>
    ///
    /// <returns>The new attribute index.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual int  AddAttribute () = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Returns the attribute at the specified index.</summary>
    ///
    /// <param name="index">Zero-based index of the attribute.</param>
    /// <param name="pVal"> [out] The attribute.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool GetAttribute(size_t index, std::shared_ptr<ICmsHeaderAttribute>& pVal) const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Removes the attribute described by index.</summary>
    ///
    /// <param name="index">Zero-based index of the attribute to remove.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool RemoveAttribute (size_t index) = 0;
};

/// <summary>Holds the optional header signing public key.</summary>
class ICmsHeaderPublicKeyExtension 
{
public:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the header signing public key.</summary>
    ///
    /// <returns>The header signing public key.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::tsCryptoData GetPublicKey() = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the header signing public key.</summary>
    ///
    /// <param name="key">The header signing public key.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetPublicKey(const tscrypto::tsCryptoData &key) = 0;
};

/// <summary>Defines the CKM 7 header.  This header is compatible to the CKM header in CMS (X9.73-2010).</summary>
class ICmsHeader : public ICmsHeaderBase
{
public:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Tests the data fragment to see if it could be a CKM 7 header.</summary>
    ///
    /// <param name="data">  The data.</param>
    /// <param name="length">The length of the data in bytes.</param>
    ///
    /// <returns>true if probable header, false if not.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool IsProbableHeader(const uint8_t *data, size_t length) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Returns the total header length if the data fragment is probably a header.</summary>
    ///
    /// <param name="data">  The data.</param>
    /// <param name="length">The length of the data in bytes.</param>
    ///
    /// <returns>The probable header length in bytes.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual int GetProbableHeaderLength(const uint8_t *data, size_t length) = 0;
    /// <summary>Clears this object to its blank/initial state.</summary>
    virtual void Clear() = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the header version.</summary>
    ///
    /// <returns>The header version.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual int GetHeaderVersion() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the header version.</summary>
    ///
    /// <param name="setTo">The header version.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual void SetHeaderVersion(int setTo) = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the identifier of the entity that created this header/working key.</summary>
    ///
    /// <returns>The identifier of the creator of this header.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::tsCryptoData GetCreatorId() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the identifier of the entity that created this header/working key.</summary>
    ///
    /// <param name="data">The identifier of the creator of this header.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual void SetCreatorId(const tscrypto::tsCryptoData &data) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the identifier of the entity that created this header/working key.</summary>
    ///
    /// <returns>The creator unique identifier.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual GUID GetCreatorGuid() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the identifier of the entity that created this header/working key.</summary>
    ///
    /// <param name="data">The creator unique identifier.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual void SetCreatorGuid(const GUID &data) = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets encryption algorithm as an oid.</summary>
    ///
    /// <returns>The encryption algorithm oid.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::tsCryptoData GetEncryptionAlgorithmOID() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets encryption algorithm as an oid.</summary>
    ///
    /// <param name="setTo">The encryption algorithm oid.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual void SetEncryptionAlgorithmOID(const tscrypto::tsCryptoData &setTo) = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets signature algorithm identifier.</summary>
    ///
    /// <returns>The signature algorithm identifier.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::TS_ALG_ID GetSignatureAlgorithmId() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the signature algorithm identifier.</summary>
    ///
    /// <param name="setTo">the signature algorithm identifier.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual void SetSignatureAlgorithmId(tscrypto::TS_ALG_ID setTo) = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the signature algorithm as an oid.</summary>
    ///
    /// <returns>The signature algorithm oid.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::tsCryptoData GetSignatureAlgorithmOID() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the signature algorithm using an oid.</summary>
    ///
    /// <param name="setTo">The signature algorithm oid.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual void SetSignatureAlgorithmOID(const tscrypto::tsCryptoData &setTo) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Determines if the signature type is a MAC.</summary>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SignatureIsMAC() = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the header signature or MAC.</summary>
    ///
    /// <returns>The header signature or MAC.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::tsCryptoData GetSignature() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the header signature.</summary>
    ///
    /// <param name="setTo">The header signature.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetSignature(const tscrypto::tsCryptoData &setTo) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Generates a MAC for the header.</summary>
    ///
    /// <param name="symmetricKey">The symmetric key.</param>
    /// <param name="macName">	   Name of the MAC algorithm.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool GenerateMAC(const tscrypto::tsCryptoData &symmetricKey, const tscrypto::tsCryptoString& macName) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Determines if the header signature is valid.</summary>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool ValidateSignature() = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Determines if the header MAC is valid.</summary>
    ///
    /// <param name="symmetricKey">The symmetric key.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool ValidateMAC(const tscrypto::tsCryptoData &symmetricKey) = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets an extension by OID.</summary>
    ///
    /// <param name="oid"> The oid.</param>
    /// <param name="pVal">[out] The located extension object.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool GetExtension(const tscrypto::tsCryptoData &oid, std::shared_ptr<ICmsHeaderExtension>& pVal) const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Removes the extension described by oid.</summary>
    ///
    /// <param name="oid">The oid.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool RemoveExtension(const tscrypto::tsCryptoData &oid) = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the number of protected extensions (extensions that are signed with the header).</summary>
    ///
    /// <returns>The protected extension count.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual size_t GetProtectedExtensionCount() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the specified protected extension by index.</summary>
    ///
    /// <param name="index">Zero-based index of the protected extension to return.</param>
    /// <param name="pVal"> [out] The protected extension.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool GetProtectedExtension(size_t index, std::shared_ptr<ICmsHeaderExtension>& pVal) const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the specified protected extension by OID.</summary>
    ///
    /// <param name="oid"> The OID of the protected extension to return.</param>
    /// <param name="pVal">[out] The protected extension.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool GetProtectedExtensionByOID(const tscrypto::tsCryptoData &oid, std::shared_ptr<ICmsHeaderExtension>& pVal) const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Adds a protected extension and returns it.</summary>
    ///
    /// <param name="oid">	   The oid of the extension.</param>
    /// <param name="critical">true if the extension is critical.</param>
    /// <param name="pVal">	   [out] The new protected extension.</param>
    ///
    /// <returns>true if it succeeds, false if the extension already exists or if an error occurred.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool AddProtectedExtension(const tscrypto::tsCryptoData &oid, bool critical, std::shared_ptr<ICmsHeaderExtension>& pVal) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Removes the protected extension described by pVal.</summary>
    ///
    /// <param name="pVal">[in] The extension to remove.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool RemoveProtectedExtension(std::shared_ptr<ICmsHeaderExtension> pVal) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Removes the protected extension described by index.</summary>
    ///
    /// <param name="index">Zero-based index of the extension to remove.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool RemoveProtectedExtensionByIndex(size_t index) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Removes the protected extension described by oid.</summary>
    ///
    /// <param name="oid">The oid.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool RemoveProtectedExtensionByOID(const tscrypto::tsCryptoData &oid) = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets unprotected extension count (extensions that are not protected with the header signature/MAC).</summary>
    ///
    /// <returns>The unprotected extension count.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual size_t GetUnprotectedExtensionCount() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the specified unprotected extension by index.</summary>
    ///
    /// <param name="index">Zero-based index of the unprotected extension to return.</param>
    /// <param name="pVal"> [out] The unprotected extension.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool GetUnprotectedExtension(size_t index, std::shared_ptr<ICmsHeaderExtension>& pVal) const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the specified unprotected extension by OID.</summary>
    ///
    /// <param name="oid"> The OID of the unprotected extension to return.</param>
    /// <param name="pVal">[out] The unprotected extension.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool GetUnprotectedExtensionByOID(const tscrypto::tsCryptoData &oid, std::shared_ptr<ICmsHeaderExtension>& pVal) const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Adds an unprotected extension.</summary>
    ///
    /// <param name="oid">	   The oid.</param>
    /// <param name="critical">true if critical.</param>
    /// <param name="pVal">	   [out] The new extension object.</param>
    ///
    /// <returns>true if it succeeds, false if the extension already exists or if an error occurred.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool AddUnprotectedExtension(const tscrypto::tsCryptoData &oid, bool critical, std::shared_ptr<ICmsHeaderExtension>& pVal) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Removes the unprotected extension described by pVal.</summary>
    ///
    /// <param name="pVal">[in] The extension to remove.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool RemoveUnprotectedExtension(std::shared_ptr<ICmsHeaderExtension> pVal) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Removes the unprotected extension described by index.</summary>
    ///
    /// <param name="index">Zero-based index of the extension to remove.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool RemoveUnprotectedExtensionByIndex(size_t index) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Removes the unprotected extension described by oid.</summary>
    ///
    /// <param name="oid">The oid.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool RemoveUnprotectedExtensionByOID(const tscrypto::tsCryptoData &oid) = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the optional header signing public key.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <returns>The header signing public key.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::tsCryptoData GetHeaderSigningPublicKey() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Query if this object has the optional header signing public key.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <returns>true if header signing public key, false if not.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool HasHeaderSigningPublicKey() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the header signing public key.</summary>
    ///
    /// <param name="encodedKey">The encoded key.</param>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetHeaderSigningPublicKey(const tscrypto::tsCryptoData &encodedKey) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Clears the header signing public key.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool ClearHeaderSigningPublicKey() = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets signable portion of the CKM 7 header.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <param name="toGenerateHeader">true if this is being called while generating the header.</param>
    ///
    /// <returns>The signable portion.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::tsCryptoData GetSignablePortion(bool toGenerateHeader) = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the optional ivec.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <returns>The ivec.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::tsCryptoData GetIVEC() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the optional ivec.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <param name="setTo">The ivec.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetIVEC(const tscrypto::tsCryptoData &setTo) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Clears the ivec.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool ClearIVEC() = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Returns the stored data length.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <returns>The data length.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual uint64_t GetFileLength() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the length of the data.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <param name="setTo">The data length.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetFileLength(uint64_t setTo) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Clears the data length.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool ClearFileLength() = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the enterprise unique identifier.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <param name="data">[out] The enterprise unique identifier.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool GetEnterpriseGuid(GUID &data) const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the enterprise unique identifier.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <param name="setTo">The enterprise unique identifier.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetEnterpriseGuid(const GUID &setTo) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Clears the enterprise unique identifier.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool ClearEnterpriseGuid() = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the optional data hash.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <returns>The data hash.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::tsCryptoData GetDataHash() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the optional data hash.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <param name="setTo">The data hash.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetDataHash(const tscrypto::tsCryptoData &setTo) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the data hash algorithm oid.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <returns>The data hash algorithm oid.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::tsCryptoData GetDataHashOID() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the data hash algorithm oid.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <param name="setTo">The data hash algorithm OID.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetDataHashOID(const tscrypto::tsCryptoData &setTo) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Clears the data hash.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool ClearDataHash() = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the stored data name.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <returns>The data name.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::tsCryptoString GetDataName() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the data name in the header.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <param name="setTo">The data name.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetDataName(const tscrypto::tsCryptoString& setTo) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Clears the data name.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool ClearDataName() = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the number of CKM 7 CryptoGroups referenced in this header.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <returns>The CryptoGroup count.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual size_t GetCryptoGroupCount() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Adds a CryptoGroup to this header and returns its index.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <param name="cryptoGroupGuid">Unique identifier for the CryptoGroup.</param>
    /// <param name="pVal">		 [out] The index of the new CryptoGroup object.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool AddCryptoGroup(const GUID &cryptoGroupGuid, int *pVal) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the specified CryptoGroup.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <param name="index">Zero-based index of the CryptoGroup to get.</param>
    /// <param name="pVal"> [out] The CryptoGroup object.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool GetCryptoGroup(size_t index, std::shared_ptr<ICmsHeaderCryptoGroup>& pVal) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the specified CryptoGroup by unique identifier.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <param name="cryptoGroupGuid">Unique identifier for the CryptoGroup.</param>
    /// <param name="pVal"> [out] The CryptoGroup object.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool GetCryptoGroupByGuid(const GUID &cryptoGroupGuid, std::shared_ptr<ICmsHeaderCryptoGroup>& pVal) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Removes the CryptoGroup described by index.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <param name="index">Zero-based index of the CryptoGroup to remove.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool RemoveCryptoGroup(size_t index) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Removes the CryptoGroup described by cryptoGroupGuid.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <param name="cryptoGroupGuid">Unique identifier for the CryptoGroup.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool RemoveCryptoGroupByGuid(const GUID &cryptoGroupGuid) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Clears the CryptoGroup list.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool ClearCryptoGroupList() = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the original header size in bytes before any conversions took place.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <returns>the original header size in bytes.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual int OriginalHeaderSize() const = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets key usage oid.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <returns>The key usage oid.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::tsCryptoData GetKeyUsageOID() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets key usage oid.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <param name="setTo">The key usage OID.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetKeyUsageOID(const tscrypto::tsCryptoData &setTo) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets key size in bits.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <returns>The key size in bits.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual int GetKeySizeInBits() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the key size in bits.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <param name="setTo">The set to.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetKeySizeInBits(int setTo) = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Clears the data format.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool ClearDataFormat() = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the data format.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <param name="blockSize">  Size of the block.</param>
    /// <param name="algorithmId">Identifier for the data block format.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetDataFormat(int blockSize, int algorithmId) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the data format.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <param name="blockSize">  [out] Size of the block.</param>
    /// <param name="algorithmId">[out] Identifier for the algorithm.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool GetDataFormat(int &blockSize, int &algorithmId) const = 0;

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the MIME type.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <returns>The MIME type.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tscrypto::tsCryptoString GetMimeType() const = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the MIME type.</summary>
    ///
    /// <remarks>This is a helper function that looks for the header extension and provides the
    /// required functionality in an easier to use package.</remarks>
    ///
    /// <param name="setTo">The MIME type.</param>
    ///
    /// <returns>true if it succeeds, false if it fails.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool SetMimeType(const tscrypto::tsCryptoString &setTo) = 0;
	/**
	 * \brief Determines if this header requires the use of a session.
	 *
	 * \return true if a session is required, false otherwise.
	 */
	virtual bool NeedsSession() = 0;
	/**
	 * \brief Determines if any terms in this header are CKM attribute based.
	 *
	 * \return true if a session is desired, false otherwise.
	 */
	virtual bool WantsSession() = 0;
	/**
	 * \brief Gets object identifier that represents the encrypted data blob.
	 *
	 * \return The object identifier.
	 */
	virtual GUID GetObjectID() = 0;
	/**
	 * \brief Sets object identifier that represents the encrypted data blob.
	 *
	 * \param setTo The set to.
	 */
	virtual void SetObjectID(const GUID& setTo) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the padded header size in bytes before any conversions took place.</summary>
	///
	/// <returns>the padded header size in bytes.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual uint32_t PaddedHeaderSize() const = 0;
	/*! @brief Sets the byte length of the header including padding
	*
	* This function sets the length in bytes (including padding) of the header byte stream.
	*/
	virtual void SetPaddedHeaderSize(uint32_t setTo) = 0;
	// Added 7.0.35
	virtual bool toBasicRecipe(Asn1::CTS::_POD_CkmRecipe& recipe) = 0;
	virtual bool fromBasicRecipe(const Asn1::CTS::_POD_CkmRecipe& recipe) = 0;
	virtual tscrypto::tsCryptoString toString(const tscrypto::tsCryptoString& type = "") = 0;
};

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Represents a callback that notifies the caller that the header is to be finished.
/// This allows the caller to modify the header before it is signed.</summary>
////////////////////////////////////////////////////////////////////////////////////////////////////
class IKeyGenCallback
{
public:
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Finish all modifications on the header.</summary>
	///
	/// <param name="key">   The working key.</param>
	/// <param name="header">[in] The header.</param>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool FinishHeader(const tscrypto::tsCryptoData &key, std::shared_ptr<ICmsHeaderBase> header) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the next callback that this object shall call when it processes FinishHeader.</summary>
	///
	/// <param name="callback">[in] The next callback in the chain.</param>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool SetNextCallback(std::shared_ptr<IKeyGenCallback> callback) = 0;
};

typedef enum {
	TS_FORMAT_CMS_PT_HASHED = tscrypto::_TS_ALG_ID::TS_ALG_RUNTIME_RESERVED + 0x00,	///< \brief The plaintext is hashed
	TS_FORMAT_CMS_CT_HASHED = tscrypto::_TS_ALG_ID::TS_ALG_RUNTIME_RESERVED + 0x01,	///< \brief The ciphertext is hashed
	TS_FORMAT_CMS_ENC_AUTH = tscrypto::_TS_ALG_ID::TS_ALG_RUNTIME_RESERVED + 0x02,	///< \brief The GCM mode of AES is used, the plaintext is split into blocks and each block is separately keyed and integrity checked.

	TS_FORMAT_MAX = tscrypto::_TS_ALG_ID::TS_ALG_RUNTIME_RESERVED + 0x7F	///< \brief The maximum format value reserved.
} CMSFileFormatIds;


class ICkmOperations
{
public:
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Calculates a header identity value that is used to bind the data to the header.</summary>
	///
	/// <param name="header">[in] The CKM header.</param>
	///
	/// <returns>The calculated header identity.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual tscrypto::tsCryptoData ComputeHeaderIdentity() = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Pads the CKM header to the specified byte size.</summary>
	///
	/// <param name="header">[in] The CKM header to pad.</param>
	/// <param name="size">  The size in bytes of the final header.</param>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool padHeaderToSize(DWORD size) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Modifies a CKM 7 header and preloads the encryption parameters in preparation of
	/// creating the working key.</summary>
	///
	/// <param name="header7">		[in,out] The CKM 7 header.</param>
	/// <param name="comp">			The compression type.</param>
	/// <param name="algorithm">	The encryption algorithm.</param>
	/// <param name="hashAlgorithm">The hash algorithm.</param>
	/// <param name="SignHeader">   true to sign the header.</param>
	/// <param name="bindData">		true to bind the data to the header.</param>
	/// <param name="DataFormat">   The data format.</param>
	/// <param name="randomIvec">   true for a random ivec.</param>
	/// <param name="paddingType">  Type of encryption padding.</param>
	/// <param name="blockSize">	Size of the block to process.</param>
	/// <param name="fileSize">		Size of the file.</param>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool PrepareHeader(CompressionType comp, tscrypto::TS_ALG_ID algorithm, tscrypto::TS_ALG_ID hashAlgorithm, bool SignHeader, bool bindData,
		CMSFileFormatIds DataFormat, bool randomIvec, tscrypto::SymmetricPaddingType paddingType, int blockSize, int64_t fileSize) = 0;
	virtual bool GenerateWorkingKey(std::shared_ptr<IKeyVEILSession> session, std::shared_ptr<IKeyGenCallback> callback, tscrypto::tsCryptoData& workingKey) = 0;
	virtual bool RegenerateWorkingKey(std::shared_ptr<IKeyVEILSession> session, tscrypto::tsCryptoData& workingKey) = 0;
	virtual bool CanGenerateWorkingKey(std::shared_ptr<IKeyVEILSession> session) = 0;
	virtual bool CanRegenerateWorkingKey(std::shared_ptr<IKeyVEILSession> session) = 0;
};

/*! \endcond */

#endif // __CMSHEADERINTERFACES_H__
/*! @} */
