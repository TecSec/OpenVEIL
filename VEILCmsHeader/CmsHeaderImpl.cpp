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
#include "CmsHeaderImpl.h"
#include "CmsHeaderExtensionImpl.h"

class CmsHeaderExtensionImpl;

using namespace tscrypto;
using namespace Asn1;
using namespace Asn1::CMS;

class HIDDEN CmsHeaderImpl :
	public ICmsHeader, public ICkmPersistable, public tsmod::IObject, public TSHeaderControl, public ICkmOperations, public ICkmJsonPersistable
{
public:
	CmsHeaderImpl(void) :
		m_originalSize(0)
	{
		m_data.clear();
	}
	virtual ~CmsHeaderImpl(void)
	{
		Clear();
	}

	// TSHeaderControl
	virtual void ClearHMAC() override
	{
		m_data.clear_Signature();
	}

	// ICmsCmsHeader
	virtual bool IsProbableHeader(const uint8_t *data, size_t length) override
	{
		if (data == nullptr)
			return false;

		Clear();

		//
		// First do a sanity test to see if this may be a header, and to limit the
		// amount of data processed.  This function may be used with a large encrypted
		// buffer that has a prepended header.  In that case, we do not want to try
		// to process the encrypted data, only the header.
		//
		int tag;
		size_t dataLength, tagLength;
		bool constructed;
		BYTE type;

		if (length < 7)
			return false;

		tagLength = TlvNode::ExtractTagAndLength(tscrypto::tsCryptoData(data, 7), 0, false, false, tag, constructed, type, dataLength);

		if (tag != TlvNode::Tlv_Sequence || type != TlvNode::Type_Universal || !constructed)
			return false;

		if (length < tagLength + dataLength)
			return false;

		length = tagLength + dataLength;
		return FromBytes(tscrypto::tsCryptoData(data, length));
	}
	virtual int GetProbableHeaderLength(const uint8_t *data, size_t length) override
	{
		if (data == nullptr)
			return 0;

		int tag;
		size_t dataLength, tagLength;
		bool constructed;
		BYTE type;

		if (length < 7)
			return 0;

		tagLength = TlvNode::ExtractTagAndLength(tscrypto::tsCryptoData(data, 7), 0, false, false, tag, constructed, type, dataLength);

		if (tag != TlvNode::Tlv_Sequence || type != TlvNode::Type_Universal || !constructed)
			return 0;

		return (int)(tagLength + dataLength);
	}
	virtual void Clear() override;
	virtual int GetHeaderVersion() const override;
	virtual void SetHeaderVersion(int setTo) override;
	virtual int GetCombinerVersion() const override;
	virtual void SetCombinerVersion(int setTo) override;
	virtual tscrypto::tsCryptoData GetCreatorId() const override;
	virtual void SetCreatorId(const tscrypto::tsCryptoData &data) override;
	virtual GUID GetCreatorGuid() const override;
	virtual void SetCreatorGuid(const GUID &data) override;
	virtual tscrypto::tsCryptoString GetCreationDate() const override;
	virtual void SetCreationDate(const tscrypto::tsCryptoString& date) override;
	virtual TS_ALG_ID GetEncryptionAlgorithmID() const override;
	virtual void SetEncryptionAlgorithmID(TS_ALG_ID setTo) override;
	virtual tscrypto::tsCryptoData GetEncryptionAlgorithmOID() const override;
	virtual void SetEncryptionAlgorithmOID(const tscrypto::tsCryptoData &setTo) override;
	virtual CompressionType GetCompressionType() const override;
	virtual void SetCompressionType(CompressionType setTo) override;
	virtual SymmetricPaddingType GetPaddingType() const override;
	virtual void SetPaddingType(SymmetricPaddingType setTo) override;
	virtual TS_ALG_ID GetSignatureAlgorithmId() const override;
	virtual void SetSignatureAlgorithmId(TS_ALG_ID setTo) override;
	virtual tscrypto::tsCryptoData GetSignatureAlgorithmOID() const override;
	virtual void SetSignatureAlgorithmOID(const tscrypto::tsCryptoData &setTo) override;
	virtual tscrypto::tsCryptoData GetSignature() const override;
	virtual bool SetSignature(const tscrypto::tsCryptoData &setTo) override;
	virtual bool SignatureIsMAC() override;
	virtual bool GenerateMAC(const tscrypto::tsCryptoData &symmetricKey, const tscrypto::tsCryptoString& macName) override;
	virtual bool ValidateSignature() override;
	virtual bool ValidateMAC(const tscrypto::tsCryptoData &symmetricKey) override;
	virtual bool GetExtension(const tscrypto::tsCryptoData &oid, std::shared_ptr<ICmsHeaderExtension>& pVal) const override;
	virtual bool RemoveExtension(const tscrypto::tsCryptoData &oid) override;
	virtual size_t GetProtectedExtensionCount() const override;
	virtual bool GetProtectedExtension(size_t index, std::shared_ptr<ICmsHeaderExtension>& pVal) const override;
	virtual bool GetProtectedExtensionByOID(const tscrypto::tsCryptoData &oid, std::shared_ptr<ICmsHeaderExtension>& pVal) const override;
	virtual bool AddProtectedExtension(const tscrypto::tsCryptoData &oid, bool critical, std::shared_ptr<ICmsHeaderExtension>& pVal) override;
	virtual bool RemoveProtectedExtension(std::shared_ptr<ICmsHeaderExtension> pVal) override;
	virtual bool RemoveProtectedExtensionByIndex(size_t index) override;
	virtual bool RemoveProtectedExtensionByOID(const tscrypto::tsCryptoData &oid) override;
	virtual size_t GetUnprotectedExtensionCount() const override;
	virtual bool GetUnprotectedExtension(size_t index, std::shared_ptr<ICmsHeaderExtension>& pVal) const override;
	virtual bool GetUnprotectedExtensionByOID(const tscrypto::tsCryptoData &oid, std::shared_ptr<ICmsHeaderExtension>& pVal) const override;
	virtual bool AddUnprotectedExtension(const tscrypto::tsCryptoData &oid, bool critical, std::shared_ptr<ICmsHeaderExtension>& pVal) override;
	virtual bool RemoveUnprotectedExtension(std::shared_ptr<ICmsHeaderExtension> pVal) override;
	virtual bool RemoveUnprotectedExtensionByIndex(size_t index) override;
	virtual bool RemoveUnprotectedExtensionByOID(const tscrypto::tsCryptoData &oid) override;
	virtual tscrypto::tsCryptoData GetHeaderSigningPublicKey() const override;
	virtual bool SetHeaderSigningPublicKey(const tscrypto::tsCryptoData &encodedKey) override;
	virtual bool ClearHeaderSigningPublicKey() override;
	virtual tscrypto::tsCryptoData GetSignablePortion(bool toGenerate) override;
	virtual tscrypto::tsCryptoData GetIVEC() const override;
	virtual bool SetIVEC(const tscrypto::tsCryptoData &setTo) override;
	virtual bool ClearIVEC() override;
	virtual uint64_t GetFileLength() const override;
	virtual bool SetFileLength(uint64_t setTo) override;
	virtual bool ClearFileLength() override;
	virtual bool GetEnterpriseGuid(GUID &data) const override;
	virtual bool SetEnterpriseGuid(const GUID &setTo) override;
	virtual bool ClearEnterpriseGuid() override;
	virtual tscrypto::tsCryptoData GetDataHash() const override;
	virtual bool SetDataHash(const tscrypto::tsCryptoData &setTo) override;
	virtual tscrypto::tsCryptoData GetDataHashOID() const override
	{
		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderHashExtension> hash;

		if (!(GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V3_FILEHASH_EXT_OID, tscrypto::tsCryptoData::OID), ext)) ||
			!(hash = std::dynamic_pointer_cast<ICmsHeaderHashExtension>(ext)))
		{
			return tscrypto::tsCryptoData();
		}
		return hash->GetHashAlgorithmOID();
	}
	virtual bool SetDataHashOID(const tscrypto::tsCryptoData &setTo) override
	{
		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderHashExtension> hash;

		if (!(GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V3_FILEHASH_EXT_OID, tscrypto::tsCryptoData::OID), ext)))
		{
			if (!(AddProtectedExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V3_FILEHASH_EXT_OID, tscrypto::tsCryptoData::OID), false, ext)))
			{
				LOG(FrameworkError, "Unable to add the Data Hash extension.");
				return false;
			}
		}
		if (!(hash = std::dynamic_pointer_cast<ICmsHeaderHashExtension>(ext)))
		{
			LOG(FrameworkError, "An extension is using the Data Hash extension OID but does not support the proper interface.");
			return false;
		}
		return hash->SetHashAlgorithmOID(setTo);
	}
	virtual bool ClearDataHash() override
	{
		return RemoveExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V3_FILEHASH_EXT_OID, tscrypto::tsCryptoData::OID));
	}
	virtual tscrypto::tsCryptoString GetDataName() const override
	{
		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderNameExtension> name;

		if (!(GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V3_FILENAME_EXT_OID, tscrypto::tsCryptoData::OID), ext)) ||
			!(name = std::dynamic_pointer_cast<ICmsHeaderNameExtension>(ext)))
		{
			return tscrypto::tsCryptoString();
		}
		return name->GetName();
	}
	virtual bool SetDataName(const tscrypto::tsCryptoString& setTo) override
	{
		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderNameExtension> name;

		if (!(GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V3_FILENAME_EXT_OID, tscrypto::tsCryptoData::OID), ext)))
		{
			if (!(AddProtectedExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V3_FILENAME_EXT_OID, tscrypto::tsCryptoData::OID), false, ext)))
			{
				LOG(FrameworkError, "Unable to add the Data Name extension.");
				return false;
			}
		}
		if (!(name = std::dynamic_pointer_cast<ICmsHeaderNameExtension>(ext)))
		{
			LOG(FrameworkError, "An extension is using the Data Name extension OID but does not support the proper interface.");
			return false;
		}
		return name->SetName(setTo);
	}
	virtual bool ClearDataName() override
	{
		return RemoveExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V3_FILENAME_EXT_OID, tscrypto::tsCryptoData::OID));
	}
	virtual size_t GetCryptoGroupCount() const override
	{
		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderCryptoGroupListExtension> cgList;

		if (!(GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_CRYPTOGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext)) ||
			!(cgList = std::dynamic_pointer_cast<ICmsHeaderCryptoGroupListExtension>(ext)))
		{
			return 0;
		}
		return cgList->GetCryptoGroupCount();
	}
	virtual bool AddCryptoGroup(const GUID &cryptoGroupGuid, int *pVal) override
	{
		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderCryptoGroupListExtension> cgList;

		if (!(GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_CRYPTOGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext)))
		{
			if (!(AddProtectedExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_CRYPTOGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), true, ext)))
			{
				LOG(FrameworkError, "Unable to add the CryptoGroup List extension.");
				return false;
			}
		}
		if (!(cgList = std::dynamic_pointer_cast<ICmsHeaderCryptoGroupListExtension>(ext)))
		{
			LOG(FrameworkError, "An extension is using the CryptoGroup List extension OID but does not support the proper interface.");
			return false;
		}
		return cgList->AddCryptoGroup(cryptoGroupGuid, pVal);
	}
	virtual bool GetCryptoGroup(size_t index, std::shared_ptr<ICmsHeaderCryptoGroup>& pVal) override
	{
		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderCryptoGroupListExtension> cgList;

		if (!(GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_CRYPTOGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext)))
		{
			if (!(AddProtectedExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_CRYPTOGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), true, ext)))
			{
				LOG(FrameworkError, "Unable to add the CryptoGroup List extension.");
				return false;
			}
		}
		if (!(cgList = std::dynamic_pointer_cast<ICmsHeaderCryptoGroupListExtension>(ext)))
		{
			LOG(FrameworkError, "An extension is using the CryptoGroup List extension OID but does not support the proper interface.");
			return false;
		}
		return cgList->GetCryptoGroup(index, pVal);
	}
	virtual bool GetCryptoGroupByGuid(const GUID &cryptoGroupGuid, std::shared_ptr<ICmsHeaderCryptoGroup>& pVal) override
	{
		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderCryptoGroupListExtension> cgList;
		std::shared_ptr<ICmsHeaderCryptoGroup> dom;

		pVal.reset();
		if (!(GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_CRYPTOGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext)) ||
			!(cgList = std::dynamic_pointer_cast<ICmsHeaderCryptoGroupListExtension>(ext)))
		{
			return false;
		}
		size_t count = cgList->GetCryptoGroupCount();
		if (count == 0)
			return false;
		for (size_t i = 0; i < count; i++)
		{
			dom.reset();
			if (GetCryptoGroup(i, dom))
			{
				if (dom->GetCryptoGroupGuid() == cryptoGroupGuid)
				{
					pVal = dom;
					return true;
				}
			}
		}
		dom.reset();
		return false;
	}
	virtual bool RemoveCryptoGroup(size_t index) override
	{
		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderCryptoGroupListExtension> cgList;

		if (!(GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_CRYPTOGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext)))
		{
			if (!(AddProtectedExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_CRYPTOGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), true, ext)))
			{
				LOG(FrameworkError, "Unable to add the CryptoGroup List extension.");
				return false;
			}
		}
		if (!(cgList = std::dynamic_pointer_cast<ICmsHeaderCryptoGroupListExtension>(ext)))
		{
			LOG(FrameworkError, "An extension is using the CryptoGroup List extension OID but does not support the proper interface.");
			return false;
		}
		return cgList->RemoveCryptoGroup(index);
	}
	virtual bool RemoveCryptoGroupByGuid(const GUID &cryptoGroupGuid) override
	{
		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderCryptoGroupListExtension> cgList;
		std::shared_ptr<ICmsHeaderCryptoGroup> dom;

		if (!(GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_CRYPTOGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext)) ||
			!(cgList = std::dynamic_pointer_cast<ICmsHeaderCryptoGroupListExtension>(ext)))
		{
			return false;
		}
		size_t count = cgList->GetCryptoGroupCount();
		if (count == 0)
			return false;
		for (size_t i = 0; i < count; i++)
		{
			dom.reset();
			if (GetCryptoGroup(i, dom))
			{
				if (dom->GetCryptoGroupGuid() == cryptoGroupGuid)
				{
					RemoveCryptoGroup(i);
					return true;
				}
			}
		}
		dom.reset();
		return false;
	}
	virtual bool ClearCryptoGroupList() override
	{
		return RemoveExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_CRYPTOGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID));
	}
	virtual bool DuplicateHeader(std::shared_ptr<ICmsHeaderBase>& pVal) override;
	virtual tscrypto::tsCryptoString GetDebugString() override;
	virtual int OriginalHeaderSize() const override;
	virtual bool HasHeaderSigningPublicKey() const override;
	virtual tscrypto::tsCryptoData GetKeyUsageOID() const override
	{
		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderKeyUsageExtension> ku;

		if (!(GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_KEY_USAGE_EXT_OID, tscrypto::tsCryptoData::OID), ext)) ||
			!(ku = std::dynamic_pointer_cast<ICmsHeaderKeyUsageExtension>(ext)))
		{
			return tscrypto::tsCryptoData(TECSEC_CKM7_SCP_KEYS_OID, tscrypto::tsCryptoData::OID);
		}
		return ku->GetKeyUsageOID();
	}
	virtual bool SetKeyUsageOID(const tscrypto::tsCryptoData &setTo) override
	{
		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderKeyUsageExtension> ku;

		if (!(GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_KEY_USAGE_EXT_OID, tscrypto::tsCryptoData::OID), ext)))
		{
			if (!(AddProtectedExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_KEY_USAGE_EXT_OID, tscrypto::tsCryptoData::OID), false, ext)))
			{
				LOG(FrameworkError, "Unable to add the Key Usage extension.");
				return false;
			}
		}
		if (!(ku = std::dynamic_pointer_cast<ICmsHeaderKeyUsageExtension>(ext)))
		{
			LOG(FrameworkError, "An extension is using the Key Usage extension OID but does not support the proper interface.");
			return false;
		}
		return ku->SetKeyUsageOID(setTo);
	}
	virtual int GetKeySizeInBits() const override
	{
		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderKeyUsageExtension> ku;

		if (!(GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_KEY_USAGE_EXT_OID, tscrypto::tsCryptoData::OID), ext)) ||
			!(ku = std::dynamic_pointer_cast<ICmsHeaderKeyUsageExtension>(ext)))
		{
			return 768;
		}
		return ku->GetKeySizeInBits();
	}
	virtual bool SetKeySizeInBits(int setTo) override
	{
		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderKeyUsageExtension> ku;

		if (!(GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_KEY_USAGE_EXT_OID, tscrypto::tsCryptoData::OID), ext)))
		{
			if (!(AddProtectedExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_KEY_USAGE_EXT_OID, tscrypto::tsCryptoData::OID), false, ext)))
			{
				LOG(FrameworkError, "Unable to add the Key Usage extension.");
				return false;
			}
		}
		if (!(ku = std::dynamic_pointer_cast<ICmsHeaderKeyUsageExtension>(ext)))
		{
			LOG(FrameworkError, "An extension is using the Key Usage extension OID but does not support the proper interface.");
			return false;
		}
		return ku->SetKeySizeInBits(setTo);
	}
	virtual bool ClearDataFormat() override
	{
		return RemoveExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_DATA_FORMAT_EXT_OID, tscrypto::tsCryptoData::OID));
	}
	virtual bool SetDataFormat(int blockSize, int algorithmId) override
	{
		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderDataFormatExtension> df;

		if (!(GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_DATA_FORMAT_EXT_OID, tscrypto::tsCryptoData::OID), ext)))
		{
			if (!(AddProtectedExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_DATA_FORMAT_EXT_OID, tscrypto::tsCryptoData::OID), false, ext)))
			{
				LOG(FrameworkError, "Unable to add the Data Format extension.");
				return false;
			}
		}
		if (!(df = std::dynamic_pointer_cast<ICmsHeaderDataFormatExtension>(ext)))
		{
			LOG(FrameworkError, "An extension is using the Data Format extension OID but does not support the proper interface.");
			return false;
		}
		return df->SetBlockSize(blockSize) && df->SetFormatAlgorithm(algorithmId);
	}
	virtual bool GetDataFormat(int &blockSize, int &algorithmId) const override
	{
		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderDataFormatExtension> df;

		if (!(GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_DATA_FORMAT_EXT_OID, tscrypto::tsCryptoData::OID), ext)) ||
			!(df = std::dynamic_pointer_cast<ICmsHeaderDataFormatExtension>(ext)))
		{
			return false;
		}
		blockSize = df->GetBlockSize();
		algorithmId = df->GetFormatAlgorithm();
		return true;
	}
	virtual tscrypto::tsCryptoString GetMimeType() const override
	{
		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderMimeTypeExtension> mt;

		if (!(GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_MIME_TYPE_EXT_OID, tscrypto::tsCryptoData::OID), ext)) ||
			!(mt = std::dynamic_pointer_cast<ICmsHeaderMimeTypeExtension>(ext)))
		{
			return "";
		}
		return mt->GetMimeType();
	}
	virtual bool SetMimeType(const tscrypto::tsCryptoString &setTo) override
	{
		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderMimeTypeExtension> mt;

		if (!(GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_MIME_TYPE_EXT_OID, tscrypto::tsCryptoData::OID), ext)))
		{
			if (!(AddProtectedExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_MIME_TYPE_EXT_OID, tscrypto::tsCryptoData::OID), false, ext)))
			{
				LOG(FrameworkError, "Unable to add the Mime Type extension.");
				return false;
			}
		}
		mt = std::dynamic_pointer_cast<ICmsHeaderMimeTypeExtension>(ext);
		if (!mt)
		{
			LOG(FrameworkError, "An extension is using the Mime Type extension OID but does not support the proper interface.");
			return false;
		}
		return mt->SetMimeType(setTo);
	}
	virtual bool NeedsSession() override
	{
		if (GetSignature().size() > 0)
		{
			// We are probably doing recombine so this function should only return true if all groups require CKM attributes
			// TODO:  Make this function check all AND groups and see if they all use a CKM Attribute item
		}

		// Probably doing Generate so if any group has a CKM attribute then a session is required
		return GetCryptoGroupCount() > 0;
	}
	virtual bool WantsSession() override
	{
		return GetCryptoGroupCount() > 0;
	}
	virtual GUID GetObjectID() override;
	virtual void SetObjectID(const GUID& setTo) override;
	virtual uint32_t PaddedHeaderSize() const override
	{
		if (m_data.exists_PaddedSize())
			return m_data.get_PaddedSize();
		return OriginalHeaderSize();
	}
	virtual void SetPaddedHeaderSize(uint32_t setTo) override
	{
		if (setTo == 0)
			m_data.clear_PaddedSize();
		else
			m_data.set_PaddedSize(setTo);
	}
	//CmsExtension *FindExtension(const tscrypto::tsCryptoData &oid);
	// Added 7.0.35
	virtual bool toBasicRecipe(Asn1::CTS::_POD_CkmRecipe& recipe) override
	{
		std::shared_ptr<ICmsHeaderExtension> headerExt;
		std::shared_ptr<ICmsHeaderCryptoGroup> headerCryptoGroup;
		std::shared_ptr<ICmsHeaderAccessGroupExtension> groupList;
		std::shared_ptr<ICmsHeaderAccessGroup> andGroup;
		std::shared_ptr<ICmsHeaderAttributeGroup> attributeGroup;
		std::shared_ptr<ICmsHeaderAttributeListExtension> attrList;
		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderKeyUsageExtension> ku;
		GUID guidCryptoGroup;
		tscrypto::tsCryptoString tmpStr;
		int ulCKMVersion = 7;
		std::shared_ptr<TlvDocument> otherAGs = TlvDocument::Create();

		recipe.clear();
		PrepareForEncode();

		if (GetCryptoGroupCount() > 1)
			return false;

		if (!(GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_KEY_USAGE_EXT_OID, tscrypto::tsCryptoData::OID), ext)) || !(ku = std::dynamic_pointer_cast<ICmsHeaderKeyUsageExtension>(ext)))
		{
			SetKeyUsageOID(tscrypto::tsCryptoData(TECSEC_CKM7_SCP_KEYS_OID, tscrypto::tsCryptoData::OID));
			SetKeySizeInBits(768);
		}
		recipe.set_bitSize(GetKeySizeInBits());
		recipe.set_keyUsage(GetKeyUsageOID());

		recipe.set_ckmVersion(ulCKMVersion);

		if (GetCryptoGroupCount() > 0)
			GetCryptoGroup(0, headerCryptoGroup);

		if (!!headerCryptoGroup)
		{
			guidCryptoGroup = headerCryptoGroup->GetCryptoGroupGuid();
			recipe.set_cryptoGroupId(guidCryptoGroup);
		}
		bool needsHeaderSigning = HasHeaderSigningPublicKey();
		if (GetObjectID() == GUID_NULL)
		{
			recipe.set_objectId(GUID_NULL);
		}
		else
		{
			recipe.set_objectId(GetObjectID());
		}
		if (!PreprocessGroups())
			return false;

		tscrypto::tsCryptoData headerPub;
		//		bool headerKeyProvided = false;

		headerPub = GetHeaderSigningPublicKey();
		if (headerPub.size() > 0 && headerPub[0] == 4)
		{
			needsHeaderSigning = false;
			//			headerKeyProvided = true;
		}
		else if (headerPub.size() > 0)
		{
			needsHeaderSigning = true;
		}
		else
		{
			headerPub.clear();
		}
		//
		// First initialize for the CKM operation
		//
		recipe.set_publicKey(headerPub);
		recipe.set_sign(needsHeaderSigning);

		if (!GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), headerExt) ||
			!(groupList = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(headerExt)))
		{
			return false;
		}

		//
		// First process all Attribute groups
		//
		for (uint32_t i = 0; i < groupList->GetAccessGroupCount(); i++)
		{
			andGroup.reset();
			if (!groupList->GetAccessGroup(i, andGroup))
			{
				return false;
			}

			attributeGroup.reset();

			switch (andGroup->GetAndGroupType())
			{
			case ag_Attrs:
				if (!!(attributeGroup = std::dynamic_pointer_cast<ICmsHeaderAttributeGroup>(andGroup)))
				{
					size_t attributeCount;
					std::shared_ptr<ICmsHeaderAttribute> hAttribute;
					Asn1::CTS::_POD_Attribute* attributeObj = nullptr;
					Asn1::CTS::_POD_AccessGroup ctsGroup;

					if (!attrList)
					{
						headerExt.reset();
						if (!GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID), headerExt) ||
							!(attrList = std::dynamic_pointer_cast<ICmsHeaderAttributeListExtension>(headerExt)))
						{
							return false;
						}
					}

					attributeCount = attributeGroup->GetAttributeCount();
					if (attributeCount < 1 || attributeCount > 128)
					{
						return false;
					}

					for (size_t k = 0; k < attributeCount; k++)
					{
						hAttribute.reset();
						attributeObj = nullptr;
						if (!attrList->GetAttribute(attributeGroup->GetAttributeIndex(k), hAttribute))
							return false;
						hAttribute->SetKeyVersion(0); // Forcing to 0 - Not needed in the recipe at this time

						Asn1::CTS::_POD_AttributeIdentifier ctsAttrId;

						ctsAttrId.set_id(hAttribute->GetAttributeGUID());
						ctsAttrId.set_version(hAttribute->GetKeyVersion());
						ctsGroup.get_attributes().add(ctsAttrId);
					}
					recipe.get_groups().add(std::move(ctsGroup));
				}
				else
				{
					return false;
				}
				break;
			default:
				return false;
			}
		}
		return true;
	}
	virtual bool fromBasicRecipe(const Asn1::CTS::_POD_CkmRecipe& recipe) override
	{
		std::shared_ptr<ICmsHeaderCryptoGroup> headerCryptoGroup;
		std::shared_ptr<ICmsHeaderExtension> headerExt;
		std::shared_ptr<ICmsHeaderAccessGroupExtension> groupList;
		std::shared_ptr<ICmsHeaderAccessGroup> andGroup;
		std::shared_ptr<ICmsHeaderAttributeGroup> attributeGroup;
		std::shared_ptr<ICmsHeaderAttributeListExtension> attrList;
		//size_t groupIndex = 0;
		int cgIndex = 0;

		Clear();

		BuildExtensionList(m_protectedExtensionList, true);
		BuildExtensionList(m_unprotectedExtensionList, false);

		SetCombinerVersion(recipe.get_ckmVersion());
		if (recipe.get_cryptoGroupId() == GUID_NULL && recipe.get_groups().size() > 0)
			return false;

		if (recipe.get_cryptoGroupId() != GUID_NULL && !this->AddCryptoGroup(recipe.get_cryptoGroupId(), &cgIndex))
			return false;

		SetObjectID(recipe.get_objectId());
		SetKeyUsageOID(recipe.get_keyUsage());
		SetKeySizeInBits(recipe.get_bitSize());
		if (recipe.get_publicKey().size() > 5)
			SetHeaderSigningPublicKey(recipe.get_publicKey());

		//		bool _sign;

		const Asn1::CTS::_POD_CkmRecipe_groups& rGroups = recipe.get_groups();

		if (rGroups.size() > 0)
		{
			if (!AddProtectedExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), true, headerExt))
			{
				if (!GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), headerExt))
					return false;
			}
			if (!(groupList = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(headerExt)))
			{
				return false;
			}
			headerExt.reset();

			if (!AddProtectedExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID), true, headerExt))
			{
				if (!GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID), headerExt))
				{
					return false;
				}
			}
			if (!(attrList = std::dynamic_pointer_cast<ICmsHeaderAttributeListExtension>(headerExt)))
			{
				return false;
			}

			for (size_t i = 0; i < rGroups.size(); i++)
			{
				andGroup.reset();
				attributeGroup.reset();

				if (!groupList->AddAccessGroup(AndGroupType::ag_Attrs, andGroup) ||
					!(attributeGroup = std::dynamic_pointer_cast<ICmsHeaderAttributeGroup>(andGroup)))
					return false;

				const Asn1::CTS::_POD_AccessGroup& ag = rGroups.get_at(i);
				const Asn1::CTS::_POD_AccessGroup_attributes& attrs = ag.get_attributes();

				for (size_t j = 0; j < attrs.size(); j++)
				{
					int idx = findAttributeIndex(attrList, attrs.get_at(j).get_id());

					if (idx == -1)
					{
						std::shared_ptr<ICmsHeaderAttribute> attr;

						idx = attrList->AddAttribute();
						if (!attrList->GetAttribute(idx, attr))
							return false;
						attr->SetAttributeGuid(attrs.get_at(j).get_id());
						attr->SetCryptoGroupNumber(cgIndex);
					}
					attributeGroup->AddAttributeIndex(idx);
				}
			}
		}

		return true;
	}
	virtual tscrypto::tsCryptoString toString(const tscrypto::tsCryptoString& type) override;

	// ICkmPersistable
	virtual tscrypto::tsCryptoData ToBytes() override;
	virtual bool FromBytes(const tscrypto::tsCryptoData &setTo) override;

	// ICkmOperations
	virtual tscrypto::tsCryptoData ComputeHeaderIdentity() override
	{
		std::shared_ptr<Hash> hasher;
		tscrypto::tsCryptoData Empty, hash;

		m_failureReason.clear();
		if (!(hasher = std::dynamic_pointer_cast<Hash>(CryptoFactory(_TS_ALG_ID::TS_ALG_SHA512))) || !hasher->initialize())
		{
			LogError("Invalid hash algorithm");
			return Empty;
		}

		if (HasHeaderSigningPublicKey())
		{
			if (!hasher->update(GetHeaderSigningPublicKey()))
			{
				LogError("Invalid hash algorithm");
				return Empty;
		}
		}
		else
		{
			std::shared_ptr<ICmsHeaderExtension> ext;

			if (!hasher->update(GetCreationDate().ToUTF8Data()))
			{
				LogError("Invalid hash algorithm");
				return Empty;
			}

			ext.reset();
			if (GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V3_IVEC_EXT_OID, tscrypto::tsCryptoData::OID), ext))
			{
				if (!hasher->update(ext->GetOID()) || !hasher->update(ext->GetContents()))
				{
					LogError("Invalid hash algorithm");
					return Empty;
				}
			}

			ext.reset();
			if (GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext))
			{
				if (!hasher->update(ext->GetOID()) || !hasher->update(ext->GetContents()))
				{
					LogError("Invalid hash algorithm");
					return Empty;
				}
			}

			ext.reset();
			if (GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID), ext))
			{
				if (!hasher->update(ext->GetOID()) || !hasher->update(ext->GetContents()))
				{
					LogError("Invalid hash algorithm");
					return Empty;
				}
			}

			ext.reset();
			if (GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_CRYPTOGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext))
			{
				if (!hasher->update(ext->GetOID()) || !hasher->update(ext->GetContents()))
				{
					LogError("Invalid hash algorithm");
					return Empty;
				}
			}
		}
		if (!hasher->finish(hash))
		{
			LogError("Invalid hash algorithm");
			return Empty;
		}
		return hash;
	}
	virtual bool padHeaderToSize(DWORD size) override
	{
		int headerLength;

		RemoveExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V3_SECRYPTM_EXT_OID, tscrypto::tsCryptoData::OID));
		RemoveExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V3_SECRYPTM_EXT_PAD2_OID, tscrypto::tsCryptoData::OID));
		SetPaddedHeaderSize(size);
		headerLength = (int)ToBytes().size();

		m_failureReason.clear();
		if ((DWORD)headerLength > size)
		{
			LogError(tsCryptoString("New header length does not match size [headerLength ").append(headerLength) << ", size " << (uint32_t)size << "]");
			return false;
		}
		return true;
	}
	virtual bool PrepareHeader(CompressionType comp, TS_ALG_ID algorithm, TS_ALG_ID hashAlgorithm, bool SignHeader, bool bindData,
		CMSFileFormatIds DataFormat, bool randomIvec, SymmetricPaddingType paddingType, int blockSize, int64_t fileSize) override
	{
		TSDECLARE_FUNCTIONExt(true);

		tscrypto::tsCryptoData buff;

		m_failureReason.clear();
		SetCompressionType(comp);
		SetEncryptionAlgorithmID(algorithm);
		SetPaddingType(paddingType);
		SetDataHashOID(tscrypto::tsCryptoData(IDtoOID(hashAlgorithm), tscrypto::tsCryptoData::OID));
		SetFileLength(fileSize);
		if (SignHeader)
		{
			buff.resize(65);
		}
		else
			buff.clear();

		SetHeaderSigningPublicKey(buff);
		buff.clear();

		size_t keyBitSize = 0;
		size_t ivecSize = 0;

		// Get the key size
		ivecSize = CryptoIVECSize(algorithm);
		keyBitSize = CryptoKeySize(algorithm);

		// Now adjust for the data hash key size if needed
		std::shared_ptr<MessageAuthenticationCode> mac;

		const char *keySizeOid = TECSEC_CKM7_KEY_AND_IVEC_OID;

		if (hashAlgorithm != _TS_ALG_ID::TS_ALG_INVALID)
		{
			if (!(mac = std::dynamic_pointer_cast<MessageAuthenticationCode>(CryptoFactory(hashAlgorithm))))
			{
				LogError("Invalid data hash detected.");
				return TSRETURN_ERROR(("Returns ~~"), false);
			}
			if (mac->requiresKey())
			{
				int maxKeyLen = (int)mac->maximumKeySizeInBits();

				keySizeOid = TECSEC_CKM7_ENC_MAC_AND_IVEC_OID;
				if (maxKeyLen < 0 || maxKeyLen > 65535) // treat large key size as "unlimited"
				{
					// "unlimited key length"
					keyBitSize += keyBitSize; // use the encryption key size for the mac key
				}
				else if ((size_t)maxKeyLen > keyBitSize)
				{
					keyBitSize += keyBitSize; // use the encryption key size for the mac key
				}
				else
				{
					// use the maximum size if less then key size
					keyBitSize += maxKeyLen;
				}
			}
		}

		// finally adjust for the ivec size
		if (randomIvec)
		{
			if (ivecSize > 0)
			{
				buff.resize(ivecSize);

				if (internalGenerateRandomBits(buff.rawData(), (uint32_t)(ivecSize * 8), true, nullptr, 0))
				{
					SetIVEC(buff);
				}
				buff.clear();
			}
		}
		else
		{
			keyBitSize += ivecSize * 8;
		}

		SetKeySizeInBits((int)keyBitSize);
		SetKeyUsageOID(tscrypto::tsCryptoData(keySizeOid, tscrypto::tsCryptoData::OID));
		if (bindData)
		{
			SetDataHashOID(tscrypto::tsCryptoData(IDtoOID(hashAlgorithm), tscrypto::tsCryptoData::OID));
		}
		else
			ClearDataHash();

		std::shared_ptr<ICmsHeaderExtension> ext;

		SetDataFormat(blockSize, DataFormat);
		SetFileLength(fileSize);
		return TSRETURN(("OK"), true);
	}
	virtual bool GenerateWorkingKey(std::shared_ptr<IKeyVEILSession> session, std::shared_ptr<IKeyGenCallback> callback, tscrypto::tsCryptoData& workingKey) override
	{
		tscrypto::tsCryptoData wk;
		Asn1::CTS::_POD_CkmCombineParameters params;
		std::shared_ptr<EccKey> headerSigning;

		m_failureReason.clear();
		workingKey.clear();

		if (!session)
		{
			LogError("Unable to generate the working key and encrypted data - No session.");
			return false;
		}
		if (!HeaderToCombinerParams_Combine(session->GetProfile(), headerSigning, params))
		{
			LogError("Unable to generate the working key and encrypted data - Cannot convert the header parameters.");
			return false;
		}
		if (!(session->GenerateWorkingKey(params, [this, &callback](Asn1::CTS::_POD_CkmCombineParameters& params, tscrypto::tsCryptoData& wk)->bool {
			if (!CombinerParamsToHeader_Combine(params))
			{
				LogError("CombinerParamsToHeader_Combine failed");
				return false;
			}
			// This call is here to force all changes to be pushed from the helper classes into the main header extensions.
			// THIS CALL MUST BE HERE.  Without it the FinishHeader callback will have incorrect information if it queries the
			// extension objects.
			GetSignablePortion(true);
			if (!!callback && !callback->FinishHeader(wk, std::dynamic_pointer_cast<ICmsHeaderBase>(_me.lock())))
			{
				LogError("callback->FinishHeader failed");
				return false;
			}
			return true;
		}, wk)))
		{
			LogError("Unable to generate the working key and encrypted data - GenerateWorkingKey.");
			if (!session->failureReason().empty())
				LogError("\n" + session->failureReason());
			return false;
		}

		if (params.get_sign() || !!headerSigning)
		{
			const char *oid = "";
			tscrypto::tsCryptoData sig;
			tscrypto::tsCryptoString name;
			std::shared_ptr<Hash> hasher;

			if (!!headerSigning)
			{
				std::shared_ptr<Signer> signer;

				switch (headerSigning->KeySize())
				{
					//case 192: // p192
					//case 224: // p224
				case 256: // p256
					oid = ECDSA_SHA256_OID;
					name = "SIGN-ECC-SHA256";
					break;
				case 384: // p384
					oid = ECDSA_SHA384_OID;
					name = "SIGN-ECC-SHA384";
					break;
				case 521:// p521
					oid = ECDSA_SHA512_OID;
					name = "SIGN-ECC-SHA512";
					break;
				default:
					LogError("Unable to sign header");
					return false;
				}
				SetSignatureAlgorithmOID(tscrypto::tsCryptoData(oid, tscrypto::tsCryptoData::OID));

				tscrypto::tsCryptoData data = GetSignablePortion(true);

				LOG(CkmDevOnly, "Signable Portion " << data);

				if (!(signer = std::dynamic_pointer_cast<Signer>(CryptoFactory(name))))
				{
					LogError("Unable to sign header");
					return false;
				}

				if (!signer->initialize(std::dynamic_pointer_cast<AsymmetricKey>(headerSigning)) || !signer->update(data) || !signer->sign(sig))
				{
					LogError("Unable to sign header");
					return false;
				}
			}
			else
			{
				return false;
				// TODO:  Implement this to handle key generation on card for header signing.
				//switch (header7->GetHeaderSigningPublicKey().size())
				//{
				//	//case 49: // p192
				//	//case 57: // p224
				//case 65: // p256
				//	oid = ECDSA_SHA256_OID;
				//	break;
				//case 97: // p384
				//	oid = ECDSA_SHA384_OID;
				//	break;
				//case 133:// p521
				//	oid = ECDSA_SHA512_OID;
				//	break;
				//default:
				//	LogError("Unable to sign header");
				//	return false;
				//}
				//header7->SetSignatureAlgorithmOID(tscrypto::tsCryptoData(oid, tscrypto::tsCryptoData::OID));
				//
				//tscrypto::tsCryptoData data = header7->GetSignablePortion(true);
				//
				//LOG(CkmDevOnly, "Signable Portion " << data);
				//
				//tscrypto::tsCryptoData hash;
				//
				//switch (header7->GetHeaderSigningPublicKey().size())
				//{
				//	//case 49: // p192
				//	//case 57: // p224
				//case 65: // p256
				//	if (!(hasher = std::dynamic_pointer_cast<Hash>(CryptoFactory("SHA256"))) || !hasher->initialize() || !hasher->update(data) || !hasher->finish(hash))
				//		return false;
				//	break;
				//case 97: // p384
				//	if (!(hasher = std::dynamic_pointer_cast<Hash>(CryptoFactory("SHA384"))) || !hasher->initialize() || !hasher->update(data) || !hasher->finish(hash))
				//		return false;
				//	break;
				//case 133:// p521
				//	if (!(hasher = std::dynamic_pointer_cast<Hash>(CryptoFactory("SHA512"))) || !hasher->initialize() || !hasher->update(data) || !hasher->finish(hash))
				//		return false;
				//	break;
				//default:
				//	LogError("Unable to sign header");
				//	return false;
				//}
				//
				////LOG(DebugDevOnly, "Signable header" << endl << indent << data.ToHexStringWithSpaces() << outdent );
				////LOG(DebugDevOnly, "Hash" << endl << indent << hash.ToHexStringWithSpaces() << outdent );
				//
				//if (!processor->CKM7SignHeaderHash(hash, sig))
				//{
				//	LogError("Unable to sign header");
				//	return false;
				//}
			}
			if (!SetSignature(sig))
			{
				LogError("Unable to save the signature");
				return false;
			}
		}
		else
		{
			if (GetSignatureAlgorithmId() == _TS_ALG_ID::TS_ALG_INVALID)
				SetSignatureAlgorithmId(_TS_ALG_ID::TS_ALG_HMAC_SHA512);
			if (!(GenerateMAC(wk, OIDtoAlgName(IDtoOID(GetSignatureAlgorithmId())))))
			{
				LogError("Header MAC generation failed.");
				return false;
		}
		}
		workingKey = wk;
		return true;
	}
	virtual bool RegenerateWorkingKey(std::shared_ptr<IKeyVEILSession> session, tscrypto::tsCryptoData& workingKey) override
	{
		Asn1::CTS::_POD_CkmCombineParameters params;
		tscrypto::tsCryptoData wk;

		m_failureReason.clear();
		if (!session)
		{
			LogError("Unable to regenerate the working key and encrypted data - No session.");
			return false;
		}
		if (HasHeaderSigningPublicKey())
		{
			if (!ValidateSignature())
			{
				LogError("The header has been modified and is no longer trusted.");
				return false;
			}
		}

		if (!HeaderToCombinerParams_Recombine(session->GetProfile(), params))
		{
			LogError("Unable to regenerate the working key and encrypted data.");
			return false;
		}
		if (!(session->RegenerateWorkingKey(params, wk)))
		{
			LogError("Unable to regenerate the working key and encrypted data.");
			return false;
		}
		if (!HasHeaderSigningPublicKey())
		{
			if (!ValidateMAC(wk))
			{
				LogError("Invalid header detected");
				return false;
			}
		}
		workingKey = wk;
		return true;
	}
	virtual bool CanGenerateWorkingKey(std::shared_ptr<IKeyVEILSession> session) override
	{
		Asn1::CTS::_POD_CkmCombineParameters params;
		std::shared_ptr<EccKey> headerSigning;

		m_failureReason.clear();
		if (!session)
		{
			LogError("Unable to generate the working key and encrypted data - No session.");
			return false;
		}
		if (!HeaderToCombinerParams_Combine(session->GetProfile(), headerSigning, params, true))
		{
			LogError("Unable to generate the working key and encrypted data - Cannot convert the header parameters.");
			return false;
		}
		return true;
	}
	virtual bool CanRegenerateWorkingKey(std::shared_ptr<IKeyVEILSession> session) override
	{
		Asn1::CTS::_POD_CkmCombineParameters params;

		m_failureReason.clear();
		if (!session)
		{
			LogError("Unable to regenerate the working key and encrypted data - No session.");
			return false;
		}
		if (!HeaderToCombinerParams_Recombine(session->GetProfile(), params))
		{
			LogError("Unable to regenerate the working key and encrypted data.");
			return false;
		}
		return true;
	}
	virtual tscrypto::tsCryptoString failureReason() { return m_failureReason; }

protected:
	CmsHeaderImpl(const CmsHeaderImpl &obj);

	//CmsExtension *FindProtectedExtensionByOID(const tscrypto::tsCryptoData &oid);
	void PrepareForEncode();
	void FinalizeAndClearHeaderParts();
	void BuildExtensionList(std::vector< std::shared_ptr< ICmsHeaderExtension> > &list, bool isProtected);

	Asn1::CTS::_POD_Attribute* getAttribute(Asn1::CTS::_POD_CryptoGroup* cg, const GUID& id)
	{
		if (cg->exists_FiefdomList())
		{
			size_t fiefdomCount = cg->get_FiefdomList()->size();
			size_t categoryCount;
			size_t attributeCount;

			for (size_t f = 0; f < fiefdomCount; f++)
			{
				Asn1::CTS::_POD_Fiefdom& fiefdom = cg->get_FiefdomList()->get_at(f);
				if (fiefdom.exists_CategoryList())
				{
					categoryCount = fiefdom.get_CategoryList()->size();
					for (size_t c = 0; c < categoryCount; c++)
					{
						Asn1::CTS::_POD_Category& category = fiefdom.get_CategoryList()->get_at(c);
						if (category.exists_AttributeList())
						{
							attributeCount = category.get_AttributeList()->size();

							for (size_t a = 0; a < attributeCount; a++)
							{
								if (category.get_AttributeList()->get_at(a).get_Id() == id)
									return &category.get_AttributeList()->get_at(a);
							}
						}
					}
				}
			}
		}
		return nullptr;
	}

	bool ComputeKeyVersions(Asn1::CTS::_POD_CryptoGroup *cryptogroup)
	{
		std::shared_ptr<ICmsHeaderAttributeListExtension> attrList;
		std::shared_ptr<ICmsHeaderExtension> headerExt;
		std::shared_ptr<ICmsHeaderAttribute> hAttribute;
		Asn1::CTS::_POD_Attribute* attributeObj = nullptr;
		size_t attributeCount;

		if (!GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID), headerExt) || !(attrList = std::dynamic_pointer_cast<ICmsHeaderAttributeListExtension>(headerExt)))
		{
			if (!headerExt)
				return true;
			return false;
		}
		attributeCount = attrList->GetAttributeCount();
		for (size_t k = 0; k < attributeCount; k++)
		{
			hAttribute.reset();
			attributeObj = nullptr;

			if (!attrList->GetAttribute(k, hAttribute))
				return false;

			attributeObj = getAttribute(cryptogroup, hAttribute->GetAttributeGUID());
			if (attributeObj == nullptr)
				return false;

			hAttribute->SetKeyVersion(attributeObj->get_ForwardVersion());
		}
		return true;
	}

	bool PreprocessGroups()
	{
		std::shared_ptr<ICmsHeaderExtension> headerExt;
		std::shared_ptr<ICmsHeaderAccessGroupExtension> groupList;
		std::shared_ptr<ICmsHeaderAccessGroup> andGroup;
		std::shared_ptr<ICmsHeaderAttributeGroup> attributeGroup;

		if (!GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), headerExt) || !(groupList = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(headerExt)))
		{
			return false;
		}

		for (uint32_t i = 0; i < groupList->GetAccessGroupCount(); i++)
		{
			andGroup.reset();
			if (!groupList->GetAccessGroup(i, andGroup))
			{
				return false;
			}

			attributeGroup.reset();

			switch (andGroup->GetAndGroupType())
			{
			case ag_Attrs:
				// No changes needed at this time
				break;
			default:
				return false;
			}
		}
		return true;
	}

	bool HeaderToCombinerParams_Combine(std::shared_ptr<Asn1::CTS::_POD_Profile> profile, std::shared_ptr<EccKey>& localSigningKey, Asn1::CTS::_POD_CkmCombineParameters& parameters, bool onlyChecking = false)
	{
		std::shared_ptr<ICmsHeaderExtension> headerExt;
		std::shared_ptr<ICmsHeaderCryptoGroup> headerCryptoGroup;
		std::shared_ptr<ICmsHeaderAccessGroupExtension> groupList;
		std::shared_ptr<ICmsHeaderAccessGroup> andGroup;
		std::shared_ptr<ICmsHeaderAttributeGroup> attributeGroup;
		std::shared_ptr<ICmsHeaderAttributeListExtension> attrList;
		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderKeyUsageExtension> ku;
		Asn1::CTS::_POD_CryptoGroup *cg = nullptr;
		GUID guidCryptoGroup;
		GUID memberGuid = GUID_NULL;
		GUID enterpriseGuid = GUID_NULL;
		tscrypto::tsCryptoString tmpStr;
		int ulCKMVersion = 7;
		std::shared_ptr<TlvDocument> otherAGs = TlvDocument::Create();

		parameters.clear();

		if (GetCryptoGroupCount() > 1)
			return false;

		if (!!profile)
		{
			memberGuid = profile->get_MemberId();
			enterpriseGuid = profile->get_EnterpriseId();
		}

		parameters.set_enterpriseId(enterpriseGuid);
		parameters.set_memberId(memberGuid);

		if (!(GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_KEY_USAGE_EXT_OID, tscrypto::tsCryptoData::OID), ext)) || !(ku = std::dynamic_pointer_cast<ICmsHeaderKeyUsageExtension>(ext)))
		{
			SetKeyUsageOID(tscrypto::tsCryptoData(TECSEC_CKM7_SCP_KEYS_OID, tscrypto::tsCryptoData::OID));
			SetKeySizeInBits(768);
		}
		parameters.set_bitSize(GetKeySizeInBits());
		parameters.set_keyUsage(GetKeyUsageOID());

		if (memberGuid != GUID_NULL)
			SetCreatorGuid(memberGuid);
		else
			return false;

		if (enterpriseGuid != GUID_NULL)
			SetEnterpriseGuid(enterpriseGuid);

		SetCombinerVersion(ulCKMVersion);
		parameters.set_ckmVersion(ulCKMVersion);
		parameters.set_creationDate(tscrypto::tsCryptoDate::Now());
		parameters.get_creationDate().GetAsZuluTime(tmpStr);
		SetCreationDate(tmpStr);

		if (GetCryptoGroupCount() > 0)
			GetCryptoGroup(0, headerCryptoGroup);

		if (!!headerCryptoGroup)
		{
			if (!profile || memberGuid == GUID_NULL || enterpriseGuid == GUID_NULL)
				return false;

			guidCryptoGroup = headerCryptoGroup->GetCryptoGroupGuid();
			parameters.set_cryptoGroupId(guidCryptoGroup);
			if (guidCryptoGroup != GUID_NULL)
			{
				if (profile->exists_cryptoGroupList())
				{
					size_t count = profile->get_cryptoGroupList()->size();
					for (size_t i = 0; i < count; i++)
					{
						cg = &profile->get_cryptoGroupList()->get_at(i);
						if (cg->get_Id() == guidCryptoGroup)
							break;
						cg = nullptr;
					}
				}
				if (cg == nullptr)
					return false;
			}
		}
		bool needsHeaderSigning = HasHeaderSigningPublicKey();
		if (cg != nullptr)
		{
			//fiefLevel = fiefdom->GetFiefdomLevel();

			if (!ComputeKeyVersions(cg))
				return false;
		}

		if (GetObjectID() == GUID_NULL)
		{
			GUID tmp;

			xp_CreateGuid(tmp);
			SetObjectID(tmp);
			parameters.set_objectId(tmp);
		}
		else
		{
			parameters.set_objectId(GetObjectID());
		}
		if (!PreprocessGroups())
			return false;

		if (cg != nullptr)
		{
			tscrypto::tsCryptoData headerPub;
			//		bool headerKeyProvided = false;

			headerPub = GetHeaderSigningPublicKey();
			if (headerPub.size() > 0 && headerPub[0] == 4)
			{
				needsHeaderSigning = false;
				//			headerKeyProvided = true;
			}
			else if (headerPub.size() > 0)
			{
				if (!onlyChecking)
				{
					std::shared_ptr<BasicVEILPreferences> prefs = BasicVEILPreferences::Create();
					tscrypto::tsCryptoString alg;

					alg = prefs->getHeaderSigningKeyAlgorithm();
					if (alg.size() == 0)
						alg = "KEY-P256";

					if (!(localSigningKey = std::dynamic_pointer_cast<EccKey>(CryptoFactory(alg))) ||
						!localSigningKey->generateKeyPair())
					{
						return false;
					}
					headerPub = localSigningKey->get_Point();
					SetHeaderSigningPublicKey(headerPub);
				}
				needsHeaderSigning = true;
			}
			else
			{
				headerPub.clear();
			}
			//
			// First initialize for the CKM operation
			//
			parameters.set_publicKey(headerPub);
			parameters.set_sign(needsHeaderSigning);
		}
		else
		{
			return true;
		}

		if (!GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), headerExt) ||
			!(groupList = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(headerExt)))
		{
			return false;
		}

		//
		// First process all Attribute groups
		//
		for (uint32_t i = 0; i < groupList->GetAccessGroupCount(); i++)
		{
			andGroup.reset();
			if (!groupList->GetAccessGroup(i, andGroup))
			{
				return false;
			}

			attributeGroup.reset();

			switch (andGroup->GetAndGroupType())
			{
			case ag_Attrs:
				if (!!(attributeGroup = std::dynamic_pointer_cast<ICmsHeaderAttributeGroup>(andGroup)))
				{
					size_t attributeCount;
					std::shared_ptr<ICmsHeaderAttribute> hAttribute;
					Asn1::CTS::_POD_Attribute* attributeObj = nullptr;
					Asn1::CTS::_POD_AccessGroup ctsGroup;

					if (!attrList)
					{
						headerExt.reset();
						if (!GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID), headerExt) ||
							!(attrList = std::dynamic_pointer_cast<ICmsHeaderAttributeListExtension>(headerExt)))
						{
							return false;
						}
					}

					attributeCount = attributeGroup->GetAttributeCount();
					if (attributeCount < 1 || attributeCount > 128)
					{
						return false;
					}

					for (size_t k = 0; k < attributeCount; k++)
					{
						hAttribute.reset();
						attributeObj = nullptr;
						if (!attrList->GetAttribute(attributeGroup->GetAttributeIndex(k), hAttribute))
							return false;
						attributeObj = getAttribute(cg, hAttribute->GetAttributeGUID());
						if (attributeObj == nullptr)
							return false;
						hAttribute->SetKeyVersion(attributeObj->get_ForwardVersion());

						Asn1::CTS::_POD_AttributeIdentifier ctsAttrId;

						ctsAttrId.set_id(hAttribute->GetAttributeGUID());
						ctsAttrId.set_version(hAttribute->GetKeyVersion());
						ctsGroup.get_attributes().add(ctsAttrId);
					}
					parameters.get_groups().add(std::move(ctsGroup));
				}
				else
				{
					return false;
				}
				break;
			default:
				return false;
			}
		}
		if (otherAGs->DocumentElement()->ChildCount() > 0)
			parameters.set_appendHash(otherAGs->DocumentElement()->InnerData());
		return true;
	}

	bool HeaderToCombinerParams_Recombine(std::shared_ptr<Asn1::CTS::_POD_Profile> profile, Asn1::CTS::_POD_CkmCombineParameters& parameters)
	{
		//HRESULT hr;
		std::shared_ptr<ICmsHeaderExtension> headerExt;
		std::shared_ptr<ICmsHeaderCryptoGroup> headerCryptoGroup;
		std::shared_ptr<ICmsHeaderAccessGroupExtension> groupList;
		std::shared_ptr<ICmsHeaderAccessGroup> andGroup;
		std::shared_ptr<ICmsHeaderAttributeGroup> attributeGroup;
		std::shared_ptr<ICmsHeaderAttributeListExtension> attrList;
		std::shared_ptr<ICmsHeaderExtension> ext;
		std::shared_ptr<ICmsHeaderKeyUsageExtension> ku;
		GUID guidCryptoGroup;
		GUID enterpriseGuid = GUID_NULL;
		std::shared_ptr<TlvDocument> otherAGs = TlvDocument::Create();
		bool foundAGoodGroup = false;
		int attrCountFound;
		Asn1::CTS::_POD_CryptoGroup *cg = nullptr;

		parameters.clear();

		GetEnterpriseGuid(enterpriseGuid);
		parameters.set_enterpriseId(enterpriseGuid);
		parameters.set_memberId(GetCreatorGuid());

		if (GetCryptoGroupCount() > 1)
			return false;

		parameters.set_bitSize(GetKeySizeInBits());
		parameters.set_keyUsage(GetKeyUsageOID());
		parameters.set_ckmVersion(GetCombinerVersion());


		parameters.set_creationDate(tscrypto::tsCryptoDate(GetCreationDate(), tscrypto::tsCryptoDate::Zulu));

		if (GetCryptoGroupCount() > 0)
			GetCryptoGroup(0, headerCryptoGroup);

		if (!!headerCryptoGroup)
		{
			if (!profile || parameters.get_memberId() == GUID_NULL || enterpriseGuid == GUID_NULL)
				return false;

			guidCryptoGroup = headerCryptoGroup->GetCryptoGroupGuid();
			parameters.set_cryptoGroupId(guidCryptoGroup);
			parameters.set_currentVersion(headerCryptoGroup->GetCurrentMaintenanceLevel());
			parameters.set_ephemeralPublic(headerCryptoGroup->GetEphemeralPublic());

			if (guidCryptoGroup != GUID_NULL)
			{
				if (profile->exists_cryptoGroupList())
				{
					size_t count = profile->get_cryptoGroupList()->size();
					for (size_t i = 0; i < count; i++)
					{
						cg = &profile->get_cryptoGroupList()->get_at(i);
						if (cg->get_Id() == guidCryptoGroup)
							break;
						cg = nullptr;
					}
				}
				if (cg == nullptr)
					return false;
			}
		}
		bool needsHeaderSigning = HasHeaderSigningPublicKey();
		parameters.set_sign(needsHeaderSigning);
		parameters.set_publicKey(GetHeaderSigningPublicKey());
		parameters.set_objectId(GetObjectID());

		if (!GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), headerExt) ||
			!(groupList = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(headerExt)))
		{
			return false;
		}

		headerExt.reset();
		if (!GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID), headerExt) ||
			!(attrList = std::dynamic_pointer_cast<ICmsHeaderAttributeListExtension>(headerExt)))
		{
			return false;
		}

		for (size_t i = 0; i < attrList->GetAttributeCount(); i++)
		{
			std::shared_ptr<ICmsHeaderAttribute> hAttribute;

			hAttribute.reset();
			if (attrList->GetAttribute(i, hAttribute))
			{
				if (hAttribute->GetSignature().size() > 0)
				{
					Asn1::CTS::_POD_AttributeSignature sig;
					sig.set_attributeId(hAttribute->GetAttributeGUID());
					sig.set_version(hAttribute->GetKeyVersion());
					sig.set_signature(hAttribute->GetSignature());
					if (!parameters.exists_signatures())
						parameters.set_signatures();
					parameters.get_signatures()->add(sig);
				}
			}
		}

		//
		// First process all Attribute groups
		//
		for (uint32_t i = 0; i < groupList->GetAccessGroupCount(); i++)
		{
			andGroup.reset();
			if (!groupList->GetAccessGroup(i, andGroup))
			{
				return false;
			}

			attributeGroup.reset();

			switch (andGroup->GetAndGroupType())
			{
			case ag_Attrs:
				if (!!(attributeGroup = std::dynamic_pointer_cast<ICmsHeaderAttributeGroup>(andGroup)))
				{
					size_t attributeCount;
					std::shared_ptr<ICmsHeaderAttribute> hAttribute;
					Asn1::CTS::_POD_AccessGroup ctsGroup;

					attributeCount = attributeGroup->GetAttributeCount();
					if (attributeCount < 1 || attributeCount > 128)
					{
						return false;
					}

					ctsGroup.set_encRand(attributeGroup->GetEncryptedRandom());

					attrCountFound = 0;

					for (size_t k = 0; k < attributeCount; k++)
					{
						hAttribute.reset();
						if (!attrList->GetAttribute(attributeGroup->GetAttributeIndex(k), hAttribute))
							return false;

						Asn1::CTS::_POD_AttributeIdentifier ctsAttrId;

						ctsAttrId.set_id(hAttribute->GetAttributeGUID());
						ctsAttrId.set_version(hAttribute->GetKeyVersion());
						ctsGroup.get_attributes().add(ctsAttrId);

						if (!foundAGoodGroup)
						{
							Asn1::CTS::_POD_Attribute* attributeObj = nullptr;

							attributeObj = getAttribute(cg, hAttribute->GetAttributeGUID());
							if (attributeObj != nullptr)
							{
								if (ctsAttrId.get_version() >= attributeObj->get_BackwardVersion() && ctsAttrId.get_version() <= attributeObj->get_ForwardVersion())
									attrCountFound++;
							}
						}
					}
					foundAGoodGroup |= (attrCountFound == attributeCount);
					parameters.get_groups().add(std::move(ctsGroup));
				}
				else
				{
					return false;
				}
				break;
			default:
				return false;
			}
		}
		if (!foundAGoodGroup && cg != nullptr && groupList->GetAccessGroupCount() > 0)
			return false;
		if (otherAGs->DocumentElement()->ChildCount() > 0)
			parameters.set_appendHash(otherAGs->DocumentElement()->InnerData());
		return true;
	}

	bool CombinerParamsToHeader_Combine(Asn1::CTS::_POD_CkmCombineParameters& parameters)
	{
		std::shared_ptr<ICmsHeaderCryptoGroup> headerCryptoGroup;
		std::shared_ptr<ICmsHeaderExtension> headerExt;
		std::shared_ptr<ICmsHeaderAccessGroupExtension> groupList;
		std::shared_ptr<ICmsHeaderAccessGroup> andGroup;
		std::shared_ptr<ICmsHeaderAttributeGroup> attributeGroup;
		std::shared_ptr<ICmsHeaderAttributeListExtension> attrList;
		size_t groupIndex = 0;

		SetCombinerVersion(parameters.get_ckmVersion());
		if (!GetCryptoGroup(0, headerCryptoGroup))
			return false;

		headerCryptoGroup->SetCurrentMaintenanceLevel(parameters.get_currentVersion());
		headerCryptoGroup->SetEphemeralPublic(parameters.get_ephemeralPublic());
		SetCreationDate(parameters.get_creationDate().ToZuluTime());
		SetEnterpriseGuid(parameters.get_enterpriseId());
		SetCreatorGuid(parameters.get_memberId());
		SetObjectID(parameters.get_objectId());

		if (!GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), headerExt) ||
			!(groupList = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(headerExt)))
		{
			return false;
		}
		headerExt.reset();
		if (!GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID), headerExt) ||
			!(attrList = std::dynamic_pointer_cast<ICmsHeaderAttributeListExtension>(headerExt)))
		{
			return false;
		}

		// Transfer the attribute signatures to the header
		if (parameters.exists_signatures())
		{
			for (size_t pi = 0; pi < parameters.get_signatures()->size(); pi++)
				//			for (std::shared_ptr<Asn1DataBaseClass>& s : *parameters.get_signatures()->_list)
			{
				Asn1::CTS::_POD_AttributeSignature& sig = parameters.get_signatures()->get_at(pi);
				size_t count = attrList->GetAttributeCount();
				std::shared_ptr<ICmsHeaderAttribute> hAttribute;
				for (size_t i = 0; i < count; i++)
				{
					hAttribute.reset();
					if (attrList->GetAttribute(i, hAttribute))
					{
						if (hAttribute->GetAttributeGUID() == sig.get_attributeId())
						{
							hAttribute->SetKeyVersion(sig.get_version());
							hAttribute->SetSignature(sig.get_signature());
							break;
						}
					}
				}
			}
		}

		// Now transfer the encrypted random values
		for (uint32_t i = 0; i < groupList->GetAccessGroupCount(); i++)
		{
			andGroup.reset();
			if (!groupList->GetAccessGroup(i, andGroup))
			{
				return false;
			}

			attributeGroup.reset();

			switch (andGroup->GetAndGroupType())
			{
			case ag_Attrs:
				if (!!(attributeGroup = std::dynamic_pointer_cast<ICmsHeaderAttributeGroup>(andGroup)))
				{
					attributeGroup->SetEncryptedRandom(parameters.get_groups().get_at(groupIndex++).get_encRand());
				}
				else
				{
					return false;
				}
				break;
			default:
				return false;
			}
		}
		return true;
	}

	int findAttributeIndex(std::shared_ptr<ICmsHeaderAttributeListExtension> list, const GUID id)
	{
		std::shared_ptr<ICmsHeaderAttribute> attr;

		for (size_t i = 0; i < list->GetAttributeCount(); i++)
		{
			attr.reset();
			if (list->GetAttribute(i, attr))
			{
				if (attr->GetAttributeGUID() == id)
					return (int)i;
			}
		}
		return -1;
	}
	tscrypto::tsCryptoString GetDebugJsonString();

private:
	std::vector< std::shared_ptr< ICmsHeaderExtension > > m_protectedExtensionList;
	std::vector< std::shared_ptr< ICmsHeaderExtension > > m_unprotectedExtensionList;
	mutable _POD_CmsHeaderData m_data;
	int m_originalSize;
	std::shared_ptr<IKeyGenCallback>	m_keyGenCallback;
	tscrypto::tsCryptoString m_failureReason;

	// Inherited via ICkmJsonPersistable
	virtual tscrypto::tsCryptoString ToJSON() override
	{
		tscrypto::tsCryptoData output;

		PrepareForEncode();

		return m_data.toJSON().ToJSON();
	}
	virtual bool FromJSON(const tscrypto::tsCryptoString & setTo) override
	{
		Clear();
		m_data.clear();

		if (!m_data.fromJSON(setTo))
			return false;

		// TODO:  Json Not sure if this will work
		if (m_data.get_OID().ToOIDString() != TECSEC_CMS_HEADER)
		{
			Clear();
			return false;
		}
		BuildExtensionList(m_protectedExtensionList, true);
		BuildExtensionList(m_unprotectedExtensionList, false);

		m_originalSize = 0;

		return true;
	}
	void LogError(tscrypto::tsCryptoString error, ...)
	{
		va_list args;
		tscrypto::tsCryptoString msg;

		if (error == NULL)
			return;
		va_start(args, error);
		msg.FormatArg(error, args);
		va_end(args);
		LOG(DebugError, msg);
		m_failureReason << msg;
	}
};


void CmsHeaderImpl::Clear()
{
	FinalizeAndClearHeaderParts();
	m_data.clear();
	m_data.set_CreationDate(tscrypto::tsCryptoDate::GetCurrentTime());
	m_data.set_CombinerVersion(7);
}

int CmsHeaderImpl::GetHeaderVersion() const
{
	return m_data.get_Version();
}

void CmsHeaderImpl::SetHeaderVersion(int setTo)
{
	ClearHMAC();
	m_data.set_Version(setTo);
}

int CmsHeaderImpl::GetCombinerVersion() const
{
	return m_data.get_CombinerVersion();
}

void CmsHeaderImpl::SetCombinerVersion(int setTo)
{
	ClearHMAC();
	m_data.set_CombinerVersion(setTo);
}

tscrypto::tsCryptoData CmsHeaderImpl::GetCreatorId() const
{
	return m_data.get_WhoCreated().get_SubjectId();
}

void CmsHeaderImpl::SetCreatorId(const tscrypto::tsCryptoData &data)
{
	m_data.get_WhoCreated().set_selectedItem(_POD_CmsHeaderData_WhoCreated::Choice_SubjectId);
	m_data.get_WhoCreated().set_SubjectId(data);
}

GUID CmsHeaderImpl::GetCreatorGuid() const
{
	return m_data.get_WhoCreated().get_SubjectGuid();
}

void CmsHeaderImpl::SetCreatorGuid(const GUID &data)
{
	m_data.get_WhoCreated().set_selectedItem(_POD_CmsHeaderData_WhoCreated::Choice_SubjectGuid);
	m_data.get_WhoCreated().set_SubjectGuid(data);
}

tscrypto::tsCryptoString CmsHeaderImpl::GetCreationDate() const
{
	return m_data.get_CreationDate().ToZuluTime();
}

void CmsHeaderImpl::SetCreationDate(const tscrypto::tsCryptoString& date)
{
	tscrypto::tsCryptoDate dt;

	dt.SetDateTimeFromZulu(date);
	m_data.set_CreationDate(dt);
}

static TS_ALG_ID getEncryptionAlgorithmAsId(_POD_CmsHeaderData& data)
{
	switch (data.get_EncAlg().get_selectedItem())
	{
	case _POD_CmsHeaderData_EncAlg::Choice_EncryptionAlgorithmId: // ID
		return data.get_EncAlg().get_EncryptionAlgorithmId();
	case _POD_CmsHeaderData_EncAlg::Choice_EncryptionAlgorithm: // AlgorithmIdentifier
		return OIDtoID(data.get_EncAlg().get_EncryptionAlgorithm().get_oid().ToOIDString());
	default:
		return _TS_ALG_ID::TS_ALG_INVALID;
	}
}
static tscrypto::tsCryptoData getEncryptionAlgorithmAsOID(_POD_CmsHeaderData& data)
{
	switch (data.get_EncAlg().get_selectedItem())
	{
	case _POD_CmsHeaderData_EncAlg::Choice_EncryptionAlgorithmId: // ID
		return tscrypto::tsCryptoData(IDtoOID(data.get_EncAlg().get_EncryptionAlgorithmId()), tscrypto::tsCryptoData::OID);
	case _POD_CmsHeaderData_EncAlg::Choice_EncryptionAlgorithm: // AlgorithmIdentifier
		return data.get_EncAlg().get_EncryptionAlgorithm().get_oid();
	default:
		return tscrypto::tsCryptoData();
	}
}
static tscrypto::TS_ALG_ID getSignatureAlgorithmAsId(_POD_CmsHeaderData& data)
{
	if (!data.exists_SignatureAlgorithm())
		return _TS_ALG_ID::TS_ALG_INVALID;

	return OIDtoID(data.get_SignatureAlgorithm()->get_oid().ToOIDString());
}
static tscrypto::tsCryptoData getSignatureAlgorithmAsOID(_POD_CmsHeaderData& data)
{
	if (data.exists_SignatureAlgorithm())
		return data.get_SignatureAlgorithm()->get_oid();
	return tscrypto::tsCryptoData();
}
static void setSignatureAlgorithmId(_POD_CmsHeaderData& data, tscrypto::TS_ALG_ID id)
{
	_POD_AlgorithmIdentifier ai;
	ai.set_oid(IDtoOID(id));
	data.set_SignatureAlgorithm(ai);
}
TS_ALG_ID CmsHeaderImpl::GetEncryptionAlgorithmID() const
{
	return getEncryptionAlgorithmAsId(m_data);
}

void CmsHeaderImpl::SetEncryptionAlgorithmID(TS_ALG_ID setTo)
{
	m_data.get_EncAlg().set_selectedItem(_POD_CmsHeaderData_EncAlg::Choice_EncryptionAlgorithmId);
	m_data.get_EncAlg().set_EncryptionAlgorithmId(setTo);
}

tscrypto::tsCryptoData CmsHeaderImpl::GetEncryptionAlgorithmOID() const
{
	return getEncryptionAlgorithmAsOID(m_data);
}

void CmsHeaderImpl::SetEncryptionAlgorithmOID(const tscrypto::tsCryptoData &setTo)
{
	m_data.get_EncAlg().set_selectedItem(_POD_CmsHeaderData_EncAlg::Choice_EncryptionAlgorithm);
	m_data.get_EncAlg().get_EncryptionAlgorithm().set_oid(setTo);
	m_data.get_EncAlg().get_EncryptionAlgorithm().clear_Parameter();
}

CompressionType CmsHeaderImpl::GetCompressionType() const
{
	return (CompressionType)m_data.get_Compression();
}

void CmsHeaderImpl::SetCompressionType(CompressionType setTo)
{
	m_data.set_Compression(setTo);
}

SymmetricPaddingType CmsHeaderImpl::GetPaddingType() const
{
	return (SymmetricPaddingType)m_data.get_Padding();
}

void CmsHeaderImpl::SetPaddingType(SymmetricPaddingType setTo)
{
	m_data.set_Padding(setTo);
}

TS_ALG_ID CmsHeaderImpl::GetSignatureAlgorithmId() const
{
	return (TS_ALG_ID)getSignatureAlgorithmAsId(m_data);
}

void CmsHeaderImpl::SetSignatureAlgorithmId(TS_ALG_ID setTo)
{
	setSignatureAlgorithmId(m_data, setTo);
}

tscrypto::tsCryptoData CmsHeaderImpl::GetSignatureAlgorithmOID() const
{
	return getSignatureAlgorithmAsOID(m_data);
}

void CmsHeaderImpl::SetSignatureAlgorithmOID(const tscrypto::tsCryptoData &setTo)
{
	_POD_AlgorithmIdentifier alg;

	alg.set_oid(setTo);
	m_data.clear_SignatureAlgorithm();
	m_data.set_SignatureAlgorithm(alg);
}

tscrypto::tsCryptoData CmsHeaderImpl::GetSignature() const
{
	if (!m_data.exists_Signature())
		return tsCryptoData();
	return *m_data.get_Signature();
}

bool CmsHeaderImpl::SetSignature(const tscrypto::tsCryptoData &setTo)
{
	m_data.set_Signature(setTo);
	return true;
}

tscrypto::tsCryptoData CmsHeaderImpl::GetSignablePortion(bool toGenerate)
{
	tscrypto::tsCryptoData output;

	if (toGenerate)
		PrepareForEncode();

	if (!m_data.Encode_Signable(output))
	{
		LOG(FrameworkError, "An error occurred while creating the data blob to sign");
		return tscrypto::tsCryptoData();
	}
	return output;
}

bool CmsHeaderImpl::SignatureIsMAC()
{
	tscrypto::tsCryptoString oid;

	if (m_data.exists_SignatureAlgorithm())
	{
		oid = getSignatureAlgorithmAsOID(m_data).ToOIDString();
	}
	if (oid.size() < 3)
	{
		LOG(FrameworkError, "Header MAC algorithm is not set");
		return false;
	}
	std::shared_ptr<MessageAuthenticationCode> mac;
	std::shared_ptr<AlgorithmInfo> info;

	if (!(mac = std::dynamic_pointer_cast<MessageAuthenticationCode>(CryptoFactory(oid))) ||
		!(info = std::dynamic_pointer_cast<AlgorithmInfo>(mac)))
	{
		return false;
	}
	return true;
}

bool CmsHeaderImpl::GenerateMAC(const tscrypto::tsCryptoData &symmetricKey, const tscrypto::tsCryptoString& macName)
{
	if (macName == NULL || macName[0] == 0)
	{
		LOG(FrameworkError, "Invalid MAC Name");
		return false;
	}

	std::shared_ptr<MessageAuthenticationCode> mac;
	std::shared_ptr<AlgorithmInfo> info;

	if (!(mac = std::dynamic_pointer_cast<MessageAuthenticationCode>(CryptoFactory(macName))) ||
		!(info = std::dynamic_pointer_cast<AlgorithmInfo>(mac)))
	{
		LOG(FrameworkError, "Unable to create the MAC algorithm.");
		return false;
	}
	// Force the correct signature algorithm here
	SetSignatureAlgorithmOID(tscrypto::tsCryptoData(info->AlgorithmOID(), tscrypto::tsCryptoData::OID));

	tscrypto::tsCryptoData signature;
	tscrypto::tsCryptoData signablePortion;

	signablePortion = GetSignablePortion(true);
#ifdef _DEBUG
	LOG(CkmCrypto, tscrypto::endl << tscrypto::endl << signablePortion.ToHexDump() << tscrypto::endl);
	LOG(CkmCrypto, "Key = " << symmetricKey.ToHexStringWithSpaces());
#endif
	if (signablePortion.size() == 0)
	{
		LOG(FrameworkError, "An error occurred while creating the data blob to sign");
		return false;
	}

	if (!mac->isUsableKey(symmetricKey))
	{
		LOG(FrameworkError, "The specified key is not usable in this MAC algorithm");
		return false;
	}
	if (!mac->initialize(symmetricKey))
	{
		LOG(FrameworkError, "The specified key is not usable in this MAC algorithm");
		return false;
	}
	if (!mac->update(signablePortion) || !mac->finish(signature))
	{
		LOG(FrameworkError, "An error occurred while generating the MAC");
		return false;
	}
	m_data.set_Signature(signature);
	return true;
}

bool CmsHeaderImpl::ValidateSignature()
{
	std::shared_ptr<Signer> signer;
	std::shared_ptr<EccKey> key;
	tscrypto::tsCryptoString oid;

	if (m_data.exists_SignatureAlgorithm())
	{
		oid = getSignatureAlgorithmAsOID(m_data).ToOIDString();
	}
	if (oid.size() < 3)
	{
		LOG(FrameworkError, "Header signature algorithm is not set");
		return false;
	}

	tscrypto::tsCryptoData pubKey = GetHeaderSigningPublicKey();
	tscrypto::tsCryptoString keyName;

	switch (pubKey.size())
	{
		//case 49:
		//    keyName = "KEY-P192";
		//    break;
		//case 57:
		//    keyName = "KEY-P224";
		//    break;
	case 65:
		keyName = "KEY-P256";
		break;
	case 97:
		keyName = "KEY-P384";
		break;
	case 133:
		keyName = "KEY-P521";
		break;
	default:
		LOG(FrameworkError, "Header signature key is invalid");
		return false;
	}

	if (!(signer = std::dynamic_pointer_cast<Signer>(CryptoFactory(oid))))
	{
		LOG(FrameworkError, "Unable to create the signature algorithm.");
		return false;
	}
	if (!(key = std::dynamic_pointer_cast<EccKey>(CryptoFactory(keyName))))
	{
		LOG(FrameworkError, "Unable to create the signature algorithm.");
		return false;
	}

	if (!key->set_Point(pubKey))
	{
		LOG(FrameworkError, "The Header signing key is invalid");
		return false;
	}

	tscrypto::tsCryptoData signable = GetSignablePortion(false);

	if (signable.size() == 0)
	{
		LOG(FrameworkError, "An error occurred while creating the data blob to sign");
		return false;
	}

	//CkmDebugHex(DBG_DEV_ONLY, signable.c_str(), signable.size(), "signable portion");

	if (!signer->initialize(std::dynamic_pointer_cast<AsymmetricKey>(key)) || !signer->update(signable) || !signer->verify(GetSignature()))
	{
		LOG(FrameworkError, "The header signature is not valid");
		return false;
	}

	return true;
}

bool CmsHeaderImpl::ValidateMAC(const tscrypto::tsCryptoData &symmetricKey)
{
	tscrypto::tsCryptoString oid;

	if (m_data.exists_SignatureAlgorithm())
	{
		oid = getSignatureAlgorithmAsOID(m_data).ToOIDString();
	}
	if (oid.size() < 3)
	{
		LOG(FrameworkError, "Header MAC algorithm is not set");
		return false;
	}
	std::shared_ptr<MessageAuthenticationCode> mac;
	std::shared_ptr<AlgorithmInfo> info;

	if (!(mac = std::dynamic_pointer_cast<MessageAuthenticationCode>(CryptoFactory(oid))) ||
		!(info = std::dynamic_pointer_cast<AlgorithmInfo>(mac)))
	{
		LOG(FrameworkError, "Unable to create the MAC algorithm.");
		return false;
	}

	tscrypto::tsCryptoData signable = GetSignablePortion(false);
#ifdef _DEBUG
	LOG(CkmCrypto, tscrypto::endl << tscrypto::endl << signable.ToHexDump() << tscrypto::endl);
	LOG(CkmCrypto, "Key = " << symmetricKey.ToHexStringWithSpaces());
#endif
	tscrypto::tsCryptoData signature;

	if (signable.size() == 0)
	{
		LOG(FrameworkError, "An error occurred while creating the data blob to verify");
		return false;
	}

	if (!mac->isUsableKey(symmetricKey))
	{
		LOG(FrameworkError, "The specified key is not usable in this MAC algorithm");
		return false;
	}
	if (!mac->initialize(symmetricKey))
	{
		LOG(FrameworkError, "The specified key is not usable in this MAC algorithm");
		return false;
	}
	if (!mac->update(signable) || !mac->finish(signature) || signature != GetSignature())
	{
		LOG(FrameworkError, "An error occurred while verifying the MAC");
		return false;
	}
	return true;
}

bool CmsHeaderImpl::GetExtension(const tscrypto::tsCryptoData &oid, std::shared_ptr<ICmsHeaderExtension>& pVal) const
{
	std::shared_ptr<ICmsHeaderExtension> ext;

	if (GetProtectedExtensionByOID(oid, ext))
	{
		pVal = ext;
		return true;
	}
	ext.reset();
	if (GetUnprotectedExtensionByOID(oid, ext))
	{
		pVal = ext;
		return true;
	}
	return false;
}

bool CmsHeaderImpl::RemoveExtension(const tscrypto::tsCryptoData &oid)
{
	if (RemoveProtectedExtensionByOID(oid) || RemoveUnprotectedExtensionByOID(oid))
		return true;
	return false;
}

size_t CmsHeaderImpl::GetProtectedExtensionCount() const
{
	return m_protectedExtensionList.size();
}

bool CmsHeaderImpl::GetProtectedExtension(size_t index, std::shared_ptr<ICmsHeaderExtension>& pVal) const
{
	size_t count = GetProtectedExtensionCount();

	pVal.reset();
	if (index >= count)
		return false;
	pVal = m_protectedExtensionList[index];
	return !!pVal;
}

bool CmsHeaderImpl::GetProtectedExtensionByOID(const tscrypto::tsCryptoData &oid, std::shared_ptr<ICmsHeaderExtension>& pVal) const
{
	size_t count;

	pVal.reset();
	count = m_protectedExtensionList.size();
	for (size_t i = 0; i < count; i++)
	{
		if (m_protectedExtensionList[i]->GetOID() == oid)
		{
			pVal = m_protectedExtensionList[i];
			return !!pVal;
		}
	}
	return false;
}

bool CmsHeaderImpl::AddProtectedExtension(const tscrypto::tsCryptoData &oid, bool critical, std::shared_ptr<ICmsHeaderExtension>& pVal)
{
	std::shared_ptr<ICmsHeaderExtension> ext;
	std::shared_ptr<ICmsHeaderExtension> extImpl;

	pVal.reset();

	if (GetExtension(oid, ext))
		return false;

	ext.reset();

	_POD_CmsExtension extData;

	extData.set_OID(oid);
	extData.set_Critical(critical);

	extImpl = CreateHeaderExtensionObject(std::dynamic_pointer_cast<ICmsHeader>(_me.lock()), extData);
	m_protectedExtensionList.push_back(extImpl);

	pVal = extImpl;
	return !!pVal;
}

bool CmsHeaderImpl::RemoveProtectedExtension(std::shared_ptr<ICmsHeaderExtension> pVal)
{
	if (pVal == NULL)
		return false;

	tscrypto::tsCryptoData oid = pVal->GetOID();

	m_protectedExtensionList.erase(std::remove_if(m_protectedExtensionList.begin(), m_protectedExtensionList.end(), [&oid](std::shared_ptr<ICmsHeaderExtension>& ext)->bool { return ext->GetOID() == oid; }), m_protectedExtensionList.end());
	return false;
}

bool CmsHeaderImpl::RemoveProtectedExtensionByIndex(size_t index)
{
	size_t count = m_protectedExtensionList.size();

	if (index >= count)
		return false;

	auto it = m_protectedExtensionList.begin();
	std::advance(it, index);
	m_protectedExtensionList.erase(it);
	return true;
}

bool CmsHeaderImpl::RemoveProtectedExtensionByOID(const tscrypto::tsCryptoData &oid)
{
	m_protectedExtensionList.erase(std::remove_if(m_protectedExtensionList.begin(), m_protectedExtensionList.end(), [&oid](std::shared_ptr<ICmsHeaderExtension>& ext)->bool { return ext->GetOID() == oid; }), m_protectedExtensionList.end());
	return true;
}

size_t CmsHeaderImpl::GetUnprotectedExtensionCount() const
{
	return m_unprotectedExtensionList.size();
}

bool CmsHeaderImpl::GetUnprotectedExtension(size_t index, std::shared_ptr<ICmsHeaderExtension>& pVal) const
{
	size_t count = GetUnprotectedExtensionCount();

	pVal.reset();

	if (index >= count)
		return false;
	pVal = m_unprotectedExtensionList[index];
	return !!pVal;
}

bool CmsHeaderImpl::GetUnprotectedExtensionByOID(const tscrypto::tsCryptoData &oid, std::shared_ptr<ICmsHeaderExtension>& pVal) const
{
	size_t count;

	pVal.reset();

	count = m_unprotectedExtensionList.size();
	for (size_t i = 0; i < count; i++)
	{
		if (m_unprotectedExtensionList[i]->GetOID() == oid)
		{
			pVal = m_unprotectedExtensionList[i];
			return !!pVal;
		}
	}
	return false;
}

bool CmsHeaderImpl::AddUnprotectedExtension(const tscrypto::tsCryptoData &oid, bool critical, std::shared_ptr<ICmsHeaderExtension>& pVal)
{
	std::shared_ptr<ICmsHeaderExtension> ext;
	std::shared_ptr<ICmsHeaderExtension> extImpl;

	pVal.reset();

	if (GetExtension(oid, ext))
		return false;

	ext.reset();

	_POD_CmsExtension extData;

	extData.set_OID(oid);
	extData.set_Critical(critical);

	extImpl = CreateHeaderExtensionObject(std::dynamic_pointer_cast<ICmsHeader>(_me.lock()), extData);
	m_unprotectedExtensionList.push_back(extImpl);

	pVal = extImpl;
	return !!pVal;
}

bool CmsHeaderImpl::RemoveUnprotectedExtension(std::shared_ptr<ICmsHeaderExtension> pVal)
{
	if (!pVal)
		return false;

	tscrypto::tsCryptoData oid = pVal->GetOID();

	size_t count = m_unprotectedExtensionList.size();

	for (size_t i = 0; i < count; i++)
	{
		if (m_unprotectedExtensionList[i]->GetOID() == oid)
		{
			auto it = m_unprotectedExtensionList.begin();
			std::advance(it, i);
			m_unprotectedExtensionList.erase(it);
			return true;
		}
	}
	return false;
}

bool CmsHeaderImpl::RemoveUnprotectedExtensionByIndex(size_t index)
{
	size_t count = m_unprotectedExtensionList.size();

	if (index >= count)
		return false;

	auto it = m_unprotectedExtensionList.begin();
	std::advance(it, index);
	m_unprotectedExtensionList.erase(it);
	return true;
}

bool CmsHeaderImpl::RemoveUnprotectedExtensionByOID(const tscrypto::tsCryptoData &oid)
{
	m_unprotectedExtensionList.erase(std::remove_if(m_unprotectedExtensionList.begin(), m_unprotectedExtensionList.end(), [&oid](std::shared_ptr<ICmsHeaderExtension>& ext)->bool { return ext->GetOID() == oid; }), m_unprotectedExtensionList.end());
	return true;
}

bool CmsHeaderImpl::DuplicateHeader(std::shared_ptr<ICmsHeaderBase>& pVal)
{
	tscrypto::tsCryptoData tmp = ToBytes();
	pVal = ::TopServiceLocator()->get_instance<ICmsHeader>("/CmsHeader");
	return pVal->FromBytes(tmp);
}

int CmsHeaderImpl::OriginalHeaderSize() const
{
	return m_originalSize;
}

GUID CmsHeaderImpl::GetObjectID()
{
	return m_data.get_objectId();
}

void CmsHeaderImpl::SetObjectID(const GUID& setTo)
{
	ClearHMAC();
	m_data.set_objectId(setTo);
}


void CmsHeaderImpl::FinalizeAndClearHeaderParts()
{
	size_t count = m_protectedExtensionList.size();
	std::shared_ptr<IHeaderPart> part;

	m_data.clear_ProtectedExtensions();
	m_data.clear_UnprotectedExtensions();

	for (size_t i = 0; i < count; i++)
	{
		part.reset();
		part = std::dynamic_pointer_cast<IHeaderPart>(m_protectedExtensionList[i]);
		if (!!part)
		{
			part->Destroy();
		}
	}
	part.reset();
	m_protectedExtensionList.clear();

	count = m_unprotectedExtensionList.size();
	for (size_t i = 0; i < count; i++)
	{
		part.reset();
		part = std::dynamic_pointer_cast<IHeaderPart>(m_unprotectedExtensionList[i]);
		if (!!part)
		{
			part->Destroy();
		}
	}
	part.reset();
	m_unprotectedExtensionList.clear();
}

void CmsHeaderImpl::PrepareForEncode()
{
	size_t count = m_protectedExtensionList.size();
	std::shared_ptr<IHeaderPart> part;

	m_data.clear_ProtectedExtensions();
	m_data.clear_UnprotectedExtensions();

	std::shared_ptr<ICmsHeaderExtension> ext;
	std::shared_ptr<ICmsHeaderKeyUsageExtension> ku;

	if (m_data.get_WhoCreated().get_selectedItem() == 0)
		SetCreatorGuid(GUID_NULL);

	if (m_data.get_EncAlg().get_selectedItem() == 0)
		SetEncryptionAlgorithmID(_TS_ALG_ID::TS_ALG_AES_GCM_256);

	if (!(GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_KEY_USAGE_EXT_OID, tscrypto::tsCryptoData::OID), ext)) ||
		!(ku = std::dynamic_pointer_cast<ICmsHeaderKeyUsageExtension>(ext)))
	{
		SetKeyUsageOID(tscrypto::tsCryptoData(TECSEC_CKM7_SCP_KEYS_OID, tscrypto::tsCryptoData::OID));
		SetKeySizeInBits(768);
	}
	if (getEncryptionAlgorithmAsId(m_data) == _TS_ALG_ID::TS_ALG_INVALID)
	{
		m_data.get_EncAlg().set_selectedItem(_POD_CmsHeaderData_EncAlg::Choice_EncryptionAlgorithmId);
		m_data.get_EncAlg().set_EncryptionAlgorithmId(_TS_ALG_ID::TS_ALG_AES_GCM_256);
	}
	//tscrypto::tsCryptoData oid = m_data.getEncryptionAlgorithmAsOID();
	//if (oid.size() > 0)
	//    SetEncryptionAlgorithmOID(oid);
	m_data.set_OID(TECSEC_CMS_HEADER);
	if (m_data.get_CreationDate().GetStatus() != tscrypto::tsCryptoDate::valid)
	{
		m_data.set_CreationDate(tscrypto::tsCryptoDate::Now());
	}
	for (size_t i = 0; i < count; i++)
	{
		part.reset();
		part = std::dynamic_pointer_cast<IHeaderPart>(m_protectedExtensionList[i]);
		if (!!part)
		{
			part->PrepareForEncode(m_data, ProtectedExtension);
		}
	}
	if (GetKeyUsageOID().size() == 0)
	{

	}
	count = m_unprotectedExtensionList.size();
	for (size_t i = 0; i < count; i++)
	{
		part.reset();
		part = std::dynamic_pointer_cast<IHeaderPart>(m_unprotectedExtensionList[i]);
		if (!!part)
		{
			part->PrepareForEncode(m_data, UnprotectedExtension);
		}
	}
}

void CmsHeaderImpl::BuildExtensionList(std::vector< std::shared_ptr< ICmsHeaderExtension> > &list, bool isProtected)
{
	int count;
	_POD_CmsExtension *ext;

	list.clear();

	if (isProtected)
	{
		if (!m_data.exists_ProtectedExtensions())
			m_data.set_ProtectedExtensions();
		count = (int)m_data.get_ProtectedExtensions()->size();
	}
	else
	{
		if (!m_data.exists_UnprotectedExtensions())
			m_data.set_UnprotectedExtensions();
		count = (int)m_data.get_UnprotectedExtensions()->size();
	}
	for (int i = 0; i < count; i++)
	{
		if (isProtected)
		{
			ext = &m_data.get_ProtectedExtensions()->get_at(i);
		}
		else
		{
			ext = &m_data.get_UnprotectedExtensions()->get_at(i);
		}
		std::shared_ptr<ICmsHeaderExtension> ptr = CreateHeaderExtensionObject(std::dynamic_pointer_cast<ICmsHeader>(_me.lock()), *ext);
		list.push_back(ptr);
	}
}

tscrypto::tsCryptoData CmsHeaderImpl::ToBytes()
{
	tscrypto::tsCryptoData output;

	PrepareForEncode();

	if (!m_data.Encode(output))
		return tscrypto::tsCryptoData();
	return output;
}

bool CmsHeaderImpl::FromBytes(const tscrypto::tsCryptoData &setTo)
{
	Clear();
	m_data.clear();

	if (!m_data.Decode(setTo))
	{
		return false;
	}
	if (m_data.get_OID().ToOIDString() != TECSEC_CMS_HEADER)
	{
		Clear();
		return false;
	}
	BuildExtensionList(m_protectedExtensionList, true);
	BuildExtensionList(m_unprotectedExtensionList, false);

	int tag;
	size_t dataLength, tagLength;
	bool constructed;
	BYTE type;

	tagLength = TlvNode::ExtractTagAndLength(setTo, 0, false, false, tag, constructed, type, dataLength);
	m_originalSize = (int)(tagLength + dataLength);

	return true;
}

tscrypto::tsCryptoData CmsHeaderImpl::GetHeaderSigningPublicKey() const
{
	std::shared_ptr<ICmsHeaderExtension> ext;

	if (!GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_SIGN_KEY_EXT_OID, tscrypto::tsCryptoData::OID), ext))
		return tscrypto::tsCryptoData();

	return ext->GetContents();
}

bool CmsHeaderImpl::HasHeaderSigningPublicKey() const
{
	std::shared_ptr<ICmsHeaderExtension> ext;

	if (!GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_SIGN_KEY_EXT_OID, tscrypto::tsCryptoData::OID), ext))
		return false;

	return true;
}

bool CmsHeaderImpl::SetHeaderSigningPublicKey(const tscrypto::tsCryptoData &encodedKey)
{
	std::shared_ptr<ICmsHeaderExtension> ext;

	if (encodedKey.size() < 5)
		return false;

	if (!GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_SIGN_KEY_EXT_OID, tscrypto::tsCryptoData::OID), ext))
	{
		if (!AddProtectedExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_SIGN_KEY_EXT_OID, tscrypto::tsCryptoData::OID), true, ext))
			return false;
	}
	ext->SetContents(encodedKey);
	return true;
}

bool CmsHeaderImpl::ClearHeaderSigningPublicKey()
{
	return RemoveExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_SIGN_KEY_EXT_OID, tscrypto::tsCryptoData::OID));
}

tscrypto::tsCryptoData CmsHeaderImpl::GetIVEC() const
{
	std::shared_ptr<ICmsHeaderExtension> ext;

	if (!GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V3_IVEC_EXT_OID, tscrypto::tsCryptoData::OID), ext))
		return tscrypto::tsCryptoData();
	return ext->GetContents();
}

bool CmsHeaderImpl::SetIVEC(const tscrypto::tsCryptoData &setTo)
{
	if (setTo.size() < 5)
		return false;

	std::shared_ptr<ICmsHeaderExtension> ext;

	if (!GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V3_IVEC_EXT_OID, tscrypto::tsCryptoData::OID), ext))
	{
		if (!AddProtectedExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V3_IVEC_EXT_OID, tscrypto::tsCryptoData::OID), true, ext))
			return false;
	}
	ext->SetContents(setTo);
	return true;
}

bool CmsHeaderImpl::ClearIVEC()
{
	return RemoveExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V3_IVEC_EXT_OID, tscrypto::tsCryptoData::OID));
}

uint64_t CmsHeaderImpl::GetFileLength() const
{
	std::shared_ptr<ICmsHeaderExtension> ext;
	std::shared_ptr<ICmsHeaderLengthExtension> length;

	if (!(GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V3_FILELENGTH_EXT_OID, tscrypto::tsCryptoData::OID), ext)) ||
		!(length = std::dynamic_pointer_cast<ICmsHeaderLengthExtension>(ext)))
	{
		return 0;
	}
	return length->GetLength();
}

bool CmsHeaderImpl::SetFileLength(uint64_t setTo)
{
	std::shared_ptr<ICmsHeaderExtension> ext;
	std::shared_ptr<ICmsHeaderLengthExtension> length;

	if (!(GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V3_FILELENGTH_EXT_OID, tscrypto::tsCryptoData::OID), ext)))
	{
		if (!(AddProtectedExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V3_FILELENGTH_EXT_OID, tscrypto::tsCryptoData::OID), false, ext)))
		{
			LOG(FrameworkError, "Unable to add the File Length extension.");
			return false;
		}
	}
	if (!(length = std::dynamic_pointer_cast<ICmsHeaderLengthExtension>(ext)))
	{
		LOG(FrameworkError, "An extension is using the File Length OID but does not support the proper interface.");
		return false;
	}
	return length->SetLength(setTo);
}

bool CmsHeaderImpl::ClearFileLength()
{
	return RemoveExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V3_FILELENGTH_EXT_OID, tscrypto::tsCryptoData::OID));
}

bool CmsHeaderImpl::GetEnterpriseGuid(GUID &data) const
{
	std::shared_ptr<ICmsHeaderExtension> ext;
	std::shared_ptr<ICmsHeaderIssuerExtension> issuer;

	if (!(GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ISSUER_EXT_OID, tscrypto::tsCryptoData::OID), ext)) ||
		!(issuer = std::dynamic_pointer_cast<ICmsHeaderIssuerExtension>(ext)))
	{
		return false;
	}
	data = issuer->GetIssuerGuid();
	return true;
}

bool CmsHeaderImpl::SetEnterpriseGuid(const GUID &setTo)
{
	std::shared_ptr<ICmsHeaderExtension> ext;
	std::shared_ptr<ICmsHeaderIssuerExtension> issuer;

	if (!(GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ISSUER_EXT_OID, tscrypto::tsCryptoData::OID), ext)))
	{
		if (!(AddProtectedExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ISSUER_EXT_OID, tscrypto::tsCryptoData::OID), false, ext)))
		{
			LOG(FrameworkError, "Unable to add the File Length extension.");
			return false;
		}
	}
	if (!(issuer = std::dynamic_pointer_cast<ICmsHeaderIssuerExtension>(ext)))
	{
		LOG(FrameworkError, "An extension is using the Issuer OID but does not support the proper interface.");
		return false;
	}
	return issuer->SetIssuerGuid(setTo);
}

bool CmsHeaderImpl::ClearEnterpriseGuid()
{
	return RemoveExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ISSUER_EXT_OID, tscrypto::tsCryptoData::OID));
}

tscrypto::tsCryptoData CmsHeaderImpl::GetDataHash() const
{
	std::shared_ptr<ICmsHeaderExtension> ext;
	std::shared_ptr<ICmsHeaderHashExtension> hash;

	if (!(GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V3_FILEHASH_EXT_OID, tscrypto::tsCryptoData::OID), ext)) ||
		!(hash = std::dynamic_pointer_cast<ICmsHeaderHashExtension>(ext)))
	{
		return tscrypto::tsCryptoData();
	}
	return hash->GetHash();
}

bool CmsHeaderImpl::SetDataHash(const tscrypto::tsCryptoData &setTo)
{
	std::shared_ptr<ICmsHeaderExtension> ext;
	std::shared_ptr<ICmsHeaderHashExtension> hash;

	if (!(GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V3_FILEHASH_EXT_OID, tscrypto::tsCryptoData::OID), ext)))
	{
		if (!(AddProtectedExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V3_FILEHASH_EXT_OID, tscrypto::tsCryptoData::OID), false, ext)))
		{
			LOG(FrameworkError, "Unable to add the Data Hash extension.");
			return false;
		}
	}
	if (!(hash = std::dynamic_pointer_cast<ICmsHeaderHashExtension>(ext)))
	{
		LOG(FrameworkError, "An extension is using the Data Hash OID but does not support the proper interface.");
		return false;
	}
	return hash->SetHash(setTo);
}

static const char *GetCompressionTypeString(int compressType)
{
	switch (compressType)
	{
	case 0:
		return "None";
	case 1:
		return "zLib";
	case 2:
		return "BZ2";
	default:
		return "unknown";
	}
}

/*
static const char *GetAlgorithmString(int alg)
{
	switch (alg)
	{
	case TS_ALG_DES_CBC:
		return " - DES CBC";
	case TS_ALG_DES_ECB:
		return " - DES ECB";
	case TS_ALG_DES3_TWOKEY_CBC:
		return " - 3DES 2 Key CBC";
	case TS_ALG_DES3_TWOKEY_ECB:
		return " - 3DES 2 Key ECB";
	case TS_ALG_DES3_THREEKEY_CBC:
		return " - 3DES 3 Key CBC";
	case TS_ALG_DES3_THREEKEY_ECB:
		return " - 3DES 3 Key ECB";
	case TS_ALG_PSQUARED:
		return " - P2";
	case TS_ALG_AES_CTR_256:
		return " - AES CTR 256";
	case TS_ALG_AES_CBC_256:
		return " - AES CBC 256";
	case TS_ALG_AES_ECB_256:
		return " - AES ECB 256";
	case TS_ALG_AES_CTR_192:
		return " - AES CTR 192";
	case TS_ALG_AES_CBC_192:
		return " - AES CBC 192";
	case TS_ALG_AES_ECB_192:
		return " - AES ECB 192";
	case TS_ALG_AES_CTR_128:
		return " - AES CTR 128";
	case TS_ALG_AES_CBC_128:
		return " - AES CBC 128";
	case TS_ALG_AES_ECB_128:
		return " - AES ECB 128";
	case TS_ALG_RC2_ECB:
		return " - RC2 ECB";
	case TS_ALG_RC2_CBC:
		return " - RC2 CBC";
	case TS_ALG_RC4:
		return " - RC4";
	case TS_ALG_DH:
		return " - DH";
	case TS_ALG_DSA:
		return " - DSA";
	case TS_ALG_DSA_SHA1:
		return " - DSA Sha1";
	case TS_ALG_DSA_SHA256:
		return " - DSA Sha 256";
	case TS_ALG_DSA_SHA512:
		return " - DSA Sha 512";
	case TS_ALG_RSA_PKCS_v15:
		return " - RSA Pkcs";
	case TS_ALG_RSA_SHA1_v15:
		return " - RSA Sha1";
	case TS_ALG_RSA_MD5_v15:
		return " - RSA MD5";
	case TS_ALG_RSA_SHA256_v15:
		return " - RSA Sha256";
	case TS_ALG_RSA_SHA384_v15:
		return " - RSA Sha384";
	case TS_ALG_RSA_SHA512_v15:
		return " - RSA Sha512";
	case TS_ALG_RSA_SHA224_v15:
		return " - RSA Sha224";
	case TS_ALG_RSA:
		return " - RSA";
	case TS_ALG_SHA1:
		return " - Sha1";
	case TS_ALG_MD5:
		return " - MD5";
	case TS_ALG_SHA256:
		return " - Sha256";
	case TS_ALG_SHA384:
		return " - Sha384";
	case TS_ALG_SHA512:
		return " - Sha512";
	case TS_ALG_SHA224:
		return " - Sha224";
	case TS_ALG_HMAC_SHA1:
		return " - HMAC Sha1";
	case TS_ALG_HMAC_MD5:
		return " - HMAC MD5";
	case TS_ALG_HMAC_SHA256:
		return " - HMAC Sha256";
	case TS_ALG_HMAC_SHA384:
		return " - HMAC Sha384";
	case TS_ALG_HMAC_SHA512:
		return " - HMAC Sha512";
	case TS_ALG_HMAC_SHA224:
		return " - HMAC Sha224";
	case TS_ALG_CKM:
		return " - CKM";
	case TS_ALG_SYM_CKM_256:
		return " - CKM Sym256";
	case TS_ALG_MISC:
		return " - Misc";
	default:
		return " - unknown";
	}
}
*/

static const char *GetPaddingString(SymmetricPaddingType padType)
{
	switch (padType)
	{
	case _SymmetricPaddingType::padding_None:
		return "None";
	case _SymmetricPaddingType::padding_Pkcs5:
		return "Pkcs #5";
	case _SymmetricPaddingType::padding_GP03:
		return "GlobalPlatform SCP03";
	case _SymmetricPaddingType::padding_Zeros:
		return "00's";
	case _SymmetricPaddingType::padding_FFs:
		return "FF's";
	default:
		return "unknown";
	}
}

static const char *DataFormatString(int dataFormat)
{
	switch (dataFormat)
	{
	case 0:
		return "Not set";
	case TS_FORMAT_CMS_CT_HASHED:
		return "Ciphertext hashed";
	case TS_FORMAT_CMS_PT_HASHED:
		return "Plaintext hashed";
	case TS_FORMAT_CMS_ENC_AUTH:
		return "Encrypted and Authenticated data";
	default:
		return "unknown";
	}
}

static tscrypto::tsCryptoString formatHex(const tscrypto::tsCryptoData &data, int pad)
{
	tscrypto::tsCryptoString tmp, output;
	tscrypto::tsCryptoData part;
	int bytesPerLine = (79 - pad) / 2;
	size_t offset = 0;

	while (offset < data.size())
	{
		if (offset > 0)
		{
			tmp.clear();
			tmp.resize(pad, ' ');
			tmp.prepend("\n");
		}
		part = data.substring(offset, bytesPerLine);
		if (part.size() == 0)
			break;
		offset += part.size();
		tmp += part.ToHexString();
		output += tmp;
	}

	return output;
}


tscrypto::tsCryptoString CmsHeaderImpl::GetDebugString()
{
	std::shared_ptr<ICmsHeaderExtension> ext;
	std::shared_ptr<ICmsHeaderExtension> ext2;
	tscrypto::tsCryptoData value;
	tscrypto::tsCryptoString tmp;
	tscrypto::tsCryptoString output;
	char buff[512];
	GUID guid;
	size_t len;

	uint64_t fileLen = GetFileLength();

	if (fileLen > 0)
	{
		TsSnPrintf(buff, sizeof(buff), "Original file length:  %lld\n", fileLen);
		output += buff;
	}
	output << "Object ID:             " << TSGuidToString(GetObjectID()) << tscrypto::endl;
	TsSnPrintf(buff, sizeof(buff), "Header length:         %d\n", OriginalHeaderSize());
	output += buff;
	TsSnPrintf(buff, sizeof(buff), "Padded Header length:  %d\n", PaddedHeaderSize());
	output += buff;

	if (GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V3_SECRYPTM_EXT_OID, tscrypto::tsCryptoData::OID), ext) &&
		GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V3_SECRYPTM_EXT_PAD2_OID, tscrypto::tsCryptoData::OID), ext2))
	{
	}
	len = 0;
	if (!!ext)
		len = ext->ToBytes().size();
	if (!!ext2)
		len += ext2->ToBytes().size();
	if (len > 0)
	{
		TsSnPrintf(buff, sizeof(buff), "   with internal padding of     %d bytes\n", len);
		output += buff;
	}

	value = GetDataName();
	if (value.size() > 0)
	{
		TsSnPrintf(buff, sizeof(buff), "Original file name:    %s\n", value.ToUtf8String().c_str());
		output += buff;
	}


	int blocksize, dataFormat;
	if (GetDataFormat(blocksize, dataFormat))
	{
		TsSnPrintf(buff, sizeof(buff), "Block size:            %d\n", blocksize);
		output += buff;
		TsSnPrintf(buff, sizeof(buff), "Data Format:           %s\n", DataFormatString(dataFormat));
		output += buff;
	}

	value = GetDataHashOID();
	if (value.size() > 0)
	{
		TsSnPrintf(buff, sizeof(buff), "Data Hash algorithm:   %s\n", OIDtoAlgName(value.ToOIDString()).c_str());
		output += buff;
		TsSnPrintf(buff, sizeof(buff), "File hash:             %s\n", formatHex(GetDataHash(), 23).c_str());
		output += buff;
	}


	TsSnPrintf(buff, sizeof(buff), "\nHeader Type:           CKM 7\n");
	output += buff;
	TsSnPrintf(buff, sizeof(buff), "Header Version:        %d\n", GetHeaderVersion());
	output += buff;
	TsSnPrintf(buff, sizeof(buff), "Combiner Version:      %d\n", GetCombinerVersion());
	output += buff;
	output += "\n";
	if (!GetEnterpriseGuid(guid))
		guid = GUID_NULL;
	TSGuidToString(guid, tmp);
	TsSnPrintf(buff, sizeof(buff), "Enterprise Guid:       %s\n", tmp.c_str());
	output += buff;
	guid = GetCreatorGuid();
	TSGuidToString(guid, tmp);
	TsSnPrintf(buff, sizeof(buff), "Creator Guid:          %s\n", tmp.c_str());
	output += buff;
	TsSnPrintf(buff, sizeof(buff), "Creation Date:         %s\n", GetCreationDate().c_str());
	output += buff;

	TsSnPrintf(buff, sizeof(buff), "Header protection:     %s\n", OIDtoAlgName(GetSignatureAlgorithmOID().ToOIDString()).c_str());
	output += buff;
	if (HasHeaderSigningPublicKey())
	{
		TsSnPrintf(buff, sizeof(buff), "Header signing public: %s\n\n", formatHex(GetHeaderSigningPublicKey(), 23).c_str());
		output += buff;
	}

	TsSnPrintf(buff, sizeof(buff), "Algorithm:             %s\n", OIDtoAlgName(GetEncryptionAlgorithmOID().ToOIDString()).c_str());
	output += buff;
	TsSnPrintf(buff, sizeof(buff), "Compression:           %d - %s\n", GetCompressionType(), GetCompressionTypeString(GetCompressionType()));
	output += buff;
	TsSnPrintf(buff, sizeof(buff), "Padding:               %d - %s\n", GetPaddingType(), GetPaddingString(GetPaddingType()));
	output += buff;
	if (GetMimeType().size() > 0)
	{
		TsSnPrintf(buff, sizeof(buff), "MIME Type:             %s\n", GetMimeType().c_str());
		output += buff;
	}
	TsSnPrintf(buff, sizeof(buff), "\n");
	output += buff;

	std::shared_ptr<ICmsHeaderAccessGroupExtension> groupList;
	std::shared_ptr<ICmsHeaderAttributeListExtension> attrList;
	std::shared_ptr<ICmsHeaderCryptoGroupListExtension> cryptoGroupList;

	ext.reset();
	if (GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_CRYPTOGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext) &&
		!!(cryptoGroupList = std::dynamic_pointer_cast<ICmsHeaderCryptoGroupListExtension>(ext)))
	{
		TsSnPrintf(buff, sizeof(buff), "CryptoGroup count:    %d", GetCryptoGroupCount());
		output += buff;

		for (uint32_t i = 0; i < GetCryptoGroupCount(); i++)
		{
			std::shared_ptr<ICmsHeaderCryptoGroup> hCg;

			hCg.reset();
			if (GetCryptoGroup(i, hCg))
			{
				tscrypto::tsCryptoString tmp;

				TsSnPrintf(buff, sizeof(buff), "\n    CryptoGroup number %d\n", i);
				output += buff;
				TsSnPrintf(buff, sizeof(buff), "    maintenance level: %d\n", hCg->GetCurrentMaintenanceLevel());
				output += buff;
				guid = hCg->GetCryptoGroupGuid();
				TSGuidToString(guid, tmp);
				TsSnPrintf(buff, sizeof(buff), "    CryptoGroup Guid: %s\n", tmp.c_str());
				output += buff;
				if (hCg->GetEphemeralPublic().size() > 0)
				{
					TsSnPrintf(buff, sizeof(buff), "    Ephemeral Public:  %s\n", formatHex(hCg->GetEphemeralPublic(), 23).c_str());
					output += buff;
				}
			}
			else
			{
				TsSnPrintf(buff, sizeof(buff), "    CryptoGroup number %d was not in the header\n", i);
				output += buff;
			}
		}
		TsSnPrintf(buff, sizeof(buff), "\n");
		output += buff;
	}
	ext.reset();

	if (GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID), ext) &&
		!!(attrList = std::dynamic_pointer_cast<ICmsHeaderAttributeListExtension>(ext)))
	{
		std::shared_ptr<ICmsHeaderAttribute> attr;

		TsSnPrintf(buff, sizeof(buff), "Attribute count:    %d", attrList->GetAttributeCount());
		output += buff;

		for (uint32_t i = 0; i < attrList->GetAttributeCount(); i++)
		{
			attr.reset();

			if (attrList->GetAttribute(i, attr))
			{
				guid = attr->GetAttributeGUID();
				TSGuidToString(guid, tmp);
				TsSnPrintf(buff, sizeof(buff), "\n    Attribute ID:     %s\n", tmp.c_str());
				output += buff;
				TsSnPrintf(buff, sizeof(buff), "    CryptoGroup Number: %d\n", attr->GetCryptoGroupNumber());
				output += buff;
				TsSnPrintf(buff, sizeof(buff), "    Key Version:        %d\n", attr->GetKeyVersion());
				output += buff;
				if (attr->GetSignature().size() > 0)
				{
					TsSnPrintf(buff, sizeof(buff), "    Signature:          %s\n", formatHex(attr->GetSignature(), 23).c_str());
					output += buff;
				}
			}
			else
			{
				TsSnPrintf(buff, sizeof(buff), "    Attribute number %d was not in the header\n", i);
				output += buff;
			}
		}
		TsSnPrintf(buff, sizeof(buff), "\n");
		output += buff;
	}
	ext.reset();
	if (GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext) &&
		!!(groupList = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(ext)))
	{
		TsSnPrintf(buff, sizeof(buff), "Access group count:  %d", groupList->GetAccessGroupCount());
		output += buff;
		for (uint32_t i = 0; i < groupList->GetAccessGroupCount(); i++)
		{
			std::shared_ptr<ICmsHeaderAccessGroup>	     group;
			std::shared_ptr<ICmsHeaderAttributeGroup>   attrs;

			group.reset();

			if (!groupList->GetAccessGroup(i, group))
			{
				TsSnPrintf(buff, sizeof(buff), "\n    Unable to retrieve access group %d\n\n", i);
				output += buff;
			}
			else
			{
				TsSnPrintf(buff, sizeof(buff), "\n    Access group number:   %d\n", i);
				output += buff;
				attrs.reset();

				if (!!(attrs = std::dynamic_pointer_cast<ICmsHeaderAttributeGroup>(group)))
				{
					TsSnPrintf(buff, sizeof(buff), "        Attribute list:\n");
					output += buff;
					for (uint32_t k = 0; k < attrs->GetAttributeCount(); k++)
					{
						if (k == 0)
						{
							TsSnPrintf(buff, sizeof(buff), "            ");
							output += buff;
						}
						else
						{
							TsSnPrintf(buff, sizeof(buff), ", ");
							output += buff;
						}
						TsSnPrintf(buff, sizeof(buff), "%d", attrs->GetAttributeIndex(k));
						output += buff;
					}
					TsSnPrintf(buff, sizeof(buff), "\n");
					output += buff;
				}
				else
				{
					TsSnPrintf(buff, sizeof(buff), "        Unknown item:\n");
					output += buff;
				}
			}
		}
	}

	output += "\n";

	if (HasHeaderSigningPublicKey())
	{
		if (ValidateSignature())
			output += "Signature Valid\n";
		else
			output += "ERROR:  Header signature INVALID\n";
	}

	return output;
}
tscrypto::tsCryptoString CmsHeaderImpl::GetDebugJsonString()
{
	std::shared_ptr<ICmsHeaderExtension> ext;
	std::shared_ptr<ICmsHeaderExtension> ext2;
	tscrypto::tsCryptoData value;
	tscrypto::tsCryptoString tmp;
	tscrypto::JSONObject output;
	GUID guid;
	size_t len;

	uint64_t fileLen = GetFileLength();

	if (fileLen > 0)
	{
		output.add("originalFileLength", (int64_t)fileLen);
	}
	output
		.add("objectId", TSGuidToString(GetObjectID()))
		.add("headerLength", (int64_t)OriginalHeaderSize())
		.add("paddedHeaderLength", (int64_t)PaddedHeaderSize())
		;

	if (GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V3_SECRYPTM_EXT_OID, tscrypto::tsCryptoData::OID), ext) &&
		GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V3_SECRYPTM_EXT_PAD2_OID, tscrypto::tsCryptoData::OID), ext2))
	{
	}
	len = 0;
	if (!!ext)
		len = ext->ToBytes().size();
	if (!!ext2)
		len += ext2->ToBytes().size();
	if (len > 0)
	{
		output.add("internalPaddingLength", (int64_t)len);
	}

	value = GetDataName();
	if (value.size() > 0)
	{
		output.add("originalFileName", value.ToUtf8String());
	}


	int blocksize, dataFormat;
	if (GetDataFormat(blocksize, dataFormat))
	{
		output
			.add("blockSize", (int64_t)blocksize)
			.add("dataFormat", tsCryptoString(DataFormatString(dataFormat)))
			;
	}

	value = GetDataHashOID();
	if (value.size() > 0)
	{
		output
			.add("dataHashAlgorithm", OIDtoAlgName(value.ToOIDString()))
			.add("fileHash", GetDataHash().ToHexStringWithSpaces())
			;
	}

	if (!GetEnterpriseGuid(guid))
		guid = GUID_NULL;

	output
		.add("headerType", "CKM 7")
		.add("headerVersion", (int64_t)GetHeaderVersion())
		.add("combinerVersion", (int64_t)GetCombinerVersion())
		.add("enterpriseGuid", ToString()(guid))
		;
	guid = GetCreatorGuid();
	output
		.add("creatorGuid", ToString()(guid))
		.add("creationDate", GetCreationDate())
		.add("headerProtection", OIDtoAlgName(GetSignatureAlgorithmOID().ToOIDString()))
		;

	if (HasHeaderSigningPublicKey())
	{
		output.add("headerSigningPublic", GetHeaderSigningPublicKey().ToHexStringWithSpaces());
	}

	output
		.add("algorithm", OIDtoAlgName(GetEncryptionAlgorithmOID().ToOIDString()))
		.add("compression", tsCryptoString(GetCompressionTypeString(GetCompressionType())))
		.add("padding", tsCryptoString(GetPaddingString(GetPaddingType())))
		;
	if (GetMimeType().size() > 0)
	{
		output.add("MIMEtype", GetMimeType());
	}

	std::shared_ptr<ICmsHeaderAccessGroupExtension> groupList;
	std::shared_ptr<ICmsHeaderAttributeListExtension> attrList;
	std::shared_ptr<ICmsHeaderCryptoGroupListExtension> cryptoGroupList;

	ext.reset();
	if (GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_CRYPTOGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext) &&
		!!(cryptoGroupList = std::dynamic_pointer_cast<ICmsHeaderCryptoGroupListExtension>(ext)))
	{
		output.createArrayField("cryptoGroups");

		for (uint32_t i = 0; i < GetCryptoGroupCount(); i++)
		{
			std::shared_ptr<ICmsHeaderCryptoGroup> hCg;

			hCg.reset();
			if (GetCryptoGroup(i, hCg))
			{
				tscrypto::JSONObject cg;

				guid = hCg->GetCryptoGroupGuid();

				cg
					.add("number", (int64_t)i)
					.add("maintenanceLevel", (int64_t)hCg->GetCurrentMaintenanceLevel())
					.add("groupGuid", ToString()(guid))
					;

				if (hCg->GetEphemeralPublic().size() > 0)
				{
					cg.add("ephemeralPublic", hCg->GetEphemeralPublic().ToHexStringWithSpaces());
				}
				output.add("cryptoGroups", cg);
			}
		}
	}
	ext.reset();

	if (GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID), ext) &&
		!!(attrList = std::dynamic_pointer_cast<ICmsHeaderAttributeListExtension>(ext)))
	{
		std::shared_ptr<ICmsHeaderAttribute> attr;

		output.createArrayField("attributes");

		for (uint32_t i = 0; i < attrList->GetAttributeCount(); i++)
		{
			attr.reset();

			if (attrList->GetAttribute(i, attr))
			{
				tscrypto::JSONObject jAttr;

				guid = attr->GetAttributeGUID();

				jAttr
					.add("index", (int64_t)i)
					.add("attributeId", ToString()(guid))
					.add("cryptogroupNumber", (int64_t)attr->GetCryptoGroupNumber())
					.add("keyVersion", (int64_t)attr->GetKeyVersion())
					;
				if (attr->GetSignature().size() > 0)
				{
					jAttr.add("signature", attr->GetSignature().ToHexStringWithSpaces());
				}
				output.add("attributes", jAttr);
			}
		}
	}
	ext.reset();
	if (GetExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext) &&
		!!(groupList = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(ext)))
	{
		output.createArrayField("accessGroups");
		for (uint32_t i = 0; i < groupList->GetAccessGroupCount(); i++)
		{
			std::shared_ptr<ICmsHeaderAccessGroup>	     group;
			std::shared_ptr<ICmsHeaderAttributeGroup>   attrs;

			group.reset();

			if (groupList->GetAccessGroup(i, group))
			{
				JSONObject g;

				g.add("groupNumber", (int64_t)i);

				attrs.reset();

				if (!!(attrs = std::dynamic_pointer_cast<ICmsHeaderAttributeGroup>(group)))
				{
					g.createArrayField("indexList");
					g.add("type", "Attributes");

					for (uint32_t k = 0; k < attrs->GetAttributeCount(); k++)
					{
						g.add("indexList", (int64_t)attrs->GetAttributeIndex(k));
					}
				}
				else
				{
					g.add("type", "Unknown");
				}
				output.add("accessGroups", g);
			}
		}
	}

	if (HasHeaderSigningPublicKey())
	{
		if (ValidateSignature())
			output.add("validity", "Signature valid");
		else
			output.add("validity", "Signature INVALID");
	}

	return output.ToJSON();
}

tscrypto::tsCryptoString CmsHeaderImpl::toString(const tscrypto::tsCryptoString& type)
{
	if (TsStriCmp(type.c_str(), "JSONRECIPE") == 0)
	{
		Asn1::CTS::_POD_CkmRecipe recipe;

		if (!toBasicRecipe(recipe))
			return "";
		return recipe.toJSON().ToJSON();
	}
	else if (TsStriCmp(type.c_str(), "JSONDEBUG") == 0)
	{
		return GetDebugJsonString();
	}
	else
	{
		return GetDebugString();
	}
}

tsmod::IObject* CreateCmsHeaderObject()
{
	return dynamic_cast<tsmod::IObject*>(new CmsHeaderImpl());
}
