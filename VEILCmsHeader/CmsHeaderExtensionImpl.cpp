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
#include "CmsHeaderAndGroupImpl.h"
#include "CmsHeaderFiefdomImpl.h"
#include "CmsHeaderAttributeImpl.h"

class CmsHeaderExtensionImpl : public ICmsHeaderExtension, public ICmsHeaderIvecExtension, public ICmsHeaderSecryptMExtension,
	public ICmsHeaderLengthExtension, public ICmsHeaderHashExtension, public ICmsHeaderNameExtension,
	public ICmsHeaderCryptoGroupListExtension, public ICmsHeaderAccessGroupExtension, public ICmsHeaderIssuerExtension,
	public ICmsHeaderAttributeListExtension, public ICmsHeaderPublicKeyExtension, public ICmsHeaderKeyUsageExtension,
	public ICmsHeaderDataFormatExtension, public ICmsHeaderMimeTypeExtension,
	public tsmod::IObject,
	public IHeaderPart
{
public:
	CmsHeaderExtensionImpl(std::shared_ptr<ICmsHeader>& header, const Asn1::CMS::_POD_CmsExtension &data);
	virtual ~CmsHeaderExtensionImpl(void);

	// ICmsHeaderExtension
	virtual tscrypto::tsCryptoData GetOID() const;
	virtual bool SetOID(const tscrypto::tsCryptoData &oid);
	virtual bool GetIsCritical() const;
	virtual bool SetIsCritical(bool setTo);
	virtual tscrypto::tsCryptoData GetContents() const;
	virtual bool SetContents(const tscrypto::tsCryptoData &data);
	virtual bool IsKnownExtension();
	virtual tscrypto::tsCryptoData ToBytes();

	// ICmsHeaderIssuerExtension
	virtual GUID GetIssuerGuid();
	virtual bool SetIssuerGuid(const GUID &guid);

	// ICmsHeaderPublicKeyExtension
	virtual tscrypto::tsCryptoData GetPublicKey();
	virtual bool SetPublicKey(const tscrypto::tsCryptoData &key);

	// ICmsHeaderAccessGroupExtension
	virtual size_t GetAccessGroupCount();
	virtual bool AddAccessGroup(AndGroupType type, std::shared_ptr<ICmsHeaderAccessGroup>& pVal);
	virtual bool GetAccessGroup(size_t index, std::shared_ptr<ICmsHeaderAccessGroup>& pVal);
	virtual bool RemoveAccessGroup(size_t index);

	// ICmsHeaderCryptoGroupListExtension
	virtual size_t GetCryptoGroupCount();
	virtual bool AddCryptoGroup(const tscrypto::tsCryptoData &cryptoGroupId, int *pVal);
	virtual bool GetCryptoGroup(size_t index, std::shared_ptr<ICmsHeaderCryptoGroup>& pVal);
	virtual bool RemoveCryptoGroup(size_t index);

	// ICmsHeaderAttributeListExtension
	virtual size_t GetAttributeCount() const;
	virtual int  AddAttribute();
	virtual bool GetAttribute(size_t index, std::shared_ptr<ICmsHeaderAttribute>& pVal) const;
	virtual bool RemoveAttribute(size_t index);

	// ICmsHeaderNameExtension
	virtual tscrypto::tsCryptoString GetName();
	virtual bool SetName(const tscrypto::tsCryptoString &name);

	// ICmsHeaderHashExtension
	virtual tscrypto::tsCryptoData GetHashAlgorithmOID();
	virtual bool SetHashAlgorithmOID(const tscrypto::tsCryptoData &oid);
	virtual tscrypto::tsCryptoData GetHash();
	virtual bool SetHash(const tscrypto::tsCryptoData &hash);

	// ICmsHeaderLengthExtension
	virtual uint64_t GetLength();
	virtual bool SetLength(uint64_t data);

	// ICmsHeaderSecryptMExtension
	virtual tscrypto::tsCryptoData GetPadding();
	virtual bool SetPadding(const tscrypto::tsCryptoData &data);

	// ICmsHeaderIvecExtension
	virtual tscrypto::tsCryptoData GetIvec();
	virtual bool SetIvec(const tscrypto::tsCryptoData &data);

	// ICmsHeaderKeyUsageExtension
	virtual tscrypto::tsCryptoData GetKeyUsageOID() const;
	virtual bool SetKeyUsageOID(const tscrypto::tsCryptoData &setTo);
	virtual int GetKeySizeInBits() const;
	virtual bool SetKeySizeInBits(int setTo);

	// Im_hea
	virtual int GetBlockSize() const;
	virtual bool SetBlockSize(int setTo);
	virtual int GetFormatAlgorithm() const;
	virtual bool SetFormatAlgorithm(int setTo);

	// ICmsHeaderMimeTypeExtension
	virtual tscrypto::tsCryptoString GetMimeType() const;
	virtual bool SetMimeType(const tscrypto::tsCryptoString &setTo);

	// IHeaderPart
	virtual void Destroy();
	virtual void PrepareForEncode(Asn1::CMS::_POD_CmsHeaderData &data, HeaderPartType type);

private:
	std::weak_ptr<ICmsHeader> m_header;

	tscrypto::tsCryptoData m_oid;
	tscrypto::tsCryptoData m_contents;
	bool m_isCritical;

	std::vector< std::shared_ptr< ICmsHeaderAccessGroup> > m_groupList;
	std::vector< std::shared_ptr< ICmsHeaderCryptoGroup> > m_cryptoGroupList;
	std::vector< std::shared_ptr< ICmsHeaderAttribute> > m_attributeList;
	tscrypto::tsCryptoData m_hash;
	tscrypto::tsCryptoData m_hashOid;

	void evaluateData();
	void clearEvaluatedData();
	void toGroupList();
	void fromGroupList();
	void toCryptoGroupList();
	void fromCryptoGroupList();
	void toHash();
	void fromHash();
	void toAttributeList();
	void fromAttributeList();
};

CmsHeaderExtensionImpl::CmsHeaderExtensionImpl(std::shared_ptr<ICmsHeader>& header, const Asn1::CMS::_POD_CmsExtension &data) :
	m_header(header),
	m_isCritical(false)
{
	m_oid = data.get_OID();
	m_isCritical = data.get_Critical();
	m_contents = data.get_Value();
	evaluateData();
}

CmsHeaderExtensionImpl::~CmsHeaderExtensionImpl(void)
{
}

tscrypto::tsCryptoData CmsHeaderExtensionImpl::GetOID() const
{
	return m_oid;
}

bool CmsHeaderExtensionImpl::SetOID(const tscrypto::tsCryptoData &oid)
{
	std::shared_ptr<ICmsHeaderExtension> ext;

	if (m_header.expired())
		return false;

	if (m_header.lock()->GetExtension(oid, ext))
		return false;

	m_oid = oid;
	clearEvaluatedData();
	evaluateData();
	return true;
}

bool CmsHeaderExtensionImpl::GetIsCritical() const
{
	return m_isCritical;
}

bool CmsHeaderExtensionImpl::SetIsCritical(bool setTo)
{
	m_isCritical = setTo;
	return true;
}

tscrypto::tsCryptoData CmsHeaderExtensionImpl::GetContents() const
{
	return m_contents;
}

bool CmsHeaderExtensionImpl::SetContents(const tscrypto::tsCryptoData &data)
{
	m_contents = data;
	clearEvaluatedData();
	evaluateData();
	return true;
}

bool CmsHeaderExtensionImpl::IsKnownExtension()
{
	tscrypto::tsCryptoString str = m_oid.ToOIDString();

	if (tsStrCmp(str.c_str(), id_TECSEC_CKMHEADER_V3_IVEC_EXT_OID) == 0 ||
		tsStrCmp(str.c_str(), id_TECSEC_CKMHEADER_V3_SECRYPTM_EXT_OID) == 0 ||
		tsStrCmp(str.c_str(), id_TECSEC_CKMHEADER_V3_FILELENGTH_EXT_OID) == 0 ||
		tsStrCmp(str.c_str(), id_TECSEC_CKMHEADER_V3_FILEHASH_EXT_OID) == 0 ||
		tsStrCmp(str.c_str(), id_TECSEC_CKMHEADER_V3_FILENAME_EXT_OID) == 0 ||
		tsStrCmp(str.c_str(), id_TECSEC_CKMHEADER_V7_CRYPTOGROUPLIST_EXT_OID) == 0 ||
		tsStrCmp(str.c_str(), id_TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID) == 0 ||
		tsStrCmp(str.c_str(), id_TECSEC_CKMHEADER_V7_ISSUER_EXT_OID) == 0 ||
		tsStrCmp(str.c_str(), id_TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID) == 0 ||
		tsStrCmp(str.c_str(), id_TECSEC_CKMHEADER_V7_SIGN_KEY_EXT_OID) == 0 ||
		tsStrCmp(str.c_str(), id_TECSEC_CKMHEADER_V7_KEY_USAGE_EXT_OID) == 0 ||
		tsStrCmp(str.c_str(), id_TECSEC_CKMHEADER_V7_DATA_FORMAT_EXT_OID) == 0 ||
		tsStrCmp(str.c_str(), id_TECSEC_CKMHEADER_V7_MIME_TYPE_EXT_OID) == 0)
	{
		return true;
	}
	return false;
}

tscrypto::tsCryptoData CmsHeaderExtensionImpl::ToBytes()
{
	Asn1::CMS::_POD_CmsExtension data;

	if (m_oid == tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V3_FILEHASH_EXT_OID, tscrypto::tsCryptoData::OID))
	{
		fromHash();
	}
	else if (m_oid == tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_CRYPTOGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID))
	{
		fromCryptoGroupList();
	}
	else if (m_oid == tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID))
	{
		fromGroupList();
	}
	else if (m_oid == tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V3_IVEC_EXT_OID, tscrypto::tsCryptoData::OID))
	{
		// No processing needed
	}
	else if (m_oid == tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V3_SECRYPTM_EXT_OID, tscrypto::tsCryptoData::OID))
	{
		// No processing needed
	}
	else if (m_oid == tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V3_FILELENGTH_EXT_OID, tscrypto::tsCryptoData::OID))
	{
		// No processing needed
	}
	else if (m_oid == tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V3_FILENAME_EXT_OID, tscrypto::tsCryptoData::OID))
	{
		// No processing needed
	}
	else if (m_oid == tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_ISSUER_EXT_OID, tscrypto::tsCryptoData::OID))
	{
		// No processing needed
	}
	else if (m_oid == tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID))
	{
		fromAttributeList();
	}
	else if (m_oid == tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_SIGN_KEY_EXT_OID, tscrypto::tsCryptoData::OID))
	{
		// No processing needed
	}
	else if (m_oid == tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_KEY_USAGE_EXT_OID, tscrypto::tsCryptoData::OID))
	{
		// No processing needed
	}
	else if (m_oid == tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_DATA_FORMAT_EXT_OID, tscrypto::tsCryptoData::OID))
	{
		// No processing needed
	}
	else if (m_oid == tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_MIME_TYPE_EXT_OID, tscrypto::tsCryptoData::OID))
	{
		// No processing needed
	}

	data.set_Critical(m_isCritical);
	data.set_OID(m_oid);
	data.set_Value(m_contents);

	tscrypto::tsCryptoData output;

	data.Encode(output);
	return output;
}

// ICmsHeaderIssuerExtension
GUID CmsHeaderExtensionImpl::GetIssuerGuid()
{
	GUID id = GUID_NULL;

	if (m_contents.size() != sizeof(GUID))
		return id;

	memcpy(&id, m_contents.c_str(), sizeof(GUID));
	return id;
}
bool CmsHeaderExtensionImpl::SetIssuerGuid(const GUID &guid)
{
	tscrypto::tsCryptoData dt((uint8_t*)&guid, sizeof(GUID));

	return SetContents(dt);
}

// ICmsHeaderPublicKeyExtension
tscrypto::tsCryptoData CmsHeaderExtensionImpl::GetPublicKey()
{
	return GetContents();
}
bool CmsHeaderExtensionImpl::SetPublicKey(const tscrypto::tsCryptoData &key)
{
	return SetContents(key);
}

// ICmsHeaderAccessGroupExtension
size_t CmsHeaderExtensionImpl::GetAccessGroupCount()
{
	return m_groupList.size();
}
bool CmsHeaderExtensionImpl::AddAccessGroup(AndGroupType type, std::shared_ptr<ICmsHeaderAccessGroup>& pVal)
{
	pVal = CreateHeaderAccessGroup(type);
	if (!pVal)
		return false;
	m_groupList.push_back(pVal);
	return true;
}
bool CmsHeaderExtensionImpl::GetAccessGroup(size_t index, std::shared_ptr<ICmsHeaderAccessGroup>& pVal)
{
	if (index >= m_groupList.size())
		return false;

	pVal = std::dynamic_pointer_cast<ICmsHeaderAccessGroup>(m_groupList[index]);
	return !!pVal;
}
bool CmsHeaderExtensionImpl::RemoveAccessGroup(size_t index)
{
	if (index >= m_groupList.size())
		return false;
	auto it = m_groupList.begin();
	std::advance(it, index);
	m_groupList.erase(it);
	fromGroupList();
	return true;
}

// ICmsHeaderCryptoGroupListExtension
size_t CmsHeaderExtensionImpl::GetCryptoGroupCount()
{
	return m_cryptoGroupList.size();
}
bool CmsHeaderExtensionImpl::AddCryptoGroup(const tscrypto::tsCryptoData &cryptoGroupId, int *pVal)
{
	if (pVal == nullptr)
		return false;
	*pVal = 0;

	std::shared_ptr<ICmsHeaderCryptoGroup> cg = CreateCryptoGroupHeaderObject(cryptoGroupId);
	m_cryptoGroupList.push_back(cg);

	*pVal = (int)m_cryptoGroupList.size() - 1;
	return true;
}
bool CmsHeaderExtensionImpl::GetCryptoGroup(size_t index, std::shared_ptr<ICmsHeaderCryptoGroup>& pVal)
{
	if (index >= m_cryptoGroupList.size())
		return false;

	pVal = m_cryptoGroupList[index];
	return !!pVal;
}
bool CmsHeaderExtensionImpl::RemoveCryptoGroup(size_t index)
{
	if (index >= m_cryptoGroupList.size())
		return false;
	auto it = m_cryptoGroupList.begin();
	std::advance(it, index);
	m_cryptoGroupList.erase(it);
	fromCryptoGroupList();
	return true;
}

//
size_t CmsHeaderExtensionImpl::GetAttributeCount() const
{
	return m_attributeList.size();
}

int CmsHeaderExtensionImpl::AddAttribute()
{
	std::shared_ptr<ICmsHeaderAttribute> attr = CreateHeaderAttribute();
	m_attributeList.push_back(attr);

	return (int)m_attributeList.size() - 1;
}

bool CmsHeaderExtensionImpl::GetAttribute(size_t index, std::shared_ptr<ICmsHeaderAttribute>& pVal) const
{
	if (index >= m_attributeList.size())
		return false;

	pVal = m_attributeList[index];
	return !!pVal;
}

bool CmsHeaderExtensionImpl::RemoveAttribute(size_t index)
{
	if (index >= m_attributeList.size())
		return false;
	auto it = m_attributeList.begin();
	std::advance(it, index);
	m_attributeList.erase(it);
	fromAttributeList();
	return true;
}

// ICmsHeaderNameExtension
tscrypto::tsCryptoString CmsHeaderExtensionImpl::GetName()
{
	return GetContents().ToUtf8String();
}
bool CmsHeaderExtensionImpl::SetName(const tscrypto::tsCryptoString &name)
{
	tscrypto::tsCryptoData dt(name, tscrypto::tsCryptoData::ASCII);

	return SetContents(dt);
}

// ICmsHeaderHashExtension
tscrypto::tsCryptoData CmsHeaderExtensionImpl::GetHashAlgorithmOID()
{
	return m_hashOid;
}
bool CmsHeaderExtensionImpl::SetHashAlgorithmOID(const tscrypto::tsCryptoData &oid)
{
	m_hashOid = oid;

	tscrypto::tsCryptoData output;

	Asn1::CMS::_POD_CmsHE_Hash data;

	data.clear();
	data.get_Algorithm().set_oid(oid);
	data.get_Algorithm().clear_Parameter();
	data.set_Hash(m_hash);
	data.Encode(output);
	SetContents(output);
	return true;
}
tscrypto::tsCryptoData CmsHeaderExtensionImpl::GetHash()
{
	return m_hash;
}
bool CmsHeaderExtensionImpl::SetHash(const tscrypto::tsCryptoData &hash)
{
	m_hash = hash;

	tscrypto::tsCryptoData output;
	Asn1::CMS::_POD_CmsHE_Hash data;

	data.clear();
	data.get_Algorithm().set_oid(m_hashOid);
	data.set_Hash(m_hash);
	data.Encode(output);
	SetContents(output);
	return true;
}

// ICmsHeaderLengthExtension
uint64_t CmsHeaderExtensionImpl::GetLength()
{
	uint64_t tmp = 0;
	tscrypto::tsCryptoData dt = GetContents();

	if (dt.size() > sizeof(uint64_t))
		dt.resize(sizeof(uint64_t));
	dt.reverse();
	memcpy(&tmp, dt.c_str(), dt.size());
	return tmp;
}
bool CmsHeaderExtensionImpl::SetLength(uint64_t data)
{
	tscrypto::tsCryptoData dt((uint8_t*)&data, sizeof(uint64_t));

	dt.reverse();
	while (dt.size() > 0 && dt[0] == 0)
		dt.erase(0, 1);

	return SetContents(dt);
}

// ICmsHeaderSecryptMExtension
tscrypto::tsCryptoData CmsHeaderExtensionImpl::GetPadding()
{
	return GetContents();
}
bool CmsHeaderExtensionImpl::SetPadding(const tscrypto::tsCryptoData &data)
{
	return SetContents(data);
}

// ICmsHeaderIvecExtension
tscrypto::tsCryptoData CmsHeaderExtensionImpl::GetIvec()
{
	return GetContents();
}
bool CmsHeaderExtensionImpl::SetIvec(const tscrypto::tsCryptoData &data)
{
	return SetContents(data);
}

// ICmsHeaderKeyUsageExtension
int CmsHeaderExtensionImpl::GetKeySizeInBits() const
{
	std::shared_ptr<TlvDocument> doc = TlvDocument::Create();

	if (!doc->LoadTlv(GetContents()) ||
		!doc->DocumentElement()->IsConstructed() || doc->DocumentElement()->ChildCount() != 2 || !doc->DocumentElement()->ChildAt(0)->IsOIDNode() || !doc->DocumentElement()->ChildAt(1)->IsNumber())
	{
		return 768;
	}
	return (int)doc->DocumentElement()->ChildAt(1)->InnerDataAsNumber();
}

bool CmsHeaderExtensionImpl::SetKeySizeInBits(int setTo)
{
	std::shared_ptr<TlvDocument> doc = TlvDocument::Create();

	if (!doc->LoadTlv(GetContents()) ||
		!doc->DocumentElement()->IsConstructed() || doc->DocumentElement()->ChildCount() != 2 ||
		!doc->DocumentElement()->ChildAt(0)->IsOIDNode() || !doc->DocumentElement()->ChildAt(1)->IsNumber())
	{
		doc->Clear();
		doc->DocumentElement()->Tag(TlvNode::Tlv_Sequence);
		doc->DocumentElement()->Type(TlvNode::Type_Universal);
		doc->DocumentElement()->AppendChild(doc->CreateOIDNode(tscrypto::tsCryptoData(id_TECSEC_CKM7_SCP_KEYS_OID, tscrypto::tsCryptoData::OID)));
		doc->DocumentElement()->AppendChild(doc->CreateNumberNode(setTo));
	}
	else
		doc->DocumentElement()->ChildAt(1)->InnerDataAsNumber(setTo);
	return SetContents(doc->SaveTlv());
}

tscrypto::tsCryptoData CmsHeaderExtensionImpl::GetKeyUsageOID() const
{
	std::shared_ptr<TlvDocument> doc = TlvDocument::Create();

	if (!doc->LoadTlv(GetContents()))
	{
		return tscrypto::tsCryptoData(id_TECSEC_CKM7_SCP_KEYS_OID, tscrypto::tsCryptoData::OID);
	}
	if (!doc->DocumentElement()->IsConstructed() || doc->DocumentElement()->ChildCount() != 2 || !doc->DocumentElement()->ChildAt(0)->IsOIDNode() || !doc->DocumentElement()->ChildAt(1)->IsNumber())
	{
		return tscrypto::tsCryptoData(id_TECSEC_CKM7_SCP_KEYS_OID, tscrypto::tsCryptoData::OID);
	}
	return doc->DocumentElement()->ChildAt(0)->InnerData();
}

bool CmsHeaderExtensionImpl::SetKeyUsageOID(const tscrypto::tsCryptoData &setTo)
{
	std::shared_ptr<TlvDocument> doc = TlvDocument::Create();

	if (!doc->LoadTlv(GetContents()) ||
		!doc->DocumentElement()->IsConstructed() || doc->DocumentElement()->ChildCount() != 2 ||
		!doc->DocumentElement()->ChildAt(0)->IsOIDNode() || !doc->DocumentElement()->ChildAt(1)->IsNumber())
	{
		doc->Clear();
		doc->DocumentElement()->Tag(TlvNode::Tlv_Sequence);
		doc->DocumentElement()->Type(TlvNode::Type_Universal);
		doc->DocumentElement()->AppendChild(doc->CreateOIDNode(setTo));
		doc->DocumentElement()->AppendChild(doc->CreateNumberNode((int)256));
	}
	doc->DocumentElement()->ChildAt(0)->InnerData(setTo);
	return SetContents(doc->SaveTlv());
}

int CmsHeaderExtensionImpl::GetBlockSize() const
{
	std::shared_ptr<TlvDocument> doc = TlvDocument::Create();

	if (!doc->LoadTlv(GetContents()))
	{
		return 5000000;
	}
	if (!doc->DocumentElement()->IsConstructed() || doc->DocumentElement()->ChildCount() != 2 || !doc->DocumentElement()->ChildAt(0)->IsNumber() || !doc->DocumentElement()->ChildAt(1)->IsNumber())
	{
		return 5000000;
	}
	return (int)doc->DocumentElement()->ChildAt(0)->InnerDataAsNumber();
}

bool CmsHeaderExtensionImpl::SetBlockSize(int setTo)
{
	std::shared_ptr<TlvDocument> doc = TlvDocument::Create();

	if (!doc->LoadTlv(GetContents()) ||
		!doc->DocumentElement()->IsConstructed() || doc->DocumentElement()->ChildCount() != 2 ||
		!doc->DocumentElement()->ChildAt(0)->IsNumber() || !doc->DocumentElement()->ChildAt(1)->IsNumber())
	{
		doc->Clear();
		doc->DocumentElement()->Tag(TlvNode::Tlv_Sequence);
		doc->DocumentElement()->Type(TlvNode::Type_Universal);
		doc->DocumentElement()->AppendChild(doc->CreateNumberNode(setTo));
		doc->DocumentElement()->AppendChild(doc->CreateNumberNode(TS_FORMAT_CMS_ENC_AUTH));
	}
	doc->DocumentElement()->ChildAt(0)->InnerData(setTo);
	return SetContents(doc->SaveTlv());
}

int CmsHeaderExtensionImpl::GetFormatAlgorithm() const
{
	std::shared_ptr<TlvDocument> doc = TlvDocument::Create();

	if (!doc->LoadTlv(GetContents()))
	{
		return TS_FORMAT_CMS_ENC_AUTH;
	}
	if (!doc->DocumentElement()->IsConstructed() || doc->DocumentElement()->ChildCount() != 2 || !doc->DocumentElement()->ChildAt(0)->IsNumber() || !doc->DocumentElement()->ChildAt(1)->IsNumber())
	{
		return TS_FORMAT_CMS_ENC_AUTH;
	}
	return (int)doc->DocumentElement()->ChildAt(1)->InnerDataAsNumber();
}

bool CmsHeaderExtensionImpl::SetFormatAlgorithm(int setTo)
{
	std::shared_ptr<TlvDocument> doc = TlvDocument::Create();

	if (!doc->LoadTlv(GetContents()) ||
		!doc->DocumentElement()->IsConstructed() || doc->DocumentElement()->ChildCount() != 2 ||
		!doc->DocumentElement()->ChildAt(0)->IsNumber() || !doc->DocumentElement()->ChildAt(1)->IsNumber())
	{
		doc->Clear();
		doc->DocumentElement()->Tag(TlvNode::Tlv_Sequence);
		doc->DocumentElement()->Type(TlvNode::Type_Universal);
		doc->DocumentElement()->AppendChild(doc->CreateNumberNode(5000000));
		doc->DocumentElement()->AppendChild(doc->CreateNumberNode(setTo));
	}
	doc->DocumentElement()->ChildAt(1)->InnerData(setTo);
	return SetContents(doc->SaveTlv());
}

// ICmsHeaderMimeTypeExtension
tscrypto::tsCryptoString CmsHeaderExtensionImpl::GetMimeType() const
{
	return m_contents.ToUtf8String();
}

// ICmsHeaderMimeTypeExtension
bool CmsHeaderExtensionImpl::SetMimeType(const tscrypto::tsCryptoString &setTo)
{
	m_contents.AsciiFromString(setTo.c_str());
	return true;
}

void CmsHeaderExtensionImpl::evaluateData()
{
	if (m_oid == tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V3_FILEHASH_EXT_OID, tscrypto::tsCryptoData::OID))
	{
		toHash();
	}
	else if (m_oid == tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_CRYPTOGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID))
	{
		toCryptoGroupList();
	}
	else if (m_oid == tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID))
	{
		toGroupList();
	}
	else if (m_oid == tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID))
	{
		toAttributeList();
	}
}

void CmsHeaderExtensionImpl::clearEvaluatedData()
{
	m_groupList.clear();
	m_cryptoGroupList.clear();
	m_hash.clear();
	m_hashOid.clear();
	m_attributeList.clear();
}

void CmsHeaderExtensionImpl::toGroupList()
{
	Asn1::CMS::_POD_CmsHE_AccessGroups data;

	if (data.Decode(m_contents))
	{
		int count = (int)data.size();

		for (int i = 0; i < count; i++)
		{
			Asn1::CMS::_POD_CmsHE_AccessGroups_Item *ext = &data.get_at(i);
			std::shared_ptr<ICmsHeaderAccessGroup> group;

			AndGroupType groupType = ag_Attrs;

			switch (ext->get_selectedItem())
			{
			case Asn1::CMS::_POD_CmsHE_AccessGroups_Item::Choice_CertItem:
				groupType = ag_FullCert;
				break;
			case Asn1::CMS::_POD_CmsHE_AccessGroups_Item::Choice_AttrItem:
				groupType = ag_Attrs;
				break;
			case Asn1::CMS::_POD_CmsHE_AccessGroups_Item::Choice_ExternalItem:
				groupType = ag_ExternalCrypto;
				break;
			case Asn1::CMS::_POD_CmsHE_AccessGroups_Item::Choice_PartialItem:
				groupType = ag_PartialCert;
				break;
			case Asn1::CMS::_POD_CmsHE_AccessGroups_Item::Choice_PinItem:
				groupType = ag_Pin;
				break;
			default:
				break;
			}

			if (!!(group = CreateHeaderAccessGroup(groupType)))
			{
				switch (groupType)
				{
				case ag_Attrs:
				{
					std::shared_ptr<ICmsHeaderAttributeGroup> attr = std::dynamic_pointer_cast<ICmsHeaderAttributeGroup>(group);

					if (!attr)
					{
						LOG(FrameworkError, "Unable to create the Attribute group");
						return;
					}

					if (ext->get_AttrItem().exists_EncryptedRandom())
						attr->SetEncryptedRandom(*ext->get_AttrItem().get_EncryptedRandom());
					for (size_t li = 0; li < ext->get_AttrItem().get_AttrIndices().size(); li++)
					{
						attr->AddAttributeIndex(ext->get_AttrItem().get_AttrIndices().get_at(li));
					}
				}
				break;
				default:
					break;
				}
				m_groupList.push_back(group);
			}
		}
	}
}

void CmsHeaderExtensionImpl::fromGroupList()
{
	Asn1::CMS::_POD_CmsHE_AccessGroups data;
	std::shared_ptr<ICmsHeaderAccessGroup> group;

	data.clear();

	for (int i = 0; i < (int)m_groupList.size(); i++)
	{
		group.reset();
		group = m_groupList[i];

		if (!!group)
		{
			switch (group->GetAndGroupType())
			{
			case ag_Attrs:
			{
				std::shared_ptr<ICmsHeaderAttributeGroup> attrs;
				if (!!(attrs = std::dynamic_pointer_cast<ICmsHeaderAttributeGroup>(group)))
				{
					Asn1::CMS::_POD_CmsHE_AccessGroups_Item item;

					item.set_selectedItem(Asn1::CMS::_POD_CmsHE_AccessGroups_Item::Choice_AttrItem);
					item.get_AttrItem().set_EncryptedRandom(attrs->GetEncryptedRandom());

					size_t attributeCount = attrs->GetAttributeCount();
					for (size_t index = 0; index < attributeCount; index++)
					{
						int tmp = attrs->GetAttributeIndex(index);
						item.get_AttrItem().get_AttrIndices().add(tmp);
					}
					data.add(item);
				}
			}
			break;
			default:
				return;
			}
		}
	}
	data.Encode(m_contents);
}

void CmsHeaderExtensionImpl::toCryptoGroupList()
{
	Asn1::CMS::_POD_CmsHE_CryptoGroupList data;

	if (data.Decode(m_contents))
	{
		size_t count = data.get_CryptoGroup().size();

		for (size_t i = 0; i < count; i++)
		{
			Asn1::CMS::_POD_CmsHE_CryptoGroup &cryptoGroupData = data.get_CryptoGroup().get_at(i);

			std::shared_ptr<ICmsHeaderCryptoGroup> cryptoGroup = CreateCryptoGroupHeaderObject(cryptoGroupData.get_CryptoGroupId());

			cryptoGroup->SetCurrentMaintenanceLevel(cryptoGroupData.get_CML());
			if (cryptoGroupData.exists_EphemeralPublic())
				cryptoGroup->SetEphemeralPublic(*cryptoGroupData.get_EphemeralPublic());
			m_cryptoGroupList.push_back(cryptoGroup);
			cryptoGroup.reset();
		}
	}
}

void CmsHeaderExtensionImpl::fromCryptoGroupList()
{
	Asn1::CMS::_POD_CmsHE_CryptoGroupList data;
	std::shared_ptr<ICmsHeaderCryptoGroup> cg;

	data.clear();

	for (int i = 0; i < (int)m_cryptoGroupList.size(); i++)
	{
		cg.reset();
		if (!!(cg = std::dynamic_pointer_cast<ICmsHeaderCryptoGroup>(m_cryptoGroupList[i])))
		{
			Asn1::CMS::_POD_CmsHE_CryptoGroup cryptoGroupData;

			cryptoGroupData.set_CML(cg->GetCurrentMaintenanceLevel());
			cryptoGroupData.set_CryptoGroupId(cg->GetCryptoGroupId());
			if (cg->GetEphemeralPublic().size() > 0)
				cryptoGroupData.set_EphemeralPublic(cg->GetEphemeralPublic());
			else
				cryptoGroupData.clear_EphemeralPublic();
			data.get_CryptoGroup().add(cryptoGroupData);
		}
	}
	std::shared_ptr<TlvDocument> doc = TlvDocument::Create();

	doc->DocumentElement()->Tag(TlvNode::Tlv_Sequence);
	doc->DocumentElement()->Type(TlvNode::Type_Universal);

	data.Encode(m_contents);
}

void CmsHeaderExtensionImpl::toHash()
{
	Asn1::CMS::_POD_CmsHE_Hash data;

	if (data.Decode(m_contents))
	{
		m_hashOid = data.get_Algorithm().get_oid();
		m_hash = data.get_Hash();
	}
}

void CmsHeaderExtensionImpl::fromHash()
{
	Asn1::CMS::_POD_CmsHE_Hash data;

	data.clear();
	data.get_Algorithm().set_oid(m_hashOid);
	data.set_Hash(m_hash);
	data.Encode(m_contents);
}

void CmsHeaderExtensionImpl::toAttributeList()
{
	Asn1::CMS::_POD_CmsHE_AttributeListExtension data;

	if (data.Decode(m_contents))
	{
		size_t count = data.get_Attributes().size();

		for (size_t i = 0; i < count; i++)
		{
			std::shared_ptr<ICmsHeaderAttribute> myAttribute;
			Asn1::CMS::_POD_CmsHE_Attribute &attr = data.get_Attributes().get_at(i);

			int attrIndex = AddAttribute();
			if (GetAttribute(attrIndex, myAttribute))
			{
				myAttribute->SetAttributeId(attr.get_Id());
				myAttribute->SetCryptoGroupNumber(attr.get_CryptoGroupNumber());
				myAttribute->SetKeyVersion(attr.get_Version());
				if (attr.exists_Signature())
					myAttribute->SetSignature(*attr.get_Signature());
			}
		}
	}
}

void CmsHeaderExtensionImpl::fromAttributeList()
{
	Asn1::CMS::_POD_CmsHE_AttributeListExtension data;
	std::shared_ptr<ICmsHeaderAttribute> attr;

	data.clear();

	for (int i = 0; i < (int)m_attributeList.size(); i++)
	{
		attr.reset();
		if (!!(attr = std::dynamic_pointer_cast<ICmsHeaderAttribute>(m_attributeList[i])))
		{
			Asn1::CMS::_POD_CmsHE_Attribute attributeData;

			attributeData.set_Id(attr->GetAttributeId());
			attributeData.set_CryptoGroupNumber(attr->GetCryptoGroupNumber());
			attributeData.set_Version(attr->GetKeyVersion());
			if (attr->GetSignature().size() > 0)
				attributeData.set_Signature(attr->GetSignature());
			else
				attributeData.clear_Signature();
			data.get_Attributes().add(attributeData);
		}
	}
	data.Encode(m_contents);
}

void CmsHeaderExtensionImpl::Destroy()
{
	m_header.reset();
}

void CmsHeaderExtensionImpl::PrepareForEncode(Asn1::CMS::_POD_CmsHeaderData &data, HeaderPartType type)
{
	if (m_oid == tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V3_FILEHASH_EXT_OID, tscrypto::tsCryptoData::OID))
	{
		fromHash();
	}
	else if (m_oid == tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_CRYPTOGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID))
	{
		fromCryptoGroupList();
	}
	else if (m_oid == tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID))
	{
		fromGroupList();
	}
	else if (m_oid == tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V3_IVEC_EXT_OID, tscrypto::tsCryptoData::OID))
	{
		// No processing needed
	}
	else if (m_oid == tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V3_SECRYPTM_EXT_OID, tscrypto::tsCryptoData::OID))
	{
		// No processing needed
	}
	else if (m_oid == tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V3_FILELENGTH_EXT_OID, tscrypto::tsCryptoData::OID))
	{
		// No processing needed
	}
	else if (m_oid == tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V3_FILENAME_EXT_OID, tscrypto::tsCryptoData::OID))
	{
		// No processing needed
	}
	else if (m_oid == tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_ISSUER_EXT_OID, tscrypto::tsCryptoData::OID))
	{
		// No processing needed
	}
	else if (m_oid == tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID))
	{
		fromAttributeList();
	}
	else if (m_oid == tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_SIGN_KEY_EXT_OID, tscrypto::tsCryptoData::OID))
	{
		// No processing needed
	}

	Asn1::CMS::_POD_CmsExtension ext;

	ext.set_OID(m_oid);
	ext.set_Critical(m_isCritical);
	ext.set_Value(m_contents);
	switch (type)
	{
	case ProtectedExtension:
		if (!data.exists_ProtectedExtensions())
			data.set_ProtectedExtensions();
		data.get_ProtectedExtensions()->add(ext);
		break;
	case UnprotectedExtension:
		if (!data.exists_UnprotectedExtensions())
			data.set_UnprotectedExtensions();
		data.get_UnprotectedExtensions()->add(ext);
		break;
	default:
		return;
	}
}

std::shared_ptr<ICmsHeaderExtension> CreateHeaderExtensionObject(std::shared_ptr<ICmsHeader> header, Asn1::CMS::_POD_CmsExtension& data)
{
	return ::TopServiceLocator()->Finish<ICmsHeaderExtension>(new CmsHeaderExtensionImpl(header, data));
}

