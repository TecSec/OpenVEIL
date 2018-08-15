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

using namespace tscrypto;

int32List tscrypto::CreateInt32List()
{
	return CreateContainer<int32_t>();
}






bool tscrypto::ClearTlv(void* data, const Asn1Metadata2* __metadata, size_t __metadataCount)
{
	size_t metaIndex = 0;
	const Asn1Metadata2 *meta;
	//        int index = 0;

	for (metaIndex = 0; metaIndex < __metadataCount; metaIndex++)
	{
		meta = &__metadata[metaIndex];
		if (meta->offsetToData >= 0)
		{
			switch (meta->fieldFlags & 0xff)
			{
			case Asn1Metadata2::tp_int8:
				*(int8_t*)(((unsigned char*)data) + meta->offsetToData) = 0;
				break;
			case Asn1Metadata2::tp_int16:
				*(int16_t*)(((unsigned char*)data) + meta->offsetToData) = 0;
				break;
			case Asn1Metadata2::tp_int32:
				*(int32_t*)(((unsigned char*)data) + meta->offsetToData) = 0;
				break;
			case Asn1Metadata2::tp_int64:
				*(int64_t*)(((unsigned char*)data) + meta->offsetToData) = 0;
				break;
			case Asn1Metadata2::tp_bool:
				*(bool*)(((unsigned char*)data) + meta->offsetToData) = 0;
				break;
			case Asn1Metadata2::tp_string:
				((tsCryptoString*)(((unsigned char*)data) + meta->offsetToData))->clear();
				break;
			case Asn1Metadata2::tp_any:
				// This is actually pointing to the internal tsCryptoData field.  Fall through.
				//((Asn1AnyField*)(((unsigned char*)data) + meta->offsetToData))->clear();
				//break;
			case Asn1Metadata2::tp_number:
			case Asn1Metadata2::tp_oid:
			case Asn1Metadata2::tp_data:
			case Asn1Metadata2::tp_bits:
				((tsCryptoData*)(((unsigned char*)data) + meta->offsetToData))->clear();
				break;
			case Asn1Metadata2::tp_date:
				((tsCryptoDate*)(((unsigned char*)data) + meta->offsetToData))->clear();
				break;
			case Asn1Metadata2::tp_guid:
				*(GUID*)(((unsigned char*)data) + meta->offsetToData) = GUID_NULL;
				break;
			case Asn1Metadata2::tp_choice:
			case Asn1Metadata2::tp_sequenceOfRef:
			case Asn1Metadata2::tp_struct:
			case Asn1Metadata2::tp_set:
				if (meta->clearer == nullptr)
					throw tscrypto::Exception("Clearer has not been set.");
				meta->clearer((((unsigned char*)data) + meta->offsetToData));
				break;
			}
		}
		if (meta->offsetToExistsFlag >= 0)
		{
			*(bool*)(((unsigned char*)data) + meta->offsetToExistsFlag) = false;
		}
		if (meta->offsetToTag >= 0)
		{
			*(int*)(((unsigned char*)data) + meta->offsetToTag) = 0;
		}
		if (meta->offsetToType >= 0)
		{
			*(uint8_t*)(((unsigned char*)data) + meta->offsetToType) = 0;
		}
		if (meta->offsetToChoiceField >= 0)
		{
			*(int*)(((unsigned char*)data) + meta->offsetToChoiceField) = 0;
		}
	}
	return true;
}
static bool CreateDataFromNode(void* data, const std::shared_ptr<TlvNode> node, const Asn1Metadata2* metadata)
{
	switch (metadata->fieldFlags & 0xff)
	{
	case Asn1Metadata2::tp_int8:
		*(int8_t*)(((unsigned char*)data) + metadata->offsetToData) = (int8_t)node->InnerDataAsNumber();
		break;
	case Asn1Metadata2::tp_int16:
		*(int16_t*)(((unsigned char*)data) + metadata->offsetToData) = (int16_t)node->InnerDataAsNumber();
		break;
	case Asn1Metadata2::tp_int32:
		*(int32_t*)(((unsigned char*)data) + metadata->offsetToData) = (int32_t)node->InnerDataAsNumber();
		break;
	case Asn1Metadata2::tp_int64:
		*(int64_t*)(((unsigned char*)data) + metadata->offsetToData) = node->InnerDataAsNumber();
		break;
	case Asn1Metadata2::tp_bool:
		*(bool*)(((unsigned char*)data) + metadata->offsetToData) = (node->InnerDataAsNumber() != 0);
		break;
	case Asn1Metadata2::tp_char:
		*(char*)(((unsigned char*)data) + metadata->offsetToData) = (char)node->InnerDataAsNumber();
		break;
	case Asn1Metadata2::tp_null:
		break;
	case Asn1Metadata2::tp_string:
		*(tsCryptoString*)(((unsigned char*)data) + metadata->offsetToData) = node->InnerString();
		break;
	case Asn1Metadata2::tp_oid:
	case Asn1Metadata2::tp_data:
		*(tsCryptoData*)(((unsigned char*)data) + metadata->offsetToData) = node->InnerData();
		break;
	case Asn1Metadata2::tp_number:
	{
		tsCryptoData tmp = node->InnerData();
		if (tmp.size() > 1 && tmp[0] == 0 && tmp[1] & 0x80)
			tmp.erase(0, 1);

		*(tsCryptoData*)(((unsigned char*)data) + metadata->offsetToData) = tmp;
		break;
	}
	case Asn1Metadata2::tp_bits:
	{
		tsCryptoData tmp = node->InnerData();
		*(tsCryptoData*)(((unsigned char*)data) + metadata->offsetToData) = tmp;

		break;
	}
	case Asn1Metadata2::tp_guid:
	{
		tsCryptoData tmp = node->InnerData();

		if (tmp.size() != sizeof(GUID))
			return false;

		*(GUID*)(((unsigned char*)data) + metadata->offsetToData) = *(const GUID*)tmp.c_str();
		break;
	}
	case Asn1Metadata2::tp_any:
		if (metadata->offsetToTag < 0 || metadata->offsetToType < 0)
			return false;
		*(int*)(((unsigned char*)data) + metadata->offsetToTag) = node->Tag();
		*(uint8_t*)(((unsigned char*)data) + metadata->offsetToType) = (uint8_t)node->Type();
		*(tsCryptoData*)(((unsigned char*)data) + metadata->offsetToData) = node->InnerData();
		break;
	case Asn1Metadata2::tp_sequenceOfRef:
	case Asn1Metadata2::tp_choice:
		//if (!((Asn1DataBaseClass*)(((unsigned char*)data) + metadata->offsetToData))->DecodeChildren(node))
		//	return false;
		//break;
	case Asn1Metadata2::tp_struct:
		if (metadata->decoder != nullptr)
		{
			if (!metadata->decoder((((unsigned char*)data) + metadata->offsetToData), node))
				return false;
		}
		else if (metadata->subMetadata != nullptr && metadata->subMetadataCount > 0)
		{
			if (!DecodeTlv((((unsigned char*)data) + metadata->offsetToData), node, metadata->subMetadata, metadata->subMetadataCount))
				return false;
		}
		else
		{
			throw tscrypto::Exception("Invalid metadata layout for structure.");
		}
		break;
	case Asn1Metadata2::tp_date:
		((tsCryptoDate*)(((unsigned char*)data) + metadata->offsetToData))->SetDateTimeFromZulu(node->InnerString());
		break;
	case Asn1Metadata2::tp_set:
		throw tscrypto::Exception("Sets are not implemented in the Tlv Decoder");
		//if (!CreateDataForSet(data, node, metadata))
		//	return false;
		//break;
	}
	if (metadata->offsetToExistsFlag >= 0)
	{
		*(bool*)(((unsigned char*)data) + metadata->offsetToExistsFlag) = true;
	}
	return true;

}
bool tscrypto::DecodeTlv(void* data, const std::shared_ptr<TlvNode> parent, const Asn1Metadata2* __metadata, size_t __metadataCount, bool decodeSelectedOnly)
{
	size_t metaIndex = 0;
	const Asn1Metadata2 *meta;
	std::shared_ptr<TlvNode> child;
	bool goToNext;

	ClearTlv(data, __metadata, __metadataCount);

	for (size_t i = 0; i < parent->ChildCount(); i++)
	{
		child = parent->ChildAt(i);

		do
		{
			goToNext = false;
			if (__metadataCount <= metaIndex)
			{
				if (decodeSelectedOnly)
					return true;
				//LOG(gMetaDebug, "ERROR:  metaIndex > count");
				return false;
			}
			meta = &__metadata[metaIndex++];
			switch (NodeMatchesMetadata(child, meta))
			{
			case Asn1Metadata2::good:
			{
				if (!CreateDataFromNode(data, child, meta))
				{
					//LOG(gMetaDebug, "ERROR:  NodeToData failed for " << meta->ItemName());
					return false;
				}
			}
			break;
			case Asn1Metadata2::defaulted:
				goToNext = true;
				break;
			case Asn1Metadata2::mismatch:
				return false;
			}
		} while (goToNext);
	}
	while (__metadataCount > metaIndex)
	{
		meta = &__metadata[metaIndex++];
		if (meta->defaultValue == nullptr && (meta->fieldFlags & Asn1Metadata2::tp_optional) == 0)
		{
			return false;
		}
		metaIndex++;
	}
	return true;
}

Asn1Metadata2::matchResult tscrypto::NodeMatchesMetadata(const std::shared_ptr<TlvNode> node, const Asn1Metadata2* metadata)
{
	if (node != nullptr && (metadata->fieldFlags & 0xff) == Asn1Metadata2::tp_any)
	{
		return Asn1Metadata2::good;
	}
	if (node == nullptr || node->Tag() != metadata->tag || node->Type() != metadata->type)
	{
		if (metadata->NodeMatchesMetadataFn != nullptr)
		{
			return metadata->NodeMatchesMetadataFn(node, metadata);
		}
		if (metadata->defaultValue != nullptr)
		{
			return Asn1Metadata2::defaulted;
		}
		if (metadata->fieldFlags & Asn1Metadata2::tp_optional)
		{
			return Asn1Metadata2::defaulted;
		}
		return Asn1Metadata2::mismatch;
	}
	return Asn1Metadata2::good;
}

static bool matches(const tsCryptoData& inOid, int32_t inVersion, const Asn1Version2& ver)
{
	if (inOid.size() == 0 || ver.oid == nullptr)
	{
		if (inOid.size() == 0 && ver.oid != nullptr)
			return false;
		if (inOid.size() != 0 && ver.oid == nullptr)
			return false;
	}
	if (ver.checkVersion)
	{
		if (inVersion >= ver.minVersion && inVersion <= ver.maxVersion)
		{

		}
		else
			return false;
	}
	if (ver.oid != nullptr && tsStrCmp(ver.oid, "*") == 0)
		return true;
	if (inOid.size() != 0)
	{
		tsCryptoData test;

		test.FromOIDString(ver.oid);

		if (test != inOid)
			return false;
	}
	return true;
}

bool tscrypto::FindVersionToEncode(void* data, const Asn1StructureDefinition2& def, const struct Asn1Metadata2*& metadata, uint32_t& count)
{
	tsCryptoData oid;
	int32_t version = -1;
	bool foundOID = false;
	bool foundVersion = false;

	metadata = nullptr;
	count = 0;

	if (def.versionCount > 0)
	{
		// Find the OID and Version
		for (size_t i = 0; i < def.versionCount && !foundOID && !foundVersion; i++)
		{
			const Asn1Version2* ver = &def.versionList[i];

			if (ver->subMetadataCount > 0 && ver->subMetadata[0].fieldFlags == Asn1Metadata2::tp_oid)
			{
				oid = *(const tsCryptoData*)(((const uint8_t*)data) + ver->subMetadata[0].offsetToData);
				if (oid.size() == 0 && def.defaultOID != nullptr)
				{
					oid.FromOIDString(def.defaultOID);
					*(tsCryptoData*)(((const uint8_t*)data) + ver->subMetadata[0].offsetToData) = oid;
				}
				foundOID = true;
				// TODO:  Setting default version is still needed.
				if (ver->subMetadataCount > 1 && !foundVersion && ver->subMetadata[1].fieldFlags == Asn1Metadata2::tp_int32)
				{
					version = *(const int32_t*)(((const uint8_t*)data) + ver->subMetadata[1].offsetToData);
					foundVersion = true;
				}
			}
			else if (ver->subMetadataCount > 0 && !foundVersion && ver->subMetadata[0].fieldFlags == Asn1Metadata2::tp_int32)
			{
				version = *(const int32_t*)(((const uint8_t*)data) + ver->subMetadata[0].offsetToData);
				foundVersion = true;
			}
		}
		for (size_t i = 0; i < def.versionCount; i++)
		{
			if (matches(oid, version, def.versionList[i]))
			{
				metadata = def.versionList[i].subMetadata;
				count = def.versionList[i].subMetadataCount;
				return true;
			}
		}
	}
	metadata = def.subMetadata;
	count = (uint32_t)def.subMetadataCount;
	if (metadata != nullptr && count > 0)
		return true;
	return false;
}
bool tscrypto::FindVersionToDecode(const std::shared_ptr<TlvNode> root, const Asn1StructureDefinition2& def, const struct Asn1Metadata2*& metadata, uint32_t& count)
{
	tsCryptoData oid;
	int32_t version = -1;

	metadata = nullptr;
	count = 0;

	if (def.versionCount > 0 && root != nullptr && root->IsConstructed())
	{
		// Find the OID and Version
		if (root->ChildCount() > 0 && root->ChildAt(0)->Tag() == TlvNode::Tlv_OID && root->ChildAt(0)->Type() == TlvNode::Type_Universal)
		{
			oid = root->ChildAt(0)->InnerData();
			if (root->ChildCount() > 1 && root->ChildAt(1)->Tag() == TlvNode::Tlv_Number && root->ChildAt(1)->Type() == TlvNode::Type_Universal)
			{
				version = (int32_t)root->ChildAt(1)->InnerDataAsNumber();
			}
		}
		else if (root->ChildCount() > 0 && root->ChildAt(0)->Tag() == TlvNode::Tlv_Number && root->ChildAt(0)->Type() == TlvNode::Type_Universal)
		{
			version = (int32_t)root->ChildAt(0)->InnerDataAsNumber();
		}

		for (size_t i = 0; i < def.versionCount; i++)
		{
			if (matches(oid, version, def.versionList[i]))
			{
				metadata = def.versionList[i].subMetadata;
				count = def.versionList[i].subMetadataCount;
				return true;
			}
		}
	}
	metadata = def.subMetadata;
	count = (uint32_t)def.subMetadataCount;
	if (metadata != nullptr && count > 0)
		return true;
	return false;
}

static bool HasData(const void* data, const Asn1Metadata2* metadata)
{
	if ((metadata->fieldFlags & 0xff) == Asn1Metadata2::tp_null)
		return true;

	if (metadata == nullptr || metadata->offsetToData < 0)
		return false;

	// if matches default then return true
	if (metadata->defaultValue != nullptr)
		return true;
	// If optional field and option flag not set the return no data
	if (metadata->offsetToExistsFlag >= 0)
	{
		if (*(bool*)(((unsigned char*)data) + metadata->offsetToExistsFlag))
		{
			return true;
		}
		return false;
	}
	if (metadata->offsetToChoiceField >= 0 && (*(int*)(((unsigned char*)data) + metadata->offsetToChoiceField)) == 0)
		return false;

	return true;
}

static std::shared_ptr<TlvNode> CreateNodeFromData(std::shared_ptr<TlvDocument> doc, void* data, const Asn1Metadata2* metadata)
{
	std::shared_ptr<TlvNode> node = doc->CreateTlvNode(metadata->tag, (uint8_t)metadata->type);
	if (node == nullptr)
		return node;

	switch (metadata->fieldFlags & 0xff)
	{
	case Asn1Metadata2::tp_int8:
		if (metadata->defaultValue != nullptr)
		{
			if (*(int8_t*)(((unsigned char*)data) + metadata->offsetToData) == tsStrToInt(metadata->defaultValue))
			{
				return nullptr;
			}
		}
		node->InnerDataAsNumber(*(int8_t*)(((unsigned char*)data) + metadata->offsetToData));
		break;
	case Asn1Metadata2::tp_int16:
		if (metadata->defaultValue != nullptr)
		{
			if (*(int16_t*)(((unsigned char*)data) + metadata->offsetToData) == tsStrToInt(metadata->defaultValue))
			{
				return nullptr;
			}
		}
		node->InnerDataAsNumber(*(int16_t*)(((unsigned char*)data) + metadata->offsetToData));
		break;
	case Asn1Metadata2::tp_int32:
		if (metadata->defaultValue != nullptr)
		{
			if (*(int32_t*)(((unsigned char*)data) + metadata->offsetToData) == tsStrToInt(metadata->defaultValue))
			{
				return nullptr;
			}
		}
		node->InnerDataAsNumber(*(int32_t*)(((unsigned char*)data) + metadata->offsetToData));
		break;
	case Asn1Metadata2::tp_int64:
		if (metadata->defaultValue != nullptr)
		{
			if (*(int64_t*)(((unsigned char*)data) + metadata->offsetToData) == tsStrToInt64(metadata->defaultValue))
			{
				return nullptr;
			}
		}
		node->InnerDataAsNumber(*(int64_t*)(((unsigned char*)data) + metadata->offsetToData));
		break;
	case Asn1Metadata2::tp_char:
		if (metadata->defaultValue != nullptr)
		{
			if (*(char*)(((unsigned char*)data) + metadata->offsetToData) == (char)tsStrToInt(metadata->defaultValue))
			{
				return nullptr;
			}
		}
		node->InnerDataAsNumber(*(char*)(((unsigned char*)data) + metadata->offsetToData));
		break;
	case Asn1Metadata2::tp_null:
		break;
	case Asn1Metadata2::tp_bool:
		if (metadata->defaultValue != nullptr)
		{
			if (*(bool*)(((unsigned char*)data) + metadata->offsetToData) == ((tsStrToInt(metadata->defaultValue) != 0) ? true : false))
			{
				return nullptr;
			}
		}
		node->InnerData(tsCryptoData((*(bool*)(((unsigned char*)data) + metadata->offsetToData)) ? (uint8_t)0xFF : (uint8_t)0));
		break;
	case Asn1Metadata2::tp_string:
		if (metadata->defaultValue != nullptr)
		{
			if (*(tsCryptoString*)(((unsigned char*)data) + metadata->offsetToData) == metadata->defaultValue)
			{
				return nullptr;
			}
		}
		node->InnerString(*(tsCryptoString*)(((unsigned char*)data) + metadata->offsetToData));
		break;
	case Asn1Metadata2::tp_data:
		if (metadata->defaultValue != nullptr)
		{
			if (*(tsCryptoData*)(((unsigned char*)data) + metadata->offsetToData) == tsCryptoData(metadata->defaultValue, tsCryptoData::HEX))
			{
				return nullptr;
			}
		}
		node->InnerData(*(tsCryptoData*)(((unsigned char*)data) + metadata->offsetToData));
		break;
	case Asn1Metadata2::tp_number:
	{
		tsCryptoData tmp = *(tsCryptoData*)(((unsigned char*)data) + metadata->offsetToData);

		if (tmp.size() > 0 && tmp[0] & 0x80)
		{
			tmp.insert(0, (unsigned char)0);
		}
		node->InnerData(tmp);
		break;
	}
	case Asn1Metadata2::tp_guid:
	{
		tsCryptoData tmp((uint8_t*)(((unsigned char*)data) + metadata->offsetToData), sizeof(GUID));
		node->InnerData(tmp);
		break;
	}
	case Asn1Metadata2::tp_any:
		if (metadata->offsetToTag < 0 || metadata->offsetToType < 0)
		{
			return nullptr;
		}
		// Just in case...
		node->Tag(TlvNode::Tlv_Octet);
		// Must set the data first incase the Tag sets m_forceConstructed
		node->InnerData(*(tsCryptoData*)(((unsigned char*)data) + metadata->offsetToData));
		node->Tag(*(int*)(((unsigned char*)data) + metadata->offsetToTag));
		node->Type(*(uint8_t*)(((unsigned char*)data) + metadata->offsetToType));
		break;
	case Asn1Metadata2::tp_sequenceOfRef:
	{
		if (metadata->fieldFlags & Asn1Metadata2::tp_optional)
		{
			if (*(bool*)(((unsigned char*)data) + metadata->offsetToExistsFlag) == false)
			{
				return nullptr;
			}
		}
		if (metadata->encoder != nullptr)
		{
			if (!metadata->encoder((((unsigned char*)data) + metadata->offsetToData), node))
				return nullptr;
		}
		else if (!EncodeSequenceOfTlv((((unsigned char*)data) + metadata->offsetToData), node, metadata->subMetadata, metadata->subMetadataCount))
		{
			return nullptr;
		}
		// TODO:  Test and review 2016
		if (node->Tag() != -1 || node->Type() != TlvNode::Type_Universal)
		{
			node->ChildAt(0)->Tag(node->Tag());
			node->ChildAt(0)->Type(node->Type());
		}
		tsCryptoData tmp = node->ChildAt(0)->OuterData();
		node->OuterData(tmp);
		break;
	}
	case Asn1Metadata2::tp_choice:
	{
		if (metadata->fieldFlags & Asn1Metadata2::tp_optional)
		{
			if (*(bool*)(((unsigned char*)data) + metadata->offsetToExistsFlag) == false)
			{
				return nullptr;
			}
		}
		unsigned char* subData = (((unsigned char*)data) + metadata->offsetToData);
		if (metadata->encoder != nullptr)
		{
			if (!metadata->encoder((((unsigned char*)data) + metadata->offsetToData), node))
				return nullptr;
		}
		else if (!EncodeChoiceTlv(subData, node, *(int*)((unsigned char*)data + metadata->offsetToChoiceField), metadata->subMetadata, metadata->subMetadataCount))
		{
			return nullptr;
		}
		//if (node->Tag() != 0 || node->Type() != TlvNode::Type_Universal)
		//{
		//	node->ChildAt(0)->Tag(node->Tag());
		//	node->ChildAt(0)->Type(node->Type());
		//}
		if (!node || node->ChildCount() == 0)
			return nullptr;
		tsCryptoData tmp = node->ChildAt(0)->OuterData();
		node->OuterData(tmp);
		break;
	}
	case Asn1Metadata2::tp_set:
	case Asn1Metadata2::tp_struct:
		if (metadata->fieldFlags & Asn1Metadata2::tp_optional)
		{
			if (metadata->offsetToExistsFlag != -1)
			{
				if ((*(bool*)(((unsigned char*)data) + metadata->offsetToExistsFlag)) == false)
				{
					return nullptr;
				}
			}
		}
		if (metadata->encoder != nullptr)
		{
			if (!metadata->encoder((((unsigned char*)data) + metadata->offsetToData), node))
				return nullptr;
			node->ChildAt(0)->Tag(node->Tag());
			node->ChildAt(0)->Type(node->Type());
			tsCryptoData tmp = node->ChildAt(0)->OuterData();
			node->OuterData(tmp);
		}
		else if (!EncodeTlv((((unsigned char*)data) + metadata->offsetToData), node, metadata->subMetadata, metadata->subMetadataCount))
		{
			return nullptr;
		}
		break;
	case Asn1Metadata2::tp_bits:
		node->InnerData(((Asn1Bitstring*)(((unsigned char*)data) + metadata->offsetToData))->dataHolder);
		break;
	case Asn1Metadata2::tp_date:
		node->InnerString(((tsCryptoDate*)(((unsigned char*)data) + metadata->offsetToData))->ToZuluTime());
		break;
	case Asn1Metadata2::tp_oid:
		node->InnerData(*((tsCryptoData*)(((unsigned char*)data) + metadata->offsetToData)));
		break;
	}
	return node;
}

bool tscrypto::EncodeTlv(void* data, std::shared_ptr<TlvNode> parent, const Asn1Metadata2* __metadata, size_t __metadataCount)
{
	size_t metaIndex = 0;
	const Asn1Metadata2 *meta;
	std::shared_ptr<TlvNode> child;
	std::shared_ptr<TlvDocument> doc = parent->OwnerDocument().lock();

	for (metaIndex = 0; metaIndex < __metadataCount; metaIndex++)
	{
		meta = &__metadata[metaIndex];
		if (HasData(data, meta))
		{
			child = CreateNodeFromData(doc, data, meta);
			if (!!child)
				parent->AppendChild(child);
			else if (meta->defaultValue == nullptr && meta->offsetToExistsFlag >= 0)
			{
				return false;
			}
		}
		else if (meta->offsetToExistsFlag >= 0 || meta->defaultValue != nullptr)
		{
		}
		else
		{
			return false;
		}
	}
	return true;
}
bool tscrypto::EncodeChoiceTlv(void* data, std::shared_ptr<TlvNode> parent, int32_t choiceItem, const Asn1Metadata2* __metadata, size_t __metadataCount)
{
	const Asn1Metadata2 *meta;
	std::shared_ptr<TlvNode> child;
	std::shared_ptr<TlvDocument> doc = parent->OwnerDocument().lock();

	if (choiceItem < 1)
	{
		return false;
	}
	if (choiceItem > (int32_t)__metadataCount)
	{
		return false;
	}


	meta = &__metadata[choiceItem - 1];
	if (HasData(data, meta))
	{
		child = CreateNodeFromData(doc, data, meta);
		if (!!child)
			parent->AppendChild(child);
		else if (meta->defaultValue == nullptr && meta->offsetToExistsFlag >= 0)
		{
			return false;
		}
	}
	else if (meta->offsetToExistsFlag >= 0 || meta->defaultValue != nullptr)
	{
	}
	else
	{
		return false;
	}
	return true;
}

bool tscrypto::DecodeChoiceTlv(void* data, const std::shared_ptr<TlvNode> parent, int32_t* choiceItem, const Asn1Metadata2* __metadata, size_t __metadataCount, bool decodeSelectedOnly)
{
	size_t metaIndex = 0;
	const Asn1Metadata2 *meta;
	bool goToNext;

	if (choiceItem == nullptr)
		return false;

	*choiceItem = 0;

	ClearTlv(data, __metadata, __metadataCount);

	do
	{
		goToNext = false;
		if (__metadataCount <= metaIndex)
		{
			if (decodeSelectedOnly)
				return true;
			//LOG(gMetaDebug, "ERROR:  metaIndex > count");
			return false;
		}
		meta = &__metadata[metaIndex++];
		switch (NodeMatchesMetadata(parent, meta))
		{
		case Asn1Metadata2::good:
		{
			if (!CreateDataFromNode(data, parent, meta))
			{
				//LOG(gMetaDebug, "ERROR:  NodeToData failed for " << meta->ItemName());
				return false;
			}
			*choiceItem = (int32_t)(metaIndex);
		}
		break;
		case Asn1Metadata2::defaulted:
			*choiceItem = (int32_t)(metaIndex);
			break;
		case Asn1Metadata2::mismatch:
			goToNext = true;
			break;
		}
	} while (goToNext);

	if (*choiceItem == 0)
		return false;
	return true;
}

static std::shared_ptr<TlvNode> CreateSequenceOfNodeFromData(std::shared_ptr<TlvDocument> doc, const void* data, const Asn1Metadata2* item_metadata, ptrdiff_t arrayOffset)
{
	std::shared_ptr<TlvNode> node = doc->CreateSequence();
	if (!node)
		return node;

	switch (item_metadata->fieldFlags & 0xff)
	{
	case Asn1Metadata2::tp_int8:
	{
		standardLayoutList<int8_t>& ary = *(standardLayoutList<int8_t>*)(((unsigned char*)data) + arrayOffset);
		for (size_t i = 0; i < ary.size(); i++)
		{
			int8_t item = ary[i];
			std::shared_ptr<TlvNode> itemnode = node->OwnerDocument().lock()->CreateTlvNode(item_metadata->tag, (uint8_t)item_metadata->type);
			itemnode->InnerDataAsNumber(item);
			node->AppendChild(itemnode);
		}
		break;
	}
	case Asn1Metadata2::tp_int16:
	{
		standardLayoutList<int16_t>& ary = *(standardLayoutList<int16_t>*)(((unsigned char*)data) + arrayOffset);
		for (size_t i = 0; i < ary.size(); i++)
		{
			int16_t item = ary[i];
			std::shared_ptr<TlvNode> itemnode = node->OwnerDocument().lock()->CreateTlvNode(item_metadata->tag, (uint8_t)item_metadata->type);
			itemnode->InnerDataAsNumber(item);
			node->AppendChild(itemnode);
		}
		break;
	}
	case Asn1Metadata2::tp_int32:
	{
		standardLayoutList<int32_t>& ary = *(standardLayoutList<int32_t>*)(((unsigned char*)data) + arrayOffset);
		for (size_t i = 0; i < ary.size(); i++)
		{
			int32_t item = ary[i];
			std::shared_ptr<TlvNode> itemnode = node->OwnerDocument().lock()->CreateTlvNode(item_metadata->tag, (uint8_t)item_metadata->type);
			itemnode->InnerDataAsNumber(item);
			node->AppendChild(itemnode);
		}
		break;
	}
	case Asn1Metadata2::tp_int64:
	{
		standardLayoutList<int64_t>& ary = *(standardLayoutList<int64_t>*)(((unsigned char*)data) + arrayOffset);
		for (size_t i = 0; i < ary.size(); i++)
		{
			int64_t item = ary[i];
			std::shared_ptr<TlvNode> itemnode = node->OwnerDocument().lock()->CreateTlvNode(item_metadata->tag, (uint8_t)item_metadata->type);
			itemnode->InnerDataAsNumber(item);
			node->AppendChild(itemnode);
		}
		break;
	}
	case Asn1Metadata2::tp_char:
	{
		standardLayoutList<char>& ary = *(standardLayoutList<char>*)(((unsigned char*)data) + arrayOffset);
		for (size_t i = 0; i < ary.size(); i++)
		{
			char item = ary[i];
			std::shared_ptr<TlvNode> itemnode = node->OwnerDocument().lock()->CreateTlvNode(item_metadata->tag, (uint8_t)item_metadata->type);
			itemnode->InnerDataAsNumber(item);
			node->AppendChild(itemnode);
		}
		break;
	}
	case Asn1Metadata2::tp_null:
		return nullptr;
	case Asn1Metadata2::tp_bool:
	{
		standardLayoutList<bool>& ary = *(standardLayoutList<bool>*)(((unsigned char*)data) + arrayOffset);
		for (size_t i = 0; i < ary.size(); i++)
		{
			bool item = ary[i];
			std::shared_ptr<TlvNode> itemnode = node->OwnerDocument().lock()->CreateTlvNode(item_metadata->tag, (uint8_t)item_metadata->type);
			itemnode->InnerDataAsNumber(item ? 0xff : 0);
			node->AppendChild(itemnode);
		}
		break;
	}
	case Asn1Metadata2::tp_string:
	{
		standardLayoutList<tsCryptoString>& ary = *(standardLayoutList<tsCryptoString>*)(((unsigned char*)data) + arrayOffset);
		for (size_t i = 0; i < ary.size(); i++)
		{
			tsCryptoString& item = ary[i];
			std::shared_ptr<TlvNode> itemnode = node->OwnerDocument().lock()->CreateTlvNode(item_metadata->tag, (uint8_t)item_metadata->type);
			itemnode->InnerString(item);
			node->AppendChild(itemnode);
		}
		break;
	}
	case Asn1Metadata2::tp_data:
	{
		standardLayoutList<tsCryptoData>& ary = *(standardLayoutList<tsCryptoData>*)(((unsigned char*)data) + arrayOffset);
		for (size_t i = 0; i < ary.size(); i++)
		{
			tsCryptoData& item = ary[i];
			std::shared_ptr<TlvNode> itemnode = node->OwnerDocument().lock()->CreateTlvNode(item_metadata->tag, (uint8_t)item_metadata->type);
			itemnode->InnerData(item);
			node->AppendChild(itemnode);
		}
		break;
	}
	case Asn1Metadata2::tp_number:
	{
		standardLayoutList<tsCryptoData>& ary = *(standardLayoutList<tsCryptoData>*)(((unsigned char*)data) + arrayOffset);
		for (size_t i = 0; i < ary.size(); i++)
		{
			tsCryptoData tmp = ary[i];
			if (tmp.size() > 0 && tmp[0] & 0x80)
				tmp.insert(0, (uint8_t)0);
			std::shared_ptr<TlvNode> itemnode = node->OwnerDocument().lock()->CreateTlvNode(item_metadata->tag, (uint8_t)item_metadata->type);
			itemnode->InnerData(tmp);
			node->AppendChild(itemnode);
		}
		break;
	}
	case Asn1Metadata2::tp_guid:
	{
		standardLayoutList<GUID>& ary = *(standardLayoutList<GUID>*)(((unsigned char*)data) + arrayOffset);
		for (size_t i = 0; i < ary.size(); i++)
		{
			GUID item = ary[i];
			tsCryptoData tmp((uint8_t*)&item, sizeof(GUID));
			std::shared_ptr<TlvNode> itemnode = node->OwnerDocument().lock()->CreateTlvNode(item_metadata->tag, (uint8_t)item_metadata->type);
			itemnode->InnerData(tmp);
			node->AppendChild(itemnode);
		}
		break;
	}
	case Asn1Metadata2::tp_any:
	{
		standardLayoutList<Asn1AnyField>& ary = *(standardLayoutList<Asn1AnyField>*)(((unsigned char*)data) + arrayOffset);
		for (size_t i = 0; i < ary.size(); i++)
		{
			Asn1AnyField item = ary[i];
			std::shared_ptr<TlvNode> itemnode = node->OwnerDocument().lock()->CreateTlvNode(item.tag, (uint8_t)item.type);
			itemnode->InnerData(item.value);
			node->AppendChild(itemnode);
		}
		break;
	}
	case Asn1Metadata2::tp_set:
	case Asn1Metadata2::tp_struct:
	case Asn1Metadata2::tp_choice:
	case Asn1Metadata2::tp_sequenceOfRef:
	{
		if (item_metadata->encoder == nullptr)
		{
			throw tscrypto::Exception("The encoder is not specified.");
		}
		standardLayoutList<Asn1ObjectWrapper>& ary = *(standardLayoutList<Asn1ObjectWrapper>*)(((unsigned char*)data) + arrayOffset);
		for (size_t i = 0; i < ary.size(); i++)
		{
			Asn1ObjectWrapper& item = ary[i];

			if (!item_metadata->encoder(item.get(), node))
				return nullptr;
		}
		break;
	}
	case Asn1Metadata2::tp_bits:
	{
		standardLayoutList<Asn1Bitstring>& ary = *(standardLayoutList<Asn1Bitstring>*)(((unsigned char*)data) + arrayOffset);
		for (size_t i = 0; i < ary.size(); i++)
		{
			Asn1Bitstring item = ary[i];
			std::shared_ptr<TlvNode> itemnode = node->OwnerDocument().lock()->CreateTlvNode(item_metadata->tag, (uint8_t)item_metadata->type);
			itemnode->InnerData(item.rawData());
			node->AppendChild(itemnode);
		}
		break;
	}
	case Asn1Metadata2::tp_date:
	{
		standardLayoutList<tsCryptoDate>& ary = *(standardLayoutList<tsCryptoDate>*)(((unsigned char*)data) + arrayOffset);
		for (size_t i = 0; i < ary.size(); i++)
		{
			tsCryptoDate item = ary[i];
			std::shared_ptr<TlvNode> itemnode = node->OwnerDocument().lock()->CreateTlvNode(item_metadata->tag, (uint8_t)item_metadata->type);
			itemnode->InnerString(item.ToZuluTime());
			node->AppendChild(itemnode);
		}
		break;
	}
	case Asn1Metadata2::tp_oid:
	{
		standardLayoutList<tsCryptoData>& ary = *(standardLayoutList<tsCryptoData>*)(((unsigned char*)data) + arrayOffset);
		for (size_t i = 0; i < ary.size(); i++)
		{
			tsCryptoData& item = ary[i];
			std::shared_ptr<TlvNode> itemnode = node->OwnerDocument().lock()->CreateTlvNode(item_metadata->tag, (uint8_t)item_metadata->type);
			itemnode->InnerData(item);
			node->AppendChild(itemnode);
		}
		break;
	}
	}
	return node;
}

bool tscrypto::ClearSequenceOfTlv(void* data, const Asn1Metadata2* meta, ptrdiff_t offsetToArray)
{
	switch (meta->fieldFlags & 0xff)
	{
	case Asn1Metadata2::tp_int8:
		((standardLayoutList<int8_t>*)(((unsigned char*)data) + offsetToArray))->clear();
		break;
	case Asn1Metadata2::tp_int16:
		((standardLayoutList<int16_t>*)(((unsigned char*)data) + offsetToArray))->clear();
		break;
	case Asn1Metadata2::tp_int32:
		((standardLayoutList<int32_t>*)(((unsigned char*)data) + offsetToArray))->clear();
		break;
	case Asn1Metadata2::tp_int64:
		((standardLayoutList<int64_t>*)(((unsigned char*)data) + offsetToArray))->clear();
		break;
	case Asn1Metadata2::tp_bool:
		((standardLayoutList<bool>*)(((unsigned char*)data) + offsetToArray))->clear();
		break;
	case Asn1Metadata2::tp_string:
		((standardLayoutList<tsCryptoString>*)(((unsigned char*)data) + offsetToArray))->clear();
		break;
	case Asn1Metadata2::tp_data:
	case Asn1Metadata2::tp_oid:
	case Asn1Metadata2::tp_number:
		((standardLayoutList<tsCryptoData>*)(((unsigned char*)data) + offsetToArray))->clear();
		break;
	case Asn1Metadata2::tp_any:
		((standardLayoutList<Asn1AnyField>*)(((unsigned char*)data) + offsetToArray))->clear();
		break;
	case Asn1Metadata2::tp_bits:
		((standardLayoutList<Asn1Bitstring>*)(((unsigned char*)data) + offsetToArray))->clear();
		break;
	case Asn1Metadata2::tp_date:
		((standardLayoutList<tsCryptoDate>*)(((unsigned char*)data) + offsetToArray))->clear();
		break;
	case Asn1Metadata2::tp_guid:
		((standardLayoutList<GUID>*)(((unsigned char*)data) + offsetToArray))->clear();
		break;
	case Asn1Metadata2::tp_struct:
	case Asn1Metadata2::tp_set:
	case Asn1Metadata2::tp_choice:
	case Asn1Metadata2::tp_sequenceOfRef:
		((standardLayoutList<Asn1ObjectWrapper>*)(((unsigned char*)data) + offsetToArray))->clear();
		break;
	}
	if (meta->offsetToExistsFlag >= 0)
	{
		*(bool*)(((unsigned char*)data) + meta->offsetToExistsFlag) = false;
	}
	return true;
}


bool tscrypto::EncodeSequenceOfTlv(void* data, std::shared_ptr<TlvNode> parent, const Asn1Metadata2* __metadata, ptrdiff_t offsetToArray)
{
	std::shared_ptr<TlvNode> child;
	std::shared_ptr<TlvDocument> doc = parent->OwnerDocument().lock();

	if (HasData(data, __metadata))
	{
		child = CreateSequenceOfNodeFromData(doc, data, __metadata, offsetToArray);
		if (!!child)
		{
			child->Tag(parent->Tag());
			child->Type(parent->Type());
			parent->OuterData(child->OuterData());
		}
		else
		{
			return false;
		}
	}
	else
	{
		return false;
	}
	return true;
}

static bool CreateDataFromSequenceOfNode(void* data, const std::shared_ptr<TlvNode> node, const Asn1Metadata2* metadata, ptrdiff_t arrayOffset)
{
	// metadata is an element in the array
	bool hadData = false;

	if (std::find_if(node->Children()->begin(), node->Children()->end(), [&data, metadata, &hadData, arrayOffset](const std::shared_ptr<TlvNode>& child)->bool {
		if ((metadata->fieldFlags & 0xff) == Asn1Metadata2::tp_any)
		{
			standardLayoutList<Asn1AnyField>& ary = *(standardLayoutList<Asn1AnyField>*)(((unsigned char*)data) + arrayOffset);
			Asn1AnyField fld;

			fld.tag = child->Tag();
			fld.type = child->Type();
			fld.value = child->InnerData();
			ary.push_back(fld);
			if (metadata->offsetToExistsFlag >= 0)
			{
				*(bool*)(((uint8_t*)data) + metadata->offsetToExistsFlag) = true;
			}
			hadData = true;
			return false;
		}

		if ((metadata->fieldFlags & 0xff) != Asn1Metadata2::tp_choice)
		{
			if (child->Tag() != metadata->tag || child->Type() != metadata->type)
				return true;
		}

		hadData = true;
		if (metadata->offsetToExistsFlag >= 0)
		{
			*(bool*)(((uint8_t*)data) + metadata->offsetToExistsFlag) = true;
		}
		switch (metadata->fieldFlags & 0xff)
		{
		case Asn1Metadata2::tp_int8:
			((standardLayoutList<int8_t>*)(((unsigned char*)data) + arrayOffset))->push_back((int8_t)child->InnerDataAsNumber());
			break;
		case Asn1Metadata2::tp_int16:
			((standardLayoutList<int16_t>*)(((unsigned char*)data) + arrayOffset))->push_back((int16_t)child->InnerDataAsNumber());
			break;
		case Asn1Metadata2::tp_int32:
			((standardLayoutList<int32_t>*)(((unsigned char*)data) + arrayOffset))->push_back((int32_t)child->InnerDataAsNumber());
			break;
		case Asn1Metadata2::tp_int64:
			((standardLayoutList<int64_t>*)(((unsigned char*)data) + arrayOffset))->push_back((int64_t)child->InnerDataAsNumber());
			break;
		case Asn1Metadata2::tp_char:
			((standardLayoutList<char>*)(((unsigned char*)data) + arrayOffset))->push_back((char)child->InnerDataAsNumber());
			break;
		case Asn1Metadata2::tp_null:
			return true;
		case Asn1Metadata2::tp_bool:
			((standardLayoutList<bool>*)(((unsigned char*)data) + arrayOffset))->push_back((child->InnerDataAsNumber() != 0) ? 1 : 0);
			break;
		case Asn1Metadata2::tp_string:
			((standardLayoutList<tsCryptoString>*)(((unsigned char*)data) + arrayOffset))->push_back(child->InnerString());
			break;
		case Asn1Metadata2::tp_oid:
		case Asn1Metadata2::tp_data:
			((standardLayoutList<tsCryptoData>*)(((unsigned char*)data) + arrayOffset))->push_back(child->InnerData());
			break;
		case Asn1Metadata2::tp_number:
		{
			tsCryptoData tmp(child->InnerData());

			if (tmp.size() > 1 && tmp[0] == 0 && tmp[1] & 0x80)
				tmp.erase(0, 1);
			((standardLayoutList<tsCryptoData>*)(((unsigned char*)data) + arrayOffset))->push_back(tmp);
			break;
		}
		case Asn1Metadata2::tp_guid:
		{
			tsCryptoData tmp(child->InnerData());

			if (tmp.size() != sizeof(GUID))
				return true;
			((standardLayoutList<GUID>*)(((unsigned char*)data) + arrayOffset))->push_back(*(const GUID*)tmp.c_str());
			break;
		}
		case Asn1Metadata2::tp_set:
			throw tscrypto::Exception("Arrays of sets not implemented in the Tlv Decoder");
			// TODO:  Implement me
			//			return true;
		case Asn1Metadata2::tp_choice:
		case Asn1Metadata2::tp_sequenceOfRef:
		case Asn1Metadata2::tp_struct:
		{
			if (metadata->creator == nullptr)
			{
				throw tscrypto::Exception("The creator is missing.");
			}
			if (metadata->decoder == nullptr)
			{
				throw tscrypto::Exception("The decoder is missing.");
			}

			standardLayoutList<Asn1ObjectWrapper>& ary = *(standardLayoutList<Asn1ObjectWrapper>*)(((unsigned char*)data) + arrayOffset);
			Asn1ObjectWrapper fld;

			fld = metadata->creator();
			if (!metadata->decoder(fld.get(), child))
				return true;
			ary.push_back(std::move(fld));
			break;
		}

		case Asn1Metadata2::tp_bits:
		{
			Asn1Bitstring fld;

			fld.rawData(child->InnerData());
			((standardLayoutList<Asn1Bitstring>*)(((unsigned char*)data) + arrayOffset))->push_back(fld);
			break;
		}
		case Asn1Metadata2::tp_date:
		{
			tsCryptoDate dt(child->InnerString(), tsCryptoDate::Zulu);
			((standardLayoutList<tsCryptoDate>*)(((unsigned char*)data) + arrayOffset))->push_back(dt);
			break;
		}
		}

		return false;
	}) != node->Children()->end())
	{
		return false;
	}
	return true;
}

bool tscrypto::DecodeSequenceOfTlv(void* data, const std::shared_ptr<TlvNode> parent, const Asn1Metadata2* __metadata, ptrdiff_t offsetToArray)
{
	ClearSequenceOfTlv(data, __metadata, offsetToArray);

	if (!CreateDataFromSequenceOfNode(data, parent, __metadata, offsetToArray))
	{
		//LOG(gMetaDebug, "ERROR:  NodeToData failed for " << meta->ItemName());
		return false;
	}
	return true;
}
