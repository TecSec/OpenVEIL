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

/*! @file tsTlvSerializer.h
* @brief This file defines a set of functions that implement a TLV serializer.
*/

#ifndef __TSTLVSERIALIZER_H__
#define __TSTLVSERIALIZER_H__

#pragma once

//#define NO_TLV_DEBUG

/**
* \brief Defines an identifier for the type of pre/post processing to perform.
*/
//typedef enum TLVProcessType {
//	tlvp_PreDecode, ///< An enum constant representing the tlvp pre decode option
//	tlvp_PostDecode,	///< An enum constant representing the tlvp post decode option
//	tlvp_PreEncode, ///< An enum constant representing the tlvp pre encode option
//	tlvp_PostEncode,	///< An enum constant representing the tlvp post encode option
//}TLVProcessType;

namespace tscrypto {

	/// <summary>If false it enables the older handling for ASN.1 any fields where we encoded them as a base64 string of the node OuterData.</summary>
	extern VEILCORE_API bool gPersistAnyfieldAsObject;


		// New form
	class VEILCORE_API Asn1ObjectWrapper
	{
	public:
		typedef void(*vvpFn)(void *);
		typedef void* (*vpvpFn)(void *);

		static void* operator new(std::size_t count) {
			return tscrypto::cryptoNew(count);
		}
		static void* operator new[](std::size_t count) {
			return tscrypto::cryptoNew(count);
		}
			static void operator delete(void* ptr) {
			tscrypto::cryptoDelete(ptr);
		}
		static void operator delete[](void* ptr) {
			tscrypto::cryptoDelete(ptr);
		}

		Asn1ObjectWrapper()
			: _deleteFunc(nullptr), _clonerFunc(nullptr), _object(nullptr) {
			static_assert(std::is_standard_layout<Asn1ObjectWrapper>::value,
				"Asn1ObjectWrapper is not a standard layout type.");
		}
		Asn1ObjectWrapper(vvpFn deleteFunc, vpvpFn cloner, void* object) : _deleteFunc(deleteFunc), _clonerFunc(cloner), _object(object)
		{
			static_assert(std::is_standard_layout<Asn1ObjectWrapper>::value, "Asn1ObjectWrapper is not a standard layout type.");
			if (deleteFunc == nullptr || object == nullptr)
				throw tscrypto::Exception("Both the deleteFunc and object must be specified.");
		}
		Asn1ObjectWrapper(const Asn1ObjectWrapper& obj) : _deleteFunc(obj._deleteFunc), _clonerFunc(obj._clonerFunc)
		{
			if (obj._object != nullptr && _clonerFunc != nullptr)
			{
				_object = _clonerFunc(obj._object);
			}
		}
		Asn1ObjectWrapper(Asn1ObjectWrapper&& obj) : _deleteFunc(obj._deleteFunc), _clonerFunc(obj._clonerFunc), _object(std::move(obj._object))
		{
			obj._deleteFunc = nullptr;
			obj._object = nullptr;
		}
		Asn1ObjectWrapper& operator=(const Asn1ObjectWrapper& obj)
		{
			if (&obj != this)
			{
				if (_object != nullptr)
				{
					_deleteFunc(_object);
				}
				_deleteFunc = nullptr;
				_clonerFunc = nullptr;
				_object = nullptr;

				_deleteFunc = obj._deleteFunc;
				_clonerFunc = obj._clonerFunc;
				_object = _clonerFunc(obj._object);
			}
			return *this;
		}
		Asn1ObjectWrapper& operator=(Asn1ObjectWrapper&& obj)
		{
			if (&obj != this)
			{
				if (_object != nullptr)
				{
					_deleteFunc(_object);
				}
				_deleteFunc = nullptr;
				_clonerFunc = nullptr;
				_object = nullptr;

				_deleteFunc = obj._deleteFunc;
				_clonerFunc = obj._clonerFunc;
				_object = obj._object;

				obj._deleteFunc = nullptr;
				obj._clonerFunc = nullptr;
				obj._object = nullptr;
			}
			return *this;
		}
		~Asn1ObjectWrapper()
		{
			if (_object != nullptr)
			{
				_deleteFunc(_object);
			}
			_deleteFunc = nullptr;
			_clonerFunc = nullptr;
			_object = nullptr;
		}
		void* get() { return _object; }
		const void* get() const { return _object; }
	private:
		vvpFn _deleteFunc;
		vpvpFn _clonerFunc;
		void* _object;
	};

	struct VEILCORE_API Asn1Metadata2 final
	{
		typedef enum { defaulted, good, mismatch } matchResult;

		static void* operator new(std::size_t count) {
			return tscrypto::cryptoNew(count);
		}
		static void* operator new[](std::size_t count) {
			return tscrypto::cryptoNew(count);
		}
			static void operator delete(void* ptr) {
			tscrypto::cryptoDelete(ptr);
		}
		static void operator delete[](void* ptr) {
			tscrypto::cryptoDelete(ptr);
		}

		enum FieldFlags {
			tp_none, tp_int8, tp_int16, tp_int32, tp_int64, tp_char, tp_bool, tp_string, tp_data, tp_date, tp_struct, tp_set, tp_number, tp_guid, tp_any, tp_oid, tp_bits, tp_null, tp_choice,
			tp_sequenceOfRef,
			//tp_ver_oid, tp_ver_number, tp_ver_oid_number, // < used for object versioning - choice field = min ver number, Secondary = max field number, OID in defaultValue
			tp_optional = 256, /*tp_array = 512*/
		} fieldFlags;
		int offsetToData;
		int offsetToExistsFlag;
		int offsetToTag;
		int offsetToType;
		int offsetToChoiceField;
		const struct Asn1Metadata2* subMetadata;
		size_t subMetadataCount;
		int tag;
		TlvNode::TlvType type;
		const char* jsonName;
		const char* name;
		const char* defaultValue;
		matchResult(*NodeMatchesMetadataFn)(const std::shared_ptr<TlvNode> node, const Asn1Metadata2* metadata);
		Asn1ObjectWrapper(*creator)();
		bool(*encoder)(void*, std::shared_ptr<tscrypto::TlvNode> parent);
		bool(*decoder)(void*, const std::shared_ptr<tscrypto::TlvNode> root);
		void(*clearer)(void*);
		//void(*destroyer)(void*);
	};
	struct VEILCORE_API Asn1Version2 final
	{
		static void* operator new(std::size_t count) {
			return tscrypto::cryptoNew(count);
		}
		static void* operator new[](std::size_t count) {
			return tscrypto::cryptoNew(count);
		}
			static void operator delete(void* ptr) {
			tscrypto::cryptoDelete(ptr);
		}
		static void operator delete[](void* ptr) {
			tscrypto::cryptoDelete(ptr);
		}

		const char* oid;
		bool checkVersion;
		int minVersion;
		int maxVersion;
		const struct Asn1Metadata2* subMetadata;
		unsigned int subMetadataCount;
	};
	struct VEILCORE_API Asn1StructureDefinition2 final
	{
		static void* operator new(std::size_t count) {
			return tscrypto::cryptoNew(count);
		}
		static void* operator new[](std::size_t count) {
			return tscrypto::cryptoNew(count);
		}
			static void operator delete(void* ptr) {
			tscrypto::cryptoDelete(ptr);
		}
		static void operator delete[](void* ptr) {
			tscrypto::cryptoDelete(ptr);
		}

		int tag;
		TlvNode::TlvType type;
		const struct Asn1Metadata2* subMetadata;
		size_t subMetadataCount;
		const struct Asn1Version2* versionList;
		size_t versionCount;
		const char* defaultOID;
		const char* defaultVersion;
		bool dontWrap;
	};
	typedef struct VEILCORE_API Asn1AnyField final {
		static void* operator new(std::size_t count) {
			return tscrypto::cryptoNew(count);
		}
		static void* operator new[](std::size_t count) {
			return tscrypto::cryptoNew(count);
		}
			static void operator delete(void* ptr) {
			tscrypto::cryptoDelete(ptr);
		}
		static void operator delete[](void* ptr) {
			tscrypto::cryptoDelete(ptr);
		}

		Asn1AnyField() : tag(0), type(TlvNode::Type_Universal) {}
		Asn1AnyField(int32_t inTag, uint8_t inType, const tsCryptoData& inValue) : tag(inTag), type(inType), value(inValue) {}
		Asn1AnyField(const JSONObject& obj) :tag(0), type(TlvNode::Type_Universal) { fromJSON(obj); }
		Asn1AnyField(const Asn1AnyField& obj) : tag(obj.tag), type(obj.type), value(obj.value) {}
		Asn1AnyField(Asn1AnyField&& obj) : tag(obj.tag), type(obj.type), value(std::move(obj.value)) { obj.tag = 0; obj.type = 0; }
		Asn1AnyField& operator=(const Asn1AnyField& obj)
		{
			if (&obj != this)
			{
				tag = obj.tag;
				type = obj.type;
				value = obj.value;
			}
			return *this;
		}
		Asn1AnyField& operator=(Asn1AnyField&& obj)
		{
			if (&obj != this)
			{
				tag = obj.tag;
				type = obj.type;
				value = std::move(obj.value);

				obj.tag = 0;
				obj.type = 0;
			}
			return *this;
		}
		bool operator==(const Asn1AnyField& obj) const { return tag == obj.tag && type == obj.type && value == obj.value; }
		bool operator!=(const Asn1AnyField& obj) const { return !(obj == *this); }

		int tag;	///< The tag
		uint8_t type;   ///< The type
		tsCryptoData value;   ///< The value

		void clear()
		{
			tag = 0;
			type = TlvNode::Type_Universal;
			value.clear();
		}
		void rawData(const tsCryptoData& setTo)
		{
			bool constructed;
			size_t length;

			size_t tLength = TlvNode::ExtractTagAndLength(setTo, 0, false, false, tag, constructed, type, length);
			value = setTo.substring(tLength, setTo.size() - tLength);
		}
		tsCryptoData EncodeToData(bool withoutWrapper = false) const
		{
			std::shared_ptr<TlvDocument> doc = TlvDocument::Create();
			std::shared_ptr<TlvNode> node = doc->CreateTlvNode(tag, (uint8_t)type);
			node->InnerData(value);
			return doc->SaveTlv();
		}
		JSONObject toJSON() const
		{
			JSONObject obj;
			if (!toJSON(obj))
				return JSONObject();
			return obj;
		}
		bool toJSON(JSONObject& obj) const
		{
			obj
				.add("tag", (int64_t)tag)
				.add("type", (int64_t)type)
				.add("data", value.ToBase64());
			return true;
		}
		bool fromJSON(const char* json)
		{
			JSONObject obj;
			if (!obj.FromJSON(json))
				return false;
			return fromJSON(obj);
		}
		bool fromJSON(const JSONObject& obj)
		{
			if (!obj.hasField("tag") || !obj.hasField("type"))
				return false;
			clear();
			tag = (int)obj.AsNumber("tag", 0);
			type = (uint8_t)obj.AsNumber("type", 0);
			value = obj.AsString("data").Base64ToData();
			return true;
		}
		bool fromJSON(const tsCryptoStringBase& json)
		{
			return fromJSON(json.c_str());
		}
	} Asn1AnyField;
	typedef struct VEILCORE_API Asn1Bitstring final
	{
		static void* operator new(std::size_t count) {
			return tscrypto::cryptoNew(count);
		}
		static void* operator new[](std::size_t count) {
			return tscrypto::cryptoNew(count);
		}
			static void operator delete(void* ptr) {
			tscrypto::cryptoDelete(ptr);
		}
		static void operator delete[](void* ptr) {
			tscrypto::cryptoDelete(ptr);
		}

		Asn1Bitstring() {}
		Asn1Bitstring(uint8_t unusedPart, const tsCryptoData& usedPart) { dataHolder.append(unusedPart).append(usedPart); }
		Asn1Bitstring(const Asn1Bitstring& obj) : dataHolder(obj.dataHolder) {}
		Asn1Bitstring(Asn1Bitstring&& obj) : dataHolder(std::move(obj.dataHolder)) {}
		Asn1Bitstring& operator=(const Asn1Bitstring& obj)
		{
			if (&obj != this)
			{
				dataHolder = obj.dataHolder;
			}
			return *this;
		}
		Asn1Bitstring& operator=(Asn1Bitstring&& obj)
		{
			if (&obj != this)
			{
				dataHolder = std::move(obj.dataHolder);
			}
			return *this;
		}
		bool operator==(const Asn1Bitstring& obj) const { return dataHolder == obj.dataHolder; }
		bool operator!=(const Asn1Bitstring& obj) const { return !(obj == *this); }
		uint8_t UnusedBitCount() const { if (dataHolder.size() == 0) return 0; return dataHolder[0]; }
		void UnusedBitCount(uint8_t setTo) { if (dataHolder.size() == 0) dataHolder.resize(1); dataHolder[0] = setTo; }
		tsCryptoData bits() const { return dataHolder.substring(1, 0x7FFFFFFF); }
		void bits(const tsCryptoData& setTo) { dataHolder.resize(1); dataHolder += setTo; }
		tsCryptoData rawData() const { return dataHolder; }
		void rawData(const tsCryptoData& setTo) { dataHolder = setTo; }
		void clear()
		{
			dataHolder.clear();
		}
		void setBit(int bitNumber) {
			int byteNumber = bitNumber >> 3;
			if ((int)dataHolder.size() <= byteNumber)
				dataHolder.resize(byteNumber + 1);
			dataHolder[byteNumber] |= (0x80 >> (bitNumber & 7));
		}
		void clearBit(int bitNumber) {
			int byteNumber = bitNumber >> 3;
			if ((int)dataHolder.size() <= byteNumber)
				return;
			dataHolder[byteNumber] &= ~(0x80 >> (bitNumber & 7));
		}
		bool testBit(int bitNumber) {
			int byteNumber = bitNumber >> 3;
			if ((int)dataHolder.size() <= byteNumber)
				return false;
			return (dataHolder[byteNumber] & (0x80 >> (bitNumber & 7))) ? true : false;
		}
		tsCryptoData toData() const
		{
			std::shared_ptr<TlvDocument> doc = TlvDocument::Create();

			doc->DocumentElement()->Tag(TlvNode::Tlv_BitString);
			doc->DocumentElement()->Type(TlvNode::Type_Universal);
			doc->DocumentElement()->InnerData(dataHolder);
			return doc->SaveTlv();
		}
		tsCryptoData dataHolder;	///< The data holder
		tsCryptoData EncodeToData(bool withoutWrapper = false) const
		{
			return toData();
		}
	} Asn1Bitstring;


#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4231)

	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API tscrypto::standardLayoutList<int8_t>;
	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API tscrypto::standardLayoutList<int16_t>;
	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API tscrypto::standardLayoutList<int32_t>;
	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API tscrypto::standardLayoutList<int64_t>;
	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API tscrypto::standardLayoutList<char>;
	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API tscrypto::standardLayoutList<bool>;
	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API tscrypto::standardLayoutList<GUID>;
	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API tscrypto::standardLayoutList<tscrypto::Asn1Bitstring>;
	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API tscrypto::standardLayoutList<tscrypto::tsCryptoDate>;
	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API tscrypto::standardLayoutList<tscrypto::tsCryptoData>;
	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API tscrypto::standardLayoutList<tscrypto::tsCryptoString>;
	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API tscrypto::standardLayoutList<tscrypto::Asn1ObjectWrapper>;
	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API tscrypto::standardLayoutList<tscrypto::Asn1AnyField>;

#pragma warning(pop)
#endif // _MSC_VER


	bool VEILCORE_API ClearTlv(void* data, const Asn1Metadata2* __metadata, size_t __metadataCount);
	bool VEILCORE_API EncodeTlv(void* data, std::shared_ptr<TlvNode> parent, const Asn1Metadata2* __metadata, size_t __metadataCount);
	bool VEILCORE_API DecodeTlv(void* data, const std::shared_ptr<TlvNode> parent, const Asn1Metadata2* __metadata, size_t __metadataCount, bool decodeSelectedOnly = false);
	Asn1Metadata2::matchResult VEILCORE_API NodeMatchesMetadata(const std::shared_ptr<TlvNode> node, const Asn1Metadata2* metadata);
	bool VEILCORE_API FindVersionToEncode(void* data, const Asn1StructureDefinition2& def, const struct Asn1Metadata2*& metadata, size_t& count);
	bool VEILCORE_API FindVersionToDecode(const std::shared_ptr<TlvNode> root, const Asn1StructureDefinition2& def, const struct Asn1Metadata2*& metadata, size_t& count);
	bool VEILCORE_API EncodeChoiceTlv(void* data, std::shared_ptr<TlvNode> parent, int32_t choiceItem, const Asn1Metadata2* __metadata, size_t __metadataCount);
	bool VEILCORE_API DecodeChoiceTlv(void* data, const std::shared_ptr<TlvNode> parent, int32_t *choiceItem, const Asn1Metadata2* __metadata, size_t __metadataCount, bool decodeSelectedOnly = false);
	bool VEILCORE_API EncodeSequenceOfTlv(void* data, std::shared_ptr<TlvNode> parent, const Asn1Metadata2* __metadata, ptrdiff_t offsetToArray);
	bool VEILCORE_API DecodeSequenceOfTlv(void* data, const std::shared_ptr<TlvNode> parent, const Asn1Metadata2* __metadata, ptrdiff_t offsetToArray);
	bool VEILCORE_API ClearSequenceOfTlv(void* data, const Asn1Metadata2* __metadata, ptrdiff_t offsetToArray);

}
#endif // __TSTLVSERIALIZER_H__

// TODO:  Tlv_ObjectDescriptor, Tlv_Real, Tlv_Set,
