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

////////////////////////////////////////////////////////////////////////////////////////////////////
/// \file   tsCryptoData.h
///
/// <summary>This file defines a common byte array container.</summary>
////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef __TSCRYPTODATA_H__
#define __TSCRYPTODATA_H__

#pragma once

namespace tscrypto {

	class tsCryptoString;
	class tsCryptoData;

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4231)
#pragma warning(disable:4251)
	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API ICryptoContainerWrapper<tsCryptoData>;
	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::shared_ptr<ICryptoContainerWrapper<tsCryptoData>>;
#pragma warning(pop)
#endif // _MSC_VER

	typedef std::shared_ptr<ICryptoContainerWrapper<tsCryptoData>> tsCryptoDataList;

	VEILCORE_API tsCryptoDataList CreateTsCryptoDataList();

	/// <summary>a common byte array container implemented with protection mechanisms for FIPS and CC.</summary>
	class VEILCORE_API tsCryptoData
	{
	public:
		typedef uint8_t value_type;
		typedef size_t size_type;
		typedef ptrdiff_t difference_type;
		typedef uint8_t* pointer;
		typedef uint8_t& reference;
		typedef const uint8_t* const_pointer;
		typedef const uint8_t& const_reference;
		typedef tsCryptoData self_type;
		typedef tsCryptoData* container_type;
		typedef const tsCryptoData* const_container_type;

		typedef CryptoIterator<self_type> iterator;
		typedef const_CryptoIterator<self_type> const_iterator;
		typedef std::reverse_iterator<iterator> reverse_iterator;
		typedef std::reverse_iterator<const_iterator> const_reverse_iterator;

		static const size_type npos;

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

		/// <summary>Specifies the type of string that is to be converted</summary>
		typedef enum DataStringType {
			ASCII,  /*!< Ascii string.  */
			OID,	/*!< OID in string form.  */
			HEX,	/*!< Data in HEX.  */
			BASE64, /*!< Data in Base 64.  */
			BASE64URL, /*!< Data in Base 64 (URL safe form  RFC-4648).  */
		} DataStringType;

		typedef enum {
			encode_Ascii,		///< Encode(d) as Ascii
			encode_Utf8,		///< Encode(d) as UTF-8
			encode_Utf16BE,		///< Encode(d) as UTF-16 big endian
			encode_Utf16LE,		///< Encode(d) as UTF-16 little endian (windows unicode)
			encode_Utf32BE,		///< Encode(d) as UTF-32 big endian
			encode_Utf32LE,		///< Encode(d) as UTF-32 little endian
			encode_Utf7,		///< Encode(d) as UTF-7
			encode_Utf1,		///< Encode(d) as UTF-1
		} UnicodeEncodingType;  ///< Type of the unicode encoding

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Default constructor.</summary>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoData();
		tsCryptoData(size_type count, value_type value);
		tsCryptoData(const tsCryptoData &obj, size_type pos);
		tsCryptoData(const tsCryptoData &obj, size_type pos, size_type count);
		tsCryptoData(const_pointer data, size_type Len);
		tsCryptoData(const_pointer data);
		template <class InputIt>
		tsCryptoData(InputIt first, InputIt last) :
			m_data(nullptr),
			m_used(0),
			m_allocated(-1)
		{
			assign(first, last);
		}
		tsCryptoData(const tsCryptoData &obj);
		tsCryptoData(tsCryptoData &&obj);
		tsCryptoData(std::initializer_list<value_type> init);

		tsCryptoData(const tsCryptoStringBase &value, DataStringType type);
		explicit tsCryptoData(const tsCryptoStringBase &value); // ASCII only
		explicit tsCryptoData(std::initializer_list<char> init);
		tsCryptoData(value_type ch);
		explicit tsCryptoData(char ch);
		~tsCryptoData();

		tsCryptoData &operator=(const tsCryptoData &obj);
		tsCryptoData &operator=(tsCryptoData &&obj);
		tsCryptoData &operator=(const_pointer data); /* zero terminated */
		tsCryptoData &operator=(value_type obj);
		tsCryptoData &operator=(std::initializer_list<value_type> iList);
		tsCryptoData &operator=(const tsCryptoStringBase &obj); // ASCII ONLY - tecsec addition
		tsCryptoData &operator=(const char *data); // zero terminated - tecsec addition

		tsCryptoData& assign(size_type count, value_type ch);
		tsCryptoData& assign(const tsCryptoData &obj);
		tsCryptoData& assign(const tsCryptoData &obj, size_type pos, size_type count = npos);
		tsCryptoData& assign(tsCryptoData &&obj);
		tsCryptoData& assign(const_pointer newData, size_type count);
		tsCryptoData& assign(const_pointer newData);
		template <class InputIt>
		tsCryptoData& assign(InputIt first, InputIt last)
		{
			clear();
			for (auto it = first; it != last; ++it)
			{
				append(*it);
			}
			return *this;
		}
		tsCryptoData &assign(std::initializer_list<value_type> iList);

		reference at(size_type index);
		const_reference at(size_type index) const;
		const_pointer data() const;
		pointer data();
		const_pointer c_str() const;
		reference front();
		const_reference front() const;
		reference back();
		const_reference back() const;
		reference operator[](size_type Index);
		const_reference operator[](size_type Index) const;

		iterator begin();
		const_iterator begin() const;
		iterator end();
		const_iterator end() const;
		const_iterator cbegin() const;
		const_iterator cend() const;
		reverse_iterator rbegin();
		reverse_iterator rend();
		const_reverse_iterator crbegin() const;
		const_reverse_iterator crend() const;

		bool empty() const;
		size_type size() const;
		size_type length() const;
		size_type max_size() const;
		_Post_satisfies_(this->m_data != nullptr) void reserve(size_type newSize = 0);
		size_type capacity() const;
		void clear();

		tsCryptoData& insert(size_type index, size_type count, value_type ch);
		tsCryptoData& insert(size_type index, value_type ch);
		tsCryptoData& insert(size_type index, const_pointer s);
		tsCryptoData& insert(size_type index, const_pointer s, size_type count);
		tsCryptoData& insert(size_type index, const tsCryptoData& str);
		tsCryptoData& insert(size_type index, const tsCryptoData& str, size_type index_str, size_type count = npos);
		tsCryptoData& insert(const_iterator pos, value_type ch);
		tsCryptoData& insert(const_iterator pos, size_type count, value_type ch);
		template <class InputIt>
		tsCryptoData& insert(const_iterator pos, InputIt first, InputIt last)
		{
			if (pos == end())
			{
				append(first, last);
				return *this;
			}
			size_type index = pos - cbegin();
			size_type count = last - first;
			size_type oldsize = size();

			if (index >= size())
				throw tscrypto::OutOfRange();

			resize(size() + count);
			memmove(&m_data[index + count], &m_data[index], sizeof(value_type) * (oldsize - index));
			for (auto it = first; it != last; ++it)
			{
				m_data[index++] = *it;
			}
			return *this;
		}
		tsCryptoData& insert(const_iterator pos, std::initializer_list<value_type> iList);

		tsCryptoData& erase(size_type pos = 0, size_type count = npos);
		iterator erase(const_iterator position);
		iterator erase(const_iterator first, const_iterator last);

		void push_back(value_type ch);
		void pop_back();

		tsCryptoData &append(size_type len, value_type ch);
		tsCryptoData &append(const tsCryptoData &obj);
		tsCryptoData &append(const tsCryptoData &obj, size_type pos, size_type count = npos);
		tsCryptoData &append(const_pointer data, size_type count);
		tsCryptoData &append(const_pointer data);
		template <class InputIt>
		tsCryptoData &append(InputIt first, InputIt last)
		{
			size_type oldsize = size();
			resize(size() + (last - first));
			for (auto it = first; it != last; ++it)
			{
				m_data[oldsize++] = *it;
			}
			return *this;
		}
		tsCryptoData &append(std::initializer_list<value_type> list);

		tsCryptoData &operator += (const tsCryptoData &obj);
		tsCryptoData &operator += (value_type data);
		tsCryptoData &operator += (const_pointer data);
		tsCryptoData &operator += (std::initializer_list<value_type> init);

		int compare(const tsCryptoData& str) const;
		int compare(size_type pos1, size_type count1, const tsCryptoData& str) const;
		int compare(size_type pos1, size_type count1, const tsCryptoData& str, size_type pos2, size_type count2) const;
		int compare(const_pointer s) const;
		int compare(size_type pos1, size_type count1, const_pointer s) const;
		int compare(size_type pos1, size_type count1, const_pointer s, size_type count2) const;

		tsCryptoData& replace(size_type pos, size_type count, const tsCryptoData& str);
		tsCryptoData& replace(const_iterator first, const_iterator last, const tsCryptoData& str);
		tsCryptoData& replace(size_type pos, size_type count, const tsCryptoData& str, size_type pos2, size_type count2 = npos);
		template <class InputIt>
		tsCryptoData& replace(const_iterator first, const_iterator last, InputIt first2, InputIt last2)
		{
			size_type index = first - cbegin();
			erase(first, last);
			insert(index, first2, last2);
			return *this;
		}
		tsCryptoData& replace(size_type pos, size_type count, const_pointer s, size_type count2);
		tsCryptoData& replace(const_iterator first, const_iterator last, const_pointer s, size_type count2);
		tsCryptoData& replace(size_type pos, size_type count, const_pointer s);
		tsCryptoData& replace(const_iterator first, const_iterator last, const_pointer s);
		tsCryptoData& replace(size_type pos, size_type count, size_type count2, value_type ch);
		tsCryptoData& replace(const_iterator first, const_iterator last, size_type count2, value_type ch);
		tsCryptoData& replace(const_iterator first, const_iterator last, std::initializer_list<value_type> iList);

		tsCryptoData substr(size_type start = 0, size_type count = npos) const;
		size_type copy(pointer dest, size_type count, size_type pos = 0) const;
		_Post_satisfies_(this->m_data != nullptr) void resize(size_type newSize);
		_Post_satisfies_(this->m_data != nullptr) void resize(size_type newSize, value_type value);
		void swap(tsCryptoData &obj);

		size_type find(const tsCryptoData& str, size_type pos = 0) const;
		size_type find(const_pointer s, size_type pos, size_type count) const;
		size_type find(const_pointer s, size_type pos = 0) const;
		size_type find(value_type ch, size_type pos = 0) const;

		size_type rfind(const tsCryptoData& str, size_type pos = npos) const;
		size_type rfind(const_pointer s, size_type pos, size_type count) const;
		size_type rfind(const_pointer s, size_type pos = npos) const;
		size_type rfind(value_type ch, size_type pos = npos) const;

		size_type find_first_of(const tsCryptoData& str, size_type pos = 0) const;
		size_type find_first_of(const_pointer s, size_type pos, size_type count) const;
		size_type find_first_of(const_pointer s, size_type pos = 0) const;
		size_type find_first_of(value_type ch, size_type pos = 0) const;

		size_type find_first_not_of(const tsCryptoData& str, size_type pos = 0) const;
		size_type find_first_not_of(const_pointer s, size_type pos, size_type count) const;
		size_type find_first_not_of(const_pointer s, size_type pos = 0) const;
		size_type find_first_not_of(value_type ch, size_type pos = 0) const;

		size_type find_last_of(const tsCryptoData& str, size_type pos = npos) const;
		size_type find_last_of(const_pointer s, size_type pos, size_type count) const;
		size_type find_last_of(const_pointer s, size_type pos = npos) const;
		size_type find_last_of(value_type ch, size_type pos = npos) const;

		size_type find_last_not_of(const tsCryptoData& str, size_type pos = npos) const;
		size_type find_last_not_of(const_pointer s, size_type pos, size_type count) const;
		size_type find_last_not_of(const_pointer s, size_type pos = npos) const;
		size_type find_last_not_of(value_type ch, size_type pos = npos) const;




		// TecSec Extensions
		void FromHexString(const tsCryptoStringBase& inValue);
		void FromOIDString(const tsCryptoStringBase& inValue);
		void FromBase64(const tsCryptoStringBase& inValue, bool base64Url = false, bool padWithEquals = true);
		tsCryptoData substring(size_type start, size_type length) const;
		tsCryptoData& assign(const char *newData, size_type count); 
		tsCryptoData& assign(const char *newData); 
		tsCryptoData& assign(const tsCryptoStringBase &obj);
		tsCryptoData &assign(std::initializer_list<char> iList);
		tsCryptoData &assign(value_type data);
		tsCryptoData &assign(char data);
		tsCryptoData &assign(int16_t val);
		tsCryptoData &assign(int32_t val);
		tsCryptoData &assign(int64_t val);
		tsCryptoData &assign(uint16_t val);
		tsCryptoData &assign(uint32_t val);
		tsCryptoData &assign(uint64_t val);

		value_type c_at(size_type index) const;
		pointer rawData(); 
		tsCryptoData& insert(size_type index, size_type count, char ch);
		tsCryptoData& insert(size_type index, char ch);
		tsCryptoData& insert(size_type index, const char* s);
		tsCryptoData& insert(size_type index, const char* s, size_type count);
		tsCryptoData& insert(size_type index, const tsCryptoStringBase& str);
		tsCryptoData& insert(size_type index, const tsCryptoStringBase& str, size_type index_str, size_type count = npos);
		tsCryptoData& insert(const_iterator pos, char ch);
		tsCryptoData& insert(const_iterator pos, size_type count, char ch);
		tsCryptoData& insert(const_iterator pos, std::initializer_list<char> iList);
		tsCryptoData &operator=(std::initializer_list<char> iList);
		void push_back(char ch);

		tsCryptoData &append(size_type len, char ch);
		tsCryptoData &append(const tsCryptoStringBase &obj);
		tsCryptoData &append(const tsCryptoStringBase &obj, size_type pos, size_type count = npos);
		tsCryptoData &append(const char* data, size_type count);
		tsCryptoData &append(const char* data);
		tsCryptoData &append(std::initializer_list<char> list);
		tsCryptoData &append(value_type data);
		tsCryptoData &append(char data);
		tsCryptoData &append(int16_t val);
		tsCryptoData &append(int32_t val);
		tsCryptoData &append(int64_t val);
		tsCryptoData &append(uint16_t val);
		tsCryptoData &append(uint32_t val);
		tsCryptoData &append(uint64_t val);

		tsCryptoData &operator += (const tsCryptoStringBase &obj);
		tsCryptoData &operator += (char data);
		tsCryptoData &operator += (const char* data);
		tsCryptoData &operator += (std::initializer_list<char> init);
		tsCryptoData &operator += (int16_t val);
		tsCryptoData &operator += (int32_t val);
		tsCryptoData &operator += (int64_t val);
		tsCryptoData &operator += (uint16_t val);
		tsCryptoData &operator += (uint32_t val);
		tsCryptoData &operator += (uint64_t val);

		int compare(const tsCryptoStringBase& str) const;
		int compare(size_type pos1, size_type count1, const tsCryptoStringBase& str) const;
		int compare(size_type pos1, size_type count1, const tsCryptoStringBase& str, size_type pos2, size_type count2) const;
		int compare(const char* s) const;
		int compare(size_type pos1, size_type count1, const char* s) const;
		int compare(size_type pos1, size_type count1, const char* s, size_type count2) const;

		tsCryptoData& replace(size_type pos, size_type count, const tsCryptoStringBase& str);
		tsCryptoData& replace(const_iterator first, const_iterator last, const tsCryptoStringBase& str);
		tsCryptoData& replace(size_type pos, size_type count, const tsCryptoStringBase& str, size_type pos2, size_type count2 = npos);
		tsCryptoData& replace(size_type pos, size_type count, const char* s, size_type count2);
		tsCryptoData& replace(const_iterator first, const_iterator last, const char* s, size_type count2);
		tsCryptoData& replace(size_type pos, size_type count, const char* s);
		tsCryptoData& replace(const_iterator first, const_iterator last, const char* s);
		tsCryptoData& replace(size_type pos, size_type count, size_type count2, char ch);
		tsCryptoData& replace(const_iterator first, const_iterator last, size_type count2, char ch);
		tsCryptoData& replace(const_iterator first, const_iterator last, std::initializer_list<char> iList);
		void reverse();
		tsCryptoData &XOR(const tsCryptoData &value);
		tsCryptoData &AND(const tsCryptoData &value);
		tsCryptoData &OR(const tsCryptoData &value);
		tsCryptoData &NOT();
		tsCryptoData right(size_type length) const;
		tsCryptoData left(size_type length) const;
		tsCryptoData &padLeft(size_type length, value_type value = 0);
		tsCryptoData &padRight(size_type length, value_type value = 0);
		tsCryptoData &truncOrPadLeft(size_type length, value_type value = 0);
		tsCryptoString ToHexString() const;
		tsCryptoString ToHexStringWithSpaces() const;
		tsCryptoString ToHexDump() const;
		tsCryptoString ToBase64(bool base64Url = false, bool padWithEquals = true) const;
		tsCryptoString ToUtf8String() const;
		tsCryptoString ToOIDString() const;
		uint64_t ToUint64() const;
		void AsciiFromString(const tsCryptoStringBase& str);
		void UTF8FromString(const tsCryptoStringBase& str);
		tsCryptoData PartialDecode(DataStringType type, size_type numberOfBytes, size_type offset = 0);
		tsCryptoString PartialEncode(DataStringType type, size_type numberOfBytes, size_type offset = 0);
		tsCryptoData &increment(value_type step = 1);
		tsCryptoData &decrement(value_type step = 1);
		UnicodeEncodingType EncodingType() const;
		UnicodeEncodingType EncodingType(uint8_t *data, size_t size) const;
		bool hasEncodingBOM() const;
		bool hasEncodingBOM(uint8_t *data, size_t size) const;
		size_t BOMByteCount() const;
		size_t BOMByteCount(uint8_t *data, size_t size) const;
		static tsCryptoData computeBOM(UnicodeEncodingType type);
		tsCryptoData &prependBOM(UnicodeEncodingType type);

	protected:
		BYTE *m_data; ///< The allocated data buffer
		size_type m_used; ///< The number of bytes in the array
		difference_type m_allocated; ///< The number of bytes allocated for the array
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Copies from the object specified in 'obj'.</summary>
		///
		/// <param name="obj">The object to copy.</param>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		void copyFrom(const tsCryptoData &obj);
		tsCryptoData FromHexString(size_type maxSize, size_type offset = 0) const;
		tsCryptoData FromBase64(size_type maxSize, size_type offset = 0, bool base64Url = false, bool padWithEquals = true) const;
	};

	VEILCORE_API bool operator==(const tsCryptoData& lhs, const tsCryptoData& rhs);
	VEILCORE_API bool operator!=(const tsCryptoData& lhs, const tsCryptoData& rhs);
	VEILCORE_API bool operator<(const tsCryptoData& lhs, const tsCryptoData& rhs);
	VEILCORE_API bool operator<=(const tsCryptoData& lhs, const tsCryptoData& rhs);
	VEILCORE_API bool operator>(const tsCryptoData& lhs, const tsCryptoData& rhs);
	VEILCORE_API bool operator>=(const tsCryptoData& lhs, const tsCryptoData& rhs);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Concatenate two byte arrays</summary>
	///
	/// <param name="lhs">[in,out] The first value.</param>
	/// <param name="rhs">A value to append.</param>
	///
	/// <returns>The result of the operation.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	TS_INLINE tsCryptoData operator+(const tsCryptoData &lhs, const tsCryptoData &rhs)
	{
		tsCryptoData tmp;

		tmp = lhs;
		tmp += rhs;
		return tmp;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Concatenate two byte arrays</summary>
	///
	/// <param name="lhs">[in,out] The first value.</param>
	/// <param name="rhs">A value to append (zero terminated).</param>
	///
	/// <returns>The result of the operation.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	TS_INLINE tsCryptoData operator+(tsCryptoData &lhs, const unsigned char *rhs)
	{
		tsCryptoData tmp;

		tmp = lhs;
		tmp += rhs;
		return tmp;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Concatenate two byte arrays</summary>
	///
	/// <param name="lhs">[in,out] The first value (zero terminated).</param>
	/// <param name="rhs">A value to append.</param>
	///
	/// <returns>The result of the operation.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	TS_INLINE tsCryptoData operator+(const unsigned char *lhs, const tsCryptoData &rhs)
	{
		tsCryptoData tmp;

		tmp = lhs;
		tmp += rhs;
		return tmp;
	}

	VEILCORE_API void swap(tsCryptoData &lhs, tsCryptoData &rhs);

	VEILCORE_API std::ostream & operator << (std::ostream &Output, const tsCryptoData &obj);
	VEILCORE_API std::wostream & operator << (std::wostream &Output, const tsCryptoData &obj);

	template <class T>
	tsCryptoData& operator<<(tsCryptoData&& string, const T& val)
	{
		string << val;
		return string;
	}

	VEILCORE_API tsCryptoData& operator<<(tsCryptoData& string, char val);
	VEILCORE_API tsCryptoData& operator<<(tsCryptoData& string, int8_t val);
	VEILCORE_API tsCryptoData& operator<<(tsCryptoData& string, int16_t val);
	VEILCORE_API tsCryptoData& operator<<(tsCryptoData& string, int32_t val);
	VEILCORE_API tsCryptoData& operator<<(tsCryptoData& string, int64_t val);
	VEILCORE_API tsCryptoData& operator<<(tsCryptoData& string, uint8_t val);
	VEILCORE_API tsCryptoData& operator<<(tsCryptoData& string, uint16_t val);
	VEILCORE_API tsCryptoData& operator<<(tsCryptoData& string, uint32_t val);
	VEILCORE_API tsCryptoData& operator<<(tsCryptoData& string, uint64_t val);
	VEILCORE_API tsCryptoData& operator<<(tsCryptoData& string, const char* val);
	VEILCORE_API tsCryptoData& operator<<(tsCryptoData& string, const tsCryptoStringBase& val);
	VEILCORE_API tsCryptoData& operator<<(tsCryptoData& string, const tsCryptoData& val);


}
#endif // __TSCRYPTODATA_H__

