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

/////////////////////////////////////////////////////////////////////////////////////////////////////
/// \file	tsCryptoString.h
///
/// <summary>Declares the TecSec Standard string class that automatically overwrites its contents on
/// 		 resize or destruction</summary>
////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef __TSCRYPTOSTRING_H__
#define __TSCRYPTOSTRING_H__

#pragma once

#include <ostream>

namespace tscrypto {

	class tsCryptoData;
	class tsCryptoString;

	typedef ICryptoContainerWrapper<tsCryptoString> tsCryptoStringListBase;
	typedef std::shared_ptr<tsCryptoStringListBase> tsCryptoStringList;

	/// <summary>the TecSec Standard Ascii string class that automatically overwrites its contents on
	/// 		 resize or destruction</summary>
	class VEILCORE_API tsCryptoString : public tscrypto::tsCryptoStringBase
	{
	public:
		typedef tsCryptoStringBase::value_type value_type;
		typedef tsCryptoStringBase::size_type size_type;
		typedef tsCryptoStringBase::difference_type difference_type;
		typedef tsCryptoStringBase::pointer pointer;
		typedef tsCryptoStringBase::reference reference;
		typedef tsCryptoStringBase::const_pointer const_pointer;
		typedef const char& const_reference;
		typedef tsCryptoString self_type;
		typedef tsCryptoString* container_type;
		typedef const tsCryptoString* const_container_type;

		typedef CryptoIterator<self_type> iterator;
		typedef const_CryptoIterator<self_type> const_iterator;
		typedef std::reverse_iterator<iterator> reverse_iterator;
		typedef std::reverse_iterator<const_iterator> const_reverse_iterator;

		/// <summary>Default constructor.</summary>
		tsCryptoString();
		tsCryptoString(tsCryptoStringBase &&obj);
		tsCryptoString(tsCryptoString &&obj);
		tsCryptoString(std::initializer_list<value_type> init);
		template <class InputIt>
		tsCryptoString(InputIt first, InputIt last)
		{
			assign(first, last);
		}


		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Copy constructor.</summary>
		///
		/// <param name="obj">The object to copy</param>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString(const tsCryptoString &obj);
		tsCryptoString(const tsCryptoStringBase &obj);

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Constructor.</summary>
		///
		/// <param name="data">The data.</param>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString(const_pointer data);

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Constructor.</summary>
		///
		/// <param name="data">The data.</param>
		/// <param name="len"> The length.</param>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString(const_pointer data, size_type len);

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Constructor that fills tsCryptoString of size numChars with the character data..</summary>
		///
		/// <param name="data">	   The data.</param>
		/// <param name="numChars">Number of characters.</param>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString(value_type data, size_type numChars);

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Destructor.</summary>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		~tsCryptoString();

		tsCryptoString &operator=(tsCryptoString &&obj);
		tsCryptoString &operator=(tsCryptoStringBase &&obj);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Assignment operator.</summary>
		///
		/// <param name="obj">The object to copy</param>
		///
		/// <returns>A reference to this object.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString &operator = (const tsCryptoString &obj);
		tsCryptoString &operator = (const tsCryptoStringBase &obj);

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Assignment operator.</summary>
		///
		/// <param name="data">The zero terminated data to assign.</param>
		///
		/// <returns>A reference to this object.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString &operator = (const_pointer data);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Assignment operator.</summary>
		///
		/// <param name="data">The zero terminated data to assign.</param>
		///
		/// <returns>A reference to this object.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString &operator = (value_type data);
		tsCryptoString &operator=(std::initializer_list<value_type> iList);

		tsCryptoString &operator += (const tsCryptoStringBase &obj);
		tsCryptoString &operator += (value_type data);
		tsCryptoString &operator += (std::initializer_list<value_type> init);

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

		tsCryptoString &operator += (const_pointer data);

		tsCryptoString &assign(size_type size, value_type ch);
		tsCryptoString &assign(const tsCryptoStringBase &obj);
		tsCryptoString &assign(const tsCryptoStringBase &obj, size_type pos, size_type = npos);
		tsCryptoString &assign(tsCryptoStringBase &&obj);
		tsCryptoString &assign(tsCryptoString &&obj);
		tsCryptoString &assign(const_pointer newData, size_type count);
		template <class InputIt>
		tsCryptoString& assign(InputIt first, InputIt last)
		{
			clear();
			for (auto it = first; it != last; ++it)
			{
				append(*it);
			}
			return *this;
		}
		tsCryptoString &assign(std::initializer_list<value_type> iList);

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Prepends the specified string to this object.</summary>
		///
		/// <param name="data">The data to prepend.</param>
		///
		/// <returns>A reference to this object.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString &prepend(const_pointer data);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Prepends the specified string to this object.</summary>
		///
		/// <param name="data">The data to prepend.</param>
		/// <param name="len"> The length of the data to prepend in characters.</param>
		///
		/// <returns>A reference to this object.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString &prepend(const_pointer data, size_type len);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Prepends the specified character to this object.</summary>
		///
		/// <param name="data">The data to prepend.</param>
		///
		/// <returns>A reference to this object.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString &prepend(value_type data);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Prepends the specified BYTE to this object.</summary>
		///
		/// <param name="data">The data to prepend.</param>
		///
		/// <returns>A reference to this object.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString &prepend(BYTE data);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Prepends the specified string to this object.</summary>
		///
		/// <param name="obj">The string to prepend.</param>
		///
		/// <returns>A reference to this object.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString &prepend(const tsCryptoStringBase &obj);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Prepends the specified long integer to this object.</summary>
		///
		/// <param name="Value">The long integer convert into a string and prepend.</param>
		///
		/// <returns>A reference to this object.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		//tsCryptoString &prepend(long Value);

		tsCryptoString &append(size_type len, value_type ch);
		tsCryptoString &append(const tsCryptoStringBase &obj);
		tsCryptoString &append(const tsCryptoStringBase &obj, size_type pos, size_type count = npos);
		tsCryptoString &append(const_pointer data, size_type len);
		tsCryptoString &append(const_pointer data);
		template <class InputIt>
		tsCryptoString &append(InputIt first, InputIt last)
		{
            tscrypto::tsCryptoStringBase::append(first, last);
			return *this;
		}
		tsCryptoString &append(std::initializer_list<value_type> list);

		tsCryptoString &append(value_type data);
		tsCryptoString &append(BYTE data);

		//tsCryptoString &append(long Value);
		//tsCryptoString &append(int8_t val);
		tsCryptoString &append(int16_t val);
		tsCryptoString &append(int32_t val);
#if defined(_MSC_VER) && !defined(__GNUC__)
		tsCryptoString &append(long val);
		tsCryptoString &append(unsigned long val);
#endif
		tsCryptoString &append(int64_t val);
		//tsCryptoString &append(uint8_t val);
		tsCryptoString &append(uint16_t val);
		tsCryptoString &append(uint32_t val);
		tsCryptoString &append(uint64_t val);

		tsCryptoString& erase(size_type pos = 0, size_type count = npos);
		iterator erase(const_iterator position);
		iterator erase(const_iterator first, const_iterator last);

		tsCryptoString& insert(size_type index, size_type count, value_type ch);
		tsCryptoString& insert(size_type index, value_type ch);
		tsCryptoString& insert(size_type index, const_pointer s);
		tsCryptoString& insert(size_type index, const_pointer s, size_type count);
		tsCryptoString& insert(size_type index, const tsCryptoStringBase& str);
		tsCryptoString& insert(size_type index, const tsCryptoStringBase& str, size_type index_str, size_type count = npos);
		tsCryptoString& insert(const_iterator pos, value_type ch);
		tsCryptoString& insert(const_iterator pos, size_type count, value_type ch);
		template <class InputIt>
		tsCryptoString& insert(const_iterator pos, InputIt first, InputIt last)
		{
			if (pos == end())
			{
				append(first, last);
				return *this;
			}
			size_type index = pos - cbegin();
			size_type count = last - first;

            if (index >= size())
                throw tscrypto::OutOfRange();

            tscrypto::tsCryptoStringBase::insert(index, (value_type)0, count);

			for (auto it = first; it != last; ++it)
			{
				data()[index++] = *it;
			}
			return *this;
		}
		tsCryptoString& insert(const_iterator pos, std::initializer_list<value_type> iList);

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Inserts a character into the string at the specified zero based index.</summary>
		///
		/// <param name="offset">The zero based position in the string.</param>
		/// <param name="value"> The character to insert.</param>
		///
		/// <returns>A reference to this object.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString &InsertAt(size_type offset, value_type value);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Inserts a character string into the string at the specified zero based index.</summary>
		///
		/// <param name="offset">The zero based position in the string.</param>
		/// <param name="value"> The character string to insert.</param>
		/// <param name="len">   (optional) the length of the string to insert or -1 to look for the null terminator.</param>
		///
		/// <returns>A reference to this object.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString &InsertAt(size_type offset, const_pointer value, int32_t len = -1);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Inserts a character string into the string at the specified zero based index.</summary>
		///
		/// <param name="offset">The zero based position in the string.</param>
		/// <param name="value"> The character string to insert.</param>
		///
		/// <returns>A reference to this object.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString &InsertAt(size_type offset, const tsCryptoStringBase &value);

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Deletes characters from the string</summary>
		///
		/// <param name="offset">The offset at which the delete starts (zero based)</param>
		/// <param name="count"> The number of characters to delete</param>
		///
		/// <returns>A reference to this object.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString &DeleteAt(size_type offset, size_type count);


		tsCryptoString& replace(size_type pos, size_type count, const tsCryptoStringBase& str);
		tsCryptoString& replace(const_iterator first, const_iterator last, const tsCryptoStringBase& str);
		tsCryptoString& replace(size_type pos, size_type count, const tsCryptoStringBase& str, size_type pos2, size_type count2 = npos);
		template <class InputIt>
		tsCryptoString& replace(const_iterator first, const_iterator last, InputIt first2, InputIt last2)
		{
			size_type index = first - cbegin();
			erase(first, last);
			insert(index, first2, last2);
			return *this;
		}
		tsCryptoString& replace(size_type pos, size_type count, const_pointer s, size_type count2);
		tsCryptoString& replace(const_iterator first, const_iterator last, const_pointer s, size_type count2);
		tsCryptoString& replace(size_type pos, size_type count, const_pointer s);
		tsCryptoString& replace(const_iterator first, const_iterator last, const_pointer s);
		tsCryptoString& replace(size_type pos, size_type count, size_type count2, value_type ch);
		tsCryptoString& replace(const_iterator first, const_iterator last, size_type count2, value_type ch);
		tsCryptoString& replace(const_iterator first, const_iterator last, std::initializer_list<value_type> iList);


		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Replaces one string for another within this object.</summary>
		///
		/// <param name="find">		  The search string that will be replaced.</param>
		/// <param name="replacement">The replacement string.</param>
		/// <param name="count">	  (optional) the number of times to replace.</param>
		///
		/// <returns>A reference to this object.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString &Replace(const_pointer find, const_pointer replacement, int32_t count = -1);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Replaces one string for another within this object.</summary>
		///
		/// <param name="find">		  The search string that will be replaced.</param>
		/// <param name="replacement">The replacement string.</param>
		/// <param name="count">	  (optional) the number of times to replace.</param>
		///
		/// <returns>A reference to this object.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString &Replace(const tsCryptoStringBase &find, const tsCryptoStringBase &replacement, int32_t count = -1);

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Replaces one string for another within this object.</summary>
		///
		/// <param name="i_Begin">		  The beginning offset to replace (zero based)</param>
		/// <param name="i_End">		  The ending offset that will be replaced (zero based)</param>
		/// <param name="i_newData">	  The data to replace with</param>
		/// <param name="i_newDataLength">(optional) length of the replacement data in characters.</param>
		///
		/// <returns>A reference to this object.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString &Replace(size_type i_Begin, size_type i_End, const_pointer i_newData, int32_t i_newDataLength = -1);

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Converts this object to an UTF 8 string</summary>
		///
		/// <returns>This object as a tsCryptoString.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString ToUTF8() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Converts this object to an UTF 8 byte array.</summary>
		///
		/// <returns>This object as a tsCryptoData.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoData ToUTF8Data() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Uses the contents of this object as a base 64 string and returns the resulting byte array</summary>
		///
		/// <returns>the byte array of the base 64 conversion</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoData Base64ToData(bool base64Url = false, bool padWithEquals = true) const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Converts the specified byte array to base 64 and then assigns it to this object</summary>
		///
		/// <param name="data">The data to convert</param>
		///
		/// <returns>A reference to this object</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString &Base64FromData(const tsCryptoData &data, bool base64Url = false, bool padWithEquals = true);
		/**
		 * \brief Converts this string as a hex string into a tsCryptoData.
		 *
		 * \return A tsCryptoData.
		 */
		tsCryptoData HexToData() const;


		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Assigns this object to the output of a printf style of string formatting</summary>
		///
		/// <param name="msg">The message to be formatted</param>
		///
		/// <returns>A reference to this object</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString &Format(const tsCryptoStringBase msg, ...);

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Assigns this object to the output of a printf style of string formatting using a va_list</summary>
		///
		/// <param name="msg">The message to be formatted</param>
		///
		/// <returns>A reference to this object</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString &FormatArg(const tsCryptoStringBase& msg, va_list arg);

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Converts this string to upper case</summary>
		///
		/// <returns>A reference to this object</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString &ToUpper();
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Converts this string to lower case</summary>
		///
		/// <returns>A reference to this object</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString &ToLower();

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Extracts a portion of this string and creates a new string</summary>
		///
		/// <param name="start"> The starting offset to copy</param>
		/// <param name="length">The number of characters to copy</param>
		///
		/// <returns>the new string containing the specified characters</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString substring(size_type start, size_type length) const;
		tsCryptoString substr(size_type start, size_type length) const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Returns a string containing the last 'length' characters</summary>
		///
		/// <param name="length">The number of characters to extract from the right of the string</param>
		///
		/// <returns>the new string</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString right(size_type length) const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Returns a string containing the first 'length' characters</summary>
		///
		/// <param name="length">The number of characters to extract from the left of the string</param>
		///
		/// <returns>the new string</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString left(size_type length) const;

		/**
		 * \brief Splits the string at all occurances of the specified character.
		 *
		 * \param splitter			 The character to split.
		 * \param maxSegments		 (Optional) the maximum segments.
		 * \param allowBlankSegments (Optional) the allow blank segments.
		 *
		 * \return A list of split strings.
		 */
		tsCryptoStringList split(value_type splitter, size_type maxSegments = npos, bool allowBlankSegments = false) const;
		/**
		 * \brief Splits the string at all occurances of any of the specified characters.
		 *
		 * \param splitters			 The character list to use to split te string.
		 * \param maxSegments		 (Optional) the maximum segments.
		 * \param allowBlankSegments (Optional) the allow blank segments.
		 *
		 * \return A list of split strings.
		 */
		tsCryptoStringList split(const_pointer splitters, size_type maxSegments = npos, bool allowBlankSegments = false) const;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Removes spaces, carriage returns, line feeds and tabs from both ends of the string</summary>
		///
		/// <returns>A reference to this object</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString &Trim();

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Removes the specifed characters from both ends of the string.</summary>
		///
		/// <param name="trimmers">The character set that is to be removed from the string</param>
		///
		/// <returns>A reference to this object.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString &Trim(const_pointer trimmers);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Removes spaces, carriage returns, line feeds and tabs from both the beginning of the string</summary>
		///
		/// <returns>A reference to this object</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString &TrimStart();

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Removes the specifed characters from the beginning of the string.</summary>
		///
		/// <param name="trimmers">The character set that is to be removed from the string</param>
		///
		/// <returns>A reference to this object.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString &TrimStart(const_pointer trimmers);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Removes spaces, carriage returns, line feeds and tabs from the end of the string</summary>
		///
		/// <returns>A reference to this object</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString &TrimEnd();

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Removes the specifed characters from the end of the string.</summary>
		///
		/// <param name="trimmers">The character set that is to be removed from the string</param>
		///
		/// <returns>A reference to this object.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString &TrimEnd(const_pointer trimmers);

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Pad the left size of the string with the specified padding if the length is less than 'width'</summary>
		///
		/// <param name="width">  The minimum width of the output string.</param>
		/// <param name="padding">The padding character.</param>
		///
		/// <returns>The padded string</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString PadLeft(size_type width, value_type padding) const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Pad the right size of the string with the specified padding if the length is less than 'width'</summary>
		///
		/// <param name="width">  The minimum width of the output string.</param>
		/// <param name="padding">The padding character.</param>
		///
		/// <returns>The padded string</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString PadRight(size_type width, value_type padding) const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Pad the left size of the string with the specified padding or truncates if neccessary based on 'width'</summary>
		///
		/// <param name="width">  The minimum width of the output string.</param>
		/// <param name="padding">The padding character.</param>
		///
		/// <returns>The padded/truncated string</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString TruncOrPadLeft(size_type width, value_type padding) const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Pad the right size of the string with the specified padding or truncates if neccessary based on 'width'</summary>
		///
		/// <param name="width">  The minimum width of the output string.</param>
		/// <param name="padding">The padding character.</param>
		///
		/// <returns>The padded/truncated string</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString TruncOrPadRight(size_type width, value_type padding) const;
	};

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4231)
	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API ICryptoContainerWrapper<tsCryptoString>;
	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::shared_ptr<ICryptoContainerWrapper<tsCryptoString>>;
#pragma warning(pop)
#endif // _MSC_VER

	VEILCORE_API tsCryptoStringList CreateTsCryptoStringList();

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Concatenate two strings</summary>
	///
	/// <param name="lhs">[in,out] The first value.</param>
	/// <param name="rhs">A value to add to it.</param>
	///
	/// <returns>The result of the operation.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	TS_INLINE tsCryptoString operator+(const tsCryptoStringBase &lhs, const tsCryptoStringBase &rhs)
	{
		tsCryptoString tmp;

		tmp.append(lhs).append(rhs);
		return tmp;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Concatenate two strings</summary>
	///
	/// <param name="lhs">[in,out] The first value.</param>
	/// <param name="rhs">A value to add to it.</param>
	///
	/// <returns>The result of the operation.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	TS_INLINE tsCryptoString operator+(const tsCryptoStringBase &lhs, const char *rhs)
	{
		tsCryptoString tmp;

		tmp.append(lhs).append(rhs);
		return tmp;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Concatenate two strings</summary>
	///
	/// <param name="lhs">[in,out] The first value.</param>
	/// <param name="rhs">A value to add to it.</param>
	///
	/// <returns>The result of the operation.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	TS_INLINE tsCryptoString operator+(const char *lhs, const tsCryptoStringBase &rhs)
	{
		tsCryptoString tmp;

		tmp.append(lhs).append(rhs);
		return tmp;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Stream insertion operator.</summary>
	///
	/// <param name="Output">[in,out] The stream object.</param>
	/// <param name="obj">   The data to stream.</param>
	///
	/// <returns>the stream object</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	VEILCORE_API std::ostream & operator << (std::ostream &Output, const tsCryptoString &obj);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Stream insertion operator.</summary>
	///
	/// <param name="Output">[in,out] The stream object.</param>
	/// <param name="obj">   The data to stream.</param>
	///
	/// <returns>the stream object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	VEILCORE_API std::wostream & operator << (std::wostream &Output, const tsCryptoString &obj);

	VEILCORE_API void swap(tsCryptoString &lhs, tsCryptoString &rhs);

	//template <class T>
	//tsCryptoString& operator<<(tsCryptoString&& string, const T& val)
	//{
	//	string << val;
	//	return string;
	//}

	VEILCORE_API tsCryptoString& operator<<(tsCryptoString& string, char val);
	VEILCORE_API tsCryptoString& operator<<(tsCryptoString& string, int8_t val);
	VEILCORE_API tsCryptoString& operator<<(tsCryptoString& string, int16_t val);
#if defined(_MSC_VER) && !defined(__GNUC__)
	VEILCORE_API tsCryptoString& operator<<(tsCryptoString& string, long val);
	VEILCORE_API tsCryptoString& operator<<(tsCryptoString& string, unsigned long val);
#endif
	VEILCORE_API tsCryptoString& operator<<(tsCryptoString& string, int32_t val);
	VEILCORE_API tsCryptoString& operator<<(tsCryptoString& string, int64_t val);
	VEILCORE_API tsCryptoString& operator<<(tsCryptoString& string, uint8_t val);
	VEILCORE_API tsCryptoString& operator<<(tsCryptoString& string, uint16_t val);
	VEILCORE_API tsCryptoString& operator<<(tsCryptoString& string, uint32_t val);
	VEILCORE_API tsCryptoString& operator<<(tsCryptoString& string, uint64_t val);
	VEILCORE_API tsCryptoString& operator<<(tsCryptoString& string, const char* val);
	VEILCORE_API tsCryptoString& operator<<(tsCryptoString& string, const tsCryptoStringBase& val);
	VEILCORE_API tsCryptoString& operator<<(tsCryptoString& string, const tsCryptoData& val);

	VEILCORE_API tsCryptoString& operator<<(tsCryptoString& string, enum SpecialStrings val);

}
#endif // __TSCRYPTOSTRING_H__

/*! @} */
