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

#define MemAllocSize 100

#ifndef MIN
#   define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif // MIN

using namespace tscrypto;

tsCryptoString::tsCryptoString()
{
	reserve(0);
};
tsCryptoString::tsCryptoString(std::initializer_list<value_type> init) : tscrypto::tsCryptoStringBase(init)
{
}
tsCryptoString::tsCryptoString(tsCryptoString &&obj) : tscrypto::tsCryptoStringBase(std::move(obj))
{
}
tsCryptoString::tsCryptoString(tsCryptoStringBase &&obj) : tscrypto::tsCryptoStringBase(std::move(obj))
{
}
tsCryptoString::tsCryptoString(const_pointer data, tsCryptoString::size_type Len) : tscrypto::tsCryptoStringBase(data, Len)
{
};
tsCryptoString::tsCryptoString(const tsCryptoString &obj) : tscrypto::tsCryptoStringBase(obj)
{
};
tsCryptoString::tsCryptoString(const tsCryptoStringBase &obj) : tscrypto::tsCryptoStringBase(obj)
{
};
tsCryptoString::tsCryptoString(const_pointer data) : tscrypto::tsCryptoStringBase(data)
{
}
tsCryptoString::tsCryptoString(value_type data, tsCryptoString::size_type numChars) : tscrypto::tsCryptoStringBase(data, numChars)
{
}
tsCryptoString::~tsCryptoString()
{
};
//#ifdef _WIN32
//void *tsCryptoString::operator new(tsCryptoString::size_type bytes) { return FrameworkAllocator(bytes); }
//void tsCryptoString::operator delete(void *ptr) { return FrameworkDeallocator(ptr); }
//#endif // _WIN32
//tsCryptoString::operator LPCTSTR ()
//{
//	return c_str();
//}
tsCryptoString &tsCryptoString::operator= (tsCryptoStringBase &&obj)
{
	tscrypto::tsCryptoStringBase::operator=(std::move(obj));
	return *this;
}
tsCryptoString &tsCryptoString::operator= (tsCryptoString &&obj)
{
	tscrypto::tsCryptoStringBase::operator=(std::move(obj));
	return *this;
}
tsCryptoString &tsCryptoString::operator= (const tsCryptoStringBase &obj)
{
	tscrypto::tsCryptoStringBase::operator=(obj);
	return *this;
}
tsCryptoString &tsCryptoString::operator= (const tsCryptoString &obj)
{
	tscrypto::tsCryptoStringBase::operator=(obj);
	return *this;
}

tsCryptoString &tsCryptoString::operator= (const_pointer data) /* zero terminated */
{
	return (*this) = (tsCryptoString(data));
}
tsCryptoString &tsCryptoString::operator= (value_type data)
{
	tscrypto::tsCryptoStringBase::operator=(data);
	return *this;
}
tsCryptoString &tsCryptoString::operator=(std::initializer_list<value_type> iList)
{
	assign(iList);
	return *this;
}
tsCryptoString &tsCryptoString::operator+= (const tsCryptoStringBase &obj)
{
	tscrypto::tsCryptoStringBase::operator+=(obj);
	return *this;
}
tsCryptoString &tsCryptoString::operator+= (const_pointer data) /* zero terminated */
{
	return (*this) += tsCryptoString(data);
}
tsCryptoString &tsCryptoString::operator+= (value_type data)
{
	tscrypto::tsCryptoStringBase::operator+=(data);
	return *this;
}
tsCryptoString &tsCryptoString::operator += (std::initializer_list<value_type> init)
{
	return append(init);
}
tsCryptoString::iterator tsCryptoString::begin()
{
	return iterator(this);
}
tsCryptoString::const_iterator tsCryptoString::begin() const
{
	return const_iterator(this);
}
tsCryptoString::iterator tsCryptoString::end()
{
	return iterator(this, size());
}
tsCryptoString::const_iterator tsCryptoString::end() const
{
	return const_iterator(this, size());
}
tsCryptoString::const_iterator tsCryptoString::cbegin() const
{
	return const_iterator(this);
}
tsCryptoString::const_iterator tsCryptoString::cend() const
{
	return const_iterator(this, size());
}
tsCryptoString::reverse_iterator tsCryptoString::rbegin()
{
	return reverse_iterator(end());
}
tsCryptoString::reverse_iterator tsCryptoString::rend()
{
	return reverse_iterator(begin());
}
tsCryptoString::const_reverse_iterator tsCryptoString::crbegin() const
{
	return const_reverse_iterator(cend());
}
tsCryptoString::const_reverse_iterator tsCryptoString::crend() const
{
	return const_reverse_iterator(cbegin());
}

tsCryptoString &tsCryptoString::assign(tsCryptoString::size_type size, tsCryptoString::value_type ch)
{
	tscrypto::tsCryptoStringBase::assign(size, ch);
	return *this;
}
tsCryptoString &tsCryptoString::assign(const tsCryptoStringBase &obj)
{
	tscrypto::tsCryptoStringBase::assign(obj);
	return *this;
}
tsCryptoString &tsCryptoString::assign(const tsCryptoStringBase &obj, tsCryptoString::size_type pos, tsCryptoString::size_type count)
{
	tscrypto::tsCryptoStringBase::assign(obj, pos, count);
	return *this;
}
tsCryptoString &tsCryptoString::assign(tsCryptoStringBase &&obj)
{
	tscrypto::tsCryptoStringBase::assign(std::move(obj));
	return *this;
}
tsCryptoString &tsCryptoString::assign(tsCryptoString &&obj)
{
	tscrypto::tsCryptoStringBase::assign(std::move(obj));
	return *this;
}
tsCryptoString &tsCryptoString::assign(const_pointer newData, tsCryptoString::size_type size)
{
	tscrypto::tsCryptoStringBase::assign(newData, size);
	return *this;
}
tsCryptoString &tsCryptoString::assign(std::initializer_list<value_type> iList)
{
	tscrypto::tsCryptoStringBase::assign(iList);
	return *this;
}
tsCryptoString &tsCryptoString::prepend(const_pointer data)
{
	if (data == nullptr)
	{
		return *this;
	}
	return prepend(tsCryptoString(data));
}
tsCryptoString &tsCryptoString::prepend(const_pointer data, tsCryptoString::size_type len)
{
	if (data == nullptr)
	{
		return *this;
	}
	return prepend(tsCryptoString(data, len));
}
tsCryptoString &tsCryptoString::prepend(value_type data)
{
	tscrypto::tsCryptoStringBase::prepend(data);
	return *this;
}
tsCryptoString &tsCryptoString::prepend(BYTE data)
{
	tscrypto::tsCryptoStringBase::prepend(data);
	return *this;
}
tsCryptoString &tsCryptoString::prepend(const tsCryptoStringBase &obj)
{
	tscrypto::tsCryptoStringBase::prepend(obj);
	return *this;
}
tsCryptoString &tsCryptoString::append(size_type len, value_type ch)
{
	tscrypto::tsCryptoStringBase::append(len, ch);
	return *this;
}
tsCryptoString &tsCryptoString::append(const tsCryptoStringBase &obj)
{
	tscrypto::tsCryptoStringBase::append(obj);
	return *this;
}
tsCryptoString &tsCryptoString::append(const tsCryptoStringBase &obj, size_type pos, size_type count)
{
	return append(obj.substr(pos, count));
}
tsCryptoString &tsCryptoString::append(const_pointer data, size_type len)
{
	tscrypto::tsCryptoStringBase::append(data, len);
	return *this;
}
tsCryptoString &tsCryptoString::append(const_pointer data)
{
	tscrypto::tsCryptoStringBase::append(data);
	return *this;
}
tsCryptoString &tsCryptoString::append(std::initializer_list<value_type> list)
{
	tscrypto::tsCryptoStringBase::append(list);
	return *this;
}
tsCryptoString &tsCryptoString::append(value_type data)
{
	tscrypto::tsCryptoStringBase::append(data);
	return *this;
}
tsCryptoString &tsCryptoString::append(BYTE data)
{
	tscrypto::tsCryptoStringBase::append(data);
	return *this;
}
//tsCryptoString &tsCryptoString::append(int8_t val)
//{
//	tsCryptoString buffer;
//
//	buffer.Format("%d", val);
//	append(buffer);
//return *this;
//}
tsCryptoString &tsCryptoString::append(int16_t val)
{
	tsCryptoString buffer;

	buffer.Format("%d", val);
	append(buffer);
	return *this;
}
tsCryptoString &tsCryptoString::append(int32_t val)
{
	tsCryptoString buffer;

	buffer.Format("%d", val);
	append(buffer);
	return *this;
}
#if defined(_MSC_VER) && !defined(__GNUC__)
tsCryptoString &tsCryptoString::append(long val)
{
	tsCryptoString buffer;

	buffer.Format("%ld", val);
	append(buffer);
	return *this;
}
tsCryptoString &tsCryptoString::append(unsigned long val)
{
	tsCryptoString buffer;

	buffer.Format("%lu", val);
	append(buffer);
	return *this;
}
#endif
tsCryptoString &tsCryptoString::append(int64_t val)
{
	tsCryptoString buffer;

	buffer.Format("%lld", val);
	append(buffer);
	return *this;
}
//tsCryptoString &tsCryptoString::append(uint8_t val)
//{
//	tsCryptoString buffer;
//
//	buffer.Format("%u", val);
//	append(buffer);
//return *this;
//}
tsCryptoString &tsCryptoString::append(uint16_t val)
{
	tsCryptoString buffer;

	buffer.Format("%u", val);
	append(buffer);
	return *this;
}
tsCryptoString &tsCryptoString::append(uint32_t val)
{
	tsCryptoString buffer;

	buffer.Format("%u", val);
	append(buffer);
	return *this;
}
tsCryptoString &tsCryptoString::append(uint64_t val)
{
	tsCryptoString buffer;

	buffer.Format("%llu", val);
	append(buffer);
	return *this;
}

tsCryptoString& tsCryptoString::erase(tsCryptoString::size_type pos, tsCryptoString::size_type count)
{
	tscrypto::tsCryptoStringBase::erase(pos, count);
	return *this;
}
tsCryptoString::iterator tsCryptoString::erase(const_iterator position)
{
	size_type pos = position - cbegin();

	tscrypto::tsCryptoStringBase::erase(pos, 1);
	return iterator(this, pos);
}
tsCryptoString::iterator tsCryptoString::erase(const_iterator first, const_iterator last)
{
	size_type pos = first - cbegin();
	size_type count = last - first;

	tscrypto::tsCryptoStringBase::erase(pos, count);
	return iterator(this, pos);
}

tsCryptoString& tsCryptoString::insert(tsCryptoString::size_type index, tsCryptoString::size_type count, tsCryptoString::value_type ch)
{
	tscrypto::tsCryptoStringBase::insert(index, count, ch);
	return *this;
}
tsCryptoString& tsCryptoString::insert(tsCryptoString::size_type index, tsCryptoString::value_type ch)
{
	tscrypto::tsCryptoStringBase::insert(index, ch);
	return *this;
}
tsCryptoString& tsCryptoString::insert(tsCryptoString::size_type index, tsCryptoString::const_pointer s)
{
	tscrypto::tsCryptoStringBase::insert(index, s);
	return *this;
}
tsCryptoString& tsCryptoString::insert(tsCryptoString::size_type index, tsCryptoString::const_pointer s, tsCryptoString::size_type count)
{
	tscrypto::tsCryptoStringBase::insert(index, s, count);
	return *this;
}
tsCryptoString& tsCryptoString::insert(tsCryptoString::size_type index, const tsCryptoStringBase& str)
{
	tscrypto::tsCryptoStringBase::insert(index, str);
	return *this;
}
tsCryptoString& tsCryptoString::insert(tsCryptoString::size_type index, const tsCryptoStringBase& str, size_type index_str, size_type count)
{
	return insert(index, str.substr(index_str, count));
}
tsCryptoString& tsCryptoString::insert(const_iterator pos, value_type ch)
{
	size_type index = pos - begin();
	return insert(index, ch);
}
tsCryptoString& tsCryptoString::insert(const_iterator pos, size_type count, value_type ch)
{
	size_type index = pos - begin();
	return insert(index, count, ch);
}
tsCryptoString& tsCryptoString::insert(const_iterator pos, std::initializer_list<value_type> iList)
{
	size_type index = pos - begin();

	tscrypto::tsCryptoStringBase::insert(index, iList);
	return *this;
}
//bool tsCryptoString::LoadString(long ID, HINSTANCE hInstance)
//{
//	long retVal;
//	long oldSize;
//
//	if ( resize(1024) != 1024 )
//	{
//		clear();
//		return false;
//	}
//
//	retVal = ::LoadString(hInstance, ID, m_data, m_used + 1);
//	while ( retVal == m_used || retVal == m_used + 1 )
//	{
//		oldSize = m_used;
//		if ( resize(m_used + 1024) != oldSize + 1024 )
//		{
//			clear();
//			return false;
//		}
//		retVal = ::LoadString(hInstance, ID, m_data, m_used + 1);
//	}
//	if ( retVal == 0 )
//	{
//		clear();
//		return false;
//	}
//	resize(retVal);
//	return true;
//}
tsCryptoString &tsCryptoString::InsertAt(tsCryptoString::size_type offset, value_type value)
{
	return InsertAt(offset, &value, 1);
}
tsCryptoString &tsCryptoString::InsertAt(tsCryptoString::size_type offset, const_pointer value, int32_t len)
{
	if (len == -1)
		return InsertAt(offset, tsCryptoString(value));
	return InsertAt(offset, tsCryptoString(value, len));
}

tsCryptoString &tsCryptoString::InsertAt(tsCryptoString::size_type offset, const tsCryptoStringBase &value)
{
	tscrypto::tsCryptoStringBase::InsertAt(offset, value);
	return *this;
}

tsCryptoString &tsCryptoString::DeleteAt(tsCryptoString::size_type offset, tsCryptoString::size_type count)
{
	tscrypto::tsCryptoStringBase::DeleteAt(offset, count);
	return *this;
}
tsCryptoString& tsCryptoString::replace(size_type pos, size_type count, const tsCryptoStringBase& str)
{
	erase(pos, count);
	insert(pos, str);
	return *this;
}
tsCryptoString& tsCryptoString::replace(const_iterator first, const_iterator last, const tsCryptoStringBase& str)
{
	size_type pos = first - cbegin();
	erase(first, last);
	insert(pos, str);
	return *this;
}
tsCryptoString& tsCryptoString::replace(size_type pos, size_type count, const tsCryptoStringBase& str, size_type pos2, size_type count2)
{
	erase(pos, count);
	insert(pos, str, pos2, count2);
	return *this;
}
tsCryptoString& tsCryptoString::replace(size_type pos, size_type count, const_pointer s, size_type count2)
{
	erase(pos, count);
	insert(pos, s, count2);
	return *this;
}
tsCryptoString& tsCryptoString::replace(const_iterator first, const_iterator last, const_pointer s, size_type count2)
{
	size_type pos = first - cbegin();
	erase(first, last);
	insert(pos, s, count2);
	return *this;
}
tsCryptoString& tsCryptoString::replace(size_type pos, size_type count, const_pointer s)
{
	erase(pos, count);
	insert(pos, s);
	return *this;
}
tsCryptoString& tsCryptoString::replace(const_iterator first, const_iterator last, const_pointer s)
{
	size_type pos = first - cbegin();
	erase(first, last);
	insert(pos, s);
	return *this;
}
tsCryptoString& tsCryptoString::replace(size_type pos, size_type count, size_type count2, value_type ch)
{
	erase(pos, count);
	insert(pos, count2, ch);
	return *this;
}
tsCryptoString& tsCryptoString::replace(const_iterator first, const_iterator last, size_type count2, value_type ch)
{
	size_type pos = first - cbegin();
	erase(first, last);
	insert(pos, count2, ch);
	return *this;
}
tsCryptoString& tsCryptoString::replace(const_iterator first, const_iterator last, std::initializer_list<value_type> iList)
{
	size_type pos = first - cbegin();
	erase(first, last);
	insert(pos, iList);
	return *this;
}

tsCryptoString &tsCryptoString::Replace(tsCryptoString::size_type i_Begin, tsCryptoString::size_type i_End, const_pointer i_newData, int32_t i_newDataLength)
{
	tscrypto::tsCryptoStringBase::Replace(i_Begin, i_End, i_newData, i_newDataLength);
	return *this;
}
tsCryptoString &tsCryptoString::Replace(const_pointer find, const_pointer replacement, int32_t count)
{
	return Replace(tsCryptoString(find), tsCryptoString(replacement), count);
}

tsCryptoString &tsCryptoString::Replace(const tsCryptoStringBase &find, const tsCryptoStringBase &replacement, int32_t count)
{
	tscrypto::tsCryptoStringBase::Replace(find, replacement, count);
	return *this;
}



tsCryptoString &tsCryptoString::Format(const tsCryptoStringBase msg, ...)
{
	va_list args;

	va_start(args, msg);
	resize(0);
	resize(10240);
	vsnprintf_s(data(), size(), size(), msg.c_str(), args);
	resize(strlen(c_str()));
	va_end(args);
	return *this;
}

tsCryptoString &tsCryptoString::FormatArg(const tsCryptoStringBase& msg, va_list arg)
{
	resize(0);
	resize(10240);
	vsnprintf_s(data(), size(), size(), msg.c_str(), arg);
	resize(strlen(c_str()));
	return *this;
}

tsCryptoString &tsCryptoString::ToUpper()
{
	tscrypto::tsCryptoStringBase::ToUpper();
	return *this;
}

tsCryptoString &tsCryptoString::ToLower()
{
	tscrypto::tsCryptoStringBase::ToLower();
	return *this;
}

tsCryptoString tsCryptoString::substring(tsCryptoString::size_type start, tsCryptoString::size_type length) const
{
	if (start >= size() || length == 0)
		return "";
	if (start + length >= size())
	{
		return tsCryptoString(&c_str()[start]);
	}
	return tsCryptoString(&c_str()[start], length);
}
tsCryptoString tsCryptoString::substr(tsCryptoString::size_type start, tsCryptoString::size_type length) const
{
	return substring(start, length);
}

tsCryptoString tsCryptoString::right(tsCryptoString::size_type length) const
{
	tsCryptoString tmp = *this;

	if (tmp.size() > length)
		tmp.DeleteAt(0, tmp.size() - length);
	return tmp;
}

tsCryptoString tsCryptoString::left(tsCryptoString::size_type length) const
{
	tsCryptoString tmp = *this;

	if (tmp.size() > length)
		tmp.resize(length);
	return tmp;
}

tsCryptoStringList tsCryptoString::split(value_type splitter, size_type maxSegments, bool allowBlankSegments) const
{
	tsCryptoString::size_type start, end;
	tsCryptoStringList tmp = CreateTsCryptoStringList();
	size_type itemsFound = 1;
	size_type m_used = size();
	const_pointer m_data = data();

	if (size() == 0)
	{
		tmp->push_back(tsCryptoString());
		return tmp;
	}
	start = 0;
	while (start < m_used)
	{
		end = start;
		while (end < m_used && m_data[end] != splitter)
		{
			end++;
		}
		if (start != end || itemsFound >= maxSegments || allowBlankSegments)
		{
			if (itemsFound++ >= maxSegments)
			{
				tmp->push_back(tsCryptoString(&m_data[start], m_used - start));
				return tmp;
			}
			else
			{
				tmp->push_back(tsCryptoString(&m_data[start], end - start));
			}
		}
		start = end + 1;
		if (start == m_used && (allowBlankSegments || tmp->size() == 0))
		{
			tmp->push_back(tsCryptoString());
		}
	}
	return tmp;
}

tsCryptoStringList tsCryptoString::split(const_pointer _splitters, size_type maxSegments, bool allowBlankSegments) const
{
	tsCryptoString::size_type start, end;
	tsCryptoStringList tmp = CreateTsCryptoStringList();
	tsCryptoString splitters(_splitters);
	size_type itemsFound = 1;
	size_type m_used = size();
	const_pointer m_data = data();

	if (size() == 0)
	{
		tmp->push_back(tsCryptoString());
		return tmp;
	}
	start = 0;
	while (start < m_used)
	{
		end = start;
		while (end < m_used && strchr(splitters.c_str(), m_data[end]) == nullptr)
		{
			end++;
		}
		if (start != end || itemsFound >= maxSegments || allowBlankSegments)
		{
			if (itemsFound++ >= maxSegments)
			{
				tmp->push_back(tsCryptoString(&m_data[start], m_used - start));
				return tmp;
			}
			else
			{
				tmp->push_back(tsCryptoString(&m_data[start], end - start));
			}
		}
		start = end + 1;
		if (start == m_used && (allowBlankSegments || tmp->size() == 0))
		{
			tmp->push_back(tsCryptoString());
		}
	}
	return tmp;
}

tsCryptoString &tsCryptoString::Trim()
{
	return Trim(("\t\r\n "));
}

tsCryptoString &tsCryptoString::Trim(const_pointer trimmers)
{
	TrimStart(trimmers);
	return TrimEnd(trimmers);
}

tsCryptoString &tsCryptoString::TrimStart()
{
	return TrimStart(("\t\r\n "));
}

tsCryptoString &tsCryptoString::TrimStart(const_pointer trimmers)
{
	difference_type index = find_first_not_of(trimmers);

	DeleteAt(0, index);
	return *this;
}

tsCryptoString &tsCryptoString::TrimEnd()
{
	return TrimEnd(("\t\r\n "));
}

tsCryptoString &tsCryptoString::TrimEnd(const_pointer trimmers)
{
	difference_type index = find_last_not_of(trimmers);

	if (index < (difference_type)(size()) - 1)
		resize(index + 1);
	return *this;
}

std::ostream & tscrypto::operator << (std::ostream &Output, const tsCryptoString &obj)
{
	Output << tsCryptoString(obj).c_str();
	return Output;
}
std::wostream & tscrypto::operator << (std::wostream &Output, const tsCryptoString &obj)
{
	Output << obj.c_str();
	return Output;
}

tsCryptoString tsCryptoString::PadLeft(tsCryptoString::size_type width, value_type padding) const
{
	tsCryptoString tmp(*this);

	if (tmp.size() < width)
	{
		tmp.prepend(tsCryptoString(padding, width - tmp.size()));
	}
	return tmp;
}

tsCryptoString tsCryptoString::PadRight(tsCryptoString::size_type width, value_type padding) const
{
	tsCryptoString tmp(*this);

	if (tmp.size() < width)
	{
		tmp.resize(width, padding);
	}
	return tmp;
}

tsCryptoString tsCryptoString::TruncOrPadLeft(tsCryptoString::size_type width, value_type padding) const
{
	tsCryptoString tmp(*this);

	if (tmp.size() < width)
	{
		tmp.prepend(tsCryptoString(padding, width - tmp.size()));
	}
	else if (tmp.size() > width)
		tmp.resize(width);
	return tmp;
}

tsCryptoString tsCryptoString::TruncOrPadRight(tsCryptoString::size_type width, value_type padding) const
{
	tsCryptoString tmp(*this);

	if (tmp.size() < width)
	{
		tmp.resize(width, padding);
	}
	else if (tmp.size() > width)
		tmp.resize(width);
	return tmp;
}

tsCryptoString tsCryptoString::ToUTF8() const
{
	return *this;
}

tsCryptoData tsCryptoString::ToUTF8Data() const
{
	tsCryptoData tmp;

	tmp.UTF8FromString(*this);
	return tmp;
}

tsCryptoData tsCryptoString::Base64ToData(bool base64Url, bool padWithEquals) const
{
	tsCryptoData tmp;

	tmp.FromBase64(this->c_str(), base64Url, padWithEquals);
	return tmp;
}

tsCryptoString &tsCryptoString::Base64FromData(const tsCryptoData &data, bool base64Url, bool padWithEquals)
{
	*this = data.ToBase64(base64Url, padWithEquals);
	return *this;
}

tsCryptoData tsCryptoString::HexToData() const
{
	return tsCryptoData(*this, tsCryptoData::HEX);
}



void tscrypto::swap(tsCryptoString &lhs, tsCryptoString &rhs)
{
	lhs.swap(rhs);
}

tsCryptoStringList tscrypto::CreateTsCryptoStringList()
{
	return CreateContainer<tsCryptoString>();
}

tsCryptoString& tscrypto::operator<<(tsCryptoString& string, char val)
{
	return string.append(val);
}
tsCryptoString& tscrypto::operator<<(tsCryptoString& string, int8_t val)
{
	return string.append(val);
}
tsCryptoString& tscrypto::operator<<(tsCryptoString& string, int16_t val)
{
	return string.append(val);
}
tsCryptoString& tscrypto::operator<<(tsCryptoString& string, int32_t val)
{
	return string.append(val);
}
#if defined(_MSC_VER) && !defined(__GNUC__)
tsCryptoString& tscrypto::operator<<(tsCryptoString& string, long val)
{
	return string.append(val);
}
tsCryptoString& tscrypto::operator<<(tsCryptoString& string, unsigned long val)
{
	return string.append(val);
}
#endif
tsCryptoString& tscrypto::operator<<(tsCryptoString& string, int64_t val)
{
	return string.append(val);
}
tsCryptoString& tscrypto::operator<<(tsCryptoString& string, uint8_t val)
{
	return string.append(val);
}
tsCryptoString& tscrypto::operator<<(tsCryptoString& string, uint16_t val)
{
	return string.append(val);
}
tsCryptoString& tscrypto::operator<<(tsCryptoString& string, uint32_t val)
{
	return string.append(val);
}
tsCryptoString& tscrypto::operator<<(tsCryptoString& string, uint64_t val)
{
	return string.append(val);
}
tsCryptoString& tscrypto::operator<<(tsCryptoString& string, const char* val)
{
	return string.append(val);
}
tsCryptoString& tscrypto::operator<<(tsCryptoString& string, const tsCryptoStringBase& val)
{
	return string.append(val);
}
tsCryptoString& tscrypto::operator<<(tsCryptoString& string, const tsCryptoData& val)
{
	return string.append(val.ToHexString());
}
tsCryptoString& tscrypto::operator<<(tsCryptoString& string, enum SpecialStrings val)
{
	switch (val)
	{
	case lf:
	case endl:
		string.append('\n');
		break;
	case tab:
		string.append('\t');
		break;
	case nullchar:
		string.resize(string.size() + 1, 0);
		break;
	case cr:
		string.append('\r');
		break;
	case crlf:
		string.append("\r\n");
		break;
	}
	return string;
}
