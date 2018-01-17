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

#define MemAllocSize 100

#ifndef MIN
#   define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif // MIN

const tscrypto::CryptoUtf16::size_type tscrypto::CryptoUtf16::npos = (size_type)(-1);

CryptoUtf16::CryptoUtf16() : m_data(nullptr), m_used(0), m_allocated(-1)
{
	reserve(0);
}
CryptoUtf16::CryptoUtf16(size_type count, value_type ch) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	resize(count, ch);
}
CryptoUtf16::CryptoUtf16(const CryptoUtf16 &obj, size_type pos) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	if (pos >= obj.size())
		reserve(0);
	else
	{
		resize(obj.size() - pos);
		obj.copy(m_data, size(), pos);
	}
}
CryptoUtf16::CryptoUtf16(const CryptoUtf16 &obj, size_type pos, size_type count) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	if (pos >= obj.size())
		reserve(0);
	else
	{
		if (count + pos > obj.size())
			count = obj.size() - pos;

		resize(count);
		obj.copy(m_data, count, pos);
	}
}
CryptoUtf16::CryptoUtf16(const_pointer data, size_type count) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	if (data == nullptr || count == 0)
		reserve(0);
	else
	{
		resize(count);
		memcpy(m_data, data, count * sizeof(value_type));
	}
}
CryptoUtf16::CryptoUtf16(const_pointer data) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	if (data == nullptr)
		reserve(0);
	else
	{
		size_type Len = tsUtf16Len((const TSUtf16*)data);
		if (Len == 0)
			reserve(0);
		else
		{
			resize(Len);
			memcpy(m_data, data, Len * sizeof(value_type));
		}
	}
}
#ifndef _WIN32
CryptoUtf16::CryptoUtf16(size_type count, wchar_t data) : m_data(nullptr), m_used(0), m_allocated(-1)
{
    TSUtf32* p;
    size_type len;
    TSBYTE_BUFF tmp = tsCreateBuffer();

    if (!tsResizeBuffer(tmp, sizeof(wchar_t) * count))
        return;

	p = (TSUtf32*)tsGetBufferDataPtr(tmp);
    for (size_type i = 0; i < count; i++)
    {
        p[i] = data;
    }
	len = tsCountedUtf16LenFromUtf32(p, count, false);
	resize(len);
	tsCountedUtf32ToUtf16(p, count, (TSUtf16*)m_data, len + 1, false);
    tsFreeBuffer(&tmp);
}
CryptoUtf16::CryptoUtf16(const wchar_t* data) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	const TSUtf32* p = (const TSUtf32*)data;
	size_type dataLen = wcslen(data);
	TSUtf16* d;
	size_type len = tsUtf16LenFromUtf32(p, false);
	resize(len);
	d = (TSUtf16*)m_data;
	tsUtf32ToUtf16(p, d, len + 1, false);
}
 CryptoUtf16::CryptoUtf16(const wchar_t* data, size_type count) : m_data(nullptr), m_used(0), m_allocated(-1)
 {
 	const TSUtf32* p = (const TSUtf32*)data;
 	TSUtf16* d;
 	size_type len = tsCountedUtf16LenFromUtf32(p, count, false);
 	resize(len);
 	d = (TSUtf16*)m_data;
    tsCountedUtf32ToUtf16(p, count, d, len + 1, false);
 }
#endif // _WIN32
CryptoUtf16::CryptoUtf16(const CryptoUtf16 &obj) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	if (obj.size() == 0)
		reserve(0);
	else
	{
		resize(obj.size());
		obj.copy(m_data, size(), 0);
	}
}
CryptoUtf16::CryptoUtf16(CryptoUtf16 &&obj)
{
	m_data = obj.m_data;
	m_used = obj.m_used;
	m_allocated = obj.m_allocated;

	obj.m_data = nullptr;
	obj.m_used = 0;
	obj.m_allocated = -1;
	obj.reserve(0);
}
CryptoUtf16::CryptoUtf16(std::initializer_list<value_type> init) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	size_type index = 0;
	resize(init.size());

	for (auto i = init.begin(); i != init.end(); ++i)
	{
		m_data[index++] = *i;
	}
}
CryptoUtf16::CryptoUtf16(const char *data) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	if (data == nullptr)
		reserve(0);
	else
	{
		append(data);
	}
}
CryptoUtf16::CryptoUtf16(const tsCryptoStringBase& data) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	append(data.data(), data.size());
}
CryptoUtf16::CryptoUtf16(const tsCryptoString& data) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	append(data.data(), data.size());
}
CryptoUtf16::CryptoUtf16(size_type count, char ch) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	append(count, ch);
}
CryptoUtf16::CryptoUtf16(const char *data, size_type count) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	append(data, count);
}
CryptoUtf16::CryptoUtf16(std::initializer_list<char> init) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	tsCryptoString tmp(init);
	append(tmp);
}
CryptoUtf16::~CryptoUtf16()
{
	if (m_data != nullptr)
	{
		if (m_used > 0)
			memset(m_data, 0, m_used * sizeof(value_type));
		tscrypto::cryptoDelete(m_data);
		m_data = nullptr;
	}
	m_used = 0;
	m_allocated = -1;
}
CryptoUtf16 &CryptoUtf16::operator=(const CryptoUtf16 &obj)
{
	copyFrom(obj);
	return *this;
}
CryptoUtf16 &CryptoUtf16::operator=(CryptoUtf16 &&obj)
{
	if (&obj != this)
	{
		resize(0);
		if (m_data != nullptr)
			tscrypto::cryptoDelete(m_data);

		m_data = obj.m_data;
		m_used = obj.m_used;
		m_allocated = obj.m_allocated;

		obj.m_data = nullptr;
		obj.m_used = 0;
		obj.m_allocated = -1;
		obj.reserve(0);
	}
	return *this;
}
CryptoUtf16 &CryptoUtf16::operator=(const_pointer data) /* zero terminated */
{
	size_type len = 0;
	if (data == nullptr)
	{
		resize(0);
	}
	else
	{
		len = tsUtf16Len((const TSUtf16*)data);

		resize(len);
		memcpy(m_data, data, len * sizeof(value_type));
	}
	return *this;
}
CryptoUtf16 &CryptoUtf16::operator=(value_type obj)
{
	resize(1);
	m_data[0] = obj;
	return *this;
}
CryptoUtf16 &CryptoUtf16::operator=(std::initializer_list<value_type> iList)
{
	clear();
	append(iList);
	return *this;
}
CryptoUtf16 &CryptoUtf16::operator=(const tsCryptoStringBase& setTo)
{
	clear();
	return append(setTo);
}
CryptoUtf16 &CryptoUtf16::operator=(const char* setTo)
{
	clear();
	return append(setTo);
}
CryptoUtf16& CryptoUtf16::assign(size_type count, value_type ch)
{
	clear();
	return append(count, ch);
}
CryptoUtf16& CryptoUtf16::assign(const CryptoUtf16 &obj)
{
	if (this != &obj)
	{
		clear();
		return append(obj);
	}
	return *this;
}
CryptoUtf16& CryptoUtf16::assign(const CryptoUtf16 &obj, size_type pos, size_type count)
{
	return assign(obj.substr(pos, count));
}
CryptoUtf16& CryptoUtf16::assign(CryptoUtf16 &&obj)
{
	if (this != &obj)
	{
		m_data = obj.m_data;
		m_used = obj.m_used;
		m_allocated = obj.m_allocated;

		obj.m_data = nullptr;
		obj.m_used = 0;
		obj.m_allocated = -1;
		obj.reserve(0);
	}
	return *this;
}
CryptoUtf16& CryptoUtf16::assign(const_pointer newData, size_type count)
{
	if (newData == nullptr || count == 0)
		resize(0);
	else
	{
		resize(count);
		memcpy(m_data, newData, count * sizeof(value_type));
	}
	return *this;
}
CryptoUtf16& CryptoUtf16::assign(const_pointer newData)
{
	if (newData == nullptr)
		resize(0);
	else
	{
		size_type count = tsUtf16Len((const TSUtf16*)newData);
		resize(count);
		memcpy(m_data, newData, count * sizeof(value_type));
	}
	return *this;
}
CryptoUtf16& CryptoUtf16::assign(std::initializer_list<value_type> iList)
{
	clear();
	append(iList);
	return *this;
}
CryptoUtf16::reference CryptoUtf16::at(size_type index)
{
	if (index >= m_used)
		throw tscrypto::OutOfRange();
	return m_data[index];
}
CryptoUtf16::const_reference CryptoUtf16::at(size_type index) const
{
	if (index >= m_used)
		throw tscrypto::OutOfRange();
	return m_data[index];
}
CryptoUtf16::pointer CryptoUtf16::data()
{
	return m_data;
}
CryptoUtf16::const_pointer CryptoUtf16::data() const
{
	return m_data;
}
CryptoUtf16::const_pointer CryptoUtf16::c_str() const
{
	return m_data;
}
CryptoUtf16::reference CryptoUtf16::front()
{
	return m_data[0];
}
CryptoUtf16::const_reference CryptoUtf16::front() const
{
	return m_data[0];
}
CryptoUtf16::reference CryptoUtf16::back()
{
	if (empty())
		throw tscrypto::OutOfRange();
	return m_data[m_used - 1];
}
CryptoUtf16::const_reference CryptoUtf16::back() const
{
	if (empty())
		throw tscrypto::OutOfRange();
	return m_data[m_used - 1];
}
CryptoUtf16::reference CryptoUtf16::operator[](size_type index)
{
	return at(index);
}
CryptoUtf16::const_reference CryptoUtf16::operator[](size_type index) const
{
	return at(index);
}
CryptoUtf16::iterator CryptoUtf16::begin()
{
	return iterator(this);
}
CryptoUtf16::const_iterator CryptoUtf16::begin() const
{
	return const_iterator(this);
}
CryptoUtf16::iterator CryptoUtf16::end()
{
	return iterator(this, size());
}
CryptoUtf16::const_iterator CryptoUtf16::end() const
{
	return const_iterator(this, size());
}
CryptoUtf16::const_iterator CryptoUtf16::cbegin() const
{
	return const_iterator(this);
}
CryptoUtf16::const_iterator CryptoUtf16::cend() const
{
	return const_iterator(this, size());
}
CryptoUtf16::reverse_iterator CryptoUtf16::rbegin()
{
	return reverse_iterator(end());
}
CryptoUtf16::reverse_iterator CryptoUtf16::rend()
{
	return reverse_iterator(begin());
}
CryptoUtf16::const_reverse_iterator CryptoUtf16::crbegin() const
{
	return const_reverse_iterator(cend());
}
CryptoUtf16::const_reverse_iterator CryptoUtf16::crend() const
{
	return const_reverse_iterator(cbegin());
}
bool CryptoUtf16::empty() const
{
	return m_used == 0;
}
CryptoUtf16::size_type CryptoUtf16::size() const
{
	return m_used;
}
CryptoUtf16::size_type CryptoUtf16::length() const
{
	return m_used;
}
CryptoUtf16::size_type CryptoUtf16::max_size() const
{
	return 0x7FFFFFFF;
}

_Post_satisfies_(this->m_data != 0)
void CryptoUtf16::reserve(size_type newSize)
{
	if (newSize > max_size())
		throw tscrypto::length_error();
	if ((difference_type)newSize > m_allocated)
	{
		pointer tmp;
		size_type origNewSize = newSize;

		{
			if (newSize > 20000)
				newSize += 1024;
			else
				newSize += MemAllocSize;
			tmp = (value_type*)tscrypto::cryptoNew(sizeof(value_type) * (newSize + 1));
			if (tmp == nullptr)
			{
				throw tscrypto::bad_alloc();
			}
			memset(&tmp[m_used], 0, (origNewSize - m_used) * sizeof(value_type));
			memset(&tmp[origNewSize], 0, (newSize + 1 - origNewSize) * sizeof(value_type));
			if (m_data != nullptr)
			{
				memcpy(tmp, m_data, m_used * sizeof(value_type));
				memset(m_data, 0, m_used * sizeof(value_type));
				tscrypto::cryptoDelete(m_data);
			}

			m_data = tmp;
			m_allocated = newSize;
		}
	}
}
CryptoUtf16::size_type CryptoUtf16::capacity() const
{
	return m_allocated;
}
void CryptoUtf16::clear()
{
	resize(0);
}
CryptoUtf16& CryptoUtf16::insert(size_type index, size_type count, value_type ch)
{
	size_type oldsize = size();

	resize(size() + count);
	memmove(&m_data[index + count], &m_data[index], sizeof(value_type) * (oldsize - index));
	for (size_type i = 0; i < count; i++)
	{
		m_data[index + i] = ch;
	}
	return *this;
}
CryptoUtf16& CryptoUtf16::insert(size_type index, value_type ch)
{
	size_type oldsize = size();

	resize(size() + 1);
	memmove(&m_data[index + 1], &m_data[index], sizeof(value_type) * (oldsize - index));
	m_data[index] = ch;
	return *this;
}
CryptoUtf16& CryptoUtf16::insert(size_type index, const_pointer s)
{
	if (s == nullptr)
		throw tscrypto::ArgumentNullException("s");

	size_type oldsize = size();
	size_type count = tsUtf16Len((const TSUtf16*)s);

	resize(size() + count);
	memmove(&m_data[index + count], &m_data[index], sizeof(value_type) * (oldsize - index));
	memcpy(&m_data[index], s, count * sizeof(value_type));
	return *this;
}
CryptoUtf16& CryptoUtf16::insert(size_type index, const_pointer s, size_type count)
{
	if (s == nullptr)
		throw tscrypto::ArgumentNullException("s");

	size_type oldsize = size();

	resize(size() + count);
	memmove(&m_data[index + count], &m_data[index], sizeof(value_type) * (oldsize - index));
	memcpy(&m_data[index], s, count * sizeof(value_type));
	return *this;
}
CryptoUtf16& CryptoUtf16::insert(size_type index, const CryptoUtf16& str)
{
	size_type oldsize = size();
	size_type count = str.size();

	if (count == 0)
		return *this;
	resize(size() + count);
	memmove(&m_data[index + count], &m_data[index], sizeof(value_type) * (oldsize - index));
	memcpy(&m_data[index], str.data(), count * sizeof(value_type));
	return *this;
}
CryptoUtf16& CryptoUtf16::insert(size_type index, const CryptoUtf16& str, size_type index_str, size_type count)
{
	return insert(index, str.substr(index_str, count));
}
CryptoUtf16& CryptoUtf16::insert(const_iterator pos, value_type ch)
{
	size_type index = pos - begin();
	return insert(index, ch);
}
CryptoUtf16& CryptoUtf16::insert(const_iterator pos, size_type count, value_type ch)
{
	size_type index = pos - begin();
	return insert(index, count, ch);
}
CryptoUtf16& CryptoUtf16::insert(const_iterator pos, std::initializer_list<value_type> iList)
{
	size_type index = pos - begin();
	size_type oldsize = size();

	if (pos == cend())
	{
		append(iList);
		return *this;
	}
	resize(size() + iList.size());
	memmove(&m_data[index + iList.size()], &m_data[index], sizeof(value_type) * (oldsize - index));
	for (auto it = iList.begin(); it != iList.end(); ++it)
	{
		m_data[index++] = *it;
	}
	return *this;
}
CryptoUtf16& CryptoUtf16::erase(size_type pos, size_type count)
{
	if (pos > size())
		throw tscrypto::OutOfRange();
	if (pos + count >= size())
	{
		resize(pos);
	}
	else
	{
		memmove(&m_data[pos], &m_data[pos + count], sizeof(value_type) * (size() - pos));
		resize(size() - count);
	}
	return *this;
}
CryptoUtf16::iterator CryptoUtf16::erase(const_iterator position)
{
	size_type pos = position - cbegin();

	if (position == cend())
		throw tscrypto::OutOfRange();

	if (pos == size() - 1)
	{
		resize(size() - 1);
		return end();
	}
	memmove(&m_data[pos], &m_data[pos + 1], sizeof(value_type) * (size() - pos));
	resize(size() - 1);
	return iterator(this, pos);
}
CryptoUtf16::iterator CryptoUtf16::erase(const_iterator first, const_iterator last)
{
	size_type pos = first - cbegin();
	size_type count = last - first;

	if (first == cend())
		throw tscrypto::OutOfRange();

	if (last == cend())
	{
		resize(size() - count);
		return end();
	}
	memmove(&m_data[pos], &m_data[pos + count], sizeof(value_type) * (size() - pos));
	resize(size() - count);
	return iterator(this, pos);
}
void CryptoUtf16::push_back(ts_wchar ch)
{
	resize(size() + 1, ch);
}
void CryptoUtf16::pop_back()
{
	if (size() > 0)
		resize(size() - 1);
}
CryptoUtf16 &CryptoUtf16::append(size_type len, value_type ch)
{
	resize(size() + len, ch);
	return *this;
}
CryptoUtf16 &CryptoUtf16::append(const CryptoUtf16 &obj)
{
	size_type objSize = obj.size();

	if (objSize > 0)
	{
		size_type oldUsed = m_used;
		resize(oldUsed + objSize);
		memcpy(&m_data[oldUsed], obj.c_str(), objSize * sizeof(value_type));
	}
	return *this;
}
CryptoUtf16 &CryptoUtf16::append(const CryptoUtf16 &obj, size_type pos, size_type count)
{
	return append(obj.substr(pos, count));
}
CryptoUtf16 &CryptoUtf16::append(const_pointer data, size_type count)
{
	if (count > 0)
	{
		size_type oldUsed = m_used;
		resize(oldUsed + count);
		memcpy(&m_data[oldUsed], data, count * sizeof(value_type));
	}
	return *this;
}
CryptoUtf16 &CryptoUtf16::append(const_pointer data)
{
	if (data == nullptr)
		return *this;
	return append(data, tsUtf16Len((const TSUtf16*)data));
}
CryptoUtf16 &CryptoUtf16::append(std::initializer_list<value_type> list)
{
	size_type index = size();
	resize(size() + list.size());

	for (auto i = list.begin(); i != list.end(); ++i)
	{
		m_data[index++] = *i;
	}
	return *this;
}
CryptoUtf16 &CryptoUtf16::operator += (const CryptoUtf16& str)
{
	return append(str);
}
CryptoUtf16 &CryptoUtf16::operator += (value_type ch)
{
	return append(ch);
}
CryptoUtf16 &CryptoUtf16::operator += (const_pointer s)
{
	return append(s);
}
CryptoUtf16 &CryptoUtf16::operator += (std::initializer_list<value_type> init)
{
	return append(init);
}
int CryptoUtf16::compare(const CryptoUtf16& str) const
{
	size_type count = MIN(size(), str.size());
	int diff = 0;

	diff = memcmp(m_data, str.m_data, count * sizeof(value_type));
	if (diff != 0)
		return diff;
	if (size() > str.size())
		return 1;
	if (size() < str.size())
		return -1;
	return 0;
}
int CryptoUtf16::compare(size_type pos1, size_type count1, const CryptoUtf16& str) const
{
	return substr(pos1, count1).compare(str);
}
int CryptoUtf16::compare(size_type pos1, size_type count1, const CryptoUtf16& str, size_type pos2, size_type count2) const
{
	return substr(pos1, count1).compare(str.substr(pos2, count2));
}
int CryptoUtf16::compare(const_pointer s) const
{
	size_type len = tsUtf16Len((const TSUtf16*)s);
	size_type count = MIN(size(), len);
	int diff = 0;

	diff = memcmp(m_data, s, count * sizeof(value_type));
	if (diff != 0)
		return diff;
	if (size() > len)
		return 1;
	if (size() < len)
		return -1;
	return 0;
}
int CryptoUtf16::compare(size_type pos1, size_type count1, const_pointer s) const
{
	return substr(pos1, count1).compare(s);
}
int CryptoUtf16::compare(size_type pos1, size_type count1, const_pointer s, size_type count2) const
{
	return substr(pos1, count1).compare(CryptoUtf16(s, count2));
}
CryptoUtf16& CryptoUtf16::replace(size_type pos, size_type count, const CryptoUtf16& str)
{
	erase(pos, count);
	insert(pos, str);
	return *this;
}
CryptoUtf16& CryptoUtf16::replace(const_iterator first, const_iterator last, const CryptoUtf16& str)
{
	size_type pos = first - cbegin();
	erase(first, last);
	insert(pos, str);
	return *this;
}
CryptoUtf16& CryptoUtf16::replace(size_type pos, size_type count, const CryptoUtf16& str, size_type pos2, size_type count2)
{
	erase(pos, count);
	insert(pos, str, pos2, count2);
	return *this;
}
CryptoUtf16& CryptoUtf16::replace(size_type pos, size_type count, const_pointer s, size_type count2)
{
	erase(pos, count);
	insert(pos, s, count2);
	return *this;
}
CryptoUtf16& CryptoUtf16::replace(const_iterator first, const_iterator last, const_pointer s, size_type count2)
{
	size_type pos = first - cbegin();
	erase(first, last);
	insert(pos, s, count2);
	return *this;
}
CryptoUtf16& CryptoUtf16::replace(size_type pos, size_type count, const_pointer s)
{
	erase(pos, count);
	insert(pos, s);
	return *this;
}
CryptoUtf16& CryptoUtf16::replace(const_iterator first, const_iterator last, const_pointer s)
{
	size_type pos = first - cbegin();
	erase(first, last);
	insert(pos, s);
	return *this;
}
CryptoUtf16& CryptoUtf16::replace(size_type pos, size_type count, size_type count2, value_type ch)
{
	erase(pos, count);
	insert(pos, count2, ch);
	return *this;
}
CryptoUtf16& CryptoUtf16::replace(const_iterator first, const_iterator last, size_type count2, value_type ch)
{
	size_type pos = first - cbegin();
	erase(first, last);
	insert(pos, count2, ch);
	return *this;
}
CryptoUtf16& CryptoUtf16::replace(const_iterator first, const_iterator last, std::initializer_list<value_type> iList)
{
	size_type pos = first - cbegin();
	erase(first, last);
	insert(pos, iList);
	return *this;
}
CryptoUtf16 CryptoUtf16::substr(size_type index, size_type count) const
{
	if (index >= size() || count == 0)
		return CryptoUtf16();
	if (index + count >= size())
	{
		count = size() - index;
	}
	return CryptoUtf16(&c_str()[index], count);
}
CryptoUtf16::size_type CryptoUtf16::copy(pointer dest, size_type count, size_type pos) const
{
	if (pos >= size())
		throw tscrypto::OutOfRange();
	if (count + pos > size())
		count = size() - pos;
	memcpy(dest, &m_data[pos], sizeof(value_type) * count);
	return count;
}
_Post_satisfies_(this->m_data != nullptr)
void CryptoUtf16::resize(size_type newSize)
{
	resize(newSize, 0);
}
_Post_satisfies_(this->m_data != nullptr)
void CryptoUtf16::resize(size_type newSize, ts_wchar value)
{
	reserve(newSize);
	if (capacity() < newSize)
		throw tscrypto::bad_alloc();

	if (newSize > m_used)
	{
		for (size_type i = 0; i < newSize - m_used; i++)
			m_data[m_used + i] = value;
		m_used = newSize;
	}
	else if (newSize < m_used)
	{
		memset(&m_data[newSize], 0, (m_used - newSize) * sizeof(value_type));
		m_used = newSize;
	}
}
void CryptoUtf16::swap(CryptoUtf16 &obj)
{
	std::swap(m_data, obj.m_data);
	std::swap(m_used, obj.m_used);
	std::swap(m_allocated, obj.m_allocated);
}
CryptoUtf16::size_type CryptoUtf16::find(const CryptoUtf16& str, size_type pos) const
{
	size_type i;
	size_type len = 0;

	len = str.size();
	if (len == 0)
		return npos;

	if (pos + len > m_used)
		return npos;
	for (i = pos; i < m_used - len + 1; i++)
	{
		const_pointer in_data_c_str = str.c_str();
		if (memcmp(in_data_c_str, &m_data[i], len * sizeof(value_type)) == 0)
		{
			return i;
		}
	}
	return npos;
}
CryptoUtf16::size_type CryptoUtf16::find(const_pointer s, size_type pos, size_type count) const
{
	if (s == nullptr)
		throw tscrypto::ArgumentNullException("s");

	size_type i;

	if (count == 0)
		return npos;

	if (pos + count > m_used)
		return npos;
	for (i = pos; i < m_used - count + 1; i++)
	{
		if (memcmp(s, &m_data[i], count * sizeof(value_type)) == 0)
		{
			return i;
		}
	}
	return npos;
}
CryptoUtf16::size_type CryptoUtf16::find(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		throw tscrypto::ArgumentNullException("s");

	return find(s, pos, tsUtf16Len((const TSUtf16*)s));
}
CryptoUtf16::size_type CryptoUtf16::find(value_type ch, size_type pos) const
{
	size_type i;

	if (pos >= m_used)
		return npos;
	for (i = pos; i < m_used; i++)
	{
		if (m_data[i] == ch)
		{
			return i;
		}
	}
	return npos;
}
CryptoUtf16::size_type CryptoUtf16::rfind(const CryptoUtf16& str, size_type pos) const
{
	size_type count = str.size();

	if (count == 0)
		return npos;

	if (pos + count > size())
		pos = size() - count;

	difference_type i;

	for (i = pos; i >= 0; i--)
	{
		if (memcmp(str.c_str(), &m_data[i], count * sizeof(value_type)) == 0)
		{
			return i;
		}
	}
	return npos;
}
CryptoUtf16::size_type CryptoUtf16::rfind(const_pointer s, size_type pos, size_type count) const
{
	if (s == nullptr)
		throw tscrypto::ArgumentNullException("s");

	if (count == 0)
		return npos;

	if (pos + count > size())
		pos = size() - count;

	difference_type i;

	for (i = pos; i >= 0; i--)
	{
		if (memcmp(s, &m_data[i], count * sizeof(value_type)) == 0)
		{
			return i;
		}
	}
	return npos;
}
CryptoUtf16::size_type CryptoUtf16::rfind(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		throw tscrypto::ArgumentNullException("s");

	return rfind(s, pos, tsUtf16Len((const TSUtf16*)s));
}
CryptoUtf16::size_type CryptoUtf16::rfind(value_type ch, size_type pos) const
{
	if (pos >= size())
		pos = size() - 1;

	difference_type i;

	for (i = pos; i >= 0; i--)
	{
		if (m_data[i] == ch)
		{
			return i;
		}
	}
	return npos;
}
CryptoUtf16::size_type CryptoUtf16::find_first_of(const CryptoUtf16& str, size_type pos) const
{
	return find_first_of(str.c_str(), pos, str.size());
}
CryptoUtf16::const_pointer CryptoUtf16::WcsChr(const_pointer list, value_type ch, size_type count)
{
	if (list == nullptr || count == 0)
		return nullptr;
	for (size_type i = 0; i < count; i++)
	{
		if (list[i] == ch)
			return &list[i];
	}
	return nullptr;
}
CryptoUtf16::size_type CryptoUtf16::find_first_of(const_pointer s, size_type pos, size_type count) const
{
	if (s == nullptr || count == 0)
		return npos;
	size_type i;

	if (pos >= size())
		return npos;

	for (i = pos; i < m_used; i++)
	{
		if (WcsChr(s, m_data[i], count) != nullptr)
		{
			return i;
		}
	}
	return npos;
}
CryptoUtf16::size_type CryptoUtf16::find_first_of(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		return npos;
	return find_first_of(s, pos, tsUtf16Len((const TSUtf16*)s));
}
CryptoUtf16::size_type CryptoUtf16::find_first_of(value_type ch, size_type pos) const
{
	return find(ch, pos);
}
CryptoUtf16::size_type CryptoUtf16::find_first_not_of(const CryptoUtf16& str, size_type pos) const
{
	return find_first_not_of(str.c_str(), pos, str.size());
}
CryptoUtf16::size_type CryptoUtf16::find_first_not_of(const_pointer s, size_type pos, size_type count) const
{
	if (s == nullptr || count == 0)
		return npos;
	size_type i;

	if (pos >= size())
		return npos;

	for (i = pos; i < m_used; i++)
	{
		if (WcsChr(s, m_data[i], count) == nullptr)
		{
			return i;
		}
	}
	return npos;
}
CryptoUtf16::size_type CryptoUtf16::find_first_not_of(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		return npos;
	return find_first_not_of(s, pos, tsUtf16Len((const TSUtf16*)s));
}
CryptoUtf16::size_type CryptoUtf16::find_first_not_of(value_type ch, size_type pos) const
{
	size_type i;

	if (pos >= size())
		return npos;

	for (i = pos; i < m_used; i++)
	{
		if (m_data[i] != ch)
		{
			return i;
		}
	}
	return npos;
}
CryptoUtf16::size_type CryptoUtf16::find_last_of(const CryptoUtf16& str, size_type pos) const
{
	return find_last_of(str.c_str(), pos, str.size());
}
CryptoUtf16::size_type CryptoUtf16::find_last_of(const_pointer s, size_type pos, size_type count) const
{
	if (s == nullptr || count == 0)
		return npos;
	difference_type i;

	if (pos >= size())
		pos = size() - 1;

	for (i = pos; i >= 0; --i)
	{
		if (WcsChr(s, m_data[i], count) != nullptr)
		{
			return i;
		}
	}
	return npos;
}
CryptoUtf16::size_type CryptoUtf16::find_last_of(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		return npos;
	return find_last_of(s, pos, tsUtf16Len((const TSUtf16*)s));
}
CryptoUtf16::size_type CryptoUtf16::find_last_of(value_type ch, size_type pos) const
{
	return rfind(ch, pos);
}
CryptoUtf16::size_type CryptoUtf16::find_last_not_of(const CryptoUtf16& str, size_type pos) const
{
	return find_last_not_of(str.c_str(), pos, str.size());
}
CryptoUtf16::size_type CryptoUtf16::find_last_not_of(const_pointer s, size_type pos, size_type count) const
{
	if (s == nullptr || count == 0)
		return npos;
	difference_type i;

	if (pos >= size())
		pos = size() - 1;

	for (i = pos; i >= 0; --i)
	{
		if (WcsChr(s, m_data[i], count) == nullptr)
		{
			return i;
		}
	}
	return npos;
}
CryptoUtf16::size_type CryptoUtf16::find_last_not_of(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		return npos;
	return find_last_not_of(s, pos, tsUtf16Len((const TSUtf16*)s));
}
CryptoUtf16::size_type CryptoUtf16::find_last_not_of(value_type ch, size_type pos) const
{
	difference_type i;

	if (pos >= size())
		pos = size() - 1;

	for (i = pos; i >= 0; --i)
	{
		if (m_data[i] != ch)
		{
			return i;
		}
	}
	return npos;
}
// TecSec Extensions
tsCryptoString CryptoUtf16::toUtf8() const
{
	tsCryptoString tmp;

	tmp.resize(tsUtf8LenFromUtf16((const TSUtf16*)m_data, false));
	const TSUtf16* srcStart = (const TSUtf16*)m_data;
    TSUtf8 *destStart = (TSUtf8*)tmp.data();
	if (tsUtf16ToUtf8(srcStart, destStart, (uint32_t)m_used, false) != 0)
		tmp.resize(0);
	return tmp;
}
CryptoUtf16& CryptoUtf16::assign(const char *newData, size_type count)
{
	clear();
	return append(newData, count);
}
CryptoUtf16& CryptoUtf16::assign(const char *newData)
{
	clear();
	return append(newData);
}
CryptoUtf16& CryptoUtf16::assign(const tsCryptoStringBase &obj)
{
	clear();
	return append(obj);
}
CryptoUtf16& CryptoUtf16::assign(std::initializer_list<char> iList)
{
	clear();
	return append(iList);
}
CryptoUtf16& CryptoUtf16::assign(value_type data)
{
	clear();
	return append(data);
}
CryptoUtf16& CryptoUtf16::assign(char data)
{
	clear();
	return append(data);
}
CryptoUtf16& CryptoUtf16::assign(int16_t val)
{
	clear();
	return append(val);
}
CryptoUtf16& CryptoUtf16::assign(int32_t val)
{
	clear();
	return append(val);
}
CryptoUtf16& CryptoUtf16::assign(int64_t val)
{
	clear();
	return append(val);
}
// CryptoUtf16& CryptoUtf16::assign(uint16_t val)
// {
// 	clear();
// 	return append(val);
// }
CryptoUtf16& CryptoUtf16::assign(uint32_t val)
{
	clear();
	return append(val);
}
CryptoUtf16& CryptoUtf16::assign(uint64_t val)
{
	clear();
	return append(val);
}
CryptoUtf16::value_type CryptoUtf16::c_at(size_type index) const
{
	return at(index);
}
CryptoUtf16::pointer CryptoUtf16::rawData()
{
	return data();
}
CryptoUtf16& CryptoUtf16::insert(size_type index, size_type count, char ch)
{
	return insert(index, count, (value_type)ch);
}
CryptoUtf16& CryptoUtf16::insert(size_type index, char ch)
{
	return insert(index, (value_type)ch);
}
CryptoUtf16& CryptoUtf16::insert(size_type index, const char* s)
{
	return insert(index, CryptoUtf16(s));
}
CryptoUtf16& CryptoUtf16::insert(size_type index, const char* s, size_type count)
{
	return insert(index, CryptoUtf16(s, count));
}
CryptoUtf16& CryptoUtf16::insert(size_type index, const tsCryptoStringBase& str)
{
	return insert(index, CryptoUtf16(str));
}
CryptoUtf16& CryptoUtf16::insert(size_type index, const tsCryptoStringBase& str, size_type index_str, size_type count)
{
	return insert(index, CryptoUtf16(str.substr(index_str, count)));
}
CryptoUtf16& CryptoUtf16::insert(const_iterator pos, char ch)
{
	return insert(pos, (value_type)ch);
}
CryptoUtf16& CryptoUtf16::insert(const_iterator pos, size_type count, char ch)
{
	return insert(pos, count, (value_type)ch);
}
CryptoUtf16& CryptoUtf16::insert(const_iterator pos, std::initializer_list<char> iList)
{
	CryptoUtf16 tmp(iList);

	return insert(pos, tmp.begin(), tmp.end());
}
CryptoUtf16 &CryptoUtf16::operator=(std::initializer_list<char> iList)
{
	return append(iList);
}
void CryptoUtf16::push_back(char ch)
{
	resize(size() + 1, (value_type)ch);
}
CryptoUtf16& CryptoUtf16::append(size_type len, char ch)
{
	resize(size() + len, (value_type)ch);
	return *this;
}
CryptoUtf16& CryptoUtf16::append(const tsCryptoStringBase &obj)
{
	return append(obj.data(), obj.size());
}
CryptoUtf16& CryptoUtf16::append(const tsCryptoStringBase &obj, size_type pos, size_type count)
{
	return append(obj.substr(pos, count));
}
CryptoUtf16& CryptoUtf16::append(const char* s, size_type count)
{
	if (s == nullptr)
	{
		return *this;
	}
	size_type oldSize = size();

    if (!isValidUtf8(s, (uint32_t)count))
    {
        clear();
        return *this;
    }
	resize(oldSize + tsUtf16LenFromUtf8((TSUtf8*)s, false));
	const TSUtf8* srcStart = (TSUtf8*)s;
    TSUtf16 *destStart = (TSUtf16*)m_data + oldSize;
	if (tsCountedUtf8ToUtf16(srcStart, (uint32_t)count, destStart, (uint32_t)m_used + 1, false) != 0)
		resize(0);
	return *this;
}
CryptoUtf16& CryptoUtf16::append(const char* s)
{
	if (s == nullptr)
	{
		return *this;
	}
	size_type oldSize = size();

	size_type Len = tsStrLen(s);
    if (!isValidUtf8(s, (uint32_t)Len))
    {
        clear();
        return *this;
    }
    resize(oldSize + tsUtf16LenFromUtf8((TSUtf8*)s, false));
	const TSUtf8* srcStart = (TSUtf8*)s;
    TSUtf16 *destStart = (TSUtf16*)m_data + oldSize;
	if (tsUtf8ToUtf16(srcStart, destStart, (uint32_t)m_used + 1, false) != 0)
		resize(0);
	return *this;
}
CryptoUtf16& CryptoUtf16::append(std::initializer_list<char> list)
{
	return append(tsCryptoString(list));
}
CryptoUtf16& CryptoUtf16::append(value_type data)
{
	resize(size() + 1, data);
	return *this;
}
CryptoUtf16& CryptoUtf16::append(char data)
{
	resize(size() + 1, (value_type)data);
	return *this;
}
CryptoUtf16& CryptoUtf16::append(int16_t val)
{
	return append(tsCryptoString().append(val));
}
CryptoUtf16& CryptoUtf16::append(int32_t val)
{
	return append(tsCryptoString().append(val));
}
CryptoUtf16& CryptoUtf16::append(int64_t val)
{
	return append(tsCryptoString().append(val));
}
// CryptoUtf16& CryptoUtf16::append(uint16_t val)
// {
// 	return append(tsCryptoString().append(val));
//}
CryptoUtf16& CryptoUtf16::append(uint32_t val)
{
	return append(tsCryptoString().append(val));
}
CryptoUtf16& CryptoUtf16::append(uint64_t val)
{
	return append(tsCryptoString().append(val));
}
CryptoUtf16& CryptoUtf16::operator += (const tsCryptoStringBase &obj)
{
	return append(obj);
}
CryptoUtf16& CryptoUtf16::operator += (char data)
{
	return append(data);
}
CryptoUtf16& CryptoUtf16::operator += (const char* data)
{
	return append(data);
}
CryptoUtf16& CryptoUtf16::operator += (std::initializer_list<char> init)
{
	return append(init);
}
CryptoUtf16& CryptoUtf16::operator += (int16_t val)
{
	return append(val);
}
CryptoUtf16& CryptoUtf16::operator += (int32_t val)
{
	return append(val);
}
CryptoUtf16& CryptoUtf16::operator += (int64_t val)
{
	return append(val);
}
// CryptoUtf16& CryptoUtf16::operator += (uint16_t val)
// {
// 	return append(val);
// }
CryptoUtf16& CryptoUtf16::operator += (uint32_t val)
{
	return append(val);
}
CryptoUtf16& CryptoUtf16::operator += (uint64_t val)
{
	return append(val);
}
int CryptoUtf16::compare(const tsCryptoStringBase& str) const
{
	return compare(CryptoUtf16(str));
}
int CryptoUtf16::compare(size_type pos1, size_type count1, const tsCryptoStringBase& str) const
{
	return compare(pos1, count1, CryptoUtf16(str));
}
int CryptoUtf16::compare(size_type pos1, size_type count1, const tsCryptoStringBase& str, size_type pos2, size_type count2) const
{
	return compare(pos1, count1, CryptoUtf16(str.substr(pos2, count2)));
}
int CryptoUtf16::compare(const char* s) const
{
	return compare(CryptoUtf16(s));
}
int CryptoUtf16::compare(size_type pos1, size_type count1, const char* s) const
{
	return compare(pos1, count1, CryptoUtf16(s));
}
int CryptoUtf16::compare(size_type pos1, size_type count1, const char* s, size_type count2) const
{
	return compare(pos1, count1, CryptoUtf16(s, count2));
}
CryptoUtf16& CryptoUtf16::replace(size_type pos, size_type count, const tsCryptoStringBase& str)
{
	return replace(pos, count, CryptoUtf16(str));
}
CryptoUtf16& CryptoUtf16::replace(const_iterator first, const_iterator last, const tsCryptoStringBase& str)
{
	return replace(first, last, CryptoUtf16(str));
}
CryptoUtf16& CryptoUtf16::replace(size_type pos, size_type count, const tsCryptoStringBase& str, size_type pos2, size_type count2)
{
	return replace(pos, count, CryptoUtf16(str.substr(pos2, count2)));
}
CryptoUtf16& CryptoUtf16::replace(size_type pos, size_type count, const char* s, size_type count2)
{
	return replace(pos, count, CryptoUtf16(s, count2));
}
CryptoUtf16& CryptoUtf16::replace(const_iterator first, const_iterator last, const char* s, size_type count2)
{
	return replace(first, last, CryptoUtf16(s, count2));
}
CryptoUtf16& CryptoUtf16::replace(size_type pos, size_type count, const char* s)
{
	return replace(pos, count, CryptoUtf16(s));
}
CryptoUtf16& CryptoUtf16::replace(const_iterator first, const_iterator last, const char* s)
{
	return replace(first, last, CryptoUtf16(s));
}
CryptoUtf16& CryptoUtf16::replace(size_type pos, size_type count, size_type count2, char ch)
{
	return replace(pos, count, CryptoUtf16(count2, ch));
}
CryptoUtf16& CryptoUtf16::replace(const_iterator first, const_iterator last, size_type count2, char ch)
{
	return replace(first, last, CryptoUtf16(count2, ch));
}
CryptoUtf16& CryptoUtf16::replace(const_iterator first, const_iterator last, std::initializer_list<char> iList)
{
	return replace(first, last, CryptoUtf16(iList));
}
CryptoUtf16 CryptoUtf16::right(size_type length) const
{
	if (length > size())
		return *this;
	return substr(size() - length);
}
CryptoUtf16 CryptoUtf16::left(size_type length) const
{
	return substr(0, length);
}
CryptoUtf16& CryptoUtf16::padLeft(size_type length, value_type value)
{
	size_type oldLen = size();

	if (oldLen < length)
	{
		CryptoUtf16 tmp(length - oldLen, value);
		insert(0, tmp);
	}
	return *this;
}
CryptoUtf16& CryptoUtf16::padRight(size_type length, value_type value)
{
	if (size() < length)
	{
		resize(length, value);
	}
	return *this;
}
CryptoUtf16& CryptoUtf16::truncOrPadLeft(size_type length, value_type value)
{
	if (size() > length)
	{
		resize(length);
	}
	else
	{
		return padLeft(length, value);
	}
	return *this;
}
void CryptoUtf16::copyFrom(const CryptoUtf16 &obj)
{
	if (&obj == this)
		return;
	resize(obj.size());
	memcpy(m_data, obj.m_data, m_used * sizeof(value_type));
}
bool CryptoUtf16::isValidUtf8(const char* s)
{
    return tsIsLegalUTF8((const TSUtf8*)s);
}
bool CryptoUtf16::isValidUtf8(const char* s, uint32_t count)
{
    return tsIsLegalUTF8Len((const TSUtf8*)s, count);
}

void tscrypto::swap(CryptoUtf16 &lhs, CryptoUtf16 &rhs)
{
	lhs.swap(rhs);
}
bool tscrypto::operator==(const CryptoUtf16& lhs, const CryptoUtf16& rhs)
{
	return lhs.compare(rhs) == 0;
}
bool tscrypto::operator!=(const CryptoUtf16& lhs, const CryptoUtf16& rhs)
{
	return lhs.compare(rhs) != 0;
}
bool tscrypto::operator<(const CryptoUtf16& lhs, const CryptoUtf16& rhs)
{
	return lhs.compare(rhs) < 0;
}
bool tscrypto::operator<=(const CryptoUtf16& lhs, const CryptoUtf16& rhs)
{
	return lhs.compare(rhs) <= 0;
}
bool tscrypto::operator>(const CryptoUtf16& lhs, const CryptoUtf16& rhs)
{
	return lhs.compare(rhs) > 0;
}
bool tscrypto::operator>=(const CryptoUtf16& lhs, const CryptoUtf16& rhs)
{
	return lhs.compare(rhs) >= 0;
}


std::ostream& tscrypto::operator << (std::ostream &Output, const CryptoUtf16 &obj)
{
	Output << obj.toUtf8();
	return Output;
}
std::wostream& tscrypto::operator << (std::wostream &Output, const CryptoUtf16 &obj)
{
	Output << obj.data();
	return Output;
}
CryptoUtf16& tscrypto::operator<<(CryptoUtf16& string, char val)
{
	return string.append(val);
}
CryptoUtf16& tscrypto::operator<<(CryptoUtf16& string, int8_t val)
{
	return string.append(val);
}
CryptoUtf16& tscrypto::operator<<(CryptoUtf16& string, int16_t val)
{
	return string.append(val);
}
CryptoUtf16& tscrypto::operator<<(CryptoUtf16& string, int32_t val)
{
	return string.append(val);
}
CryptoUtf16& tscrypto::operator<<(CryptoUtf16& string, int64_t val)
{
	return string.append(val);
}
CryptoUtf16& tscrypto::operator<<(CryptoUtf16& string, uint8_t val)
{
	return string.append(val);
}
// CryptoUtf16& tscrypto::operator<<(CryptoUtf16& string, uint16_t val)
// {
// 	return string.append(val);
// }
CryptoUtf16& tscrypto::operator<<(CryptoUtf16& string, uint32_t val)
{
	return string.append(val);
}
CryptoUtf16& tscrypto::operator<<(CryptoUtf16& string, uint64_t val)
{
	return string.append(val);
}
CryptoUtf16& tscrypto::operator<<(CryptoUtf16& string, const char* val)
{
	return string.append(val);
}
CryptoUtf16& tscrypto::operator<<(CryptoUtf16& string, const tsCryptoStringBase& val)
{
	return string.append(val);
}
CryptoUtf16& tscrypto::operator<<(CryptoUtf16& string, const CryptoUtf16& val)
{
	return string.append(val);
}

