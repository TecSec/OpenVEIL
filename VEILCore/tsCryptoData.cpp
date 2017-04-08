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
#include "ConvertUTF.h"

#define MemAllocSize 100

#define BASE64_ENCODE_RATIO 1.4
#define BASE64_DECODE_RATIO 1.3

#ifndef MIN
#   define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif// MIN

using namespace tscrypto;

const tscrypto::tsCryptoData::size_type tscrypto::tsCryptoData::npos = (size_type)(-1);

tsCryptoData::tsCryptoData() : m_data(nullptr), m_used(0), m_allocated(-1)
{
	reserve(0);
}
tsCryptoData::tsCryptoData(size_type count, value_type value) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	resize(count, value);
}
tsCryptoData::tsCryptoData(const tsCryptoData &obj, size_type pos) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	if (pos >= obj.size())
		reserve(0);
	else
	{
		resize(obj.size() - pos);
		obj.copy(m_data, size(), pos);
	}
}
tsCryptoData::tsCryptoData(const tsCryptoData &obj, size_type pos, size_type count) : m_data(nullptr), m_used(0), m_allocated(-1)
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
tsCryptoData::tsCryptoData(const_pointer data, size_type Len) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	if (data == nullptr || Len == 0)
		reserve(0);
	else
	{
		resize(Len);
		memcpy(m_data, data, Len);
	}
}
tsCryptoData::tsCryptoData(const_pointer data) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	if (data == nullptr)
		reserve(0);
	else
	{
		size_type Len = TsStrLen((const char*)data);
		if (Len == 0)
			reserve(0);
		else
		{
			resize(Len);
			memcpy(m_data, data, Len);
		}
	}
}
tsCryptoData::tsCryptoData(const tsCryptoData &obj) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	if (obj.size() == 0)
		reserve(0);
	else
	{
		resize(obj.size());
		obj.copy(m_data, size(), 0);
	}
}
tsCryptoData::tsCryptoData(tsCryptoData &&obj)
{
	m_data = obj.m_data;
	m_used = obj.m_used;
	m_allocated = obj.m_allocated;

	obj.m_data = nullptr;
	obj.m_used = 0;
	obj.m_allocated = -1;
	obj.reserve(0);
}
tsCryptoData::tsCryptoData(std::initializer_list<value_type> init) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	size_type index = 0;
	resize(init.size());

	for (auto i = init.begin(); i != init.end(); ++i)
	{
		m_data[index++] = *i;
	}
}
tsCryptoData::tsCryptoData(const tsCryptoStringBase &value, DataStringType type) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	size_type Len = value.size();
	if (Len > 0)
	{
		switch (type)
		{
		case OID:
			FromOIDString(value);
			break;
		case HEX:
			FromHexString(value);
			break;
		case BASE64:
			FromBase64(value);
			break;
		case BASE64URL:
			FromBase64(value, true);
			break;
		case ASCII:
		default:
			resize(Len);
			if (m_data != nullptr)
				memcpy(m_data, value.c_str(), Len);
			break;
		}
	}
	else
		reserve(0);
}
// ASCII only
tsCryptoData::tsCryptoData(const tsCryptoStringBase &value) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	if (value.size() == 0)
		reserve(0);
	else
	{
		resize(value.size());
		memcpy(m_data, value.data(), value.size());
	}
}
tsCryptoData::tsCryptoData(std::initializer_list<char> init) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	size_type index = 0;
	resize(init.size());

	for (auto i = init.begin(); i != init.end(); ++i)
	{
		m_data[index++] = *i;
	}
}
tsCryptoData::tsCryptoData(value_type ch) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	resize(1, ch);
}
tsCryptoData::tsCryptoData(char ch) : m_data(nullptr), m_used(0), m_allocated(-1)
{
	resize(1, (value_type)ch);
}
tsCryptoData::~tsCryptoData()
{
	if (m_data != nullptr)
	{
		if (m_used > 0)
			memset(m_data, 0, m_used);
		tscrypto::cryptoDelete(m_data);
		m_data = nullptr;
	}
	m_used = 0;
	m_allocated = -1;
}

tsCryptoData &tsCryptoData::operator=(const tsCryptoData &obj)
{
	copyFrom(obj);
	return *this;
}
tsCryptoData &tsCryptoData::operator=(tsCryptoData &&obj)
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
tsCryptoData &tsCryptoData::operator=(const_pointer data) /* zero terminated */
{
	size_type len = 0;
	if (data == nullptr)
	{
		resize(0);
	}
	else
	{
		len = TsStrLen((const char *)data);

		resize(len);
		memcpy(m_data, data, len);
	}
	return *this;
}
tsCryptoData &tsCryptoData::operator=(value_type obj)
{
	resize(1);
	m_data[0] = obj;
	return *this;
}
tsCryptoData &tsCryptoData::operator=(std::initializer_list<value_type> iList)
{
	assign(iList);
	return *this;
}
tsCryptoData &tsCryptoData::operator=(const tsCryptoStringBase &obj) // ASCII ONLY - tecsec addition
{
	assign(obj);
	return *this;
}
tsCryptoData &tsCryptoData::operator=(const char *data) // zero terminated - tecsec addition
{
	size_type len = 0;
	if (data == nullptr)
	{
		resize(0);
	}
	else
	{
		len = TsStrLen(data);

		resize(len);
		memcpy(m_data, data, len);
	}
	return *this;
}
tsCryptoData &tsCryptoData::operator=(std::initializer_list<char> iList)
{
	assign(iList);
	return *this;
}

tsCryptoData& tsCryptoData::assign(size_type count, value_type ch)
{
	clear();
	resize(count, ch);
	return *this;
}
tsCryptoData& tsCryptoData::assign(const tsCryptoData &obj)
{
	if (this == &obj)
		return *this;
	return assign(obj.c_str(), obj.size());
}
tsCryptoData& tsCryptoData::assign(const tsCryptoData &obj, size_type pos, size_type count)
{
	if (this == &obj)
		return *this;
	return assign(obj.substr(pos, count));
}
tsCryptoData& tsCryptoData::assign(tsCryptoData &&obj)
{
	if (this == &obj)
		return *this;

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

	return *this;
}
tsCryptoData& tsCryptoData::assign(const_pointer newData, size_type count)
{
	resize(count);
	if (count > 0 && newData != nullptr)
	{
		memcpy(m_data, newData, count);
	}
	return *this;
}
tsCryptoData& tsCryptoData::assign(const_pointer newData)
{
	return assign(newData, (newData != nullptr) ? TsStrLen((const char *)newData) : 0);
}
tsCryptoData& tsCryptoData::assign(std::initializer_list<value_type> iList)
{
	size_type pos = size();

	resize(iList.size());
	for (auto it = iList.begin(); it != iList.end(); ++it)
	{
		m_data[pos++] = *it;
	}
	return *this;
}
tsCryptoData& tsCryptoData::assign(const char *newData, size_type count) // tecsec extension
{
	resize(count);
	if (count > 0 && newData != nullptr)
	{
		memcpy(m_data, newData, count);
	}
	return *this;
}
tsCryptoData& tsCryptoData::assign(const char *newData) // tecsec extension
{
	return assign(newData, (newData != nullptr) ? TsStrLen(newData) : 0);
}
tsCryptoData& tsCryptoData::assign(const tsCryptoStringBase &obj) // ASCII ONLY - tecsec extension
{
	return assign(obj.c_str(), obj.size());
}
tsCryptoData& tsCryptoData::assign(std::initializer_list<char> iList)
{
	size_type pos = size();

	resize(iList.size());
	for (auto it = iList.begin(); it != iList.end(); ++it)
	{
		m_data[pos++] = *it;
	}
	return *this;
}

tsCryptoData::reference tsCryptoData::at(size_type index)
{
	if (index >= m_used)
	{
		throw tscrypto::OutOfRange();
	}
	return m_data[index];
}
tsCryptoData::const_reference tsCryptoData::at(size_type index) const
{
	if (index >= m_used)
	{
		throw tscrypto::OutOfRange();
	}
	return m_data[index];
}
tsCryptoData::value_type tsCryptoData::c_at(size_type index) const // tecsec addition
{
	if (index >= m_used)
	{
		throw tscrypto::OutOfRange();
	}
	return m_data[index];
}
tsCryptoData::const_pointer tsCryptoData::data() const
{
	return m_data;
}
tsCryptoData::pointer tsCryptoData::data()
{
	return m_data;
}
tsCryptoData::pointer tsCryptoData::rawData() // tecsec addition
{
	return m_data;
}
tsCryptoData::const_pointer tsCryptoData::c_str() const
{
	return m_data;
}
tsCryptoData::reference tsCryptoData::front()
{
	return m_data[0];
}
tsCryptoData::const_reference tsCryptoData::front() const
{
	return m_data[0];
}
tsCryptoData::reference tsCryptoData::back()
{
	if (empty())
		throw tscrypto::OutOfRange();
	return m_data[m_used - 1];
}
tsCryptoData::const_reference tsCryptoData::back() const
{
	if (empty())
		throw tscrypto::OutOfRange();
	return m_data[m_used - 1];
}
tsCryptoData::reference tsCryptoData::operator [] (size_type index)
{
	return at(index);
}
tsCryptoData::const_reference tsCryptoData::operator [] (size_type index) const
{
	return at(index);
}

tsCryptoData::iterator tsCryptoData::begin()
{
	return iterator(this);
}
tsCryptoData::const_iterator tsCryptoData::begin() const
{
	return const_iterator(this);
}
tsCryptoData::iterator tsCryptoData::end()
{
	return iterator(this, size());
}
tsCryptoData::const_iterator tsCryptoData::end() const
{
	return const_iterator(this, size());
}
tsCryptoData::const_iterator tsCryptoData::cbegin() const
{
	return const_iterator(this);
}
tsCryptoData::const_iterator tsCryptoData::cend() const
{
	return const_iterator(this, size());
}
tsCryptoData::reverse_iterator tsCryptoData::rbegin()
{
	return reverse_iterator(end());
}
tsCryptoData::reverse_iterator tsCryptoData::rend()
{
	return reverse_iterator(begin());
}
tsCryptoData::const_reverse_iterator tsCryptoData::crbegin() const
{
	return const_reverse_iterator(cend());
}
tsCryptoData::const_reverse_iterator tsCryptoData::crend() const
{
	return const_reverse_iterator(cbegin());
}

bool tsCryptoData::empty() const
{
	return m_used == 0;
}
tsCryptoData::size_type  tsCryptoData::size() const
{
	return m_used;
}
tsCryptoData::size_type  tsCryptoData::length() const
{
	return m_used;
}
tsCryptoData::size_type tsCryptoData::max_size() const
{
	return 0x7FFFFFFF;
}
_Post_satisfies_(this->m_data != nullptr) void tsCryptoData::reserve(size_type newSize)
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
tsCryptoData::size_type tsCryptoData::capacity() const
{
	return m_allocated;
}
void tsCryptoData::clear()
{
	resize(0);
}

tsCryptoData& tsCryptoData::insert(size_type index, size_type count, value_type ch)
{
	size_type oldsize = size();

	resize(size() + count);
	memmove(&m_data[index + count], &m_data[index], sizeof(value_type) * (oldsize - index));
	memset(&m_data[index], ch, count);
	return *this;
}
tsCryptoData& tsCryptoData::insert(size_type index, value_type ch)
{
	size_type oldsize = size();

	resize(size() + 1);
	memmove(&m_data[index + 1], &m_data[index], sizeof(value_type) * (oldsize - index));
	m_data[index] = ch;
	return *this;
}
tsCryptoData& tsCryptoData::insert(size_type index, const_pointer s)
{
	if (s == nullptr)
		throw tscrypto::ArgumentNullException("s");

	size_type oldsize = size();
	size_type count = TsStrLen((const char *)s);

	resize(size() + count);
	memmove(&m_data[index + count], &m_data[index], sizeof(value_type) * (oldsize - index));
	memcpy(&m_data[index], s, count);
	return *this;
}
tsCryptoData& tsCryptoData::insert(size_type index, const_pointer s, size_type count)
{
	if (s == nullptr)
		throw tscrypto::ArgumentNullException("s");

	size_type oldsize = size();

	resize(size() + count);
	memmove(&m_data[index + count], &m_data[index], sizeof(value_type) * (oldsize - index));
	memcpy(&m_data[index], s, count);
	return *this;
}
tsCryptoData& tsCryptoData::insert(size_type index, const tsCryptoData& str)
{
	size_type oldsize = size();
	size_type count = str.size();

	if (count == 0)
		return *this;
	resize(size() + count);
	memmove(&m_data[index + count], &m_data[index], sizeof(value_type) * (oldsize - index));
	memcpy(&m_data[index], str.data(), count);
	return *this;
}
tsCryptoData& tsCryptoData::insert(size_type index, const tsCryptoData& str, size_type index_str, size_type count)
{
	return insert(index, str.substr(index_str, count));
}
tsCryptoData& tsCryptoData::insert(const_iterator pos, value_type ch)
{
	size_type index = pos - begin();
	return insert(index, ch);
}
tsCryptoData& tsCryptoData::insert(const_iterator pos, size_type count, value_type ch)
{
	size_type index = pos - begin();
	return insert(index, count, ch);
}
tsCryptoData& tsCryptoData::insert(const_iterator pos, std::initializer_list<value_type> iList)
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

tsCryptoData& tsCryptoData::erase(size_type pos, size_type count)
{
	if (pos > size())
		throw tscrypto::OutOfRange();
	if (pos + count >= size())
	{
		resize(pos);
	}
	else
	{
		memmove(&m_data[pos], &m_data[pos + count], sizeof(value_type) * (size() - count - pos));
		resize(size() - count);
	}
	return *this;
}
tsCryptoData::iterator tsCryptoData::erase(const_iterator position)
{
	size_type pos = position - cbegin();

	if (position == cend())
		throw tscrypto::OutOfRange();

	if (pos == size() - 1)
	{
		resize(size() - 1);
		return end();
	}
	memmove(&m_data[pos], &m_data[pos + 1], sizeof(value_type) * (size() - pos - 1));
	resize(size() - 1);
	return iterator(this, pos);
}
tsCryptoData::iterator tsCryptoData::erase(const_iterator first, const_iterator last)
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
	memmove(&m_data[pos], &m_data[pos + count], sizeof(value_type) * (size() - count - pos));
	resize(size() - count);
	return iterator(this, pos);
}

void tsCryptoData::push_back(value_type ch)
{
	resize(size() + 1, ch);
}
void tsCryptoData::pop_back()
{
	if (size() > 0)
		resize(size() - 1);
}

tsCryptoData &tsCryptoData::append(size_type len, value_type ch)
{
	resize(size() + len, ch);
	return *this;
}
tsCryptoData &tsCryptoData::append(const tsCryptoData &obj)
{
	size_type objSize = obj.size();

	if (objSize > 0)
	{
		tsCryptoString::size_type oldUsed = m_used;
		resize(oldUsed + objSize);
		memcpy(&m_data[oldUsed], obj.c_str(), objSize * sizeof(value_type));
	}
	return *this;
}
tsCryptoData &tsCryptoData::append(const tsCryptoData &obj, size_type pos, size_type count)
{
	return append(obj.substr(pos, count));
}
tsCryptoData &tsCryptoData::append(const_pointer data, size_type count)
{
	if (data == nullptr)
	{
		return *this;
	}
	return append(tsCryptoData(data, count));
}
tsCryptoData &tsCryptoData::append(const_pointer data)
{
	if (data == nullptr)
	{
		return *this;
	}
	return append(tsCryptoData(data));
}
tsCryptoData &tsCryptoData::append(std::initializer_list<value_type> list)
{
	size_type pos = size();

	resize(size() + list.size());
	for (auto it = list.begin(); it != list.end(); ++it)
	{
		m_data[pos++] = *it;
	}
	return *this;
}

tsCryptoData &tsCryptoData::operator+= (const tsCryptoData &obj)
{
	tsCryptoData::size_type len = 0;
	tsCryptoData::size_type oldUsed = m_used;
	if (obj.size() > 0)
	{
		len = obj.size();
		resize(m_used + len);
		memcpy(&m_data[oldUsed], obj.m_data, len * sizeof(value_type));
	}
	return *this;
}
tsCryptoData &tsCryptoData::operator+= (const_pointer data) /* zero terminated */
{
	return (*this) += tsCryptoData(data);
}
tsCryptoData &tsCryptoData::operator+= (value_type data)
{
	tsCryptoData::size_type len = 0;
	tsCryptoData::size_type oldUsed = m_used;
	//	if ( data != nullptr )
	{
		len = 1;

		resize(m_used + len);
		m_data[oldUsed] = data;
	}
	return *this;
}
tsCryptoData &tsCryptoData::operator += (std::initializer_list<value_type> init)
{
	return append(init);
}

int tsCryptoData::compare(const tsCryptoData& str) const
{
	size_type count = MIN(size(), str.size());
	int diff = 0;

	diff = memcmp(m_data, str.m_data, count);
	if (diff != 0)
		return diff;
	if (size() > str.size())
		return 1;
	if (size() < str.size())
		return -1;
	return 0;
}
int tsCryptoData::compare(size_type pos1, size_type count1, const tsCryptoData& str) const
{
	return substr(pos1, count1).compare(str);
}
int tsCryptoData::compare(size_type pos1, size_type count1, const tsCryptoData& str, size_type pos2, size_type count2) const
{
	return substr(pos1, count1).compare(str.substr(pos2, count2));
}
int tsCryptoData::compare(const_pointer s) const
{
	size_type len = TsStrLen((const char *)s);
	size_type count = MIN(size(), len);
	int diff = 0;

	diff = memcmp(m_data, s, count);
	if (diff != 0)
		return diff;
	if (size() > len)
		return 1;
	if (size() < len)
		return -1;
	return 0;
}
int tsCryptoData::compare(size_type pos1, size_type count1, const_pointer s) const
{
	return substr(pos1, count1).compare(s);
}
int tsCryptoData::compare(size_type pos1, size_type count1, const_pointer s, size_type count2) const
{
	return substr(pos1, count1).compare(tsCryptoData(s, count2));
}
tsCryptoData& tsCryptoData::replace(size_type pos, size_type count, const tsCryptoData& str)
{
	erase(pos, count);
	insert(pos, str);
	return *this;
}
tsCryptoData& tsCryptoData::replace(const_iterator first, const_iterator last, const tsCryptoData& str)
{
	size_type pos = first - cbegin();
	erase(first, last);
	insert(pos, str);
	return *this;
}
tsCryptoData& tsCryptoData::replace(size_type pos, size_type count, const tsCryptoData& str, size_type pos2, size_type count2)
{
	erase(pos, count);
	insert(pos, str, pos2, count2);
	return *this;
}
tsCryptoData& tsCryptoData::replace(size_type pos, size_type count, const_pointer s, size_type count2)
{
	erase(pos, count);
	insert(pos, s, count2);
	return *this;
}
tsCryptoData& tsCryptoData::replace(const_iterator first, const_iterator last, const_pointer s, size_type count2)
{
	size_type pos = first - cbegin();
	erase(first, last);
	insert(pos, s, count2);
	return *this;
}
tsCryptoData& tsCryptoData::replace(size_type pos, size_type count, const_pointer s)
{
	erase(pos, count);
	insert(pos, s);
	return *this;
}
tsCryptoData& tsCryptoData::replace(const_iterator first, const_iterator last, const_pointer s)
{
	size_type pos = first - cbegin();
	erase(first, last);
	insert(pos, s);
	return *this;
}
tsCryptoData& tsCryptoData::replace(size_type pos, size_type count, size_type count2, value_type ch)
{
	erase(pos, count);
	insert(pos, count2, ch);
	return *this;
}
tsCryptoData& tsCryptoData::replace(const_iterator first, const_iterator last, size_type count2, value_type ch)
{
	size_type pos = first - cbegin();
	erase(first, last);
	insert(pos, count2, ch);
	return *this;
}
tsCryptoData& tsCryptoData::replace(const_iterator first, const_iterator last, std::initializer_list<value_type> iList)
{
	size_type pos = first - cbegin();
	erase(first, last);
	insert(pos, iList);
	return *this;
}
tsCryptoData tsCryptoData::substr(size_type start, size_type length) const
{
	if (start >= size() || length == 0)
		return tsCryptoData();
	if (start + length >= size())
	{
		length = size() - start;
	}
	return tsCryptoData(&c_str()[start], length);
}
tsCryptoData::size_type tsCryptoData::copy(pointer dest, size_type count, size_type pos) const
{
	if (pos >= size())
		throw tscrypto::OutOfRange();
	if (count + pos > size())
		count = size() - pos;
	memcpy(dest, &m_data[pos], sizeof(value_type) * count);
	return count;
}
_Post_satisfies_(this->m_data != nullptr) void tsCryptoData::resize(size_type newSize)
{
	resize(newSize, 0);
}
_Post_satisfies_(this->m_data != nullptr) void tsCryptoData::resize(size_type newSize, value_type value)
{
	reserve(newSize);
	if (capacity() < newSize)
		throw tscrypto::bad_alloc();

	if (newSize > m_used)
	{
		memset(&m_data[m_used], value, newSize - m_used);
		m_used = newSize;
	}
	else if (newSize < m_used)
	{
		memset(&m_data[newSize], 0, m_used - newSize);
		m_used = newSize;
	}
}
void tsCryptoData::swap(tsCryptoData &obj)
{
	std::swap(m_data, obj.m_data);
	std::swap(m_used, obj.m_used);
	std::swap(m_allocated, obj.m_allocated);
}

tsCryptoData::size_type tsCryptoData::find(const tsCryptoData& str, size_type pos) const
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
		if (memcmp(in_data_c_str, &m_data[i], len) == 0)
		{
			return i;
		}
	}
	return npos;
}
tsCryptoData::size_type tsCryptoData::find(const_pointer s, size_type pos, size_type count) const
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
		if (memcmp(s, &m_data[i], count) == 0)
		{
			return i;
		}
	}
	return npos;
}
tsCryptoData::size_type tsCryptoData::find(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		throw tscrypto::ArgumentNullException("s");

	size_type i;
	size_type len;

	len = TsStrLen((const char*)s);
	if (len == 0)
		return npos;
	if (pos + len > m_used)
		return npos;
	for (i = pos; i < m_used - len + 1; i++)
	{
		if (memcmp(s, &m_data[i], len) == 0)
		{
			return i;
		}
	}
	return npos;
}
tsCryptoData::size_type tsCryptoData::find(value_type ch, size_type pos) const
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

tsCryptoData::size_type tsCryptoData::rfind(const tsCryptoData& str, size_type pos) const
{
	size_type count = str.size();

	if (count == 0)
		return npos;

	if (pos + count > size())
		pos = size() - count;

	difference_type i;

	for (i = pos; i >= 0; i--)
	{
		if (memcmp(str.c_str(), &m_data[i], count) == 0)
		{
			return i;
		}
	}
	return npos;
}
tsCryptoData::size_type tsCryptoData::rfind(const_pointer s, size_type pos, size_type count) const
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
		if (memcmp(s, &m_data[i], count) == 0)
		{
			return i;
		}
	}
	return npos;
}
tsCryptoData::size_type tsCryptoData::rfind(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		throw tscrypto::ArgumentNullException("s");

	size_type count = TsStrLen((const char*)s);
	if (count == 0)
		return npos;

	return rfind(s, pos, count);
}
tsCryptoData::size_type tsCryptoData::rfind(value_type ch, size_type pos) const
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

tsCryptoData::size_type tsCryptoData::find_first_of(const tsCryptoData& str, size_type pos) const
{
	return find_first_of(str.c_str(), pos, str.size());
}
tsCryptoData::size_type tsCryptoData::find_first_of(const_pointer s, size_type pos, size_type count) const
{
	if (s == nullptr || count == 0)
		return npos;
	size_type i;

	if (pos >= size())
		return npos;

	for (i = pos; i < m_used; i++)
	{
		if (memchr(s, m_data[i], count) != nullptr)
		{
			return i;
		}
	}
	return npos;
}
tsCryptoData::size_type tsCryptoData::find_first_of(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		return npos;
	return find_first_of(s, pos, TsStrLen((const char*)s));
}
tsCryptoData::size_type tsCryptoData::find_first_of(value_type ch, size_type pos) const
{
	return find(ch, pos);
}

tsCryptoData::size_type tsCryptoData::find_first_not_of(const tsCryptoData& str, size_type pos) const
{
	return find_first_not_of(str.c_str(), pos, str.size());
}
tsCryptoData::size_type tsCryptoData::find_first_not_of(const_pointer s, size_type pos, size_type count) const
{
	if (s == nullptr || count == 0)
		return npos;
	size_type i;

	if (pos >= size())
		return npos;

	for (i = pos; i < m_used; i++)
	{
		if (memchr(s, m_data[i], count) == nullptr)
		{
			return i;
		}
	}
	return npos;
}
tsCryptoData::size_type tsCryptoData::find_first_not_of(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		return npos;
	return find_first_not_of(s, pos, TsStrLen((const char*)s));
}
tsCryptoData::size_type tsCryptoData::find_first_not_of(value_type ch, size_type pos) const
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

tsCryptoData::size_type tsCryptoData::find_last_of(const tsCryptoData& str, size_type pos) const
{
	return find_last_of(str.c_str(), pos, str.size());
}
tsCryptoData::size_type tsCryptoData::find_last_of(const_pointer s, size_type pos, size_type count) const
{
	if (s == nullptr || count == 0)
		return npos;
	difference_type i;

	if (pos >= size())
		pos = size() - 1;

	for (i = pos; i >= 0; --i)
	{
		if (memchr(s, m_data[i], count) != nullptr)
		{
			return i;
		}
	}
	return npos;
}
tsCryptoData::size_type tsCryptoData::find_last_of(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		return npos;
	return find_last_of(s, pos, TsStrLen((const char*)s));
}
tsCryptoData::size_type tsCryptoData::find_last_of(value_type ch, size_type pos) const
{
	return rfind(ch, pos);
}

tsCryptoData::size_type tsCryptoData::find_last_not_of(const tsCryptoData& str, size_type pos) const
{
	return find_last_not_of(str.c_str(), pos, str.size());
}
tsCryptoData::size_type tsCryptoData::find_last_not_of(const_pointer s, size_type pos, size_type count) const
{
	if (s == nullptr || count == 0)
		return npos;
	difference_type i;

	if (pos >= size())
		pos = size() - 1;

	for (i = pos; i >= 0; --i)
	{
		if (memchr(s, m_data[i], count) == nullptr)
		{
			return i;
		}
	}
	return npos;
}
tsCryptoData::size_type tsCryptoData::find_last_not_of(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		return npos;
	return find_last_not_of(s, pos, TsStrLen((const char*)s));
}
tsCryptoData::size_type tsCryptoData::find_last_not_of(value_type ch, size_type pos) const
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
void  tsCryptoData::FromHexString(const tsCryptoStringBase& inVal)
{
	tsCryptoString inValue(inVal);

	tsCryptoStringList list = inValue.split("\r\n");

	resize(384);
	clear();
	inValue.clear();
	for (difference_type i = list->size() - 1; i >= 0; i--)
	{
		list->at(i).Trim().Replace("\t", " ").Replace("0x", " ").Replace("0X", " ");
		if (list->at(i).size() == 0)
		{
			auto it = list->begin();
			std::advance(it, i);
			list->erase(it);
		}
	}
	for (size_type i = 0; i < list->size(); i++)
	{
		if (list->at(i).find_first_not_of("0123456789abcdefABCDEF ") != tsCryptoString::npos)
			return;

		tsCryptoStringList list2 = list->at(i).split(' ');
		for (size_type j = 0; j < list2->size(); j++)
		{
			list2->at(j).Trim();
			if (list2->at(j).size() & 1)
			{
				inValue += "0";
			}
			inValue += list2->at(j);
		}
	}

	size_type len = inValue.size();;
	size_type posiCount = 0;
	size_type posi;
	value_type val = 0;

	resize((len / 2));
	resize(0);

	posiCount = (len & 1);
	for (posi = 0; posi < len; posi++)
	{
		if (posi == 0 && inValue[posi] == '0' && inValue[posi + 1] == 'x')
		{
			posi++;
		}
		else if (inValue[posi] >= '0' && inValue[posi] <= '9')
		{
			posiCount++;
			val = (value_type)((val << 4) | (inValue[posi] - '0'));
		}
		else if (inValue[posi] >= 'a' && inValue[posi] <= 'f')
		{
			posiCount++;
			val = (value_type)((val << 4) | (inValue[posi] - 'a' + 10));
		}
		else if (inValue[posi] >= 'A' && inValue[posi] <= 'F')
		{
			posiCount++;
			val = (value_type)((val << 4) | (inValue[posi] - 'A' + 10));
		}
		else
		{
			if (posiCount > 0)
			{
				posiCount = 2;
			}
		}
		if (posiCount == 2)
		{
			(*this) += val;
			posiCount = 0;
			val = 0;
		}
	}
	if (posiCount > 0)
	{
		(*this) += val;
	}
}
tsCryptoData tsCryptoData::FromHexString(size_type maxSize, size_type offset) const
{
	tsCryptoData tmp;

	tsCryptoStringList list;

	if (offset > 0)
	{
		list = ToUtf8String().split("\r\n");
	}
	else
		list = ToUtf8String().split("\r\n");

	tsCryptoString inValue;

	for (difference_type i = list->size() - 1; i >= 0; i--)
	{
		(*list)[i].Trim().Replace("\t", " ").Replace("0x", " ").Replace("0X", " ");
		if ((*list)[i].size() == 0)
		{
			auto it = list->begin();
			std::advance(it, i);
			list->erase(it);
		}
	}
	for (size_type i = 0; i < list->size(); i++)
	{
		if (list->at(i).find_first_not_of("0123456789abcdefABCDEF ") != tsCryptoString::npos)
			return tmp;

		tsCryptoStringList list2 = list->at(i).split(' ');
		for (size_type j = 0; j < (size_type)list2->size(); j++)
		{
			(*list2)[j].Trim();
			if ((*list2)[j].size() & 1)
			{
				inValue += "0";
			}
			inValue += (*list2)[j];
		}
	}

	size_type len = inValue.size();;
	size_type posiCount = 0;
	size_type posi;
	value_type val = 0;

	if (len > maxSize)
		len = maxSize;

	tmp.resize((len / 2));
	tmp.resize(0);

	posiCount = (len & 1);
	for (posi = 0; posi < len; posi++)
	{
		if (posi == 0 && inValue[posi] == '0' && inValue[posi + 1] == 'x')
		{
			posi++;
		}
		else if (inValue[posi] >= '0' && inValue[posi] <= '9')
		{
			posiCount++;
			val = (value_type)((val << 4) | (inValue[posi] - '0'));
		}
		else if (inValue[posi] >= 'a' && inValue[posi] <= 'f')
		{
			posiCount++;
			val = (value_type)((val << 4) | (inValue[posi] - 'a' + 10));
		}
		else if (inValue[posi] >= 'A' && inValue[posi] <= 'F')
		{
			posiCount++;
			val = (value_type)((val << 4) | (inValue[posi] - 'A' + 10));
		}
		else
		{
			if (posiCount > 0)
			{
				posiCount = 2;
			}
		}
		if (posiCount == 2)
		{
			tmp += val;
			posiCount = 0;
			val = 0;
		}
	}
	if (posiCount > 0)
	{
		tmp += val;
	}
	return tmp;
}
static const char *dtableUrl = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");        /* encode / decode table */
static const char *dtableNormal = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");        /* encode / decode table */
static bool  base64Encode(const char *dtable,
	bool padWithEquals,
	const uint8_t * const pInput,     /* in */
	size_t             ulInSize,   /* in */
	char *             outbuf,
	size_t * const     pulOutSize) /* out */
{
	size_t i, j, loopcount;
	BOOL done = FALSE;
	size_t sz;

	if (pInput == nullptr)
	{
		return false;
	}

	if (ulInSize == 0)
	{
		return false;
	}

	if (pulOutSize == nullptr)
	{
		return false;
	}

	/* determine the size of the output buffer */
	sz = (size_t)(ulInSize * BASE64_ENCODE_RATIO);
	sz += sz % 4;
	sz += 2 * (sz / 76);
	sz += 1; /* NULL terminator */
	sz += 10; /* make sure that we never have heap damage in case this computation is wrong. */

	if (outbuf == nullptr)
	{
		*pulOutSize = sz;
		return true;
	}
	if (*pulOutSize < sz)
	{
		*pulOutSize = sz;
		return false;
	}
	/* allocate the output buffer */
	memset(outbuf, 0, sz);

	i = 0;
	j = 0;
	loopcount = 0;
	while (!done) {
		uint8_t igroup[3];
		char ogroup[4];
		int n;

		igroup[0] = igroup[1] = igroup[2] = 0;
		for (n = 0; n < 3; n++) {
			if (i < ulInSize) {
				igroup[n] = pInput[i];
				i++;
			}
			else {
				done = TRUE;
				break;
			}
		}
		if (n > 0) {
			ogroup[0] = dtable[igroup[0] >> 2];
			ogroup[1] = dtable[((igroup[0] & 3) << 4) | (igroup[1] >> 4)];
			ogroup[2] = dtable[((igroup[1] & 0xF) << 2) | (igroup[2] >> 6)];
			ogroup[3] = dtable[igroup[2] & 0x3F];

			/* Replace characters in output stream with "=" pad
			characters if fewer than three characters were
			read from the end of the input stream. */

			if (padWithEquals)
			{
				if (n < 3) {
					ogroup[3] = '=';
					if (n < 2) {
						ogroup[2] = '=';
					}
				}
			}
			else
			{
				if (n < 3) {
					ogroup[3] = '\0';
					if (n < 2) {
						ogroup[2] = '\0';
					}
				}
			}

			/* Every 19 iterations of this loop that writes to the output buffer,
			add the CR & LF characters to end the line.  This is necessary to
			keep the lines exactly 76 characters long (19 * 4 = 76). */
			//if( ((loopcount % 19) == 0) && (loopcount != 0) )
			//{
			//    outbuf[j] = '\r';
			//    j++;
			//    outbuf[j] = '\n';
			//    j++;
			//} /* end if */
			for (n = 0; n < 4; n++, j++) {
				outbuf[j] = ogroup[n];
			}
			loopcount++;
		}
	}

	*pulOutSize = j;
	outbuf[j] = '\0';

	return true;
}
void  tsCryptoData::FromBase64(const tsCryptoStringBase& pInput, bool base64Url, bool padWithEquals)
{
	int i = 0, n = 0;
	unsigned int j = 0, k = 0;
	value_type encodeTable[256];         /* encode / decode table */
	size_type sz;
	size_type ulInSize;
	value_type *outbuf;
	bool comment = false;

	clear();

	if (pInput == nullptr)
	{
		return;
	}
	ulInSize = TsStrLen(pInput);

	if (ulInSize == 0)
	{
		return;
	}

	sz = (size_type)(ulInSize / BASE64_DECODE_RATIO) + 1;
	sz += 5; /* make sure that we never have heap damage in case this computation is wrong. */

			 /* create the output buffer */
	resize(sz);

	outbuf = m_data;

	/*  Create the Base64 alphabet table */
	for (i = 0; i < 255; i++) {
		encodeTable[i] = 0x80;
	}
	for (i = 'A'; i <= 'Z'; i++) {
		encodeTable[i] = (value_type)(0 + (i - 'A'));
	}
	for (i = 'a'; i <= 'z'; i++) {
		encodeTable[i] = (value_type)(26 + (i - 'a'));
	}
	for (i = '0'; i <= '9'; i++) {
		encodeTable[i] = (value_type)(52 + (i - '0'));
	}
	if (base64Url)
	{
		encodeTable[(int)'-'] = 62;
		encodeTable[(int)'_'] = 63;
	}
	else
	{
		encodeTable[(int)'+'] = 62;
		encodeTable[(int)'/'] = 63;
	}
	encodeTable[(int)'='] = 0;

	j = 0;
	k = 0;
	for (;;) {
		value_type a[4], b[4], o[3];
		short padding;
		for (i = 0; i < 4; i++) {
			short c;
		SKIPCHAR:
			if (j < ulInSize) {
				c = pInput[j];
				j++;
			}
			else {
				resize(k);
				return;
			}

			if (c == 0) {
				/* End of stream */
				resize(k);
				return;
			}
			if (c == '-')
			{
				comment = true;
			}
			else if ((c == '\r' || c == '\n' || c == '\t' || c == ' '))
			{
				if (c == '\r' || c == '\n')
					comment = false;
				/*
				* Skip the whitespace characters
				*/
				goto SKIPCHAR;
			}
			else if (comment)
			{
				goto SKIPCHAR;
			}

			/*
			* check for invalid characters.  If found, abort.
			*/
			if (encodeTable[c] & 0x80) {
				resize(0);
				return;
			}
			a[i] = (value_type)c;
			b[i] = (value_type)encodeTable[c];
		}

		/* convert the 4 character group into the original 3 characters */
		o[0] = (value_type)((b[0] << 2) | (b[1] >> 4));
		o[1] = (value_type)((b[1] << 4) | (b[2] >> 2));
		o[2] = (value_type)((b[2] << 6) | b[3]);

		/* determine if there is any padding at the end of the string */
		if (padWithEquals)
		{
			padding = (short)((a[2] == '=' ? 1 : (a[3] == '=' ? 2 : 3)));
		}
		else
		{
			padding = (short)((a[2] == '\0' ? 1 : (a[3] == '\0' ? 2 : 3)));
		}
		for (n = 0; n < padding; n++, k++) {
			outbuf[k] = o[n];
		}

		/* if we are out of characters, there is nothing left to do */
		if (i < 1) {
			break;
		}
	}

	resize(0);
}
tsCryptoData  tsCryptoData::FromBase64(size_type maxSize, size_type offset, bool base64Url, bool padWithEquals) const
{
	int i = 0, n = 0;
	unsigned int j = 0, k = 0;
	value_type encodeTable[256];         /* encode / decode table */
	size_type sz;
	size_type ulInSize;
	value_type *outbuf;
	bool comment = false;
	tsCryptoData tmp;

	if (offset >= size())
		return tmp;

	const char *pInput = (const char*)&c_str()[offset];

	ulInSize = TsStrLen(pInput);

	if (ulInSize == 0)
	{
		return tmp;
	}

	sz = (size_type)(ulInSize / BASE64_DECODE_RATIO) + 1;
	sz += 5; /* make sure that we never have heap damage in case this computation is wrong. */

	if (sz > maxSize)
		sz = maxSize;

	/* create the output buffer */
	tmp.resize(sz);

	outbuf = tmp.rawData();

	/*  Create the Base64 alphabet table */
	for (i = 0; i < 255; i++) {
		encodeTable[i] = 0x80;
	}
	for (i = 'A'; i <= 'Z'; i++) {
		encodeTable[i] = (value_type)(0 + (i - 'A'));
	}
	for (i = 'a'; i <= 'z'; i++) {
		encodeTable[i] = (value_type)(26 + (i - 'a'));
	}
	for (i = '0'; i <= '9'; i++) {
		encodeTable[i] = (value_type)(52 + (i - '0'));
	}
	if (base64Url)
	{
		encodeTable[(int)'-'] = 62;
		encodeTable[(int)'_'] = 63;
	}
	else
	{
		encodeTable[(int)'+'] = 62;
		encodeTable[(int)'/'] = 63;
	}
	encodeTable[(int)'='] = 0;

	j = 0;
	k = 0;
	for (;;) {
		value_type a[4], b[4], o[3];
		short padding;
		for (i = 0; i < 4; i++) {
			short c;
		SKIPCHAR:
			if (j < ulInSize) {
				c = pInput[j];
				j++;
			}
			else {
				tmp.resize(k);
				return tmp;
			}

			if (c == 0) {
				/* End of stream */
				tmp.resize(k);
				return tmp;
			}
			if (c == '-')
			{
				comment = true;
			}
			else if ((c == '\r' || c == '\n' || c == '\t' || c == ' '))
			{
				if (c == '\r' || c == '\n')
					comment = false;
				/*
				* Skip the whitespace characters
				*/
				goto SKIPCHAR;
			}
			else if (comment)
			{
				goto SKIPCHAR;
			}

			/*
			* check for invalid characters.  If found, abort.
			*/
			if (encodeTable[c] & 0x80) {
				tmp.resize(0);
				return tmp;
			}
			a[i] = (value_type)c;
			b[i] = (value_type)encodeTable[c];
		}

		/* convert the 4 character group into the original 3 characters */
		o[0] = (value_type)((b[0] << 2) | (b[1] >> 4));
		o[1] = (value_type)((b[1] << 4) | (b[2] >> 2));
		o[2] = (value_type)((b[2] << 6) | b[3]);

		/* determine if there is any padding at the end of the string */
		if (padWithEquals)
		{
			padding = (short)((a[2] == '=' ? 1 : (a[3] == '=' ? 2 : 3)));
		}
		else
		{
			padding = (short)((a[2] == '\0' ? 1 : (a[3] == '\0' ? 2 : 3)));
		}
		for (n = 0; n < padding; n++, k++) {
			if (k >= sz)
				return tmp;
			outbuf[k] = o[n];
		}

		/* if we are out of characters, there is nothing left to do */
		if (i < 1) {
			break;
		}
	}

	tmp.resize(0);
	return tmp;
}
static void encodeOIDPart(tsCryptoData &dest, uint32_t value, bool firstPart)
{
	if (value > 127)
	{
		encodeOIDPart(dest, value >> 7, false);
	}
	value &= 127;
	if (!firstPart)
		value |= 128;
	dest += (uint8_t)value;
}
void tsCryptoData::FromOIDString(const tsCryptoStringBase& inValue)
{
	uint32_t partNumber = 0;
	uint32_t value = 0;
	char *token = nullptr;
	const char *p;
	tsCryptoString str(inValue);

	clear();

	p = TsStrTok(str.rawData(), ".", &token);
	while (p != nullptr)
	{
		if (partNumber == 1)
		{
			value = value * 40 + TsStrToLong(p);
		}
		else
		{
			value = TsStrToLong(p);
		}
		if (partNumber != 0)
		{
			encodeOIDPart(*this, value, true);
		}

		partNumber++;
		p = TsStrTok(nullptr, ".", &token);
	}
}
tsCryptoData tsCryptoData::substring(size_type start, size_type length) const
{
	if (start >= size() || length == 0)
		return tsCryptoData();
	if (start + length >= size())
	{
		length = size() - start;
	}
	return tsCryptoData(&c_str()[start], length);
}
tsCryptoData& tsCryptoData::insert(size_type index, size_type count, char ch)
{
	size_type oldsize = size();

	resize(size() + count);
	memmove(&m_data[index + count], &m_data[index], sizeof(value_type) * (oldsize - index));
	memset(&m_data[index], ch, count);
	return *this;
}
tsCryptoData& tsCryptoData::insert(size_type index, char ch)
{
	size_type oldsize = size();

	resize(size() + 1);
	memmove(&m_data[index + 1], &m_data[index], sizeof(value_type) * (oldsize - index));
	m_data[index] = ch;
	return *this;
}
tsCryptoData& tsCryptoData::insert(size_type index, const char* s)
{
	if (s == nullptr)
		throw tscrypto::ArgumentNullException("s");

	size_type oldsize = size();
	size_type count = TsStrLen(s);

	resize(size() + count);
	memmove(&m_data[index + count], &m_data[index], sizeof(value_type) * (oldsize - index));
	memcpy(&m_data[index], s, count);
	return *this;
}
tsCryptoData& tsCryptoData::insert(size_type index, const char* s, size_type count)
{
	if (s == nullptr)
		throw tscrypto::ArgumentNullException("s");

	size_type oldsize = size();

	resize(size() + count);
	memmove(&m_data[index + count], &m_data[index], sizeof(value_type) * (oldsize - index));
	memcpy(&m_data[index], s, count);
	return *this;
}
tsCryptoData& tsCryptoData::insert(size_type index, const tsCryptoStringBase& str)
{
	size_type oldsize = size();
	size_type count = str.size();

	if (count == 0)
		return *this;
	resize(size() + count);
	memmove(&m_data[index + count], &m_data[index], sizeof(value_type) * (oldsize - index));
	memcpy(&m_data[index], str.data(), count);
	return *this;
}
tsCryptoData& tsCryptoData::insert(size_type index, const tsCryptoStringBase& str, size_type index_str, size_type count)
{
	return insert(index, str.substr(index_str, count));
}
tsCryptoData& tsCryptoData::insert(const_iterator pos, char ch)
{
	size_type index = pos - begin();
	return insert(index, ch);
}
tsCryptoData& tsCryptoData::insert(const_iterator pos, size_type count, char ch)
{
	size_type index = pos - begin();
	return insert(index, count, ch);
}
tsCryptoData& tsCryptoData::insert(const_iterator pos, std::initializer_list<char> iList)
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
void tsCryptoData::push_back(char ch)
{
	resize(size() + 1, (value_type)ch);
}

tsCryptoData &tsCryptoData::assign(value_type data)
{
	clear();
	resize(1, data);
	return *this;
}
tsCryptoData &tsCryptoData::assign(char data)
{
	clear();
	resize(1, (value_type)data);
	return *this;
}
tsCryptoData &tsCryptoData::assign(int16_t val)
{
	size_type last = 0;

	resize(2);
	m_data[last++] = (value_type)(val >> 8);
	m_data[last] = (value_type)(val);
	return *this;
}
tsCryptoData &tsCryptoData::assign(int32_t val)
{
	size_type last = 0;

	resize(4);
	m_data[last++] = (value_type)(val >> 24);
	m_data[last++] = (value_type)(val >> 16);
	m_data[last++] = (value_type)(val >> 8);
	m_data[last] = (value_type)(val);
	return *this;
}
tsCryptoData &tsCryptoData::assign(int64_t val)
{
	size_type last = 0;

	resize(8);
	m_data[last++] = (value_type)(val >> 56);
	m_data[last++] = (value_type)(val >> 48);
	m_data[last++] = (value_type)(val >> 40);
	m_data[last++] = (value_type)(val >> 32);
	m_data[last++] = (value_type)(val >> 24);
	m_data[last++] = (value_type)(val >> 16);
	m_data[last++] = (value_type)(val >> 8);
	m_data[last] = (value_type)(val);
	return *this;
}
tsCryptoData &tsCryptoData::assign(uint16_t val)
{
	size_type last = 0;

	resize(2);
	m_data[last++] = (value_type)(val >> 8);
	m_data[last] = (value_type)(val);
	return *this;
}
tsCryptoData &tsCryptoData::assign(uint32_t val)
{
	size_type last = 0;

	resize(4);
	m_data[last++] = (value_type)(val >> 24);
	m_data[last++] = (value_type)(val >> 16);
	m_data[last++] = (value_type)(val >> 8);
	m_data[last] = (value_type)(val);
	return *this;
}
tsCryptoData &tsCryptoData::assign(uint64_t val)
{
	size_type last = 0;

	resize(8);
	m_data[last++] = (value_type)(val >> 56);
	m_data[last++] = (value_type)(val >> 48);
	m_data[last++] = (value_type)(val >> 40);
	m_data[last++] = (value_type)(val >> 32);
	m_data[last++] = (value_type)(val >> 24);
	m_data[last++] = (value_type)(val >> 16);
	m_data[last++] = (value_type)(val >> 8);
	m_data[last] = (value_type)(val);
	return *this;
}

tsCryptoData &tsCryptoData::append(size_type len, char ch)
{
	resize(size() + len, (value_type)ch);
	return *this;
}
tsCryptoData &tsCryptoData::append(const tsCryptoStringBase &obj)
{
	size_type objSize = obj.size();

	if (objSize > 0)
	{
		tsCryptoString::size_type oldUsed = m_used;
		resize(oldUsed + objSize);
		memcpy(&m_data[oldUsed], obj.c_str(), objSize * sizeof(value_type));
	}
	return *this;
}
tsCryptoData &tsCryptoData::append(const tsCryptoStringBase &obj, size_type pos, size_type count)
{
	return append(obj.substr(pos, count));
}
tsCryptoData &tsCryptoData::append(const char* data, size_type count)
{
	if (data == nullptr)
	{
		return *this;
	}
	return append(tsCryptoString(data, count));
}
tsCryptoData &tsCryptoData::append(const char* data)
{
	if (data == nullptr)
	{
		return *this;
	}
	return append(tsCryptoString(data));
}
tsCryptoData &tsCryptoData::append(std::initializer_list<char> list)
{
	size_type pos = size();

	resize(size() + list.size());
	for (auto it = list.begin(); it != list.end(); ++it)
	{
		m_data[pos++] = *it;
	}
	return *this;
}
tsCryptoData &tsCryptoData::append(value_type data)
{
	resize(size() + 1, data);
	return *this;
}
tsCryptoData &tsCryptoData::append(char data)
{
	resize(size() + 1, (value_type)data);
	return *this;
}
tsCryptoData &tsCryptoData::append(int16_t val)
{
	size_type last = size();

	resize(size() + 2);
	m_data[last++] = (value_type)(val >> 8);
	m_data[last] = (value_type)(val);
	return *this;
}
tsCryptoData &tsCryptoData::append(int32_t val)
{
	size_type last = size();

	resize(size() + 4);
	m_data[last++] = (value_type)(val >> 24);
	m_data[last++] = (value_type)(val >> 16);
	m_data[last++] = (value_type)(val >> 8);
	m_data[last] = (value_type)(val);
	return *this;
}
tsCryptoData &tsCryptoData::append(int64_t val)
{
	size_type last = size();

	resize(size() + 8);
	m_data[last++] = (value_type)(val >> 56);
	m_data[last++] = (value_type)(val >> 48);
	m_data[last++] = (value_type)(val >> 40);
	m_data[last++] = (value_type)(val >> 32);
	m_data[last++] = (value_type)(val >> 24);
	m_data[last++] = (value_type)(val >> 16);
	m_data[last++] = (value_type)(val >> 8);
	m_data[last] = (value_type)(val);
	return *this;
}
tsCryptoData &tsCryptoData::append(uint16_t val)
{
	size_type last = size();

	resize(size() + 2);
	m_data[last++] = (value_type)(val >> 8);
	m_data[last] = (value_type)(val);
	return *this;
}
tsCryptoData &tsCryptoData::append(uint32_t val)
{
	size_type last = size();

	resize(size() + 4);
	m_data[last++] = (value_type)(val >> 24);
	m_data[last++] = (value_type)(val >> 16);
	m_data[last++] = (value_type)(val >> 8);
	m_data[last] = (value_type)(val);
	return *this;
}
tsCryptoData &tsCryptoData::append(uint64_t val)
{
	size_type last = size();

	resize(size() + 8);
	m_data[last++] = (value_type)(val >> 56);
	m_data[last++] = (value_type)(val >> 48);
	m_data[last++] = (value_type)(val >> 40);
	m_data[last++] = (value_type)(val >> 32);
	m_data[last++] = (value_type)(val >> 24);
	m_data[last++] = (value_type)(val >> 16);
	m_data[last++] = (value_type)(val >> 8);
	m_data[last] = (value_type)(val);
	return *this;
}

tsCryptoData &tsCryptoData::operator+= (const tsCryptoStringBase &obj)
{
	tsCryptoData::size_type len = 0;
	tsCryptoData::size_type oldUsed = m_used;
	if (obj.size() > 0)
	{
		len = obj.size();
		resize(m_used + len);
		memcpy(&m_data[oldUsed], obj.data(), len * sizeof(value_type));
	}
	return *this;
}
tsCryptoData &tsCryptoData::operator+= (const char* data) /* zero terminated */
{
	return (*this) += tsCryptoData(data);
}
tsCryptoData &tsCryptoData::operator+= (char data)
{
	tsCryptoData::size_type len = 0;
	tsCryptoData::size_type oldUsed = m_used;
	//	if ( data != nullptr )
	{
		len = 1;

		resize(m_used + len);
		m_data[oldUsed] = data;
	}
	return *this;
}
tsCryptoData &tsCryptoData::operator += (std::initializer_list<char> init)
{
	return append(init);
}
tsCryptoData &tsCryptoData::operator += (int16_t val)
{
	return append(val);
}
tsCryptoData &tsCryptoData::operator += (int32_t val)
{
	return append(val);
}
tsCryptoData &tsCryptoData::operator += (int64_t val)
{
	return append(val);
}
tsCryptoData &tsCryptoData::operator += (uint16_t val)
{
	return append(val);
}
tsCryptoData &tsCryptoData::operator += (uint32_t val)
{
	return append(val);
}
tsCryptoData &tsCryptoData::operator += (uint64_t val)
{
	return append(val);
}

int tsCryptoData::compare(const tsCryptoStringBase& str) const
{
	size_type count = MIN(size(), str.size());
	int diff = 0;

	diff = memcmp(m_data, str.data(), count);
	if (diff != 0)
		return diff;
	if (size() > str.size())
		return 1;
	if (size() < str.size())
		return -1;
	return 0;
}
int tsCryptoData::compare(size_type pos1, size_type count1, const tsCryptoStringBase& str) const
{
	return substr(pos1, count1).compare(str);
}
int tsCryptoData::compare(size_type pos1, size_type count1, const tsCryptoStringBase& str, size_type pos2, size_type count2) const
{
	return substr(pos1, count1).compare(str.substr(pos2, count2));
}
int tsCryptoData::compare(const char* s) const
{
	size_type len = TsStrLen(s);
	size_type count = MIN(size(), len);
	int diff = 0;

	diff = memcmp(m_data, s, count);
	if (diff != 0)
		return diff;
	if (size() > len)
		return 1;
	if (size() < len)
		return -1;
	return 0;
}
int tsCryptoData::compare(size_type pos1, size_type count1, const char* s) const
{
	return substr(pos1, count1).compare(s);
}
int tsCryptoData::compare(size_type pos1, size_type count1, const char* s, size_type count2) const
{
	return substr(pos1, count1).compare(tsCryptoString(s, count2));
}

tsCryptoData& tsCryptoData::replace(size_type pos, size_type count, const tsCryptoStringBase& str)
{
	erase(pos, count);
	insert(pos, str);
	return *this;
}
tsCryptoData& tsCryptoData::replace(const_iterator first, const_iterator last, const tsCryptoStringBase& str)
{
	size_type pos = first - cbegin();
	erase(first, last);
	insert(pos, str);
	return *this;
}
tsCryptoData& tsCryptoData::replace(size_type pos, size_type count, const tsCryptoStringBase& str, size_type pos2, size_type count2)
{
	erase(pos, count);
	insert(pos, str, pos2, count2);
	return *this;
}
tsCryptoData& tsCryptoData::replace(size_type pos, size_type count, const char* s, size_type count2)
{
	erase(pos, count);
	insert(pos, s, count2);
	return *this;
}
tsCryptoData& tsCryptoData::replace(const_iterator first, const_iterator last, const char* s, size_type count2)
{
	size_type pos = first - cbegin();
	erase(first, last);
	insert(pos, s, count2);
	return *this;
}
tsCryptoData& tsCryptoData::replace(size_type pos, size_type count, const char* s)
{
	erase(pos, count);
	insert(pos, s);
	return *this;
}
tsCryptoData& tsCryptoData::replace(const_iterator first, const_iterator last, const char* s)
{
	size_type pos = first - cbegin();
	erase(first, last);
	insert(pos, s);
	return *this;
}
tsCryptoData& tsCryptoData::replace(size_type pos, size_type count, size_type count2, char ch)
{
	erase(pos, count);
	insert(pos, count2, ch);
	return *this;
}
tsCryptoData& tsCryptoData::replace(const_iterator first, const_iterator last, size_type count2, char ch)
{
	size_type pos = first - cbegin();
	erase(first, last);
	insert(pos, count2, ch);
	return *this;
}
tsCryptoData& tsCryptoData::replace(const_iterator first, const_iterator last, std::initializer_list<char> iList)
{
	size_type pos = first - cbegin();
	erase(first, last);

	auto it = begin();
	std::advance(it, pos);
	insert(it, iList);
	return *this;
}
void tsCryptoData::reverse()
{
	value_type value;

	for (unsigned int i = 0; i < (m_used >> 1); i++)
	{
		value = m_data[i];
		m_data[i] = m_data[m_used - i - 1];
		m_data[m_used - i - 1] = value;
	}
}
tsCryptoData &tsCryptoData::XOR(const tsCryptoData &value)
{
	size_type len = value.size();

	if (size() < len)
		resize(len);

	for (unsigned int i = 0; i < len; i++)
	{
		m_data[i] ^= value[i];
	}
	return *this;
}
tsCryptoData &tsCryptoData::AND(const tsCryptoData &value)
{
	size_type len = value.size();

	if (size() < len)
		resize(len);

	for (unsigned int i = 0; i < len; i++)
	{
		m_data[i] &= value[i];
	}
	return *this;
}
tsCryptoData &tsCryptoData::OR(const tsCryptoData &value)
{
	size_type len = value.size();

	if (size() < len)
		resize(len);

	for (unsigned int i = 0; i < len; i++)
	{
		m_data[i] |= value[i];
	}
	return *this;
}
tsCryptoData &tsCryptoData::NOT()
{
	for (unsigned int i = 0; i < m_used; i++)
	{
		m_data[i] = ~m_data[i];
	}
	return *this;
}
tsCryptoData tsCryptoData::right(size_type length) const
{
	tsCryptoData tmp = *this;

	if (tmp.size() > length)
		tmp.erase(0, tmp.size() - length);
	return tmp;
}
tsCryptoData tsCryptoData::left(size_type length) const
{
	tsCryptoData tmp = *this;

	if (tmp.size() > length)
		tmp.resize(length);
	return tmp;
}
tsCryptoData &tsCryptoData::padLeft(size_type length, value_type value)
{
	size_type oldLen = size();

	if (oldLen < length)
	{
		resize(length);
		memmove(&m_data[length - oldLen], &m_data[0], oldLen);
		memset(m_data, value, length - oldLen);
	}
	return *this;
}
tsCryptoData &tsCryptoData::padRight(size_type length, value_type value)
{
	if (size() < length)
	{
		resize(length, value);
	}
	return *this;
}
tsCryptoData &tsCryptoData::truncOrPadLeft(size_type length, value_type value)
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
tsCryptoString tsCryptoData::ToOIDString() const
{
	tsCryptoString tmp;
	uint32_t value;
	uint32_t posi = 1;

	if (size() == 0)
		return "";

	value = m_data[0];
	tmp.append((value / 40)).append(".").append((value % 40));
	value = 0;
	while (posi < size())
	{
		value = (value << 7) | (m_data[posi] & 0x7f);
		if ((m_data[posi] & 0x80) == 0)
		{
			tmp.append(".").append(value);
			value = 0;
		}
		posi++;
	}
	if (value != 0)
		return ""; // Bad OID encoding
	return tmp;
}
tscrypto::tsCryptoData::UnicodeEncodingType tsCryptoData::EncodingType() const
{
	UnicodeEncodingType encoding = encode_Ascii;
	//bool hasBOM = true;

	if (size() > 3)
	{
		const uint8_t *p = (const uint8_t *)m_data;

		if (p[0] == 0xEF && p[1] == 0xBB && p[2] == 0xBF)
		{
			encoding = encode_Utf8;
		}
		else if (p[0] == 0x00 && p[1] == 0x00 && p[2] == 0xFE && p[3] == 0xFF)
		{
			encoding = encode_Utf32BE;
		}
		else if (p[0] == 0xFF && p[1] == 0xFE && p[2] == 0x00 && p[3] == 0x00)
		{
			encoding = encode_Utf32LE;
		}
		else if (p[0] == 0xFE && p[1] == 0xFF)
		{
			encoding = encode_Utf16BE;
		}
		else if (p[0] == 0xFF && p[1] == 0xFE)
		{
			encoding = encode_Utf16LE;
		}
		else if (p[0] == 0x2B && p[1] == 0x2F && p[2] == 0x76)
		{
			encoding = encode_Utf7;
		}
		else if (p[0] == 0xF7 && p[1] == 0x64 && p[2] == 0x4C)
		{
			encoding = encode_Utf1;
		}
		else
		{
			//hasBOM = false;
		}
	}
	else
	{
		//hasBOM = false;
	}
	return encoding;
}

tscrypto::tsCryptoData::UnicodeEncodingType tsCryptoData::EncodingType(uint8_t *data, size_t size) const
{
	UnicodeEncodingType encoding = encode_Ascii;
	//bool hasBOM = true;

	if (size > 3)
	{
		const uint8_t *p = (const uint8_t *)data;

		if (p[0] == 0xEF && p[1] == 0xBB && p[2] == 0xBF)
		{
			encoding = encode_Utf8;
		}
		else if (p[0] == 0x00 && p[1] == 0x00 && p[2] == 0xFE && p[3] == 0xFF)
		{
			encoding = encode_Utf32BE;
		}
		else if (p[0] == 0xFF && p[1] == 0xFE && p[2] == 0x00 && p[3] == 0x00)
		{
			encoding = encode_Utf32LE;
		}
		else if (p[0] == 0xFE && p[1] == 0xFF)
		{
			encoding = encode_Utf16BE;
		}
		else if (p[0] == 0xFF && p[1] == 0xFE)
		{
			encoding = encode_Utf16LE;
		}
		else if (p[0] == 0x2B && p[1] == 0x2F && p[2] == 0x76)
		{
			encoding = encode_Utf7;
		}
		else if (p[0] == 0xF7 && p[1] == 0x64 && p[2] == 0x4C)
		{
			encoding = encode_Utf1;
		}
		else
		{
			//hasBOM = false;
		}
	}
	else
	{
		//hasBOM = false;
	}
	return encoding;
}

tsCryptoData tsCryptoData::computeBOM(UnicodeEncodingType type)
{
	switch (type)
	{
	case encode_Utf8:
		return tsCryptoData({ (uint8_t)0xEF, (uint8_t)0xBB, (uint8_t)0xBF });
	case encode_Utf16BE:
		return tsCryptoData({ (uint8_t)0xFE, (uint8_t)0xFF });
	case encode_Utf16LE:
		return tsCryptoData({ (uint8_t)0xFF, (uint8_t)0xFE });
	case encode_Utf32BE:
		return tsCryptoData({ (uint8_t)0, (uint8_t)0, (uint8_t)0xFE, (uint8_t)0xff });
	case encode_Utf32LE:
		return tsCryptoData({ (uint8_t)0xff, (uint8_t)0xFE, (uint8_t)0, (uint8_t)0 });
	case encode_Utf7:
		return tsCryptoData({ (uint8_t)0x2B, (uint8_t)0x2F, (uint8_t)0x76 });
	case encode_Utf1:
		return tsCryptoData({ (uint8_t)0xF7, (uint8_t)0x64, (uint8_t)0x4C });
	default:
	case encode_Ascii:
		return tsCryptoData();
	}
}
tsCryptoData& tsCryptoData::prependBOM(UnicodeEncodingType type)
{
	tsCryptoData tmp(computeBOM(type));

	if (tmp.size() > 0)
		insert(0, tmp);
	return *this;
}
bool tsCryptoData::hasEncodingBOM() const
{
	//	UnicodeEncodingType encoding = encode_Ascii;
	bool hasBOM = true;

	if (size() > 3)
	{
		const uint8_t *p = (const uint8_t *)m_data;

		if (p[0] == 0xEF && p[1] == 0xBB && p[2] == 0xBF)
		{
			//encoding = encode_Utf8;
		}
		else if (p[0] == 0x00 && p[1] == 0x00 && p[2] == 0xFE && p[3] == 0xFF)
		{
			//encoding = encode_Utf32BE;
		}
		else if (p[0] == 0xFF && p[1] == 0xFE && p[2] == 0x00 && p[3] == 0x00)
		{
			//encoding = encode_Utf32LE;
		}
		else if (p[0] == 0xFE && p[1] == 0xFF)
		{
			//encoding = encode_Utf16BE;
		}
		else if (p[0] == 0xFF && p[1] == 0xFE)
		{
			//encoding = encode_Utf16LE;
		}
		else if (p[0] == 0x2B && p[1] == 0x2F && p[2] == 0x76)
		{
			//encoding = encode_Utf7;
		}
		else if (p[0] == 0xF7 && p[1] == 0x64 && p[2] == 0x4C)
		{
			//encoding = encode_Utf1;
		}
		else
		{
			hasBOM = false;
		}
	}
	else
	{
		hasBOM = false;
	}
	return hasBOM;
}

bool tsCryptoData::hasEncodingBOM(uint8_t *data, size_t size) const
{
	//	UnicodeEncodingType encoding = encode_Ascii;
	bool hasBOM = true;

	if (size > 3)
	{
		const uint8_t *p = (const uint8_t *)data;

		if (p[0] == 0xEF && p[1] == 0xBB && p[2] == 0xBF)
		{
			//			encoding = encode_Utf8;
		}
		else if (p[0] == 0x00 && p[1] == 0x00 && p[2] == 0xFE && p[3] == 0xFF)
		{
			//			encoding = encode_Utf32BE;
		}
		else if (p[0] == 0xFF && p[1] == 0xFE && p[2] == 0x00 && p[3] == 0x00)
		{
			//			encoding = encode_Utf32LE;
		}
		else if (p[0] == 0xFE && p[1] == 0xFF)
		{
			//			encoding = encode_Utf16BE;
		}
		else if (p[0] == 0xFF && p[1] == 0xFE)
		{
			//			encoding = encode_Utf16LE;
		}
		else if (p[0] == 0x2B && p[1] == 0x2F && p[2] == 0x76)
		{
			//			encoding = encode_Utf7;
		}
		else if (p[0] == 0xF7 && p[1] == 0x64 && p[2] == 0x4C)
		{
			//			encoding = encode_Utf1;
		}
		else
		{
			hasBOM = false;
		}
	}
	else
	{
		hasBOM = false;
	}
	return hasBOM;
}

size_t tsCryptoData::BOMByteCount() const
{
	return BOMByteCount(m_data, size());
}

size_t tsCryptoData::BOMByteCount(uint8_t *data, size_t size) const
{
	int count = 0;

	if (size > 3)
	{
		const uint8_t *p = (const uint8_t *)data;

		if (p[0] == 0xEF && p[1] == 0xBB && p[2] == 0xBF)
		{
			count = 3;
		}
		else if (p[0] == 0x00 && p[1] == 0x00 && p[2] == 0xFE && p[3] == 0xFF)
		{
			count = 4;
		}
		else if (p[0] == 0xFF && p[1] == 0xFE && p[2] == 0x00 && p[3] == 0x00)
		{
			count = 4;
		}
		else if (p[0] == 0xFE && p[1] == 0xFF)
		{
			count = 2;
		}
		else if (p[0] == 0xFF && p[1] == 0xFE)
		{
			count = 2;
		}
		else if (p[0] == 0x2B && p[1] == 0x2F && p[2] == 0x76)
		{
			count = 3;
		}
		else if (p[0] == 0xF7 && p[1] == 0x64 && p[2] == 0x4C)
		{
			count = 3;
		}
	}
	return count;
}

tsCryptoString tsCryptoData::ToUtf8String() const
{
	tsCryptoString tmp;
	size_t destCount;
	UTF8 *dest;
	const UTF16 *src16;
	const UTF32 *src32;
	size_t BOMcount = BOMByteCount();

	if (BOMcount > 0)
	{
		switch (EncodingType())
		{
		case encode_Utf16BE:
			src16 = (UTF16*)(m_data + BOMcount);
			destCount = UTF16toUTF8Length(src16, (UTF16*)(m_data + size()), true, lenientConversion);
			tmp.resize(destCount);
			dest = (UTF8*)tmp.rawData();
			src16 = (UTF16*)(m_data + BOMcount);
			ConvertUTF16toUTF8(&src16, (UTF16*)(m_data + size()), &dest, dest + tmp.size(), true, lenientConversion);
			break;
		case encode_Utf16LE:
			src16 = (UTF16*)(m_data + BOMcount);
			destCount = UTF16toUTF8Length(src16, (UTF16*)(m_data + size()), false, lenientConversion);
			tmp.resize(destCount);
			dest = (UTF8*)tmp.rawData();
			src16 = (UTF16*)(m_data + BOMcount);
			ConvertUTF16toUTF8(&src16, (UTF16*)(m_data + size()), &dest, dest + tmp.size(), false, lenientConversion);
			break;
		case encode_Utf32BE:
			src32 = (UTF32*)(m_data + BOMcount);
			destCount = UTF32toUTF8Length(src32, (UTF32*)(m_data + size()), true, lenientConversion);
			tmp.resize(destCount);
			dest = (UTF8*)tmp.rawData();
			src32 = (UTF32*)(m_data + BOMcount);
			ConvertUTF32toUTF8(&src32, (UTF32*)(m_data + size()), &dest, dest + tmp.size(), true, lenientConversion);
			break;
		case encode_Utf32LE:
			src32 = (UTF32*)(m_data + BOMcount);
			destCount = UTF32toUTF8Length(src32, (UTF32*)(m_data + size()), false, lenientConversion);
			tmp.resize(destCount);
			dest = (UTF8*)tmp.rawData();
			src32 = (UTF32*)(m_data + BOMcount);
			ConvertUTF32toUTF8(&src32, (UTF32*)(m_data + size()), &dest, dest + tmp.size(), false, lenientConversion);
			break;

		default:
		case encode_Ascii:
		case encode_Utf8:
		case encode_Utf7:
		case encode_Utf1:
			tmp.resize(size() - BOMcount);
			memcpy(tmp.rawData(), c_str() + BOMcount, tmp.size());
			break;
		}
	}
	else
	{
		tmp.resize(size());
		memcpy(tmp.rawData(), c_str(), size());
	}
	return tmp;
}

//tsCryptoString tsCryptoData::ToUtf8String() const
//{
//	tsCryptoString tmp;
//
//	tmp.resize(size());
//	memcpy(tmp.rawData(), c_str(), size());
//	return tmp;
//}
void tsCryptoData::AsciiFromString(const tsCryptoStringBase& str)
{
	resize(str.size());
	memcpy(rawData(), str.c_str(), size());
}
void tsCryptoData::UTF8FromString(const tsCryptoStringBase& str)
{
	size_type len = 0;

	len = str.size();
	resize(len);
	memcpy(rawData(), str.data(), len);
}
uint64_t tsCryptoData::ToUint64() const
{
	tsCryptoData tmp(*this);

	while (tmp.size() < sizeof(uint64_t))
	{
		tmp.insert(0, (value_type)0);
	}
	tmp.resize(sizeof(uint64_t));

#if (BYTE_ORDER == LITTLE_ENDIAN)
	tmp.reverse();
#endif
	return *(uint64_t*)tmp.c_str();
}
tsCryptoString tsCryptoData::ToHexString() const
{
	size_type count = size();
	size_type i;
	tsCryptoString outValue;

	outValue.resize(count * 2);
	outValue.resize(0);

	for (i = 0; i < count; i++)
	{
		value_type val = (*this)[i];

		outValue += ("0123456789ABCDEF")[val >> 4];
		outValue += ("0123456789ABCDEF")[val & 0x0f];
	}
	return outValue;
}
tsCryptoString tsCryptoData::ToHexStringWithSpaces() const
{
	size_type count = size();
	size_type i;
	tsCryptoString outValue;

	outValue.resize(count * 3);
	outValue.resize(0);

	for (i = 0; i < count; i++)
	{
		value_type val = (*this)[i];

		outValue += ("0123456789ABCDEF")[val >> 4];
		outValue += ("0123456789ABCDEF")[val & 0x0f];
		outValue += " ";
	}
	if (outValue.size() > 0)
		outValue.resize(outValue.size() - 1);
	return outValue;
}
tsCryptoString tsCryptoData::ToHexDump() const
{
	size_type posi = 0, len;
	tsCryptoData tmp;
	tsCryptoString output, tmpS;

	while (posi < m_used)
	{
		len = m_used - posi;
		if (len > 16)
			len = 16;

		tmpS.Format("%08X", posi);

		tmp = substring(posi, len);
		posi += len;
		output.append(tmpS).append(": ").append(tmp.ToHexStringWithSpaces().PadRight(50, ' '));
		for (size_type i = 0; i < tmp.size(); i++)
		{
			value_type b = tmp[i];
			if (b > 0x1f && b < 0x80)
				output += (char)b;
			else
				output += '.';
		}
		output.append('\n');
	}
	return output;
}
tsCryptoString tsCryptoData::ToBase64(bool base64Url, bool padWithEquals) const
{
	size_type len;
	tsCryptoString outValue;

	outValue.erase();
	if (!base64Encode(base64Url ? dtableUrl : dtableNormal, padWithEquals, m_data, m_used, nullptr, &len))
		outValue.erase();
	else
	{
		outValue.resize(len);
		if (!base64Encode(base64Url ? dtableUrl : dtableNormal, padWithEquals, m_data, m_used, outValue.rawData(), &len) ||
			len == 0)
		{
			outValue.erase();
		}
		outValue.resize(len);
	}
	return outValue;
}
tsCryptoData tsCryptoData::PartialDecode(DataStringType type, size_type numberOfBytes, size_type offset)
{
	switch (type)
	{
	case ASCII:
		return substring(offset, numberOfBytes);
	case OID:
		return substring(offset, numberOfBytes);
	case HEX:
		return FromHexString(numberOfBytes, offset);
	case BASE64:
		return FromBase64(numberOfBytes, offset);
	case BASE64URL:
		return FromBase64(numberOfBytes, offset, true);
	default:
		return tsCryptoData();
	}
}
tsCryptoString tsCryptoData::PartialEncode(DataStringType type, size_type numberOfBytes, size_type offset)
{
	switch (type)
	{
	case ASCII:
		return substring(offset, numberOfBytes).ToUtf8String();
	case OID:
		return substring(offset, numberOfBytes).ToOIDString();
	case HEX:
		return substring(offset, numberOfBytes).ToHexString();
	case BASE64:
		return substring(offset, numberOfBytes).ToBase64();
	case BASE64URL:
		return substring(offset, numberOfBytes).ToBase64(true);
	default:
		return "";
	}
}
tsCryptoData &tsCryptoData::increment(value_type step)
{
	difference_type offset = size() - 1;
	int tmp;

	while (offset >= 0)
	{
		tmp = m_data[offset] + step;
		m_data[offset] = (value_type)tmp;
		tmp >>= 8;
		if (tmp == 0)
			break;
		step = (value_type)tmp;
		offset--;
	}

	return *this;
}
tsCryptoData &tsCryptoData::decrement(value_type step)
{
	difference_type offset = size() - 1;
	int tmp;

	while (offset >= 0)
	{
		tmp = m_data[offset] - step;
		m_data[offset] = (value_type)tmp;
		tmp >>= 8;
		if (tmp == 0)
			break;
		step = (value_type)(-tmp);
		offset--;
	}

	return *this;
}
void  tsCryptoData::copyFrom(const tsCryptoData &obj)
{
	if (&obj == this)
		return;
	resize(obj.size());
	memcpy(m_data, obj.m_data, m_used);
}





std::ostream & tscrypto::operator << (std::ostream &Output, const tsCryptoData &obj)
{
	Output << tsCryptoString(obj.ToHexStringWithSpaces()).c_str();
	return Output;
}
std::wostream & tscrypto::operator << (std::wostream &Output, const tsCryptoData &obj)
{
	Output << obj.ToHexStringWithSpaces().c_str();
	return Output;
}


tsCryptoDataList tscrypto::CreateTsCryptoDataList()
{
	return CreateContainer<tsCryptoData>();
}

bool tscrypto::operator==(const tsCryptoData& lhs, const tsCryptoData& rhs)
{
	return lhs.compare(rhs) == 0;
}
bool tscrypto::operator!=(const tsCryptoData& lhs, const tsCryptoData& rhs)
{
	return lhs.compare(rhs) != 0;
}
bool tscrypto::operator<(const tsCryptoData& lhs, const tsCryptoData& rhs)
{
	return lhs.compare(rhs) < 0;
}
bool tscrypto::operator<=(const tsCryptoData& lhs, const tsCryptoData& rhs)
{
	return lhs.compare(rhs) <= 0;
}
bool tscrypto::operator>(const tsCryptoData& lhs, const tsCryptoData& rhs)
{
	return lhs.compare(rhs) > 0;
}
bool tscrypto::operator>=(const tsCryptoData& lhs, const tsCryptoData& rhs)
{
	return lhs.compare(rhs) >= 0;
}

void tscrypto::swap(tsCryptoData &lhs, tsCryptoData &rhs)
{
	lhs.swap(rhs);
}


tsCryptoData& tscrypto::operator<<(tsCryptoData& data, char val)
{
	return data.append(val);
}
tsCryptoData& tscrypto::operator<<(tsCryptoData& data, int8_t val)
{
	return data.append(val);
}
tsCryptoData& tscrypto::operator<<(tsCryptoData& data, int16_t val)
{
	return data.append(val);
}
tsCryptoData& tscrypto::operator<<(tsCryptoData& data, int32_t val)
{
	return data.append(val);
}
tsCryptoData& tscrypto::operator<<(tsCryptoData& data, int64_t val)
{
	return data.append(val);
}
tsCryptoData& tscrypto::operator<<(tsCryptoData& data, uint8_t val)
{
	return data.append(val);
}
tsCryptoData& tscrypto::operator<<(tsCryptoData& data, uint16_t val)
{
	return data.append(val);
}
tsCryptoData& tscrypto::operator<<(tsCryptoData& data, uint32_t val)
{
	return data.append(val);
}
tsCryptoData& tscrypto::operator<<(tsCryptoData& data, uint64_t val)
{
	return data.append(val);
}
tsCryptoData& tscrypto::operator<<(tsCryptoData& data, const char* val)
{
	return data.append(val);
}
tsCryptoData& tscrypto::operator<<(tsCryptoData& data, const tsCryptoStringBase& val)
{
	return data.append(val);
}
tsCryptoData& tscrypto::operator<<(tsCryptoData& data, const tsCryptoData& val)
{
	return data.append(val);
}

bool tscrypto::tsCryptoDataStream::WriteBinary(const tscrypto::tsCryptoData & dataToAppend)
{
	append(dataToAppend);
	return true;
}

bool tscrypto::tsCryptoDataStream::WriteString(const tscrypto::tsCryptoStringBase & dataToAppend)
{
	append(dataToAppend);
	return true;
}
