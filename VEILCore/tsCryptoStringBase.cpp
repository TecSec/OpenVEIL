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

const tscrypto::tsCryptoStringBase::size_type tscrypto::tsCryptoStringBase::npos = (size_type)(-1);

tsCryptoStringBase::tsCryptoStringBase() :
	m_data(nullptr),
	m_used(0),
	m_allocated(-1)
{
	reserve(0);
};
tsCryptoStringBase::tsCryptoStringBase(std::initializer_list<value_type> init) :
	m_data(nullptr),
	m_used(0),
	m_allocated(-1)
{
	tsCryptoStringBase::size_type index = 0;
	reserve(0);
	resize(init.size());

	for (auto i = init.begin(); i != init.end(); ++i)
	{
		m_data[index++] = *i;
	}
}
tsCryptoStringBase::tsCryptoStringBase(tsCryptoStringBase &&obj) :
	m_data(nullptr),
	m_used(0),
	m_allocated(-1)
{
	m_data = obj.m_data;
	m_used = obj.m_used;
	m_allocated = obj.m_allocated;

	obj.m_data = nullptr;
	obj.m_used = 0;
	obj.m_allocated = -1;
	obj.reserve(0);
}
tsCryptoStringBase::tsCryptoStringBase(const_pointer data, tsCryptoStringBase::size_type Len) :m_data(nullptr), m_used(0), m_allocated(-1)
{
	if (Len > 0 && data != nullptr)
	{
		resize(Len);
		memcpy(m_data, data, Len * sizeof(data[0]));
	}
	else
		reserve(0);
};
tsCryptoStringBase::tsCryptoStringBase(const tsCryptoStringBase &obj) :m_data(nullptr), m_used(0), m_allocated(-1)
{
	reserve(0);
	copyFrom(obj);
};
tsCryptoStringBase::tsCryptoStringBase(const_pointer data) :m_data(nullptr), m_used(0), m_allocated(-1)
{
	tsCryptoStringBase::size_type Len = 0;
	if (data != nullptr)
	{
		Len = strlen(data);
	}
	if (Len > 0 && data != nullptr)
	{
		resize(Len);
		memcpy(m_data, data, Len * sizeof(value_type));
	}
	else
		reserve(0);
}
tsCryptoStringBase::tsCryptoStringBase(value_type data, tsCryptoStringBase::size_type numChars) :m_data(nullptr), m_used(0), m_allocated(-1)
{
	reserve(0);
	resize(numChars, data);
}
tsCryptoStringBase::~tsCryptoStringBase()
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
};
//tsCryptoStringBase::operator LPCTSTR ()
//{
//	return c_str();
//}
tsCryptoStringBase &tsCryptoStringBase::operator= (tsCryptoStringBase &&obj)
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
tsCryptoStringBase &tsCryptoStringBase::operator= (const tsCryptoStringBase &obj)
{
	copyFrom(obj);
	return *this;
}

tsCryptoStringBase &tsCryptoStringBase::operator= (const_pointer data) /* zero terminated */
{
	return (*this) = (tsCryptoStringBase(data));
}
tsCryptoStringBase &tsCryptoStringBase::operator= (value_type data)
{
	resize(1);
	m_data[0] = data;
	return *this;
}
tsCryptoStringBase &tsCryptoStringBase::operator=(std::initializer_list<value_type> iList)
{
	assign(iList);
	return *this;
}
tsCryptoStringBase &tsCryptoStringBase::operator+= (const tsCryptoStringBase &obj)
{
	tsCryptoStringBase::size_type len = 0;
	tsCryptoStringBase::size_type oldUsed = m_used;
	if (obj.size() > 0)
	{
		len = obj.size();
		resize(m_used + len);
		memcpy(&m_data[oldUsed], obj.m_data, len * sizeof(value_type));
	}
	return *this;
}
tsCryptoStringBase &tsCryptoStringBase::operator+= (const_pointer data) /* zero terminated */
{
	return (*this) += tsCryptoStringBase(data);
}
tsCryptoStringBase &tsCryptoStringBase::operator+= (value_type data)
{
	tsCryptoStringBase::size_type len = 0;
	tsCryptoStringBase::size_type oldUsed = m_used;
	//	if ( data != nullptr )
	{
		len = 1;

		resize(m_used + len);
		m_data[oldUsed] = data;
	}
	return *this;
}
tsCryptoStringBase &tsCryptoStringBase::operator += (std::initializer_list<value_type> init)
{
	return append(init);
}
int tsCryptoStringBase::compare(const tsCryptoStringBase& str) const
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
int tsCryptoStringBase::compare(size_type pos1, size_type count1, const tsCryptoStringBase& str) const
{
	return substr(pos1, count1).compare(str);
}
int tsCryptoStringBase::compare(size_type pos1, size_type count1, const tsCryptoStringBase& str, size_type pos2, size_type count2) const
{
	return substr(pos1, count1).compare(str.substr(pos2, count2));
}
int tsCryptoStringBase::compare(const_pointer s) const
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
int tsCryptoStringBase::compare(size_type pos1, size_type count1, const_pointer s) const
{
	return substr(pos1, count1).compare(s);
}
int tsCryptoStringBase::compare(size_type pos1, size_type count1, const_pointer s, size_type count2) const
{
	return substr(pos1, count1).compare(tsCryptoStringBase(s, count2));
}
tsCryptoStringBase::size_type tsCryptoStringBase::size() const
{
	return m_used;
}
tsCryptoStringBase::size_type tsCryptoStringBase::length() const
{
	return m_used;
}
void tsCryptoStringBase::clear()
{
	resize(0);
}
_Post_satisfies_(this->m_data != nullptr) void tsCryptoStringBase::reserve(tsCryptoStringBase::size_type newSize)
{
	if (newSize > max_size())
		throw tscrypto::length_error();
	if ((ptrdiff_t)newSize > m_allocated)
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
tsCryptoStringBase::size_type tsCryptoStringBase::capacity() const
{
	return m_allocated;
}
tsCryptoStringBase::size_type tsCryptoStringBase::max_size() const
{
	return 0x7FFFFFFF;
}
_Post_satisfies_(this->m_data != nullptr) void tsCryptoStringBase::resize(tsCryptoStringBase::size_type newSize)
{
	resize(newSize, (value_type)0);
}
_Post_satisfies_(this->m_data != nullptr) void tsCryptoStringBase::resize(tsCryptoStringBase::size_type newSize, value_type value)
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
tsCryptoStringBase::reference tsCryptoStringBase::at(tsCryptoStringBase::size_type index)
{
	if (index >= m_used)
	{
		throw tscrypto::OutOfRange();
	}
	return m_data[index];
}
tsCryptoStringBase::const_reference tsCryptoStringBase::at(tsCryptoStringBase::size_type index) const
{
	if (index >= m_used)
	{
		throw tscrypto::OutOfRange();
	}
	return m_data[index];
}
tsCryptoStringBase::value_type tsCryptoStringBase::c_at(tsCryptoStringBase::size_type index) const
{
	if (index >= m_used)
	{
		throw tscrypto::OutOfRange();
	}
	return m_data[index];
}
//
// used to access the buffer directly.
// In all cases this will return a buffer for this class instance only.
//
// NOTE:  Do not access data beyond size() characters
//
tsCryptoStringBase::pointer tsCryptoStringBase::data()
{
	return m_data;
}
tsCryptoStringBase::const_pointer tsCryptoStringBase::data() const
{
	return m_data;
}
tsCryptoStringBase::reference tsCryptoStringBase::front()
{
	return m_data[0];
}
tsCryptoStringBase::const_reference tsCryptoStringBase::front() const
{
	return m_data[0];
}
tsCryptoStringBase::reference tsCryptoStringBase::back()
{
	if (empty())
		throw tscrypto::OutOfRange();
	return m_data[m_used - 1];
}
tsCryptoStringBase::const_reference tsCryptoStringBase::back() const
{
	if (empty())
		throw tscrypto::OutOfRange();
	return m_data[m_used - 1];
}
bool tsCryptoStringBase::empty() const
{
	return m_used == 0;
}
tsCryptoStringBase::const_pointer tsCryptoStringBase::c_str() const
{
	return m_data;
}
void tsCryptoStringBase::push_back(value_type ch)
{
	resize(size() + 1, ch);
}
void tsCryptoStringBase::pop_back()
{
	if (size() > 0)
		resize(size() - 1);
}
tsCryptoStringBase::reference tsCryptoStringBase::operator [] (tsCryptoStringBase::size_type index)
{
	return at(index);
}
tsCryptoStringBase::const_reference tsCryptoStringBase::operator [] (tsCryptoStringBase::size_type index) const
{
	return at(index);
}
tsCryptoStringBase &tsCryptoStringBase::assign(tsCryptoStringBase::size_type size, tsCryptoStringBase::value_type ch)
{
	clear();
	resize(size, ch);
	return *this;
}
tsCryptoStringBase &tsCryptoStringBase::assign(const tsCryptoStringBase &obj)
{
	*this = obj;
	return *this;
}
tsCryptoStringBase &tsCryptoStringBase::assign(const tsCryptoStringBase &obj, tsCryptoStringBase::size_type pos, tsCryptoStringBase::size_type count)
{
	*this = obj.substr(pos, count);
	return *this;
}
tsCryptoStringBase &tsCryptoStringBase::assign(tsCryptoStringBase &&obj)
{
	*this = std::move(obj);
	return *this;
}
tsCryptoStringBase &tsCryptoStringBase::assign(const_pointer newData, tsCryptoStringBase::size_type size)
{
	resize(size);
	if (size > 0 && newData != nullptr)
	{
		memcpy(m_data, newData, size * sizeof(value_type));
	}
	return *this;
}
tsCryptoStringBase &tsCryptoStringBase::assign(std::initializer_list<value_type> iList)
{
	size_type pos = size();

	resize(iList.size());
	for (auto it = iList.begin(); it != iList.end(); ++it)
	{
		m_data[pos++] = *it;
	}
	return *this;
}
tsCryptoStringBase::size_type tsCryptoStringBase::copy(pointer dest, size_type count, size_type pos) const
{
	if (pos >= size())
		throw tscrypto::OutOfRange();
	if (count + pos > size())
		count = size() - pos;
	memcpy(dest, &m_data[pos], sizeof(value_type) * count);
	return count;
}
void tsCryptoStringBase::copyFrom(const tsCryptoStringBase &obj)
{
	if (&obj == this)
		return;
	resize(obj.size());
	memcpy(m_data, obj.m_data, m_used * sizeof(value_type));
}
void tsCryptoStringBase::swap(tsCryptoStringBase &obj)
{
	std::swap(m_data, obj.m_data);
	std::swap(m_used, obj.m_used);
	std::swap(m_allocated, obj.m_allocated);
}
tsCryptoStringBase &tsCryptoStringBase::prepend(const_pointer data)
{
	if (data == nullptr)
	{
		return *this;
	}
	return prepend(tsCryptoStringBase(data));
}
tsCryptoStringBase &tsCryptoStringBase::prepend(const_pointer data, tsCryptoStringBase::size_type len)
{
	if (data == nullptr)
	{
		return *this;
	}
	return prepend(tsCryptoStringBase(data, len));
}
tsCryptoStringBase &tsCryptoStringBase::prepend(value_type data)
{
	if (data == 0)
	{
		return *this;
	}
	tsCryptoStringBase::size_type oldUsed = m_used;
	resize(oldUsed + 1);
	memmove(&m_data[1], m_data, oldUsed * sizeof(value_type));
	m_data[0] = data;
	return *this;
}
tsCryptoStringBase &tsCryptoStringBase::prepend(BYTE data)
{
	tsCryptoStringBase::size_type oldUsed = m_used;
	resize(oldUsed + 1);
	memmove(&m_data[1], m_data, oldUsed * sizeof(value_type));
	m_data[0] = data;
	return *this;
}
tsCryptoStringBase &tsCryptoStringBase::prepend(const tsCryptoStringBase &obj)
{
	if (obj.size() > 0)
	{
		tsCryptoStringBase::size_type oldUsed = m_used;
		resize(oldUsed + obj.size());
		memmove(&m_data[obj.size()], m_data, oldUsed * sizeof(value_type));
		memcpy(m_data, obj.c_str(), obj.size() * sizeof(value_type));
	}
	return *this;
}
tsCryptoStringBase &tsCryptoStringBase::append(size_type len, value_type ch)
{
	resize(size() + len, ch);
	return *this;
}
tsCryptoStringBase &tsCryptoStringBase::append(const tsCryptoStringBase &obj)
{
	size_type objSize = obj.size();

	if (objSize > 0)
	{
		tsCryptoStringBase::size_type oldUsed = m_used;
		resize(oldUsed + objSize);
		memcpy(&m_data[oldUsed], obj.c_str(), objSize * sizeof(value_type));
	}
	return *this;
}
tsCryptoStringBase &tsCryptoStringBase::append(const tsCryptoStringBase &obj, size_type pos, size_type count)
{
	return append(obj.substr(pos, count));
}
tsCryptoStringBase &tsCryptoStringBase::append(const_pointer data, size_type len)
{
	if (data == nullptr)
	{
		return *this;
	}
	return append(tsCryptoStringBase(data, len));
}
tsCryptoStringBase &tsCryptoStringBase::append(const_pointer data)
{
	if (data == nullptr)
	{
		return *this;
	}
	return append(tsCryptoStringBase(data));
}
tsCryptoStringBase &tsCryptoStringBase::append(std::initializer_list<value_type> list)
{
	size_type pos = size();

	resize(size() + list.size());
	for (auto it = list.begin(); it != list.end(); ++it)
	{
		m_data[pos++] = *it;
	}
	return *this;
}
tsCryptoStringBase &tsCryptoStringBase::append(value_type data)
{
	tsCryptoStringBase::size_type oldUsed = m_used;
	resize(oldUsed + 1);
	m_data[oldUsed] = data;
	return *this;
}
tsCryptoStringBase &tsCryptoStringBase::append(BYTE data)
{
	tsCryptoStringBase buffer;

	buffer.Format("%d", data);
	append(buffer);
	return *this;
}
//tsCryptoStringBase &tsCryptoStringBase::append(int8_t val)
//{
//	tsCryptoStringBase buffer;
//
//	buffer.Format("%d", val);
//	append(buffer);
//return *this;
//}
tsCryptoStringBase &tsCryptoStringBase::append(int16_t val)
{
	tsCryptoStringBase buffer;

	buffer.Format("%d", val);
	append(buffer);
	return *this;
}
tsCryptoStringBase &tsCryptoStringBase::append(int32_t val)
{
	tsCryptoStringBase buffer;

	buffer.Format("%d", val);
	append(buffer);
	return *this;
}
#ifdef _MSC_VER
tsCryptoStringBase &tsCryptoStringBase::append(long val)
{
	tsCryptoStringBase buffer;

	buffer.Format("%ld", val);
	append(buffer);
	return *this;
}
tsCryptoStringBase &tsCryptoStringBase::append(unsigned long val)
{
	tsCryptoStringBase buffer;

	buffer.Format("%lu", val);
	append(buffer);
	return *this;
}
#endif
tsCryptoStringBase &tsCryptoStringBase::append(int64_t val)
{
	tsCryptoStringBase buffer;

	buffer.Format("%lld", val);
	append(buffer);
	return *this;
}
//tsCryptoStringBase &tsCryptoStringBase::append(uint8_t val)
//{
//	tsCryptoStringBase buffer;
//
//	buffer.Format("%u", val);
//	append(buffer);
//return *this;
//}
tsCryptoStringBase &tsCryptoStringBase::append(uint16_t val)
{
	tsCryptoStringBase buffer;

	buffer.Format("%u", val);
	append(buffer);
	return *this;
}
tsCryptoStringBase &tsCryptoStringBase::append(uint32_t val)
{
	tsCryptoStringBase buffer;

	buffer.Format("%u", val);
	append(buffer);
	return *this;
}
tsCryptoStringBase &tsCryptoStringBase::append(uint64_t val)
{
	tsCryptoStringBase buffer;

	buffer.Format("%llu", val);
	append(buffer);
	return *this;
}

tsCryptoStringBase& tsCryptoStringBase::erase(tsCryptoStringBase::size_type pos, tsCryptoStringBase::size_type count)
{
	if (pos > size())
		throw tscrypto::OutOfRange();
	if (pos + count >= size())
	{
		resize(pos);
	}
	else
	{
		memmove(&m_data[pos], &m_data[pos + count], sizeof(value_type) * (size() - pos - count));
		resize(size() - count);
	}
	return *this;
}
tsCryptoStringBase& tsCryptoStringBase::insert(tsCryptoStringBase::size_type index, tsCryptoStringBase::size_type count, tsCryptoStringBase::value_type ch)
{
	size_type oldsize = size();

	resize(size() + count);
	memmove(&m_data[index + count], &m_data[index], sizeof(value_type) * (oldsize - index));
	memset(&m_data[index], ch, count);
	return *this;
}
tsCryptoStringBase& tsCryptoStringBase::insert(tsCryptoStringBase::size_type index, tsCryptoStringBase::value_type ch)
{
	size_type oldsize = size();

	resize(size() + 1);
	memmove(&m_data[index + 1], &m_data[index], sizeof(value_type) * (oldsize - index));
	m_data[index] = ch;
	return *this;
}
tsCryptoStringBase& tsCryptoStringBase::insert(tsCryptoStringBase::size_type index, tsCryptoStringBase::const_pointer s)
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
tsCryptoStringBase& tsCryptoStringBase::insert(tsCryptoStringBase::size_type index, tsCryptoStringBase::const_pointer s, tsCryptoStringBase::size_type count)
{
	if (s == nullptr)
		throw tscrypto::ArgumentNullException("s");

	size_type oldsize = size();

	resize(size() + count);
	memmove(&m_data[index + count], &m_data[index], sizeof(value_type) * (oldsize - index));
	memcpy(&m_data[index], s, count);
	return *this;
}
tsCryptoStringBase& tsCryptoStringBase::insert(tsCryptoStringBase::size_type index, const tsCryptoStringBase& str)
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
tsCryptoStringBase& tsCryptoStringBase::insert(tsCryptoStringBase::size_type index, const tsCryptoStringBase& str, size_type index_str, size_type count)
{
	return insert(index, str.substr(index_str, count));
}
tsCryptoStringBase& tsCryptoStringBase::insert(size_type pos, std::initializer_list<value_type> iList)
{
	size_type oldsize = size();

	if (pos >= size())
	{
		append(iList);
		return *this;
	}
	resize(size() + iList.size());
	memmove(&m_data[pos + iList.size()], &m_data[pos], sizeof(value_type) * (oldsize - pos));
	for (auto it = iList.begin(); it != iList.end(); ++it)
	{
		m_data[pos++] = *it;
	}
	return *this;

}

//bool tsCryptoStringBase::LoadString(long ID, HINSTANCE hInstance)
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
tsCryptoStringBase &tsCryptoStringBase::InsertAt(tsCryptoStringBase::size_type offset, value_type value)
{
	return InsertAt(offset, &value, 1);
}
tsCryptoStringBase &tsCryptoStringBase::InsertAt(tsCryptoStringBase::size_type offset, const_pointer value, int32_t len)
{
	if (len == -1)
		return InsertAt(offset, tsCryptoStringBase(value));
	return InsertAt(offset, tsCryptoStringBase(value, len));
}

tsCryptoStringBase &tsCryptoStringBase::InsertAt(tsCryptoStringBase::size_type offset, const tsCryptoStringBase &value)
{
	tsCryptoStringBase::size_type oldLen = m_used;

	if (value.size() == 0)
		return *this;
	if (offset > m_used)
	{
		offset = m_used;
	}
	resize(oldLen + value.size());
	memmove(&m_data[offset + value.size()], &m_data[offset], (oldLen - offset) * sizeof(value_type));
	memcpy(&m_data[offset], value.c_str(), value.size() * sizeof(value_type));
	return *this;
}

tsCryptoStringBase &tsCryptoStringBase::DeleteAt(tsCryptoStringBase::size_type offset, tsCryptoStringBase::size_type count)
{
	if (count == 0)
		return *this;

	if (offset >= m_used)
		return *this;

	if (count + offset > m_used)
		count = m_used - offset;

	if (count + offset < m_used)
	{
		memmove(&m_data[offset], &m_data[offset + count], (m_used - offset - count) * sizeof(value_type));
	}
	resize(size() - count);
	return *this;
}
tsCryptoStringBase& tsCryptoStringBase::replace(size_type pos, size_type count, const tsCryptoStringBase& str)
{
	erase(pos, count);
	insert(pos, str);
	return *this;
}
tsCryptoStringBase& tsCryptoStringBase::replace(size_type pos, size_type count, const tsCryptoStringBase& str, size_type pos2, size_type count2)
{
	erase(pos, count);
	insert(pos, str, pos2, count2);
	return *this;
}
tsCryptoStringBase& tsCryptoStringBase::replace(size_type pos, size_type count, const_pointer s, size_type count2)
{
	erase(pos, count);
	insert(pos, s, count2);
	return *this;
}
tsCryptoStringBase& tsCryptoStringBase::replace(size_type pos, size_type count, const_pointer s)
{
	erase(pos, count);
	insert(pos, s);
	return *this;
}
tsCryptoStringBase& tsCryptoStringBase::replace(size_type pos, size_type count, size_type count2, value_type ch)
{
	erase(pos, count);
	insert(pos, count2, ch);
	return *this;
}
tsCryptoStringBase &tsCryptoStringBase::Replace(tsCryptoStringBase::size_type i_Begin, tsCryptoStringBase::size_type i_End, const_pointer i_newData, int32_t i_newDataLength)
{
	tsCryptoStringBase::size_type repLen;

	if (i_Begin > i_End || i_newData == nullptr)
		return *this;

	if (i_newDataLength == -1)
	{
		repLen = strlen(i_newData);
	}
	else
	{
		repLen = i_newDataLength;
	}
#ifdef HAVE_ISBADREADPTR
	if (IsBadReadPtr(i_newData, repLen))
		return *this;
#endif
	if (i_Begin >= m_used)
		return *this;
	if (i_End >= m_used)
		i_End = m_used - 1;

	if (!(DeleteAt(i_Begin, i_End - i_Begin + 1).c_str()))
		return *this;

	return InsertAt(i_Begin, i_newData, (int32_t)repLen);
}
tsCryptoStringBase &tsCryptoStringBase::Replace(const_pointer find, const_pointer replacement, int32_t count)
{
	return Replace(tsCryptoStringBase(find), tsCryptoStringBase(replacement), count);
}

tsCryptoStringBase &tsCryptoStringBase::Replace(const tsCryptoStringBase &find, const tsCryptoStringBase &replacement, int32_t count)
{
	tsCryptoStringBase::size_type posi;
	tsCryptoStringBase::size_type findLen;
	tsCryptoStringBase::size_type repLen;

	findLen = find.size();
	repLen = replacement.size();
	if (findLen < 1 || findLen > m_used)
		return *this;
	if (count == -1)
		count = (int32_t)max_size();
	posi = 0;
	while (posi + findLen <= m_used && count > 0)
	{
		if (strncmp(&m_data[posi], find.c_str(), findLen) == 0)
		{
			count--;
			if (findLen == repLen)
			{
				memcpy(&m_data[posi], replacement.c_str(), repLen * sizeof(value_type));
				posi += repLen - 1;
			}
			else if (findLen < repLen)
			{
				tsCryptoStringBase::size_type oldLen = size();

				resize(oldLen + repLen - findLen);
				if (oldLen - findLen > posi)
					memmove(&m_data[posi + repLen], &m_data[posi + findLen], (oldLen - posi - findLen) * sizeof(value_type));
				memcpy(&m_data[posi], replacement.c_str(), repLen * sizeof(value_type));
				posi += repLen - 1;
			}
			else
			{
				tsCryptoStringBase::size_type oldLen = size();

				if (oldLen - findLen > posi)
				{
					memmove(&m_data[posi + repLen], &m_data[posi + findLen], (oldLen - posi - findLen) * sizeof(value_type));
				}
				if (repLen > 0)
					memcpy(&m_data[posi], replacement.c_str(), repLen * sizeof(value_type));
				resize(oldLen + repLen - findLen);
				posi += repLen - 1;
			}
		}
		posi++;
	}
	return *this;
}
tsCryptoStringBase::size_type tsCryptoStringBase::find(const tsCryptoStringBase& str, size_type pos) const
{
	tsCryptoStringBase::size_type i;
	tsCryptoStringBase::size_type len = 0;

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
tsCryptoStringBase::size_type tsCryptoStringBase::find(const_pointer s, size_type pos, size_type count) const
{
	if (s == nullptr)
		throw tscrypto::ArgumentNullException("s");

	tsCryptoStringBase::size_type i;

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
tsCryptoStringBase::size_type tsCryptoStringBase::find(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		throw tscrypto::ArgumentNullException("s");

	tsCryptoStringBase::size_type i;
	tsCryptoStringBase::size_type len;

	len = TsStrLen(s);
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
tsCryptoStringBase::size_type tsCryptoStringBase::find(value_type ch, size_type pos) const
{
	tsCryptoStringBase::size_type i;

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

tsCryptoStringBase::size_type tsCryptoStringBase::rfind(const tsCryptoStringBase& str, size_type pos) const
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
tsCryptoStringBase::size_type tsCryptoStringBase::rfind(const_pointer s, size_type pos, size_type count) const
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
tsCryptoStringBase::size_type tsCryptoStringBase::rfind(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		throw tscrypto::ArgumentNullException("s");

	size_type count = TsStrLen(s);
	if (count == 0)
		return npos;

	return rfind(s, pos, count);
}
tsCryptoStringBase::size_type tsCryptoStringBase::rfind(value_type ch, size_type pos) const
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

tsCryptoStringBase::size_type tsCryptoStringBase::find_first_of(const tsCryptoStringBase& str, size_type pos) const
{
	return find_first_of(str.c_str(), pos, str.size());
}
tsCryptoStringBase::size_type tsCryptoStringBase::find_first_of(const_pointer s, size_type pos, size_type count) const
{
	if (s == nullptr || count == 0)
		return npos;
	tsCryptoStringBase::size_type i;

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
tsCryptoStringBase::size_type tsCryptoStringBase::find_first_of(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		return npos;
	return find_first_of(s, pos, TsStrLen(s));
}
tsCryptoStringBase::size_type tsCryptoStringBase::find_first_of(value_type ch, size_type pos) const
{
	return find(ch, pos);
}

tsCryptoStringBase::size_type tsCryptoStringBase::find_first_not_of(const tsCryptoStringBase& str, size_type pos) const
{
	return find_first_not_of(str.c_str(), pos, str.size());
}
tsCryptoStringBase::size_type tsCryptoStringBase::find_first_not_of(const_pointer s, size_type pos, size_type count) const
{
	if (s == nullptr || count == 0)
		return npos;
	tsCryptoStringBase::size_type i;

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
tsCryptoStringBase::size_type tsCryptoStringBase::find_first_not_of(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		return npos;
	return find_first_not_of(s, pos, TsStrLen(s));
}
tsCryptoStringBase::size_type tsCryptoStringBase::find_first_not_of(value_type ch, size_type pos) const
{
	tsCryptoStringBase::size_type i;

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

tsCryptoStringBase::size_type tsCryptoStringBase::find_last_of(const tsCryptoStringBase& str, size_type pos) const
{
	return find_last_of(str.c_str(), pos, str.size());
}
tsCryptoStringBase::size_type tsCryptoStringBase::find_last_of(const_pointer s, size_type pos, size_type count) const
{
	if (s == nullptr || count == 0)
		return npos;
	tsCryptoStringBase::difference_type i;

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
tsCryptoStringBase::size_type tsCryptoStringBase::find_last_of(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		return npos;
	return find_last_of(s, pos, TsStrLen(s));
}
tsCryptoStringBase::size_type tsCryptoStringBase::find_last_of(value_type ch, size_type pos) const
{
	return rfind(ch, pos);
}

tsCryptoStringBase::size_type tsCryptoStringBase::find_last_not_of(const tsCryptoStringBase& str, size_type pos) const
{
	return find_last_not_of(str.c_str(), pos, str.size());
}
tsCryptoStringBase::size_type tsCryptoStringBase::find_last_not_of(const_pointer s, size_type pos, size_type count) const
{
	if (s == nullptr || count == 0)
		return npos;
	tsCryptoStringBase::difference_type i;

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
tsCryptoStringBase::size_type tsCryptoStringBase::find_last_not_of(const_pointer s, size_type pos) const
{
	if (s == nullptr)
		return npos;
	return find_last_not_of(s, pos, TsStrLen(s));
}
tsCryptoStringBase::size_type tsCryptoStringBase::find_last_not_of(value_type ch, size_type pos) const
{
	tsCryptoStringBase::difference_type i;

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



tsCryptoStringBase &tsCryptoStringBase::Format(const char *msg, ...)
{
	va_list args;

	va_start(args, msg);
	resize(0);
	resize(10240);
	vsnprintf_s(data(), size(), size(), msg, args);
	resize(strlen(c_str()));
	va_end(args);
	return *this;
}

tsCryptoStringBase &tsCryptoStringBase::Format(tsCryptoStringBase msg, ...)
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

tsCryptoStringBase &tsCryptoStringBase::FormatArg(const char *msg, va_list arg)
{
	resize(0);
	resize(10240);
	vsnprintf_s(data(), size(), size(), msg, arg);
	resize(strlen(c_str()));
	return *this;
}

tsCryptoStringBase &tsCryptoStringBase::FormatArg(const tsCryptoStringBase& msg, va_list arg)
{
	resize(0);
	resize(10240);
	vsnprintf_s(data(), size(), size(), msg.c_str(), arg);
	resize(strlen(c_str()));
	return *this;
}

tsCryptoStringBase &tsCryptoStringBase::ToUpper()
{
	tsCryptoStringBase::size_type count = size();
	tsCryptoStringBase::size_type i;

	for (i = 0; i < count; i++)
	{
		if (m_data[i] >= 'a' && m_data[i] <= 'z')
			m_data[i] -= 0x20;
	}
	return *this;
}

tsCryptoStringBase &tsCryptoStringBase::ToLower()
{
	tsCryptoStringBase::size_type count = size();
	tsCryptoStringBase::size_type i;

	for (i = 0; i < count; i++)
	{
		if (m_data[i] >= 'A' && m_data[i] <= 'Z')
			m_data[i] += 0x20;
	}
	return *this;
}

tsCryptoStringBase tsCryptoStringBase::substring(tsCryptoStringBase::size_type start, tsCryptoStringBase::size_type length) const
{
	if (start >= size() || length == 0)
		return "";
	if (start + length >= size())
	{
		return tsCryptoStringBase(&c_str()[start]);
	}
	return tsCryptoStringBase(&c_str()[start], length);
}
tsCryptoStringBase tsCryptoStringBase::substr(tsCryptoStringBase::size_type start, tsCryptoStringBase::size_type length) const
{
	return substring(start, length);
}

tsCryptoStringBase tsCryptoStringBase::right(tsCryptoStringBase::size_type length) const
{
	tsCryptoStringBase tmp = *this;

	if (tmp.size() > length)
		tmp.DeleteAt(0, tmp.size() - length);
	return tmp;
}

tsCryptoStringBase tsCryptoStringBase::left(tsCryptoStringBase::size_type length) const
{
	tsCryptoStringBase tmp = *this;

	if (tmp.size() > length)
		tmp.resize(length);
	return tmp;
}

tsCryptoStringBase &tsCryptoStringBase::Trim()
{
	return Trim(("\t\r\n "));
}

tsCryptoStringBase &tsCryptoStringBase::Trim(const_pointer trimmers)
{
	TrimStart(trimmers);
	return TrimEnd(trimmers);
}

tsCryptoStringBase &tsCryptoStringBase::TrimStart()
{
	return TrimStart(("\t\r\n "));
}

tsCryptoStringBase &tsCryptoStringBase::TrimStart(const_pointer trimmers)
{
	difference_type index = find_first_not_of(trimmers);

	DeleteAt(0, index);
	return *this;
}

tsCryptoStringBase &tsCryptoStringBase::TrimEnd()
{
	return TrimEnd(("\t\r\n "));
}

tsCryptoStringBase &tsCryptoStringBase::TrimEnd(const_pointer trimmers)
{
	difference_type index = find_last_not_of(trimmers);

	if (index < (difference_type)(size()) - 1)
		resize(index + 1);
	return *this;
}

std::ostream & tscrypto::operator << (std::ostream &Output, const tsCryptoStringBase &obj)
{
	Output << tsCryptoStringBase(obj).c_str();
	return Output;
}
std::wostream & tscrypto::operator << (std::wostream &Output, const tsCryptoStringBase &obj)
{
	Output << obj.c_str();
	return Output;
}

tsCryptoStringBase tsCryptoStringBase::PadLeft(tsCryptoStringBase::size_type width, value_type padding) const
{
	tsCryptoStringBase tmp(*this);

	if (tmp.size() < width)
	{
		tmp.prepend(tsCryptoStringBase(padding, width - tmp.size()));
	}
	return tmp;
}

tsCryptoStringBase tsCryptoStringBase::PadRight(tsCryptoStringBase::size_type width, value_type padding) const
{
	tsCryptoStringBase tmp(*this);

	if (tmp.size() < width)
	{
		tmp.resize(width, padding);
	}
	return tmp;
}

tsCryptoStringBase tsCryptoStringBase::TruncOrPadLeft(tsCryptoStringBase::size_type width, value_type padding) const
{
	tsCryptoStringBase tmp(*this);

	if (tmp.size() < width)
	{
		tmp.prepend(tsCryptoStringBase(padding, width - tmp.size()));
	}
	else if (tmp.size() > width)
		tmp.resize(width);
	return tmp;
}

tsCryptoStringBase tsCryptoStringBase::TruncOrPadRight(tsCryptoStringBase::size_type width, value_type padding) const
{
	tsCryptoStringBase tmp(*this);

	if (tmp.size() < width)
	{
		tmp.resize(width, padding);
	}
	else if (tmp.size() > width)
		tmp.resize(width);
	return tmp;
}

tsCryptoStringBase tsCryptoStringBase::ToUTF8() const
{
	return *this;
}

bool tscrypto::operator==(const tsCryptoStringBase& lhs, const tsCryptoStringBase& rhs)
{
	return lhs.compare(rhs) == 0;
}
bool tscrypto::operator!=(const tsCryptoStringBase& lhs, const tsCryptoStringBase& rhs)
{
	return lhs.compare(rhs) != 0;
}
bool tscrypto::operator<(const tsCryptoStringBase& lhs, const tsCryptoStringBase& rhs)
{
	return lhs.compare(rhs) < 0;
}
bool tscrypto::operator<=(const tsCryptoStringBase& lhs, const tsCryptoStringBase& rhs)
{
	return lhs.compare(rhs) <= 0;
}
bool tscrypto::operator>(const tsCryptoStringBase& lhs, const tsCryptoStringBase& rhs)
{
	return lhs.compare(rhs) > 0;
}
bool tscrypto::operator>=(const tsCryptoStringBase& lhs, const tsCryptoStringBase& rhs)
{
	return lhs.compare(rhs) >= 0;
}


void tscrypto::swap(tsCryptoStringBase &lhs, tsCryptoStringBase &rhs)
{
	lhs.swap(rhs);
}

tsCryptoStringBase& tscrypto::operator<<(tsCryptoStringBase& string, char val)
{
	return string.append(val);
}
tsCryptoStringBase& tscrypto::operator<<(tsCryptoStringBase& string, int8_t val)
{
	return string.append(val);
}
tsCryptoStringBase& tscrypto::operator<<(tsCryptoStringBase& string, int16_t val)
{
	return string.append(val);
}
tsCryptoStringBase& tscrypto::operator<<(tsCryptoStringBase& string, int32_t val)
{
	return string.append(val);
}
#ifdef _MSC_VER
tsCryptoStringBase& tscrypto::operator<<(tsCryptoStringBase& string, long val)
{
	return string.append(val);
}
tsCryptoStringBase& tscrypto::operator<<(tsCryptoStringBase& string, unsigned long val)
{
	return string.append(val);
}
#endif
tsCryptoStringBase& tscrypto::operator<<(tsCryptoStringBase& string, int64_t val)
{
	return string.append(val);
}
tsCryptoStringBase& tscrypto::operator<<(tsCryptoStringBase& string, uint8_t val)
{
	return string.append(val);
}
tsCryptoStringBase& tscrypto::operator<<(tsCryptoStringBase& string, uint16_t val)
{
	return string.append(val);
}
tsCryptoStringBase& tscrypto::operator<<(tsCryptoStringBase& string, uint32_t val)
{
	return string.append(val);
}
tsCryptoStringBase& tscrypto::operator<<(tsCryptoStringBase& string, uint64_t val)
{
	return string.append(val);
}
//tsCryptoStringBase& tscrypto::operator<<(tsCryptoStringBase& string, const char* val)
//{
//	return string.append(val);
//}
tsCryptoStringBase& tscrypto::operator<<(tsCryptoStringBase& string, const tsCryptoStringBase& val)
{
	return string.append(val);
}
tsCryptoStringBase& tscrypto::operator<<(tsCryptoStringBase& string, enum SpecialStrings val)
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