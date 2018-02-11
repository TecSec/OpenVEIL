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

#define BASE64_ENCODE_RATIO 1.4
#define BASE64_DECODE_RATIO 1.3

#ifndef MIN
#   define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif// MIN

using namespace tscrypto;

const tscrypto::tsCryptoData::size_type tscrypto::tsCryptoData::npos = (size_type)(-1);

tsCryptoData::tsCryptoData() : _data(tsCreateBuffer())
{
}
tsCryptoData::tsCryptoData(size_type count, value_type value) : _data(tsCreateBuffer())
{
    resize(count, value);
}
tsCryptoData::tsCryptoData(const tsCryptoData &obj, size_type pos) : _data(tsCreateBuffer())
{
    tsCopyBuffer(obj._data, _data);
}
tsCryptoData::tsCryptoData(const tsCryptoData &obj, size_type pos, size_type count) : _data(tsCreateBuffer())
{
    if (pos < obj.size())
    {
        if (count + pos > obj.size())
            count = obj.size() - pos;

        resize(count);
        obj.copy(rawData(), count, pos);
    }
}
tsCryptoData::tsCryptoData(const_pointer data, size_type Len) : _data(tsCreateBuffer())
{
    if (data != nullptr && Len != 0)
    {
        resize(Len);
        memcpy(rawData(), data, Len);
    }
}
tsCryptoData::tsCryptoData(const_pointer data) : _data(tsCreateBuffer())
{
    if (data != nullptr)
    {
        size_type Len = tsStrLen((const char*)data);
        if (Len != 0)
        {
            resize(Len);
            memcpy(rawData(), data, Len);
        }
    }
}
tsCryptoData::tsCryptoData(const tsCryptoData &obj) : _data(tsCreateBuffer())
{
    if (obj.size() != 0)
    {
        resize(obj.size());
        obj.copy(rawData(), size(), 0);
    }
}
tsCryptoData::tsCryptoData(tsCryptoData &&obj)
{
    _data = obj._data;

    obj._data = tsCreateBuffer();
}
tsCryptoData::tsCryptoData(std::initializer_list<value_type> init) : _data(tsCreateBuffer())
{
    size_type index = 0;
    resize(init.size());

    pointer ptr = rawData();
    for (auto i = init.begin(); i != init.end(); ++i)
    {
        ptr[index++] = *i;
    }
}
tsCryptoData::tsCryptoData(const tsCryptoStringBase &value, DataStringType type) : _data(tsCreateBuffer())
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
            memcpy(rawData(), value.c_str(), Len);
            break;
        }
    }
}
// ASCII only
tsCryptoData::tsCryptoData(const tsCryptoStringBase &value) : _data(tsCreateBuffer())
{
    if (value.size() != 0)
    {
        resize(value.size());
        memcpy(rawData(), value.data(), value.size());
    }
}
tsCryptoData::tsCryptoData(std::initializer_list<char> init) : _data(tsCreateBuffer())
{
    size_type index = 0;
    resize(init.size());

    pointer ptr = rawData();
    for (auto i = init.begin(); i != init.end(); ++i)
    {
        ptr[index++] = *i;
    }
}
tsCryptoData::tsCryptoData(value_type ch) : _data(tsCreateBuffer())
{
    resize(1, ch);
}
tsCryptoData::tsCryptoData(char ch) : _data(tsCreateBuffer())
{
    resize(1, (value_type)ch);
}
tsCryptoData::tsCryptoData(TSBYTE_BUFF&& data) : _data(data)
{
    data = NULL;
}
tsCryptoData::tsCryptoData(const TSBYTE_BUFF& data) : _data(tsCreateBuffer())
{
    tsCopyBuffer(data, _data);
}

tsCryptoData::~tsCryptoData()
{
    tsFreeBuffer(&_data);
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
        tsEmptyBuffer(_data);
        tsMoveBuffer(obj._data, _data);
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
        len = tsStrLen((const char *)data);

        resize(len);
        memcpy(this->data(), data, len);
    }
    return *this;
}
tsCryptoData &tsCryptoData::operator=(value_type obj)
{
    resize(1);
    data()[0] = obj;
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
        len = tsStrLen(data);

        resize(len);
        memcpy(this->data(), data, len);
    }
    return *this;
}
tsCryptoData &tsCryptoData::operator=(std::initializer_list<char> iList)
{
    assign(iList);
    return *this;
}
tsCryptoData &tsCryptoData::operator=(TSBYTE_BUFF&& obj)
{
    if (this->_data != obj)
    {
        tsFreeBuffer(&this->_data);
        this->_data = obj;
        obj = NULL;
    }
    return *this;
}
tsCryptoData &tsCryptoData::operator=(const TSBYTE_BUFF& obj)
{
    if (this->_data != obj)
    {
        tsEmptyBuffer(this->_data);
        tsCopyBuffer(obj, this->_data);
    }
    return *this;
}

TSBYTE_BUFF tsCryptoData::getByteBuff() const
{
    return _data;
}
TSBYTE_BUFF* tsCryptoData::getByteBuffPtr()
{
    return &_data;
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

    tsMoveBuffer(obj._data, _data);

    return *this;
}
tsCryptoData& tsCryptoData::assign(const_pointer newData, size_type count)
{
    resize(count);
    if (count > 0 && newData != nullptr)
    {
        memcpy(this->data(), newData, count);
    }
    return *this;
}
tsCryptoData& tsCryptoData::assign(const_pointer newData)
{
    return assign(newData, (newData != nullptr) ? tsStrLen((const char *)newData) : 0);
}
tsCryptoData& tsCryptoData::assign(std::initializer_list<value_type> iList)
{
    size_type pos = size();

    resize(iList.size());
    pointer ptr = this->data();
    for (auto it = iList.begin(); it != iList.end(); ++it)
    {
        ptr[pos++] = *it;
    }
    return *this;
}
tsCryptoData& tsCryptoData::assign(const char *newData, size_type count) // tecsec extension
{
    resize(count);
    if (count > 0 && newData != nullptr)
    {
        memcpy(this->data(), newData, count);
    }
    return *this;
}
tsCryptoData& tsCryptoData::assign(const char *newData) // tecsec extension
{
    return assign(newData, (newData != nullptr) ? tsStrLen(newData) : 0);
}
tsCryptoData& tsCryptoData::assign(const tsCryptoStringBase &obj) // ASCII ONLY - tecsec extension
{
    return assign(obj.c_str(), obj.size());
}
tsCryptoData& tsCryptoData::assign(std::initializer_list<char> iList)
{
    size_type pos = size();

    resize(iList.size());
    pointer ptr = this->data();
    for (auto it = iList.begin(); it != iList.end(); ++it)
    {
        this->data()[pos++] = *it;
    }
    return *this;
}

tsCryptoData::reference tsCryptoData::at(size_type index)
{
    if (index >= size())
    {
        throw tscrypto::OutOfRange();
    }
    return this->data()[index];
}
tsCryptoData::const_reference tsCryptoData::at(size_type index) const
{
    if (index >= size())
    {
        throw tscrypto::OutOfRange();
    }
    return this->data()[index];
}
tsCryptoData::value_type tsCryptoData::c_at(size_type index) const // tecsec addition
{
    if (index >= size())
    {
        throw tscrypto::OutOfRange();
    }
    return this->data()[index];
}
tsCryptoData::const_pointer tsCryptoData::data() const
{
    const_pointer p = (const_pointer)tsGetBufferDataPtr(_data);

    if (p == NULL)
        p = (const_pointer)"";
    return p;
}
tsCryptoData::pointer tsCryptoData::data()
{
    return (pointer)tsGetBufferDataPtr(_data);
}
tsCryptoData::pointer tsCryptoData::rawData() // tecsec addition
{
    return (pointer)tsGetBufferDataPtr(_data);
}
tsCryptoData::const_pointer tsCryptoData::c_str() const
{
    const_pointer p = tsGetBufferDataPtr(_data);

    if (p == NULL)
        p = (const_pointer)"";
    return p;
}
tsCryptoData::reference tsCryptoData::front()
{
    return this->data()[0];
}
tsCryptoData::const_reference tsCryptoData::front() const
{
    return this->data()[0];
}
tsCryptoData::reference tsCryptoData::back()
{
    if (empty())
        throw tscrypto::OutOfRange();
    return this->data()[size() - 1];
}
tsCryptoData::const_reference tsCryptoData::back() const
{
    if (empty())
        throw tscrypto::OutOfRange();
    return this->data()[size() - 1];
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
    return size() == 0;
}
tsCryptoData::size_type  tsCryptoData::size() const
{
    return tsBufferUsed(_data);
}
tsCryptoData::size_type  tsCryptoData::length() const
{
    return size();
}
tsCryptoData::size_type tsCryptoData::max_size() const
{
    return 0x7FFFFFFF;
}
_Post_satisfies_(this->_data != nullptr) void tsCryptoData::reserve(size_type newSize)
{
    if (newSize > max_size() || !tsReserveBuffer(_data, (uint32_t)newSize))
        throw tscrypto::length_error();
}
tsCryptoData::size_type tsCryptoData::capacity() const
{
    return tsBufferReserved(_data);
}
void tsCryptoData::clear()
{
    resize(0);
}

tsCryptoData& tsCryptoData::insert(size_type index, size_type count, value_type ch)
{
    size_type oldsize = size();

    resize(size() + count);
    pointer ptr = this->data();
    memmove(&ptr[index + count], &ptr[index], sizeof(value_type) * (oldsize - index));
    memset(&ptr[index], ch, count);
    return *this;
}
tsCryptoData& tsCryptoData::insert(size_type index, value_type ch)
{
    size_type oldsize = size();

    resize(size() + 1);
    pointer ptr = this->data();
    memmove(&ptr[index + 1], &ptr[index], sizeof(value_type) * (oldsize - index));
    ptr[index] = ch;
    return *this;
}
tsCryptoData& tsCryptoData::insert(size_type index, const_pointer s)
{
    if (s == nullptr)
        throw tscrypto::ArgumentNullException("s");

    size_type oldsize = size();
    size_type count = tsStrLen((const char *)s);

    resize(size() + count);
    pointer ptr = this->data();
    memmove(&ptr[index + count], &ptr[index], sizeof(value_type) * (oldsize - index));
    memcpy(&ptr[index], s, count);
    return *this;
}
tsCryptoData& tsCryptoData::insert(size_type index, const_pointer s, size_type count)
{
    if (s == nullptr)
        throw tscrypto::ArgumentNullException("s");

    size_type oldsize = size();

    resize(size() + count);
    pointer ptr = this->data();
    memmove(&ptr[index + count], &ptr[index], sizeof(value_type) * (oldsize - index));
    memcpy(&ptr[index], s, count);
    return *this;
}
tsCryptoData& tsCryptoData::insert(size_type index, const tsCryptoData& str)
{
    size_type oldsize = size();
    size_type count = str.size();

    if (count == 0)
        return *this;
    resize(size() + count);
    pointer ptr = this->data();
    memmove(&ptr[index + count], &ptr[index], sizeof(value_type) * (oldsize - index));
    memcpy(&ptr[index], str.data(), count);
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
    pointer ptr = this->data();
    memmove(&ptr[index + iList.size()], &ptr[index], sizeof(value_type) * (oldsize - index));
    for (auto it = iList.begin(); it != iList.end(); ++it)
    {
        ptr[index++] = *it;
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
        memmove(&this->data()[pos], &this->data()[pos + count], sizeof(value_type) * (size() - count - pos));
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
    memmove(&this->data()[pos], &this->data()[pos + 1], sizeof(value_type) * (size() - pos - 1));
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
    memmove(&this->data()[pos], &this->data()[pos + count], sizeof(value_type) * (size() - count - pos));
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
        tsCryptoString::size_type oldUsed = size();
        resize(oldUsed + objSize);
        memcpy(&this->data()[oldUsed], obj.c_str(), objSize * sizeof(value_type));
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
    pointer ptr = this->data();
    for (auto it = list.begin(); it != list.end(); ++it)
    {
        ptr[pos++] = *it;
    }
    return *this;
}

tsCryptoData &tsCryptoData::operator+= (const tsCryptoData &obj)
{
    tsCryptoData::size_type len = 0;
    tsCryptoData::size_type oldUsed = size();
    if (obj.size() > 0)
    {
        len = obj.size();
        resize(size() + len);
        memcpy(&this->data()[oldUsed], obj.data(), len * sizeof(value_type));
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
    tsCryptoData::size_type oldUsed = size();
    //	if ( data != nullptr )
    {
        len = 1;

        resize(size() + len);
        this->data()[oldUsed] = data;
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

    diff = memcmp(this->data(), str.data(), count);
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
    size_type len = tsStrLen((const char *)s);
    size_type count = MIN(size(), len);
    int diff = 0;

    diff = memcmp(data(), s, count);
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
    memcpy(dest, &data()[pos], sizeof(value_type) * count);
    return count;
}
_Post_satisfies_(this->_data != nullptr) void tsCryptoData::resize(size_type newSize)
{
    resize(newSize, 0);
}
_Post_satisfies_(this->_data != nullptr) void tsCryptoData::resize(size_type newSize, value_type value)
{
    uint32_t oldSize = (uint32_t)size();
    if (!tsResizeBuffer(_data, (uint32_t)newSize))
        throw tscrypto::bad_alloc();

    if (newSize > oldSize)
    {
        memset(&data()[oldSize], value, newSize - oldSize);
    }
}
void tsCryptoData::swap(tsCryptoData &obj)
{
    std::swap(_data, obj._data);
}

tsCryptoData::size_type tsCryptoData::find(const tsCryptoData& str, size_type pos) const
{
    size_type i;
    size_type len = 0;

    len = str.size();
    if (len == 0)
        return npos;

    if (pos + len > size())
        return npos;
    const_pointer ptr = data();
    for (i = pos; i < size() - len + 1; i++)
    {
        const_pointer in_data_c_str = str.c_str();
        if (memcmp(in_data_c_str, &ptr[i], len) == 0)
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

    if (pos + count > size())
        return npos;
    const_pointer ptr = data();
    for (i = pos; i < size() - count + 1; i++)
    {
        if (memcmp(s, &ptr[i], count) == 0)
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

    len = tsStrLen((const char*)s);
    if (len == 0)
        return npos;
    if (pos + len > size())
        return npos;
    const_pointer ptr = data();
    for (i = pos; i < size() - len + 1; i++)
    {
        if (memcmp(s, &ptr[i], len) == 0)
        {
            return i;
        }
    }
    return npos;
}
tsCryptoData::size_type tsCryptoData::find(value_type ch, size_type pos) const
{
    size_type i;

    if (pos >= size())
        return npos;
    const_pointer ptr = data();
    for (i = pos; i < size(); i++)
    {
        if (ptr[i] == ch)
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
    const_pointer ptr = data();
    for (i = pos; i >= 0; i--)
    {
        if (memcmp(str.c_str(), &ptr[i], count) == 0)
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
    const_pointer ptr = data();

    for (i = pos; i >= 0; i--)
    {
        if (memcmp(s, &ptr[i], count) == 0)
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

    size_type count = tsStrLen((const char*)s);
    if (count == 0)
        return npos;

    return rfind(s, pos, count);
}
tsCryptoData::size_type tsCryptoData::rfind(value_type ch, size_type pos) const
{
    if (pos >= size())
        pos = size() - 1;

    difference_type i;
    const_pointer ptr = data();

    for (i = pos; i >= 0; i--)
    {
        if (ptr[i] == ch)
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

    const_pointer ptr = data();
    for (i = pos; i < size(); i++)
    {
        if (memchr(s, ptr[i], count) != nullptr)
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
    return find_first_of(s, pos, tsStrLen((const char*)s));
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

    const_pointer ptr = data();
    for (i = pos; i < size(); i++)
    {
        if (memchr(s, ptr[i], count) == nullptr)
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
    return find_first_not_of(s, pos, tsStrLen((const char*)s));
}
tsCryptoData::size_type tsCryptoData::find_first_not_of(value_type ch, size_type pos) const
{
    size_type i;

    if (pos >= size())
        return npos;

    const_pointer ptr = data();
    for (i = pos; i < size(); i++)
    {
        if (ptr[i] != ch)
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

    const_pointer ptr = data();
    for (i = pos; i >= 0; --i)
    {
        if (memchr(s, ptr[i], count) != nullptr)
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
    return find_last_of(s, pos, tsStrLen((const char*)s));
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

    const_pointer ptr = data();
    for (i = pos; i >= 0; --i)
    {
        if (memchr(s, ptr[i], count) == nullptr)
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
    return find_last_not_of(s, pos, tsStrLen((const char*)s));
}
tsCryptoData::size_type tsCryptoData::find_last_not_of(value_type ch, size_type pos) const
{
    difference_type i;

    if (pos >= size())
        pos = size() - 1;

    const_pointer ptr = data();
    for (i = pos; i >= 0; --i)
    {
        if (ptr[i] != ch)
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
    bool done = false;
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
                done = true;
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
    ulInSize = tsStrLen(pInput.c_str());

    if (ulInSize == 0)
    {
        return;
    }

    sz = (size_type)(ulInSize / BASE64_DECODE_RATIO) + 1;
    sz += 5; /* make sure that we never have heap damage in case this computation is wrong. */

             /* create the output buffer */
    resize(sz);

    outbuf = data();

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

    ulInSize = tsStrLen(pInput);

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

    p = tsStrTok(str.rawData(), ".", &token);
    while (p != nullptr)
    {
        if (partNumber == 1)
        {
            value = value * 40 + tsStrToInt(p);
        }
        else
        {
            value = tsStrToInt(p);
        }
        if (partNumber != 0)
        {
            encodeOIDPart(*this, value, true);
        }

        partNumber++;
        p = tsStrTok(nullptr, ".", &token);
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
    memmove(&data()[index + count], &data()[index], sizeof(value_type) * (oldsize - index));
    memset(&data()[index], ch, count);
    return *this;
}
tsCryptoData& tsCryptoData::insert(size_type index, char ch)
{
    size_type oldsize = size();

    resize(size() + 1);
    memmove(&data()[index + 1], &data()[index], sizeof(value_type) * (oldsize - index));
    data()[index] = ch;
    return *this;
}
tsCryptoData& tsCryptoData::insert(size_type index, const char* s)
{
    if (s == nullptr)
        throw tscrypto::ArgumentNullException("s");

    size_type oldsize = size();
    size_type count = tsStrLen(s);

    resize(size() + count);
    memmove(&data()[index + count], &data()[index], sizeof(value_type) * (oldsize - index));
    memcpy(&data()[index], s, count);
    return *this;
}
tsCryptoData& tsCryptoData::insert(size_type index, const char* s, size_type count)
{
    if (s == nullptr)
        throw tscrypto::ArgumentNullException("s");

    size_type oldsize = size();

    resize(size() + count);
    memmove(&data()[index + count], &data()[index], sizeof(value_type) * (oldsize - index));
    memcpy(&data()[index], s, count);
    return *this;
}
tsCryptoData& tsCryptoData::insert(size_type index, const tsCryptoStringBase& str)
{
    size_type oldsize = size();
    size_type count = str.size();

    if (count == 0)
        return *this;
    resize(size() + count);
    memmove(&data()[index + count], &data()[index], sizeof(value_type) * (oldsize - index));
    memcpy(&data()[index], str.data(), count);
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
    pointer ptr = data();
    memmove(&ptr[index + iList.size()], &ptr[index], sizeof(value_type) * (oldsize - index));
    for (auto it = iList.begin(); it != iList.end(); ++it)
    {
        ptr[index++] = *it;
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
    data()[last++] = (value_type)(val >> 8);
    data()[last] = (value_type)(val);
    return *this;
}
tsCryptoData &tsCryptoData::assign(int32_t val)
{
    size_type last = 0;

    resize(4);
    pointer ptr = data();
    ptr[last++] = (value_type)(val >> 24);
    ptr[last++] = (value_type)(val >> 16);
    ptr[last++] = (value_type)(val >> 8);
    ptr[last] = (value_type)(val);
    return *this;
}
tsCryptoData &tsCryptoData::assign(int64_t val)
{
    size_type last = 0;

    resize(8);
    pointer ptr = data();
    ptr[last++] = (value_type)(val >> 56);
    ptr[last++] = (value_type)(val >> 48);
    ptr[last++] = (value_type)(val >> 40);
    ptr[last++] = (value_type)(val >> 32);
    ptr[last++] = (value_type)(val >> 24);
    ptr[last++] = (value_type)(val >> 16);
    ptr[last++] = (value_type)(val >> 8);
    ptr[last] = (value_type)(val);
    return *this;
}
tsCryptoData &tsCryptoData::assign(uint16_t val)
{
    size_type last = 0;

    resize(2);
    pointer ptr = data();
    ptr[last++] = (value_type)(val >> 8);
    ptr[last] = (value_type)(val);
    return *this;
}
tsCryptoData &tsCryptoData::assign(uint32_t val)
{
    size_type last = 0;

    resize(4);
    pointer ptr = data();
    ptr[last++] = (value_type)(val >> 24);
    ptr[last++] = (value_type)(val >> 16);
    ptr[last++] = (value_type)(val >> 8);
    ptr[last] = (value_type)(val);
    return *this;
}
tsCryptoData &tsCryptoData::assign(uint64_t val)
{
    size_type last = 0;

    resize(8);
    pointer ptr = data();
    ptr[last++] = (value_type)(val >> 56);
    ptr[last++] = (value_type)(val >> 48);
    ptr[last++] = (value_type)(val >> 40);
    ptr[last++] = (value_type)(val >> 32);
    ptr[last++] = (value_type)(val >> 24);
    ptr[last++] = (value_type)(val >> 16);
    ptr[last++] = (value_type)(val >> 8);
    ptr[last] = (value_type)(val);
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
        tsCryptoString::size_type oldUsed = size();
        resize(oldUsed + objSize);
        memcpy(&data()[oldUsed], obj.c_str(), objSize * sizeof(value_type));
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
    pointer ptr = data();
    for (auto it = list.begin(); it != list.end(); ++it)
    {
        ptr[pos++] = *it;
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
    pointer ptr = data();
    ptr[last++] = (value_type)(val >> 8);
    ptr[last] = (value_type)(val);
    return *this;
}
tsCryptoData &tsCryptoData::append(int32_t val)
{
    size_type last = size();

    resize(size() + 4);
    pointer ptr = data();
    ptr[last++] = (value_type)(val >> 24);
    ptr[last++] = (value_type)(val >> 16);
    ptr[last++] = (value_type)(val >> 8);
    ptr[last] = (value_type)(val);
    return *this;
}
tsCryptoData &tsCryptoData::append(int64_t val)
{
    size_type last = size();

    resize(size() + 8);
    pointer ptr = data();
    ptr[last++] = (value_type)(val >> 56);
    ptr[last++] = (value_type)(val >> 48);
    ptr[last++] = (value_type)(val >> 40);
    ptr[last++] = (value_type)(val >> 32);
    ptr[last++] = (value_type)(val >> 24);
    ptr[last++] = (value_type)(val >> 16);
    ptr[last++] = (value_type)(val >> 8);
    ptr[last] = (value_type)(val);
    return *this;
}
tsCryptoData &tsCryptoData::append(uint16_t val)
{
    size_type last = size();

    resize(size() + 2);
    pointer ptr = data();
    ptr[last++] = (value_type)(val >> 8);
    ptr[last] = (value_type)(val);
    return *this;
}
tsCryptoData &tsCryptoData::append(uint32_t val)
{
    size_type last = size();

    resize(size() + 4);
    pointer ptr = data();
    ptr[last++] = (value_type)(val >> 24);
    ptr[last++] = (value_type)(val >> 16);
    ptr[last++] = (value_type)(val >> 8);
    ptr[last] = (value_type)(val);
    return *this;
}
tsCryptoData &tsCryptoData::append(uint64_t val)
{
    size_type last = size();

    resize(size() + 8);
    pointer ptr = data();
    ptr[last++] = (value_type)(val >> 56);
    ptr[last++] = (value_type)(val >> 48);
    ptr[last++] = (value_type)(val >> 40);
    ptr[last++] = (value_type)(val >> 32);
    ptr[last++] = (value_type)(val >> 24);
    ptr[last++] = (value_type)(val >> 16);
    ptr[last++] = (value_type)(val >> 8);
    ptr[last] = (value_type)(val);
    return *this;
}

tsCryptoData &tsCryptoData::operator+= (const tsCryptoStringBase &obj)
{
    tsCryptoData::size_type len = 0;
    tsCryptoData::size_type oldUsed = size();
    if (obj.size() > 0)
    {
        len = obj.size();
        resize(size() + len);
        memcpy(&data()[oldUsed], obj.data(), len * sizeof(value_type));
    }
    return *this;
}
tsCryptoData &tsCryptoData::operator+= (const char* data) /* zero terminated */
{
    return (*this) += tsCryptoData(data);
}
tsCryptoData &tsCryptoData::operator+= (char setTo)
{
    tsCryptoData::size_type len = 0;
    tsCryptoData::size_type oldUsed = size();
    //	if ( data != nullptr )
    {
        len = 1;

        resize(size() + len);
        data()[oldUsed] = setTo;
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

    diff = memcmp(data(), str.data(), count);
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
    size_type len = tsStrLen(s);
    size_type count = MIN(size(), len);
    int diff = 0;

    diff = memcmp(data(), s, count);
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
    pointer ptr = data();
    uint32_t sz = (uint32_t)size();

    for (unsigned int i = 0; i < (sz >> 1); i++)
    {
        value = ptr[i];
        ptr[i] = ptr[sz - i - 1];
        ptr[sz - i - 1] = value;
    }
}
tsCryptoData &tsCryptoData::XOR(const tsCryptoData &value)
{
    size_type len = value.size();

    if (size() < len)
        resize(len);

    pointer ptr = data();

    for (unsigned int i = 0; i < len; i++)
    {
        ptr[i] ^= value[i];
    }
    return *this;
}
tsCryptoData &tsCryptoData::AND(const tsCryptoData &value)
{
    size_type len = value.size();

    if (size() < len)
        resize(len);

    pointer ptr = data();

    for (unsigned int i = 0; i < len; i++)
    {
        ptr[i] &= value[i];
    }
    return *this;
}
tsCryptoData &tsCryptoData::OR(const tsCryptoData &value)
{
    size_type len = value.size();

    if (size() < len)
        resize(len);

    pointer ptr = data();

    for (unsigned int i = 0; i < len; i++)
    {
        ptr[i] |= value[i];
    }
    return *this;
}
tsCryptoData &tsCryptoData::NOT()
{
    pointer ptr = data();

    for (unsigned int i = 0; i < size(); i++)
    {
        ptr[i] = ~ptr[i];
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
        memmove(&data()[length - oldLen], &data()[0], oldLen);
        memset(data(), value, length - oldLen);
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

    const_pointer ptr = data();

    value = ptr[0];
    tmp.append((value / 40)).append(".").append((value % 40));
    value = 0;
    while (posi < size())
    {
        value = (value << 7) | (ptr[posi] & 0x7f);
        if ((ptr[posi] & 0x80) == 0)
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
        const uint8_t *p = (const uint8_t *)data();

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
        const uint8_t *p = (const uint8_t *)data();

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
    return BOMByteCount(data(), size());
}

size_t tsCryptoData::BOMByteCount(const uint8_t *data, size_t size) const
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
    TSUtf8 *dest;
    const TSUtf16 *src16;
    const TSUtf32 *src32;
    size_t BOMcount = BOMByteCount();

    if (BOMcount > 0)
    {
        switch (EncodingType())
        {
        case encode_Utf16BE:
            src16 = (TSUtf16*)(data() + BOMcount);
            destCount = tsUtf8LenFromUtf16(src16, false);
            tmp.resize(destCount);
            dest = (TSUtf8*)tmp.rawData();
            src16 = (TSUtf16*)(data() + BOMcount);
            tsUtf16BEToUtf8(src16, dest, (uint32_t)tmp.size(), false);
            break;
        case encode_Utf16LE:
            src16 = (TSUtf16*)(data() + BOMcount);
            destCount = tsUtf8LenFromUtf16(src16, false);
            tmp.resize(destCount);
            dest = (TSUtf8*)tmp.rawData();
            src16 = (TSUtf16*)(data() + BOMcount);
            tsUtf16LEToUtf8(src16, dest, (uint32_t)tmp.size(), false);
            break;
        case encode_Utf32BE:
            src32 = (TSUtf32*)(data() + BOMcount);
            destCount = tsUtf8LenFromUtf32(src32, false);
            tmp.resize(destCount);
            dest = (TSUtf8*)tmp.rawData();
            src32 = (TSUtf32*)(data() + BOMcount);
            tsUtf32BEToUtf8(src32, dest, (uint32_t)tmp.size(), false);
            break;
        case encode_Utf32LE:
            src32 = (TSUtf32*)(data() + BOMcount);
            destCount = tsUtf8LenFromUtf32(src32, false);
            tmp.resize(destCount);
            dest = (TSUtf8*)tmp.rawData();
            src32 = (TSUtf32*)(data() + BOMcount);
            tsUtf32LEToUtf8(src32, dest, (uint32_t)tmp.size(), false);
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

    while (posi < size())
    {
        len = size() - posi;
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
    if (!base64Encode(base64Url ? dtableUrl : dtableNormal, padWithEquals, data(), size(), nullptr, &len))
        outValue.erase();
    else
    {
        outValue.resize(len);
        if (!base64Encode(base64Url ? dtableUrl : dtableNormal, padWithEquals, data(), size(), outValue.rawData(), &len) ||
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
    pointer ptr = data();

    while (offset >= 0)
    {
        tmp = ptr[offset] + step;
        ptr[offset] = (value_type)tmp;
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
    pointer ptr = data();

    while (offset >= 0)
    {
        tmp = ptr[offset] - step;
        ptr[offset] = (value_type)tmp;
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
    memcpy(data(), obj.data(), size());
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
