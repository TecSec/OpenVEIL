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

/// <returns>
/// </returns>
/// <summary>
/// 	<para>Initializes an instance of the <see cref="tsAttributeMap" /> class.</para>
/// </summary>
tsAttributeMap::tsAttributeMap() : _list(tsCreateNameValueList())
{
}

tsAttributeMap::tsAttributeMap(TSNAME_VALUE_LIST list) : _list(tsCreateNameValueList())
{
    tsMoveNameValueListData(list, _list);
}
tsAttributeMap::tsAttributeMap(TSNAME_VALUE_LIST&& list) : _list(list)
{
    list = NULL;
}
/// <returns>
/// </returns>
/// <summary>
/// 	<para>Initializes an instance of the <see cref="tsAttributeMap" /> class.</para>
/// </summary>
/// <param name="obj">
/// </param>
tsAttributeMap::tsAttributeMap(const tsAttributeMap &obj) : _list(tsCreateNameValueList())
{
	copyFrom (obj);
}
tsAttributeMap::tsAttributeMap(tsAttributeMap &&obj) : _list(obj._list)
{
    obj._list = tsCreateNameValueList();
}

/// <summary>
/// </summary>
/// <returns>
/// </returns>
tsAttributeMap::~tsAttributeMap()
{
    tsFreeNameValueList(&_list);
}

//void *tsAttributeMap::operator new(size_t bytes) 
//{ 
//    return FrameworkAllocator(bytes); 
//}
//
//void tsAttributeMap::operator delete(void *ptr) 
//{ 
//    return FrameworkDeallocator(ptr); 
//}

/// <summary>
/// </summary>
/// <returns>
/// </returns>
/// <param name="obj">
/// </param>
tsAttributeMap &tsAttributeMap::operator = (const tsAttributeMap &obj)
{
	if ( this != &obj )
		copyFrom(obj);
	return *this;
}
tsAttributeMap &tsAttributeMap::operator = (tsAttributeMap &&obj)
{
	if (this != &obj)
		moveFrom(std::move(obj));
	return *this;
}

/// <summary>
/// </summary>
/// <returns>
/// </returns>
size_t tsAttributeMap::count() const
{
	return tsNameValueUsed(_list);
}

/// <summary>
/// </summary>
/// <returns>
/// </returns>
/// <param name="index">
/// </param>
tscrypto::tsCryptoString tsAttributeMap::item(size_t index) const
{
	if ( index >= count() )
		return "";
    return tsGetNameValueValueByIndex(_list, (uint32_t)index);
}

/// <summary>
/// </summary>
/// <returns>
/// </returns>
/// <param name="name">
/// </param>
tscrypto::tsCryptoString tsAttributeMap::item(const tscrypto::tsCryptoStringBase &name) const
{
    return tsGetNameValueValueByName(_list, name.c_str());
}

int tsAttributeMap::itemAsNumber(const tscrypto::tsCryptoStringBase &name, int defaultValue) const
{
    const char* c = tsGetNameValueValueByName(_list, name.c_str());

    if (c == nullptr)
        return defaultValue;
	return tsStrToInt(c);
}

bool tsAttributeMap::itemAsBoolean(const tscrypto::tsCryptoStringBase &name, bool defaultValue) const
{
    const char* c = tsGetNameValueValueByName(_list, name.c_str());

    if (c == nullptr)
        return defaultValue;
	tsCryptoString tmp = c;
	tmp.Trim();
	if (tmp.size() == 0)
		return defaultValue;
    return tsStrToBool(tmp.c_str());
}

bool tsAttributeMap::hasItem(const tscrypto::tsCryptoStringBase &name) const
{
    const char* c = tsGetNameValueValueByName(_list, name.c_str());

    return (c != nullptr);
}

/// <summary>
/// </summary>
/// <returns>
/// </returns>
/// <param name="index">
/// </param>
tscrypto::tsCryptoString tsAttributeMap::name(size_t index) const
{
	if ( index >= count() )
		return "";
    return tsGetNameValueName(_list, (uint32_t)index);
}

/// <summary>
/// </summary>
/// <returns>
/// </returns>
/// <param name="name">
/// </param>
/// <param name="value">
/// </param>
bool tsAttributeMap::AddItem(const tscrypto::tsCryptoStringBase &name, const tscrypto::tsCryptoStringBase &value)
{
    return tsAddNameValue(_list, name.c_str(), -1, value.c_str(), -1);
}

bool tsAttributeMap::AddItem(const tscrypto::tsCryptoStringBase &name, int value)
{
	char buff[20];

	tsSnPrintf(buff, sizeof(buff) / sizeof(char), "%d", value);
    return tsAddNameValue(_list, name.c_str(), -1, buff, -1);
}

/// <summary>
/// </summary>
/// <returns>
/// </returns>
void tsAttributeMap::ClearAll ()
{
    tsEmptyNameValues(_list);
}

/// <summary>
/// </summary>
/// <returns>
/// </returns>
/// <param name="index">
/// </param>
void tsAttributeMap::RemoveItem(size_t index)
{
    tsRemoveNameValueByIndex(_list, (uint32_t)index);
}

/// <summary>
/// </summary>
/// <returns>
/// </returns>
/// <param name="name">
/// </param>
void tsAttributeMap::RemoveItem(const tscrypto::tsCryptoStringBase &name)
{
    tsRemoveNameValueByName(_list, name.c_str());
}
/// <summary>
/// </summary>
/// <returns>
/// </returns>
/// <param name="xml">
/// </param>
void tsAttributeMap::ToXML(tscrypto::tsCryptoStringBase &xml) const
{
	tsCryptoString value;
    uint32_t _count = (uint32_t)count();

    for (uint32_t i = 0; i < _count; i++)
	{
		if (xml.size() > 0)
			xml += " ";
		xml += name(i);
		xml += "=\"";
		TSPatchValueForXML(item(i), value);
		xml += value;
		xml += "\"";
	}
}

/// <summary>
/// </summary>
/// <returns>
/// </returns>
/// <param name="obj">
/// </param>
void tsAttributeMap::copyFrom(const tsAttributeMap &obj)
{
    ClearAll();
    tsFreeNameValueList(&_list);

    _list = tsDuplicateNameValueList(obj._list);
}
void tsAttributeMap::moveFrom(tsAttributeMap &&obj)
{
	_list = std::move(obj._list);
    obj._list = nullptr;
}

void tsAttributeMap::remove_if(std::function<bool(const char* name, const char* item)> func)
{
	ptrdiff_t i;

	for (i = count() - 1; i >= 0; i--)
	{
		if (func(tsGetNameValueName(_list, (uint32_t)i), tsGetNameValueValueByIndex(_list, (uint32_t)i)))
		{
            tsRemoveNameValueByIndex(_list, (uint32_t)i);
		}
	}
}

void tsAttributeMap::foreach(std::function<void(const char* name, const char* item)> func)
{
    for (uint32_t i = 0; i < count(); i++)
	{ 
        func(tsGetNameValueName(_list, i), tsGetNameValueValueByIndex(_list, i));
	}
}

void tsAttributeMap::foreach(std::function<void(const char* name, const char* item)> func) const
{
    for (uint32_t i = 0; i < count(); i++)
	{ 
        func(tsGetNameValueName(_list, i), tsGetNameValueValueByIndex(_list, i));
	}
}

tsCryptoString tsAttributeMap::first_value_that(std::function<bool(const char* name, const char* item)> func) const
{
    for (uint32_t i = 0; i < count(); i++)
    {
        if (func(tsGetNameValueName(_list, i), tsGetNameValueValueByIndex(_list, i)))
            return tsGetNameValueValueByIndex(_list, i);
    }
		return "";
}

tsCryptoString tsAttributeMap::first_name_that(std::function<bool(const char* name, const char* item)> func) const
{
    for (uint32_t i = 0; i < count(); i++)
    {
        if (func(tsGetNameValueName(_list, i), tsGetNameValueValueByIndex(_list, i)))
            return tsGetNameValueName(_list, i);
    }
		return "";
}

void tsAttributeMap::ToJSON(JSONObject& obj) const
{
    foreach([&obj](const char* name, const char* item) { obj.add(name, item); });
}
tsCryptoString tsAttributeMap::tag(size_t index) const
{
	if (index >= count())
		return "";

    return tsGetNameValueTagByIndex(_list, (uint32_t)index);
}

void tsAttributeMap::tag(size_t index, const tsCryptoStringBase& setTo)
{
	if (index >= count())
		return ;
    tsSetNameValueTagByIndex(_list, (uint32_t)index, setTo.c_str(), -1);
}
tsCryptoString tsAttributeMap::tag(const tsCryptoStringBase &name) const
{
    return tsGetNameValueTagByName(_list, name.c_str());
}

void tsAttributeMap::tag(const tsCryptoStringBase &name, const tsCryptoStringBase& setTo)
{
    tsSetNameValueTagByName(_list, name.c_str(), setTo.c_str(), -1);
}
bool tsAttributeMap::RenameItem(const tsCryptoStringBase &oldName, const tsCryptoStringBase &newName)
{
    return tsRenameNameValue(_list, oldName.c_str(), newName.c_str());
}
