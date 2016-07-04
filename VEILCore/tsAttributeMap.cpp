//	Copyright (c) 2016, TecSec, Inc.
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
tsAttributeMap::tsAttributeMap()
{
	m_list = tscrypto::CreateContainer<__tsAttributeMapItem>();
}

/// <returns>
/// </returns>
/// <summary>
/// 	<para>Initializes an instance of the <see cref="tsAttributeMap" /> class.</para>
/// </summary>
/// <param name="obj">
/// </param>
tsAttributeMap::tsAttributeMap(const tsAttributeMap &obj)
{
	copyFrom (obj);
}

/// <summary>
/// </summary>
/// <returns>
/// </returns>
tsAttributeMap::~tsAttributeMap()
{
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

/// <summary>
/// </summary>
/// <returns>
/// </returns>
size_t tsAttributeMap::count() const
{
	return m_list->size();
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
	return m_list->at(index).m_value;
}

/// <summary>
/// </summary>
/// <returns>
/// </returns>
/// <param name="name">
/// </param>
tscrypto::tsCryptoString tsAttributeMap::item(const tscrypto::tsCryptoString &name) const
{
	auto item = std::find_if(m_list->begin(), m_list->end(), [&name](const __tsAttributeMapItem& item)->bool{ return item.m_name == name.c_str(); });
	
	if (item == m_list->end())
		return "";
	return item->m_value;
}

int tsAttributeMap::itemAsNumber(const tscrypto::tsCryptoString &name, int defaultValue) const
{
	auto item = std::find_if(m_list->begin(), m_list->end(), [&name](const __tsAttributeMapItem& item)->bool{ return item.m_name == name.c_str(); });

	if (item == m_list->end())
        return defaultValue;
    return atoi(item->m_value.c_str());
}

bool tsAttributeMap::itemAsBoolean(const tscrypto::tsCryptoString &name, bool defaultValue) const
{
	auto item = std::find_if(m_list->begin(), m_list->end(), [&name](const __tsAttributeMapItem& item)->bool{ return item.m_name == name.c_str(); });

	if (item == m_list->end())
        return defaultValue;
	tscrypto::tsCryptoString tmp = item->m_value;
	tmp.Trim();
	if (tmp.size() == 0)
		return defaultValue;
	if (_stricmp(tmp.c_str(), "T") == 0 ||
		_stricmp(tmp.c_str(), "TRUE") == 0 ||
		_stricmp(tmp.c_str(), "Y") == 0 ||
		_stricmp(tmp.c_str(), "YES") == 0 ||
		atoi(tmp.c_str()) != 0)
	{
		return true;
	}
    return false;
}

bool tsAttributeMap::hasItem(const tscrypto::tsCryptoString &name) const
{
	auto item = std::find_if(m_list->begin(), m_list->end(), [&name](const __tsAttributeMapItem& item)->bool{ return item.m_name == name.c_str(); });
	return item != m_list->end();
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
	return m_list->at(index).m_name;
}

/// <summary>
/// </summary>
/// <returns>
/// </returns>
/// <param name="name">
/// </param>
/// <param name="value">
/// </param>
bool tsAttributeMap::AddItem(const tscrypto::tsCryptoString &name, const tscrypto::tsCryptoString &value)
{
	auto it = std::find_if(m_list->begin(), m_list->end(), [&name](const __tsAttributeMapItem& item)->bool{ return item.m_name == name.c_str(); });
	if (it == m_list->end())
	{
		__tsAttributeMapItem item;
		item.m_value = value;
		item.m_name = name;
		m_list->push_back(item);
	}
	else
		it->m_value = value;
	return true;
}

bool tsAttributeMap::AddItem(const tscrypto::tsCryptoString &name, int value)
{
	auto it = std::find_if(m_list->begin(), m_list->end(), [&name](const __tsAttributeMapItem& item)->bool{ return item.m_name == name.c_str(); });
	char buff[20];

	_snprintf_s(buff, sizeof(buff) / sizeof(char), sizeof(buff) / sizeof(char), ("%d"), value);
	if (it == m_list->end())
	{
		__tsAttributeMapItem item;

		RemoveItem(name);
		item.m_value = buff;
		item.m_name = name;
		m_list->push_back(item);
	}
	else
		it->m_value = buff;
	return true;
}

/// <summary>
/// </summary>
/// <returns>
/// </returns>
void tsAttributeMap::ClearAll ()
{
	m_list->clear();
}

/// <summary>
/// </summary>
/// <returns>
/// </returns>
/// <param name="index">
/// </param>
void tsAttributeMap::RemoveItem(size_t index)
{
	auto it = m_list->begin();
	std::advance(it, index);
	m_list->erase(it);
}

/// <summary>
/// </summary>
/// <returns>
/// </returns>
/// <param name="name">
/// </param>
void tsAttributeMap::RemoveItem(const tscrypto::tsCryptoString &name)
{
	auto item = std::find_if(m_list->begin(), m_list->end(), [&name](__tsAttributeMapItem& item)->bool{ return item.m_name == name.c_str(); });
	if ( item != m_list->end() )
	{
		m_list->erase(item);
	}
}
/// <summary>
/// </summary>
/// <returns>
/// </returns>
/// <param name="xml">
/// </param>
void tsAttributeMap::ToXML(tscrypto::tsCryptoString &xml) const
{
	tscrypto::tsCryptoString value;

	for (auto item : *m_list)
	{
		if (xml.size() > 0)
			xml += " ";
		xml += item.m_name;
		xml += "=\"";
		TSPatchValueForXML(item.m_value, value);
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
	m_list = obj.m_list->cloneContainer();
}

void tsAttributeMap::remove_if(std::function<bool(const __tsAttributeMapItem& item)> func)
{
	ptrdiff_t i;

	for (i = m_list->size() - 1; i >= 0; i--)
	{
		if (func(m_list->at(i)))
		{
			auto it = m_list->begin();
			std::advance(it, i);
			m_list->erase(it);
		}
	}
}

void tsAttributeMap::foreach(std::function<void(__tsAttributeMapItem& item)> func)
{
	for (auto item : *m_list)
	{ 
		func(item); 
	}
}

void tsAttributeMap::foreach(std::function<void(const __tsAttributeMapItem& item)> func) const
{
	for (auto item : *m_list)
	{ 
		func(item); 
	}
}

tscrypto::tsCryptoString tsAttributeMap::first_value_that(std::function<bool(const __tsAttributeMapItem& item)> func) const
{
	auto item = std::find_if(m_list->begin(), m_list->end(), [&func](const __tsAttributeMapItem& item)->bool{ return func(item); });
	if (item == m_list->end())
		return "";
	return item->m_value;
}

tscrypto::tsCryptoString tsAttributeMap::first_name_that(std::function<bool(const __tsAttributeMapItem& item)> func) const
{
	auto item = std::find_if(m_list->begin(), m_list->end(), [&func](const __tsAttributeMapItem& item)->bool{ return func(item); });
	if (item == m_list->end())
		return "";
	return item->m_value;
}

void tsAttributeMap::ToJSON(JSONObject& obj) const
{
	foreach([&obj](const __tsAttributeMapItem& item) { obj.add(item.m_name, item.m_value);});
}
tscrypto::tsCryptoString tsAttributeMap::tag(size_t index) const
{
	if (index >= count())
		return "";
	return m_list->at(index).m_tag;
}

void tsAttributeMap::tag(size_t index, const tscrypto::tsCryptoString& setTo)
{
	if (index >= count())
		return ;
	m_list->at(index).m_tag = setTo;
}
tscrypto::tsCryptoString tsAttributeMap::tag(const tscrypto::tsCryptoString &name) const
{
	auto item = std::find_if(m_list->begin(), m_list->end(), [&name](const __tsAttributeMapItem& item)->bool{ return item.m_name == name.c_str(); });

	if (item == m_list->end())
		return "";
	return item->m_tag;
}

void tsAttributeMap::tag(const tscrypto::tsCryptoString &name, const tscrypto::tsCryptoString& setTo)
{
	auto item = std::find_if(m_list->begin(), m_list->end(), [&name](const __tsAttributeMapItem& item)->bool{ return item.m_name == name.c_str(); });

	if (item == m_list->end())
		return ;
	item->m_tag = setTo;
}