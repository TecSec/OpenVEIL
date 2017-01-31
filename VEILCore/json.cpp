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
#include "core/CryptoUtf16.h"

using namespace tscrypto;

JSONFieldList tscrypto::CreateJSONFieldList()
{
	return CreateContainer<JSONField>();
}

static JSONElement* findRoot(JSONElement* startFrom)
{
	while (startFrom != nullptr && startFrom->Parent() != nullptr)
		startFrom = startFrom->Parent();
	return startFrom;
}

static const char *eatWhitespace(const char *query)
{
	while (query && (query[0] == ' ' || query[0] == '\t' || query[0] == '\r' || query[0] == '\n'))
		query++;
	return query;
}

static bool parseFieldName(const char *&posi, tsCryptoStringBase &name)
{
	name.clear();
	if (*posi == '.' && posi[1] != '.')
	{
		posi++;
		while (
			(*posi >= 'A' && *posi <= 'Z') ||
			(*posi >= 'a' && *posi <= 'z') ||
			(*posi >= '0' && *posi <= '9' && name.size() > 0) ||
			*posi == '_')
		{
			name += *posi;
			posi++;
		}
	}
	else if (*posi == '[' && posi[1] == '\'')
	{
		posi += 2;
		while (*posi && posi[0] != '\'')
		{
			name += *posi;
			posi++;
		}
		if (posi[0] != '\'' || posi[1] != ']')
		{
			name.clear();
			return false;
		}
		posi += 2;
	}
	else
		return false;
	return true;
}

static void processFormula(JSONElement* startNode, const tsCryptoStringBase& formula, JsonSearchResultList &list)
{
	// TODO:  Implement me when we support Formulas

}

static void processIndexing(JSONElement* startNode, tsCryptoStringList parts, JsonSearchResultList &list)
{
	ptrdiff_t start = 0, end = 0x7FFFFFFF, step = 1;
	size_t count;

	if (!list)
		list = CreateContainer<JSONElement*>();

	if (startNode == nullptr || startNode->ElementType() != jet_Field)
		return;

	JSONField *fld = reinterpret_cast<JSONField*>(startNode);

	if (fld == nullptr)
		return;
	if (fld->Type() != JSONField::jsonArray)
		return;

	JSONFieldList& ary = fld->AsArray();
	count = ary->size();

	if (parts->size() > 0 && parts->at(0).size() != 0)
	{
		// TODO:  Possibly support functions here
		start = TsStrToInt(parts->at(0));
	}
	if (parts->size() > 1 && parts->at(1).size() != 0)
	{
		// TODO:  Possibly support functions here
		end = TsStrToInt(parts->at(1));
	}
	if (parts->size() > 2 && parts->at(2).size() != 0)
	{
		// TODO:  Possibly support functions here
		step = TsStrToInt(parts->at(2));
	}

	if (start < 0)
	{
		start = count + start;
	}

	if (end > (ptrdiff_t)count)
		end = count;

	if (end < 0)
		end = count + end;

	if (step == 0)
		return;
	if (step < 0)
	{
		if (start < end)
			start = end;
		for (ptrdiff_t i = start; i > end; i += step)
		{
			list->push_back(&ary->at(i));
		}
	}
	else
	{
		if (start > end)
			start = end;
		for (ptrdiff_t i = start; i < end; i += step)
		{
			list->push_back(&ary->at(i));
		}
	}
}

static void RecursivelyFindNodeByName(JSONElement* startNode, const tsCryptoStringBase& nodeName, JsonSearchResultList &list)
{
	if (startNode->ElementType() == jet_Field)
	{
		// Field
		JSONField *fld = reinterpret_cast<JSONField*>(startNode);

		if (!list)
			list = CreateContainer<JSONElement*>();

		if (fld->Type() == JSONField::jsonObject)
		{
			JSONObject& obj = fld->AsObject();

			if (obj.hasField(nodeName))
			{
				list->push_back(&obj.field(nodeName));
			}
			obj.foreach([&list, &nodeName](JSONField& fld) {
				if (fld.Name() != nodeName)
				{
					if (fld.Type() == JSONField::jsonArray || fld.Type() == JSONField::jsonObject)
					{
						RecursivelyFindNodeByName(&fld, nodeName, list);
					}
				}
			});
		}
		else if (fld->Type() == JSONField::jsonArray)
		{
			JSONFieldList& ary = fld->AsArray();

			for (auto fld1 : *ary)
			{
				RecursivelyFindNodeByName(&fld1, nodeName, list);
			}
		}
		else
		{
			return;
		}
	}
	else
	{
		// Object
		JSONObject *obj = reinterpret_cast<JSONObject*>(startNode);

		if (obj->hasField(nodeName))
		{
			list->push_back(&obj->field(nodeName));
		}
		obj->foreach([&list, &nodeName](JSONField& fld) {
			if (fld.Name() != nodeName)
			{
				if (fld.Type() == JSONField::jsonArray || fld.Type() == JSONField::jsonObject)
				{
					RecursivelyFindNodeByName(&fld, nodeName, list);
				}
			}
		});
	}
}

static void processNode(JSONElement* startNode, const char *posi, JsonSearchResultList &list, bool createNode)
{
	tsCryptoString nodeName;
	size_t count;
	JsonSearchResultList nodesToTest = CreateContainer<JSONElement*>();

	if (!list)
		list = CreateContainer<JSONElement*>();

	if (posi[0] == '.' && posi[1] == '.')
	{
		// Recursive search for nodes of some name.
		posi += 2;
		if (!parseFieldName(posi, nodeName))
			return;

		// Now perform the recursive search here
		RecursivelyFindNodeByName(startNode, nodeName, nodesToTest);
	}
	else if (posi[0] == '*')
	{
		posi++;
		if (startNode->ElementType() == jet_Field)
		{
			// Field
			JSONField *fld = reinterpret_cast<JSONField*>(startNode);

			if (fld->Type() == JSONField::jsonObject)
			{
				JSONObject& obj = fld->AsObject();

				obj.foreach([&nodesToTest](JSONField& fld) { nodesToTest->push_back(&fld); });
			}
			else if (fld->Type() == JSONField::jsonArray)
			{
				JSONFieldList& ary = fld->AsArray();

				for (auto fld1 : *ary)
				{
					nodesToTest->push_back(&fld1);
				}
			}
			else
			{
				return;
			}
		}
		else
		{
			// Object
			JSONObject *obj = reinterpret_cast<JSONObject*>(startNode);

			obj->foreach([&nodesToTest](JSONField& fld) { nodesToTest->push_back(&fld); });
		}
	}
	else if (posi[0] == '[' && posi[1] == '*' && posi[2] == ']')
	{
		posi += 3;
		// Handle the select all elements in an array
		if (startNode->ElementType() == jet_Field)
		{
			JSONField* fld = reinterpret_cast<JSONField*>(startNode);

			if (fld->Type() == JSONField::jsonArray)
			{
				JSONFieldList& ary = fld->AsArray();

				for (auto fld1 : *ary)
				{
					nodesToTest->push_back(&fld1);
				}
			}
		}
	}
	else if (posi[0] == '[' && posi[1] == ',' && posi[2] == ']')
	{
		list->push_back(startNode);
		return;
	}
	else if (posi[0] == '[' && posi[1] == '?')
	{
		tsCryptoString formula;

		// This is where we process formulas
		posi += 2;
		while (*posi && *posi != ']')
		{
			formula.append(*posi);
			posi++;
		}
		if (*posi != ']')
			return;
		posi++;

		processFormula(startNode, formula, nodesToTest);
	}
	else if (posi[0] == '[' && posi[1] != '\'')
	{
		// This is where we process arrays
		posi++;
		tsCryptoString indexValues;

		// This is where we process formulas
		posi += 2;
		while (*posi && *posi != ']')
		{
			indexValues.append(*posi);
			posi++;
		}
		if (*posi != ']')
			return;
		posi++;

		tsCryptoStringList parts = indexValues.split(":");

		processIndexing(startNode, parts, nodesToTest);
	}
	else if (parseFieldName(posi, nodeName))
	{
		if (startNode->ElementType() == jet_Field)
		{
			// Field
			JSONField *fld = reinterpret_cast<JSONField*>(startNode);

			if (fld->Type() == JSONField::jsonNull && createNode)
			{
				// Must be creating a chain of objects
				fld->Value(JSONObject());
			}
			if (fld->Type() == JSONField::jsonObject)
			{
				JSONObject& obj = fld->AsObject();

				if (obj.hasField(nodeName))
				{
					nodesToTest->push_back(&obj.field(nodeName));
				}
				else if (createNode)
				{
					JSONField fld(nodeName);
					obj.add(fld);
					nodesToTest->push_back(&obj.field(nodeName));
				}
			}
		}
		else
		{
			// Object
			JSONObject *obj = reinterpret_cast<JSONObject*>(startNode);

			if (obj->hasField(nodeName))
			{
				nodesToTest->push_back(&obj->field(nodeName));
			}
			else if (createNode)
			{
				JSONField fld(nodeName);
				obj->add(fld);
				nodesToTest->push_back(&obj->field(nodeName));
			}
		}
	}

	if (*posi == 0 || (posi[0] == '[' && posi[1] == ',' && posi[2] == ']'))
	{
		count = nodesToTest->size();
		for (size_t i = 0; i < count; i++)
		{
			list->push_back(nodesToTest->at(i));
		}
	}

	count = nodesToTest->size();
	for (size_t i = 0; i < count; i++)
	{
		processNode(nodesToTest->at(i), posi, list, createNode);
	}
}

static const char *processStartNode(JSONElement* startNode, const char *posi, JsonSearchResultList &list, bool createNode)
{
	tsCryptoString name;
	JsonSearchResultList nodesToTest = CreateContainer<JSONElement*>();

	if (posi[0] == '$')
	{
		posi++;

		startNode = findRoot(startNode);

		if (posi[0] == 0)
		{
			nodesToTest->push_back(startNode);
		}
		else
		{
			nodesToTest->push_back(startNode);
		}
	}
	else if (posi[0] == '@')
	{
		posi += 1;
		nodesToTest->push_back(startNode);
	}
	else
	{
		nodesToTest->push_back(startNode);
	}

	//
	// We now have the starting point.  Start the search. 
	//

	if (posi[0] == 0)
	{
		size_t count = nodesToTest->size();
		size_t i;

		for (i = 0; i < count; i++)
		{
			list->push_back(nodesToTest->at(i));
		}
		return posi;
	}
	else if (posi[0] == '[' && posi[1] == ',' && posi[2] == ']')
	{
		size_t count = nodesToTest->size();
		size_t i;

		for (i = 0; i < count; i++)
		{
			list->push_back(nodesToTest->at(i));
		}
		return posi;
	}

	//
	// Now process subnodes...
	//

	size_t i;
	size_t count = nodesToTest->size();

	for (i = 0; i < count; i++)
	{
		processNode(nodesToTest->at(i), posi, list, createNode);
	}

	if (!createNode)
	{
		while (*posi != 0 && !(posi[0] == '[' && posi[1] == ',' && posi[2] == ']'))
		{
			posi++;
		}
	}
	return posi;
}

static JsonSearchResultList jsonPath(JSONElement* callingElement, const tsCryptoStringBase& _path, bool createNode)
{
	JsonSearchResultList list;
	const char *p = _path.data();

	if (callingElement == nullptr)
		return list;

	p = processStartNode(callingElement, p, list, createNode);

	//
	// We now have the starting point.  Start the search.  NOTE:  we do not support attributes outside of a predicate
	//

	p = eatWhitespace(p);

	if (createNode)
	{
		if (p[0] == 0)
		{
			return list;
		}
		while (p[0] == '[' && p[1] == ',' && p[2] == ']')
		{
			p += 3;
			p = eatWhitespace(p);
			p = processStartNode(callingElement, p, list, false);
		}
	}

	return list;
}

JSONField::JSONField() :
	_type(jsonNull),
	_numberVal(0),
	_boolVal(false),
	_isNull(true),
	_objectVal(nullptr)
{
}
JSONField::JSONField(const tsCryptoStringBase& name) :
	_type(jsonNull),
	_name(name),
	_numberVal(0),
	_boolVal(false),
	_isNull(true),
	_objectVal(nullptr)
{
}
JSONField::JSONField(const tsCryptoStringBase& name, const tsCryptoStringBase& value) :
	_type(jsonNull),
	_name(name),
	_numberVal(0),
	_boolVal(false),
	_isNull(true),
	_objectVal(nullptr)
{
	Value(value);
}
JSONField::JSONField(const tsCryptoStringBase& name, const char* value) :
	_type(jsonNull),
	_name(name),
	_numberVal(0),
	_boolVal(false),
	_isNull(true),
	_objectVal(nullptr)
{
	Value(value);
}
JSONField::JSONField(const tsCryptoStringBase& name, bool value) :
	_type(jsonNull),
	_name(name),
	_numberVal(0),
	_boolVal(false),
	_isNull(true),
	_objectVal(nullptr)
{
	Value(value);
}
JSONField::JSONField(const tsCryptoStringBase& name, int64_t value) :
	_type(jsonNull),
	_name(name),
	_numberVal(0),
	_boolVal(false),
	_isNull(true),
	_objectVal(nullptr)
{
	Value(value);
}
JSONField::JSONField(const tsCryptoStringBase& name, const JSONObject& value) :
	_type(jsonNull),
	_name(name),
	_numberVal(0),
	_boolVal(false),
	_isNull(true),
	_objectVal(nullptr)
{
	Value(value);
}
JSONField::JSONField(const tsCryptoStringBase& name, JSONObject&& value) :
	_type(jsonNull),
	_name(name),
	_numberVal(0),
	_boolVal(false),
	_isNull(true),
	_objectVal(nullptr)
{
	Value(std::move(value));
}
JSONField::JSONField(const tsCryptoStringBase& name, const JSONFieldList& value) :
	_type(jsonNull),
	_name(name),
	_numberVal(0),
	_boolVal(false),
	_isNull(true),
	_objectVal(nullptr)
{
	Value(value);
}
JSONField::~JSONField()
{
	if (_objectVal != nullptr)
		delete _objectVal;
	_objectVal = nullptr;
	_type = (jsonNull);
	_numberVal = (0);
	_boolVal = (false);
	_isNull = (true);
}
JSONField::JSONField(const JSONField& obj) :
	_type(obj._type),
	_name(obj._name),
	_numberVal(obj._numberVal),
	_boolVal(obj._boolVal),
	_isNull(obj._isNull),
	_objectVal(nullptr)
{
	switch (_type)
	{
	case jsonArray:
		_arrayVal = obj._arrayVal;
		FixLineage();
		break;
	case jsonString:
		_stringVal = obj._stringVal;
		break;
	case jsonObject:
		_objectVal = new JSONObject(*obj._objectVal);
		_objectVal->Parent(this);
		break;
	default:
		break;
	}
}
JSONField::JSONField(JSONField&& obj) :
	_type(obj._type),
	_name(std::move(obj._name)),
	_numberVal(obj._numberVal),
	_boolVal(obj._boolVal),
	_isNull(obj._isNull),
	_objectVal(nullptr)
{
	switch (_type)
	{
	case jsonArray:
		_arrayVal = std::move(obj._arrayVal);
		FixLineage();
		break;
	case jsonString:
		_stringVal = std::move(obj._stringVal);
		break;
	case jsonObject:
		_objectVal = obj._objectVal;
		_objectVal->Parent(this);
		obj._objectVal = nullptr;
		break;
	default:
		break;
	}
	_type = (obj._type);
	_numberVal = (obj._numberVal);
	_boolVal = (obj._boolVal);
	_isNull = (obj._isNull);
}
JSONField& JSONField::operator=(const JSONField& obj)
{
	if (&obj != this)
	{
		clear();
		_type = (obj._type);
		_name = (obj._name);
		_numberVal = (obj._numberVal);
		_boolVal = (obj._boolVal);
		_isNull = (obj._isNull);

		switch (_type)
		{
		case jsonArray:
			_arrayVal = obj._arrayVal;
			FixLineage();
			break;
		case jsonString:
			_stringVal = obj._stringVal;
			break;
		case jsonObject:
			_objectVal = new JSONObject(*obj._objectVal);
			_objectVal->Parent(this);
			break;
		default:
			break;
		}
	}
	return *this;
}
JSONField& JSONField::operator=(JSONField&& obj)
{
	if (&obj != this)
	{
		clear();

		_type = (obj._type);
		_name = (std::move(obj._name));
		_numberVal = (obj._numberVal);
		_boolVal = (obj._boolVal);
		_isNull = (obj._isNull);
		_objectVal = (nullptr);

		switch (_type)
		{
		case jsonArray:
			_arrayVal = std::move(obj._arrayVal);
			FixLineage();
			break;
		case jsonString:
			_stringVal = std::move(obj._stringVal);
			break;
		case jsonObject:
			_objectVal = obj._objectVal;
			_objectVal->Parent(this);
			obj._objectVal = nullptr;
			break;
		default:
			break;
		}
		obj.clear();
	}
	return *this;
}
bool JSONField::operator==(const JSONField& obj) const
{
	if (_type != obj._type)
		return false;

	switch (_type)
	{
	case jsonNull:
		return true;
	case jsonBool:
		return _boolVal == obj._boolVal;
	case jsonNumber:
		return _numberVal == obj._numberVal;
	case jsonArray:
		return _arrayVal == obj._arrayVal;
	case jsonString:
		return _stringVal == obj._stringVal;
	case jsonObject:
		if (_objectVal == nullptr && obj._objectVal != nullptr)
			return false;
		if (obj._objectVal == nullptr && _objectVal != nullptr)
			return false;
		if (_objectVal == nullptr && obj._objectVal == nullptr)
			return true;
		return *_objectVal == *obj._objectVal;
	}
	return false;
}
JSONField::jsonFieldType JSONField::Type() const
{
	return _type;
}
tsCryptoString JSONField::Name() const
{
	return _name;
}
void JSONField::Name(const tsCryptoStringBase& setTo)
{
	_name = setTo;
}
tsCryptoString JSONField::AsString() const
{
	switch (_type)
	{
	case jsonNull:
		return "";
	case jsonBool:
		return _boolVal ? "true" : "false";
	case jsonNumber:
		return tsCryptoString().append(_numberVal);
	case jsonArray:
	{
		tsCryptoString tmp;

		tmp.append("[");

		for (auto fld : *_arrayVal)
		{
			if (tmp.size() > 1)
				tmp.append(",");
			tmp.append(fld.ToJSON());
		}

		tmp.append("]");
		return tmp;
	}
	case jsonString:
		return _stringVal;
	case jsonObject:
		if (_objectVal == nullptr)
			return "{}";
		return _objectVal->ToJSON();
	}
	return "";
}
tsCryptoString JSONField::ToJSON() const
{
	switch (_type)
	{
	case jsonNull:
		return "null";
	case jsonBool:
		return _boolVal ? "true" : "false";
	case jsonNumber:
		return tsCryptoString().append(_numberVal);
	case jsonArray:
	{
		tsCryptoString tmp;

		tmp.append("[");

		for (auto fld : *_arrayVal)
		{
			if (tmp.size() > 1)
				tmp.append(",");
			tmp.append(fld.ToJSON());
		}

		tmp.append("]");
		return tmp;
	}
	case jsonString:
	{
		tsCryptoString tmp(_stringVal);

		tmp.Replace("\\", "\\\\").Replace("\b", "\\b").Replace("\r", "\\r").Replace("\n", "\\n").Replace("\f", "\\f").Replace("\t", "\\t").Replace("\"", "\\\"");
		return "\"" + tmp + "\"";
	}
	case jsonObject:
		if (_objectVal == nullptr)
			return "{}";
		return _objectVal->ToJSON();
	}
	return "";
}
bool JSONField::AsBool(bool defaultValue) const
{
	switch (_type)
	{
	case jsonNull:
		return defaultValue;
	case jsonBool:
		return _boolVal;
	case jsonNumber:
		return _numberVal != 0;
	case jsonArray:
		return _arrayVal->size() > 0;
	case jsonString:
	{
		if (_stringVal.size() == 0)
			return defaultValue;
		if (_stricmp(_stringVal.data(), "T") == 0 ||
			_stricmp(_stringVal.data(), "TRUE") == 0 ||
			_stricmp(_stringVal.data(), "Y") == 0 ||
			_stricmp(_stringVal.data(), "YES") == 0 ||
			atoi(_stringVal.data()) != 0)
		{
			return true;
		}
		return false;
	}
	case jsonObject:
		if (_objectVal == nullptr)
			return false;
		return true;
	}
	return defaultValue;
}
int64_t JSONField::AsNumber(int64_t defaultValue) const
{
	switch (_type)
	{
	case jsonNull:
		return defaultValue;
	case jsonBool:
		return _boolVal ? 1 : 0;
	case jsonNumber:
		return _numberVal;
	case jsonArray:
		return _arrayVal->size();
	case jsonString:
		return _atoi64(_stringVal.data());
	case jsonObject:
		return defaultValue;
	}
	return defaultValue;
}
std::nullptr_t JSONField::AsNull() const
{
	return nullptr;
}
const JSONObject& JSONField::AsObject() const
{
	switch (_type)
	{
	default:
	case jsonNull:
	case jsonBool:
	case jsonNumber:
	case jsonArray:
	case jsonString:
		throw std::runtime_error("This field is not an object");
	case jsonObject:
		return *_objectVal;
	}
}
JSONObject& JSONField::AsObject()
{
	switch (_type)
	{
	default:
	case jsonNull:
	case jsonBool:
	case jsonNumber:
	case jsonArray:
	case jsonString:
		throw std::runtime_error("This field is not an object");
	case jsonObject:
		return *_objectVal;
	}
}
const JSONFieldList& JSONField::AsArray() const
{
	switch (_type)
	{
	case jsonNull:
	case jsonBool:
	case jsonNumber:
	case jsonString:
	case jsonObject:
		throw std::runtime_error("Invalid field type requested.");
	case jsonArray:
		return _arrayVal;
	}
	throw std::runtime_error("Invalid field type requested.");
}
JSONFieldList& JSONField::AsArray()
{
	switch (_type)
	{
	case jsonNull:
	case jsonBool:
	case jsonNumber:
	case jsonString:
	case jsonObject:
		throw std::runtime_error("Invalid field type requested.");
	case jsonArray:
		return _arrayVal;
	}
	throw std::runtime_error("Invalid field type requested.");
}
void JSONField::ValueAsNull()
{
	clear();
}
void JSONField::Value(std::nullptr_t)
{
	clear();
}
void JSONField::Value(bool setTo)
{
	if (Type() != jsonBool)
		clear();
	_boolVal = setTo;
	_type = jsonBool;
}
void JSONField::Value(const tsCryptoStringBase& setTo)
{
	if (Type() != jsonString)
		clear();
	_stringVal = setTo;
	_type = jsonString;
}
void JSONField::Value(const char* setTo)
{
	if (Type() != jsonString)
		clear();
	_stringVal = setTo;
	_type = jsonString;
}
void JSONField::Value(int64_t setTo)
{
	if (Type() != jsonNumber)
		clear();
	_numberVal = setTo;
	_type = jsonNumber;
}
void JSONField::Value(const JSONObject& setTo)
{
	clear();
	_objectVal = new JSONObject(setTo);
	_type = jsonObject;
	_objectVal->Parent(this);
}
void JSONField::Value(JSONObject&& setTo)
{
	clear();
	_objectVal = new JSONObject(std::move(setTo));
	_type = jsonObject;
	_objectVal->Parent(this);
}
void JSONField::Value(const JSONFieldList& setTo)
{
	clear();
	_arrayVal = setTo->cloneContainer();
	FixLineage();
	_type = jsonArray;
}
void JSONField::Value(JSONFieldList&& setTo)
{
	clear();
	_arrayVal = std::move(setTo);
	FixLineage();
	_type = jsonArray;
}
void JSONField::clear()
{
	if (_objectVal != nullptr)
		delete _objectVal;
	_objectVal = nullptr;
	_type = (jsonNull);
	_numberVal = (0);
	_boolVal = (false);
	_isNull = (true);
	_stringVal.clear();
	if (!!_arrayVal)
		_arrayVal->clear();
}

bool JSONField::isXmlAttribute() const
{
	if (strncmp(Name().data(), "Att.", 4) == 0 || strstr(Name().data(), ":Att.") != nullptr)
		return true;
	return false;
}
bool JSONField::isXmlTextNode() const
{
	return Name().size() == 0 && Type() == jsonString;
}
tsCryptoString JSONField::ToXML(const tsCryptoStringBase& arrayNode) const
{
	tsCryptoString tmp;
	tsCryptoString tmp2;
	tsCryptoString name(Name());
	bool wasAttr = false;
	bool wasCollection = false;

	if (isXmlAttribute())
	{
		tsCryptoStringList parts = name.split(":");

		name.clear();
		for (size_t i = 0; i < parts->size() - 1; i++)
		{
			if (i > 0)
				name.append(":");
			name.append(parts->at(i));
		}
		if (name.size() > 0)
			name.append(":");
		if (strncmp(parts->at(parts->size() - 1).data(), "Att.", 4) == 0)
		{
			wasAttr = true;
			parts->at(parts->size() - 1).DeleteAt(0, 4);
		}
		name.append(parts->at(parts->size() - 1));
	}
	else if (name.size() == 0)
	{
		name = arrayNode;
		if (TsStrLen(arrayNode) > 10 && strcmp(&arrayNode[TsStrLen(arrayNode) - 10], "Collection") == 0)
		{
			wasCollection = true;
			name.DeleteAt(TsStrLen(arrayNode) - 10, 10);
		}
	}

	if (Name().size() == 0 && !wasCollection)
	{
		return AsString();
	}
	if (wasAttr)
	{
		TSPatchValueForXML(AsString(), tmp2);

		tmp.append(name).append("=\"").append(tmp2).append("\"");
		return tmp;
	}

	switch (_type)
	{
	case jsonNull:
		tmp.append("<").append(name).append("/>");
		break;
	case jsonBool:
		tmp.append("<").append(name).append(">").append((_boolVal ? "true" : "false")).append("</").append(name).append(">");
		break;
	case jsonNumber:
		tmp.append("<").append(name).append(">").append(_numberVal).append("</").append(name).append(">");
		break;
	case jsonString:
		TSPatchValueForXML(_stringVal, tmp2);
		tmp.append("<").append(name).append(">").append(tmp2).append("</").append(name).append(">");
		break;
	case jsonObject:
		if (_objectVal != nullptr)
			tmp.append(_objectVal->ToXML(name));
		else
			tmp.append("<").append(name).append("/>");
		break;
	case jsonArray:
		tmp.append("<").append(name).append(">");
		for (auto fld : *_arrayVal)
		{
			tmp.append(fld.ToXML(name));
		}
		tmp.append("</").append(name).append(">");
		break;
	}
	return tmp;
}

void JSONField::FixLineage()
{
	switch (_type)
	{
	case jsonArray:
		for (auto fld : *_arrayVal)
		{
			fld.Parent(this);
			fld.FixLineage();
		}
		break;
	case jsonObject:
		if (_objectVal != nullptr)
		{
			_objectVal->Parent(this);
			_objectVal->FixLineage();
		}
		break;
	default:
		break;
	}
}

JsonSearchResultList JSONField::JSONPathQuery(const tsCryptoStringBase& path)
{
	return jsonPath(this, path, false);
}

bool JSONField::DeleteMeFromParent()
{
	if (Parent() != nullptr)
	{
		JSONElement *parent = Parent();

		if (parent->ElementType() == jet_Field)
		{
			JSONField *parentField = reinterpret_cast<JSONField*>(parent);

			// If this is not an array then it is invalid
			if (parentField->Type() != JSONField::jsonArray)
				return false;

			// Now we need to find the field in the array and remove it.
			parentField->_arrayVal->erase(std::find_if(parentField->_arrayVal->begin(), parentField->_arrayVal->end(), [this](JSONField& fld) {
				return this == &fld;
			}));
		}
		else
		{
			// Object
			JSONObject *parentObject = reinterpret_cast<JSONObject*>(parent);

			parentObject->deleteField(Name());
		}
		return true;
	}
	return false;
}

JSONElement* JSONField::findSingleItem(const tsCryptoStringBase& path, bool createNode)
{
	JsonSearchResultList tmp = jsonPath(this, path, createNode);

	if (tmp->size() != 1)
		return nullptr;
	return tmp->at(0);
}

const JSONElement* JSONField::findSingleItem(const tsCryptoStringBase& path) const
{
	JsonSearchResultList tmp = jsonPath((JSONElement*)this, path, false);

	if (tmp->size() != 1)
		return nullptr;
	return tmp->at(0);
}
void JSONField::for_each(std::function<void(JSONField& fld)> func)
{
	if (Type() == jsonArray)
	{
		std::for_each(_arrayVal->begin(), _arrayVal->end(), func);
	}
	else if (Type() == jsonObject)
	{
		_objectVal->foreach(func);
	}
	else
		func(*this);
}
void JSONField::for_each(std::function<void(const JSONField& fld)> func) const
{
	if (Type() == jsonArray)
	{
		std::for_each(_arrayVal->begin(), _arrayVal->end(), func);
	}
	else if (Type() == jsonObject)
	{
		((const JSONObject*)(_objectVal))->foreach(func);
	}
	else
		func(*this);
}

void JSONField::erase_if(std::function<bool(JSONField& fld)> func)
{
	if (Type() == jsonArray)
	{
		_arrayVal->erase(std::remove_if(_arrayVal->begin(), _arrayVal->end(), func), _arrayVal->end());
	}
	else if (Type() == jsonObject)
	{
		_objectVal->remove_if(func);
	}

}

















JSONObject::JSONObject()
{
	_fields = CreateJSONFieldList();
}
JSONObject::~JSONObject()
{
}
JSONObject::JSONObject(const JSONObject& obj) :
	_fields(obj._fields->cloneContainer())
{
	FixLineage();
}
JSONObject::JSONObject(JSONObject&& obj) :
	_fields(std::move(obj._fields))
{
	FixLineage();
}
JSONObject& JSONObject::operator=(const JSONObject& obj)
{
	if (&obj != this)
	{
		_fields = obj._fields->cloneContainer();
		FixLineage();
	}
	return *this;
}
JSONObject& JSONObject::operator=(JSONObject&& obj)
{
	if (&obj != this)
	{
		_fields = std::move(obj._fields);
		FixLineage();
	}
	return *this;
}
bool JSONObject::operator==(const JSONObject& obj) const
{
	return _fields == obj._fields;
}
JSONFieldList& JSONObject::Fields()
{
	return _fields;
}
const JSONFieldList& JSONObject::Fields() const
{
	return _fields;
}
size_t JSONObject::fieldCount() const
{
	return _fields->size();
}
const JSONField& JSONObject::field(size_t index) const
{
	return _fields->at(index);
}
JSONField& JSONObject::field(size_t index)
{
	return _fields->at(index);
}
const JSONField& JSONObject::field(const tsCryptoStringBase& index) const
{
	auto it = std::find_if(_fields->begin(), _fields->end(), [&index](const JSONField& fld)->bool {return fld.Name() == index; });
	if (it == _fields->end())
		throw std::invalid_argument("field not found");
	return *it;
}
JSONField& JSONObject::field(const tsCryptoStringBase& index)
{
	auto it = std::find_if(_fields->begin(), _fields->end(), [&index](const JSONField& fld)->bool {return fld.Name() == index; });
	if (it == _fields->end())
		throw std::invalid_argument("field not found");
	return *it;
}
tsCryptoString JSONObject::ToJSON() const
{
	tsCryptoString tmp;

	tmp.append("{");
	for (auto fld : *_fields)
	{
		if (tmp.size() > 1)
			tmp.append(",");
		tmp.append("\"").append(fld.Name()).append("\":").append(fld.ToJSON());
	}
	tmp.append("}");
	return tmp;
}
void JSONObject::clear()
{
	_fields->clear();
}
static void EatWhitespace(const char*& p)
{
	while (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t')
		p++;
}
static bool addHexNibble(const char*&p, ts_wchar& c)
{
	if (*p >= '0' && *p <= '9')
		c = (c << 4) | (*p++ - '0');
	else if (*p >= 'a' && *p <= 'f')
		c = (c << 4) | (*p++ - 'a' + 10);
	else if (*p >= 'A' && *p <= 'F')
		c = (c << 4) | (*p++ - 'A' + 10);
	else
		return false;
	return true;
}
static bool GetString(const char*& p, tsCryptoStringBase& name)
{
	CryptoUtf16 tmp;
	char matching;

	EatWhitespace(p);
	if (*p != '"' && *p != '\'')
		return false;
	matching = *p;
	p++;
	name.clear();
	while (*p && *p != matching)
	{
		if (*p == '\\')
		{
			p++;
			switch (*p)
			{
			case '"':
				tmp += "\"";
				p++;
				break;
			case '\\':
				tmp += "\\";
				p++;
				break;
			case '/':
				tmp += "/";
				p++;
				break;
			case 'b':
				tmp += "\b";
				p++;
				break;
			case 'f':
				tmp += "\f";
				p++;
				break;
			case 'n':
				tmp += "\n";
				p++;
				break;
			case 'r':
				tmp += "\r";
				p++;
				break;
			case 't':
				tmp += "\t";
				p++;
				break;
			case 'u':
			{
				ts_wchar c = 0;

				p++;
				if (!addHexNibble(p, c) || !addHexNibble(p, c) || !addHexNibble(p, c) || !addHexNibble(p, c))
					return false;
				tmp += c;
			}
			break;
			default:
				return false;
			}
		}
		else if (*p < 32)
			return false;
		else
			tmp += *p++;
	}
	if (*p != matching)
		return false;
	p++;
	name = tmp.toUtf8();
	EatWhitespace(p);
	return true;
}
static bool GetValue(const char*& p, JSONField& fld)
{
	EatWhitespace(p);
	if (strncmp(p, "true", 4) == 0)
	{
		fld.Value(true);
		p += 4;
	}
	else if (strncmp(p, "null", 4) == 0)
	{
		fld.Value(nullptr);
		p += 4;
	}
	else if (strncmp(p, "false", 5) == 0)
	{
		fld.Value(false);
		p += 5;
	}
	else if ((*p >= '0' && *p <= '9') || *p == '-')
	{
		bool negate = false;
		int64_t num = 0;

		if (*p == '-')
		{
			negate = true;
			p++;
		}
		while (*p >= '0' && *p <= '9')
		{
			num = num * 10 + (*p++ - '0');
		}
		if (negate)
			num = -num;
		fld.Value(num);
	}
	else if (*p == '"' || *p == '\'')
	{
		tsCryptoString val;

		if (!GetString(p, val))
		{
			return false;
		}
		fld.Value(val);
	}
	else if (*p == '[')
	{
		JSONFieldList array = CreateJSONFieldList();

		p++;
		EatWhitespace(p);
		if (*p == ']')
		{
			p++;
			fld.Value(array);
			return true;
		}
		do
		{
			EatWhitespace(p);
			JSONField innerFld;

			if (!GetValue(p, innerFld))
				return false;

			array->push_back(innerFld);

			EatWhitespace(p);
			if (*p == ',')
			{
				p++;
				if (*p == ']')
					return false; // looking for another value here but found the end of the array
			}
			else if (*p != ']')
				return false;
		} while (*p != 0 && *p != ']');

		if (*p != ']')
			return false;
		p++;

		fld.Value(array);
	}
	else if (*p == '{')
	{
		JSONObject obj;

		ptrdiff_t len = obj.FromJSON(p);
		if (len <= 0)
		{
			return false;
		}
		p += len;
		fld.Value(obj);
	}
	else
	{
		return false;
	}
	return true;
}
ptrdiff_t JSONObject::FromJSON(const char* json)
{
	return FromJSON(tsCryptoString(json));
}
ptrdiff_t JSONObject::FromJSON(const tsCryptoStringBase& json)
{
	const char *p = json.data();
	tsCryptoString name;

	clear();
	EatWhitespace(p);
	if (*p != '{')
		return 0; // not an object
	p++;

	do
	{
		EatWhitespace(p);
		if (*p == '}')
		{
			p++;
			return p - json.data();
		}
		else if (*p == '"' || *p == '\'')
		{
			// We have a field
			if (!GetString(p, name))
			{
				clear();
				return 0;
			}
			EatWhitespace(p);
			if (*p != ':')
			{
				clear();
				return 0;
			}
			p++;
			EatWhitespace(p);
			JSONField fld(name);
			if (!GetValue(p, fld))
			{
				clear();
				return 0;
			}
			fld.Parent(this);
			_fields->push_back(fld);
			EatWhitespace(p);
			if (*p == ',')
				p++;
			else if (*p == '}')
			{
				p++;
				return p - json.data();
			}
			else
			{
				clear();
				return 0;
			}
			EatWhitespace(p);
		}
		else
		{
			clear();
			return 0;
		}
	} while (*p != 0);
	return p - json.data();
}

tsCryptoString JSONObject::ToXML(const tsCryptoStringBase& rootName) const
{
	tsCryptoString tmp;
	bool hadOtherFields = false;

	tmp.append("<").append(rootName);

	for (auto fld : *_fields)
	{
		if (fld.isXmlAttribute())
		{
			tmp.append(" ").append(fld.ToXML(fld.Name()));
		}
		else
			hadOtherFields = true;
	}

	if (!hadOtherFields)
	{
		tmp.append("/>");
		return tmp;
	}
	tmp.append(">");

	for (auto fld : *_fields)
	{
		if (fld.isXmlTextNode())
		{
			tmp.append(fld.ToXML(fld.Name()));
		}
	}
	for (auto fld : *_fields)
	{
		if (!fld.isXmlAttribute() && !fld.isXmlTextNode())
		{
			tmp.append(fld.ToXML(fld.Name()));
		}
	}

	tmp.append("</").append(rootName).append(">");
	return tmp;
}

JSONObject& JSONObject::add(const JSONField& fld)
{
	auto it = std::find_if(_fields->begin(), _fields->end(), [&fld](const JSONField& field)->bool {return field.Name() == fld.Name();});

	if (it == _fields->end())
	{
		_fields->push_back(fld);
		FixLineage();
	}
	else if (it->Type() == JSONField::jsonArray)
	{
		it->AsArray()->push_back(fld);
	}
	else
	{
		JSONFieldList list = CreateJSONFieldList();

		list->push_back(*it);
		list->push_back(fld);
		it->Value(std::move(list));
	}
	return *this;
}
JSONObject& JSONObject::add(JSONField&& fld)
{
	auto it = std::find_if(_fields->begin(), _fields->end(), [&fld](const JSONField& field)->bool {return field.Name() == fld.Name(); });

	if (it == _fields->end())
	{
		fld.Parent(this);
		_fields->push_back(std::move(fld));
	}
	else if (it->Type() == JSONField::jsonArray)
	{
		it->AsArray()->push_back(std::move(fld));
	}
	else
	{
		JSONFieldList list = CreateJSONFieldList();

		list->push_back(*it);
		list->push_back(std::move(fld));
		it->Value(std::move(list));
	}
	return *this;
}
JSONObject& JSONObject::add(const tsCryptoStringBase& name, const tsCryptoStringBase& val)
{
	auto it = std::find_if(_fields->begin(), _fields->end(), [&name](const JSONField& fld)->bool {return fld.Name() == name; });

	if (it == _fields->end())
	{
		JSONField fld(name);
		fld.Value(val);
		fld.Parent(this);
		_fields->push_back(fld);
	}
	else if (it->Type() == JSONField::jsonArray)
	{
		it->AsArray()->push_back(JSONField(name, val));
		FixLineage();
	}
	else
	{
		JSONFieldList list = CreateJSONFieldList();

		list->push_back(*it);
		list->push_back(JSONField(name, val));
		it->Value(std::move(list));
		FixLineage();
	}
	return *this;
}
JSONObject& JSONObject::add(const tsCryptoStringBase& name, const char* val)
{
	auto it = std::find_if(_fields->begin(), _fields->end(), [&name](const JSONField& fld)->bool {return fld.Name() == name; });

	if (it == _fields->end())
	{
		JSONField fld(name);
		fld.Value(val);
		fld.Parent(this);
		_fields->push_back(fld);
	}
	else if (it->Type() == JSONField::jsonArray)
	{
		it->AsArray()->push_back(JSONField(name, val));
		FixLineage();
	}
	else
	{
		JSONFieldList list = CreateJSONFieldList();

		list->push_back(*it);
		list->push_back(JSONField(name, val));
		it->Value(std::move(list));
		FixLineage();
	}
	return *this;
}
JSONObject& JSONObject::add(const tsCryptoStringBase& name, int64_t val)
{
	auto it = std::find_if(_fields->begin(), _fields->end(), [&name](const JSONField& fld)->bool {return fld.Name() == name; });

	if (it == _fields->end())
	{
		JSONField fld(name);
		fld.Value(val);
		fld.Parent(this);
		_fields->push_back(fld);
	}
	else if (it->Type() == JSONField::jsonArray)
	{
		it->AsArray()->push_back(JSONField(name, val));
		FixLineage();
	}
	else
	{
		JSONFieldList list = CreateJSONFieldList();

		list->push_back(*it);
		list->push_back(JSONField(name, val));
		it->Value(std::move(list));
		FixLineage();
	}
	return *this;
}
JSONObject& JSONObject::add(const tsCryptoStringBase& name)
{
	auto it = std::find_if(_fields->begin(), _fields->end(), [&name](const JSONField& fld)->bool {return fld.Name() == name; });

	if (it == _fields->end())
	{
		JSONField fld(name);
		fld.Parent(this);
		_fields->push_back(fld);
	}
	else if (it->Type() == JSONField::jsonArray)
	{
		it->AsArray()->push_back(JSONField(name));
		FixLineage();
	}
	else
	{
		JSONFieldList list = CreateJSONFieldList();

		list->push_back(*it);
		list->push_back(JSONField(name));
		it->Value(std::move(list));
		FixLineage();
	}
	return *this;
}
JSONObject& JSONObject::add(const tsCryptoStringBase& name, bool val)
{
	auto it = std::find_if(_fields->begin(), _fields->end(), [&name](const JSONField& fld)->bool {return fld.Name() == name; });

	if (it == _fields->end())
	{
		JSONField fld(name);
		fld.Value(val);
		fld.Parent(this);
		_fields->push_back(fld);
	}
	else if (it->Type() == JSONField::jsonArray)
	{
		it->AsArray()->push_back(JSONField(name, val));
		FixLineage();
	}
	else
	{
		JSONFieldList list = CreateJSONFieldList();

		list->push_back(*it);
		list->push_back(JSONField(name, val));
		it->Value(std::move(list));
		FixLineage();
	}
	return *this;
}
JSONObject& JSONObject::add(const tsCryptoStringBase& name, const JSONObject& val)
{
	auto it = std::find_if(_fields->begin(), _fields->end(), [&name](const JSONField& fld)->bool {return fld.Name() == name; });

	if (it == _fields->end())
	{
		JSONField fld(name);
		fld.Value(val);
		fld.Parent(this);
		_fields->push_back(fld);
	}
	else if (it->Type() == JSONField::jsonArray)
	{
		it->AsArray()->push_back(JSONField(name, val));
		FixLineage();
	}
	else
	{
		JSONFieldList list = CreateJSONFieldList();

		list->push_back(*it);
		list->push_back(JSONField(name, val));
		it->Value(std::move(list));
		FixLineage();
	}
	return *this;
}
JSONObject& JSONObject::add(const tsCryptoStringBase& name, JSONObject&& val)
{
	auto it = std::find_if(_fields->begin(), _fields->end(), [&name](const JSONField& fld)->bool {return fld.Name() == name; });

	if (it == _fields->end())
	{
		JSONField fld(name);
		fld.Value(val);
		fld.Parent(this);
		_fields->push_back(fld);
	}
	else if (it->Type() == JSONField::jsonArray)
	{
		it->AsArray()->push_back(JSONField(name, val));
		FixLineage();
	}
	else
	{
		JSONFieldList list = CreateJSONFieldList();

		list->push_back(*it);
		list->push_back(JSONField(name, val));
		it->Value(std::move(list));
		FixLineage();
	}
	return *this;
}
JSONObject& JSONObject::add(const tsCryptoStringBase& name, const JSONFieldList& val)
{
	auto it = std::find_if(_fields->begin(), _fields->end(), [&name](const JSONField& fld)->bool {return fld.Name() == name; });

	if (it == _fields->end())
	{
		JSONField fld(name);
		fld.Value(val);
		fld.Parent(this);
		_fields->push_back(fld);
	}
	else if (it->Type() == JSONField::jsonArray)
	{
		it->AsArray()->push_back(JSONField(name, val));
		FixLineage();
	}
	else
	{
		JSONFieldList list = CreateJSONFieldList();

		list->push_back(*it);
		list->push_back(JSONField(name, val));
		it->Value(std::move(list));
		FixLineage();
	}
	return *this;
}
JSONObject& JSONObject::add(const tsCryptoStringBase& name, JSONFieldList&& val)
{
	auto it = std::find_if(_fields->begin(), _fields->end(), [&name](const JSONField& fld)->bool {return fld.Name() == name; });

	if (it == _fields->end())
	{
		JSONField fld(name);
		fld.Value(val);
		fld.Parent(this);
		_fields->push_back(fld);
	}
	else if (it->Type() == JSONField::jsonArray)
	{
		it->AsArray()->push_back(JSONField(name, val));
		FixLineage();
	}
	else
	{
		JSONFieldList list = CreateJSONFieldList();

		list->push_back(*it);
		list->push_back(JSONField(name, val));
		it->Value(std::move(list));
		FixLineage();
	}
	return *this;
}

bool JSONObject::hasField(size_t index) const
{
	return (index < _fields->size());
}
bool JSONObject::hasField(const tsCryptoStringBase& index) const
{
	auto it = std::find_if(_fields->begin(), _fields->end(), [index](const JSONField& fld)->bool {return fld.Name() == index; });
	return (it != _fields->end());
}
JSONObject& JSONObject::deleteField(const tsCryptoStringBase& name)
{
	auto it = std::find_if(_fields->begin(), _fields->end(), [&name](const JSONField& fld)->bool {return fld.Name() == name; });
	if (it != _fields->end())
		_fields->erase(it);
	return *this;
}

JSONObject& JSONObject::renameField(const tsCryptoStringBase& oldname, const tsCryptoStringBase& newname)
{
	if (!hasField(oldname))
		return *this;

	JSONField fld = field(oldname);
	deleteField(oldname);
	fld.Name(newname);
	add(fld);
	return *this;
}

JSONObject& JSONObject::expand(const JSONObject& obj)
{
	obj.foreach([this](const JSONField& fld) { if (!hasField(fld.Name())) add(fld); });
	return *this;
}

JSONObject& JSONObject::expand(const tsCryptoStringBase& obj)
{
	JSONObject j;

	j.FromJSON(obj);
	return expand(j);
}

JSONObject& JSONObject::merge(const JSONObject& obj)
{
	obj.foreach([this](const JSONField& fld) { replace(fld); });
	return *this;
}

JSONObject& JSONObject::merge(const tsCryptoStringBase& obj)
{
	JSONObject j;

	j.FromJSON(obj);
	return merge(j);
}

JSONObject& JSONObject::unionOf(const JSONObject& obj)
{
	obj.foreach([this](const JSONField& fld) { add(fld); });
	return *this;
}

JSONObject& JSONObject::unionOf(const tsCryptoStringBase& obj)
{
	JSONObject j;

	j.FromJSON(obj);
	return unionOf(j);
}

tsCryptoString JSONObject::AsString(const tsCryptoStringBase& fieldName) const
{
	if (!hasField(fieldName))
		return "";
	return field(fieldName).AsString();
}

bool JSONObject::AsBool(const tsCryptoStringBase& fieldName, bool defaultValue) const
{
	if (!hasField(fieldName))
		return defaultValue;

	return field(fieldName).AsBool(defaultValue);
}

int64_t JSONObject::AsNumber(const tsCryptoStringBase& fieldName, int64_t defaultValue) const
{
	if (!hasField(fieldName))
		return defaultValue;

	return field(fieldName).AsNumber(defaultValue);
}

std::nullptr_t JSONObject::AsNull(const tsCryptoStringBase& fieldName) const
{
	return field(fieldName).AsNull();
}

JSONObject& JSONObject::AsObject(const tsCryptoStringBase& fieldName)
{
	return field(fieldName).AsObject();
}

const JSONObject& JSONObject::AsObject(const tsCryptoStringBase& fieldName) const
{
	return field(fieldName).AsObject();
}

const JSONFieldList& JSONObject::AsArray(const tsCryptoStringBase& fieldName) const
{
	return field(fieldName).AsArray();
}

JSONFieldList& JSONObject::AsArray(const tsCryptoStringBase& fieldName)
{
	return field(fieldName).AsArray();
}

void JSONObject::foreach(std::function<void(JSONField&)> func)
{
	std::for_each(_fields->begin(), _fields->end(), func);
}

void JSONObject::foreach(std::function<void(const JSONField&)> func) const
{
	std::for_each(_fields->begin(), _fields->end(), func);
}

void JSONObject::remove_if(std::function<bool(JSONField&)> func)
{
	auto it = std::remove_if(_fields->begin(), _fields->end(), func);
	if (it != _fields->end())
		_fields->erase(it, _fields->end());
}

void JSONObject::remove_if(const tsCryptoStringBase& arrayFieldName, std::function<bool(JSONField&)> func)
{
	auto fld_it = std::find_if(_fields->begin(), _fields->end(), [&arrayFieldName](const JSONField& fld)->bool {return fld.Name() == arrayFieldName; });

	if (fld_it == _fields->end())
		return;

	if (fld_it->Type() != JSONField::jsonArray)
	{
		if (func(*fld_it))
		{
			_fields->erase(fld_it);
		}
	}
	else
	{
		JSONFieldList &ary = fld_it->AsArray();
		ary->erase(std::remove_if(ary->begin(), ary->end(), func), ary->end());
	}
}

void JSONObject::foreach(const tsCryptoStringBase& fieldName, std::function<void(JSONField&)> func)
{
	if (!hasField(fieldName))
		return;
	JSONField& fld = field(fieldName);

	if (fld.Type() == JSONField::jsonArray)
	{
		JSONFieldList &ary = fld.AsArray();
		std::for_each(ary->begin(), ary->end(), func);
	}
	else
		func(fld);
}

void JSONObject::foreach(const tsCryptoStringBase& fieldName, std::function<void(const JSONField&)> func) const
{
	if (!hasField(fieldName))
		return;
	const JSONField& fld = field(fieldName);

	if (fld.Type() == JSONField::jsonArray)
	{
		const JSONFieldList &ary = fld.AsArray();
		std::for_each(ary->begin(), ary->end(), func);
	}
	else
		func(fld);
}

JSONObject& JSONObject::replace(const JSONField& fld)
{
	deleteField(fld.Name());
	add(fld);
	return *this;
}
JSONObject& JSONObject::replace(JSONField&& fld)
{
	deleteField(fld.Name());
	add(std::move(fld));
	return *this;
}
JSONObject& JSONObject::replace(const tsCryptoStringBase& name, int64_t val)
{
	deleteField(name);
	add(name, val);
	return *this;
}
JSONObject& JSONObject::replaceWithNull(const tsCryptoStringBase& name)
{
	deleteField(name);
	add(name);
	return *this;
}
JSONObject& JSONObject::replace(const tsCryptoStringBase& name, bool val)
{
	deleteField(name);
	add(name, val);
	return *this;
}
JSONObject& JSONObject::replace(const tsCryptoStringBase& name, const JSONObject& val)
{
	deleteField(name);
	add(name, val);
	return *this;
}
JSONObject& JSONObject::replace(const tsCryptoStringBase& name, JSONObject&& val)
{
	deleteField(name);
	add(name, std::move(val));
	return *this;
}
JSONObject& JSONObject::replace(const tsCryptoStringBase& name, const JSONFieldList& val)
{
	deleteField(name);
	add(name, val);
	return *this;
}
JSONObject& JSONObject::replace(const tsCryptoStringBase& name, const tsCryptoStringBase& val)
{
	deleteField(name);
	add(name, val);
	return *this;
}
JSONObject& JSONObject::replace(const tsCryptoStringBase& name, const char* val)
{
	deleteField(name);
	add(name, val);
	return *this;
}
JSONObject& JSONObject::replace(const tsCryptoStringBase& name, JSONFieldList&& val)
{
	deleteField(name);
	add(name, std::move(val));
	return *this;
}
void JSONObject::FixLineage()
{
	this->foreach([this](JSONField& fld) { fld.Parent(this); fld.FixLineage(); });
}
JsonSearchResultList JSONObject::JSONPathQuery(const tsCryptoStringBase& path)
{
	return jsonPath(this, path, false);
}

bool JSONObject::DeleteMeFromParent()
{
	if (Parent() != nullptr)
	{
		JSONElement *parent = Parent();

		if (parent->ElementType() == jet_Field)
		{
			// An object with a parent is always wrapped in a field.  Get that field and delete it.
			if (!(reinterpret_cast<JSONField*>(parent))->DeleteMeFromParent())
			{
				// OK  This is a wierd case where the Object is in a field but that field is not contained in anything.  
				// Change the field to null and still delete me
				(reinterpret_cast<JSONField*>(parent))->Value(nullptr);
			}
		}
		else
		{
			return false; // Objects are never within an object
		}

		return true;
	}
	return false;
}

JSONElement* JSONObject::findSingleItem(const tsCryptoStringBase& path, bool createNode)
{
	JsonSearchResultList tmp = jsonPath(this, path, createNode);

	if (tmp->size() != 1)
		return nullptr;
	return tmp->at(0);
}

const JSONElement* JSONObject::findSingleItem(const tsCryptoStringBase& path) const
{
	JsonSearchResultList tmp = jsonPath((JSONElement*)this, path, false);

	if (tmp->size() != 1)
		return nullptr;
	return tmp->at(0);
}

JSONFieldList JSONObject::createArrayField(const tsCryptoStringBase& fieldName)
{
	auto it = std::find_if(_fields->begin(), _fields->end(), [&fieldName](const JSONField& fld)->bool {return fld.Name() == fieldName; });

	if (it == _fields->end())
	{
		JSONFieldList list = CreateJSONFieldList();
		JSONField fld(fieldName);

		fld.Value(std::move(list));
		fld.Parent(this);
		_fields->push_back(fld);
		FixLineage();
		return list;
	}
	else if (it->Type() == JSONField::jsonArray)
	{
		return it->AsArray();
	}
	else
	{
		JSONFieldList list = CreateJSONFieldList();

		list->push_back(*it);
		it->Value(std::move(list));
		FixLineage();
		return list;
	}
}
