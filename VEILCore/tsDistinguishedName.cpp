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

using namespace tscrypto;

static struct
{
	const char* name;
	const char* oid;
} gNameTable[] = 
{
	{"CN", id_at_commonName_OID},
	{"L", id_at_localityName_OID },
	{"ST", id_at_stateOrProvinceName_OID },
	{"O", id_at_organizationName_OID },
	{"OU", id_at_organizationalUnitName_OID },
	{"C", id_at_countryName_OID },
	{"STREET", id_at_streetAddress_OID },
	{"DC", id_domainComponent_OID },
	{"UID", id_DN_PART_UID_OID },
};

tsDnPart::tsDnPart()
{
}

tsDnPart::tsDnPart(const tsCryptoStringBase& name) :
	_name(name)
{
}

tsDnPart::tsDnPart(const tsCryptoStringBase& name, const tsCryptoStringBase& value) :
	_name(name),
	_value(value)
{
}

tsDnPart::tsDnPart(const tsCryptoData& oid, const tsCryptoStringBase& value) :
	_value(value)
{
	NameAsOID(oid.ToOIDString());
}

tsDnPart::~tsDnPart()
{
}

tsDnPart::tsDnPart(const tsDnPart& obj) :
	_name(obj._name),
	_value(obj._value)
{
}

tsDnPart::tsDnPart(tsDnPart&& obj) :
	_name(std::move(obj._name)),
	_value(std::move(obj._value))
{
}

tsDnPart& tsDnPart::operator=(const tsDnPart& obj)
{
	if (&obj != this)
	{
		_name = obj._name;
		_value = obj._value;
	}
	return *this;
}

tsDnPart& tsDnPart::operator=(tsDnPart&& obj)
{
	if (&obj != this)
	{
		_name = std::move(obj._name);
		_value = std::move(obj._value);
	}
	return *this;
}

bool tsDnPart::operator==(const tsDnPart& obj) const
{
	return _name == obj._name && _value == obj._value;
}

tsCryptoString tsDnPart::Name() const
{
	return _name;
}

void tsDnPart::Name(const tsCryptoStringBase& setTo)
{
	_name = setTo;
}

void tsDnPart::Name(const char* setTo)
{
	_name = setTo;
}

tsCryptoData tsDnPart::NameAsOID() const
{
	for (size_t i = 0; i < sizeof(gNameTable) / sizeof(gNameTable[0]); i++)
	{
		if (tsStriCmp(gNameTable[i].name, _name.c_str()) == 0)
			return tsCryptoData(gNameTable[i].oid, tsCryptoData::OID);
	}
	return tsCryptoData(_name, tsCryptoData::OID);
}
void tsDnPart::NameAsOID(const tsCryptoData& oid)
{
	NameAsOID(oid.ToOIDString());
}
void tsDnPart::NameAsOID(const tsCryptoStringBase& oid)
{
	for (size_t i = 0; i < sizeof(gNameTable) / sizeof(gNameTable[0]); i++)
	{
		if (tsStrCmp(oid.c_str(), gNameTable[i].oid) == 0)
		{
			_name = gNameTable[i].name;
			return;
		}
	}
	_name = oid;
}

tsCryptoString tsDnPart::Value() const
{
	return _value;
}

tsCryptoString tsDnPart::ToString() const
{
	tsCryptoString tmp, val;

	tmp.append(Name()).append("=");

	val = Value();
	val.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace(",", "\\,").Replace("+", "\\+").Replace("<", "\\<").Replace(">", "\\>").Replace(";", "\\;");
	if (val.size() > 0 && (val[0] == ' ' || val[0] == '#'))
	{
		val.prepend("\\");
	}
	if (val.size() > 0 && val[val.size() - 1] == ' ')
	{
		val.InsertAt(val.size() - 1, "\\");
	}
	tmp += val;
	return tmp;
}

void tsDnPart::Value (const tsCryptoStringBase& setTo)
{
	_value = setTo;
}

void tsDnPart::Value (const char* setTo)
{
	_value = setTo;
}

void tsDnPart::clear()
{
	_name.clear();
	_value.clear();
}




tsDistinguishedName::tsDistinguishedName()
{
	_parts = CreateContainer<tsDnPart>();
}

tsDistinguishedName::~tsDistinguishedName()
{
	_parts = CreateContainer<tsDnPart>();
}

tsDistinguishedName::tsDistinguishedName(const tsDistinguishedName& obj) :
	_parts(obj._parts)
{
}

tsDistinguishedName::tsDistinguishedName(tsDistinguishedName&& obj) :
	_parts(std::move(obj._parts))
{
}

tsDistinguishedName& tsDistinguishedName::operator=(const tsDistinguishedName& obj)
{
	if (&obj != this)
	{
		_parts = obj._parts;
	}
	return *this;
}

tsDistinguishedName& tsDistinguishedName::operator=(tsDistinguishedName&& obj)
{
	if (&obj != this)
	{
		_parts = std::move(obj._parts);
	}
	return *this;
}

bool tsDistinguishedName::operator==(const tsDistinguishedName& obj) const
{
	return _parts == obj._parts;
}

tsDnPartList& tsDistinguishedName::Parts()
{
	return _parts;
}

const tsDnPartList& tsDistinguishedName::Parts() const
{
	return _parts;
}

size_t tsDistinguishedName::partCount() const
{
	return _parts->size();
}

const tsDnPart& tsDistinguishedName::part(size_t index) const
{
	return _parts->at(index);
}

tsDnPart& tsDistinguishedName::part(size_t index)
{
	return _parts->at(index);
}

tsCryptoString tsDistinguishedName::ToString() const
{
	tsCryptoString tmp;

	for (const tsDnPart& part : *_parts)
	{
		if (tmp.size() > 0)
			tmp += ",";
		tmp += part.ToString();
	}
	return tmp;
}

static void EatWhitespace(const char*& p)
{
	while (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t')
		p++;
}

//		 ",", "+", """, "\", "<", ">" or ";"
static bool GetName(const char*& p, tsCryptoString& name)
{
	tsCryptoString tmp;

	EatWhitespace(p);
	name.clear();
	while (*p && *p != '=')
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
			case ',':
				tmp += ",";
				p++;
				break;
			case '+':
				tmp += "+";
				p++;
				break;
			case '<':
				tmp += "<";
				p++;
				break;
			case '>':
				tmp += ">";
				p++;
				break;
			case ';':
				tmp += ";";
				p++;
				break;
			case ' ':
				tmp += " ";
				p++;
				break;
			case '#':
				tmp += "#";
				p++;
				break;
			default:
				if (((p[0] >= '0' && p[0] <= '9') ||
                    (p[0] >= 'a' && p[0] <= 'f') ||
                    (p[0] >= 'A' && p[0] <= 'F')) &&
					((p[1] >= '0' && p[1] <= '9') ||
                     (p[1] >= 'a' && p[1] <= 'f') ||
                     (p[1] >= 'A' && p[1] <= 'F')))
				{
					char c = (char)tsCryptoData(tsCryptoString(p, 2), tsCryptoData::HEX)[0];
					tmp += c;
					p += 2;
				}
				else
					return false;
			}
		}
		else if (p[0] == 'U' && p[1] == '+')
		{
			if (((p[0] >= '0' && p[0] <= '9') ||
                (p[0] >= 'a' && p[0] <= 'f') ||
                (p[0] >= 'A' && p[0] <= 'F')) &&
				((p[1] >= '0' && p[1] <= '9') ||
                 (p[1] >= 'a' && p[1] <= 'f') ||
                 (p[1] >= 'A' && p[1] <= 'F')) &&
				((p[2] >= '0' && p[2] <= '9') ||
                 (p[2] >= 'a' && p[2] <= 'f') ||
                 (p[2] >= 'A' && p[2] <= 'F')) &&
				((p[3] >= '0' && p[3] <= '9') ||
                 (p[3] >= 'a' && p[3] <= 'f') ||
                 (p[3] >= 'A' && p[3] <= 'F')))
			{
				tsCryptoData dt(tsCryptoString(p, 4), tsCryptoData::HEX);
				tmp += dt.ToUtf8String();
				p += 4;
			}
			else
				tmp += "U+";
		}
		else if (*p < 32)
			return false;
		else
			tmp += *p++;
	}
	if (*p != '=')
		return false;
	p++;
	name = tmp;
	EatWhitespace(p);
	return true;
}

static bool GetValue(const char*& p, tsCryptoString& value)
{
	tsCryptoString tmp;

	EatWhitespace(p);
	value.clear();
	if (*p == '"')
	{
		p++;
		while (*p && *p != '"')
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
				case ',':
					tmp += ",";
					p++;
					break;
				case '+':
					tmp += "+";
					p++;
					break;
				case '<':
					tmp += "<";
					p++;
					break;
				case '>':
					tmp += ">";
					p++;
					break;
				case ';':
					tmp += ";";
					p++;
					break;
				case ' ':
					tmp += " ";
					p++;
					break;
				case '#':
					tmp += "#";
					p++;
					break;
				default:
					if (((p[0] >= '0' && p[0] <= '9') || (p[0] >= 'a' && p[0] <= 'f') || (p[0] >= 'A' && p[0] <= 'F')) &&
						((p[1] >= '0' && p[1] <= '9') || (p[1] >= 'a' && p[1] <= 'f') || (p[1] >= 'A' && p[1] <= 'F')))
					{
						char c = (char)tsCryptoData(tsCryptoString(p, 2), tsCryptoData::HEX)[0];
						tmp += c;
						p += 2;
					}
					else
						return false;
				}
			}
			else if (p[0] == 'U' && p[1] == '+')
			{
				if (((p[0] >= '0' && p[0] <= '9') || (p[0] >= 'a' && p[0] <= 'f') || (p[0] >= 'A' && p[0] <= 'F')) &&
					((p[1] >= '0' && p[1] <= '9') || (p[1] >= 'a' && p[1] <= 'f') || (p[1] >= 'A' && p[1] <= 'F')) &&
					((p[2] >= '0' && p[2] <= '9') || (p[2] >= 'a' && p[2] <= 'f') || (p[2] >= 'A' && p[2] <= 'F')) &&
					((p[3] >= '0' && p[3] <= '9') || (p[3] >= 'a' && p[3] <= 'f') || (p[3] >= 'A' && p[3] <= 'F')))
				{
					tsCryptoData dt(tsCryptoString(p, 4), tsCryptoData::HEX);
					tmp += dt.ToUtf8String();
					p += 4;
				}
				else
					tmp += "U+";
			}
			else if (*p < 32)
				return false;
			else
				tmp += *p++;
		}
		if (*p == '"')
			p++;
	}
	else
	{
		while (*p && *p != ',' && *p != ';')
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
				case ',':
					tmp += ",";
					p++;
					break;
				case '+':
					tmp += "+";
					p++;
					break;
				case '<':
					tmp += "<";
					p++;
					break;
				case '>':
					tmp += ">";
					p++;
					break;
				case ';':
					tmp += ";";
					p++;
					break;
				case ' ':
					tmp += " ";
					p++;
					break;
				case '#':
					tmp += "#";
					p++;
					break;
				default:
					if (((p[0] >= '0' && p[0] <= '9') || (p[0] >= 'a' && p[0] <= 'f') || (p[0] >= 'A' && p[0] <= 'F')) &&
						((p[1] >= '0' && p[1] <= '9') || (p[1] >= 'a' && p[1] <= 'f') || (p[1] >= 'A' && p[1] <= 'F')))
					{
						char c = (char)tsCryptoData(tsCryptoString(p, 2), tsCryptoData::HEX)[0];
						tmp += c;
						p += 2;
					}
					else
						return false;
				}
			}
			else if (p[0] == 'U' && p[1] == '+')
			{
				if (((p[0] >= '0' && p[0] <= '9') || (p[0] >= 'a' && p[0] <= 'f') || (p[0] >= 'A' && p[0] <= 'F')) &&
					((p[1] >= '0' && p[1] <= '9') || (p[1] >= 'a' && p[1] <= 'f') || (p[1] >= 'A' && p[1] <= 'F')) &&
					((p[2] >= '0' && p[2] <= '9') || (p[2] >= 'a' && p[2] <= 'f') || (p[2] >= 'A' && p[2] <= 'F')) &&
					((p[3] >= '0' && p[3] <= '9') || (p[3] >= 'a' && p[3] <= 'f') || (p[3] >= 'A' && p[3] <= 'F')))
				{
					tsCryptoData dt(tsCryptoString(p, 4), tsCryptoData::HEX);
					tmp += dt.ToUtf8String();
					p += 4;
				}
				else
					tmp += "U+";
			}
			else if (*p < 32)
				return false;
			else
				tmp += *p++;
		}
		if (tmp.size() > 0 && tmp[tmp.size() - 1] == ' ')
		{
			if (p[-2] != '\\')
				tmp.TrimEnd(" ");
		}
	}
	EatWhitespace(p);
	if (*p && *p != ',' && *p != ';')
		return false;
	value = tmp;
	EatWhitespace(p);
	return true;
}

ptrdiff_t tsDistinguishedName::FromString(const char* inputString)
{
	const char *p = inputString;
	tsCryptoString name, value;

	clear();
	EatWhitespace(p);
	while (p != nullptr && *p != 0)
	{
		if (!GetName(p, name))
			return 0;
		EatWhitespace(p);
		if (!GetValue(p, value))
			return 0;
		_parts->push_back(tsDnPart(name, value));
		if (*p != 0 && (*p != ',') && (*p != ';'))
		{
			return 0;
		}
		if (*p == ',' || *p == ';')
			p++;
		EatWhitespace(p);
	}
	return p - inputString;
}

void tsDistinguishedName::clear()
{
	_parts->clear();
}

tsDnPart* tsDistinguishedName::findPartByName(const char* name)
{
	for (size_t i = 0; i < partCount(); i++)
	{
		if (tsStriCmp(part(i).Name().c_str(), name) == 0)
			return &part(i);
	}

	return nullptr;
}
tsDnPart* tsDistinguishedName::findPartByOID(const char* oid)
{
	for (size_t i = 0; i < partCount(); i++)
	{
		if (part(i).NameAsOID().ToOIDString() == oid)
			return &part(i);
	}

	return nullptr;
}

void tsDistinguishedName::AddPart(const char* name, const char* value)
{
	_parts->push_back(tsDnPart(name, value));
}

void tsDistinguishedName::AddPartByOID(const char* oid, const char* value)
{
	_parts->push_back(tsDnPart(tsCryptoData(oid, tsCryptoData::OID), value));
}

