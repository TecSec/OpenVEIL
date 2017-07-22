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

NameValueList CreateNameValueList()
{
	return CreateContainer<NameValue>();
}

UrlParser::UrlParser()
	:
	_port(0)
{
	_parameters = CreateNameValueList();
}

UrlParser::~UrlParser()
{
}

void UrlParser::clear()
{
	_scheme.clear();
	_server.clear();
	_port = 0;
	_path.clear();
	_parameters->clear();
	_hash.clear();
}

tscrypto::tsCryptoString UrlParser::encodeParameterValue(const tscrypto::tsCryptoString& value)
{
	tscrypto::tsCryptoString val(value);

	val.Replace("%", "%25").Replace(" ", "%20").Replace("<", "%3C").Replace(">", "%3E").Replace("#", "%23").Replace("\"", "%22").Replace("=", "%3D").Replace("&", "%26")
		.Replace("{", "%7b").Replace("}", "%7d").Replace("|", "%7c").Replace("\\", "%5C").Replace("^", "%5E").Replace("[", "%5B").Replace("]", "%5D").Replace("`", "%60");

	return val;
}

tscrypto::tsCryptoString UrlParser::encodeParameterName(const tscrypto::tsCryptoString& value)
{
	tscrypto::tsCryptoString val(value);

	val.Replace("%", "%25").Replace(" ", "%20").Replace("<", "%3C").Replace(">", "%3E").Replace("#", "%23").Replace("\"", "%22")
		.Replace("{", "%7b").Replace("}", "%7d").Replace("|", "%7c").Replace("\\", "%5C").Replace("^", "%5E").Replace("[", "%5B").Replace("]", "%5D").Replace("`", "%60");

	return val;
}

tscrypto::tsCryptoString UrlParser::encodeServer(const tscrypto::tsCryptoString& value)
{
	tscrypto::tsCryptoString val(value);

	val.Replace("%", "%25").Replace(" ", "%20").Replace("<", "%3C").Replace(">", "%3E").Replace("#", "%23").Replace("\"", "%22")
		.Replace("{", "%7b").Replace("}", "%7d").Replace("|", "%7c").Replace("\\", "%5C").Replace("^", "%5E").Replace("[", "%5B").Replace("]", "%5D").Replace("`", "%60");

	return val;
}

tscrypto::tsCryptoString UrlParser::encodePath(const tscrypto::tsCryptoString& value)
{
	tscrypto::tsCryptoString val(value);

	val.Replace("%", "%25").Replace(" ", "%20").Replace("<", "%3C").Replace(">", "%3E").Replace("#", "%23").Replace("\"", "%22")
		.Replace("{", "%7b").Replace("}", "%7d").Replace("|", "%7c").Replace("\\", "%5C").Replace("^", "%5E").Replace("[", "%5B").Replace("]", "%5D").Replace("`", "%60");

	return val;
}

static int getHexByte(const char *str)
{
	int c = 0;

	if (str[0] >= '0' && str[0] <= '9')
		c = (str[0] - '0') << 4;
	else if (str[0] >= 'a' && str[0] <= 'f')
		c = (str[0] - 'a' + 10) << 4;
	else if (str[0] >= 'A' && str[0] <= 'F')
		c = (str[0] - 'A' + 10) << 4;
	else
		return -1;
	if (str[1] >= '0' && str[1] <= '9')
		c |= (str[1] - '0');
	else if (str[1] >= 'a' && str[1] <= 'f')
		c |= (str[1] - 'a' + 10);
	else if (str[1] >= 'A' && str[1] <= 'F')
		c |= (str[1] - 'A' + 10);
	else
		return -1;
	return c;
}
tscrypto::tsCryptoString UrlParser::decodeParameterValue(const tscrypto::tsCryptoString& value)
{
	tscrypto::tsCryptoString val(value);
	size_t offset = 0;

	while (offset < val.size())
	{
		if (val[offset] == '%' && offset + 2 < val.size())
		{
			int c = getHexByte(&val.c_str()[offset + 1]);
			if (c >= 0)
			{
				val[offset] = (char)c;
				val.DeleteAt(offset + 1, 2);
			}
		}
		offset++;
	}

	return val;
}

tscrypto::tsCryptoString UrlParser::decodeParameterName(const tscrypto::tsCryptoString& value)
{
	return decodeParameterValue(value);
}

tscrypto::tsCryptoString UrlParser::decodeServer(const tscrypto::tsCryptoString& value)
{
	return decodeParameterValue(value);
}

tscrypto::tsCryptoString UrlParser::decodePath(const tscrypto::tsCryptoString& value)
{
	return decodeParameterValue(value);
}

bool UrlParser::ParseFullUrl(const tscrypto::tsCryptoString& url)
{
	tscrypto::tsCryptoStringList parts;
	tscrypto::tsCryptoString remainder;

	clear();

	// First remove the hash part
	parts = url.split('#', 2);
	if (parts->size() > 1)
		_hash = parts->at(1);

	remainder = parts->at(0);

	// Now split off the parameters
	parts = remainder.split('?', 2);
	if (parts->size() > 1)
	{
		// Process parameters here
		tscrypto::tsCryptoStringList nvParts = parts->at(1).split('&');
		for (tscrypto::tsCryptoString& nv : *nvParts)
		{
			tscrypto::tsCryptoStringList nameVal = nv.split('=', 2);
			NameValue param;

			param.name = decodeParameterName(nameVal->at(0));
			if (nameVal->size() > 1)
				param.value = decodeParameterValue(nameVal->at(1));
			_parameters->push_back(param);
		}
	}
	remainder = parts->at(0);

	// Split off the optional scheme part here
    if (!remainder.empty())
    {
	char c = remainder[0];

	if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
	{
		_scheme += c;
		remainder.DeleteAt(0, 1);
		while (remainder.size() > 0)
		{
			c = remainder[0];
			if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.')
			{
				_scheme += c;
				remainder.DeleteAt(0, 1);
			}
			else
				break;
		}
		if (remainder.size() < 3 || remainder[0] != ':' || remainder[1] != '/' || remainder[2] != '/')
		{
			// Must be a relative path
			remainder.prepend(_scheme);
			_scheme.clear();
		}
		else
			remainder.DeleteAt(0, 3);
	}
    }
	if (_scheme.size() > 0)
	{
		// We have a scheme.  Therefore parse the server and port from the path
		parts = remainder.split('/', 2);
		if (parts->size() > 1)
			_path = "/" + decodePath(parts->at(1));
		remainder = parts->at(0);

		// Now split the server and port
		parts = remainder.split(':', 2);
		if (parts->size() > 1)
            _port = TsStrToInt(parts->at(1).c_str());
		_server = decodeServer(parts->at(0));
	}
	else
		_path = decodePath(remainder);
	return true;
}

tscrypto::tsCryptoString UrlParser::BuildUrl() const
{
	tscrypto::tsCryptoString url;

	if (_scheme.size() > 0)
	{
		url << _scheme << "://";
		url << encodeServer(_server);
		if (_port != 0)
			url << ":" << _port;
	}
	if (_path.size() > 0)
		url << encodePath(_path);
	else
		url << "/";
	if (_parameters->size() > 0)
	{
		bool first = true;

		url << "?";
		for (const NameValue& nv : *_parameters)
		{
			if (!first)
				url << "&";
			first = false;
			url << encodeParameterName(nv.name);
			if (nv.value.size() > 0)
				url << "=" << encodeParameterValue(nv.value);
		}
	}
	if (_hash.size() > 0)
		url << "#" << _hash;
	return url;
}

tscrypto::tsCryptoString UrlParser::getScheme() const
{
	return _scheme;
}

void UrlParser::setScheme(const tscrypto::tsCryptoString& setTo)
{
	_scheme = setTo;
}

tscrypto::tsCryptoString UrlParser::getServer() const
{
	return _server;
}

void UrlParser::setServer(const tscrypto::tsCryptoString& setTo)
{
	_server = setTo;
}

int UrlParser::getPort() const
{
	if (_port == 0)
	{
        if (TsStriCmp(getScheme().c_str(), "http") == 0)
			return 80;
        if (TsStriCmp(getScheme().c_str(), "https") == 0)
			return 443;
        if (TsStriCmp(getScheme().c_str(), "httpv") == 0)
			return 8001;
	}
	return _port;
}

void UrlParser::setPort(int setTo)
{
	_port = setTo;
}

tscrypto::tsCryptoString UrlParser::getPath() const
{
	return _path;
}

void UrlParser::setPath(const tscrypto::tsCryptoString& setTo)
{
	_path = setTo;
}

const NameValueList UrlParser::getParameters() const
{
	return _parameters;
}

void UrlParser::setParameters(NameValueList setTo)
{
	_parameters = CreateNameValueList();
	if (!!setTo)
	{
		for (NameValue nv : *setTo)
		{
			_parameters->push_back(nv);
		}
	}
}

tscrypto::tsCryptoString UrlParser::getHash() const
{
	return _hash;
}

void UrlParser::setHash(const tscrypto::tsCryptoString& setTo)
{
	_hash = setTo;
}

tscrypto::tsCryptoString UrlParser::getFile() const
{
	tscrypto::tsCryptoString path(_path);
	ptrdiff_t offset;

	if (path.size() == 0 || path == "/")
		return "";

	if (path[path.size() - 1] == '/')
		path.resize(_path.size() - 1);
	offset = _path.size() - 1;
	while (offset >= 0 && _path[offset] != '/')
	{
		offset--;
	}
	if (offset < 0)
		return "";
	return path.substring(offset + 1, path.size() - offset - 1);
}

void UrlParser::RemoveFileFromPath()
{
	ptrdiff_t offset;

	if (_path.size() == 0 || _path == "/")
		return;

	if (_path[_path.size() - 1] == '/')
		_path.resize(_path.size() - 1);
	offset = _path.size() - 1;
	while (offset >= 0 && _path[offset] != '/')
	{
		_path.resize(offset);
		offset--;
	}
	if (offset < 0)
		_path = "/";
}

void UrlParser::AppendToPath(const tscrypto::tsCryptoString& part)
{
	if (_path.size() > 0 && _path[_path.size() - 1] != '/')
		_path += "/";
	_path += part;
}

