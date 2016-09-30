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

#pragma once

struct VEILCORE_API NameValue
{
	static void *operator new(std::size_t count) {
		return tscrypto::cryptoNew(count);
	}
	static void *operator new[](std::size_t count) {
		return tscrypto::cryptoNew(count);
	}
	static void operator delete(void *ptr) { tscrypto::cryptoDelete(ptr); }
	static void operator delete[](void *ptr) { tscrypto::cryptoDelete(ptr); }

	NameValue() {}
	NameValue(const tscrypto::tsCryptoString& _name, const tscrypto::tsCryptoString& _value) : name(_name), value(_value) {}
	~NameValue() {}

	tscrypto::tsCryptoString name;
	tscrypto::tsCryptoString value;
	bool operator==(const NameValue& obj) const { return name == obj.name; }
};


#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4231)
VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API tscrypto::ICryptoContainerWrapper<NameValue>;
VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::shared_ptr<tscrypto::ICryptoContainerWrapper<NameValue>>;
#pragma warning(pop)
#endif // _MSC_VER

typedef std::shared_ptr<tscrypto::ICryptoContainerWrapper<NameValue>> NameValueList;
extern VEILCORE_API NameValueList CreateNameValueList();

class VEILCORE_API UrlParser
{
public:
	static void *operator new(std::size_t count) {
		return tscrypto::cryptoNew(count);
	}
	static void *operator new[](std::size_t count) {
		return tscrypto::cryptoNew(count);
	}
	static void operator delete(void *ptr) { tscrypto::cryptoDelete(ptr); }
	static void operator delete[](void *ptr) { tscrypto::cryptoDelete(ptr); }

	UrlParser();
	~UrlParser();

	static tscrypto::tsCryptoString encodeParameterValue(const tscrypto::tsCryptoString& value);
	static tscrypto::tsCryptoString encodeParameterName(const tscrypto::tsCryptoString& value);
	static tscrypto::tsCryptoString encodeServer(const tscrypto::tsCryptoString& value);
	static tscrypto::tsCryptoString encodePath(const tscrypto::tsCryptoString& value);
	static tscrypto::tsCryptoString decodeParameterValue(const tscrypto::tsCryptoString& value);
	static tscrypto::tsCryptoString decodeParameterName(const tscrypto::tsCryptoString& value);
	static tscrypto::tsCryptoString decodeServer(const tscrypto::tsCryptoString& value);
	static tscrypto::tsCryptoString decodePath(const tscrypto::tsCryptoString& value);
	bool ParseFullUrl(const tscrypto::tsCryptoString& url);
	tscrypto::tsCryptoString BuildUrl() const;
	void clear();

	tscrypto::tsCryptoString getScheme() const;
	void setScheme(const tscrypto::tsCryptoString& setTo);
	tscrypto::tsCryptoString getServer() const;
	void setServer(const tscrypto::tsCryptoString& setTo);
	int getPort() const;
	void setPort(int setTo);
	tscrypto::tsCryptoString getPath() const;
	void setPath(const tscrypto::tsCryptoString& setTo);
	const NameValueList getParameters() const;
	void setParameters(NameValueList setTo);
	tscrypto::tsCryptoString getHash() const;
	void setHash(const tscrypto::tsCryptoString& setTo);

	tscrypto::tsCryptoString getFile() const;

	void RemoveFileFromPath();
	void AppendToPath(const tscrypto::tsCryptoString& part);

protected:
	tscrypto::tsCryptoString _scheme;
	tscrypto::tsCryptoString _server;
	int     _port;
	tscrypto::tsCryptoString _path;
	NameValueList _parameters;
	tscrypto::tsCryptoString _hash;
};

