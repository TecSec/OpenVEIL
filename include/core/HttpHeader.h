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

#ifndef _WIN32
struct __xp_socket{};
typedef ID<__xp_socket, int, 0> SOCKET;
#define INVALID_SOCKET SOCKET::invalid()
inline void closesocket(SOCKET& sock) { close((int)sock); }
#endif // _WIN32

struct VEILCORE_API HttpAttribute
{
	HttpAttribute() {};
	HttpAttribute(LPCSTR name, LPCSTR value) : m_Name(name), m_Value(value) { }
	HttpAttribute(const tscrypto::tsCryptoString& name, const tscrypto::tsCryptoString& value) : m_Name(name), m_Value(value) { }
	tscrypto::tsCryptoString m_Name;
	tscrypto::tsCryptoString m_Value;
	bool operator==(const HttpAttribute& obj) const { return m_Name == obj.m_Name && m_Value == obj.m_Value; }
};

class IHttpResponse
{
public:
	virtual ~IHttpResponse(void) {}

	virtual const tscrypto::tsCryptoString &Errors()const = 0;
	virtual void ClearErrors() = 0;

	virtual tscrypto::tsCryptoString status() const = 0;
	virtual tscrypto::tsCryptoString reason() const = 0;
	virtual tscrypto::tsCryptoString version() const = 0;
	virtual size_t dataPartSize() const = 0;
	virtual const tscrypto::tsCryptoData& dataPart() const = 0;
	virtual void dataPart(const tscrypto::tsCryptoString& setTo) = 0;
	virtual void dataPart(const tscrypto::tsCryptoData& setTo) = 0;
	virtual WORD errorCode() const = 0;
	virtual void errorCode(WORD setTo) = 0;
	virtual size_t attributeCount() const = 0;
	virtual const HttpAttribute* attribute(size_t index) const = 0;
	virtual const HttpAttribute* attributeByName(const tscrypto::tsCryptoString& index) const = 0;
	virtual const HttpAttribute* attributeByName(const char *index) const = 0;
	virtual tscrypto::tsCryptoData recreateResponse() const = 0;
};


VEILCORE_API IHttpResponse* CreateHttpResponse();
