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

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif  // MIN

class HttpHeader : public IHttpHeader
{
public:

	HttpHeader();
	~HttpHeader(void);

	virtual const tscrypto::tsCryptoString &Errors()const override;
	virtual void ClearErrors() override;
	virtual tscrypto::tsCryptoString status() const override;
	virtual tscrypto::tsCryptoString reason() const override;
	virtual tscrypto::tsCryptoString version() const override;
	virtual size_t dataPartSize() const override;
	virtual const tscrypto::tsCryptoData& dataPart() const override;
	virtual void dataPart(const tscrypto::tsCryptoString& setTo) override;
	virtual void dataPart(const tscrypto::tsCryptoData& setTo) override;
	virtual uint16_t errorCode() const override;
	virtual void errorCode(uint16_t setTo) override;
	virtual size_t attributeCount() const override
	{
		return m_attributes.size();
	}
	virtual const HttpAttribute* attribute(size_t index) const override
	{
		if (index >= attributeCount())
			return nullptr;
		return &m_attributes[index];
	}
	virtual const HttpAttribute* attributeByName(const tscrypto::tsCryptoStringBase& index) const override
	{
		return attributeByName(index.c_str());
	}
	virtual const HttpAttribute* attributeByName(const char *index) const override
	{
		auto it = std::find_if(m_attributes.begin(), m_attributes.end(), [&index](const HttpAttribute& attr)->bool { return tsStriCmp(index, attr.m_Name.c_str()) == 0; });
		if (it == m_attributes.end())
			return nullptr;
		return &*it;
	}
	virtual tscrypto::tsCryptoData recreateResponse() const override;

	virtual ReadCode ReadStream(std::shared_ptr<ITcpConnection> channel, const tscrypto::tsCryptoData& leadin, std::shared_ptr<IHttpChannelProcessor>& processor) override;
	virtual void clear() override;

private:
	typedef enum {
		pse_InRequest,
		pse_InHeader,
		pse_InData,
		pse_Error,
		pse_Done,
	} parseStateEnum;
	void ParseOffHeaders();
	bool ParseOffResponseLine(int &posi);
	bool GetNextToken(int &posi, tscrypto::tsCryptoData &token);
	bool GetLine(int &posi, bool eat_spaces, tscrypto::tsCryptoData &line);
	bool PeekLine(int posi, bool eat_spaces, tscrypto::tsCryptoData &line);
	bool IsWhiteSpace(int posi) const;

private:
	tscrypto::tsCryptoData                     m_dataPart;
	tscrypto::tsCryptoString                    m_version;
	tscrypto::tsCryptoString                    m_status;
	tscrypto::tsCryptoString                    m_reason;
	tscrypto::tsCryptoString                    m_lastAttribute;
	tscrypto::tsCryptoString                    m_errors;
	uint16_t                       m_errorCode;
	parseStateEnum             m_parseState;
	bool                       m_isSimpleRequest;
	std::vector<HttpAttribute> m_attributes;
};

HttpHeader::HttpHeader() :
	m_errorCode(404),
	m_parseState(pse_InRequest),
	m_isSimpleRequest(false)
{
}

HttpHeader::~HttpHeader(void)
{
}

HttpHeader::ReadCode HttpHeader::ReadStream(std::shared_ptr<ITcpConnection> channel, const tscrypto::tsCryptoData& leadin, std::shared_ptr<IHttpChannelProcessor>& processor)
{
	tscrypto::tsCryptoData buff;
	int requiredDataLength = 0;
	int targetLength;

	clear();
	m_parseState = pse_InRequest;

	if (leadin.size() > 0)
		m_dataPart = leadin.ToUtf8String();
	else
		m_dataPart.clear();

	m_errorCode = 200;
	do
	{
		buff.clear();

		if (m_parseState == pse_InHeader ||
			m_parseState == pse_InRequest)
			targetLength = 1023;
		else
		{
			targetLength = (int)MIN(1023, (requiredDataLength - m_dataPart.size()));
		}
		if (!channel->RawReceive(buff, targetLength))
		{
			m_errors += "Unable to read the data from the socket\n";
			//
			// Data retrieval error (should never happen)
			//
			return hh_Failure;
		}

		//
		// Is there data in the buffer?
		//
		if (!buff.empty())
		{
			LOG(httpData, "recv'd" << tscrypto::endl << buff.ToHexDump());

			if (processor != nullptr)
			{
				if (!processor->UnwrapTransport(buff))
				{
					m_errors += "Malformed response - Transport failed\n";
					return hh_Failure;
				}
			}

			if (buff.size() > 0)
			{
				m_dataPart += buff.ToUtf8String();
				if (m_parseState == pse_InHeader || m_parseState == pse_InRequest)
				{
					ParseOffHeaders();
					if (m_parseState == pse_InData)
					{
						const HttpAttribute* p = attributeByName("content-length");

						if (p == nullptr || p->m_Value.size() == 0)
						{
							if (tsStrToInt(m_status.c_str()) != 200)
							{
								m_parseState = pse_Done;
								m_errorCode = (uint16_t)tsStrToInt(m_status.c_str());
								return hh_Success;
							}
							m_errors += "Malformed response - no content-length attribute\n";
							return hh_Failure;
						}
						requiredDataLength = tsStrToInt(p->m_Value.c_str());
						if ((int)m_dataPart.size() >= requiredDataLength && m_parseState == pse_InData)
							m_parseState = pse_Done;
					}
				}
				else if ((int)m_dataPart.size() >= requiredDataLength && m_parseState == pse_InData)
					m_parseState = pse_Done;
			}
		}
		else
		{
			return hh_CloseSocket;
		}
	} while (m_parseState != pse_Done && m_parseState != pse_Error);


	m_errorCode = (uint16_t)tsStrToInt(m_status.c_str());
	return hh_Success;
}

void HttpHeader::clear()
{
	m_dataPart.clear();
	m_version.clear();
	m_status.clear();
	m_reason.clear();
	m_lastAttribute.clear();
	m_errorCode = 404;
	m_parseState = pse_InRequest;
	m_isSimpleRequest = false;
	m_attributes.clear();
	m_errors.clear();
}

tscrypto::tsCryptoString HttpHeader::status() const
{
	return m_status;
}

tscrypto::tsCryptoString HttpHeader::reason() const
{
	return m_reason;
}

tscrypto::tsCryptoString HttpHeader::version() const
{
	return m_version;
}

size_t HttpHeader::dataPartSize() const
{
	return m_dataPart.size();
}

const tscrypto::tsCryptoData& HttpHeader::dataPart() const
{
	return m_dataPart;
}

void HttpHeader::dataPart(const tscrypto::tsCryptoString& setTo)
{
	m_dataPart = setTo;
}

void HttpHeader::dataPart(const tscrypto::tsCryptoData& setTo)
{
	m_dataPart = setTo;
}

void HttpHeader::ParseOffHeaders()
{
	tscrypto::tsCryptoData line;
	int posi = 0;
	tscrypto::tsCryptoData nextPart;

	if (m_parseState == pse_InRequest)
	{
		if (!PeekLine(posi, false, line) || line.size() == 0)
		{
			if (line.size() > 0)
			{
				// Perform some simple validations here to make sure we do not have really bad data
				if (line[0] < 'A' || (line[0] > 'Z' && line[0] < 'a') || line[0] > 'z')
				{
					m_parseState = pse_Error;
					m_errorCode = 400;
					return;
				}
			}
			return; // we do not have a complete line yet.
		}
		//
		// First parse off the request line
		//
		if (!ParseOffResponseLine(posi))
		{
			m_parseState = pse_Error;
			m_errorCode = 400;
			return;
		}
		m_parseState = pse_InHeader;
	}
	//
	// Now get the attributes from the header
	//
	while (PeekLine(posi, false, line) && line.size() > 0)
	{
		tscrypto::tsCryptoData attrName;
		//bool append = false;

		if (IsWhiteSpace(posi))
		{
			if (m_lastAttribute.size() == 0)
			{
				m_parseState = pse_Error;
				m_errorCode = 400;
				return;
			}
			//append = true;
			attrName.AsciiFromString(m_lastAttribute.c_str());
		}
		else
		{
			if (!GetNextToken(posi, attrName))
			{
				m_parseState = pse_Error;
				m_errorCode = 400;
				return;
			}
			if (attrName.size() == 0 || attrName[attrName.size() - 1] != ':')
			{
				m_parseState = pse_Error;
				m_errorCode = 400;
				return;
			}
			attrName.erase(attrName.size() - 1, 1);
			m_lastAttribute = attrName.ToUtf8String();
		}
		GetLine(posi, true, line);
		while (PeekLine(posi, false, nextPart) && nextPart.size() > 0 &&
			(nextPart[0] == ' ' || nextPart[0] == 9))
		{
			GetLine(posi, true, nextPart);
			line += (uint8_t)0x20;
			line += nextPart;
		}
		//if ( append )
		//{
		//	auto it = m_attributes.first_that([&attrName](HttpAttribute& attr)->bool{ return tsStriCmp(attrName.ToUtf8String(), attr.m_Name) == 0; });

		//	if ( it.AtEnd() )
		//	{
		//		m_parseState = pse_Error;
		//		m_errorCode = 400;
		//		return;
		//	}
		//	it->m_Value += (char)0x20;
		//	it->m_Value += line.ToTSString();
		//}
		//else
		{
			HttpAttribute attr;
			attr.m_Name = attrName.ToUtf8String();
			attr.m_Value = line.ToUtf8String();
			m_attributes.push_back(attr);
		}
	}
	if (PeekLine(posi, false, nextPart) && nextPart.size() == 0)
	{
		GetLine(posi, false, nextPart);
		m_parseState = pse_InData;
		m_errorCode = 200;
	}
	m_dataPart.erase(0, posi);
	return;
}

bool HttpHeader::ParseOffResponseLine(int &posi)
{
	tscrypto::tsCryptoData token;
	if (!GetNextToken(posi, token))
	{
		return false;
	}
	m_version = token.ToUtf8String();
	if (!GetNextToken(posi, token))
	{
		return false;
	}
	m_status = token.ToUtf8String();
	if (!GetLine(posi, true, token))
		return false;
	m_reason = token.ToUtf8String();

	// TODO: Not sure about this
	//if ( !GetLine(posi, true, token) )
	//    return false;
	//if ( token.size() == 0 )
	//{
	//    m_isSimpleRequest = true;
	//    return true;
	//}
	return true;
}

bool HttpHeader::GetNextToken(int &posi, tscrypto::tsCryptoData &token)
{
	token.clear();
	if (posi >= (int)m_dataPart.size())
		return false;
	while (posi < (int)m_dataPart.size() && (m_dataPart[posi] == 0x20))
		posi++;
	if (posi >= (int)m_dataPart.size())
		return false;
	while (posi < (int)m_dataPart.size() && m_dataPart[posi] != 0x20 && m_dataPart[posi] != 10 && m_dataPart[posi] != 13)
	{
		token += (uint8_t)m_dataPart[posi++];
	}
	if (token.size() == 0)
		return false;
	return true;
}

bool HttpHeader::IsWhiteSpace(int posi) const
{
	if (posi >= (int)m_dataPart.size())
		return false;
	if (m_dataPart.c_at(posi) == ' ' || m_dataPart.c_at(posi) == 9)
		return true;
	return false;
}

bool HttpHeader::GetLine(int &posi, bool eat_spaces, tscrypto::tsCryptoData &line)
{
	line.clear();
	if (posi >= (int)m_dataPart.size())
		return false;
	if (eat_spaces)
	{
		while (posi < (int)m_dataPart.size() && (m_dataPart[posi] == 0x20))
			posi++;
	}
	while (posi < (int)m_dataPart.size() && m_dataPart[posi] != 10 && m_dataPart[posi] != 13)
	{
		line += (uint8_t)m_dataPart[posi++];
	}
	if (posi >= (int)m_dataPart.size())
		return false;
	if (m_dataPart[posi] == 13)
	{
		posi++;
		if (m_dataPart[posi] == 10)
			posi++;
		else
			return false;
	}
	else if (m_dataPart[posi] == 10)
		posi++;
	else
		return false;
	return true;
}

bool HttpHeader::PeekLine(int posi, bool eat_spaces, tscrypto::tsCryptoData &line)
{
	return GetLine(posi, eat_spaces, line);
}

uint16_t HttpHeader::errorCode() const
{
	return m_errorCode;
}

void HttpHeader::errorCode(uint16_t setTo)
{
	m_errorCode = setTo;
}

#if 0
int HTMLHelper::FindAttributeIndexHelper(HTMLHelper::HttpAttribute *data, void *param)
{
	if (param == NULL)
		return 0;
	if (tsStriCmp(data->m_Name.c_str(), ((const char *)param)) == 0)
		return 1;
	return 0;
}
#endif

const tscrypto::tsCryptoString &HttpHeader::Errors()const
{
	return m_errors;
}

void HttpHeader::ClearErrors()
{
	m_errors.clear();
}

tscrypto::tsCryptoData HttpHeader::recreateResponse() const
{
	tscrypto::tsCryptoString header;
	tscrypto::tsCryptoData tmp;

	header << "HTTP/1.1 " << status() << " " << reason() << "\r\n";
	for (size_t i = 0; i < attributeCount(); i++)
	{
		const HttpAttribute* attr = attribute(i);
		if (attr != nullptr)
		{
			header << attr->m_Name << ": " << attr->m_Value << "\r\n";
		}
	}
	header << "Content-Length: " << dataPartSize() << "\r\n\r\n";
	tmp = header.ToUTF8Data();
	tmp << dataPart();
	return tmp;
}

IHttpResponse* CreateHttpResponse()
{
	return dynamic_cast<IHttpResponse*>(new HttpHeader());
}
