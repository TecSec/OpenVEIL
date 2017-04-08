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

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif // MIN

class JsonChannel : public TcpChannel, public virtual IJsonChannel
{
public:
	JsonChannel()
	{
	}
	virtual ~JsonChannel(void)
	{
	}

	// Inherited via IJsonChannel
	virtual const tscrypto::tsCryptoString &Server() const override
	{
		return TcpConnection::Server();
	}
	virtual void Server(const tscrypto::tsCryptoString &setTo) override
	{
		TcpConnection::Server(setTo);
	}
	virtual unsigned short Port() const override
	{
		return TcpConnection::Port();
	}
	virtual void Port(unsigned short setTo) override
	{
		TcpConnection::Port(setTo);
	}
	virtual tscrypto::tsCryptoString Errors() const override
	{
		return TcpConnection::Errors();
	}
	virtual void ClearErrors() override
	{
		TcpConnection::ClearErrors();
	}
	virtual bool RawSend(const tscrypto::tsCryptoData& data) override
	{
		return TcpConnection::RawSend(data);
	}
	virtual bool RawReceive(tscrypto::tsCryptoData& _data, size_t size) override
	{
		return TcpConnection::RawReceive(_data, size);
	}
	virtual bool isConnected() const override
	{
		return TcpConnection::isConnected();
	}
	virtual bool Disconnect() override
	{
		return TcpConnection::Disconnect();
	}
	virtual bool Connect() override
	{
		return TcpConnection::Connect();
	}
	virtual void SendLogout() override
	{
		TcpChannel::SendLogout();
	}
	virtual bool Send(const tscrypto::tsCryptoData& _data) override
	{
		return TcpChannel::Send(_data);
	}
	virtual bool Receive(tscrypto::tsCryptoData& _data, size_t size) override
	{
		return TcpChannel::Receive(_data, size);
	}
	virtual bool isAuthenticated() const override
	{
		return TcpChannel::isAuthenticated();
	}
	virtual bool processAuthenticationMessages() override
	{
		return TcpChannel::processAuthenticationMessages();
	}
	std::shared_ptr<IChannelProcessor> getChannelProcessor() const override
	{
		return TcpChannel::getChannelProcessor();
	}

	virtual bool Send(const tscrypto::JSONObject & __body) override
	{
		tscrypto::tsCryptoData message;
		JSONObject _body(__body);
		uint32_t len;

		flushBuffer();

		if (!!m_processor)
		{
			tscrypto::tsCryptoData buff;

			do
			{
				if (!m_processor)
					return false;
				switch (m_processor->GetTransportState())
				{
				case IHttpChannelProcessor::inactive:
				case IHttpChannelProcessor::active:
				case IHttpChannelProcessor::logout:
					break;
				case IHttpChannelProcessor::login:
					buff.clear();

					if (!RawReceive(buff, 1024))
						return false;

					if (buff.size() > 0)
					{
						LOG(httpData, "recv'd" << tscrypto::endl << buff.ToHexDump());

						if (!m_processor || !m_processor->UnwrapTransport(buff))
							return false;
						if (buff.size() > 0)
							m_bufferedData << buff;
					}
					else
					{
						XP_Sleep(100);
					}
					break;
				}
			} while (!!m_processor && m_processor->GetTransportState() == IHttpChannelProcessor::login);
		}

		if (!WrapMessage(_body))
		{
			m_errors += "Message wrapping failed\n";
			_errorSignals.Fire(this, m_errors);
			return false;
		}

		message.resize(4);
		message += _body.ToJSON().ToUTF8Data();
		len = (uint32_t)(message.size() - 4);
		message[0] = (uint8_t)(len >> 24);
		message[1] = (uint8_t)(len >> 16);
		message[2] = (uint8_t)(len >> 8);
		message[3] = (uint8_t)(len);

		// And that we can connect to the server
		if (!Connect())
		{
			m_errors += "Unable to connect to the server\n";
			_errorSignals.Fire(this, m_errors);
			return false;
		}
		if (!WrapTransport(message))
		{
			m_errors += "Transport wrapping failed\n";
			_errorSignals.Fire(this, m_errors);
			return false;
		}

		if (message.size() == 0)
			return true; // Already handled

						 // Send it
		return RawSend(message);
	}
	virtual bool Receive(tscrypto::JSONObject & body) override
	{
		uint32_t len = 0;
		tsCryptoData part;

		body.clear();

		for (;;)
		{
			if (!isConnected())
				return false;

			if (len == 0)
			{
				if (!RawReceive(part, 4))
				{
					_errorSignals.Fire(this, m_errors);
					return false;
				}
				m_bufferedData << part;
				if (m_bufferedData.size() >= 4)
				{
					len = *(const uint32_t*)m_bufferedData.c_str();
					m_bufferedData.erase(0, 4);
#if TS_BYTE_ORDER == TS_LITTLE_ENDIAN
					TS_BIG_ENDIAN4(len);
#endif
				}
			}
			if (!RawReceive(part, len - m_bufferedData.size()))
			{
				_errorSignals.Fire(this, m_errors);
				return false;
			}
			m_bufferedData << part;
			if (m_bufferedData.size() >= len)
			{
				if (!body.FromJSON(m_bufferedData.ToUtf8String().c_str()))
				{
					m_errors += "Invalid JSON received.\n";
					_errorSignals.Fire(this, m_errors);
					return false;
				}
				m_bufferedData.erase(0, len);
				if (!UnwrapMessage(body))
				{
					m_errors += "Unable to unwrap the received message.\n";
					_errorSignals.Fire(this, m_errors);
					return false;
				}
				//LOG(httpLog, "Processed Receive in " << (GetTicks() - start) / 1000.0 << " ms");
				return true;
			}
		}
	}
	virtual std::shared_ptr<IJsonChannelProcessor> getJsonChannelProcessor() const override
	{
		return m_jsonProcessor;
	}
	void setChannelProcessor(std::shared_ptr<IChannelProcessor> setTo) override
	{
		TcpChannel::setChannelProcessor(setTo);
		m_jsonProcessor = std::dynamic_pointer_cast<IJsonChannelProcessor>(setTo);
	}

protected:
	virtual bool WrapMessage(tscrypto::JSONObject &body)
	{
		if (!!m_jsonProcessor)
			return m_jsonProcessor->WrapMessage(body);

		return true;
	}
	virtual bool UnwrapMessage(tscrypto::JSONObject & body)
	{
		//tsCryptoString encode = headers.AsString("Content-Encoding");

		//if (TsStriCmp(encode, "deflate") == 0)
		//{
		//	tscrypto::tsCryptoData tmp;

		//	if (!zlibDecompress(header->dataPart().c_str(), header->dataPartSize(), tmp) && !raw_zlibDecompress(header->dataPart().c_str(), header->dataPartSize(), tmp))
		//		return false;
		//	header->dataPart(tmp);
		//}

		//if (TsStriCmp(encode, "gzip") == 0)
		//{
		//	tscrypto::tsCryptoData tmp;

		//	if (!gzipDecompress(header->dataPart().c_str(), header->dataPartSize(), tmp))
		//		return false;
		//	header->dataPart(tmp);
		//}

		if (!!m_jsonProcessor)
			return m_jsonProcessor->UnwrapMessage(body);

		return true;
	}
protected:
	std::shared_ptr<IJsonChannelProcessor> m_jsonProcessor;

};


std::shared_ptr<IJsonChannel> CreateJsonChannel()
{
	return ::TopServiceLocator()->Finish<IJsonChannel>(new JsonChannel());
}
