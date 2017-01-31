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

typedef enum {
	Continuation = 0,
	TextFrame = 1,
	BinaryFrame = 2,
	ReservedData1 = 3,
	ReservedData2 = 4,
	ReservedData3 = 5,
	ReservedData4 = 6,
	ReservedData5 = 7,

	ConnectionClose = 8,
	Ping = 9,
	Pong = 10,

	ReservedControl1 = 11,
	ReservedControl2 = 12,
	ReservedControl3 = 13,
	ReservedControl4 = 14,
	ReservedControl5 = 15,

} WebSocketOpcode;
typedef struct FrameHeader {
	bool fin;
	bool rsv1;
	bool rsv2;
	bool rsv3;
	uint8_t opcode;
	bool mask;
	uint64_t payloadLen;
	uint8_t maskingKey[4];
} FrameHeader;

class WebSocket : public IWebSocket, public tsmod::IObject, INetworkConnectionEvents
{
public:
	WebSocket(std::shared_ptr<ITcpChannel> channel, const tscrypto::tsCryptoString& protocol, const tscrypto::tsCryptoString& extensions) : 
		_channel(channel), _protocol(protocol), _extensions(extensions), dataType(0), sendingDataType(0), _sentClose(false)
	{}
	virtual ~WebSocket() 
	{
		if (_receiver.Active())
		{
			if (!!_channel && _channel->isConnected())
			{
				if (!_sentClose)
				{
					SendError(IWebSocket::ClosureCode::Normal, tscrypto::tsCryptoData());
				}
				_channel->Disconnect();
				_channel.reset();
			}

			_receiver.Cancel();
			if (!_receiver.WaitForThread(10000))
				_receiver.Kill();
		}
	}

	virtual void OnConstructionFinished() override
	{
		_receiver.SetWorker([this]()->int {
			return OnLookForData();
		});
		_receiver.Start();
	}
	// Inherited via IWebSocket
	virtual const tscrypto::tsCryptoString & Server() const override
	{
		if (!_channel || !_channel->isConnected())
			throw std::runtime_error("The channel has been closed.");
		return _channel->Server();
	}
	virtual void Server(const tscrypto::tsCryptoString & setTo) override
	{
		throw std::runtime_error("Changing the server on a WebSocket is not supported.");
	}
	virtual unsigned short Port() const override
	{
		if (!_channel || !_channel->isConnected())
			throw std::runtime_error("The channel has been closed.");
		return _channel->Port();
	}
	virtual void Port(unsigned short setTo) override
	{
		throw std::runtime_error("Changing the port on a WebSocket is not supported.");
	}
	virtual tscrypto::tsCryptoString Errors() const override
	{
		tscrypto::tsCryptoString tmp(_errors);

		if (!_channel || !_channel->isConnected())
			throw std::runtime_error("The channel has been closed.");
		if (_channel->Errors().size() > 0)
		{
			if (tmp.size() > 0)
				tmp << tscrypto::endl;
			tmp << _channel->Errors();
		}
		return tmp;
	}
	virtual void ClearErrors() override
	{
		if (!_channel || !_channel->isConnected())
			throw std::runtime_error("The channel has been closed.");
		_channel->ClearErrors();
		_errors.clear();
	}
	virtual bool RawSend(const tscrypto::tsCryptoData & data) override
	{
		if (!_channel || !_channel->isConnected())
			throw std::runtime_error("The channel has been closed.");
		return _channel->RawSend(data);
	}
	virtual bool RawReceive(tscrypto::tsCryptoData & data, size_t size) override
	{
		if (!_channel || !_channel->isConnected())
			throw std::runtime_error("The channel has been closed.");
		return _channel->RawReceive(data, size);
	}
	virtual bool isConnected() const override
	{
		if (!_channel || !_channel->isConnected())
			return false;
		return true;
	}
	virtual bool Disconnect() override
	{
		if (!_channel || !_channel->isConnected())
			return true;
		if (!_sentClose)
		{
			SendError(IWebSocket::ClosureCode::Normal, tscrypto::tsCryptoData());
		}
		bool retVal = _channel->Disconnect();

		_channel.reset();

		_receiver.Cancel();
		_receiver.WaitForThread(10000);
		return retVal;
	}
	virtual bool Connect() override
	{
		throw std::runtime_error("Connect is not allowed on WebSocket connections.");
	}
	virtual bool SendBinary(bool finalBlock, const tscrypto::tsCryptoData & data) override
	{
		if (!_channel || !_channel->isConnected())
			throw std::runtime_error("The channel has been closed.");

		if (sendingDataType == 1)
			return false; // was sending a text message
		bool retVal = SendFrame(finalBlock, sendingDataType > 0 ? 0 : 2, data);
		if (finalBlock)
			sendingDataType = 0;
		else
			sendingDataType = 2;
		return retVal;
	}
	virtual bool SendText(bool finalBlock, const tscrypto::tsCryptoString & data) override
	{
		if (!_channel || !_channel->isConnected())
			throw std::runtime_error("The channel has been closed.");

		if (sendingDataType == 2)
			return false; // was sending a binary message
		bool retVal = SendFrame(finalBlock, sendingDataType > 0 ? 0 : 1, data.ToUTF8Data());
		if (finalBlock)
			sendingDataType = 0;
		else
			sendingDataType = 1;
		return retVal;
	}
	virtual bool CloseChannel(ClosureCode code, const tscrypto::tsCryptoData & otherData) override
	{
		if (!_channel || !_channel->isConnected())
			throw std::runtime_error("The channel has been closed.");

		_sentClose = true;
		SendError(code, otherData);
		_disconnectSignals.Fire(this);
		return true;
	}
	virtual bool Ping(const tscrypto::tsCryptoData & otherData) override
	{
		if (!_channel || !_channel->isConnected())
			throw std::runtime_error("The channel has been closed.");

		return SendFrame(true, WebSocketOpcode::Ping, otherData);
	}
	virtual bool setOnBinaryFrameReceived(std::function<bool(bool finalBlock, const tscrypto::tsCryptoData&data)> setTo) override
	{
		if (!_channel || !_channel->isConnected())
			throw std::runtime_error("The channel has been closed.");

		OnBinaryFrameReceived = setTo;
		return true;
	}
	virtual bool setOnTextFrameReceived(std::function<bool(bool finalBlock, const tscrypto::tsCryptoString&data)> setTo) override
	{
		if (!_channel || !_channel->isConnected())
			throw std::runtime_error("The channel has been closed.");

		OnTextFrameReceived = setTo;
		return true;
	}
	virtual bool setOnPongReceived(std::function<bool()> setTo) override
	{
		if (!_channel || !_channel->isConnected())
			throw std::runtime_error("The channel has been closed.");

		OnPongReceived = setTo;
		return true;
	}
	virtual bool setOnCloseReceived(std::function<bool()> setTo) override
	{
		if (!_channel || !_channel->isConnected())
			throw std::runtime_error("The channel has been closed.");

		OnCloseReceived = setTo;
		return true;
	}
	virtual tscrypto::tsCryptoString protocolSelected() const override
	{
		if (!_channel || !_channel->isConnected())
			throw std::runtime_error("The channel has been closed.");

		return _protocol;
	}
	virtual tscrypto::tsCryptoString extensionsSelected() const override
	{
		if (!_channel || !_channel->isConnected())
			throw std::runtime_error("The channel has been closed.");

		return _extensions;
	}
protected:
	std::shared_ptr<ITcpChannel> _channel;
	tscrypto::tsCryptoString _errors;
	tsThread _receiver;
	tscrypto::tsCryptoString _protocol;
	tscrypto::tsCryptoString _extensions;
	uint8_t dataType;
	uint8_t sendingDataType;
	bool _sentClose;
	tscrypto::tsCryptoData _bufferedData;
	std::function<bool(bool finalBlock, const tscrypto::tsCryptoData&data)> OnBinaryFrameReceived;
	std::function<bool(bool finalBlock, const tscrypto::tsCryptoString&data)> OnTextFrameReceived;
	std::function<bool()> OnPongReceived;
	std::function<bool()> OnCloseReceived;
	tsIObjectSignal _connectSignals;
	tsIObjStringSignal _errorSignals;
	tsIObjectSignal _disconnectSignals;

	bool SendFrame(bool fin, uint8_t opcode, const tscrypto::tsCryptoData& data)
	{
		tscrypto::tsCryptoData frame;
		uint64_t len = data.size();

		if (!_channel || !_channel->isConnected())
			throw std::runtime_error("The channel has been closed.");

		frame.resize(2);
		frame[0] = (fin ? 0x80 : 0) | (opcode & 15);
		if (len > 65535)
		{
			frame[1] = 127;
			frame << (uint8_t)(len >> 56) << (uint8_t)(len >> 48) << (uint8_t)(len >> 40) << (uint8_t)(len >> 32) <<
				(uint8_t)(len >> 24) << (uint8_t)(len >> 16) << (uint8_t)(len >> 8) << (uint8_t)(len);
		}
		else if (len > 125)
		{
			frame[1] = 126;
			frame << (uint8_t)(len >> 8) << (uint8_t)(len);
		}
		else
		{
			frame[1] = (uint8_t)(len & 127);
		}
		frame << data;
		if (opcode == WebSocketOpcode::ConnectionClose)
		{
			_sentClose = true;
		}
		bool retVal = RawSend(frame);
		if (opcode == WebSocketOpcode::ConnectionClose)
		{
			dataType = 0;
			sendingDataType = 0;
		}
		return retVal;
	}
	void SendError(IWebSocket::ClosureCode code, const tscrypto::tsCryptoData& otherData)
	{
		tscrypto::tsCryptoData data;

		data << (uint8_t)(code >> 8) << (uint8_t)(code) << otherData;
		_sentClose = true;
		SendFrame(true, WebSocketOpcode::ConnectionClose, data);
	}
	bool ProcessDataBlock(const tscrypto::tsCryptoData& data)
	{
		FrameHeader header;
		tscrypto::tsCryptoData fragment;
		int offset = 2;

		_bufferedData << data;
		try
		{
			// Now process the protocol data
			do
			{
				if (_bufferedData.size() >= 2)
				{
					// Extract the header
					header.fin = ((_bufferedData[0] & 0x80) != 0);
					header.rsv1 = ((_bufferedData[0] & 0x40) != 0);
					header.rsv2 = ((_bufferedData[0] & 0x20) != 0);
					header.rsv3 = ((_bufferedData[0] & 0x10) != 0);
					header.opcode = (_bufferedData[0] & 0x0f);
					header.mask = ((_bufferedData[1] & 0x80) != 0);
					header.payloadLen = (_bufferedData[1] & 0x7f);
					if (header.payloadLen == 126)
					{
						if (_bufferedData.size() < 4)
						{
							// More data needed
							return true;
						}
						header.payloadLen = (_bufferedData[2] << 8) | _bufferedData[3];
						offset += 2;
					}
					else if (header.payloadLen == 127)
					{
						if (_bufferedData.size() < 10)
						{
							// More data needed
							return true;
						}
						header.payloadLen = ((uint64_t)_bufferedData[2] << 56) | ((uint64_t)_bufferedData[3] << 48) | ((uint64_t)_bufferedData[4] << 40) |
							((uint64_t)_bufferedData[5] << 32) | ((uint64_t)_bufferedData[6] << 24) | ((uint64_t)_bufferedData[7] << 16) |
							((uint64_t)_bufferedData[8] << 8) | (uint64_t)_bufferedData[9];
						offset += 8;
					}
					if (header.mask)
					{
						if (_bufferedData.size() < offset + 4)
						{
							// More data needed
							return true;
						}
						memcpy(header.maskingKey, &_bufferedData.c_str()[offset], 4);
						offset += 4;
					}
					// See if we need more data
					if (_bufferedData.size() < offset + header.payloadLen)
					{
						// More data needed
						return true;
					}
					// We have all of the data, now do some validations
					if (header.rsv1 || header.rsv2 || header.rsv3)
					{
						// Send error
					}
					if (!header.mask)
					{
						// send error - client must always mask
					}
					if (header.payloadLen > 1000000) // TODO:  Make this configurable
					{
						// send error - limiting max data length and frame is too long
					}
					// extract and unmask the data
					fragment = _bufferedData.substring(offset, header.payloadLen);
					_bufferedData.erase(0, offset + header.payloadLen);
					if (header.mask)
					{
						size_t count = fragment.size();
						for (size_t i = 0; i < count; i++)
						{
							fragment[i] ^= header.maskingKey[(i & 3)];
						}
					}
					// Now process the data - Remember to handle any extensions also
					switch (header.opcode)
					{
					case WebSocketOpcode::Continuation: // Continuation data frame
						if (dataType == 1)
						{
							if (!!OnTextFrameReceived)
							{
								OnTextFrameReceived(header.fin, fragment.ToUtf8String()); // TODO:  What if false returned
							}
							if (header.fin)
								dataType = 0;
						}
						else if (dataType == 2)
						{
							if (!!OnBinaryFrameReceived)
							{
								OnBinaryFrameReceived(header.fin, fragment); // TODO:  What if false returned
							}
							if (header.fin)
								dataType = 0;
						}
						else
							SendError(IWebSocket::ClosureCode::ProtocolError, tscrypto::tsCryptoData());
						break;
					case WebSocketOpcode::TextFrame: // text frame
						dataType = 1;
						if (!!OnTextFrameReceived)
						{
							OnTextFrameReceived(header.fin, fragment.ToUtf8String()); // TODO:  What if false returned
						}
						if (header.fin)
							dataType = 0;
						break;
					case WebSocketOpcode::BinaryFrame: // binary frame
						dataType = 2;
						if (!!OnBinaryFrameReceived)
						{
							OnBinaryFrameReceived(header.fin, fragment); // TODO:  What if false returned
						}
						if (header.fin)
							dataType = 0;
						break;
					case WebSocketOpcode::ConnectionClose:
						if (!_sentClose)
						{
							SendFrame(true, WebSocketOpcode::ConnectionClose, fragment);
						}
						_sentClose = true;
						_bufferedData.clear();
						if (!!OnCloseReceived)
						{
							OnCloseReceived();
						}
						_disconnectSignals.Fire(this);
						return true;
					case WebSocketOpcode::Ping: // ping
						SendFrame(true, WebSocketOpcode::Pong, fragment);
						break;
					case WebSocketOpcode::Pong: // pong - response to ping
						if (!!OnPongReceived)
						{
							OnPongReceived();
						}
						break;
					case WebSocketOpcode::ReservedData1:
					case WebSocketOpcode::ReservedData2:
					case WebSocketOpcode::ReservedData3:
					case WebSocketOpcode::ReservedData4:
					case WebSocketOpcode::ReservedData5:
					case WebSocketOpcode::ReservedControl1:
					case WebSocketOpcode::ReservedControl2:
					case WebSocketOpcode::ReservedControl3:
					case WebSocketOpcode::ReservedControl4:
					case WebSocketOpcode::ReservedControl5:
					default:
						SendError(IWebSocket::ClosureCode::ProtocolError, tscrypto::tsCryptoData());
						break;
					}
				}
				else
				{
					// More data needed
					return true;
				}
			} while (_bufferedData.size() > 0);
			return true;
		}
		catch (...)
		{
			SendError(IWebSocket::ClosureCode::ProtocolError, tscrypto::tsCryptoData());
			return true;
		}

	}
	int OnLookForData()
	{
		tscrypto::tsCryptoData data;

		while (_receiver.Active())
		{
			switch (_receiver.cancelEvent().WaitForEvent(200))
			{
			case CryptoEvent::Timeout:
				break;
			case CryptoEvent::AlreadyLocked:
			case CryptoEvent::Succeeded_Object1:
				return 0;
			case CryptoEvent::Failed:
				return 1;
            default:
                break;
			}
			// Now look for changes
			if (!isConnected())
			{
				return 0;
			}
			else
			{
				data.clear();

				while (RawReceive(data, 65536) || data.size() > 0)
				{
					bool retVal = ProcessDataBlock(data);
					data.clear();
					if (!retVal)
					{
						Disconnect();
						return 0;
					}
				}
			}
		}
		return 0;
	}

	// Inherited via INetworkConnectionEvents
	virtual size_t AddOnConnect(std::function<void(const tsmod::IObject*)> func) override
	{
		return _connectSignals.Add(func);
	}
	virtual void RemoveOnConnect(size_t cookie) override
	{
		_connectSignals.Remove(cookie);
	}
	virtual size_t AddOnError(std::function<void(const tsmod::IObject*, const tscrypto::tsCryptoStringBase&)> func) override
	{
		return _errorSignals.Add(func);
	}
	virtual void RemoveOnError(size_t cookie) override
	{
		_errorSignals.Remove(cookie);
	}
	virtual size_t AddOnDisconnect(std::function<void(const tsmod::IObject*)> func) override
	{
		return _disconnectSignals.Add(func);
	}
	virtual void RemoveOnDisconnect(size_t cookie) override
	{
		_disconnectSignals.Remove(cookie);
	}
};

class HttpChannel : public TcpChannel, public virtual IHttpChannel
{
public:
	HttpChannel()
	{
	}
	virtual ~HttpChannel(void)
	{
	}

	// Resolve virtual funcs in the interface class inheritance
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

	virtual bool Send(const tscrypto::tsCryptoString& __verb, const tscrypto::tsCryptoString& __destination, const tscrypto::tsCryptoData &__body, const tscrypto::tsCryptoString& __mimeType, HttpAttributeList __headers) override
	{
		tscrypto::tsCryptoString strMessage;
		tscrypto::tsCryptoData message;

		tscrypto::tsCryptoString _verb(__verb);
		tscrypto::tsCryptoString _destination(__destination);
		tscrypto::tsCryptoData _body(__body);
		tscrypto::tsCryptoString _mimeType(__mimeType);
		HttpAttributeList _headers = CreateHttpAttributeList();

		if (__verb == "GET" || __verb == "DELETE" || __verb == "MOVE" || __verb == "HEAD")
		{
			if (__body.size() > 0)
			{
				UrlParser url;

				if (url.ParseFullUrl(__destination))
				{
					JSONObject obj;

					if (obj.FromJSON(__body.ToUtf8String().c_str()))
					{
						obj.foreach([&url](JSONField& fld) {
							url.getParameters()->push_back(NameValue(fld.Name(), fld.AsString()));
						});
						_destination = url.BuildUrl();
						_body.clear();
					}
				}

			}
		}

		bool hasAcceptEncoding = false;
		if (!!__headers && __headers->size() > 0)
		{
			for (size_t i = 0; i < __headers->size(); i++)
			{
				_headers->push_back(__headers->at(i));
				if (TsStriCmp(__headers->at(i).m_Name, "Accept-Encoding") == 0)
					hasAcceptEncoding = true;
			}
		}

		flushBuffer();

		if (!hasAcceptEncoding)
		{
			_headers->push_back(HttpAttribute("Accept-Encoding", "gzip, deflate"));
		}

		if (!!m_processor)
		{
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
				{
					int len;
					tscrypto::tsCryptoData buff;

					buff.resize(1024);
#ifdef _WIN32
					len = recv(m_socket, (char*)buff.rawData(), 1023, MSG_PEEK);
#else
					len = recv((int)m_socket, (char*)buff.rawData(), 1023, MSG_PEEK);
#endif
					if (len > 0)
					{
#ifdef _WIN32
						len = recv(m_socket, (char*)buff.rawData(), len, 0);
#else
						len = recv((int)m_socket, (char*)buff.rawData(), len, 0);
#endif
						if (len > 0)
						{
							buff.resize(len);

							LOG(httpData, "recv'd" << tscrypto::endl << buff.ToHexDump());

							if (!m_processor || !m_processor->UnwrapTransport(buff))
								return false;
							if (buff.size() > 0)
								m_bufferedData << buff;
						}
						else if (len == SOCKET_ERROR)
							return false;
					}
					else if (len == SOCKET_ERROR)
						return false;
					else
					{
						XP_Sleep(100);
					}
				}
				}
			} while (!!m_processor && m_processor->GetTransportState() == IHttpChannelProcessor::login);
		}

		if (!WrapMessage(_verb, _destination, _body, _mimeType, _headers))
		{
			m_errors += "Message wrapping failed\n";
			_errorSignals.Fire(this, m_errors);
			return false;
		}

		strMessage << _verb << " " << _destination << " " << "HTTP/1.1\r\n";
		strMessage << "Host: " << m_server << ":" << m_port << "\r\n";
		strMessage << "Content-Length: " << (_body.size()) << "\r\n";
		strMessage << "Content-Type: " << _mimeType << "\r\n";
		for (auto attr : *_headers)
		{
			strMessage << attr.m_Name << ": " << attr.m_Value << "\r\n";
		}
		strMessage += "\r\n";
		message.AsciiFromString(strMessage);
		message += _body;

		// Make sure that WSA is initialized
		if (!WSAInitialize())
		{
			m_errors += "Unable to initialize the socket system.\n";
			_errorSignals.Fire(this, m_errors);
			return false;
		}
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
	virtual bool Receive(IHttpResponse *header) override
	{
		//int64_t start = GetTicks();

		IHttpHeader* hdr = dynamic_cast<IHttpHeader*>(header);

		if (hdr == nullptr)
			return false;

		switch (hdr->ReadStream(m_socket, m_bufferedData, m_httpProcessor))
		{
		case IHttpHeader::hh_Success:
			break;
		case IHttpHeader::hh_Failure:
			m_errors += hdr->Errors();
			hdr->ClearErrors();
			_errorSignals.Fire(this, m_errors);
			return false;
		case IHttpHeader::hh_CloseSocket:
#ifdef _WIN32
			closesocket(m_socket);
#else
			if (m_socket != INVALID_SOCKET)
				close((int)m_socket);
#endif
			m_socket = INVALID_SOCKET;
			m_isConnected = false;
			return false;
		}

		while (TsStrToInt(hdr->status()) == 100)
		{
			//
			// We got a continue command from the server.  Eat it and reparse using any remaining data
			//
			tscrypto::tsCryptoData data = hdr->dataPart();
			hdr->clear();
			switch (hdr->ReadStream(m_socket, data, m_httpProcessor))
			{
			case IHttpHeader::hh_Success:
				break;
			case IHttpHeader::hh_Failure:
				m_errors += hdr->Errors();
				hdr->ClearErrors();
				_errorSignals.Fire(this, m_errors);
				return false;
			case IHttpHeader::hh_CloseSocket:
#ifdef _WIN32
				closesocket(m_socket);
#else
				if (m_socket != INVALID_SOCKET)
					close((int)m_socket);
#endif
				m_socket = INVALID_SOCKET;
				m_isConnected = false;
				return false;
			}
		}
		//LOG(httpLog, "Data Receive in " << (GetTicks() - start) / 1000.0 << " ms");
		if (!UnwrapMessage(header))
		{
			m_errors += "Unable to unwrap the received message.\n";
			_errorSignals.Fire(this, m_errors);
			return false;
		}
		//LOG(httpLog, "Processed Receive in " << (GetTicks() - start) / 1000.0 << " ms");
		return true;
	}
	virtual bool Transceive(const tscrypto::tsCryptoString& verb, const tscrypto::tsCryptoString& destination, const tscrypto::tsCryptoData &body, const tscrypto::tsCryptoString& mimeType, IHttpResponse *header, HttpAttributeList requestHeaders) override
	{
		//		int64_t start = GetTicks();

		if (!Send(verb, destination, body, mimeType, requestHeaders) || !Receive(header))
			return false;
		//		LOG(httpLog, "Transceive in " << (GetTicks() - start) / 1000.0 << " ms");
		return true;
	}

	std::shared_ptr<IHttpChannelProcessor> getHttpChannelProcessor() const override
	{
		return m_httpProcessor;
	}
	void setChannelProcessor(std::shared_ptr<IChannelProcessor> setTo) override
	{
		TcpChannel::setChannelProcessor(setTo);
		m_httpProcessor = std::dynamic_pointer_cast<IHttpChannelProcessor>(setTo);
	}
	virtual std::shared_ptr<IWebSocket> UpgradeToWebSocket(const tscrypto::tsCryptoString& url, const tscrypto::tsCryptoString & protocols, const tscrypto::tsCryptoString & extensions) override
	{
		HttpAttributeList _headers = CreateHttpAttributeList();
		tscrypto::tsCryptoData tmp;
		tscrypto::tsCryptoData hash;
		tscrypto::tsCryptoString gotprotocol;
		tscrypto::tsCryptoString gotextensions;
		std::shared_ptr<IHttpResponse> _hdr = std::shared_ptr<IHttpResponse>(dynamic_cast<IHttpResponse*>(CreateHttpResponse()));

		if (!_hdr || !TSGenerateRandom(tmp, 16))
			return nullptr;

		_headers->push_back(HttpAttribute("Upgrade", "WebSocket"));
		_headers->push_back(HttpAttribute("Sec-WebSocket-Key", tmp.ToBase64()));
		if (protocols.size() > 0)
			_headers->push_back(HttpAttribute("Sec-WebSocket-Protocol", protocols));
		if (extensions.size() > 0)
			_headers->push_back(HttpAttribute("Sec-WebSocket-Extension", extensions));

		if (!Send("GET", url, tscrypto::tsCryptoData(), "", _headers) || !Receive(_hdr.get()) || _hdr->errorCode() != 101)
			return nullptr;

		TSHash((tmp.ToBase64() + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").ToUTF8Data(), hash, _TS_ALG_ID::TS_ALG_SHA1);
		const HttpAttribute* attr = _hdr->attributeByName("Sec-WebSocket-Accept");
		if (attr == nullptr || attr->m_Value != hash.ToBase64())
			return nullptr;

		attr = _hdr->attributeByName("Sec-WebSocket-Protocol");
		if (attr != nullptr)
			gotprotocol = attr->m_Value;
		attr = _hdr->attributeByName("Sec-WebSocket-Extension");
		if (attr != nullptr)
			gotextensions = attr->m_Value;

		std::shared_ptr<WebSocket> ws = std::make_shared<WebSocket>(std::dynamic_pointer_cast<ITcpChannel>(_me.lock()), gotprotocol, gotextensions);
		return std::dynamic_pointer_cast<IWebSocket>(ws);
	}

protected:
	virtual bool WrapMessage(tscrypto::tsCryptoString& verb, tscrypto::tsCryptoString& destination, tscrypto::tsCryptoData &body, tscrypto::tsCryptoString& mimeType, HttpAttributeList& headers)
	{
		if (!!m_httpProcessor)
			return m_httpProcessor->WrapMessage(verb, destination, body, mimeType, headers);

		return true;
	}
	virtual bool UnwrapMessage(IHttpResponse *header)
	{
		const HttpAttribute* attr = header->attributeByName("Content-Encoding");

		if (attr != nullptr && TsStriCmp(attr->m_Value, "deflate") == 0)
		{
			tscrypto::tsCryptoData tmp;

			if (!zlibDecompress(header->dataPart().c_str(), header->dataPartSize(), tmp) && !raw_zlibDecompress(header->dataPart().c_str(), header->dataPartSize(), tmp))
				return false;
			header->dataPart(tmp);
		}

		if (attr != nullptr && TsStriCmp(attr->m_Value, "gzip") == 0)
		{
			tscrypto::tsCryptoData tmp;

			if (!gzipDecompress(header->dataPart().c_str(), header->dataPartSize(), tmp))
				return false;
			header->dataPart(tmp);
		}

		if (!!m_httpProcessor)
			return m_httpProcessor->UnwrapMessage(header);

		return true;
	}
protected:
	std::shared_ptr<IHttpChannelProcessor> m_httpProcessor;
};


std::shared_ptr<IHttpChannel> CreateHttpChannel()
{
	return ::TopServiceLocator()->Finish<IHttpChannel>(new HttpChannel());
}

// Based on RFC3986
tscrypto::tsCryptoString UrlEncode(const tscrypto::tsCryptoString& src)
{
	tscrypto::tsCryptoString tmp;

	tmp.resize(src.size());
	tmp.resize(0);

	for (size_t i = 0; i < src.size(); i++)
	{
		char c = src[i];

		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '-' || c == '_' || c == '.' || c == '~')
		{
			tmp << c;
		}
		else
		{
			tmp << "%" << "0123456789ABCDEF"[(c >> 4) & 0x0f] << "0123456789ABCDEF"[c & 0x0f];
		}
	}
	return tmp;
}

static bool isHexNibble(char c)
{
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
static char getHexNibble(char c)
{
	if (c >= '0' && c <= '9')
	{
		return (c - '0');
	}
	if (c >= 'a' && c <= 'f')
	{
		return (c + 10 - 'a');
	}
	if (c >= 'A' && c <= 'F')
	{
		return (c + 10 - 'A');
	}
	return 0;
}
// Based on RFC3986
tscrypto::tsCryptoString UrlDecode(const tscrypto::tsCryptoString& src)
{
	tscrypto::tsCryptoString tmp;

	tmp.resize(src.size());
	tmp.clear();

	for (size_t i = 0; i < src.size(); i++)
	{
		char c = src[i];

		if (c == '%')
		{
			if (src.size() < i + 3 || !isHexNibble(src[i + 1]) || !isHexNibble(src[i + 2]))
			{
				tmp << c;
			}
			else
			{
				c = (char)(getHexNibble(src[i + 1]) << 4) | getHexNibble(src[i + 2]);
				i += 2;
				tmp << c;
			}
		}
		else
			tmp << c;
	}
	return tmp;
}



