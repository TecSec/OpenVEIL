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

class TcpChannel : public TcpConnection, public ITcpChannel, public tsmod::IObject
{
public:
	TcpChannel();
	virtual ~TcpChannel(void);

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


	virtual void SendLogout() override;
	virtual bool Send(const tscrypto::tsCryptoData& _data) override;
	virtual bool Receive(tscrypto::tsCryptoData& _data, size_t size) override;
	virtual bool isAuthenticated() const override;
	virtual bool processAuthenticationMessages() override;

	std::shared_ptr<IChannelProcessor> getChannelProcessor() const override;
	void setChannelProcessor(std::shared_ptr<IChannelProcessor> setTo) override;

protected:
	virtual bool WrapTransport(tscrypto::tsCryptoData& content);
	virtual bool UnwrapTransport(tscrypto::tsCryptoData& content);

protected:
	std::shared_ptr<IChannelProcessor> m_processor;
};

