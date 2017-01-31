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

#pragma once

#include "HttpHeader.h"

class VEILCORE_API IChannelProcessor
{
public:
	typedef enum {
		inactive,
		login,
		logout,
		active
	} TransportState;

	virtual bool WrapTransport(tscrypto::tsCryptoData& content) = 0;
	virtual bool UnwrapTransport(tscrypto::tsCryptoData& content) = 0;
	virtual bool Logout() = 0;

	virtual TransportState GetTransportState() = 0;
	virtual bool isAuthenticated() const = 0;

	virtual ~IChannelProcessor() {}
	virtual tscrypto::tsCryptoString failureReason() const = 0;

	// TLS 1.2 control - Added 7.0.23 
	virtual void ClearTlsCipherList() = 0;
	virtual void SetCipherList(SSL_CIPHER* list, size_t count) = 0;
	virtual void AddCipher(SSL_CIPHER cipher) = 0;
	virtual void RegisterCertificateVerifier(std::function<SSL_AlertDescription(const tscrypto::tsCryptoDataList& certificate, SSL_CIPHER cipher)> func) = 0;
	virtual void RegisterPSKCallback(std::function<bool(const tscrypto::tsCryptoData& hint, tscrypto::tsCryptoData& identity, tscrypto::tsCryptoData& psk)> func) = 0;
	virtual tscrypto::tsCryptoString CkmAuthUsername() const = 0;
	virtual void CkmAuthUsername(const tscrypto::tsCryptoString& setTo) = 0;
	// Added 7.0.40
	virtual bool shouldCloseAfterTransmit() = 0;
};

class VEILCORE_API IChannelProcessorEvents
{
public:
	virtual ~IChannelProcessorEvents()
	{
	}
	virtual size_t AddOnLogin(std::function<void(const tsmod::IObject*)> func) = 0;
	virtual void RemoveOnLogin(size_t cookie) = 0;

	virtual size_t AddOnLogout(std::function<void(const tsmod::IObject*)> func) = 0;
	virtual void RemoveOnLogout(size_t cookie) = 0;

	virtual size_t AddOnStateChanged(std::function<void(const tsmod::IObject*, uint32_t currentState)> func) = 0;
	virtual void RemoveOnStateChanged(size_t cookie) = 0;

	virtual size_t AddOnFailure(std::function<void(const tsmod::IObject*, const tscrypto::tsCryptoStringBase&)> func) = 0;
	virtual void RemoveOnFailure(size_t cookie) = 0;

	virtual size_t AddOnPacketReceived(std::function<void(const tsmod::IObject*, uint8_t packetType, const uint8_t* data, uint32_t dataLen)> func) = 0;
	virtual void RemoveOnPacketReceived(size_t cookie) = 0;

	virtual size_t AddOnPacketSent(std::function<void(const tsmod::IObject*, uint8_t packetType, const uint8_t* data, uint32_t dataLen)> func) = 0;
	virtual void RemoveOnPacketSent(size_t cookie) = 0;
};

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4231)
VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API tscrypto::ICryptoContainerWrapper<HttpAttribute>;
VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::shared_ptr<tscrypto::ICryptoContainerWrapper<HttpAttribute>>;
#pragma warning(pop)
#endif // _MSC_VER

typedef std::shared_ptr<tscrypto::ICryptoContainerWrapper<HttpAttribute>> HttpAttributeList;
extern VEILCORE_API HttpAttributeList CreateHttpAttributeList();

class VEILCORE_API IHttpChannelProcessor : public IChannelProcessor
{
public:
	virtual bool WrapMessage(tscrypto::tsCryptoString& verb, tscrypto::tsCryptoString& destination, tscrypto::tsCryptoData &body, tscrypto::tsCryptoString& mimeType, HttpAttributeList headers) = 0;
	virtual bool UnwrapMessage(IHttpResponse *header) = 0;

	virtual ~IHttpChannelProcessor() {}
};

class VEILCORE_API INetworkConnectionEvents
{
public:
	virtual ~INetworkConnectionEvents()
	{
	}
	virtual size_t AddOnConnect(std::function<void(const tsmod::IObject*)> func) = 0;
	virtual void RemoveOnConnect(size_t cookie) = 0;

	virtual size_t AddOnError(std::function<void(const tsmod::IObject*, const tscrypto::tsCryptoStringBase&)> func) = 0;
	virtual void RemoveOnError(size_t cookie) = 0;

	virtual size_t AddOnDisconnect(std::function<void(const tsmod::IObject*)> func) = 0;
	virtual void RemoveOnDisconnect(size_t cookie) = 0;
};

class VEILCORE_API ITcpConnection
{
public:
	virtual ~ITcpConnection(void) {}

	virtual const tscrypto::tsCryptoString &Server() const = 0;
	virtual void Server(const tscrypto::tsCryptoString &setTo) = 0;

	virtual unsigned short Port() const = 0;
	virtual void Port(unsigned short setTo) = 0;

	virtual tscrypto::tsCryptoString Errors() const = 0;
	virtual void ClearErrors() = 0;

	virtual bool RawSend(const tscrypto::tsCryptoData& data) = 0;
	virtual bool RawReceive(tscrypto::tsCryptoData& data, size_t size = 5000) = 0;

	virtual bool isConnected() const = 0;

	virtual bool Disconnect() = 0;
	virtual bool Connect() = 0;
};


class VEILCORE_API ITcpChannel : public ITcpConnection
{
public:
	virtual ~ITcpChannel(void) {}

	virtual bool Send(const tscrypto::tsCryptoData& data) = 0;
	virtual void SendLogout() = 0;
	virtual bool Receive(tscrypto::tsCryptoData& data, size_t size = 5000) = 0;

	virtual bool isAuthenticated() const = 0;

	virtual std::shared_ptr<IChannelProcessor> getChannelProcessor() const = 0;
	virtual void setChannelProcessor(std::shared_ptr<IChannelProcessor> setTo) = 0;

	// Added 7.0.15 to force the handling of the authentication when httpv is used.
	virtual bool processAuthenticationMessages() = 0;
};

class VEILCORE_API IWebSocket : public ITcpConnection
{
public:
	typedef enum {
		Normal = 1000,
		GoingAway = 1001,
		ProtocolError = 1002,
		UnsupportedData = 1003,

		NoStatusRcvd = 1005,
		AbnormalClosure = 1006,
		InvalidPayloadData = 1007,
		PolicyViolation = 1008,
		MessageTooBig = 1009,
		MandatoryExt = 1010,
		InternalError = 1011,
		ServiceRestart = 1012,
		TryAgainLater = 1013,
		TlsHandshake = 1015,

		FirstPrivate = 4000,
		LastPrivate = 4999,
	} ClosureCode;

	virtual ~IWebSocket() {}

	virtual bool SendBinary(bool finalBlock, const tscrypto::tsCryptoData& data) = 0;
	virtual bool SendText(bool finalBlock, const tscrypto::tsCryptoString& data) = 0;
	virtual bool CloseChannel(ClosureCode code, const tscrypto::tsCryptoData& otherData) = 0;
	virtual bool Ping(const tscrypto::tsCryptoData& otherData) = 0;
	virtual bool setOnBinaryFrameReceived(std::function<bool(bool finalBlock, const tscrypto::tsCryptoData& data)> setTo) = 0;
	virtual bool setOnTextFrameReceived(std::function<bool(bool finalBlock, const tscrypto::tsCryptoString& data)> setTo) = 0;
	virtual bool setOnPongReceived(std::function<bool()> setTo) = 0;
	virtual bool setOnCloseReceived(std::function<bool()> setTo) = 0;
	virtual tscrypto::tsCryptoString protocolSelected() const = 0;
	virtual tscrypto::tsCryptoString extensionsSelected() const = 0;
};

class VEILCORE_API IHttpChannel : public ITcpChannel
{
public:
	virtual ~IHttpChannel(void) {}

	virtual bool Send(const tscrypto::tsCryptoString& verb, const tscrypto::tsCryptoString& destination, const tscrypto::tsCryptoData &body, const tscrypto::tsCryptoString& mimeType, HttpAttributeList headers = nullptr) = 0;
	virtual bool Receive(IHttpResponse *header) = 0;
	virtual bool Transceive(const tscrypto::tsCryptoString& verb, const tscrypto::tsCryptoString& destination, const tscrypto::tsCryptoData &body, const tscrypto::tsCryptoString& mimeType, IHttpResponse *header, HttpAttributeList requestHeaders = nullptr) = 0;

	virtual std::shared_ptr<IHttpChannelProcessor> getHttpChannelProcessor() const = 0;
	virtual std::shared_ptr<IWebSocket> UpgradeToWebSocket(const tscrypto::tsCryptoString& url, const tscrypto::tsCryptoString& protocols, const tscrypto::tsCryptoString& extensions) = 0;
private:
	using ITcpChannel::Send;
	using ITcpChannel::Receive;
};

class VEILCORE_API IMessageProcessorControl
{
public:
	virtual ~IMessageProcessorControl() {}
	virtual void clear() = 0;
	virtual void start(const tscrypto::tsCryptoData& sessionId, const tscrypto::tsCryptoData& sessionKey) = 0; // http message level only
	virtual bool startTunnel(const tscrypto::tsCryptoString& scheme, std::shared_ptr<ITcpChannel> channel, const tscrypto::tsCryptoString& username = "", const tscrypto::tsCryptoData& password = tscrypto::tsCryptoData()) = 0; // https/httpv message/tunnel 
};

VEILCORE_API std::shared_ptr<IHttpChannel> CreateHttpChannel();
VEILCORE_API std::shared_ptr<ITcpChannel> CreateTcpChannel();
VEILCORE_API tscrypto::tsCryptoString UrlEncode(const tscrypto::tsCryptoString& src);
VEILCORE_API tscrypto::tsCryptoString UrlDecode(const tscrypto::tsCryptoString& src);
