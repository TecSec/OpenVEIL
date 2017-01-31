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

typedef struct tag_CallbackHolder
{
	std::function<void(JSONObject& eventData)> func;
	std::function<void()> generalFunc;
	size_t cookie;
} CallbackHolder;

class KeyVEILConnector : public IKeyVEILConnector, public tsmod::IObject
{
public:
	KeyVEILConnector() : _isGenericConnection(false), _nextCallbackId(0), _lastEvent(0), _lastConnected(false)
	{
	}
	virtual ~KeyVEILConnector()
	{
		if (_callbackThread.Active())
		{
			_callbackThread.Cancel();
			_callbackThread.WaitForThread(20000);
		}
		_callbacks.clear();
		disconnect();
	}

	virtual ConnectionStatus genericConnectToServer(const tscrypto::tsCryptoStringBase& url, const tscrypto::tsCryptoStringBase& username, const tscrypto::tsCryptoStringBase& password) override
	{
		tscrypto::tsCryptoString cmd, errors, filename;
		UrlParser parser;
		tscrypto::CryptoEvent done;
		tscrypto::tsCryptoData authKey;

		if (!!_channel)
		{
			disconnect();
		}
		_isGenericConnection = true;
		TSAUTOLOCKER lock(_channelLock);
		_channel = CreateHttpChannel();
		_hdr = std::shared_ptr<IHttpResponse>(dynamic_cast<IHttpResponse*>(CreateHttpResponse()));

		_msgProcessor = ::TopServiceLocator()->get_instance<IMessageProcessorControl>("TcpMessageProcessor");
		_httpProcessor = std::dynamic_pointer_cast<IHttpChannelProcessor>(_msgProcessor);

		if (!parser.ParseFullUrl(url))
		{
			return connStatus_UrlBad;
		}

		_scheme = parser.getScheme();
		parser.setScheme("");

		cmd = parser.BuildUrl();

		_genericBaseUrl << cmd;

		if (cmd.size() > 0 && cmd[cmd.size() - 1] == '/')
			cmd.resize(cmd.size() - 1);

		if (cmd.size() >= 14 && TsStriCmp("/ebadmin.tsmod", &cmd.c_str()[cmd.size() - 14]) == 0)
			cmd.resize(cmd.size() - 14);
		else if (cmd.size() > 4 && TsStriCmp("/bin", &cmd.c_str()[cmd.size() - 4]) == 0)
			cmd.resize(cmd.size() - 4);

		_baseUri << cmd << "/bin/";
		_baseUri.Replace("//bin", "/bin");

		_channel->Server(parser.getServer());
		_channel->Port(parser.getPort() == 0 ? 80 : (WORD)parser.getPort());

		if (!_channel->Connect())
		{
			_msgProcessor.reset();
			_httpProcessor.reset();
			_channel->setChannelProcessor(nullptr);
			return connStatus_NoServer;
		}

		if (_scheme == "httpv" || _scheme == "https")
		{
			_channel->SendLogout();
			if (password.size() == 0)
			{
				disconnect();
				return connStatus_BadAuth;
			}
			if (!_msgProcessor->startTunnel(_scheme, std::dynamic_pointer_cast<ITcpChannel>(_channel), username, tsCryptoData(password)))
			{
				disconnect();
				return connStatus_BadAuth;
			}
			_channel->setChannelProcessor(_httpProcessor);
			if (!_channel->processAuthenticationMessages() || _httpProcessor->GetTransportState() != IHttpChannelProcessor::active)
			{
				disconnect();
				return connStatus_BadAuth;
			}
		}
		else
		{
			_channel->SendLogout();
			if (username.size() > 0 && password.size() > 0)
			{
				if (!Login(_channel, _hdr.get(), _baseUri, username, tsCryptoData(password)))
				{
					disconnect();
					return connStatus_BadAuth;
				}
			}
			// TODO:  Need new logic here if https is used.
			else if (username.size() > 0)
			{
				disconnect();
				return connStatus_BadAuth;
			}
		}

		_username = username;
		_password = password;
		_lastConnected = true;
		return connStatus_Connected;
	}
	virtual ConnectionStatus connect(const tscrypto::tsCryptoStringBase& url, const tscrypto::tsCryptoStringBase& username, const tscrypto::tsCryptoStringBase& password) override
	{
		tscrypto::tsCryptoString cmd, errors, filename;
		UrlParser parser;
		tscrypto::CryptoEvent done;
		tscrypto::tsCryptoData authKey;

		if (!!_channel)
		{
			disconnect();
		}
		TSAUTOLOCKER lock(_channelLock);
		_isGenericConnection = false;

		_msgProcessor = ::TopServiceLocator()->get_instance<IMessageProcessorControl>("TcpMessageProcessor");
		_httpProcessor = std::dynamic_pointer_cast<IHttpChannelProcessor>(_msgProcessor);

		_channel = CreateHttpChannel();
		_hdr = std::shared_ptr<IHttpResponse>(dynamic_cast<IHttpResponse*>(CreateHttpResponse()));


		if (!parser.ParseFullUrl(url))
		{
			return connStatus_UrlBad;
		}

		_scheme = parser.getScheme();
		parser.setScheme("");

		cmd = parser.BuildUrl();

		_baseUri.clear();
		_baseUri << cmd << "/bin/";
		_baseUri.Replace("//bin", "/bin");

		_channel->Server(parser.getServer());
		_channel->Port(parser.getPort() == 0 ? 80 : (WORD)parser.getPort());

		if (!_channel->Connect())
		{
			_msgProcessor.reset();
			_httpProcessor.reset();
			_channel->setChannelProcessor(nullptr);
			return connStatus_NoServer;
		}

		if (_scheme == "httpv" || _scheme == "https")
		{
			_channel->SendLogout();
			if (password.size() == 0)
			{
				disconnect();
				return connStatus_BadAuth;
			}
			if (!_msgProcessor->startTunnel(_scheme, _channel, username, tsCryptoData(password)))
			{
				disconnect();
				return connStatus_BadAuth;
			}
			_channel->setChannelProcessor(_httpProcessor);
			if (!_channel->processAuthenticationMessages() || _httpProcessor->GetTransportState() != IHttpChannelProcessor::active)
			{
				disconnect();
				return connStatus_BadAuth;
			}
		}
		else
		{
			_channel->SendLogout();
			if (password.size() > 0)
			{
				if (!Login(_channel, _hdr.get(), _baseUri, username, tsCryptoData(password)))
				{
					disconnect();
					return connStatus_BadAuth;
				}
			}
			// TODO:  Need new logic here if https is used.
			else
			{
				disconnect();
				return connStatus_BadAuth;
			}
		}

		LoadTokens();

		_username = username;
		_password = password;
		_lastConnected = true;
		return connStatus_Connected;
	}
	virtual void disconnect() override
	{
		TSAUTOLOCKER lock(_channelLock);
		if (!!_channel)
		{
			if (_channel->isAuthenticated())
				_channel->SendLogout();
			_channel->Disconnect();
		}
		_isGenericConnection = false;
		_genericBaseUrl.clear();
		_channel.reset();
		_hdr.reset();
		_msgProcessor.reset();
		_httpProcessor.reset();
		_username.clear();
		_password.clear();
		TSAUTOLOCKER tokenLock(_tokenListLock);
		_tokens.clear();
		TSAUTOLOCKER favLock(_favoriteListLock);
		_favorites.clear();
		_lastConnected = false;
	}
	virtual bool isConnected() override
	{
		bool retVal = !!_channel && _channel->isConnected();

		if (retVal != _lastConnected)
		{
			_lastConnected = retVal;
			if (!retVal)
			{
				disconnect();

				TSAUTOLOCKER lock(_callbackLock);
				for (auto holder : _callbacks)
				{
					if (!!holder.generalFunc)
						holder.generalFunc();
				}
			}
		}
		return retVal;
	}
	virtual bool refresh() override
	{
		TSAUTOLOCKER favLock(_favoriteListLock);
		_favorites.clear();
		favLock.Unlock();

		TSAUTOLOCKER lock(_channelLock);
		if (!_channel)
			return false;
		if (!_channel->isConnected())
		{
			if (!_channel->Connect())
			{
				disconnect();
				return false;
			}
		}
		if (!_channel->isAuthenticated())
		{
			if (_scheme == "httpv" || _scheme == "https")
			{
				_channel->SendLogout();
				if (!_msgProcessor->startTunnel(_scheme, _channel, _username, _password.ToUTF8Data()))
				{
					disconnect();
					return false;
				}
				_channel->setChannelProcessor(_httpProcessor);
			}
			else
			{
				_channel->SendLogout();
				if (!_isGenericConnection || _password.size() > 0)
				{
					if (!Login(_channel, _hdr.get(), _baseUri, _username, _password.ToUTF8Data()))
					{
						disconnect();
						return false;
					}
				}
			}
		}

		if (_isGenericConnection)
			return true;
		return LoadTokens();
	}
	virtual size_t tokenCount() override
	{
		TSAUTOLOCKER tokenLock(_tokenListLock);
		return _tokens.size();
	}
	virtual std::shared_ptr<IToken> token(size_t index) override
	{
		if (index >= tokenCount())
			return nullptr;
		TSAUTOLOCKER tokenLock(_tokenListLock);
		return _tokens[index];
	}
	virtual std::shared_ptr<IToken> token(const tscrypto::tsCryptoStringBase& tokenName) override
	{
		TSAUTOLOCKER tokenLock(_tokenListLock);
		auto it = std::find_if(_tokens.begin(), _tokens.end(), [&tokenName](std::shared_ptr<IToken>& token)->bool { return tokenName == token->tokenName(); });
		if (it == _tokens.end())
			return nullptr;
		return *it;
	}
	virtual std::shared_ptr<IToken> token(const tscrypto::tsCryptoData& serialNumber) override
	{
		TSAUTOLOCKER tokenLock(_tokenListLock);
		auto it = std::find_if(_tokens.begin(), _tokens.end(), [&serialNumber](std::shared_ptr<IToken>& token)->bool { return serialNumber == token->serialNumber(); });
		if (it == _tokens.end())
			return nullptr;
		return *it;
	}
	virtual std::shared_ptr<IToken> token(const GUID& id) override
	{
		TSAUTOLOCKER tokenLock(_tokenListLock);
		auto it = std::find_if(_tokens.begin(), _tokens.end(), [&id](std::shared_ptr<IToken>& token)->bool { return id == token->id(); });
		if (it == _tokens.end())
			return nullptr;
		return *it;
	}
	virtual bool sendJsonRequest(const tscrypto::tsCryptoStringBase& verb, const tscrypto::tsCryptoStringBase& cmd, const JSONObject &inData, JSONObject& outData, int& status) override
	{
		tscrypto::tsCryptoString cmdToUse;

		TSAUTOLOCKER lock(_channelLock);
		if (!_channel || !_channel->isConnected() /*|| !_channel->isAuthenticated()*/)
		{
			//			if (!refresh())
			{
				LOG(FrameworkError, "Not connected to KeyVEIL.");
				return false;
			}
		}

		if (_isGenericConnection)
		{
			cmdToUse << _genericBaseUrl << cmd;
		}
		else
		{
			cmdToUse << _baseUri << cmd;
		}
		if (!runJsonCommand(_channel, _hdr.get(), cmdToUse, verb, [this, &status, &outData](const tscrypto::tsCryptoData& data, int code) {
			LOG(FrameworkDevOnly, "Returned code " << code << " and data:" << tscrypto::endl << data.ToHexDump());
			status = code;
			if (data.size() > 0)
			{
				if (outData.FromJSON(data.ToUtf8String().c_str()) <= 0)
				{
					LOG(httpLog, "The returned data is not JSON:" << data.ToHexDump());
				}
			}
		},
			[this, &status, &outData](const tscrypto::tsCryptoData& data, int code) {

			JSONObject obj;

			if (!obj.FromJSON(data.ToUtf8String().c_str()))
			{
				obj.clear();
				obj.add("nonJSONError", data.ToUtf8String());
			}
			outData = obj;
			status = code;

			LOG(FrameworkError, "Failed with code " << code << " and data: " << tscrypto::endl << data.ToHexDump());
		}, inData.ToJSON().ToUTF8Data()))
		{
			LOG(FrameworkError, "Communications with KeyVEIL failed.");
			return false;
		}
		return true;
	}
	virtual bool sendRequest(const tscrypto::tsCryptoStringBase& verb, const tscrypto::tsCryptoStringBase& cmd, const tscrypto::tsCryptoData &inData, tscrypto::tsCryptoData& outData, int& status) override
	{
		tscrypto::tsCryptoString cmdToUse;

		TSAUTOLOCKER lock(_channelLock);
		if (!_channel || !_channel->isConnected() /*|| !_channel->isAuthenticated()*/)
		{
			//			if (!refresh())
			{
				LOG(FrameworkError, "Not connected to KeyVEIL.");
				return false;
			}
		}

		if (_isGenericConnection)
		{
			cmdToUse << _genericBaseUrl << cmd;
		}
		else
		{
			cmdToUse << _baseUri << cmd;
		}
		if (!runJsonCommand(_channel, _hdr.get(), cmdToUse, verb, [this, &status, &outData](const tscrypto::tsCryptoData& data, int code) {
			LOG(FrameworkDevOnly, "Returned code " << code << " and data:" << tscrypto::endl << data.ToHexDump());
			status = code;
			if (data.size() > 0)
			{
				outData = data;
			}
		},
			[this, &status, &outData](const tscrypto::tsCryptoData& data, int code) {
			status = code;
			outData = data;
			LOG(FrameworkError, "Failed with code " << code << " and data: " << tscrypto::endl << data.ToHexDump());
		}, inData))
		{
			LOG(FrameworkError, "Communications with KeyVEIL failed.");
			return false;
		}
		return true;
	}
	virtual tscrypto::tsCryptoString status() const override
	{
		return _hdr->status();
	}
	virtual tscrypto::tsCryptoString reason() const override
	{
		return _hdr->reason();
	}
	virtual tscrypto::tsCryptoString version() const override
	{
		return _hdr->version();
	}
	virtual size_t dataPartSize() const override
	{
		return _hdr->dataPartSize();
	}
	virtual const tscrypto::tsCryptoData& dataPart() const override
	{
		return _hdr->dataPart();
	}
	virtual WORD errorCode() const override
	{
		return _hdr->errorCode();
	}
	virtual size_t attributeCount() const override
	{
		return _hdr->attributeCount();
	}
	virtual const HttpAttribute* attribute(size_t index) const override
	{
		return _hdr->attribute(index);
	}
	virtual const HttpAttribute* attributeByName(const tscrypto::tsCryptoStringBase& index) const override
	{
		return _hdr->attributeByName(index);
	}
	virtual const HttpAttribute* attributeByName(const char *index) const override
	{
		return _hdr->attributeByName(index);
	}
	virtual size_t favoriteCount() override
	{
		TSAUTOLOCKER favLock(_favoriteListLock);
		if (_favorites.size() == 0)
		{
			if (!_channel || !_channel->isAuthenticated())
				return 0;

			LoadFavorites();
		}
		return _favorites.size();
	}
	virtual std::shared_ptr<IFavorite> favorite(size_t index) override
	{
		if (index >= favoriteCount())
			return nullptr;
		TSAUTOLOCKER favLock(_favoriteListLock);
		return _favorites[index];
	}
	virtual std::shared_ptr<IFavorite> favorite(const tscrypto::tsCryptoStringBase& name) override
	{
		if (favoriteCount() == 0)
			return nullptr;

		TSAUTOLOCKER favLock(_favoriteListLock);
		auto it = std::find_if(_favorites.begin(), _favorites.end(), [&name](std::shared_ptr<IFavorite> obj) -> bool {
			return obj->favoriteName() == name;
		});
		if (it == _favorites.end())
			return nullptr;
		return *it;
	}
	virtual std::shared_ptr<IFavorite> favorite(const GUID& id) override
	{
		if (favoriteCount() == 0)
			return nullptr;

		TSAUTOLOCKER favLock(_favoriteListLock);
		auto it = std::find_if(_favorites.begin(), _favorites.end(), [&id](std::shared_ptr<IFavorite> obj) -> bool {
			return obj->favoriteId() == id;
		});
		if (it == _favorites.end())
			return nullptr;
		return *it;
	}
	virtual GUID CreateFavorite(std::shared_ptr<IToken> token, const tscrypto::tsCryptoData& headerData, const tscrypto::tsCryptoStringBase& name) override
	{
		return CreateFavorite(token->serialNumber(), headerData, name);
	}
	virtual GUID CreateFavorite(const GUID& tokenId, const tscrypto::tsCryptoData& headerData, const tscrypto::tsCryptoStringBase& name) override
	{
		if (tokenId == GUID_NULL)
			return CreateFavorite(tscrypto::tsCryptoData(), headerData, name);

		std::shared_ptr<IToken> tok = token(tokenId);

		if (!tok)
			return GUID_NULL;
		return CreateFavorite(tok->serialNumber(), headerData, name);
	}
	virtual GUID CreateFavorite(const tscrypto::tsCryptoData& tokenSerial, const tscrypto::tsCryptoData& headerData, const tscrypto::tsCryptoStringBase& name) override
	{
		JSONObject params, result;
		int status;
		tscrypto::tsCryptoData outData;

		TSAUTOLOCKER lock(_channelLock);
		if (!this->isConnected())
			return GUID_NULL;

		params
			.add("data", headerData.ToBase64())
			.add("serial", tokenSerial.ToBase64())
			.add("name", name);

		if (!runJsonCommand(_channel, _hdr.get(), "/bin/Favorite", "POST", [this, &status, &outData](const tscrypto::tsCryptoData& data, int code) {
			LOG(FrameworkDevOnly, "Returned code " << code << " and data:" << tscrypto::endl << data.ToHexDump());
			status = code;
			if (data.size() > 0)
			{
				outData = data;
			}
		},
			[this, &status, &outData](const tscrypto::tsCryptoData& data, int code) {
			status = code;
			outData = data;
			LOG(FrameworkError, "Failed with code " << code << " and data: " << tscrypto::endl << data.ToHexDump());
		}, params.ToJSON().ToUTF8Data()))
		{
			LOG(FrameworkError, "Communications with KeyVEIL failed.");
			return GUID_NULL;
		}

		LoadFavorites();

		result.FromJSON(outData.ToUtf8String().c_str());

		return ToGuid()(result.AsString("id"));
	}
	virtual bool DeleteFavorite(const GUID& id) override
	{
		tscrypto::tsCryptoData outData;
		int status;

		TSAUTOLOCKER lock(_channelLock);
		if (!this->isConnected())
			return false;

		if (!runJsonCommand(_channel, _hdr.get(), "/bin/Favorite?favoriteId=" + ToString()(id), "DELETE", [this, &status, &outData](const tscrypto::tsCryptoData& data, int code) {
			LOG(FrameworkDevOnly, "Returned code " << code << " and data:" << tscrypto::endl << data.ToHexDump());
			status = code;
			if (data.size() > 0)
			{
				outData = data;
			}
			LoadFavorites();
		},
			[this, &status, &outData](const tscrypto::tsCryptoData& data, int code) {
			status = code;
			outData = data;
			LOG(FrameworkError, "Failed with code " << code << " and data: " << tscrypto::endl << data.ToHexDump());
		}, tscrypto::tsCryptoData()))
		{
			LOG(FrameworkError, "Communications with KeyVEIL failed.");
			return false;
		}

		return (status < 400);
	}
	virtual bool UpdateFavoriteName(const GUID& id, const tscrypto::tsCryptoStringBase& name) override
	{
		JSONObject params;
		tscrypto::tsCryptoData outData;
		int status;

		TSAUTOLOCKER lock(_channelLock);
		if (!this->isConnected())
			return false;

		params.add("favoriteId", ToString()(id)).add("name", name);
		if (!runJsonCommand(_channel, _hdr.get(), "/bin/Favorite", "PUT", [this, &status, &outData](const tscrypto::tsCryptoData& data, int code) {
			LOG(FrameworkDevOnly, "Returned code " << code << " and data:" << tscrypto::endl << data.ToHexDump());
			status = code;
			if (data.size() > 0)
			{
				outData = data;
			}
			LoadFavorites();
		},
			[this, &status, &outData](const tscrypto::tsCryptoData& data, int code) {
			status = code;
			outData = data;
			LOG(FrameworkError, "Failed with code " << code << " and data: " << tscrypto::endl << data.ToHexDump());
		}, params.ToJSON().ToUTF8Data()))
		{
			LOG(FrameworkError, "Communications with KeyVEIL failed.");
			return false;
		}

		return (status < 400);
	}
	virtual bool UpdateFavorite(const GUID& id, const tscrypto::tsCryptoData& setTo) override
	{
		JSONObject params;
		tscrypto::tsCryptoData outData;
		int status;

		TSAUTOLOCKER lock(_channelLock);
		if (!this->isConnected())
			return false;

		params.add("favoriteId", ToString()(id)).add("data", setTo.ToBase64());
		if (!runJsonCommand(_channel, _hdr.get(), "/bin/Favorite", "PUT", [this, &status, &outData](const tscrypto::tsCryptoData& data, int code) {
			LOG(FrameworkDevOnly, "Returned code " << code << " and data:" << tscrypto::endl << data.ToHexDump());
			status = code;
			if (data.size() > 0)
			{
				outData = data;
			}
			LoadFavorites();
		},
			[this, &status, &outData](const tscrypto::tsCryptoData& data, int code) {
			status = code;
			outData = data;
			LOG(FrameworkError, "Failed with code " << code << " and data: " << tscrypto::endl << data.ToHexDump());
		}, params.ToJSON().ToUTF8Data()))
		{
			LOG(FrameworkError, "Communications with KeyVEIL failed.");
			return false;
		}

		return (status < 400);
	}
	virtual size_t tokenCountForEnterprise(const GUID& enterprise) override
	{
		size_t count = tokenCount(); // Makes sure that the tokens are loaded

		TSAUTOLOCKER tokenLock(_tokenListLock);
		for (auto token : _tokens)
		{
			if (token->enterpriseId() != enterprise)
				count--;
		}
		return count;
	}
	virtual std::shared_ptr<IToken> tokenForEnterprise(const GUID& enterprise, size_t index) override
	{
		if (index >= tokenCountForEnterprise(enterprise))
			return nullptr;

		TSAUTOLOCKER tokenLock(_tokenListLock);
		auto it = std::find_if(_tokens.begin(), _tokens.end(), [&index, &enterprise](std::shared_ptr<IToken>& token) -> bool {
			if (token->enterpriseId() == enterprise)
			{
				if (index == 0)
					return true;
				index--;
			}
			return false;
		});
		if (it == _tokens.end())
			return nullptr;
		return *it;
	}
	virtual size_t favoriteCountForEnterprise(const GUID& enterprise) override
	{
		size_t count = favoriteCount(); // Makes sure that the tokens are loaded

		TSAUTOLOCKER favLock(_favoriteListLock);
		for (auto fav : _favorites)
		{
			if (fav->enterpriseId() != enterprise)
				count--;
		}
		return count;
	}
	virtual std::shared_ptr<IFavorite> favoriteForEnterprise(const GUID& enterprise, size_t index) override
	{
		if (index >= favoriteCountForEnterprise(enterprise))
			return nullptr;

		TSAUTOLOCKER favLock(_favoriteListLock);
		auto it = std::find_if(_favorites.begin(), _favorites.end(), [&index, &enterprise](std::shared_ptr<IFavorite>& fav) -> bool {
			if (fav->enterpriseId() == enterprise)
			{
				if (index == 0)
					return true;
				index--;
			}
			return false;
		});
		if (it == _favorites.end())
			return nullptr;
		return *it;
	}

	virtual size_t AddKeyVEILChangeCallback(std::function<void(JSONObject& eventData)> func) override
	{
		CallbackHolder holder;

		holder.cookie = InterlockedIncrement(&_nextCallbackId);
		holder.func = func;
		TSAUTOLOCKER lock(_callbackLock);
		_callbacks.push_back(holder);
		StartCallbackSystem();
		return holder.cookie;
	}
	virtual size_t AddKeyVEILGeneralChangeCallback(std::function<void()> func) override
	{
		CallbackHolder holder;

		holder.cookie = InterlockedIncrement(&_nextCallbackId);
		holder.generalFunc = func;
		TSAUTOLOCKER lock(_callbackLock);
		_callbacks.push_back(holder);
		StartCallbackSystem();
		return holder.cookie;
	}
	virtual void RemoveKeyVEILChangeCallback(size_t cookie) override
	{
		TSAUTOLOCKER lock(_callbackLock);

		_callbacks.erase(std::remove_if(_callbacks.begin(), _callbacks.end(), [&cookie](CallbackHolder& holder) { return holder.cookie == cookie; }), _callbacks.end());
		if (_callbacks.size() == 0)
		{
			_callbackThread.Cancel();
			_callbackThread.WaitForThread(3000);
		}
	}


protected:

	bool runJsonCommand(std::shared_ptr<IHttpChannel>& _channel, IHttpResponse* hdr, const tscrypto::tsCryptoString& cmd, const tscrypto::tsCryptoString& verb, std::function<void(const tscrypto::tsCryptoData&, int)> success, std::function<void(const tscrypto::tsCryptoData&, int)> failed, const tscrypto::tsCryptoData& data)
	{
		if (!_channel)
		{
			failed(tsCryptoData("Not connected."), 500);
			return false;
		}
		if (!_channel->isConnected())
		{
			if (!_channel->Connect())
			{
				if (!!failed)
				{
					failed(tsCryptoData("Unable to connect to the server."), 500);
				}
				return false;
			}
		}

		TSAUTOLOCKER lock(_threadControl);

		if (!_channel->Send(verb, cmd, data, "text/json"))
		{
			if (!!failed)
			{
				failed(tsCryptoData("Unable to send the command to the server.  Check that the server is available and active."), 500);
			}
			return false;
		}

		if (!_channel->Receive(hdr))
		{
			if (!!failed)
			{
				failed(tsCryptoData("Unable to receive the response from the server."), 500);
			}
			return false;
		}

		//if (jqXHR.status == = 440) {
		//	// reauthenticate here and resubmit
		//	eb.main.loadDialog('login', { success: function() { eb.main.sendEncryptedData(origUrl, origCmd); } });
		//}
		//else if (jqXHR.status == = 401) {
		//	// reauthenticate here and resubmit
		//	eb.main.loadDialog('login', { success: function() { eb.main.sendEncryptedData(origUrl, origCmd); } });
		//}


		//printf("%s: %s -> %d\nIN: \n%s\nOUT:\n%s\n", verb.c_str(), cmd.c_str(), hdr->errorCode(), data.ToHexDump().c_str(), hdr->dataPart().ToHexDump().c_str());

		if (hdr->errorCode() >= 400)
		{
			if (!!failed)
			{
				failed(hdr->dataPart(), hdr->errorCode());
			}
			return false;
		}
		if (!!success)
		{
			success(hdr->dataPart(), hdr->errorCode());
		}
		return true;
	}
	bool LoginPart3(std::shared_ptr<IHttpChannel>& _channel, const tscrypto::tsCryptoString& MITMProof, const tscrypto::tsCryptoData& initiatorSessionKey, const tscrypto::tsCryptoData& data)
	{
		JSONObject obj;

		if (!_channel || !obj.FromJSON(data.ToUtf8String().c_str()))
			return false;

		if (obj.AsString("msg") != MITMProof) {
			return false;
		}

		// Start the authentication process with the session key
		_msgProcessor->start(obj.AsString("sessionId").Base64ToData(), initiatorSessionKey);
		_channel->setChannelProcessor(_httpProcessor);

		return true;
	}
	bool LoginPart2(std::shared_ptr<IHttpChannel>& _channel, IHttpResponse* hdr, const tscrypto::tsCryptoString& baseUri, const tscrypto::tsCryptoData& Pin, const tscrypto::tsCryptoData& data)
	{
		JSONObject params;
		tscrypto::tsCryptoData nonce;
		tscrypto::tsCryptoData salt;
		int iter = 0;
		tscrypto::tsCryptoData pubKey;
		tscrypto::tsCryptoData identity;
		_POD_CkmAuthServerParameters authParams;
		tscrypto::tsCryptoData bsAuthParams;
		std::shared_ptr<AuthenticationInitiator> initiator;
		_POD_CkmAuthInitiatorParameters initParams;
		_POD_CkmAuthResponderParameters respParams;
		tscrypto::tsCryptoData initiatorParams;
		tscrypto::tsCryptoData responderParams;
		tscrypto::tsCryptoData MITMProof;
		tscrypto::tsCryptoData responderMITMProof;
		tscrypto::tsCryptoData initiatorSessionKey;
		bool retVal = false;

		if (!_channel)
			return false;

		params.FromJSON(data.ToUtf8String().c_str());

		tscrypto::tsCryptoStringList parts = params.AsString("msg").split(',');

		auto it = std::find_if(parts->begin(), parts->end(), [&nonce, &salt, &iter, &pubKey, &identity](const tscrypto::tsCryptoString& str)->bool {
			tscrypto::tsCryptoData _pubKey(pubKey); // fix VC10 bug
			tscrypto::tsCryptoData _identity(identity);

			if (str.size() < 2 || (str)[1] != '=')
				return true;
			if ((str)[0] == 'r')
			{
				nonce = str.substring(2, str.size() - 2).Base64ToData();
			}
			else if ((str)[0] == 's')
			{
				salt = str.substring(2, str.size() - 2).Base64ToData();
			}
			else if ((str)[0] == 'i')
			{
				iter = TsStrToInt(str.substring(2, str.size() - 2));
			}
			else if ((str)[0] == 'm')
			{
				tscrypto::tsCryptoStringList mParts = str.substring(2, str.size() - 2).Base64ToData().ToUtf8String().split(',');
				auto it2 = std::find_if(mParts->begin(), mParts->end(), [&_pubKey, &_identity](const tscrypto::tsCryptoString& str)->bool {
					if (str.size() < 2 || (str)[1] != '=')
						return true;
					if ((str)[0] == 'r')
					{
						_pubKey = str.substring(2, str.size() - 2).Base64ToData();
					}
					else if ((str)[0] == 'i')
					{
						_identity = str.substring(2, str.size() - 2);
					}
					else
						return true;
					return false;
				});
				pubKey = _pubKey;
				identity = _identity;

				if (it2 != mParts->end())
					return true;
			}
			else
				return true;
			return false;
		});

		if (it != parts->end())
		{
			return false;
		}

		// Now check that we got all of the parameters
		if (nonce.size() == 0 || iter == 0 || salt.size() == 0 || pubKey.size() == 0 || identity.size() == 0)
		{
			return false;
		}

		authParams.clear();
		authParams.get_params().set_selectedItem(_POD_CkmAuthServerParameters_params::Choice_Pbkdf);
		authParams.get_params().get_Pbkdf().get_hmacAlgorithm().set_oid(RSADSI_HMAC_SHA512_OID);
		authParams.get_params().get_Pbkdf().set_IterationCount(iter);
		authParams.get_params().get_Pbkdf().set_Salt(salt);
		authParams.Encode(bsAuthParams);

		if (!(initiator = std::dynamic_pointer_cast<AuthenticationInitiator>(CryptoFactory("CKMAUTH"))))
		{
			return false;
		}

		initParams.set_authParameters(authParams);
		initParams.set_keySizeInBits(256);
		initParams.set_oidInfo(identity);
		initParams.set_responderPublicKey(pubKey);
		initParams.set_nonce(nonce);
		if (!initParams.Encode(initiatorParams))
		{
			return false;
		}
		if (!initiator->computeInitiatorValues(initiatorParams, Pin, responderParams, MITMProof, initiatorSessionKey))
		{
			return false;
		}
		if (!respParams.Decode(responderParams))
		{
			return false;
		}

		tscrypto::tsCryptoString m, msg;
		JSONObject obj;

		m << "e=" << respParams.get_ephemeralPublic().ToBase64() << ",k=" << respParams.get_eKGK().ToBase64() << ",v=" << respParams.get_initiatorMITMProof().ToBase64();

		msg << "c=biws,r=" + nonce.ToBase64();
		msg << ",m=" + m.ToUTF8Data().ToBase64() << ",p=" << respParams.get_initiatorAuthProof().ToBase64();

		obj.add("msg", msg);

		tscrypto::tsCryptoString sMITMProof;

		sMITMProof << "v=" << MITMProof.ToBase64();

		runJsonCommand(_channel, hdr, baseUri + "CkmAuth", "PUT", [&_channel, &retVal, &sMITMProof, &initiatorSessionKey, this](const tscrypto::tsCryptoData& data, int code) {
			MY_UNREFERENCED_PARAMETER(code);
			retVal = LoginPart3(_channel, sMITMProof, initiatorSessionKey, data);
		}, nullptr, obj.ToJSON().ToUTF8Data());

		return retVal;
	}
	bool Login(std::shared_ptr<IHttpChannel>& _channel, IHttpResponse* hdr, const tscrypto::tsCryptoString& baseUri, const tscrypto::tsCryptoString& username, const tscrypto::tsCryptoData& Pin)
	{
		bool retVal = false;

		tscrypto::tsCryptoString user = username;
		tscrypto::tsCryptoString msg;
		JSONObject obj;

		user.Replace("=", "=3D").Replace(",", "=2C");
		msg = "n,,n=" + user;
		obj.add("msg", msg);


		if (!_channel)
		{
			return false;
		}

		runJsonCommand(_channel, hdr, baseUri + "CkmAuth", "PUT", [&_channel, hdr, &baseUri, &retVal, &Pin, this](const tscrypto::tsCryptoData& data, int code) {
			MY_UNREFERENCED_PARAMETER(code);
			retVal = LoginPart2(_channel, hdr, baseUri, Pin, data);
		}, nullptr, obj.ToJSON().ToUTF8Data());


		return retVal;
	}

	// Load the current list of tokens from the KeyVEIL and update the current token list
	bool LoadTokens()
	{
		JSONObject upData, downData;
		int status;

		if (!sendJsonRequest("GET", "Token", upData, downData, status) || (status != 200 && status != 204))
		{
			return false;
		}

		if (!downData.hasField("tokens") || downData.field("tokens").Type() != JSONField::jsonArray)
			return false;

		TSAUTOLOCKER tokenLock(_tokenListLock);

		JSONFieldList& ary = downData.field("tokens").AsArray();
		std::vector<std::shared_ptr<IToken> > tmpAry = _tokens;

		for (auto fld : *ary)
		{
			if (fld.Type() != JSONField::jsonObject)
				continue;
			JSONObject& o = fld.AsObject();
			GUID id = TSStringToGuid(o.AsString("id"));
			auto it = std::find_if(tmpAry.begin(), tmpAry.end(), [&id](std::shared_ptr<IToken>& token)->bool {
				return token->id() == id;
			});
			if (it == tmpAry.end())
			{
				// Add the new token to the list
				_tokens.push_back(CreateTokenObject(std::dynamic_pointer_cast<IKeyVEILConnector>(_me.lock()), o));
			}
			else
			{
				// remove this token from the temporary list as it was found.
				tmpAry.erase(it);
			}
		}
		if (tmpAry.size() > 0)
		{
			// Now remove the tokens that are no longer valid from the token list
			_tokens.erase(std::remove_if(_tokens.begin(), _tokens.end(), [&tmpAry](std::shared_ptr<IToken>& token)->bool {
				auto it = std::find_if(tmpAry.begin(), tmpAry.end(), [&token](std::shared_ptr<IToken>&tmpToken)->bool { return token->id() == tmpToken->id(); });
				return it != tmpAry.end();
			}), _tokens.end());
		}
		return true;
	}
	bool LoadFavorites()
	{
		JSONObject upData, downData;
		int status;

		if (!sendJsonRequest("GET", "Favorite", upData, downData, status) || (status != 200 && status != 204))
		{
			return false;
		}

		if (!downData.hasField("FavoriteCollection") || downData.field("FavoriteCollection").Type() != JSONField::jsonArray)
			return false;

		TSAUTOLOCKER favLock(_favoriteListLock);
		JSONFieldList& ary = downData.field("FavoriteCollection").AsArray();
		std::vector<std::shared_ptr<IFavorite> > tmpAry = _favorites;

		for (auto fld : *ary)
		{
			if (fld.Type() != JSONField::jsonObject)
				continue;
			JSONObject& o = fld.AsObject();
			GUID id = TSStringToGuid(o.AsString("id"));

			auto it = std::find_if(tmpAry.begin(), tmpAry.end(), [&id](std::shared_ptr<IFavorite>& fav)->bool {
				return fav->favoriteId() == id;
			});
			if (it == tmpAry.end())
			{
				// Add the new token to the list
				_favorites.push_back(CreateFavoriteObject(std::dynamic_pointer_cast<IKeyVEILConnector>(_me.lock()), o));
			}
			else
			{
				// remove this token from the temporary list as it was found.
				tmpAry.erase(it);

				// Update the contents
				(*it)->favoriteName(o.AsString("favoriteName"));
				(*it)->tokenSerialNumber(o.AsString("tokenSerial").HexToData());
				(*it)->headerData(o.AsString("data").Base64ToData());
			}
		}
		if (tmpAry.size() > 0)
		{
			// Now remove the tokens that are no longer valid from the token list
			_favorites.erase(std::remove_if(_favorites.begin(), _favorites.end(), [&tmpAry](std::shared_ptr<IFavorite>& fav)->bool {
				auto it = std::find_if(tmpAry.begin(), tmpAry.end(), [&fav](std::shared_ptr<IFavorite>&tmpFav)->bool { return fav->favoriteId() == tmpFav->favoriteId(); });
				return it != tmpAry.end();
			}), _favorites.end());
		}
		return true;
	}
	void StartCallbackSystem()
	{
		if (!_callbackThread.Active())
		{
			std::shared_ptr<BasicVEILPreferences> prefs = BasicVEILPreferences::Create();

			prefs->loadValues();
			int timeout = prefs->getKVPollTime();
			prefs.reset();

			_callbackThread.SetWorker([this, timeout]()->int {

				while (_callbackThread.Active())
				{
					switch (_callbackThread.cancelEvent().WaitForEvent(timeout))
					{
					case tscrypto::CryptoEvent::Timeout:
						break;
					case tscrypto::CryptoEvent::AlreadyLocked:
					case tscrypto::CryptoEvent::Succeeded_Object1:
						return 0;
					case tscrypto::CryptoEvent::Failed:
						return 1;
					default:
						break;
					}
					// Now look for changes
					if (!isConnected())
					{
						// Loop around and do it again
					}
					else
					{
						JSONObject outObj;
						int status;

						tscrypto::tsCryptoString tmp;
						tmp << "Events?timeout=10&since=" << _lastEvent;
						if (sendJsonRequest("GET", tmp, JSONObject(), outObj, status) && status >= 200 && status <= 399)
						{
							if (outObj.hasField("lastEvent"))
							{
								_lastEvent = outObj.AsNumber("lastEvent", 0);
							}
							if (!outObj.AsBool("failure", false))
							{
								refresh();
								TSAUTOLOCKER lock(_callbackLock);
								for (auto holder : _callbacks)
								{
									if (!!holder.generalFunc)
										holder.generalFunc();
								}
								if (outObj.hasField("events") && outObj.field("events").Type() == JSONField::jsonArray)
								{
									outObj.foreach("events", [this](JSONField& fld) {
										if (fld.Type() == JSONField::jsonObject)
										{
											JSONObject& obj = fld.AsObject();
											for (auto holder : _callbacks)
											{
												if (!!holder.func)
													holder.func(obj);
											}
										}
									});
								}
							}
						}
					}
				}
				return 0;
			});
			_callbackThread.Start();
		}
	}
	tscrypto::AutoCriticalSection _channelLock;
	std::shared_ptr<IHttpChannel>  _channel;
	std::shared_ptr<IHttpResponse> _hdr;
	std::shared_ptr<IMessageProcessorControl>  _msgProcessor;
	std::shared_ptr<IHttpChannelProcessor> _httpProcessor;
	tscrypto::AutoCriticalSection _tokenListLock;
	std::vector<std::shared_ptr<IToken> > _tokens;
	tscrypto::AutoCriticalSection _favoriteListLock;
	std::vector<std::shared_ptr<IFavorite> > _favorites;
	tscrypto::tsCryptoString _username;
	tscrypto::tsCryptoString _password;
	tscrypto::tsCryptoString _scheme;
	tscrypto::tsCryptoString _baseUri;
	tscrypto::tsCryptoString _genericBaseUrl;
	bool _isGenericConnection;
	tscrypto::AutoCriticalSection _threadControl;
	std::vector<CallbackHolder> _callbacks;
	tscrypto::AutoCriticalSection _callbackLock;
	size_t _nextCallbackId;
	tsThread _callbackThread;
	int64_t _lastEvent;
	bool _lastConnected;
};

tsmod::IObject* CreateKeyVEILConnector()
{
	return dynamic_cast<tsmod::IObject*>(new KeyVEILConnector());
}
