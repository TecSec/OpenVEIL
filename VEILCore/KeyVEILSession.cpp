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

class KeyVEILSession : public IKeyVEILSession, public tsmod::IObject
{
public:
	KeyVEILSession(const GUID& tokenId, std::shared_ptr<IKeyVEILConnector> connector)
		:
		_tokenId(tokenId),
		_connector(connector)
	{

	}
	virtual ~KeyVEILSession(){}
	virtual LoginStatus Login(const tscrypto::tsCryptoStringBase& pin) override
	{
		std::shared_ptr<IKeyVEILConnector> conn = _connector.lock();
		JSONObject obj, result;
		int status;

		//printf("Logging into the token with pwd:  %s\n", pin.c_str());

		if (!conn)
			return LoginStatus::loginStatus_NoServer;
		obj.add("tokenId", TSGuidToString(_tokenId)).add("password", pin);
		if (!conn->sendJsonRequest("POST", "TokenAuth", obj, result, status))
		{
			if (status > 399)
			{
				if (result.hasField("type") && result.AsString("type") == "NotAllowedException")
					return LoginStatus::loginStatus_BadAuth;
				return LoginStatus::loginStatus_NoServer;
			}
			return LoginStatus::loginStatus_NoServer;
		}
		if (status > 399 || status < 200)
		{
			if (result.hasField("type") && result.AsString("type") == "NotAllowedException")
				return LoginStatus::loginStatus_BadAuth;
			return LoginStatus::loginStatus_BadAuth;
		}
		_profile.reset();
		return LoginStatus::loginStatus_Connected;
	}
	virtual bool IsLoggedIn() override
	{
		std::shared_ptr<IKeyVEILConnector> conn = _connector.lock();
		JSONObject obj, result;
		int status;

		if (!conn)
			return false;

		if (!conn->sendJsonRequest("GET", "TokenAuth?tokenId=" + TSGuidToString(_tokenId), obj, result, status))
		{
			return false;
		}
		if (status > 399 || status < 200)
		{
			return false;
		}
		return result.AsBool("authenticated", false);
	}
	virtual bool Logout() override
	{
		std::shared_ptr<IKeyVEILConnector> conn = _connector.lock();
		JSONObject obj, result;
		int status;

		if (!conn)
			return false;

		if (!conn->sendJsonRequest("DELETE", "TokenAuth?tokenId=" + TSGuidToString(_tokenId), obj, result, status))
		{
			return false;
		}
		if (status > 399 || status < 200)
		{
			return false;
		}
		return true;
	}
	virtual bool GenerateWorkingKey(Asn1::CTS::_POD_CkmCombineParameters& params, std::function<bool(Asn1::CTS::_POD_CkmCombineParameters&, tscrypto::tsCryptoData&)> headerCallback, tscrypto::tsCryptoData &WorkingKey) override
	{
		std::shared_ptr<IKeyVEILConnector> conn = _connector.lock();
		JSONObject obj, result;
		int status;

		if (!conn)
        {
            LOG(FrameworkError, "Unable to connect to KeyVEIL.");
            return false;
        }

		obj
			.add("tokenId", TSGuidToString(_tokenId));
		obj.expand(params.toJSON());

		if (!conn->sendJsonRequest("POST", "KeyGen", obj, result, status))
		{
            LOG(FrameworkError, "The key gen request failed." << tscrypto::endl << "Result = " << result.ToJSON());
			return false;
		}
		if (status > 399 || status < 200)
		{
            LOG(FrameworkError, "The key gen request failed with status " << status << ".");
			return false;
		}
		WorkingKey = result.AsString("key").Base64ToData();
		result.deleteField("key");
		params.clear();
		if (!params.fromJSON(result))
        {
            LOG(FrameworkError, "The response is not properly formed." << tscrypto::endl << result.ToJSON());
			return false;
        }

		if (!!headerCallback)
			return headerCallback(params, WorkingKey);

		return true;
	}
	virtual bool RegenerateWorkingKey(Asn1::CTS::_POD_CkmCombineParameters& params, tscrypto::tsCryptoData &WorkingKey) override
	{
		std::shared_ptr<IKeyVEILConnector> conn = _connector.lock();
		JSONObject obj, result;
		int status;

		if (!conn)
			return false;

		obj
			.add("tokenId", TSGuidToString(_tokenId));
		obj.expand(params.toJSON());

		if (!conn->sendJsonRequest("PUT", "KeyGen", obj, result, status))
		{
			return false;
		}
		if (status > 399 || status < 200)
		{
			return false;
		}
		WorkingKey = result.AsString("key").Base64ToData();
		result.deleteField("key");
		params.clear();
		if (!params.fromJSON(result))
			return false;

		return true;
	}

	virtual std::shared_ptr<Asn1::CTS::_POD_Profile> GetProfile() override
	{
		if (!_profile)
		{
			std::shared_ptr<IKeyVEILConnector> conn = _connector.lock();
			JSONObject obj, result;
			int status;

			if (!conn)
				return nullptr;

			if (!conn->sendJsonRequest("GET", "Token?tokenId=" + TSGuidToString(_tokenId), obj, result, status))
			{
				return nullptr;
			}
			if (status > 399 || status < 200)
			{
				return nullptr;
			}

			_profile = std::shared_ptr<Asn1::CTS::_POD_Profile>(new Asn1::CTS::_POD_Profile());
			if (!_profile->fromJSON(result.AsObject("profile")))
			{
				_profile->clear();
			}
		}
		return _profile;
	}
	virtual bool Close(void) override
	{
		_profile.reset();
		_connector.reset();
		return true;
	}
	virtual bool IsLocked() override
	{
		std::shared_ptr<IKeyVEILConnector> conn = _connector.lock();
		JSONObject obj, result;
		int status;

		if (!conn)
			return false;

		if (!conn->sendJsonRequest("GET", "TokenAuth?tokenId=" + TSGuidToString(_tokenId), obj, result, status))
		{
			return false;
		}
		if (status > 399 || status < 200)
		{
			return false;
		}
		return result.AsString("status") == "locked";
	}
	virtual size_t retriesLeft() override
	{
		std::shared_ptr<IKeyVEILConnector> conn = _connector.lock();
		JSONObject obj, result;
		int status;

		if (!conn)
			return 0;

		if (!conn->sendJsonRequest("GET", "TokenAuth?tokenId=" + TSGuidToString(_tokenId), obj, result, status))
		{
			return 0;
		}
		if (status > 399 || status < 200)
		{
			return 0;
		}
		size_t count = (size_t)result.AsNumber("failedTries", 0);
		if (count == 0)
			return 16;
		if (count == 16)
			return 0;
		return (15 - count);
	}
	virtual bool IsValid() override
	{
		std::shared_ptr<IKeyVEILConnector> conn = _connector.lock();
		JSONObject obj, result;
		int status;

		if (!conn)
			return false;

		if (!conn->sendJsonRequest("GET", "TokenAuth?tokenId=" + TSGuidToString(_tokenId), obj, result, status))
		{
			return false;
		}
		if (status > 399 || status < 200)
		{
			return false;
		}
		return true;
	}
	virtual std::shared_ptr<IKeyVEILSession> Duplicate() override
	{
		KeyVEILSession* newSession = new KeyVEILSession(_tokenId, _connector.lock());

		if (newSession == nullptr)
			return nullptr;

		if (!!_profile)
		{
			newSession->_profile = std::shared_ptr<Asn1::CTS::_POD_Profile>(new Asn1::CTS::_POD_Profile(*_profile.get()));
		}
		newSession->_profile = _profile;
		return ::TopServiceLocator()->Finish<IKeyVEILSession>(newSession);
	}
	virtual int LastKeyVEILStatus() override
	{
		std::shared_ptr<IKeyVEILConnector> conn = Connector();

		if (!conn)
			return 0;
		return conn->errorCode();
	}
	virtual std::shared_ptr<IKeyVEILConnector> Connector() override
	{
		return _connector.lock();
	}

protected:
	GUID									 _tokenId;
	std::shared_ptr<Asn1::CTS::_POD_Profile> _profile;
	std::weak_ptr<IKeyVEILConnector>		 _connector;
};

std::shared_ptr<IKeyVEILSession> CreateKeyVEILSession(const GUID& tokenId, std::shared_ptr<IKeyVEILConnector> connector)
{
	return ::TopServiceLocator()->Finish<IKeyVEILSession>(new KeyVEILSession(tokenId, connector));
}
