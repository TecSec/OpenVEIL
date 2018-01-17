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

class Token : public IToken, public tsmod::IObject
{
public:
	Token(std::shared_ptr<IKeyVEILConnector> connector, JSONObject contents)
	{
		_connector = connector;
		_id = TSStringToGuid(contents.AsString("id"));
		_enterpriseId = TSStringToGuid(contents.AsString("entId"));
		_memberId = TSStringToGuid(contents.AsString("memId"));
		_serialNumber = contents.AsString("serial").HexToData();
		_tokenName = contents.AsString("tokenName");
		_enterpriseName = contents.AsString("enterpriseName");
		_memberName = contents.AsString("memberName");
		_tokenType = contents.AsString("type");
	}
	virtual ~Token()
	{
		_sessions.erase(std::remove_if(_sessions.begin(), _sessions.end(), [](std::weak_ptr<IKeyVEILSession>& sess) -> bool { return sess.expired(); }), _sessions.end());

		for (auto sess : _sessions)
		{
			std::shared_ptr<IKeyVEILSession> session = sess.lock();
			if (!!session)
				session->Close();
		}
	}

	virtual tscrypto::tsCryptoString tokenName() override { return _tokenName; }
	virtual bool tokenName(const tscrypto::tsCryptoStringBase& setTo) override
	{
		JSONObject upData, downData;
		int status;

		if (setTo == tokenName())
			return true;
		std::shared_ptr<IKeyVEILConnector> connector = _connector.lock();
		if (!connector)
			return false;

		upData
			.add("serialNumber", serialNumber().ToHexString())
			.add("name", setTo);

		if (!connector->sendJsonRequest("PUT", "Token", upData, downData, status) || (status != 200 && status != 204))
		{
			return false;
		}
		_tokenName = setTo;
		return true;
	}
	virtual tscrypto::tsCryptoData serialNumber() override { return _serialNumber; }
	virtual GUID id() override { return _id; }
	virtual tscrypto::tsCryptoString enterpriseName() override { return _enterpriseName; }
	virtual tscrypto::tsCryptoString memberName() override { return _memberName; }
	virtual tscrypto::tsCryptoString tokenType() override { return _tokenType; }
	virtual GUID enterpriseId() override { return _enterpriseId; }
	virtual GUID memberId() override { return _memberId; }

	virtual std::shared_ptr<IKeyVEILSession> openSession() override
	{
		if (_connector.use_count() == 0)
			return nullptr;

		TSAUTOLOCKER lock(_sessionLock);

		// Remove sessions that have been closed
		_sessions.erase(std::remove_if(_sessions.begin(), _sessions.end(), [](std::weak_ptr<IKeyVEILSession>& sess) -> bool { return sess.expired(); }), _sessions.end());

		std::shared_ptr<IKeyVEILSession> session = CreateKeyVEILSession(_id, _connector.lock());
		_sessions.push_back(session);
		return session;
	}
protected:
	std::weak_ptr<IKeyVEILConnector> _connector;
	std::vector<std::weak_ptr<IKeyVEILSession> > _sessions;
	tscrypto::AutoCriticalSection _sessionLock;
	GUID _id;
	GUID _enterpriseId;
	GUID _memberId;
	tscrypto::tsCryptoString _tokenName;
	tscrypto::tsCryptoString _tokenType;
	tscrypto::tsCryptoString _enterpriseName;
	tscrypto::tsCryptoString _memberName;
	tscrypto::tsCryptoData  _serialNumber;
};

std::shared_ptr<IToken> CreateTokenObject(std::shared_ptr<IKeyVEILConnector> connector, JSONObject contents)
{
	return ::TopServiceLocator()->Finish<IToken>(new Token(connector, contents));
}
