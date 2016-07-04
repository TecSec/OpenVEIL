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
#include "uv.h"

#ifndef _WIN32
#include <sys/un.h>
#include <unistd.h>

# define TEST_PIPENAME "/run/veilssm.sk"
#endif

class SSMKeyList : public ISSMKeyList
{
public:
	SSMKeyList(){}
	virtual ~SSMKeyList(){}

	virtual size_t count() override
	{
		return _list.size();
	}
	// Throws an exception if the index is out of range
	virtual const VEILssmAsn::KeyInfo& keyInfo(size_t item) override
	{
		if (item >= count())
			throw std::invalid_argument("The index is invalid");
		return *_list[item].get();
	}

	void AddKeyInfo(const VEILssmAsn::KeyInfo& info)
	{
		_list.push_back(std::shared_ptr<VEILssmAsn::KeyInfo>(new VEILssmAsn::KeyInfo(info)));
	}
protected:
	std::vector<std::shared_ptr<VEILssmAsn::KeyInfo> > _list;
};

class SSM : public ISoftwareSecurityModule, public tsmod::IObject
{
public:
	SSM() : _socket_fd(0){ }
	virtual ~SSM()
	{
	}

	virtual std::shared_ptr<ISSMKeyList> GetKeyList(VEILssmAsn::ListKeysType type) override
	{
		std::shared_ptr<SSMKeyList> list = std::shared_ptr<SSMKeyList>(new SSMKeyList());
		VEILssmAsn::Request rqst;
		VEILssmAsn::Response rsp;
		GUID sessionId;
		tsData tmp;
		int tag;
		bool constructed;
		uint8_t tagType;
		size_t length;

        LOG(httpLog, "ListKeys called");
		if (!xp_CreateGuid(sessionId) || !Connect())
			return nullptr;

		if (!Connect())
			return nullptr;

		auto closer = finally([this](){ Close(); });

		rqst.set_Id(sessionId);
		rqst.set_command(VEILssmAsn::cmd_CreateKey);
		rqst._commandInfo.selectedItem = VEILssmAsn::Request_commandInfo::Choice_listKeys;
		rqst._commandInfo._listKeys._type = type;

		if (!rqst.Encode(tmp))
			return nullptr;

#ifndef _WIN32
		write(_socket_fd, tmp.c_str(), tmp.size());
#endif
		tmp.resize(6);
#ifdef _MSC_VER
		tmp.resize(_read(_socket_fd, tmp.rawData(), 6));
#else // _MSC_VER
		tmp.resize(read(_socket_fd, tmp.rawData(), 6));
#endif // _MSC_VER

		if (tmp.size() != 6 || tmp[0] != 0x30)
			return nullptr;

		if (TlvNode::ExtractTagAndLength(tmp, 0, false, false, tag, constructed, tagType, length) == 0)
			return nullptr;

		tmp.resize(length + 6);
#ifdef _MSC_VER
		tmp.resize(_read(_socket_fd, &tmp.rawData()[6], (int)length - 6) + 6);
#else // _MSC_VER
#endif // _MSC_VER

		if (!rsp.Decode(tmp))
			return nullptr;

		if (rsp.get_command() != VEILssmAsn::cmd_ListKeys || rsp.get_Id() != sessionId || rsp._responseInfo.selectedItem != VEILssmAsn::Response_responseInfo::Choice_listKeys)
			return nullptr;

		VEILssmAsn::ListKeysResponse& lk = rsp._responseInfo._listKeys;

		for (size_t i = 0; i < lk.get_Keys().size(); i++)
		{
			VEILssmAsn::KeyInfo& keyInfo = lk.get_Keys().get_at(i);
			list->AddKeyInfo(keyInfo);
		}
		return std::dynamic_pointer_cast<ISSMKeyList>(list);
	}
	virtual GUID CreateKey(VEILssmAsn::KeyType keytype, const tsAscii& name, VEILssmAsn::RightsType userRights, VEILssmAsn::RightsType groupRights,
			VEILssmAsn::RightsType worldRights) override
	{
		VEILssmAsn::Request rqst;
		VEILssmAsn::Response rsp;
		GUID sessionId;
		tsData data;
		int tag;
		bool constructed;
		uint8_t tagType;
		size_t length;
		tsData tmp;

        LOG(httpLog, "CreateKey called");
		if (!xp_CreateGuid(sessionId) || !Connect())
			return GUID_NULL;

		auto closer = finally([this](){ Close(); });

		rqst.set_Id(sessionId);
		rqst.set_command(VEILssmAsn::cmd_CreateKey);
		rqst._commandInfo.selectedItem = VEILssmAsn::Request_commandInfo::Choice_createKey;

		VEILssmAsn::CreateKeyRequest &req = rqst._commandInfo._createKey;
#ifdef _WIN32
		// TODO:  Not really supported in windows.  VEILssm is a Linux app
		req.set_UserID(-1);
		req.set_GroupID(-1);
#else
		req.set_UserID(getuid());
		req.set_GroupID(getgid());
#endif
		req.set_name(name);
		req.set_keyType(keytype);
		req.set_userRights(userRights);
		req.set_groupRights(groupRights);
		req.set_worldRights(worldRights);

		if (!rqst.Encode(data))
			return GUID_NULL;

#ifdef _MSC_VER
		if (_write(_socket_fd, data.c_str(), (int)data.size()) < 0)
			return GUID_NULL;
#else // _MSC_VER
		if (write(_socket_fd, data.c_str(), (int)data.size()) < 0)
			return GUID_NULL;
#endif // _MSC_VER

		tmp.resize(6);
#ifdef _MSC_VER
		tmp.resize(_read(_socket_fd, tmp.rawData(), 6));
#else // _MSC_VER
		tmp.resize(read(_socket_fd, tmp.rawData(), 6));
#endif // _MSC_VER

		if (tmp.size() != 6 || tmp[0] != 0x30)
			return GUID_NULL;

		if (TlvNode::ExtractTagAndLength(tmp, 0, false, false, tag, constructed, tagType, length) == 0)
			return GUID_NULL;

		tmp.resize(length + 6);
#ifdef _MSC_VER
		tmp.resize(_read(_socket_fd, &tmp.rawData()[6], (unsigned int)length) + 6);
#else // _MSC_VER
		tmp.resize(read(_socket_fd, &tmp.rawData()[6], (unsigned int)length) + 6);
#endif // _MSC_VER

		if (!rsp.Decode(tmp))
			return GUID_NULL;
		if (rsp.get_command() != VEILssmAsn::cmd_CreateKey || rsp.get_Id() != sessionId || rsp._responseInfo.selectedItem != VEILssmAsn::Response_responseInfo::Choice_ResultId)
			return GUID_NULL;
		return rsp._responseInfo._ResultId;
	}
	virtual bool DeleteKey(const GUID& keyId) override
	{
		VEILssmAsn::Request rqst;
		VEILssmAsn::Response rsp;
		GUID sessionId;
		tsData data;
		int tag;
		bool constructed;
		uint8_t tagType;
		size_t length;
		tsData tmp;

        LOG(httpLog, "DeleteKey called");
		if (!xp_CreateGuid(sessionId) || !Connect())
			return false;

		auto closer = finally([this](){ Close(); });

		rqst.set_Id(sessionId);
		rqst.set_command(VEILssmAsn::cmd_DeleteKey);
		rqst._commandInfo.selectedItem = VEILssmAsn::Request_commandInfo::Choice_KeyId;
		rqst._commandInfo._KeyId = keyId;

		if (!rqst.Encode(data))
			return false;

#ifdef _MSC_VER
		if (_write(_socket_fd, data.c_str(), (unsigned int)data.size()) < 0)
			return false;
#else // _MSC_VER
		if (write(_socket_fd, data.c_str(), (unsigned int)data.size()) < 0)
			return false;
#endif // _MSC_VER

		tmp.resize(6);
#ifdef _MSC_VER
		tmp.resize(_read(_socket_fd, tmp.rawData(), 6));
#else // _MSC_VER
		tmp.resize(read(_socket_fd, tmp.rawData(), 6));
#endif // _MSC_VER

		if (tmp.size() != 6 || tmp[0] != 0x30)
			return false;

		if (TlvNode::ExtractTagAndLength(tmp, 0, false, false, tag, constructed, tagType, length) == 0)
			return false;

		tmp.resize(length + 6);
#ifdef _MSC_VER
		tmp.resize(_read(_socket_fd, &tmp.rawData()[6], (unsigned int)length) + 6);
#else // _MSC_VER
		tmp.resize(read(_socket_fd, &tmp.rawData()[6], (unsigned int)length) + 6);
#endif // _MSC_VER

		if (!rsp.Decode(tmp))
			return false;
		if (rsp.get_command() != VEILssmAsn::cmd_CreateKey || rsp.get_Id() != sessionId)
			return false;
		return rsp.get_resultCode() == VEILssmAsn::rslt_OK;
	}
	virtual tsData Derive(const GUID& keyId, std::shared_ptr<EccKey> pubKey) override
	{
		VEILssmAsn::Request rqst;
		VEILssmAsn::Response rsp;
		GUID sessionId;
		tsData data;
		int tag;
		bool constructed;
		uint8_t tagType;
		size_t length;
		tsData tmp;

        LOG(httpLog, "Derive called");
		if (!xp_CreateGuid(sessionId) || !Connect())
			return tsData();

		auto closer = finally([this](){ Close(); });

		rqst.set_Id(sessionId);
		rqst.set_command(VEILssmAsn::cmd_Derive);
		rqst._commandInfo.selectedItem = VEILssmAsn::Request_commandInfo::Choice_deriveKey;

		VEILssmAsn::DeriveKeyRequest &req = rqst._commandInfo._deriveKey;

		req._KeyId = keyId;
		req._AsymPublicKey = pubKey->get_Point();

		if (!rqst.Encode(data))
			return tsData();

#ifdef _MSC_VER
		if (_write(_socket_fd, data.c_str(), (unsigned int)data.size()) < 0)
			return tsData();
#else // _MSC_VER
		if (write(_socket_fd, data.c_str(), (unsigned int)data.size()) < 0)
			return tsData();
#endif // _MSC_VER

		tmp.resize(6);
#ifdef _MSC_VER
		tmp.resize(_read(_socket_fd, tmp.rawData(), 6));
#else // _MSC_VER
		tmp.resize(read(_socket_fd, tmp.rawData(), 6));
#endif // _MSC_VER

		if (tmp.size() != 6 || tmp[0] != 0x30)
			return tsData();

		if (TlvNode::ExtractTagAndLength(tmp, 0, false, false, tag, constructed, tagType, length) == 0)
			return tsData();

		tmp.resize(length + 6);
#ifdef _MSC_VER
		tmp.resize(_read(_socket_fd, &tmp.rawData()[6], (unsigned int)length) + 6);
#else // _MSC_VER
		tmp.resize(read(_socket_fd, &tmp.rawData()[6], (unsigned int)length) + 6);
#endif // _MSC_VER

		if (!rsp.Decode(tmp))
			return tsData();
		if (rsp.get_command() != VEILssmAsn::cmd_Derive || rsp.get_Id() != sessionId || rsp._responseInfo.selectedItem != VEILssmAsn::Response_responseInfo::Choice_data)
			return tsData();
		return rsp._responseInfo._data;
	}
	virtual tsData Derive(const GUID& keyId, const tsData& context, int keyBitSize) override
	{
		VEILssmAsn::Request rqst;
		VEILssmAsn::Response rsp;
		GUID sessionId;
		tsData data;
		int tag;
		bool constructed;
		uint8_t tagType;
		size_t length;
		tsData tmp;

        LOG(httpLog, "Derive called");
		if (!xp_CreateGuid(sessionId) || !Connect())
			return tsData();

		auto closer = finally([this](){ Close(); });

		rqst.set_Id(sessionId);
		rqst.set_command(VEILssmAsn::cmd_Derive);
		rqst._commandInfo.selectedItem = VEILssmAsn::Request_commandInfo::Choice_deriveKey;

		VEILssmAsn::DeriveKeyRequest &req = rqst._commandInfo._deriveKey;

		req._KeyId = keyId;
		req._Context = context;
		req._keyBitSize = keyBitSize;

		if (!rqst.Encode(data))
			return tsData();

#ifdef _MSC_VER
		if (_write(_socket_fd, data.c_str(), (unsigned int)data.size()) < 0)
			return tsData();
#else // _MSC_VER
		if (write(_socket_fd, data.c_str(), (unsigned int)data.size()) < 0)
			return tsData();
#endif // _MSC_VER

		tmp.resize(6);
#ifdef _MSC_VER
		tmp.resize(_read(_socket_fd, tmp.rawData(), 6));
#else // _MSC_VER
		tmp.resize(read(_socket_fd, tmp.rawData(), 6));
#endif // _MSC_VER

		if (tmp.size() != 6 || tmp[0] != 0x30)
			return tsData();

		if (TlvNode::ExtractTagAndLength(tmp, 0, false, false, tag, constructed, tagType, length) == 0)
			return tsData();

		tmp.resize(length + 6);
#ifdef _MSC_VER
		tmp.resize(_read(_socket_fd, &tmp.rawData()[6], (unsigned int)length) + 6);
#else // _MSC_VER
		tmp.resize(read(_socket_fd, &tmp.rawData()[6], (unsigned int)length) + 6);
#endif // _MSC_VER

		if (!rsp.Decode(tmp))
			return tsData();
		if (rsp.get_command() != VEILssmAsn::cmd_Derive || rsp.get_Id() != sessionId || rsp._responseInfo.selectedItem != VEILssmAsn::Response_responseInfo::Choice_data)
			return tsData();
		return rsp._responseInfo._data;
	}
	virtual tsData Derive(const GUID& keyId, std::shared_ptr<EccKey> pubKey, const tsData& context, int keyBitSize) override
	{
		VEILssmAsn::Request rqst;
		VEILssmAsn::Response rsp;
		GUID sessionId;
		tsData data;
		int tag;
		bool constructed;
		uint8_t tagType;
		size_t length;
		tsData tmp;

        LOG(httpLog, "Derive called");
		if (!xp_CreateGuid(sessionId) || !Connect())
			return tsData();

		auto closer = finally([this](){ Close(); });

		rqst.set_Id(sessionId);
		rqst.set_command(VEILssmAsn::cmd_Derive);
		rqst._commandInfo.selectedItem = VEILssmAsn::Request_commandInfo::Choice_deriveKey;

		VEILssmAsn::DeriveKeyRequest &req = rqst._commandInfo._deriveKey;

		req._KeyId = keyId;
		req._AsymPublicKey = pubKey->get_Point();
		req._Context = context;
		req._keyBitSize = keyBitSize;

		if (!rqst.Encode(data))
			return tsData();

#ifdef _MSC_VER
		if (_write(_socket_fd, data.c_str(), (unsigned int)data.size()) < 0)
			return tsData();
#else // _MSC_VER
		if (write(_socket_fd, data.c_str(), (unsigned int)data.size()) < 0)
			return tsData();
#endif // _MSC_VER

		tmp.resize(6);
#ifdef _MSC_VER
		tmp.resize(_read(_socket_fd, tmp.rawData(), 6));
#else // _MSC_VER
		tmp.resize(read(_socket_fd, tmp.rawData(), 6));
#endif // _MSC_VER

		if (tmp.size() != 6 || tmp[0] != 0x30)
			return tsData();

		if (TlvNode::ExtractTagAndLength(tmp, 0, false, false, tag, constructed, tagType, length) == 0)
			return tsData();

		tmp.resize(length + 6);
#ifdef _MSC_VER
		tmp.resize(_read(_socket_fd, &tmp.rawData()[6], (unsigned int)length) + 6);
#else // _MSC_VER
		tmp.resize(read(_socket_fd, &tmp.rawData()[6], (unsigned int)length) + 6);
#endif // _MSC_VER

		if (!rsp.Decode(tmp))
			return tsData();
		if (rsp.get_command() != VEILssmAsn::cmd_Derive || rsp.get_Id() != sessionId || rsp._responseInfo.selectedItem != VEILssmAsn::Response_responseInfo::Choice_data)
			return tsData();
		return rsp._responseInfo._data;
	}

protected:
	int _socket_fd;

	bool Connect()
	{
#ifdef _WIN32
		return false;
#else
		struct sockaddr_un address;

		_socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
		if (_socket_fd < 0)
		{
		    LOG(httpLog, "Unable to open the VEILssm socket.");
			return false;
		}
		memset(&address, 0, sizeof(address));
		address.sun_family = AF_UNIX;
		snprintf(address.sun_path, sizeof(address.sun_path), "%s", TEST_PIPENAME);
//		address.sun_path[0] = 0; // Anonymous

		if (connect(_socket_fd, (struct sockaddr*)&address, sizeof(struct sockaddr_un)) != 0)
        {
            LOG(httpLog, "Unable to connect to the VEILssm socket.");
			return false;
        }
		return true;
#endif
	}
	bool Close()
	{
#ifdef _WIN32
		return false;
#else
		if (_socket_fd != 0)
		{
			close(_socket_fd);
			_socket_fd = 0;
		}
		return true;
#endif
	}
};


tsmod::IObject* CreateSSM()
{
	return dynamic_cast<tsmod::IObject*>(new SSM());
}

