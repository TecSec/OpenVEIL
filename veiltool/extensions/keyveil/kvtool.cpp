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

#ifndef NO_LOGGING
tsDebugStream gHttpLog("HttpLog", DEBUG_LEVEL_INFORMATION);
tsTraceStream gLog("Log", DEBUG_LEVEL_INFORMATION);
#endif

enum options { OPT_HELP = 1000, };

static tsmod::IObject* CreateKeyVEILTool()
{
	std::shared_ptr<tsmod::IVeilUtilities> utils = ::TopServiceLocator()->get_instance<tsmod::IVeilUtilities>("VeilUtilities");
	return utils->buildCommandMenu("Perform KeyVEIL operations", "/KV-COMMANDS/", "kv", "KV");
}

extern tsmod::IObject* CreateGetKeyListTool();
extern tsmod::IObject* CreateKvTokensTool();
extern tsmod::IObject* CreateKeyVEILTokenListTool();
extern tsmod::IObject* CreateKeyVEILTokenInfoTool();
extern tsmod::IObject* CreateKvKeyTool();
extern tsmod::IObject* CreateKeyGenerateTool();
extern tsmod::IObject* CreateGenerateEccTool();
extern tsmod::IObject* CreateGenerateRsaTool();

#ifdef _WIN32
#define EXPORTME __declspec(dllexport)
#else
#define EXPORTME EXPORT_SYMBOL
#endif

extern "C"
bool EXPORTME Initialize_keyveiltool(std::shared_ptr<tsmod::IServiceLocator> servLoc, tsmod::IReportError* log)
{
	UNREFERENCED_PARAMETER(servLoc);
	UNREFERENCED_PARAMETER(log);

		::TopServiceLocator()->AddClass("/COMMANDS/KV", CreateKeyVEILTool);
		::TopServiceLocator()->AddClass("/KVKEY-COMMANDS/LIST", CreateGetKeyListTool);
		::TopServiceLocator()->AddClass("/KVKEY-COMMANDS/GENERATE", CreateKeyGenerateTool);
		::TopServiceLocator()->AddClass("/KVKEYGEN-COMMANDS/ECC", CreateGenerateEccTool);
		::TopServiceLocator()->AddClass("/KVKEYGEN-COMMANDS/RSA", CreateGenerateRsaTool);
		::TopServiceLocator()->AddClass("/KV-COMMANDS/TOKEN", CreateKvTokensTool);
		::TopServiceLocator()->AddClass("/KV-COMMANDS/KEY", CreateKvKeyTool);
		::TopServiceLocator()->AddClass("/KVTOKEN-COMMANDS/LIST", CreateKeyVEILTokenListTool);
		::TopServiceLocator()->AddClass("/KVTOKEN-COMMANDS/INFO", CreateKeyVEILTokenInfoTool);
	return true;
}

extern "C"
bool EXPORTME Terminate_keyveiltool(std::shared_ptr<tsmod::IServiceLocator> servLoc)
{
	UNREFERENCED_PARAMETER(servLoc);

		if (::HasServiceLocator())
		{
		::TopServiceLocator()->DeleteClass("/KV-COMMANDS/TOKEN");
		::TopServiceLocator()->DeleteClass("/KV-COMMANDS/KEY");

		::TopServiceLocator()->DeleteClass("/KVTOKEN-COMMANDS/LIST");
		::TopServiceLocator()->DeleteClass("/KVTOKEN-COMMANDS/INFO");

		::TopServiceLocator()->DeleteClass("/KVKEY-COMMANDS/LIST");
		::TopServiceLocator()->DeleteClass("/KVKEY-COMMANDS/GENERATE");

		::TopServiceLocator()->DeleteClass("/KVKEYGEN-COMMANDS/ECC");
		::TopServiceLocator()->DeleteClass("/KVKEYGEN-COMMANDS/RSA");

		::TopServiceLocator()->CleanEmptyCollections();
		::TopServiceLocator()->DeleteClass("/COMMANDS/KV");
		}
	return true;
}



bool ConnectToKeyVEIL(std::shared_ptr<IKeyVEILConnector>& connector, const tscrypto::tsCryptoString& url, const tscrypto::tsCryptoString& username, const tscrypto::tsCryptoString& password)
{
	char buff[1024] = "";
	JSONObject settings;
	tscrypto::tsCryptoString Username;
	tscrypto::tsCryptoString Password;
	int len;
	tscrypto::tsCryptoString Url;
	std::shared_ptr<BasicVEILPreferences> prefs = BasicVEILPreferences::Create();

	if (url.size() == 0)
	{
		if (prefs->KeyVEILUrlLocation() != jc_NotFound)
		{
			printf("The default KeyVEIL URL is '%s'\n", prefs->getKeyVEILUrl().c_str());
		}
		printf("Enter the KeyVEIL URL to use or leave it blank to use the default.\n");
		fflush(stdin);
		fgets(buff, sizeof(buff), stdin);

		len = (int)tsStrLen(buff);
		if (len > 0)
		{
			if (buff[len - 1] == '\n')
				len--;
			buff[len] = 0;
		}
		//if (len != 0)
		//{
		//	settings.deleteField("KeyVEILUrl").add("KeyVEILUrl", buff);
		//}
		Url = buff;
		if (Url.size() == 0)
			Url = prefs->getKeyVEILUrl();
	}
	else
	{
		Url = url;
	}

	if (username.size() == 0)
	{
		if (prefs->KeyVEILUsernameLocation() != jc_NotFound)
		{
			printf("The default KeyVEIL username is '%s'\n", prefs->getKeyVEILUsername().c_str());
		}
		printf("Enter the user name or leave it blank to use the default:  ");

		fflush(stdin);
		fgets(buff, sizeof(buff), stdin);

		len = (int)tsStrLen(buff);
		if (len > 0)
		{
			if (buff[len - 1] == '\n')
				len--;
			buff[len] = 0;
		}
		Username = buff;
		if (Username.size() == 0)
			Username = prefs->getKeyVEILUsername();
	}
	else
		Username = username;

	std::shared_ptr<tsmod::IVeilUtilities> utils = ::TopServiceLocator()->get_instance<tsmod::IVeilUtilities>("VeilUtilities");

	if (password.size() == 0)
	{
		utils->console().GetPin(Password, 64, "Enter the password:  ");
		if (Password.size() == 0)
			return false;
	}
	else
		Password = password;

	switch (connector->connect(Url, Username, Password))
	{
	case connStatus_BadAuth:
		ERROR("The authentication information was incorrect.");
		return false;
	case connStatus_NoServer:
		ERROR("The server was not found at the specified address.");
		return false;
	case connStatus_UrlBad:
		ERROR("The URL is not properly formed.");
		return false;
	case connStatus_WrongProtocol:
		ERROR("The specified protocol was not recognized.");
		return false;
	case connStatus_Connected:
		break;
	}
	return true;
}
std::shared_ptr<IKeyVEILConnector> GetConnector(const tscrypto::tsCryptoString& url, const tscrypto::tsCryptoString& username, const tscrypto::tsCryptoString& password)
{
	std::shared_ptr<IKeyVEILConnector> connector;

	if (::TopServiceLocator()->CanCreate("/KeyVEIL"))
	{
		connector = ::TopServiceLocator()->get_instance<IKeyVEILConnector>("/KeyVEIL");
	}
	else
	{
		connector = ::TopServiceLocator()->try_get_instance<IKeyVEILConnector>("/KeyVEILConnector");
		if (!connector)
		{
			return nullptr;
		}
		::TopServiceLocator()->AddSingletonObject("/KeyVEIL", std::dynamic_pointer_cast<tsmod::IObject>(connector));
	}

	if (!connector->isConnected())
	{
		if (!ConnectToKeyVEIL(connector, url, username, password))
		{
			return nullptr;
		}
	}
	return connector;
}
