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

enum options { OPT_HELP, OPT_URL, OPT_PASSWORD, OPT_USERNAME, OPT_TOKEN_PASSWORD, OPT_TOKEN_ID, OPT_TOKEN_NAME, OPT_TOKEN_SERIAL };

static const struct OptionList Options[] = {
	{ "", "VEIL TOKEN INFO options" },
	{ "", "=================================" },
	{ "--help, -h, -?", "This help information." },
	{ "-k, --keyveil=<url>", "The url to KeyVEIL" },
	{ "-u, --username=<name>", "The username to use to connect to KeyVEIL." },
	{ "-p, --password", "The password used to authenticate to KeyVEIL." },
	{ "-t, --token-password", "The password used to authenticate to the token." },
	{ "-i, --token-id", "The id of the token to view." },
	{ "-n, --token-name", "The name of the token to view." },
	{ "-s, --token-serial", "The serial number of the token to view." },
	{ "", "" },
};

static const CSimpleOptA::SOption OptionList[] =
{
	{ OPT_HELP,              "-?",                  SO_NONE },
	{ OPT_HELP,              "-h",                  SO_NONE },
	{ OPT_HELP,              "--help",              SO_NONE },
	{ OPT_URL,               "-k",                  SO_REQ_SEP },
	{ OPT_URL,               "--keyveil",           SO_REQ_SEP },
	{ OPT_PASSWORD,          "-p",                  SO_REQ_SEP },
	{ OPT_PASSWORD,          "--password",          SO_REQ_SEP },
	{ OPT_USERNAME,          "-u",                  SO_REQ_SEP },
	{ OPT_USERNAME,          "--username",          SO_REQ_SEP },
	{ OPT_TOKEN_PASSWORD,    "-t",                  SO_REQ_SEP },
	{ OPT_TOKEN_PASSWORD,    "--token-password",    SO_REQ_SEP },
	{ OPT_TOKEN_ID,          "-i",                  SO_REQ_SEP },
	{ OPT_TOKEN_ID,          "--token-id",          SO_REQ_SEP },
	{ OPT_TOKEN_NAME,        "-n",                  SO_REQ_SEP },
	{ OPT_TOKEN_NAME,        "--token-name",        SO_REQ_SEP },
	{ OPT_TOKEN_SERIAL,      "-s",                  SO_REQ_SEP },
	{ OPT_TOKEN_SERIAL,      "--token-serial",      SO_REQ_SEP },

	SO_END_OF_OPTIONS
};

class TokenInfoTool : public IVeilToolCommand, public tsmod::IObject
{
public:
	TokenInfoTool()
	{}
	~TokenInfoTool()
	{}

	// tsmod::IObject
	virtual void OnConstructionFinished()
	{
		utils = ::ServiceLocator()->get_instance<IVeilUtilities>("VeilUtilities");
	}

	// Inherited via IVeilToolCommand
	virtual tsAscii getDescription() const override
	{
		return "Display token information";
	}
	virtual int RunCommand(CSimpleOptA & opts) override
	{
		int retVal = 1;
		tsAscii username, password, url, tokenPassword, tokenId, tokenName, tokenSerial;

		opts.Init(opts.FileCount(), opts.Files(), OptionList, SO_O_NOERR | SO_O_USEALL | SO_O_ICASE);
		while (opts.Next())
		{
			if (opts.LastError() == SO_SUCCESS)
			{
				if (opts.OptionId() == OPT_HELP)
				{
					Usage();
					return 0;
				}
				else if (opts.OptionId() == OPT_URL)
				{
					url = opts.OptionArg();
				}
				else if (opts.OptionId() == OPT_PASSWORD)
				{
					password = opts.OptionArg();
				}
				else if (opts.OptionId() == OPT_USERNAME)
				{
					username = opts.OptionArg();
				}
				else if (opts.OptionId() == OPT_TOKEN_PASSWORD)
				{
					tokenPassword = opts.OptionArg();
				}
				else if (opts.OptionId() == OPT_TOKEN_ID)
				{
					tokenId = opts.OptionArg();
				}
				else if (opts.OptionId() == OPT_TOKEN_NAME)
				{
					tokenName = opts.OptionArg();
				}
				else if (opts.OptionId() == OPT_TOKEN_SERIAL)
				{
					tokenSerial = opts.OptionArg();
				}
				else
				{
					Usage();
					return 1;
				}
			}
			else
			{
				Usage();
				return 1;
			}
		}

		std::shared_ptr<IKeyVEILConnector> connector = GetConnector(url, username, password);

		if (!connector)
		{
			printf("An error occurred while creating the KeyVEIL connector.\n");
			return 0;
		}

		GUID id = ToGuid()(tokenId);
		tsData serial = tokenSerial.HexToData();


		std::shared_ptr<IToken> token;
		std::shared_ptr<IKeyVEILSession> session;
		std::shared_ptr<Asn1::CTS::Profile> profile;

		if (id != GUID_NULL)
			token = connector->token(id);
		if (!token && serial.size() > 0)
			token = connector->token(serial);
		if (!token && tokenName.size() > 0)
			token = connector->token(tokenName);

		if (!token)
		{
			printf("An error occurred while retrieving the token.\n");
			return 0;
		}
		printf("Token:  %s\n", token->tokenName().c_str());
		printf("    serial number:  %s\n         Token ID:  %s\n", token->serialNumber().ToHexString().c_str(), TSGuidToString(token->id()).c_str());
		printf("       Enterprise:  %s\n    Enterprise ID:  %s\n", token->enterpriseName().c_str(), TSGuidToString(token->enterpriseId()).c_str());
		printf("           Member:  %s\n        Member ID:  %s\n", token->memberName().c_str(), TSGuidToString(token->memberId()).c_str());

		if (!(session = token->openSession()))
		{
			printf("An error occurred while opening a session to this token.\n");
			return 1;
		}
		printf("        Is Locked:  %s\n      Retry count:  %d\n\n", session->IsLocked() ? "true" : "false", (int)session->retriesLeft());

		if (!session->IsLoggedIn())
		{
			if (password.size() > 0)
			{
				if (password.size() != 0)
				{
					switch (session->Login(password))
					{
					case LoginStatus::loginStatus_Connected:
						break;
					case LoginStatus::loginStatus_BadAuth:
						printf("\nThe password for the token is incorrect.\n");
						break;
					case LoginStatus::loginStatus_NoServer:
					default:
						printf("\nA communications error has occurred while logging into the token.\n");
						break;
					}
				}
			}
		}
		if (!session->IsLoggedIn())
		{
			tsAscii pin;
			xp_console ts_out;

			ts_out.GetPin(pin, 64, "Enter the password for this token to view the private data or leave it blank to display only the public information.\n\nEnter the password:");

			if (pin.size() != 0)
			{
				switch (session->Login(pin))
				{
				case LoginStatus::loginStatus_Connected:
					break;
				case LoginStatus::loginStatus_BadAuth:
					printf("\nThe password for the token is incorrect.\n");
					break;
				case LoginStatus::loginStatus_NoServer:
				default:
					printf("\nA communications error has occurred while logging into the token.\n");
					break;
				}
			}
			if (!session->IsLoggedIn())
				printf("\nPUBLIC DATA ONLY - NOT LOGGED INTO THE TOKEN\n\n");
		}
		profile = session->GetProfile();
		if (!!profile)
		{
			for (size_t c = 0; c < profile->get_cryptoGroupList_count(); c++)
			{
				Asn1::CTS::CryptoGroup& grp = profile->get_cryptoGroupList_at(c);

				if (grp.get_Usage() == Asn1::CTS::cgu_User)
				{
					size_t fiefdomCount;
					size_t categoryCount;
					size_t attributeCount;

					printf("Crypto Group:  %s\n", grp.get_Name().c_str());
					printf("----------------------------------------------------------------------\n");
					printf("  ID:  %s\n", TSGuidToString(grp.get_Id()).c_str());
					printf("  Forward Level:  %d   Backwards Level:  %d\n", grp.get_ForwardVersion(), grp.get_BackwardVersion());
					printf("  Issue Date:  %s  Expire Date:  %s\n", grp.get_Issue().ToString().c_str(), grp.get_Expire().ToString().c_str());
					printf("  Expire Action:  %d  Rollback Action:  %d  Grace Period:  %d\n", grp.get_expireAction(), grp.get_rollbackAction(), grp.get_gracePeriod());

					if (grp._FiefdomList.exists)
					{
						fiefdomCount = grp._FiefdomList.value->size();
						for (size_t i = 0; i < fiefdomCount; i++)
						{
							std::shared_ptr<Asn1::CTS::Fiefdom> fief = std::dynamic_pointer_cast<Asn1::CTS::Fiefdom>(grp._FiefdomList.value->at(i));
							if (!!fief)
							{
								printf("\n    Fiefdom:  %s\n", fief->get_Name().c_str());

								categoryCount = fief->get_CategoryList_count();
								for (size_t j = 0; j < categoryCount; j++)
								{
									std::shared_ptr<Asn1::CTS::Category> cat = std::dynamic_pointer_cast<Asn1::CTS::Category>(fief->_CategoryList.value->at(j));
									attributeCount = cat->get_AttributeList_count();

									printf("\n      Category:  %s\n", cat->get_Name().c_str());

									for (size_t k = 0; k < attributeCount; k++)
									{
										std::shared_ptr<Asn1::CTS::Attribute> attr = std::dynamic_pointer_cast<Asn1::CTS::Attribute>(cat->_AttributeList.value->at(k));

										printf("\n        Attribute:  %s\n", attr->get_Name().c_str());
										printf("        --------------------------------------------------------------\n");
										printf("        ID:  %s\n", TSGuidToString(attr->get_Id()).c_str());
										printf("        Forward Level:  %d   Backwards Level:  %d\n", attr->get_ForwardVersion(), attr->get_BackwardVersion());
										printf("        Issue Date:  %s  Expire Date:  %s\n", attr->get_Issue().ToString().c_str(), attr->get_Expire().ToString().c_str());
										if (attr->get_SymOnly())
										{
											printf("        Symmetric\n");
										}
										else
										{
											printf("        Has Read:  %s  Has Write:  %s\n", attr->get_hasRead() ? "true" : "false", attr->get_hasWrite() ? "true" : "false");
										}
									}
								}
							}
						}
					}
				}
			}
		}

		return retVal;
	}
	virtual tsAscii getCommandName() const override
	{
		return "info";
	}
protected:
	void Usage()
	{
		utils->Usage(Options, sizeof(Options) / sizeof(Options[0]));
	}
	std::shared_ptr<IKeyVEILConnector> GetConnector(const tsAscii& url, const tsAscii& username, const tsAscii& password)
	{
		std::shared_ptr<IKeyVEILConnector> connector;

		if (::ServiceLocator()->CanCreate("/KeyVEIL"))
		{
			connector = ::ServiceLocator()->get_instance<IKeyVEILConnector>("/KeyVEIL");
		}
		else
		{
			connector = ::ServiceLocator()->try_get_instance<IKeyVEILConnector>("/KeyVEILConnector");
			if (!connector)
			{
				return nullptr;
			}
			::ServiceLocator()->AddSingletonObject("/KeyVEIL", std::dynamic_pointer_cast<tsmod::IObject>(connector));
		}

		if (!connector->isConnected())
		{
			int argc = 0;
			const char **argv = nullptr;
			if (!ConnectToKeyVEIL(connector, url, username, password))
			{
				return nullptr;
			}
		}
		return connector;
	}
	bool ConnectToKeyVEIL(std::shared_ptr<IKeyVEILConnector>& connector, const tsAscii& url, const tsAscii& username, const tsAscii& password)
	{
		char buff[1024] = "";
		JSONObject settings;
		tsAscii Username;
		tsAscii Password;
		int len;
		tsAscii Url;
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

			len = (int)strlen(buff);
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

			len = (int)strlen(buff);
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

		if (password.size() == 0)
		{
			utils->console().GetPin(Password, 64, "Enter the password:  ");
			if (Password.size() == 0)
				return false;
		}
		else
			Password = password;

		return connector->connect(Url, Username, Password) == connStatus_Connected;
	}
protected:
	std::shared_ptr<IVeilUtilities> utils;
};

tsmod::IObject* CreateTokenInfoTool()
{
	return dynamic_cast<tsmod::IObject*>(new TokenInfoTool());
}

