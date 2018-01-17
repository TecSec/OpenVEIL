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

enum options { OPT_HELP, OPT_URL, OPT_PASSWORD, OPT_USERNAME, OPT_TOKEN_PASSWORD, OPT_TOKEN_ID, OPT_TOKEN_NAME, OPT_TOKEN_SERIAL };

static const struct tsmod::OptionList Options[] = {
	{ "", "VEIL KEYVEIL TOKEN INFO options" },
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

class KeyVEILTokenInfoTool : public tsmod::IVeilToolCommand, public tsmod::IObject
{
public:
	KeyVEILTokenInfoTool()
	{}
	~KeyVEILTokenInfoTool()
	{}

	// tsmod::IObject
	virtual void OnConstructionFinished() override
	{
		utils = ::TopServiceLocator()->get_instance<tsmod::IVeilUtilities>("VeilUtilities");
	}

	// Inherited via tsmod::IVeilToolCommand
	virtual tscrypto::tsCryptoString getDescription() const override
	{
		return "Display token information";
	}
	virtual int RunCommand(CSimpleOptA & opts) override
	{
		int retVal = 1;
		tscrypto::tsCryptoString username, password, url, tokenPassword, tokenId, tokenName, tokenSerial;

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
		tscrypto::tsCryptoData serial = tokenSerial.HexToData();


		std::shared_ptr<IToken> token;
		std::shared_ptr<IKeyVEILSession> session;
		std::shared_ptr<Asn1::CTS::_POD_Profile> profile;

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
			tscrypto::tsCryptoString pin;
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
		if (!!profile && profile->exists_cryptoGroupList())
		{
			for (size_t c = 0; c < profile->get_cryptoGroupList()->size(); c++)
			{
				Asn1::CTS::_POD_CryptoGroup& grp = profile->get_cryptoGroupList()->get_at(c);

				if (grp.get_Usage() == Asn1::CTS::cgu_User)
				{
					size_t fiefdomCount;
					size_t categoryCount;
					size_t attributeCount;

					printf("Crypto Group:  %s\n", grp.get_Name().c_str());
					printf("----------------------------------------------------------------------\n");
					printf("  ID:  %s\n", grp.get_Id().ToHexString().c_str());
					printf("  Forward Level:  %d   Backwards Level:  %d\n", grp.get_ForwardVersion(), grp.get_BackwardVersion());
					printf("  Issue Date:  %s  Expire Date:  %s\n", grp.get_Issue().ToString().c_str(), grp.get_Expire().ToString().c_str());
					printf("  Expire Action:  %d  Rollback Action:  %d  Grace Period:  %d\n", grp.get_expireAction(), grp.get_rollbackAction(), grp.get_gracePeriod());

					if (grp.exists_FiefdomList())
					{
						fiefdomCount = grp.get_FiefdomList()->size();
						for (size_t i = 0; i < fiefdomCount; i++)
						{
							Asn1::CTS::_POD_Fiefdom& fief = grp.get_FiefdomList()->get_at(i);
							printf("\n    Fiefdom:  %s\n", fief.get_Name().c_str());

							if (fief.exists_CategoryList())
							{
							categoryCount = fief.get_CategoryList()->size();
								for (size_t j = 0; j < categoryCount; j++)
								{
								Asn1::CTS::_POD_Category& cat = fief.get_CategoryList()->get_at(j);
									if (cat.exists_AttributeList())
									{
								attributeCount = cat.get_AttributeList()->size();

								printf("\n      Category:  %s\n", cat.get_Name().c_str());

									for (size_t k = 0; k < attributeCount; k++)
									{
									Asn1::CTS::_POD_Attribute& attr = cat.get_AttributeList()->get_at(k);

									printf("\n        Attribute:  %s\n", attr.get_Name().c_str());
										printf("        --------------------------------------------------------------\n");
									printf("        ID:  %s\n", attr.get_Id().ToHexString().c_str());
									printf("        Forward Level:  %d   Backwards Level:  %d\n", attr.get_ForwardVersion(), attr.get_BackwardVersion());
									printf("        Issue Date:  %s  Expire Date:  %s\n", attr.get_Issue().ToString().c_str(), attr.get_Expire().ToString().c_str());
									if (attr.get_SymOnly())
										{
											printf("        Symmetric\n");
										}
										else
										{
										printf("        Has Read:  %s  Has Write:  %s\n", attr.get_hasRead() ? "true" : "false", attr.get_hasWrite() ? "true" : "false");
											}
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
	virtual tscrypto::tsCryptoString getCommandName() const override
	{
		return "info";
	}
protected:
	void Usage()
	{
		utils->Usage(Options, sizeof(Options) / sizeof(Options[0]));
	}
protected:
	std::shared_ptr<tsmod::IVeilUtilities> utils;
};

tsmod::IObject* CreateKeyVEILTokenInfoTool()
{
	return dynamic_cast<tsmod::IObject*>(new KeyVEILTokenInfoTool());
}

