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

tsmod::IObject* CreateKeyGenerateTool()
{
	std::shared_ptr<tsmod::IVeilUtilities> utils = ::TopServiceLocator()->get_instance<tsmod::IVeilUtilities>("VeilUtilities");
	return utils->buildCommandMenu("Generate keys", "/KVKEYGEN-COMMANDS/", "generate", "GENERATE");
}


namespace eccoptions {
	enum options { OPT_HELP, OPT_KEYSIZE, OPT_NAME, OPT_SERVER, OPT_USERNAME, OPT_PASSWORD, OPT_FORENCRYPTION, OPT_EXPORTABLE };

	struct tsmod::OptionList GenEccOptions[] = {
		{ "", "VEIL tool genecc options" },
		{ "", "=================================" },
		{ "--help, -h, -?", "This help information." },
		{ "-s, --server=url", "The URL of KeyVEIL ." },
		{ "-u, --username=user", "Your user name within that KeyVEIL." },
		{ "-p, --password=pin", "The password to use (optional).  If the password is not specified here then you will be prompted for it when needed." },
		{ "-k, --keysize=<filename>", "The size in bits of the generated key" },
		{ "-n, --name=<keyname>", "The name for the new key" },
		{ "-e, --for-encryption", "Mark this key as an encryption key (default for signing)" },
		{ "--exportable", "Mark this key as an exportable key." },
		{ "", "" },
	};

	CSimpleOptA::SOption genEccOptionList[] =
	{
		{ OPT_HELP,              "-?",                  SO_NONE },
		{ OPT_HELP,              "-h",                  SO_NONE },
		{ OPT_HELP,              "--help",              SO_NONE },
		{ OPT_KEYSIZE,           "-k",                  SO_REQ_SEP },
		{ OPT_KEYSIZE,           "--keysize",           SO_REQ_SEP },
		{ OPT_NAME,              "-n",                  SO_REQ_SEP },
		{ OPT_NAME,              "--name",              SO_REQ_SEP },
		{ OPT_SERVER, "-s", SO_REQ_SEP },
		{ OPT_SERVER, "--server", SO_REQ_SEP },
		{ OPT_USERNAME, "-u", SO_REQ_SEP },
		{ OPT_USERNAME, "--username", SO_REQ_SEP },
		{ OPT_PASSWORD, "-p", SO_REQ_SEP },
		{ OPT_PASSWORD, "--password", SO_REQ_SEP },
		{ OPT_FORENCRYPTION, "-e", SO_NONE },
		{ OPT_FORENCRYPTION, "--for-encryption", SO_NONE },
		{ OPT_EXPORTABLE, "--exportable", SO_NONE },

		SO_END_OF_OPTIONS
	};
}
class genecc : public tsmod::IVeilToolCommand, public tsmod::IObject
{
public:
	genecc()
	{}
	~genecc()
	{}

	// tsmod::IObject
	virtual void OnConstructionFinished() override
	{
		utils = ::TopServiceLocator()->get_instance<tsmod::IVeilUtilities>("VeilUtilities");
	}

	// Inherited via tsmod::IVeilToolCommand
	virtual tscrypto::tsCryptoString getDescription() const override
	{
		return "Generate ECC key";
	}
	virtual int RunCommand(CSimpleOptA & opts) override
	{
		tscrypto::tsCryptoString name;
		int retVal = 1;
		int keysize = 0;
		tscrypto::tsCryptoString encryptionAlgName;
		tscrypto::tsCryptoString username, url;
		tscrypto::tsCryptoString password;
		bool forEncryption = false;
		bool exportable = false;
		JSONObject response;
		int status;

		opts.Init(opts.FileCount(), opts.Files(), eccoptions::genEccOptionList, SO_O_NOERR | SO_O_USEALL | SO_O_ICASE);
		while (opts.Next())
		{
			if (opts.LastError() == SO_SUCCESS)
			{
				if (opts.OptionId() == eccoptions::OPT_HELP)
				{
					Usage();
					return 0;
				}
				else if (opts.OptionId() == eccoptions::OPT_SERVER)
				{
					url = opts.OptionArg();
				}
				else if (opts.OptionId() == eccoptions::OPT_USERNAME)
				{
					username = opts.OptionArg();
				}
				else if (opts.OptionId() == eccoptions::OPT_PASSWORD)
				{
					password = opts.OptionArg();
				}
				else if (opts.OptionId() == eccoptions::OPT_KEYSIZE)
				{
					keysize = TsStrToInt(opts.OptionArg());
				}
				else if (opts.OptionId() == eccoptions::OPT_FORENCRYPTION)
				{
					forEncryption = true;
				}
				else if (opts.OptionId() == eccoptions::OPT_EXPORTABLE)
				{
					exportable = true;
				}
				else if (opts.OptionId() == eccoptions::OPT_NAME)
				{
					name = opts.OptionArg();
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

		// Connect to the KeyVEIL server
		std::shared_ptr<IKeyVEILConnector> connector = GetConnector(url, username, password);

		if (!connector)
		{
			printf("An error occurred while creating the KeyVEIL connector.\n");
			return 0;
		}

		JSONObject cmdData;

		cmdData
			.add("action", "CREATE")
			.add("spec", tsCryptoString(forEncryption ? "Encrypt" : "Sign"))
			.add("type", "ECC")
			.add("exportable", exportable)
			.add("length", (int64_t)keysize);

		if (name.size() > 0)
			cmdData.add("name", name);
		//		tscrypto::tsCryptoString hashAlg = postData.AsString("hashAlg");

		if (!connector->sendJsonRequest("POST", "Key", cmdData, response, status))
		{
			LOG(gHttpLog, "  Failed to generate the key");
			ERROR("Failed to generate the key");
			connector->disconnect();
			return false;
		}

		if (status >= 400)
		{
			printf("An error occurred in processing this command.  %d\n", status);
			connector->disconnect();
			return false;
		}

		printf("Name                                    ID                                     Type  Spec    Length\n");
		printf("===================================================================================================\n");

		if (response.hasField("name"))
		{
			printf("%-39s %-38s %-5s %-7s   %4d\n", response.AsString("name").c_str(), response.AsString("Id").c_str(), response.AsString("type").c_str(), response.AsString("spec").c_str(), (int)response.AsNumber("length"));
		}

		return retVal;
	}
	virtual tscrypto::tsCryptoString getCommandName() const override
	{
		return "ecc";
	}
protected:
	void Usage()
	{
		utils->Usage(eccoptions::GenEccOptions, sizeof(eccoptions::GenEccOptions) / sizeof(eccoptions::GenEccOptions[0]));
	}
protected:
	std::shared_ptr<tsmod::IVeilUtilities> utils;
};

tsmod::IObject* CreateGenerateEccTool()
{
	return dynamic_cast<tsmod::IObject*>(new genecc());
}

namespace rsaoptions {
	enum options { OPT_HELP, OPT_KEYSIZE, OPT_NAME, OPT_SERVER, OPT_USERNAME, OPT_PASSWORD, OPT_FORENCRYPTION, OPT_EXPORTABLE };

	struct tsmod::OptionList GenRsaOptions[] = {
		{ "", "VEIL tool genecc options" },
		{ "", "=================================" },
		{ "--help, -h, -?", "This help information." },
		{ "-s, --server=url", "The URL of KeyVEIL ." },
		{ "-u, --username=user", "Your user name within that KeyVEIL." },
		{ "-p, --password=pin", "The password to use (optional).  If the password is not specified here then you will be prompted for it when needed." },
		{ "-k, --keysize=<filename>", "The size in bits of the generated key" },
		{ "-n, --name=<keyname>", "The name for the new key" },
		{ "-e, --for-encryption", "Mark this key as an encryption key (default for signing)" },
		{ "--exportable", "Mark this key as an exportable key." },
		{ "", "" },
	};

	CSimpleOptA::SOption genRsaOptionList[] =
	{
		{ OPT_HELP,              "-?",                  SO_NONE },
		{ OPT_HELP,              "-h",                  SO_NONE },
		{ OPT_HELP,              "--help",              SO_NONE },
		{ OPT_KEYSIZE,           "-k",                  SO_REQ_SEP },
		{ OPT_KEYSIZE,           "--keysize",           SO_REQ_SEP },
		{ OPT_NAME,              "-n",                  SO_REQ_SEP },
		{ OPT_NAME,              "--name",              SO_REQ_SEP },
		{ OPT_SERVER, "-s", SO_REQ_SEP },
		{ OPT_SERVER, "--server", SO_REQ_SEP },
		{ OPT_USERNAME, "-u", SO_REQ_SEP },
		{ OPT_USERNAME, "--username", SO_REQ_SEP },
		{ OPT_PASSWORD, "-p", SO_REQ_SEP },
		{ OPT_PASSWORD, "--password", SO_REQ_SEP },
		{ OPT_FORENCRYPTION, "-e", SO_NONE },
		{ OPT_FORENCRYPTION, "--for-encryption", SO_NONE },
		{ OPT_EXPORTABLE, "--exportable", SO_NONE },

		SO_END_OF_OPTIONS
	};
}
class genrsa : public tsmod::IVeilToolCommand, public tsmod::IObject
{
public:
	genrsa()
	{}
	~genrsa()
	{}

	// tsmod::IObject
	virtual void OnConstructionFinished() override
	{
		utils = ::TopServiceLocator()->get_instance<tsmod::IVeilUtilities>("VeilUtilities");
	}

	// Inherited via tsmod::IVeilToolCommand
	virtual tscrypto::tsCryptoString getDescription() const override
	{
		return "Generate RSA key";
	}
	virtual int RunCommand(CSimpleOptA & opts) override
	{
		tscrypto::tsCryptoString name;
		int retVal = 1;
		int keysize = 0;
		tscrypto::tsCryptoString encryptionAlgName;
		tscrypto::tsCryptoString username, url;
		tscrypto::tsCryptoString password;
		bool forEncryption = false;
		bool exportable = false;
		JSONObject response;
		int status;

		opts.Init(opts.FileCount(), opts.Files(), rsaoptions::genRsaOptionList, SO_O_NOERR | SO_O_USEALL | SO_O_ICASE);
		while (opts.Next())
		{
			if (opts.LastError() == SO_SUCCESS)
			{
				if (opts.OptionId() == rsaoptions::OPT_HELP)
				{
					Usage();
					return 0;
				}
				else if (opts.OptionId() == rsaoptions::OPT_SERVER)
				{
					url = opts.OptionArg();
				}
				else if (opts.OptionId() == rsaoptions::OPT_USERNAME)
				{
					username = opts.OptionArg();
				}
				else if (opts.OptionId() == rsaoptions::OPT_PASSWORD)
				{
					password = opts.OptionArg();
				}
				else if (opts.OptionId() == rsaoptions::OPT_KEYSIZE)
				{
					keysize = TsStrToInt(opts.OptionArg());
				}
				else if (opts.OptionId() == rsaoptions::OPT_FORENCRYPTION)
				{
					forEncryption = true;
				}
				else if (opts.OptionId() == rsaoptions::OPT_EXPORTABLE)
				{
					exportable = true;
				}
				else if (opts.OptionId() == rsaoptions::OPT_NAME)
				{
					name = opts.OptionArg();
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

		// Connect to the KeyVEIL server
		std::shared_ptr<IKeyVEILConnector> connector = GetConnector(url, username, password);

		if (!connector)
		{
			printf("An error occurred while creating the KeyVEIL connector.\n");
			return 0;
		}

		JSONObject cmdData;

		cmdData
			.add("action", "CREATE")
			.add("spec", tsCryptoString(forEncryption ? "Encrypt" : "Sign"))
			.add("type", "RSA")
			.add("exportable", exportable)
			.add("length", (int64_t)keysize);

		if (name.size() > 0)
			cmdData.add("name", name);
		//		tscrypto::tsCryptoString hashAlg = postData.AsString("hashAlg");

		if (!connector->sendJsonRequest("POST", "Key", cmdData, response, status))
		{
			LOG(gHttpLog, "  Failed to generate the key");
			ERROR("Failed to generate the key");
			connector->disconnect();
			return false;
		}

		if (status >= 400)
		{
			printf("An error occurred in processing this command.  %d\n", status);
			connector->disconnect();
			return false;
		}

		printf("Name                                    ID                                     Type  Spec    Length\n");
		printf("===================================================================================================\n");

		if (response.hasField("name"))
		{
			printf("%-39s %-38s %-5s %-7s   %4d\n", response.AsString("name").c_str(), response.AsString("Id").c_str(), response.AsString("type").c_str(), response.AsString("spec").c_str(), (int)response.AsNumber("length"));
		}

		return retVal;
	}
	virtual tscrypto::tsCryptoString getCommandName() const override
	{
		return "ecc";
	}
protected:
	void Usage()
	{
		utils->Usage(rsaoptions::GenRsaOptions, sizeof(rsaoptions::GenRsaOptions) / sizeof(rsaoptions::GenRsaOptions[0]));
	}
protected:
	std::shared_ptr<tsmod::IVeilUtilities> utils;
};

tsmod::IObject* CreateGenerateRsaTool()
{
	return dynamic_cast<tsmod::IObject*>(new genrsa());
}





