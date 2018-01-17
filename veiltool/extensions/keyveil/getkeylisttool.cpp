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

enum {
	OPT_HELP = 0, OPT_SERVER, OPT_USERNAME, OPT_PASSWORD, 
};

//printf("USAGE: GetMyCTS <username> <ServerUrl>\n");

static const struct tsmod::OptionList options[] = {
	{ "", "VEIL tool KEYVEIL KEYLIST options" },
	{ "", "=================================" },
	{ "--help, -h, -?", "This help information." },
	{ "-s, --server=url", "The URL of KeyVEIL ." },
	{ "-u, --username=user", "Your user name within that KeyVEIL." },
	{ "-p, --password=pin", "The password to use (optional).  If the password is not specified here then you will be prompted for it when needed." },
	{ "", "" },
};
static const CSimpleOptA::SOption g_rgOptions1[] =
{
	{ OPT_HELP, "-?", SO_NONE },
	{ OPT_HELP, "-h", SO_NONE },
	{ OPT_HELP, "--help", SO_NONE },
	{ OPT_SERVER, "-s", SO_REQ_SEP },
	{ OPT_SERVER, "--server", SO_REQ_SEP },
	{ OPT_USERNAME, "-u", SO_REQ_SEP },
	{ OPT_USERNAME, "--username", SO_REQ_SEP },
	{ OPT_PASSWORD, "-p", SO_REQ_SEP },
	{ OPT_PASSWORD, "--password", SO_REQ_SEP },
	SO_END_OF_OPTIONS
};

class GetKeyListTool : public tsmod::IVeilToolCommand, public tsmod::IObject
{
public:
	GetKeyListTool()
	{}
	~GetKeyListTool()
	{}

	// tsmod::IObject
	virtual void OnConstructionFinished() override
	{
		utils = ::TopServiceLocator()->get_instance<tsmod::IVeilUtilities>("VeilUtilities");
	}

	// Inherited via tsmod::IVeilToolCommand
	virtual tscrypto::tsCryptoString getDescription() const override
	{
		return "Get the list of keys available.";
	}
	virtual int RunCommand(CSimpleOptA & opts) override
	{
		int64_t start;
		tscrypto::tsCryptoString username, url, filename, baseUri, cmd;
		tscrypto::tsCryptoData outData;
		JSONObject response;
		int status;
		tscrypto::tsCryptoString password;


		opts.Init(opts.FileCount(), opts.Files(), g_rgOptions1, SO_O_NOERR | SO_O_USEALL | SO_O_ICASE);

		while (opts.Next())
		{
			if (opts.LastError() == SO_SUCCESS)
			{
				if (opts.OptionId() == OPT_SERVER)
				{
					url = opts.OptionArg();
				}
				else if (opts.OptionId() == OPT_USERNAME)
				{
					username = opts.OptionArg();
				}
				else if (opts.OptionId() == OPT_PASSWORD)
				{
					password = opts.OptionArg();
				}
				else if (opts.OptionId() == OPT_HELP)
				{
					Usage();
					return 0;
				}
				else {
					ERROR("Unknown option: " << opts.OptionText());
					return 8;
				}
			}
			else
			{
				ERROR("Invalid arguments detected.");
				Usage();
				return 9;
			}
		}

		if (opts.FileCount() > 0)
		{
			ERROR("Unknown options were detected.");
			return 12;
		}

		// Connect to the KeyVEIL server
		std::shared_ptr<IKeyVEILConnector> connector = GetConnector(url, username, password);

		if (!connector)
		{
			printf("An error occurred while creating the KeyVEIL connector.\n");
			return 0;
		}

		cmd << "Key";

		start = GetTicks();
		LOG(gHttpLog, "GET " << cmd);
		start = GetTicks();
		if (!connector->sendJsonRequest("GET", cmd, JSONObject(), response, status))
		{
			LOG(gHttpLog, "  Failed to retrieve the list of keys for this user");
			ERROR("Failed to retrieve the list of keys for this user");
			connector->disconnect();
			return false;
		}
		LOG(gHttpLog, "  Success - " << ToString()((GetTicks() - start) / 1000.0) << " ms  Status:  " << status);

		if (status >= 400)
		{
			connector->disconnect();
			return false;
		}

		printf("Name                                    ID                                     Type  Spec    Length\n");
		printf("===================================================================================================\n");

		if (response.hasField("KeyCollection"))
		{
			for (auto it : *response.AsArray("KeyCollection"))
			{
				JSONObject obj = it.AsObject();

				printf("%-39s %-38s %-5s %-7s   %4d\n", obj.AsString("name").c_str(), obj.AsString("Id").c_str(), obj.AsString("type").c_str(), obj.AsString("spec").c_str(), (int)obj.AsNumber("length"));
			}
		}
		// Disconnect from the CTS server
		connector->disconnect();
		connector.reset();

		// Shutdown the system
		return 0;
	}
	virtual tscrypto::tsCryptoString getCommandName() const override
	{
		return "list";
	}
protected:
	void Usage()
	{
		utils->Usage(options, sizeof(options) / sizeof(options[0]));
	}
protected:
	std::shared_ptr<tsmod::IVeilUtilities> utils;
};

tsmod::IObject* HIDDEN CreateGetKeyListTool()
{
	return dynamic_cast<tsmod::IObject*>(new GetKeyListTool());
}

