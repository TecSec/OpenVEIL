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

enum {
	OPT_HELP = 0, OPT_SERVER, OPT_USERNAME, OPT_PASSWORD, 
};

//printf("USAGE: GetMyCTS <username> <ServerUrl>\n");

static const struct OptionList options[] = {
	{ "", "VEIL tool CTS GET options" },
	{ "", "=================================" },
	{ "--help, -h, -?", "This help information." },
	{ "-s, --server=url", "The URL of the VEIL Enterprise Builder that you are a member of." },
	{ "-u, --username=user", "Your user name within that Enterprise Builder." },
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

#ifdef _WIN32
#undef ERROR
#endif

#define ERROR(a) utils->console() << BoldRed << "ERROR:  " << BoldWhite << a << tscrypto::endl

class GetMyCtsTool : public IVeilToolCommand, public tsmod::IObject
{
public:
	GetMyCtsTool()
	{}
	~GetMyCtsTool()
	{}

	// tsmod::IObject
	virtual void OnConstructionFinished()
	{
		utils = ::TopServiceLocator()->get_instance<IVeilUtilities>("VeilUtilities");
	}

	// Inherited via IVeilToolCommand
	virtual tscrypto::tsCryptoString getDescription() const override
	{
		return "Get your lastest CTS token";
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


		// Validate the commandline arguments
		if (username.size() == 0 || url.size() == 0)
		{
			Usage();
			return 10;
		}

		if (password.size() == 0)
		{
			// Get the password from the user
			utils->console().GetPin(password, 64, "Enter the password:");
		}
		if (password.size() == 0)
		{
			printf("Operation cancelled by user request.\n");
			return 0;
		}

		// Connect to the CTS server
		std::shared_ptr<IKeyVEILConnector> connector = ::TopServiceLocator()->get_instance<IKeyVEILConnector>("KeyVEILConnector");

		switch (connector->genericConnectToServer(url, username, password))
		{
		case connStatus_BadAuth:
			ERROR("The authentication information was incorrect.");
			return 1;
		case connStatus_NoServer:
			ERROR("The server was not found at the specified address.");
			return 2;
		case connStatus_UrlBad:
			ERROR("The URL is not properly formed.");
			return 3;
		case connStatus_WrongProtocol:
			ERROR("The specified protocol was not recognized.");
			return 4;
		case connStatus_Connected:
			break;
		}

		baseUri << "/bin/";

		// Request the CTS token for the specified user
		cmd = baseUri;
		cmd << "TokenProfile?username=" << username << "&format=cts";

		start = GetTicks();
		LOG(gHttpLog, "GET " << cmd);
		start = GetTicks();
		if (!connector->sendJsonRequest("GET", cmd, JSONObject(), response, status))
		{
			LOG(gHttpLog, "  Failed to create the CTS profile");
			ERROR("Failed to create the CTS profile");
			connector->disconnect();
			return false;
		}
		LOG(gHttpLog, "  Success - " << ToString()((GetTicks() - start) / 1000.0) << " ms  Status:  " << status);

		if (status >= 400)
		{
			connector->disconnect();
			return false;
		}

		// Retrieve the generated CTS data
		cmd = baseUri;
		cmd << "Results?id=" << response.AsString("id");

		LOG(gHttpLog, "GET " << cmd);
		start = GetTicks();
		if (!connector->sendRequest("GET", cmd, tscrypto::tsCryptoData(), outData, status))
		{
			LOG(gLog, "  Failed to retrieve the CTS profile");
			ERROR("Failed to retrieve the CTS profile");
			connector->disconnect();
			return false;
		}
		LOG(gHttpLog, "  Success - " << ToString()((GetTicks() - start) / 1000.0) << " ms  Status:  " << status);

		if (status >= 400)
		{
			connector->disconnect();
			return false;
		}

		// Save the data to the specified output file
		const HttpAttribute *attr = connector->attributeByName("content-disposition");

		tscrypto::tsCryptoStringList dispos;

		filename = "tmp.cts";

		if (attr != nullptr)
		{
			dispos = attr->m_Value.split(";");

			for (const tscrypto::tsCryptoString& str : *dispos)
			{
				tscrypto::tsCryptoStringList list = str.split("=", 2);

				if (list->size() > 1)
				{
					if (TsStriCmp(list->at(0), "filename") == 0)
					{
						filename = list->at(1);
					}
				}
			}
		}

		tscrypto::tsCryptoString path;

		xp_GetSpecialFolder(sft_UserTokensFolder, path);
		if (path.size() > 0)
		{
			if (xp_GetFileAttributes(path) == XP_INVALID_FILE_ATTRIBUTES)
			{
				xp_CreateDirectory(path, true);
			}
			path << filename;
		}
		else
			path = filename;

		printf("\n");
		if (xp_WriteBytes(path, connector->dataPart()))
		{
			LOGC(gLog, "The CTS file has been created in: " << path);
		}
		else
		{
			LOGC(gLog, "We failed to create the CTS file with the name of " << path);
		}

		LOGC(gLog, "\nThe CTS file has been saved.  You need to register it so that it can be available for use.\n");

		// Disconnect from the CTS server
		connector->disconnect();
		connector.reset();

		// Shutdown the system
		return 0;
	}
	virtual tscrypto::tsCryptoString getCommandName() const override
	{
		return "get";
	}
protected:
	void Usage()
	{
		utils->Usage(options, sizeof(options) / sizeof(options[0]));
	}
protected:
	std::shared_ptr<IVeilUtilities> utils;
};

tsmod::IObject* HIDDEN CreateGetMyCtsTool()
{
	return dynamic_cast<tsmod::IObject*>(new GetMyCtsTool());
}

