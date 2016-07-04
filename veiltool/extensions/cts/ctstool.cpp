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

#ifndef NO_LOGGING
tsDebugStream gHttpLog("HttpLog", DEBUG_LEVEL_INFORMATION);
tsTraceStream gLog("Log", DEBUG_LEVEL_INFORMATION);
#endif

enum options { OPT_HELP = 1000, };

static tsmod::IObject* CreateCTSTool()
{
	std::shared_ptr<IVeilUtilities> utils = ::TopServiceLocator()->get_instance<IVeilUtilities>("VeilUtilities");
	return utils->buildCommandMenu("Perform file operations", "/CTS-COMMANDS/", "cts", "CTS");
}

extern tsmod::IObject* CreateGetMyCtsTool();

#ifdef _WIN32
	#define EXPORTME __declspec(dllexport)
#else
	#define EXPORTME EXPORT_SYMBOL
#endif

extern "C"
bool EXPORTME Initializects(std::shared_ptr<tsmod::IServiceLocator> servLoc, tsmod::IReportError* log)
{
	UNREFERENCED_PARAMETER(servLoc);
	UNREFERENCED_PARAMETER(log);

	//		extern tsmod::IObject* CreateFileInfoTool();

		::TopServiceLocator()->AddClass("/COMMANDS/CTS", CreateCTSTool);
		::TopServiceLocator()->AddClass("/CTS-COMMANDS/GET", CreateGetMyCtsTool);
	//		::ServiceLocator()->AddClass("/CTS-COMMANDS/INFO", CreateFileInfoTool);
	return true;
}
extern "C"
bool EXPORTME Terminatects(std::shared_ptr<tsmod::IServiceLocator> servLoc)
{
	UNREFERENCED_PARAMETER(servLoc);
		if (::HasServiceLocator())
		{
		::TopServiceLocator()->DeleteClass("/CTS-COMMANDS/GET");
			//		::ServiceLocator()->DeleteClass("/CTS-COMMANDS/INFO");
		::TopServiceLocator()->CleanEmptyCollections();
		::TopServiceLocator()->DeleteClass("/COMMANDS/CTS");
	}
	return true;
}

#if 0

static int usage()
{
	printf("USAGE: GetMyCTS <username> <ServerUrl>\n");

	return 0;
}

int main(int argc, const char *argv[])
{
	int64_t start;
	tscrypto::tsCryptoString username, url, filename, baseUri, cmd;
	tscrypto::tsCryptoData outData;
	JSONObject response;
	int status;
	tscrypto::tsCryptoString password;

	// Start the logging system
	tsLog::DisallowLogs("HttpLog");
	tsLog::SetApplicationJsonPreferences(SimpleJsonDebugPreferences::Create("default", "GetMyCTS", jc_System));

	// Validate the commandline arguments
    if (argc != 3)
    {
		TerminateVEILSystem();
        usage();
		return 10;
    }
	username = argv[1];
	url = argv[2];

	// Get the password from the user
	GetConsolePin(password, 64, "Enter the password:");


	// Connect to the CTS server
	std::shared_ptr<IKeyVEILConnector> connector = ::TopServiceLocator()->get_instance<IKeyVEILConnector>("KeyVEILConnector");

	switch (connector->genericConnectToServer(url, username, password))
	{
	case connStatus_BadAuth:
		LOGC(gLog, "The authentication information was incorrect.");
		return 1;
	case connStatus_NoServer:
		LOGC(gLog, "The server was not found at the specified address.");
		return 2;
	case connStatus_UrlBad:
		LOGC(gLog, "The URL is not properly formed.");
		return 3;
	case connStatus_WrongProtocol:
		LOGC(gLog, "The specified protocol was not recognized.");
		return 4;
	case connStatus_Connected:
		break;
	}

	baseUri << "/ebadmin.tsmod/";


	// Request the CTS token for the specified user
	cmd = baseUri;
	cmd << "TokenProfile?username=" << username << "&format=cts";

	start = GetTicks();
	LOG(gHttpLog, "GET " << cmd);
	start = GetTicks();
	if (!connector->sendJsonRequest("GET", cmd, JSONObject(), response, status))
	{
		LOGC(gHttpLog, "  Failed to create the CTS profile");
		connector->disconnect();
		TerminateVEILSystem();
		return false;
	}
	LOG(gHttpLog, "  Success - " << (GetTicks() - start) / 1000.0 << " ms  Status:  " << status);

	if (status >= 400)
	{
		connector->disconnect();
		TerminateVEILSystem();
		return false;
	}

	// Retrieve the generated CTS data
	cmd = baseUri;
	cmd << "Results?id=" << response.AsString("id");

	LOG(gHttpLog, "GET " << cmd);
	start = GetTicks();
	if (!connector->sendRequest("GET", cmd, tscrypto::tsCryptoData(), outData, status))
	{
		LOGC(gLog, "  Failed to retrieve the CTS profile");
		connector->disconnect();
		TerminateVEILSystem();
		return false;
	}
	LOG(gHttpLog, "  Success - " << (GetTicks() - start) / 1000.0 << " ms  Status:  " << status);

	if (status >= 400)
	{
		connector->disconnect();
		TerminateVEILSystem();
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
	TerminateVEILSystem();
    return 0;
}
#endif // 0
