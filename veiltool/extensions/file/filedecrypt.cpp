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

#ifdef _WIN32
#undef ERROR
#endif

#define ERROR(a) utils->console() << BoldRed << "ERROR:  " << BoldWhite << a << ::endl
#define WARN(a) utils->console() << BoldGreen << "WARNING:  " << BoldWhite << a << ::endl
#define BLOCKSIZE 4096

template <class T>
static bool ReleasePtr(std::shared_ptr<T> &ptr) { ptr.reset(); return true; }

typedef tscrypto::tsCryptoStringList stringList;

enum {
	OPT_HELP = 0, OPT_OUTPUT, OPT_OVERWRITE, OPT_URL, OPT_USERNAME, OPT_KVPIN, OPT_SERIAL, OPT_ID, OPT_NAME, OPT_PIN, OPT_VERBOSE
};

static const struct tsmod::OptionList options[] = {
	{ "", "VEIL tool FILE DECRYPT commands" },
	{ "", "=================================" },
	{ "--help, -h, -?", "This help information." },
	{ "-o, --output=<name>", "The name of the output file or path." },
	{ "-w, --overwrite", "Overwrite any existing output files." },
	{ "--url=keyVEILUrl", "The url of the KeyVEIL server to use.  If this is not specified then the default url in the settings will be used.  (See the " VEILCORENAME " program for details.)" },
	{ "-u, --user=<KeyVEIL User Name>", "The user name to use to authenticate to the KeyVEIL server.  If this is not specified then you will be prompted for the username." },
	{ "-k, --keyveil-password=password", "The password to use to authenticate to the KeyVEIL server.  If this is not specified then you will be prompted for the password." },
	{ "--serialnumber=serial", "The serial number of the token to use." },
	{ "--token=id", "The identifier of the token to use." },
	{ "--name=tokenName", "The name of the token to use." },
	{ "-p, --pin=<pinValue>", "The PIN/password to use for the selected token." },
	{ "-v, --verbose", "Give more verbose status messages during the processing of the input file." },
	{ "", "" },
};
static const CSimpleOptA::SOption g_rgOptions1[] =
{
	{ OPT_HELP, "-?", SO_NONE },
	{ OPT_HELP, "-h", SO_NONE },
	{ OPT_HELP, "--help", SO_NONE },
	{ OPT_OUTPUT, "-o", SO_REQ_SEP },
	{ OPT_OUTPUT, "--output", SO_REQ_SEP },
	{ OPT_OVERWRITE, "-w", SO_NONE },
	{ OPT_OVERWRITE, "--overwrite", SO_NONE },
	{ OPT_URL, "--url", SO_REQ_SEP },
	{ OPT_USERNAME, "-u", SO_REQ_SEP },
	{ OPT_USERNAME, "--user", SO_REQ_SEP },
	{ OPT_KVPIN, "-k", SO_REQ_SEP },
	{ OPT_KVPIN, "--keyveil-password", SO_REQ_SEP },
	{ OPT_SERIAL, "--serialnumber", SO_REQ_SEP },
	{ OPT_ID, "--token", SO_REQ_SEP },
	{ OPT_NAME, "--name", SO_REQ_SEP },
	{ OPT_PIN, "-p", SO_REQ_SEP },
	{ OPT_PIN, "--pin", SO_REQ_SEP },
	{ OPT_VERBOSE, "-v", SO_NONE },
	{ OPT_VERBOSE, "--verbose", SO_NONE },
	SO_END_OF_OPTIONS
};

class FileDecryptTool : public tsmod::IVeilToolCommand, public tsmod::IObject
{
public:
	FileDecryptTool() : g_doStatus(false)
	{}
	~FileDecryptTool()
	{}

	// tsmod::IObject
	virtual void OnConstructionFinished() override
	{
		utils = ::TopServiceLocator()->get_instance<tsmod::IVeilUtilities>("VeilUtilities");
	}

	// Inherited via tsmod::IVeilToolCommand
	virtual tscrypto::tsCryptoString getDescription() const override
	{
		return "Perform file decryption operations";
	}
	virtual int RunCommand(CSimpleOptA & opts) override
	{
		std::shared_ptr<IKeyVEILConnector> connector;
		std::shared_ptr<IToken> token;
		std::shared_ptr<IKeyVEILSession> session;
		std::shared_ptr<Asn1::CTS::_POD_Profile> profile;
		tscrypto::tsCryptoString enteredPin;
		tscrypto::tsCryptoString pin;
		int retVal = 0;
		JSONObject settings;

		if (!InitializeCmsHeader())
		{
			ERROR("We were unable to initialize the CMS Header system.");
			return 1;
		}

		if (!ReadDefaultSettings(settings))
		{
			settings.clear();
		}

		try
		{
			tscrypto::tsCryptoString inputFile;
			tscrypto::tsCryptoString outputFile;
			tscrypto::tsCryptoString outputPath;
			tscrypto::tsCryptoString overwriteFlag;
			stringList attrNames;
			std::vector<stringList> pAGList;
			Asn1::CTS::_POD_CryptoGroup* pCG = nullptr;
			//OPT_URL, OPT_KVPIN, OPT_SERIAL, OPT_ID, OPT_NAME
			tscrypto::tsCryptoString url;
			tscrypto::tsCryptoString username;
			tscrypto::tsCryptoString kvPin;
			tscrypto::tsCryptoString serialNumber;
			GUID tokenId = GUID_NULL;
			tscrypto::tsCryptoString tokenName;
			//bool bFavProvided = false;
			tscrypto::tsCryptoString favorite;

			opts.Init(opts.FileCount(), opts.Files(), g_rgOptions1, SO_O_NOERR | SO_O_USEALL | SO_O_ICASE);

			while (opts.Next())
			{
				if (opts.LastError() == SO_SUCCESS)
				{
					if (opts.OptionId() == OPT_VERBOSE)
					{
						g_doStatus = true;
					}
					else if (opts.OptionId() == OPT_OUTPUT)
					{
						outputFile = opts.OptionArg();
					}
					else if (opts.OptionId() == OPT_OVERWRITE)
					{
						overwriteFlag = "y";
					}
					else if (opts.OptionId() == OPT_PIN)
					{
						pin = opts.OptionArg();
					}
					//else if (opts.OptionId() == OPT_FAVORITE)
					//{
					//	favorite = opts.OptionArg();
					//	bFavProvided = true;
					//}
					else if (opts.OptionId() == OPT_URL)
					{
						url = opts.OptionArg();
						if (url.size() == 0)
						{
							ERROR("Invalid serial number specification: " << opts.OptionArg());
							return 2;
						}
					}
					else if (opts.OptionId() == OPT_USERNAME)
					{
						username = opts.OptionArg();
						if (url.size() == 0)
						{
							ERROR("Invalid user name: " << opts.OptionArg());
							return 3;
						}
					}
					else if (opts.OptionId() == OPT_KVPIN)
					{
						kvPin = opts.OptionArg();
						if (kvPin.size() == 0)
						{
							ERROR("Invalid KeyVEIL Password: " << opts.OptionArg());
							return 4;
						}
					}
					else if (opts.OptionId() == OPT_SERIAL)
					{
						serialNumber = opts.OptionArg();
						if (serialNumber.size() == 0)
						{
							ERROR("Invalid serial number Specification: " << opts.OptionArg());
							return 5;
						}
					}
					else if (opts.OptionId() == OPT_ID)
					{
						tokenId = TSStringToGuid(opts.OptionArg());
						if (tokenId == GUID_NULL)
						{
							ERROR("Invalid Token ID: " << opts.OptionArg());
							return 6;
						}
					}
					else if (opts.OptionId() == OPT_NAME)
					{
						tokenName = opts.OptionArg();
						if (tokenName.size() == 0)
						{
							ERROR("Invalid Token Name: " << opts.OptionArg());
							return 7;
						}
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

			auto cleanupConnector = finally([&connector, &token, &session, &profile]() {
				profile.reset();
				if (!!session)
					session->Close();
				session.reset();
				token.reset();
				if (!!connector)
					connector->disconnect();
				connector.reset();
			});

			if (opts.FileCount() < 1)
			{
				ERROR("At least one input file must be specified.");
				return 12;
			}
			if (opts.FileCount() > 1)
			{
				if (outputFile.size() > 0)
				{
					if (!xp_IsDirectory(outputFile))
					{
						ERROR("If an output file/path was specified using the '--output' argument and there are more than 1 input files, then the output must be a path. The specified output was not a valid path.");
						return 13;
					}
				}
			}

			if (xp_IsDirectory(outputFile))
			{
				outputPath = outputFile;
				outputFile.clear();
			}
			{
				if (!(connector = GetConnector()))
				{
					ERROR("An error occurred while attempting to retrieve the KeyVEIL connector");
					return 14;
				}

				if (connector->connect(GetUrl(url, settings), GetUsername(username, settings), GetKVPassword(kvPin)) != connStatus_Connected)
				{
					ERROR("We were unable to connect to KeyVEIL.");
					return 15;
				}

				if (tokenId != GUID_NULL)
				{
					if (!(token = connector->token(tokenId)))
					{
						ERROR("The specified token ID is invalid.");
						return 16;
					}
				}
				else if (serialNumber.HexToData().size() != 0)
				{
					if (!(token = connector->token(serialNumber.HexToData())))
					{
						ERROR("The specified token serial number is invalid.");
						return 17;
					}
				}
				else if (tokenName.size() != 0)
				{
					if (!(token = connector->token(tokenName)))
					{
						ERROR("The specified token name is not unique or is invalid.");
						return 18;
					}
				}
				else
				{
					ERROR("You must specify one of the following:  Token ID, Serial Number or Token Name.");
					return 19;
				}

				if (!(session = token->openSession()))
				{
					ERROR("An error occurred while attempting to use the selected token.");
					return 20;
				}
				tscrypto::tsCryptoString memberName;
				tscrypto::tsCryptoString tokenName;

				if (!(profile = session->GetProfile()) || (memberName = profile->get_MemberName()).size() == 0)
				{
					memberName = "Unknown";
				}

				if (!profile || (tokenName = profile->get_tokenName()).size() == 0)
				{
					tokenName = "Unknown";
				}

				utils->console() << ::endl << "Using token " << tokenName << " issued to " << memberName << ::endl;

				// must be logged into the token
				if (pin.size() == 0)
				{
					utils->console().GetPin(enteredPin, 65, "Please enter PIN: ");
					utils->console() << ::endl;
					pin = enteredPin;
				}
				switch (session->Login(pin))
				{
				case LoginStatus::loginStatus_BadAuth:
					ERROR("Error logging into the token:");
					return 40;
				case LoginStatus::loginStatus_Connected:
					break;
				case LoginStatus::loginStatus_NoServer:
				default:
					ERROR("Error logging into the token because the connection to the server was lost:");
					return 41;
				}
				profile.reset();
				if (!(profile = session->GetProfile()))
				{
					ERROR("An error occurred while retrieving the updated profile information.");
					return 42;
				}
			}
			for (int fileIndex = 0; retVal == 0 && fileIndex < opts.FileCount(); fileIndex++)
			{
				inputFile = opts.File(fileIndex);

				if (inputFile.size() == 0)
				{
					ERROR("Input File must be specified.");
					return 50;
				}

				if (outputFile.size() == 0)
				{
					tscrypto::tsCryptoString dir, file, ext;

					xp_SplitPath(inputFile, dir, file, ext);
					if (TsStriCmp(ext, ".ckm") != 0)
					{
						ERROR("Output File not specified and input file does not have a .ckm extension.");
						return 54;
					}
					outputFile << dir << file;
				}

				// Put on the output path
				if (outputPath.size() > 0)
				{
					tscrypto::tsCryptoString dir, file, ext;

					xp_SplitPath(outputFile, dir, file, ext);
					outputFile.clear();
					outputFile << outputPath;
					if (outputFile[outputFile.size() - 1] != XP_PATH_SEP_CHAR)
						outputFile << XP_PATH_SEP_STR;
					outputFile << file << ext;
				}

				retVal = streamDecrypt(session, inputFile, outputFile, connector);

			} // for each file
			pCG = nullptr;
			if (!!session)
				session->Close();
			session.reset();
		}
		catch (...)
		{
			ERROR("An exception occured.  The operation did not complete properly.");
			retVal = 5000;
		}

		return retVal;
	}
	virtual tscrypto::tsCryptoString getCommandName() const override
	{
		return "decrypt";
	}
protected:
	class StatusClass : public IFileVEILOperationStatus, public tsmod::IObject
	{
	public:
		StatusClass(bool doStatus) : _doStatus(doStatus) {}
		// tsmod::IObject
		virtual void OnConstructionFinished()
		{
			utils = ::TopServiceLocator()->get_instance<tsmod::IVeilUtilities>("VeilUtilities");
		}

		virtual bool Status(const tscrypto::tsCryptoString& taskName, int taskNumber, int ofTaskCount, int taskPercentageDone)
		{
			if (_doStatus)
			{
				utils->console() << "Task " << taskNumber << " of " << ofTaskCount << " " << taskName << " " << taskPercentageDone << "%" << ::endl;
			}
			return true;
		}
		virtual void    FailureReason(const tscrypto::tsCryptoString&failureText)
		{
			ERROR(failureText);
		}

	private:
		virtual ~StatusClass() {}
	protected:
		std::shared_ptr<tsmod::IVeilUtilities> utils;
		bool _doStatus;
	};


	void Usage()
	{
		utils->Usage(options, sizeof(options) / sizeof(options[0]));
	}
	bool ReadDefaultSettings(JSONObject& settings)
	{
		tscrypto::tsCryptoString path;

		xp_GetSpecialFolder(sft_UserConfigFolder, path);

		std::shared_ptr<IDataReader> reader = std::dynamic_pointer_cast<IDataReader>(CreateFileReader(path + "default.ovc"));

		if (reader->DataLength() > 0)
		{
			tscrypto::tsCryptoData data;

			if (reader->ReadData((int)reader->DataLength(), data))
				settings.FromJSON(data.ToUtf8String().c_str());
		}
		reader->Close();
		reader.reset();
		return true;
	}

	std::shared_ptr<IKeyVEILConnector> GetConnector()
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

		return connector;
	}


	tscrypto::tsCryptoString GetUrl(const tscrypto::tsCryptoString& commandLineUrl, JSONObject& settings)
	{
		char buff[1024] = "";

		if (commandLineUrl.size() > 0)
			return commandLineUrl;
		if (settings.hasField("KeyVEILUrl"))
		{
			return settings.AsString("KeyVEILUrl");
		}
		printf("Enter the KeyVEIL URL to use or leave it blank to cancel this operation.\n");
		fflush(stdin);
		fgets(buff, sizeof(buff), stdin);

		int len = (int)strlen(buff);
		if (len > 0)
		{
			if (buff[len - 1] == '\n')
				len--;
			buff[len] = 0;
		}
		return buff;
	}

	tscrypto::tsCryptoString GetUsername(const tscrypto::tsCryptoString& commandLineUsername, JSONObject& settings)
	{
		char buff[1024] = "";

		if (commandLineUsername.size() > 0)
			return commandLineUsername;
		if (settings.hasField("KeyVEILUsername"))
		{
			return settings.AsString("KeyVEILUsername");
		}
		printf("Enter the KeyVEIL User Name to use or leave it blank to cancel this operation.\n");
		fflush(stdin);
		fgets(buff, sizeof(buff), stdin);

		int len = (int)strlen(buff);
		if (len > 0)
		{
			if (buff[len - 1] == '\n')
				len--;
			buff[len] = 0;
		}
		return buff;
	}

	tscrypto::tsCryptoString GetKVPassword(const tscrypto::tsCryptoString& commandLineKVPassword)
	{
		tscrypto::tsCryptoString password;

		if (commandLineKVPassword.size() > 0)
			return commandLineKVPassword;
		utils->console().GetPin(password, 64, "Enter the password:  ");
		return password;
	}
	int streamDecrypt(std::shared_ptr<IKeyVEILSession>& pSession,
		const tscrypto::tsCryptoString &inputFile,
		tscrypto::tsCryptoString &outputFile,
		std::shared_ptr<IKeyVEILConnector>& connector)
	{
		std::shared_ptr<IFileVEILOperations> fileOps;
		std::shared_ptr<IFileVEILOperationStatus> status;

		if (xp_GetFileAttributes(inputFile) == XP_INVALID_FILE_ATTRIBUTES || xp_IsDirectory(inputFile))
		{
			ERROR("File -> " << inputFile.c_str() << " <- does not exist Decrypt operation aborted");
			return 100;
		}

		status = ::TopServiceLocator()->Finish<IFileVEILOperationStatus>(new StatusClass(g_doStatus));

		if (!(fileOps = CreateFileVEILOperationsObject()) ||
			!(fileOps->SetStatusInterface(status)) ||
			!(fileOps->SetSession(pSession)))
		{
			ERROR("An error occurred while building the file decryptor.  The " VEILCORENAME " may be damaged.");
			return 101;
		}

		if (!fileOps->DecryptFileAndStreams(inputFile, outputFile))
		{
			if (!connector->isConnected())
			{
				WARN("The connection to the server was lost.");
			}
			else
				ERROR("An error occurred while decrypting the file.");
			return 102;
		}

		cout << inputFile.c_str() << "  successfully decrypted to " << outputFile.c_str() << std::endl;
		return 0;
	}
protected:
	std::shared_ptr<tsmod::IVeilUtilities> utils;
	bool g_doStatus;
};

tsmod::IObject* HIDDEN CreateFileDecryptTool()
{
	return dynamic_cast<tsmod::IObject*>(new FileDecryptTool());
}

