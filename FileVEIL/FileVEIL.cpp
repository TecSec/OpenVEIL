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
#include <fstream>
#include <iostream>
#include "core/SimpleOpt.h"
#ifdef _WIN32
#    include "io.h"
#endif
#include <sys/types.h>
#include <sys/stat.h>

using namespace std;
bool g_decrypt = false;
bool g_delete = false;
bool g_doStatus = false;
xp_console ts_out;

#ifdef _WIN32
#undef ERROR
#endif
#define ERROR(a) ts_out << BoldRed << "ERROR:  " << BoldWhite << a << ::endl
#define WARN(a) ts_out << BoldGreen << "WARNING:  " << BoldWhite << a << ::endl

#define BLOCKSIZE 4096

typedef tscrypto::tsCryptoStringList stringList;

int streamEncryptCkm7(std::shared_ptr<IKeyVEILSession>& pSession,
	const tscrypto::tsCryptoString &inputFile,
	tscrypto::tsCryptoString &outputFile,
	std::vector<stringList> &pAGList,
	Asn1::CTS::_POD_CryptoGroup* pCG,
	std::shared_ptr<IKeyVEILConnector>& connector,
	bool compressFlag = true);

int streamDecrypt(std::shared_ptr<IKeyVEILSession>& pSession,
	const tscrypto::tsCryptoString &inputFile,
	tscrypto::tsCryptoString &outputFile,
	std::shared_ptr<IKeyVEILConnector>& connector);

//int streamEncryptAudienceFavCkm7(std::shared_ptr<IKeyVEILSession>& pSession,
//	const tscrypto::tsCryptoString &inputFile,
//	tscrypto::tsCryptoString &outputFile,
//	const tscrypto::tsCryptoString &overwriteFlag,
//	ICmsHeader *Audience,
//	bool compressFlag);
int streamDelete(const tscrypto::tsCryptoString &inputFile);

bool ReadFavorite(const tscrypto::tsCryptoString& favName, ICmsHeaderBase **outAudience);


struct tsmod::OptionList options[] = {
	{ "", "FileVEIL options  file1 file2 ... fileN" },
	{ "", "=======================================" },
	{ "-o, --output=<name>", "The name of the output file or path." },
	{ "-w, --overwrite", "Overwrite any existing output files." },
	{ "--url=keyVEILUrl", "The url of the KeyVEIL server to use.  If this is not specified then the default url in the settings will be used.  (See the " VEILCORENAME " program for details.)" },
	{ "-u, --user=<KeyVEIL User Name>", "The user name to use to authenticate to the KeyVEIL server.  If this is not specified then you will be prompted for the username." },
	{ "-k, --keyveil-password=password", "The password to use to authenticate to the KeyVEIL server.  If this is not specified then you will be prompted for the password." },
	{ "--serialnumber=serial", "The serial number of the token to use." },
	{ "--token=id", "The identifier of the token to use." },
	{ "--name=tokenName", "The name of the token to use." },
	{ "-p, --pin=<pinValue>", "The PIN/password to use for the selected token." },
	{ "-c, --cryptoGroup=<cryptogroup name>", "The cryptogroup to use for the encryption specified by name or id." },
	{ "-n, --no-compress", "Specify that compression is not to be used before encryption." },
	{ "-a, --attributes=<Attribute list>", "The list of attributes that are required in one encryption group. The attributes are either the Name or ID separated by ','.  Encryption groups are 'OR'd together.  This option may be specified multiple times." },
	{ "-d, --decrypt", "Decrypt the input file." },
	{ "--favorite=<favName>", "Use the selected favorite to specify the encryption parameters." },
	{ "--delete", "Securely delete the input file." },
	{ "-v, --verbose", "Give more verbose status messages during the processing of the input file." },
};
static void Usage()
{
	for (int i = 0; i < sizeof(options) / sizeof(options[0]); i++)
	{
		if (options[i].option[0] == 0)
		{
			// header
			ts_out << BoldWhite << options[i].description << ::endl;
		}
		else
		{
			ts_out << BoldGreen;
			if (tsStrLen(options[i].option) > 24)
			{
				ts_out << options[i].option << ::endl << "\t\t\t ";
			}
			else
			{
				ts_out << XP_Console::width(-25) << options[i].option;
			}
			ts_out << BoldWhite;
			tscrypto::tsCryptoString description(options[i].description);

			do {
				ts_out << description.substring(0, ts_out.consoleWidth() - 26) << ::endl;
				description.DeleteAt(0, ts_out.consoleWidth() - 26);
				description.TrimStart();
				if (description.size() > 0)
					ts_out << "\t\t\t ";
			} while (description.size() > 0);
		}
	}
}

enum {
	OPT_HELP = 0, OPT_OUTPUT, OPT_OVERWRITE, OPT_URL, OPT_USERNAME, OPT_KVPIN, OPT_SERIAL, OPT_ID, OPT_NAME, OPT_PIN, OPT_CRYPTOGROUP, OPT_NO_COMPRESS, OPT_ATTRIBUTES, OPT_DECRYPT,
	/*OPT_FAVORITE,*/ OPT_DELETE, OPT_VERBOSE
};

CSimpleOptA::SOption g_rgOptions1[] =
{
	{ OPT_HELP, "-?", SO_NONE },
	{ OPT_HELP, "-h", SO_NONE },
	{ OPT_HELP, "--help", SO_NONE },
	{ OPT_OUTPUT, "-o", SO_REQ_CMB },
	{ OPT_OUTPUT, "--output", SO_REQ_CMB },
	{ OPT_OVERWRITE, "-w", SO_NONE },
	{ OPT_OVERWRITE, "--overwrite", SO_NONE },
	{ OPT_URL, "--url", SO_REQ_CMB },
	{ OPT_USERNAME, "-u", SO_REQ_CMB },
	{ OPT_USERNAME, "--user", SO_REQ_CMB },
	{ OPT_KVPIN, "-k", SO_REQ_CMB },
	{ OPT_KVPIN, "--keyveil-password", SO_REQ_CMB },
	{ OPT_SERIAL, "--serialnumber", SO_REQ_CMB },
	{ OPT_ID, "--token", SO_REQ_CMB },
	{ OPT_NAME, "--name", SO_REQ_CMB },
	{ OPT_PIN, "-p", SO_REQ_CMB },
	{ OPT_PIN, "--pin", SO_REQ_CMB },
	{ OPT_CRYPTOGROUP, "-c", SO_REQ_CMB },
	{ OPT_CRYPTOGROUP, "--cryptoGroup", SO_REQ_CMB },
	{ OPT_NO_COMPRESS, "-n", SO_NONE },
	{ OPT_NO_COMPRESS, "--no-compress", SO_NONE },
	{ OPT_ATTRIBUTES, "-a", SO_REQ_CMB },
	{ OPT_ATTRIBUTES, "--attributes", SO_REQ_CMB },
	{ OPT_DECRYPT, "-d", SO_NONE },
	{ OPT_DECRYPT, "--decrypt", SO_NONE },
	//{ OPT_FAVORITE, "--favorite", SO_REQ_CMB },
	{ OPT_DELETE, "--delete", SO_NONE },
	{ OPT_VERBOSE, "-v", SO_NONE },
	{ OPT_VERBOSE, "--verbose", SO_NONE },
	SO_END_OF_OPTIONS
};

bool ReadDefaultSettings(JSONObject& settings)
{
	char path[MAX_PATH];

	tsGetSpecialFolder(tsSft_UserConfigFolder, path, sizeof(path));

    tsStrCat(path, sizeof(path), "default.ovc");

	std::shared_ptr<IDataReader> reader = std::dynamic_pointer_cast<IDataReader>(CreateFileReader(path));

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


static tscrypto::tsCryptoString GetUrl(const tscrypto::tsCryptoString& commandLineUrl, JSONObject& settings)
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

	int len = (int)tsStrLen(buff);
	if (len > 0)
	{
		if (buff[len - 1] == '\n')
			len--;
		buff[len] = 0;
	}
	return buff;
}

static tscrypto::tsCryptoString GetUsername(const tscrypto::tsCryptoString& commandLineUsername, JSONObject& settings)
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

	int len = (int)tsStrLen(buff);
	if (len > 0)
	{
		if (buff[len - 1] == '\n')
			len--;
		buff[len] = 0;
	}
	return buff;
}

static tscrypto::tsCryptoString GetKVPassword(const tscrypto::tsCryptoString& commandLineKVPassword)
{
	tscrypto::tsCryptoString password;

	if (commandLineKVPassword.size() > 0)
		return commandLineKVPassword;
	ts_out.GetPin(password, 64, "Enter the password:  ");
	return password;
}

class StatusClass : public IFileVEILOperationStatus, public tsmod::IObject
{
public:
	StatusClass() {}
	virtual bool Status(const tscrypto::tsCryptoString& taskName, int taskNumber, int ofTaskCount, int taskPercentageDone)
	{
		if (g_doStatus)
		{
			ts_out << "Task " << taskNumber << " of " << ofTaskCount << " " << taskName << " " << taskPercentageDone << "%" << ::endl;
		}
		return true;
	}
	virtual void    FailureReason(const tscrypto::tsCryptoString&failureText)
	{
		ERROR(failureText);
	}

private:
	virtual ~StatusClass() {}
};

int main(int argc, char* argv[])
{
	std::shared_ptr<IKeyVEILConnector> connector;
	std::shared_ptr<IToken> token;
	std::shared_ptr<IKeyVEILSession> session;
	std::shared_ptr<Asn1::CTS::_POD_Profile> profile;
	tscrypto::tsCryptoString enteredPin;
	tscrypto::tsCryptoString pin;
	//	uint32_t fiefLevel = 0;
	tscrypto::tsCryptoString cgName;
	bool compress = true;
//	bool bCGProvided = false;
	int retVal = 0;
	JSONObject settings;

#ifndef NO_LOGGING
    tsLog::SetApplicationJsonPreferences(SimpleJsonDebugPreferences::Create("default", "FileVEIL"));
#endif // NO_LOGGING
	ts_out << Black_Background << White;

	if (!InitializeCmsHeader())
	{
		ERROR("We were unable to initialize the CMS Header system.");
		return 1;
	}
	auto cleanupVeil = finally([]() { TerminateVEILSystem(); });

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
		bool bFavProvided = false;
		tscrypto::tsCryptoString favorite;

		CSimpleOpt args(argc, argv, g_rgOptions1, SO_O_SHORTARG | SO_O_ICASE);

		while (args.Next())
		{
			if (args.LastError() == SO_SUCCESS)
			{
				if (args.OptionId() == OPT_VERBOSE)
				{
					g_doStatus = true;
				}
				else if (args.OptionId() == OPT_DECRYPT)
				{
					g_decrypt = true;
				}
				else if (args.OptionId() == OPT_OUTPUT)
				{
					outputFile = args.OptionArg();
				}
				else if (args.OptionId() == OPT_OVERWRITE)
				{
					overwriteFlag = "y";
				}
				else if (args.OptionId() == OPT_PIN)
				{
					pin = args.OptionArg();
				}
				//else if (args.OptionId() == OPT_FAVORITE)
				//{
				//	favorite = args.OptionArg();
				//	bFavProvided = true;
				//}
				else if (args.OptionId() == OPT_CRYPTOGROUP)
				{
					cgName = args.OptionArg();
//					bCGProvided = true;
				}
				else if (args.OptionId() == OPT_URL)
				{
					url = args.OptionArg();
					if (url.size() == 0)
					{
						ERROR("Invalid serial number specification: " << args.OptionArg());
						return 2;
					}
				}
				else if (args.OptionId() == OPT_USERNAME)
				{
					username = args.OptionArg();
					if (url.size() == 0)
					{
						ERROR("Invalid user name: " << args.OptionArg());
						return 3;
					}
				}
				else if (args.OptionId() == OPT_KVPIN)
				{
					kvPin = args.OptionArg();
					if (kvPin.size() == 0)
					{
						ERROR("Invalid KeyVEIL Password: " << args.OptionArg());
						return 4;
					}
				}
				else if (args.OptionId() == OPT_SERIAL)
				{
					serialNumber = args.OptionArg();
					if (serialNumber.size() == 0)
					{
						ERROR("Invalid serial number Specification: " << args.OptionArg());
						return 5;
					}
				}
				else if (args.OptionId() == OPT_ID)
				{
					tokenId = TSStringToGuid(args.OptionArg());
					if (tokenId == GUID_NULL)
					{
						ERROR("Invalid Token ID: " << args.OptionArg());
						return 6;
					}
				}
				else if (args.OptionId() == OPT_NAME)
				{
					tokenName = args.OptionArg();
					if (tokenName.size() == 0)
					{
						ERROR("Invalid Token Name: " << args.OptionArg());
						return 7;
					}
				}
				else if (args.OptionId() == OPT_NO_COMPRESS)
				{
					compress = false;
				}
				else if (args.OptionId() == OPT_ATTRIBUTES)
				{
					tscrypto::tsCryptoStringList list = CreateTsAsciiList();

					tscrypto::tsCryptoStringList parts = tscrypto::tsCryptoString(args.OptionArg()).split(',');

					for(auto str : *parts)
					{
						list->push_back(str.Trim()); 
					}

					pAGList.push_back(list);
				}
				else if (args.OptionId() == OPT_DELETE)
				{
					g_delete = true;
				}
				else if (args.OptionId() == OPT_HELP)
				{
					Usage();
					return 0;
				}
				else {
					ERROR("Unknown option: " << args.OptionText());
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
		if (!g_delete && !g_decrypt)
		{
			//if (fiefdom.size() == 0)
			//{
			//	ERROR("The fiefdom must be specified for an encryption.");
			//	return 10;
			//}
			if (pAGList.size() == 0)
			{
				ERROR("At least one group of attributes must be specified for an encryption.");
				return 11;
			}
		}
		if (args.FileCount() < 1)
		{
			ERROR("At least one input file must be specified.");
			return 12;
		}
		if (args.FileCount() > 1)
		{
			if (!g_delete && outputFile.size() > 0)
			{
				if (!tsIsDirectory(outputFile.c_str()))
				{
					ERROR("If an output file/path was specified using the '--output' argument and there are more than 1 input files, then the output must be a path. The specified output was not a valid path.");
					return 13;
				}
			}
		}

		if (tsIsDirectory(outputFile.c_str()))
		{
			outputPath = outputFile;
			outputFile.clear();
		}

		if (!g_delete)
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

			if (!profile || !profile->exists_tokenName() || (tokenName = *profile->get_tokenName()).size() == 0)
			{
				tokenName = "Unknown";
			}

			cout << std::endl << "Using token " << tokenName << " issued to " << memberName << std::endl;

			// must be logged into the token
			if (pin.size() == 0)
			{
				ts_out.GetPin(enteredPin, 65, "Please enter PIN: ");
				cout << std::endl;
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
		} // if !delete

		for (int fileIndex = 0; retVal == 0 && fileIndex < args.FileCount(); fileIndex++)
		{
			inputFile = args.File(fileIndex);

			if (inputFile.size() == 0)
			{
				ERROR("Input File must be specified.");
				return 50;
			}


			if (g_delete)
			{
				retVal = streamDelete(inputFile);
				if (retVal == 0)
				{
					cout << inputFile << " deleted successfully." << std::endl;
				}
				else
				{
					ERROR(inputFile << " was NOT deleted.");
				}
			}
			else
			{
				if (!g_decrypt)
				{
					if (!bFavProvided)   //If Favorite not provided, get the cryptogroup
					{
						if (!profile || !profile->exists_cryptoGroupList() || profile->get_cryptoGroupList()->size() == 0)
						{
							ERROR("There are no attributes available on this token.");
							return 51;
						}
						if (profile->get_cryptoGroupList()->size() == 1)
						{
							pCG = &profile->get_cryptoGroupList()->get_at(0);
							if (pCG == nullptr)
							{
								ERROR("Error obtaining the default CryptoGroup ");
								return 52;
							}
						}
						else
						{
							for (size_t i = 0; i < profile->get_cryptoGroupList()->size(); i++)
							{
								pCG = nullptr;
								if ((pCG = &profile->get_cryptoGroupList()->get_at(i)) != nullptr)
								{
									if (pCG->get_Usage() == Asn1::CTS::cgu_User)
									{
										break;
									}
								}
								pCG = nullptr;
							}

							if (pCG == nullptr)
							{
								ERROR("Error obtaining default enterprise crypto group");
								return 53;
							}
						}
					}
				}

				if (outputFile.size() == 0)
				{
					if (g_decrypt)
					{
						tscrypto::tsCryptoString dir, file, ext;

						xp_SplitPath(inputFile, dir, file, ext);
						if (tsStriCmp(ext.c_str(), ".ckm") != 0)
						{
							ERROR("Output File not specified and input file does not have a .ckm extension.");
							return 54;
						}
						outputFile << dir << file;
					}
					else
					{
						outputFile = inputFile.c_str();
						outputFile += ".ckm";
					}
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

				if (g_decrypt)
				{
					retVal = streamDecrypt(session, inputFile, outputFile, connector);
				}
				else
				{
					// CKM 7 fiefdom
					if (!bFavProvided)
					{
						retVal = streamEncryptCkm7(session, inputFile, outputFile, pAGList, pCG, connector, compress);
					}
					else
					{
						//tsCComPtr<ICKMHeaderBase> theAudience;

						//if (ReadFavorite(favorite, &theAudience))
						//{
						//	tsCComPtr<ICKM7CmsHeader> header7;

						//	if (FAILED(theAudience->QueryInterface(IID_ICKM7CmsHeader, (void**)&header7)))
						//	{
						//		ERROR("Error finding the Favorite. Please ensure the correct name used.");
						//		retVal = 56;
						//	}
						//	else if (!!header7)
						//	{
						//		retVal = streamEncryptAudienceFavCkm7(session, inputFile, outputFile, overwriteFlag, header7, compress);
						//	}
						//	else
						//	{
						//		retVal = 57;
						//	}
						//}
						//else
						{
							ERROR("Error finding the Favorite. Please ensure the correct name used.");
							retVal = 58;
						}
					}
				}
			}
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

int streamDecrypt(std::shared_ptr<IKeyVEILSession>& pSession,
	const tscrypto::tsCryptoString &inputFile,
	tscrypto::tsCryptoString &outputFile,
	std::shared_ptr<IKeyVEILConnector>& connector)
{
	std::shared_ptr<IFileVEILOperations> fileOps;
	std::shared_ptr<IFileVEILOperationStatus> status;

	if (tsGetFileAttributes(inputFile.c_str()) == TS_INVALID_FILE_ATTRIBUTES || tsIsDirectory(inputFile.c_str()))
	{
		ERROR("File -> " << inputFile.c_str() << " <- does not exist Decrypt operation aborted");
		return 100;
	}

	status = ::TopServiceLocator()->Finish<IFileVEILOperationStatus>(new StatusClass());

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


bool attributeNameToId(Asn1::CTS::_POD_CryptoGroup* pCG, const tscrypto::tsCryptoString& name, tscrypto::tsCryptoData &id, bool &isAsym)
{
	Asn1::CTS::_POD_Attribute* attr;
    GUID gId;

	TSStringToGuid(name, gId);
    id.assign((const uint8_t*)&gId, sizeof(GUID));

	if (gId != GUID_NULL)
	{
		if (!(attr = pCG->get_AttributeById(id)))
			return false;
	}
	else
	{
		if (!(attr = pCG->get_AttributeByName(name)))
			return false;
	}
	id.assign((const uint8_t*)&attr->get_Id(), sizeof(GUID));
	isAsym = !attr->get_SymOnly();
	return true;
}

template <class T>
static bool ReleasePtr(std::shared_ptr<T> &ptr) { ptr.reset(); return true; }

bool buildHeader(std::vector<stringList> &pAGList, Asn1::CTS::_POD_CryptoGroup* pCG, std::shared_ptr<IKeyVEILSession>& session, std::shared_ptr<ICmsHeader>& pVal)
{
	std::shared_ptr<ICmsHeaderCryptoGroupListExtension> cgList;
	std::shared_ptr<ICmsHeaderAttributeListExtension> attrList;
	int cgNumber = 0;
	std::shared_ptr<ICmsHeaderCryptoGroup> headCg;
	std::shared_ptr<ICmsHeaderExtension> ext;
	std::shared_ptr<ICmsHeaderAccessGroupExtension> andGroupList;
	std::shared_ptr<ICmsHeaderAttribute> headerAttr;
	std::shared_ptr<ICmsHeaderAccessGroup>  andGroup;
	std::shared_ptr<ICmsHeaderAttributeGroup> attrs;
	std::shared_ptr<ICmsHeader>         header;
	std::shared_ptr<Asn1::CTS::_POD_Profile> profile;
	GUID enterprise;
    tscrypto::tsCryptoData cg;
	GUID member;
    tscrypto::tsCryptoData id;
	bool hasAsym = false;

	pVal.reset();
	if (!(profile = session->GetProfile()) ||
		!(header = ::TopServiceLocator()->get_instance<ICmsHeader>("/CmsHeader")))
	{
		ERROR("The Cms Header support is missing.");
		return false;
	}

	cg.assign((const uint8_t*)&pCG->get_Id(), sizeof(GUID));
	enterprise = profile->get_EnterpriseId();
	member = profile->get_MemberId();

	if (!header->AddProtectedExtension(tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_CRYPTOGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), true, ext) ||
		!(cgList = std::dynamic_pointer_cast<ICmsHeaderCryptoGroupListExtension>(ext)) ||
		!ReleasePtr(ext) ||
		!header->AddProtectedExtension(tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID), true, ext) ||
		!(attrList = std::dynamic_pointer_cast<ICmsHeaderAttributeListExtension>(ext)) ||
		!ReleasePtr(ext) ||
		!cgList->AddCryptoGroup(cg, &cgNumber) ||
		!cgList->GetCryptoGroup(cgNumber, headCg) ||
		!header->AddProtectedExtension(tscrypto::tsCryptoData(id_TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), true, ext) ||
		!(andGroupList = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(ext)) ||
		!ReleasePtr(ext))
	{
		return false;
	}

	for (int group = 0; group < (int)pAGList.size(); group++)
	{
		stringList& list = pAGList[group];

		headerAttr.reset();
		attrs.reset();

		if (!andGroupList->AddAccessGroup(ag_Attrs, andGroup) ||
			!(attrs = std::dynamic_pointer_cast<ICmsHeaderAttributeGroup>(andGroup)))
		{
			return false;
		}

		for (int attrIndex = 0; attrIndex < (int)list->size(); attrIndex++)
		{
			int attributeIndex = -1;
			bool isAsym;

			if (!attributeNameToId(pCG, list->at(attrIndex), id, isAsym))
			{
				ERROR("The attribute called " << list->at(attrIndex) << " is invalid.");
				return false;
			}

			hasAsym |= isAsym;

			for (uint32_t idx = 0; attributeIndex < 0 && idx < attrList->GetAttributeCount(); idx++)
			{
				headerAttr.reset();
				if (attrList->GetAttribute(idx, headerAttr))
				{
					if (headerAttr->GetAttributeId() == id)
						attributeIndex = idx;
				}
			}
			if (attributeIndex == -1)
			{
				headerAttr.reset();
				attributeIndex = attrList->AddAttribute();
				if (attrList->GetAttribute(attributeIndex, headerAttr))
				{
					if (!headerAttr->SetAttributeId(id) ||
						!headerAttr->SetCryptoGroupNumber(cgNumber) ||
						!headerAttr->SetKeyVersion(0))
					{
						return false;
					}
				}
			}
			if (!attrs->AddAttributeIndex(attributeIndex))
			{
				return false;
			}
		}
	}

	header->SetCreatorGuid(member);
	header->SetEnterpriseGuid(enterprise);
	//	header->SetEncryptionAlgorithmID(gDesktopPrefs->getEncryptionAlgorithm());
	header->SetEncryptionAlgorithmID(_TS_ALG_ID::TS_ALG_AES_GCM_256);
	header->SetCombinerVersion(7);
	header->SetPaddingType(_SymmetricPaddingType::padding_Pkcs5);
	if (!hasAsym)
	{
		header->SetSignatureAlgorithmId(_TS_ALG_ID::TS_ALG_HMAC_SHA512);
	}
	else
	{
		tscrypto::tsCryptoData tmp;

		tmp.resize(65);
		header->SetSignatureAlgorithmOID(tscrypto::tsCryptoData(id_ECDSA_SHA512_OID, tscrypto::tsCryptoData::OID));
		header->SetHeaderSigningPublicKey(tmp);
	}
	//	header->SetCompressionType(gFilePrefs->getCompressionType());
	header->SetKeyUsageOID(tscrypto::tsCryptoData(id_TECSEC_CKM7_KEY_AND_IVEC_OID, tscrypto::tsCryptoData::OID));

	size_t keySize = 0;
	size_t ivSize = 0;

	keySize = CryptoKeySize(header->GetEncryptionAlgorithmID());
	ivSize = CryptoIVECSize(header->GetEncryptionAlgorithmID());
	keySize += ivSize * 8;

	header->SetKeySizeInBits((int)keySize);
	header->SetDataHashOID(tscrypto::tsCryptoData(id_NIST_SHA512_OID, tscrypto::tsCryptoData::OID));

	pVal = header;
	return true;
}

int streamEncryptCkm7(std::shared_ptr<IKeyVEILSession>& pSession,
	const tscrypto::tsCryptoString &inputFile,
	tscrypto::tsCryptoString &outputFile,
	std::vector<stringList> &pAGList,
	Asn1::CTS::_POD_CryptoGroup* pCG,
	std::shared_ptr<IKeyVEILConnector>& connector,
	bool compressFlag)
{
	std::shared_ptr<IFileVEILOperations> fileOps;
	std::shared_ptr<ICmsHeader> header;
	std::shared_ptr<IFileVEILOperationStatus> status;

	if (tsGetFileAttributes(inputFile.c_str()) == TS_INVALID_FILE_ATTRIBUTES || tsIsDirectory(inputFile.c_str()))
	{
		ERROR("File -> " << inputFile.c_str() << " <- does not exist Encrypt operation aborted");
		return 300;
	}

	status = ::TopServiceLocator()->Finish<IFileVEILOperationStatus>(new StatusClass());

	if (!(fileOps = CreateFileVEILOperationsObject()) ||
		!(fileOps->SetStatusInterface(status)) ||
		!(fileOps->SetSession(pSession)))
	{
		ERROR("An error occurred while building the file encryptor.  The CKM Runtime may be damaged.");
		return 301;
	}

	// Create output file name based on the input file name
	if (outputFile.size() == 0)
	{
		outputFile = inputFile;
		outputFile += ".ckm";
	}

	if (!buildHeader(pAGList, pCG, pSession, header))
	{
		ERROR("An error occurred while building the encryption header.");
		return 302;
	}

	// Indicate compression is desired.
	if (compressFlag)
	{
		//        header->SetCompress(ct_zLib);
		header->SetCompressionType(ct_zLib);
	}
	else
	{
		//        header->SetCompress(ct_None);
		header->SetCompressionType(ct_None);
	}

	if (!(fileOps->EncryptFileAndStreams(inputFile.c_str(), outputFile.c_str(), header, compressFlag ? ct_zLib : ct_None,
		header->GetEncryptionAlgorithmID(), OIDtoID(header->GetDataHashOID().ToOIDString().c_str()),
		header->HasHeaderSigningPublicKey(), true,
		(Alg2Mode(header->GetEncryptionAlgorithmID()) == _SymmetricMode::CKM_SymMode_GCM ||
		Alg2Mode(header->GetEncryptionAlgorithmID()) == _SymmetricMode::CKM_SymMode_CCM) ?
	TS_FORMAT_CMS_ENC_AUTH : TS_FORMAT_CMS_CT_HASHED,
							 false, header->GetPaddingType(), 5000000)))
	{
		if (!connector->isConnected())
		{
			WARN("The connection to the server was lost.");
		}
		return 303;
	}

	cout << inputFile.c_str() << "  successfully encrypted to " << outputFile.c_str() << std::endl;
	return 0;
}

int streamDelete(const tscrypto::tsCryptoString &inputFile)
{
	std::shared_ptr<IFileVEILOperations> fileOps;
	int passCount = 3;

	if (inputFile.length() == 0)
	{
		ERROR("Invalid file name. Cannot delete");
		return 600;
	}

	if (tsGetFileAttributes(inputFile.c_str()) == TS_INVALID_FILE_ATTRIBUTES || tsIsDirectory(inputFile.c_str()))
	{
		ERROR("File -> " << inputFile.c_str() << " <- does not exist delete operation aborted");
		return 601;
	}

	if (!(fileOps = CreateFileVEILOperationsObject()))
	{
		ERROR("We were unable to access the CKM Runtime.  Please make sure that the CKM Desktop product is installed properly.");
		return 602;
	}

	if (!fileOps->secureDelete(inputFile.c_str(), passCount))
	{
		ERROR("Failed to delete -> " << inputFile.c_str() << " <- delete operation aborted ");
		return 603;
	}
	else
	{
		cout << inputFile.c_str() << " successfully deleted" << std::endl;
		return 0;
	}
}
