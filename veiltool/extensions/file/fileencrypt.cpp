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
	OPT_HELP = 0, OPT_OUTPUT, OPT_OVERWRITE, OPT_URL, OPT_USERNAME, OPT_KVPIN, OPT_SERIAL, OPT_ID, OPT_NAME, OPT_PIN, OPT_CRYPTOGROUP, OPT_NO_COMPRESS, OPT_ATTRIBUTES,
	OPT_FAVORITE, OPT_VERBOSE
};

static const struct OptionList options[] = {
	{ "", "VEIL tool FILE ENCRYPT commands" },
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
	{ "-c, --cryptoGroup=<cryptogroup name>", "The cryptogroup to use for the encryption specified by name or id." },
	{ "-n, --no-compress", "Specify that compression is not to be used before encryption." },
	{ "-a, --attributes=<Attribute list>", "The list of attributes that are required in one encryption group. The attributes are either the Name or ID separated by ','.  Encryption groups are 'OR'd together.  This option may be specified multiple times." },
	{ "--favorite=<favName>", "Use the selected favorite to specify the encryption parameters." },
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
	{ OPT_CRYPTOGROUP, "-c", SO_REQ_SEP },
	{ OPT_CRYPTOGROUP, "--cryptoGroup", SO_REQ_SEP },
	{ OPT_NO_COMPRESS, "-n", SO_NONE },
	{ OPT_NO_COMPRESS, "--no-compress", SO_NONE },
	{ OPT_ATTRIBUTES, "-a", SO_REQ_SEP },
	{ OPT_ATTRIBUTES, "--attributes", SO_REQ_SEP },
	{ OPT_FAVORITE, "--favorite", SO_REQ_SEP },
	{ OPT_VERBOSE, "-v", SO_NONE },
	{ OPT_VERBOSE, "--verbose", SO_NONE },
	SO_END_OF_OPTIONS
};

class FileEncryptTool : public IVeilToolCommand, public tsmod::IObject
{
public:
	FileEncryptTool() : g_doStatus(false)
	{}
	~FileEncryptTool()
	{}

	// tsmod::IObject
	virtual void OnConstructionFinished()
	{
		utils = ::TopServiceLocator()->get_instance<IVeilUtilities>("VeilUtilities");
	}

	// Inherited via IVeilToolCommand
	virtual tscrypto::tsCryptoString getDescription() const override
	{
		return "Perform file encryption operations";
	}
	virtual int RunCommand(CSimpleOptA & opts) override
	{
		std::shared_ptr<IKeyVEILConnector> connector;
		std::shared_ptr<IToken> token;
		std::shared_ptr<IKeyVEILSession> session;
		std::shared_ptr<Asn1::CTS::Profile> profile;
		tscrypto::tsCryptoString enteredPin;
		tscrypto::tsCryptoString pin;
		tscrypto::tsCryptoString cgName;
		bool compress = true;
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
			Asn1::CTS::CryptoGroup* pCG = nullptr;
			//OPT_URL, OPT_KVPIN, OPT_SERIAL, OPT_ID, OPT_NAME
			tscrypto::tsCryptoString url;
			tscrypto::tsCryptoString username;
			tscrypto::tsCryptoString kvPin;
			tscrypto::tsCryptoString serialNumber;
			GUID tokenId = GUID_NULL;
			tscrypto::tsCryptoString tokenName;
			bool bFavProvided = false;
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
					//else if (args.OptionId() == OPT_FAVORITE)
					//{
					//	favorite = args.OptionArg();
					//	bFavProvided = true;
					//}
					else if (opts.OptionId() == OPT_CRYPTOGROUP)
					{
						cgName = opts.OptionArg();
						//					bCGProvided = true;
					}
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
					else if (opts.OptionId() == OPT_NO_COMPRESS)
					{
						compress = false;
					}
					else if (opts.OptionId() == OPT_ATTRIBUTES)
					{
						tscrypto::tsCryptoStringList list = CreateTsAsciiList();

						tscrypto::tsCryptoStringList parts = tscrypto::tsCryptoString(opts.OptionArg()).split(',');

						for (tscrypto::tsCryptoString& str : *parts)
						{
							list->push_back(str.Trim()); 
						}

						pAGList.push_back(list);
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
			{
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

				if (outputFile.size() == 0)
				{
					outputFile = inputFile.c_str();
					outputFile += ".ckm";
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
		return "encrypt";
	}
protected:
	class StatusClass : public IFileVEILOperationStatus, public tsmod::IObject
	{
	public:
		StatusClass(bool doStatus) : _doStatus(doStatus) {}
		// tsmod::IObject
		virtual void OnConstructionFinished()
		{
			utils = ::TopServiceLocator()->get_instance<IVeilUtilities>("VeilUtilities");
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
		std::shared_ptr<IVeilUtilities> utils;
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
	bool attributeNameToGUID(Asn1::CTS::CryptoGroup* pCG, const tscrypto::tsCryptoString& name, GUID &id, bool &isAsym)
	{
		std::shared_ptr<Asn1::CTS::Attribute> attr;

		TSStringToGuid(name, id);

		if (id != GUID_NULL)
		{
			if (!(attr = pCG->get_AttributeById(id)))
				return false;
		}
		else
		{
			if (!(attr = pCG->get_AttributeByName(name)))
				return false;
		}
		id = attr->get_Id();
		isAsym = !attr->get_SymOnly();
		return true;
	}
	bool buildHeader(std::vector<stringList> &pAGList, Asn1::CTS::CryptoGroup* pCG, std::shared_ptr<IKeyVEILSession>& session, std::shared_ptr<ICmsHeader>& pVal)
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
		std::shared_ptr<Asn1::CTS::Profile> profile;
		GUID enterprise;
		GUID cg;
		GUID member;
		GUID id;
		bool hasAsym = false;

		pVal.reset();
		if (!(profile = session->GetProfile()) ||
			!(header = ::TopServiceLocator()->get_instance<ICmsHeader>("/CmsHeader")))
		{
			ERROR("The Cms Header support is missing.");
			return false;
		}

		cg = pCG->get_Id();
		enterprise = profile->get_EnterpriseId();
		member = profile->get_MemberId();

		if (!header->AddProtectedExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_CRYPTOGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), true, ext) ||
			!(cgList = std::dynamic_pointer_cast<ICmsHeaderCryptoGroupListExtension>(ext)) ||
			!ReleasePtr(ext) ||
			!header->AddProtectedExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID), true, ext) ||
			!(attrList = std::dynamic_pointer_cast<ICmsHeaderAttributeListExtension>(ext)) ||
			!ReleasePtr(ext) ||
			!cgList->AddCryptoGroup(cg, &cgNumber) ||
			!cgList->GetCryptoGroup(cgNumber, headCg) ||
			!header->AddProtectedExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), true, ext) ||
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

				if (!attributeNameToGUID(pCG, list->at(attrIndex), id, isAsym))
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
						if (headerAttr->GetAttributeGUID() == id)
							attributeIndex = idx;
					}
				}
				if (attributeIndex == -1)
				{
					headerAttr.reset();
					attributeIndex = attrList->AddAttribute();
					if (attrList->GetAttribute(attributeIndex, headerAttr))
					{
						if (!headerAttr->SetAttributeGuid(id) ||
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
			header->SetSignatureAlgorithmOID(tscrypto::tsCryptoData(ECDSA_SHA512_OID, tscrypto::tsCryptoData::OID));
			header->SetHeaderSigningPublicKey(tmp);
		}
		//	header->SetCompressionType(gFilePrefs->getCompressionType());
		header->SetKeyUsageOID(tscrypto::tsCryptoData(TECSEC_CKM7_KEY_AND_IVEC_OID, tscrypto::tsCryptoData::OID));

		size_t keySize = 0;
		size_t ivSize = 0;

		keySize = CryptoKeySize(header->GetEncryptionAlgorithmID());
		ivSize = CryptoIVECSize(header->GetEncryptionAlgorithmID());
		keySize += ivSize * 8;

		header->SetKeySizeInBits((int)keySize);
		header->SetDataHashOID(tscrypto::tsCryptoData(NIST_SHA512_OID, tscrypto::tsCryptoData::OID));

		pVal = header;
		return true;
	}
	int streamEncryptCkm7(std::shared_ptr<IKeyVEILSession>& pSession,
		const tscrypto::tsCryptoString &inputFile,
		tscrypto::tsCryptoString &outputFile,
		std::vector<stringList> &pAGList,
		Asn1::CTS::CryptoGroup* pCG,
		std::shared_ptr<IKeyVEILConnector>& connector,
		bool compressFlag)
	{
		std::shared_ptr<IFileVEILOperations> fileOps;
		std::shared_ptr<ICmsHeader> header;
		std::shared_ptr<IFileVEILOperationStatus> status;

		if (xp_GetFileAttributes(inputFile) == XP_INVALID_FILE_ATTRIBUTES || xp_IsDirectory(inputFile))
		{
			ERROR("File -> " << inputFile.c_str() << " <- does not exist Encrypt operation aborted");
			return 300;
		}

		status = ::TopServiceLocator()->Finish<IFileVEILOperationStatus>(new StatusClass(g_doStatus));

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

		utils->console() << inputFile.c_str() << "  successfully encrypted to " << outputFile.c_str() << ::endl;
		return 0;
	}
protected:
	std::shared_ptr<IVeilUtilities> utils;
	bool g_doStatus;
};

tsmod::IObject* HIDDEN CreateFileEncryptTool()
{
	return dynamic_cast<tsmod::IObject*>(new FileEncryptTool());
}

