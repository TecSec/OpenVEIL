//	Copyright (c) 2017, TecSec, Inc.
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

class pair
{
public:
	tscrypto::tsCryptoString type;
	tscrypto::tsCryptoString filename;
};

enum options { OPT_HELP, OPT_LIST, OPT_SET, OPT_POLICY, OPT_SYSTEM, OPT_USER, OPT_PUBLIC, OPT_CONFIGNAME, OPT_SECTION, };

static const struct tsmod::OptionList options[] = {
	{ "", "VEIL tool settings options" },
	{ "", "=================================" },
	{ "--help, -h, -?", "This help information." },
	{ "LIST", "List the specified settings without aggregation." },
	{ "SET", "Set one or more settings of the form setting=value.  If a hierarchy is needed use the '.' character to separate the path parts." },

	{ "POLICY", "policy level settings" },
	{ "SYSTEM", "system level settings" },
	{ "USER", "user level settings" },
	{ "PUBLIC", "public level settings" },

	{ "-c, --config=<configName>", "Use the specified configuration name (default:  DEFAULT)" },
	{ "-s, --section=<name>", "Display or set settings for the specified section.  If not specifed then the different sections will be listed.  SET requires that the setting name be specified or the path form must be used." },
	{ "", "" },
	{ "", "Common sections and settings (global user level settings)" },
	{ "", "=========================================================" },
	{ "KeyVEILUrl", "The default url used to access KeyVEIL" },
	{ "KeyVEILUsername", "The username to use when accessing KeyVEIL" },
	{ "AIDList", "The Application IDs for the smart card SILOS that are valid for the utilities run from this computer." },
	{ "", "" },
	{ "", "Common sections and settings (path form)" },
	{ "", "========================================" },
	{ "Desktop:EncryptionAlgorithm", "The id of the default encryption algorithm" },
	{ "Desktop:HashAlgorithm", "The id of the default digest algorithm" },
	{ "", "" },
};

static const CSimpleOptA::SOption optionList[] =
{
	{ OPT_HELP,               "-?",                   SO_NONE },
	{ OPT_HELP,               "-h",                   SO_NONE },
	{ OPT_HELP,               "--help",               SO_NONE },
	{ OPT_LIST,               "list",                 SO_NONE },
	{ OPT_SET,                "set",                  SO_NONE },
	{ OPT_POLICY,             "policy",               SO_NONE },
	{ OPT_SYSTEM,             "system",               SO_NONE },
	{ OPT_USER,               "user",                 SO_NONE },
	{ OPT_PUBLIC,             "public",               SO_NONE },
	{ OPT_CONFIGNAME,         "--config",             SO_REQ_SEP},
	{ OPT_CONFIGNAME,         "-c",                   SO_REQ_SEP },
	{ OPT_SECTION,            "--section",            SO_REQ_SEP },
	{ OPT_SECTION,            "-s",                   SO_REQ_SEP },

	SO_END_OF_OPTIONS
};

class SettingsTool : public tsmod::IVeilToolCommand, public tsmod::IObject
{
public:
	SettingsTool()
	{}
	~SettingsTool()
	{}

	// tsmod::IObject
	virtual void OnConstructionFinished() override
	{
		utils = ::TopServiceLocator()->get_instance<tsmod::IVeilUtilities>("VeilUtilities");
	}

	// Inherited via tsmod::IVeilToolCommand
	virtual tscrypto::tsCryptoString getDescription() const override
	{
		return "Display and set system properties";
	}
	virtual int RunCommand(CSimpleOptA & opts) override
	{
		int retVal = 1;
		tscrypto::tsCryptoString command = "LIST";
		tscrypto::tsCryptoString level = "ALL";
		tscrypto::tsCryptoString config = "default";
		tscrypto::tsCryptoString section;

		opts.Init(opts.FileCount(), opts.Files(), optionList, SO_O_NOERR | SO_O_USEALL | SO_O_ICASE);
		while (opts.Next())
		{
			if (opts.LastError() == SO_SUCCESS)
			{
				if (opts.OptionId() == OPT_HELP)
				{
					Usage();
					return 0;
				}
				else if (opts.OptionId() == OPT_LIST)
				{
					command = "LIST";
				}
				else if (opts.OptionId() == OPT_SET)
				{
					command = "SET";
				}
				else if (opts.OptionId() == OPT_POLICY)
				{
					level = "POLICY";
				}
				else if (opts.OptionId() == OPT_SYSTEM)
				{
					level = "SYSTEM";
				}
				else if (opts.OptionId() == OPT_USER)
				{
					level = "USER";
				}
				else if (opts.OptionId() == OPT_PUBLIC)
				{
					level = "PUBLIC";
				}
				else if (opts.OptionId() == OPT_CONFIGNAME)
				{
					config = opts.OptionArg();
				}
				else if (opts.OptionId() == OPT_SECTION)
				{
					section = opts.OptionArg();
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

		if (command == "SET")
		{
			if (level == "POLICY")
			{
				utils->console() << BoldRed << "ERROR:  " << BoldWhite << "SET may not be used to set values in POLICY." << ::endl;
				return 1;
			}
			if (level == "ALL")
			{
				level = "USER";
			}
			if (opts.FileCount() == 0)
				return 0;

			JSONObject obj;
			tscrypto::tsCryptoString prefix;
			
			if (!LoadSettings(level, config, "", obj))
			{
				utils->console() << BoldRed << "ERROR:  " << BoldWhite << "Unable to load the settings file." << ::endl;
				return 1;
			}
			prefix << "$.";
			if (section.size() > 0)
				prefix << section << ".";

			for (int i = 0; i < opts.FileCount(); i++)
			{
				tscrypto::tsCryptoString path;
				tscrypto::tsCryptoStringList pair = tscrypto::tsCryptoString(opts.File(i)).split("=", 2);
				path << prefix << pair->at(0);

				if (!SetSettingValue(obj, path, pair->size() > 1 ? pair->at(1) : ""))
				{
					utils->console() << BoldRed << "ERROR:  " << BoldWhite << "The setting " << pair->at(0) << " could not be set." << ::endl;
					return 1;
				}
			}
			if (!SaveSettings(level, config, obj))
			{
				utils->console() << BoldRed << "ERROR:  " << BoldWhite << "Unable to save the new settings file." << ::endl;
				return 1;
			}
		}
		else if (command == "LIST")
		{
			if (level == "ALL")
			{
				DisplaySettings("POLICY", config, section, opts.FileCount(), opts.Files());
				DisplaySettings("SYSTEM", config, section, opts.FileCount(), opts.Files());
				DisplaySettings("USER", config, section, opts.FileCount(), opts.Files());
				DisplaySettings("PUBLIC", config, section, opts.FileCount(), opts.Files());
			}
			else
			{
				DisplaySettings(level, config, section, opts.FileCount(), opts.Files());
			}
		}

		return retVal;
	}
	virtual tscrypto::tsCryptoString getCommandName() const override
	{
		return "settings";
	}
protected:
	void Usage()
	{
		utils->Usage(options, sizeof(options) / sizeof(options[0]));
	}
	void OutputError(char *msg, ...)
	{
		tscrypto::tsCryptoString results;
		va_list args;

		va_start(args, msg);
		results.FormatArg(msg, args);
		va_end(args);
		results << tscrypto::endl;
		utils->console() << BoldRed << results << BoldWhite << ::endl;
	}
	bool IsNumber(const tscrypto::tsCryptoString& value)
	{
		if (value.size() == 0)
			return false;

		for (size_t i = 0; i < value.size(); i++)
		{
			if (value[i] < '0' || value[i] > '9')
				return false;
		}
		return true;
	}
	bool SetSettingValue(JSONObject& obj, const tscrypto::tsCryptoString& path, const tscrypto::tsCryptoString& value)
	{
		JSONElement* ele = obj.findSingleItem(path, true);

		if (ele == nullptr)
			return false;

		if (ele->ElementType() == JsonElementType::jet_Object)
		{
			return false;
		}
		if (value.size() == 0)
		{
			(dynamic_cast<JSONField*>(ele))->Value(nullptr);
		}
		else if (TsStriCmp(value.c_str(), "true") == 0)
		{
			(dynamic_cast<JSONField*>(ele))->Value(true);
		}
		else if (TsStriCmp(value.c_str(), "false") == 0)
		{
			(dynamic_cast<JSONField*>(ele))->Value(false);
		}
		else if (IsNumber(value))
		{
			(dynamic_cast<JSONField*>(ele))->Value(TsStrToInt64(value.c_str()));
		}
		else
		{
			(dynamic_cast<JSONField*>(ele))->Value(value);
		}
		return true;
	}
	bool LoadSettings(const tscrypto::tsCryptoString &level, const tscrypto::tsCryptoString& config, const tscrypto::tsCryptoString& section, JSONObject &obj)
	{
		JsonConfigLocation loc = jc_User;
		tscrypto::tsCryptoString path;
		tscrypto::tsCryptoString json;
		JSONObject tmp;

		if (level == "POLICY")
			loc = jc_Policy;
		else if (level == "SYSTEM")
			loc = jc_System;
		else if (level == "USER")
			loc = jc_User;
		else if (level == "PUBLIC")
			loc = jc_Public;

		obj.clear();
		if (!tsJsonPreferencesBase::buildAndTestPath(loc, config, path))
			return true;

		if (xp_GetFileSize(path) > 1000000)
			return false;

		if (!xp_ReadAllText(path, json))
		{
			return false;
		}
		if (!tmp.FromJSON(json.c_str()))
		{
			return false;
		}
		if (section.size() > 0)
		{
			if (!tmp.hasField(section) || tmp.field(section).Type() != JSONField::jsonObject)
				return false;
			obj = tmp.AsObject(section);
			return true;
		}
		obj = tmp;
		return true;
	}
	bool SaveSettings(const tscrypto::tsCryptoString &level, const tscrypto::tsCryptoString& config, const JSONObject& obj)
	{
		JsonConfigLocation loc = jc_User;
		tscrypto::tsCryptoString path;
		tscrypto::tsCryptoString json;

		if (level == "POLICY")
			loc = jc_Policy;
		else if (level == "SYSTEM")
			loc = jc_System;
		else if (level == "USER")
			loc = jc_User;
		else if (level == "PUBLIC")
			loc = jc_Public;

		if (!tsJsonPreferencesBase::buildAndTestPath(loc, config, path) && path.size() == 0)
			return false;

		json = obj.ToJSON();

		if (!xp_WriteText(path, json))
			return false;
		return true;
	}
	void DumpArrayObject(const JSONFieldList& ary, const tscrypto::tsCryptoString& prefix, bool& foundOne)
	{
		for (size_t index = 0; index < ary->size(); index++)
		{
			tscrypto::tsCryptoString arrayName;
			const JSONField& af = ary->at(index);

			arrayName << prefix << "[" << index << "]";
			switch (af.Type())
			{
			case JSONField::jsonArray:
				DumpArrayObject(af.AsArray(), arrayName, foundOne);
				break;
			case JSONField::jsonObject:
				DumpObject(af.AsObject(), arrayName, foundOne);
				break;
			case JSONField::jsonNull:
				utils->DumpOptionLine(arrayName, "<null>");
				break;
			default:
				utils->DumpOptionLine(arrayName, af.AsString());
				break;
			}
		}
	}
	void DumpObject(const JSONObject& obj, const tscrypto::tsCryptoString& prefix, bool& foundOne)
	{
		obj.foreach([this, &foundOne, &prefix](const JSONField &fld) {
			foundOne = true;
			tscrypto::tsCryptoString name;

			if (prefix.size() > 0)
				name << prefix << ".";
			name << fld.Name();

			switch (fld.Type())
			{
			case JSONField::jsonArray:
				DumpArrayObject(fld.AsArray(), name, foundOne);
				break;
			case JSONField::jsonObject:
				DumpObject(fld.AsObject(), name, foundOne);
				break;
			case JSONField::jsonNull:
				utils->DumpOptionLine(name, "<null>");
				break;
			default:
				utils->DumpOptionLine(name, fld.AsString());
				break;
			}
		});

	}
	void DisplaySettings(const tscrypto::tsCryptoString &level, const tscrypto::tsCryptoString& config, const tscrypto::tsCryptoString& section, int argc, char** argv)
	{
		tscrypto::tsCryptoString prefix;
		JSONObject obj;
		bool foundOne = false;

		if (!LoadSettings(level, config, section, obj))
		{
			return;
		}
		if (section.size() > 0)
			prefix << section;

		if (argc > 0)
		{
			utils->console() << ::endl;
			utils->console() << BoldWhite << "Displaying selected settings in " << level << "  " << section << ::endl;
			utils->console() << "=============================================================" << ::endl;
			for (int i = 0; i < argc; i++)
			{
				tscrypto::tsCryptoString path = argv[i];

				path.prepend("@.");
				const JSONElement* ele = obj.findSingleItem(path);
				if (ele != nullptr)
				{
					switch (ele->ElementType())
					{
					case JsonElementType::jet_Field:
					{
						const JSONField &fld = *dynamic_cast<const JSONField*>(ele);
						switch (fld.Type())
						{
						case JSONField::jsonArray:
							DumpArrayObject(fld.AsArray(), argv[i], foundOne);
							break;
						case JSONField::jsonObject:
							DumpObject(fld.AsObject(), argv[i], foundOne);
							break;
						case JSONField::jsonNull:
							utils->DumpOptionLine(argv[i], "<null>");
							break;
						default:
							utils->DumpOptionLine(argv[i], fld.AsString());
							break;
						}
						break;
					}
					case JsonElementType::jet_Object:
						DumpObject(*dynamic_cast<const JSONObject*>(ele), argv[i], foundOne);
						break;
                    default:
                        break;
					}
				}

			}
		}
		else
		{
			utils->console() << ::endl;
			utils->console() << BoldWhite << "Displaying settings in " << level << "  " << section << ::endl;
			utils->console() << "=============================================================" << ::endl;

			DumpObject(obj, prefix, foundOne);
		}
		if (!foundOne)
		{
			utils->DumpOptionLine(" ", "No entries found");
		}
	}
protected:
	std::shared_ptr<tsmod::IVeilUtilities> utils;
};

tsmod::IObject* CreateSettingsTool()
{
	return dynamic_cast<tsmod::IObject*>(new SettingsTool());
}
