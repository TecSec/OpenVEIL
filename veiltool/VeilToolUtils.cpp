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
#if defined(DEBUG) && defined(linux)
#include <exception>
#include <stdexcept>
#endif

class CommandMenu : public IVeilToolCommand, public tsmod::IObject
{
public:
	CommandMenu(const tscrypto::tsCryptoString& description, const tscrypto::tsCryptoString& commandPrefix, const tscrypto::tsCryptoString& name, const tscrypto::tsCryptoString& menuHeader) : _description(description), _commandPrefix(commandPrefix), _name(name), _menuHeader(menuHeader)
	{}
	~CommandMenu()
	{}

	// tsmod::IObject
	virtual void OnConstructionFinished()
	{
		utils = ::TopServiceLocator()->get_instance<IVeilUtilities>("VeilUtilities");
	}

	// Inherited via IVeilToolCommand
	virtual tscrypto::tsCryptoString getDescription() const override
	{
		return _description;
	}
	virtual int RunCommand(CSimpleOptA & opts) override
	{
		tscrypto::tsCryptoString tmp(_commandPrefix);

		if (tmp[tmp.size() - 1] == '/')
			tmp.resize(tmp.size() - 1);
		if (!::TopServiceLocator()->CanCreate(tmp.c_str()))
		{
			utils->console() << BoldRed << "ERROR:  " << BoldWhite << "There are no " << _name << " commands registered in the system." << ::endl;
			return 1;
		}
		tscrypto::tsCryptoStringList cmdNameList = ::TopServiceLocator()->ObjectGroup(_commandPrefix.c_str(), false);
		std::vector<CSimpleOptA::SOption> options;
		tscrypto::tsCryptoString cmdName;

		for (size_t i = 0; i < cmdNameList->size(); i++)
		{
			CSimpleOptA::SOption option;

			option.nArgType = SO_NONE;
			option.nId = (int)i;
			option.pszArg = &cmdNameList->at(i).c_str()[_commandPrefix.size()];
			options.push_back(option);
		}
		//options.push_back(CSimpleOptA::SOption() = { OPT_HELP, "-?", SO_NONE });
		//options.push_back(CSimpleOptA::SOption() = { OPT_HELP, "-h", SO_NONE });
		//options.push_back(CSimpleOptA::SOption() = { OPT_HELP, "--help", SO_NONE });
		options.push_back(CSimpleOptA::SOption() = SO_END_OF_OPTIONS);

		// Process the options
		opts.Init(opts.FileCount(), opts.Files(), options.data(), SO_O_NOERR | SO_O_USEALL | SO_O_ICASE);

		while (opts.Next())
		{
			if (opts.LastError() == SO_SUCCESS)
			{
				if (opts.OptionId() == 1000)
				{
					Usage();
					return 0;
				}
				else
				{

					if (cmdName.size() > 0)
					{
						Usage();
						return 1;
					}
					cmdName = cmdNameList->at(opts.OptionId());
					if (cmdName.size() == 0)
					{
						Usage();
						return 1;
					}
				}
			}
		}

		std::shared_ptr<IVeilToolCommand> cmd = ::TopServiceLocator()->try_get_instance<IVeilToolCommand>(cmdName.c_str());

		if (!cmd)
		{
			Usage();
			return 1;
		}

		return cmd->RunCommand(opts);
	}
	virtual tscrypto::tsCryptoString getCommandName() const override
	{
		return _name;
	}
protected:

	void Usage()
	{
		tscrypto::tsCryptoString tmp(_commandPrefix);

		if (tmp[tmp.size() - 1] == '/')
			tmp.resize(tmp.size() - 1);
		if (!::TopServiceLocator()->CanCreate(tmp.c_str()))
		{
			utils->console() << BoldRed << "ERROR:  " << BoldWhite << "There are no " << _name << " commands registered in the system." << ::endl;
			return;
		}
			
		std::vector<std::shared_ptr<IVeilToolCommand> > list = ::TopServiceLocator()->get_group<IVeilToolCommand>(_commandPrefix.c_str(), false);

		if (list.size() > 1)
		{
			std::sort(list.begin(), list.end(), [](std::shared_ptr<IVeilToolCommand> left, std::shared_ptr<IVeilToolCommand> right) {
				return TsStriCmp(left->getCommandName(), right->getCommandName()) < 0;
			});
		}

		utils->console() << BoldWhite << "VEIL "<< _menuHeader <<" Options" << ::endl << "================================" << ::endl;
		utils->console() << BoldGreen << XP_Console::width(-25) << "--help, -h, -?" << BoldWhite << "This help information." << ::endl;
		utils->console() << " " << ::endl;
		utils->console() << BoldWhite << "VEIL "<< _menuHeader <<" Commands" << ::endl << "================================" << ::endl;

		for (std::shared_ptr<IVeilToolCommand> option : list)
		{
			tscrypto::tsCryptoString description = option->getDescription();
			tscrypto::tsCryptoString name = option->getCommandName();

			utils->DumpOptionLine(name, description);
		}
	}
protected:
	std::shared_ptr<IVeilUtilities> utils;
	const tscrypto::tsCryptoString _description;
	const tscrypto::tsCryptoString _commandPrefix;
	const tscrypto::tsCryptoString _name;
	const tscrypto::tsCryptoString _menuHeader;
};

class VeilUtilities : public IVeilUtilities, public tsmod::IObject 
{
public:
	VeilUtilities()
	{}
	virtual ~VeilUtilities()
	{}

	// Inherited via IVeilUtilities
	virtual xp_console & console() override
	{
		return ts_out;
	}
	virtual void TopUsage() override
	{
		std::vector<std::shared_ptr<IVeilToolCommand> > list = ::TopServiceLocator()->get_group<IVeilToolCommand>("/COMMANDS/", false);

		std::sort(list.begin(), list.end(), [](std::shared_ptr<IVeilToolCommand> left, std::shared_ptr<IVeilToolCommand> right) {
			return TsStriCmp(left->getCommandName(), right->getCommandName()) < 0;
		});

		ts_out << BoldWhite << "VEIL Tool Options" << ::endl << "================================" << ::endl;
		ts_out << BoldGreen << XP_Console::width(-25) << "--help, -h, -?" << BoldWhite << "This help information." << ::endl;
		ts_out << " " << ::endl;
		ts_out << BoldWhite << "VEIL Tool Commands" << ::endl << "================================" << ::endl;

		for (std::shared_ptr<IVeilToolCommand> option : list)
		{
			tscrypto::tsCryptoString description = option->getDescription();
			tscrypto::tsCryptoString name = option->getCommandName();

			DumpOptionLine(name, description);
		}
	}
	virtual void DumpOptionLine(const tscrypto::tsCryptoString& left, const tscrypto::tsCryptoString& right) override
	{
		if (left.size() == 0)
		{
			// header
			ts_out << BoldWhite << right << ::endl;
		}
		else
		{
			ts_out << BoldGreen;
			if (TsStrLen(left) > 24)
			{
				ts_out << left << ::endl << "\t\t\t " << BoldWhite;
			}
			else
			{
				ts_out << XP_Console::width(-25) << left << BoldWhite;
			}
			tscrypto::tsCryptoString description(right);

			do {
				ts_out << description.substring(0, ts_out.consoleWidth() - 26) << ::endl;
				description.DeleteAt(0, ts_out.consoleWidth() - 26);
				description.TrimStart();
				if (description.size() > 0)
					ts_out << "\t\t\t ";
			} while (description.size() > 0);
		}
	}
	virtual void Usage(const OptionList * list, size_t count) override
	{
		for (int i = 0; i < (int)count; i++)
		{
			DumpOptionLine(list[i].option, list[i].description);
		}
	}
	virtual void localGetConsolePin(tscrypto::tsCryptoString & enteredPin, uint32_t len, const tscrypto::tsCryptoString & prompt) override
	{
		console().GetPin(enteredPin, len, prompt);
	}
	virtual void OutputError(char * msg, ...) override
	{
		tscrypto::tsCryptoString results;
		va_list args;

		va_start(args, msg);
		results.FormatArg(msg, args);
		va_end(args);
		results << tscrypto::endl;
		ts_out << BoldRed << results << BoldWhite << ::endl;
	}
	virtual tsmod::IObject* buildCommandMenu(const tscrypto::tsCryptoString& description, const tscrypto::tsCryptoString& commandPrefix, const tscrypto::tsCryptoString& name, const tscrypto::tsCryptoString& menuHeader) override
	{
		return dynamic_cast<tsmod::IObject*>(new CommandMenu(description, commandPrefix, name, menuHeader));
	}
protected:
	xp_console ts_out;
};
tsmod::IObject* CreateVeilUtilities()
{
	return dynamic_cast<tsmod::IObject*>(new VeilUtilities());
}


class PemOutputCollector : public IOutputCollector, public tsmod::IObject
{
public:
	PemOutputCollector()
	{
		sections = CreateTSNamedBinarySectionList();
		_pbkdf = std::dynamic_pointer_cast<PbKdf>(CryptoFactory("KDF-PBKDF2"));
	}
	virtual ~PemOutputCollector()
	{}

	// tsmod::IObject
	virtual void OnConstructionFinished()
	{
		utils = ::TopServiceLocator()->get_instance<IVeilUtilities>("VeilUtilities");
	}

	// Inherited via IOutputCollector
	virtual int AddOutputData(const tscrypto::tsCryptoData & outData, const tscrypto::tsCryptoString & dataType, bool sensitive = false, const tsAttributeMap & attrs = tsAttributeMap()) override
	{
		TSNamedBinarySection section;

		section.Name = dataType;
		section.Attributes = attrs;

		if (sensitive)
		{
			if ((Password().size() > 0 || usePassword()) && !!_alg)
			{
				int keySizeNeededInBytes;

				if (Password().size() == 0)
				{
					tscrypto::tsCryptoString pwd;

					utils->localGetConsolePin(pwd, 64, "Enter the password that is to protect the new keys:  ");
					if (pwd.size() == 0)
						return 0;
					Password(pwd);
				}
				tscrypto::tsCryptoData iv;
				tscrypto::tsCryptoString param;
				tscrypto::tsCryptoData data1, data2;

				keySizeNeededInBytes = (int)(_alg->currentKeySizeInBits() / 8);
				if (!_alg->createIVEC(iv))
				{
					iv.clear();
				}
				section.Attributes.AddItem("Proc-Type", "4,ENCRYPTED");

				param << encryptionAlgName();
				if (iv.size() > 0)
					param << "," << iv.ToHexString();
				section.Attributes.AddItem("DEK-Info", param);

				tscrypto::tsCryptoData key;

				if (!_pbkdf->PBKDF1("HASH-MD5", Password(), iv, keySizeNeededInBytes, key))
				{
					return 1;
				}
				_alg->setPaddingType(_SymmetricPaddingType::padding_Pkcs5);

				if (!_alg->init(true, _alg->getCurrentMode(), key, iv) ||
					!_alg->updateAndFinish(outData, data1))
				{
					utils->console() << BoldRed << "ERROR:  " << BoldWhite << "Unable to encrypt the payload." << ::endl << ::endl;
					return 1;
				}
				section.Contents = data1;
			}
			else
			{
				// TODO:  Perform encryption here
				section.Contents = outData;
			}
		}
		else
		{
			section.Contents = outData;
		}
		sections->push_back(section);
		return 0;
	}
	virtual bool usePassword() const override
	{
		return _usePassword;
	}
	virtual void usePassword(bool setTo) override
	{
		_usePassword = setTo;
	}
	virtual tscrypto::tsCryptoString Password() const override
	{
		return _password;
	}
	virtual void Password(const tscrypto::tsCryptoString & setTo) override
	{
		_password = setTo;
	}
	virtual tscrypto::tsCryptoString encryptionAlgName() const override
	{
		return _encryptionAlgName;
	}
	virtual bool encryptionAlgName(const tscrypto::tsCryptoString & setTo) override
	{
		_alg.reset();
		_encryptionAlgName.clear();
		if (setTo.size() > 0)
		{
			_alg = std::dynamic_pointer_cast<Symmetric>(CryptoFactory(setTo));
			if (!_alg)
				return false;
		}
		_encryptionAlgName = setTo;
		return true;
	}
	virtual bool writeToStdout() override
	{
		tscrypto::tsCryptoString str;

		if (!xp_WriteArmoredString(sections, str))
		{
			utils->console() << BoldRed << "ERROR:  " << BoldWhite << "Unable to format the data output." << ::endl << ::endl;
			return false;
		}
		printf("%s\n", str.c_str());
		return true;
	}
	virtual bool writeToFile(const tscrypto::tsCryptoString & filename) override
	{
		tscrypto::tsCryptoString str;

		if (!xp_WriteArmoredString(sections, str))
		{
			utils->console() << BoldRed << "ERROR:  " << BoldWhite << "Unable to format the data output." << ::endl << ::endl;
			return false;
		}
		if (filename.size() == 0)
		{
			printf("%s\n", str.c_str());
			return true;
		}
		else
			return xp_WriteBytes(filename, str.ToUTF8Data());
	}

protected:
	bool _usePassword;
	tscrypto::tsCryptoString _password;
	tscrypto::tsCryptoString _encryptionAlgName;
	std::shared_ptr<Symmetric> _alg;
	TSNamedBinarySectionList sections;
	std::shared_ptr<IVeilUtilities> utils;
	std::shared_ptr<PbKdf> _pbkdf;
};

tsmod::IObject* CreatePemOutputCollector()
{
	return dynamic_cast<tsmod::IObject*>(new PemOutputCollector());
}

class HexOutputCollector : public IOutputCollector, public tsmod::IObject
{
public:
	HexOutputCollector()
	{
	}
	virtual ~HexOutputCollector()
	{}

	// tsmod::IObject
	virtual void OnConstructionFinished()
	{
		utils = ::TopServiceLocator()->get_instance<IVeilUtilities>("VeilUtilities");
	}

	// Inherited via IOutputCollector
	virtual int AddOutputData(const tscrypto::tsCryptoData & outData, const tscrypto::tsCryptoString & dataType, bool sensitive = false, const tsAttributeMap & attrs = tsAttributeMap()) override
	{
		data << "---- " << dataType << " ----" << tscrypto::endl << outData.ToHexStringWithSpaces() << tscrypto::endl;
		return 0;
	}
	virtual bool usePassword() const override
	{
		return false;
	}
	virtual void usePassword(bool setTo) override
	{
	}
	virtual tscrypto::tsCryptoString Password() const override
	{
		return "";
	}
	virtual void Password(const tscrypto::tsCryptoString & setTo) override
	{
	}
	virtual tscrypto::tsCryptoString encryptionAlgName() const override
	{
		return "";
	}
	virtual bool encryptionAlgName(const tscrypto::tsCryptoString & setTo) override
	{
		return false;
	}
	virtual bool writeToStdout() override
	{
		printf("%s\n", data.c_str());
		return true;
	}
	virtual bool writeToFile(const tscrypto::tsCryptoString & filename) override
	{
		if (filename.size() == 0)
		{
			printf("%s\n", data.c_str());
			return true;
		}
		else
			return xp_WriteText(filename, data);
	}

protected:
	std::shared_ptr<IVeilUtilities> utils;
	tscrypto::tsCryptoString data;
};

tsmod::IObject* CreateHexOutputCollector()
{
	return dynamic_cast<tsmod::IObject*>(new HexOutputCollector());
}
