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
	OPT_HELP = 0, 
};

static const struct OptionList options[] = {
	{ "", "VEIL SMARTCARD AID ADD options" },
	{ "", "=======================================" },
	{ "--help, -h, -?", "This help information." },
	{ "", "" },
	{ "", "The list of aids to add are specified after the options and are HEX strings with no spaces." },
	{ "", "" },
};
static const CSimpleOptA::SOption g_rgOptions1[] =
{
	{ OPT_HELP, "-?", SO_NONE },
	{ OPT_HELP, "-h", SO_NONE },
	{ OPT_HELP, "--help", SO_NONE },

	SO_END_OF_OPTIONS
};

class AddAIDTool : public IVeilToolCommand, public tsmod::IObject
{
public:
	AddAIDTool()
	{}
	~AddAIDTool()
	{}

	// tsmod::IObject
	virtual void OnConstructionFinished()
	{
		utils = ::TopServiceLocator()->get_instance<IVeilUtilities>("VeilUtilities");
	}

	// Inherited via IVeilToolCommand
	virtual tscrypto::tsCryptoString getDescription() const override
	{
		return "Add AIDs that the system will use for VEIL Tokens";
	}
	virtual int RunCommand(CSimpleOptA & opts) override
	{
		opts.Init(opts.FileCount(), opts.Files(), g_rgOptions1, SO_O_NOERR | SO_O_USEALL | SO_O_ICASE);
		while (opts.Next())
		{
			if (opts.LastError() == SO_SUCCESS)
			{
				if (opts.OptionId() == OPT_HELP)
				{
					Usage();
					return 0;
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

		std::shared_ptr<BasicVEILPreferences> prefs = BasicVEILPreferences::Create();
		tscrypto::tsCryptoData bsAID;

		prefs->loadValues();

		for (int i = 0; i < opts.FileCount(); i++)
		{
			bsAID.FromHexString(opts.File(i));

			if (bsAID.size() == 0)
			{
				printf("Invalid AID data format detected.\n");
				return 1;
			}

			printf("New AID = %s\n", bsAID.ToHexString().c_str());

			tscrypto::tsCryptoString aidvalue = prefs->getAIDList();
			tscrypto::tsCryptoStringList aidlist = aidvalue.split(';');

			for (size_t i = 0; i < aidlist->size(); i++)
			{
				if (aidlist->at(i).compare(bsAID.ToHexString()) == 0)
				{
					printf("AID already exists.  Please reenter\n");
					return 1;
				}
			}
			aidvalue.clear();
			for (size_t i = 0; i < aidlist->size(); i++)
			{
				if (i > 0)
					aidvalue << ";";
				aidvalue << aidlist->at(i);
			}
			if (aidvalue.size() > 0)
				aidvalue << ";";
			aidvalue << bsAID.ToHexString();

			prefs->setAIDList(aidvalue);
		}
		prefs->saveConfigurationChanges();
		return 0;
	}
	virtual tscrypto::tsCryptoString getCommandName() const override
	{
		return "add";
	}
protected:
	void Usage()
	{
		utils->Usage(options, sizeof(options) / sizeof(options[0]));
	}
protected:
	std::shared_ptr<IVeilUtilities> utils;
};

tsmod::IObject* HIDDEN CreateAddAIDTool()
{
	return dynamic_cast<tsmod::IObject*>(new AddAIDTool());
}

