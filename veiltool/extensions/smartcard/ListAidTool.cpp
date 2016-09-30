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

static const struct tsmod::OptionList options[] = {
	{ "", "VEIL SMARTCARD AID LIST options" },
	{ "", "=======================================" },
	{ "--help, -h, -?", "This help information." },
	{ "", "" },
};
static const CSimpleOptA::SOption g_rgOptions1[] =
{
	{ OPT_HELP, "-?", SO_NONE },
	{ OPT_HELP, "-h", SO_NONE },
	{ OPT_HELP, "--help", SO_NONE },

	SO_END_OF_OPTIONS
};

class ListAIDTool : public tsmod::IVeilToolCommand, public tsmod::IObject
{
public:
	ListAIDTool()
	{}
	~ListAIDTool()
	{}

	// tsmod::IObject
	virtual void OnConstructionFinished() override
	{
		utils = ::TopServiceLocator()->get_instance<tsmod::IVeilUtilities>("VeilUtilities");
	}

	// Inherited via tsmod::IVeilToolCommand
	virtual tscrypto::tsCryptoString getDescription() const override
	{
		return "List the AIDs that the system will use for VEIL Tokens";
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

		prefs->loadValues();

		tscrypto::tsCryptoString aidvalue = prefs->getAIDList();
		tscrypto::tsCryptoStringList aidlist = aidvalue.split(';');
		tscrypto::tsCryptoString aidascii;

		printf("\n");

		for (size_t i = 0; i < aidlist->size(); i++)
		{
			aidascii.assign(aidlist->at(i));
			printf("AID entry %d --> %s\n", (int)i, aidascii.c_str());
		}

		aidlist->clear();
		aidvalue.clear();
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

tsmod::IObject* HIDDEN CreateListAIDTool()
{
	return dynamic_cast<tsmod::IObject*>(new ListAIDTool());
}

