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

class pair
{
public:
	tscrypto::tsCryptoString type;
	tscrypto::tsCryptoString filename;
};

enum options { OPT_HELP,  };

static const struct OptionList options[] = {
	{ "", "VEIL tool selftest options" },
	{ "", "=================================" },
	{ "--help, -h, -?", "This help information." },
	{ "", "" },
};

static const CSimpleOptA::SOption optionList[] =
{
	{ OPT_HELP,               "-?",                   SO_NONE },
	{ OPT_HELP,               "-h",                   SO_NONE },
	{ OPT_HELP,               "--help",               SO_NONE },

	SO_END_OF_OPTIONS
};

class selftestTool : public IVeilToolCommand, public tsmod::IObject
{
public:
	selftestTool()
	{}
	~selftestTool()
	{}

	// tsmod::IObject
	virtual void OnConstructionFinished()
	{
		utils = ::TopServiceLocator()->get_instance<IVeilUtilities>("VeilUtilities");
	}

	// Inherited via IVeilToolCommand
	virtual tscrypto::tsCryptoString getDescription() const override
	{
		return "Crypto Selftests";
	}
	virtual int RunCommand(CSimpleOptA & opts) override
	{
		try
		{
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
			}
			else
			{
				Usage();
				return 1;
			}
		}

		size_t count = GetAlgorithmCount();

		for (size_t i = 0; i < count; i++)
		{
			tscrypto::tsCryptoString name = GetAlgorithmNameByIndex(i);
			std::shared_ptr<Selftest> test = std::dynamic_pointer_cast<Selftest>(ConstructAlgorithmByIndex(i));
			std::shared_ptr<AlgorithmInfo> info = std::dynamic_pointer_cast<AlgorithmInfo>(test);


			if (!test)
			{
				printf("%-25s -> No self test published\n", name.c_str());
			}
			else 
			{
				tscrypto::tsCryptoString name(info->AlgorithmName());
				tscrypto::tsCryptoString oid(info->AlgorithmOID());
				tscrypto::tsCryptoString id;
				id << info->AlgorithmID();
				name.resize(35, ' ');
				oid.resize(27, ' ');
				id.resize(4, ' ');

				cout << name << " " << oid << "  " << id;

				if (test->runTests(true))
				{
					printf(" -> success\n");
				}
				else
				{
					printf(" -> FAILED\n");
				}
			}
		}
		}
		catch (...)
		{
			printf(" -> EXCEPTION\n");
		}
		return 0;
	}
	virtual tscrypto::tsCryptoString getCommandName() const override
	{
		return "selftest";
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
protected:
	std::shared_ptr<IVeilUtilities> utils;
};

tsmod::IObject* CreateSelftestTool()
{
	return dynamic_cast<tsmod::IObject*>(new selftestTool());
}
