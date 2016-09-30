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

extern tsmod::IObject* CreateGenDsaParameters();
extern tsmod::IObject* CreateGenDsaKey();
extern tsmod::IObject* CreateGenRsa();
extern tsmod::IObject* CreateGenEcc();
extern tsmod::IObject* CreateGenX25519();
extern tsmod::IObject* CreatePemTool();
extern tsmod::IObject* CreateSelftestTool();
extern tsmod::IObject* CreateSettingsTool();
extern tsmod::IObject* CreateFoldersTool();


extern tsmod::IObject* CreatePemOutputCollector();
extern tsmod::IObject* CreateHexOutputCollector();
extern tsmod::IObject* CreateVeilUtilities();


enum { OPT_NOAESNI, OPT_NOSSE, OPT_NOSSE2 };

//static const struct tsmod::OptionList sysoptions[] = {
//	{ "", "VEIL system options" },
//	{ "", "=================================" },
//	{ "--no-aesni", "Disable the AES-NI instructions." },
//	{ "--no-sse", "Disable the SSE instructions." },
//	{ "--no-sse2", "Disable the SSE2 instructions." },
//	{ "", "" },
//};

static const CSimpleOptA::SOption sysoptionList[] =
{
	{ OPT_NOAESNI,               "--no-aesni",        SO_NONE },
	{ OPT_NOSSE,                 "--no-sse",          SO_NONE },
	{ OPT_NOSSE2,                "--no-sse2",          SO_NONE },

	SO_END_OF_OPTIONS
};

int main(int argc, const char* argv[])
{
	tscrypto::tsCryptoString cmdName;
	std::shared_ptr<tsmod::IVeilUtilities> utils;

#if defined(DEBUG) && defined(linux)
	std::set_terminate(__gnu_cxx::__verbose_terminate_handler);
#endif

	// Process the options
	CSimpleOptA opts(argc, (char**)argv, sysoptionList, SO_O_NOERR | SO_O_SHORTARG | SO_O_ICASE | SO_O_EXACT);
	while (opts.Next())
	{
		if (opts.LastError() == SO_SUCCESS)
		{
			if (opts.OptionId() == OPT_NOAESNI)
			{
				gCpuSupportsAES = false;
			}
			else if (opts.OptionId() == OPT_NOSSE)
			{
				gCpuSupportsSSE = false;
			}
			else if (opts.OptionId() == OPT_NOSSE2)
			{
				gCpuSupportsSSE2 = false;
			}
		}
	}

#ifndef NO_LOGGING
	tsLog::DisallowLogs("SRVDATA,SERVICE,HTTPSENT");
	tsLog::SetApplicationJsonPreferences(SimpleJsonDebugPreferences::Create("default", "veiltool"));
#endif // NO_LOGGING

	auto cleanup1 = finally([]() {
		TerminateVEILSystem();
		fflush(stdout);
	});

	::TopServiceLocator()->AddSingletonClass("VeilUtilities", CreateVeilUtilities);
	::TopServiceLocator()->AddClass("PemOutput", CreatePemOutputCollector);
	::TopServiceLocator()->AddClass("HexOutput", CreateHexOutputCollector);

	// Register the built in commands
	::TopServiceLocator()->AddClass("/COMMANDS/GENDSAPARAMS", CreateGenDsaParameters);
	::TopServiceLocator()->AddClass("/COMMANDS/GENDSA", CreateGenDsaKey);
	::TopServiceLocator()->AddClass("/COMMANDS/GENRSA", CreateGenRsa);
	::TopServiceLocator()->AddClass("/COMMANDS/GENECC", CreateGenEcc);
	::TopServiceLocator()->AddClass("/COMMANDS/GENX25519", CreateGenX25519);
	::TopServiceLocator()->AddClass("/COMMANDS/PEM", CreatePemTool);
	::TopServiceLocator()->AddClass("/COMMANDS/SELFTEST", CreateSelftestTool);
	::TopServiceLocator()->AddClass("/COMMANDS/SETTINGS", CreateSettingsTool);
	::TopServiceLocator()->AddClass("/COMMANDS/FOLDERS", CreateFoldersTool);

	// Initialize the VeilUtilities class
	utils = ::TopServiceLocator()->get_instance<tsmod::IVeilUtilities>("VeilUtilities");
	utils->console() << Black_Background;

	// Now load any extensions
	std::shared_ptr<tsmod::IPluginModuleManager> mgr = ::TopServiceLocator()->try_get_instance<tsmod::IPluginModuleManager>("PluginManager");
	auto cleanupPlugins = finally([&mgr]() { 
		if (!!mgr)
		{
			mgr->TerminateAllPlugins();
		}
		mgr.reset(); 
	});
	if (!!mgr)
	{
		tscrypto::tsCryptoString path, dir, file, ext;
		xp_GetModuleFileName(XP_MODULE_INVALID, path);
		xp_SplitPath(path, dir, file, ext);

		mgr->LoadModulesOfType((dir + "*.veil").c_str(), nullptr, AddSystemTerminationFunction);
	}

	// and build the option list
	tscrypto::tsCryptoStringList cmdNameList = ::TopServiceLocator()->ObjectGroup("/COMMANDS/", false);
	std::vector<CSimpleOptA::SOption> options;

	for (size_t i = 0; i < cmdNameList->size(); i++)
	{
		CSimpleOptA::SOption option;

		option.nArgType = SO_NONE;
		option.nId = (int)i;
		option.pszArg = &cmdNameList->at(i).c_str()[10];
		options.push_back(option);
	}
	options.push_back(CSimpleOptA::SOption() = SO_END_OF_OPTIONS);

	opts.Init(opts.FileCount(), opts.Files(), options.data(), SO_O_NOERR | SO_O_SHORTARG | SO_O_ICASE | SO_O_EXACT | SO_O_USEALL);
	while (opts.Next())
	{
		if (opts.LastError() == SO_SUCCESS)
		{
			if (cmdName.size() > 0)
			{
				utils->TopUsage();
				return 1;
			}
			cmdName = cmdNameList->at(opts.OptionId());
			if (cmdName.size() == 0)
			{
				utils->TopUsage();
				return 1;
			}
		}
	}

	std::shared_ptr<tsmod::IVeilToolCommand> cmd = ::TopServiceLocator()->try_get_instance<tsmod::IVeilToolCommand>(cmdName.c_str());

	if (!cmd)
	{
		utils->TopUsage();
		return 1;
	}

	return cmd->RunCommand(opts);
}

