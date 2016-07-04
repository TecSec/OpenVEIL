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

static const uint8_t selectCmd[] = { 0x00, 0xa4, 0x04, 0x00, 0x0b, 0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00 };

enum {
	OPT_HELP = 0, 
};

static const struct OptionList options[] = {
	{ "", "VEIL SMARTCARD MONITOR options" },
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

//static void CheckForPiv(const char *reader)
//{
//	std::shared_ptr<ICkmWinscardContext> context;
//	std::shared_ptr<ICkmWinscardConnection> card;
//	tscrypto::tsCryptoData cmd(selectCmd, sizeof(selectCmd));
//	size_t sw;
//	tscrypto::tsCryptoData data;
//
//	if (!monitor->CreateContext(context) ||
//		!context->Connect(reader, 3, card))
//	{
//		return;
//	}
//	if (!card->Transmit(cmd, 0, data, sw))
//		return;
//	if (sw == 0x9000)
//		printf("\tPIV Card\n");
//}

class Changes : public ICkmWinscardChange, public tsmod::IObject
{
public:
	Changes() {};
	~Changes() {};

	virtual void readerAdded(const tscrypto::tsCryptoString &name) { std::cout << "Reader Added:  " << name << std::endl; }
	virtual void readerRemoved(const tscrypto::tsCryptoString &name) { std::cout << "Reader Removed:  " << name << std::endl; }
	virtual void cardInserted(const tscrypto::tsCryptoString &name) { std::cout << "Card Inserted:  " << name << std::endl; /*CheckForPiv(name.c_str());*/ }
	virtual void cardRemoved(const tscrypto::tsCryptoString &name) { std::cout << "Card Removed:  " << name << std::endl; }

private:
};

class SmartCardMonitorTool : public IVeilToolCommand, public tsmod::IObject
{
public:
	SmartCardMonitorTool()
	{}
	~SmartCardMonitorTool()
	{}

	// tsmod::IObject
	virtual void OnConstructionFinished()
	{
		utils = ::TopServiceLocator()->get_instance<IVeilUtilities>("VeilUtilities");
	}

	// Inherited via IVeilToolCommand
	virtual tscrypto::tsCryptoString getDescription() const override
	{
		return "Monitor smart card insertion and removal";
	}
	virtual int RunCommand(CSimpleOptA & opts) override
	{
		char buff[1024];

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

		//gLoadedCkmFunctions->winscardSupport->SetCkmWinscardDebugParameters("winscard", true, false, true, true);
		std::shared_ptr<ICkmWinscardMonitor> monitor = ::TopServiceLocator()->try_get_instance<ICkmWinscardMonitor>("SmartCardMonitor");
		if (!monitor)
			return 1;

		printf("Press ENTER to close the program\n\nCurrent reader list\n");

		//std::shared_ptr<ICkmChangeMonitor> changeMonitor;

		//changeMonitor = GetChangeMonitor();
		//if (!changeMonitor)
		//   {
		//       printf ("Unable to retrieve the change monitor.\n");
		//       return 1;
		//   }

		//   changeMonitor->LookForChanges();
		//   monitor->ScanForChanges();

		ICkmWinscardReaderList readers = monitor->GetReaderList();

		int i = 0;
		for (auto r : *readers)
		{
			i++; 
			printf("Reader %d:  %-40s %08X\n", i, r->ReaderName().c_str(), r->Status());
		}

		printf("\nDetected changes\n");
		int cookie = monitor->RegisterChangeReceiver(::TopServiceLocator()->Finish<ICkmWinscardChange>(new Changes()));
		//changeMonitor->StartChangeMonitorThread();
#ifdef HAVE_GETS_S
		gets_s(buff, sizeof(buff));
#else
		gets(buff);
#endif
		//	changeMonitor->StopChangeMonitorThread();

		//changeMonitor.reset();
		monitor->UnregisterChangeReceiver(cookie);
		monitor.reset();
		return 0;
	}
	virtual tscrypto::tsCryptoString getCommandName() const override
	{
		return "monitor";
	}
protected:
	void Usage()
	{
		utils->Usage(options, sizeof(options) / sizeof(options[0]));
	}
protected:
	std::shared_ptr<IVeilUtilities> utils;
};

tsmod::IObject* HIDDEN CreateSmartCardMonitorTool()
{
	return dynamic_cast<tsmod::IObject*>(new SmartCardMonitorTool());
}

