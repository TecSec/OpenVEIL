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

//static const uint8_t selectCmd[] = { 0x00, 0xa4, 0x04, 0x00, 0x0b, 0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00 };

enum {
	OPT_HELP = 0, 
};

static const struct tsmod::OptionList options[] = {
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

static void ReaderAdded(void* params, const char* readerName)
{
    std::cout << "Reader Added:  " << readerName << std::endl;
}
static void ReaderRemoved(void* params, const char* readerName)
{
    std::cout << "Reader Removed:  " << readerName << std::endl;
}
static void CardInserted(void* params, const char* readerName)
{
    std::cout << "Card Inserted:  " << readerName << std::endl; /*CheckForPiv(name.c_str());*/
}
static void CardRemoved(void* params, const char* readerName)
{
    std::cout << "Card Removed:  " << readerName << std::endl;
}

static const TSSmartCard_ChangeConsumer mySmartcardChanges = {
    &ReaderAdded, &ReaderRemoved, &CardInserted, &CardRemoved,
};

class SmartCardMonitorTool : public tsmod::IVeilToolCommand, public tsmod::IObject
{
public:
	SmartCardMonitorTool()
	{
    }
	~SmartCardMonitorTool()
	{
    }

	// tsmod::IObject
	virtual void OnConstructionFinished() override
	{
		utils = ::TopServiceLocator()->get_instance<tsmod::IVeilUtilities>("VeilUtilities");
	}

	// Inherited via tsmod::IVeilToolCommand
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

        TSBYTE_BUFF_LIST readers = scMan->allReaders();

		int i = 0;
        int count = (int)tsByteBufferListUsed(readers);
        for (i = 0; i < count; i++)
		{
            const char* readerName = tsGetByteBufferListItemAsString(readers, i);
            printf("Reader %d:  %-40s %08X\n", i, readerName, scMan->getReaderStatus(readerName));
		}
        tsFreeByteBufferList(&readers);

		printf("\nDetected changes\n");
        uint32_t cookie = scMan->registerChangeConsumer(&mySmartcardChanges, NULL);
        auto unreg1 = finally([&cookie]() {scMan->unregisterChangeConsumer(cookie); });

        if (cookie == 0)
            return 1;

		//changeMonitor->StartChangeMonitorThread();
#ifdef HAVE_GETS_S
		gets_s(buff, sizeof(buff));
#else
		gets(buff);
#endif
		//	changeMonitor->StopChangeMonitorThread();

		//changeMonitor.reset();
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
	std::shared_ptr<tsmod::IVeilUtilities> utils;
};

tsmod::IObject* HIDDEN CreateSmartCardMonitorTool()
{
	return dynamic_cast<tsmod::IObject*>(new SmartCardMonitorTool());
}

