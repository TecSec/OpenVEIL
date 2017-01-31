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

#ifdef _WIN32
#undef ERROR
#endif

#define ERROR(a) utils->console() << BoldRed << "ERROR:  " << BoldWhite << a << ::endl
#define WARN(a) utils->console() << BoldGreen << "WARNING:  " << BoldWhite << a << ::endl
#define BLOCKSIZE 4096


enum {
	OPT_HELP = 1, 
};

static const struct tsmod::OptionList options[] = {
	{ "", "VEIL tool FILE DELETE options" },
	{ "", "=================================" },
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

class FileDeleteTool : public tsmod::IVeilToolCommand, public tsmod::IObject
{
public:
	FileDeleteTool()
	{}
	~FileDeleteTool()
	{}

	// tsmod::IObject
	virtual void OnConstructionFinished() override
	{
		utils = ::TopServiceLocator()->get_instance<tsmod::IVeilUtilities>("VeilUtilities");
	}

	// Inherited via tsmod::IVeilToolCommand
	virtual tscrypto::tsCryptoString getDescription() const override
	{
		return "Perform secure file deletion - this is not recoverable";
	}
	virtual int RunCommand(CSimpleOptA & opts) override
	{
		int retVal = 0;

		try
		{
			tscrypto::tsCryptoString inputFile;

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

			if (opts.FileCount() < 1)
			{
				ERROR("At least one input file must be specified.");
				return 12;
			}

			for (int fileIndex = 0; retVal == 0 && fileIndex < opts.FileCount(); fileIndex++)
			{
				inputFile = opts.File(fileIndex);

				if (inputFile.size() == 0)
				{
					ERROR("Input File must be specified.");
					return 50;
				}


				retVal = streamDelete(inputFile);
				if (retVal == 0)
				{
					cout << inputFile << " deleted successfully." << std::endl;
				}
				else
				{
					ERROR(inputFile << " was NOT deleted.");
				}
			} // for each file
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
		return "delete";
	}
protected:
	void Usage()
	{
		utils->Usage(options, sizeof(options) / sizeof(options[0]));
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

		if (xp_GetFileAttributes(inputFile) == XP_INVALID_FILE_ATTRIBUTES || xp_IsDirectory(inputFile))
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

protected:
	std::shared_ptr<tsmod::IVeilUtilities> utils;
};

tsmod::IObject* HIDDEN CreateFileDeleteTool()
{
	return dynamic_cast<tsmod::IObject*>(new FileDeleteTool());
}

