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
	OPT_HELP = 0,
};

static const struct tsmod::OptionList options[] = {
	{ "", "VEIL tool FILE DECRYPT commands" },
	{ "", "=================================" },
	{ "--help, -h, -?", "This help information." },
	{ "", "" },
	{ "", "The list of files to read follow the options." },
	{ "", "" },
};
static const CSimpleOptA::SOption g_rgOptions1[] =
{
	{ OPT_HELP, "-?", SO_NONE },
	{ OPT_HELP, "-h", SO_NONE },
	{ OPT_HELP, "--help", SO_NONE },
	SO_END_OF_OPTIONS
};

class FileInfoTool : public tsmod::IVeilToolCommand, public tsmod::IObject
{
public:
	FileInfoTool()
	{}
	~FileInfoTool()
	{}

	// tsmod::IObject
	virtual void OnConstructionFinished() override
	{
		utils = ::TopServiceLocator()->get_instance<tsmod::IVeilUtilities>("VeilUtilities");
	}

	// Inherited via tsmod::IVeilToolCommand
	virtual tscrypto::tsCryptoString getDescription() const override
	{
		return "Perform file decryption operations";
	}
	virtual int RunCommand(CSimpleOptA & opts) override
	{
		int retVal = 0;
		std::shared_ptr<IFileVEILOperations> ops;
		std::shared_ptr<IVEILFileList> filelist;
		tscrypto::tsCryptoString path;
		int count;
		int index;
		tscrypto::tsCryptoString name;
        char filename[MAX_PATH] = { 0, };

		if (!InitializeCmsHeader())
		{
			ERROR("We were unable to initialize the CMS Header system.");
			return 1;
		}

		if (!(ops = CreateFileVEILOperationsObject()))
		{
			ERROR("Unable to access the file support functions\n");
			return 1;
		}

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

		if (opts.FileCount() == 0)
		{
			Usage();
			return 9;
		}

		for (int i = 0; i < opts.FileCount(); i++)
		{
			TSFileListHandle files = tsGetFileListHandle(opts.File(i));
			uint32_t fileCount = (uint32_t)tsGetFileCount(files);

			for (uint32_t f = 0; f < fileCount; f++)
			{

				if (tsGetFileName(files, f, filename, sizeof(filename)))
				{
					filelist.reset();

					if (!(ops->GetStreamNames(filename, filelist)))
					{
						//        printf("Unable to retrieve the list of file streams for file '%s'\n", fileToEncrypt.c_str());
						//        return 1;
					}

					printf("-------------------------------------------------------------------------------\n");
					DumpInfo(filename);
					if (!filelist)
					{
						count = 0;
					}
					else
					{
						count = filelist->FileCount();
					}
					for (index = 0; index < count; index++)
					{
						printf("-------------------------------------------------------------------------------\n");
						if (filelist->GetFileName(index, path))
						{
							name = filename;
							name += path;
							DumpInfo(name.c_str());
						}
					}
				}
			}
            tsCloseFileList(files);
		}

		return retVal;
	}
	virtual tscrypto::tsCryptoString getCommandName() const override
	{
		return "info";
	}
protected:
	void Usage()
	{
		utils->Usage(options, sizeof(options) / sizeof(options[0]));
	}
	int DumpInfo(const char *filename)
	{
		int64_t fileLength;
		//	int len;
		TSFILE infile;
		std::shared_ptr<ICmsHeader> header7;
		bool isCkm7 = true;
		tscrypto::tsCryptoData fileContents;

		if (tsFOpen(&infile, filename, "rb", tsShare_DenyNO) != 0 || infile == NULL)
		{
			cout << "Unable to open the input file '" << filename << "'." << std::endl;
			return 1;
		}
        fileLength = tsGetFileSize64FromHandle(infile);

		if (fileLength > 20480)
			fileContents.resize(20480);
		else
			fileContents.resize((int)fileLength);

		if (tsReadFile(fileContents.rawData(), 1, (uint32_t)fileContents.size(), infile) != (uint32_t)fileContents.size())
		{
			tsCloseFile(infile);
			printf("Unable to read from the input file '%s'.\n", filename);
			return 1;
		}
        tsCloseFile(infile);

		if (!(header7 = ::TopServiceLocator()->try_get_instance<ICmsHeader>("/CmsHeader")))
		{
			printf("An error occurred while creating the CMS Header.\n");
			return 1;
		}
		if (!header7->IsProbableHeader(fileContents.c_str(), fileContents.size()))
		{
			isCkm7 = false;
			printf("The input file '%s' does not contain the required CKM Header.\n", filename);
			return 1;
		}

		tscrypto::tsCryptoString output;
		char buff[512];

		if (isCkm7)
		{
			std::shared_ptr<IFileVEILOperations> ops;

			output = header7->GetDebugString();

			if (!!(ops = CreateFileVEILOperationsObject()))
			{
				bool hr = ops->ValidateFileContents_PublicOnly(filename);

				if (!hr)
				{
					output += "ERROR:  File integrity checks FAILED\n";
				}
				else
				{
					output += "File integrity checks PASS\n";
				}
			}
			else
			{
				output += "File integrity not checked\n";
			}
		}
		else
		{
			output = "This file is not a CKM 7 encrypted file.\n";
		}

        tsSnPrintf(buff, sizeof(buff), "File length:           %lld\n", fileLength);
		output.prepend(buff);

        tsSnPrintf(buff, sizeof(buff), "File name:             %s\n", filename);
		output.prepend(buff);

		printf("%s\n", output.c_str());
		return 0;
	}
protected:
	std::shared_ptr<tsmod::IVeilUtilities> utils;
};

tsmod::IObject* HIDDEN CreateFileInfoTool()
{
	return dynamic_cast<tsmod::IObject*>(new FileInfoTool());
}

