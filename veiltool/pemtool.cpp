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

enum options { OPT_HELP, OPT_TOPEM, OPT_FROMPEM, OPT_INPUT, OPT_TYPE, OPT_OUTPUT, OPT_DISPLAY_ATTRIBUTES };

static const struct OptionList options[] = {
	{ "", "VEIL tool pem options" },
	{ "", "=================================" },
	{ "--help, -h, -?", "This help information." },
	{ "--out=<filename>", "The output file name" },
	{ "--topem", "Convert the input files into a PEM file." },
	{ "--frompem", "Convert the PEM into output files." },
	{ "--in=<filename>", "An input filename" },
	{ "--type=<PEM Type>", "The ascii descriptive  text for this PEM part [CERTIFICATE, RSA PRIVATE KEY, ...]" },
	{ "--display-attributes", "Display the attributes for any decoded PEM file." },
	{ "", "" },
};

static const CSimpleOptA::SOption optionList[] =
{
	{ OPT_HELP,               "-?",                   SO_NONE },
	{ OPT_HELP,               "-h",                   SO_NONE },
	{ OPT_HELP,               "--help",               SO_NONE },
	{ OPT_TOPEM,              "--topem",              SO_NONE },
	{ OPT_FROMPEM,            "--frompem",            SO_NONE },
	{ OPT_OUTPUT,             "--out",                SO_REQ_SEP },
	{ OPT_INPUT,              "--in",                 SO_REQ_SEP },
	{ OPT_TYPE,               "--type",               SO_REQ_SEP },
	{ OPT_DISPLAY_ATTRIBUTES, "--display-attributes", SO_NONE },

	SO_END_OF_OPTIONS
};

class pemtool : public IVeilToolCommand, public tsmod::IObject
{
public:
	pemtool()
	{}
	~pemtool()
	{}

	// tsmod::IObject
	virtual void OnConstructionFinished()
	{
		utils = ::TopServiceLocator()->get_instance<IVeilUtilities>("VeilUtilities");
	}

	// Inherited via IVeilToolCommand
	virtual tscrypto::tsCryptoString getDescription() const override
	{
		return "Convert PEM files";
	}
	virtual int RunCommand(CSimpleOptA & opts) override
	{
		tscrypto::tsCryptoString names;
		int retVal = 1;
		bool toPem = false;
		tscrypto::tsCryptoString type = "CERTIFICATE";
		std::vector<::pair> files;
		tscrypto::tsCryptoString outputName = "output.bin";
		bool displayAttributes = false;

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
				else if (opts.OptionId() == OPT_TOPEM)
				{
					toPem = true;
				}
				else if (opts.OptionId() == OPT_FROMPEM)
				{
					toPem = false;
				}
				else if (opts.OptionId() == OPT_TYPE)
				{
					type = opts.OptionArg();
					if (type.size() == 0)
					{
						Usage();
						return 1;
					}
					type.ToUpper();
				}
				else if (opts.OptionId() == OPT_INPUT)
				{
					tscrypto::tsCryptoString filename = opts.OptionArg();
					if (filename.size() == 0)
					{
						Usage();
						return 1;
					}
					::pair tmp;
					tmp.filename = filename;
					tmp.type = type;
					files.push_back(tmp);
				}
				else if (opts.OptionId() == OPT_OUTPUT)
				{
					outputName = opts.OptionArg();
					if (outputName.size() == 0)
					{
						Usage();
						return 1;
					}
				}
				else if (opts.OptionId() == OPT_DISPLAY_ATTRIBUTES)
				{
					displayAttributes = true;
				}
			}
			else
			{
				Usage();
				return 1;
			}
		}

		if (toPem)
		{
			tscrypto::tsCryptoString path, name, ext;
			TSNamedBinarySectionList sections = CreateTSNamedBinarySectionList();

			xp_SplitPath(outputName, path, name, ext);

			if (ext.size() == 0 || ext == ".bin")
				ext = ".pem";

			outputName.clear();
			outputName << path << name << ext;

			if (files.size() == 0)
			{
				OutputError("ERROR:  No input files were specified.");
				Usage();
				return 1;
			}
			for (::pair& part : files)
			{
				TSNamedBinarySection section;

				section.Name = part.type;
				if (!xp_ReadAllBytes(part.filename, section.Contents))
				{
					OutputError("ERROR:  Unable to read file '%s'", part.filename.c_str());
				}
				else
				{
					sections->push_back(section);
				}
			}
			if (!xp_WriteArmoredFile(outputName, sections))
			{
				OutputError("ERROR:  Unable to write the output PEM file '%s'", outputName.c_str());
			}
			else
			{
				utils->console() << "Successfully wrote the output PEM file '" << outputName << "'" << ::endl;
			}
		}
		else
		{
			tscrypto::tsCryptoString path, name, ext;
			int count = 1;

			xp_SplitPath(outputName, path, name, ext);

			for (::pair& part : files)
			{
				// These three lines are needed for VC10 lambda support
				tscrypto::tsCryptoString path1(path), name1(name), ext1(ext);
				int count1(count);
				bool displayAttributes1(displayAttributes);

				TSNamedBinarySectionList sections;
				if (!xp_ReadArmoredFile(part.filename, sections))
				{
					OutputError("ERROR:  Unable to read the input file '%s'", part.filename.c_str());
				}
				else
				{
					for (TSNamedBinarySection& section : *sections)
					{
						tscrypto::tsCryptoString filename;

						if (section.Name.size() > 0)
						{
							filename << path1 << name1 << (count1++) << ext1;

							if (displayAttributes1)
							{
								utils->console() << "Section " << section.Name << " attributes->" << ::endl;
								for (size_t i = 0; i < section.Attributes.count(); i++)
								{
									utils->console() << section.Attributes.name(i) << ": " << section.Attributes.item(i) << ::endl;
								}
								utils->console() << " " << ::endl;
							}

							if (!xp_WriteBytes(filename, section.Contents))
							{
								OutputError("ERROR:  Unable to write file '%s'", filename.c_str());
							}
							else
							{
								utils->console() << "Successfully wrote '" << filename << " containing " << section.Name << ::endl;
							}
						}
						else
						{
							utils->console() << "Skipped unnamed section" << ::endl;
						}
				}
				}
			}

		}
		return retVal;
	}
	virtual tscrypto::tsCryptoString getCommandName() const override
	{
		return "pem";
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

tsmod::IObject* CreatePemTool()
{
	return dynamic_cast<tsmod::IObject*>(new pemtool());
}
