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

enum options { OPT_HELP, OPT_KEYSIZE, OPT_OUTPUT, OPT_ALGORITHM, OPT_PASSWORD, OPT_DSA_PARAMETERFILE };

struct OptionList GenDhParamsOptions[] = {
	{ "", "VEIL tool gendsaparams options" },
	{ "", "=================================" },
	{ "--help, -h, -?", "This help information." },
	{ "--out=<filename>", "The output file name" },
	{ "-k, --keysize=<filename>", "The size in bits of the generated key" },
	{ "", "" },
};
CSimpleOptA::SOption genDhParamsOptionList[] =
{
	{ OPT_HELP,              "-?",                  SO_NONE },
	{ OPT_HELP,              "-h",                  SO_NONE },
	{ OPT_HELP,              "--help",              SO_NONE },
	{ OPT_OUTPUT,            "--out",               SO_REQ_SEP },
	{ OPT_KEYSIZE,           "-k",                  SO_REQ_SEP },
	{ OPT_KEYSIZE,           "--keysize",           SO_REQ_SEP },

	SO_END_OF_OPTIONS
};

class gendhparameters : public IVeilToolCommand, public tsmod::IObject
{
public:
	gendhparameters()
	{}
	~gendhparameters()
	{}
	
	// tsmod::IObject
	virtual void OnConstructionFinished()
	{
		utils = ::TopServiceLocator()->get_instance<IVeilUtilities>("VeilUtilities");
	}

	// Inherited via IVeilToolCommand
	virtual tscrypto::tsCryptoString getDescription() const override
	{
		return "Generate Diffie-Hellman Parameterset";
	}
	virtual int RunCommand(CSimpleOptA & opts) override
	{
		tscrypto::tsCryptoString names;
		int retVal = 1;
		tscrypto::tsCryptoString outputName;
		int keysize = 0;

		opts.Init(opts.FileCount(), opts.Files(), genDhParamsOptionList, SO_O_NOERR | SO_O_USEALL | SO_O_ICASE);
		while (opts.Next())
		{
			if (opts.LastError() == SO_SUCCESS)
			{
				if (opts.OptionId() == OPT_HELP)
				{
					Usage();
					return 0;
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
				else if (opts.OptionId() == OPT_KEYSIZE)
				{
					keysize = TsStrToInt(opts.OptionArg());
				}
			}
			else
			{
				Usage();
				return 1;
			}
		}
		if (!output)
		{
			output = ::TopServiceLocator()->try_get_instance<IOutputCollector>("PemOutput");
			if (!output)
			{
				utils->console() << BoldRed << "ERROR:  " << BoldWhite << "The specified output device is not accessible." << ::endl << ::endl;
				Usage();
				return 1;
			}
		}

		retVal = GenerateDsaParameters(keysize);
		if (retVal != 0)
			return retVal;

		if (!output->writeToFile(outputName))
			return 1;
		return retVal;
	}
	virtual tscrypto::tsCryptoString getCommandName() const override
	{
		return "gendsaparams";
	}
protected:
	void Usage()
	{
		utils->Usage(GenDhParamsOptions, sizeof(GenDhParamsOptions) / sizeof(GenDhParamsOptions[0]));
	}
	int GenerateDsaParameters(int keysize)
	{
		std::shared_ptr<DhParameters> params;
		tscrypto::tsCryptoData outputData;

		switch (keysize)
		{
		case 1024:
			break;
		case 0:
		case 2048:
			keysize = 2048;
			break;
		case 3072:
			break;
		default:
			utils->console() << BoldRed << "ERROR:  " << BoldWhite << "DSA key sizes are 1024, 2048 or 3072." << ::endl << ::endl;
			Usage();
			return 1;
		}
		if (!TSBuildDhParams(params) || !params->generateProbablePrimeParameters("SHA512", keysize, keysize == 1024 ? 160 : 256, 512, tscrypto::tsCryptoData(), 0))
		{
			utils->console() << BoldRed << "ERROR:  " << BoldWhite << "Unable to generate the parameterset." << ::endl << ::endl;
			Usage();
			return 1;
		}
		PemDsaParameters data;

		data.set_p(params->get_prime());
		data.set_q(params->get_subprime());
		data.set_g(params->get_generator());

		if (!data.Encode(outputData))
		{
			utils->console() << BoldRed << "ERROR:  " << BoldWhite << "The system could not encode the requested key." << ::endl << ::endl;
			Usage();
			return 1;
		}

		return output->AddOutputData(outputData, "DSA PARAMETERS", false);
	}
protected:
	std::shared_ptr<IOutputCollector> output;
	std::shared_ptr<IVeilUtilities> utils;
};

tsmod::IObject* CreateGenDsaParameters()
{
	return dynamic_cast<tsmod::IObject*>(new gendhparameters());
}

















struct OptionList GenDhKeyOptions[] = {
	{ "", "VEIL tool gendsa options" },
	{ "", "=================================" },
	{ "--help, -h, -?", "This help information." },
	{ "--out=<filename>", "The output file name" },
	{ "-k, --keysize=<filename>", "The size in bits of the generated key" },
	{ "-a, --algorithm=<alg>", "The algorithm to use to protect private keys." },
	{ "-p, --password", "Use a password to protect generated keys." },
	{ "-d, --dhparams=<filename>", "Specify the DH/DSA parameterset to use for DSA key generation." },
	{ "", "" },
};

CSimpleOptA::SOption genDhKeyOptionList[] =
{
	{ OPT_HELP,              "-?",                  SO_NONE },
	{ OPT_HELP,              "-h",                  SO_NONE },
	{ OPT_HELP,              "--help",              SO_NONE },
	{ OPT_OUTPUT,            "--out",               SO_REQ_SEP },
	{ OPT_KEYSIZE,           "-k",                  SO_REQ_SEP },
	{ OPT_KEYSIZE,           "--keysize",           SO_REQ_SEP },
	{ OPT_ALGORITHM,         "-a",                  SO_REQ_SEP },
	{ OPT_ALGORITHM,         "--algorithm",         SO_REQ_SEP },
	{ OPT_PASSWORD,          "-p",                  SO_NONE },
	{ OPT_PASSWORD,          "--password",          SO_NONE },
	{ OPT_DSA_PARAMETERFILE, "-d",                  SO_REQ_SEP },
	{ OPT_DSA_PARAMETERFILE, "--dhparams",          SO_REQ_SEP },

	SO_END_OF_OPTIONS
};
class gendhkey : public IVeilToolCommand, public tsmod::IObject
{
public:
	gendhkey()
	{}
	~gendhkey()
	{}

	// tsmod::IObject
	virtual void OnConstructionFinished()
	{
		utils = ::TopServiceLocator()->get_instance<IVeilUtilities>("VeilUtilities");
	}

	// Inherited via IVeilToolCommand
	virtual tscrypto::tsCryptoString getDescription() const override
	{
		return "Generate Diffie-Hellman Key";
	}
	virtual int RunCommand(CSimpleOptA & opts) override
	{
		tscrypto::tsCryptoString names;
		int retVal = 1;
		tscrypto::tsCryptoString outputName;
		int keysize = 0;
		bool usePassword = false;
		tscrypto::tsCryptoString encryptionAlgName;

		opts.Init(opts.FileCount(), opts.Files(), genDhKeyOptionList, SO_O_NOERR | SO_O_USEALL | SO_O_ICASE);
		while (opts.Next())
		{
			if (opts.LastError() == SO_SUCCESS)
			{
				if (opts.OptionId() == OPT_HELP)
				{
					Usage();
					return 0;
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
				else if (opts.OptionId() == OPT_KEYSIZE)
				{
					keysize = TsStrToInt(opts.OptionArg());
				}
				else if (opts.OptionId() == OPT_ALGORITHM)
				{
					encryptionAlgName = opts.OptionArg();
				}
				else if (opts.OptionId() == OPT_PASSWORD)
				{
					usePassword = true;
				}
				else if (opts.OptionId() == OPT_DSA_PARAMETERFILE)
				{
					dhParameterFile = opts.OptionArg();
					if (dhParameterFile.size() == 0)
					{
						Usage();
						return 1;
					}
				}
			}
			else
			{
				Usage();
				return 1;
			}
		}
		if (!output)
		{
			output = ::TopServiceLocator()->try_get_instance<IOutputCollector>("PemOutput");
			if (!output)
			{
				utils->console() << BoldRed << "ERROR:  " << BoldWhite << "The specified output device is not accessible." << ::endl << ::endl;
				Usage();
				return 1;
			}
		}
		output->usePassword(usePassword);
		if (!output->encryptionAlgName(encryptionAlgName))
		{
			utils->console() << BoldRed << "ERROR:  " << BoldWhite << "The specified algorithm is not valid.  It must be one of the supported symmetric algorithms." << ::endl << ::endl;
			Usage();
			return 1;
		}

		retVal = GenerateDsaKey(keysize);
		if (retVal != 0)
			return retVal;

		if (!output->writeToFile(outputName))
			return 1;
		return retVal;
	}
	virtual tscrypto::tsCryptoString getCommandName() const override
	{
		return "gendsa";
	}
protected:
	void Usage()
	{
		utils->Usage(GenDhKeyOptions, sizeof(GenDhKeyOptions) / sizeof(GenDhKeyOptions[0]));
	}
	bool loadDsaParameterset(const tscrypto::tsCryptoString& filename, std::shared_ptr<DhParameters> &parameters)
	{
		TSNamedBinarySectionList sections;

		if (!xp_ReadArmoredFile(filename, sections))
		{
			return false;
		}
		auto it = std::find_if(sections->begin(), sections->end(), [](TSNamedBinarySection& section) {
			return TsStriCmp(section.Name, "DSA PARAMETERS") == 0;
		});
		if (it == sections->end())
			return false;

		PemDsaParameters params;

		if (!params.Decode(it->Contents))
		{
			return false;
		}
		if (!TSBuildDhParams(parameters))
			return false;

		if (!parameters->set_prime(params.get_p()) ||
			!parameters->set_subprime(params.get_q()) ||
			!parameters->set_generator(params.get_g()))
		{
			parameters.reset();
			return false;
		}
		return true;
	}

	int GenerateDsaKey(int keysize)
	{
		tscrypto::tsCryptoString keyName = "KEY-DH";
		std::shared_ptr<DhParameters> parameters;
		std::shared_ptr<DhKey> key;
		std::shared_ptr<AsymmetricKey> asym;
		tscrypto::tsCryptoData outputData;

		if (!loadDsaParameterset(dhParameterFile, parameters))
		{
			switch (keysize)
			{
			case 1024:
				break;
			case 0:
			case 2048:
				keysize = 2048;
				break;
			case 3072:
				break;
			default:
				utils->console() << BoldRed << "ERROR:  " << BoldWhite << "DSA key sizes are 1024, 2048 or 3072." << ::endl << ::endl;
				Usage();
				return 1;
			}
			if (!TSBuildDhParams(parameters) || !parameters->generateProbablePrimeParameters("SHA512", keysize, keysize == 1024 ? 160 : 256, 512, tscrypto::tsCryptoData(), 0))
			{
				utils->console() << BoldRed << "ERROR:  " << BoldWhite << "Unable to generate the parameterset." << ::endl << ::endl;
				Usage();
				return 1;
			}
		}

		if (!(asym = parameters->generateKeyPair()) || !(key = std::dynamic_pointer_cast<DhKey>(asym)))
		{
			utils->console() << BoldRed << "ERROR:  " << BoldWhite << "Unable to generate the key pair." << ::endl << ::endl;
			Usage();
			return 1;
		}

		PemDsaPrivateKey data;

		data.set_p(parameters->get_prime());
		data.set_q(parameters->get_subprime());
		data.set_g(parameters->get_generator());
		data.set_y(key->get_PublicKey());
		data.set_x(key->get_PrivateKey());

		if (!data.Encode(outputData))
		{
			utils->console() << BoldRed << "ERROR:  " << BoldWhite << "The system could not encode the requested key." << ::endl << ::endl;
			Usage();
			return 1;
		}

		return output->AddOutputData(outputData, "DSA PRIVATE KEY", false);
	}
protected:
	std::shared_ptr<IOutputCollector> output;
	tscrypto::tsCryptoString dhParameterFile;
	std::shared_ptr<IVeilUtilities> utils;
};
tsmod::IObject* CreateGenDsaKey()
{
	return dynamic_cast<tsmod::IObject*>(new gendhkey());
}

