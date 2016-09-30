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

enum options { OPT_HELP, OPT_KEYSIZE, OPT_OUTPUT, OPT_ALGORITHM, OPT_PASSWORD };

struct tsmod::OptionList GenRsaOptions[] = {
	{ "", "VEIL tool genrsa options" },
	{ "", "=================================" },
	{ "--help, -h, -?", "This help information." },
	{ "--out=<filename>", "The output file name" },
	{ "-k, --keysize=<filename>", "The size in bits of the generated key" },
	{ "-a, --algorithm=<alg>", "The algorithm to use to protect private keys." },
	{ "-p, --password", "Use a password to protect generated keys." },
	{ "", "" },
};

CSimpleOptA::SOption genRsaOptionList[] =
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

	SO_END_OF_OPTIONS
};

class genrsa : public tsmod::IVeilToolCommand, public tsmod::IObject
{
public:
	genrsa()
	{}
	~genrsa()
	{}

	// tsmod::IObject
	virtual void OnConstructionFinished() override
	{
		utils = ::TopServiceLocator()->get_instance<tsmod::IVeilUtilities>("VeilUtilities");
	}

	// Inherited via tsmod::IVeilToolCommand
	virtual tscrypto::tsCryptoString getDescription() const override
	{
		return "Generate RSA key";
	}
	virtual int RunCommand(CSimpleOptA & opts) override
	{
		tscrypto::tsCryptoString names;
		int retVal = 1;
		tscrypto::tsCryptoString outputName;
		int keysize = 0;
		bool usePassword = false;
		tscrypto::tsCryptoString encryptionAlgName;

		opts.Init(opts.FileCount(), opts.Files(), genRsaOptionList, SO_O_NOERR | SO_O_USEALL | SO_O_ICASE);
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
			}
			else
			{
				Usage();
				return 1;
			}
		}
		if (!output)
		{
			output = ::TopServiceLocator()->try_get_instance<tsmod::IOutputCollector>("PemOutput");
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

		retVal = GenerateRsaKey(keysize);
		if (retVal != 0)
			return retVal;

		if (!output->writeToFile(outputName))
			return 1;
		return retVal;
	}
	virtual tscrypto::tsCryptoString getCommandName() const override
	{
		return "genrsa";
	}
protected:
	void Usage()
	{
		utils->Usage(GenRsaOptions, sizeof(GenRsaOptions) / sizeof(GenRsaOptions[0]));
	}
	int GenerateRsaKey(int keysize)
	{
		tscrypto::tsCryptoString keyName = "KEY-RSA";
		std::shared_ptr<RsaKey> rsa;
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
			utils->console() << BoldRed << "ERROR:  " << BoldWhite << "RSA key sizes are 1024, 2048 or 3072." << ::endl << ::endl;
			Usage();
			return 1;
		}
		rsa = std::dynamic_pointer_cast<RsaKey>(CryptoFactory(keyName));
		if (!rsa)
		{
			utils->console() << BoldRed << "ERROR:  " << BoldWhite << "RSA keys are currently not supported." << ::endl << ::endl;
			Usage();
			return 1;
		}
		if (!rsa->generateKeyPair(_RSA_Key_Gen_Type::rsakg_Probable_Composite, "HASH-SHA512", keysize))
		{
			utils->console() << BoldRed << "ERROR:  " << BoldWhite << "The system could not generate the requested key." << ::endl << ::endl;
			Usage();
			return 1;
		}
		_POD_Pkcs8RSAPrivateKey data;

		data.set_modulus(rsa->get_PublicModulus());
		data.set_publicExponent(rsa->get_PublicModulus());
		data.set_privateExponent(rsa->get_PrivateExponent());
		data.set_prime1(rsa->get_p());
		data.set_prime2(rsa->get_q());
		data.set_exponent1(rsa->get_dp());
		data.set_exponent2(rsa->get_dq());
		data.set_coefficient(rsa->get_qInv());

		if (!data.Encode(outputData))
		{
			utils->console() << BoldRed << "ERROR:  " << BoldWhite << "The system could not encode the requested key." << ::endl << ::endl;
			Usage();
			return 1;
		}

		return output->AddOutputData(outputData, "RSA PRIVATE KEY", true);
	}
protected:
	std::shared_ptr<tsmod::IOutputCollector> output;
	std::shared_ptr<tsmod::IVeilUtilities> utils;
};

tsmod::IObject* CreateGenRsa()
{
	return dynamic_cast<tsmod::IObject*>(new genrsa());
}


