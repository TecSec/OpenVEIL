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

static struct OptionList GenEccOptions[] = {
	{ "", "VEIL tool genecc options" },
	{ "", "=================================" },
	{ "--help, -h, -?", "This help information." },
	{ "--out=<filename>", "The output file name" },
	{ "-k, --keysize=<filename>", "The size in bits of the generated key" },
	{ "-a, --algorithm=<alg>", "The algorithm to use to protect private keys." },
	{ "-p, --password", "Use a password to protect generated keys." },
	{ "", "" },
};

static CSimpleOptA::SOption genEccOptionList[] =
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

class genecc : public IVeilToolCommand, public tsmod::IObject
{
public:
	genecc()
	{}
	~genecc()
	{}

	// tsmod::IObject
	virtual void OnConstructionFinished()
	{
		utils = ::TopServiceLocator()->get_instance<IVeilUtilities>("VeilUtilities");
	}

	// Inherited via IVeilToolCommand
	virtual tscrypto::tsCryptoString getDescription() const override
	{
		return "Generate ECC key";
	}
	virtual int RunCommand(CSimpleOptA & opts) override
	{
		tscrypto::tsCryptoString names;
		int retVal = 1;
		tscrypto::tsCryptoString outputName;
		int keysize = 0;
		bool usePassword = false;
		tscrypto::tsCryptoString encryptionAlgName;

		opts.Init(opts.FileCount(), opts.Files(), genEccOptionList, SO_O_NOERR | SO_O_USEALL | SO_O_ICASE);
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

		retVal = GenerateEccKey(keysize);
		if (retVal != 0)
			return retVal;

		if (!output->writeToFile(outputName))
			return 1;
		return retVal;
	}
	virtual tscrypto::tsCryptoString getCommandName() const override
	{
		return "genecc";
	}
protected:
	void Usage()
	{
		utils->Usage(GenEccOptions, sizeof(GenEccOptions) / sizeof(GenEccOptions[0]));
	}
	int GenerateEccKey(int keysize)
	{
		tscrypto::tsCryptoString keyName = "KEY-";
		std::shared_ptr<EccKey> ecc;
		tscrypto::tsCryptoData outputData;

		switch (keysize)
		{
		case 0:
		case 256:
			keysize = 256;
			break;
		case 384:
			break;
		case 521:
			break;
		default:
			utils->console() << BoldRed << "ERROR:  " << BoldWhite << "ECC key sizes are 256, 384 or 521." << ::endl << ::endl;
			Usage();
			return 1;
		}
		if (!TSGenerateECCKeysBySize(keysize, ecc))
		{
			utils->console() << BoldRed << "ERROR:  " << BoldWhite << "The system could not generate the requested key." << ::endl << ::endl;
			Usage();
			return 1;
		}

		std::shared_ptr<TlvDocument> doc = TlvDocument::Create();
		Pkcs8EccPrivateKey data;
		Pkcs8EccCurve curve;
		Pkcs8EccPubKeyPart pub;
		std::shared_ptr<AlgorithmInfo> info = std::dynamic_pointer_cast<AlgorithmInfo>(ecc);

		doc->DocumentElement()->AppendChild(doc->CreateOIDNode(tscrypto::tsCryptoData(info->AlgorithmOID(), tscrypto::tsCryptoData::OID)));

		curve._parameters.oidString(info->AlgorithmOID());
		data.set_curve(curve);
		data.set_privateKey(ecc->get_PrivateValue());
		pub._value.bits(ecc->get_Point());
		data.set_publicKey(pub);

		if (!data.Encode(outputData))
		{
			utils->console() << BoldRed << "ERROR:  " << BoldWhite << "The system could not encode the requested key." << ::endl << ::endl;
			Usage();
			return 1;
		}

		tscrypto::tsCryptoData paramData = doc->DocumentElement()->InnerData();
		
		if (output->AddOutputData(paramData, "EC PARAMETERS", false) != 0)
			return 1;
		return output->AddOutputData(outputData, "EC PRIVATE KEY", true);
	}
protected:
	std::shared_ptr<IOutputCollector> output;
	std::shared_ptr<IVeilUtilities> utils;
};

tsmod::IObject* CreateGenEcc()
{
	return dynamic_cast<tsmod::IObject*>(new genecc());
}

