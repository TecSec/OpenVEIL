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

// ckmtools.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

enum options { OPT_HELP, OPT_OUTPUT, OPT_ALGORITHM, OPT_PASSWORD, OPT_SIGNATURE, OPT_HEX };

static struct tsmod::OptionList GenEccOptions[] = {
	{ "", "VEIL tool genecc options" },
	{ "", "=================================" },
	{ "--help, -h, -?", "This help information." },
	{ "--out=<filename>", "The output file name" },
	{ "-s, --signature", "Create an Ed25519 signature key" },
	{ "-a, --algorithm=<alg>", "The algorithm to use to protect private keys." },
	{ "-p, --password", "Use a password to protect generated keys." },
	{ "-x, --hex", "Output the keys in HEX." },
	{ "", "" },
};

static CSimpleOptA::SOption genEccOptionList[] =
{
	{ OPT_HELP,              "-?",                  SO_NONE },
	{ OPT_HELP,              "-h",                  SO_NONE },
	{ OPT_HELP,              "--help",              SO_NONE },
	{ OPT_OUTPUT,            "--out",               SO_REQ_SEP },
	{ OPT_SIGNATURE,         "-s",                  SO_NONE },
	{ OPT_SIGNATURE,         "--signature",         SO_NONE },
	{ OPT_ALGORITHM,         "-a",                  SO_REQ_SEP },
	{ OPT_ALGORITHM,         "--algorithm",         SO_REQ_SEP },
	{ OPT_PASSWORD,          "-p",                  SO_NONE },
	{ OPT_PASSWORD,          "--password",          SO_NONE },
	{ OPT_HEX,				 "-x",                  SO_NONE },
	{ OPT_HEX,				 "--hex",          SO_NONE },

	SO_END_OF_OPTIONS
};

class genx25519 : public tsmod::IVeilToolCommand, public tsmod::IObject
{
public:
	genx25519()
	{}
	~genx25519()
	{}

	// tsmod::IObject
	virtual void OnConstructionFinished() override
	{
		utils = ::TopServiceLocator()->get_instance<tsmod::IVeilUtilities>("VeilUtilities");
	}

	// Inherited via tsmod::IVeilToolCommand
	virtual tscrypto::tsCryptoString getDescription() const override
	{
		return "Generate X25519 or Ed25519 key";
	}
	virtual int RunCommand(CSimpleOptA & opts) override
	{
		tscrypto::tsCryptoString names;
		int retVal = 1;
		tscrypto::tsCryptoString outputName;
		bool signature = false;
		bool usePassword = false;
		bool useHex = false;
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
				else if (opts.OptionId() == OPT_SIGNATURE)
				{
					signature = true;
				}
				else if (opts.OptionId() == OPT_HEX)
				{
					useHex = true;
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
			if (useHex)
			{
				output = ::TopServiceLocator()->try_get_instance<tsmod::IOutputCollector>("HexOutput");
			}
			else
				output = ::TopServiceLocator()->try_get_instance<tsmod::IOutputCollector>("PemOutput");
			if (!output)
			{
				utils->console() << BoldRed << "ERROR:  " << BoldWhite << "The specified output device is not accessible." << ::endl << ::endl;
				Usage();
				return 1;
			}
		}
		if (!useHex)
		{
			output->usePassword(usePassword);
			if (!output->encryptionAlgName(encryptionAlgName))
			{
				utils->console() << BoldRed << "ERROR:  " << BoldWhite << "The specified algorithm is not valid.  It must be one of the supported symmetric algorithms." << ::endl << ::endl;
				Usage();
				return 1;
			}
		}
		retVal = GenerateX25519Key(signature);
		if (retVal != 0)
			return retVal;

		if (!output->writeToFile(outputName))
			return 1;
		return retVal;
	}
	virtual tscrypto::tsCryptoString getCommandName() const override
	{
		return "genx25519";
	}
protected:
	void Usage()
	{
		utils->Usage(GenEccOptions, sizeof(GenEccOptions) / sizeof(GenEccOptions[0]));
	}
	int GenerateX25519Key(bool signature)
	{
		tscrypto::tsCryptoString keyName = "X25519";
		std::shared_ptr<EccKey> ecc;
		tscrypto::tsCryptoData outputData;

		if (!TSBuildEccKey(tscrypto::tsCryptoData(id_X25519, tscrypto::tsCryptoData::OID), ecc) || !ecc->generateKeyPair(signature))
		{
			utils->console() << BoldRed << "ERROR:  " << BoldWhite << "The system could not generate the requested key." << ::endl << ::endl;
			Usage();
			return 1;
		}

		std::shared_ptr<TlvDocument> doc = TlvDocument::Create();
		_POD_Pkcs8EccPrivateKey data;
		_POD_Pkcs8EccCurve curve;
		_POD_Pkcs8EccPubKeyPart pub;
		std::shared_ptr<AlgorithmInfo> info = std::dynamic_pointer_cast<AlgorithmInfo>(ecc);

		doc->DocumentElement()->AppendChild(doc->CreateOIDNode(tscrypto::tsCryptoData(info->AlgorithmOID(), tscrypto::tsCryptoData::OID)));

		curve.set_parameters(info->AlgorithmOID());
		data.set_curve(curve);
		data.set_privateKey(ecc->get_PrivateValue());
		pub.get_value().bits(ecc->get_Point());
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
	std::shared_ptr<tsmod::IOutputCollector> output;
	std::shared_ptr<tsmod::IVeilUtilities> utils;
};

tsmod::IObject* CreateGenX25519()
{
	return dynamic_cast<tsmod::IObject*>(new genx25519());
}

