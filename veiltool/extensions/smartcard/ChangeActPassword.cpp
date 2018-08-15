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

enum {
	OPT_HELP = 0, 
};

#define USER_SALT_LEN 32
#define PIN_REF_USER 0x10
#define USER_PIN_INFO_LEN 120
#define MAX_PASSWORD_LEN 64
const tscrypto::tsCryptoData gActivationAID("A0 00 00 04 45 00 0D 01 01 FF FF 01 00 00 00 02", tscrypto::tsCryptoData::HEX);

static const struct tsmod::OptionList options[] = {
	{ "", "VEIL SMARTCARD CHANGE PASSWORD commands" },
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


class ChangeActPasswordTool : public tsmod::IVeilToolCommand, public tsmod::IObject
{
public:
	ChangeActPasswordTool() : gSmartCardDone(true, false)
	{
    }
	~ChangeActPasswordTool()
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
		return "Change the Server Activation smart card password";
	}
	virtual int RunCommand(CSimpleOptA & opts) override
	{
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

		std::cout << "Insert the smart card that you want to change the server activation password." << std::endl;

		gSmartCardDone.Reset();

		uint32_t cookie = scMan->registerChangeConsumer(&mySmartcardChanges, this);
		auto cleanup1 = finally([&cookie]() {scMan->unregisterChangeConsumer(cookie); });
		gSmartCardDone.WaitForEvent(INFINITE);
		return 0;

	}
	virtual tscrypto::tsCryptoString getCommandName() const override
	{
		return "activation";
	}
protected:
	void Usage()
	{
		utils->Usage(options, sizeof(options) / sizeof(options[0]));
	}
	void ChangeServerActivationPassword(const tscrypto::tsCryptoString& readerName)
	{
		tscrypto::tsCryptoData cardcmd("00 A4 04 00", tscrypto::tsCryptoData::HEX);
		TSWORKSPACE card = NULL;
        const TSISmartCardConnection* cardDesc = nullptr;
		tscrypto::tsCryptoString tokenName;
		uint8_t outData[280];
        uint32_t outDataLen;
		uint32_t sw;
		tscrypto::tsCryptoString prompt;
		tscrypto::tsCryptoString oldPin, newPin, confirmPin;
		tscrypto::tsCryptoData oldPinInfo;
		tscrypto::tsCryptoData authKey;
		tscrypto::tsCryptoData newSalt;
		tscrypto::tsCryptoData data, key2, mac2, kek;
		xp_console ts_out;

        card = tsCreateWorkspaceForAlgorithm("SMARTCARD_CONNECTION");
        cardDesc = TSWorker(TSISmartCardConnection, card);
        if (cardDesc == nullptr)
            return;

        if (!cardDesc->connectToReader(card, readerName.c_str()))
		{
			std::cout << "ERROR:  Unable to connect to the smart card." << std::endl;
			gSmartCardDone.Set();
            tsFreeWorkspace(&card);
			return;
		}
        auto discon = finally([&card, &outData]() { tsFreeWorkspace(&card); memset(outData, 0, sizeof(outData)); });

		cardcmd << (uint8_t)gActivationAID.size() << gActivationAID;
		{
			SmartCardTransaction trans(card);

            outDataLen = sizeof(outData);
			if (!cardDesc->sendCommand(card, cardcmd.c_str(), (uint32_t)cardcmd.size(), 0, outData, &outDataLen, &sw) || sw != 0x9000)
			{
				std::cout << "ERROR:  That card does not contain the activation information for this enterprise." << std::endl;
				gSmartCardDone.Set();
				return;
			}
			tokenName = GetTokenName(card);
		}

		do
		{
			prompt << "Enter the old password for '" << tokenName << "' (Leave empty to cancel)";

			ts_out.GetPin(oldPin, 64, prompt);

			std::cout << std::endl;

			oldPin.Trim();
			if (oldPin.size() == 0)
			{
				std::cout << "Cancelling the process." << std::endl;
				gSmartCardDone.Set();
				return;
			}

			prompt.clear();
			prompt << "Enter the new password:  ";

			ts_out.GetPin(newPin, 64, prompt);

			std::cout << std::endl;

			newPin.Trim();
			if (newPin.size() == 0)
			{
				std::cout << "Cancelling the process." << std::endl;
				gSmartCardDone.Set();
				return;
			}

			prompt.clear();
			prompt << "Enter the new password again for confirmation:  ";

			ts_out.GetPin(confirmPin, 64, prompt);

			std::cout << std::endl;

			confirmPin.Trim();
			if (confirmPin.size() == 0)
			{
				std::cout << "Cancelling the process." << std::endl;
				gSmartCardDone.Set();
				return;
			}
			if (newPin != confirmPin)
				std::cout << "The pins do not match" << std::endl;
			else if (newPin.size() < 6)
				std::cout << "The new pin does not match the password policy" << std::endl;
		} while (newPin != confirmPin || newPin.size() < 6);

		if (!(TSGenerateRandom(newSalt, USER_SALT_LEN)))
		{
			std::cout << "Unable to generate the new salt value." << std::endl;
			return;
		}

		// The next piece is to authenticate to the card and retrieve the server pin
		std::cout << "Authenticating to the card" << std::endl;

		{
			SmartCardTransaction trans(card);
			uint8_t outData[280];
            uint32_t outDataLen = sizeof(outData);
            TSWORKSPACE channel = NULL;
            bool retVal;


			if (!cardDesc->sendCommand(card, cardcmd.c_str(), (uint32_t)cardcmd.size(), 0, outData, &outDataLen, &sw) || sw != 0x9000)
			{
				std::cout << "ERROR:  That card does not contain the activation information for this enterprise." << std::endl;
                memset(outData, 0, sizeof(outData));
				return;
			}
			if (!ExternalAuthCkm(card, PIN_REF_USER, oldPin, authKey, kek))
			{
				std::cout << "ERROR:  The specified pin did not work." << std::endl;
                memset(outData, 0, sizeof(outData));
				return;
			}
            channel = cardDesc->getSecureChannel(card);
			// Retrieve the server pin
            outDataLen = sizeof(outData);
            retVal = cardDesc->sendCommand(card, tscrypto::tsCryptoData("00A40000020030", tscrypto::tsCryptoData::HEX).c_str(), 7, 0, outData, &outDataLen, &sw) && sw == 0x9000;
            outDataLen = sizeof(outData);
            retVal = retVal && (cardDesc->sendCommand(card, tscrypto::tsCryptoData("00B0000000", tscrypto::tsCryptoData::HEX).c_str(), 5, 0, outData, &outDataLen, &sw) && sw == 0x9000);
				if (!channel)
				{
                const TSISmartCardServerSecureChannel* desc = TSWorker(TSISmartCardServerSecureChannel, channel);
                desc->finish(channel);
				}
			if (!retVal)
			{
                memset(outData, 0, sizeof(outData));
				std::cout << "ERROR:  Unable to retrieve the server authentication." << std::endl;
				return;
			}
			oldPinInfo.assign(outData, outDataLen);
            memset(outData, 0, sizeof(outData));
		}
		//
		// Now compute the new key information and insert it into the Token
		//
		data = newPin;
		data.resize(MAX_PASSWORD_LEN, (uint8_t)0xff);

		if (!(TSCreatePBEKeyAndMac("HMAC-SHA512", data.ToUtf8String(), newSalt, 1000, 96, key2, mac2)))
		{
			std::cout << "ERROR:  Failed to create the key" << std::endl;
			return;
		}

		TsDateStruct_t tm;
		tscrypto::tsCryptoData encKey;

		//
		// Now we need to extract the old Encryption Key and re-encrypt it
		//
		tscrypto::tsCryptoData key1a, key2a;

		key1a = authKey;
		key2a = key2;
		key1a.erase(0, 64);
		key2a.erase(0, 64);

		if (!(TSUnwrap(key1a, kek, encKey)) || !(TSWrap(key2a, encKey, kek)))
		{
			std::cout << "ERROR:  Failed to re-encrypt the key" << std::endl;
			return;
		}
		//#ifdef _DEBUG
		//		CkmDebugHEXDUMP(DBG_CRYPTO, "RKEK", encKey.size(), encKey.c_str());
		//		CkmDebugHEXDUMP(DBG_CRYPTO, "EncKEK", Kek.size(), Kek.c_str());
		//#endif

		key2 += newSalt;
        tsGetNowInGMT(&tm);
		tscrypto::tsCryptoString creationDate;
		TSTMToZuluString(tm, creationDate);
		creationDate.resize(16);
		key2 += creationDate;
		key2 += kek;

		// Now authenticate to the card again and unwrap this value
		{
			SmartCardTransaction trans(card);
            uint8_t outData[280];
            uint32_t outDataLen = sizeof(outData);
			TSWORKSPACE channel = NULL;


            if (!cardDesc->sendCommand(card, cardcmd.c_str(), (uint32_t)cardcmd.size(), 0, outData, &outDataLen, &sw) || sw != 0x9000)
			{
                memset(outData, 0, sizeof(outData));
				std::cout << "ERROR:  That card does not contain the activation information for this enterprise." << std::endl;
				return;
			}
			if (StartSecureChannel(card, authKey.substring(0, 32), authKey.substring(32, 32), authKey.substring(64, 32), 3, 0x60, 0x33, PIN_REF_USER, 0) != 0x9000)
			{
                memset(outData, 0, sizeof(outData));
				std::cout << "ERROR:  The specified pin did not work." << std::endl;
				return;
			}
            channel = cardDesc->getSecureChannel(card);

			cardcmd.FromHexString("00 24 01 10");
			cardcmd << (uint8_t)key2.size();
			cardcmd << key2;

            outDataLen = sizeof(outData);
            if (!cardDesc->sendCommand(card, cardcmd.c_str(), (uint32_t)cardcmd.size(), 0, outData, &outDataLen, &sw) || sw != 0x9000)
            {
				// TODO:  This may be the bug in 1.002 ckm applet where ChangeRef fails but ResetRetry works.  Try it

				key2.insert(0, (uint8_t)5); // TODO:  Should get this from the password policy
				key2.insert(0, (uint8_t)5);

				cardcmd.FromHexString("00 2C 02 10");
				cardcmd << (uint8_t)key2.size();
				cardcmd << key2;

                outDataLen = sizeof(outData);
                if (!cardDesc->sendCommand(card, cardcmd.c_str(), (uint32_t)cardcmd.size(), 0, outData, &outDataLen, &sw) || sw != 0x9000)
                {
                    memset(outData, 0, sizeof(outData));
					std::cout << "ERROR:  Unable to change reference data" << std::endl;
					return;
				}
			}
			if (!channel)
			{
                const TSISmartCardServerSecureChannel* desc = TSWorker(TSISmartCardServerSecureChannel, channel);

                desc->finish(channel);
			}
            memset(outData, 0, sizeof(outData));
		}
		gSmartCardDone.Set();
	}
	tscrypto::tsCryptoString GetTokenName(TSWORKSPACE card)
	{
		uint8_t outData[280];
        uint32_t outDataLen = sizeof(outData);
		uint32_t sw;
        const TSISmartCardConnection* cardDesc = TSWorker(TSISmartCardConnection, card);

		if (card == NULL)
			return "";

        if (!cardDesc->sendCommand(card, tscrypto::tsCryptoData("00 A4 00 00 02 60 00", tscrypto::tsCryptoData::HEX).c_str(), 7, 0, outData, &outDataLen, &sw) || sw != 0x9000)
        {
            memset(outData, 0, sizeof(outData));
            return "";
        }
        outDataLen = sizeof(outData);
        if (!cardDesc->sendCommand(card, tscrypto::tsCryptoData("00 B0 00 00 00", tscrypto::tsCryptoData::HEX).c_str(), 5, 0, outData, &outDataLen, &sw) || sw != 0x9000)
        {
            memset(outData, 0, sizeof(outData));
            return "";
        }

        tsStrTrim((char*)outData, " \t\n\r");
		return (const char*)outData;
	}
	bool ExternalAuthCkm(TSWORKSPACE connection, uint8_t reference, const tscrypto::tsCryptoString &in_pin, tscrypto::tsCryptoData& authKey, tscrypto::tsCryptoData& kek)
	{
		tscrypto::tsCryptoData challenge;
		tscrypto::tsCryptoData iv;
		tscrypto::tsCryptoData command;
		//bool needsNewChallenge = false;
		//		size_t sw;

		//
		// We need to compute the key and perform a mutual authentication
		//
		tscrypto::tsCryptoData salt;
		tscrypto::tsCryptoData mac;
		tscrypto::tsCryptoData data;
		tscrypto::tsCryptoData pin(in_pin);
		tscrypto::tsCryptoData key;

		if (reference == PIN_REF_USER)
		{
			if (getUserSaltAndKek(connection, salt, kek))
			{
				//needsNewChallenge = true;
			}

			if (salt.size() != 32)
				return false;

			pin.resize(MAX_PASSWORD_LEN, (uint8_t)0xff);
			if (!(TSCreatePBEKeyAndMac("HMAC-SHA512", pin.ToUtf8String(), salt, 1000, 96, key, mac)))
				return false;
		}
		else
		{
			return false;
		}

		authKey = key;
		if (StartSecureChannel(connection, key.substring(0, 32), key.substring(32, 32), key.substring(64, 32), 3, 0x60, 0x33, reference, 0) != 0x9000)
			return false;

		return true;
	}
	int StartSecureChannel(TSWORKSPACE connection, const tscrypto::tsCryptoData& encKey, const tscrypto::tsCryptoData& macKey, const tscrypto::tsCryptoData& kek, uint8_t SCPVersion, uint8_t SCPLevel, uint8_t SecurityLevel, uint8_t keyRef, uint8_t keyVersion)
	{
		uint8_t outdata[280];
        uint32_t outdataLen = sizeof(outdata);
		uint32_t sw;
		TSWORKSPACE channel = NULL;
        const TSISmartCardServerSecureChannel* desc = nullptr;
        const TSISmartCardConnection* cardDesc = TSWorker(TSISmartCardConnection, connection);

		if (connection == NULL)
			return 0x6F00;

        channel = cardDesc->getSecureChannel(connection);
        desc = TSWorker(TSISmartCardServerSecureChannel, channel);

		if (!channel)
		{
			if (!(channel = tsCreateWorkspaceForAlgorithm("SECURE_CHANNEL_SERVER")))
				return 0x6F80;
            cardDesc->setSecureChannel(connection, channel);
            desc = TSWorker(TSISmartCardServerSecureChannel, channel);
		}
        desc->setSCPVersion(channel, SCPVersion);
        desc->setSCPLevel(channel, SCPLevel);
        desc->finish(channel);

		uint8_t cmd[260];
        uint32_t cmdLen = sizeof(cmd);

        if (!desc->computeHostChallengeCommand(channel, keyRef, cmd, &cmdLen))
			return 0x6F00;

		if (keyRef != 0 && keyVersion != 0)
		{
			cmd[2] = keyVersion;
			cmd[3] = keyRef;
		}

        if (!cardDesc->sendCommand(connection, cmd, cmdLen, 0, outdata, &outdataLen, &sw) || sw != 0x9000)
		{
            memset(outdata, 0, sizeof(outdata));
            return (int)sw;
		}
        desc->setBaseKeys(channel, encKey.c_str(), (uint32_t)encKey.size(), macKey.c_str(), (uint32_t)macKey.size(), kek.c_str(), (uint32_t)kek.size());

        cmdLen = sizeof(cmd);
        if (!desc->computeAuthentication(channel, outdata, outdataLen, SecurityLevel, cmd, &cmdLen))
        {
            memset(outdata, 0, sizeof(outdata));
            return 0x6F00;
        }

        outdataLen = sizeof(outdata);
        if (!cardDesc->sendCommand(connection, cmd, cmdLen, 0, outdata, &outdataLen, &sw) || sw != 0x9000)
		{
            memset(outdata, 0, sizeof(outdata));
            return (int)sw;
		}
        memset(outdata, 0, sizeof(outdata));
        desc->activateChannel(channel);
		return (int)sw;
	}
	bool getUserSaltAndKek(TSWORKSPACE connection, tscrypto::tsCryptoData &salt, tscrypto::tsCryptoData& kek)
	{
        uint8_t outData[280];
        uint32_t outDataLen = sizeof(outData);
        uint32_t sw;
        const TSISmartCardConnection* cardDesc = TSWorker(TSISmartCardConnection, connection);

		salt.clear();

        if (!cardDesc->sendCommand(connection, tscrypto::tsCryptoData("00A40000020030", tscrypto::tsCryptoData::HEX).c_str(), 7, 0, outData, &outDataLen, &sw) || sw != 0x9000)
		{
            memset(outData, 0, sizeof(outData));
			return false;
		}
        outDataLen = sizeof(outData);
        if (!cardDesc->sendCommand(connection, tscrypto::tsCryptoData("00B0000000", tscrypto::tsCryptoData::HEX).c_str(), 5, 0, outData, &outDataLen, &sw) || sw != 0x9000)
		{
            memset(outData, 0, sizeof(outData));
			return false;
		}
		salt.assign(outData, USER_SALT_LEN);
		kek.assign(outData + 48, outDataLen - 48);
        memset(outData, 0, sizeof(outData));
		return salt.size() == USER_SALT_LEN;
	}
protected:
	std::shared_ptr<tsmod::IVeilUtilities> utils;
	tscrypto::CryptoEvent gSmartCardDone;

    static void CardInserted(void* params, const char* readerName)
    {
        ChangeActPasswordTool* This = (ChangeActPasswordTool*)params;
        This->ChangeServerActivationPassword(readerName);
    }

    static const TSISmartCard_ChangeConsumer mySmartcardChanges;
};

const TSISmartCard_ChangeConsumer ChangeActPasswordTool::mySmartcardChanges = {
    NULL, NULL, &ChangeActPasswordTool::CardInserted, NULL,
};

tsmod::IObject* HIDDEN CreateChangeActPasswordTool()
{
	return dynamic_cast<tsmod::IObject*>(new ChangeActPasswordTool());
}

