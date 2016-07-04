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

enum {
	OPT_HELP = 0, 
};

#define USER_SALT_LEN 32
#define PIN_REF_USER 0x10
#define USER_PIN_INFO_LEN 120
#define MAX_PASSWORD_LEN 64
const tscrypto::tsCryptoData gActivationAID("A0 00 00 04 45 00 0D 01 01 FF FF 01 00 00 00 02", tscrypto::tsCryptoData::HEX);

static const struct OptionList options[] = {
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

class ChangeActPasswordTool : public IVeilToolCommand, public tsmod::IObject
{
public:
	ChangeActPasswordTool() : gSmartCardDone(true, false)
	{}
	~ChangeActPasswordTool()
	{}

	// tsmod::IObject
	virtual void OnConstructionFinished()
	{
		utils = ::TopServiceLocator()->get_instance<IVeilUtilities>("VeilUtilities");
	}

	// Inherited via IVeilToolCommand
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


		std::shared_ptr<ICkmWinscardMonitor> _monitor;

		std::cout << "Insert the smart card that you want to change the server activation password." << std::endl;

		if (!(_monitor = ::TopServiceLocator()->try_get_instance<ICkmWinscardMonitor>("/SmartCardMonitor")))
			return false;
		_monitor->ScanForChanges();

		gSmartCardDone.Reset();

		int cookie = _monitor->RegisterChangeReceiver(std::shared_ptr<ICkmWinscardChange>(new SmartCardChanges([&_monitor,this](const tscrypto::tsCryptoString& readerName) {ChangeServerActivationPassword(readerName, _monitor); })));
		auto cleanup1 = finally([&cookie, &_monitor]() {_monitor->UnregisterChangeReceiver(cookie); });
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
	void ChangeServerActivationPassword(const tscrypto::tsCryptoString& readerName, std::shared_ptr<ICkmWinscardMonitor> monitor)
	{
		tscrypto::tsCryptoData cardcmd("00 A4 04 00", tscrypto::tsCryptoData::HEX);
		std::shared_ptr<ISmartCardConnection> card;
		tscrypto::tsCryptoString tokenName;
		tscrypto::tsCryptoData outData;
		int sw;
		tscrypto::tsCryptoString prompt;
		tscrypto::tsCryptoString oldPin, newPin, confirmPin;
		tscrypto::tsCryptoData oldPinInfo;
		tscrypto::tsCryptoData authKey;
		tscrypto::tsCryptoData newSalt;
		tscrypto::tsCryptoData data, key2, mac2, kek;
		xp_console ts_out;

		card = ::TopServiceLocator()->get_instance<ISmartCardConnection>("LocalSmartCardConnection");
		card->ReaderName(readerName);
		if (!card->Start())
		{
			std::cout << "ERROR:  Unable to connect to the smart card." << std::endl;
			gSmartCardDone.Set();
			return;
		}
		cardcmd << (uint8_t)gActivationAID.size() << gActivationAID;
		{
			SmartCardTransaction trans(card);

			if (!card->Transmit(cardcmd, 0, outData, sw) || sw != 0x9000)
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
			tscrypto::tsCryptoData outData;
			std::shared_ptr<ServerSecureChannel> channel;

			if (!card->Transmit(cardcmd, 0, outData, sw) || sw != 0x9000)
			{
				std::cout << "ERROR:  That card does not contain the activation information for this enterprise." << std::endl;
				return;
			}
			if (!ExternalAuthCkm(card, PIN_REF_USER, oldPin, authKey, kek))
			{
				std::cout << "ERROR:  The specified pin did not work." << std::endl;
				return;
			}
			card->GetSecureChannel(channel);
			// Retrieve the server pin
			if (!card->Transmit(tscrypto::tsCryptoData("00A40000020030", tscrypto::tsCryptoData::HEX), 0, outData, sw) || sw != 0x9000 ||
				!card->Transmit(tscrypto::tsCryptoData("00B0000000", tscrypto::tsCryptoData::HEX), 0, outData, sw) || sw != 0x9000)
			{
				if (!channel)
				{
					channel->finish();
				}
				std::cout << "ERROR:  Unable to retrieve the server authentication." << std::endl;
				return;
			}
			if (!channel)
			{
				channel->finish();
			}
			oldPinInfo = outData;
		}
		//
		// Now compute the new key information and insert it into the Token
		//
		data = newPin;
		data.resize(MAX_PASSWORD_LEN, (BYTE)0xff);

		if (!(TSCreatePBEKeyAndMac("HMAC-SHA512", data.ToUtf8String(), newSalt, 1000, 96, key2, mac2)))
		{
			std::cout << "ERROR:  Failed to create the key" << std::endl;
			return;
		}

		SYSTEMTIME tm;
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
		GetSystemTime(&tm);
		tscrypto::tsCryptoString creationDate;
		TSTMToZuluString(tm, creationDate);
		creationDate.resize(16);
		key2 += creationDate;
		key2 += kek;

		// Now authenticate to the card again and unwrap this value
		{
			SmartCardTransaction trans(card);
			tscrypto::tsCryptoData outData;
			std::shared_ptr<ServerSecureChannel> channel;

			if (!card->Transmit(cardcmd, 0, data, sw) || sw != 0x9000)
			{
				std::cout << "ERROR:  That card does not contain the activation information for this enterprise." << std::endl;
				return;
			}
			if (StartSecureChannel(card, authKey.substring(0, 32), authKey.substring(32, 32), authKey.substring(64, 32), 3, 0x60, 0x33, PIN_REF_USER, 0) != 0x9000)
			{
				std::cout << "ERROR:  The specified pin did not work." << std::endl;
				return;
			}
			card->GetSecureChannel(channel);

			cardcmd.FromHexString("00 24 01 10");
			cardcmd << (uint8_t)key2.size();
			cardcmd << key2;

			if (!card->Transmit(cardcmd, 0, outData, sw) || sw != 0x9000)
			{
				// TODO:  This may be the bug in 1.002 ckm applet where ChangeRef fails but ResetRetry works.  Try it

				key2.insert(0, (BYTE)5); // TODO:  Should get this from the password policy
				key2.insert(0, (BYTE)5);

				cardcmd.FromHexString("00 2C 02 10");
				cardcmd << (uint8_t)key2.size();
				cardcmd << key2;

				if (!card->Transmit(cardcmd, 0, outData, sw) || sw != 0x9000)
				{
					std::cout << "ERROR:  Unable to change reference data" << std::endl;
					return;
				}
			}
			if (!channel)
			{
				channel->finish();
			}
		}
		gSmartCardDone.Set();
	}
	tscrypto::tsCryptoString GetTokenName(std::shared_ptr<ISmartCardConnection> card)
	{
		tscrypto::tsCryptoData outData;
		int sw;

		if (card == NULL)
			return "";

		if (!card->Transmit(tscrypto::tsCryptoData("00 A4 00 00 02 60 00", tscrypto::tsCryptoData::HEX), 0, outData, sw) || sw != 0x9000)
			return "";

		if (!card->Transmit(tscrypto::tsCryptoData("00 B0 00 00 00", tscrypto::tsCryptoData::HEX), 0, outData, sw) || sw != 0x9000)
			return "";

		return outData.ToUtf8String().Trim();
	}
	bool ExternalAuthCkm(std::shared_ptr<ISmartCardConnection> connection, BYTE reference, const tscrypto::tsCryptoString &in_pin, tscrypto::tsCryptoData& authKey, tscrypto::tsCryptoData& kek)
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

			pin.resize(MAX_PASSWORD_LEN, (BYTE)0xff);
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
	int StartSecureChannel(std::shared_ptr<ISmartCardConnection> connection, const tscrypto::tsCryptoData& encKey, const tscrypto::tsCryptoData& macKey, const tscrypto::tsCryptoData& kek, uint8_t SCPVersion, uint8_t SCPLevel, uint8_t SecurityLevel, uint8_t keyRef, uint8_t keyVersion)
	{
		tscrypto::tsCryptoData outdata;
		int sw;
		std::shared_ptr<ServerSecureChannel> channel;

		if (connection == NULL)
			return 0x6F00;

		connection->GetSecureChannel(channel);

		if (!channel)
		{
			if (!(channel = std::dynamic_pointer_cast<ServerSecureChannel>(CryptoFactory("SECURE_CHANNEL-SERVER"))))
				return 0x6F80;
			connection->SetSecureChannel(channel);
		}
		channel->setSCPLevel(SCPLevel);
		channel->setSCPVersion(SCPVersion);
		channel->finish();

		tscrypto::tsCryptoData cmd;

		if (!channel->ComputeHostChallengeCommand(keyRef, cmd))
			return 0x6F00;

		if (keyRef != 0 && keyVersion != 0)
		{
			cmd[2] = keyVersion;
			cmd[3] = keyRef;
		}

		connection->Transmit(cmd, 0, outdata, sw);
		if (sw != 0x9000)
		{
			return (int)sw;
		}
		channel->SetBaseKeys(encKey, macKey, kek);

		cmd.clear();
		if (!channel->ComputeAuthentication(outdata, SecurityLevel, cmd))
			return 0x6F00;

		connection->Transmit(cmd, 0, outdata, sw);
		if (sw != 0x9000)
		{
			return (int)sw;
		}
		channel->ActivateChannel();
		return (int)sw;
	}
	bool getUserSaltAndKek(std::shared_ptr<ISmartCardConnection> connection, tscrypto::tsCryptoData &salt, tscrypto::tsCryptoData& kek)
	{
		tscrypto::tsCryptoData outData;
		int sw;

		salt.clear();

		if (!connection->Transmit(tscrypto::tsCryptoData("00A40000020030", tscrypto::tsCryptoData::HEX), 0, outData, sw) || sw != 0x9000)
		{
			return false;
		}
		if (!connection->Transmit(tscrypto::tsCryptoData("00B0000000", tscrypto::tsCryptoData::HEX), 0, outData, sw) || sw != 0x9000)
		{
			return false;
		}
		salt = outData.substring(0, USER_SALT_LEN);
		kek = outData.substring(48, outData.size() - 48);
		return salt.size() == USER_SALT_LEN;
	}
protected:
	std::shared_ptr<IVeilUtilities> utils;
	tscrypto::CryptoEvent gSmartCardDone;
};

tsmod::IObject* HIDDEN CreateChangeActPasswordTool()
{
	return dynamic_cast<tsmod::IObject*>(new ChangeActPasswordTool());
}

