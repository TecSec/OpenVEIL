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

static const tscrypto::tsCryptoData gActivationAID("A0 00 00 04 45 00 0D 01 01 FF FF 01 00 00 00 02", tscrypto::tsCryptoData::HEX);
#ifdef _DEBUG
static const tscrypto::tsCryptoData gSiloManagerLicenseAID("A0 00 00 04 45 00 0D 01 01 FF FF 01 00 00 00 03", tscrypto::tsCryptoData::HEX);
#endif
//static const uint8_t gSelectCkmInfo[] = { 0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x04, 0x45, 0x00, 0x03, 0x01, 0x00 };
static const uint8_t gGetEEAvailable[] = { 0x00, 0x00, 0x00, 0x00, 0x00 };
static const uint8_t gGetDeselectRamAvailable[] = { 0x00, 0x02, 0x00, 0x00, 0x00 };
static const uint8_t gGetResetRamAvailable[] = { 0x00, 0x04, 0x00, 0x00, 0x00 };
//static const uint8_t gSelectISD[] = { 0x00, 0xA4, 0x04, 0x00, 0x00 };
//static const uint8_t gSelectSSD[] = { 0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x04, 0x45, 0x00, 0x01, 0x01, 0x00 };
//static const uint8_t gSelectDAP[] = { 0x00, 0xA4, 0x04, 0x00, 0x0A, 0xa0, 0x00, 0x00, 0x04, 0x45, 0xFF, 0x00, 0x01, 0x01, 0x00 };
//static const uint8_t gSelectBmoc[] = { 0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x04, 0x45, 0x00, 0x0E, 0x01, 0x00 };
//static const uint8_t gSelectPiv[] = { 0x00, 0xA4, 0x04, 0x00, 0x0b, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00 };

static const uint8_t gIsdAid[] = { 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00 };
//static const uint8_t gSsdAid[] = { 0xA0, 0x00, 0x00, 0x04, 0x45, 0x00, 0x01, 0x01, 0x00 };
//static const uint8_t gDapAid[] = { 0xa0, 0x00, 0x00, 0x04, 0x45, 0xFF, 0x00, 0x01, 0x01, 0x00 };
static const uint8_t gPivAid[] = { 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00 };
static const uint8_t gBmocAid[] = { 0xA0, 0x00, 0x00, 0x04, 0x45, 0x00, 0x0E, 0x01, 0x00 };
static const uint8_t gCkmInfoAid[] = { 0xA0, 0x00, 0x00, 0x04, 0x45, 0x00, 0x03, 0x01, 0x00 };

enum {
	OPT_HELP = 0, 
};

static const struct tsmod::OptionList options[] = {
	{ "", "VEIL SMARTCARD INFO commands" },
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

class SmartCardInfoTool : public tsmod::IVeilToolCommand, public tsmod::IObject
{
public:
	SmartCardInfoTool() : gSmartCardDone(true, false)
	{}
	~SmartCardInfoTool()
	{}

	// tsmod::IObject
	virtual void OnConstructionFinished() override
	{
		utils = ::TopServiceLocator()->get_instance<tsmod::IVeilUtilities>("VeilUtilities");
	}

	// Inherited via tsmod::IVeilToolCommand
	virtual tscrypto::tsCryptoString getDescription() const override
	{
		return "Retrieve basic information about a smartcard.";
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

		std::cout << "Insert the smart card that you want to inspect." << std::endl;

		if (!(_monitor = ::TopServiceLocator()->try_get_instance<ICkmWinscardMonitor>("/SmartCardMonitor")))
			return false;

		_monitor->ScanForChanges();

		gSmartCardDone.Reset();

		int cookie = _monitor->RegisterChangeReceiver(std::shared_ptr<ICkmWinscardChange>(new SmartCardChanges([this](const tscrypto::tsCryptoString& readerName) {GetSmartCardInfo(readerName);} )));
		auto cleanup1 = finally([&cookie, &_monitor]() {_monitor->UnregisterChangeReceiver(cookie); });
		gSmartCardDone.WaitForEvent(INFINITE);
		return 0;
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
	void GetSmartCardInfo(const tscrypto::tsCryptoString& readerName)
	{
		std::shared_ptr<ISmartCardConnection> connection;
		std::shared_ptr<ISmartCardInformation> cardinfo;
		JSONObject out;
		tscrypto::tsCryptoData selectResponse;

		if (!(connection = ::TopServiceLocator()->get_instance<ISmartCardConnection>("LocalSmartCardConnection")) ||
			!(cardinfo = ::TopServiceLocator()->get_instance<ISmartCardInformation>("SmartCardInformation")))
		{
			std::cout << "ERROR:  Unable to create the Winscard Connector." << std::endl;
			gSmartCardDone.Set();
			return;
		}
		connection->ReaderName(readerName);

		if (!connection->Start())
		{
			std::cout << "ERROR:  Unable to start the smart card connector\n" << std::endl;
			gSmartCardDone.Set();
			return;
		}

		// Lock the card for exclusive access to this thread/process
		SmartCardTransaction trans(connection);
		// Retrieve information about this card

		if (SelectISD(connection, selectResponse) == 0x6D00)
		{
			out.add("TransportLocked", true);
		}
		else
		{
			cardinfo->PopulateCardInformation(connection);

			out
				.add("TransportLocked", false)
				.add("OSVersion", cardinfo->OSVersion())
				.add("ChipID", (int64_t)cardinfo->ChipID())
				.add("SerialNumber", cardinfo->SerialNumber().ToHexStringWithSpaces())
				.add("IsFlash", cardinfo->isFlashChip())
				.add("IsROM", cardinfo->isRomChip())
				.add("IsContact", cardinfo->isContact())
				.add("IsContactless", cardinfo->isContactless())
				.add("IIN", cardinfo->IIN().ToHexStringWithSpaces())
				.add("CIN", cardinfo->CIN().ToHexStringWithSpaces());

			if (cardinfo->IsdAid().size() > 0)
			{
				JSONObject applet;

				applet
					.add("AID", cardinfo->IsdAid().ToHexStringWithSpaces())
					.add("SCPProtocol", (int64_t)cardinfo->ISDSecureChannelProtocol())
					.add("SCPParameter", (int64_t)cardinfo->ISDSecureChannelParameter())
					.add("KeyVersion", (int64_t)cardinfo->ISDKeyVersion())
					.add("KeyLength", (int64_t)cardinfo->ISDKeyLength())
					.add("KeyType", (int64_t)cardinfo->ISDKeyType())
					.add("MaxSecLevel", (int64_t)cardinfo->ISDMaximumSecurityLevel())
					.createArrayField("KeyList");

				for (size_t i = 0; i < cardinfo->ISDKeyCount(); i++)
				{
					std::shared_ptr<ISmartCardKeyInformation> info;

					if (cardinfo->ISDKeyItem(i, info))
					{
						JSONObject keyinfo;

						keyinfo
							.add("KeyVersion", (int64_t)info->KeyVersion())
							.add("KeyNumber", (int64_t)info->KeyNumber())
							.add("KeyType", (int64_t)info->KeyType())
							.add("KeyLength", (int64_t)info->KeyLength())
							.add("OtherInfo", info->OtherInfo().ToHexStringWithSpaces());
						applet.add("KeyList", keyinfo);
					}
				}

				out.add("ISD", applet);
			}
			if (cardinfo->SsdAid().size() > 0)
			{
				JSONObject applet;

				applet
					.add("AID", cardinfo->SsdAid().ToHexStringWithSpaces())
					.add("SCPProtocol", (int64_t)cardinfo->SSDSecureChannelProtocol())
					.add("SCPParameter", (int64_t)cardinfo->SSDSecureChannelParameter())
					.add("KeyVersion", (int64_t)cardinfo->SSDKeyVersion())
					.add("KeyLength", (int64_t)cardinfo->SSDKeyLength())
					.add("KeyType", (int64_t)cardinfo->SSDKeyType())
					.add("MaxSecLevel", (int64_t)cardinfo->SSDMaximumSecurityLevel())
					.createArrayField("KeyList");

				for (size_t i = 0; i < cardinfo->SSDKeyCount(); i++)
				{
					std::shared_ptr<ISmartCardKeyInformation> info;

					if (cardinfo->SSDKeyItem(i, info))
					{
						JSONObject keyinfo;

						keyinfo
							.add("KeyVersion", (int64_t)info->KeyVersion())
							.add("KeyNumber", (int64_t)info->KeyNumber())
							.add("KeyType", (int64_t)info->KeyType())
							.add("KeyLength", (int64_t)info->KeyLength())
							.add("OtherInfo", info->OtherInfo().ToHexStringWithSpaces());
						applet.add("KeyList", keyinfo);
					}
				}

				out.add("SSD", applet);
			}
			if (cardinfo->DapAid().size() > 0)
			{
				JSONObject applet;

				applet
					.add("AID", cardinfo->DapAid().ToHexStringWithSpaces())
					.add("SCPProtocol", (int64_t)cardinfo->DAPSecureChannelProtocol())
					.add("SCPParameter", (int64_t)cardinfo->DAPSecureChannelParameter())
					.add("KeyVersion", (int64_t)cardinfo->DAPKeyVersion())
					.add("KeyLength", (int64_t)cardinfo->DAPKeyLength())
					.add("KeyType", (int64_t)cardinfo->DAPKeyType())
					.add("MaxSecLevel", (int64_t)cardinfo->DAPMaximumSecurityLevel())
					.createArrayField("KeyList");

				for (size_t i = 0; i < cardinfo->DAPKeyCount(); i++)
				{
					std::shared_ptr<ISmartCardKeyInformation> info;

					if (cardinfo->DAPKeyItem(i, info))
					{
						JSONObject keyinfo;

						keyinfo
							.add("KeyVersion", (int64_t)info->KeyVersion())
							.add("KeyNumber", (int64_t)info->KeyNumber())
							.add("KeyType", (int64_t)info->KeyType())
							.add("KeyLength", (int64_t)info->KeyLength())
							.add("OtherInfo", info->OtherInfo().ToHexStringWithSpaces());
						applet.add("KeyList", keyinfo);
					}
				}

				out.add("DAP", applet);
			}

			connection->Status("Checking for resource availability...");
			// Memory information
			if (SelectCkmInfo(connection, selectResponse) == 0x9000)
			{
				int ee = GetFreeCardMemory(connection);
				int deselect = GetFreeDeselectRam(connection);
				int reset = GetFreeResetRam(connection);

				if (ee < 0)
					ee = 0;
				if (deselect < 0)
					deselect = 0;
				if (reset < 0)
					reset = 0;
				out
					.add("EE", (int64_t)ee)
					.add("DeselectRAM", (int64_t)deselect)
					.add("ResetRAM", (int64_t)reset);
			}

			if (SelectPiv(connection, selectResponse) == 0x9000)
			{
				JSONObject applet;

				applet.add("AID", tscrypto::tsCryptoData(gPivAid, sizeof(gPivAid)).ToHexStringWithSpaces());
				// TODO: Get PIV information

				out.add("PIV", applet);
			}
			if (SelectBmoc(connection, selectResponse) == 0x9000)
			{
				JSONObject applet;
				std::shared_ptr<TlvDocument> doc = TlvDocument::Create();

				applet.add("AID", tscrypto::tsCryptoData(gBmocAid, sizeof(gBmocAid)).ToHexStringWithSpaces());
				if (doc->LoadTlv(selectResponse))
				{
					std::shared_ptr<TlvNode> node = doc->DocumentElement()->FindFirstTag(5, TlvNode::Type_Context);
					if (!!node)
					{
						tscrypto::tsCryptoData data = node->InnerData();
						char buff[10];

						if (data.size() >= 4)
						{
							switch (data[0])
							{
							case 1:
								applet.add("Algorithm", "Precise 378");
								break;
							case 2:
								applet.add("Algorithm", "Neuro CC");
								break;
							case 3:
								applet.add("Algorithm", "Precise Iso");
								break;
							case 255:
								applet.add("Algorithm", "Precise Proprietary");
								break;
							default:
								applet.add("Algorithm", "Unknown");
								break;
							}
							_snprintf_s(buff, sizeof(buff), sizeof(buff), "%d.%03d", data[1], data[2]);
							applet.add("Version", tsCryptoString(buff));
							switch (data[3])
							{
							case 0:
								applet.add("Channel", "Original");
								break;
							case 1:
								applet.add("Channel", "AES-CMAC with SP800-108");
								break;
							default:
								applet.add("Channel", "Unknown");
								break;
							}
						}
					}
				}

				out.add("BMOC", applet);
			}
			GetSiloInfo(connection, out, "Server Activation", gActivationAID);
#ifdef _DEBUG
			GetSiloInfo(connection, out, "Silo Manager License", gSiloManagerLicenseAID);
#endif 
			// Now look for silos
			std::shared_ptr<BasicVEILPreferences> prefs = BasicVEILPreferences::Create();
			if (!!prefs)
			{
				prefs->loadValues();

				tscrypto::tsCryptoString tmp = prefs->getAIDList();
				tscrypto::tsCryptoStringList aidList = tmp.split(";");

				for (const tscrypto::tsCryptoString& aidHex : *aidList)
				{
					tscrypto::tsCryptoData aid = aidHex.HexToData();
					if (aid.size() > 0)
						GetSiloInfo(connection, out, "Silo", aid);
				}
			}
		}

		trans.ExitTransaction(SCardLeaveCard);

		DisplayCardInfo(out);
		gSmartCardDone.Set();
	}
	int SelectCkmInfo(std::shared_ptr<ISmartCardConnection> connection, tscrypto::tsCryptoData& selectResponse)
	{
		return SelectApplet(connection, tscrypto::tsCryptoData(gCkmInfoAid, sizeof(gCkmInfoAid)), selectResponse);
	}
	int GetFreeCardMemory(std::shared_ptr<ISmartCardConnection> connection)
	{
		tscrypto::tsCryptoData outData;
		int sw;

		if (!SelectCkmInfo(connection, outData))
		{
			return -1;
		}

		connection->Transmit(tscrypto::tsCryptoData(gGetEEAvailable, sizeof(gGetEEAvailable)), 0, outData, sw);
		if (sw == 0x9000)
		{
			uint32_t value;

			// Size comes from card big-endian, convert it to UInt32 and then fix if needed
			value = *(uint32_t*)outData.rawData();
			TS_BIG_ENDIAN4(value);
			return (int)value;
		}
		else
		{
			return -1;
		}
	}
	int GetFreeDeselectRam(std::shared_ptr<ISmartCardConnection>  connection)
	{
		tscrypto::tsCryptoData outData;
		int sw;

		if (!SelectCkmInfo(connection, outData))
		{
			return -1;
		}

		connection->Transmit(tscrypto::tsCryptoData(gGetDeselectRamAvailable, sizeof(gGetDeselectRamAvailable)), 0, outData, sw);
		if (sw == 0x9000)
		{
			uint16_t value;

			// Size comes from card big-endian, convert it to UInt16 and then fix if needed
			value = *(uint16_t*)outData.rawData();
			value = _TS_BIG_ENDIAN2(value);
			return (int)value;
		}
		else
		{
			return -1;
		}
	}
	int GetFreeResetRam(std::shared_ptr<ISmartCardConnection>  connection)
	{
		tscrypto::tsCryptoData outData;
		int sw;

		if (!SelectCkmInfo(connection, outData))
		{
			return -1;
		}

		connection->Transmit(tscrypto::tsCryptoData(gGetResetRamAvailable, sizeof(gGetResetRamAvailable)), 0, outData, sw);
		if (sw == 0x9000)
		{
			uint16_t value;

			// Size comes from card big-endian, convert it to UInt16 and then fix if needed
			value = *(uint16_t*)outData.rawData();
			value = _TS_BIG_ENDIAN2(value);
			return (int)value;
		}
		else
		{
			return -1;
		}
	}
	int SelectISD(std::shared_ptr<ISmartCardConnection> connection, tscrypto::tsCryptoData& selectResponse)
	{
		return SelectApplet(connection, tscrypto::tsCryptoData(gIsdAid, sizeof(gIsdAid)), selectResponse);
	}
	int SelectPiv(std::shared_ptr<ISmartCardConnection> connection, tscrypto::tsCryptoData& selectResponse)
	{
		return SelectApplet(connection, tscrypto::tsCryptoData(gPivAid, sizeof(gPivAid)), selectResponse);
	}
	int SelectBmoc(std::shared_ptr<ISmartCardConnection> connection, tscrypto::tsCryptoData& selectResponse)
	{
		return SelectApplet(connection, tscrypto::tsCryptoData(gBmocAid, sizeof(gBmocAid)), selectResponse);
	}
	int SelectApplet(std::shared_ptr<ISmartCardConnection> connection, const tscrypto::tsCryptoData& aid, tscrypto::tsCryptoData& selectResponse)
	{
		int sw;
		tscrypto::tsCryptoData cmd("00 A4 04 00", tscrypto::tsCryptoData::HEX);

		if (connection == NULL)
			return 0x6F00;

		cmd << (uint8_t)aid.size() << aid;
		connection->Transmit(cmd, 0, selectResponse, sw);
		return (int)sw;
	}
	void GetSiloInfo(std::shared_ptr<ISmartCardConnection> connection, JSONObject& obj, const tscrypto::tsCryptoString& name, const tscrypto::tsCryptoData& aid)
	{
		tscrypto::tsCryptoData selectResponse;

		if (SelectApplet(connection, aid, selectResponse) == 0x9000)
		{
			JSONObject o;
			int sw;
			tscrypto::tsCryptoData outData;

			if (!obj.hasField("Silos"))
				obj.createArrayField("Silos");

			o.add("Name", name).add("AID", aid.ToHexStringWithSpaces());

			std::shared_ptr<TlvDocument> doc = TlvDocument::Create();

			if (doc->LoadTlv(selectResponse))
			{
				std::shared_ptr<TlvNode> n = doc->DocumentElement()->FindFirstTag(0x0a, TlvNode::Type_Context);
				if (!!n)
					o.add("LCSI", n->InnerDataAsNumber());

				n = doc->DocumentElement()->FindFirstTag(0x05, TlvNode::Type_Context);
				if (!!n && n->InnerData().size() >= 6)
				{
					o
						.add("AppletMajor", (int64_t)n->InnerData()[0])
						.add("AppletMinor", (int64_t)n->InnerData()[1])
						.add("ChannelType", (int64_t)n->InnerData()[2])
						.add("ChannelSub", (int64_t)n->InnerData()[3]);

					if (n->InnerData()[4] == 4)
						o.add("CkmVersion", (int64_t)7);
					else
						o.add("CkmVersion", (int64_t)n->InnerData()[4]);

					switch (n->InnerData()[5])
					{
					case 1:
						o.add("HashType", "SHA256");
						break;
					case 2:
						o.add("HashType", "SHA512");
						break;
					case 3:
						o.add("HashType", "Dynamic");
						break;
					default:
						o.add("HashType", "[[unknown]]");
						break;
					}
				}
			}
			o.add("SerialNumber", GetSerialNumber(connection).ToHexString());

			sw = connection->SendCommand(tscrypto::tsCryptoData("0020001000", tscrypto::tsCryptoData::HEX), outData);
			if (sw == 0x9000)
			{
				o.add("userLogin", "Authenticated");
			}
			else if ((sw & 0xFFF0) == 0x63C0)
			{
				tscrypto::tsCryptoString tmp;
				tmp << (sw & 0x0f) << " tries left";
				o.add("userLogin", tmp);
			}
			else if (sw == 0x6983)
			{
				o.add("userLogin", "locked");
			}
			else if (sw == 0x6D00)
			{
				o.add("userLogin", "");
			}
			else
			{
				o.add("userLogin", "not available");
			}

			obj.add("Silos", o);
		}
	}
	tscrypto::tsCryptoData GetSerialNumber(std::shared_ptr<ISmartCardConnection> card)
	{
		tscrypto::tsCryptoData outData;
		int sw;

		if (card == NULL)
			return tscrypto::tsCryptoData();

		if (!card->Transmit(tscrypto::tsCryptoData("80 34 00 01 00", tscrypto::tsCryptoData::HEX), 0, outData, sw) || sw != 0x9000)
			return tscrypto::tsCryptoData();
		if (outData.size() < 20)
			return tscrypto::tsCryptoData();
		return outData.substring(11, 8);
	}
	void DumpApplet(const char* appletName, const JSONObject& obj)
	{
		printf("%s:\n  AID: %s  SCP: %02X-%02X-%02X  KeyVersion: %02X\n  Keys:\n", appletName, obj.AsString("AID").c_str(),
			(int)obj.AsNumber("SCPProtocol", 0), (int)obj.AsNumber("SCPParameter", 0), (int)obj.AsNumber("MaxSecLevel", 0),
			(int)obj.AsNumber("KeyVersion", 0));
		obj.foreach("KeyList", [](const JSONField& fld) {
			const JSONObject& obj = fld.AsObject();

			printf("    Number: %02X  Version: %02X  Type: %X  Length: %d bytes  %s\n", (int)obj.AsNumber("KeyNumber", 0), (int)obj.AsNumber("KeyVersion", 0),
				(int)obj.AsNumber("KeyType", 0), (int)obj.AsNumber("KeyLength", 0), obj.AsString("OtherInfo").c_str());
		});
	}
	void DumpSilo(const char* appletName, const JSONObject& obj)
	{
		printf("%s:\n  AID: %s  \n", appletName, obj.AsString("AID").c_str());
		printf("    Version %2d.%02d    Secure Channel:  %02X/%02X  CKM Version:  %d\n", (int)obj.AsNumber("AppletMajor", 0), (int)obj.AsNumber("AppletMinor", 0), (int)obj.AsNumber("ChannelType", 0), (int)obj.AsNumber("ChannelSub", 0), (int)obj.AsNumber("CkmVersion", 0));
		printf("    Hash type:  %s   Lifecycle State:  %s\n", obj.AsString("HashType").c_str(), GetLcsi((byte)obj.AsNumber("LCSI", 0)));
		printf("    SerialNumber:  %s    Login state:  %s\n", obj.AsString("SerialNumber").c_str(), obj.AsString("userLogin").c_str());
	}
	void DisplayCardInfo(JSONObject& obj)
	{
		if (obj.AsBool("TransportLocked", false))
		{
			printf("\nThis card is transport locked\n");
		}
		else
		{
			printf("\nCard information:\n  OS: %s   Chip: %d  Serial No: %s\n", obj.AsString("OSVersion").c_str(), (int)obj.AsNumber("ChipID"), obj.AsString("SerialNumber").c_str());
			printf("  Is ROM:  %s  Is Flash: %s  Interface: %s\n", obj.AsBool("IsROM", false) ? "true" : "false", obj.AsBool("IsFlash", false) ? "true" : "false", obj.AsBool("IsContact", false) ? "contact" : "contactless");
			printf("  IIN:  %s   CIN:  %s\n", obj.AsString("IIN").c_str(), obj.AsString("CIN").c_str());
			if (obj.hasField("EE"))
				printf("Memory:\n  Free EE:  %d  Free Deselect RAM:  %d  Free Reset RAM:  %d\n", (int)obj.AsNumber("EE", 0), (int)obj.AsNumber("DeselectRAM", 0), (int)obj.AsNumber("ResetRAM", 0));
			if (obj.hasField("ISD"))
			{
				DumpApplet("ISD", obj.AsObject("ISD"));
			}
			if (obj.hasField("SSD"))
			{
				DumpApplet("SSD", obj.AsObject("SSD"));
			}
			if (obj.hasField("DAP"))
			{
				DumpApplet("DAP", obj.AsObject("DAP"));
			}
			if (obj.hasField("PIV"))
			{
				JSONObject piv = obj.AsObject("PIV");

				printf("PIV:\n  AID:  %s\n", piv.AsString("AID").c_str());
			}
			if (obj.hasField("BMOC"))
			{
				JSONObject bmoc = obj.AsObject("BMOC");

				printf("BMOC:\n  AID:  %s  Version: %s  Alg: %s  Channel: %s\n", bmoc.AsString("AID").c_str(),
					bmoc.AsString("Version").c_str(), bmoc.AsString("Algorithm").c_str(), bmoc.AsString("Channel").c_str());
			}
			if (obj.hasField("Silos"))
			{
				obj.foreach("Silos", [this](const JSONField& f) {
					if (f.Type() == JSONField::jsonObject)
					{
						const JSONObject& o = f.AsObject();

						DumpSilo(o.AsString("Name").c_str(), o);
					}
				});
			}
		}
	}
	const char *GetLcsi(byte lcsi)
	{
		switch (lcsi)
		{
		case 1:
			return "Creation";
		case 3:
			return "Initialize";
		case 5:
			return "Active";
		case 4:
			return "Inactive";
		case 12:
			return "Terminated";
		default:
			return "unknown";
		}
	}
protected:
	std::shared_ptr<tsmod::IVeilUtilities> utils;
	tscrypto::CryptoEvent gSmartCardDone;
};

tsmod::IObject* HIDDEN CreateSmartCardInfoTool()
{
	return dynamic_cast<tsmod::IObject*>(new SmartCardInfoTool());
}

