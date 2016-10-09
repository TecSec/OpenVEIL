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

static uint8_t gSelectISD[] = { 0x00, 0xA4, 0x04, 0x00, 0x00 };
static uint8_t gSelectSSD[] = { 0x00, 0xA4, 0x04, 0x00, 0x09, 0xA0, 0x00, 0x00, 0x04, 0x45, 0x00, 0x01, 0x01, 0x00 };
static uint8_t gSelectDAP[] = { 0x00, 0xA4, 0x04, 0x00, 0x0A, 0xa0, 0x00, 0x00, 0x04, 0x45, 0xFF, 0x00, 0x01, 0x01, 0x00 };
static uint8_t gIsdAid[] = { 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00 };
static uint8_t gSsdAid[] = { 0xA0, 0x00, 0x00, 0x04, 0x45, 0x00, 0x01, 0x01, 0x00 };
static uint8_t gDapAid[] = { 0xa0, 0x00, 0x00, 0x04, 0x45, 0xFF, 0x00, 0x01, 0x01, 0x00 };
static uint8_t gGetCPLCCmd[] = { 0x80, 0xCA, 0x9F, 0x7F, 0x00 };
static uint8_t gGetIIN[] = { 0x80, 0xCA, 0x00, 0x42, 0x00 };
static uint8_t gGetCIN[] = { 0x80, 0xCA, 0x00, 0x45, 0x00 };
static uint8_t gGetSCPInfo[] = { 0x80, 0x50, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static uint8_t gGetKeyInfo[] = { 0x80, 0xca, 0x00, 0xe0, 0x00 };

class SmartCardTransaction
{
public:
	SmartCardTransaction(std::shared_ptr<ISmartCardConnection> connection) : _connection2(connection), _alreadyHadTransaction(false)
	{
		if (!!_connection2)
		{
			_alreadyHadTransaction = connection->IsInTransaction();
			if (!_alreadyHadTransaction)
				connection->StartTransaction();
		}
	}
	bool ExitTransaction(SCardDisposition disposition)
	{
		if (_connection2 != nullptr && !_alreadyHadTransaction)
		{
			_alreadyHadTransaction = false;
			_connection2->FinishTransaction(disposition == SCardResetCard);
			_connection2 = nullptr;
			return true;
		}
		return true;
	}
	~SmartCardTransaction()
	{
		if (_connection2 != nullptr && !_alreadyHadTransaction)
		{
			_connection2->FinishTransaction(false);
		}
	}
private:
	std::shared_ptr<ISmartCardConnection> _connection2;
	bool _alreadyHadTransaction;
};

class SmartCardKeyInformation : public ISmartCardKeyInformation, public tsmod::IObject
{
public:
	SmartCardKeyInformation(uint8_t version, uint8_t number, uint8_t type, int length, const tscrypto::tsCryptoData &info) :
		_KeyVersion(version), _KeyNumber(number), _KeyType(type), _KeyLength(length), _OtherInfo(info)
	{}
	virtual ~SmartCardKeyInformation() {}

	// ISmartCardKeyInformation
	virtual uint8_t KeyVersion() const { return _KeyVersion; }
	virtual uint8_t KeyNumber() const { return _KeyNumber; }
	virtual uint8_t KeyType() const { return _KeyType; }
	virtual int KeyLength() const { return _KeyLength; }
	virtual tscrypto::tsCryptoData OtherInfo() const { return _OtherInfo; }

private:
	uint8_t _KeyVersion;
	uint8_t _KeyNumber;
	uint8_t _KeyType;
	int _KeyLength;
	tscrypto::tsCryptoData _OtherInfo;
};

class SmartCardInformation : public ISmartCardInformation, public tsmod::IObject
{
public:
	SmartCardInformation() : _chipId(0), _transportLocked(false),
		_IsdKeyVersion(0), _isdKeyLength(0), _isdKeyType(0), _SsdKeyVersion(0), _ssdKeyLength(0), _ssdKeyType(0), _DapKeyVersion(0), _dapKeyLength(0), _dapKeyType(0), _IsdSCPNumber(0), _IsdSCPParameter(0), _SsdSCPNumber(0), _SsdSCPParameter(0),_DapSCPNumber(0), _DapSCPParameter(0) {}
	virtual ~SmartCardInformation() {}

	// ISmartCardInformation
	virtual tscrypto::tsCryptoString OSVersion() const { return _osVersion; }
	virtual int ChipID() const { return _chipId; }
	virtual tscrypto::tsCryptoData SerialNumber() const { return _serialNumber; }
	virtual bool isFlashChip() const { return ChipID() == 0x0107 || ChipID() == 0x010A; }
	virtual bool isRomChip() const { return ChipID() == 0x010E || ChipID() == 0x0108 || ChipID() == 48879/*simulator*/; }
	virtual bool isContact() const { return ChipID() == 0x010A || ChipID() == 0x0108 || ChipID() == 48879/*simulator*/; }
	virtual bool isContactless() const { return ChipID() == 0x0107 || ChipID() == 0x010E; }
	virtual tscrypto::tsCryptoData IsdAid() const { return _IsdAid; }
	virtual tscrypto::tsCryptoData SsdAid() const { return _SsdAid; }
	virtual tscrypto::tsCryptoData DapAid() const { return _DapAid; }
	virtual uint8_t ISDSecureChannelProtocol() const { return _IsdSCPNumber; }
	virtual uint8_t SSDSecureChannelProtocol() const { return _SsdSCPNumber; }
	virtual uint8_t DAPSecureChannelProtocol() const { return _DapSCPNumber; }
	virtual uint8_t ISDSecureChannelParameter() const { return _IsdSCPParameter; }
	virtual uint8_t SSDSecureChannelParameter() const { return _SsdSCPParameter; }
	virtual uint8_t DAPSecureChannelParameter() const { return _DapSCPParameter; }
	virtual uint8_t ISDKeyVersion() const { return _IsdKeyVersion; }
	virtual uint8_t SSDKeyVersion() const { return _SsdKeyVersion; }
	virtual uint8_t DAPKeyVersion() const { return _DapKeyVersion; }
	virtual void ISDKeyVersion(uint8_t setTo) { _IsdKeyVersion = setTo; }
	virtual void SSDKeyVersion(uint8_t setTo) { _SsdKeyVersion = setTo; }
	virtual void DAPKeyVersion(uint8_t setTo) { _DapKeyVersion = setTo; }
	virtual uint8_t ISDKeyLength() const { return _isdKeyLength; }
	virtual uint8_t SSDKeyLength() const { return _ssdKeyLength; }
	virtual uint8_t DAPKeyLength() const { return _dapKeyLength; }
	virtual uint8_t ISDKeyType() const { return _isdKeyType; }
	virtual uint8_t SSDKeyType() const { return _ssdKeyType; }
	virtual uint8_t DAPKeyType() const { return _dapKeyType; }
	virtual uint8_t ISDMaximumSecurityLevel() const { return _IsdMaximumSecurityLevel; }
	virtual uint8_t SSDMaximumSecurityLevel() const { return _SsdMaximumSecurityLevel; }
	virtual uint8_t DAPMaximumSecurityLevel() const { return _DapMaximumSecurityLevel; }
	virtual size_t ISDKeyCount() const { return _ISDKeyList.size(); }
	virtual bool ISDKeyItem(size_t index, std::shared_ptr<ISmartCardKeyInformation>& pVal) const {
		if (index >= ISDKeyCount()) return false; 
		pVal = _ISDKeyList[index];
		return !!pVal;
	}
	virtual size_t SSDKeyCount() const { return _SSDKeyList.size(); }
	virtual bool SSDKeyItem(size_t index, std::shared_ptr<ISmartCardKeyInformation>& pVal) const { 
		if (index >= SSDKeyCount()) return false; pVal = _SSDKeyList[index]; return !!pVal;
	}
	virtual size_t DAPKeyCount() const { return _DAPKeyList.size(); }
	virtual bool DAPKeyItem(size_t index, std::shared_ptr<ISmartCardKeyInformation>& pVal) const { 
		if (index >= DAPKeyCount()) return false; pVal = _DAPKeyList[index]; return !!pVal;
	}
	virtual tscrypto::tsCryptoData IIN() const { 
		return _IIN; 
	}
	virtual tscrypto::tsCryptoData CIN() const { 
		return _CIN; 
	}
	virtual void OverrideIIN(const tscrypto::tsCryptoData& setTo)
	{
		_IIN = setTo;
	}
	virtual void OverrideCIN(const tscrypto::tsCryptoData& setTo)
	{
		_CIN = setTo;
	}

	virtual void PopulateCardInformation(std::shared_ptr<ISmartCardConnection> connection)
	{
		size_t sw;
		tscrypto::tsCryptoData outData;
		tscrypto::tsCryptoData scpInfo;
		tscrypto::tsCryptoData keySpec;
		bool initUpdateFailed = false;
		uint8_t keyType = 0;

		_transportLocked = false;
		_chipId = 0;
		_IIN.clear();
		_CIN.clear();
		_osVersion.clear();
		_serialNumber.clear();
		_IsdAid.clear();
		_SsdAid.clear();
		_DapAid.clear();
		_IsdKeyVersion = 0;
		_IsdMaximumSecurityLevel = 0;
		_isdKeyLength = 0;
		_isdKeyType = 0;
		_SsdKeyVersion = 0;
		_SsdMaximumSecurityLevel = 0;
		_ssdKeyLength = 0;
		_ssdKeyType = 0;
		_DapKeyVersion = 0;
		_DapMaximumSecurityLevel = 0;
		_dapKeyLength = 0;
		_dapKeyType = 0;
		_IsdSCPNumber = 0;
		_IsdSCPParameter = 0;
		_SsdSCPNumber = 0;
		_SsdSCPParameter = 0;
		_DapSCPNumber = 0;
		_DapSCPParameter = 0;
		_ISDKeyList.clear();
		_SSDKeyList.clear();
		_DAPKeyList.clear();

		if (!connection)
		{
			FixupData();
			return;
		}

		SmartCardTransaction locker(connection);

		if ((sw = connection->Transmit(tscrypto::tsCryptoData(gSelectISD, sizeof(gSelectISD)), outData)) != 0x9000)
		{
			if (sw == 0x6D00)
			{
				_transportLocked = true;
			}
			else
				FixupData();
			return;
		}

		_IsdAid.assign(gIsdAid, sizeof(gIsdAid));
		if (connection->Transmit(tscrypto::tsCryptoData(gGetCPLCCmd, sizeof(gGetCPLCCmd)), outData) == 0x9000 && outData.size() >= 45)
		{
			_osVersion = outData.substring(7, 2).ToHexString() + "-" + outData.substring(9, 2).ToHexString() + "-" + outData.substring(11, 2).ToHexString();
			_chipId = outData[5] << 8 | outData[6];
			_serialNumber = outData.substring(13, 8);
		}

		if (connection->Transmit(tscrypto::tsCryptoData(gGetIIN, sizeof(gGetIIN)), outData) == 0x9000)
		{
			_IIN = outData.substring(2, outData.size() - 2);
		}
		if (connection->Transmit(tscrypto::tsCryptoData(gGetCIN, sizeof(gGetCIN)), outData) == 0x9000)
		{
			_CIN = outData.substring(2, outData.size() - 2);
		}
		//
		// Now determine the SCP version and counter
		//
		if (connection->Transmit(tscrypto::tsCryptoData(gGetSCPInfo, sizeof(gGetSCPInfo)), scpInfo) == 0x9000)
		{
			//
			// Now parse the information and set up the default SCP variables
			//
			if (scpInfo[11] == 1)
			{
				_IsdSCPNumber = 1;
				_IsdSCPParameter = 5;
				_IsdKeyVersion = scpInfo[10];
				_isdKeyLength = 16;
				_IsdMaximumSecurityLevel = 3;
			}
			else if (scpInfo[11] == 3)
			{
				_IsdSCPNumber = 3;
				_IsdSCPParameter = scpInfo[12];
				_IsdKeyVersion = scpInfo[10];
				_isdKeyLength = 32;
				_IsdMaximumSecurityLevel = 0x33;
			}
			if (_CIN.size() == 0 || (_CIN.size() == 1 && _CIN[0] == 0))
			{
				_CIN = scpInfo.substring(0, 10);
			}
			if (_serialNumber.size() == 0)
			{
				_serialNumber = scpInfo.substring(2, 8);
			}
		}
		else
			initUpdateFailed = true;

		connection->Transmit(tscrypto::tsCryptoData(gSelectISD, sizeof(gSelectISD)), outData);

		//
		// Now get the key length for the encryption key
		//
		sw = connection->Transmit(tscrypto::tsCryptoData(gGetKeyInfo, sizeof(gGetKeyInfo)), keySpec);
		if (sw == 0x9000 || sw == 0x6283)
		{
			std::shared_ptr<TlvDocument> doc = TlvDocument::Create();

			if (doc->LoadTlv(keySpec))
			{
				int count = (int)doc->DocumentElement()->ChildCount();
				for (int i = 0; i < count; i++)
				{
					std::shared_ptr<TlvNode> node = doc->DocumentElement()->ChildAt(i);

					tscrypto::tsCryptoData data = node->InnerData();

					if (data.size() >= 4)
					{
						if (data[0] == 1 && data[1] < 0x70)
						{
							_IsdKeyVersion = data[1];
							_isdKeyLength = data[3];
							_isdKeyType = data[2];
							keyType = data[2];
						}
						_ISDKeyList.push_back(::TopServiceLocator()->Finish<SmartCardKeyInformation>(new SmartCardKeyInformation(data[1], data[0], data[2], data[3], data.substring(4, data.size() - 4))));
					}
				}
			}
		}

		if (initUpdateFailed)
		{
			switch (keyType)
			{
			default:
			case 0x80:
				_IsdSCPNumber = 1;
				_IsdSCPParameter = 5;
				_IsdMaximumSecurityLevel = 0x03;
				break;
			case 0x88:
				_IsdSCPNumber = 3;
				_IsdSCPParameter = 0x60;
				_IsdMaximumSecurityLevel = 0x33;
				break;
			}
		}

		//
		// Now do it again for the SSD.
		//
		initUpdateFailed = false;
		keyType = 0;

		if (connection->Transmit(tscrypto::tsCryptoData(gSelectSSD, sizeof(gSelectSSD)), outData) == 0x9000)
		{
			_SsdAid.assign(gSsdAid, sizeof(gSsdAid));

			if (connection->Transmit(tscrypto::tsCryptoData(gGetSCPInfo, sizeof(gGetSCPInfo)), scpInfo) == 0x9000)
			{
				//
				// Now parse the information and set up the default SCP variables
				//
				if (scpInfo[11] == 1)
				{
					_SsdSCPNumber = 1;
					_SsdSCPParameter = 5;
					_SsdKeyVersion = scpInfo[10];
					_ssdKeyLength = 16;
					_SsdMaximumSecurityLevel = 3;
				}
				else if (scpInfo[11] == 3)
				{
					_SsdSCPNumber = 3;
					_SsdSCPParameter = scpInfo[12];
					_SsdKeyVersion = scpInfo[10];
					_ssdKeyLength = 32;
					_SsdMaximumSecurityLevel = 0x33;
				}
				if (_CIN.size() == 0 || (_CIN.size() == 1 && _CIN[0] == 0))
				{
					_CIN = scpInfo.substring(0, 10);
				}
				if (_serialNumber.size() == 0)
				{
					_serialNumber = scpInfo.substring(2, 8);
				}
			}
			else
				initUpdateFailed = true;

			connection->Transmit(tscrypto::tsCryptoData(gSelectSSD, sizeof(gSelectSSD)), outData);

			sw = connection->Transmit(tscrypto::tsCryptoData(gGetKeyInfo, sizeof(gGetKeyInfo)), keySpec);
			if (sw == 0x9000 || sw == 0x6283)
			{
				std::shared_ptr<TlvDocument> doc = TlvDocument::Create();

				if (doc->LoadTlv(keySpec))
				{
					int count = (int)doc->DocumentElement()->ChildCount();

					for (int i = 0; i < count; i++)
					{
						tscrypto::tsCryptoData data = doc->DocumentElement()->ChildAt(i)->InnerData();

						if (data.size() >= 4)
						{
							if (data[0] == 1 && data[1] < 0x70)
							{
								_SsdKeyVersion = data[1];
								_ssdKeyLength = data[3];
								_ssdKeyType = data[2];
								keyType = data[2];
							}
							_SSDKeyList.push_back(::TopServiceLocator()->Finish<SmartCardKeyInformation>(new SmartCardKeyInformation(data[1], data[0], data[2], data[3], data.substring(4, data.size() - 4))));
						}
					}
				}
			}
			if (initUpdateFailed)
			{
				switch (keyType)
				{
				default:
				case 0x80:
					_SsdSCPNumber = 1;
					_SsdSCPParameter = 5;
					_SsdMaximumSecurityLevel = 0x03;
					break;
				case 0x88:
					_SsdSCPNumber = 3;
					_SsdSCPParameter = 0x60;
					_SsdMaximumSecurityLevel = 0x33;
					break;
				}
			}
		}
		else
			_SsdAid.clear();

		//
		// and again for the DAP SSD.
		//
		initUpdateFailed = false;
		keyType = 0;
		if (connection->Transmit(tscrypto::tsCryptoData(gSelectDAP, sizeof(gSelectDAP)), outData) == 0x9000)
		{
			_DapAid.assign(gDapAid, sizeof(gDapAid));

			if (connection->Transmit(tscrypto::tsCryptoData(gGetSCPInfo, sizeof(gGetSCPInfo)), scpInfo) == 0x9000)
			{
				//
				// Now parse the information and set up the default SCP variables
				//
				if (scpInfo[11] == 1)
				{
					_DapSCPNumber = 1;
					_DapSCPParameter = 5;
					_DapKeyVersion = scpInfo[10];
					_dapKeyLength = 16;
					_DapMaximumSecurityLevel = 3;
				}
				else if (scpInfo[11] == 3)
				{
					_DapSCPNumber = 3;
					_DapSCPParameter = scpInfo[12];
					_DapKeyVersion = scpInfo[10];
					_dapKeyLength = 32;
					_DapMaximumSecurityLevel = 0x33;
				}
				if (_CIN.size() == 0 || (_CIN.size() == 1 && _CIN[0] == 0))
				{
					_CIN = scpInfo.substring(0, 10);
				}
				if (_serialNumber.size() == 0)
				{
					_serialNumber = scpInfo.substring(2, 8);
				}
			}
			else
				initUpdateFailed = true;

			connection->Transmit(tscrypto::tsCryptoData(gSelectDAP, sizeof(gSelectDAP)), outData);

			sw = connection->Transmit(tscrypto::tsCryptoData(gGetKeyInfo, sizeof(gGetKeyInfo)), keySpec);
			if (sw == 0x9000 || sw == 0x6283)
			{
				std::shared_ptr<TlvDocument> doc = TlvDocument::Create();

				if (doc->LoadTlv(keySpec))
				{
					int count = (int)doc->DocumentElement()->ChildCount();

					for (int i = 0; i < count; i++)
					{
						tscrypto::tsCryptoData data = doc->DocumentElement()->ChildAt(i)->InnerData();

						if (data.size() >= 4)
						{
							if (data[0] == 1 && data[1] < 0x70)
							{
								_DapKeyVersion = data[1];
								_dapKeyLength = data[3];
								_dapKeyType = data[2];
								keyType = data[2];
							}
							_DAPKeyList.push_back(::TopServiceLocator()->Finish<SmartCardKeyInformation>(new SmartCardKeyInformation(data[1], data[0], data[2], data[3], data.substring(4, data.size() - 4))));
						}
					}
				}
			}
			if (initUpdateFailed)
			{
				switch (keyType)
				{
				default:
				case 0x80:
					_DapSCPNumber = 1;
					_DapSCPParameter = 5;
					_DapMaximumSecurityLevel = 0x03;
					break;
				case 0x88:
					_DapSCPNumber = 3;
					_DapSCPParameter = 0x60;
					_DapMaximumSecurityLevel = 0x33;
					break;
				}
			}
		}
		else
			_DapAid.clear();

		connection->Transmit(tscrypto::tsCryptoData(gSelectISD, sizeof(gSelectISD)), outData);
		FixupData();
	}
	virtual bool isTransportLocked() const
	{
		return _transportLocked;
	}
private:
	int _chipId;
	bool _transportLocked;
	tscrypto::tsCryptoData _IIN, _CIN;
	tscrypto::tsCryptoString _osVersion;
	tscrypto::tsCryptoData _serialNumber;
	tscrypto::tsCryptoData _IsdAid;
	tscrypto::tsCryptoData _SsdAid;
	tscrypto::tsCryptoData _DapAid;
	uint8_t _IsdKeyVersion;
	uint8_t _IsdMaximumSecurityLevel;
	uint8_t _isdKeyLength;
	uint8_t _isdKeyType;
	uint8_t _SsdKeyVersion;
	uint8_t _SsdMaximumSecurityLevel;
	uint8_t _ssdKeyLength;
	uint8_t _ssdKeyType;
	uint8_t _DapKeyVersion;
	uint8_t _DapMaximumSecurityLevel;
	uint8_t _dapKeyLength;
	uint8_t _dapKeyType;
	uint8_t _IsdSCPNumber;
	uint8_t _IsdSCPParameter;
	uint8_t _SsdSCPNumber;
	uint8_t _SsdSCPParameter;
	uint8_t _DapSCPNumber;
	uint8_t _DapSCPParameter;
	std::vector<std::shared_ptr<ISmartCardKeyInformation> > _ISDKeyList;
	std::vector<std::shared_ptr<ISmartCardKeyInformation> > _SSDKeyList;
	std::vector<std::shared_ptr<ISmartCardKeyInformation> > _DAPKeyList;

	void FixupData()
	{
		if ((_IIN.size() == 0 || (_IIN.size() == 1 && _IIN[0] == 0)) &&
			_IsdSCPNumber == 3 && _IsdSCPParameter == 0x60)
		{
			if (_osVersion.size() == 0)
				_osVersion = "8211-0264-0001"; // default in these conditions to a contactless Armored Card chip
			if (_chipId == 0)
				_chipId = 0x10e;
			if (_isdKeyLength == 0)
			{
				_isdKeyLength = 32;
				_isdKeyType = 0x88;
			}
			if (_ssdKeyLength == 0)
			{
				_ssdKeyLength = 32;
				_ssdKeyType = 0x88;
			}
			if (_dapKeyLength == 0)
			{
				_dapKeyLength = 32;
				_dapKeyType = 0x88;
			}
		}
	}

};

tsmod::IObject* CreateSmartCardInformation()
{
	return dynamic_cast<tsmod::IObject*>(new SmartCardInformation());
}
