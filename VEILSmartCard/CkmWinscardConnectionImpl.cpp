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

class CkmWinscardConnectionImpl : public tsmod::IObject, public ICkmWinscardConnection
{
public:
	CkmWinscardConnectionImpl(std::shared_ptr<ICkmWinscardContext> context, const tscrypto::tsCryptoString& readerName, SCARDHANDLE handle, DWORD protocol) :
		m_handle(handle),
		m_protocol(protocol),
		m_hasTransaction(false),
		m_context(context),
		m_readerName(readerName),
		m_proxyMode(false)
	{
	}
	virtual ~CkmWinscardConnectionImpl(void) {}

	virtual bool Disconnect(SCardDisposition disposition)
	{
		if (m_handle == 0)
			return false;

		m_hasTransaction = false;
		if (tsSCardDisconnect(m_handle, disposition) != ERROR_SUCCESS)
		{
			m_handle = 0;
			return false;
		}
		m_handle = 0;
		return true;
	}
	virtual bool Reconnect(SCardDisposition disposition, uint32_t protocolsToAllow)
	{
		if (m_handle == 0)
			return false;

		m_hasTransaction = false;
		if (tsSCardReconnect(m_handle, SCARD_SHARE_SHARED, protocolsToAllow, disposition, &m_protocol) != ERROR_SUCCESS)
			return false;
		return true;
	}
	virtual bool Transmit(const tscrypto::tsCryptoData &dataToSend, int Le, tscrypto::tsCryptoData &dataReceived, size_t &sw)
	{
		if (!internalTransmit2(dataToSend, Le, dataReceived, sw))
			return false;

		if ((sw & 0xff00) == 0x9100 && dataToSend[0] == 0x80 && dataToSend[1] == 0xE2)
		{
			tscrypto::tsCryptoData cmd2;

			cmd2 += (uint8_t)0x80;
			cmd2 += (uint8_t)0xCA;
			cmd2 += (uint8_t)0x00;
			cmd2 += (uint8_t)0x72;
			cmd2 += (uint8_t)0x00;
			if (!internalTransmit2(cmd2, Le, dataReceived, sw))
				return false;
		}
		return true;
	}
	virtual bool GetAttribute(uint32_t attributeId, tscrypto::tsCryptoData &value)
	{
		DWORD len = 0;

		if (m_handle == 0)
			return false;

		if (tsSCardGetAttrib(m_handle, attributeId, NULL, &len) != ERROR_SUCCESS)
			return false;

		value.resize(len);

		if (tsSCardGetAttrib(m_handle, attributeId, value.rawData(), &len) != ERROR_SUCCESS)
			return false;
		return true;
	}
	virtual bool BeginTransaction()
	{
		LONG retVal;

		if (m_handle == 0)
			return false;
		if (m_hasTransaction)
			return false;

		if ((retVal = tsSCardBeginTransaction(m_handle)) != ERROR_SUCCESS)
		{
			if (retVal == SCARD_W_RESET_CARD)
			{
				if (tsSCardReconnect(m_handle, SCARD_SHARE_SHARED, m_protocol, SCardResetCard, &m_protocol) != ERROR_SUCCESS)
				{
					return false;
				}
				if ((retVal = tsSCardBeginTransaction(m_handle)) != ERROR_SUCCESS)
					return false;
			}
			else
				return false;
		}
		m_hasTransaction = true;
		return true;
	}
	virtual bool EndTransaction(SCardDisposition disposition)
	{
		if (m_handle == 0)
			return false;

		if (tsSCardEndTransaction(m_handle, disposition) != ERROR_SUCCESS)
			return false;
		m_hasTransaction = false;
		return true;
	}
	virtual bool IsInTransaction()
	{
		return m_hasTransaction;
	}
	virtual bool SetSecureChannel(std::shared_ptr<ServerSecureChannel> pObj)
	{
		m_channel.reset();
		if (pObj != NULL)
			m_channel = pObj;
		return true;
	}
	virtual bool GetSecureChannel(std::shared_ptr<ServerSecureChannel>& pObj)
	{
		pObj = m_channel;
		return true;
	}
	virtual const tscrypto::tsCryptoString GetReaderName()
	{
		return m_readerName;
	}
	virtual int  GetProtocol()
	{
		return m_protocol;
	}
	virtual bool IsInProxyMode()
	{
		return m_proxyMode;
	}
	virtual void SetProxyMode(bool setTo)
	{
		m_proxyMode = setTo;
	}
	virtual int Status()
	{
		char readerNames[500];
		DWORD cch = sizeof(readerNames) / sizeof(readerNames[0]);
		BYTE bAtr[32];
		DWORD cByte = sizeof(bAtr);
		DWORD dwState, dwProtocol;
		LONG lReturn;

		lReturn = tsSCardStatus(m_handle, readerNames, &cch, &dwState, &dwProtocol, bAtr, &cByte);
		if (lReturn != SCARD_S_SUCCESS)
			return 0;
		return (int)dwState;
	}

private:
	SCARDHANDLE m_handle;
	DWORD m_protocol;
	bool m_hasTransaction;
	std::shared_ptr<ICkmWinscardContext> m_context;
	tscrypto::tsCryptoString m_readerName;
	std::shared_ptr<ServerSecureChannel> m_channel;
	bool m_proxyMode;

	bool ShouldRetryCommand(int32_t errorCode)
	{
		//    int eventState;
		SCARD_READERSTATE state;

		switch (errorCode)
		{
		case (int32_t)0x80100067: //SCARD_W_UNPOWERED_CARD:
		case (int32_t)0x8010002F: //SCARD_E_COMM_DATA_LOST:
			if (tsSCardReconnect(m_handle, SCARD_SHARE_SHARED, m_protocol, SCardResetCard, &m_protocol) != ERROR_SUCCESS)
			{
				return false;
			}
			if (m_hasTransaction)
			{
				m_hasTransaction = false;
				BeginTransaction();
			}
			LOG(debug, "Retrying command - reconnected");
			return true;
		case (int32_t)0x80100068: //SCARD_W_RESET_CARD:
			if (tsSCardReconnect(m_handle, SCARD_SHARE_SHARED, m_protocol, SCardResetCard, &m_protocol) != ERROR_SUCCESS)
			{
				return false;
			}
			if (m_hasTransaction)
			{
				m_hasTransaction = false;
				BeginTransaction();
			}
			LOG(debug, "Retrying command - card was reset");
			return true;
		case (int32_t)0x80100069: //SCARD_W_REMOVED_CARD:
			state.dwCurrentState = 0;
			state.cbAtr = 0;
			state.dwEventState = SCARD_STATE_UNKNOWN;
			state.pvUserData = NULL;
			state.szReader = m_readerName.c_str();

			std::shared_ptr<ICkmWinscardHandle> handleAccessor = std::dynamic_pointer_cast<ICkmWinscardHandle>(m_context);
			if (!!handleAccessor)
			{
				if (tsSCardGetStatusChange(handleAccessor->GetHandle(), 0, &state, 1) == ERROR_SUCCESS &&
					(state.dwEventState & SCARD_STATE_PRESENT) != 0)
				{
					if (tsSCardReconnect(m_handle, SCARD_SHARE_SHARED, m_protocol, SCardResetCard, &m_protocol) != ERROR_SUCCESS)
					{
						return false;
					}
					if (m_hasTransaction)
					{
						m_hasTransaction = false;
						BeginTransaction();
					}
					LOG(debug, "Retrying command - card was removed and reinserted");
					return true;
				}
			}
			return false;
		}
		return false;
	}
	bool internalTransmit(const tscrypto::tsCryptoData &dataToSend, tscrypto::tsCryptoData &dataReceived, size_t &sw)
	{
		uint8_t outBuff[258];
		DWORD outLen = sizeof(outBuff);
		LONG errNo;
		bool repeat;
		tscrypto::tsCryptoData data(dataToSend);
		struct st
		{
			DWORD p1;
			DWORD p2;
		} sendType = { m_protocol, 8 };
		int64_t start, end;

		if (m_handle == 0)
			return false;

		do
		{
			do
			{
				repeat = false;
				LOG(debug, "SEND " << data);

				start = GetTicks();

				errNo = tsSCardTransmit(m_handle, (LPCSCARD_IO_REQUEST)&sendType, data.c_str(), (DWORD)data.size(), NULL, outBuff, &outLen);

				end = GetTicks();

				if (gTimeCommands)
				{
					LOG(debug, "; " << ToString()((end - start) / 1000.0) << " ms");
				}

				if (errNo != 0)
				{
					LOG(debug, "; ERROR " << (int)errNo);

					if (errNo == ERROR_MORE_DATA)
					{
						if (outLen > 258)
							return false;
						repeat = true;
						continue;
					}
					if ((errNo == 0x7A || errNo == SCARD_F_INTERNAL_ERROR) && outLen < 3)
					{
						outLen = 70;

						repeat = true;
						continue;
					}
					if (ShouldRetryCommand(errNo))
					{
						repeat = true;
						continue;
					}
					return false;
				}
			} while (repeat);

			if (outLen > 1)
			{
				sw = (outBuff[outLen - 2] << 8) | (outBuff[outLen - 1]);
				outLen -= 2;
			}

			tscrypto::tsCryptoData tmp;
			tmp.resize(2);
			tmp[0] = (uint8_t)(sw >> 8);
			tmp[1] = (uint8_t)(sw);

			LOG(debug, "; SW " << tmp);
			if (outLen > 0)
			{
				LOG(debug, "; RECV " << tscrypto::tsCryptoData(outBuff, outLen));
			}

			if ((sw & 0xFF00) == 0x6C00)
			{
				outLen = (uint8_t)(sw & 0xff);
				if (data.size() == 5)
				{
					data[4] = (uint8_t)outLen;
				}
				outLen += 2;
				repeat = true;
			}
			else if (sw == 0x9100 && !IsInProxyMode())
			{
				static const uint8_t getReturnDataSSDCmd[] = { 0x80, 0xCA, 0x00, 0x72, 0x00 };

				data.assign(getReturnDataSSDCmd, sizeof(getReturnDataSSDCmd));
				repeat = true;
				outLen = sizeof(outBuff);
			}
		} while (repeat);

		if (outLen > 0)
			dataReceived.append(outBuff, outLen);
		outLen = sizeof(outBuff);
		return true;
	}
	bool internalTransmit2(const tscrypto::tsCryptoData &dataToSend, int Le, tscrypto::tsCryptoData &dataReceived, size_t &sw)
	{
		tscrypto::tsCryptoData cmd(dataToSend);
		int multiPartResponseCount = 0;
		int realSW;

		dataReceived.clear();

		if (m_handle == 0)
			return false;

		//
		// Wrap the command here if there is an active secure channel
		//
		if (!!m_channel)
		{
			if ((m_channel->getSecurityLevel() & 3) != 0 && gLogDecryptedInfo)
			{
				LOG(debug, "; Command to wrap:  " << dataToSend);
			}
			if (!m_channel->Wrap(dataToSend, cmd))
				return false;
		}

		if (cmd.size() == 5 && Le < 256 && Le >= 0)
		{
			cmd[4] = (uint8_t)Le;
		}
		if (cmd.size() > 5 && (m_protocol & SCARD_PROTOCOL_T1) == SCARD_PROTOCOL_T1)
		{
			cmd.append((uint8_t)Le);
		}

		if (!internalTransmit(cmd, dataReceived, sw))
			return false;

		if (IsInProxyMode())
			return true;

		cmd.resize(5);
		cmd[0] = 0;
		cmd[1] = 0xc0;
		cmd[2] = 0;
		cmd[3] = 0;

		while ((sw & 0xff00) == 0x6100)
		{
			cmd[4] = (uint8_t)sw;

			if (!internalTransmit(cmd, dataReceived, sw))
				return false;
			multiPartResponseCount++;
		}

		if (!!m_channel && (m_channel->getSecurityLevel() & 0x30) != 0)
		{
			realSW = (int)sw;
			if (sw == 0x6310)
				sw = 0x9000;
			if (!m_channel->Unwrap(dataToSend[0], dataToSend[1], dataToSend[2], dataToSend[3], dataToSend[4], dataToSend.substring(5, 9999), 0x00, dataReceived, sw))
			{
				sw = realSW;
				return false;
			}
			sw = realSW;
			if (gLogDecryptedInfo)
			{
				LOG(debug, "; Unwrapped results:  " << dataReceived);
			}
		}
		else if (multiPartResponseCount > 1)
		{
			LOG(debug, ";- RECV " << dataReceived);
		}

		return true;
	}
};


std::shared_ptr<ICkmWinscardConnection> CreateWinscardConnection(std::shared_ptr<ICkmWinscardContext> context, const tscrypto::tsCryptoString& readerName, SCARDHANDLE handle, DWORD protocol)
{
	return ::TopServiceLocator()->Finish<ICkmWinscardConnection>(new CkmWinscardConnectionImpl(context, readerName, handle, protocol));
}
