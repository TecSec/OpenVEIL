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

#include "stdafx.h"

tsDebugStream debugSmartCard("SmartCard", DEBUG_LEVEL_SENSITIVE);

class SmartCardChangeReceiver
{
public:
	virtual void ReaderInserted(const tscrypto::tsCryptoString& readerName) = 0;
	virtual void ReaderRemoved(const tscrypto::tsCryptoString& readerName) = 0;
	virtual void CardInserted(const tscrypto::tsCryptoString& readerName) = 0;
	virtual void CardRemoved(const tscrypto::tsCryptoString& readerName) = 0;
};

class SmartcardChanges : public ICkmWinscardChange, public tsmod::IObject
{
public:
	SmartcardChanges(std::shared_ptr<SmartCardChangeReceiver> conn) : m_conn(conn) {};
	~SmartcardChanges() {};

	virtual void readerAdded(const tscrypto::tsCryptoString &name) { if (m_conn.expired()) return; m_conn.lock()->ReaderInserted(name); }
	virtual void readerRemoved(const tscrypto::tsCryptoString &name) { if (m_conn.expired()) return; m_conn.lock()->ReaderRemoved(name); }
	virtual void cardInserted(const tscrypto::tsCryptoString &name) { if (m_conn.expired()) return; m_conn.lock()->CardInserted(name); }
	virtual void cardRemoved(const tscrypto::tsCryptoString &name) { if (m_conn.expired()) return; m_conn.lock()->CardRemoved(name); }

private:
	std::weak_ptr<SmartCardChangeReceiver> m_conn;
};

class SmartCardConnection : public ISmartCardConnection
{
public:
	SmartCardConnection() :
		_connectionActive(false),
		_protocol(0),
		m_responseSw(0),
		m_firstCommand(true),
		m_failed(false),
		_stillProcessing(true)
	{
	}

	virtual ~SmartCardConnection()
	{
		m_channel.reset();
	}

	virtual bool StillProcessing()
	{
		return _stillProcessing;
	}

	virtual bool IsInTransaction()
	{
		m_command.Command = SmartCardCommand::scc_GetTransactionStatus;
		m_command.Data.clear();

		LOG(debugSmartCard, "Get transaction status");

		PrepareForCommand();

		if (!DoCommand())
			throw tsstd::CommunicationTimeoutException();
		m_command.Clear();

		LOG(debugSmartCard, "  " << ((m_responseSw != 0) ? "true" : "false"));
		if (!!_detailLogger)
			_detailLogger(tsCryptoString("    ;+ Get Transaction Status -> ") + ((m_responseSw != 0) ? "true" : "false"));

		return (m_responseSw != 0);
	}
	virtual void Disconnect(bool reset)
	{
		m_command.Command = SmartCardCommand::scc_Disconnect;
		m_command.Data = (uint8_t)(reset ? 255 : 0);

		LOG(debugSmartCard, "Disconnect from card" << (reset ? " with reset" : ""));
		if (!!_detailLogger)
			_detailLogger(tsCryptoString("    ;+ Disconnect from card") + (reset ? " with reset" : ""));

		PrepareForCommand();

		if (!DoCommand())
			throw tsstd::CommunicationTimeoutException();
		m_command.Clear();
		_connectionActive = false;
	}
	virtual void FinishTransaction(bool reset)
	{
		m_command.Command = SmartCardCommand::scc_FinishTransaction;
		m_command.Data = (uint8_t)(reset ? 255 : 0);

		LOG(debugSmartCard, "Finish Transaction" << (reset ? " with reset" : ""));
		if (!!_detailLogger)
			_detailLogger(tsCryptoString("    ;+ Finish Transaction") + (reset ? " with reset" : ""));

		PrepareForCommand();

		if (!DoCommand())
			throw tsstd::CommunicationTimeoutException();
		m_command.Clear();
		_connectionActive = false;
	}
	virtual void Unpower()
	{
		m_command.Command = SmartCardCommand::scc_Unpower;
		m_command.Data.clear();

		LOG(debugSmartCard, "Unpower card");
		if (!!_detailLogger)
			_detailLogger("    ;+ Unpower card");

		PrepareForCommand();

		if (!DoCommand())
			throw tsstd::CommunicationTimeoutException();
		m_command.Clear();
		_connectionActive = false;
	}
	virtual void Reconnect(bool reset)
	{
		m_command.Command = SmartCardCommand::scc_Reconnect;
		m_command.Data = (uint8_t)(reset ? 255 : 0);

		LOG(debugSmartCard, "Reconnect to card" << (reset ? " with reset" : ""));
		if (!!_detailLogger)
			_detailLogger(tsCryptoString("    ;+ Reconnect to card") + (reset ? " with reset" : ""));

		PrepareForCommand();

		if (!DoCommand())
			throw tsstd::CommunicationTimeoutException();
		m_command.Clear();
		_connectionActive = false;
	}
	virtual void StartTransaction()
	{
		m_command.Command = SmartCardCommand::scc_StartTransaction;
		m_command.Data.clear();

		LOG(debugSmartCard, "Start transaction");
		if (!!_detailLogger)
			_detailLogger("    ;+ Start transaction");

		PrepareForCommand();

		if (!DoCommand())
			throw tsstd::CommunicationTimeoutException();
		m_command.Clear();
		_connectionActive = true;
	}
	virtual void OperationFailed(const tscrypto::tsCryptoString& message)
	{
		m_command.Command = SmartCardCommand::scc_OperationFailed;
		m_command.Data = message.ToUTF8Data();

		LOG(debugSmartCard, "Operation failed with message '" << message << "'");
		if (!!_detailLogger)
			_detailLogger(tsCryptoString("    ;+ Operation failed with message '") + message + "'");

		_stillProcessing = false;

		PrepareForCommand();

		m_firstCommand = true;
		_connectionActive = false;
		m_failed = true;
	}
	virtual void Status(const tscrypto::tsCryptoString& message)
	{
		m_command.Command = SmartCardCommand::scc_Status;
		m_command.Data = message.ToUTF8Data();

		LOG(debugSmartCard, "Status with message '" << message << "'");
		if (!!_detailLogger)
			_detailLogger(tsCryptoString("    ;+ Status with message '") + message + "'");

		PrepareForCommand();

		if (!DoCommand())
			throw tsstd::CommunicationTimeoutException();
		m_command.Clear();
	}
	virtual void CardUpdated(const tscrypto::tsCryptoString& message)
	{
		if (m_failed)
			return;
		m_command.Command = SmartCardCommand::scc_CardUpdated;
		m_command.Data = message.ToUTF8Data();

		LOG(debugSmartCard, "Card updated");
		if (!!_detailLogger)
			_detailLogger("    ;+ Card updated");

		_stillProcessing = false;

		PrepareForCommand();

		m_firstCommand = true;
		_connectionActive = false;
	}
	virtual bool Transmit(const tscrypto::tsCryptoData& dataToSend, int Le, tscrypto::tsCryptoData& dataReceived, int& sw)
	{
#ifdef _DEBUG
		int64_t start, end;

		start = GetTicks();
		LOG(debugSmartCard, "");
#endif

		if (!internalTransmit2(dataToSend, Le, dataReceived, sw))
		{
#ifdef _DEBUG
			end = GetTicks();

			LOG(debugSmartCard, "; Total Time " << ToString()((end - start) / 1000.0) << " ms");
			if (!!_detailLogger)
				_detailLogger("    ;+ Total Time " + ToString()((end - start) / 1000.0) + " ms");
#endif
			return false;
		}

		if ((sw & 0xff00) == 0x9100 && dataToSend[0] == 0x80 && dataToSend[1] == 0xE2)
		{
			tscrypto::tsCryptoData cmd2("80 CA 00 72 00", tscrypto::tsCryptoData::HEX);

			if (!internalTransmit2(cmd2, Le, dataReceived, sw))
			{
#ifdef _DEBUG
				end = GetTicks();

				LOG(debugSmartCard, "; Total Time " << ToString()((end - start) / 1000.0) << " ms");
				if (!!_detailLogger)
					_detailLogger("    ;+ Total Time " + ToString()((end - start) / 1000.0) + " ms");
#endif
				return false;
			}
		}
#ifdef _DEBUG
		end = GetTicks();

		LOG(debugSmartCard, "; Total Time " << ToString()((end - start) / 1000.0) << " ms");
		if (!!_detailLogger)
			_detailLogger("    ;+ Total Time " + ToString()((end - start) / 1000.0) + " ms");
#endif
		return (sw & 0xFF00) == 0x9000;
	}
	virtual int Transmit(const tscrypto::tsCryptoData& dataToSend, int Le, tscrypto::tsCryptoData& dataReceived)
	{
		int sw = 0;

		Transmit(dataToSend, Le, dataReceived, sw);
		return sw;
	}
	virtual int Transmit(const tscrypto::tsCryptoData& dataToSend, tscrypto::tsCryptoData& dataReceived)
	{
		int sw = 0;

		Transmit(dataToSend, 0, dataReceived, sw);
		return sw;
	}
	virtual tscrypto::tsCryptoData GetCardAtr()
	{
		m_command.Command = SmartCardCommand::scc_GetCardAtr;
		m_command.Data.clear();

		LOG(debugSmartCard, "GetCardAtr");

		PrepareForCommand();

		if (!DoCommand())
			throw tsstd::CommunicationTimeoutException();
		m_command.Clear();

		LOG(debugSmartCard, "  returned '" << m_responseData.ToHexStringWithSpaces() << "'");
		if (!!_detailLogger)
			_detailLogger(tsCryptoString("    ;+ GetCardAtr  returned '") + m_responseData.ToHexStringWithSpaces() + "'");

		return m_responseData;
	}
	virtual bool CardInReader()
	{
		m_command.Command = SmartCardCommand::scc_CardInReader;
		m_command.Data.clear();
		m_responseSw = 0;

		LOG(debugSmartCard, "Card in reader");

		PrepareForCommand();

		if (!DoCommand())
			throw tsstd::CommunicationTimeoutException();
		m_command.Clear();

		LOG(debugSmartCard, "  returned " << ((m_responseSw != 0) ? "true" : "false"));
		if (!!_detailLogger)
			_detailLogger(tsCryptoString("    ;+ Card in reader -> ") + ((m_responseSw != 0) ? "true" : "false") + "");

		return m_responseSw != 0;
	}
	virtual tscrypto::tsCryptoData BuildCmd(BYTE CLA, BYTE INS, BYTE P1, BYTE P2, const tscrypto::tsCryptoData& data, BYTE Le)
	{
		int len;

		if (data.size() == 0)
			len = 5;
		else
			len = 5 + (int)data.size();

		tscrypto::tsCryptoData cmd;
		cmd.resize(5);
		cmd[0] = CLA;
		cmd[1] = INS;
		cmd[2] = P1;
		cmd[3] = P2;
		if (data.size() == 0)
			cmd[4] = Le;
		else
		{
			cmd[4] = (uint8_t)len;
			cmd += data;
		}
		return cmd;
	}
	virtual int SendCommand(BYTE CLA, BYTE INS, BYTE P1, BYTE P2, BYTE Lc, const tscrypto::tsCryptoData& inData, BYTE Le, tscrypto::tsCryptoData& outData)
	{
		int sw;

		if (inData.size() == 0)
			Lc = 0;
		else if (inData.size() < Lc)
		{
			Lc = (BYTE)inData.size();
		}
		tscrypto::tsCryptoData data(inData);

		if (inData.size() != 0 && Lc != inData.size())
		{
			data = inData.substring(0, Lc);
		}
		Transmit(BuildCmd(CLA, INS, P1, P2, data, Le), Le, outData, sw);
		return sw;
	}
	virtual int SendCommand(const tscrypto::tsCryptoData& inData, tscrypto::tsCryptoData& outData)
	{
		int sw;

		Transmit(inData, 0, outData, sw);
		return sw;
	}
	virtual bool GetSecureChannel(std::shared_ptr<ServerSecureChannel>& pVal)
	{
		pVal = m_channel;
		return !!pVal;
	}
	virtual bool SetSecureChannel(std::shared_ptr<ServerSecureChannel> setTo)
	{
		m_channel.reset();
		m_channel = setTo;
		return true;
	}

	virtual tscrypto::tsCryptoString ReaderName() const
	{
		return _readerName;
	}
	virtual void ReaderName(const tscrypto::tsCryptoString& setTo)
	{
		_readerName = setTo;
	}

	// These functions are called by the communication thread and make up the command processing pump
	//
	// When the communications thread has a response from the last command it calls CommunicateWithCard.  Then
	// the communications thread periodically polls the hasCommandReady for polling mode or waitForCommandReady if only
	// a single card connection is used for this overall job.
	// Then the communication thread calls GetCommand when either hasCommandReady or waitForCommand returns true and sends
	// the response to the client.
	//
	virtual void CommunicateWithCard(const tscrypto::tsCryptoData& response, int sw) = 0;
	virtual bool hasCommandReady() = 0;
	virtual bool waitForCommandReady() = 0;
	virtual SmartCardCommandData GetCommand() = 0;

	virtual void RegisterEventHandler(std::shared_ptr<ISmartCardConnectionEvents> handler) { _eventHandlers.push_back(handler); }
	virtual void UnregisterEventHandler(std::shared_ptr<ISmartCardConnectionEvents> handler) {
		_eventHandlers.erase(std::remove_if(_eventHandlers.begin(), _eventHandlers.end(), [handler](std::shared_ptr<ISmartCardConnectionEvents>& hndlr)->bool { return handler == hndlr; }), _eventHandlers.end());
	}
	virtual void PingCard()
	{
		if (m_failed)
			return;
		m_command.Command = SmartCardCommand::scc_PingCard;
		m_command.Data.clear();

		LOG(debugSmartCard, "Ping Card");
		if (!!_detailLogger)
			_detailLogger("    ;+ Ping Card");

		_stillProcessing = false;

		PrepareForCommand();

		m_firstCommand = true;
		_connectionActive = false;
	}

protected:
	bool internalTransmit2(const tscrypto::tsCryptoData& dataToSend, int Le, tscrypto::tsCryptoData& dataReceived, int& sw)
	{
		tscrypto::tsCryptoData cmd(dataToSend);
		int multiPartResponseCount = 0;
		int realSW;

		dataReceived.clear();

		//
		// Wrap the command here if there is an active secure channel
		//
		if (!!m_channel)
		{
			if ((m_channel->getSecurityLevel() & 3) != 0)
			{
#if _DEBUG
				LOG(debugSmartCard, "; Command to wrap -> " << dataToSend.ToHexStringWithSpaces());
				if (!!_detailLogger)
					_detailLogger("    ;+ Command to wrap -> " + dataToSend.ToHexStringWithSpaces());
#endif
				//debug << "; Command to wrap:  " << dataToSend << endl;
			}
			m_channel->Wrap(dataToSend, cmd);
		}

		if (cmd.size() == 5 && Le < 256 && Le >= 0)
		{
			cmd[4] = (byte)Le;
		}
		//if (cmd.Length > 5 && (Protocol & 2) == 2) // T=1
		//{
		//    cmd = ByteUtilities.Concat(cmd, new byte[] { (byte)Le });
		//}
		dataReceived.clear();

		if (!internalTransmit(cmd, dataReceived, sw))
			return false;

		cmd.clear();
		cmd.resize(5);

		cmd[0] = 0;
		cmd[1] = 0xc0;
		cmd[2] = 0;
		cmd[3] = 0;

		while ((sw & 0xff00) == 0x6100)
		{
			cmd[4] = (byte)sw;

			if (!internalTransmit(cmd, dataReceived, sw))
			{
				//#if DEBUG
				//            logger.Log("", Severity.Information);
				//#endif
				return false;
			}
			multiPartResponseCount++;
		}

		if (!!m_channel && (m_channel->getSecurityLevel() & 0x30) != 0)
		{
			realSW = sw;
			if (sw == 0x6310)
				sw = 0x9000;
			size_t swt = sw;
			m_channel->Unwrap(dataToSend[0], dataToSend[1], dataToSend[2], dataToSend[3], dataToSend[4], dataToSend.substring(5, 9999), 0x00, dataReceived, swt);
			sw = (int)swt;
			if (realSW == 0x6310)
				sw = realSW;
#if _DEBUG
			LOG(debugSmartCard, "; Response -> " << dataReceived.ToHexStringWithSpaces());
			if (!!_detailLogger)
				_detailLogger("    ;+     Response -> " + dataReceived.ToHexStringWithSpaces());
#endif
		}
		else if (multiPartResponseCount > 1)
		{
			//debug << ";- RECV " << dataReceived << endl;
		}

		//#if DEBUG
		//    logger.Log("", Severity.Information);
		//#endif
		return true;
	}

	bool internalTransmit(const tscrypto::tsCryptoData& dataToSend, tscrypto::tsCryptoData& dataReceived, int& sw)
	{
		tscrypto::tsCryptoData outBuff;
		int outLen = 0;
		bool repeat;
		tscrypto::tsCryptoData data(dataToSend);
		int64_t start, end;

		sw = 0;

		do
		{
			do
			{
				repeat = false;
				//debug << "SEND " << data << endl;

				start = GetTicks();

				LOG(debugSmartCard, "SEND " << data.ToHexStringWithSpaces());
				if (!!_detailLogger)
					_detailLogger("    ;+ SEND " + data.ToHexStringWithSpaces());

				m_command.Command = SmartCardCommand::scc_CardCommand;
				m_command.Data = data;

				PrepareForCommand();

				if (!DoCommand())
					throw tsstd::CommunicationTimeoutException();
				m_command.Clear();
				outBuff = m_responseData;
				sw = m_responseSw;

				LOG(debugSmartCard, "; SW " << ToHex()((uint16_t)sw));
				if (!!_detailLogger)
					_detailLogger("    ;+     SW " + ToHex()((uint16_t)sw));
				if (outBuff.size() > 0)
				{
					LOG(debugSmartCard, "; RECV " << outBuff.ToHexStringWithSpaces());
					if (!!_detailLogger)
						_detailLogger("    ;+     RECV " + outBuff.ToHexStringWithSpaces());
				}

				end = GetTicks();

				//if (gTimeCommands)
				//{
				LOG(debugSmartCard, "; " << ToString()((end - start) / 1000.0) << " ms");
				if (!!_detailLogger)
					_detailLogger("    ;+     " + ToString()((end - start) / 1000.0) + " ms");
				//}

				//if (errNo != 0)
				//{
				//    debug << "; ERROR " << errNo << endl;

				//    if (errNo == ERROR_MORE_DATA)
				//    {
				//        if (outLen > 258)
				//            return false;
				//        repeat = true;
				//        continue;
				//    }
				//    if ((errNo == 0x7A || errNo == SCARD_F_INTERNAL_ERROR) && outLen < 3)
				//    {
				//        outLen = 70;

				//        repeat = true;
				//        continue;
				//    }
				//    if (ShouldRetryCommand(errNo))
				//    {
				//        repeat = true;
				//        continue;
				//    }
				//    return false;
				//}
			} while (repeat);

			outLen = (int)outBuff.size();

			//tsCryptoData tmp;
			//tmp.resize(2);
			//tmp[0] = (uint8_t)(sw >> 8);
			//tmp[1] = (uint8_t)(sw);

			//debug << "; SW " << tmp << endl;
			//if (outLen > 0)
			//{
			//    debug << "; RECV " << tsCryptoData(outBuff, outLen) << endl;
			//}

			if ((sw & 0xFF00) == 0x6C00)
			{
				outLen = (byte)(sw & 0xff);
				if (data.size() == 5)
				{
					data[4] = (byte)outLen;
				}
				outLen += 2;
				repeat = true;
			}
		} while (repeat);

		if (outLen > 0)
			dataReceived = outBuff.substring(0, outLen);
		return true;
	}
	tscrypto::tsCryptoString BuildDebugInfo(SmartCardCommandData rsp)
	{
		switch (rsp.Command)
		{
		case SmartCardCommand::scc_OperationFailed:
		case SmartCardCommand::scc_Status:
			return rsp.Data.ToUtf8String();
		case SmartCardCommand::scc_Reconnect:
		case SmartCardCommand::scc_FinishTransaction:
		case SmartCardCommand::scc_Disconnect:
			if (rsp.Data[0] != 0)
				return "with Reset";
			return "no reset";
		default:
			return "";
		}
	}

	// If we are doing single threaded communications then these three functions have the following use:
	//
	//  PrepareForCommand - Do nothing
	//  DoCommand         - Execute the command here and only return false for fatal error
	//  ClearCommandQueue - Do nothing
	//
	// If we are doing multi-thread processing then the CommunicateWithCard function set shall be used and these functions have the following meaning:
	//
	// PrepareForCommand - Clear the command received event and set the CommandReady event to signal hasCommandReady
	// DoCommand         - Wait for a received command that shall be signalled from CommunicateWithCard
	// ClearCommandQueue - Set both commandReceived and commandReady so that all paths return control to the communications thread
	//
	virtual void PrepareForCommand() = 0;
	virtual bool DoCommand() = 0;
	virtual void ClearCommandQueue() = 0;
	virtual void setDetailMessageLogger(std::function<void(const tsCryptoStringBase& msg)> func) override
	{
		_detailLogger = func;
	}

protected:
	std::shared_ptr<ServerSecureChannel> m_channel;
	bool _connectionActive;
	int  _protocol;

	tscrypto::tsCryptoData m_responseData;
	int m_responseSw;
	SmartCardCommandData m_command;
	bool m_firstCommand;
	bool m_failed;
	int64_t commandReadyTimeout;
	tscrypto::tsCryptoString _readerName;
	std::vector<std::shared_ptr<ISmartCardConnectionEvents> > _eventHandlers;
	bool _stillProcessing;
	std::function<void(const tsCryptoStringBase& msg)> _detailLogger;


	void FireOnCardUpdated(const tscrypto::tsCryptoString& message)
	{
		for (std::shared_ptr<ISmartCardConnectionEvents>& hndlr : _eventHandlers)
		{
			hndlr->CardUpdated(message);
		}
	}
	void FireOnOperationFailed(const tscrypto::tsCryptoString& msg)
	{
		for (std::shared_ptr<ISmartCardConnectionEvents>& hndlr : _eventHandlers)
		{
			hndlr->OperationFailed(msg);
		}
	}
	void FireOnStatus(const tscrypto::tsCryptoString& msg)
	{
		for (std::shared_ptr<ISmartCardConnectionEvents>& hndlr : _eventHandlers)
		{
			hndlr->Status(msg);
		}
	}
};


class LocalSmartCardConnection : public SmartCardConnection, public SmartCardChangeReceiver, public tsmod::IObject
{
public:
	LocalSmartCardConnection() : cookie(0) {
		_watchdog.SetWorker([this]()->int {
			bool done = false;
			while (!done)
			{
				switch (_watchdog.cancelEvent().WaitForEvent(3000)) // 3 second timer until cancelled
				{
				case tscrypto::CryptoEvent::Succeeded_Object1:
				case tscrypto::CryptoEvent::AlreadyLocked:
					done = true;
					break;
				case tscrypto::CryptoEvent::Failed:
					return 1;
				case tscrypto::CryptoEvent::Timeout:
					GetCardStatus();
					break;
				}
			}
			return 0;
		});
	}
	virtual ~LocalSmartCardConnection()
	{
		StopWatchdog();
		if (!!_card)
			_card->Disconnect(SCardLeaveCard);
		_card.reset();
		if (!!_monitor && cookie != 0)
			_monitor->UnregisterChangeReceiver(cookie);
		_monitor.reset();
		cookie = 0;
	}

	virtual void SetCancelEvent(tscrypto::CryptoEvent* cancelEvent) { UNREFERENCED_PARAMETER(cancelEvent); }
	// These functions are called by the communication thread and make up the command processing pump
	//
	// When the communications thread has a response from the last command it calls CommunicateWithCard.  Then
	// the communications thread periodically polls the hasCommandReady for polling mode or waitForCommandReady if only
	// a single card connection is used for this overall job.
	// Then the communication thread calls GetResponse when either hasCommandReady or waitForCommand returns true and sends
	// the response to the client.
	//
	virtual void CommunicateWithCard(const tscrypto::tsCryptoData& response, int sw)
	{
		UNREFERENCED_PARAMETER(response);
		UNREFERENCED_PARAMETER(sw);
		// intentionally empty
	}
	virtual bool hasCommandReady()
	{
		// intentionally empty
		return false;
	}
	virtual bool waitForCommandReady()
	{
		// intentionally empty
		return false;
	}
	virtual SmartCardCommandData GetCommand()
	{
		return m_command;
	}

	virtual void CardInserted(const tscrypto::tsCryptoString& readerName)
	{
		UNREFERENCED_PARAMETER(readerName);
	}
	virtual void CardRemoved(const tscrypto::tsCryptoString& readerName)
	{
		UNREFERENCED_PARAMETER(readerName);
	}
	virtual void ReaderInserted(const tscrypto::tsCryptoString& readerName)
	{
		UNREFERENCED_PARAMETER(readerName);
	}
	virtual void ReaderRemoved(const tscrypto::tsCryptoString& readerName)
	{
		UNREFERENCED_PARAMETER(readerName);
	}

	virtual bool Start()
	{
		StopWatchdog();
		if (!!_card)
			_card->Disconnect(SCardLeaveCard);
		_card.reset();
		if (!!_monitor && cookie != 0)
			_monitor->UnregisterChangeReceiver(cookie);
		_monitor.reset();
		cookie = 0;

		_monitor = ::TopServiceLocator()->try_get_instance<ICkmWinscardMonitor>("/SmartCardMonitor");

		if (!!_monitor && !!GetChangeMonitor())
		{
			GetChangeMonitor()->LookForChanges();
			_monitor->ScanForChanges();

			if (!_monitor->CreateContext(_context))
				return false;

			ICkmWinscardReaderList readers = _monitor->GetReaderList();
			for (auto r : *readers)
			{
				ReaderInserted(r->ReaderName());
				if (!r->Empty())
					CardInserted(r->ReaderName());
			}
			cookie = _monitor->RegisterChangeReceiver(::TopServiceLocator()->Finish<ICkmWinscardChange>(new SmartcardChanges(std::dynamic_pointer_cast<SmartCardChangeReceiver>(_me.lock()))));
			return true;
		}
		return false;
	}

	virtual bool connectToReader()
	{
		if (!_monitor)
			return false;

		disconnectFromReader();

		if (_card_CardInReader(ReaderName()))
		{
			if (!_context)
				if (!_monitor->CreateContext(_context))
					return false;

			if (!_context)
				return false;

			_context->Connect(ReaderName(), 3, _card);
			if (!!_card && !!_detailLogger)
				_card->setDetailMessageLogger(_detailLogger);

			// TODO:  Review me _card->SetProxyMode(true);
		}
		return !!_card;
	}
	virtual bool disconnectFromReader()
	{
		StopWatchdog();
		if (!!_card)
			_card->Disconnect(SCardLeaveCard);
		_card.reset();
		return true;
	}

	tscrypto::tsCryptoString ReaderName() const
	{
		return m_readerName;
	}
	void ReaderName(const tscrypto::tsCryptoString& setTo)
	{
		if (setTo != m_readerName)
		{
			disconnectFromReader();
			m_readerName = setTo;
		}
	}
	virtual int GetCardStatus()
	{
		if (!_card)
			return 0;
		return _card->Status();
	}

protected:
	// If we are doing single threaded communications then these three functions have the following use:
	//
	//  PrepareForCommand - Do nothing
	//  DoCommand         - Execute the command here and only return false for fatal error
	//  ClearCommandQueue - Do nothing
	//
	// If we are doing multi-thread processing then the CommunicateWithCard function set shall be used and these functions have the following meaning:
	//
	// PrepareForCommand - Clear the command received event and set the CommandReady event to signal hasCommandReady
	// DoCommand         - Wait for a received command that shall be signalled from CommunicateWithCard
	// ClearCommandQueue - Set both commandReceived and commandReady so that all paths return control to the communications thread
	//
	virtual void PrepareForCommand()
	{
		// intentionally empty
	}
	virtual bool DoCommand()
	{
		if (!_context)
			return false;

		m_responseSw = 0;
		m_responseData.clear();

		switch (m_command.Command)
		{
		case SmartCardCommand::scc_CardCommand:
			m_responseSw = _card_SendCardCommand(m_command.Data, m_responseData);
			break;
		case SmartCardCommand::scc_CardInReader:
			m_responseSw = _card_CardInReader() ? 1 : 0;
			break;
		case SmartCardCommand::scc_CardUpdated:
			FireOnCardUpdated(m_command.Data.ToUtf8String());
			return false;
		case SmartCardCommand::scc_Disconnect:
			_card_Disconnect(m_command.Data.size() > 0 && m_command.Data[0] != 0);
			break;
		case SmartCardCommand::scc_FinishTransaction:
			_card_FinishTransaction(m_command.Data.size() > 0 && m_command.Data[0] != 0);
			break;
		case SmartCardCommand::scc_GetCardAtr:
			m_responseData = _card_GetCardAtr();
			break;
		case SmartCardCommand::scc_GetProtocol:
			m_responseSw = _card_GetProtocol();
			break;
		case SmartCardCommand::scc_OperationFailed:
			FireOnOperationFailed(m_command.Data.ToUtf8String());
			return false;
		case SmartCardCommand::scc_Reconnect:
			_card_Reconnect(m_command.Data.size() > 0 && m_command.Data[0] != 0);
			break;
		case SmartCardCommand::scc_StartTransaction:
			_card_StartTransaction();
			break;
		case SmartCardCommand::scc_Status:
			FireOnStatus(m_command.Data.ToUtf8String());
			break;
		case SmartCardCommand::scc_Unpower:
			_card_Unpower();
			break;
		case SmartCardCommand::scc_GetTransactionStatus:
			m_responseSw = (_card_IsInTransaction() ? 1 : 0);
			break;
		case SmartCardCommand::scc_PingCard:
			GetCardStatus();
			m_responseSw = 1;
			break;
        default:
            break;
		}
		return true;
	}
	virtual void ClearCommandQueue()
	{
		// intentionally empty
	}


	int    _card_SendCardCommand(const tscrypto::tsCryptoData& cmd, tscrypto::tsCryptoData&  outData)
	{
		size_t sw;

		if (!_card && CardInReader())
		{
			connectToReader();
		}
		if (!_card)
		{
			outData.clear();
			return 0x6FFE;
		}
		_card->Transmit(cmd, 0, outData, sw);
		return (int)sw;
	}
	bool   _card_CardInReader()
	{
		if (!_monitor)
			return false;

		ICkmWinscardReaderList readers = _monitor->GetReaderList();
		for (auto r : *readers)
		{
			if (r->ReaderName() == m_readerName)
				return (!r->Empty());
		}
		return false;
	}
	bool   _card_CardInReader(const tscrypto::tsCryptoString& readerName)
	{
		if (!_monitor)
			return false;

		ICkmWinscardReaderList readers = _monitor->GetReaderList();
		for (auto r : *readers)
		{
			if (r->ReaderName() == readerName)
				return (!r->Empty());
		}
		return false;
	}
	void   _card_Disconnect(bool reset)
	{
		StopWatchdog();
		if (!!_card)
		{
			_card->Disconnect(reset ? SCardResetCard : SCardLeaveCard);
			_card.reset();
		}
	}
	void   _card_FinishTransaction(bool reset)
	{
		if (!_card)
			return;

		if (!_card->IsInTransaction())
			return;

		_card->EndTransaction(reset ? SCardResetCard : SCardLeaveCard);
		if (reset)
			Reconnect(false);
	}
	tscrypto::tsCryptoData _card_GetCardAtr()
	{
		return _card_GetCardAtr(ReaderName());
	}
	tscrypto::tsCryptoData _card_GetCardAtr(const tscrypto::tsCryptoString& readerName)
	{
		if (!_monitor)
			return tscrypto::tsCryptoData();

		ICkmWinscardReaderList readers = _monitor->GetReaderList();
		for (auto r : *readers)
		{
			if (r->ReaderName() == readerName)
				return r->ATR();
		}
		return tscrypto::tsCryptoData();
	}
	int    _card_GetProtocol()
	{
		if (!_card && CardInReader())
		{
			connectToReader();
		}
		if (!_card)
		{
			return 0;
		}
		return _card->GetProtocol();
	}
	void   _card_Reconnect(bool reset)
	{
		StopWatchdog();
		if (!_card && CardInReader())
		{
			connectToReader();
		}
		if (!!_card)
		{
			_card->Reconnect(reset ? SCardResetCard : SCardLeaveCard, 3);
		}
	}
	void   _card_StartTransaction()
	{
		if (!_card && CardInReader())
		{
			connectToReader();
		}
		if (!_card)
		{
			return;
		}
		_card->BeginTransaction();
		if (!_watchdog.Active())
			_watchdog.Start();
	}
	void   _card_Unpower()
	{
		StopWatchdog();
		if (!_card && CardInReader())
		{
			connectToReader();
		}
		if (!!_card)
		{
			_card->Reconnect(SCardUnpowerCard, 3);
			_card->Reconnect(SCardLeaveCard, 3);
		}
	}
	bool   _card_IsInTransaction()
	{
		if (!_card)
			return false;
		return _card->IsInTransaction();
	}

	//event_Message OnCardInserted;
	//event_Message OnCardRemoved;
	//event_Message OnReaderAdded;
	//event_Message OnReaderRemoved;

	void StopWatchdog()
	{
		if (_watchdog.Active())
		{
			_watchdog.Cancel();
			if (!_watchdog.WaitForThread(30000))
				_watchdog.Kill();
		}
	}

private:
	std::shared_ptr<ICkmWinscardMonitor> _monitor;
	std::shared_ptr<ICkmWinscardContext> _context;
	std::shared_ptr<ICkmWinscardConnection> _card;
	tscrypto::tsCryptoString m_readerName;
	int cookie;
	tsThread                                _watchdog;
};

tsmod::IObject* CreateLocalSmartCardConnectionObject()
{
	return dynamic_cast<tsmod::IObject*>(new LocalSmartCardConnection());
}

class ServerSmartCardConnection : public SmartCardConnection, public tsmod::IObject
{
public:
	ServerSmartCardConnection() :
		commandReady(),
		commandReceived(),
		cancelEvent(nullptr),
		m_lRefCount(0) {}
	virtual ~ServerSmartCardConnection() {}

	virtual void SetCancelEvent(tscrypto::CryptoEvent* _cancelEvent)
	{
		this->cancelEvent = _cancelEvent;
	}
	virtual int GetCardStatus()
	{
		return 0;
	}
	virtual void CommunicateWithCard(const tscrypto::tsCryptoData& response, int sw)
	{
		m_responseData = response;
		m_responseSw = sw;
		if (!m_firstCommand)
		{
			//logger.Log(() => { return "CommunicateWithCard:  Received response of SW: 0x" + ByteUtilities.BytesToHex(ByteUtilities.NumberToBytes(sw)); }, Severity.Trace);
			commandReceived.Set();
		}
		else
		{
			m_firstCommand = false;
			//logger.Log(() => { return "CommunicateWithCard:  Starting the pump"; }, Severity.Trace);
		}
		commandReadyTimeout = GetTicks() + 600000000LL; // 10 minutes
	}
	virtual bool hasCommandReady()
	{
		int64_t current;

		if (cancelEvent == nullptr)
			return false;

		current = GetTicks();
		if (current > commandReadyTimeout)
		{
			m_command.Command = SmartCardCommand::scc_OperationFailed;
			m_command.Data.clear();
			return true;
		}
		switch (commandReady.WaitForEvents(0, *cancelEvent))
		{
		case tscrypto::CryptoEvent::Succeeded_Object1:
			return true;
		default:
			return false;
		}
	}
	virtual bool waitForCommandReady()
	{
		if (cancelEvent == nullptr)
			return false;

		switch (commandReady.WaitForEvents(600000, *cancelEvent))
		{
		case tscrypto::CryptoEvent::Succeeded_Object1:
			return true;
		default:
			m_command.Command = SmartCardCommand::scc_OperationFailed;
			m_command.Data.clear();
			return true;
		}
	}
	virtual SmartCardCommandData GetCommand()
	{
		if (m_command.Command == SmartCardCommand::scc_CardUpdated || m_command.Command == SmartCardCommand::scc_OperationFailed)
			_stillProcessing = false;
		return m_command;
	}
	virtual bool Start()
	{
		return true;
	}

protected:
	virtual void PrepareForCommand()
	{
		commandReceived.Reset();
		commandReady.Set();
	}
	virtual bool DoCommand()
	{
		if (cancelEvent == nullptr)
			return false;

		switch (commandReceived.WaitForEvents(600000, *cancelEvent))
		{
		case tscrypto::CryptoEvent::Succeeded_Object1:
			return true;
		default:
			return false;
		}
	}
	virtual void ClearCommandQueue()
	{
		commandReceived.Set();
		commandReady.Set();
	}

protected:
	tscrypto::CryptoEvent commandReady;
	tscrypto::CryptoEvent commandReceived;
	tscrypto::CryptoEvent *cancelEvent;
	uint32_t m_lRefCount;
};

extern tsmod::IObject* CreateServerSmartCardConnectionObject()
{
	return dynamic_cast<tsmod::IObject*>(new ServerSmartCardConnection());
}

