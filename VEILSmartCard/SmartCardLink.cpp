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

class SmartCardLink : public ISmartCardLink, public ICkmWinscardChange, public tsmod::IObject
{
public:
	SmartCardLink() : _runnable(false), _sw(0x6fff), _changeCookie(0)
	{
		_monitor = ::TopServiceLocator()->try_get_instance<ICkmWinscardMonitor>("/SmartCardMonitor");
		if (!!_monitor)
		{
			_monitor->ScanForChanges();
		}
	}
	virtual ~SmartCardLink()
	{
		if (!!_card)
			_card->Disconnect(SCardLeaveCard);
		_card.reset();
		if (!!_monitor && _changeCookie != 0)
			_monitor->UnregisterChangeReceiver(_changeCookie);
		_changeCookie = 0;
		_context.reset();
		_monitor.reset();
	}

	// ISmartCardLink
	virtual bool CardInReader(const tscrypto::tsCryptoString& readerName)
	{
		ICkmWinscardReaderList list;

		list = _monitor->GetReaderList();

		auto it = std::find_if(list->begin(), list->end(), [&readerName](std::shared_ptr<ICkmWinscardReader>& reader)->bool{
			return reader->ReaderName() == readerName;
		});
		if (it == list->end())
			return false;
		return (*it)->Present();
	}
	virtual bool IsInTransaction()
	{
		if (!_card)
			return false;
		return _card->IsInTransaction();
	}
	virtual tscrypto::tsCryptoString GetReaderName()
	{
		return _readerName;
	}
	virtual void SetReaderName(const tscrypto::tsCryptoString& setTo)
	{
		if (_readerName != setTo)
		{
			disconnectFromReader();
			_readerName = setTo;
		}
	}
	virtual bool StartCardPump()
	{
		if (_worker.Active())
			return false;

		_runnable = true;
		_worker.SetWorker([this]()->int{ return DoWork(); });
		_worker.SetCompletion([this](){ _runnable = false; });
		return _worker.Start();

	}
	virtual void CloseCardPump()
	{
		_runnable = false;
		if (_worker.Active())
		{
			_worker.Cancel();
			if (!!_events)
				_events->ServerCancelledOperation(GetReaderName());
		}

	}
	virtual void GetEventHandler(std::shared_ptr<ISmartCardLinkEvents>& pVal)
	{
		pVal = _events;
	}
	virtual void SetEventHandler(std::shared_ptr<ISmartCardLinkEvents> setTo)
	{
		_events.reset();
		_events = setTo;
	}


	// ICkmWinscardChange
	virtual void readerAdded(const tscrypto::tsCryptoString &name)
	{
		if (!!_events)
			_events->ReaderInserted(name);
		if (name == GetReaderName())
		{
			if (!_card)
			{
				connectToReader();
			}
		}
	}
	virtual void readerRemoved(const tscrypto::tsCryptoString &name)
	{
		if (!!_events)
			_events->ReaderRemoved(name);
		if (name == GetReaderName())
		{
			if (!!_card)
			{
				disconnectFromReader();
			}
		}
	}
	virtual void cardInserted(const tscrypto::tsCryptoString &name)
	{
		if (!!_events)
			_events->CardInserted(name);
		if (name == GetReaderName())
		{
			if (!_card)
			{
				connectToReader();
			}
		}
	}
	virtual void cardRemoved(const tscrypto::tsCryptoString &name)
	{
		if (!!_events)
			_events->CardRemoved(name);
		if (name == GetReaderName())
		{
			if (!!_card)
			{
				disconnectFromReader();
			}
		}
	}

protected:
	void CardUpdated(const tscrypto::tsCryptoString& message)
	{
		if (!!_monitor && _changeCookie != 0)
			_monitor->UnregisterChangeReceiver(_changeCookie);
		_changeCookie = 0;
		if (!!_events)
		{
			_events->OnSuccess(GetReaderName(), message);
		}
	}

	void OperationFailed(const tscrypto::tsCryptoString& message)
	{
		if (!!_monitor && _changeCookie != 0)
			_monitor->UnregisterChangeReceiver(_changeCookie);
		_changeCookie = 0;
		if (!!_events)
		{
			_events->OnFailure(GetReaderName(), message);
		}
	}

	void Status(const tscrypto::tsCryptoString& message)
	{
		if (!!_events)
		{
			_events->OnStatus(GetReaderName(), message);
		}
	}
	bool CardInReader()
	{
		bool status;
		tscrypto::tsCryptoData atr = GetCardAtr();

		if (atr.size() == 0)
		{
			status = false;
		}
		else
		{
			status = true;
		}
		return status;
	}

private:
	void connectToReader()
	{
		disconnectFromReader();

		if (CardInReader(GetReaderName()))
		{
			if (!_context)
			{
				_monitor->CreateContext(_context);
			}
			if (_context->Connect(GetReaderName(), 3, _card) && !!_card)
				_card->SetProxyMode(true);
		}
	}

	void disconnectFromReader()
	{
		if (!!_card)
			_card->Disconnect(SCardLeaveCard);
		_card.reset();
	}

	int SendCardCommand(tscrypto::tsCryptoData& response, const tscrypto::tsCryptoData& cardData)
	{
		size_t sw;

		if (!_card  && CardInReader())
		{
			connectToReader();
		}
		if (!_card)
		{
			response.clear();
			return 0x6FFE;
		}
		_card->Transmit(cardData, 0, response, sw);
		return (int)sw;
	}
	void Disconnect(bool reset)
	{
		if (!!_card)
		{
			_card->Disconnect(reset ? SCardResetCard : SCardLeaveCard);
			_card.reset();
		}
	}

	void FinishTransaction(bool reset)
	{

		if (!_card)
			return;

		if (!_card->IsInTransaction())
			return;

		_card->EndTransaction(reset ? SCardResetCard : SCardLeaveCard);
		if (reset)
			Reconnect(false);
	}
	void Unpower()
	{
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

	void Reconnect(bool reset)
	{
		if (!_card && CardInReader())
		{
			connectToReader();
		}
		if (!!_card)
		{
			_card->Reconnect(reset ? SCardResetCard : SCardLeaveCard, 3);
		}
	}

	int GetCardStatus()
	{
		if (!_card && CardInReader())
		{
			connectToReader();
		}
		if (!!_card)
		{
			return _card->Status();
		}
		return 0;
	}

	void StartTransaction()
	{
		if (!_card && CardInReader())
		{
			connectToReader();
		}
		if (!_card)
		{
			throw tsstd::Exception("No card in reader " + GetReaderName());
		}
		_card->BeginTransaction();
	}

	tscrypto::tsCryptoData GetCardAtr()
	{
		ICkmWinscardReaderList list;

		list = _monitor->GetReaderList();

		auto it = std::find_if(list->begin(), list->end(), [this](std::shared_ptr<ICkmWinscardReader>& reader)->bool{
			return reader->ReaderName() == GetReaderName();
		});

		if (it == list->end())
		{
			return tscrypto::tsCryptoData();
		}
		return (*it)->ATR();
	}

	tscrypto::tsCryptoData GetCardAtr(const tscrypto::tsCryptoString& readerName)
	{
		ICkmWinscardReaderList list;

		list = _monitor->GetReaderList();

		auto it = std::find_if(list->begin(), list->end(), [readerName](std::shared_ptr<ICkmWinscardReader>& reader)->bool{
			return reader->ReaderName() == readerName;
		});

		if (it == list->end())
		{
			return tscrypto::tsCryptoData();
		}
		return (*it)->ATR();
	}
	int GetProtocol()
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



	int DoWork()
	{
		SmartCardCommandResponse response;
		std::shared_ptr<ISmartCardLink> Me(this);

		if (!_monitor)
			return -1;

		if (!_context)
		{
			_monitor->CreateContext(_context);
		}
		if (!_events)
			return -1;

		_changeCookie = _monitor->RegisterChangeReceiver(std::dynamic_pointer_cast<ICkmWinscardChange>(_me.lock()));

		do
		{
			try
			{
				response = _events->RespondToServer(GetReaderName(), _responseData, _sw);
				_sw = 0;
				_responseData.clear();
				switch (response.Command)
				{
				case scc_PingCard:
					_sw = GetCardStatus();
					break;
				case scc_CardCommand:
					_sw = SendCardCommand(_responseData, response.Data);
					break;
				case scc_CardInReader:
					_sw = CardInReader() ? 1 : 0;
					break;
				case scc_CardUpdated:
					_runnable = false;
					CardUpdated(response.Data.ToUtf8String());
					break;
				case scc_Disconnect:
					Disconnect(response.Data.size() > 0 && response.Data[0] != 0);
					break;
				case scc_FinishTransaction:
					FinishTransaction(response.Data.size() > 0 && response.Data[0] != 0);
					break;
				case scc_GetCardAtr:
					_responseData = GetCardAtr();
					break;
				case scc_GetProtocol:
					_sw = GetProtocol();
					break;
				case scc_OperationFailed:
					_runnable = false;
					OperationFailed(response.Data.ToUtf8String());
					break;
				case scc_Reconnect:
					Reconnect(response.Data.size() > 0 && response.Data[0] != 0);
					break;
				case scc_StartTransaction:
					StartTransaction();
					break;
				case scc_Status:
					Status(response.Data.ToUtf8String());
					break;
				case scc_Unpower:
					Unpower();
					break;
				case scc_GetTransactionStatus:
					_sw = (IsInTransaction() ? 1 : 0);
					break;
				}
			}
			catch (tsstd::Exception &ex)
			{
				OperationFailed(tsCryptoString(("EXCEPTION:  " + ex.Message()).c_str()));
				CloseCardPump();
			}
		} while (_runnable);
		if (!!_monitor && _changeCookie != 0)
			_monitor->UnregisterChangeReceiver(_changeCookie);
		_changeCookie = 0;
		return 0;
	}

protected:
	std::shared_ptr<ISmartCardLinkEvents>   _events;
	std::shared_ptr<ICkmWinscardConnection> _card;
	std::shared_ptr<ICkmWinscardMonitor>    _monitor;
	std::shared_ptr<ICkmWinscardContext>    _context;
	tscrypto::tsCryptoString                           _readerName;
	volatile bool                     _runnable;
	int                               _sw;
	tscrypto::tsCryptoData                            _responseData;
	int                               _changeCookie;
	tsThread                          _worker;
};

tsmod::IObject* CreateSmartCardLink()
{
	return dynamic_cast<tsmod::IObject*>(new SmartCardLink());
}
