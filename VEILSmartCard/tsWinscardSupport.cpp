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
#include "tsWinscardSupport.h"

static volatile long checkingForChanges = 0;
//static uint32_t gNextReaderName = 0;
static uint32_t gNextConsumer = 0;

static fnSCardEstablishContext    m__EstablishContext = nullptr;
static fnSCardReleaseContext	  m__ReleaseContext = nullptr;
static fnSCardListReaders		  m__ListReaders = nullptr;
static fnSCardConnect			  m__Connect = nullptr;
static fnSCardDisconnect		  m__Disconnect = nullptr;
static fnSCardTransmit			  m__Transmit = nullptr;
static fnSCardGetStatusChange     m__GetStatusChange = nullptr;
static fnSCardReconnect           m__Reconnect = nullptr;
static fnSCardGetAttrib           m__GetAttrib = nullptr;
static fnSCardBeginTransaction    m__BeginTransaction = nullptr;
static fnSCardEndTransaction      m__EndTransaction = nullptr;
static fnSCardStatus              m__Status = nullptr;
static fnSCardAccessStartedEvent  m__AccessStartedEvent = nullptr;
static fnSCardReleaseStartedEvent m__ReleaseStartedEvent = nullptr;
static fnSCardCancel              m__Cancel = nullptr;
static fnSCardFreeMemory          m__FreeMemory = nullptr;
static fnSCardIsValidContext      m__isValidContext = nullptr;
static XP_MODULE                  m_hLib = XP_MODULE_INVALID;

//static int gPolling = 250000;

static tsDebugStream scdebug("WINSCARD", DEBUG_LEVEL_INFORMATION);

static LONG tsSCardListReaders(IN SCARDCONTEXT hContext, IN const char *mszGroup, OUT char *mszReaders, IN OUT LPDWORD pcchReaders);

class WinscardMonitorThread : public CancelableTsThread
{
public:
	WinscardMonitorThread() : _context(0), _accessEvent(0), _initialized(true, false)
	{
		_consumers = CreateConsumerList();
		LOG(scdebug, "Configuring smart card thread");
		SetWorker([this]()->int { return monitor(); });
		SetCancel([this]() { cancelMonitor(); });
	}
	virtual ~WinscardMonitorThread()
	{
		LOG(scdebug, "Shutting down smart card thread");
		if (_accessEvent != 0)
		{
			tsSCardReleaseStartedEvent();
			_accessEvent = 0;
		}
		if (Active())
		{
			Cancel();
			if (!WaitForThread(30000))
				Kill();
		}
		for (size_t i = 0; i < _readers.size(); i++)
		{
			if (_readers[i].szReader != nullptr)
			{
				free((void*)_readers[i].szReader);
				_readers[i].szReader = nullptr;
			}
		}
		_readers.clear();
	}
	virtual bool Start()
	{
		_initialized.Reset();
		if (!CancelableTsThread::Start())
		{
			return false;
		}
		if (_initialized.WaitForEvent(3000) != tscrypto::CryptoEvent::Succeeded_Object1)
			return false;
		return true;
	}
	ReaderInfoList ReaderList()
	{
		ReaderInfoList infoList = CreateReaderInfoList();

		if (!Active())
		{
			return infoList;
		}

		TSAUTOLOCKER locker(_readerNameListLock);

		for (size_t i = 1; i < _readers.size(); i++)
		{
			ReaderInfo info;

			info.atr.assign(_readers[i].rgbAtr, _readers[i].cbAtr);
			info.name = _readers[i].szReader;
			info.status = _readers[i].dwCurrentState;
			infoList->push_back(info);
		}
		return infoList;
	}
	uint32_t AddConsumer(std::shared_ptr<TSWC_ChangeConsumer> func)
	{
		uint32_t id = InterlockedIncrement(&gNextConsumer);
		tscrypto::tsCryptoStringList readers = CreateTsAsciiList();
		tscrypto::tsCryptoStringList cards = CreateTsAsciiList();
		int i, count;

		if (func == NULL)
		{
			return 0;
		}
		else
		{
			Consumer cons;
			cons.func = func;
			cons.id = id;

			TSAUTOLOCKER locker(_consumerListLock);
			_consumers->push_back(cons);
		}
		{
			TSAUTOLOCKER locker(_readerNameListLock);

			for (size_t i = 1; i < _readers.size(); i++)
			{
				readers->push_back(_readers[i].szReader);

				if ((_readers[i].dwCurrentState & SCARD_STATE_PRESENT) != 0)
				{
					cards->push_back(_readers[i].szReader);
				}
			}
		}
		count = (int)readers->size();
		for (i = 0; i < count; i++)
		{
			func->ReaderAdded(readers->at(i));
		}
		count = (int)cards->size();
		for (i = 0; i < count; i++)
		{
			func->CardInserted(cards->at(i));
		}
		//FTRACE((program, ("Returning cookie %d"), id));
		return id;
	}
	void RemoveConsumer(uint32_t consumerCookie)
	{
		TSAUTOLOCKER locker(_consumerListLock);

		//FTRACE((program, ("Removing cookie %d"), consumerCookie));
		auto it = std::find_if(_consumers->begin(), _consumers->end(), [consumerCookie](const Consumer& obj) -> bool { return obj.id == consumerCookie; });
		if (it != _consumers->end())
			_consumers->erase(it);
	}
	void FireReaderAdded(const tscrypto::tsCryptoString &readerName)
	{
		SEH_TRY
			_FireReaderAdd(readerName);
		SEH_CATCH
			//FTRACE((program, ("EXCEPTION:  TS_FireChange - SEH [%08X]"), GetExceptionCode()));
			SEH_DONE
	}
	void FireReaderRemoved(const tscrypto::tsCryptoString &readerName)
	{
		SEH_TRY
			_FireReaderRemoved(readerName);
		SEH_CATCH
			//FTRACE((program, ("EXCEPTION:  TS_FireChange - SEH [%08X]"), GetExceptionCode()));
			SEH_DONE
	}
	void FireCardInserted(const tscrypto::tsCryptoString &readerName)
	{
		SEH_TRY
			_FireCardInsert(readerName);
		SEH_CATCH
			//FTRACE((program, ("EXCEPTION:  TS_FireChange - SEH [%08X]"), GetExceptionCode()));
			SEH_DONE
	}
	void FireCardRemoved(const tscrypto::tsCryptoString &readerName)
	{
		SEH_TRY
			_FireCardRemoved(readerName);
		SEH_CATCH
			//FTRACE((program, ("EXCEPTION:  TS_FireChange - SEH [%08X]"), GetExceptionCode()));
			SEH_DONE
	}
	void UpdateReaderNameList()
	{
		SEH_TRY
			_UpdateReaderNameList();
		SEH_CATCH
			//FTRACE((program, ("EXCEPTION:  UpdateReaderNameList - SEH [%08D]"), GetExceptionCode()));
			SEH_DONE
	}

protected:
	SCARDCONTEXT _context;
	//ReaderNameList _readers;
	std::vector<SCARD_READERSTATE> _readers;
	tscrypto::AutoCriticalSection _readerNameListLock;
	ConsumerList _consumers;
	tscrypto::AutoCriticalSection _consumerListLock;
	HANDLE _accessEvent;
	CryptoEvent _initialized;

	int _monitor()
	{
		LOG(scdebug, "In the inner monitor loop");
		while ((_accessEvent != 0 || (_context != 0 && _readers.size() > 0)) && cancel.WaitForEvent(0) == tscrypto::CryptoEvent::Timeout)
		{
#ifdef _WIN32
			if (_accessEvent != nullptr && _context == 0)
			{
				HANDLE list[2] = { _accessEvent, cancel.GetHandle() };

				switch (WaitForMultipleObjects(2, list, FALSE, INFINITE))
				{
				case WAIT_OBJECT_0:
					LOG(scdebug, "Got notice of SCARD running");

					if (tsSCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &_context) != SCARD_S_SUCCESS)
					{
					}
					// Build the initial list of readers
					if (_context != 0)
						_UpdateReaderNameList();
					break;
				case WAIT_OBJECT_0 + 1:
					LOG(scdebug, "Cancelled");
					return 0;
				case WAIT_FAILED:
				default:
					LOG(scdebug, "Thread FAILURE");
					return 1;
				}
			}
			else
#endif // _WIN32
			{
				_readers[0].pvUserData = nullptr;
				XP_Sleep(100);
				bool hadChange = false;
				{
					// This convoluted code is here to avoid a deadlock situation.  We must first lock the list and clone it.  
					// Then we wait in a potentially long process (SCardGetStatusChange).
					// Then we have to lock the list again and sync the lists back up for later processing.
					std::vector<SCARD_READERSTATE> tmpReaders;
					{
						// Duplicate the list
						TSAUTOLOCKER lock(_readerNameListLock);
						for (auto reader : _readers)
						{
							tmpReaders.push_back(reader);
						}
					}
					hadChange = (tsSCardGetStatusChange(_context, INFINITE, tmpReaders.data(), (DWORD)tmpReaders.size()) == SCARD_S_SUCCESS);
					{
						// sync up the lists
						TSAUTOLOCKER lock(_readerNameListLock);
						for (auto reader : tmpReaders)
						{
							auto it = std::find_if(_readers.begin(), _readers.end(), [&reader](SCARD_READERSTATE& rdr) { return reader.szReader == rdr.szReader; });  // we can compare the szReader pointers as they are shallow copied above
							if (it != _readers.end())
							{
								*it = reader;
							}
						}
					}
				}
				if (hadChange)
				{
					// Process the changes here
					tscrypto::tsCryptoStringList cardsRemoved = CreateTsAsciiList();
					tscrypto::tsCryptoStringList cardsAdded = CreateTsAsciiList();
					bool haveReaderChanges = false;

					{
						TSAUTOLOCKER lock(_readerNameListLock);
						for (size_t i = 0; i < _readers.size(); i++)
						{
							SCARD_READERSTATE& readerState = _readers[i];

							if (readerState.dwEventState & SCARD_STATE_CHANGED)
							{
								LOG(scdebug, "Reader state changed  Name: " << readerState.szReader << "  state: " << ToHex()((uint32_t)readerState.dwEventState));
								if (i == 0)
								{
									if ((readerState.dwEventState & 0xffff0000) != (readerState.dwCurrentState & 0xffff0000))
									{
										haveReaderChanges = true;
									}
								}
								else if ((readerState.dwEventState & 0xffff0000) != (readerState.dwCurrentState & 0xffff0000))
								{
									if (readerState.dwCurrentState & SCARD_STATE_PRESENT)
									{
										tscrypto::tsCryptoString name(readerState.szReader);
										if (std::find_if(cardsRemoved->begin(), cardsRemoved->end(), [&name](tscrypto::tsCryptoString& str) {return TsStriCmp(name, str) == 0; }) == cardsRemoved->end())
											cardsRemoved->push_back(name);
									}
									if (readerState.dwEventState & SCARD_STATE_PRESENT)
									{
										tscrypto::tsCryptoString name(readerState.szReader);
										if (std::find_if(cardsAdded->begin(), cardsAdded->end(), [&name](tscrypto::tsCryptoString& str) {return TsStriCmp(name, str) == 0; }) == cardsAdded->end())
											cardsAdded->push_back(name);
									}
								}
								else if ((readerState.dwEventState & SCARD_STATE_PRESENT) != (readerState.dwCurrentState & SCARD_STATE_PRESENT))
								{
									if ((readerState.dwEventState & SCARD_STATE_PRESENT) == 0)
									{
										if (readerState.dwCurrentState & SCARD_STATE_PRESENT)
										{
											tscrypto::tsCryptoString name(readerState.szReader);
											if (std::find_if(cardsRemoved->begin(), cardsRemoved->end(), [&name](tscrypto::tsCryptoString& str) {return TsStriCmp(name, str) == 0; }) == cardsRemoved->end())
												cardsRemoved->push_back(name);
										}
									}
									else
									{
										if ((readerState.dwEventState & SCARD_STATE_MUTE) == 0)
										{
											tscrypto::tsCryptoString name(readerState.szReader);
											if (std::find_if(cardsAdded->begin(), cardsAdded->end(), [&name](tscrypto::tsCryptoString& str) {return TsStriCmp(name, str) == 0; }) == cardsAdded->end())
												cardsAdded->push_back(name);
										}
									}
								}
							}
							readerState.dwCurrentState = (readerState.dwEventState & ~SCARD_STATE_CHANGED);
							readerState.dwEventState = 0;
						}
					}
					// Now process the changes
					for (tscrypto::tsCryptoString& name : *cardsRemoved)
					{
						FireCardRemoved(name);
					}
					for (tscrypto::tsCryptoString& name : *cardsAdded)
					{
						FireCardInserted(name);
					}
					if (haveReaderChanges)
					{
						_UpdateReaderNameList();
					}
				}
			}
			_initialized.Set();
		}
		return 0;
	}
	int monitor()
	{
		int retVal = 0;

		if (tsSCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &_context) != SCARD_S_SUCCESS)
		{
			_accessEvent = tsSCardAccessStartedEvent();
			if (_accessEvent == 0)
			{
				LOG(scdebug, "access event is NULL");
				return 1;
			}
		}
		// Build the initial list of readers
		if (_context != 0)
			_UpdateReaderNameList();
		try
		{
			retVal = _monitor();
		}
		catch (...)
		{
			retVal = 9999;
		}
		if (_context != 0)
			tsSCardReleaseContext(_context);
		_context = 0;
		if (_accessEvent != 0)
			tsSCardReleaseStartedEvent();
		_accessEvent = 0;

		return retVal;
	}
	void cancelMonitor()
	{
		if (!Active())
			return;
		if (_context == 0)
			return;
		tsThread::Cancel();
		if (_context != 0)
			tsSCardCancel(_context);
	}

	void _FireReaderAdd(const tscrypto::tsCryptoString &readerName)
	{
		TSAUTOLOCKER locker(_consumerListLock);
		ConsumerList list = CreateConsumerList();

		for (auto c : *_consumers)
		{
			list->push_back(c);
		}
		locker.Unlock();

		//FTRACE((program, ("Firing changes")));

		for (auto cons : *list)
		{
			if (cons.func != NULL)
			{
				//FTRACE((program, ("Before Consumer")));
				cons.func->ReaderAdded(readerName);
				//FTRACE((program, ("After Consumer")));
			}
		}
	}
	void _FireReaderRemoved(const tscrypto::tsCryptoString &readerName)
	{
		TSAUTOLOCKER locker(_consumerListLock);
		ConsumerList list = CreateConsumerList();

		for (auto c : *_consumers)
		{
			list->push_back(c);
		}
		locker.Unlock();

		for (auto cons : *list)
		{
			if (cons.func != NULL)
			{
				//FTRACE((program, ("Before Consumer")));
				cons.func->ReaderRemoved(readerName);
				//FTRACE((program, ("After Consumer")));
			}
		}
	}
	void _FireCardInsert(const tscrypto::tsCryptoString &readerName)
	{
		TSAUTOLOCKER locker(_consumerListLock);
		ConsumerList list = CreateConsumerList();

		for (auto c : *_consumers)
		{
			list->push_back(c);
		}
		locker.Unlock();

		for (auto cons : *list)
		{
			if (cons.func != NULL)
			{
				//FTRACE((program, ("Before Consumer")));
				cons.func->CardInserted(readerName);
				//FTRACE((program, ("After Consumer")));
			}
		}
	}
	void _FireCardRemoved(const tscrypto::tsCryptoString &readerName)
	{
		TSAUTOLOCKER locker(_consumerListLock);
		ConsumerList list = CreateConsumerList();

		for (auto c : *_consumers)
		{
			list->push_back(c);
		}
		locker.Unlock();

		for (auto cons : *list)
		{
			if (cons.func != NULL)
			{
				//FTRACE((program, ("Before Consumer")));
				cons.func->CardRemoved(readerName);
				//FTRACE((program, ("After Consumer")));
			}
		}
	}
	void _UpdateReaderNameList()
	{
		DWORD cch = 0;
		char * buffer = NULL;
		tscrypto::tsCryptoStringList readersAdded = CreateTsAsciiList();
		tscrypto::tsCryptoStringList readersRemoved = CreateTsAsciiList();
		const char *p;

		{
			TSAUTOLOCKER locker(_readerNameListLock);

			for (size_t i = 1; i < _readers.size(); i++)
			{
				_readers[i].pvUserData = nullptr;
			}

			if (m_hLib == XP_MODULE_INVALID)
			{
				return;
			}
			switch (tsSCardListReaders(_context, NULL, NULL, &cch))
			{
			case SCARD_S_SUCCESS:
				if (cch < 2)
				{
					buffer = new char[2];
					memcpy(buffer, ("\0"), 2);
					cch = 2;
				}
				else
				{
					buffer = new char[cch];
					if (tsSCardListReaders(_context, NULL, buffer, &cch) != SCARD_S_SUCCESS)
					{
						delete[] buffer;
						return;
					}
				}
				break;
			case SCARD_E_NO_READERS_AVAILABLE:
				buffer = new char[2];
				memcpy(buffer, ("\0"), 2);
				cch = 2;
				break;
			default:
				m__ReleaseContext(_context);
				_context = 0;
				// TODO:  Review me				BsiReader::ShutdownAllReaders();
				return;
			}
			p = buffer;

			while (*p)
			{
				readersAdded->push_back(p);
				p += TsStrLen(p) + 1;
			}
			delete[] buffer;

			// Now go through the list and remove those that are already being tracked.  Mark those as tracked by setting pvUserData to 1
			if (_readers.size() > 1)
			{
				for (size_t i = 1; i < _readers.size(); i++)
				{
					tscrypto::tsCryptoString name = _readers[i].szReader;
					auto it = std::find_if(readersAdded->begin(), readersAdded->end(), [&name](tscrypto::tsCryptoString& str)->bool { return TsStriCmp(name, str) == 0; });

					if (it != readersAdded->end())
					{
						_readers[i].pvUserData = (void*)1;
						readersAdded->erase(it);
					}
				}
				if (_readers.size() > 0)
					_readers[0].pvUserData = (void*)1; // make sure that the Plug-N-Play entry is never removed

				// Now go through the list of tracked readers and remove all removed readers
				_readers.erase(std::remove_if(_readers.begin(), _readers.end(), [&readersRemoved](SCARD_READERSTATE& state) ->bool {
					if (state.pvUserData == nullptr)
					{
						if (state.szReader != nullptr)
						{
							readersRemoved->push_back(state.szReader);
							free((void*)state.szReader);
						}
						state.szReader = nullptr;
						return true;
					}
					return false;
				}), _readers.end());
			}
			// Now see if the list is big enough for any new readers added
			if (_readers.size() == 0)
			{
				SCARD_READERSTATE state;

				memset(&state, 0, sizeof(state));
				state.dwCurrentState = SCARD_STATE_UNAWARE;
#ifdef _MSC_VER
				state.szReader = _strdup("\\\\?PnP?\\Notification");
#else // _MSC_VER
				state.szReader = strdup("\\\\?PnP?\\Notification");
#endif // _MSC_VER
				_readers.push_back(state);
			}
			for (tscrypto::tsCryptoString& name : *readersAdded)
			{
				SCARD_READERSTATE state;

				memset(&state, 0, sizeof(state));
				state.dwCurrentState = SCARD_STATE_UNAWARE;
#ifdef _MSC_VER
				state.szReader = _strdup(name.c_str());
#else // _MSC_VER
				state.szReader = strdup(name.c_str());
#endif // _MSC_VER
				_readers.push_back(state);
			}
		}

		int i, count;

		count = (int)readersAdded->size();
		for (i = 0; i < count; i++)
		{
			FireReaderAdded(readersAdded->at(i));
		}
		count = (int)readersRemoved->size();
		for (i = 0; i < count; i++)
		{
			FireCardRemoved(readersRemoved->at(i));
			FireReaderRemoved(readersRemoved->at(i));
		}
	}
};

static std::shared_ptr<WinscardMonitorThread> gWinscardMonitorThread;

static const char *gDispositionStrings[] =
{
	"LeaveCard",
	"ResetCard",
	"UnpowerCard",
	"EjectCard"
};

const char *GetDisposition(DWORD disp)
{
	if (disp >= (DWORD)(sizeof(gDispositionStrings) / sizeof(gDispositionStrings[0])))
		return "unknown";
	return gDispositionStrings[disp];
}

static LONG Result(const char *name, LONG retVal)
{
	if (retVal != 0 && retVal != 0x8010000A /* Timeout */)
	{
		LOG(scdebug, name << " Returned " << ToHex()((int)retVal));
	}
	return retVal;
}
#pragma region Basic Winscard functions
LONG tsSCardEstablishContext(IN  DWORD dwScope, IN  LPCVOID pvReserved1, IN  LPCVOID pvReserved2, OUT LPSCARDCONTEXT phContext)
{
	return Result("EstablishContext", m__EstablishContext(dwScope, pvReserved1, pvReserved2, phContext));
}

LONG tsSCardReleaseContext(IN SCARDCONTEXT hContext)
{
	return Result("ReleaseContext", m__ReleaseContext(hContext));
}

static LONG tsSCardListReaders(IN SCARDCONTEXT hContext, IN const char *mszGroup, OUT char *mszReaders, IN OUT LPDWORD pcchReaders)
{
	return Result("ListReaders", m__ListReaders(hContext, mszGroup, mszReaders, pcchReaders));
}

LONG tsSCardConnect(IN SCARDCONTEXT hContext, IN const char *szReader, IN DWORD dwShareMode, IN DWORD dwPreferredProtocols, OUT LPSCARDHANDLE phCard, OUT LPDWORD pdwActiveProtocol)
{
	return Result("Connect", m__Connect(hContext, szReader, dwShareMode, dwPreferredProtocols, phCard, pdwActiveProtocol));
}

ReaderInfoList tsSCardReaderList()
{
	if (!gWinscardMonitorThread)
	{
		return CreateReaderInfoList();
	}
	return gWinscardMonitorThread->ReaderList();
}

LONG tsSCardDisconnect(IN SCARDHANDLE hCard, IN DWORD dwDisposition)
{
	LOG(scdebug, "Disconnecting from card -> " << GetDisposition(dwDisposition));

	return Result("Disconnect", m__Disconnect(hCard, dwDisposition));
}

LONG tsSCardTransmit(IN SCARDHANDLE hCard, IN LPCSCARD_IO_REQUEST pioSendPci, IN LPCBYTE pbSendBuffer, IN DWORD cbSendLength,
	IN OUT LPSCARD_IO_REQUEST pioRecvPci, OUT LPBYTE pbRecvBuffer, IN OUT LPDWORD pcbRecvLength)
{
	return Result("Transmit", m__Transmit(hCard, pioSendPci, pbSendBuffer, cbSendLength, pioRecvPci, pbRecvBuffer, pcbRecvLength));
}

LONG tsSCardGetStatusChange(IN SCARDCONTEXT hContext, IN DWORD dwTimeout, IN OUT LPSCARD_READERSTATE rgReaderStates, IN DWORD cReaders)
{
	return Result("GetStatusChange", m__GetStatusChange(hContext, dwTimeout, rgReaderStates, cReaders));
}

LONG tsSCardReconnect(IN SCARDHANDLE hCard, IN DWORD dwShareMode, IN DWORD dwPreferredProtocols, IN DWORD dwInitialization, OUT LPDWORD pdwActiveProtocol)
{
	LOG(scdebug, "Reconnect to card");

	return Result("Reconnect", m__Reconnect(hCard, dwShareMode, dwPreferredProtocols, dwInitialization, pdwActiveProtocol));
}

LONG tsSCardGetAttrib(SCARDHANDLE hCard, DWORD dwAttrId, LPBYTE pbAttr, LPDWORD pcbAttrLen)
{
	return Result("GetAttrib", m__GetAttrib(hCard, dwAttrId, pbAttr, pcbAttrLen));
}

LONG tsSCardBeginTransaction(IN SCARDHANDLE hCard)
{
	LOG(scdebug, "Start Transaction");

	LONG retVal;
	int retryCount = 0;

	do {
		retVal = m__BeginTransaction(hCard);

		if (retVal == SCARD_E_SERVER_TOO_BUSY || retVal == SCARD_E_SHARING_VIOLATION)
		{
			XP_Sleep(250);
			retVal++;
		}
		else if (retVal == SCARD_W_REMOVED_CARD || retVal == SCARD_W_RESET_CARD)
		{
			DWORD protocol;

			retVal++;
			tsSCardReconnect(hCard, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, SCARD_LEAVE_CARD, &protocol);
		}
		else if (retVal != SCARD_S_SUCCESS)
			retryCount = 1000;
	} while (retVal != SCARD_S_SUCCESS && retryCount < 8);

	return Result("BeginTransaction", retVal);
}

LONG tsSCardEndTransaction(IN SCARDHANDLE hCard, IN DWORD dwDisposition)
{
	LOG(scdebug, "End Transaction -> " << GetDisposition(dwDisposition));

	return Result("EndTransaction", m__EndTransaction(hCard, dwDisposition));
}

HANDLE tsSCardAccessStartedEvent(void)
{
	if (m__AccessStartedEvent != nullptr)
	{
		HANDLE retVal = m__AccessStartedEvent();
		LOG(scdebug, "AccessStartedEvent -> " << ToHex()((void*)retVal));
		return retVal;
	}
	return 0;
}
void tsSCardReleaseStartedEvent(void)
{
	if (m__ReleaseStartedEvent != nullptr)
	{
		LOG(scdebug, "ReleaseStartedEvent");
		m__ReleaseStartedEvent();
	}
}

LONG tsSCardCancel(IN SCARDCONTEXT hContext)
{
	LOG(scdebug, "Cancel card");

	return Result("Cancel", m__Cancel(hContext));
}

LONG tsSCardFreeMemory(IN SCARDCONTEXT hContext, IN LPCVOID pvMem)
{
	return Result("FreeMemory", m__FreeMemory(hContext, pvMem));
}

LONG tsSCardIsValidContext(IN SCARDCONTEXT hContext)
{
	return Result("isValidContext", m__isValidContext(hContext));
}
LONG tsSCardStatus(IN SCARDHANDLE hCard, OUT LPSTR mszReaderNames, IN OUT LPDWORD pcchReaderLen, OUT LPDWORD pdwState, OUT LPDWORD pdwProtocol, OUT LPBYTE pbAtr, OUT LPDWORD pcbAtrLen)
{
	return m__Status(hCard, mszReaderNames, pcchReaderLen, pdwState, pdwProtocol, pbAtr, pcbAtrLen);
}
#pragma endregion

static uint32_t gWinscardInitCount = 0;


#pragma region Library initialization and termination
bool tsWinscardInit(void)
{
	if (InterlockedIncrement(&gWinscardInitCount) > 1)
		return true;

	if (xp_LoadSharedLib(PCSC_DLL_NAME, &m_hLib))
	{
		InterlockedDecrement(&gWinscardInitCount);
		//		MessageBox(NULL, "LoadLibrary failed", "Status", MB_OK);
		return false;
	}

#ifdef _WIN32
	m__ListReaders = (fnSCardListReaders)xp_GetProcAddress(m_hLib, "SCardListReadersA");
	m__Connect = (fnSCardConnect)xp_GetProcAddress(m_hLib, "SCardConnectA");
	m__GetStatusChange = (fnSCardGetStatusChange)xp_GetProcAddress(m_hLib, "SCardGetStatusChangeA");
	m__Status = (fnSCardStatus)xp_GetProcAddress(m_hLib, "SCardStatusA");
#else
	m__ListReaders = (fnSCardListReaders)xp_GetProcAddress(m_hLib, "SCardListReaders");
	m__Connect = (fnSCardConnect)xp_GetProcAddress(m_hLib, "SCardConnect");
	m__GetStatusChange = (fnSCardGetStatusChange)xp_GetProcAddress(m_hLib, "SCardGetStatusChange");
#endif // _WIN32
	m__EstablishContext = (fnSCardEstablishContext)xp_GetProcAddress(m_hLib, "SCardEstablishContext");
	m__ReleaseContext = (fnSCardReleaseContext)xp_GetProcAddress(m_hLib, "SCardReleaseContext");
	m__Disconnect = (fnSCardDisconnect)xp_GetProcAddress(m_hLib, "SCardDisconnect");
	m__Transmit = (fnSCardTransmit)xp_GetProcAddress(m_hLib, "SCardTransmit");
	m__Reconnect = (fnSCardReconnect)xp_GetProcAddress(m_hLib, "SCardReconnect");
	m__GetAttrib = (fnSCardGetAttrib)xp_GetProcAddress(m_hLib, "SCardGetAttrib");
	m__BeginTransaction = (fnSCardBeginTransaction)xp_GetProcAddress(m_hLib, "SCardBeginTransaction");
	m__EndTransaction = (fnSCardEndTransaction)xp_GetProcAddress(m_hLib, "SCardEndTransaction");
	m__AccessStartedEvent = (fnSCardAccessStartedEvent)xp_GetProcAddress(m_hLib, "SCardAccessStartedEvent");
	m__ReleaseStartedEvent = (fnSCardReleaseStartedEvent)xp_GetProcAddress(m_hLib, "SCardReleaseStartedEvent");
	m__FreeMemory = (fnSCardFreeMemory)xp_GetProcAddress(m_hLib, "SCardFreeMemory");
	m__Cancel = (fnSCardCancel)xp_GetProcAddress(m_hLib, "SCardCancel");
	m__isValidContext = (fnSCardIsValidContext)xp_GetProcAddress(m_hLib, "SCardIsValidContext");

	if (m__EstablishContext == NULL || m__ReleaseContext == NULL || m__ListReaders == NULL ||
		m__Connect == NULL || m__Disconnect == NULL || m__Transmit == NULL ||
		m__GetStatusChange == NULL || m__Reconnect == NULL || m__GetAttrib == NULL ||
		m__BeginTransaction == NULL || m__EndTransaction == NULL || //m__AccessStartedEvent == NULL ||
		/*m__ReleaseStartedEvent == NULL ||*/ m__Cancel == NULL || m__FreeMemory == NULL ||
		m__isValidContext == NULL || m__Status == NULL)
	{
		//		MessageBox(NULL, "Winscard function pointers failed", "Status", MB_OK);
		tsWinscardRelease();
		return false;
	}

	gWinscardMonitorThread = std::shared_ptr<WinscardMonitorThread>(new WinscardMonitorThread());
	if (!gWinscardMonitorThread)
	{
		//		MessageBox(NULL, "Winscard function pointers failed", "Status", MB_OK);
		tsWinscardRelease();
		return false;
	}
	gWinscardMonitorThread->Start();


	return true;
}

bool tsWinscardRelease(void)
{
	if (InterlockedDecrement(&gWinscardInitCount) > 0)
		return true;

	if (!!gWinscardMonitorThread)
	{
		if (gWinscardMonitorThread->Active())
		{
			gWinscardMonitorThread->Cancel();
			if (!gWinscardMonitorThread->WaitForThread(30000))
				gWinscardMonitorThread->Kill();
		}
		gWinscardMonitorThread.reset();
	}

	m__EstablishContext = NULL;
	m__ReleaseContext = NULL;
	m__ListReaders = NULL;
	m__Connect = NULL;
	m__Disconnect = NULL;
	m__Transmit = NULL;
	m__GetStatusChange = NULL;
	m__Reconnect = NULL;
	m__GetAttrib = NULL;
	m__BeginTransaction = NULL;
	m__EndTransaction = NULL;
	m__AccessStartedEvent = NULL;
	m__ReleaseStartedEvent = NULL;
	m__FreeMemory = NULL;
	m__Cancel = NULL;
	m__isValidContext = NULL;
	m__Status = NULL;

	if (m_hLib != XP_MODULE_INVALID)
		xp_FreeSharedLib(m_hLib);

	m_hLib = XP_MODULE_INVALID;
	return true;
}
#pragma endregion

uint32_t TSWC_RegisterChangeConsumer(std::shared_ptr<TSWC_ChangeConsumer> consumer)
{
	if (!gWinscardMonitorThread)
		return 0;
	return gWinscardMonitorThread->AddConsumer(consumer);
}

void TSWC_UnregisterChangeConsumer(uint32_t consumerCookie)
{
	if (!!gWinscardMonitorThread)
		gWinscardMonitorThread->RemoveConsumer(consumerCookie);
}

