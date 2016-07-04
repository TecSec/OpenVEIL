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
#include "CkmWinscardMonitorImpl.h"

static bool gDisableSmartCardAccess = false;
//HIDDEN tsCComPtr<ReferenceCountedWeakOleList<TSNameBase> > gDllObjectList = new ReferenceCountedWeakOleList<TSNameBase>;
HIDDEN tscrypto::tsCryptoString gLogFileName;
HIDDEN bool gLogToFile = false;
HIDDEN bool gLogToCkmLog = false;
HIDDEN bool gTimeCommands = false;
HIDDEN bool gLogDecryptedInfo = false;
HIDDEN tsDebugStream debug("Winscard", DEBUG_LEVEL_SENSITIVE);
//static tsDebugListener *listener2 = NULL;
static int gProducerCookie = 0;

//virtual void DisableSmartCardAccess(bool disabled) = 0;
//virtual bool SmartCardAccessDisabled() const = 0;

extern tsmod::IObject* CreateSmartCardLink();
extern tsmod::IObject* CreateServerSmartCardConnectionObject();
extern tsmod::IObject* CreateLocalSmartCardConnectionObject();
extern tsmod::IObject* CreateSmartCardInformation();

ICkmWinscardReaderList CreateICkmWinscardReaderList()
{
	return CreateContainer<std::shared_ptr<ICkmWinscardReader>>();
}
ReaderNameList CreateReaderNameList()
{
	return CreateContainer<ReaderName>();
}
ConsumerList CreateConsumerList()
{
	return CreateContainer<Consumer>();
}
ReaderInfoList CreateReaderInfoList()
{
	return CreateContainer<ReaderInfo>();

}
class SCChangeHelper : public TSWC_ChangeConsumer, public tsmod::IObject
{
public:
	SCChangeHelper(std::shared_ptr<ICkmWinscardChange> bridge) : m_bridge(bridge), cookie(0)
	{
		tsWinscardInit();
	}
	~SCChangeHelper()
	{
		Unregister();
		tsWinscardRelease();
	}

	virtual void ReaderAdded(const tscrypto::tsCryptoString& readerName) { if (!m_bridge.expired()) m_bridge.lock()->readerAdded(readerName); }
	virtual void ReaderRemoved(const tscrypto::tsCryptoString& readerName) { if (!m_bridge.expired()) m_bridge.lock()->readerRemoved(readerName); }
	virtual void CardInserted(const tscrypto::tsCryptoString& readerName) { if (!m_bridge.expired()) m_bridge.lock()->cardInserted(readerName); }
	virtual void CardRemoved(const tscrypto::tsCryptoString& readerName) { if (!m_bridge.expired()) m_bridge.lock()->cardRemoved(readerName); }
	void Register()
	{
		if (cookie == 0)
		{
			cookie = TSWC_RegisterChangeConsumer(std::dynamic_pointer_cast<TSWC_ChangeConsumer>(_me.lock()));
		}
	}
	void Unregister()
	{
		if (cookie != 0)
		{
			int cook(cookie);
			cookie = 0;
			TSWC_UnregisterChangeConsumer(cook);
		}
	}
private:
	std::weak_ptr<ICkmWinscardChange> m_bridge;
	int cookie;
};

class ChangeProducer : public CkmChangeProducerCore, public ICkmWinscardChange, public tsmod::IObject
{
public:
	ChangeProducer()
	{
	}
	virtual ~ChangeProducer()
	{
		m_bridge->Unregister();
	}
	virtual void OnConstructionFinished()
	{
		m_bridge = ::TopServiceLocator()->Finish<SCChangeHelper>(new SCChangeHelper(std::dynamic_pointer_cast<ICkmWinscardChange>(_me.lock())));

		m_bridge->Register();
	}

	virtual void ScanForChanges(void) { /* No longer needed */ }

	// ICkmWinscardChange
	virtual void readerAdded(const tscrypto::tsCryptoString& name)
	{
		GetChangeMonitor()->RaiseChange(::TopServiceLocator()->Finish<ICkmChangeEvent>(new CkmWinscardEventImpl(wcard_AddReader, name)));
	}
	virtual void readerRemoved(const tscrypto::tsCryptoString& name)
	{
		GetChangeMonitor()->RaiseChange(::TopServiceLocator()->Finish<ICkmChangeEvent>(new CkmWinscardEventImpl(wcard_RemoveReader, name)));
	}
	virtual void cardInserted(const tscrypto::tsCryptoString& name)
	{
		GetChangeMonitor()->RaiseChange(::TopServiceLocator()->Finish<ICkmChangeEvent>(new CkmWinscardEventImpl(wcard_InsertCard, name)));
	}
	virtual void cardRemoved(const tscrypto::tsCryptoString& name)
	{
		GetChangeMonitor()->RaiseChange(::TopServiceLocator()->Finish<ICkmChangeEvent>(new CkmWinscardEventImpl(wcard_RemoveCard, name)));
	}

private:
	std::shared_ptr<SCChangeHelper> m_bridge;
};

static void TerminateCkmWinscardLibrary()
{
	if (gProducerCookie != 0)
	{
		GetChangeMonitor()->UnregisterChangeProducer(gProducerCookie);
	}
	gProducerCookie = 0;
}
static bool SetCkmWinscardFuncs()
{
	gProducerCookie = GetChangeMonitor()->RegisterChangeProducer(::TopServiceLocator()->Finish<ICkmChangeProducer>(new ChangeProducer()));
	return TRUE;
}

static bool Terminate()
{
	std::shared_ptr<tsmod::IServiceLocator> servLoc = ::TopServiceLocator();

	if (gProducerCookie != 0)
		TerminateCkmWinscardLibrary();
	servLoc->DeleteClass("SmartCardLink");
	servLoc->DeleteClass("SmartCardInformation");
	servLoc->DeleteClass("ServerSmartCardConnection");
	servLoc->DeleteClass("LocalSmartCardConnection");
	servLoc->DeleteClass("SmartCardMonitor");

	return true;
}

bool InitializeSmartCard()
{
	std::shared_ptr<tsmod::IServiceLocator> servLoc = ::TopServiceLocator();

	if (!servLoc->CanCreate("SmartCardLink"))
	{
		servLoc->AddClass("SmartCardLink", CreateSmartCardLink);
		servLoc->AddClass("SmartCardInformation", CreateSmartCardInformation);
		servLoc->AddClass("ServerSmartCardConnection", CreateServerSmartCardConnectionObject);
		servLoc->AddClass("LocalSmartCardConnection", CreateLocalSmartCardConnectionObject);
		servLoc->AddSingletonClass("SmartCardMonitor", CreateSmartCardMonitor);
		if (!gDisableSmartCardAccess && gProducerCookie == 0)
			SetCkmWinscardFuncs();
		AddSystemTerminationFunction(Terminate);
	}

	return true;
}

void DisableSmartCardAccess(bool disabled)
{
	gDisableSmartCardAccess = disabled;
	if (disabled)
		TerminateCkmWinscardLibrary();
	else
		SetCkmWinscardFuncs();
}
bool SmartCardAccessDisabled()
{
	return gDisableSmartCardAccess;
}


