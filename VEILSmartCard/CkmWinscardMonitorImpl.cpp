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
#include "CkmWinscardReaderImpl.h"
#include "CkmWinscardContextImpl.h"

static uint32_t gTlpCount = 0;
static uint32_t gNextChangeStruct = 0;


class CkmWinscardMonitorImpl : public ICkmWinscardMonitor, public TSWC_ChangeConsumer, public tsmod::IObject
{
	struct ChangeStruct
	{
		std::shared_ptr<ICkmWinscardChange> func;
		uint32_t id;
	};
public:
	CkmWinscardMonitorImpl(void);
	virtual ~CkmWinscardMonitorImpl(void);

	virtual int RegisterChangeReceiver(std::shared_ptr<ICkmWinscardChange> pObj);
	virtual bool UnregisterChangeReceiver(int cookie);
	virtual void ScanForChanges();
	virtual bool CreateContext(std::shared_ptr<ICkmWinscardContext>& pObj);
	virtual ICkmWinscardReaderList GetReaderList();

protected:
	virtual void ReaderAdded(const tscrypto::tsCryptoString& readerName);
	virtual void ReaderRemoved(const tscrypto::tsCryptoString& readerName);
	virtual void CardInserted(const tscrypto::tsCryptoString& readerName);
	virtual void CardRemoved(const tscrypto::tsCryptoString& readerName);

private:
	std::vector<ChangeStruct> m_notifiers;
	tscrypto::AutoCriticalSection m_notifierListLock;
	int _cookie;

	//    static void ChangeConsumer(IN void *userParams,IN TSWC_ChangeType type,IN const tscrypto::tsCryptoString &readerName,IN void *otherParams);
};


CkmWinscardMonitorImpl::CkmWinscardMonitorImpl(void) :
	_cookie(0)
{
	tsWinscardInit();
	InterlockedIncrement(&gTlpCount);
}

CkmWinscardMonitorImpl::~CkmWinscardMonitorImpl(void)
{
	tsWinscardRelease();
}

int CkmWinscardMonitorImpl::RegisterChangeReceiver(std::shared_ptr<ICkmWinscardChange> pObj)
{
	if (pObj == NULL)
		return 0;

	ChangeStruct cs;
	bool registerConsumer = false;

	cs.func = pObj;
	cs.id = InterlockedIncrement(&gNextChangeStruct);
	{
		TSAUTOLOCKER lock(m_notifierListLock);
		m_notifiers.push_back(cs);
		registerConsumer = (m_notifiers.size() == 1);
	}

	if (registerConsumer)
	{
		_cookie = TSWC_RegisterChangeConsumer(std::dynamic_pointer_cast<TSWC_ChangeConsumer>(_me.lock()));
	}
	return cs.id;
}

bool CkmWinscardMonitorImpl::UnregisterChangeReceiver(int cookie)
{
	if (cookie == 0)
		return true;

	TSAUTOLOCKER lock(m_notifierListLock);
	m_notifiers.erase(std::remove_if(m_notifiers.begin(), m_notifiers.end(), [cookie](ChangeStruct& obj)->bool { return obj.id == cookie; }), m_notifiers.end());
	if (_cookie != 0 && m_notifiers.size() == 0)
	{
		TSWC_UnregisterChangeConsumer(_cookie);
		_cookie = 0;
	}
	return true;
}

void CkmWinscardMonitorImpl::ScanForChanges()
{
	/* No longer needed */
}

bool CkmWinscardMonitorImpl::CreateContext(std::shared_ptr<ICkmWinscardContext>& pObj)
{
	pObj = CreateWinscardContext();
	return !!pObj;
}

ICkmWinscardReaderList CkmWinscardMonitorImpl::GetReaderList()
{
	ICkmWinscardReaderList list = CreateICkmWinscardReaderList();
	ReaderInfoList readers;
	//    int i = 0;
	/* No longer needed */

	readers = tsSCardReaderList();
	list->reserve(readers->size());

	for (auto iter = readers->begin(); iter != readers->end(); iter++)
	{
		list->push_back(CreateWinscardReader(iter->name.c_str(), iter->atr, iter->status));
	}

	return list;
}

void CkmWinscardMonitorImpl::ReaderAdded(const tscrypto::tsCryptoString& readerName)
{
	std::vector<ChangeStruct> tmpList;

	{
		TSAUTOLOCKER lock(m_notifierListLock);
		tmpList = m_notifiers;
	}

	for (ChangeStruct& obj : tmpList)
	{
		obj.func->readerAdded(readerName);
	}
}

void CkmWinscardMonitorImpl::ReaderRemoved(const tscrypto::tsCryptoString& readerName)
{
	std::vector<ChangeStruct> tmpList;

	{
		TSAUTOLOCKER lock(m_notifierListLock);
		tmpList = m_notifiers;
	}

	for (ChangeStruct& obj : tmpList)
	{
		obj.func->readerRemoved(readerName);
	}
}

void CkmWinscardMonitorImpl::CardInserted(const tscrypto::tsCryptoString& readerName)
{
	std::vector<ChangeStruct> tmpList;

	{
		TSAUTOLOCKER lock(m_notifierListLock);
		tmpList = m_notifiers;
	}

	for (ChangeStruct& obj : tmpList)
	{
		obj.func->cardInserted(readerName);
	}
}

void CkmWinscardMonitorImpl::CardRemoved(const tscrypto::tsCryptoString& readerName)
{
	std::vector<ChangeStruct> tmpList;

	{
		TSAUTOLOCKER lock(m_notifierListLock);
		tmpList = m_notifiers;
	}

	for (ChangeStruct& obj : tmpList)
	{
		obj.func->cardRemoved(readerName);
	}
}

tsmod::IObject* CreateSmartCardMonitor()
{
	return dynamic_cast<tsmod::IObject*>(new CkmWinscardMonitorImpl());
}
