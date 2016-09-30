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


class ProducerHolder : public tsmod::IObject
{
    public:
		ProducerHolder(std::shared_ptr<ICkmChangeProducer> producer, uint32_t cookie) : m_producer(producer), id(cookie)
        {
        }
        ~ProducerHolder()
        {
            m_producer.reset();
        }
		std::shared_ptr<ICkmChangeProducer> GetProducer()
        {
            return m_producer;
        }
		uint32_t Id() const { return id; }
    private:
        std::shared_ptr<ICkmChangeProducer> m_producer;
        uint32_t id;
};
class ConsumerHolder : public tsmod::IObject
{
    public:
		ConsumerHolder(std::shared_ptr<ICkmChangeConsumer> consumer, uint32_t cookie) : m_consumer(consumer), id(cookie)
        {
        }
        ~ConsumerHolder()
        {
            m_consumer.reset();
        }
		std::shared_ptr<ICkmChangeConsumer> GetConsumer()
        {
            return m_consumer;
        }
		uint32_t Id() const { return id; }
	private:
		std::shared_ptr<ICkmChangeConsumer> m_consumer;
        uint32_t id;
};

typedef std::list<std::shared_ptr<ConsumerHolder> > ConsumerTreeList;
typedef std::list<std::shared_ptr<ProducerHolder> > ProducerTreeList;

class HIDDEN CkmChangeMonitorImpl : public tsmod::IObject, public ICkmChangeMonitor
{
public:
	CkmChangeMonitorImpl(void) : gNextConsumer(0), gNextProducer(0)
	{
	TSAUTOLOCKER locker(gThreadLock);

	if (!gThreadConfigured)
	{
			gThreadHandle.SetWorker([this]()->int { return monitorFunc(); });
		gThreadConfigured = true;
	}
	}
	~CkmChangeMonitorImpl(void)
	{
    StopChangeMonitorThread();
		ConsumerList.clear();
		ProducerList.clear();
	}

	// CkmChangeMonitor COM interface
	virtual bool StartChangeMonitorThread(void)
	{
	if (gThreadHandle.Active())
        return false;
    gCloseThread = false;
	gThreadHandle.Start();

	return gThreadHandle.Active();
	}
	virtual bool StopChangeMonitorThread(void)
	{
	if (!gThreadHandle.Active())
        return false;

    gCloseThread = true;
	gThreadHandle.WaitForThread((DWORD)-1); // INFINITE
    ProducerList.clear();
    ConsumerList.clear();
    return true;
	}
	virtual bool KillChangeMonitorThread(void)
	{
	if (!gThreadHandle.Active())
        return false;

    gCloseThread = true;
	gThreadHandle.Kill();
    return true;
	}
	virtual bool LookForChanges(void)
	{
		for (auto obj : ProducerList)
		{
			if (!!obj && !!obj->GetProducer())
				obj->GetProducer()->ScanForChanges();
		}
		return true;
	}

	// ICkmChangeMonitor
	virtual bool     UnregisterChangeProducer(uint32_t cookie)
	{
		ProducerList.remove_if([&cookie](std::shared_ptr<ProducerHolder>& obj) -> bool {return obj->Id() == cookie; });
		return true;
	}
	virtual bool     UnregisterChangeConsumer(uint32_t cookie)
	{
		ConsumerList.remove_if([&cookie](std::shared_ptr<ConsumerHolder>& obj) -> bool {return obj->Id() == cookie; });
		return true;
	}
	virtual uint32_t RegisterChangeProducer(std::shared_ptr<ICkmChangeProducer> setTo)
	{
    uint32_t producerId = InterlockedIncrement(&gNextProducer);

	if (setTo == NULL)
		return 0;

		ProducerList.push_back(ServiceLocator()->Finish<ProducerHolder>(new ProducerHolder(setTo, producerId)));
    return producerId;
	}
	virtual uint32_t RegisterChangeConsumer(std::shared_ptr<ICkmChangeConsumer> setTo)
	{
    long consumerId = InterlockedIncrement(&gNextConsumer);

	if (setTo == NULL)
		return 0;

	ConsumerList.push_back(ServiceLocator()->Finish<ConsumerHolder>(new ConsumerHolder(setTo, consumerId)));
	return consumerId;
	}
	virtual bool     RaiseChange(std::shared_ptr<ICkmChangeEvent> eventObj)
	{
    CKMChangeType type;

		if (eventObj == NULL)
        return false;

	type = eventObj->GetChangeType();
		for (auto obj : ConsumerList)
		{
		if ((obj->GetConsumer()->WantsChangesMatching() & type) != 0)
		{
			obj->GetConsumer()->OnCkmChange(eventObj);
		}
		}
	return true;
	}

private:
	int monitorFunc()
	{
		//TSDECLARE_FUNCTIONExt(true);
		try
		{
			while (!gCloseThread)
			{
				XP_Sleep(250);
				try
				{
					if (!gChangeMonitor)
						break;
					gChangeMonitor->LookForChanges();
				}
				catch (...)
				{
				}
			}
		}
		catch (...)
		{
		}
		//return TSRETURN(("Closing thread"), 0);
		return 0;
	}

private:
	tsThread gThreadHandle;
	volatile bool gCloseThread = false;
	bool gThreadConfigured = false;
	tscrypto::AutoCriticalSection gThreadLock;
	ConsumerTreeList ConsumerList;
	uint32_t gNextConsumer;
	ProducerTreeList ProducerList;
	uint32_t gNextProducer;

	//CkmChangeMonitorImpl(const CkmChangeMonitorImpl &obj) : TSName("CkmChangeMonitorImpl"), TSProvideClassInfoImpl<gCryptoSupportTypeLib>(CLSID_CCkmChangeMonitor) { MY_UNREFERENCED_PARAMETER(obj); }
	//CkmChangeMonitorImpl &operator=(const CkmChangeMonitorImpl &obj){MY_UNREFERENCED_PARAMETER(obj); return *this;}
};

bool ShutdownChangeMonitor()
{
	if (!gChangeMonitor)
		return true;

	gChangeMonitor->StopChangeMonitorThread();
	gChangeMonitor.reset();

	return true;
}

std::shared_ptr<ICkmChangeMonitor> GetChangeMonitor()
{
	if (!gChangeMonitor)
    {
		std::shared_ptr<CkmChangeMonitorImpl> obj = TopServiceLocator()->Finish<CkmChangeMonitorImpl>(new CkmChangeMonitorImpl());
        if (!obj)
            return nullptr;
		gChangeMonitor = obj;
		AddSystemTerminationFunction(ShutdownChangeMonitor);
    }
	return gChangeMonitor;
}

bool HasChangeMonitor()
{
    return (!!gChangeMonitor);
}
