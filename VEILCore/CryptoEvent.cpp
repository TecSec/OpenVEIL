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
#ifndef _WIN32
    #include "core/pevents.h"
#endif // _WIN32

using namespace tscrypto;

CryptoEvent::CryptoEvent(bool manualReset, bool initialValue) : _theEvent(nullptr)
{
#ifdef _WIN32
	_theEvent = (void*)CreateEvent(nullptr, manualReset, initialValue, nullptr);
#else
	_theEvent = neosmart::CreateEvent(manualReset, initialValue);
#endif
}

CryptoEvent::~CryptoEvent()
{
#ifdef _WIN32
	CloseHandle((HANDLE)_theEvent);
#else
    neosmart::DestroyEvent((neosmart::neosmart_event_t)_theEvent);
#endif
	_theEvent = nullptr;
}

bool CryptoEvent::IsActive() const
{
#ifdef _WIN32
	return _theEvent != nullptr;
#else
	return _theEvent != nullptr;
#endif
}

bool CryptoEvent::Set()
{
#ifdef _WIN32
	return SetEvent(_theEvent) != FALSE;
#else
	return neosmart::SetEvent((neosmart::neosmart_event_t)_theEvent) != FALSE;
#endif
}

bool CryptoEvent::Reset()
{
#ifdef _WIN32
	return ResetEvent(_theEvent) != FALSE;
#else
	return neosmart::ResetEvent((neosmart::neosmart_event_t)_theEvent) != FALSE;
#endif
}

CryptoEvent::EventStatus CryptoEvent::WaitForEvent(uint32_t timeout)
{
#ifdef _WIN32
	switch (WaitForSingleObject(_theEvent, timeout))
	{
	case WAIT_ABANDONED:
	case WAIT_OBJECT_0:
		return CryptoEvent::Succeeded_Object1;
	case WAIT_TIMEOUT:
		return CryptoEvent::Timeout;
	default:
	case WAIT_FAILED:
		return CryptoEvent::Failed;
	}
#else
	if (neosmart::WaitForEvent((neosmart::neosmart_event_t)_theEvent, timeout) != 0)
	{
		return CryptoEvent::Timeout;
	}
	return CryptoEvent::Succeeded_Object1;
#endif
}

CryptoEvent::EventStatus CryptoEvent::WaitForEvents(uint32_t timeout, CryptoEvent& event2)
{
#ifdef _WIN32
	HANDLE list[2] = {_theEvent, event2._theEvent};

	switch (WaitForMultipleObjects(2, list, false, timeout))
	{
	case WAIT_ABANDONED:
	case WAIT_OBJECT_0:
		return CryptoEvent::Succeeded_Object1;
	case WAIT_ABANDONED + 1:
	case WAIT_OBJECT_0 + 1:
		return CryptoEvent::Succeeded_Object2;
	case WAIT_TIMEOUT:
		return CryptoEvent::Timeout;
	default:
	case WAIT_FAILED:
		return CryptoEvent::Failed;
	}
#else
	neosmart::neosmart_event_t list[2] = {(neosmart::neosmart_event_t)_theEvent, (neosmart::neosmart_event_t)event2._theEvent};
    int index = 0;

    if (neosmart::WaitForMultipleEvents(list, 2, false, timeout, index) != 0)
        return CryptoEvent::Timeout;
    if (index < 2 && index >= 0)
    {
        return (CryptoEvent::EventStatus)(CryptoEvent::Succeeded_Object1 + index);
    }
    return CryptoEvent::Failed;
#endif
}

CryptoEvent::EventStatus CryptoEvent::WaitForEvents(uint32_t timeout, CryptoEvent& event2, CryptoEvent& event3)
{
#ifdef _WIN32
	HANDLE list[3] = { _theEvent, event2._theEvent, event3._theEvent };

	switch (WaitForMultipleObjects(3, list, false, timeout))
	{
	case WAIT_ABANDONED:
	case WAIT_OBJECT_0:
		return CryptoEvent::Succeeded_Object1;
	case WAIT_ABANDONED + 1:
	case WAIT_OBJECT_0 + 1:
		return CryptoEvent::Succeeded_Object2;
	case WAIT_ABANDONED + 2:
	case WAIT_OBJECT_0 + 2:
		return CryptoEvent::Succeeded_Object3;
	case WAIT_TIMEOUT:
		return CryptoEvent::Timeout;
	default:
	case WAIT_FAILED:
		return CryptoEvent::Failed;
	}
#else
	neosmart::neosmart_event_t list[3] = {(neosmart::neosmart_event_t)_theEvent, (neosmart::neosmart_event_t)event2._theEvent,
	(neosmart::neosmart_event_t)event3._theEvent};
    int index = 0;

    if (neosmart::WaitForMultipleEvents(list, 3, false, timeout, index) != 0)
        return CryptoEvent::Timeout;
    if (index < 3 && index >= 0)
    {
        return (CryptoEvent::EventStatus)(CryptoEvent::Succeeded_Object1 + index);
    }
    return CryptoEvent::Failed;
#endif
}

CryptoEvent::EventStatus CryptoEvent::WaitForEvents(uint32_t timeout, CryptoEvent& event2, CryptoEvent& event3, CryptoEvent& event4)
{
#ifdef _WIN32
	HANDLE list[4] = { _theEvent, event2._theEvent, event3._theEvent, event4._theEvent };

	switch (WaitForMultipleObjects(4, list, false, timeout))
	{
	case WAIT_ABANDONED:
	case WAIT_OBJECT_0:
		return CryptoEvent::Succeeded_Object1;
	case WAIT_ABANDONED + 1:
	case WAIT_OBJECT_0 + 1:
		return CryptoEvent::Succeeded_Object2;
	case WAIT_ABANDONED + 2:
	case WAIT_OBJECT_0 + 2:
		return CryptoEvent::Succeeded_Object3;
	case WAIT_ABANDONED + 3:
	case WAIT_OBJECT_0 + 3:
		return CryptoEvent::Succeeded_Object4;
	case WAIT_TIMEOUT:
		return CryptoEvent::Timeout;
	default:
	case WAIT_FAILED:
		return CryptoEvent::Failed;
	}
#else
	neosmart::neosmart_event_t list[4] = {(neosmart::neosmart_event_t)_theEvent, (neosmart::neosmart_event_t)event2._theEvent,
                                          (neosmart::neosmart_event_t)event3._theEvent, (neosmart::neosmart_event_t)event4._theEvent};
    int index = 0;

    if (neosmart::WaitForMultipleEvents(list, 4, false, timeout, index) != 0)
        return CryptoEvent::Timeout;
    if (index < 4 && index >= 0)
    {
        return (CryptoEvent::EventStatus)(CryptoEvent::Succeeded_Object1 + index);
    }
    return CryptoEvent::Failed;
#endif
}


