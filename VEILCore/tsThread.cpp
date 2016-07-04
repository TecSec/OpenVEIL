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

tsThread::tsThread() :
	cancel(true, false),
	threadId(0),
#ifdef HAVE_WINDOWS_H
	hThread(nullptr)
#else
	hThread(0)
#endif // HAVE_WINDOWS_H
{
}
tsThread::tsThread(tsThread&& obj)
{
	threadId = obj.threadId;
	obj.threadId = 0;
	hThread = obj.hThread;
	obj.hThread = 0;
	cancel = std::move(obj.cancel);
	_worker = std::move(obj._worker);
	_onComplete = std::move(obj._onComplete);
}

tsThread::~tsThread()
{
	if (Active())
		Cancel();

	if (!WaitForThread(30000))
	{
		Kill();
	}
}

tsThread& tsThread::operator=(tsThread&& obj)
{
	if (&obj != this)
	{
		if (Active())
		{
			Cancel();
			if (!WaitForThread(30000))
			{
				Kill();
			}
		}
		threadId = obj.threadId;
		obj.threadId = 0;
		hThread = obj.hThread;
		obj.hThread = 0;
		cancel = std::move(obj.cancel);
		_worker = std::move(obj._worker);
		_onComplete = std::move(obj._onComplete);
	}
	return *this;
}

bool tsThread::Cancel()
{
	return cancel.Set();
}

void tsThread::Kill()
{
	if (!Active())
		return;
#ifdef HAVE_WINDOWS_H
	TerminateThread(hThread, 0);
	hThread = nullptr;
#elif defined(ANDROID)
	hThread = 0;
#else
	pthread_cancel(hThread);
	hThread = 0;
#endif // HAVE_WINDOWS_H
	threadId = 0;
}

bool tsThread::WaitForThread(DWORD timeToWait)
{
	if (!Active())
		return true;

#ifdef HAVE_WINDOWS_H
	switch (WaitForSingleObject(hThread, timeToWait))
	{
	case WAIT_ABANDONED:
	case WAIT_OBJECT_0:
		hThread = nullptr;
		threadId = 0;
		return true;
	case WAIT_TIMEOUT:
		return false;
	default:
	case WAIT_FAILED:
		return false;
	}
#elif defined(ANDROID)
	if (pthread_join(hThread, nullptr) == 0)
		return true;
#else
	if (timeToWait == INFINITE)
	{
		if (pthread_join(hThread, nullptr) == 0)
			return true;
	}
	else
	{
		struct timespec ts;

		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += (timeToWait / 1000);
		ts.tv_nsec += (timeToWait % 1000) * 1000000;
		if (pthread_timedjoin_np(hThread, nullptr, &ts) == 0)
			return true;
	}
	return false;
#endif // HAVE_WINDOWS_H
}

bool tsThread::Active()
{
#ifdef HAVE_WINDOWS_H
	return hThread != nullptr;
#else
	return hThread != 0;
#endif // HAVE_WINDOWS_H
}

bool tsThread::Start()
{
	if (Active())
		return false;
	if (!_worker)
		return false;

	cancel.Reset();

#ifdef HAVE_WINDOWS_H
	hThread = (HANDLE)_beginthreadex(nullptr, 50000, taskStart, this, CREATE_SUSPENDED, &threadId);
	if (hThread == nullptr)
		return false;
	return ResumeThread(hThread) != (DWORD)-1;
#else
	if (pthread_create(&hThread, nullptr, taskStart, this) != 0)
		return false;
	return true;
#endif // HAVE_WINDOWS_H
}

bool tsThread::SetWorker(std::function<int()> func)
{
	if (Active())
		return false;
	_worker = func;
	return true;
}
bool tsThread::SetCompletion(std::function<void()> func)
{
	if (Active())
		return false;
	_onComplete = func;
	return true;
}
#ifdef HAVE_WINDOWS_H
unsigned __stdcall tsThread::taskStart(void * params)
{
	tsThread *This = (tsThread*)params;

#ifndef MINGW
	_set_se_translator(&tsstd::SeException::SeTranslator);
#endif // MINGW

	CoInitialize(nullptr);

	unsigned int retVal = 0xffffffff;

	if (!!This->_worker)
		retVal = (unsigned)This->_worker();

	if (!!This->_onComplete)
		This->_onComplete();

	CoUninitialize();
	CloseHandle(This->hThread);
	This->hThread = nullptr;
	return retVal;
}
#else
void* tsThread::taskStart(void* params)
{
	tsThread* This = (tsThread*)params;
	uint32_t retVal = (uint32_t)-1;

	This->threadId = pthread_self();

	if (!!This->_worker)
		retVal = This->_worker();
	if (!!This->_onComplete)
		This->_onComplete();
	pthread_exit((void*)(INT_PTR)retVal);
}
#endif // HAVE_WINDOWS_H

// ======================================================================
// CancelableTsThread
CancelableTsThread::CancelableTsThread() : tsThread()
{
}
CancelableTsThread::CancelableTsThread(CancelableTsThread&& obj) : tsThread(std::move(obj))
{
}
CancelableTsThread::~CancelableTsThread()
{
}
CancelableTsThread& CancelableTsThread::operator=(CancelableTsThread&& obj)
{
	if (&obj != this)
	{
		tsThread::operator=(std::move(obj));
		_doCancel = std::move(obj._doCancel);
	}
	return *this;
}
bool CancelableTsThread::SetCancel(std::function<void()> func)
{
	_doCancel = func;
	return true;
}
bool CancelableTsThread::Cancel()
{
	if (!!_doCancel)
	{
		_doCancel();
		return true;
	}
	else
		return tsThread::Cancel();
}
void CancelableTsThread::Kill()
{
	if (!!_doCancel)
	{
		_doCancel();
	}
	tsThread::Kill();
}
