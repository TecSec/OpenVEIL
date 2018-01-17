//	Copyright (c) 2018, TecSec, Inc.
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

int tsThread::workerFunc(TSTHREAD thread, void* params)
{
    tsThread* This = (tsThread*)params;
    uint32_t retVal = (uint32_t)-1;

#ifdef _WIN32
#ifndef MINGW
    _set_se_translator(&tsstd::SeException::SeTranslator);
#endif // MINGW

    if (!!This->_worker)
        retVal = (unsigned)This->_worker();

#else

    if (!!This->_worker)
        retVal = This->_worker();

#endif // _WIN32
    return retVal;
}
void tsThread::completionFunc(TSTHREAD thread, void* params)
{
    tsThread* This = (tsThread*)params;

    if (!!This->_onComplete)
        This->_onComplete();
}
void tsThread::cancelFunc(TSTHREAD thread, void* params)
{
    tsThread* This = (tsThread*)params;

    if (!!This->_doCancel)
        This->_doCancel();

}

tsThread::tsThread() :
    threadHandle(nullptr)
{
    threadHandle = tsCreateThread();
    if (threadHandle != nullptr)
    {
        tsSetThreadWorker(threadHandle, &tsThread::workerFunc, this);
        tsSetThreadCompletion(threadHandle, &tsThread::completionFunc, this);
    }
}
tsThread::tsThread(tsThread&& obj) : threadHandle(obj.threadHandle), _worker(std::move(obj._worker)), _onComplete(std::move(obj._onComplete)), _doCancel(std::move(obj._doCancel))
{
    obj.threadHandle = nullptr;
    if (threadHandle != nullptr)
    {
        tsSetThreadWorker(threadHandle, &tsThread::workerFunc, this);
        tsSetThreadCompletion(threadHandle, &tsThread::completionFunc, this);
        if (!!_doCancel)
            tsSetThreadCancel(threadHandle, &tsThread::cancelFunc, this);
    }
}

tsThread::~tsThread()
{
    tsFreeThread(&threadHandle);
}

tsThread& tsThread::operator=(tsThread&& obj)
{
    if (&obj != this)
    {
        tsFreeThread(&threadHandle);
        threadHandle = obj.threadHandle;
        obj.threadHandle = nullptr;
        _worker = std::move(_worker);
        _onComplete = std::move(_onComplete);
        _doCancel = std::move(obj._doCancel);
        if (threadHandle != nullptr)
        {
            tsSetThreadWorker(threadHandle, &tsThread::workerFunc, this);
            tsSetThreadCompletion(threadHandle, &tsThread::completionFunc, this);
            if (!!_doCancel)
                tsSetThreadCancel(threadHandle, &tsThread::cancelFunc, this);
            else
                tsSetThreadCancel(threadHandle, nullptr, nullptr);
        }
    }
    return *this;
}

bool tsThread::Cancel()
{
    return tsCancelThread(threadHandle);
}

void tsThread::Kill()
{
    tsKillThread(threadHandle);
    tsFreeThread(&threadHandle);
}

bool tsThread::WaitForThread(uint32_t timeToWait)
{
    return tsWaitForThread(threadHandle, timeToWait);
}

bool tsThread::Active()
{
    return tsThreadActive(threadHandle);
}

bool tsThread::Start()
{
    if (Active())
        return false;
    if (!_worker)
        return false;

    if (threadHandle == nullptr)
    {
        threadHandle = tsCreateThread();
        if (threadHandle != nullptr)
        {
            tsSetThreadWorker(threadHandle, &tsThread::workerFunc, this);
            tsSetThreadCompletion(threadHandle, &tsThread::completionFunc, this);
            if (!!_doCancel)
                tsSetThreadCancel(threadHandle, &tsThread::cancelFunc, this);
            else
                tsSetThreadCancel(threadHandle, nullptr, nullptr);
        }
    }
    return tsStartThread(threadHandle);
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
bool tsThread::SetCancel(std::function<void()> func)
{
    _doCancel = func;
    if (threadHandle != nullptr)
    {
        if (!!_doCancel)
            tsSetThreadCancel(threadHandle, &tsThread::cancelFunc, this);
        else
            tsSetThreadCancel(threadHandle, nullptr, nullptr);
    }
    return true;
}

