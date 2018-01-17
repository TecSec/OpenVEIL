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

/*! \defgroup TSFRAMEWORK CKM Framework support
 * @{
 */

 ////////////////////////////////////////////////////////////////////////////////////////////////////
 /// \file   tsThread.h
 ///
 /// \brief  Thread management object that represents a single thread
 ////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef tsThread_H_INCLUDED
#define tsThread_H_INCLUDED

#pragma once


#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4231)
template class VEILCORE_API std::function<int()>; ///< Constructs this templated object in the TSFramework dll
template class VEILCORE_API std::function<void()>; ///< Constructs this templated object in the TSFramework dll
#pragma warning(pop)
#endif // _MSC_VER

class VEILCORE_API tsThread
{
public:
	tsThread();
	tsThread(const tsThread&) = delete;
	tsThread(tsThread&& obj);
	virtual ~tsThread();
	tsThread& operator=(const tsThread&) = delete;
	tsThread& operator=(tsThread&& obj);

	virtual bool Cancel();
	virtual void Kill(); // Last resort
	virtual bool WaitForThread(uint32_t timeToWait);
	virtual bool Active();
	virtual bool Start();
	virtual bool SetWorker(std::function<int()> func);
	virtual bool SetCompletion(std::function<void()> func);
    virtual bool SetCancel(std::function<void()> func);

    TSEVENT cancelEvent() { return tsThreadCancelEvent(threadHandle); }

protected:
    TSTHREAD threadHandle;
	std::function<int()> _worker;
	std::function<void()> _onComplete;
    std::function<void()> _doCancel;

    static int workerFunc(TSTHREAD thread, void* params);
    static void completionFunc(TSTHREAD thread, void* params);
    static void cancelFunc(TSTHREAD thread, void* params);
};

typedef tsThread CancelableTsThread;

#endif // tsThread_H_INCLUDED

/*!
 * @}
 */
