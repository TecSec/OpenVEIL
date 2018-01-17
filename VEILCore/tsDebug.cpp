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

//#define DEBUG_HEAP
//#define DEBUG_PROCESS_HEAP

#ifdef DEBUG_HEAP
#include <malloc.h>
#endif



HIDDEN uint32_t GetNewObjectId()
{
	static uint32_t gNextObjectId = 0;

	return InterlockedIncrement(&gNextObjectId);
}

#ifdef _WIN32
tscrypto::tsCryptoString COMMessage(HRESULT hr)
{
	tscrypto::tsCryptoString sHr;

	switch (hr)
	{
	case S_OK: sHr = "OK"; break;
	case S_FALSE: sHr = "FALSE"; break;
	case E_NOTIMPL: sHr = "Not Implemented"; break;
	case E_UNEXPECTED: sHr = "Unexpected operation"; break;
	case E_OUTOFMEMORY: sHr = "Out Of Memory"; break;
	case E_INVALIDARG: sHr = "Invalid Argument"; break;
	case E_NOINTERFACE: sHr = "No Interface"; break;
	case E_POINTER: sHr = "Invalid Pointer"; break;
	case E_HANDLE: sHr = "Invalid Handle"; break;
	case E_ABORT: sHr = "Aborted"; break;
	case E_FAIL: sHr = "General Failure"; break;
	case E_ACCESSDENIED: sHr = "Access Denied"; break;
	case E_PENDING: sHr = ""; break;
	default:
		sHr.Format("0x%08X", hr);
		break;
	}
#ifndef NO_IDISPATCH
	if (FAILED(hr))
	{
		IErrorInfo* pErrInfo = nullptr;

		if (::GetErrorInfo(0, &pErrInfo) == S_OK)
		{
			BSTR tmp = nullptr;

			if (SUCCEEDED(pErrInfo->GetDescription(&tmp)))
				sHr << " - " << CryptoUtf16(tmp).toUtf8();
			SysFreeString(tmp);
			pErrInfo->Release();
		}
	}
#endif // NO_IDISPATCH
	return sHr;
}
#endif // _WIN32

HIDDEN void TSTRACEValidateHeaps()
{
#ifdef DEBUG_HEAP
	if ( _heapchk() != _HEAPOK )
	{
		CkmError("*****  HEAP DAMAGE DETECTED *****");
		LOG(CallTrace, "Error: *****  HEAP DAMAGE DETECTED *****");
		DebugBreak();
	}
#endif
#ifdef DEBUG_PROCESS_HEAP
	tsByteString buffer;
	uint32_t heapCount;

	buffer.resize (sizeof(HANDLE));
	heapCount = GetProcessHeaps(1, (PHANDLE)buffer.rawData());
	if ( heapCount > 1 )
	{
		buffer.resize(sizeof(HANDLE) * heapCount);
		heapCount = GetProcessHeaps(heapCount, (PHANDLE)buffer.rawData());
	}
	for (int ii = 0; ii < heapCount; ii++)
	{
		if ( !HeapValidate(((PHANDLE)buffer.rawData())[ii], 0, NULL) )
		{
			CkmError("*****  PROCESS HEAP DAMAGE DETECTED *****");
			LOG(CallTrace, "Error: *****  PROCESS HEAP DAMAGE DETECTED *****");
			//            DebugBreak();
		}
	}
#endif // DEBUG_PROCESS_HEAP
}

_tsTraceClassExt::_tsTraceClassExt(const _tsTraceInfoExt &info) :
m_TraceInfo(info),
m_classInstance(GetNewObjectId())
{
	if (m_TraceInfo.enabled)
	{
		LOG(CallTrace, "CREATE  " << m_TraceInfo.name << " [" << ToHex()(this) << " - " << m_classInstance << "]");
	}
}

_tsTraceClassExt::_tsTraceClassExt(const _tsTraceClassExt &info) :
m_TraceInfo(info.m_TraceInfo),
m_classInstance(info.m_classInstance)
{
}

_tsTraceClassExt::~_tsTraceClassExt()
{
	if (m_TraceInfo.enabled)
	{
		LOG(CallTrace, "DESTROY " << m_TraceInfo.name << " [" << ToHex()(this) << " - " << m_classInstance << "]");
	}
}

_tsTraceInfoExt::_tsTraceInfoExt(const tscrypto::tsCryptoString& FuncName, const tscrypto::tsCryptoString& InfoName, _tsTraceTypeEnumExt Tp, bool allow) :
next(_gTsTraceHeadExt),
name(FuncName),
info(InfoName),
type(Tp),
enabled(allow)
{
	id = InterlockedIncrement(&gNextTraceIDExt);
	_gTsTraceHeadExt = this;

	if (type == tsTraceModuleExt)
		_gTsTraceModuleExt = this;
}

_tsTraceFunctionExt::_tsTraceFunctionExt(const _tsTraceInfoExt &info, void *This) :
m_info(info),
m_This(This),
m_error(false)
{
	TSTRACEValidateHeaps();
	if (m_info.enabled)
	{
		if (This != NULL)
		{
			LOG(CallTrace, "BEGIN " << m_info.name << " // 0x" << ToHex()(this) << "  " << m_info.info);
		}
		else
		{
			LOG(CallTrace, "BEGIN " << m_info.name << " // " << m_info.info);
		}
		LOGD(CallTrace, indent);
	}
}

_tsTraceFunctionExt::~_tsTraceFunctionExt()
{
	TSTRACEValidateHeaps();
	if (m_info.enabled)
	{
		if (m_outMessage.size() != 0)
		{
			if (m_error)
			{
				LOG(FrameworkError, m_outMessage);
				LOG(CallTrace, "Error: " << m_outMessage);
			}
			else
			{
				LOG(CallTrace, m_outMessage);
			}
		}
		else
		{
			LOG(FrameworkError, "Error:  Exception or unknown return value\n");
			LOG(CallTrace, "Error:  Exception or unknown return value\n");
		}
		if (m_This != NULL)
		{
			LOGD(CallTrace, outdent);
			LOG(CallTrace, "END " << m_info.name << " // 0x" << ToHex()(this));
		}
		else
		{
			LOGD(CallTrace, outdent);
			LOG(CallTrace, "END " << m_info.name);
		}
		CallTrace << tscrypto::endl;
	}
}

_tsTraceFunctionExt &_tsTraceFunctionExt::setError()
{
	m_error = true;
	return *this;
}
#ifdef _WIN32
_tsTraceFunctionExt &_tsTraceFunctionExt::returnCOMMsg(HRESULT hr, tscrypto::tsCryptoString fmt, ...)
{
	tscrypto::tsCryptoString sHr;
	va_list args;

	switch (hr)
	{
	case S_OK: sHr = "OK"; break;
	case S_FALSE: sHr = "FALSE"; break;
	case E_NOTIMPL: sHr = "Not Implemented"; break;
	case E_UNEXPECTED: sHr = "Unexpected operation"; break;
	case E_OUTOFMEMORY: sHr = "Out Of Memory"; break;
	case E_INVALIDARG: sHr = "Invalid Argument"; break;
	case E_NOINTERFACE: sHr = "No Interface"; break;
	case E_POINTER: sHr = "Invalid Pointer"; break;
	case E_HANDLE: sHr = "Invalid Handle"; break;
	case E_ABORT: sHr = "Aborted"; break;
	case E_FAIL: sHr = "General Failure"; break;
	case E_ACCESSDENIED: sHr = "Access Denied"; break;
	case E_PENDING: sHr = ""; break;
	default:
		sHr.Format("0x%08X", hr);
		break;
	}
	setErrorTo(FAILED(hr) != FALSE);
	va_start(args, fmt);
	m_outMessage.clear();
	m_outMessage.resize(MAX_TRACE_MSG_LEN);
    tsVsnPrintf(m_outMessage.rawData(), m_outMessage.size(), fmt.c_str(), args);
	m_outMessage.resize((uint32_t)tsStrLen(m_outMessage.c_str()));
	m_outMessage.Replace("~~", sHr.c_str());
	returns(hr);
	return *this;
}

_tsTraceFunctionExt &_tsTraceFunctionExt::returnCOM(HRESULT hr)
{
	tscrypto::tsCryptoString sHr = COMMessage(hr);

	setErrorTo(FAILED(hr) != FALSE);
	m_outMessage = sHr;
	returns(hr);
	return *this;
}
#endif // def _WIN32

_tsTraceMethodExt::_tsTraceMethodExt(const _tsTraceClassExt &info, const tscrypto::tsCryptoString& MethodName, const void *This) :
m_This(This),
m_error(false),
m_method(MethodName),
enabled(info.m_TraceInfo.enabled),
classInstance(info.m_classInstance)
{
	TSTRACEValidateHeaps();
	if (enabled)
	{
		LOG(CallTrace, "BEGIN  // " << m_method << " [" << ToHex()(this) << " - " << classInstance << "]");
		LOGD(CallTrace, indent);
	}
}

_tsTraceMethodExt::~_tsTraceMethodExt()
{
	TSTRACEValidateHeaps();
	if (enabled)
	{
		if (m_outMessage.size() != 0)
		{
			if (m_error)
			{
				FrameworkError << m_outMessage << tscrypto::endl;
				LOG(CallTrace, "Error: " << m_outMessage);
			}
			else
			{
				LOG(CallTrace, m_outMessage);
			}
		}
		else
		{
			LOG(FrameworkError, "Error:  Exception or unknown return value\n");
			LOG(CallTrace, "Error:  Exception or unknown return value\n");
		}
		LOGD(CallTrace, outdent);
		LOG(CallTrace, "END // " << m_method << " [" << ToHex()(this) << " - " << classInstance << "]");
	}
}

_tsTraceMethodExt &_tsTraceMethodExt::setError()
{
	m_error = true;
	return *this;
}
#ifdef _WIN32
_tsTraceMethodExt &_tsTraceMethodExt::returnCOMMsg(HRESULT hr, tscrypto::tsCryptoString fmt, ...)
{
	tscrypto::tsCryptoString sHr;
	va_list args;

	switch (hr)
	{
	case S_OK: sHr = "OK"; break;
	case S_FALSE: sHr = "FALSE"; break;
	case E_NOTIMPL: sHr = "Not Implemented"; break;
	case E_UNEXPECTED: sHr = "Unexpected operation"; break;
	case E_OUTOFMEMORY: sHr = "Out Of Memory"; break;
	case E_INVALIDARG: sHr = "Invalid Argument"; break;
	case E_NOINTERFACE: sHr = "No Interface"; break;
	case E_POINTER: sHr = "Invalid Pointer"; break;
	case E_HANDLE: sHr = "Invalid Handle"; break;
	case E_ABORT: sHr = "Aborted"; break;
	case E_FAIL: sHr = "General Failure"; break;
	case E_ACCESSDENIED: sHr = "Access Denied"; break;
	case E_PENDING: sHr = ""; break;
	default:
		sHr.Format("0x%08X", hr);
		break;
	}
	setErrorTo(FAILED(hr) != FALSE);
	va_start(args, fmt);
	m_outMessage.clear();
	m_outMessage.resize(MAX_TRACE_MSG_LEN);
    tsVsnPrintf(m_outMessage.rawData(), m_outMessage.size(), fmt.c_str(), args);
	m_outMessage.resize((uint32_t)tsStrLen(m_outMessage.c_str()));
	m_outMessage.Replace("~~", sHr.c_str());
	returns(hr);
	return *this;
}

_tsTraceMethodExt &_tsTraceMethodExt::returnCOM(HRESULT hr)
{
	tscrypto::tsCryptoString sHr = COMMessage(hr);

	setErrorTo(FAILED(hr) != FALSE);
	m_outMessage = sHr;
	returns(hr);
	return *this;
}
#endif // def _WIN32
bool _tsTraceMethodExt::Enabled()
{
	return this->enabled;
}

void CkmDebug_LOCKING(const tscrypto::tsCryptoString& lockName, const tscrypto::tsCryptoString& lockType, void *lockAddr, TSTRACE_LOCK_STATE state)
{
	static uint32_t instance = 0;

	try
	{
		uint32_t currInstance = InterlockedIncrement(&instance);

		LOG(FrameworkLocks, ToHex()(currInstance) << ": " << (state == tsLockWillAcquire ? "ASKING FOR" : (state == tsLockAcquired ? "ACQUIRED" : (state == tsLockTimeout ? "TIMEOUT" : "RELEASED")))
			<< ":" << (lockType.c_str() ? lockType : "unknown") << ":" << (lockName.c_str() ? lockName : "unknown") << " -> " << ToHex()(lockAddr));
	}
	catch (...)
	{
	}
}

