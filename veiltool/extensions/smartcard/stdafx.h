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
// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//
// Written by Roger Butler

#pragma once

#ifdef _WIN32
#include "targetver.h"
#endif // _WIN32

#ifdef __APPLE__
#   include "PCSC/winscard.h"
#   include "PCSC/pcsclite.h"
typedef uint32_t* LPDWORD;
#define ERROR_SUCCESS 0
#endif

#include "VEIL.h"

#if defined(__linux)
#   include "winscard.h"
#   include "pcsclite.h"
#define ERROR_SUCCESS 0
#endif

#include "core/SimpleOpt.h"
#include <iostream>
using namespace std;
using namespace tscrypto;

#include "core/IVeilToolCommand.h"
#include "core/IOutputCollector.h"
#include "core/IVeilUtilities.h"

extern const TSISmartCardManager* scMan;

class SmartCardTransaction
{
public:
	SmartCardTransaction(TSWORKSPACE connection) : _connection2(connection), _alreadyHadTransaction(false), desc(TSWorker(TSISmartCardConnection, connection))
	{
		if (!!_connection2 && desc != NULL)
		{
            _alreadyHadTransaction = desc->isInTransaction(connection);
			if (!_alreadyHadTransaction)
				desc->startTransaction(connection);
		}
	}
	bool ExitTransaction(bool reset)
	{
		if (_connection2 != nullptr && desc != NULL && !_alreadyHadTransaction)
		{
			_alreadyHadTransaction = false;
            desc->finishTransaction(_connection2, reset);
			_connection2 = nullptr;
			return true;
		}
		return true;
	}
	~SmartCardTransaction()
	{
		if (_connection2 != nullptr && desc != NULL && !_alreadyHadTransaction)
		{
            desc->finishTransaction(_connection2, false);
        }
	}
private:
    TSWORKSPACE _connection2;
    const TSISmartCardConnection* desc;
	bool _alreadyHadTransaction;
};

// TODO:  remove me when done merging to C code
//class SmartCardChanges : public ICkmWinscardChange
//{
//public:
//	SmartCardChanges(std::function<void(const tscrypto::tsCryptoString& readerName)> onInsert) : _onInsert(onInsert) {};
//	~SmartCardChanges() {};
//
//	virtual void readerAdded(const tscrypto::tsCryptoString &name) { }
//	virtual void readerRemoved(const tscrypto::tsCryptoString &name) { }
//	virtual void cardInserted(const tscrypto::tsCryptoString &name) { _onInsert(name); }
//	virtual void cardRemoved(const tscrypto::tsCryptoString &name) { }
//
//private:
//	std::function<void(const tscrypto::tsCryptoString& readerName)> _onInsert;
//};
