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

////////////////////////////////////////////////////////////////////////////////////////////////////
/// \file   CryptoEvent.h
///
/// \brief  Event handling
////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef CryptoEvent_H_INCLUDED
#define CryptoEvent_H_INCLUDED

#pragma once

namespace tscrypto {

#ifndef INFINITE
#define INFINITE -1
#endif // INFINITE

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Wait for the event forever</summary>
	////////////////////////////////////////////////////////////////////////////////////////////////////
#define XP_EVENT_INFINITE           ((uint32_t)-1)
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Try to get the event or time out immediately.</summary>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define XP_EVENT_TRY                ((uint32_t)0)

	class VEILCORE_API CryptoEvent
	{
	public:
		typedef enum {
			AlreadyLocked = 0,	///< Already locked
			Failed = -1,		///< Failed
			Timeout = -2,
			Succeeded_Object1 = 1,	///< Success
			Succeeded_Object2 = 2,	///< Success
			Succeeded_Object3 = 3,	///< Success
			Succeeded_Object4 = 4,	///< Success
		} EventStatus;

		static void* operator new(std::size_t count) {
			return tscrypto::cryptoNew(count);
		}
		static void* operator new[](std::size_t count) {
			return tscrypto::cryptoNew(count);
		}
		static void operator delete(void* ptr) {
			tscrypto::cryptoDelete(ptr);
		}
		static void operator delete[](void* ptr) {
			tscrypto::cryptoDelete(ptr);
		}

		CryptoEvent(bool manualReset = false, bool initialValue = false);
		virtual ~CryptoEvent();

		virtual bool IsActive() const;
		virtual bool Set();
		virtual bool Reset();
		virtual EventStatus WaitForEvent(uint32_t timeout);
		virtual EventStatus WaitForEvents(uint32_t timeout, CryptoEvent& event2);
		virtual EventStatus WaitForEvents(uint32_t timeout, CryptoEvent& event2, CryptoEvent& event3);
		virtual EventStatus WaitForEvents(uint32_t timeout, CryptoEvent& event2, CryptoEvent& event3, CryptoEvent& event4);
		void* GetHandle() { return _theEvent; }

	private:
		void* _theEvent;
	};

}
#endif // CryptoEvent_H_INCLUDED

/*!
 * @}
 */
