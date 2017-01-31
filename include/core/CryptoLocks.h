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

/*! @file tsLocks.h
 * @brief This file defines a functions and classes for critical sections and mutexes.
*/

#ifndef CRYPTOLOCKS_H_INCLUDED
#define CRYPTOLOCKS_H_INCLUDED

namespace tscrypto
{
#pragma warning(push)
#pragma warning(disable: 28204)
	/// <summary>Defines an interface that can be automatically locked and unlocked using the tsAutoLocker class.</summary>
	class VEILCORE_API ILockable
	{
	public:
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Locks the controlled object and if timeouts are used, limit the wait time to timeout.</summary>
		///
		/// <param name="timeout">(optional) the timeout.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual BOOL Lock(uint32_t timeout = -1) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Unlocks the controlled object.</summary>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual BOOL Unlock() = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Query if the controlled object is still valid for locking and unlocking.</summary>
		///
		/// <returns>true if valid, false if not.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual BOOL isValid() = 0;
	};

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Implements a lockable object using the Windows Critical Section for locking critical code.</summary>
	///
	/// <seealso cref="ITSLockable"/>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	class VEILCORE_API AutoCriticalSection
	{
	public:
		/// <summary>Default constructor.</summary>
		AutoCriticalSection();
		/// <summary>Destructor.</summary>
		~AutoCriticalSection();

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Locks the object.  If the object is locked on another thread, this thread will wait.</summary>
		///
		/// <param name="timeout">(optional) the timeout (not used).</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		_Acquires_lock_(this->m_section) BOOL Lock(uint32_t timeout = -1);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Unlocks this object.</summary>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		_Releases_lock_(this->m_section) BOOL Unlock();
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Query if this object is valid.</summary>
		///
		/// <returns>true</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		BOOL isValid();

	protected:
		CRITICAL_SECTION m_section; ///< The lockable object, a critical section
	};
#pragma warning(pop)


	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Manages a lockable object and automatically unlocks it upon exit from that code block.</summary>
	///
	/// <remarks>This class automatically locks a critical section or mutex.  When the class is
	/// destructed it unlocks the critical section or mutex.</remarks>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	template <class T>
	class VEILCORE_API AutoLocker
	{
	public:
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Constructor.</summary>
		///
		/// <param name="list">[in,out] The lockable object.</param>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		AutoLocker(T &list) :
			m_list(list),
			locked(false)
		{
			m_list.Lock();
			locked = true;
		}
		/// <summary>Destructor. Unlocks the object.</summary>
		~AutoLocker()
		{
			Unlock();
		}
		void Unlock()
		{
			if (locked)
			{
				m_list.Unlock();
				locked = false;
			}
		}

	protected:
		T &m_list;
		bool locked;

	private:
		AutoLocker &operator=(const AutoLocker &) = delete;
	};
}

#ifndef _NO_TS_LOCK_DEFINES
#   define TSAUTOLOCKER tscrypto::AutoLocker<tscrypto::AutoCriticalSection>
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4231)

VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API tscrypto::AutoLocker<tscrypto::AutoCriticalSection>;

#pragma warning(pop)
#endif // _MSC_VER

#endif // CRYPTOLOCKS_H_INCLUDED
/*! @} */