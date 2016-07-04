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


//////////////////////////////////////////////////////////////////////////////////
/// \file ChangeTracker.h
/// \brief An implementation if the TecSecCrypto_Fips::ICkmChangeProducer interface.
//////////////////////////////////////////////////////////////////////////////////

#ifndef __CHANGETRACKER_H__
#define __CHANGETRACKER_H__

#pragma once

	/// <summary>This type is used to report or look for a specific type of change from the CKM Change system.</summary>
	typedef enum CKMChangeType {
		CKMChange_NoChange = 0,           ///< Indicates that no changes are wanted or found (placeholder)
		CKMChange_ProviderChange = 1,     ///< Looking for or reporting a Token Provider change
		CKMChange_TokenChange = 2,        ///< Looking for or reporting a Token change
		CKMChange_CkmAppChange = 4,       ///< Looking for or reporting a CKM Enabled Application change
		CKMChange_FavoriteChange = 8,     ///< Looking for or reporting a CKM Favorite change
		CKMChange_WinscardChange = 16,    ///< Looking for or reporting a CKM Smartcard monitor change
		CKMChange_Preferences = 32,		  ///< Looking for or reporting a CKM Preferences change
		CKMChange_File = 64,              ///< Looking for or reporting a potential change in a watched file

		CKMChange_AnyChange = (int)0xFFFFFFFF  ///< Looking for all change types
	} CKMChangeType;

	/// <summary>Base type for the reported change.  All changes must start with this information.<summary>
	class EXPORT_SYMBOL ICkmChangeEvent
	{
	public:
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the change type.</summary>
		///
		/// <returns>The change type.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual CKMChangeType GetChangeType() = 0;
	};

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>All change producers must implement this interface and register with CkmLoader using
	/// the RegisterChangeProducer function.</summary>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	class EXPORT_SYMBOL ICkmChangeProducer
	{
	public:
		/// <summary>Called by the change monitoring system to scan for changes.</summary>
		virtual void ScanForChanges(void) = 0;
	};

	/// <summary>All change consumers (listeners for changes) must implement this interface.</summary>
	class EXPORT_SYMBOL ICkmChangeConsumer
	{
	public:
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Specifies the types of changes desired.</summary>
		///
		/// <returns>The types of changes desired.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual CKMChangeType WantsChangesMatching() = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Called by the change monitoring system to report a relevant change.</summary>
		///
		/// <param name="eventObj">[in] The event object.</param>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual void          OnCkmChange(std::shared_ptr<ICkmChangeEvent>& eventObj) = 0;
	};
	/// <summary>Describes the change monitoring system</summary>
	class EXPORT_SYMBOL ICkmChangeMonitor
	{
	public:
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>Start a thread and run the change monitor in that thread.</summary>
        ///
        /// <returns>S_OK for success or a standard COM error for failure.</returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        virtual bool StartChangeMonitorThread( void) = 0;
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>Stops the change monitor thread.</summary>
        ///
        /// <returns>S_OK for success or a standard COM error for failure.</returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool StopChangeMonitorThread(void) = 0;
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>Forcefully kills the change monitor thread.</summary>
        ///
        /// <returns>S_OK for success or a standard COM error for failure.</returns>
        /// \warning The thread resources are NOT released when this function is used.
        ////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool KillChangeMonitorThread(void) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Registers the change producer described by setTo.</summary>
		///
		/// <param name="setTo">[in] The change producer to register.</param>
		///
		/// <returns>A cookie that is used to unregister this change producer.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual uint32_t  RegisterChangeProducer(std::shared_ptr<ICkmChangeProducer> setTo) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Unregisters the change producer described by cookie.</summary>
		///
		/// <param name="cookie">The cookie.</param>
		///
        /// <returns>S_OK for success or a standard COM error for failure.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool UnregisterChangeProducer(uint32_t cookie) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Scans all change producers to see if any of them have detected a change.</summary>
		///
        /// <returns>S_OK for success or a standard COM error for failure.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool LookForChanges() = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Registers a change consumer described by setTo.</summary>
		///
		/// <param name="setTo">[in] A change consumer.</param>
		///
		/// <returns>A cookie that identifies this change consumer.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual uint32_t  RegisterChangeConsumer(std::shared_ptr<ICkmChangeConsumer> setTo) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Unregisters the change consumer described by cookie.</summary>
		///
		/// <param name="cookie">The cookie.</param>
		///
        /// <returns>S_OK for success or a standard COM error for failure.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool UnregisterChangeConsumer(uint32_t cookie) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Called by a change producer to signal that a change has been detected.</summary>
		///
		/// <param name="eventObj">[in] The event object describing the change detected.</param>
		///
        /// <returns>S_OK for success or a standard COM error for failure.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool RaiseChange(std::shared_ptr<ICkmChangeEvent> eventObj) = 0;
	};

#if (defined(_WIN32) || defined(VEILCORE_EXPORTS)) && !defined(MSYS) && !defined(MINGW)
#pragma warning(push)
#pragma warning(disable:4231)
	class ChangeTracker;
	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::shared_ptr<ICkmChangeMonitor>;
	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::shared_ptr<ICkmChangeProducer>;
	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::shared_ptr<ChangeTracker>;
#pragma warning(pop)
#endif // defined

	/** \brief The global change monitor object instance
	*/
	extern std::shared_ptr<ICkmChangeMonitor> VEILCORE_API gChangeMonitor;
	/**
	* \brief Gets the change monitor.  Will start the change monitor if needed.
	*
	* \param [in,out] pVal If non-null, the value.
	*
	* \return The change monitor.
	*/
	std::shared_ptr<ICkmChangeMonitor> VEILCORE_API GetChangeMonitor();
	/**
	* \brief Indicates if there currently is an active change monitor.
	*
	* \return A TSFRAMEWORK_API.
	*/
	bool VEILCORE_API HasChangeMonitor();

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>An implementation if the TecSecCrypto_Fips::ICkmChangeProducer interface.</summary>
///
/// <typeparam name="T">Generic type parameter.</typeparam>
///
/// <seealso cref="TecSecCrypto_Fips::ICkmChangeProducer"/>
////////////////////////////////////////////////////////////////////////////////////////////////////
	class EXPORT_SYMBOL VEILCORE_API ChangeTracker : public ICkmChangeProducer, public tsmod::IObject
{
public:
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Constructor.</summary>
	///
	/// <param name="obj">[in,out] the object that will be called to ceck for changes.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	ChangeTracker(std::shared_ptr<ICkmChangeProducer> obj) :
		m_obj(obj)
	{
        if (GetChangeMonitor() != nullptr)
			m_cookie = GetChangeMonitor()->RegisterChangeProducer(std::dynamic_pointer_cast<ICkmChangeProducer>(_me.lock()));
	}
	/// <summary>Destructor.</summary>
	~ChangeTracker()
	{
		if (!!GetChangeMonitor() && m_cookie != 0)
        {
			GetChangeMonitor()->UnregisterChangeProducer(m_cookie);
        }
		m_cookie = 0;
	}
	/// <summary>Disconnects the object from this change tracker.</summary>
	void Disconnect()
	{
		m_obj.reset();
	}
	/// <summary>Called by the change tracker system to look for changes.</summary>
	virtual void ScanForChanges(void)
	{
		if (!!m_obj)
			m_obj->ScanForChanges();
	}
protected:
	std::shared_ptr<ICkmChangeProducer> m_obj;
	int m_cookie;
};

#endif // __CHANGETRACKER_H__

