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

//////////////////////////////////////////////////////////////////////////////////
/// \file tsCertificateExtension.h
/// \brief This file defines the tsCertficateExtension class that is used in the tsCertificateParser class.
//////////////////////////////////////////////////////////////////////////////////


 #ifndef __TSCERTIFICATEEXTENSION_H__
 #define __TSCERTIFICATEEXTENSION_H__
 
#pragma once

namespace tscrypto
{
	/// <summary>Defines a certificate extension</summary>
	class VEILCORE_API  tsCertificateExtension
	{
	public:
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

		/// <summary>Default constructor.</summary>
		tsCertificateExtension();
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Constructor.</summary>
		///
		/// <param name="OID">	   The oid.</param>
		/// <param name="critical">true if critical.</param>
		/// <param name="value">   The value.</param>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCertificateExtension(const tsCryptoData &OID, bool critical, const tsCryptoData &value);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Copy constructor.</summary>
		///
		/// <param name="obj">The object to copy.</param>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCertificateExtension(const tsCertificateExtension &obj);
		/// <summary>Destructor.</summary>
		~tsCertificateExtension();

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Assignment operator.</summary>
		///
		/// <param name="obj">The object to copy.</param>
		///
		/// <returns>A reference to of this object.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCertificateExtension &operator=(const tsCertificateExtension &obj);

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Populates this class with the information in the encoded extension.</summary>
		///
		/// <param name="node">[in,out] The encoded extension node.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		bool LoadExtension(std::shared_ptr<tscrypto::TlvNode> node);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Creates an encoded node and populates it with the information from this class and
		/// adds it to 'parent'.</summary>
		///
		/// <param name="parent">[in,out] The parent node.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		bool AddToNode(std::shared_ptr<tscrypto::TlvNode> parent) const;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the extension OID.</summary>
		///
		/// <returns>the extension OID.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		const tsCryptoData &OID() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the extension OID.</summary>
		///
		/// <param name="setTo">[in,out] the extension OID.</param>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		void OID(tsCryptoData &setTo);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Queries this node to see if it must be understood.</summary>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		bool Critical() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the flag that indicates that the user of the certificate must understand this
		/// extension.</summary>
		///
		/// <param name="setTo">the flag that indicates that the user of the certificate must understand
		/// this extension.</param>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		void Critical(bool setTo);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the value stored in this extension.</summary>
		///
		/// <returns>the value stored in this extension.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		const tsCryptoData &Value() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the value stored in this extension.</summary>
		///
		/// <param name="setTo">[in,out] the value stored in this extension.</param>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		void Value(tsCryptoData &setTo);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the oid for this extension as a string.</summary>
		///
		/// <returns>the oid for this extension as a string.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString oidString() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the name of this extension.</summary>
		///
		/// <returns>the name of this extension.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString ExtensionName() const;
		/// <summary>Clears this object to its blank/initial state.</summary>
		void Clear();

		//////////////////////////////////////////////////////////////////////////////////////////////////////
		///// <summary>Object allocation operator.</summary>
		/////
		///// <param name="bytes">The number of bytes to allocate.</param>
		/////
		///// <returns>The allocated object.</returns>
		//////////////////////////////////////////////////////////////////////////////////////////////////////
		//void *operator new(size_t bytes);
		//////////////////////////////////////////////////////////////////////////////////////////////////////
		///// <summary>Object de-allocation operator.</summary>
		/////
		///// <param name="ptr">[in,out] If non-null, the pointer to delete.</param>
		//////////////////////////////////////////////////////////////////////////////////////////////////////
		//void operator delete(void *ptr);

		bool operator==(const tsCertificateExtension& obj) const
		{
			return m_oid == obj.m_oid;
		}
		bool operator!=(const tsCertificateExtension& obj) const
		{
			return m_oid != obj.m_oid;
		}
	private:
		tsCryptoData m_oid;
		tsCryptoData m_value;
		bool       m_critical;
		tsCryptoString   m_oidString;
		tsCryptoString m_extName;
	};

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4231)
#pragma warning(disable:4251)
	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API tscrypto::ICryptoContainerWrapper<tsCertificateExtension>;
	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::shared_ptr<tscrypto::ICryptoContainerWrapper<tsCertificateExtension>>;
#pragma warning(pop)
#endif // _MSC_VER

	typedef std::shared_ptr<tscrypto::ICryptoContainerWrapper<tsCertificateExtension>> tsCertificateExtensionList;
}

#endif // __TSCERTIFICATEEXTENSION_H__
