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

/*! \defgroup HighLevelHelpers High Level Helpers
 * @{
 */

 /** \file tsDistinguishedName.h
 */
 
#ifndef __TSDISTINGUISHEDNAME_H__
#define __TSDISTINGUISHEDNAME_H__

#pragma once

#ifndef DO_NOT_DOCUMENT  // internal API

namespace tscrypto {

	class VEILCORE_API tsDnPart
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

		tsDnPart();
		tsDnPart(const tsCryptoStringBase& name);
		tsDnPart(const tsCryptoStringBase& name, const tsCryptoStringBase& value);
		tsDnPart(const tsCryptoData& oid, const tsCryptoStringBase& value);
		~tsDnPart();
		tsDnPart(const tsDnPart& obj);
		tsDnPart(tsDnPart&& obj);
		tsDnPart& operator=(const tsDnPart& obj);
		tsDnPart& operator=(tsDnPart&& obj);
		bool operator==(const tsDnPart& obj) const;

		tsCryptoString Name() const;
		void Name(const tsCryptoStringBase& setTo);
		void Name(const char* setTo);
		tsCryptoData NameAsOID() const;
		void NameAsOID(const tsCryptoData& oid);
		void NameAsOID(const tsCryptoStringBase& oid);

		tsCryptoString Value() const;
		tsCryptoString ToString() const;

		void Value(const tsCryptoStringBase& setTo);
		void Value(const char* setTo);

		void clear();

	protected:
		tsCryptoString _name;
		tsCryptoString _value;
	};
#endif // DO_NOT_DOCUMENT

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4231)
	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API ICryptoContainerWrapper<tsDnPart>;
	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::shared_ptr<ICryptoContainerWrapper<tsDnPart>>;
#pragma warning(pop)
#endif // _MSC_VER

	typedef std::shared_ptr<ICryptoContainerWrapper<tsDnPart>> tsDnPartList;

	/// <summary>The core class for member names within an organizational unit</summary>
	class VEILCORE_API tsDistinguishedName
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

		tsDistinguishedName();
		~tsDistinguishedName();
		tsDistinguishedName(const tsDistinguishedName& obj);
		tsDistinguishedName(tsDistinguishedName&& obj);
		tsDistinguishedName& operator=(const tsDistinguishedName& obj);
		tsDistinguishedName& operator=(tsDistinguishedName&& obj);
		bool operator==(const tsDistinguishedName& obj) const;

		tsDnPartList& Parts();
		const tsDnPartList& Parts() const;

		size_t partCount() const;
		const tsDnPart& part(size_t index) const;
		tsDnPart& part(size_t index);

		tsCryptoString ToString() const;
		ptrdiff_t FromString(const char* value);

		void clear();

		tsDnPart* findPartByName(const char* name);
		tsDnPart* findPartByOID(const char* oid);

		void AddPart(const char* name, const char* value);
		void AddPartByOID(const char* oid, const char* value);

	protected:
		tsDnPartList _parts;
	};

}

#endif // __TSDISTINGUISHEDNAME_H__

/*! @} */
