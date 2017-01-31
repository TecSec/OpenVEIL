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


/*! \defgroup TSFRAMEWORK CKM Framework support
 * @{
 */

////////////////////////////////////////////////////////////////////////////////////////////////////
/// \file   IPropertyMap.h
///
/// \brief  Contains a list of named values (properties).
////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef __IPROPERTYMAP_H__
#define __IPROPERTYMAP_H__

#pragma once

class VEILCORE_API IPropertyMap
{
public:
	virtual ~IPropertyMap(){}
	virtual size_t count() const = 0;
	virtual tscrypto::tsCryptoString item(size_t index) const = 0;
	virtual tscrypto::tsCryptoString item(const tscrypto::tsCryptoString &name) const = 0;
	virtual int itemAsNumber(const tscrypto::tsCryptoString &name, int defaultValue) const = 0;
	virtual bool itemAsBoolean(const tscrypto::tsCryptoString &name, bool defaultValue) const = 0;
	virtual bool hasItem(const tscrypto::tsCryptoString &name) const = 0;
	virtual tscrypto::tsCryptoString name(size_t index) const = 0;
	virtual bool AddItem(const tscrypto::tsCryptoString &name, const tscrypto::tsCryptoString &value) = 0;
	virtual bool AddItem(const tscrypto::tsCryptoString &name, int value) = 0;
	virtual void ClearAll () = 0;
	virtual void RemoveItem(size_t index) = 0;
	virtual void RemoveItem(const tscrypto::tsCryptoString &name) = 0;
	virtual tscrypto::tsCryptoString tag(size_t index) const = 0;
	virtual void tag(size_t index, const tscrypto::tsCryptoString& setTo) = 0;
	virtual tscrypto::tsCryptoString tag(const tscrypto::tsCryptoString &name) const = 0;
	virtual void tag(const tscrypto::tsCryptoString &name, const tscrypto::tsCryptoString& setTo) = 0;
	// Added 7.0.35
	virtual bool parseUrlQueryString(const tscrypto::tsCryptoString& queryString) = 0;
	virtual tscrypto::tsCryptoString createUrlQueryString() const = 0;
};


#endif // __IPROPERTYMAP_H__
