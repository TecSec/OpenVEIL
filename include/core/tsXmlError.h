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

/*! @file tsXmlError.h
 * @brief This file defines the object that will hold an error node found when parsing the XML with tsXMLParser.
*/

#if !defined(AFX_tsXmlError_H__5BB47447_4058_4300_87A3_BB6528B3407A__INCLUDED_)
#define AFX_tsXmlError_H__5BB47447_4058_4300_87A3_BB6528B3407A__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "tsAttributeMap.h"

/// <summary>Holds a parsed XML Error</summary>
class VEILCORE_API tsXmlError : public tsmod::IObject
{
public:
    /// <summary>Default constructor.</summary>
    tsXmlError();
    /// <summary>Destructor.</summary>
    virtual ~tsXmlError();

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the error description.</summary>
    ///
    /// <returns>The error description.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    const tscrypto::tsCryptoString &Description() const;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the error description</summary>
    ///
    /// <param name="parameter1">The error description.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    void Description(const tscrypto::tsCryptoString&);
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the component that produced the error.</summary>
    ///
    /// <returns>the component that produced the error.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    const tscrypto::tsCryptoString &Component() const;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the component that produced the error.</summary>
    ///
    /// <param name="parameter1">the component that produced the error.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    void Component(const tscrypto::tsCryptoString&);
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the method that produced the error.</summary>
    ///
    /// <returns>the method that produced the error.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    const tscrypto::tsCryptoString &Method() const;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the method that produced the error.</summary>
    ///
    /// <param name="parameter1">the method that produced the error.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    void Method(const tscrypto::tsCryptoString&);
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the error number.</summary>
    ///
    /// <returns>The error number.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    int32_t Number() const;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the error number.</summary>
    ///
    /// <param name="parameter1">The error number.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    void Number(int32_t);

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Converts this error into an XML string.</summary>
    ///
    /// <param name="appendToXML">[in,out] The string that is to have the XML error appended.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    void ToXML(tscrypto::tsCryptoString &appendToXML, bool useAttributes) const;

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

protected:
    tscrypto::tsCryptoString m_description;
    tscrypto::tsCryptoString m_component;
    tscrypto::tsCryptoString m_method;
    int32_t m_number;
};

#endif // !defined(AFX_tsXmlError_H__5BB47447_4058_4300_87A3_BB6528B3407A__INCLUDED_)
