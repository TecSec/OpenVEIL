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

/*! @file tsXmlParser.h
 * @brief This file defines an XML parser that contains extended functionality used by the CKM Runtime
*/

#if !defined(__tsXMLPARSER_H__)
#define __tsXMLPARSER_H__

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "tsXmlParserCallback.h"

/// <summary>An XML parser that uses a callback system to process the parsed data.  This is a SAX style parser.</summary>
class VEILCORE_API tsXmlParser
{
public:
	static void *operator new(std::size_t count) {
		return tscrypto::cryptoNew(count);
	}
	static void *operator new[](std::size_t count) {
		return tscrypto::cryptoNew(count);
	}
	static void operator delete(void *ptr) { tscrypto::cryptoDelete(ptr); }
	static void operator delete[](void *ptr) { tscrypto::cryptoDelete(ptr); }

		/// <summary>Default constructor.</summary>
	tsXmlParser();
	/// <summary>Destructor.</summary>
	~tsXmlParser();

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Parses the specified XML using the callback interface.</summary>
	///
	/// <param name="xml">	   The XML.</param>
	/// <param name="callback">[in] The callback interface.</param>
	/// <param name="Results"> [in,out] The results.</param>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	bool Parse(const tscrypto::tsCryptoStringBase &xml, tsXmlParserCallback *callback, tscrypto::tsCryptoStringBase &Results);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Parses the specified XML using the callback interface.</summary>
	///
	/// <param name="xml">	   The XML.</param>
	/// <param name="callback">[in] The callback interface.</param>
	/// <param name="Results"> [in,out] The results.</param>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	bool Parse(const char *xml, tsXmlParserCallback *callback, tscrypto::tsCryptoStringBase &Results);

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

    static TSXmlParserCallbackResultCodes xml_processInstruction(void* params, const char* name, uint32_t nameLen, TSNAME_VALUE_LIST attributes, const char* contents, uint32_t contentsLen);
    static TSXmlParserCallbackResultCodes xml_startNode(void* params, const char* nodeName, uint32_t nodeNameLen, TSNAME_VALUE_LIST attributes, const char* innerXmlStart, const char* innerXmlEnd, ts_bool singleNode);
    static TSXmlParserCallbackResultCodes xml_endNode(void* params, const char* nodeName, uint32_t nodeNameLen);
    static TSXmlParserCallbackResultCodes xml_comment(void* params, const char* commentStart, const char* commentEnd);
    static TSXmlParserCallbackResultCodes xml_cdata(void* params, const char* cdataStart, const char* cdataEnd);
    static TSXmlParserCallbackResultCodes xml_text(void* params, const char* textStart, const char* textEnd);
    static TSXmlParserCallbackResultCodes xml_whitespace(void* params, const char* whitespaceStart, const char* whitespaceEnd);
    static void xml_reportError(void* params, const char* errorMessage);

    static TSXmlParserCallback gXmlCallbacks;

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Logs an error into the error string.</summary>
	///
	/// <param name="Results">[in,out] The error string.</param>
	/// <param name="number"> The error number.</param>
	/// <param name="value">  The error description.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void LogError(tscrypto::tsCryptoStringBase &Results, int32_t number, const char *value);
protected:

    tscrypto::tsCryptoString m_results;
	tsXmlParserCallback *m_callback;
};

#endif

