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

/*! @file tsXmlParserCallback.h
 * @brief This file defines the callback interface used by the SAX style XML Parser tsXmlParser.
*/

#if !defined(__tsXMLPARSERCALLBACK_H__)
#define __tsXMLPARSERCALLBACK_H__

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "tsXmlError.h"

#ifndef PURE
#define PURE = 0
#endif

/// <summary>Defines the callback interface that the XML parser uses to notify the user of the contents of the XML being parsed.</summary>
class VEILCORE_API tsXmlParserCallback
{
public:
    /// <summary>Default constructor.</summary>
    tsXmlParserCallback() {}
    /// <summary>Destructor.</summary>
    virtual ~tsXmlParserCallback() {}

    /// <summary>Defines the parser error codes.</summary>
    typedef enum {
		rcSuccess,			///< Success, continue processing
		rcSkipInner,		///< Success but do not process the inner XML
		rcStopWithSuccess,	///< Stop processing but report success
		rcAbort,			///< Failure, stop processing
		rcNotFound			///< Item not found
	} resultCodes;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Called by the parser when a processing instruction has been found.</summary>
    ///
    /// <param name="contents">The contents of the processing instruction.</param>
    /// <param name="Results"> [in,out] The error results.</param>
    ///
    /// <returns>The parser error code for this tag.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual resultCodes ProcessInstruction (const tscrypto::tsCryptoStringBase &contents, tscrypto::tsCryptoStringBase &Results) PURE;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Called by the parser when a start node has been detected.</summary>
    ///
    /// <param name="NodeName">  Name of the node.</param>
    /// <param name="attributes">[in,out] The attributes for the node.</param>
    /// <param name="InnerXML">  The inner XML.</param>
    /// <param name="SingleNode">true if this node has no contents or end node (single node).</param>
    /// <param name="Results">   [in,out] The error results.</param>
    ///
    /// <returns>The parser error code for this tag.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual resultCodes StartNode (const tscrypto::tsCryptoStringBase &NodeName, const tsAttributeMap &attributes, const tscrypto::tsCryptoStringBase &InnerXML, bool SingleNode, tscrypto::tsCryptoStringBase &Results) PURE;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Called by the parser when an end node has been detected.</summary>
    ///
    /// <param name="NodeName">Name of the node.</param>
    /// <param name="Results"> [in,out] The error results.</param>
    ///
    /// <returns>The parser error code for this tag.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual resultCodes EndNode (const tscrypto::tsCryptoStringBase &NodeName, tscrypto::tsCryptoStringBase &Results) PURE;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Called by the parser when a comment has been detected.</summary>
    ///
    /// <param name="Contents">The contents of the comment.</param>
    /// <param name="Results"> [in,out] The error results.</param>
    ///
    /// <returns>The parser error code for this tag.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual resultCodes Comment (const tscrypto::tsCryptoStringBase &Contents, tscrypto::tsCryptoStringBase &Results) PURE;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Called by the parser when a CDATA section has been detected</summary>
    ///
    /// <param name="Contents">The CDATA contents.</param>
    /// <param name="Results"> [in,out] The error results.</param>
    ///
    /// <returns>The parser error code for this tag.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual resultCodes CData (const tscrypto::tsCryptoStringBase &Contents, tscrypto::tsCryptoStringBase &Results) PURE;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Called by the parser when node text is detected.</summary>
    ///
    /// <param name="Contents">The node text.</param>
    /// <param name="Results"> [in,out] The error results.</param>
    ///
    /// <returns>The parser error code for this tag.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual resultCodes Text (const tscrypto::tsCryptoStringBase &Contents, tscrypto::tsCryptoStringBase &Results) PURE;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Adds a parse error to 'Results'.</summary>
    ///
    /// <param name="ErrorStr">The error string.</param>
    /// <param name="Results"> [in,out] The error results.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual void AddParseError (const tscrypto::tsCryptoStringBase &ErrorStr, tscrypto::tsCryptoStringBase &Results) PURE;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Called by the parser when whitespace has bee detected.</summary>
    ///
    /// <param name="Whitespace">The whitespace detected by the parser/.</param>
    /// <param name="Results">   [in,out] The error results.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual void WhiteSpace (const tscrypto::tsCryptoStringBase &Whitespace, tscrypto::tsCryptoStringBase &Results) {UNREFERENCED_PARAMETER(Whitespace); UNREFERENCED_PARAMETER(Results);};
};

#endif

