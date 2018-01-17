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


#include "stdafx.h"

TSXmlParserCallback tsXmlParser::gXmlCallbacks =
{
    &tsXmlParser::xml_processInstruction,
    &tsXmlParser::xml_startNode,
    &tsXmlParser::xml_endNode,
    &tsXmlParser::xml_comment,
    &tsXmlParser::xml_cdata,
    &tsXmlParser::xml_text,
    &tsXmlParser::xml_whitespace,
    &tsXmlParser::xml_reportError,
};

tsXmlParser::tsXmlParser()
{
}

tsXmlParser::~tsXmlParser()
{
}

//void *tsXmlParser::operator new(size_t bytes)
//{
//    return FrameworkAllocator(bytes);
//}
//
//void tsXmlParser::operator delete(void *ptr)
//{
//    return FrameworkDeallocator(ptr);
//}

bool tsXmlParser::Parse(const tsCryptoStringBase &xml, tsXmlParserCallback *callback, tsCryptoStringBase &Results)
{
    return Parse(xml.c_str(), callback, Results);
}

bool tsXmlParser::Parse(const char *xml, tsXmlParserCallback *callback, tsCryptoStringBase &Results)
{
    bool retVal;

    if (callback == NULL)
        return false;
    m_callback = callback;
    m_results = Results;
    retVal = tsParseXml(xml, &gXmlCallbacks, this);
    Results = m_results;
    return retVal;
}

//bool tsXmlParser::Parse(const char *xml, size_t len, tsXmlParserCallback *callback, tsCryptoString &Results)
//{
//	if ( xml == NULL || callback == NULL )
//		return false;
//	m_xml.assign(xml, len);
//	m_callback = callback;
//	m_attributes.ClearAll();
//	m_nodeLevel = 0;
//	m_position = 0;
//	m_regularNodeCountLevel1 = 0;
//	return Parse(Results) != tsXmlParserCallback::rcAbort;
//}



//
// This routine adds an error message to the Results variable.
//
void tsXmlParser::LogError(tsCryptoStringBase &Results, int32_t number, const char *value)
{
    tsCryptoString tmp;

    if (m_callback == NULL)
    {
        Results += "<Error><NumberAtt>";
        Results.append(number);
        Results += "</NumberAtt><ValueAtt>";
        TSPatchValueForXML(value, tmp);
        Results += tmp;
        Results += "</ValueAtt><MethodAtt>";
        Results += "XMLParser";
        Results += "</MethodAtt><ComponentAtt>";
        Results += "XMLParser";
        Results += "</ComponentAtt></Error>";
    }
    else
        m_callback->AddParseError(value, Results);
}




TSXmlParserCallbackResultCodes tsXmlParser::xml_processInstruction(void* params, const char* name, uint32_t nameLen, TSNAME_VALUE_LIST attributes, const char* contents, uint32_t contentsLen)
{
    tsXmlParser* This = (tsXmlParser*)params;

    if (This == nullptr)
    {
        return tsxpcrcAbort;
    }
    if (This->m_callback != nullptr)
    {
        return (TSXmlParserCallbackResultCodes)This->m_callback->ProcessInstruction(tsCryptoString(contents, contentsLen), This->m_results);
    }
    return tsxpcrcSuccess;
}
TSXmlParserCallbackResultCodes tsXmlParser::xml_startNode(void* params, const char* nodeName, uint32_t nodeNameLen, TSNAME_VALUE_LIST attributes, const char* innerXmlStart, const char* innerXmlEnd, ts_bool singleNode)
{
    tsXmlParser* This = (tsXmlParser*)params;

    if (This == nullptr)
    {
        return tsxpcrcAbort;
    }
    if (This->m_callback != nullptr)
    {
        if (innerXmlEnd == nullptr)
        {
            innerXmlEnd = innerXmlStart;
        }
        TSXmlParserCallbackResultCodes retVal = (TSXmlParserCallbackResultCodes)This->m_callback->StartNode(tsCryptoString(nodeName, nodeNameLen), tsAttributeMap(attributes), tsCryptoString(innerXmlStart, innerXmlEnd - innerXmlStart), singleNode, This->m_results);
        return retVal;
    }
    return tsxpcrcSuccess;
}
TSXmlParserCallbackResultCodes tsXmlParser::xml_endNode(void* params, const char* nodeName, uint32_t nodeNameLen)
{
    tsXmlParser* This = (tsXmlParser*)params;

    if (This == nullptr)
    {
        return tsxpcrcAbort;
    }
    if (This->m_callback != nullptr)
    {
        return (TSXmlParserCallbackResultCodes)This->m_callback->EndNode(tsCryptoString(nodeName, nodeNameLen), This->m_results);
    }
    return tsxpcrcSuccess;
}
TSXmlParserCallbackResultCodes tsXmlParser::xml_comment(void* params, const char* commentStart, const char* commentEnd)
{
    tsXmlParser* This = (tsXmlParser*)params;

    if (This == nullptr)
    {
        return tsxpcrcAbort;
    }
    if (This->m_callback != nullptr)
    {
        if (commentEnd == nullptr)
        {
            commentEnd = commentStart;
        }
        return (TSXmlParserCallbackResultCodes)This->m_callback->Comment(tsCryptoString(commentStart, commentEnd - commentStart), This->m_results);
    }
    return tsxpcrcSuccess;
}
TSXmlParserCallbackResultCodes tsXmlParser::xml_cdata(void* params, const char* cdataStart, const char* cdataEnd)
{
    tsXmlParser* This = (tsXmlParser*)params;

    if (This == nullptr)
    {
        return tsxpcrcAbort;
    }
    if (This->m_callback != nullptr)
    {
        if (cdataEnd == nullptr)
        {
            cdataEnd = cdataStart;
        }
        return (TSXmlParserCallbackResultCodes)This->m_callback->CData(tsCryptoString(cdataStart, cdataEnd - cdataStart), This->m_results);
    }
    return tsxpcrcSuccess;
}
TSXmlParserCallbackResultCodes tsXmlParser::xml_text(void* params, const char* textStart, const char* textEnd)
{
    tsXmlParser* This = (tsXmlParser*)params;

    if (This == nullptr)
    {
        return tsxpcrcAbort;
    }
    if (This->m_callback != nullptr)
    {
        if (textEnd == nullptr)
        {
            textEnd = textStart;
        }
        return (TSXmlParserCallbackResultCodes)This->m_callback->Text(tsCryptoString(textStart, textEnd - textStart), This->m_results);
    }
    return tsxpcrcSuccess;
}
TSXmlParserCallbackResultCodes tsXmlParser::xml_whitespace(void* params, const char* whitespaceStart, const char* whitespaceEnd)
{
    tsXmlParser* This = (tsXmlParser*)params;

    if (This == nullptr)
    {
        return tsxpcrcAbort;
    }
    if (This->m_callback != nullptr)
    {
        if (whitespaceEnd == nullptr)
        {
            whitespaceEnd = whitespaceStart;
        }
        This->m_callback->WhiteSpace(tsCryptoString(whitespaceStart, whitespaceEnd - whitespaceStart), This->m_results);
    }
    return tsxpcrcSuccess;
}
void tsXmlParser::xml_reportError(void* params, const char* errorMessage)
{
    tsXmlParser* This = (tsXmlParser*)params;

    if (This == nullptr)
    {
        return;
    }
    This->LogError(This->m_results, IDS_E_XML_CANT_GENERATE, errorMessage);
}
