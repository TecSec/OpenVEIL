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


#include "stdafx.h"

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
#ifdef HAVE_BSTR
bool tsXmlParser::Parse(const ts_wchar * xml,	tsXmlParserCallback *callback, tscrypto::tsCryptoStringBase &Results)
{
	if ( xml == NULL || callback == NULL )
		return false;
	m_xml = tscrypto::CryptoUtf16(xml).toUtf8();
	m_callback = callback;
	m_attributes.ClearAll();
	m_nodeLevel = 0;
	m_position = 0;
	m_regularNodeCountLevel1 = 0;
	return Parse(Results) != tsXmlParserCallback::rcAbort;
}

bool tsXmlParser::Parse(const ts_wchar * xml, size_t len, tsXmlParserCallback *callback, tscrypto::tsCryptoStringBase &Results)
{
	if ( xml == NULL || callback == NULL )
		return false;
	m_xml = tscrypto::CryptoUtf16(xml, len).toUtf8();
	m_callback = callback;
	m_attributes.ClearAll();
	m_nodeLevel = 0;
	m_position = 0;
	m_regularNodeCountLevel1 = 0;
	return Parse(Results) != tsXmlParserCallback::rcAbort;
}
#endif // HAVE_BSTR

bool tsXmlParser::Parse(const tscrypto::tsCryptoStringBase &xml,	tsXmlParserCallback *callback, tscrypto::tsCryptoStringBase &Results)
{
	if ( callback == NULL )
		return false;
	m_xml = xml;
	m_callback = callback;
	m_attributes.ClearAll();
	m_nodeLevel = 0;
	m_position = 0;
	m_regularNodeCountLevel1 = 0;
	return Parse(Results) != tsXmlParserCallback::rcAbort;
}

bool tsXmlParser::Parse(const char *xml,	tsXmlParserCallback *callback, tscrypto::tsCryptoStringBase &Results)
{
	if ( xml == NULL || callback == NULL )
		return false;
	m_xml = xml;
	m_callback = callback;
	m_attributes.ClearAll();
	m_nodeLevel = 0;
	m_position = 0;
	m_regularNodeCountLevel1 = 0;
	return Parse(Results) != tsXmlParserCallback::rcAbort;
}

bool tsXmlParser::Parse(const char *xml, size_t len, tsXmlParserCallback *callback, tscrypto::tsCryptoStringBase &Results)
{
	if ( xml == NULL || callback == NULL )
		return false;
	m_xml.assign(xml, len);
	m_callback = callback;
	m_attributes.ClearAll();
	m_nodeLevel = 0;
	m_position = 0;
	m_regularNodeCountLevel1 = 0;
	return Parse(Results) != tsXmlParserCallback::rcAbort;
}

//
// Process all the nodes until an error is detected or the callback says to stop or
// the end of XML is reached.
//
tsXmlParserCallback::resultCodes tsXmlParser::Parse(tscrypto::tsCryptoStringBase &Results)
{
	tsXmlParserCallback::resultCodes retVal = tsXmlParserCallback::rcAbort;

	if ( !EatWhitespace(Results)  || m_position >= m_xml.size() )
	{
		if ( m_nodeLevel == 0 )
		{
			LogError(Results, 1, ("Empty XML specified."));
			return tsXmlParserCallback::rcAbort;
		}
		return tsXmlParserCallback::rcSuccess;
	}
	if ( !EatWhitespace(Results) )
	{
		LogError (Results, 1, ("Invalid end of input detected."));
		m_nodeLevel--;
		return tsXmlParserCallback::rcAbort;
	}
	while ( m_position < m_xml.size() &&
		    (retVal = ParseNode(Results)) != tsXmlParserCallback::rcAbort &&
			 retVal != tsXmlParserCallback::rcStopWithSuccess )
	{
		if ( !EatWhitespace(Results) )
		{
			break;
		}
	}
	if ( retVal == tsXmlParserCallback::rcAbort )
	{
		return retVal;
	}
	if ( retVal == tsXmlParserCallback::rcStopWithSuccess )
		return tsXmlParserCallback::rcSuccess;

	if ( m_regularNodeCountLevel1 != 1 )
	{
		LogError(Results, 1, ("Improperly formatted XML."));
		return tsXmlParserCallback::rcAbort;
	}
	if ( m_nodeLevel != 0 )
	{
		LogError(Results, 1, ("Improperly formed XML."));
		return tsXmlParserCallback::rcAbort;
	}
	return tsXmlParserCallback::rcSuccess;
}

//
// Eat all whitespace characters.  Return true unless the end of xml is detected.
//
bool tsXmlParser::EatWhitespace(tscrypto::tsCryptoStringBase &Results)
{
	char c;
    char st[2];
    tscrypto::tsCryptoString WhiteSpace;

	if ( m_position >= m_xml.size() )
		return false;
	while ( m_position < m_xml.size() )
	{
		c = m_xml.at(m_position);
		if ( c == ' ' || c == '\t' || c == '\r' || c == '\n' )
        {
            st[0] = c;
            st[1] = 0;
            WhiteSpace += st;
			m_position++;
        }
		else
			break;
	}
    if ( WhiteSpace.size() > 0 )
        m_callback->WhiteSpace(WhiteSpace.c_str(), Results);
	return true;
}

bool tsXmlParser::EatWhitespaceQuiet(tscrypto::tsCryptoStringBase & /*Results*/)
{
	char c;

	if ( m_position >= m_xml.size() )
		return false;
	while ( m_position < m_xml.size() )
	{
		c = m_xml.at(m_position);
		if ( c == ' ' || c == '\t' || c == '\r' || c == '\n' )
        {
			m_position++;
        }
		else
			break;
	}
	return true;
}

//
// Parse a double quote delimited tscrypto::tsCryptoString out of the xml.
//
bool tsXmlParser::ParseQuotedString(const char **Start, tscrypto::tsCryptoStringBase &Results)
{
	char c;

	if ( Start == NULL )
	{
		LogError (Results, 1, "Invalid argument passed to ParseQuotedString.");
		return false;
	}

	if ( m_position + 1 >= m_xml.size() )
	{
		return false;
	}
	c = m_xml.at(m_position);
	if ( c != '"' )
		return false;

	m_position++;
	*Start = &m_xml.c_str()[m_position];
	while ( m_position < m_xml.size() && m_xml.at(m_position) != '"' )
		m_position++;

	if ( m_position >= m_xml.size() || m_xml.at(m_position) != '"' )
		return false;

	m_xml.at(m_position++) = 0;
	return true;
}

//
// See if the letter is acceptable as the first letter of a node or attribute name.
//
bool tsXmlParser::IsStartingNameChar(char c)
{
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c == '_');
}

//
// See if the letter is acceptable as the second or later letter of a node or attribute name
//
bool tsXmlParser::IsNameChar(char c)
{
	return IsStartingNameChar(c) || (c >= '0' && c <= '9') || (c == '-') || (c == ':') || (c == '.');
}

//
// Parse a node or attribute name out of the xml
//
bool tsXmlParser::ParseName(const char **Start, tscrypto::tsCryptoStringBase &Results)
{
	if ( Start == NULL )
	{
		LogError(Results, 1, "Invalid argument specified in ParseName.");
		return false;
	}
	if ( m_position + 1 >= m_xml.size() )
	{
		return false;
	}
	*Start = &m_xml.c_str()[m_position];
	if ( !IsStartingNameChar(m_xml.at(m_position)) )
		return false;
	do
	{
		m_position++;
	}
	while ( m_position < m_xml.size() && IsNameChar(m_xml.at(m_position)) );
	return true;
}

//
// Parse one node out of the XML.
//
tsXmlParserCallback::resultCodes tsXmlParser::ParseNode(tscrypto::tsCryptoStringBase &Results)
{
	char c;

	//
	// We are already positioned at the beginning of the node.  Get the first character
	// and see what type of node it is.  Then process the node and call the callback.
	//
	c = m_xml.at(m_position);
	if ( c != '<' && m_nodeLevel >= 1 )
	{
		// Must be a text node, therefore get the text
		return ParseTextNode(Results);
	}
	else if ( c == '<' )
	{
		// We have the start of a standard node.
		m_position++;
		c = m_xml.at(m_position);
		if ( m_position + 7 < m_xml.size() &&
			 c == '!' && m_xml.at(m_position+1) == '-' && m_xml.at(m_position+2) == '-' )
		{
			// We have a comment.  Process it.
			m_position += 3;
			return ParseComment(Results);
		}
		else if (m_position + 12 < m_xml.size() &&
			c == '!' && strncmp(&m_xml.c_str()[m_position], "![CDATA[", 8) == 0 )
		{
			// We have a CDATA section.  Process it.
			if ( m_nodeLevel == 0 )
			{
				LogError(Results, 1, "CDATA sections are invalid outside of the top node.");
				return tsXmlParserCallback::rcAbort;
			}
			m_position += 8;
			return ParseCData(Results);
		}
		else if ( m_position + 4 < m_xml.size() && c == '!' )  // added for HTML metadata instructions RDBJ 1-22-03
		{
			// We have a processing instruction.  Process it.
			m_position++;
			return ParseMetadataInstruction(Results);
		}
		else if ( m_position + 4 < m_xml.size() && c == '?' )
		{
			// We have a processing instruction.  Process it.
			m_position++;
			return ParseProcessingInstruction(Results);
		}
		else if ( m_position + 4 < m_xml.size() && c == '/' )
		{
			const char *Name;
			size_t NameEnd;

			// We have an End Node.  Process it.
			m_position++;
			if ( !ParseName(&Name, Results) )
			{
				LogError(Results, 1, "Malformed end node.");
				return tsXmlParserCallback::rcAbort;
			}
			NameEnd = m_position;
			if ( !EatWhitespace(Results) )
			{
				LogError(Results, 1, "Malformed end node.");
				return tsXmlParserCallback::rcAbort;
			}
			if ( m_position >= m_xml.size() )
			{
				LogError(Results, 1, "Malformed end node.");
				return tsXmlParserCallback::rcAbort;
			}
			if ( m_xml.at(m_position) != '>' )
			{
				LogError(Results, 1, "Malformed end node.");
				return tsXmlParserCallback::rcAbort;
			}
			m_position++;
			m_xml.at(NameEnd) = 0;
			m_nodeLevel--;
			return m_callback->EndNode(Name, Results);
		}
		else
		{
			const char *Name = NULL;
			size_t NameEnd;
			tsXmlParserCallback::resultCodes retVal;

			if ( !ParseName(&Name, Results) )
			{
				LogError(Results, 1, "Invalid node name detected.");
				return tsXmlParserCallback::rcAbort;
			}
			NameEnd = m_position;
			if ( !EatWhitespace(Results) )
			{
				LogError(Results, 1, "Malformed XML node detected.");
				return tsXmlParserCallback::rcAbort;
			}
			//
			// Process any and all attributes
			//
			m_attributes.ClearAll();
			while ( (retVal = ParseAttribute(Results)) == tsXmlParserCallback::rcSuccess )
			{
				if ( !EatWhitespace(Results) )
				{
					LogError(Results, 1, "Malformed XML node detected.");
					return tsXmlParserCallback::rcAbort;
				}
			}
			if ( retVal == tsXmlParserCallback::rcAbort )
				return retVal;
			if ( !EatWhitespace(Results) )
			{
				LogError(Results, 1, "Malformed XML node detected.");
				return tsXmlParserCallback::rcAbort;
			}
			c = m_xml.at(m_position);
			if ( c == '>' )
			{
				size_t EndNodePosition;
				size_t EndNodeEnd;
				char c1;

				// Now we need to find the end node, and process this node.
				m_position++;
				if ( !FindEndNode (Name, EndNodePosition, EndNodeEnd, Results) )
				{
					LogError(Results, 1, "Unable to find the end node.");
					return tsXmlParserCallback::rcAbort;
				}
				c1 = m_xml.at(EndNodePosition);
				m_xml.at(EndNodePosition) = 0;
				m_nodeLevel++;
				if ( m_nodeLevel == 1 )
					m_regularNodeCountLevel1++;
				m_xml.at(NameEnd) = 0;
				retVal = m_callback->StartNode(Name,m_attributes, &m_xml.c_str()[m_position], false, Results);
				m_xml.at(EndNodePosition) = c1;
				if ( retVal == tsXmlParserCallback::rcSkipInner )
				{
					m_position = EndNodePosition;
				}
				return retVal;
			}
			else if ( c == '/' && m_position + 1 < m_xml.size() && m_xml.at(m_position+1) == '>' )
			{
				// Now we have a single node and we need to process it.
				m_position += 2;
				m_nodeLevel++;
				if ( m_nodeLevel == 1 )
					m_regularNodeCountLevel1++;
				m_xml.at(NameEnd) = 0;
				retVal = m_callback->StartNode(Name, m_attributes, "", true, Results);
				if ( retVal == tsXmlParserCallback::rcSuccess ||
					 retVal == tsXmlParserCallback::rcSkipInner )
					retVal = m_callback->EndNode(Name, Results);
				m_nodeLevel--;
				return retVal;
			}
			else
			{
				LogError(Results, 1, "Malformed XML node detected.");
				return tsXmlParserCallback::rcAbort;
			}
		}
	}
	else
	{
		LogError(Results, 1, "Invalid character detected.");
		return tsXmlParserCallback::rcAbort;
	}
}

//
// This routine is used to locate the end of the current node.  This is used to get the
// XML that exists between the open and close nodes in question.  We also check to make
// sure that the detected close node is the proper node and is well formed.
//
bool tsXmlParser::FindEndNode(const char *Name, size_t &EndNodePosition, size_t &EndNodeEnd, tscrypto::tsCryptoStringBase &Results)
{
	int32_t nodeLevel = 1;
	size_t posi = m_position;
	const char *p;

	do
	{
		if ( !EatWhitespaceQuiet(Results) )
		{
			m_position = posi;
			return false;
		}
		p = &m_xml.c_str()[m_position];
		if ( strncmp(p, ("<!--"), 4) == 0 )
		{
			// We found a comment, so skip it.
			m_position += 4;  // skip over the start of comment.
			p += 4;
			while ( m_position + 2 < m_xml.size() && strncmp(p, ("-->"), 3) != 0 )
			{
				p++;
				m_position++;
			}
			if ( m_position + 2 >= m_xml.size() || strncmp(p, ("-->"), 3) != 0 )
			{
				m_position = posi;
				return false;
			}
			m_position += 3; // skip the close comment symbol.
		}
		else if ( strncmp(p, ("<![CDATA["), 9) == 0 )
		{
			// We found a CData section, so skip it.
			m_position += 9;  // skip over the start of comment.
			p += 9;
			while ( m_position + 2 < m_xml.size() && strncmp(p, ("]]>"), 3) != 0 )
			{
				p++;
				m_position++;
			}
			if ( m_position + 2 >= m_xml.size() || strncmp(p, ("]]>"), 3) != 0 )
			{
				m_position = posi;
				return false;
			}
			m_position += 3; // skip the close CData symbol.
		}
		else if ( strncmp(p, ("</"), 2) == 0 )
		{
			size_t NameStart;
			size_t NodeStart;

			NodeStart = m_position;
			// We found an end node, so process it.
			m_position += 2;
			p += 2;
			if ( !EatWhitespaceQuiet(Results) )
			{
				m_position = posi;
				return false;
			}
			NameStart = m_position;
			if ( !IsStartingNameChar(*p) )
			{
				m_position = posi;
				return false;
			}
			do
			{
				p++;
				m_position++;
			}
			while (IsNameChar(*p));
			if ( !EatWhitespaceQuiet(Results) )
			{
				m_position = posi;
				return false;
			}
			if ( *p != '>' )
			{
				m_position = posi;
				return false;
			}
			nodeLevel--;
			if ( nodeLevel == 0 )
			{
				// This should be the closing node we are looking for.  Therefore check it.
				if ( strncmp (Name, &m_xml.c_str()[NameStart], m_position - NameStart) != 0 )
				{
					// We have a problem here.  The node found does not have the same name.
					LogError(Results, 1, ("End node has a different name."));
					m_position = posi;
					return false;
				}
				EndNodePosition = NodeStart;
				EndNodeEnd = m_position + 1;
				m_position = posi;
				return true;
			}
		}
		else if ( *p == '<' )
		{
			// We found a regular node, so process it.
			m_position++;
			p++;
			while ( m_position < m_xml.size() &&
					(*p != '/' || m_position == m_xml.size() - 1 || p[1] != '>') &&
					*p != '>' )
			{
				m_position++;
				p++;
			}
			if ( m_position >= m_xml.size() )
			{
				m_position = posi;
				return false;
			}
			if ( *p == '/' && p[1] == '>' )
			{
				// We have a singleton node.
				p += 2;
				m_position += 2;
			}
			else
			{
				p++;
				m_position++;
				nodeLevel++;
			}
		}
		else
		{
			// Must be a text node.
			while ( m_position < m_xml.size() && (*p != '<') )
			{
				p++;
				m_position++;
			}
		}
	}
	while (m_position < m_xml.size());
	LogError(Results, 1, ("End node not found."));
	m_position = posi;
	return false;
}

//
// This routine parses one attribute from the xml.  If successful, the attribute is
// added to m_attributes.
//
tsXmlParserCallback::resultCodes tsXmlParser::ParseAttribute(tscrypto::tsCryptoStringBase &Results)
{
	const char *Name;
	const char *Value;
	tscrypto::tsCryptoString tmp;

	if ( m_position < m_xml.size() &&
		(m_xml.at(m_position) == '/' || m_xml.at(m_position) == '>') )
		return tsXmlParserCallback::rcNotFound;
	if ( !ParseName(&Name, Results) )
	{
		LogError(Results, 1, ("Attribute name missing or invalid."));
		return tsXmlParserCallback::rcAbort;
	}
	if ( m_position >= m_xml.size() )
	{
		LogError(Results, 1, ("Malformed attribute found."));
		return tsXmlParserCallback::rcAbort;
	}
	if ( m_xml.at(m_position) != '=' )
	{
		LogError(Results, 1, ("Equals sign missing in attribute."));
		return tsXmlParserCallback::rcAbort;
	}
	m_xml.at(m_position++) = 0;
	if ( !ParseQuotedString(&Value, Results) )
	{
		LogError (Results, 1, ("Malformed attribute found."));
		return tsXmlParserCallback::rcAbort;
	}
	TSPatchValueFromXML(Value, tmp);	// in xmlhelper.cpp
	m_attributes.AddItem(Name, tmp.c_str());

	return tsXmlParserCallback::rcSuccess;
}

//
// This routine is used to find the end of the detected metadata instruction.  It also
// calls the callback system.
//
tsXmlParserCallback::resultCodes tsXmlParser::ParseMetadataInstruction(tscrypto::tsCryptoStringBase &Results)
{
	size_t start = m_position;

	while ( m_position + 1 < m_xml.size() &&
		    (m_xml.at(m_position) != '>') )
		m_position++;

	if ( m_position >= m_xml.size() || m_xml.at(m_position) != '>' )
		return tsXmlParserCallback::rcAbort;

	m_xml.at(m_position++) = 0;
	return m_callback->ProcessInstruction(&m_xml.c_str()[start], Results);
}

//
// This routine is used to find the end of the detected processing instruction.  It also
// calls the callback system.
//
tsXmlParserCallback::resultCodes tsXmlParser::ParseProcessingInstruction(tscrypto::tsCryptoStringBase &Results)
{
	size_t start = m_position;

	while ( m_position + 1 < m_xml.size() &&
		    (m_xml.at(m_position) != '?' || m_xml.at(m_position + 1) != '>') )
		m_position++;

	if ( m_position >= m_xml.size() || m_xml.at(m_position) != '?' || m_xml.at(m_position + 1) != '>' )
		return tsXmlParserCallback::rcAbort;

	m_xml.at(m_position++) = 0;
	m_position++;
	return m_callback->ProcessInstruction(&m_xml.c_str()[start], Results);
}

//
// This routine is used to find the end of the detected text block.  It also
// calls the callback system.
//
tsXmlParserCallback::resultCodes tsXmlParser::ParseTextNode (tscrypto::tsCryptoStringBase &Results)
{
	size_t start = m_position;
	tsXmlParserCallback::resultCodes retVal;

	while ( m_position < m_xml.size() && m_xml.at(m_position) != '<' )
		m_position++;

	if ( m_position >= m_xml.size() || m_xml.at(m_position) != '<' )
		return tsXmlParserCallback::rcAbort;

	m_xml.at(m_position) = 0;
	retVal = m_callback->Text(&m_xml.c_str()[start], Results);
	m_xml.at(m_position) = '<';
	return retVal;
}

//
// This routine is used to find the end of the detected comment.  It also
// calls the callback system.
//
tsXmlParserCallback::resultCodes tsXmlParser::ParseComment(tscrypto::tsCryptoStringBase &Results)
{
	size_t start = m_position;

	while ( m_position + 2 < m_xml.size() && (m_xml.at(m_position) != '-' ||
			m_xml.at(m_position + 1) != '-' || m_xml.at(m_position + 2) != '>') )
		m_position++;
	if ( m_position >= m_xml.size() || m_xml.at(m_position) != '-' ||
			m_xml.at(m_position + 1) != '-' || m_xml.at(m_position + 2) != '>' )
		return tsXmlParserCallback::rcAbort;

	m_xml.at(m_position++) = 0;
	m_position++;
	m_position++;
	return m_callback->Comment(&m_xml.c_str()[start], Results);
}

//
// This routine is used to find the end of the detected CData section.  It also
// calls the callback system.
//
tsXmlParserCallback::resultCodes tsXmlParser::ParseCData(tscrypto::tsCryptoStringBase &Results)
{
	size_t start = m_position;

	while ( m_position + 2 < m_xml.size() && (m_xml.at(m_position) != ']' ||
			m_xml.at(m_position + 1) != ']' || m_xml.at(m_position + 2) != '>') )
		m_position++;

	if ( m_position >= m_xml.size() || m_xml.at(m_position) != ']' ||
			m_xml.at(m_position + 1) != ']' || m_xml.at(m_position + 2) != '>' )
		return tsXmlParserCallback::rcAbort;

	m_xml.at(m_position++) = 0;
	m_position++;
	m_position++;
	return m_callback->CData(&m_xml.c_str()[start], Results);
}

//
// This routine adds an error message to the Results variable.
//
void tsXmlParser::LogError(tscrypto::tsCryptoStringBase &Results, int32_t number, const char *value)
{
	tscrypto::tsCryptoString tmp;

	if ( m_callback == NULL )
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

