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

using namespace tscrypto;

static bool processArmoredLines(tscrypto::tsCryptoStringList lines, TSNamedBinarySectionList& contents)
{
	tscrypto::tsCryptoString name;
	tscrypto::tsCryptoString value;
	//bool processingAttributes = false;
	//bool beginningOfSection = false;
	tscrypto::tsCryptoString attrName, attrValue;
	tsAttributeMap map;
	tscrypto::tsCryptoString txt;
	enum { TextArea, StartOfSection, Attributes, SectionData } state = TextArea;

	for (tscrypto::tsCryptoString& line : *lines)
	{
		txt = line;
		txt.Trim();

		if (TsStrnCmp(txt, "-----", 5) == 0)
		{
			tscrypto::tsCryptoString markerLine(txt);

			// We may have a marker.
			markerLine.Trim(" -"); // Remove the marker prefix and suffix
			if (TsStrniCmp(markerLine, "BEGIN ", 6) == 0 && state == TextArea)
			{
				markerLine.DeleteAt(0, 6); // Remove the BEGIN to get to the Name
				if (value.size() > 0)
				{
					TSNamedBinarySection section;

					section.Contents = value;
					contents->push_back(section);
					value.clear();
				}
				name = markerLine;
				state = StartOfSection;
				map.ClearAll();
				attrName.clear();
				attrValue.clear();
			}
			else if (TsStrniCmp(markerLine, "END ", 4) == 0 && state != TextArea)
			{
				TSNamedBinarySection section;

				markerLine.DeleteAt(0, 4); // Remove the END to get to the Name

				section.Attributes = map;
				section.Name = name;
				section.Contents = value.Base64ToData();
				contents->push_back(section);
				value.clear();
				map.ClearAll();
				name.clear();
				state = TextArea;
				attrName.clear();
				attrValue.clear();
			}
			else
			{
				// Not a valid marker
				value.append(line).append('\n');
			}
		}
		else
		{
			if (state == StartOfSection)
			{
				if (TsStrChr(txt, ':') != nullptr)
				{
					state = Attributes;
				}
				else
					state = SectionData;
			}

			if (state == Attributes)
			{
				if (txt.size() == 0)
				{
					if (attrName.size() != 0)
					{
						map.AddItem(attrName, attrValue);
						attrName.clear();
						attrValue.clear();
					}
					state = SectionData;
				}
				else if (txt[0] == ' ' || txt[0] == '\t')
				{
					attrValue += txt[0];
					// Folded attribute;
					txt.TrimStart(" \t");
					attrValue += txt;
				}
				else
				{
					if (attrName.size() > 0)
						map.AddItem(attrName, attrValue);
					attrName.clear();
					attrValue.clear();
					if (TsStrChr(txt, ':') != nullptr)
					{
						tscrypto::tsCryptoStringList list = txt.split(':', 2);
						attrName = list->at(0);
						if (list->size() > 1)
							attrValue = list->at(1);
					}
				}
			}
			else if (state == SectionData)
			{
				value += txt;
			}
			else
			{
				value.append(line).append('\n');
			}
		}
	}
	if (state != TextArea)
		return false;
	if (value.size() > 0)
	{
		TSNamedBinarySection section;

		section.Contents = value;
		contents->push_back(section);
		value.clear();
	}
	return true;
}
bool xp_ReadArmoredFile(const tscrypto::tsCryptoString& filename, TSNamedBinarySectionList& contents)
{
	// RFC 822 processing
	tscrypto::tsCryptoStringList lines;

	if (!contents)
		contents = CreateTSNamedBinarySectionList();
	else
		contents->clear();

	if (!xp_ReadAllTextLines(filename, lines))
		return false;
	return processArmoredLines(lines, contents);
}

bool xp_WriteArmoredFile(const tscrypto::tsCryptoString& filename, const TSNamedBinarySectionList& contents)
{
	if (!contents)
		return false;

	XP_FILE file = xp_CreateFile(filename, XP_GENERIC_WRITE, XP_FILE_SHARE_READ, nullptr, XP_CREATE_ALWAYS, XP_FILE_ATTRIBUTE_NORMAL, nullptr);

	if (file == XP_FILE_INVALID)
		return false;

	auto cleanup = finally([&file]() {xp_CloseFile(file);});

	for (auto section : *contents)
	{
		tscrypto::tsCryptoString tmp;
		uint32_t count;
		size_t start, end;
		tscrypto::tsCryptoString part;
		tscrypto::tsCryptoString namePart;

		if (section.Name.size() > 0)
		{
			tmp.clear();
			namePart = section.Name;
			namePart.ToUpper();
			tmp.append("-----BEGIN ").append(namePart).append("-----\n");
			if (!xp_WriteFile(file, tmp.rawData(), (uint32_t)tmp.size(), &count, nullptr) || count != (uint32_t)tmp.size())
			{
				return false;
			}

			if (section.Attributes.count() > 0)
			{
				for (size_t i = 0; i < section.Attributes.count(); i++)
				{
					tmp.clear();
					tmp.append(section.Attributes.name(i)).append(": ").append(section.Attributes.item(i)).append('\n');
					// TODO:  Add folding here (CRLF plus whitespace (RFC 822)
					if (!xp_WriteFile(file, tmp.rawData(), (uint32_t)tmp.size(), &count, nullptr) || count != (uint32_t)tmp.size())
					{
						return false;
					}
				}
				// Blank line required here to separate attributes from body
				tmp.clear();
				tmp += "\n";
				if (!xp_WriteFile(file, tmp.rawData(), (uint32_t)tmp.size(), &count, nullptr) || count != (uint32_t)tmp.size())
				{
					return false;
				}
			}

			tmp = section.Contents.ToBase64();
			start = 0;
			end = 0;
			while (end < tmp.size())
			{
				if (tmp.size() - start <= 64)
					end = tmp.size();
				else
					end = start + 64;
				part.assign(&tmp.c_str()[start], end - start);
				start = end;
				part += "\n";
				if (!xp_WriteFile(file, part.rawData(), (uint32_t)part.size(), &count, nullptr) || count != (uint32_t)part.size())
				{
					return false;
				}
			}

			tmp.clear();
			namePart = section.Name;
			namePart.ToUpper();
			tmp.append("-----END ").append(namePart).append("-----\n");
			if (!xp_WriteFile(file, tmp.rawData(), (uint32_t)tmp.size(), &count, nullptr) || count != (uint32_t)tmp.size())
			{
				return false;
			}
		}
		else
		{
			tmp.clear();
			tmp.append(section.Contents.ToUtf8String()).append('\n');
			if (!xp_WriteFile(file, tmp.rawData(), (uint32_t)tmp.size(), &count, nullptr) || count != (uint32_t)tmp.size())
			{
				return false;
			}
		}
	}
	return true;
}

bool xp_ReadArmoredString(const tscrypto::tsCryptoString& input, TSNamedBinarySectionList& contents)
{
	// RFC 822 processing
	tscrypto::tsCryptoStringList lines;

	if (!contents)
		contents = CreateTSNamedBinarySectionList();
	else
		contents->clear();

	if (!xp_StringToTextLines(input, lines))
		return false;
	return processArmoredLines(lines, contents);
}

bool xp_WriteArmoredString(const TSNamedBinarySectionList& contents, tscrypto::tsCryptoString& output)
{
	if (!contents)
		return false;

	output.clear();

	for (auto section : *contents)
	{
		tscrypto::tsCryptoString tmp;
		size_t start, end;
		tscrypto::tsCryptoString part;
		tscrypto::tsCryptoString namePart;

		if (section.Name.size() > 0)
		{
			namePart = section.Name;
			namePart.ToUpper();
			output.append("-----BEGIN ").append(namePart).append("-----\n");

			if (section.Attributes.count() > 0)
			{
				for (size_t i = 0; i < section.Attributes.count(); i++)
				{
					output.append(section.Attributes.name(i)).append(": ").append(section.Attributes.item(i)).append('\n');
					// TODO:  Add folding here (CRLF plus whitespace (RFC 822)
				}
				// Blank line required here to separate attributes from body
				output += "\n";
			}

			tmp = section.Contents.ToBase64();
			start = 0;
			end = 0;
			while (end < tmp.size())
			{
				if (tmp.size() - start <= 64)
					end = tmp.size();
				else
					end = start + 64;
				part.assign(&tmp.c_str()[start], end - start);
				start = end;
				part += '\n';;
				output += part;
			}

			namePart = section.Name;
			namePart.ToUpper();
			output.append("-----END ").append(namePart).append("-----\n");
		}
		else
		{
			output.append(section.Contents.ToUtf8String()).append('\n');
		}
	}

	return true;
}
