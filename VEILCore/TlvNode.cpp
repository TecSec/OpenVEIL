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

using namespace tscrypto;

TlvNodeCollection CreateTlvNodeCollection()
{
	return CreateContainer<std::shared_ptr<TlvNode>>();
}

std::shared_ptr<TlvNode> TlvNode::Create(std::shared_ptr<TlvDocument> document)
{
	return ::CryptoLocator()->Finish<TlvNode>(new TlvNode(std::weak_ptr<TlvDocument>(document)));
}

std::shared_ptr<TlvNode> TlvNode::Create(std::weak_ptr<TlvDocument> document)
{
	return ::CryptoLocator()->Finish<TlvNode>(new TlvNode(document));
}

std::shared_ptr<TlvNode> TlvNode::Create(std::shared_ptr<TlvDocument> document, int tag, uint8_t type)
{
	return ::CryptoLocator()->Finish<TlvNode>(new TlvNode(std::weak_ptr<TlvDocument>(document), tag, type));
}

std::shared_ptr<TlvNode> TlvNode::Create(std::weak_ptr<TlvDocument> document, int tag, uint8_t type)
{
	return ::CryptoLocator()->Finish<TlvNode>(new TlvNode(document, tag, type));
}

TlvNode::~TlvNode(void)
{
}

TlvNode::TlvNode(std::weak_ptr<TlvDocument> document) :
	m_tag(0),
	m_type(0),
	m_document(document),
	m_forceConstructed(false)
{
	m_children = CreateTlvNodeCollection();
}

TlvNode::TlvNode(std::weak_ptr<TlvDocument> document, int tag, uint8_t type) :
	m_tag(tag),
	m_type(type),
	m_document(document),
	m_forceConstructed(false)
{
	std::shared_ptr<TlvDocument> doc(m_document.lock());

	m_children = CreateTlvNodeCollection();
	m_forceConstructed = ((m_tag == Tlv_Sequence || m_tag == Tlv_Set) && m_type == Type_Universal && !doc->FlatModel() && !doc->CacSimpleTlv());
}

//#ifdef _WIN32
//void *TlvNode::operator new(size_t bytes) { return FrameworkAllocator(bytes); }
//void TlvNode::operator delete(void *ptr) { return FrameworkDeallocator(ptr); }
//#endif // _WIN32
std::weak_ptr<TlvNode> TlvNode::Parent() const
{
	return m_parent;
}

void TlvNode::Parent(std::weak_ptr<TlvNode> parent)
{
	m_parent = parent;
}

std::weak_ptr<TlvDocument> TlvNode::OwnerDocument() const
{
	return m_document;
}

bool TlvNode::IsConstructed() const
{
	std::shared_ptr<TlvDocument> doc(m_document.lock());

	return (ForceConstructed() || !m_children->empty() || (((m_tag == Tlv_Sequence || m_tag == Tlv_Set) && m_type == Type_Universal && !doc->FlatModel() && !doc->CacSimpleTlv()) && m_data.size() > 0)) ? true : false;
}

int TlvNode::Tag() const
{
	return m_tag;
}

TlvNode* TlvNode::Tag(int setTo)
{
	std::shared_ptr<TlvDocument> doc(m_document.lock());

	m_tag = setTo;
	//    m_forceConstructed = ((m_tag == Tlv_Sequence || m_tag == Tlv_Set) && m_type == Type_Universal && !doc->FlatModel() && !doc->CacSimpleTlv());
	return this;
}

int TlvNode::FlatTag() const
{
	return Tag();
}

uint8_t TlvNode::Type() const
{
	return m_type;
}

TlvNode* TlvNode::Type(uint8_t setTo)
{
	if (setTo < 4)
	{
		std::shared_ptr<TlvDocument> doc(m_document.lock());

		m_type = setTo;
		//        m_forceConstructed = ((m_tag == Tlv_Sequence || m_tag == Tlv_Set) && m_type == Type_Universal && !doc->FlatModel() && !doc->CacSimpleTlv());
	}
	else
	{
		// TODO:  Error handling here
	}
	return this;
}

bool TlvNode::ForceConstructed() const
{
	return m_forceConstructed;
}

void TlvNode::ForceConstructed(bool setTo)
{
	m_forceConstructed = setTo;
}

const TlvNodeCollection &TlvNode::Children() const
{
	return m_children;
}

TlvNode* TlvNode::AppendChild(std::shared_ptr<TlvNode> child)
{
	m_data.clear();
	if (!m_children)
		m_children = CreateTlvNodeCollection();
	m_children->push_back(child);
	child->Parent(std::dynamic_pointer_cast<TlvNode>(_me.lock()));
	return this;
}

void TlvNode::RemoveChild(std::shared_ptr<TlvNode> child)
{
	m_children->erase(std::remove_if(m_children->begin(), m_children->end(), [&child](std::shared_ptr<TlvNode>& node)->bool { return child.get() == node.get(); }), m_children->end());
}

tsCryptoData TlvNode::InnerData() const
{
	tsCryptoData data;

	if (!m_children->empty())
	{
		for (auto child : *m_children)
		{
			data += child->OuterData();
		}
		return data;
	}
	else
	{
		return m_data;
	}
}

int64_t TlvNode::InnerDataAsNumber() const
{
	int64_t tmp = 0;

	if (IsConstructed())
		return 0;

	for (size_t i = 0; i < m_data.size(); i++)
	{
		tmp = (tmp << 8) | (m_data[i] & 0xff);
	}
	return tmp;
}

TlvNode * TlvNode::InnerData(const tsCryptoData &setTo)
{
	m_data = setTo;
	return this;
}

TlvNode * TlvNode::InnerData(uint8_t setTo)
{
	m_data = setTo;
	return this;
}

TlvNode * TlvNode::InnerData(short setTo)
{
	m_data = (uint8_t)(setTo >> 8);
	m_data += (uint8_t)(setTo);

	while (m_data.size() > 1 && m_data[0] == 0)
		m_data.erase(0, 1);

	if (m_data.size() > 0 && (m_data[0] & 0x80) != 0)
		m_data.insert(0, (uint8_t)0);
	return this;
}

TlvNode * TlvNode::InnerData(int setTo)
{
	m_data = (uint8_t)(setTo >> 24);
	m_data += (uint8_t)(setTo >> 16);
	m_data += (uint8_t)(setTo >> 8);
	m_data += (uint8_t)(setTo);

	while (m_data.size() > 1 && m_data[0] == 0)
		m_data.erase(0, 1);

	if (m_data.size() > 0 && (m_data[0] & 0x80) != 0)
		m_data.insert(0, (uint8_t)0);
	return this;
}

TlvNode * TlvNode::InnerData(int64_t setTo)
{
	m_data = (uint8_t)(setTo >> 56);
	m_data += (uint8_t)(setTo >> 48);
	m_data += (uint8_t)(setTo >> 40);
	m_data += (uint8_t)(setTo >> 32);
	m_data = (uint8_t)(setTo >> 24);
	m_data += (uint8_t)(setTo >> 16);
	m_data += (uint8_t)(setTo >> 8);
	m_data += (uint8_t)(setTo);

	while (m_data.size() > 1 && m_data[0] == 0)
		m_data.erase(0, 1);

	if (m_data.size() > 0 && (m_data[0] & 0x80) != 0)
		m_data.insert(0, (uint8_t)0);
	return this;
}

TlvNode * TlvNode::InnerDataAsNumber(uint8_t setTo)
{
	m_data = setTo;
	if (m_data[0] & 0x80)
		m_data.insert(0, (uint8_t)0);
	return this;
}

TlvNode * TlvNode::InnerDataAsNumber(int16_t setTo)
{
	m_data = (uint8_t)(setTo >> 8);
	m_data += (uint8_t)(setTo);

	while (m_data.size() > 1 && m_data[0] == 0)
		m_data.erase(0, 1);
	return this;
}

TlvNode * TlvNode::InnerDataAsNumber(uint16_t setTo)
{
	m_data = (uint8_t)(setTo >> 8);
	m_data += (uint8_t)(setTo);

	while (m_data.size() > 1 && m_data[0] == 0)
		m_data.erase(0, 1);

	if (m_data.size() > 0 && (m_data[0] & 0x80) != 0)
		m_data.insert(0, (uint8_t)0);

	return this;
}

TlvNode * TlvNode::InnerDataAsNumber(int32_t setTo)
{
	m_data = (uint8_t)(setTo >> 24);
	m_data += (uint8_t)(setTo >> 16);
	m_data += (uint8_t)(setTo >> 8);
	m_data += (uint8_t)(setTo);

	while (m_data.size() > 1 && m_data[0] == 0)
		m_data.erase(0, 1);

	return this;
}

TlvNode * TlvNode::InnerDataAsNumber(uint32_t setTo)
{
	m_data = (uint8_t)(setTo >> 24);
	m_data += (uint8_t)(setTo >> 16);
	m_data += (uint8_t)(setTo >> 8);
	m_data += (uint8_t)(setTo);

	while (m_data.size() > 1 && m_data[0] == 0)
		m_data.erase(0, 1);

	if (m_data.size() > 0 && (m_data[0] & 0x80) != 0)
		m_data.insert(0, (uint8_t)0);

	return this;
}

TlvNode * TlvNode::InnerDataAsNumber(int64_t setTo)
{
	m_data = (uint8_t)(setTo >> 56);
	m_data += (uint8_t)(setTo >> 48);
	m_data += (uint8_t)(setTo >> 40);
	m_data += (uint8_t)(setTo >> 32);
	m_data += (uint8_t)(setTo >> 24);
	m_data += (uint8_t)(setTo >> 16);
	m_data += (uint8_t)(setTo >> 8);
	m_data += (uint8_t)(setTo);

	while (m_data.size() > 1 && m_data[0] == 0)
		m_data.erase(0, 1);

	return this;
}

TlvNode * TlvNode::InnerDataAsNumber(uint64_t setTo)
{
	m_data = (uint8_t)(setTo >> 56);
	m_data += (uint8_t)(setTo >> 48);
	m_data += (uint8_t)(setTo >> 40);
	m_data += (uint8_t)(setTo >> 32);
	m_data = (uint8_t)(setTo >> 24);
	m_data += (uint8_t)(setTo >> 16);
	m_data += (uint8_t)(setTo >> 8);
	m_data += (uint8_t)(setTo);

	while (m_data.size() > 1 && m_data[0] == 0)
		m_data.erase(0, 1);

	if (m_data.size() > 0 && (m_data[0] & 0x80) != 0)
		m_data.insert(0, (uint8_t)0);

	return this;
}

tsCryptoString TlvNode::InnerString() const
{
	if (!m_children->empty())
	{
		// TODO:  Error handling here
		//throw new TlvParserException("This node is constructed.  Getting of InnerTSString is not allowed.");
		return ("");
	}
	// TODO:  Implement WIDE Char support here
	//else if ( Tag() == 0x1E && Type() == 0 )
	//    return FastBSTR(m_data);
	else
		return m_data.ToUtf8String();
}

TlvNode *TlvNode::InnerString(const tsCryptoStringBase &setTo)
{
	InnerData(tsCryptoData(setTo, tsCryptoData::ASCII));
	return this;
}

tsCryptoData TlvNode::OuterData() const
{
	tsCryptoData data;

	PutTagIntoBuffer(data);
	PutLengthIntoBuffer(data);

	std::shared_ptr<TlvDocument> doc(m_document.lock());

	if (!m_children->empty() && !!doc && !doc->FlatModel())
	{
		for (auto child : *m_children)
		{
			data += child->OuterData();
		}
	}
	else
	{
		data += m_data;
	}
	return data;
}

size_t TlvNode::OuterData(const tsCryptoData &setTo)
{
	size_t tlLen;
	int tag = 0;
	bool constructed = false;
    uint8_t type = 0;
	size_t length = 0;
	uint32_t startOffset = 0;
	size_t offset = 0;
	std::shared_ptr<TlvDocument> doc(m_document.lock());
	std::shared_ptr<TlvNode> Me(std::dynamic_pointer_cast<TlvNode>(_me.lock()));

	if (!m_children->empty())
		m_children->clear();

	if (!doc)
		return 0;

	tlLen = ExtractTagAndLength(setTo, offset, doc->FlatModel(), doc->CacSimpleTlv(), tag, constructed, type, length);

	if (tlLen <= 0 || offset + tlLen + length < offset || offset + tlLen + length > setTo.size())
	{
		// TODO:  Error handling here
		//throw new TlvParserException("Invalid data passed to FromBytes");
		return 0;
	}
	Tag(tag);
	Type(type);
	if (constructed && !doc->FlatModel())
	{
		offset += tlLen;
		while (offset < length + tlLen + startOffset)
		{
			size_t innertlLen;
			int innertag = 0;
			bool innerconstructed = false;
            uint8_t innertype = 0;
			size_t innerlength = 0;

			innertlLen = ExtractTagAndLength(setTo, offset, doc->FlatModel(), doc->CacSimpleTlv(), innertag, innerconstructed, innertype, innerlength);
			if (innertlLen == 0 || offset + innerlength + innertlLen > setTo.size())
			{
				// TODO:  Error handling here
				//throw new TlvParserException("Invalid data passed to FromBytes");
				return 0;
			}
			std::shared_ptr<TlvNode> node = TlvNode::Create(m_document, innertag, innertype);
			node->OuterData(tsCryptoData(&setTo.c_str()[offset], innerlength + innertlLen));
			offset += innerlength + innertlLen;
			m_children->push_back(node);
			node->Parent(Me);
		}
		if (offset > length + tlLen + startOffset)
		{
			// TODO:  Error handling here
			//throw new TlvParserException("Invalid data detected");
			return 0;
		}
	}
	else
	{
		m_data.assign(&setTo.c_str()[offset + tlLen], length);
		offset += tlLen;
		offset += length;
	}
	return tlLen + length;
}

size_t TlvNode::InnerTlv(const tsCryptoData& setTo)
{
	size_t tlLen;
	size_t length = 0;
	uint32_t startOffset = 0;
	size_t offset = 0;
	std::shared_ptr<TlvDocument> doc(m_document.lock());
	std::shared_ptr<TlvNode> Me(std::dynamic_pointer_cast<TlvNode>(_me.lock()));

	if (!m_children->empty())
		m_children->clear();
	this->m_data.clear();

	tlLen = 0;
	length = setTo.size();

	if (!doc->FlatModel())
	{
		offset += tlLen;
		while (offset < length + tlLen + startOffset)
		{
			size_t innertlLen;
			int innertag = 0;
			bool innerconstructed = false;
            uint8_t innertype = 0;
			size_t innerlength = 0;

			innertlLen = ExtractTagAndLength(setTo, offset, doc->FlatModel(), doc->CacSimpleTlv(), innertag, innerconstructed, innertype, innerlength);
			if (innertlLen == 0 || offset + innerlength + innertlLen > setTo.size())
			{
				// TODO:  Error handling here
				//throw new TlvParserException("Invalid data passed to FromBytes");
				return 0;
			}
			std::shared_ptr<TlvNode> node = TlvNode::Create(m_document, innertag, innertype);
			node->OuterData(tsCryptoData(&setTo.c_str()[offset], innerlength + innertlLen));
			offset += innerlength + innertlLen;
			m_children->push_back(node);
			node->Parent(Me);
		}
		if (offset > length + tlLen + startOffset)
		{
			// TODO:  Error handling here
			//throw new TlvParserException("Invalid data detected");
			return 0;
		}
	}
	else
	{
		m_data.assign(&setTo.c_str()[offset + tlLen], length);
		offset += tlLen;
		offset += length;
	}
	return tlLen + length;
}

tsCryptoData TlvNode::InnerTlv() const
{
	tsCryptoData data;
	std::shared_ptr<TlvDocument> doc(m_document.lock());

	if (!m_children->empty() && !doc->FlatModel())
	{
		for (auto child : *m_children)
		{
			data += child->OuterData();
		}
	}
	return data;
}

size_t TlvNode::DataSize() const
{
	size_t size = ContainedDataSize();
	std::shared_ptr<TlvDocument> doc(m_document.lock());

	size += ComputeLengthSize(size, doc->CacSimpleTlv());
	size += ComputeTagSize();
	return size;
}

size_t TlvNode::ContainedDataSize() const
{
	size_t size = 0;

	if (!m_children->empty())
	{
		for (auto child : *m_children)
		{
			size = size + child->DataSize();
		}
	}
	else
	{
		size = m_data.size();
	}
	return size;
}

int TlvNode::ComputeTagSize() const
{
	std::shared_ptr<TlvDocument> doc(m_document.lock());

	if (!doc)
		return 0;

	if (doc->FlatModel())
	{
		return 1;
	}
	if (Tag() > 0xfe00000 || Tag() < 0)
		return 6;
	else if (Tag() > 0x1fc000)
		return 5;
	else if (Tag() > 0x3f80)
		return 4;
	else if (Tag() > 0x7f)
		return 3;
	else if (Tag() > 0x1F)
		return 2;
	else
		return 1;
}

size_t TlvNode::ComputeLengthSize(size_t dataLength, bool simpleTlv)
{
	if (simpleTlv)
	{
		if (dataLength > 0xFE)
		{
			return 3;
		}
		else
		{
			return 1;
		}
	}

	if (dataLength > 0xffffff)
		return 5;
	if (dataLength > 0xffff)
		return 4;
	if (dataLength > 0xff)
		return 3;
	if (dataLength > 0x7f)
		return 2;
	return 1;
}

size_t TlvNode::ExtractTagAndLength(const tsCryptoData &buffer, size_t offset, bool flatTag, bool simpleLength, int &tag,
	bool &constructed, uint8_t &type, size_t &length)
{
	size_t curByte = offset;
	size_t size;
    uint8_t firstTag;
    uint8_t firstLen;

	size = buffer.size();
	type = 0;
	constructed = false;

	if (curByte >= size)
		return 0;

	firstTag = buffer[curByte];
	if (flatTag)
	{
		tag = firstTag;
		curByte++;
	}
	else
	{
		constructed = ((firstTag & 0x20) != 0) ? true : false;
		type = (uint8_t)(firstTag >> 6);
		firstTag = (uint8_t)(firstTag & 0x1f);

		tag = 0;
		if (firstTag > 30)
		{
			curByte++;
			if (curByte < size)
			{
				do
				{
					firstTag = buffer[curByte++];
					if ((firstTag & 0x80) == 0)
					{
						tag <<= 7;
						tag |= firstTag;
					}
					else
					{
						tag <<= 7;
						tag |= (firstTag & 0x7f);
					}
				} while ((firstTag & 0x80) != 0 && curByte < size);
				if (curByte >= size && (firstTag & 0x80) != 0)
					return 0;
			}
			else
				return 0;
		}
		else
		{
			tag = firstTag;
			curByte++;
		}
	}

	length = 0;
	if (curByte >= size)
		return 0;

	firstLen = buffer[curByte++];
	if (simpleLength)
	{
		if (firstLen == 255)
		{
			if (curByte + 2 > size)
				return 0;

			length = buffer[curByte++];
			length += (((size_t)buffer[curByte++]) << 8);
		}
		else
		{
			length = firstLen;
		}
	}
	else
	{
		if ((firstLen & 0x80) != 0)
		{
			if (curByte + (firstLen & 0x7f) > size)
				return 0;

			for (int32_t i = 0; i < (firstLen & 0x7f); i++)
			{
				length = (length << 8) | buffer[curByte++];
			}
		}
		else
		{
			length = firstLen;
		}
	}
	return curByte - offset;
}

void TlvNode::PutTagIntoBuffer(tsCryptoData &buffer) const
{
	int tagSize = ComputeTagSize();
	int i;
	int myTag;
	bool first = true;
	std::shared_ptr<TlvDocument> doc(m_document.lock());

	if (tagSize == 1)
	{
		if (doc->FlatModel())
			buffer += (uint8_t)(Tag());
		else
			buffer += (uint8_t)(Tag() + (Type() << 6) + (IsConstructed() ? 0x20 : 0x00));
		return;
	}
	if (tagSize > 1)
		buffer += (uint8_t)(0x1f + (Type() << 6) + (IsConstructed() ? 0x20 : 0x00));
	i = tagSize - 1;
	int offset = (int)buffer.size();
	buffer.resize(buffer.size() + i);
	myTag = Tag();
	while (i > 0)
	{
		if (first)
			buffer[offset + i - 1] = (uint8_t)(myTag & 0x7f);
		else
			buffer[offset + i - 1] = (uint8_t)((myTag & 0x7f) | 0x80);
		first = false;
		myTag = (myTag >> 7) & 0x1ffffff;
		i--;
	}
	return;
}

void TlvNode::PutLengthIntoBuffer(tsCryptoData &buffer) const
{
	size_t myData = ContainedDataSize();
	std::shared_ptr<TlvDocument> doc(m_document.lock());
	if (!doc)
		return;

	size_t dataSize = ComputeLengthSize(myData, doc->CacSimpleTlv());
	ptrdiff_t i;

	if (dataSize == 1)
	{
		buffer += (uint8_t)(myData);
		return;
	}

	if (doc->CacSimpleTlv())
	{
		buffer += (uint8_t)(myData & 0xff);
		myData >>= 8;
		buffer += (uint8_t)(myData & 0xff);
		return;
	}

	dataSize--;
	buffer += (uint8_t)(0x80 + dataSize);
	i = dataSize;
	int offset = (int)buffer.size();
	buffer.resize(offset + i);
	while (i > 0)
	{
		buffer[offset + i - 1] = (uint8_t)(myData & 0xff);
		myData = (myData >> 8) & 0xfffffff;
		i--;
	}
	return;
}

void TlvNode::Search(TlvNodeCollection &list, int tag, int type)
{
	if (!list)
		list = CreateTlvNodeCollection();

	if (Tag() == tag && Type() == type)
	{
		list->push_back(std::dynamic_pointer_cast<TlvNode>(_me.lock()));
	}
	for (auto child : *m_children)
	{
		child->Search(list, tag, type);
	}
}

std::shared_ptr<TlvNode> TlvNode::FindFirstTag(int tag, int type)
{
	std::shared_ptr<TlvDocument> doc(m_document.lock());

	if (doc->FlatModel())
	{
		auto it = std::find_if(m_children->begin(), m_children->end(), [tag](std::shared_ptr<TlvNode>& child) -> bool { return child->FlatTag() == tag; });
		if (it != m_children->end())
			return *it;
	}
	else
	{
		auto it = std::find_if(m_children->begin(), m_children->end(), [tag, type](std::shared_ptr<TlvNode>& child) -> bool { return child->Tag() == tag && child->Type() == type; });
		if (it != m_children->end())
			return *it;
	}
	return nullptr;
}
std::shared_ptr<TlvNode> TlvNode::FindFirstTag(int tag, int type) const
{
	std::shared_ptr<TlvDocument> doc(m_document.lock());

	if (doc->FlatModel())
	{
		auto it = std::find_if(m_children->begin(), m_children->end(), [tag](const std::shared_ptr<TlvNode>& child) -> bool { return child->FlatTag() == tag; });
		if (it != m_children->end())
			return *it;
	}
	else
	{
		auto it = std::find_if(m_children->begin(), m_children->end(), [tag, type](const std::shared_ptr<TlvNode>& child) -> bool { return child->Tag() == tag && child->Type() == type; });
		if (it != m_children->end())
			return *it;
	}
	return nullptr;
}

void TlvNode::SortByTag()
{
	std::shared_ptr<TlvDocument> doc(m_document.lock());

	if (doc->FlatModel())
	{
		std::sort(m_children->begin(), m_children->end(), [](std::shared_ptr<TlvNode> left, std::shared_ptr<TlvNode> right)->bool { return left->FlatTag() < right->FlatTag(); });
	}
	else
	{
		std::sort(m_children->begin(), m_children->end(), [](std::shared_ptr<TlvNode> left, std::shared_ptr<TlvNode> right)->bool { return left->Type() < right->Type() || (left->Type() == right->Type() && left->Tag() < right->Tag()); });
	}
}

size_t TlvNode::ChildCount() const
{
	return m_children->size();
}

std::shared_ptr<TlvNode> TlvNode::ChildAt(size_t index) const
{
	if (index >= ChildCount())
		return nullptr;

	auto it = m_children->begin();
	std::advance(it, index);
	return *it;
}

std::shared_ptr<TlvNode> TlvNode::ChildAt(size_t index)
{
	if (index >= ChildCount())
		return NULL;

	auto it = m_children->begin();
	std::advance(it, index);
	return *it;
}

bool TlvNode::IsOIDNode() const
{
	if (Tag() != (int)TlvNode::Tlv_OID || Type() != TlvNode::Type_Universal)
		return false;
	return true;
}
bool TlvNode::IsOIDNode(const tsCryptoData &oid) const
{
	if (!IsOIDNode())
		return false;
	tsCryptoData tmp = InnerData();
	return tmp == oid;
}
bool TlvNode::IsSequence() const
{
	if (Tag() != (int)TlvNode::Tlv_Sequence || Type() != TlvNode::Type_Universal)
		return false;
	return true;
}
bool TlvNode::IsSet() const
{
	if (Tag() != (int)TlvNode::Tlv_Set || Type() != TlvNode::Type_Universal)
		return false;
	return true;
}
bool TlvNode::IsString() const
{
	if (Type() != TlvNode::Type_Universal)
		return false;
	switch (Tag())
	{
	case (int)TlvNode::Tlv_UTF8String:
	case (int)TlvNode::Tlv_NumericString:
	case (int)TlvNode::Tlv_PrintableString:
	case (int)TlvNode::Tlv_T61String:
	case (int)TlvNode::Tlv_VideoTexString:
	case (int)TlvNode::Tlv_IA5String:
	case (int)TlvNode::Tlv_GraphicString:
	case (int)TlvNode::Tlv_VisibleString:
	case (int)TlvNode::Tlv_GeneralString:
	case (int)TlvNode::Tlv_UniversalString:
	case (int)TlvNode::Tlv_BmpString:
		return true;
	default:
		return false;
	}
}
bool TlvNode::IsBoolean() const
{
	if (Tag() != (int)TlvNode::Tlv_Boolean || Type() != TlvNode::Type_Universal)
		return false;
	return true;
}
bool TlvNode::IsNumber() const
{
	if (Type() != TlvNode::Type_Universal)
		return false;
	switch (Tag())
	{
	case (int)TlvNode::Tlv_Number:
	case (int)TlvNode::Tlv_Enumerated:
		return true;
	default:
		return false;
	}
}
bool TlvNode::IsNumber(int64_t value) const
{
	if (!IsNumber())
		return false;

	return InnerDataAsNumber() == value;
}
bool TlvNode::IsDate() const
{
	if (Type() != TlvNode::Type_Universal)
		return false;
	switch (Tag())
	{
	case (int)TlvNode::Tlv_UTCTime:
	case (int)TlvNode::Tlv_GeneralizedTime:
		return true;
	default:
		return false;
	}
}
bool TlvNode::IsNull() const
{
	if (Type() != TlvNode::Type_Universal)
		return false;
	switch (Tag())
	{
	case (int)TlvNode::Tlv_NULL:
		return true;
	default:
		return false;
	}
}
bool TlvNode::IsOctet() const
{
	if (Type() != TlvNode::Type_Universal)
		return false;
	switch (Tag())
	{
	case (int)TlvNode::Tlv_Octet:
		return true;
	default:
		return false;
	}
}

tsCryptoDate TlvNode::InnerDataAsDateTime() const
{
	if (!IsDate())
		return tsCryptoDate();

	tsCryptoDate dt;
	tsCryptoString date = InnerString();

	if (Tag() == (int)TlvNode::Tlv_UTCTime)
	{
		if (date.size() != 13 || date[12] != 'Z')
			return tsCryptoDate();
		if (tsStrToInt(date.substring(0, 2).c_str()) < 50)
			date.prepend("20");
		else
			date.prepend("19");
	}
	dt.SetDateTimeFromZulu(date);
	return dt;
}
