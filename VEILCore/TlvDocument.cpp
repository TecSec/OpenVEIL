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

std::shared_ptr<TlvDocument> TlvDocument::Create()
{
	std::shared_ptr<TlvDocument> doc = ::CryptoLocator()->Finish<TlvDocument>(new TlvDocument);
	if (!doc)
		return nullptr;
	doc->_ThisDoc = doc;
	doc->m_document = TlvNode::Create(doc, 0, 0);
	return doc;
}

TlvDocument::TlvDocument(void) :
    m_flatModel(false),
    m_cacSimpleTlv(false),
    m_fakeTopNode(false)
{
}

TlvDocument::~TlvDocument(void)
{
	m_document.reset();
}
//#ifdef _WIN32
//void *TlvDocument::operator new(size_t bytes) { return FrameworkAllocator(bytes); }
//void TlvDocument::operator delete(void *ptr) { return FrameworkDeallocator(ptr); }
//#endif // _WIN32
bool TlvDocument::FlatModel() const
{
    return m_flatModel;
}

void TlvDocument::FlatModel(bool setTo)
{
    m_flatModel = setTo;
    m_cacSimpleTlv = false;
}

bool TlvDocument::CacSimpleTlv() const
{
    return m_cacSimpleTlv;
}

void TlvDocument::CacSimpleTlv(bool setTo)
{
    m_cacSimpleTlv = setTo;
    if ( m_cacSimpleTlv )
        m_flatModel = true;
}

void TlvDocument::Clear()
{
    m_fakeTopNode = false;
	m_document.reset();
	m_document = TlvNode::Create(_ThisDoc, 0, 0);
}

bool TlvDocument::LoadTlv(const tsCryptoData &buff)
{
    tsCryptoData buffer(buff);
    bool secondRound = true;
    bool firstRound = true;
    size_t datalen = 0;

    Clear();
    while ( buffer.size() > 1 )
    {
        if ( firstRound )
        {
        }
        else if ( secondRound )
        {
			std::shared_ptr<TlvNode> node1 = TlvNode::Create(_ThisDoc, 0x10, 0x00);
            node1->AppendChild(m_document);
            m_document = node1;
            secondRound = false;
            m_fakeTopNode = true;
        }
		std::shared_ptr<TlvNode> node = TlvNode::Create(_ThisDoc);
        datalen = node->OuterData(buffer);
        if ( datalen == 0 )
            return false;
        buffer.erase(0, datalen);
        if ( firstRound )
        {
            firstRound = !firstRound;
            m_document.reset();
            m_document = node;
        }
        else
            m_document->AppendChild(node);
    }
    return true;
}

bool TlvDocument::hasFakeTopNode() const
{
    return m_fakeTopNode;
}

tsCryptoData TlvDocument::SaveTlv() const
{
    if ( m_fakeTopNode )
    {
        return m_document->InnerData();
    }
    else
    {
        return m_document->OuterData();
    }
}

std::shared_ptr<TlvNode> TlvDocument::CreateTlvNode (int tag, uint8_t type)
{
	return TlvNode::Create(_ThisDoc, tag, type);
}

std::shared_ptr<TlvNode> TlvDocument::CreateOIDNode(const tsCryptoData &oid)
{
    std::shared_ptr<TlvNode> node = CreateTlvNode(6, 0);

    node->InnerData (oid);
    return node;
}

std::shared_ptr<TlvNode> TlvDocument::CreateBoolean(bool setTo)
{
    std::shared_ptr<TlvNode> node = CreateTlvNode(TlvNode::Tlv_Boolean, TlvNode::Type_Universal);

    node->InnerData (tsCryptoData((uint8_t)(setTo ? 0xff : 0)));
    return node;
}

std::shared_ptr<TlvNode> TlvDocument::CreateOctetString(const tsCryptoData &data)
{
    std::shared_ptr<TlvNode> node = CreateTlvNode(4, 0);

    node->InnerData (data);
    return node;
}

std::shared_ptr<TlvNode> TlvDocument::CreateSequence()
{
    return CreateTlvNode(0x10, 0);
}

std::shared_ptr<TlvNode> TlvDocument::CreateSet()
{
    return CreateTlvNode(0x11, 0);
}

std::shared_ptr<TlvNode> TlvDocument::CreateApplicationNode(int tag)
{
    return CreateTlvNode(tag, 1);
}

std::shared_ptr<TlvNode> TlvDocument::CreateContextNode(int tag)
{
    return CreateTlvNode(tag, 2);
}

std::shared_ptr<TlvNode> TlvDocument::CreatePrivateNode(int tag)
{
    return CreateTlvNode(tag, 3);
}

std::shared_ptr<TlvNode> TlvDocument::CreateNumberNode(uint8_t number)
{
    tsCryptoData tmp;

    tmp += (uint8_t)number;
    return CreateNumberNode(tmp);
}

std::shared_ptr<TlvNode> TlvDocument::CreateNumberNode(short number)
{
    tsCryptoData data;

    if ( (number >> 8) & 0xff )
        data += (uint8_t)((number >> 8) & 0xff);
    data += (uint8_t)((number)      & 0xff);
    return CreateNumberNode(data);
}

std::shared_ptr<TlvNode> TlvDocument::CreateNumberNode(int number)
{
    tsCryptoData data;

    if ( (number >> 24) & 0xff )
        data += (uint8_t)((number >> 24) & 0xff);
    if ( (number >> 16) )
        data += (uint8_t)((number >> 16) & 0xff);
    if ( (number >> 8) )
        data += (uint8_t)((number >> 8)  & 0xff);
    data += (uint8_t)((number)       & 0xff);
    return CreateNumberNode(data);
}

std::shared_ptr<TlvNode> TlvDocument::CreateNumberNode(int64_t number)
{
    tsCryptoData data;

    if ( (number >> 56) )
        data += (uint8_t)((number >> 56) & 0xff);
    if ( (number >> 48) )
        data += (uint8_t)((number >> 48) & 0xff);
    if ( (number >> 40) )
        data += (uint8_t)((number >> 40) & 0xff);
    if ( (number >> 32) )
        data += (uint8_t)((number >> 32) & 0xff);
    if ( (number >> 24) )
        data += (uint8_t)((number >> 24) & 0xff);
    if ( (number >> 16) )
        data += (uint8_t)((number >> 16) & 0xff);
    if ( (number >> 8) )
        data += (uint8_t)((number >> 8)  & 0xff);
    data += (uint8_t)((number)       & 0xff);
    return CreateNumberNode(data);
}

std::shared_ptr<TlvNode> TlvDocument::CreateNumberNode(uint64_t number)
{
    tsCryptoData data;

    if ( (number >> 56) )
        data += (uint8_t)((number >> 56) & 0xff);
    if ( (number >> 48) )
        data += (uint8_t)((number >> 48) & 0xff);
    if ( (number >> 40) )
        data += (uint8_t)((number >> 40) & 0xff);
    if ( (number >> 32) )
        data += (uint8_t)((number >> 32) & 0xff);
    if ( (number >> 24) )
        data += (uint8_t)((number >> 24) & 0xff);
    if ( (number >> 16) )
        data += (uint8_t)((number >> 16) & 0xff);
    if ( (number >> 8) )
        data += (uint8_t)((number >> 8)  & 0xff);
    data += (uint8_t)((number)       & 0xff);
    return CreateNumberNode(data);
}

std::shared_ptr<TlvNode> TlvDocument::CreateNumberNode(const tsCryptoData &number)
{
    std::shared_ptr<TlvNode> node = CreateTlvNode(0x02, 0);

    if ( number.size() == 0 )
    {
        tsCryptoData data;
        data.resize(1);

        node->InnerData(data);
        return node;
    }
    if ( (number[0] & 0x80) != 0 )
    {
        tsCryptoData data(number);
        data.insert(0, (uint8_t)0);
        node->InnerData(data);
    }
    else
        node->InnerData(number);
    return node;
}

std::shared_ptr<TlvNode> TlvDocument::CreateNULL()
{
    return CreateTlvNode(5, 0);
}

std::shared_ptr<TlvNode> TlvDocument::CreateUTF8String(const tsCryptoStringBase &val)
{
    std::shared_ptr<TlvNode> node = CreateTlvNode(12, 0);

    node->InnerString(val);
    return node;
}

std::shared_ptr<TlvNode> TlvDocument::CreateBitString(uint8_t unusedBits, uint8_t data)
{
    std::shared_ptr<TlvNode> node = CreateTlvNode(3, 0);
    tsCryptoData newData;

    newData += unusedBits;
    newData += data;
    node->InnerData(newData);
    return node;
}

std::shared_ptr<TlvNode> TlvDocument::CreateBitString(uint8_t unusedBits, const tsCryptoData &data)
{
    std::shared_ptr<TlvNode> node = CreateTlvNode(3, 0);
    tsCryptoData newData;

    newData += unusedBits;
    newData += data;
    node->InnerData(newData);
    return node;
}

std::shared_ptr<TlvNode> TlvDocument::DocumentElement() const
{
    return m_document;
}

/*
public void LoadTlvIntoNode(TlvNode parent, byte[] buffer, int offset, int length)
{
    int end = offset + length;

    if ( buffer == null )
        throw new TlvParserException("Invalid argument");
    if ( buffer.GetLength (0) <= offset || buffer.GetLength(0) < end )
        throw new TlvParserException("Invalid buffer offset/length specified");

    while ( offset < end )
    {
        TlvNode node = new TlvNode(this);
        node.FromBytes(buffer, ref offset, end);
        parent.Children.Add(node);
    }
}
*/
