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

/*! @file TlvNode.h
 * @brief This file defines the class that holds the information for one TLV node
*/

#ifndef __TLVNODE_H__
#define __TLVNODE_H__

#pragma once

namespace tscrypto {

	class TlvNode;
	class TlvDocument;

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4231)
	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::shared_ptr<TlvNode>;
	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::weak_ptr<TlvNode>;
	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::weak_ptr<TlvDocument>;
	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::shared_ptr<TlvDocument>;

	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API ICryptoContainerWrapper<std::shared_ptr<TlvNode>>;
	VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::shared_ptr<ICryptoContainerWrapper<std::shared_ptr<TlvNode>>>;
#pragma warning(pop)
#endif // _MSC_VER

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Holds a list of node references.</summary>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	typedef std::shared_ptr<ICryptoContainerWrapper<std::shared_ptr<TlvNode>>> TlvNodeCollection;

	/// <summary>Holds the type length and data information for one node</summary>
	class VEILCORE_API  TlvNode : public tscrypto::ICryptoObject
	{
	public:
		typedef enum {
			Tlv_Boolean = 1,			///< An enum constant representing a boolean value
			Tlv_Number = 2,				///< An enum constant representing a number
			Tlv_BitString = 3,			///< An enum constant representing an array of bits
			Tlv_Octet = 4,				///< An enum constant representing an array of bytes
			Tlv_NULL = 5,				///< An enum constant representing a NULL node
			Tlv_OID = 6,				///< An enum constant representing an OID
			Tlv_ObjectDescriptor = 7,   ///< An enum constant representing an object descriptor
			Tlv_External = 8,			///< An enum constant representing an external set of nodes
			Tlv_Real = 9,				///< An enum constant representing a real number
			Tlv_Enumerated = 10,		///< An enum constant representing an enumeration
			Tlv_Embedded_Pdv = 11,		///< An enum constant representing an embedded PDV
			Tlv_UTF8String = 12,		///< An enum constant representing a UTF8 string
			Tlv_Sequence = 16,			///< An enum constant representing a sequence of tags (structure)
			Tlv_Set = 17,				///< An enum constant representing a set of tags (unordered list of tags)
			Tlv_NumericString = 18,		///< An enum constant representing numeric string
			Tlv_PrintableString = 19,   ///< An enum constant representing string of printable characters
			Tlv_T61String = 20,			///< An enum constant representing a T61 string
			Tlv_VideoTexString = 21,	///< An enum constant representing a Videotex string
			Tlv_IA5String = 22,			///< An enum constant representing an IA5 string
			Tlv_UTCTime = 23,			///< An enum constant representing a UTC timestamp (obsolete - use Tlv_GeneralizedTime)
			Tlv_GeneralizedTime = 24,   ///< An enum constant representing a universal GMT based timestamp
			Tlv_GraphicString = 25,		///< An enum constant representing a graphic string
			Tlv_VisibleString = 26,		///< An enum constant representing a visible string
			Tlv_GeneralString = 27,		///< An enum constant representing a general string
			Tlv_UniversalString = 28,   ///< An enum constant representing a universal string
			Tlv_BmpString = 30			///< An enum constant representing a BMP string
		} TlvTag;   ///< Defines the values for the universal tags
		typedef enum {
			Type_Universal = 0,		///< specifies that the ASN.1 universal tags are used
			Type_Application = 1,   ///< specifies that application specific tags are used
			Type_Context = 2,		///< specifies that the tags are defined by the context of the node
			Type_Private = 3		///< specifies that the tags are from a private set
		} TlvType;  ///< Defines the family of tags that are used for a node

		/// <summary>Destructor.</summary>
		~TlvNode(void);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Creates a generic node with default values</summary>
		///
		/// <param name="document">[in] The document that shall contain the node</param>
		///
		/// <returns>null if it fails, else the TlvNode</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		static std::shared_ptr<TlvNode> Create(std::weak_ptr<TlvDocument> document);
		static std::shared_ptr<TlvNode> Create(std::shared_ptr<TlvDocument> document);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Creates a generic node with he specified tag and type</summary>
		///
		/// <param name="document">[in] The document that shall contain the node</param>
		/// <param name="tag">	   The tag.</param>
		/// <param name="type">	   The type.</param>
		///
		/// <returns>null if it fails, else the TlvNode</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		static std::shared_ptr<TlvNode> Create(std::weak_ptr<TlvDocument> document, int tag, BYTE type);
		static std::shared_ptr<TlvNode> Create(std::shared_ptr<TlvDocument> document, int tag, BYTE type);
	protected:
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Constructor.</summary>
		///
		/// <param name="document">[in] The document that shall contain the node</param>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		TlvNode(std::weak_ptr<TlvDocument> document);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Constructor.</summary>
		///
		/// <param name="document">[in] The document that shall contain the node</param>
		/// <param name="tag">	   The tag.</param>
		/// <param name="type">	   The type.</param>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		TlvNode(std::weak_ptr<TlvDocument> document, int tag, BYTE type);
	public:
		//#ifdef _WIN32
		//    ////////////////////////////////////////////////////////////////////////////////////////////////////
		//    /// <summary>Object allocation operator.</summary>
		//    ///
		//    /// <param name="bytes">The number of bytes to allocate.</param>
		//    ///
		//    /// <returns>The allocated object.</returns>
		//    ////////////////////////////////////////////////////////////////////////////////////////////////////
		//    void *operator new(size_t bytes);
		//    ////////////////////////////////////////////////////////////////////////////////////////////////////
		//    /// <summary>Object de-allocation operator.</summary>
		//    ///
		//    /// <param name="ptr">[in,out] If non-null, the pointer to delete.</param>
		//    ////////////////////////////////////////////////////////////////////////////////////////////////////
		//    void operator delete(void *ptr);
		//#endif // _WIN32

			////////////////////////////////////////////////////////////////////////////////////////////////////
			/// <summary>Gets the document that owns this node.</summary>
			///
			/// <returns>the TlvDocument that owns this node</returns>
			////////////////////////////////////////////////////////////////////////////////////////////////////
		std::weak_ptr<TlvDocument> OwnerDocument() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Query if this node contains subnodes</summary>
		///
		/// <returns>true if constructed, false if not.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		bool IsConstructed() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the tag value</summary>
		///
		/// <returns>the tag value</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		int Tag() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the tag value for this node</summary>
		///
		/// <param name="setTo">the new tag value</param>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		TlvNode* Tag(int setTo);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the value of the tag as if the node was a flat model node</summary>
		///
		/// <returns>The tag value as a flat model tag</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		int FlatTag() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the type</summary>
		///
		/// <returns>the type</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		BYTE Type() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the type for this node</summary>
		///
		/// <param name="setTo">the new type value</param>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		TlvNode* Type(BYTE setTo);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the list of child nodes</summary>
		///
		/// <returns>A list of child nodes</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		const TlvNodeCollection &Children() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Appends a child node to the list of children</summary>
		///
		/// <param name="child">the child to add</param>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		TlvNode* AppendChild(std::shared_ptr<TlvNode> child);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Removes the child from the list of children</summary>
		///
		/// <param name="child">the child to remove</param>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		void RemoveChild(std::shared_ptr<TlvNode> child);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Searches for all children with the specified tag and type</summary>
		///
		/// <param name="list">[in,out] The list of children that match the tag and type</param>
		/// <param name="tag"> The tag.</param>
		/// <param name="type">The type.</param>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		void Search(TlvNodeCollection &list, int tag, int type);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the data contained in this node as an array of bytes</summary>
		///
		/// <returns>the byte array</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoData InnerData() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the data contained in this node as a number</summary>
		///
		/// <returns>64 bit integer</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		int64_t InnerDataAsNumber() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the data of this node from an array of bytes</summary>
		///
		/// <param name="setTo">the new data value for this node</param>
		///
		/// <returns>a pointer to this node</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		TlvNode *InnerData(const tsCryptoData &setTo);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the data of this node from a byte</summary>
		///
		/// <param name="setTo">the new data value for this node</param>
		///
		/// <returns>a pointer to this node</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		TlvNode *InnerData(BYTE setTo);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the data of this node from a short</summary>
		///
		/// <param name="setTo">the new data value for this node</param>
		///
		/// <returns>a pointer to this node</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		TlvNode *InnerData(short setTo);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the data of this node from an integer</summary>
		///
		/// <param name="setTo">the new data value for this node</param>
		///
		/// <returns>a pointer to this node</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		TlvNode *InnerData(int setTo);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the data of this node from 64 bit integer</summary>
		///
		/// <param name="setTo">the new data value for this node</param>
		///
		/// <returns>a pointer to this node</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		TlvNode *InnerData(int64_t setTo);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the data of this node from a byte</summary>
		///
		/// <param name="setTo">the new data value for this node</param>
		///
		/// <returns>a pointer to this node</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		TlvNode *InnerDataAsNumber(BYTE setTo);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the data of this node from a 16 bit integer</summary>
		///
		/// <param name="setTo">the new data value for this node</param>
		///
		/// <returns>a pointer to this node</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		TlvNode *InnerDataAsNumber(int16_t setTo);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the data of this node from an unsigned 16 bit integer</summary>
		///
		/// <param name="setTo">the new data value for this node</param>
		///
		/// <returns>a pointer to this node</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		TlvNode *InnerDataAsNumber(uint16_t setTo);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the data of this node from a 32 bit integer</summary>
		///
		/// <param name="setTo">the new data value for this node</param>
		///
		/// <returns>a pointer to this node</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		TlvNode *InnerDataAsNumber(int32_t setTo);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the data of this node from an unsigned 32 bit integer</summary>
		///
		/// <param name="setTo">the new data value for this node</param>
		///
		/// <returns>a pointer to this node</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		TlvNode *InnerDataAsNumber(uint32_t setTo);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the data of this node from a 64 bit integer</summary>
		///
		/// <param name="setTo">the new data value for this node</param>
		///
		/// <returns>a pointer to this node</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		TlvNode *InnerDataAsNumber(int64_t setTo);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the data of this node from an unsigned 64 bit integer</summary>
		///
		/// <param name="setTo">the new data value for this node</param>
		///
		/// <returns>a pointer to this node</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		TlvNode *InnerDataAsNumber(uint64_t setTo);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the contents of this node as a string</summary>
		///
		/// <returns>.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoString InnerString() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the data of this node from a string</summary>
		///
		/// <param name="setTo">the new data value for this node</param>
		///
		/// <returns>a pointer to this node</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		TlvNode *InnerString(const tsCryptoStringBase &setTo);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>converts this node and all of its children into a BER encoded byte array</summary>
		///
		/// <returns>the encoded representation of this node and its children</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoData OuterData() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>changes the value of this node and its children to te encoded value specified</summary>
		///
		/// <param name="setTo">the encoded value</param>
		///
		/// <returns>0 for error or the length of the data processed</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		size_t OuterData(const tsCryptoData &setTo);
		/**
		 * \brief Deletes any contained data or nodes and then places the indicated nodes as children.
		 *
		 * \param setTo The Tlv of the new children.
		 *
		 * \return The number of bytes read from the Tlv data buffer.
		 */
		size_t InnerTlv(const tsCryptoData& setTo);
		/**
		 * \brief builds the Tlv data of any and all children of this node
		 *
		 * \return The Tlv representation of the child nodes.
		 */
		tsCryptoData InnerTlv() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Computes the number of bytes needed to store the encoded value of this tag and all children</summary>
		///
		/// <returns>the encoded size for this node and all of its children</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		size_t DataSize() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Computes the number of bytes needed to hold the inner data and/or all of this node's children</summary>
		///
		/// <returns>size in bytes to hold the data contained in this node</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		size_t ContainedDataSize() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Calculates the unmberof bytes needed to encode the tag for this node</summary>
		///
		/// <returns>The calculated tag size.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		int ComputeTagSize() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Searches for the child with the specified type and tag</summary>
		///
		/// <param name="tag"> The tag.</param>
		/// <param name="type">The type.</param>
		///
		/// <returns>null if it fails, else the found tag.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		std::shared_ptr<TlvNode> FindFirstTag(int tag, int type);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Searches for the child with the specified type and tag</summary>
		///
		/// <param name="tag"> The tag.</param>
		/// <param name="type">The type.</param>
		///
		/// <returns>null if it fails, else the found tag.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		std::shared_ptr<TlvNode> FindFirstTag(int tag, int type) const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Returns the parent node that contains this node</summary>
		///
		/// <returns>null if it fails, else.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		std::weak_ptr<TlvNode> Parent() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the parent node for this node</summary>
		///
		/// <param name="parent">the parent node</param>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		void Parent(std::weak_ptr<TlvNode> parent);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the number of children in this node</summary>
		///
		/// <returns>the number of children in this node</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		size_t ChildCount() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>returns th child node at the specified position</summary>
		///
		/// <param name="index">Zero-based index of the child to return</param>
		///
		/// <returns>null if the index is invalid or the child at that position</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		std::shared_ptr<TlvNode> ChildAt(size_t index) const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>returns th child node at the specified position</summary>
		///
		/// <param name="index">Zero-based index of the child to return</param>
		///
		/// <returns>null if the index is invalid or the child at that position</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		std::shared_ptr<TlvNode> ChildAt(size_t index);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Indicates that the constructed flag was forced for this node</summary>
		///
		/// <returns>if the constructed flag was forced</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		bool ForceConstructed() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the ForceConstructed flag</summary>
		///
		/// <param name="setTo">true to indicate that the constructed flag must be set</param>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		void ForceConstructed(bool setTo);

		/// <summary>sorts the child nodes by their tag values</summary>
		void SortByTag();
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Query if this object is an oid node.</summary>
		///
		/// <returns>true if oid node, false if not.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		bool IsOIDNode() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Query if this object is an oid node with the value specified.</summary>
		///
		/// <param name="oid">The oid to test against</param>
		///
		/// <returns>true if oid node that matches the test value, false if not.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		bool IsOIDNode(const tsCryptoData &oid) const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Query if this object is a sequence node.</summary>
		///
		/// <returns>true if sequence, false if not.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		bool IsSequence() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Query if this object is a set node.</summary>
		///
		/// <returns>true if set, false if not.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		bool IsSet() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Query if this object is a string node.</summary>
		///
		/// <returns>true if string, false if not.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		bool IsString() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Query if this object is a boolean node.</summary>
		///
		/// <returns>true if boolean, false if not.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		bool IsBoolean() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Query if this object is a number node.</summary>
		///
		/// <returns>true if number, false if not.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		bool IsNumber() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Query if this object is a number node with the specified value.</summary>
		///
		/// <param name="value">The value needed</param>
		///
		/// <returns>true if number, false if not.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		bool IsNumber(int64_t value) const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Query if this object is a date node.</summary>
		///
		/// <returns>true if date, false if not.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		bool IsDate() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Query if this object is a null node.</summary>
		///
		/// <returns>true if null, false if not.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		bool IsNull() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Query if this object is an octet node.</summary>
		///
		/// <returns>true if octet, false if not.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		bool IsOctet() const;
	    ////////////////////////////////////////////////////////////////////////////////////////////////////
	    /// <summary>Gets the inner data as a date time.</summary>
	    ///
	    /// <returns>the inner data converted to a date time</returns>
	    ////////////////////////////////////////////////////////////////////////////////////////////////////
	    tsCryptoDate InnerDataAsDateTime() const;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Calculates the number of bytes needed to encode the length</summary>
		///
		/// <param name="dataLength">data length to encode</param>
		/// <param name="simpleTlv"> true if encoding for CAC simple tlv.</param>
		///
		/// <returns>The calculated encoding size for length</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		static size_t ComputeLengthSize(size_t dataLength, bool simpleTlv);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Extracts the tag and length from a byte array</summary>
		///
		/// <param name="buffer">	   The buffer to process</param>
		/// <param name="offset">	   The offset into the buffer to start the </param>
		/// <param name="flatTag">	   true if we need to treat the tags as flat tags.</param>
		/// <param name="simpleLength">true if we are processing CAC simple length nodes</param>
		/// <param name="tag">		   [out] The tag found</param>
		/// <param name="constructed"> [out] The constructed flag for this tag</param>
		/// <param name="type">		   [out] The type of this tag</param>
		/// <param name="length">	   [out] The length of the data contained in this node</param>
		///
		/// <returns>the total length of the data for this node including the tag and length elements.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		static size_t ExtractTagAndLength(const tsCryptoData &buffer, size_t offset, bool flatTag, bool simpleLength, int &tag,
			bool &constructed, BYTE &type, size_t &length);

	protected:
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Encodes the tag for this node and appends it to the buffer</summary>
		///
		/// <param name="buffer">[in,out] The buffer to which the encoded tag is appended</param>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		void PutTagIntoBuffer(tsCryptoData &buffer) const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Encodes the data length for this node and appends it to the buffer</summary>
		///
		/// <param name="buffer">[in,out] The buffer to which the encoded length is appended</param>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		void PutLengthIntoBuffer(tsCryptoData &buffer) const;

	protected:
		TlvNodeCollection m_children;
		int m_tag;
		BYTE m_type;
		tsCryptoData m_data;
		std::weak_ptr<TlvDocument> m_document;
		std::weak_ptr<TlvNode> m_parent;
		bool m_forceConstructed;

		TlvNode &operator=(const TlvNode &) { return *this; };
	};
}

#endif // __TLVNODE_H__

