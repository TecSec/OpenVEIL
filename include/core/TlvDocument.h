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

/*! @file TlvDocument.h
 * @brief This file defines a TLV parser that is compatible with ASN.1 BER encoding
*/

#ifndef __TLVDOCUMENT_H__
#define __TLVDOCUMENT_H__

#pragma once

namespace tscrypto {

	/// <summary>ASN.1 parser/generator</summary>
	class VEILCORE_API  TlvDocument : public tscrypto::ICryptoObject
	{
	protected:
		/// <summary>Default constructor.</summary>
		TlvDocument(void);
	public:
		static std::shared_ptr<TlvDocument> Create();
		/// <summary>Destructor.</summary>
		~TlvDocument(void);

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
			/// <summary>gets the flag that indicates that flat model is to be used</summary>
			/// 
			/// <remarks>If flat model is enabled then the ber encoding of the tag value will be disabled.
			/// 		 This means that the tags can not contain sub tags and that the tag is a simple number
			/// 		 instead of a type and number.  Flat model is used to process PIV data objects.</remarks>
			///
			/// <returns>true if flat model is enabled</returns>
			////////////////////////////////////////////////////////////////////////////////////////////////////
		bool FlatModel() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Enables or disables flat model</summary>
		///
		/// <remarks>If flat model is enabled then the BER encoding of the tag value will be disabled.
		/// 		 This means that the tags can not contain sub tags and that the tag is a simple number
		/// 		 instead of a type and number.  Flat model is used to process PIV data objects.</remarks>
		///
		/// <param name="setTo">true to enable Flat Model</param>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		void FlatModel(bool setTo);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>gets the flag that indicates that the CAC Simple TLV mode is to be used</summary>
		///
		/// <remarks>Just like FlatModel disables many of the BER encoding rules for the Tag, CACSimpleTlv 
		/// 		 changes how the length field is encoded.  It also removes the handling of sub tags.
		/// 		 
		/// 		 When CACSimpleTlv is enabled the length field of all tags will be either 1 ot three 
		/// 		 bytes. If the length is &lt; 255 then it is encoded as a single byte.  For lengths &gt; 254
		/// 		 then the length is encoded as three bytes, FF HH LL where FF is the value 255, HH is 
		/// 		 the high byte of the length and LL is the low byte of the length.</remarks>
		///
		/// <returns>true if CAC Simple Model is enabled</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		bool CacSimpleTlv() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Enables or disables CAC Simple TLV handling</summary>
		///
		/// <remarks>Just like FlatModel disables many of the BER encoding rules for the Tag, CACSimpleTlv 
		/// 		 changes how the length field is encoded.  It also removes the handling of sub tags.
		/// 		 
		/// 		 When CACSimpleTlv is enabled the length field of all tags will be either 1 ot three 
		/// 		 bytes. If the length is &lt; 255 then it is encoded as a single byte.  For lengths &gt; 254
		/// 		 then the length is encoded as three bytes, FF HH LL where FF is the value 255, HH is 
		/// 		 the high byte of the length and LL is the low byte of the length.</remarks>
		///
		/// <param name="setTo">true to enable CACSimpleTlv mode</param>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		void CacSimpleTlv(bool setTo);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Query if this object has a fake top node.</summary>
		///
		/// <remarks>While parsing an ASN.1 dataset it is possible that more than one top level node exists.
		/// 		 In this case TlvDocument will create a placeholder node at the top that contains the 
		/// 		 parsed data.  If a placeholder node was created then this function will return true.</remarks>
		/// 
		/// <returns>true if fake top node, false if not.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		bool hasFakeTopNode() const;
		/// <summary>Clears this object to its blank/initial state.</summary>
		void Clear();
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Parses a BER encoded buffer into a tree of TlvNode objects.</summary>
		///
		/// <param name="buffer">The ASN.1 BER buffer.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		bool LoadTlv(const tsCryptoData &buffer);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Converts the TlvNode objects into a BER encoded data buffer</summary>
		///
		/// <returns>the BER encoded data</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		tsCryptoData SaveTlv() const;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Creates a generic TLV node</summary>
		///
		/// <param name="tag"> The tag.</param>
		/// <param name="type">The type.</param>
		///
		/// <returns>null if it fails, else the new tlv node.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		std::shared_ptr<TlvNode> CreateTlvNode(int tag, BYTE type);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Creates a universal OID node and initializes it</summary>
		///
		/// <param name="oid">The oid.</param>
		///
		/// <returns>null if it fails, else the new oid node.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		std::shared_ptr<TlvNode> CreateOIDNode(const tsCryptoData &oid);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Creates a universal boolean node and initializes it</summary>
		///
		/// <param name="setTo">true to set to.</param>
		///
		/// <returns>null if it fails, else the new boolean.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		std::shared_ptr<TlvNode> CreateBoolean(bool setTo);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Creates a universal octet string (byte array) node and initializes it</summary>
		///
		/// <param name="data">The data.</param>
		///
		/// <returns>null if it fails, else the new octet string.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		std::shared_ptr<TlvNode> CreateOctetString(const tsCryptoData &data);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Creates a universal sequence node that is used to hold a sequence of tags</summary>
		///
		/// <returns>null if it fails, else the new sequence.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		std::shared_ptr<TlvNode> CreateSequence();
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Createsa universal set node (think array) that is used to hold a set of tags</summary>
		///
		/// <returns>null if it fails, else the new set.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		std::shared_ptr<TlvNode> CreateSet();
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Creates a TlvNode with the specified tag and the type of Type_Application</summary>
		///
		/// <param name="tag">The tag.</param>
		///
		/// <returns>null if it fails, else the new application node.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		std::shared_ptr<TlvNode> CreateApplicationNode(int tag);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Creates a TlvNode with the specified tag and the type of Type_Context</summary>
		///
		/// <param name="tag">The tag.</param>
		///
		/// <returns>null if it fails, else the new context node.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		std::shared_ptr<TlvNode> CreateContextNode(int tag);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Creates a TlvNode with the specified tag and the type of Type_Private</summary>
		///
		/// <param name="tag">The tag.</param>
		///
		/// <returns>null if it fails, else the new private node.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		std::shared_ptr<TlvNode> CreatePrivateNode(int tag);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Creates a number node and initializes it</summary>
		///
		/// <param name="number">The value to initialize the node</param>
		///
		/// <returns>null if it fails, else the new number node.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		std::shared_ptr<TlvNode> CreateNumberNode(BYTE number);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Creates a number node and initializes it</summary>
		///
		/// <param name="number">The value to initialize the node</param>
		///
		/// <returns>null if it fails, else the new number node.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		std::shared_ptr<TlvNode> CreateNumberNode(short number);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Creates a number node and initializes it</summary>
		///
		/// <param name="number">The value to initialize the node</param>
		///
		/// <returns>null if it fails, else the new number node.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		std::shared_ptr<TlvNode> CreateNumberNode(int number);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Creates a number node and initializes it</summary>
		///
		/// <param name="number">The value to initialize the node</param>
		///
		/// <returns>null if it fails, else the new number node.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		std::shared_ptr<TlvNode> CreateNumberNode(int64_t number);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Creates a number node and initializes it</summary>
		///
		/// <param name="number">The value to initialize the node</param>
		///
		/// <returns>null if it fails, else the new number node.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		std::shared_ptr<TlvNode> CreateNumberNode(uint64_t number);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Creates a number node and initializes it</summary>
		///
		/// <param name="number">The value to initialize the node</param>
		///
		/// <returns>null if it fails, else the new number node.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		std::shared_ptr<TlvNode> CreateNumberNode(const tsCryptoData &number);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Creates a null node</summary>
		///
		/// <returns>null if it fails, else the new null.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		std::shared_ptr<TlvNode> CreateNULL();
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Creates a UTF8 string node and initializes it</summary>
		///
		/// <param name="val">The string to initialize the node</param>
		///
		/// <returns>null if it fails, else the new UTF 8 string.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		std::shared_ptr<TlvNode> CreateUTF8String(const tsCryptoStringBase &val);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Creates a bit-string (array of bits) node and initializes it</summary>
		///
		/// <param name="unusedBits">The unused bits.</param>
		/// <param name="data">		 The bit array data</param>
		///
		/// <returns>null if it fails, else the new bit string.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		std::shared_ptr<TlvNode> CreateBitString(BYTE unusedBits, BYTE data);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Creates a bit-string (array of bits) node and initializes it</summary>
		///
		/// <param name="unusedBits">The unused bits.</param>
		/// <param name="data">		 The bit array data</param>
		///
		/// <returns>null if it fails, else the new bit string.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		std::shared_ptr<TlvNode> CreateBitString(BYTE unusedBits, const tsCryptoData &data);
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the top level node</summary>
		///
		/// <returns>the top level node</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		std::shared_ptr<TlvNode> DocumentElement() const;

	protected:
		std::shared_ptr<TlvNode> m_document;
		std::weak_ptr<TlvDocument> _ThisDoc;
		bool m_flatModel;
		bool m_cacSimpleTlv;
		bool m_fakeTopNode;
	};
}

#endif // __TLVDOCUMENT_H__

