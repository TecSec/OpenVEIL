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

/*! \defgroup TSFRAMEWORK CKM Framework support
 * @{
 */

 /*! @file xp_file.h
 * @brief This file defines the cross platform file functions.
 */

#if !defined(__PEM_H__)
#define __PEM_H__

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000


 /**
 * \brief Represents a named binary section of a PEM encoded object
 */
class VEILCORE_API TSNamedBinarySection
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

		/**
	* \brief Default constructor.
	*/
		TSNamedBinarySection() {}
	/**
	* \brief Copy constructor.
	*
	* \param obj The object.
	*/
	TSNamedBinarySection(const TSNamedBinarySection& obj) : Name(obj.Name), Contents(obj.Contents), Attributes(obj.Attributes) {}
	/**
	* \brief Move constructor.
	*
	* \param [in,out] obj The object.
	*/
	TSNamedBinarySection(TSNamedBinarySection&& obj) : Name(std::move(obj.Name)), Contents(std::move(obj.Contents)), Attributes(std::move(obj.Attributes)) {}
	/**
	* \brief Assignment operator.
	*
	* \param obj The object.
	*
	* \return A shallow copy of this object.
	*/
	TSNamedBinarySection& operator=(const TSNamedBinarySection& obj) { if (&obj != this) { Name = obj.Name; Contents = obj.Contents; Attributes = obj.Attributes; } return *this; }
	/**
	* \brief Move assignment operator.
	*
	* \param [in,out] obj The object.
	*
	* \return A shallow copy of this object.
	*/
	TSNamedBinarySection& operator=(TSNamedBinarySection&& obj) { if (&obj != this) { Name = std::move(obj.Name); Contents = std::move(obj.Contents); Attributes = std::move(obj.Attributes); } return *this; }
	/**
	* \brief Equality operator.
	*
	* \param obj The object.
	*
	* \return true if the parameters are considered equivalent.
	*/
	bool operator==(const TSNamedBinarySection& obj) const { return Name == obj.Name && Contents == obj.Contents; }

	tscrypto::tsCryptoString Name;   ///< The name of the binary section
	tscrypto::tsCryptoData  Contents;   ///< The contents of the binary section
	tsAttributeMap Attributes;  ///< The attributes of the binary section
};

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4231)
VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API tscrypto::ICryptoContainerWrapper<TSNamedBinarySection>;
VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::shared_ptr<tscrypto::ICryptoContainerWrapper<TSNamedBinarySection>>;
#pragma warning(pop)
#endif // _MSC_VER

typedef std::shared_ptr<tscrypto::ICryptoContainerWrapper<TSNamedBinarySection>> TSNamedBinarySectionList;
extern VEILCORE_API TSNamedBinarySectionList CreateTSNamedBinarySectionList();

/**
* \brief Reads a PEM encoded armored file into a vector of sections
*
* \param filename		    Filename of the file.
* \param [in,out] contents The contents.
*
* \return true if it succeeds, false if it fails.
*/
extern bool VEILCORE_API xp_ReadArmoredFile(const tscrypto::tsCryptoString& filename, TSNamedBinarySectionList& contents);
/**
* \brief Reads a PEM encoded armored string into a vector of sections
*
* \param input		    The string to convert.
* \param [in,out] contents The contents.
*
* \return true if it succeeds, false if it fails.
*/
extern bool VEILCORE_API xp_ReadArmoredString(const tscrypto::tsCryptoString& input, TSNamedBinarySectionList& contents);
/**
* \brief Writes a vector of sections into a PEM encoded armored file
*
* \param filename Filename of the file.
* \param contents The contents.
*
* \return true if it succeeds, false if it fails.
*/
extern bool VEILCORE_API xp_WriteArmoredFile(const tscrypto::tsCryptoString& filename, const TSNamedBinarySectionList& contents);
/**
* \brief Writes a vector of sections into a PEM encoded armored string.
*
* \param contents		  The contents.
* \param [in,out] output The output.
*
* \return true if it succeeds, false if it fails.
*/
extern bool VEILCORE_API xp_WriteArmoredString(const TSNamedBinarySectionList& contents, tscrypto::tsCryptoString& output);

#endif // __PEM_H__

/*! @} */