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

//////////////////////////////////////////////////////////////////////////////////
/// \file tsCertificateNamePart.h
/// \brief Defines a portion of an issuer or subject name.
//////////////////////////////////////////////////////////////////////////////////

#ifndef TSCERTIFICATENAMEPART_H
#define TSCERTIFICATENAMEPART_H

#if 0

namespace tscrypto
{
	/// <summary>Defines a portion of an issuer or subject name.</summary>
	class VEILCORE_API tsCertificateNamePart
	{
	public:
		/// <summary>The name part defined here.</summary>
		typedef enum {
			Unknown,		///< Unknown
			Name,			///< The entire name
			Surname,		///< The surname
			givenName,		///< The given name
			Initials,		///< Your initials
			Suffix,			///< Your suffix
			CommonName,		///< Your common name
			locality,		///< The locality (city for example)
			state,			///< your state name
			OrgName,		///< Your organization's name
			OrgUnit,		///< The name of an organizational unit
			Title,			///< Your title
			dnQualifier,	///< The distinquished name qualifier
			Country			///< Your country
		} NamePartType;

	public:
		/// <summary>Default constructor.</summary>
		tsCertificateNamePart(); // TODO: Implement this class
		/// <summary>Destructor.</summary>
		virtual ~tsCertificateNamePart();

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
	private:
	};
}
#endif // 0

#endif // TSCERTIFICATENAMEPART_H
