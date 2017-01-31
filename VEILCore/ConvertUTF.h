/*
 * Copyright 2001-2004 Unicode, Inc.
 *
 * Disclaimer
 *
 * This source code is provided as is by Unicode, Inc. No claims are
 * made as to fitness for any particular purpose. No warranties of any
 * kind are expressed or implied. The recipient agrees to determine
 * applicability of information provided. If this file has been
 * purchased on magnetic or optical media from Unicode, Inc., the
 * sole remedy for any claim will be exchange of defective media
 * within 90 days of receipt.
 *
 * Limitations on Rights to Redistribute This Code
 *
 * Unicode, Inc. hereby grants the right to freely use the information
 * supplied in this file in the creation of products supporting the
 * Unicode Standard, and to make copies of this file in any form
 * for internal or external distribution as long as this notice
 * remains attached.
 */

 /* ---------------------------------------------------------------------

	 Conversions between UTF32, UTF-16, and UTF-8.  Header file.

	 Several funtions are included here, forming a complete set of
	 conversions between the three formats.  UTF-7 is not included
	 here, but is handled in a separate source file.

	 Each of these routines takes pointers to input buffers and output
	 buffers.  The input buffers are const.

	 Each routine converts the text between *sourceStart and sourceEnd,
	 putting the result into the buffer between *targetStart and
	 targetEnd. Note: the end pointers are *after* the last item: e.g.
	 *(sourceEnd - 1) is the last item.

	 The return result indicates whether the conversion was successful,
	 and if not, whether the problem was in the source or target buffers.
	 (Only the first encountered problem is indicated.)

	 After the conversion, *sourceStart and *targetStart are both
	 updated to point to the end of last text successfully converted in
	 the respective buffers.

	 Input parameters:
	 sourceStart - pointer to a pointer to the source buffer.
	 The contents of this are modified on return so that
	 it points at the next thing to be converted.
	 targetStart - similarly, pointer to pointer to the target buffer.
	 sourceEnd, targetEnd - respectively pointers to the ends of the
	 two buffers, for overflow checking only.

	 These conversion functions take a ConversionFlags argument. When this
	 flag is set to strict, both irregular sequences and isolated surrogates
	 will cause an error.  When the flag is set to lenient, both irregular
	 sequences and isolated surrogates are converted.

	 Whether the flag is strict or lenient, all illegal sequences will cause
	 an error return. This includes sequences such as: <F4 90 80 80>, <C0 80>,
	 or <A0> in UTF-8, and values above 0x10FFFF in UTF-32. Conformant code
	 must check for illegal sequences.

	 When the flag is set to lenient, characters over 0x10FFFF are converted
	 to the replacement character; otherwise (when the flag is set to strict)
	 they constitute an error.

	 Output parameters:
	 The value "sourceIllegal" is returned from some routines if the input
	 sequence is malformed.  When "sourceIllegal" is returned, the source
	 value will point to the illegal value that caused the problem. E.g.,
	 in UTF-8 when a sequence is malformed, it points to the start of the
	 malformed sequence.

	 Author: Mark E. Davis, 1994.
	 Rev History: Rick McGowan, fixes & updates May 2001.
	 Fixes & updates, Sept 2001.

	 ------------------------------------------------------------------------ */

	 /* ---------------------------------------------------------------------
		 The following 4 definitions are compiler-specific.
		 The C standard does not guarantee that wchar_t has at least
		 16 bits, so wchar_t is no less portable than unsigned short!
		 All should be unsigned values to avoid sign extension during
		 bit mask & shift operations.
		 ------------------------------------------------------------------------ */

		 /*! \file ConvertUTF.h
		  * \brief A utility file from Unicode, Inc. that we use to perform UTF string conversions.
		  */

#ifndef __CONVERT_UTF_H__
#define __CONVERT_UTF_H__

namespace tscrypto {

	typedef uint32_t   UTF32;  /*!< \brief at least 32 bits */
	typedef uint16_t   UTF16;  /*!< \brief at least 16 bits */
	typedef uint8_t    UTF8;   /*!< \brief typically 8 bits */
	typedef uint8_t    Boolean; /*!< \brief 0 or 1 */

	/* Some fundamental constants */

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>A macro that defines the unicode replacement character.</summary>
	////////////////////////////////////////////////////////////////////////////////////////////////////
#define UNI_REPLACEMENT_CHAR (UTF32)0x0000FFFD
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that defines the maximum BMP value.</summary>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define UNI_MAX_BMP (UTF32)0x0000FFFF
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that defines the maximum UTF16 character value.</summary>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define UNI_MAX_UTF16 (UTF32)0x0010FFFF
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that defines the maximum UTF32 character value.</summary>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define UNI_MAX_UTF32 (UTF32)0x7FFFFFFF
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that defines the maximum legal UTF32 character value.</summary>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define UNI_MAX_LEGAL_UTF32 (UTF32)0x0010FFFF

/// <summary>Conversion error codes</summary>
	typedef enum {
		conversionOK,       /*!< \brief conversion successful */
		sourceExhausted,    /*!< \brief partial character in source, but hit end */
		targetExhausted,    /*!< \brief insuff. room in target for conversion */
		sourceIllegal       /*!< \brief source sequence is illegal/malformed */
	} ConversionResult;

	/// <summary>Conversion flags</summary>
	typedef enum {
		strictConversion = 0,/*!< \brief Strict adherance to the UTF rules */
		lenientConversion/*!< \brief Lenient adherance to the UTF rules */
	} ConversionFlags;

	/* This is for C++ and does no harm in C */

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Converts a UTF 8 string into a UTF 16 string.</summary>
		///
		/// <param name="sourceStart">Source start.</param>
		/// <param name="sourceEnd">  Source end.</param>
		/// <param name="targetStart">[in,out] If non-null, target start.</param>
		/// <param name="targetEnd">  [in,out] If non-null, target end.</param>
		/// <param name="flags">	  The flags.</param>
		///
		/// <returns>The conversion error code.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
	ConversionResult ConvertUTF8toUTF16(
		const UTF8** sourceStart, const UTF8* sourceEnd,
		UTF16** targetStart, UTF16* targetEnd, ConversionFlags flags);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Converts a UTF 16 string into a UTF 8 string.</summary>
	///
	/// <param name="sourceStart">  Source start.</param>
	/// <param name="sourceEnd">	Source end.</param>
	/// <param name="targetStart">  [in,out] If non-null, target start.</param>
	/// <param name="targetEnd">	[in,out] If non-null, target end.</param>
	/// <param name="ConvertEndian">true to convert endian.</param>
	/// <param name="flags">		The flags.</param>
	///
	/// <returns>The conversion error code.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	ConversionResult ConvertUTF16toUTF8(
		const UTF16** sourceStart, const UTF16* sourceEnd,
		UTF8** targetStart, UTF8* targetEnd, bool ConvertEndian, ConversionFlags flags);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Converts a UTF 8 string into a UTF 32 string.</summary>
	///
	/// <param name="sourceStart">Source start.</param>
	/// <param name="sourceEnd">  Source end.</param>
	/// <param name="targetStart">[in,out] If non-null, target start.</param>
	/// <param name="targetEnd">  [in,out] If non-null, target end.</param>
	/// <param name="flags">	  The flags.</param>
	///
	/// <returns>The conversion error code.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	ConversionResult ConvertUTF8toUTF32(
		const UTF8** sourceStart, const UTF8* sourceEnd,
		UTF32** targetStart, UTF32* targetEnd, ConversionFlags flags);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Converts a UTF 32 string into a UTF 8 string.</summary>
	///
	/// <param name="sourceStart">  Source start.</param>
	/// <param name="sourceEnd">	Source end.</param>
	/// <param name="targetStart">  [in,out] If non-null, target start.</param>
	/// <param name="targetEnd">	[in,out] If non-null, target end.</param>
	/// <param name="ConvertEndian">true to convert endian.</param>
	/// <param name="flags">		The flags.</param>
	///
	/// <returns>The conversion error code.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	ConversionResult ConvertUTF32toUTF8(
		const UTF32** sourceStart, const UTF32* sourceEnd,
		UTF8** targetStart, UTF8* targetEnd, bool ConvertEndian, ConversionFlags flags);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Converts a UTF 16 string into a UTF 32 string.</summary>
	///
	/// <param name="sourceStart">  Source start.</param>
	/// <param name="sourceEnd">	Source end.</param>
	/// <param name="targetStart">  [in,out] If non-null, target start.</param>
	/// <param name="targetEnd">	[in,out] If non-null, target end.</param>
	/// <param name="ConvertEndian">true to convert endian.</param>
	/// <param name="flags">		The flags.</param>
	///
	/// <returns>The conversion error code.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	ConversionResult ConvertUTF16toUTF32(
		const UTF16** sourceStart, const UTF16* sourceEnd,
		UTF32** targetStart, UTF32* targetEnd, bool ConvertEndian, ConversionFlags flags);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Converts a UTF 32 string into a UTF 16 string.</summary>
	///
	/// <param name="sourceStart">  Source start.</param>
	/// <param name="sourceEnd">	Source end.</param>
	/// <param name="targetStart">  [in,out] If non-null, target start.</param>
	/// <param name="targetEnd">	[in,out] If non-null, target end.</param>
	/// <param name="ConvertEndian">true to convert endian.</param>
	/// <param name="flags">		The flags.</param>
	///
	/// <returns>The conversion error code.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	ConversionResult ConvertUTF32toUTF16(
		const UTF32** sourceStart, const UTF32* sourceEnd,
		UTF16** targetStart, UTF16* targetEnd, bool ConvertEndian, ConversionFlags flags);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Query if 'source' is legal UTF 8 sequence.</summary>
	///
	/// <param name="source">   Source for the check.</param>
	/// <param name="sourceEnd">Source end.</param>
	///
	/// <returns>true if legal UTF 8 sequence, false if not.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	Boolean isLegalUTF8Sequence(const UTF8 *source, const UTF8 *sourceEnd);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Computes the number of UTF16 characters are needed to hold the source string.</summary>
	///
	/// <param name="sourceStart">Source start.</param>
	/// <param name="sourceEnd">  Source end.</param>
	/// <param name="flags">	  The flags.</param>
	///
	/// <returns>the number of UTF16 characters that are needed.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	int32_t UTF8toUTF16Length(const UTF8* sourceStart, const UTF8* sourceEnd, ConversionFlags flags);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Computes the number of UTF8 characters are needed to hold the source string.</summary>
	///
	/// <param name="sourceStart">Source start.</param>
	/// <param name="sourceEnd">  Source end.</param>
	/// <param name="ConvertEndian">true to convert endian.</param>
	/// <param name="flags">	  The flags.</param>
	///
	/// <returns>the number of UTF16 characters that are needed.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	int32_t UTF16toUTF8Length(const UTF16* sourceStart, const UTF16* sourceEnd, bool ConvertEndian, ConversionFlags flags);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Computes the number of UTF32 characters are needed to hold the source string.</summary>
	///
	/// <param name="sourceStart">Source start.</param>
	/// <param name="sourceEnd">  Source end.</param>
	/// <param name="flags">	  The flags.</param>
	///
	/// <returns>the number of UTF16 characters that are needed.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	int32_t UTF8toUTF32Length(const UTF8* sourceStart, const UTF8* sourceEnd, ConversionFlags flags);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Computes the number of UTF8 characters are needed to hold the source string.</summary>
	///
	/// <param name="sourceStart">Source start.</param>
	/// <param name="sourceEnd">  Source end.</param>
	/// <param name="ConvertEndian">true to convert endian.</param>
	/// <param name="flags">	  The flags.</param>
	///
	/// <returns>the number of UTF16 characters that are needed.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	int32_t UTF32toUTF8Length(const UTF32* sourceStart, const UTF32* sourceEnd, bool ConvertEndian, ConversionFlags flags);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Computes the number of UTF32 characters are needed to hold the source string.</summary>
	///
	/// <param name="sourceStart">Source start.</param>
	/// <param name="sourceEnd">  Source end.</param>
	/// <param name="ConvertEndian">true to convert endian.</param>
	/// <param name="flags">	  The flags.</param>
	///
	/// <returns>the number of UTF16 characters that are needed.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	int32_t UTF16toUTF32Length(const UTF16* sourceStart, const UTF16* sourceEnd, bool ConvertEndian, ConversionFlags flags);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Computes the number of UTF16 characters are needed to hold the source string.</summary>
	///
	/// <param name="sourceStart">Source start.</param>
	/// <param name="sourceEnd">  Source end.</param>
	/// <param name="ConvertEndian">true to convert endian.</param>
	/// <param name="flags">	  The flags.</param>
	///
	/// <returns>the number of UTF16 characters that are needed.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	int32_t UTF32toUTF16Length(const UTF32* sourceStart, const UTF32* sourceEnd, bool ConvertEndian, ConversionFlags flags);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Returns the number of UTF32 characters in the UTF32 source string.</summary>
	///
	/// <param name="sourceStart">Source start.</param>
	///
	/// <returns>the number of UTF32 characters.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	int32_t UTF32Length(const UTF32* sourceStart);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Returns the number of UTF16 characters in the UTF16 source string.</summary>
	///
	/// <param name="sourceStart">Source start.</param>
	///
	/// <returns>the number of UTF16 characters.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	int32_t UTF16Length(const UTF16* sourceStart);

}

#endif // __CONVERT_UTF_H__

