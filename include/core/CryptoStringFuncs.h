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

////////////////////////////////////////////////////////////////////////////////////////////////////
/// \file   cryptostringFuncs.h
///
/// \brief  Declares the string funcs class.
////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef __CRYPTOSTRINGFUNCS_H__
#define __CRYPTOSTRINGFUNCS_H__

#pragma once

namespace tscrypto {
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>generic printf function for character strings into a buffer</summary>
	///
	/// <param name="buffer">   [in,out] If non-null, the buffer using a va_list.</param>
	/// <param name="bufferLen">Length of the buffer.</param>
	/// <param name="msg">		The message.</param>
	/// <param name="args">		The arguments.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void            VEILCORE_API TsVsnPrintf(char * buffer, size_t bufferLen, const char * msg, va_list args);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>generic printf function for character strings into a buffer</summary>
	///
	/// <param name="buffer">   [in,out] If non-null, the buffer using a va_list.</param>
	/// <param name="bufferLen">Length of the buffer.</param>
	/// <param name="msg">		The message.</param>
	/// <param name="args">		The arguments.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void            VEILCORE_API TsVsnPrintf(char * buffer, size_t bufferLen, const tsCryptoStringBase& msg, va_list args);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Function to search for a string in a string using Ascii characters</summary>
	///
	/// <param name="a">the string to search</param>
	/// <param name="b">the string to search for</param>
	///
	/// <returns>null if the string does not exist, otherwise a pointer to the first character of the first occurance</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	const char         VEILCORE_API *TsStrStr(const char * a, const char * b);


	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Function to search for a string in a string using Ascii characters</summary>
	///
	/// <param name="a">the string to search</param>
	/// <param name="b">the string to search for</param>
	///
	/// <returns>null if the string does not exist, otherwise a pointer to the first character of the first occurance</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	const char         VEILCORE_API *TsStrStr(const tsCryptoStringBase& a, const char * b);
	const char         VEILCORE_API *TsStrStr(const tsCryptoStringBase& a, const tsCryptoStringBase& b);
	const char         VEILCORE_API *TsStrStr(const char * a, const tsCryptoStringBase& b);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Find the next token in an ascii string</summary>
	///
	/// <param name="src">	  [in] If non-null, the string to start the search, otherwise NULL to continue processing the prior string</param>
	/// <param name="tokens"> The token separator characters</param>
	/// <param name="context">[in,out] The parse context</param>
	///
	/// <returns>null if no data left to process, else the beginning of the token</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	char VEILCORE_API *      TsStrTok(char *src, const char * tokens, char **context);
	char VEILCORE_API *      TsStrTok(tsCryptoStringBase& src, const char * tokens, char **context);
	char VEILCORE_API *      TsStrTok(tsCryptoStringBase& src, const tsCryptoStringBase& tokens, char **context);
	char VEILCORE_API *      TsStrTok(char* src, const tsCryptoStringBase& tokens, char **context);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>returns the length of the ascii string. Terminates at the first '/0'</summary>
	///
	/// <param name="str">The string to read</param>
	///
	/// <returns>the length in characters of the ascii string</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	size_t   VEILCORE_API TsStrLen(const char * str);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>returns the length of the ascii string. Terminates at the first '/0'</summary>
	///
	/// <param name="str">The string to read</param>
	///
	/// <returns>the length in characters of the ascii string</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	size_t   VEILCORE_API TsStrLen(const tsCryptoStringBase& str);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Compare two ascii strings</summary>
	///
	/// <param name="a">the left string</param>
	/// <param name="b">the right string</param>
	///
	/// <returns>negative if the left is less than the right, 0 if they are the same, otherwise positive</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	int             VEILCORE_API TsStrCmp(const char * a, const char * b);


	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Compare two ascii strings</summary>
	///
	/// <param name="a">the left string</param>
	/// <param name="b">the right string</param>
	///
	/// <returns>negative if the left is less than the right, 0 if they are the same, otherwise positive</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	int             VEILCORE_API TsStrCmp(const tsCryptoStringBase& a, const char * b);


	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Compare two ascii strings</summary>
	///
	/// <param name="a">the left string</param>
	/// <param name="b">the right string</param>
	///
	/// <returns>negative if the left is less than the right, 0 if they are the same, otherwise positive</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	int             VEILCORE_API TsStrCmp(const tsCryptoStringBase& a, const tsCryptoStringBase& b);
	int             VEILCORE_API TsStrCmp(const char* a, const tsCryptoStringBase& b);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>printf into an ascii string using the passed in arguments</summary>
	///
	/// <param name="buffer">   The buffer that will receive the result</param>
	/// <param name="bufferLen">Length of the buffer.</param>
	/// <param name="msg">		The message.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void            VEILCORE_API TsSnPrintf(char * buffer, size_t bufferLen, const char * msg, ...);
	void            VEILCORE_API TsSnPrintf(char * buffer, size_t bufferLen, tsCryptoStringBase msg, ...);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>fixed length ascii string compare</summary>
	///
	/// <param name="a">left string </param>
	/// <param name="b">right string</param>
	/// <param name="n">the maximum length to compare</param>
	///
	/// <returns>negative if the left is less than the right, 0 if they are the same, otherwise positive</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	int             VEILCORE_API TsStrnCmp(const char * a, const char * b, size_t n);
	int             VEILCORE_API TsStrnCmp(const tsCryptoStringBase& a, const char * b, size_t n);
	int             VEILCORE_API TsStrnCmp(const tsCryptoStringBase& a, const tsCryptoStringBase& b, size_t n);
	int             VEILCORE_API TsStrnCmp(const char * a, const tsCryptoStringBase& b, size_t n);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>search an ascii string for the first occurance of the indicated character</summary>
	///
	/// <param name="str">The string to search</param>
	/// <param name="c">  The search character</param>
	///
	/// <returns>null if the character is not in the string, otherwise the address of the first occurance
	/// 		 of the character in the string is returned</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	char      VEILCORE_API *TsStrChr(char *str, char c);


	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>search an ascii string for the first occurance of the indicated character</summary>
	///
	/// <param name="str">The string to search</param>
	/// <param name="c">  The search character</param>
	///
	/// <returns>null if the character is not in the string, otherwise the address of the first occurance
	/// 		 of the character in the string is returned</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	const char      VEILCORE_API *TsStrChr(const char *str, char c);


	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>search an ascii string for the first occurance of the indicated character</summary>
	///
	/// <param name="str">The string to search</param>
	/// <param name="c">  The search character</param>
	///
	/// <returns>null if the character is not in the string, otherwise the address of the first occurance
	/// 		 of the character in the string is returned</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	const char      VEILCORE_API *TsStrChr(const tsCryptoStringBase& str, char c);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>search an ascii string for the first occurance of the indicated character</summary>
	///
	/// <param name="str">The string to search</param>
	/// <param name="c">  The search character</param>
	///
	/// <returns>null if the character is not in the string, otherwise the address of the first occurance
	/// 		 of the character in the string is returned</returns>
	char      VEILCORE_API *TsStrChr(tsCryptoStringBase& str, char c);
	////////////////////////////////////////////////////////////////////////////////////////////////////

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>search an ascii string for the last occurance of the indicated character</summary>
	///
	/// <param name="str">The string to search</param>
	/// <param name="c">  The search character</param>
	///
	/// <returns>null if the character is not in the string, otherwise the address of the last occurance
	/// 		 of the character in the string is returned</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	char      VEILCORE_API *TsStrrChr(char *str, char c);


	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>search an ascii string for the last occurance of the indicated character</summary>
	///
	/// <param name="str">The string to search</param>
	/// <param name="c">  The search character</param>
	///
	/// <returns>null if the character is not in the string, otherwise the address of the last occurance
	/// 		 of the character in the string is returned</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	const char      VEILCORE_API *TsStrrChr(const char *str, char c);


	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>search an ascii string for the last occurance of the indicated character</summary>
	///
	/// <param name="str">The string to search</param>
	/// <param name="c">  The search character</param>
	///
	/// <returns>null if the character is not in the string, otherwise the address of the last occurance
	/// 		 of the character in the string is returned</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	const char      VEILCORE_API *TsStrrChr(const tsCryptoStringBase& str, char c);


	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>search an ascii string for the last occurance of the indicated character</summary>
	///
	/// <param name="str">The string to search</param>
	/// <param name="c">  The search character</param>
	///
	/// <returns>null if the character is not in the string, otherwise the address of the last occurance
	/// 		 of the character in the string is returned</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	char      VEILCORE_API *TsStrrChr(tsCryptoStringBase& str, char c);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>case insensitive string compare for unicode strings that is limited in length</summary>
	///
	/// <param name="a">  the left string</param>
	/// <param name="b">  the right string</param>
	/// <param name="len">the maximum length (in characters) of the strings to compare</param>
	///
	/// <returns>negative if the left is less than the right, 0 if they are the same, otherwise positive</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	int             VEILCORE_API TsStrniCmp(const tsCryptoStringBase& a, const char * b, int len);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>case insensitive string compare for unicode strings that is limited in length</summary>
	///
	/// <param name="a">  the left string</param>
	/// <param name="b">  the right string</param>
	/// <param name="len">the maximum length (in characters) of the strings to compare</param>
	///
	/// <returns>negative if the left is less than the right, 0 if they are the same, otherwise positive</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	int             VEILCORE_API TsStrniCmp(const char * a, const tsCryptoStringBase& b, int len);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>case insensitive string compare for unicode strings that is limited in length</summary>
	///
	/// <param name="a">  the left string</param>
	/// <param name="b">  the right string</param>
	/// <param name="len">the maximum length (in characters) of the strings to compare</param>
	///
	/// <returns>negative if the left is less than the right, 0 if they are the same, otherwise positive</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	int             VEILCORE_API TsStrniCmp(const tsCryptoStringBase& a, const tsCryptoStringBase& b, int len);


	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>case insensitive string compare for ascii strings</summary>
	///
	/// <param name="a">the left string</param>
	/// <param name="b">the right string</param>
	///
	/// <returns>negative if the left is less than the right, 0 if they are the same, otherwise positive</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	int             VEILCORE_API TsStriCmp(const char * a, const char * b);


	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>case insensitive string compare for ascii strings that is limited in length</summary>
	///
	/// <param name="a">  the left string</param>
	/// <param name="b">  the right string</param>
	/// <param name="len">the maximum length (in characters) of the strings to compare</param>
	///
	/// <returns>negative if the left is less than the right, 0 if they are the same, otherwise positive</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	int             VEILCORE_API TsStrniCmp(const char * a, const char * b, int len);


	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>case insensitive string compare for ascii strings</summary>
	///
	/// <param name="a">the left string</param>
	/// <param name="b">the right string</param>
	///
	/// <returns>negative if the left is less than the right, 0 if they are the same, otherwise positive</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	int             VEILCORE_API TsStriCmp(const tsCryptoStringBase& a, const tsCryptoStringBase& b);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>case insensitive string compare for ascii strings</summary>
	///
	/// <param name="a">the left string</param>
	/// <param name="b">the right string</param>
	///
	/// <returns>negative if the left is less than the right, 0 if they are the same, otherwise positive</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	int             VEILCORE_API TsStriCmp(const char* a, const tsCryptoStringBase& b);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>case insensitive string compare for ascii strings</summary>
	///
	/// <param name="a">the left string</param>
	/// <param name="b">the right string</param>
	///
	/// <returns>negative if the left is less than the right, 0 if they are the same, otherwise positive</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	int             VEILCORE_API TsStriCmp(const tsCryptoStringBase& a, const char* b);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>copies one ascii string into another</summary>
	///
	/// <param name="outBuff">   string buffer that is the destination of the copy</param>
	/// <param name="outBuffLen">the length of the output buffer in characters</param>
	/// <param name="inBuff">	 the source string to copy</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void            VEILCORE_API TsStrCpy(char * outBuff, size_t outBuffLen, const char * inBuff);
	void            VEILCORE_API TsStrCpy(tsCryptoStringBase& outBuff, const char * inBuff);
	void            VEILCORE_API TsStrCpy(tsCryptoStringBase& outBuff, const tsCryptoStringBase& inBuff);
	void            VEILCORE_API TsStrCpy(char * outBuff, size_t outBuffLen, const tsCryptoStringBase& inBuff);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>concatenate one ascii string to another</summary>
	///
	/// <param name="outBuff">   string buffer that is the destination of the concatenation</param>
	/// <param name="outBuffLen">the length of the output buffer in characters</param>
	/// <param name="inBuff">	 the source string to concatenate</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void            VEILCORE_API TsStrCat(char * outBuff, size_t outBuffLen, const char * inBuff);


	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>concatenate one ascii string to another</summary>
	///
	/// <param name="outBuff">   string buffer that is the destination of the concatenation</param>
	/// <param name="outBuffLen">the length of the output buffer in characters</param>
	/// <param name="inBuff">	 the source string to concatenate</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void            VEILCORE_API TsStrCat(char * outBuff, size_t outBuffLen, const tsCryptoStringBase& inBuff);
	void            VEILCORE_API TsStrCat(tsCryptoStringBase& outBuff, const tsCryptoStringBase& inBuff);
	void            VEILCORE_API TsStrCat(tsCryptoStringBase& outBuff, const char* inBuff);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>copy one ascii string to another buffer while limiting the number of characters</summary>
	///
	/// <param name="outBuff">   string buffer that is the destination of the concatenation</param>
	/// <param name="outBuffLen">the length of the output buffer in characters</param>
	/// <param name="inBuff">	 the source string to concatenate</param>
	/// <param name="bytes">	 the maximum number of characters to copy</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	void            VEILCORE_API TsStrnCpy(char * outBuff, size_t outBuffLen, const char * inBuff, size_t bytes);
	void            VEILCORE_API TsStrnCpy(tsCryptoStringBase& outBuff, const char * inBuff, size_t bytes);
	void            VEILCORE_API TsStrnCpy(tsCryptoStringBase& outBuff, const tsCryptoStringBase& inBuff, size_t bytes);
	void            VEILCORE_API TsStrnCpy(char * outBuff, size_t outBuffLen, const tsCryptoStringBase& inBuff, size_t bytes);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Convert a base 10 ascii string to an int</summary>
	///
	/// <param name="str">The base 10 ascii string</param>
	///
	/// <returns>the integer value</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	int             VEILCORE_API TsStrToInt(const char * str);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Convert a base 10 ascii string to an int</summary>
	///
	/// <param name="str">The base 10 ascii string</param>
	///
	/// <returns>the integer value</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	int             VEILCORE_API TsStrToInt(const tsCryptoStringBase& str);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Convert a base 10 ascii string to a long</summary>
	///
	/// <param name="str">The base 10 ascii string</param>
	///
	/// <returns>the long integer value</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	long            VEILCORE_API TsStrToLong(const char * str);
	/**
	 * \brief Ts string to long.
	 *
	 * \param str The.
	 *
	 * \return A VEILCORE_API.
	 */
	long            VEILCORE_API TsStrToLong(const tsCryptoStringBase& str);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Convert a base 10 ascii string to a double</summary>
	///
	/// <param name="str">The base 10 ascii string</param>
	///
	/// <returns>the double value</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	double          VEILCORE_API TsStrToDouble(const char * str);


	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Convert a base 10 ascii string to a double</summary>
	///
	/// <param name="str">The base 10 ascii string</param>
	///
	/// <returns>the double value</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	double          VEILCORE_API TsStrToDouble(const tsCryptoStringBase& str);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Convert a base 10 ascii string to a 64 bit integer</summary>
	///
	/// <param name="str">The base 10 ascii string</param>
	///
	/// <returns>the 64 bit integer value</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	int64_t         VEILCORE_API TsStrToInt64(const char * str);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Convert a base 10 ascii string to a 64 bit integer</summary>
	///
	/// <param name="str">The base 10 ascii string</param>
	///
	/// <returns>the 64 bit integer value</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	int64_t         VEILCORE_API TsStrToInt64(const tsCryptoStringBase& str);


}
#endif //__CRYPTOSTRINGFUNCS_H__
