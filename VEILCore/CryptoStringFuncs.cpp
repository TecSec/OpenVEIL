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

namespace tscrypto
{
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// \fn void TsVsnPrintf(TS_STRING buffer, size_t bufferLen,
	/// TS_CSTRING msg, va_list args)
	///
	/// \brief  Ts vsn printf.
	///
	/// \author Rogerb
	/// \date   12/4/2010
	///
	/// \param  buffer      The buffer.
	/// \param  bufferLen   Length of the buffer.
	/// \param  msg         The message.
	/// \param  args        The arguments.
	///
	/// \return .
	////////////////////////////////////////////////////////////////////////////////////////////////////

	void TsVsnPrintf(char * buffer, size_t bufferLen, const char * msg, va_list args)
	{
#if defined (_WIN32_WCE)
		_vsnprintf(buffer, bufferLen, msg, args);
#elif (defined(_MSC_VER) && defined(_WIN32)) || defined(MINGW)
		_vsnprintf_s(buffer, bufferLen, bufferLen, msg, args);
#else
		vsnprintf(buffer, bufferLen, msg, args);
#endif
	}
	void TsVsnPrintf(char * buffer, size_t bufferLen, const tsCryptoStringBase& msg, va_list args)
	{
		TsVsnPrintf(buffer, bufferLen, msg.c_str(), args);
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// \fn TS_CSTRING TsStrStr(TS_CSTRING a, TS_CSTRING b)
	///
	/// \brief  Ts string.
	///
	/// \author Rogerb
	/// \date   12/4/2010
	///
	/// \param  a   a.
	/// \param  b   The.
	///
	/// \return .
	////////////////////////////////////////////////////////////////////////////////////////////////////

	const char  *TsStrStr(const char * a, const char * b)
	{
#if defined (HAVE_STRSTR)
		return strstr(a, b);
#else
#error Implement me
#endif
	}

	const char *TsStrStr(const tsCryptoStringBase& a, const char * b)
	{
		return TsStrStr(a.c_str(), b);
	}
	const char *TsStrStr(const tsCryptoStringBase& a, const tsCryptoStringBase& b)
	{
		return TsStrStr(a.c_str(), b.c_str());
	}
	const char *TsStrStr(const char* a, const tsCryptoStringBase& b)
	{
		return TsStrStr(a, b.c_str());
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// \fn size_t TsStrLen(TS_CSTRING str)
	///
	/// \brief  Ts string length. Terminates at the first '/0'
	///
	/// \author Rogerb
	/// \date   12/4/2010
	///
	/// \param  str The string.
	///
	/// \return .
	////////////////////////////////////////////////////////////////////////////////////////////////////

	size_t TsStrLen(const char * str)
	{
#if defined (_WIN32_WCE)
		return strlen(str);
#elif (defined(_MSC_VER) && defined(_WIN32)) || defined(MINGW)
		return strlen(str);
#elif defined(linux)
		return strlen(str);
#else
		return strlen(str);
#endif
	}

	size_t TsStrLen(const tsCryptoStringBase& str)
	{
		return TsStrLen(str.c_str());
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// \fn int TsStrCmp(TS_CSTRING a, TS_CSTRING b)
	///
	/// \brief  Ts string compare.
	///
	/// \author Rogerb
	/// \date   12/4/2010
	///
	/// \param  a   a.
	/// \param  b   The.
	///
	/// \return .
	////////////////////////////////////////////////////////////////////////////////////////////////////

	int TsStrCmp(const char * a, const char * b)
	{
#if defined (_WIN32_WCE)
		return strcmp(a, b);
#elif (defined(_MSC_VER) && defined(_WIN32)) || defined(MINGW)
		return strcmp(a, b);
#elif defined(linux)
		return strcmp(a, b);
#else
		return strcmp(a, b);
#endif
	}
	int TsStrCmp(const tsCryptoStringBase& a, const char * b)
	{
		return TsStrCmp(a.c_str(), b);
	}
	int TsStrCmp(const tsCryptoStringBase& a, const tsCryptoStringBase& b)
	{
		return TsStrCmp(a.c_str(), b.c_str());
	}
	int TsStrCmp(const char* a, const tsCryptoStringBase& b)
	{
		return TsStrCmp(a, b.c_str());
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// \fn void TsSnPrintf(TS_STRING buffer, size_t bufferLen,
	/// TS_CSTRING msg, ...)
	///
	/// \brief  Ts serial number printf.
	///
	/// \author Rogerb
	/// \date   12/4/2010
	///
	/// \param  buffer      The buffer.
	/// \param  bufferLen   Length of the buffer.
	/// \param  msg         The message.
	///
	/// \return .
	////////////////////////////////////////////////////////////////////////////////////////////////////

	void TsSnPrintf(char * buffer, size_t bufferLen, const char * msg, ...)
	{
		va_list arg;

		va_start(arg, msg);
		TsVsnPrintf(buffer, bufferLen, msg, arg);
		va_end(arg);
	}

	void TsSnPrintf(char * buffer, size_t bufferLen, tsCryptoStringBase msg, ...)
	{
		va_list arg;

		va_start(arg, msg);
		TsVsnPrintf(buffer, bufferLen, msg, arg);
		va_end(arg);
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// \fn int TsStrnCmp(TS_CSTRING a, TS_CSTRING b, size_t n)
	///
	/// \brief  Ts strn compare.
	///
	/// \author Rogerb
	/// \date   12/4/2010
	///
	/// \param  a   a.
	/// \param  b   The.
	/// \param  n   The.
	///
	/// \return .
	////////////////////////////////////////////////////////////////////////////////////////////////////

	int TsStrnCmp(const char * a, const char * b, size_t n)
	{
#if defined (_WIN32_WCE)
		return strncmp(a, b, n);
#elif (defined(_MSC_VER) && defined(_WIN32)) || defined(MINGW)
		return strncmp(a, b, n);
#elif defined(linux)
		return strncmp(a, b, n);
#else
		return strncmp(a, b, n);
#endif
	}
	int TsStrnCmp(const tsCryptoStringBase& a, const char * b, size_t n)
	{
		return TsStrnCmp(a.c_str(), b, n);
	}

	int TsStrnCmp(const tsCryptoStringBase& a, const tsCryptoStringBase& b, size_t n)
	{
		return TsStrnCmp(a.c_str(), b.c_str(), n);
	}

	int TsStrnCmp(const char * a, const tsCryptoStringBase& b, size_t n)
	{
		return TsStrnCmp(a, b.c_str(), n);
	}


	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// \fn TS_CSTRING TsStrChr(TS_CSTRING str, TS_CHAR c)
	///
	/// \brief  Ts string character.
	///
	/// \author Rogerb
	/// \date   12/4/2010
	///
	/// \param  str The string.
	/// \param  c   The.
	///
	/// \return .
	////////////////////////////////////////////////////////////////////////////////////////////////////

	char *TsStrChr(char *str, char c)
	{
#if defined (_WIN32_WCE)
		return strchr(str, c);
#elif (defined(_MSC_VER) && defined(_WIN32)) || defined(MINGW)
		return strchr(str, c);
#elif defined(linux)
		return strchr(str, c);
#else
		return strchr(str, c);
#endif
	}


	const char *TsStrChr(const char *str, char c)
	{
#if defined (_WIN32_WCE)
		return strchr(str, c);
#elif (defined(_MSC_VER) && defined(_WIN32)) || defined(MINGW)
		return strchr(str, c);
#elif defined(linux)
		return strchr(str, c);
#else
		return strchr(str, c);
#endif
	}

	const char *TsStrChr(const tsCryptoStringBase& str, char c)
	{
		return TsStrChr(str.c_str(), c);
	}

	char *TsStrChr(tsCryptoStringBase& str, char c)
	{
		return TsStrChr(str.rawData(), c);
	}


	char *TsStrrChr(char *str, char c)
	{
#if defined (_WIN32_WCE)
		return strrchr(str, c);
#elif (defined(_MSC_VER) && defined(_WIN32)) || defined(MINGW)
		return strrchr(str, c);
#elif defined(linux)
		return strrchr(str, c);
#else
		return strrchr(str, c);
#endif
	}


	const char *TsStrrChr(const char *str, char c)
	{
#if defined (_WIN32_WCE)
		return strrchr(str, c);
#elif (defined(_MSC_VER) && defined(_WIN32)) || defined(MINGW)
		return strrchr(str, c);
#elif defined(linux)
		return strrchr(str, c);
#else
		return strrchr(str, c);
#endif
	}

	const char *TsStrrChr(const tsCryptoStringBase& str, char c)
	{
		return TsStrrChr(str.c_str(), c);
	}

	char *TsStrrChr(tsCryptoStringBase& str, char c)
	{
		return TsStrrChr(str.rawData(), c);
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// \fn int TsStriCmp(TS_CSTRING a, TS_CSTRING b)
	///
	/// \brief  Ts stri compare.
	///
	/// \author Rogerb
	/// \date   12/4/2010
	///
	/// \param  a   a.
	/// \param  b   The.
	///
	/// \return .
	////////////////////////////////////////////////////////////////////////////////////////////////////

	int TsStriCmp(const char * a, const char * b)
	{
#if defined (HAVE__STRICMP)
		return _stricmp(a, b);
#elif defined(HAVE__STRCASECMP)
		return _strcasecmp(a, b);
#elif defined(HAVE_STRCASECMP)
		return strcasecmp(a, b);
#elif defined(HAVE_STRICMP)
		return stricmp(a, b);
#else
#error Implement me
#endif
	}

	int TsStriCmp(const tsCryptoStringBase& a, const tsCryptoStringBase& b)
	{
		return TsStriCmp(a.c_str(), b.c_str());
	}

	int TsStriCmp(const char* a, const tsCryptoStringBase& b)
	{
		return TsStriCmp(a, b.c_str());
	}

	int TsStriCmp(const tsCryptoStringBase& a, const char* b)
	{
		return TsStriCmp(a.c_str(), b);
	}


	int TsStrniCmp(const char * a, const char * b, int len)
	{
#if defined (HAVE__STRNICMP)
		return _strnicmp(a, b, len);
#elif defined(HAVE__STRNCASECMP)
		return _strncasecmp(a, b, len);
#elif defined(HAVE_STRNCASECMP)
		return strncasecmp(a, b, len);
#elif defined(HAVE_STRNICMP)
		return strnicmp(a, b, len);
#else
#error Implement me
#endif
	}

	int TsStrniCmp(const tsCryptoStringBase& a, const tsCryptoStringBase& b, int len)
	{
		return TsStrniCmp(a.c_str(), b.c_str(), len);
	}

	int TsStrniCmp(const tsCryptoStringBase& a, const char* b, int len)
	{
		return TsStrniCmp(a.c_str(), b, len);
	}

	int TsStrniCmp(const char* a, const tsCryptoStringBase& b, int len)
	{
		return TsStrniCmp(a, b.c_str(), len);
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// \fn void TsStrCpy(TS_STRING outBuff, size_t outBuffLen,
	/// TS_CSTRING inBuff)
	///
	/// \brief  Ts string copy.
	///
	/// \author Rogerb
	/// \date   12/4/2010
	///
	/// \param  outBuff     Buffer for out data.
	/// \param  outBuffLen  Length of the out buffer.
	/// \param  inBuff      Buffer for in data.
	///
	/// \return .
	////////////////////////////////////////////////////////////////////////////////////////////////////

	void TsStrCpy(char * outBuff, size_t outBuffLen, const char * inBuff)
	{
#if defined (_WIN32_WCE)
		strcpy_s(outBuff, outBuffLen, inBuff);
#elif (defined(_MSC_VER) && defined(_WIN32)) || defined(MINGW)
		strcpy_s(outBuff, outBuffLen, inBuff);
#elif defined(linux)
		strcpy(outBuff, inBuff);
#else
		strcpy(outBuff, inBuff);
#endif
	}
	void            TsStrCpy(tsCryptoStringBase& outBuff, const char * inBuff)
	{
		outBuff = inBuff;
	}

	void            TsStrCpy(tsCryptoStringBase& outBuff, const tsCryptoStringBase& inBuff)
	{
		outBuff = inBuff;
	}

	void            TsStrCpy(char * outBuff, size_t outBuffLen, const tsCryptoStringBase& inBuff)
	{
#if defined (_WIN32_WCE)
		strcpy_s(outBuff, outBuffLen, inBuff.c_str());
#elif (defined(_MSC_VER) && defined(_WIN32)) || defined(MINGW)
		strcpy_s(outBuff, outBuffLen, inBuff.c_str());
#elif defined(linux)
		strcpy(outBuff, inBuff.c_str());
#else
		strcpy(outBuff, inBuff.c_str());
#endif
	}
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// \fn void TsStrCat(TS_STRING outBuff, size_t outBuffLen,
	/// TS_CSTRING inBuff)
	///
	/// \brief  Ts string category.
	///
	/// \author Rogerb
	/// \date   12/4/2010
	///
	/// \param  outBuff     Buffer for out data.
	/// \param  outBuffLen  Length of the out buffer.
	/// \param  inBuff      Buffer for in data.
	///
	/// \return .
	////////////////////////////////////////////////////////////////////////////////////////////////////

	void TsStrCat(char * outBuff, size_t outBuffLen, const char * inBuff)
	{
#if defined (_WIN32_WCE)
		strcat(outBuff, inBuff);
#elif (defined(_MSC_VER) && defined(_WIN32)) || defined(MINGW)
		strcat_s(outBuff, outBuffLen, inBuff);
#elif defined(linux)
		strcat(outBuff, inBuff);
#else
		strcat(outBuff, inBuff);
#endif
	}

	void TsStrCat(char * outBuff, size_t outBuffLen, const tsCryptoStringBase& inBuff)
	{
		TsStrCat(outBuff, outBuffLen, inBuff.c_str());
	}

	void            TsStrCat(tsCryptoStringBase& outBuff, const tsCryptoStringBase& inBuff)
	{
		outBuff += inBuff;
	}

	void            TsStrCat(tsCryptoStringBase& outBuff, const char* inBuff)
	{
		outBuff += inBuff;
	}


	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// \fn void TsStrnCpy(TS_STRING outBuff, size_t outBuffLen,
	/// TS_CSTRING inBuff, size_t bytes)
	///
	/// \brief  Ts strn copy.
	///
	/// \author Rogerb
	/// \date   12/4/2010
	///
	/// \param  outBuff     Buffer for out data.
	/// \param  outBuffLen  Length of the out buffer.
	/// \param  inBuff      Buffer for in data.
	/// \param  bytes       The bytes.
	///
	/// \return .
	////////////////////////////////////////////////////////////////////////////////////////////////////

	void TsStrnCpy(char * outBuff, size_t outBuffLen, const char * inBuff, size_t bytes)
	{
#if defined (_WIN32_WCE)
		strncpy(outBuff, inBuff, bytes);
#elif (defined(_MSC_VER) && defined(_WIN32)) || defined(MINGW)
		strncpy_s(outBuff, outBuffLen, inBuff, bytes);
#elif defined(linux)
		strncpy(outBuff, inBuff, bytes);
#else
		strncpy(outBuff, inBuff, bytes);
#endif
	}
	void            TsStrnCpy(tsCryptoStringBase& outBuff, const char * inBuff, size_t bytes)
	{
		outBuff = inBuff;
		if (outBuff.size() > bytes)
			outBuff.resize(bytes);
	}

	void            TsStrnCpy(tsCryptoStringBase& outBuff, const tsCryptoStringBase& inBuff, size_t bytes)
	{
		outBuff = inBuff;
		if (outBuff.size() > bytes)
			outBuff.resize(bytes);
	}

	void            TsStrnCpy(char * outBuff, size_t outBuffLen, const tsCryptoStringBase& inBuff, size_t bytes)
	{
		TsStrnCpy(outBuff, outBuffLen, inBuff.c_str(), bytes);
	}


	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// \fn int TsStrToInt(TS_CSTRING str)
	///
	/// \brief  Ts string to int.
	///
	/// \author Rogerb
	/// \date   12/4/2010
	///
	/// \param  str The string.
	///
	/// \return .
	////////////////////////////////////////////////////////////////////////////////////////////////////

	int TsStrToInt(const char * str)
	{
#if defined (_WIN32_WCE)
		return atoi(str);
#elif (defined(_MSC_VER) && defined(_WIN32)) || defined(MINGW)
		return atoi(str);
#elif defined(linux)
		return atoi(str);
#else
		return atoi(str);
#endif
	}
	int TsStrToInt(const tsCryptoStringBase& str)
	{
		return TsStrToInt(str.c_str());
	}

	long TsStrToLong(const char * str)
	{
#if defined (_WIN32_WCE)
		return atol(str);
#elif (defined(_MSC_VER) && defined(_WIN32)) || defined(MINGW)
		return atol(str);
#elif defined(linux)
		return atol(str);
#else
		return atol(str);
#endif
	}

	long TsStrToLong(const tsCryptoStringBase& str)
	{
		return TsStrToLong(str.c_str());
	}

	double TsStrToDouble(const char * str)
	{
#if defined (_WIN32_WCE)
		return atof(str);
#elif (defined(_MSC_VER) && defined(_WIN32)) || defined(MINGW)
		return atof(str);
#elif defined(linux)
		return atof(str);
#else
		return atof(str);
#endif
	}
	double TsStrToDouble(const tsCryptoStringBase& str)
	{
		return TsStrToDouble(str.c_str());
	}

	int64_t         TsStrToInt64(const char * str)
	{
#if defined (HAVE__ATOI64)
		return _atoi64(str);
#elif defined(HAVE_ATOLL)
		return atoll(str);
#elif defined(HAVE_ATOQ)
		return atoq(str);
#else
#error Implement me
#endif
	}

	int64_t         TsStrToInt64(const tsCryptoStringBase& str)
	{
		return TsStrToInt64(str.c_str());
	}



	char *      TsStrTok(char *src, const char * tokens, char **context)
	{
		return strtok_s(src, tokens, context);
	}
	char *      TsStrTok(tsCryptoStringBase& src, const char * tokens, char **context)
	{
		return strtok_s(src.rawData(), tokens, context);
	}
	char *      TsStrTok(tsCryptoStringBase& src, const tsCryptoStringBase& tokens, char **context)
	{
		return strtok_s(src.rawData(), tokens.c_str(), context);
	}
	char *      TsStrTok(char *src, const tsCryptoStringBase& tokens, char **context)
	{
		return strtok_s(src, tokens.c_str(), context);
	}

}