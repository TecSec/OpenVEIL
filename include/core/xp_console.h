//	Copyright (c) 2016, TecSec, Inc.
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

/*! \file xp_console.h
 * <summary>Trace logging classes, functions and variables</summary>
 */
 
#ifndef __XP_CONSOLE_H__
#define __XP_CONSOLE_H__
 
#pragma once

class VEILCORE_API xp_console;

/// <summary>A specialized structure used in the stream operators to call a function with one parameter</summary>
template<class _Arg>
struct _TSConsolemanip
{	// store function pointer and argument value
	_TSConsolemanip(xp_console& (xp_console::*_Left)(_Arg), _Arg _Val)
		: _Pfun(_Left), _Manarg(_Val)
	{	// construct from function pointer and argument value
	}

	xp_console& (xp_console::*_Pfun)(_Arg);	// the function pointer
	_Arg _Manarg;	// the argument value
};

class VEILCORE_API xp_console
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

	xp_console();
	/// <summary>Destructor.</summary>
	~xp_console(void);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Stream insertion operator.</summary>
	///
	/// <param name="value">The value.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	xp_console &operator<< (const tscrypto::tsCryptoString &value);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Stream insertion operator.</summary>
	///
	/// <param name="value">The value.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	xp_console &operator<< (int16_t value);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Stream insertion operator.</summary>
	///
	/// <param name="value">The value.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	xp_console &operator<< (uint16_t value);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Stream insertion operator.</summary>
	///
	/// <param name="value">The value.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	xp_console &operator<< (uint8_t value);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Stream insertion operator.</summary>
	///
	/// <param name="value">The value.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	xp_console &operator<< (int32_t value);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Stream insertion operator.</summary>
	///
	/// <param name="value">The value.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	xp_console &operator<< (uint32_t value);
#ifdef _WIN32
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Stream insertion operator.</summary>
	///
	/// <param name="value">The value.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	xp_console &operator<< (long value);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Stream insertion operator.</summary>
	///
	/// <param name="value">The value.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	xp_console &operator<< (unsigned long value);
#endif
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Stream insertion operator.</summary>
	///
	/// <param name="value">The value.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	xp_console &operator<< (int8_t value);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Stream insertion operator.</summary>
	///
	/// <param name="value">The value.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	xp_console &operator<< (int64_t value);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Stream insertion operator.</summary>
	///
	/// <param name="value">The value.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	xp_console &operator<< (uint64_t value);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Stream insertion operator.</summary>
	///
	/// <param name="value">The value.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	xp_console &operator<< (double value);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Stream insertion operator.</summary>
	///
	/// <param name="value">The value.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	xp_console &operator<< (const tscrypto::tsCryptoData &value);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Stream insertion operator.</summary>
	///
	/// <param name="value">The value.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	//xp_console &operator<< (const wchar_t *value);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Stream insertion operator.</summary>
	///
	/// <param name="value">The value.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	xp_console &operator<< (const char *value);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Stream insertion operator.</summary>
	///
	/// <param name="_Pfn">Runs the specified function on this object</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual xp_console &operator<<(xp_console &(*_Pfn)(xp_console &obj));
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Stream insertion operator.</summary>
	///
	/// <param name="_Manip">Holds the function pointer and argument that is to be run.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	template <class _Arg>
	xp_console& operator<<(const _TSConsolemanip<_Arg>& _Manip)
	{
		(this->*_Manip._Pfun)(_Manip._Manarg);
		return *this;
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Increment the indentation level</summary>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual xp_console &indent();
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Decrements the indentation level</summary>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual xp_console &outdent();
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets a prefix string for the following line</summary>
	///
	/// <param name="prfx">The prefix string.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual xp_console &setPrefix(const tscrypto::tsCryptoString& prfx);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets float precision for the next stream operator.</summary>
	///
	/// <param name="left"> The number of digits to the left.</param>
	/// <param name="right">The number of digits to the right.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual xp_console &SetFloatPrecision(int left, int right);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the padding width for the next stream operator.</summary>
	///
	/// <param name="setTo">The width.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual xp_console &SetWidth(int setTo);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the filler character for the next stream operator</summary>
	///
	/// <param name="_filler">The filler.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual xp_console &SetFiller(char _filler);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the number base to use when converting the next integer using the stream
	/// 		 operator.</summary>
	///
	/// <param name="numbase">The base of the number (10, 16, ...).</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual xp_console &setbase(int numbase);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Set the number base to 16 for HEX output</summary>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual xp_console &hex() { return setbase(16); }
	virtual xp_console &Black();
	virtual xp_console &Red();
	virtual xp_console &Green();
	virtual xp_console &Yellow();
	virtual xp_console &Blue();
	virtual xp_console &Purple();
	virtual xp_console &Cyan();
	virtual xp_console &White();

	virtual xp_console &BoldBlack();
	virtual xp_console &BoldRed();
	virtual xp_console &BoldGreen();
	virtual xp_console &BoldYellow();
	virtual xp_console &BoldBlue();
	virtual xp_console &BoldPurple();
	virtual xp_console &BoldCyan();
	virtual xp_console &BoldWhite();

	virtual xp_console &Black_Background();
	virtual xp_console &Red_Background();
	virtual xp_console &Green_Background();
	virtual xp_console &Yellow_Background();
	virtual xp_console &Blue_Background();
	virtual xp_console &Purple_Background();
	virtual xp_console &Cyan_Background();
	virtual xp_console &White_Background();

	virtual size_t consoleWidth();
	virtual size_t consoleHeight();

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Set the number base to 10 for decimal output</summary>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual xp_console &dec() { return setbase(10); }
	//   ////////////////////////////////////////////////////////////////////////////////////////////////////
	//   /// <summary>Set the output formatting for pointers</summary>
	//   ///
	//   /// <returns>A reference to this object.</returns>
	//   ////////////////////////////////////////////////////////////////////////////////////////////////////
	//tsTraceStream &ptr() { setbase(16);SetFiller('0'); return SetWidth(sizeof(void*)); }
	//   ////////////////////////////////////////////////////////////////////////////////////////////////////
	//   /// <summary>Restores the output formatting for non-pointers</summary>
	//   ///
	//   /// <returns>A reference to this object.</returns>
	//   ////////////////////////////////////////////////////////////////////////////////////////////////////
	//tsTraceStream &noptr() { setbase(10);SetFiller(' '); return SetWidth(0); }
	virtual xp_console &ptr(const void *pointer);

	template <typename TODUMP>
	xp_console &hexDump(TODUMP& data)
	{
		tscrypto::tsCryptoData tmp(data);

		return hexDump(tmp);
	}

	xp_console &hexDump(tscrypto::tsCryptoData& data);
	void GetPin(tscrypto::tsCryptoString& enteredPin, uint32_t len, const tscrypto::tsCryptoString& prompt);

protected:
	int leftDoublePrecision;
	int rightDoublePrecision;
	bool justHadNewline;
	tscrypto::tsCryptoString prefix;
	int numberBase;
	int width;
	char filler;
	tscrypto::tsCryptoString _partialLine;
	int _indentLevel;
#ifdef _WIN32
	HANDLE hConsole;
	CONSOLE_SCREEN_BUFFER_INFO screenInfo;
	WORD _currentColor;
#endif

	void processData(tscrypto::tsCryptoString &data);
	void resetSingleOps();

	void HandleColorChange();
};

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A new line for the Trace logging class</summary>
///
/// <param name="strm">[in,out] The strm.</param>
///
/// <returns>A reference to this object.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
inline xp_console &endl(xp_console &strm)
{
	strm << "\n";
	return strm;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Helper function to indent the following lines in the log</summary>
///
/// <param name="strm">[in,out] The strm.</param>
///
/// <returns>A reference to this object.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
inline xp_console &indent(xp_console &strm)
{
	strm.indent();
	return strm;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Helper function to outdent the following lines in the log</summary>
///
/// <param name="strm">[in,out] The strm.</param>
///
/// <returns>A reference to this object.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
inline xp_console &outdent(xp_console &strm)
{
	strm.outdent();
	return strm;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Helper function to put the stream into HEX mode</summary>
///
/// <param name="strm">[in,out] The strm.</param>
///
/// <returns>A reference to this object.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
inline xp_console &hex(xp_console &strm)
{
	strm.hex();
	return strm;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Helper function to put the string into Decimal mode</summary>
///
/// <param name="strm">[in,out] The strm.</param>
///
/// <returns>A reference to this object.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
inline xp_console &dec(xp_console &strm)
{
	strm.dec();
	return strm;
}

inline xp_console &Black(xp_console &strm) { strm.Black(); return strm; }
inline xp_console &Red(xp_console &strm) { strm.Red(); return strm; }
inline xp_console &Green(xp_console &strm) { strm.Green(); return strm; }
inline xp_console &Yellow(xp_console &strm) { strm.Yellow(); return strm; }
inline xp_console &Blue(xp_console &strm) { strm.Blue(); return strm; }
inline xp_console &Purple(xp_console &strm) { strm.Purple(); return strm; }
inline xp_console &Cyan(xp_console &strm) { strm.Cyan(); return strm; }
inline xp_console &White(xp_console &strm) { strm.White(); return strm; }

inline xp_console &BoldBlack(xp_console &strm) { strm.BoldBlack(); return strm; }
inline xp_console &BoldRed(xp_console &strm) { strm.BoldRed(); return strm; }
inline xp_console &BoldGreen(xp_console &strm) { strm.BoldGreen(); return strm; }
inline xp_console &BoldYellow(xp_console &strm) { strm.BoldYellow(); return strm; }
inline xp_console &BoldBlue(xp_console &strm) { strm.BoldBlue(); return strm; }
inline xp_console &BoldPurple(xp_console &strm) { strm.BoldPurple(); return strm; }
inline xp_console &BoldCyan(xp_console &strm) { strm.BoldCyan(); return strm; }
inline xp_console &BoldWhite(xp_console &strm) { strm.BoldWhite(); return strm; }

inline xp_console &Black_Background(xp_console &strm) { strm.Black_Background(); return strm; }
inline xp_console &Red_Background(xp_console &strm) { strm.Red_Background(); return strm; }
inline xp_console &Green_Background(xp_console &strm) { strm.Green_Background(); return strm; }
inline xp_console &Yellow_Background(xp_console &strm) { strm.Yellow_Background(); return strm; }
inline xp_console &Blue_Background(xp_console &strm) { strm.Blue_Background(); return strm; }
inline xp_console &Purple_Background(xp_console &strm) { strm.Purple_Background(); return strm; }
inline xp_console &Cyan_Background(xp_console &strm) { strm.Cyan_Background(); return strm; }
inline xp_console &White_Background(xp_console &strm) { strm.White_Background(); return strm; }

namespace XP_Console {
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Helper function to set the number base for this stream</summary>
	///
	/// <param name="setTo">[in,out].</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	inline _TSConsolemanip<int> __cdecl width(int setTo)
	{
		return _TSConsolemanip<int>(&xp_console::SetWidth, setTo);
	}
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Helper function to set the number base for this stream</summary>
	///
	/// <param name="setTo">[in,out].</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	inline _TSConsolemanip<int> __cdecl setbase(int setTo)
	{
		return _TSConsolemanip<int>(&xp_console::setbase, setTo);
	}
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Helper function to set the filler character for this stream</summary>
	///
	/// <param name="setTo">[in,out].</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	inline _TSConsolemanip<char> __cdecl filler(char setTo)
	{
		return _TSConsolemanip<char>(&xp_console::SetFiller, setTo);
	}
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Helper function to set pointer mode</summary>
	///
	/// <param name="pointer">[in,out].</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	inline _TSConsolemanip<const void *> __cdecl ptr(const void *pointer)
	{
		return _TSConsolemanip<const void *>(&xp_console::ptr, pointer);
	}

	template <typename TODUMP>
	inline _TSConsolemanip<TODUMP &> __cdecl hexDump(TODUMP& data)
	{
		return _TSConsolemanip<TODUMP&>(&xp_console::hexDump, data);
	}
}

#endif // __XP_CONSOLE_H__

