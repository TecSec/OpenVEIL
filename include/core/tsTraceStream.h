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

/*! \file tsTraceStream.h
 * <summary>Trace logging classes, functions and variables</summary>
 */
 #ifndef __TSTRACESTREAM_H__
 #define __TSTRACESTREAM_H__
 
#pragma once


/// <summary>A macro that defines category audit information.</summary>
#define CAT_AUDIT_INFO    "Info"
/// <summary>A macro that defines category audit success.</summary>
#define CAT_AUDIT_SUCCESS "Success"
/// <summary>A macro that defines category audit warning.</summary>
#define CAT_AUDIT_WARN    "Warning"
/// <summary>A macro that defines category audit failure.</summary>
#define CAT_AUDIT_FAIL    "Fail"

/// <summary>A macro that defines category debug.</summary>
#define CAT_DEBUG "Debug"
/// <summary>A macro that defines category error.</summary>
#define CAT_ERROR "Error"
/// <summary>A macro that defines category development.</summary>
#define CAT_DEV   "Dev"

#define NEWLINE endl

#define LOG(logger,...) {if (logger.WillLog()){ tscrypto::tsCryptoString ___tmp; ___tmp << __VA_ARGS__ << tscrypto::endl; logger << ___tmp; }}
#define LOGD(logger,...) {if (logger.WillLog()){ logger << __VA_ARGS__; }}

class VEILCORE_API tsTraceStream;

/// <summary>A specialized structure used in the stream operators to call a function with one parameter</summary>
template<class _Arg>
	struct _TSTracemanip
	{	// store function pointer and argument value
		_TSTracemanip(tsTraceStream& (tsTraceStream::*_Left)(_Arg), _Arg _Val)
		: _Pfun(_Left), _Manarg(_Val)
		{	// construct from function pointer and argument value
		}

	tsTraceStream& (tsTraceStream::*_Pfun)(_Arg);	// the function pointer
	_Arg _Manarg;	// the argument value
	};

/// <summary>The core class used to create Trace logs</summary>
	class VEILCORE_API tsTraceStream
{
public:
    /**
     * \brief Constructor.
     *
     * \param name  true to link to master loggers.
     * \param level The Trace level for this stream.
     */
    tsTraceStream(const tscrypto::tsCryptoStringBase& name, int level);
    /// <summary>Destructor.</summary>
    ~tsTraceStream(void);

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
    /// <summary>Stream insertion operator.</summary>
    ///
    /// <param name="value">The value.</param>
    ///
    /// <returns>A reference to this object.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    tsTraceStream &operator<< (const tscrypto::tsCryptoStringBase &value);
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Stream insertion operator.</summary>
    ///
    /// <param name="value">The value.</param>
    ///
    /// <returns>A reference to this object.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    tsTraceStream &operator<< (int16_t value);
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Stream insertion operator.</summary>
    ///
    /// <param name="value">The value.</param>
    ///
    /// <returns>A reference to this object.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    tsTraceStream &operator<< (uint16_t value);
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Stream insertion operator.</summary>
    ///
    /// <param name="value">The value.</param>
    ///
    /// <returns>A reference to this object.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    tsTraceStream &operator<< (uint8_t value);
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Stream insertion operator.</summary>
    ///
    /// <param name="value">The value.</param>
    ///
    /// <returns>A reference to this object.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    tsTraceStream &operator<< (int32_t value);
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Stream insertion operator.</summary>
    ///
    /// <param name="value">The value.</param>
    ///
    /// <returns>A reference to this object.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    tsTraceStream &operator<< (uint32_t value);
#ifdef _WIN32
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Stream insertion operator.</summary>
	///
	/// <param name="value">The value.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsTraceStream &operator<< (long value);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Stream insertion operator.</summary>
	///
	/// <param name="value">The value.</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	tsTraceStream &operator<< (unsigned long value);
#endif
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Stream insertion operator.</summary>
    ///
    /// <param name="value">The value.</param>
    ///
    /// <returns>A reference to this object.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    tsTraceStream &operator<< (int8_t value);
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Stream insertion operator.</summary>
    ///
    /// <param name="value">The value.</param>
    ///
    /// <returns>A reference to this object.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    tsTraceStream &operator<< (int64_t value);
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Stream insertion operator.</summary>
    ///
    /// <param name="value">The value.</param>
    ///
    /// <returns>A reference to this object.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    tsTraceStream &operator<< (uint64_t value);
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Stream insertion operator.</summary>
    ///
    /// <param name="value">The value.</param>
    ///
    /// <returns>A reference to this object.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    tsTraceStream &operator<< (double value);
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Stream insertion operator.</summary>
    ///
    /// <param name="value">The value.</param>
    ///
    /// <returns>A reference to this object.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    tsTraceStream &operator<< (const tscrypto::tsCryptoData &value);
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Stream insertion operator.</summary>
    ///
    /// <param name="value">The value.</param>
    ///
    /// <returns>A reference to this object.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    //tsTraceStream &operator<< (const wchar_t *value);
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Stream insertion operator.</summary>
    ///
    /// <param name="value">The value.</param>
    ///
    /// <returns>A reference to this object.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	tsTraceStream &operator<< (const char *value);
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    ///// <summary>Stream insertion operator.</summary>
    /////
    ///// <param name="value">The value.</param>
    /////
    ///// <returns>A reference to this object.</returns>
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    //tsTraceStream &operator<< (void *value);
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    ///// <summary>Stream insertion operator.</summary>
    /////
    ///// <param name="value">The value.</param>
    /////
    ///// <returns>A reference to this object.</returns>
    //////////////////////////////////////////////////////////////////////////////////////////////////////
    //tsTraceStream &operator<< (const void *value);
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Stream insertion operator.</summary>
    ///
    /// <param name="_Pfn">Runs the specified function on this object</param>
    ///
    /// <returns>A reference to this object.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tsTraceStream &operator<<(tsTraceStream &(*_Pfn)(tsTraceStream &obj));
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Stream insertion operator.</summary>
    ///
    /// <param name="_Manip">Holds the function pointer and argument that is to be run.</param>
    ///
    /// <returns>A reference to this object.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	template <class _Arg>
	tsTraceStream& operator<<(const _TSTracemanip<_Arg>& _Manip)
	{
		(this->*_Manip._Pfun)(_Manip._Manarg);
		return *this;
	}

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Increment the indentation level</summary>
    ///
    /// <returns>A reference to this object.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tsTraceStream &indent();
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Decrements the indentation level</summary>
    ///
    /// <returns>A reference to this object.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tsTraceStream &outdent();
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets a prefix string for the following line</summary>
    ///
    /// <param name="prfx">The prefix string.</param>
    ///
    /// <returns>A reference to this object.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tsTraceStream &setPrefix(const tscrypto::tsCryptoStringBase& prfx);

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets float precision for the next stream operator.</summary>
    ///
    /// <param name="left"> The number of digits to the left.</param>
    /// <param name="right">The number of digits to the right.</param>
    ///
    /// <returns>A reference to this object.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tsTraceStream &SetFloatPrecision(int left, int right);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the padding width for the next stream operator.</summary>
	///
	/// <param name="setTo">The width.</param>
	///
    /// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual tsTraceStream &SetWidth(int setTo);
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the filler character for the next stream operator</summary>
	///
	/// <param name="_filler">The filler.</param>
	///
    /// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual tsTraceStream &SetFiller(char _filler);

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the number base to use when converting the next integer using the stream
    /// 		 operator.</summary>
    ///
    /// <param name="numbase">The base of the number (10, 16, ...).</param>
    ///
    /// <returns>A reference to this object.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tsTraceStream &setbase(int numbase);
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Set the number base to 16 for HEX output</summary>
    ///
    /// <returns>A reference to this object.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tsTraceStream &hex() { return setbase(16); }
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Set the number base to 10 for decimal output</summary>
    ///
    /// <returns>A reference to this object.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tsTraceStream &dec() { return setbase(10); }
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
	virtual tsTraceStream &ptr(const void *pointer);

	template <typename TODUMP>
	tsTraceStream &hexDump(TODUMP& data)
	{
		tscrypto::tsCryptoData tmp(data);

		return hexDump(tmp);
	}

	tsTraceStream &hexDump(tscrypto::tsCryptoData& data);

	bool WillLog() const
	{
		return tsLog::WillLog(_name.c_str(), _level);
	}
protected:
    int leftDoublePrecision;
    int rightDoublePrecision;
    bool justHadNewline;
    tscrypto::tsCryptoString prefix;
    int numberBase;
	int width;
	char filler;
	tscrypto::tsCryptoString _name;
	int _level;
	tscrypto::tsCryptoString _partialLine;

    void processData(tscrypto::tsCryptoStringBase &data);
	void resetSingleOps();
};

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A new line for the Trace logging class</summary>
///
/// <param name="strm">[in,out] The strm.</param>
///
/// <returns>A reference to this object.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
inline tsTraceStream &endl(tsTraceStream &strm)
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
inline tsTraceStream &indent(tsTraceStream &strm)
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
inline tsTraceStream &outdent(tsTraceStream &strm)
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
inline tsTraceStream &hex(tsTraceStream &strm)
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
inline tsTraceStream &dec(tsTraceStream &strm)
{
    strm.dec();
    return strm;
}

//namespace TSTrace {
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Helper function to set the number base for this stream</summary>
///
/// <param name="setTo">[in,out].</param>
///
/// <returns>A reference to this object.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
	inline _TSTracemanip<int> __cdecl width(int setTo)
	{
		return _TSTracemanip<int>(&tsTraceStream::SetWidth, setTo);
	}
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Helper function to set the number base for this stream</summary>
///
/// <param name="setTo">[in,out].</param>
///
/// <returns>A reference to this object.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
	inline _TSTracemanip<int> __cdecl setbase(int setTo)
	{
		return _TSTracemanip<int>(&tsTraceStream::setbase, setTo);
	}
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Helper function to set the filler character for this stream</summary>
///
/// <param name="setTo">[in,out].</param>
///
/// <returns>A reference to this object.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
	inline _TSTracemanip<char> __cdecl filler(char setTo)
	{
		return _TSTracemanip<char>(&tsTraceStream::SetFiller, setTo);
	}
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Helper function to set pointer mode</summary>
	///
	/// <param name="pointer">[in,out].</param>
	///
	/// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	inline _TSTracemanip<const void *> __cdecl ptr(const void *pointer)
	{
		return _TSTracemanip<const void *>(&tsTraceStream::ptr, pointer);
	}

	template <typename TODUMP>
	inline _TSTracemanip<TODUMP &> __cdecl hexDump(TODUMP& data)
	{
		return _TSTracemanip<TODUMP&>(&tsTraceStream::hexDump, data);
	}
//}

//////////////////////////////////////////////////////////////////////////////////////////////////////
///// <summary>Helper function to set pointer mode</summary>
/////
///// <param name="strm">[in,out] The strm.</param>
/////
///// <returns>A reference to this object.</returns>
//////////////////////////////////////////////////////////////////////////////////////////////////////
//inline tsTraceStream &ptr(tsTraceStream &strm, const void *pointer)
//{
//	strm.ptr(pointer);
//	return strm;
//}

//////////////////////////////////////////////////////////////////////////////////////////////////////
///// <summary>Helper function to restore non-pointer mode</summary>
/////
///// <param name="strm">[in,out] The strm.</param>
/////
///// <returns>A reference to this object.</returns>
//////////////////////////////////////////////////////////////////////////////////////////////////////
//inline tsTraceStream &noptr(tsTraceStream &strm)
//{
//	strm.noptr();
//    return strm;
//}

/// <summary>Allows for the logging of the entry and exit from a code block (function, if statement, ...)</summary>
	class VEILCORE_API tsTraceStreamSection
{
public:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Constructor.</summary>
    ///
    /// <param name="strm">[in,out] The stream.</param>
    /// <param name="name">The name of this section.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    tsTraceStreamSection(tsTraceStream &strm, const tscrypto::tsCryptoStringBase& name) :
        m_stream(strm),
        m_name(name)
    {
        m_stream << "START:  " << name << tscrypto::endl;
        m_stream.indent();
    }
    /// <summary>Destructor.</summary>
    ~tsTraceStreamSection()
    {
        m_stream.outdent() << "END:  " << m_name << tscrypto::endl;
    }
//#ifdef _WIN32
//    ////////////////////////////////////////////////////////////////////////////////////////////////////
//    /// <summary>Object allocation operator.</summary>
//    ///
//    /// <param name="bytes">The number of bytes to allocate.</param>
//    ///
//    /// <returns>The allocated object.</returns>
//    ////////////////////////////////////////////////////////////////////////////////////////////////////
//    void *operator new(size_t bytes) { return FrameworkAllocator(bytes); }
//    ////////////////////////////////////////////////////////////////////////////////////////////////////
//    /// <summary>Object de-allocation operator.</summary>
//    ///
//    /// <param name="ptr">[in,out] If non-null, the pointer to delete.</param>
//    ////////////////////////////////////////////////////////////////////////////////////////////////////
//    void operator delete(void *ptr) { return FrameworkDeallocator(ptr); }
//#endif // _WIN32
protected:
    tsTraceStream &m_stream;
    tscrypto::tsCryptoString m_name;

private:
    tsTraceStreamSection(const tsTraceStreamSection &obj):m_stream(obj.m_stream),m_name(obj.m_name){}
    tsTraceStreamSection& operator=(const tsTraceStreamSection &obj){UNREFERENCED_PARAMETER(obj);return *this;}
};

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A helper macro to create a tsTraceStreamSection using the indicated stream
/// 		 object.</summary>
///
/// <param name="strm">The stream to log.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define STREAMTRACEFUNC(strm) tsTraceStreamSection __funcStreamTrace(strm, __FUNCSIG__)

#endif // __TSTRACESTREAM_H__

/*! @} */
