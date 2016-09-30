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

/*! \file tsDebugStream.h
 * <summary>Debug logging classes, functions and variables</summary>
 */
 
 #ifndef __TSDEBUGSTREAM_H__
 #define __TSDEBUGSTREAM_H__
 
#pragma once

//#ifdef _DEBUG
	#define DBOUT(x) x
	#define RELOUT(x)
//#else
//	#define DBOUT(x)
//	#define RELOUT(x) x
//#endif

#include <ostream>

template <typename T> struct TSDebugLogImpl;

/// <summary>The core class used to create debug logs</summary>
class VEILCORE_API tsDebugStream : public tsTraceStream
{
public:
    /**
     * \brief Constructor.
     *
     * \param name  true to link to master loggers.
     * \param level The debug level for this stream.
     */
    tsDebugStream(const tscrypto::tsCryptoStringBase& name, int level);
    /// <summary>Destructor.</summary>
    ~tsDebugStream(void);

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Increment the indentation level</summary>
    ///
    /// <returns>A reference to this object.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual tsDebugStream &indent() 
	{
		DBOUT( tsTraceStream::indent(); )
		return *this;
	}
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Decrements the indentation level</summary>
    ///
    /// <returns>A reference to this object.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tsDebugStream &outdent()
	{
		DBOUT( tsTraceStream::outdent(); )
		return *this;
	}
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets a prefix string for the following line</summary>
    ///
    /// <param name="prfx">The prefix string.</param>
    ///
    /// <returns>A reference to this object.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tsDebugStream &setPrefix(const tscrypto::tsCryptoStringBase& prfx)
	{
		DBOUT( tsTraceStream::setPrefix(prfx); )
		RELOUT( UNREFERENCED_PARAMETER(prfx); )
		return *this;
	}

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets float precision for the next stream operator.</summary>
    ///
    /// <param name="left"> The number of digits to the left.</param>
    /// <param name="right">The number of digits to the right.</param>
    ///
    /// <returns>A reference to this object.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tsDebugStream &SetFloatPrecision(int left, int right)
	{
		DBOUT( tsTraceStream::SetFloatPrecision(left, right); )
		RELOUT( UNREFERENCED_PARAMETER(left); UNREFERENCED_PARAMETER(right); )
		return *this;
	}
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the padding width for the next stream operator.</summary>
	///
	/// <param name="setTo">The width.</param>
	///
    /// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual tsDebugStream &SetWidth(int setTo)
	{
		DBOUT( tsTraceStream::SetWidth(setTo); )
		RELOUT( UNREFERENCED_PARAMETER(setTo); )
		return *this;
	}
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the filler character for the next stream operator</summary>
	///
	/// <param name="_filler">The filler.</param>
	///
    /// <returns>A reference to this object.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual tsDebugStream &SetFiller(char _filler)
	{
		DBOUT( tsTraceStream::SetFiller(_filler); )
		RELOUT( UNREFERENCED_PARAMETER(_filler); )
		return *this;
	}

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the number base to use when converting the next integer using the stream
    /// 		 operator.</summary>
    ///
    /// <param name="numbase">The base of the number (10, 16, ...).</param>
    ///
    /// <returns>A reference to this object.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tsDebugStream &setbase(int numbase)
	{
		DBOUT( tsTraceStream::setbase(numbase); )
		RELOUT( UNREFERENCED_PARAMETER(numbase); )
		return *this;
	}
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Set the number base to 16 for HEX output</summary>
    ///
    /// <returns>A reference to this object.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tsDebugStream &hex()
	{
		DBOUT( tsTraceStream::hex(); )
		return *this;
	}
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Set the number base to 10 for decimal output</summary>
    ///
    /// <returns>A reference to this object.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual tsDebugStream &dec()
	{
		DBOUT( tsTraceStream::dec(); )
		return *this;
	}
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
	virtual tsDebugStream &ptr(const void *pointer)
	{
		DBOUT( tsTraceStream::ptr(pointer); )
		RELOUT( UNREFERENCED_PARAMETER(pointer); )
		return *this;
	}
};

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A new line for the Trace logging class</summary>
///
/// <param name="strm">[in,out] The strm.</param>
///
/// <returns>A reference to this object.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
inline tsDebugStream &endl(tsDebugStream &strm)
{
    DBOUT( strm << "\n"; )
    return strm;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Helper function to indent the following lines in the log</summary>
///
/// <param name="strm">[in,out] The strm.</param>
///
/// <returns>A reference to this object.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
inline tsDebugStream &indent(tsDebugStream &strm)
{
    DBOUT( strm.indent(); )
    return strm;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Helper function to outdent the following lines in the log</summary>
///
/// <param name="strm">[in,out] The strm.</param>
///
/// <returns>A reference to this object.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
inline tsDebugStream &outdent(tsDebugStream &strm)
{
    DBOUT( strm.outdent(); )
    return strm;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Helper function to put the stream into HEX mode</summary>
///
/// <param name="strm">[in,out] The strm.</param>
///
/// <returns>A reference to this object.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
inline tsDebugStream &hex(tsDebugStream &strm)
{
    DBOUT( strm.hex(); )
    return strm;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Helper function to put the string into Decimal mode</summary>
///
/// <param name="strm">[in,out] The strm.</param>
///
/// <returns>A reference to this object.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
inline tsDebugStream &dec(tsDebugStream &strm)
{
    DBOUT( strm.dec(); )
    return strm;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Helper function to set the padding width for this stream</summary>
///
/// <param name="strm">[in,out] The strm.</param>
/// <param name="setTo">value to set strm to</param>
/// <returns>A reference to this object.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
inline tsDebugStream &width(tsDebugStream &strm, int setTo)
{
    DBOUT( strm.SetWidth(setTo); )
	RELOUT( UNREFERENCED_PARAMETER(setTo); )
    return strm;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Helper function to set the padding width for this stream</summary>
///
/// <param name="strm">[in,out] The strm.</param>
/// <param name="setTo">value to set strm to</param>
/// <returns>A reference to this object.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
inline tsDebugStream &filler(tsDebugStream &strm, char setTo)
{
    DBOUT( strm.SetFiller(setTo); )
	RELOUT( UNREFERENCED_PARAMETER(setTo); )
    return strm;
}

#ifndef DO_NOT_DOCUMENT  // internal templates

template <typename T> struct TSDebugLogImpl<T&&>
{
	static tsDebugStream &Process(tsDebugStream &strm, T&& t) { DBOUT( (*static_cast<tsTraceStream*>(&strm)) << t; ) return strm; }
};

template <typename T> struct TSDebugLogImpl<std::shared_ptr<T>&>
{
	static tsDebugStream &Process(tsDebugStream &strm, std::shared_ptr<T>& t) { DBOUT( (*static_cast<tsTraceStream*>(&strm)) << t; ) return strm; }
};

template <typename T> struct TSDebugLogImpl<const std::shared_ptr<T>&>
{
	static tsDebugStream &Process(tsDebugStream &strm, const std::shared_ptr<T>& t) { DBOUT((*static_cast<tsTraceStream*>(&strm)) << t;) return strm; }
};

template <typename T> struct TSDebugLogImpl<T*&>
{
	static tsDebugStream &Process(tsDebugStream &strm, T*& t) { DBOUT( (*static_cast<tsTraceStream*>(&strm)) << t; ) return strm; }
};

template <typename T> struct TSDebugLogImpl<const T*&>
{
	static tsDebugStream &Process(tsDebugStream &strm, const T*& t) { DBOUT( (*static_cast<tsTraceStream*>(&strm)) << t; ) return strm; }
};

template <typename T> struct TSDebugLogImpl<T&>
{
	static tsDebugStream &Process(tsDebugStream &strm, T& t) { DBOUT( (*static_cast<tsTraceStream*>(&strm)) << t; ) return strm; }
};

template <typename T> struct TSDebugLogImpl<const T&>
{
	static tsDebugStream &Process(tsDebugStream &strm, const T& t) { DBOUT( (*static_cast<tsTraceStream*>(&strm)) << t; ) return strm; }
};

 //   virtual tsTraceStream &operator<<(tsTraceStream &(*_Pfn)(tsTraceStream &obj))
	//{
	//	DBOUT( return *static_cast<tsDebugStream*>(this) << _Pfn; )
	//	RELOUT( UNREFERENCED_PARAMETER(_Pfn); return *this; )
	//}

template<typename T> tsDebugStream &operator<<(tsDebugStream &strm, T&& t) 
{ 
	RELOUT( UNREFERENCED_PARAMETER(t); )
	DBOUT( TSDebugLogImpl<T&&>::Process(strm, std::forward<T>(t)); )
	return strm;
}

#endif // DO_NOT_DOCUMENT

/// <summary>Allows for the logging of the entry and exit from a code block (function, if statement, ...)</summary>
class VEILCORE_API tsDebugStreamSection
{
public:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Constructor.</summary>
    ///
    /// <param name="strm">[in,out] The stream.</param>
    /// <param name="name">The name of this section.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    tsDebugStreamSection(tsDebugStream &strm, const tscrypto::tsCryptoStringBase& name) :
        m_stream(strm),
        m_name(name)
    {
        m_stream << "BEGIN //  " << name << ::endl;
        m_stream.indent();
    }
    /// <summary>Destructor.</summary>
    ~tsDebugStreamSection()
    {
        m_stream.outdent() << "END   //  " << m_name << ::endl;
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
    tsDebugStream &m_stream;
    tscrypto::tsCryptoString m_name;

private:
    tsDebugStreamSection(const tsDebugStreamSection &obj):m_stream(obj.m_stream),m_name(obj.m_name){}
    tsDebugStreamSection& operator=(const tsDebugStreamSection &obj){UNREFERENCED_PARAMETER(obj);return *this;}
};

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A helper macro to create a tsDebugStreamSection using the indicated stream
/// 		 object.</summary>
///
/// <param name="strm">The stream to log.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define STREAMFUNC(strm) tsDebugStreamSection __funcStreamDebug(strm, __FUNCSIG__)

#endif // __TSDEBUGSTREAM_H__

