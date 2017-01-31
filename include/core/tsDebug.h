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

#pragma once

/*! @file tsDebug.h
 * @brief This file defines a set of functions that allow for the use of the CKM Debug Logging system.
*/

#ifndef TSDEBUG_H_INCLUDED
#define TSDEBUG_H_INCLUDED

extern tsTraceStream VEILCORE_API httpData;
extern tsTraceStream VEILCORE_API httpLog;
extern tsTraceStream VEILCORE_API FrameworkError;		/**< \brief Used to report CKM Framework Helper errors */
extern tsDebugStream VEILCORE_API FrameworkInfo1;		/**< \brief Used to report CKM Framework Helper informational messages */
extern tsDebugStream VEILCORE_API FrameworkInternal;		/**< \brief Used to report CKM Framework Helper internal messages */
extern tsDebugStream VEILCORE_API FrameworkDevOnly;		/**< \brief Used to report CKM Framework Helper developer level messages */
extern tsDebugStream VEILCORE_API FrameworkLocks;		/**< \brief Used to report CKM Framework Helper lock related messages */
extern tsTraceStream VEILCORE_API gMetaError;			/**< \brief Used to report CKM Framework Helper error messages for Tlv serialization */
extern tsDebugStream VEILCORE_API gMetaDebug;			/**< \brief Used to report CKM Framework Helper informational messages for Tlv serialization */
extern tsDebugStream VEILCORE_API CallTrace;				/**< \brief Used to report CKM Framework Helper call stack trace messages */
extern tsTraceStream VEILCORE_API gLoaderError;			/**< \brief Used to report CKM Framework Helper loader error messages */
extern tsDebugStream VEILCORE_API gLoaderTrace;			/**< \brief Used to report CKM Framework Helper loader trace messages */
extern tsDebugStream VEILCORE_API gDebugAuth;
extern tsTraceStream VEILCORE_API gTunnel;
extern tsTraceStream VEILCORE_API gTunnelError;
extern tsTraceStream VEILCORE_API CkmError;
extern tsDebugStream VEILCORE_API CkmInfo1;
extern tsDebugStream VEILCORE_API CkmInfo2;
extern tsDebugStream VEILCORE_API CkmDevOnly;
extern tsDebugStream VEILCORE_API CkmCrypto;
extern tsDebugStream VEILCORE_API DebugInfo1; ///< Debug log with Information level 1
extern tsDebugStream VEILCORE_API DebugInfo2; ///< Debug log with Information level 2
extern tsDebugStream VEILCORE_API DebugInfo3; ///< Debug log with Information level 3
extern tsDebugStream VEILCORE_API DebugConfig; ///< Debug log for configuration information
extern tsDebugStream VEILCORE_API DebugToken; ///< Debug log for token information
extern tsDebugStream VEILCORE_API DebugCrypto; ///< Debug log for crypto information
extern tsDebugStream VEILCORE_API DebugPki; ///< Debug log for PKI information
extern tsDebugStream VEILCORE_API DebugInternal; ///< Debug log for Internal diagnostic information
extern tsDebugStream VEILCORE_API DebugDevOnly; ///< Debug log for Development Only information
extern tsDebugStream VEILCORE_API DebugFile; ///< Debug log for File IO information
extern tsDebugStream VEILCORE_API DebugNetwork; ///< Debug log for Network information
extern tsDebugStream VEILCORE_API DebugUI; ///< Debug log for UI information
extern tsTraceStream VEILCORE_API DebugError; ///< Debug log for Error information
extern tsTraceStream VEILCORE_API DebugFatal; ///< Debug log for Fatal Error information
extern tsDebugStream VEILCORE_API DebugLocks; ///< Debug log for locks
extern tsDebugStream VEILCORE_API gSql;

//extern tsDebugStream VEILCORE_API AuditInfo;			///< Audit log for information
//extern tsDebugStream VEILCORE_API AuditLoginFailure;	///< Audit log for failures
//extern tsDebugStream VEILCORE_API AuditLoginSuccess;	///< Audit log for success
//extern tsDebugStream VEILCORE_API AuditLogout;			///< Audit log for logout
//extern tsDebugStream VEILCORE_API AuditEncryptFailure;	///< Audit log for encrypt failures
//extern tsDebugStream VEILCORE_API AuditEncryptSuccess;	///< Audit log for encrypt success
//extern tsDebugStream VEILCORE_API AuditDecryptFailure; ///< Audit log for decrypt failures
//extern tsDebugStream VEILCORE_API AuditDecryptSuccess; ///< Audit log for decrypt success
//extern tsDebugStream VEILCORE_API AuditSignFailure;	///< Audit log for signing failure
//extern tsDebugStream VEILCORE_API AuditSignSuccess;	///< Audit log for signing success
//extern tsDebugStream VEILCORE_API AuditVerifyFailure;	///< Audit log for verification failures
//extern tsDebugStream VEILCORE_API AuditVerifySuccess;	///< Audit log for verification success
//extern tsDebugStream VEILCORE_API AuditHashFailure;	///< Audit log for hash failures
//extern tsDebugStream VEILCORE_API AuditHashSuccess;	///< Audit log for hash success

/// <summary>Defines the type of block tracing</summary>
enum _tsTraceTypeEnumExt {
	tsTraceFunctionExt, ///< <summary>Function level tracing</summary>
	tsTraceClassExt,	///< <summary>Class level tracing</summary>
	tsTraceModuleExt	///< <summary>Module level tracing</summary>
};

/// <summary>Holds the name and state for a trace section.</summary>
class VEILCORE_API  _tsTraceInfoExt {
public:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Constructor.</summary>
    ///
    /// <param name="FuncName">Name of the function.</param>
    /// <param name="InfoName">Name of the information.</param>
    /// <param name="Tp">	   The type of section.</param>
    /// <param name="allow">   true to allow.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    _tsTraceInfoExt(const tscrypto::tsCryptoString& FuncName, const tscrypto::tsCryptoString& InfoName, _tsTraceTypeEnumExt Tp, bool allow);

    _tsTraceInfoExt *next;  ///< The next _tsTraceInfoExt in the list
    tscrypto::tsCryptoString name; ///< The name of the function or section
    tscrypto::tsCryptoString info; ///< The information
    _tsTraceTypeEnumExt type;   ///< The type of section
    int id; ///< The unique identifier for this _tsTraceInfoExt
    bool enabled;   ///< true if this section is enabled to log
};

/// <summary>The maximum length in characters of a trace message.</summary>
#define MAX_TRACE_MSG_LEN 512

/// <summary>Defines a class that is used to trace entry and exit from a function.</summary>
class VEILCORE_API  _tsTraceFunctionExt
{
public:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Constructor.</summary>
    ///
    /// <param name="info">The section object controling this object.</param>
    /// <param name="This">[in,out] If non-null the 'this' pointer for the class, or NULL for a non-class function.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    _tsTraceFunctionExt(const _tsTraceInfoExt &info, void *This);
    /// <summary>Destructor.</summary>
    ~_tsTraceFunctionExt();

private:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Assignment operator.  Disabled</summary>
    ///
    /// <param name="parameter1">The object to copy.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    _tsTraceFunctionExt &operator = (const _tsTraceFunctionExt &)
    {
        return *this;
    }
public:
    /// <summary>Sets the "we had an error" flag.</summary>
    _tsTraceFunctionExt &setError();
	_tsTraceFunctionExt &setErrorTo(bool value) { m_error = value; return *this; }
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Replaces the special '~~' tag in the output message with the pointer value passed in.</summary>
    ///
    /// <param name="value">[in,out] If non-null, the value.</param>
    ///
    /// <returns>null if it fails, else.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    template <class T>
    T *returns (T *value)
    {
        char buff[20];

#if !defined(HAVE_SPRINTF_S)
        sprintf(buff, "%p", value);
#else
        sprintf_s(buff, sizeof(buff), "%p", value);
#endif
        m_outMessage.Replace("~~", buff);
        return value;
    }
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Replaces the special '~~' tag in the output message with the integer value passed in.</summary>
    ///
    /// <param name="value">[in,out] If non-null, the value.</param>
    ///
    /// <returns>null if it fails, else.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    template <class T>
    T returns (T value)
    {
        char buff[20];

#if !defined(HAVE_SPRINTF_S)
        sprintf(buff, "0x%08X", (int)value);
#else
        sprintf_s(buff, sizeof(buff), "0x%08X", (int)value);
#endif
        m_outMessage.Replace("~~", buff);
        return value;
    }
	template <class T>
	std::shared_ptr<T> returns(std::shared_ptr<T> value)
	{
		char buff[20];

#if !defined(HAVE_SPRINTF_S)
		sprintf(buff, "0x%p", value.get());
#else
		sprintf_s(buff, sizeof(buff), "0x%p", value.get());
#endif
		m_outMessage.Replace("~~", buff);
		return value;
	}
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Replaces the special '~~' tag in the output message with the nullptr value passed in.</summary>
	///
	/// <param name="value">[in,out] nullptr.</param>
	///
	/// <returns>null if it fails, else.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
    std::nullptr_t returns(std::nullptr_t value)
	{
		m_outMessage.Replace("~~", "<<nullptr>>");
		return value;
	}
	////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Replaces the special '~~' tag in the output message with the int64 value passed in.</summary>
    ///
    /// <param name="value">[in,out] If non-null, the value.</param>
    ///
    /// <returns>null if it fails, else.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    int64_t returns (int64_t value)
    {
        char buff[70];

#if !defined(HAVE_SPRINTF_S)
        sprintf(buff, "0x%016llX", value);
#else
        sprintf_s(buff, sizeof(buff), "0x%016llX", value);
#endif
        m_outMessage.Replace("~~", buff);
        return value;
    }
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Replaces the special '~~' tag in the output message with the boolean value passed in.</summary>
    ///
    /// <param name="value">[in,out] If non-null, the value.</param>
    ///
    /// <returns>null if it fails, else.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    bool returns (bool value)
    {
        if ( value )
            m_outMessage.Replace("~~", "true");
        else
            m_outMessage.Replace("~~", "false");
        return value;
    }
	tscrypto::tsCryptoData& returns(tscrypto::tsCryptoData& value)
	{
		m_outMessage.Replace("~~", value.ToHexStringWithSpaces());
		return value;
	}
	tscrypto::tsCryptoData returns(tscrypto::tsCryptoData&& value)
	{
		m_outMessage.Replace("~~", value.ToHexStringWithSpaces());
		return std::move(value);
	}
	const tscrypto::tsCryptoData& returns(const tscrypto::tsCryptoData& value)
	{
		m_outMessage.Replace("~~", value.ToHexStringWithSpaces());
		return value;
	}
	tscrypto::tsCryptoString& returns(tscrypto::tsCryptoString& value)
	{
		m_outMessage.Replace("~~", value.c_str());
		return value;
	}
	tscrypto::tsCryptoString returns(tscrypto::tsCryptoString&& value)
	{
		m_outMessage.Replace("~~", value.c_str());
		return std::move(value);
	}
	const tscrypto::tsCryptoString& returns(const tscrypto::tsCryptoString& value)
	{
		m_outMessage.Replace("~~", value.c_str());
		return value;
	}
	////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the message string that is logged on destruction of this class with specified
    /// format string and optional parameters.</summary>
    ///
    /// <param name="fmt">Describes the format to use.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    _tsTraceFunctionExt &returnMsg (tscrypto::tsCryptoString fmt, ...)
    {
        va_list args;
        va_start(args, fmt);
        m_outMessage.clear();
        m_outMessage.resize(MAX_TRACE_MSG_LEN);
#ifdef HAVE__VSNPRINTF_S
		_vsnprintf_s(m_outMessage.rawData(), m_outMessage.size(), m_outMessage.size(), fmt.c_str(), args);
#else
        vsnprintf(m_outMessage.rawData(), m_outMessage.size(), fmt.c_str(), args);
#endif
        m_outMessage.resize((uint32_t)tscrypto::TsStrLen(m_outMessage.c_str()));
        return *this;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>A special helper function that contains the format string, output string value and
    /// optional parameters.</summary>
    ///
    /// <param name="fmt">  Describes the format to use.</param>
    /// <param name="value">The string value.</param>
    ///
    /// <returns>The string value.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    tscrypto::tsCryptoString returns(const tscrypto::tsCryptoString& fmt, const tscrypto::tsCryptoString& value, ...);
#ifdef _WIN32
	/**
	* \brief Sets the message string that is logged on destruction of this class with specified format
	* string and optional parameters.
	*
	* \param hr  The COM error.
	* \param fmt Describes the format to use.
	*/
	_tsTraceFunctionExt &returnCOMMsg(HRESULT hr, tscrypto::tsCryptoString fmt, ...);
	/**
	* \brief Sets the message string that is logged on destruction of this class with specified format
	* string and optional parameters.
	*
	* \param hr The COM error.
	*/
	_tsTraceFunctionExt &returnCOM(HRESULT hr);
#endif // _WIN32
protected:
    const _tsTraceInfoExt &m_info;
    void *m_This;
    tscrypto::tsCryptoString m_outMessage;
    bool m_error;
};

/// <summary>A special class that automatically logs the construction and destruction of a class that inherits from this class.</summary>
class VEILCORE_API  _tsTraceClassExt
{
public:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Constructor.</summary>
    ///
    /// <param name="info">The section information.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    _tsTraceClassExt(const _tsTraceInfoExt &info);
    _tsTraceClassExt(const _tsTraceClassExt &info);
    /// <summary>Destructor.</summary>
    ~_tsTraceClassExt();

    const _tsTraceInfoExt &m_TraceInfo; ///< <summary>The section information controlling the logging of this object</summary>
    uint32_t m_classInstance;   ///< <summary>The unique identifier for this object</summary>
private:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Assignment operator (disabled).</summary>
    ///
    /// <param name="parameter1">The object to copy.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    _tsTraceClassExt &operator = (const _tsTraceClassExt &)
    {
        return *this;
    }
};

/// <summary>A helper class that is used for class method tracing</summary>
class VEILCORE_API  _tsTraceMethodExt
{
public:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Constructor.</summary>
    ///
    /// <param name="info">		 The section object.</param>
    /// <param name="MethodName">Name of the method.</param>
    /// <param name="This">		 The class instance 'this' pointer.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    _tsTraceMethodExt(const _tsTraceClassExt &info, const tscrypto::tsCryptoString& MethodName, const void *This);
    /// <summary>Destructor.</summary>
    ~_tsTraceMethodExt();
public:
    /// <summary>Sets the "we had an error" flag.</summary>
    _tsTraceMethodExt &setError();
	_tsTraceMethodExt &setErrorTo(bool value) {m_error = value; return *this;}
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Replaces the special '~~' tag in the output message with the pointer value passed in.</summary>
    ///
    /// <param name="value">[in,out] If non-null, the value.</param>
    ///
    /// <returns>null if it fails, else.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    template <class T>
    T *returns (T *value)
    {
        char buff[20];

#if !defined(HAVE_SPRINTF_S)
        sprintf(buff, "%p", value);
#else
        sprintf_s(buff, sizeof(buff), "%p", value);
#endif
        m_outMessage.Replace("~~", buff);
        return value;
    }
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Replaces the special '~~' tag in the output message with the integer value passed in.</summary>
    ///
    /// <param name="value">[in,out] If non-null, the value.</param>
    ///
    /// <returns>null if it fails, else.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    template <class T>
    T returns (T value)
    {
        char buff[20];

#if !defined(HAVE_SPRINTF_S)
        sprintf(buff, "0x%08X", (int)value);
#else
        sprintf_s(buff, sizeof(buff), "0x%08X", value);
#endif
        m_outMessage.Replace("~~", buff);
        return value;
    }
	template <class T>
	std::shared_ptr<T> returns(std::shared_ptr<T> value)
	{
		char buff[20];

#if !defined(HAVE_SPRINTF_S)
		sprintf(buff, "0x%p", value.get());
#else
		sprintf_s(buff, sizeof(buff), "0x%p", value.get());
#endif
		m_outMessage.Replace("~~", buff);
		return value;
	}
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Replaces the special '~~' tag in the output message with the nullptr value passed in.</summary>
	///
	/// <param name="value">[in,out] nullptr.</param>
	///
	/// <returns>null if it fails, else.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
    std::nullptr_t returns(std::nullptr_t value)
	{
		m_outMessage.Replace("~~", "<<nullptr>>");
		return value;
	}
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Replaces the special '~~' tag in the output message with the int64 value passed in.</summary>
    ///
    /// <param name="value">[in,out] If non-null, the value.</param>
    ///
    /// <returns>null if it fails, else.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    int64_t returns (int64_t value)
    {
        char buff[70];

#if !defined(HAVE_SPRINTF_S)
        sprintf(buff, "0x%016llX", value);
#else
        sprintf_s(buff, sizeof(buff), "0x%016llX", value);
#endif
        m_outMessage.Replace("~~", buff);
        return value;
    }
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Replaces the special '~~' tag in the output message with the boolean value passed in.</summary>
    ///
    /// <param name="value">[in,out] If non-null, the value.</param>
    ///
    /// <returns>null if it fails, else.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    bool returns (bool value)
    {
        if ( value )
            m_outMessage.Replace("~~", "true");
        else
            m_outMessage.Replace("~~", "false");
        return value;
    }
	tscrypto::tsCryptoData& returns(tscrypto::tsCryptoData& value)
	{
		m_outMessage.Replace("~~", value.ToHexStringWithSpaces());
		return value;
	}
	tscrypto::tsCryptoData returns(tscrypto::tsCryptoData&& value)
	{
		m_outMessage.Replace("~~", value.ToHexStringWithSpaces());
		return std::move(value);
	}
	const tscrypto::tsCryptoData& returns(const tscrypto::tsCryptoData& value)
	{
		m_outMessage.Replace("~~", value.ToHexStringWithSpaces());
		return value;
	}
	tscrypto::tsCryptoString& returns(tscrypto::tsCryptoString& value)
	{
		m_outMessage.Replace("~~", value.c_str());
		return value;
	}
	tscrypto::tsCryptoString returns(tscrypto::tsCryptoString&& value)
	{
		m_outMessage.Replace("~~", value.c_str());
		return std::move(value);
	}
	const tscrypto::tsCryptoString& returns(const tscrypto::tsCryptoString& value)
	{
		m_outMessage.Replace("~~", value.c_str());
		return value;
	}

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the message string that is logged on destruction of this class with specified
    /// format string and optional parameters.</summary>
    ///
    /// <param name="fmt">Describes the format to use.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    _tsTraceMethodExt &returnMsg (tscrypto::tsCryptoString fmt, ...)
    {
        va_list args;
        va_start(args, fmt);
        m_outMessage.clear();
        m_outMessage.resize(MAX_TRACE_MSG_LEN);
#ifdef HAVE__VSNPRINTF_S
		_vsnprintf_s(m_outMessage.rawData(), m_outMessage.size(), m_outMessage.size(), fmt.c_str(), args);
#else
        vsnprintf(m_outMessage.rawData(), m_outMessage.size(), fmt.c_str(), args);
#endif
        m_outMessage.resize((uint32_t)tscrypto::TsStrLen(m_outMessage.c_str()));
        return *this;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>A special helper function that contains the format string, output string value and
    /// optional parameters.</summary>
    ///
    /// <param name="fmt">  Describes the format to use.</param>
    /// <param name="value">The string value.</param>
    ///
    /// <returns>The string value.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    tscrypto::tsCryptoString returns(const tscrypto::tsCryptoString& fmt, const tscrypto::tsCryptoString& value, ...);

#ifdef _WIN32
	/**
	* \brief Sets the message string that is logged on destruction of this class with specified format
	* string and optional parameters.
	*
	* \param hr  The COM error.
	* \param fmt Describes the format to use.
	*/
	_tsTraceMethodExt &returnCOMMsg(HRESULT hr, tscrypto::tsCryptoString fmt, ...);
	/**
	* \brief Sets the message string that is logged on destruction of this class with specified format
	* string and optional parameters.
	*
	* \param hr The COM error.
	*/
	_tsTraceMethodExt &returnCOM(HRESULT hr);
#endif // _WIN32
	bool Enabled();
protected:
    const void *m_This;
    tscrypto::tsCryptoString m_outMessage;
    bool m_error;
    tscrypto::tsCryptoString m_method;
	bool enabled;
	uint32_t classInstance;
private:
    _tsTraceMethodExt &operator = (const _tsTraceMethodExt &)
    {
        return *this;
    }
};

/// <summary>Identifies lock types for the lock tracing system.</summary>
typedef enum {
    tsLockWillAcquire,  ///< <summary>About to acquire a lock</summary>
    tsLockAcquired,  ///< <summary>Lock acquired</summary>
    tsLockReleased,  ///< <summary>Lock released</summary>
    tsLockTimeout  ///< <summary>Lock attempt timed out</summary>
} TSTRACE_LOCK_STATE;

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A function that is used to log lock messages</summary>
///
/// <param name="lockName">Name of the lock.</param>
/// <param name="lockType">Type of the lock.</param>
/// <param name="lockAddr">[in] The lock address.</param>
/// <param name="state">   The state.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
extern void VEILCORE_API  CkmDebug_LOCKING(const tscrypto::tsCryptoString& lockName, const tscrypto::tsCryptoString& lockType, void *lockAddr, TSTRACE_LOCK_STATE state);

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro used to conditionally hide a debug item.</summary>
///
/// <param name="a">The item to hide.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define CkmDebug_HIDEINFO(a) a

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that declares the module level section object.  This should only be called in a cpp file.</summary>
///
/// <param name="ModuleName">Name of the module.</param>
/// <param name="Enabled">   Is enabled.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define DECLARE_MODULE(ModuleName,Enabled) _tsTraceInfoExt __tsModule##ModuleName(#ModuleName,"",tsTraceModuleExt,Enabled);
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that defines the module level section object.  This should be used in a header file.</summary>
///
/// <param name="ModuleName">Name of the module.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define DEFINE_MODULE(ModuleName) extern class _tsTraceInfoExt __tsModule##ModuleName;

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that declares the class level section object.  This should only be called in a cpp file.</summary>
///
/// <param name="ClassName">Name of the class.</param>
/// <param name="Enabled">  Is enabled.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define DECLARE_CLASS(ClassName,Enabled) class _tsTraceInfoExt __tsClass##ClassName(#ClassName,"",tsTraceClassExt,Enabled);
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that defines the class level section object.  This should be used in a header file.</summary>
///
/// <param name="ClassName">Name of the class.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define DEFINE_CLASS(ClassName) extern class _tsTraceInfoExt __tsClass##ClassName;
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that declares a method level trace object.</summary>
///
/// <param name="MethodName">Name of the method.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define METHOD _tsTraceMethodExt __methodTrace((*(_tsTraceClassExt*)this),__FUNCSIG__,(void*)this);
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A helper object that effectively disables tracing for this method without deleting the source.</summary>
///
/// <param name="MethodName">Name of the method.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define METHOD0
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that is used as a variable initializer in the class constructor.</summary>
///
/// <param name="ClassName">Name of the class.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define CLASSINIT(ClassName) _tsTraceClassExt (__tsClass##ClassName)

#if defined(_WIN32) && !defined(__GNUC__)
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>A macro that declares a function level trace object that can be disabled.</summary>
    ///
    /// <param name="Enabled">True if logging is to be enabled.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    #define DECLARE_FUNCTION(Enabled) static _tsTraceInfoExt __tsFunction (__FUNCTION__, __FUNCSIG__, tsTraceFunctionExt, Enabled); _tsTraceFunctionExt __functionTrace(__tsFunction, NULL);
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>A macro that declares a method level trace object that can be disabled.</summary>
    ///
    /// <param name="Enabled">True if logging is to be enabled.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    #define DECLARE_METHOD(Enabled) static _tsTraceInfoExt __tsFunction (__FUNCTION__, __FUNCSIG__, tsTraceFunctionExt, Enabled); _tsTraceFunctionExt __functionTrace(__tsFunction, (void*)this);
#else
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>A macro that declares a function level trace object that can be disabled.</summary>
    ///
    /// <param name="Enabled">True if logging is to be enabled.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    #define DECLARE_FUNCTION(Enabled) static _tsTraceInfoExt __tsFunction (__FUNCTION__, __PRETTY_FUNCTION__, tsTraceFunctionExt, Enabled); _tsTraceFunctionExt __functionTrace (__tsFunction, NULL);
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>A macro that declares a method level trace object that can be disabled.</summary>
    ///
    /// <param name="Enabled">True if logging is to be enabled.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    #define DECLARE_METHOD(Enabled) static _tsTraceInfoExt __tsFunction (__FUNCTION__, __PRETTY_FUNCTION__, tsTraceFunctionExt, Enabled); _tsTraceFunctionExt __functionTrace (__tsFunction, (void*)this);
#endif

/// <summary>A macro that provides access to the function trace object.</summary>
#define TRACER __functionTrace
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that sets the return message information for a function trace object.</summary>
///
/// <param name="value">The return value for this function.</param>
/// <param name="msg">The format string and optional parameters enclosed in parenthesis</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define TRACER_RETURNS(value,msg,...) __functionTrace.returnMsg(msg,__VA_ARGS__) .returns(value)
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that sets the return message information for a function trace object and sets
/// the error flag.</summary>
///
/// <param name="value">The return value for this function.</param>
/// <param name="msg">The format string and optional parameters enclosed in parenthesis</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define TRACER_RETURNS_ERROR(value,msg,...) __functionTrace.returnMsg(msg,__VA_ARGS__).setError().returns(value)
/**
 * \brief A macro that sets the return message information for a function trace object.
 *
 * \param value The format string and optional parameters enclosed in parenthesis.
 * \param msg   The return value for this function.
 */
#define RETURN(value,msg,...) return TRACER_RETURNS(value,msg,__VA_ARGS__)
/**
 * \brief A macro that sets the return message information for a function trace object and sets the
 * error flag.
 *
 * \param value The format string and optional parameters enclosed in parenthesis.
 * \param msg   The return value for this function.
 */
#define RETURN_ERROR(value,msg,...) return TRACER_RETURNS_ERROR(value,msg,__VA_ARGS__)
/**
 * \brief A macro that sets the return message information for a void function.
 *
 * \param msg The format string and optional parameters enclosed in parenthesis.
 */
#define RETURN_V(msg,...) {__functionTrace.returnMsg(msg,__VA_ARGS__); return;}
/**
 * \brief A macro that sets the return message information for a void function and sets the error
 * flag.
 *
 * \param msg The format string and optional parameters enclosed in parenthesis.
 */
#define RETURN_ERROR_V(msg,...) {__functionTrace.returnMsg(msg,__VA_ARGS__).setError(); return;}

#define METHODTRACER __methodTrace

/**
 * \brief A macro that sets the return message information for a function trace object.
 *
 * \param value The format string and optional parameters enclosed in parenthesis.
 * \param msg   The return value for this function.
 */
#define METHODRETURN(value,msg,...) return __methodTrace.returnMsg(msg,__VA_ARGS__).returns(value)
/**
 * \brief A macro that sets the return message information for a function trace object and sets the
 * error flag.
 *
 * \param value The format string and optional parameters enclosed in parenthesis.
 * \param msg   The return value for this function.
 */
#define METHODRETURN_ERROR(value,msg,...) return __methodTrace.returnMsg(msg,__VA_ARGS__).setError().returns(value)
/**
 * \brief A macro that sets the return message information for a void function.
 *
 * \param msg The format string and optional parameters enclosed in parenthesis.
 */
#define METHODRETURN_V(msg,...) {__methodTrace.returnMsg(msg,__VA_ARGS__); return;}
/**
 * \brief A macro that sets the return message information for a void function and sets the error
 * flag.
 *
 * \param msg The format string and optional parameters enclosed in parenthesis.
 */
#define METHODRETURN_ERROR_V(msg,...) {__methodTrace.returnMsg(msg,__VA_ARGS__).setError(); return;}
#define RETURNCOM(hr) { HRESULT value = hr; __methodTrace.returnCOM(value); return value; }
#define RETURNCOMMSG(hr,msg,...){ HRESULT value = hr; __methodTrace.returnCOMMsg(value,msg,__VA_ARGS__); return value; }
//#define TSFUNCINFO(a) {if ( __tsFunction.enabled ) TSTRACEExt a;}
/// <summary>A macro that returns if function logging is enabled for this function.</summary>
#define FUNCTION_LOGGING_ENABLED __tsFunction.enabled

// ===============================================
// ==== Obsoleting these macros               ====
// ===============================================
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that declares the module level section object.  This should only be called in a cpp file.</summary>
///
/// <param name="ModuleName">Name of the module.</param>
/// <param name="Enabled">   Is enabled.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define TSDECLARE_MODULEExt(ModuleName,Enabled) _tsTraceInfoExt __tsModule##ModuleName(#ModuleName,"",tsTraceModuleExt,Enabled);
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that defines the module level section object.  This should be used in a header file.</summary>
///
/// <param name="ModuleName">Name of the module.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define TSDEFINE_MODULEExt(ModuleName) extern class _tsTraceInfoExt __tsModule##ModuleName;

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that declares the class level section object.  This should only be called in a cpp file.</summary>
///
/// <param name="ClassName">Name of the class.</param>
/// <param name="Enabled">  Is enabled.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define TSDECLARE_CLASSExt(ClassName,Enabled) class _tsTraceInfoExt __tsClass##ClassName(#ClassName,"",tsTraceClassExt,Enabled);
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that defines the class level section object.  This should be used in a header file.</summary>
///
/// <param name="ClassName">Name of the class.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define TSDEFINE_CLASSExt(ClassName) extern class _tsTraceInfoExt __tsClass##ClassName;
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that declares a method level trace object.</summary>
///
/// <param name="MethodName">Name of the method.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define CkmDebugMETHOD(MethodName) _tsTraceMethodExt __methodTrace((*(_tsTraceClassExt*)this),#MethodName,(void*)this);
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A helper object that effectively disables tracing for this method without deleting the source.</summary>
///
/// <param name="MethodName">Name of the method.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define CkmDebugMETHOD0(MethodName)
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that is used as a variable initializer in the class constructor.</summary>
///
/// <param name="ClassName">Name of the class.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define CkmDebugCLASSINIT(ClassName) _tsTraceClassExt(__tsClass##ClassName)

#if defined(_WIN32) && !defined(__GNUC__)
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>A macro that declares a function level trace object that can be disabled.</summary>
    ///
    /// <param name="Enabled">True if logging is to be enabled.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    #define TSDECLARE_FUNCTIONExt(Enabled) static _tsTraceInfoExt __tsFunction(__FUNCTION__,__FUNCSIG__,tsTraceFunctionExt,Enabled);_tsTraceFunctionExt __functionTrace(__tsFunction, NULL);
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>A macro that declares a method level trace object that can be disabled.</summary>
    ///
    /// <param name="Enabled">True if logging is to be enabled.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	#define TSDECLARE_METHODExt(Enabled) static _tsTraceInfoExt __tsFunction(__FUNCTION__,__FUNCSIG__,tsTraceFunctionExt,Enabled);_tsTraceFunctionExt __functionTrace(__tsFunction, (void*)this);
	#define TSDECLARE_METHODT(Enabled,T) static _tsTraceInfoExt __tsFunction(__FUNCTION__,__FUNCSIG__,tsTraceFunctionExt,Enabled);_tsTraceFunctionExt __functionTrace(__tsFunction, (void*)(T*)this);
#else
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>A macro that declares a function level trace object that can be disabled.</summary>
    ///
    /// <param name="Enabled">True if logging is to be enabled.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    #define TSDECLARE_FUNCTIONExt(Enabled) static _tsTraceInfoExt __tsFunction(__FUNCTION__,__PRETTY_FUNCTION__,tsTraceFunctionExt,Enabled);_tsTraceFunctionExt __functionTrace(__tsFunction, NULL);
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>A macro that declares a method level trace object that can be disabled.</summary>
    ///
    /// <param name="Enabled">True if logging is to be enabled.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    #define TSDECLARE_METHODExt(Enabled) static _tsTraceInfoExt __tsFunction(__FUNCTION__,__PRETTY_FUNCTION__,tsTraceFunctionExt,Enabled);_tsTraceFunctionExt __functionTrace(__tsFunction, (void*)this);
#endif

/// <summary>A macro that provides access to the function trace object.</summary>
#define TRACER __functionTrace
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that sets the return message information for a function trace object.</summary>
///
/// <param name="a">The return value for this function.</param>
/// <param name="b">The format string and optional parameters enclosed in parenthesis</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define TS_TRACER_RETURNS(a,b) __functionTrace.returnMsg b .returns(a)
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that sets the return message information for a function trace object and sets
/// the error flag.</summary>
///
/// <param name="a">The return value for this function.</param>
/// <param name="b">The format string and optional parameters enclosed in parenthesis</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define TS_TRACER_RETURNS_ERROR(a,b) __functionTrace.returnMsg b .setError().returns(a)
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that sets the return message information for a function trace object.</summary>
///
/// <param name="a">The format string and optional parameters enclosed in parenthesis</param>
/// <param name="b">The return value for this function.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define TSRETURN(a,b) TS_TRACER_RETURNS(b,a)
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that sets the return message information for a function trace object and sets
/// the error flag.</summary>
///
/// <param name="a">The format string and optional parameters enclosed in parenthesis</param>
/// <param name="b">The return value for this function.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define TSRETURN_ERROR(a,b) TS_TRACER_RETURNS_ERROR(b,a)
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that sets the return message information for a void function.</summary>
///
/// <param name="a">The format string and optional parameters enclosed in parenthesis.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define TSRETURN_V(a) __functionTrace.returnMsg a
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A macro that sets the return message information for a void function and sets the
/// error flag.</summary>
///
/// <param name="a">The format string and optional parameters enclosed in parenthesis.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
#define TSRETURN_ERROR_V(a) __functionTrace.returnMsg a .setError()
//#define TSFUNCINFO(a) {if ( __tsFunction.enabled ) TSTRACEExt a;}
/// <summary>A macro that returns if function logging is enabled for this function.</summary>
#define TS_FUNCTION_LOGGING_ENABLED __tsFunction.enabled

#ifdef _WIN32
tscrypto::tsCryptoString VEILCORE_API COMMessage(HRESULT hr);
#endif // _WIN32

#endif // TSDEBUG_H_INCLUDED
