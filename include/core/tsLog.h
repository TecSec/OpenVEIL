//	Copyright (c) 2018, TecSec, Inc.
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

/*! @file tsLog.h
 * @brief This file defines a set of functions that allow for the use of the CKM Debug Logging system.
*/

#ifndef TSLOG_H_INCLUDED
#define TSLOG_H_INCLUDED

#define DEBUG_LEVEL_SENSITIVE       1
#define DEBUG_LEVEL_DEV_ONLY        2
#define DEBUG_LEVEL_TRACE			3
#define DEBUG_LEVEL_DEBUG			4
#define DEBUG_LEVEL_INFORMATION		5
#define DEBUG_LEVEL_WARNING			6
#define DEBUG_LEVEL_ERROR			7
#define DEBUG_LEVEL_FATAL_ERROR		8
//
// <Debug>
//   <Outputs>
//     <output id="name" type="typename" formatter="{$msg}" {param attrs here}>
//       {may have param nodes here}
//     </output>
//   </Outputs>
//   <!-- Sensitive, DevOnly, Trace, Debug, Info, Warn, Error, Fatal -->
//   <Map>
//     <item id="outputname|*" outputTo="outputid" level="" minlevel="" final="true|false"/>
//   </Map>
//   <Whitelist>log1,log2,log3</Whitelist>
//   <Blacklist>log1,log2,log3</Blacklist>
// </Debug>
//
// Logger names are set in code
// Replaceable parameters in formatter:
//   {$msg}    - The message contents
//   {$thread} - The thread ID formatted as 'tXXXX' where XXXX is the thread ID in hex
//   {$logger} - The name of the source of the message
//   {$level}  - The logging level of this message
//
//
// Loggers predefined and parameters:
//   Consumer       - no parameters
//   Console		- no parameters
//   DebugString	- no parameters
//   File			- filename="filename" deleteFile="1|0"
//

/// <summary>Defines an interface for a debug message consumer</summary>
class VEILCORE_API tsDebugConsumer : public tsmod::IObject
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

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>Writes a line to the output.</summary>
        ///
        /// <param name="category">The category.</param>
        /// <param name="priority">The priority.</param>
        /// <param name="message"> The message.</param>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual void WriteLine(const tscrypto::tsCryptoStringBase &category, int priority, const tscrypto::tsCryptoStringBase &message) = 0;
    virtual bool WantsUnfiltered() const = 0;
};


/**
 * \brief Base class for log output types.
 */
class VEILCORE_API tsLogOutput
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

    tsLogOutput();
    virtual ~tsLogOutput();

    virtual void WriteToOutput(const char *msg) { UNREFERENCED_PARAMETER(msg); };

    virtual void WriteToLog(const tscrypto::tsCryptoString& loggerName, int level, tscrypto::tsCryptoString& msg);
    void setFormatString(const char *formatter);
    tscrypto::tsCryptoString getFormatString() const { return _formatter; }
    tscrypto::tsCryptoString getName() const;
    virtual void indent();
    virtual void outdent();

    // Added 7.0.8
    virtual bool initialize(const tscrypto::JSONObject& node);

protected:
    tsLogOutput(const tsLogOutput &obj);
    virtual tsLogOutput &operator=(const tsLogOutput &obj);
    tscrypto::tsCryptoString &IndentData();

protected:
    tscrypto::tsCryptoString _formatter;
    tscrypto::tsCryptoString _name;
    tscrypto::tsCryptoString _indent;
};


PUSH_WARNINGS
IGNORE_WARNING(TS_DEPRECATED_WARNING)

/**
 * \brief The log writer
 */
class VEILCORE_API tsLog
{
public:
    static void WriteToLog(const char *loggerName, int level, const char *msg);
    static void SetApplicationJsonPreferences(std::shared_ptr<tsJsonPreferencesBase> prefs);
    static std::shared_ptr<tsJsonPreferencesBase> GetApplicationJsonPreferences();
#if (_MSC_VER >= 1700)
    static void RegisterLoggerCreator(const char *typeName, std::function<tsLogOutput *()> creator);
#endif
    static void RegisterLoggerCreator(const char *typeName, tsLogOutput *(*creator)());
    static void UnregisterLoggerCreator(const char *typeName);
    static void UnregisterAllLoggerCreators();
    static void Refresh();
    static void ClearMaps();

    static void AddJsonMap(const tscrypto::tsCryptoStringBase &json);
    static void ConfigureJson(const tscrypto::tsCryptoStringBase &json);
    static void ConfigureJsonMaps(const tscrypto::tsCryptoStringBase &mapjson);
    static void ConfigureMaps(const tscrypto::JSONField& mapsNode);
    static void ConfigureJsonOutputs(const tscrypto::tsCryptoStringBase &outputsjson);
    static void ConfigureOutputs(const tscrypto::JSONField& node);
    static void ConfigureJsonBlacklist(const tscrypto::tsCryptoStringBase &listjson);
    static void ConfigureBlacklist(const tscrypto::JSONField& listNode);
    static void ConfigureJsonWhitelist(const tscrypto::tsCryptoStringBase &listjson);
    static void ConfigureWhitelist(const tscrypto::JSONField& listNode);

    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Adds a consumer to all instances of this class.</summary>
    ///
    /// <param name="consumer">[in] The consumer.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    static void AddMasterConsumer(std::shared_ptr<tsDebugConsumer> consumer);
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Removes a consumer from all instance of this class.</summary>
    ///
    /// <param name="consumer">[in] The consumer.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    static void RemoveMasterConsumer(std::shared_ptr<tsDebugConsumer> consumer);
    /// <summary>Remove all consumers from all instances of this class.</summary>
    static void ClearMasterConsumers();
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Writes a message to all consumers.</summary>
    ///
    /// <param name="category">The category.</param>
    /// <param name="priority">The priority.</param>
    /// <param name="message"> The message.</param>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    static void WriteToConsumers(const tscrypto::tsCryptoStringBase &category, int priority, const tscrypto::tsCryptoStringBase &message);
    static void WriteToUnfilteredConsumers(const tscrypto::tsCryptoStringBase &category, int priority, const tscrypto::tsCryptoStringBase &message);
    static void AllowLogs(const char *logList);
    static void DisallowLogs(const char *logList);
    static void indent(const char *loggerName, int level);
    static void outdent(const char *loggerName, int level);
    static bool WillLog(const char *loggerName, int level);

protected:
    static void CreateDefaultLoggerCreators();
private:
    tsLog() {}
    tsLog(const tsLog &) {}
    ~tsLog() {}
    tsLog &operator=(const tsLog &) { return *this; }
};
POP_WARNINGS


#endif // TSLOG_H_INCLUDED
