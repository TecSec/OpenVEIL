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

#ifndef __VEILCORE_H__
#define __VEILCORE_H__

#pragma once

#if defined(_DEBUG) && defined(_MSC_VER)
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#endif 

#ifdef _WIN32
	#ifdef _STATIC_VEILCORE
		#define VEILCORE_API
		#define VEILCORE_TEMPLATE_EXTERN extern
	#else
		#if defined(VEILCORE_EXPORTS) || defined(VEILCORE_NM_EXPORTS)
			#define EXPORTED_VEILCORE_API __declspec(dllexport)
			#define VEILCORE_API __declspec(dllexport)
			#define VEILCORE_TEMPLATE_EXTERN
		#else
			#define EXPORTED_VEILCORE_API __declspec(dllimport)
			#define VEILCORE_API __declspec(dllimport)
			#define VEILCORE_TEMPLATE_EXTERN extern
		#endif
	#endif
#else
	#if defined(VEILCORE_EXPORTS)
		#define VEILCORE_API EXPORT_SYMBOL
		#define EXPORTED_VEILCORE_API EXPORT_SYMBOL
		#define VEILCORE_TEMPLATE_EXTERN
	#else
		#define VEILCORE_API
		#define EXPORTED_VEILCORE_API EXPORT_SYMBOL
		#define VEILCORE_TEMPLATE_EXTERN extern
	#endif // defined
#endif

#include "VEILCrypto.h"


// Clear all option defines
#undef HAVE_BSTR
#undef SUPPORT_XML

// Now uncomment these options that are valid for the codebase
#ifdef _WIN32
#define HAVE_BSTR
#define SUPPORT_XML
#else
	//#define HAVE_BSTR
#define SUPPORT_XML
#endif

#ifdef _WIN32
#   define ALIGNTO(a) __declspec(align(a))
#else
#   define ALIGNTO(a) __attribute__((aligned(a)))
#endif // _WIN32

#ifdef _M_IX86
/**
* \brief A macro that defines size t cast into an int
*/
#   define SIZE_T_CAST(a) ((int)(a))
#else
/**
* \brief A macro that defines size t cast into an int
*/
#   define SIZE_T_CAST(a) ((INT_PTR)(a))
#endif

template<class Tag, class impl, impl default_value>
class ID
{
public:
	static ID invalid() { return ID{}; }
	ID() : m_val(default_value) { }
	explicit ID(impl val) : m_val(val) {}
	explicit operator impl() const { return m_val; }
	friend bool operator==(ID a, ID b) { return a.m_val == b.m_val; }
	friend bool operator!=(ID a, ID b) { return a.m_val != b.m_val; }
private:
	impl m_val;
};

/*! @brief Defines the type of compression that was applied to the data before it was encrypted
*
* This enumeration defines the types of compression that is currently supported by the CKM encryption process.
*/
typedef enum {
	ct_None,    /*!< The data was not compressed */
	ct_zLib,    /*!< zLib/Zip style compression was used */
	ct_BZ2      /*!< BZ2 compression was used */
} CompressionType;


inline tscrypto::tsCryptoString ToJSONValue(const tscrypto::tsCryptoStringBase& val) { tscrypto::tsCryptoString tmp(val); tmp.Replace("\\", "\\\\").Replace("\"", "\\\""); return tmp; }

inline tscrypto::tsCryptoDataList CreateTsDataList() { return tscrypto::CreateTsCryptoDataList(); }

#include "core/tsmod_extension.h"
#include "core/UrlParser.h"

inline tscrypto::tsCryptoStringList CreateTsAsciiList() { return tscrypto::CreateTsCryptoStringList(); }



namespace tsmod {
	class VEILCORE_API IAlgorithmList : tscrypto::IAlgorithmList
	{
	};
}

namespace tsstd {
	typedef tscrypto::Exception Exception;

	class VEILCORE_API OverflowException : public Exception
	{
	public:
		OverflowException() {}
		OverflowException(const tscrypto::tsCryptoStringBase& msg) : Exception(msg) {}
		OverflowException(const OverflowException& obj) :
			Exception(obj._msg)
		{
		}
		OverflowException(OverflowException&& obj) :
			Exception(std::move(obj._msg))
		{
		}
		virtual ~OverflowException() {}
	};
	class VEILCORE_API DivideByZeroException : public Exception
	{
	public:
		DivideByZeroException() {}
		DivideByZeroException(const tscrypto::tsCryptoStringBase& msg) : Exception(msg) {}
		DivideByZeroException(const DivideByZeroException& obj) :
			Exception(obj._msg)
		{
		}
		DivideByZeroException(DivideByZeroException&& obj) :
			Exception(std::move(obj._msg))
		{
		}
		virtual ~DivideByZeroException() {}
	};
	class VEILCORE_API NotImplementedException : public Exception
	{
	public:
		NotImplementedException() {}
		NotImplementedException(const tscrypto::tsCryptoStringBase& msg) : Exception(msg) {}
		NotImplementedException(const NotImplementedException& obj) :
			Exception(obj._msg)
		{
		}
		NotImplementedException(NotImplementedException&& obj) :
			Exception(std::move(obj._msg))
		{
		}
		virtual ~NotImplementedException() {}
	};
	class VEILCORE_API CommunicationTimeoutException : public Exception
	{
	public:
		CommunicationTimeoutException() {}
		CommunicationTimeoutException(const tscrypto::tsCryptoStringBase& msg) : Exception(msg) {}
		CommunicationTimeoutException(const CommunicationTimeoutException& obj) :
			Exception(obj._msg)
		{
		}
		CommunicationTimeoutException(CommunicationTimeoutException&& obj) :
			Exception(std::move(obj._msg))
		{
		}
		virtual ~CommunicationTimeoutException() {}
	};
	class VEILCORE_API ArgumentNullException : public Exception
	{
	public:
		ArgumentNullException(const tscrypto::tsCryptoStringBase& message) : Exception(message)
		{
		}
	};
	class VEILCORE_API ArgumentException : public Exception
	{
	public:
		ArgumentException(const tscrypto::tsCryptoStringBase& message) : Exception(message)
		{
		}
	};
	class VEILCORE_API OutOfRange : public tscrypto::OutOfRange
	{
	public:
		OutOfRange(const tscrypto::tsCryptoStringBase& message) : tscrypto::OutOfRange(message)
		{
		}
	};
	class VEILCORE_API FileNotFoundException : public Exception
	{
	public:
		FileNotFoundException(const tscrypto::tsCryptoStringBase& message, const tscrypto::tsCryptoStringBase& filename) : Exception(message), _filename(filename)
		{
		}
		tscrypto::tsCryptoString Filename() const { return _filename; }
	private:
		tscrypto::tsCryptoString _filename;
	};

#ifdef _WIN32

#define SE_CASE(nSeCode,TsString) case EXCEPTION_##nSeCode:\
    TsString.Format("Exception %s (0x%.8X) at address 0x%p.", #nSeCode, EXCEPTION_##nSeCode, _excPointers->ExceptionRecord->ExceptionAddress);\
    break;

	class VEILCORE_API SeException : public Exception
	{
	public:
		SeException(UINT nSeCode, struct _EXCEPTION_POINTERS* pExcPointers) :
			_seCode(nSeCode),
			_excPointers(pExcPointers)
		{
			GetErrorMessage(_msg, nullptr);
		}
		SeException(const SeException& obj) :
			Exception(obj),
			_seCode(obj._seCode),
			_excPointers(obj._excPointers)
		{
		}
		SeException(SeException&& obj) :
			Exception(std::move(obj)),
			_seCode(obj._seCode),
			_excPointers(obj._excPointers)
		{
			obj._seCode = 0;
			obj._excPointers = nullptr;
		}
		virtual ~SeException() {}

		UINT GetSeCode() const { return _seCode; }
		_EXCEPTION_POINTERS* GetSePointers() const { return _excPointers; }
		PVOID GetExceptionAddress() const { return _excPointers->ExceptionRecord->ExceptionAddress; }

		void Delete()
		{
			delete this;
		}

		bool GetErrorMessage(tscrypto::tsCryptoStringBase& description, UINT* helpContext)
		{
			bool retVal = true;

			if (helpContext != nullptr)
				*helpContext = 0;

			switch (GetSeCode())
			{
				SE_CASE(ACCESS_VIOLATION, description);
				SE_CASE(DATATYPE_MISALIGNMENT, description);
				SE_CASE(BREAKPOINT, description);
				SE_CASE(SINGLE_STEP, description);
				SE_CASE(ARRAY_BOUNDS_EXCEEDED, description);
				SE_CASE(FLT_DENORMAL_OPERAND, description);
				SE_CASE(FLT_INEXACT_RESULT, description);
				SE_CASE(FLT_DIVIDE_BY_ZERO, description);
				SE_CASE(FLT_INVALID_OPERATION, description);
				SE_CASE(FLT_OVERFLOW, description);
				SE_CASE(FLT_STACK_CHECK, description);
				SE_CASE(FLT_UNDERFLOW, description);
				SE_CASE(INT_DIVIDE_BY_ZERO, description);
				SE_CASE(INT_OVERFLOW, description);
				SE_CASE(PRIV_INSTRUCTION, description);
				SE_CASE(IN_PAGE_ERROR, description);
				SE_CASE(ILLEGAL_INSTRUCTION, description);
				SE_CASE(NONCONTINUABLE_EXCEPTION, description);
				SE_CASE(STACK_OVERFLOW, description);
				SE_CASE(INVALID_DISPOSITION, description);
				SE_CASE(GUARD_PAGE, description);
				SE_CASE(INVALID_HANDLE, description);
			default:
				description = "Unknown exception";
				retVal = false;
				break;
			}
			return retVal;
		}
		static void __cdecl SeTranslator(UINT seCode, struct _EXCEPTION_POINTERS* ptrs)
		{
			throw SeException(seCode, ptrs);
		}
	protected:
		UINT _seCode;
		struct _EXCEPTION_POINTERS* _excPointers;
	};
#endif // _WIN32
}

#include "core/HttpHeader.h"
#include "core/HttpChannel.h"
#include "core/CkmFileStreams.h"
#include "core/CkmFileReader.h"
#include "core/CkmFileWriter.h"
#include "core/CkmMemoryFifoStream.h"
#include "core/CkmMemoryStream.h"
#include "core/CkmReadAppendFile.h"
#include "core/CkmReadWriteFile.h"
#include "core/xp_console.h"

// RFC 1950 compression for HTTP
_Check_return_ bool VEILCORE_API zlibCompress(const uint8_t* src, size_t srcLen, int level, uint8_t* dest, size_t& destLen);
_Check_return_ bool VEILCORE_API zlibDecompress(const uint8_t* src, size_t srcLen, uint8_t* dest, size_t& destLen);
_Check_return_ bool VEILCORE_API zlibDecompress(const uint8_t* src, size_t srcLen, tscrypto::tsCryptoData& outputData);

// RFC 1951 compression for HTTP (raw deflate with no header
_Check_return_ bool VEILCORE_API raw_zlibCompress(const uint8_t* src, size_t srcLen, int level, uint8_t* dest, size_t& destLen);
_Check_return_ bool VEILCORE_API raw_zlibDecompress(const uint8_t* src, size_t srcLen, uint8_t* dest, size_t& destLen);
_Check_return_ bool VEILCORE_API raw_zlibDecompress(const uint8_t* src, size_t srcLen, tscrypto::tsCryptoData& outputData);

// RFC 1952 GZIP compression for HTTP
_Check_return_ bool VEILCORE_API gzipCompress(const uint8_t* src, size_t srcLen, int level, uint8_t* dest, size_t& destLen);
_Check_return_ bool VEILCORE_API gzipDecompress(const uint8_t* src, size_t srcLen, uint8_t* dest, size_t& destLen);
_Check_return_ bool VEILCORE_API gzipDecompress(const uint8_t* src, size_t srcLen, tscrypto::tsCryptoData& outputData);

namespace TecSecResources {
	struct ResourceHeader
	{
		int EntryCount;
		int NameStringTable;
		int DataTable;
	};
	struct NameEntry
	{
		int nameOffset;
		int dataSize;
		int dataOffset;
	};
}


class VEILCORE_API ITestable
{
public:
	virtual ~ITestable() {}
	virtual bool RunSelfTest(bool runDetailedTests) = 0;
};


VEILCORE_API std::shared_ptr<tsmod::IServiceLocator> TopServiceLocator();
VEILCORE_API bool HasServiceLocator();
#ifndef HIDE_SERVICE_LOCATOR
VEILCORE_API std::shared_ptr<tsmod::IServiceLocator> ServiceLocator();
#endif

_Check_return_ extern bool VEILCORE_API GCM_Encrypt(const tscrypto::tsCryptoData &key, const tscrypto::tsCryptoData &iv, const tscrypto::tsCryptoData &authHeader, tscrypto::tsCryptoData &data, tscrypto::tsCryptoData &tag, const char* algorithm = "GCM-AES");
_Check_return_ extern bool VEILCORE_API GCM_Decrypt(const tscrypto::tsCryptoData &key, const tscrypto::tsCryptoData &iv, const tscrypto::tsCryptoData &authHeader, tscrypto::tsCryptoData &data, const tscrypto::tsCryptoData &tag, const char* algorithm = "GCM-AES");

_Check_return_ extern bool VEILCORE_API xp_CreateGuid(GUID &guid);

#ifdef _WIN32
/// <summary>A macro that defines cross platform path separator character.</summary>
#define XP_PATH_SEP_CHAR '\\'
/// <summary>A macro that defines cross platform path separator string.</summary>
#define XP_PATH_SEP_STR "\\"
/// <summary>A macro that defines cross platform pathlist separator.</summary>
#define XP_PATHLIST_SEPARATOR ';'
#else
#define XP_PATH_SEP_CHAR '/'
#define XP_PATH_SEP_STR "/"
#define XP_PATHLIST_SEPARATOR ':'
#endif

#include "TokenPacket.h"
#include "CTSProfile.h"

typedef enum LoginStatus
{
	loginStatus_Connected,
	loginStatus_NoServer,
	loginStatus_BadAuth,
} LoginStatus;

class IKeyVEILConnector;

class VEILCORE_API IKeyVEILSession
{
public:
	virtual ~IKeyVEILSession() {}
	virtual LoginStatus Login(const tscrypto::tsCryptoStringBase& pin) = 0;
	virtual bool IsLoggedIn() = 0;
	virtual bool Logout() = 0;
	virtual bool GenerateWorkingKey(Asn1::CTS::_POD_CkmCombineParameters& params, std::function<bool(Asn1::CTS::_POD_CkmCombineParameters&, tscrypto::tsCryptoData&)> headerCallback, tscrypto::tsCryptoData &WorkingKey) = 0;
	virtual bool RegenerateWorkingKey(Asn1::CTS::_POD_CkmCombineParameters& params, tscrypto::tsCryptoData &WorkingKey) = 0;

	virtual std::shared_ptr<Asn1::CTS::_POD_Profile> GetProfile() = 0;
	virtual bool Close(void) = 0;

	// Added in 7.0.3
	virtual bool IsLocked() = 0;
	virtual size_t retriesLeft() = 0;

	// Added in 7.0.5
	virtual bool IsValid() = 0; // Warning - this also will do a keep-alive.  Session timeout would be restarted for each call made.

	// Added in 7.0.7
	virtual std::shared_ptr<IKeyVEILSession> Duplicate() = 0;

	// Added in 7.0.19
	virtual int LastKeyVEILStatus() = 0;
	virtual std::shared_ptr<IKeyVEILConnector> Connector() = 0;
};

typedef enum ConnectionStatus
{
	connStatus_Connected,
	connStatus_NoServer,
	connStatus_BadAuth,
	connStatus_WrongProtocol,
	connStatus_UrlBad,
} ConnectionStatus;

class VEILCORE_API IToken
{
public:
	virtual ~IToken() {}
	virtual tscrypto::tsCryptoString tokenName() = 0;
	virtual bool tokenName(const tscrypto::tsCryptoStringBase& setTo) = 0;
	virtual tscrypto::tsCryptoData serialNumber() = 0;
	virtual GUID id() = 0;
	virtual tscrypto::tsCryptoString enterpriseName() = 0;
	virtual tscrypto::tsCryptoString memberName() = 0;
	virtual tscrypto::tsCryptoString tokenType() = 0;
	virtual GUID enterpriseId() = 0;
	virtual GUID memberId() = 0;

	virtual std::shared_ptr<IKeyVEILSession> openSession() = 0;
};

class VEILCORE_API IFavorite
{
public:
	virtual ~IFavorite() {}

	virtual GUID favoriteId() = 0;
	virtual void favoriteId(const GUID& setTo) = 0;

	virtual GUID enterpriseId() = 0;
	virtual void enterpriseId(const GUID& setTo) = 0;

	virtual tscrypto::tsCryptoString favoriteName() = 0;
	virtual void favoriteName(const tscrypto::tsCryptoStringBase& setTo) = 0;

	virtual tscrypto::tsCryptoData tokenSerialNumber() = 0;
	virtual void tokenSerialNumber(const tscrypto::tsCryptoData& setTo) = 0;

	virtual tscrypto::tsCryptoData headerData() = 0;
	virtual void headerData(const tscrypto::tsCryptoData& setTo) = 0;
};

class VEILCORE_API IKeyVEILConnector
{
public:
	virtual ~IKeyVEILConnector() {}
	virtual ConnectionStatus connect(const tscrypto::tsCryptoStringBase& url, const tscrypto::tsCryptoStringBase& username, const tscrypto::tsCryptoStringBase& password) = 0;
	virtual void disconnect() = 0;
	virtual bool isConnected() = 0;
	virtual bool refresh() = 0;
	virtual size_t tokenCount() = 0;
	virtual std::shared_ptr<IToken> token(size_t index) = 0;
	virtual std::shared_ptr<IToken> token(const tscrypto::tsCryptoStringBase& tokenName) = 0;
	virtual std::shared_ptr<IToken> token(const tscrypto::tsCryptoData& serialNumber) = 0;
	virtual std::shared_ptr<IToken> token(const GUID& id) = 0;
	virtual bool sendJsonRequest(const tscrypto::tsCryptoStringBase& verb, const tscrypto::tsCryptoStringBase& cmd, const tscrypto::JSONObject &inData, tscrypto::JSONObject& outData, int& status) = 0;

	// Added 7.0.1
	virtual ConnectionStatus genericConnectToServer(const tscrypto::tsCryptoStringBase& url, const tscrypto::tsCryptoStringBase& username, const tscrypto::tsCryptoStringBase& password) = 0;
	virtual bool sendRequest(const tscrypto::tsCryptoStringBase& verb, const tscrypto::tsCryptoStringBase& cmd, const tscrypto::tsCryptoData &inData, tscrypto::tsCryptoData& outData, int& status) = 0;

	// Response data
	virtual tscrypto::tsCryptoString status() const = 0;
	virtual tscrypto::tsCryptoString reason() const = 0;
	virtual tscrypto::tsCryptoString version() const = 0;
	virtual size_t dataPartSize() const = 0;
	virtual const tscrypto::tsCryptoData& dataPart() const = 0;
	virtual WORD errorCode() const = 0;
	virtual size_t attributeCount() const = 0;
	virtual const HttpAttribute* attribute(size_t index) const = 0;
	virtual const HttpAttribute* attributeByName(const tscrypto::tsCryptoStringBase& index) const = 0;
	virtual const HttpAttribute* attributeByName(const char *index) const = 0;

	// Added 7.0.5
	virtual size_t favoriteCount() = 0;
	virtual std::shared_ptr<IFavorite> favorite(size_t index) = 0;
	virtual std::shared_ptr<IFavorite> favorite(const tscrypto::tsCryptoStringBase& name) = 0;
	virtual std::shared_ptr<IFavorite> favorite(const GUID& id) = 0;
	virtual GUID CreateFavorite(std::shared_ptr<IToken> token, const tscrypto::tsCryptoData& headerData, const tscrypto::tsCryptoStringBase& name) = 0;
	virtual GUID CreateFavorite(const GUID& tokenId, const tscrypto::tsCryptoData& headerData, const tscrypto::tsCryptoStringBase& name) = 0;
	virtual GUID CreateFavorite(const tscrypto::tsCryptoData& tokenSerial, const tscrypto::tsCryptoData& headerData, const tscrypto::tsCryptoStringBase& name) = 0;
	virtual bool DeleteFavorite(const GUID& id) = 0;
	virtual bool UpdateFavoriteName(const GUID& id, const tscrypto::tsCryptoStringBase& name) = 0;
	virtual bool UpdateFavorite(const GUID& id, const tscrypto::tsCryptoData& setTo) = 0;
	virtual size_t tokenCountForEnterprise(const GUID& enterprise) = 0;
	virtual std::shared_ptr<IToken> tokenForEnterprise(const GUID& enterprise, size_t index) = 0;
	virtual size_t favoriteCountForEnterprise(const GUID& enterprise) = 0;
	virtual std::shared_ptr<IFavorite> favoriteForEnterprise(const GUID& enterprise, size_t index) = 0;

	// Added 7.0.6
	virtual size_t AddKeyVEILChangeCallback(std::function<void(tscrypto::JSONObject& eventData)> func) = 0; // For details
	virtual size_t AddKeyVEILGeneralChangeCallback(std::function<void()> func) = 0; // for general notice
	virtual void RemoveKeyVEILChangeCallback(size_t cookie) = 0;
};

#include "core/ChangeTracker.h"

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Defines the core functionality needed to implement a Ckm Change Producer</summary>
///
/// <seealso cref="TecSecCrypto_Fips::ICkmChangeProducer"/>
/// <seealso cref="TSDispatchImpl{CkmChangeProducer"/>
////////////////////////////////////////////////////////////////////////////////////////////////////
class VEILCORE_API CkmChangeProducerCore : public ICkmChangeProducer
{
public:
	/// <summary>Default constructor.</summary>
	CkmChangeProducerCore()
	{}
	// ICkmChangeProducer
	virtual void ScanForChanges(void) = 0;

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Scans for changes changes for the CkmChangeProducer interface.</summary>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool ScanChanges(void) { ScanForChanges(); return true; }
};

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Defines the core functionality needed to implement a Ckm Change Consumer</summary>
///
/// <seealso cref="T:TecSecCrypto_Fips::ICkmChangeConsumer"/>
/// <seealso cref="T:TSDispatchImpl{CkmChangeConsumer"/>
////////////////////////////////////////////////////////////////////////////////////////////////////
class VEILCORE_API CkmChangeConsumerCore : public ICkmChangeConsumer
{
public:
	/// <summary>Default constructor.</summary>
	CkmChangeConsumerCore()
	{}
	/**
	* \brief Specifies the type of changes to report.
	*
	* \return A CKMChangeType.
	*/
	virtual CKMChangeType WantsChangesMatching() = 0;
	/**
	* \brief Called by the change system when a desired change type is detected
	*
	* \param [in,out] eventObj If non-null, the event object.
	*/
	virtual void          OnCkmChange(std::shared_ptr<ICkmChangeEvent>& eventObj) = 0;

};

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Defines the core functionality needed to implement a Ckm Change Event</summary>
///
/// <seealso cref="T:TecSecCrypto_Fips::ICkmChangeEvent"/>
/// <seealso cref="T:TSDispatchImpl{CkmChangeEvent"/>
////////////////////////////////////////////////////////////////////////////////////////////////////
class VEILCORE_API CkmChangeEventCore : public ICkmChangeEvent
{
public:
	/// <summary>Default constructor.</summary>
	CkmChangeEventCore()
	{ }
	/**
	* \brief Gets the change type.
	*
	* \return The change type.
	*/
	virtual CKMChangeType GetChangeType() = 0;
};

#include "core/IPreferenceChangeNotify.h"
#include "core/tsJsonPreferencesBase.h"
#include "core/BasicVEILPreferences.h"
#include "core/tsAttributeMap.h"
#include "core/pem.h"
#include "core/nargv.h"


////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Convert the XML escape sequences back into the XML reserved characters.</summary>
///
/// <param name="value">The string to patch.</param>
/// <param name="out">  [in,out] The destination.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
void VEILCORE_API TSPatchValueFromXML(const tscrypto::tsCryptoStringBase &value, tscrypto::tsCryptoStringBase &out);

class VEILCORE_API ToBool //: public boost::static_visitor<bool>
{
public:
	//bool operator()(bool i) const
	//{
	//    return i;
	//}
	//
	bool operator()(int i) const
	{
		return i != 0;
	}

	bool operator()(const tscrypto::tsCryptoStringBase & str) const
	{
		return TsStrToInt(str) != 0;
	}

#ifdef INCLUDE_DATASET
	bool operator()(std::shared_ptr<ObservableDataset> data) const
	{
		return data->rowCount() != 0;
	}
#endif // INCLUDE_DATASET
	bool operator()(GUID data) const
	{
		MY_UNREFERENCED_PARAMETER(data);
		return false;
	}
	bool operator()(const tscrypto::tsCryptoDate& dt) const
	{
		return dt.GetStatus() == tscrypto::tsCryptoDate::valid;
	}
#ifdef INCLUDE_DATASET
	bool operator()(DatasetRow* data) const
	{
		return data != nullptr;
	}
	bool operator()(DatasetColumn* data) const
	{
		return data != nullptr;
	}
#endif // #ifndef INCLUDE_DATASET

	//bool operator()(std::shared_ptr<EnterpriseBuilder::IrootNode> obj)
	//{
	//	return obj.get() != nullptr;
	//}
};

class VEILCORE_API ToInt //: public boost::static_visitor<int>
{
public:
	//int operator()(bool i) const
	//{
	//    return i ? 1 : 0;
	//}
	//
	int operator()(int i) const
	{
		return i;
	}

	int operator()(const tscrypto::tsCryptoStringBase & str) const
	{
		return TsStrToInt(str);
	}

	int operator()(GUID data) const
	{
		MY_UNREFERENCED_PARAMETER(data);
		return 0;
	}
	int operator()(const tscrypto::tsCryptoDate& dt) const
	{
#ifdef HAVE_BSTR
		tscrypto::tsCryptoDate tmp(dt);
		return (int)tmp.ToOleDate();
#else
		return tscrypto::SYSTEMTIMEtoJulian(dt.GetYear(), dt.GetMonth(), dt.GetDay()) - tscrypto::SYSTEMTIMEtoJulian(1899, 12, 30);
#endif
	}
#ifdef INCLUDE_DATASET
	int operator()(std::shared_ptr<ObservableDataset> data) const
	{
		return (int)data->rowCount();
	}
	int operator()(DatasetRow* data) const
	{
		return data != nullptr ? 1 : 0;
	}
	int operator()(DatasetColumn* data) const
	{
		return data != nullptr ? 1 : 0;
	}
#endif // #ifdef INCLUDE_DATASET
	//int operator()(std::shared_ptr<EnterpriseBuilder::IrootNode> obj)
	//{
	//	MY_UNREFERENCED_PARAMETER(obj);
	//	return 0;
	//}
};

class VEILCORE_API ToHex //: public boost::static_visitor<GUID>
{
public:
	tscrypto::tsCryptoString operator()(int8_t i) const
	{
		tscrypto::tsCryptoString tmp;
		tmp.Format("%02X", i);
		return tmp;
	}
	tscrypto::tsCryptoString operator()(int16_t i) const
	{
		tscrypto::tsCryptoString tmp;
		tmp.Format("%04X", i);
		return tmp;
	}
	tscrypto::tsCryptoString operator()(int32_t i) const
	{
		tscrypto::tsCryptoString tmp;
		tmp.Format("%08X", i);
		return tmp;
	}
	tscrypto::tsCryptoString operator()(int64_t i) const
	{
		tscrypto::tsCryptoString tmp;
		tmp.Format("%016LLX", i);
		return tmp;
	}
	tscrypto::tsCryptoString operator()(uint8_t i) const
	{
		tscrypto::tsCryptoString tmp;
		tmp.Format("%02X", i);
		return tmp;
	}
	tscrypto::tsCryptoString operator()(uint16_t i) const
	{
		tscrypto::tsCryptoString tmp;
		tmp.Format("%04X", i);
		return tmp;
	}
	tscrypto::tsCryptoString operator()(uint32_t i) const
	{
		tscrypto::tsCryptoString tmp;
		tmp.Format("%08X", i);
		return tmp;
	}
	tscrypto::tsCryptoString operator()(uint64_t i) const
	{
		tscrypto::tsCryptoString tmp;
		tmp.Format("%016LLX", i);
		return tmp;
	}
	tscrypto::tsCryptoString operator()(const void* i) const
	{
		tscrypto::tsCryptoString tmp;
		tmp.Format("%p", i);
		return tmp;
	}
	tscrypto::tsCryptoString operator()(double i) const
	{
		tscrypto::tsCryptoString tmp;
		tmp.Format("%lf", i);
		return tmp;
	}
};

class VEILCORE_API ToGuid //: public boost::static_visitor<GUID>
{
public:
	//GUID operator()(bool i) const
	//{
	//    MY_UNREFERENCED_PARAMETER(i);
	//    return GUID_NULL;
	//}
	//
	GUID operator()(int i) const
	{
		MY_UNREFERENCED_PARAMETER(i);
		return GUID_NULL;
	}

	GUID operator()(const tscrypto::tsCryptoStringBase & str) const
	{
		return TSStringToGuid(str);
	}

	GUID operator()(GUID data) const
	{
		return data;
	}
	GUID operator()(const tscrypto::tsCryptoDate& dt) const
	{
		MY_UNREFERENCED_PARAMETER(dt);
		return GUID_NULL;
	}
#ifdef INCLUDE_DATASET
	GUID operator()(std::shared_ptr<ObservableDataset> data) const
	{
		return GUID_NULL;
	}
	GUID operator()(DatasetRow* data) const
	{
		MY_UNREFERENCED_PARAMETER(data);
		return GUID_NULL;
	}
	GUID operator()(DatasetColumn* data) const
	{
		MY_UNREFERENCED_PARAMETER(data);
		return GUID_NULL;
	}
#endif // #ifdef INCLUDE_DATASET
	//GUID operator()(std::shared_ptr<EnterpriseBuilder::IrootNode> obj)
	//{
	//	MY_UNREFERENCED_PARAMETER(obj);
	//	return GUID_NULL;
	//}
};

class VEILCORE_API ToString //: public boost::static_visitor<tscrypto::tsCryptoString>
{
public:
	tscrypto::tsCryptoString operator()(bool i) const
	{
		return i ? "true" : "false";
	}

	tscrypto::tsCryptoString operator()(int8_t i) const
	{
		return tscrypto::tsCryptoString().append(i);
	}
	tscrypto::tsCryptoString operator()(uint8_t i) const
	{
		return tscrypto::tsCryptoString().append(i);
	}
	tscrypto::tsCryptoString operator()(int16_t i) const
	{
		return tscrypto::tsCryptoString().append(i);
	}
	tscrypto::tsCryptoString operator()(uint16_t i) const
	{
		return tscrypto::tsCryptoString().append(i);
	}
	tscrypto::tsCryptoString operator()(int32_t i) const
	{
		return tscrypto::tsCryptoString().append(i);
	}
	tscrypto::tsCryptoString operator()(uint32_t i) const
	{
		return tscrypto::tsCryptoString().append(i);
	}
	tscrypto::tsCryptoString operator()(int64_t i) const
	{
		return tscrypto::tsCryptoString().append(i);
	}
	tscrypto::tsCryptoString operator()(uint64_t i) const
	{
		return tscrypto::tsCryptoString().append(i);
	}

	tscrypto::tsCryptoString operator()(const tscrypto::tsCryptoString & str) const
	{
		return str;
	}

	tscrypto::tsCryptoString operator()(GUID data) const
	{
		return tscrypto::TSGuidToString(data);
	}
	tscrypto::tsCryptoString operator()(const tscrypto::tsCryptoDate& dt) const
	{
		return dt.AsISO8601Time();
	}
#ifdef INCLUDE_DATASET
	tscrypto::tsCryptoString operator()(std::shared_ptr<ObservableDataset> data) const
	{
		return tscrypto::tsCryptoString() << "ObservableDataset at " << (void*)data.get();
	}
	tscrypto::tsCryptoString operator()(DatasetRow* data) const
	{
		return tscrypto::tsCryptoString() << "DatasetRow at " << (void*)data;
	}
	tscrypto::tsCryptoString operator()(DatasetColumn* data) const
	{
		return tscrypto::tsCryptoString() << "DatasetColumn at " << (void*)data;
	}
#endif // #ifdef INCLUDE_DATASET
	//tscrypto::tsCryptoString operator()(std::shared_ptr<EnterpriseBuilder::IrootNode> obj)
	//{
	//	return obj->NodeName();
	//}
	tscrypto::tsCryptoString operator()(double val) const
	{
		return tscrypto::tsCryptoString().Format("%lf", val);
	}
};

#ifdef INCLUDE_DATASET
class VEILCORE_API ToDataset //: public boost::static_visitor<std::shared_ptr<ObservableDataset> >
{
public:
	//std::shared_ptr<ObservableDataset> operator()(bool i) const
	//{
	//    MY_UNREFERENCED_PARAMETER(i);
	//    return nullptr;
	//}
	//
	std::shared_ptr<ObservableDataset> operator()(int i) const
	{
		MY_UNREFERENCED_PARAMETER(i);
		return nullptr;
	}

	std::shared_ptr<ObservableDataset> operator()(const tscrypto::tsCryptoString & str) const
	{
		MY_UNREFERENCED_PARAMETER(str);
		return nullptr;
	}

	std::shared_ptr<ObservableDataset> operator()(std::shared_ptr<ObservableDataset> data) const
	{
		return data;
	}
	std::shared_ptr<ObservableDataset> operator()(GUID data) const
	{
		MY_UNREFERENCED_PARAMETER(data);
		return nullptr;
	}
	std::shared_ptr<ObservableDataset> operator()(const tscrypto::tsCryptoDate& dt) const
	{
		MY_UNREFERENCED_PARAMETER(dt);
		return nullptr;
	}
	std::shared_ptr<ObservableDataset> operator()(DatasetRow* data) const
	{
		MY_UNREFERENCED_PARAMETER(data);
		return nullptr;
	}
	std::shared_ptr<ObservableDataset> operator()(DatasetColumn* data) const
	{
		MY_UNREFERENCED_PARAMETER(data);
		return nullptr;
	}
	//std::shared_ptr<ObservableDataset> operator()(std::shared_ptr<EnterpriseBuilder::IrootNode> obj)
	//{
	//	MY_UNREFERENCED_PARAMETER(obj);
	//	return nullptr;
	//}
};
#endif // #ifdef INCLUDE_DATASET

class VEILCORE_API ToTsDate //: public boost::static_visitor<tscrypto::tsCryptoDate>
{
public:
	//tscrypto::tsCryptoDate operator()(bool i) const
	//{
	//    return i;
	//}
	//
	tscrypto::tsCryptoDate operator()(int i) const
	{
		tscrypto::tsCryptoDate dt((DATE)i);
		return dt;
	}

	tscrypto::tsCryptoDate operator()(const tscrypto::tsCryptoStringBase & str) const
	{
		tscrypto::tsCryptoDate dt(str, tscrypto::tsCryptoDate::ISO8601);
		return dt;
	}

	tscrypto::tsCryptoDate operator()(GUID data) const
	{
		MY_UNREFERENCED_PARAMETER(data);
		return tscrypto::tsCryptoDate();
	}
	tscrypto::tsCryptoDate operator()(const tscrypto::tsCryptoDate& dt) const
	{
		return dt;
	}
#ifdef INCLUDE_DATASET
	tscrypto::tsCryptoDate operator()(std::shared_ptr<ObservableDataset> data) const
	{
		MY_UNREFERENCED_PARAMETER(data);
		return tscrypto::tsCryptoDate();
	}
	tscrypto::tsCryptoDate operator()(DatasetRow* data) const
	{
		MY_UNREFERENCED_PARAMETER(data);
		return tscrypto::tsCryptoDate();
	}
	tscrypto::tsCryptoDate operator()(DatasetColumn* data) const
	{
		MY_UNREFERENCED_PARAMETER(data);
		return tscrypto::tsCryptoDate();
	}
#endif // #ifdef INCLUDE_DATASET
	//tscrypto::tsCryptoDate operator()(std::shared_ptr<EnterpriseBuilder::IrootNode> obj)
	//{
	//	MY_UNREFERENCED_PARAMETER(obj);
	//	return tscrypto::tsCryptoDate();
	//}
};
#ifdef INCLUDE_DATASET
class VEILCORE_API ToDatasetRow //: public boost::static_visitor<DatasetRow* >
{
public:
	//std::shared_ptr<ObservableDataset> operator()(bool i) const
	//{
	//    MY_UNREFERENCED_PARAMETER(i);
	//    return nullptr;
	//}
	//
	DatasetRow* operator()(int i) const
	{
		MY_UNREFERENCED_PARAMETER(i);
		return nullptr;
	}

	DatasetRow* operator()(const tscrypto::tsCryptoStringBase & str) const
	{
		MY_UNREFERENCED_PARAMETER(str);
		return nullptr;
	}

	DatasetRow* operator()(std::shared_ptr<ObservableDataset> data) const
	{
		MY_UNREFERENCED_PARAMETER(data);
		return nullptr;
	}
	DatasetRow* operator()(GUID data) const
	{
		MY_UNREFERENCED_PARAMETER(data);
		return nullptr;
	}
	DatasetRow* operator()(const tscrypto::tsCryptoDate& dt) const
	{
		MY_UNREFERENCED_PARAMETER(dt);
		return nullptr;
	}
	DatasetRow* operator()(DatasetRow* data) const
	{
		return data;
	}
	DatasetRow* operator()(DatasetColumn* data) const
	{
		MY_UNREFERENCED_PARAMETER(data);
		return nullptr;
	}
	//DatasetRow* operator()(std::shared_ptr<EnterpriseBuilder::IrootNode> obj)
	//{
	//	MY_UNREFERENCED_PARAMETER(obj);
	//	return nullptr;
	//}
};

class VEILCORE_API ToDatasetColumn //: public boost::static_visitor<DatasetColumn* >
{
public:
	//std::shared_ptr<ObservableDataset> operator()(bool i) const
	//{
	//    MY_UNREFERENCED_PARAMETER(i);
	//    return nullptr;
	//}
	//
	DatasetColumn* operator()(int i) const
	{
		MY_UNREFERENCED_PARAMETER(i);
		return nullptr;
	}

	DatasetColumn* operator()(const tscrypto::tsCryptoStringBase & str) const
	{
		MY_UNREFERENCED_PARAMETER(str);
		return nullptr;
	}

	DatasetColumn* operator()(std::shared_ptr<ObservableDataset> data) const
	{
		MY_UNREFERENCED_PARAMETER(data);
		return nullptr;
	}
	DatasetColumn* operator()(GUID data) const
	{
		MY_UNREFERENCED_PARAMETER(data);
		return nullptr;
	}
	DatasetColumn* operator()(const tscrypto::tsCryptoDate& dt) const
	{
		MY_UNREFERENCED_PARAMETER(dt);
		return nullptr;
	}
	DatasetColumn* operator()(DatasetRow* data) const
	{
		MY_UNREFERENCED_PARAMETER(data);
		return nullptr;
	}
	DatasetColumn* operator()(DatasetColumn* data) const
	{
		return data;
	}
	//DatasetColumn* operator()(std::shared_ptr<EnterpriseBuilder::IrootNode> obj)
	//{
	//	MY_UNREFERENCED_PARAMETER(obj);
	//	return nullptr;
	//}
};
#endif // #ifdef INCLUDE_DATASET

VEILCORE_API void AddSystemInitializationFunction(std::function<bool()> func);
VEILCORE_API void AddSystemTerminationFunction(std::function<bool()> func);
VEILCORE_API void RunInitializers();
VEILCORE_API void TerminateVEILSystem();

_Check_return_ extern VEILCORE_API bool TSGenerateRandom(tscrypto::tsCryptoData& data, size_t lenInBytes);
_Check_return_ extern VEILCORE_API bool TSGenerateRandom(uint8_t* data, size_t lenInBytes);
_Check_return_ extern VEILCORE_API bool TSGenerateStrongRandom(tscrypto::tsCryptoData& data, size_t lenInBytes);
_Check_return_ extern VEILCORE_API bool TSGenerateStrongRandom(uint8_t* data, size_t lenInBytes);
_Check_return_ extern VEILCORE_API bool TSWrap(const tscrypto::tsCryptoData &key, const tscrypto::tsCryptoData &dataToWrap, tscrypto::tsCryptoData &wrappedData, tscrypto::TS_ALG_ID alg = tscrypto::_TS_ALG_ID::TS_ALG_KEYWRAP_AES256);
_Check_return_ extern VEILCORE_API bool TSUnwrap(const tscrypto::tsCryptoData &key, const tscrypto::tsCryptoData &dataToUnwrap, tscrypto::tsCryptoData &unwrappedData, tscrypto::TS_ALG_ID alg = tscrypto::_TS_ALG_ID::TS_ALG_KEYWRAP_AES256);
_Check_return_ extern VEILCORE_API bool TSPad(tscrypto::tsCryptoData& value, int blockSize);
_Check_return_ extern VEILCORE_API bool TSUnpad(tscrypto::tsCryptoData& value, int blockSize);
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Create a context to allow the encryption of data using a symmetric algorithm</summary>
///
/// <param name="Key">	  The key.</param>
/// <param name="IV">	  The initialization vector.</param>
/// <param name="Context">[out] The context.</param>
/// <param name="AlgID">  (optional) identifier for the algorithm.</param>
///
/// <returns>S_OK for success, otherwise a standard COM error code.</returns>
/// <seealso cref="tsCrypto::TSEncrypt"/>
////////////////////////////////////////////////////////////////////////////////////////////////////
_Check_return_ extern VEILCORE_API bool TSEncryptInit(const tscrypto::tsCryptoData &Key, const tscrypto::tsCryptoData &IV, tscrypto::CryptoContext &Context, tscrypto::TS_ALG_ID AlgID = tscrypto::_TS_ALG_ID::TS_ALG_INVALID);
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Encrypts data</summary>
///
/// <param name="source"> Source data to encrypt</param>
/// <param name="dest">   [in,out] Destination for the encrypted data</param>
/// <param name="Context">[in,out] The context from tsCrypto::TSEncryptInit.</param>
///
/// <returns>S_OK for success, otherwise a standard COM error code.</returns>
/// <seealso cref="tsCrypto::TSEncryptInit"/>
////////////////////////////////////////////////////////////////////////////////////////////////////
_Check_return_ extern VEILCORE_API bool TSEncrypt(const tscrypto::tsCryptoData &source, tscrypto::tsCryptoData &dest, tscrypto::CryptoContext &Context);
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Create a context to allow the encryption of data using a symmetric algorithm</summary>
///
/// <param name="Key">	  The key.</param>
/// <param name="IV">	  The initialization vector.</param>
/// <param name="Context">[in,out] The context.</param>
/// <param name="AlgID">  (optional) identifier for the algorithm.</param>
///
/// <returns>S_OK for success, otherwise a standard COM error code.</returns>
/// <seealso cref="tsCrypto::TSDecrypt"/>
////////////////////////////////////////////////////////////////////////////////////////////////////
_Check_return_ extern VEILCORE_API bool TSDecryptInit(const tscrypto::tsCryptoData &Key, const tscrypto::tsCryptoData &IV, tscrypto::CryptoContext &Context, tscrypto::TS_ALG_ID AlgID = tscrypto::_TS_ALG_ID::TS_ALG_INVALID);
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Decrypts data</summary>
///
/// <param name="source"> Source data to decrypt</param>
/// <param name="dest">   [in,out] Destination for the decrypted data</param>
/// <param name="Context">[in,out] The context from tsCrypto::TSDecryptInit.</param>
///
/// <returns>S_OK for success, otherwise a standard COM error code.</returns>
/// <seealso cref="tsCrypto::TSEncryptInit"/>
////////////////////////////////////////////////////////////////////////////////////////////////////
_Check_return_ extern VEILCORE_API bool TSDecrypt(const tscrypto::tsCryptoData &source, tscrypto::tsCryptoData &dest, tscrypto::CryptoContext &Context);


_Check_return_ bool VEILCORE_API TSBytesToKey(const tscrypto::tsCryptoData &Bytes, tscrypto::tsCryptoData &Key, tscrypto::TS_ALG_ID AlgID);

VEILCORE_API void xor8(const uint8_t* src, const uint8_t* second, uint8_t* dest);
VEILCORE_API void xor16(const uint8_t* src, const uint8_t* second, uint8_t* dest);
VEILCORE_API void xor32(const uint8_t* src, const uint8_t* second, uint8_t* dest);

#include "core/tsLog.h"
#include "core/tsTraceStream.h"
#include "core/tsDebugStream.h"
#include "core/tsDebug.h"

#include "core/IPropertyMap.h"
#include "core/INotifyPropertyChange.h"

#include "core/tsXmlError.h"
#include "core/tsXmlNode.h"
#include "core/tsXmlParserCallback.h"
#include "core/tsXmlParser.h"
#include "core/tsAppConfig.h"
#include "core/tsPreferencesBase.h"
#include "core/tsThread.h"
#include "core/SimpleOpt.h"
#include "core/IOutputCollector.h"
#include "core/IVeilToolCommand.h"
#include "core/IVeilUtilities.h"


/// <summary>Defines an alias representing the function that converts an error number to a message.</summary>
typedef tscrypto::tsCryptoString(*GetErrorStringFn)(int errorNumber);
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Sets the function that the crypto library shall use to convert error numbers into messages.</summary>
///
/// <param name="fn">The function.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
extern VEILCORE_API void SetErrorStringFunction(GetErrorStringFn fn);
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Converts an error number into a string using the function set with <see cref="SetErrorStringFunction"/>.</summary>
///
/// <param name="errorNumber">The error number.</param>
///
/// <returns>The error string.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
extern VEILCORE_API tscrypto::tsCryptoString GetErrorString(int errorNumber);

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Convert the error information into an XML string and append it to Results</summary>
///
/// <param name="Results">	  [in,out] The results.</param>
/// <param name="component">  The component where the error occurred.</param>
/// <param name="NodeName">   Name of the node.</param>
/// <param name="ErrorNumber">The error number.</param>
/// <param name="vArg">		  The arguments to the error message.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
void VEILCORE_API TSAddXMLError(tscrypto::tsCryptoStringBase &Results, const tscrypto::tsCryptoStringBase &component, const tscrypto::tsCryptoStringBase &NodeName, int32_t ErrorNumber, va_list vArg);
void VEILCORE_API TSAddToXML(tscrypto::tsCryptoStringBase &xml, const tscrypto::tsCryptoStringBase& AttrName, const tscrypto::tsCryptoStringBase& value);
void VEILCORE_API TSAddGuidToXML(tscrypto::tsCryptoStringBase &xml, const tscrypto::tsCryptoStringBase& AttrName, const GUID &id);

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Bitwise 'exclusive or' operator for GUIDs.</summary>
///
/// <param name="left"> The left GUID.</param>
/// <param name="right">The right GUID.</param>
///
/// <returns>The result of the operation.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
inline GUID operator ^(const GUID &left, const GUID &right)
{
	uint32_t *l, *r, *t;
	GUID tmp;

	l = ((uint32_t*)&left);
	r = ((uint32_t*)&right);
	t = ((uint32_t*)&tmp);

	for (int i = 0; i < sizeof(GUID) / sizeof(uint32_t); i++)
	{
		t[i] = l[i] ^ r[i];
	}
	return tmp;
}
/**
* \brief Greater-than comparison operator for GUIDs.
*
* \param left  The first instance to compare.
* \param right The second instance to compare.
*
* \return true if the first parameter is greater than to the second.
*/
inline bool operator>(const GUID& left, const GUID& right)
{
	return memcmp(&left, &right, sizeof(GUID)) > 0;
}
/**
* \brief Greater-than-or-equal comparison operator for GUIDs.
*
* \param left  The first instance to compare.
* \param right The second instance to compare.
*
* \return true if the first parameter is greater than or equal to the second.
*/
inline bool operator>=(const GUID& left, const GUID& right)
{
	return memcmp(&left, &right, sizeof(GUID)) >= 0;
}
/**
* \brief Less-than comparison operator for GUIDs.
*
* \param left  The first instance to compare.
* \param right The second instance to compare.
*
* \return true if the first parameter is less than the second.
*/
inline bool operator<(const GUID& left, const GUID& right)
{
	return memcmp(&left, &right, sizeof(GUID)) < 0;
}
/**
* \brief Less-than-or-equal comparison operator for GUIDs.
*
* \param left  The first instance to compare.
* \param right The second instance to compare.
*
* \return true if the first parameter is less than or equal to the second.
*/
inline bool operator<=(const GUID& left, const GUID& right)
{
	return memcmp(&left, &right, sizeof(GUID)) <= 0;
}

class VEILCORE_API DataProtector
{
public:
	virtual bool Active() = 0;
	virtual bool Activate() = 0;
	virtual bool ProtectData(const GUID &objectId, const tscrypto::tsCryptoData &authenticationData, const tscrypto::tsCryptoData &inData, tscrypto::tsCryptoData &outData) = 0;
	virtual bool UnprotectData(const GUID &objectId, const tscrypto::tsCryptoData &authenticationData, const tscrypto::tsCryptoData &inData, tscrypto::tsCryptoData &outData) = 0;
};


class ISignalArgs;
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4231)
VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::function<void(IUnknown*, ISignalArgs*)>;
#pragma warning(pop)
#endif // _MSC_VER

class VEILCORE_API ISignalArgs
{
public:
	virtual ~ISignalArgs() {}
};

class VEILCORE_API IPropertyChangedEventArgs : public ISignalArgs
{
public:
	virtual tscrypto::tsCryptoString PropertyName() = 0;
};

class VEILCORE_API INotifyPropertyChanged
{
public:
	virtual size_t AddPropertyChangedEvent(std::function<void(const tsmod::IObject*, IPropertyChangedEventArgs*)> func) = 0;
	virtual void RemovePropertyChangedEvent(size_t cookie) = 0;
	virtual void OnPropertyChanged(const tsmod::IObject* object, const tscrypto::tsCryptoStringBase& args) const = 0;
	virtual void OnPropertyChanged(const tsmod::IObject* object, IPropertyChangedEventArgs* args) const = 0;
};

class VEILCORE_API tsStringSignal
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

	tsStringSignal();
	~tsStringSignal();
	size_t Add(std::function<void(const tscrypto::tsCryptoStringBase&)> func);
	void Remove(size_t cookie);
	void Fire(const tscrypto::tsCryptoStringBase& param) const;
	void clear();

protected:
	void *contents;
};
class VEILCORE_API tsIObjStringSignal
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

	tsIObjStringSignal();
	~tsIObjStringSignal();
	size_t Add(std::function<void(const tsmod::IObject*, const tscrypto::tsCryptoStringBase&)> func);
	void Remove(size_t cookie);
	void Fire(const tsmod::IObject* object, const tscrypto::tsCryptoStringBase& param) const;
	void clear();

protected:
	void *contents;
};
class VEILCORE_API tsIObjStringVarStringSignal
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

	tsIObjStringVarStringSignal();
	~tsIObjStringVarStringSignal();
	size_t Add(std::function<void(const tsmod::IObject*, const tscrypto::tsCryptoStringBase&, tscrypto::tsCryptoStringBase&)> func);
	void Remove(size_t cookie);
	void Fire(const tsmod::IObject* object, const tscrypto::tsCryptoStringBase& param, tscrypto::tsCryptoStringBase& varString) const;
	void clear();

protected:
	void *contents;
};
class VEILCORE_API tsIObjPacketSignal
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

	tsIObjPacketSignal();
	~tsIObjPacketSignal();
	size_t Add(std::function<void(const tsmod::IObject*, uint8_t packetType, const uint8_t* data, uint32_t dataLen)> func);
	void Remove(size_t cookie);
	void Fire(const tsmod::IObject* object, uint8_t packetType, const uint8_t* data, uint32_t dataLen) const;
	void clear();

protected:
	void *contents;
};
class VEILCORE_API tsIObjectSignal
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

	tsIObjectSignal();
	~tsIObjectSignal();
	size_t Add(std::function<void(const tsmod::IObject*)> func);
	void Remove(size_t cookie);
	void Fire(const tsmod::IObject* object) const;
	void clear();

protected:
	void *contents;
};

class VEILCORE_API tsIObjectUint32Signal
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

	tsIObjectUint32Signal();
	~tsIObjectUint32Signal();
	size_t Add(std::function<void(const tsmod::IObject*, uint32_t)> func);
	void Remove(size_t cookie);
	void Fire(const tsmod::IObject* object, uint32_t value) const;
	void clear();

protected:
	void *contents;
};

class VEILCORE_API tsVoidSignal
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

	tsVoidSignal();
	~tsVoidSignal();
	size_t Add(std::function<void()> func);
	void Remove(size_t cookie);
	void Fire() const;
	void clear();

protected:
	void *contents;
};
class VEILCORE_API tsSignal
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

	tsSignal();
	~tsSignal();
	size_t Add(std::function<void(const tsmod::IObject*, ISignalArgs*)> func);
	void Remove(size_t cookie);
	void Fire(const tsmod::IObject*object, ISignalArgs*args) const;
	void clear();
protected:
	void *contents;
};
class VEILCORE_API tsPropChangeSignal
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

	tsPropChangeSignal();
	~tsPropChangeSignal();
	size_t Add(std::function<void(const tsmod::IObject*, IPropertyChangedEventArgs*)> func);
	void Remove(size_t cookie);
	void Fire(const tsmod::IObject*object, IPropertyChangedEventArgs*args) const;
	void clear();
protected:
	void *contents;
};

_Check_return_ extern VEILCORE_API bool CreatePropertyChangedEventArgs(const tscrypto::tsCryptoStringBase& propertyName, std::shared_ptr<IPropertyChangedEventArgs>& pVal);

tscrypto::tsCryptoString VEILCORE_API ToXml(const char *src, const char* nullValue = "");
tscrypto::tsCryptoString VEILCORE_API ToXml(const tscrypto::tsCryptoStringBase &src, const char* nullValue = "");
tscrypto::tsCryptoString VEILCORE_API ToXml(const GUID &src, const char* nullValue = "");
tscrypto::tsCryptoString VEILCORE_API ToXml(bool src, const char* nullValue = "");
tscrypto::tsCryptoString VEILCORE_API ToXml(int src, const char* nullValue = "");
tscrypto::tsCryptoString VEILCORE_API ToXml(double src, const char* nullValue = "");
tscrypto::tsCryptoString VEILCORE_API ToXml(const tscrypto::tsCryptoDate &src, const char* nullValue = "");
//tscrypto::tsCryptoString VEILCORE_API ToXml(bool exists, const char* src, const char* nullValue = "");
//tscrypto::tsCryptoString VEILCORE_API ToXml(bool exists, const tscrypto::tsCryptoStringBase &src, const char* nullValue = "");
//tscrypto::tsCryptoString VEILCORE_API ToXml(bool exists, const GUID &src, const char* nullValue = "");
//tscrypto::tsCryptoString VEILCORE_API ToXml(bool exists, bool src, const char* nullValue = "");
//tscrypto::tsCryptoString VEILCORE_API ToXml(bool exists, int src, const char* nullValue = "");
//tscrypto::tsCryptoString VEILCORE_API ToXml(bool exists, double src, const char* nullValue = "");
//tscrypto::tsCryptoString VEILCORE_API ToXml(bool exists, const tscrypto::tsCryptoDate &src, const char* nullValue = "");

VEILCORE_API uint32_t xp_GetUserName(tscrypto::tsCryptoStringBase& name);
VEILCORE_API uint32_t xp_GetComputerName(tscrypto::tsCryptoStringBase& name);

#endif // Header Protector
