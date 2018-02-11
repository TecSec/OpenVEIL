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

/// \file VEILCrypto.h

#ifndef __VEILCRYPTO_H__
#define __VEILCRYPTO_H__

#pragma once

#ifdef __APPLE__
#   include "CyberVEIL/CyberVEIL.h"
#   include "CyberVEILsup/CyberVEILsup.h"
#   include "CyberVEILdb/CyberVEILdb.h"
#   include "CyberVEILnet/CyberVEILnet.h"
#   include "CyberVEILsc/CyberVEILsc.h"
#else
#   include "CyberVEIL.h"
#   include "CyberVEILsup.h"
#   include "CyberVEILdb.h"
#   include "CyberVEILnet.h"
#   include "CyberVEILsc.h"
#endif

#ifndef _WIN32
#   include <sys/socket.h>
#   include <sys/un.h> 
#   include <netinet/ip.h>
#   include <netdb.h>
#   include <arpa/inet.h>
#   define SOCKET_ERROR -1

static inline bool operator!=(const GUID& left, const GUID& right) { return memcmp(&left, &right, sizeof(GUID)) != 0; }
#endif

#ifdef NO_LOGGING
#define LOG(a,...)
#define TSRETURN_ERROR(a,b) b
#define TSRETURN(a,b) b
#define TSRETURN_V(a,...)
#define TSDECLARE_METHODExt(a)
#define TSDECLARE_FUNCTIONExt(a)
#endif

/*! \defgroup HighLevelHelpers High Level Helpers
*/

/*! \defgroup LowLevelClasses Low Level Foundation classes and functions
*/

//
// Use these defines to help remove Microsoft specific code
//
//#undef S_OK
//#define S_OK asdfadsfadsf
//#undef E_FAIL
//#define E_FAIL asdfadfadsf
//#undef E_POINTER
//#define E_POINTER asdfadfadsf
//#undef E_INVALIDARG
//#define E_INVALIDARG asdfadfadsf
//#undef S_FALSE
//#define S_FALSE asdfadfadsf
//#undef STDMETHODCALLTYPE
//#define STDMETHODCALLTYPE asfadsfasdf
//
// The following symbols are required for bzip2 and a few windows specific function calls.  When you uncomment these defines some code will not compile under windows.
//
//#define __stdcall asdfadsfasdf
//#define HRESULT asdfadsfadf
//#undef SUCCEEDED
//#define SUCCEEDED asdfadfadsf
//#undef FAILED
//#define FAILED asdfadfadsf


#if defined(_WIN32) && !defined(MSYS) && !defined(MINGW)
#   define SEH_TRY __try{
#   define SEH_CATCH }__except(EXCEPTION_EXECUTE_HANDLER){
#   define SEH_DONE }
#else
#   define SEH_TRY try{
#   define SEH_CATCH }catch(...){
#   define SEH_DONE }
#endif // _WIN32

/// <summary>
/// The tscrypto namespace.
/// </summary>
namespace tscrypto
{
	extern VEILCORE_API void* cryptoNew(size_t size);
	extern VEILCORE_API void cryptoDelete(void* ptr);
	/// <summary>
	/// Used to create ad hock cleanup code.
	/// </summary>
	template <typename F>
	struct FinalAction
	{
		/// <summary>
		/// Initializes a new instance of the <see cref="FinalAction{F}"/> struct.
		/// </summary>
		/// <param name="f">The function to run that performs the cleanup operation.</param>
		FinalAction(F f) : clean_(f) {}
		/// <summary>
		/// Finalizes an instance of the <see cref="FinalAction{F}"/> class.
		/// </summary>
		~FinalAction() { clean_(); }
		/// <summary>
		/// The cleanup function.
		/// </summary>
		F clean_;
	};
	/// <summary>
	/// Creates an object that when it goes out of scope will call the specified function or lambda to perform clean operations.
	/// </summary>
	/// <param name="f">The function that is to be run during cleanup.</param>
	/// <returns>The object that handles the cleanup.</returns>
	template <typename F>
	tscrypto::FinalAction<F> finally(F f) { return tscrypto::FinalAction<F>(f); }

	/// <summary>
	/// This template class is used to safely encapsulate a handle and make it opaque.  This helps for type safety and to make math operations not work.
	/// </summary>
	template<class Tag, class impl, impl default_value>
	class ID
	{
	public:
		/// <summary>
		/// A value that represents the "Invalid" state for this ID type.
		/// </summary>
		/// <returns>ID&lt;Tag, impl, default_value&gt;.</returns>
		static ID invalid() { return ID{}; }
		/// <summary>
		/// Initializes a new instance of the <see cref="ID"/> class.
		/// </summary>
		ID() : m_val(default_value) { }
		/// <summary>
		/// Initializes a new instance of the <see cref="ID"/> class.
		/// </summary>
		/// <param name="val">The value.</param>
		explicit ID(impl val) : m_val(val) {}
		/// <summary>
		/// Returns the underlying value.
		/// </summary>
		/// <returns>The underlying handle value.</returns>
		explicit operator impl() const { return m_val; }
		/// <summary>
		/// Tests for equality between the two objects
		/// </summary>
		/// <param name="a">The first object to check</param>
		/// <param name="b">The second object to check</param>
		/// <returns>true if the objects are equivalent</returns>
		friend bool operator==(ID a, ID b) { return a.m_val == b.m_val; }
		/// <summary>
		/// Tests for inequality between the two objects
		/// </summary>
		/// <param name="a">The first object to check</param>
		/// <param name="b">The second object to check</param>
		/// <returns>true if the objects are not equivalent</returns>
		friend bool operator!=(ID a, ID b) { return a.m_val != b.m_val; }
	private:
		impl m_val;
	};
	class tsCryptoStringBase;
	class VEILCORE_API IStringWriter
	{
	public:
		virtual ~IStringWriter()
		{
		}
		virtual bool WriteString(const tscrypto::tsCryptoStringBase& dataToAppend) = 0;
	};
	class tsCryptoData;
	class VEILCORE_API IBinaryWriter
	{
	public:
		virtual ~IBinaryWriter()
		{
		}
		virtual bool WriteBinary(const tscrypto::tsCryptoData& dataToAppend) = 0;
	};
}

#include "CryptoLocks.h"
#include "standardLayoutList.h"
#include "tsCryptoStringBase.h"

#include "CryptoExceptions.h"
#include "CryptoIterators.h"
#include "CryptoContainerWrapper.h"
#include "tsCryptoString.h"
#include "CryptoUtf16.h"
#include "tsCryptoData.h"
#include "FipsState.h"
#include "cryptolocator.h"
#include "cryptolocatorwriter.h"
#include "tsCryptoDate.h"
#include "json.h"
#include "TlvNode.h"
#include "TlvDocument.h"
#include "tsTlvSerializer.h"
#ifndef ONLY_ALG_LIBS
#include "CryptoAsn1.h"
#include "CryptoInterfaces.h"
#endif

#include "tsDistinguishedName.h"
#ifndef ONLY_ALG_LIBS
#include "PKIX.h"
#include "PKIX_Cert.h"
#include "PKIX_OCSP.h"
#endif
#include "xp_sharedlib.h"
#include "xp_file.h"
#include "CryptoEvent.h"
#include "Endian.h"
#ifndef ONLY_ALG_LIBS
#include "tsCertificateNamePart.h"
#include "tsCertificateExtension.h"
#include "tsCertificateBuilder.h"
#include "tsCertificateParser.h"

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4231)

VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API tscrypto::ICryptoContainerWrapper<int32_t>;
VEILCORE_TEMPLATE_EXTERN template class VEILCORE_API std::shared_ptr<tscrypto::ICryptoContainerWrapper<int32_t>>;

#pragma warning(pop)
#endif // _MSC_VER


namespace tscrypto {
	typedef std::shared_ptr<tscrypto::ICryptoContainerWrapper<int32_t>> int32List;
	extern VEILCORE_API int32List CreateInt32List();
}

/// <summary>
/// The tscrypto namespace.
/// </summary>
namespace tscrypto
{
	/// <summary>
	/// holds the state for a current cryptographic operation
	/// </summary>
	/// \ingroup HighLevelHelpers
	class VEILCORE_API CryptoContext
	{
	public:

		static void* operator new(std::size_t count) {
			return tscrypto::cryptoNew(count);
		}
		static void* operator new[](std::size_t count) {
			return tscrypto::cryptoNew(count);
		}
			static void operator delete(void* ptr) {
			tscrypto::cryptoDelete(ptr);
		}
		static void operator delete[](void* ptr) {
			tscrypto::cryptoDelete(ptr);
		}

			/// <summary>
			/// Default constructor.
			/// </summary>
			CryptoContext() {}
		/// <summary>Constructor.</summary>
		/// <param name="ctx">[in,out] If non-null, the context.</param>
		CryptoContext(std::shared_ptr<tscrypto::ICryptoObject> ctx) { m_context = ctx; }
		/// <summary>Copy constructor.</summary>
		/// <param name="obj">The object.</param>
		CryptoContext(const CryptoContext &obj) { m_context = obj.m_context; }
		/// <summary>
		/// Initializes a new instance of the <see cref="CryptoContext"/> class.
		/// </summary>
		/// <param name="obj">The object.</param>
		CryptoContext(CryptoContext &&obj) { m_context = std::move(obj.m_context); }

		/// <summary>
		/// Destructor.
		/// </summary>
		~CryptoContext() {}

		/// <summary>Assignment operator.</summary>
		/// <param name="obj">The object to copy</param>
		/// <returns>a reference to this object</returns>
		CryptoContext& operator=(const CryptoContext &obj) { if (this != &obj) { m_context.reset(); m_context = obj.m_context; } return *this; }
		/// <summary>
		/// Operator=s the specified object.
		/// </summary>
		/// <param name="obj">The object.</param>
		/// <returns>tscrypto.CryptoContext &.</returns>
		CryptoContext& operator=(CryptoContext &&obj) { if (this != &obj) { m_context.reset(); m_context = std::move(obj.m_context); } return *this; }
		/// <summary>Assignment operator.</summary>
		/// <param name="obj">The object to copy</param>
		/// <returns>a reference to this object</returns>
		CryptoContext& operator=(std::shared_ptr<tscrypto::ICryptoObject> obj) { m_context.reset(); m_context = obj; return *this; }

		/// <summary>Indicates if the context is not valid</summary>
		/// <returns>true if the context is invalid</returns>
		bool operator!() { return !m_context; }

		/// <summary>
		/// Gets this instance.
		/// </summary>
		/// <returns>std.shared_ptr&lt;_Ty&gt;.</returns>
		template <class T>
		std::shared_ptr<T> get() { return std::dynamic_pointer_cast<T>(m_context); }

		/// <summary>
		/// Gets this instance.
		/// </summary>
		/// <returns>std.shared_ptr&lt;_Ty&gt;.</returns>
		std::shared_ptr<tscrypto::ICryptoObject> get() { return m_context; }


		/// <summary>
		/// Clears this object to its blank/initial state.
		/// </summary>
		void clear() { m_context.reset(); }

	private:
		/// <summary>
		/// The m_context
		/// </summary>
		std::shared_ptr<tscrypto::ICryptoObject> m_context;
	};
	typedef tsCryptoData HashDigest;

	// /// <summary>
	// /// A flag indicating that the cpu supports AESNI instructions
	// /// </summary>
	// extern VEILCORE_API bool gCpuSupportsAES;
	// /// <summary>
	// /// A flag indicating that the cpu supports SSE instructions
	// /// </summary>
	// extern VEILCORE_API bool gCpuSupportsSSE;
	// /// <summary>
	// /// A flag indicating that the cpu supports SSE-2 instructions
	// /// </summary>
	// extern VEILCORE_API bool gCpuSupportsSSE2;

	/// <summary>
	/// A service locator for the cryptograpic operations in this SDK.
	/// </summary>
	/// <description>
	/// This cryptographic SDK contains two levels of functionality.  The top level is a 
	/// set of helper functions that hides some of the details.  The lower level is a 
	/// collection of "services" that are retrieved by name, OID or ID through the 
	/// "Service Locator".  This function returns the service locator object for the SDK.
	/// </description>
	/// <returns>A shared pointer to the Service Locator (tscrypto.ICryptoLocator).</returns>
	extern VEILCORE_API std::shared_ptr<tscrypto::ICryptoLocator> CryptoLocator();
	/// <summary>
	/// Determines if the crypto service locator is available and the crypto library is ready for use.
	/// </summary>
	/// <returns>true if the crypto service locator is available and ready for use.</returns>
	extern VEILCORE_API bool HasCryptoLocator();
	/// <summary>
	/// Adds an initialization function that is to be run on the first call to CryptoLocator().
	/// </summary>
	/// <param name="func">An initialization function that is to be run.</param>
	extern VEILCORE_API void AddCryptoInitializationFunction(std::function<bool()> func);
	/// <summary>
	/// Adds a termination function that is to be run when TerminateCryptoSystem() is called.  This is used to cleanly shut down the system.
	/// </summary>
	/// <param name="func">A termination function that is to be called later</param>
	extern VEILCORE_API void AddCryptoTerminationFunction(std::function<bool()> func);
	/// <summary>
	/// Properly shuts down the crypto system.
	/// </summary>
	extern VEILCORE_API void TerminateCryptoSystem();

	/// <summary>
	/// Gets a list of the algorithms based on the specified filtering.
	/// </summary>
	/// <param name="flags">The filter flags that indicate the types of algorithms to return.</param>
	/// <param name="matchAllFlags">If true an algorithm must match all of the specified flags to be returned.</param>
	/// <returns>A list of matching algorithms</returns>
	extern VEILCORE_API std::shared_ptr<tscrypto::IAlgorithmList> GetAlgorithmList(CryptoAlgType flags = (CryptoAlgType)0, bool matchAllFlags = true);
	/// <summary>
	/// Translates an algorithm name into the internal id.
	/// </summary>
	/// <param name="algName">Name of the alg.</param>
	/// <returns>The internal id for that algorithm.</returns>
	extern VEILCORE_API TS_ALG_ID LookUpAlgID(const tsCryptoStringBase& algName);
	/// <summary>
	/// Translates an algorithm name into the matching algorithm OID.
	/// </summary>
	/// <param name="algName">Name of the algorithm.</param>
	/// <returns>The OID of the algorithm in string form.</returns>
	extern VEILCORE_API tsCryptoString LookUpAlgOID(const tsCryptoStringBase& algName);
	/// <summary>
	/// Translates the algorithm OID into its matching algorithm name.
	/// </summary>
	/// <param name="oid">The OID of the algorithm.</param>
	/// <returns>The name of the algorithm</returns>
	extern VEILCORE_API tsCryptoString OIDtoAlgName(const tsCryptoStringBase& oid);
	/// <summary>
	/// Translates the algorithm OID into the internal id.
	/// </summary>
	/// <param name="OID">The algorithm OID.</param>
	/// <returns>The internal id</returns>
	extern VEILCORE_API TS_ALG_ID OIDtoID(const tsCryptoStringBase& OID);
	/// <summary>
	/// Translates the internal id into the matching algorithm OID.
	/// </summary>
	/// <param name="id">The internal id.</param>
	/// <returns>The algorithm OID in string form.</returns>
	extern VEILCORE_API tsCryptoString IDtoOID(TS_ALG_ID id);
	/// <summary>
	/// A helper function that returns an algorithm specified by name or OID in string form.
	/// </summary>
	/// <param name="nameOrOID">The name or OID.</param>
	/// <returns>The algorithm object in a shared pointer (represented by the common base class of tscrypto.ICryptoObject)</returns>
	/// \ingroup HighLevelHelpers
	extern VEILCORE_API std::shared_ptr<tscrypto::ICryptoObject> CryptoFactory(const tsCryptoStringBase& nameOrOID);
	/// <summary>
	/// A helper function that returns an algorithm specified by internal id.
	/// </summary>
	/// <param name="alg">The algorithm id.</param>
	/// <returns>The algorithm object in a shared pointer (represented by the common base class of tscrypto.ICryptoObject)</returns>
	/// \ingroup HighLevelHelpers
	extern VEILCORE_API std::shared_ptr<tscrypto::ICryptoObject> CryptoFactory(TS_ALG_ID alg);
	/// <summary>
	/// Gets the name of an algorithm based on its position in the global algorithm list.
	/// </summary>
	/// <param name="index">The index of the algorithm.</param>
	/// <returns>The name of the algorithm</returns>
	extern VEILCORE_API tsCryptoString GetAlgorithmNameByIndex(size_t index);
	/// <summary>
	/// Instantiates an algorithm object as identified by its position in the global algorithm list.
	/// </summary>
	/// <param name="index">The index of the algorithm to construct.</param>
	/// <returns>The algorithm object in a shared pointer (represented by the common base class of tscrypto.ICryptoObject)</returns>
	extern VEILCORE_API std::shared_ptr<tscrypto::ICryptoObject> ConstructAlgorithmByIndex(size_t index);
	/// <summary>
	/// Gets the number algorithms in the global algorithm list.
	/// </summary>
	/// <returns>algorithm count</returns>
	extern VEILCORE_API size_t  GetAlgorithmCount();

	/// <summary>
	/// Returns the key size needed for the algorithm specified.
	/// </summary>
	/// <param name="AlgID">The internal algorithm identifier.</param>
	/// <returns>key size.</returns>
	/// \ingroup HighLevelHelpers
	extern VEILCORE_API size_t CryptoKeySize(TS_ALG_ID AlgID);
	/// <summary>
	/// Gets the symmetric encryption mode for the specified algorithm
	/// </summary>
	/// <param name="AlgID">The internal algorithm identifier.</param>
	/// <returns>SymmetricMode</returns>
	/// \ingroup HighLevelHelpers
	extern VEILCORE_API SymmetricMode Alg2Mode(TS_ALG_ID AlgID);
	/// <summary>
	/// Returns the key type for the specified algorithm
	/// </summary>
	/// <param name="AlgID">The internal algorithm identifier.</param>
	/// <returns>KeyType.</returns>
	/// \ingroup HighLevelHelpers
	extern VEILCORE_API KeyType Alg2KeyType(TS_ALG_ID AlgID);
	/// <summary>
	/// Returns the required Initialization Vector (IVEC) size in bytes for the specified algorithm.
	/// </summary>
	/// <param name="AlgID">The internal algorithm identifier.</param>
	/// <returns>length in bytes.</returns>
	/// \ingroup HighLevelHelpers
	extern VEILCORE_API size_t CryptoIVECSize(TS_ALG_ID AlgID);
	/// <summary>
	/// Returns the encryption block size for the specified algorithm
	/// </summary>
	/// <param name="AlgID">The internal algorithm identifier.</param>
	/// <returns>block size in bytes.</returns>
	/// \ingroup HighLevelHelpers
	extern VEILCORE_API size_t CryptoBlockSize(TS_ALG_ID AlgID);

	/// <summary>
	/// Returns the state of the crypto SDK
	/// </summary>
	/// <returns>true if the crypto system is operational</returns>
	_Check_return_ extern VEILCORE_API bool CryptoOperational();
	/// <summary>
	/// This function tells the crypto system that a required test has failed and therefore will disable all algorithms.
	/// </summary>
	extern VEILCORE_API void CryptoTestFailed();
	/// <summary>
	/// Generates a random byte array.
	/// </summary>
	/// <param name="data">The destination for the random data.</param>
	/// <param name="lenInBytes">The length in bytes.</param>
	/// <returns>true if the data was generated.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool GenerateRandom(tsCryptoData& data, size_t lenInBytes);
	/// <summary>
	/// Generates a random byte array.
	/// </summary>
	/// <param name="data">The destination for the random data.</param>
	/// <param name="lenInBytes">The length in bytes.</param>
	/// <returns>true if the data was generated.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool GenerateRandom(uint8_t* data, size_t lenInBytes);

	/// <summary>
	/// Generates a hash value of the specified data
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="hash">The hash output.</param>
	/// <param name="AlgID">The internal algorithm identifier.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSHash(const tsCryptoData &data, HashDigest &hash, TS_ALG_ID AlgID = tscrypto::_TS_ALG_ID::TS_ALG_SHA1);
	/// <summary>
	/// Generates a hash value of the specified data
	/// </summary>
	/// <param name="data">The data to hash.</param>
	/// <param name="hash">The hash output.</param>
	/// <param name="AlgID">The hash algorithm name.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSHash(const tsCryptoData &data, HashDigest &hash, const char* AlgID);
	/// <summary>
	/// Generates a hash value of the specified data
	/// </summary>
	/// <param name="data">The pointer to the data to hash.</param>
	/// <param name="inLen">Length of the data to hash.</param>
	/// <param name="hash">The pointer to the hash output.</param>
	/// <param name="hashLen">Length of the hash buffer.</param>
	/// <param name="AlgID">The internal algorithm identifier.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSHash(const uint8_t* data, size_t inLen, uint8_t* hash, size_t hashLen, TS_ALG_ID AlgID);
	/// <summary>
	/// Generates a hash value of the specified data
	/// </summary>
	/// <param name="data">The pointer to the data to hash.</param>
	/// <param name="inLen">Length of the data to hash.</param>
	/// <param name="hash">The pointer to the hash output.</param>
	/// <param name="hashLen">Length of the hash buffer.</param>
	/// <param name="AlgID">The hash algorithm name.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSHash(const uint8_t* data, size_t inLen, uint8_t* hash, size_t hashLen, const char* AlgID);
	/// <summary>
	/// Starts an incremental hash session to hash multiple pieces of data.
	/// </summary>
	/// <param name="ctx">The cryptographic context object that represents this hash session.</param>
	/// <param name="AlgID">The internal hash algorithm identifier.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSIncrementalHashStart(CryptoContext &ctx, TS_ALG_ID AlgID);
	/// <summary>
	/// Starts an incremental hash session to hash multiple pieces of data.
	/// </summary>
	/// <param name="ctx">The cryptographic context object that represents this hash session.</param>
	/// <param name="AlgID">The hash algorithm name.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSIncrementalHashStart(CryptoContext &ctx, const char* AlgID);
	/// <summary>
	/// Applies another piece of data to the hash
	/// </summary>
	/// <param name="data">The data to be hashed.</param>
	/// <param name="ctx">The cryptographic context object that represents this hash session.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSIncrementalHash(const tsCryptoData &data, CryptoContext &ctx);
	/// <summary>
	/// Applies another piece of data to the hash
	/// </summary>
	/// <param name="data">The pointer to the data to be hashed.</param>
	/// <param name="dataLen">Length of the data to be hashed.</param>
	/// <param name="ctx">The cryptographic context object that represents this hash session.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSIncrementalHash(const uint8_t* data, size_t dataLen, CryptoContext &ctx);
	/// <summary>
	/// Finalizes the hash operation, frees up the context and returns the hash value.
	/// </summary>
	/// <param name="ctx">The cryptographic context object that represents this hash session.</param>
	/// <param name="hash">The hash output.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSIncrementalHashFinish(CryptoContext &ctx, HashDigest &hash);
	/// <summary>
	/// Finalizes the hash operation, frees up the context and returns the hash value.
	/// </summary>
	/// <param name="ctx">The cryptographic context object that represents this hash session.</param>
	/// <param name="hash">The pointer to the hash buffer.</param>
	/// <param name="hashLen">Length of the hash buffer.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSIncrementalHashFinish(CryptoContext &ctx, uint8_t* hash, size_t hashLen);

	/// <summary>
	/// Creates a key and HMAC value from a password using PKCS #5 PBKDF2 (Password Based Key Derivation Function 2)
	/// </summary>
	/// <param name="hmacName">Name of the hmac algorithm to use.</param>
	/// <param name="Password">The password.</param>
	/// <param name="seed">The seed value.</param>
	/// <param name="Count">The number of iterations to use (should be at least 1000).</param>
	/// <param name="KeyLen">Length of the key in bytes.</param>
	/// <param name="Key">The key output.</param>
	/// <param name="Mac">The mac output.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSCreatePBEKeyAndMac(const tsCryptoStringBase& hmacName, const tsCryptoStringBase &Password, const tsCryptoData &seed, size_t Count, size_t KeyLen, tsCryptoData &Key, tsCryptoData &Mac);
	/// <summary>
	/// Creates a key value from a password using PKCS #5 PBKDF2 (Password Based Key Derivation Function 2)
	/// </summary>
	/// <param name="hmacName">Name of the hmac algorithm to use.</param>
	/// <param name="Password">The password.</param>
	/// <param name="seed">The seed value.</param>
	/// <param name="Count">The number of iterations to use (should be at least 1000).</param>
	/// <param name="KeyLen">Length of the key in bytes.</param>
	/// <param name="Key">The key output.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSCreatePBEKey(const tsCryptoStringBase& hmacName, const tsCryptoStringBase &Password, const tsCryptoData &seed, size_t Count, size_t KeyLen, tsCryptoData &Key);

	/// <summary>
	/// Performs a key derivation using the algorithms specified in NIST SP800-108
	/// </summary>
	/// <param name="key">The key.</param>
	/// <param name="Label">The label.</param>
	/// <param name="Context">The context.</param>
	/// <param name="bitSize">Size of the output in bits.</param>
	/// <param name="outputData">The output data.</param>
	/// <param name="containsBitLength">Include the bitsize in the key derivation data</param>
	/// <param name="bytesOfBitLength">How many bytes are to be used to hold the bit size in the key derivation data</param>
	/// <param name="counterFirst">Place the counter at the beginning of the key derivation data.</param>
	/// <param name="counterByteLength">The length in bytes of the counter data</param>
	/// <param name="algorithm">The key derivation algorithm name.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool SP800_108_Counter(const tsCryptoData &key, const tsCryptoData &Label, const tsCryptoData &Context, int bitSize, tsCryptoData &outputData, bool containsBitLength = true, int bytesOfBitLength = 4, int32_t counterLocation = 0, int counterByteLength = 4, const tsCryptoStringBase &algorithm = "KDF-HMAC-SHA512");
	/// <summary>
	/// Generates an ECC Key Pair specifed by the internal algorithm identifier.
	/// </summary>
	/// <param name="alg">The internal algorithm identifier of the ECC key type.</param>
	/// <param name="keyPair">The key pair is returned here.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSGenerateECCKeysByAlg(tscrypto::TS_ALG_ID alg, std::shared_ptr<tscrypto::EccKey>& keyPair);
	/// <summary>
	/// Generates an ECC Key Pair specifed by the algorithm name.
	/// </summary>
	/// <param name="algName">Name of the alg.</param>
	/// <param name="keyPair">The key pair is returned here.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSGenerateECCKeysByName(const tsCryptoStringBase& algName, std::shared_ptr<tscrypto::EccKey>& keyPair);
	/// <summary>
	/// Generates an ECC Key Pair specifed by the key size.
	/// </summary>
	/// <param name="bitSize">Size of the keypair in bits.</param>
	/// <param name="keyPair">The key pair.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	/// \warning This function may not use the ECC curve you want if multiple curves are of the same bit length.  Therefore it is recommended that you use one of the other key generation functions.
	_Check_return_ extern VEILCORE_API bool TSGenerateECCKeysBySize(size_t bitSize, std::shared_ptr<tscrypto::EccKey>& keyPair);
	/// <summary>
	/// Generates an ECC Key Pair specifed by the key size.
	/// </summary>
	/// <param name="bitSize">Size of the key pair in bits.</param>
	/// <param name="PublicKey">The public key.</param>
	/// <param name="PrivateKey">The private key.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	/// \warning This function may not use the ECC curve you want if multiple curves are of the same bit length.  Therefore it is recommended that you use one of the other key generation functions.
	_Check_return_ extern VEILCORE_API bool TSGenerateECCKeysBySize(size_t bitSize, tsCryptoData &PublicKey, tsCryptoData &PrivateKey);
	/// <summary>
	/// Builds an ECC Key Pair object specifed by the algorithm name.
	/// </summary>
	/// <param name="keyName">Name of the ECC key to generate.</param>
	/// <param name="key">The key output.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSBuildEccKey(const tsCryptoStringBase& keyName, std::shared_ptr<tscrypto::EccKey>& key);
	/// <summary>
	/// Builds an ECC Key Pair object specifed by the algorithm OID.
	/// </summary>
	/// <param name="keyOID">The ECC key algorithm OID.</param>
	/// <param name="key">The key output.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSBuildEccKey(const tsCryptoData &keyOID, std::shared_ptr<tscrypto::EccKey>& key);
	/// <summary>
	/// Create an ECC Key object and populate it from a serialized key blob
	/// </summary>
	/// <param name="blob">The serialized ECC key BLOB.</param>
	/// <param name="key">The key object is put here.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSBuildECCKeyFromBlob(const tsCryptoData &blob, std::shared_ptr<tscrypto::EccKey>& key);
	/// <summary>
	/// Create an ECC key object and populate it with a private key value
	/// </summary>
	/// <param name="value">The private key value.</param>
	/// <param name="key">The key object is put here.</param>
	/// <param name="preferEdwards">Some ECC keys have different representations for ECCDH and signatures.  Pass true in this parameter for the signature keys.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSBuildECCKeyFromPrivateValue(const tsCryptoData &value, std::shared_ptr<tscrypto::EccKey>& key, bool preferEdwards = false);
	/// <summary>
	/// Create an ECC key object and populate it with a public key point
	/// </summary>
	/// <param name="point">The public key point.</param>
	/// <param name="key">The key object is put here.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSBuildECCKeyFromPoint(const tsCryptoData &point, std::shared_ptr<EccKey>& key);

	/// <summary>
	/// Begin a multipart HMAC session.
	/// </summary>
	/// <param name="algorithm">The internal algorithm identifier.</param>
	/// <param name="key">The key for the HMAC.</param>
	/// <param name="ctx">The cryptographic context object that represents this hash session.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSHMACStart(tscrypto::TS_ALG_ID algorithm, const tscrypto::tsCryptoData &key, tscrypto::CryptoContext &ctx);
	/// <summary>
	/// Begin a multipart HMAC session.
	/// </summary>
	/// <param name="algorithm">The HMAC algorithm name.</param>
	/// <param name="key">The key for the HMAC.</param>
	/// <param name="ctx">The cryptographic context object that represents this hash session.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSHMACStart(const char* algorithm, const tscrypto::tsCryptoData &key, tscrypto::CryptoContext &ctx);
	/// <summary>
	/// Adds data to the HMAC computation
	/// </summary>
	/// <param name="data">The data to add.</param>
	/// <param name="ctx">The cryptographic context object that represents this hash session.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	extern VEILCORE_API bool TSHMACUpdate(const tscrypto::tsCryptoData &data, tscrypto::CryptoContext &ctx);
	/// <summary>
	/// Finishes the HMAC computation, clears the cryptographic context and returns the HMAC value.
	/// </summary>
	/// <param name="hmac">The HMAC value is put here.</param>
	/// <param name="ctx">The cryptographic context object that represents this hash session.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSHMACFinish(tscrypto::tsCryptoData &hmac, tscrypto::CryptoContext &ctx);
	/// <summary>
	/// Performs an HMAC computation in one call.
	/// </summary>
	/// <param name="algorithm">The internal algorithm identifier.</param>
	/// <param name="key">The key for the HMAC.</param>
	/// <param name="data">The data to HMAC.</param>
	/// <param name="hmac">The computed HMAC value is put here.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSHMAC(tscrypto::TS_ALG_ID algorithm, const tscrypto::tsCryptoData &key, const tscrypto::tsCryptoData &data, tscrypto::tsCryptoData &hmac);
	/// <summary>
	/// Performs an HMAC computation in one call.
	/// </summary>
	/// <param name="algorithm">The algorithm name.</param>
	/// <param name="key">The key for the HMAC.</param>
	/// <param name="data">The data to HMAC.</param>
	/// <param name="hmac">The computed HMAC value is put here.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSHMAC(const char* algorithm, const tscrypto::tsCryptoData &key, const tscrypto::tsCryptoData &data, tscrypto::tsCryptoData &hmac);

	/// <summary>
	/// Creates a Diffie-Hellman key object
	/// </summary>
	/// <param name="key">The key is put here.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSBuildDhKey(std::shared_ptr<tscrypto::DhKey>& key);
	/// <summary>
	/// Creates a Diffie-Hellman key object and populates it with the key blob.
	/// </summary>
	/// <param name="blob">The key BLOB.</param>
	/// <param name="key">The key object is put uere.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSBuildDhKeyFromBlob(const tsCryptoData &blob, std::shared_ptr<tscrypto::DhKey>& key);
	/// <summary>
	/// Creates a Diffie-Hellman parameter set object
	/// </summary>
	/// <param name="params">The parameterset is put here.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSBuildDhParams(std::shared_ptr<tscrypto::DhParameters>& params);
	/// <summary>
	/// Creates a Diffie-Hellman parameter set object and populates it with the specified data
	/// </summary>
	/// <param name="blob">The parameterset in a BLOB format.</param>
	/// <param name="params">The parameterset is put here.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSBuildDhParamsFromBlob(const tsCryptoData &blob, std::shared_ptr<tscrypto::DhParameters>& key);
	/// <summary>
	/// Creates an asymmetric key object and populates it with the key in the opaque blob specified.
	/// </summary>
	/// <param name="blob">The key data.</param>
	/// <returns>a shared pointer to the created key object</returns>
	/// \ingroup HighLevelHelpers
	extern VEILCORE_API std::shared_ptr<tscrypto::AsymmetricKey> TSBuildAsymmetricKeyFromBlob(const tsCryptoData& blob);

	/// <summary>
	/// Creates an RSA key object blob and populates the public key values with the values specified.
	/// </summary>
	/// <param name="modulus">The modulus for the key (big-endian).</param>
	/// <param name="exponent">The public exponent for the key (big-endian).</param>
	/// <returns>the serialized RSA key blob</returns>
	/// \ingroup HighLevelHelpers
	extern VEILCORE_API tsCryptoData TSBuildRSAPublicKeyBlob(const tsCryptoData &modulus, const tsCryptoData &exponent);
	/// <summary>
	/// Creates an RSA key object blob and populates it with the specified private key values.
	/// </summary>
	/// <param name="modulus">The modulus for the key (big-endian).</param>
	/// <param name="exponent">The pubic exponent for the key (big-endian).</param>
	/// <param name="d">The private exponent for the key (big-endian).</param>
	/// <param name="p">The CRT p value (prime 1) for the key (big-endian).</param>
	/// <param name="q">The CRT q value (prime 2) for the key (big-endian).</param>
	/// <param name="dp">The CRT factor dP for the key (big-endian).</param>
	/// <param name="dq">The CRT factor dQ for the key (big-endian).</param>
	/// <param name="qInv">The CRT q inverse for the key (big-endian).</param>
	/// <returns>the serialized RSA key blob.</returns>
	/// \ingroup HighLevelHelpers
	extern VEILCORE_API tsCryptoData TSBuildRSAPrivateKeyBlob(const tsCryptoData &modulus, const tsCryptoData &exponent, const tsCryptoData &d, const tsCryptoData &p, const tsCryptoData &q, const tsCryptoData &dp, const tsCryptoData &dq, const tsCryptoData &qInv);
	/// <summary>
	/// Creates an RSA key object
	/// </summary>
	/// <param name="key">The key object is put here.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool   TSBuildRSAKey(std::shared_ptr<tscrypto::RsaKey>& key);
	/// <summary>
	/// Creates an RSA key object and populates it with the specified key blob.
	/// </summary>
	/// <param name="blob">The key data.</param>
	/// <param name="key">The key object is put here.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool   TSBuildRSAKeyFromBlob(const tsCryptoData &blob, std::shared_ptr<tscrypto::RsaKey>& key);

	/// <summary>
	/// Extracts the public modulus from the RSA key blob
	/// </summary>
	/// <param name="blob">The key data.</param>
	/// <param name="modulus">The modulus in big endian form.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSGetRsaModulus(const tsCryptoData &blob, tsCryptoData &modulus);
	/// <summary>
	/// Extracts the public exponent from the RSA key blob
	/// </summary>
	/// <param name="blob">The key data.</param>
	/// <param name="exponent">The public exponent in big endian form.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSGetRsaExponent(const tsCryptoData &blob, tsCryptoData &exponent);
	/// <summary>
	/// Extracts the public modulus and exponent from the RSA key blob.
	/// </summary>
	/// <param name="blob">The key data.</param>
	/// <param name="modulus">The public modulus in big-endian form.</param>
	/// <param name="exponent">The public exponent in big-endian form.</param>
	/// <returns>true is successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSGetRsaPublicComponents(const tsCryptoData &blob, tsCryptoData &modulus, tsCryptoData &exponent);
	/// <summary>
	/// Generates an RSA key pair and returns the public and private key blobs
	/// </summary>
	/// <param name="bitSize">Size of the key to generate in bits (1024, 2048 or 3072).</param>
	/// <param name="PublicKey">The public key blob is returned here.</param>
	/// <param name="PrivateKey">The private key blob is returned here.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSGenerateRSAKeys(size_t bitSize, tsCryptoData &PublicKey, tsCryptoData &PrivateKey);
	/// <summary>
	/// Generates an RSA key object and then generates a new key pair in that object.
	/// </summary>
	/// <param name="bitSize">Size of the key to generate in bits (1024, 2048 or 3072).</param>
	/// <param name="rsa">The RSA key object is put here.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSGenerateRSAKeys(size_t bitSize, std::shared_ptr<tscrypto::RsaKey> &rsa);
	/// <summary>
	/// Signs the data using the RSA key blob and PKCS #11 signature formatting.
	/// </summary>
	/// <param name="RSAPrivate">The RSA private key blob.</param>
	/// <param name="value">The data value to be signed.</param>
	/// <param name="valueLen">Length of the data value.</param>
	/// <param name="signature">The signature is returned here.</param>
	/// <param name="signAlgorithm">The signature algorithm to use.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSRSAPKCS11Sign(const tsCryptoData &RSAPrivate, const uint8_t *value, size_t valueLen, tsCryptoData &signature, tscrypto::TS_ALG_ID signAlgorithm);
	/// <summary>
	/// Signs the data using the RSA key blob and PKCS #11 signature formatting.
	/// </summary>
	/// <param name="RSAPrivate">The RSA private key blob.</param>
	/// <param name="value">The data value to be signed.</param>
	/// <param name="signature">The signature is returned here.</param>
	/// <param name="signAlgorithm">The signature algorithm to use.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSRSAPKCS11Sign(const tsCryptoData &RSAPrivate, const tsCryptoData &value, tsCryptoData &signature, tscrypto::TS_ALG_ID signAlgorithm);
	/// <summary>
	/// Verifies an RSA PKCS #11 signature
	/// </summary>
	/// <param name="RSAPublic">The RSA public key blob.</param>
	/// <param name="value">The data value to verify.</param>
	/// <param name="valueLen">Length of the value.</param>
	/// <param name="signature">The signature value.</param>
	/// <param name="signAlgorithm">The signature algorithm that was used to create the signature.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSRSAPKCS11Verify(const tsCryptoData &RSAPublic, const uint8_t *value, const uint32_t valueLen, const tsCryptoData &signature, tscrypto::TS_ALG_ID signAlgorithm);
	/// <summary>
	/// Verifies an RSA PKCS #11 signature
	/// </summary>
	/// <param name="RSAPublic">The RSA public key value.</param>
	/// <param name="value">The data value to verify.</param>
	/// <param name="signature">The signature value.</param>
	/// <param name="signAlgorithm">The signature algorithm that was used to create the signature.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSRSAPKCS11Verify(const tsCryptoData &RSAPublic, const tsCryptoData &value, const tsCryptoData &signature, tscrypto::TS_ALG_ID signAlgorithm);
	/// <summary>
	/// Returns the size in bits of the key specified in the key blob
	/// </summary>
	/// <param name="blob">The key BLOB.</param>
	/// <returns>size of the key in bits.</returns>
	/// \ingroup HighLevelHelpers
	extern VEILCORE_API size_t TSGetRsaKeySize(const tsCryptoData &blob);
	/// <summary>
	/// Signs the specified data using the key and appropriate hash algorithm. (Can do RSA, DSA, ECDSA, EDDSA)
	/// </summary>
	/// <param name="key">The key to be used to sign the data.</param>
	/// <param name="data">The data that is to be signed.</param>
	/// <param name="signature">The signature is put here.</param>
	/// <param name="signAlgSuffix">The signature algorithm suffix that can be used to force encoding and/or hash algorithms.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSSignData(std::shared_ptr<tscrypto::AsymmetricKey> key, const tsCryptoData& data, tsCryptoData& signature, const char* signAlgSuffix = nullptr);
	/// <summary>
	/// Verifies a signature using the specified key...  (Can do RSA, DSA, ECDSA, EDDSA)
	/// </summary>
	/// <param name="key">The key to be used to verify the signature.</param>
	/// <param name="data">The data that was signed.</param>
	/// <param name="signature">The signature.</param>
	/// <param name="signAlgSuffix">The signature algorithm suffix that can be used to force encoding and/or hash algorithms.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSVerifyData(std::shared_ptr<tscrypto::AsymmetricKey> key, const tsCryptoData& data, const tsCryptoData& signature, const char* signAlgSuffix = nullptr);
	/// <summary>
	/// Signs the specified data hash using the key and appropriate hash algorithm. (Can do RSA, DSA, ECDSA, EDDSA(pre-hashed only???))
	/// </summary>
	/// <param name="key">The key that is used to sign the data.</param>
	/// <param name="hash">The hash of the data.</param>
	/// <param name="signature">The signature is put here.</param>
	/// <param name="signAlgSuffix">The signature algorithm suffix that can be used to force encoding and/or hash algorithms.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSSignHash(std::shared_ptr<tscrypto::AsymmetricKey> key, const tsCryptoData& hash, tsCryptoData& signature, const char* signAlgSuffix = nullptr);
	/// <summary>
	/// Verifies a signature using the specified key...  (Can do RSA, DSA, ECDSA, EDDSA)
	/// </summary>
	/// <param name="key">The key to be used to verify the signature.</param>
	/// <param name="hash">The hash of the data.</param>
	/// <param name="signature">The signature.</param>
	/// <param name="signAlgSuffix">The signature algorithm suffix that can be used to force encoding and/or hash algorithms.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup HighLevelHelpers
	_Check_return_ extern VEILCORE_API bool TSVerifyHash(std::shared_ptr<tscrypto::AsymmetricKey> key, const tsCryptoData& hash, const tsCryptoData& signature, const char* signAlgSuffix = nullptr);

	/// <summary>
	/// Creates an ASN.1 formatted bitstring node
	/// </summary>
	/// <param name="data">The data content within the bitstring.</param>
	/// <param name="unusedBits">The number of unused bits in the data content.</param>
	/// <param name="doc">The TLV document object.</param>
	/// <returns>A shared pointer to the tscrypto.TlvNode containing the bitstring data.</returns>
	/// \ingroup LowLevelClasses
	extern VEILCORE_API std::shared_ptr<TlvNode> MakeBitString(const tsCryptoData &data, uint8_t unusedBits, std::shared_ptr<TlvDocument>& doc);
	/// <summary>
	/// Creates an ASN.1 formatted integer node
	/// </summary>
	/// <param name="data">The number data that is to be encoded.</param>
	/// <param name="doc">The TLV document object.</param>
	/// <returns>A shared pointer to the tscrypto.TlvNode containing the number data.</returns>
	/// \ingroup LowLevelClasses
	extern VEILCORE_API std::shared_ptr<TlvNode> MakeIntegerNode(const tsCryptoData &data, std::shared_ptr<TlvDocument>& doc);
	/// <summary>
	/// Takes an ASN.1 encoded number and removes the encoding.
	/// </summary>
	/// <param name="data">The number data that is encoded.</param>
	/// <returns>the raw unsigned number</returns>
	/// \ingroup LowLevelClasses
	extern VEILCORE_API tsCryptoData AdjustASN1Number(tsCryptoData data);
	/// <summary>
	/// Takes an ASN.1 encoded bitstring data and removes the encoding.
	/// </summary>
	/// <param name="data">The bitstring data that is encoded.</param>
	/// <returns>the raw bitstring data</returns>
	/// \ingroup LowLevelClasses
	extern VEILCORE_API tsCryptoData AdjustBitString(tsCryptoData data);
	/// <summary>
	/// Checks if the tscrypto.TlvNode is an OID node and contains the specified OID value
	/// </summary>
	/// <param name="node">The node to check.</param>
	/// <param name="oid">The OID we are looking for.</param>
	/// <returns>true if successful.</returns>
	/// \ingroup LowLevelClasses
	_Check_return_ extern VEILCORE_API bool IsSequenceOID(const std::shared_ptr<TlvNode>& node, const tsCryptoData &oid);
	/// <summary>
	/// Causes the current thread to sleep for at least the specified time.
	/// </summary>
	/// <param name="milliseconds">The number of milliseconds to sleep.</param>
	/// \ingroup LowLevelClasses
	extern VEILCORE_API void XP_Sleep(uint32_t milliseconds);

	struct WeierstrassCurveData; // needed for BaseXXEccCurve.h
}

#define USE_BLINDING
//#define FORCE_C_OPS
#define ENABLE_SPA

/// <summary>
/// The tscrypto namespace.
/// </summary>
namespace tscrypto
{
	/// <summary>
	/// Performs a byte by byte exclusive-or of 64 bit blocks and puts the result in dest.  dest may point to either of the input buffers.
	/// </summary>
	/// <param name="src">The source block.</param>
	/// <param name="second">The second source block.</param>
	/// <param name="dest">The destination bloc (may point to either of the source blocks).</param>
	/// \ingroup LowLevelClasses
	extern VEILCORE_API void xor8(const uint8_t* src, const uint8_t* second, uint8_t* dest);
	/// <summary>
	/// Performs a byte by byte exclusive-or of 128 bit blocks and puts the result in dest.  dest may point to either of the input buffers.
	/// </summary>
	/// <param name="src">The source block.</param>
	/// <param name="second">The second source block.</param>
	/// <param name="dest">The destination bloc (may point to either of the source blocks).</param>
	/// \ingroup LowLevelClasses
	extern VEILCORE_API void xor16(const uint8_t* src, const uint8_t* second, uint8_t* dest);
	/// <summary>
	/// Performs a byte by byte exclusive-or of 256 bit blocks and puts the result in dest.  dest may point to either of the input buffers.
	/// </summary>
	/// <param name="src">The source block.</param>
	/// <param name="second">The second source block.</param>
	/// <param name="dest">The destination bloc (may point to either of the source blocks).</param>
	/// \ingroup LowLevelClasses
	extern VEILCORE_API void xor32(const uint8_t* src, const uint8_t* second, uint8_t* dest);
	/// <summary>
	/// Encodes a string for XML (quoting/translating special characters)
	/// </summary>
	/// <param name="value">The value that is to be translated.</param>
	/// <param name="out">The output is put here.</param>
	/// \ingroup LowLevelClasses
	extern VEILCORE_API void TSPatchValueForXML(const tsCryptoStringBase &value, tsCryptoStringBase &out);
	extern VEILCORE_API void TSGuidToString(const GUID &id, tsCryptoStringBase &out);
	extern VEILCORE_API tsCryptoString TSGuidToString(const GUID &id);
	extern VEILCORE_API void TSStringToGuid(const tsCryptoStringBase &strGuid, GUID &id);
	extern VEILCORE_API GUID TSStringToGuid(const tsCryptoStringBase &strGuid);
}
#endif // ONLY_ALG_LIBS

/*! @mainpage
	The TecSec VEIL Crypto SDK is comprised of a collection of classes and functions that provide the foundation for an application
	that needs secure and certifiable cryptographic operations.  Included in this sdk are:

	  * specialized string and byte array classes that automatically overwrite their contents
	  * ASN.1 encoding and serializing routines
	  * big integer computation routines
	  * A partial C level API for low level cryptographic operations
	  * A medium level C++ interface for full access to the cryptographic routines
	  * A partial high level access that simplifies some of the cryptographic operations

	This SDK makes heavy use of C++11 standards and the Standard Template Library.  Therefore we do not support any compilers that do not support
	these features.  On windows we currently support:

	  * Visual Studio 2013 (VC12)
	  * Visual Studio 2015 (VC14)
	  * MinGW-w64 using one of the following GCC compilers:
		  - 4.8.2 using SEH and either Win32 or Posix threads
		  - 4.9.3 using SEH and either Win32 or Posix threads
		  - 5.3.0 using SEH and either Win32 or Posix threads

	Other compilers and platforms are available upon request.

	The C interfaces currently support a subset of the algorithms.  It includes many of the hashes, bulk data encryption algorithms and hmac/cmac
	algorithms.  More will be added over time.

	The C++ interfaces are the most complete.  They make heavy use of the specialized string and byte array classes as well as shared_ptr and other
	STL classes.  This is the main interface that the VEIL suite of products use.  Access to objects in this interface are through the CryptoLocator()
	function.  This function uses the Service Locator design pattern to look up an algorithm based on name or OID.  There is also a helper function
	called CryptoFactory that will create the objects based on name, OID or an internal ID. See the \ref Algorithms page for a table of the supported
	algorithms.
*/

#endif // __VEILCRYPTO_H__
