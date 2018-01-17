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

//////////////////////////////////////////////////////////////////////////////////
/// \file VEILFileSupport.h
/// \brief Support functionality for file based encryption and decryption.
//////////////////////////////////////////////////////////////////////////////////

#ifndef VEILFILESUPPORT_H_INCLUDED
#define VEILFILESUPPORT_H_INCLUDED

#ifdef VEILFILESUPPORT_STATIC
#define VEILFILESUPPORT_EXPORT
#define VEILFILESUPPORT_TEMPLATE_EXTERN 
#else
#ifdef _WIN32
#ifdef _STATIC_RUNTIME_LOADER
#define VEILFILESUPPORT_EXPORT
#define VEILFILESUPPORT_TEMPLATE_EXTERN extern
#else
#if !defined(VEILFILESUPPORTDEF) && !defined(DOXYGEN)
#define VEILFILESUPPORT_EXPORT  __declspec(dllimport)
#define VEILFILESUPPORT_TEMPLATE_EXTERN extern
#else
/// <summary>A macro that defines extern syntax for templates.</summary>
#define VEILFILESUPPORT_TEMPLATE_EXTERN
/// <summary>A macro that defines the export modifiers for the AppPlatform components.</summary>
#define VEILFILESUPPORT_EXPORT __declspec(dllexport)
#endif
#endif
#else
#if !defined(VEILFILESUPPORTDEF) && !defined(DOXYGEN)
#define VEILFILESUPPORT_EXPORT
#define VEILFILESUPPORT_TEMPLATE_EXTERN extern
#else
#define VEILFILESUPPORT_EXPORT EXPORT_SYMBOL
#define VEILFILESUPPORT_TEMPLATE_EXTERN
#endif
#endif // _WIN32
#endif // VEILFILESUPPORT_STATIC

class VEILFILESUPPORT_EXPORT IReservedLength
{
public:
	virtual ~IReservedLength(){}
	virtual int ReservedHeaderLength() const = 0;
};
/// <summary>A list of files.</summary>
class VEILFILESUPPORT_EXPORT IVEILFileList
{
public:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Adds a file to the list.</summary>
    ///
    /// <param name="filename">Filename.</param>
    ///
    /// <returns>S_OK for success or a standard COM error code for failure.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool AddFile(const tscrypto::tsCryptoString& filename) = 0;
    /// <summary>Clears this object to its blank/initial state.</summary>
    virtual void    Clear() = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the number of files in this list.</summary>
    ///
    /// <returns>the number of files in this list.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual uint32_t   FileCount() = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Removes the file described by index.</summary>
    ///
    /// <param name="index">Zero-based index of the file to remove.</param>
    ///
    /// <returns>S_OK for success or a standard COM error code for failure.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool RemoveFile(uint32_t index) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the file name.</summary>
    ///
    /// <param name="index">Zero-based index of the file to return.</param>
    /// <param name="name"> [in,out] The name.</param>
    ///
    /// <returns>S_OK for success or a standard COM error code for failure.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    virtual bool GetFileName(uint32_t index, tscrypto::tsCryptoString& name) = 0;
};

struct VEILFILESUPPORT_EXPORT FileVEILFileOp_recoveredKey
{
    tscrypto::tsCryptoData signature;
    tscrypto::tsCryptoData key;
};

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>A callback interface used to update the caller on the status of long running
/// operations.</summary>
////////////////////////////////////////////////////////////////////////////////////////////////////
class VEILFILESUPPORT_EXPORT IFileVEILOperationStatus
{
public:
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Provides an update of the status of the ongoing operation.</summary>
	///
	/// <param name="taskName">			 Name of the task being performed.</param>
	/// <param name="taskNumber">		 The task number.</param>
	/// <param name="ofTaskCount">		 The total number of tasks.</param>
	/// <param name="taskPercentageDone">The task percentage done.</param>
	///
	/// <returns>true for continue or false to abort the operation.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool Status(const tscrypto::tsCryptoString& taskName, int taskNumber, int ofTaskCount, int taskPercentageDone) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>The operation failed for the specified reason.</summary>
	///
	/// <param name="failureText">The failure reason.</param>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual void    FailureReason(const tscrypto::tsCryptoString& failureText) = 0;
};

/**
* \brief Defines a callback to retrieve a session for the file operation.
*/
class VEILFILESUPPORT_EXPORT IFileVEILSessionCallback
{
public:
	/**
	* \brief Gets session for header.
	*
	* \param forGenerate	  true if generating a working key.
	* \param [in,out] header The header being processed.
	* \param cryptoGroupIndex	  Zero-based index of the CryptoGroup being processed.
	* \param [in,out] pVal   The session that is to be used for the operation.
	*
	* \return The session for header.
	*/
	virtual bool GetSessionForHeader(bool forGenerate, std::shared_ptr<ICmsHeaderBase> header, int cryptoGroupIndex, std::shared_ptr<IKeyVEILSession>& pVal) = 0;
};

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4231)
VEILFILESUPPORT_TEMPLATE_EXTERN template class VEILFILESUPPORT_EXPORT tscrypto::ICryptoContainerWrapper<FileVEILFileOp_recoveredKey>;
VEILFILESUPPORT_TEMPLATE_EXTERN template class VEILFILESUPPORT_EXPORT std::shared_ptr<tscrypto::ICryptoContainerWrapper<FileVEILFileOp_recoveredKey>>;
#pragma warning(pop)
#endif // _MSC_VER

typedef std::shared_ptr<tscrypto::ICryptoContainerWrapper<FileVEILFileOp_recoveredKey>> FileVEILFileOp_recoveredKeyList;
extern VEILFILESUPPORT_EXPORT FileVEILFileOp_recoveredKeyList CreateFileVEILFileOp_recoveredKeyList();

/// <summary>The primary functionality of the FileVEIL application is implemented here.</summary>
class VEILFILESUPPORT_EXPORT IFileVEILOperations
{
public:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the status interface object that is to receive operation updates (normally for a GUI).</summary>
    ///
    /// <param name="status">[in,out] the status interface.</param>
    ///
    /// <returns>S_OK for success or a standard COM error code for failure.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool SetStatusInterface(std::shared_ptr<IFileVEILOperationStatus> status) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Sets the Key VEIL session that is to be used by the operations in this object.</summary>
    ///
    /// <param name="session">[in,out] If non-null, the session.</param>
    ///
    /// <returns>S_OK for success or a standard COM error code for failure.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool SetSession(std::shared_ptr<IKeyVEILSession> session) = 0;

    /**
    *  @brief  Securely delete a file to prevent data recovery.
    *
    * Securely delete the indicated file by alternately overwriting its
    * data with 111s and 000s. The 1 paramater version of this method
    * makes 3 overwrite passes. The 2 paramater version of this method
    * can be configured to make more or less passes based on desired
    * security parameters and speed requirements.
    *
    * Based on the threat you wish to guard against, consider carefully
    * how many delete passes you wish to use. DoD standard 5220.22-M
    * (section 8-3-5) calls for 3 passes. This should be sufficient
    * for anything less than a forensic analysis of the media.
    *
    *
    * Note: The minimum and maximum values which can be specified for inDeletePasses
    * are 3 and 200. The larger the value specified for inDeletePasses,
    * the longer it will take to complete secure deletion of the file.
    * @param inFilename - [in] The name of the file to be securely deleted.
    * @param inDeletePasses - [in] The number of "cleaning" passes to make
    */
	virtual bool secureDelete(const tscrypto::tsCryptoString& inFilename, int inDeletePasses) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the stream names within a file.</summary>
    ///
    /// <param name="sFile">The file.</param>
    /// <param name="pVal"> [out] The file list.</param>
    ///
    /// <returns>S_OK for success or a standard COM error code for failure.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool GetStreamNames(const tscrypto::tsCryptoString& sFile, std::shared_ptr<IVEILFileList>& pVal) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Encrypts a file using CKM 7.</summary>
    ///
    /// <param name="sFile">		The source filename.</param>
    /// <param name="sEncrFile">	The encrypted filename.</param>
    /// <param name="header">		[in,out] The CMS header.</param>
    /// <param name="comp">			Compression type.</param>
    /// <param name="algorithm">	The encryption algorithm.</param>
    /// <param name="hashAlgorithm">The hash algorithm.</param>
    /// <param name="SignHeader">   true to sign header using ECDSA.</param>
    /// <param name="bindData">		true to bind the data to the header.</param>
    /// <param name="DataFormat">   The data format.</param>
    /// <param name="randomIvec">   true for random ivec.</param>
    /// <param name="paddingType">  Type of data padding.</param>
    /// <param name="blockSize">	(optional) size of the block to process.</param>
    ///
    /// <returns>S_OK for success or a standard COM error code for failure.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool Encrypt_File(const tscrypto::tsCryptoString& sFile, const tscrypto::tsCryptoString& sEncrFile, std::shared_ptr<ICmsHeader> header, CompressionType comp, tscrypto::TS_ALG_ID algorithm, tscrypto::TS_ALG_ID hashAlgorithm,
		bool SignHeader, bool bindData, CMSFileFormatIds DataFormat, bool randomIvec, tscrypto::SymmetricPaddingType paddingType, int blockSize = 5000000) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Encrypts a stream within a file using CKM 7.</summary>
    ///
    /// <param name="sFile">		[in] The source file.</param>
    /// <param name="sEncrFile">	[in] The encrypted file.</param>
    /// <param name="header">		[in] The CMS header.</param>
    /// <param name="comp">			Compression type.</param>
    /// <param name="algorithm">	The encryption algorithm.</param>
    /// <param name="hashAlgorithm">The hash algorithm.</param>
    /// <param name="SignHeader">   true to sign header.</param>
    /// <param name="bindData">		true to bind data to the header.</param>
    /// <param name="DataFormat">   The data format.</param>
    /// <param name="randomIvec">   true for random ivec.</param>
    /// <param name="paddingType">  Type of data padding.</param>
    /// <param name="blockSize">	(optional) size of the block to process.</param>
    ///
    /// <returns>S_OK for success or a standard COM error code for failure.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool EncryptStream(std::shared_ptr<IDataReader> sFile, std::shared_ptr<IDataWriter> sEncrFile, std::shared_ptr<ICmsHeader> header, CompressionType comp, tscrypto::TS_ALG_ID algorithm, tscrypto::TS_ALG_ID hashAlgorithm,
		bool SignHeader, bool bindData, CMSFileFormatIds DataFormat, bool randomIvec, tscrypto::SymmetricPaddingType paddingType, int blockSize = 5000000) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Encrypts a file and its streams using CKM 7.</summary>
    ///
    /// <param name="sFile">		The source filename.</param>
    /// <param name="sEncrFile">	The encrypted filename.</param>
    /// <param name="header">		[in] The CMS header.</param>
    /// <param name="comp">			Compression type.</param>
    /// <param name="algorithm">	The encryption algorithm.</param>
    /// <param name="hashAlgorithm">The hash algorithm.</param>
    /// <param name="SignHeader">   true to sign header.</param>
    /// <param name="bindData">		true to bind data to the header.</param>
    /// <param name="DataFormat">   The data format.</param>
    /// <param name="randomIvec">   true for random ivec.</param>
    /// <param name="paddingType">  Type of data padding.</param>
    /// <param name="blockSize">	(optional) size of the block to process.</param>
    ///
    /// <returns>S_OK for success or a standard COM error code for failure.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool EncryptFileAndStreams(const tscrypto::tsCryptoString& sFile, const tscrypto::tsCryptoString& sEncrFile, std::shared_ptr<ICmsHeader> header, CompressionType comp, tscrypto::TS_ALG_ID algorithm,
		tscrypto::TS_ALG_ID hashAlgorithm, bool SignHeader, bool bindData, CMSFileFormatIds DataFormat, bool randomIvec, tscrypto::SymmetricPaddingType paddingType, int blockSize = 5000000) = 0;

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Decrypts a file and its streams.</summary>
	///
	/// <param name="sFile">	The source filename.</param>
	/// <param name="sDecrFile">The decrypted filename.</param>
	///
	/// <returns>true for success or false for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool DecryptFileAndStreams(const tscrypto::tsCryptoString& sFile, const tscrypto::tsCryptoString& sDecrFile) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Decrypts a stream using CKM7.</summary>
    ///
    /// <param name="sFile">	[in,out] The encrypted file.</param>
    /// <param name="sDecrFile">[in,out] The decrypted file.</param>
    ///
    /// <returns>S_OK for success or a standard COM error code for failure.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool DecryptStream(std::shared_ptr<IDataReader> sFile, std::shared_ptr<IDataWriter> sDecrFile) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Tests a stream to see if it begins with a CMS header.</summary>
	///
	/// <param name="stream">[in,out] The stream to test.</param>
	/// <param name="pVal">  [in,out] The CMS header.</param>
	///
	/// <returns>true if it succeeds, false if it fails.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool    StreamStartsWithCmsHeader(std::shared_ptr<IDataReader> stream, std::shared_ptr<ICmsHeaderBase>& pVal) = 0;
	virtual bool  FileStartsWithCmsHeader(const tscrypto::tsCryptoString& filename, std::shared_ptr<ICmsHeaderBase>& pVal) = 0;

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Validates the file contents using public checks only.</summary>
	///
	/// <param name="sFile">The file to validate.</param>
	///
    /// <returns>S_OK for success or a standard COM error code for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool ValidateFileContents_PublicOnly(const tscrypto::tsCryptoString& sFile) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the Key Gen callback interface.</summary>
	///
	/// <param name="callback">[in,out] The callback interface.</param>
	///
    /// <returns>S_OK for success or a standard COM error code for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool SetKeyGenCallback(std::shared_ptr<IKeyGenCallback> callback) = 0;
	/**
	 * \brief Callback, called when a session is not specified and is needed.
	 *
	 * \param [in,out] callback the callback interface object.
	 *
	 * \return .
	 */
	virtual bool SetSessionCallback(std::shared_ptr<IFileVEILSessionCallback> callback) = 0;
    /**
     * \brief Decrypts a stream using CKM7.
     *
     * \param [in,out] sFile	 The encrypted file.
     * \param [in,out] sDecrFile The decrypted file.
     * \param [in,out] header    If non-null, the header.
     *
     * \return S_OK for success or a standard COM error code for failure.
     */
	virtual bool DecryptStreamWithHeader(std::shared_ptr<IDataReader> sFile, std::shared_ptr<IDataWriter> sDecrFile, std::shared_ptr<ICmsHeaderBase>& header) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Encrypts a stream within a file using CKM 7.</summary>
    ///
    /// <param name="sFile">		[in] The source file.</param>
    /// <param name="sEncrFile">	[in] The encrypted file.</param>
    /// <param name="header">		[in] The CMS header.</param>
    /// <param name="comp">			Compression type.</param>
    /// <param name="algorithm">	The encryption algorithm.</param>
    /// <param name="hashAlgorithm">The hash algorithm.</param>
    /// <param name="SignHeader">   true to sign header.</param>
    /// <param name="bindData">		true to bind data to the header.</param>
    /// <param name="DataFormat">   The data format.</param>
    /// <param name="randomIvec">   true for random ivec.</param>
    /// <param name="paddingType">  Type of data padding.</param>
    /// <param name="blockSize">	(optional) size of the block to process.</param>
    ///
    /// <returns>S_OK for success or a standard COM error code for failure.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool EncryptCryptoData(const tscrypto::tsCryptoData &inputData, tscrypto::tsCryptoData &outputData, std::shared_ptr<ICmsHeader> header, CompressionType comp, tscrypto::TS_ALG_ID algorithm,
		tscrypto::TS_ALG_ID hashAlgorithm, bool SignHeader, bool bindData, CMSFileFormatIds DataFormat, bool randomIvec, tscrypto::SymmetricPaddingType paddingType, int blockSize = 5000000) = 0;

	virtual bool RecoverKeys(const tscrypto::tsCryptoString& inputFile, FileVEILFileOp_recoveredKeyList& keys) = 0;
	/**
	* \brief Decrypts a byte array using CKM7 and returns the decrypted data.
	*
	* \param [in] inputData	  The encrypted data.
	* \param [out] outputData The decrypted data.
	*
	* \return true for success.
	*/
	virtual bool DecryptCryptoData(const tscrypto::tsCryptoData &inputData, tscrypto::tsCryptoData &outputData) = 0;
	// Added 7.0.8
	/**
	* \brief Decrypts a byte array using CKM7 and returns the decrypted data and the header.
	*
	* \param [in] inputData	  The encrypted data.
	* \param [out] outputData The decrypted data.
	* \param [out] header     The header extracted from the data.
	*
	* \return true for success.
	*/
	virtual bool DecryptCryptoDataWithHeader(const tscrypto::tsCryptoData &inputData, tscrypto::tsCryptoData &outputData, std::shared_ptr<ICmsHeaderBase>& header) = 0;
	// Added 7.0.30
	virtual bool  DataStartsWithCmsHeader(const tscrypto::tsCryptoData& contents, std::shared_ptr<ICmsHeaderBase>& pVal) = 0;
	// Added 7.0.43
	virtual tscrypto::tsCryptoString failureReason() = 0;
	// Added 7.0.46
	virtual bool GetFileInformation(const tscrypto::tsCryptoString& filename, tscrypto::JSONObject& info) = 0;
};


/// <summary>A factory interface used to create the VEIL File Support objects.</summary>
class VEILFILESUPPORT_EXPORT IVEILFileSupportFactory
{
public:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Creates a file operations object.</summary>
    ///
    /// <param name="pVal">[in,out] The created object.</param>
    ///
    /// <returns>S_OK for success or a standard COM error code for failure.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool CreateFileOperations(std::shared_ptr<IFileVEILOperations>& pVal) = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Creates a file list object.</summary>
    ///
    /// <param name="pVal">[in,out] The created object.</param>
    ///
    /// <returns>S_OK for success or a standard COM error code for failure.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool CreateFileList(std::shared_ptr<IVEILFileList>& pVal) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Creates a file stream.</summary>
	///
	/// <param name="filename">Filename of the file to open.</param>
	/// <param name="readable">true if readable.</param>
	/// <param name="writable">true if writable.</param>
	/// <param name="pVal">	   [in,out] The created object.</param>
	///
    /// <returns>S_OK for success or a standard COM error code for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool CreateFileStream(const tscrypto::tsCryptoString& filename, bool readable, bool writable, std::shared_ptr<IDataIOBase>& pVal) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Creates a stream that uses a byte array in memory to hold the data.</summary>
	///
	/// <param name="pVal">[in,out] The created object.</param>
	///
    /// <returns>S_OK for success or a standard COM error code for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool CreateMemoryStream(std::shared_ptr<IDataIOBase>& pVal) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Creates a FIFO memory stream.</summary>
	///
	/// <param name="pVal">[in,out] The created object.</param>
	///
    /// <returns>S_OK for success or a standard COM error code for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool CreateFifoMemoryStream(std::shared_ptr<IDataIOBase>& pVal) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Creates read and append file stream.</summary>
	///
	/// <param name="filename">Filename of the file to open.</param>
	/// <param name="pVal">	   [in,out] The created object.</param>
	///
    /// <returns>S_OK for success or a standard COM error code for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool CreateReadAppendFileStream(const tscrypto::tsCryptoString& filename, std::shared_ptr<IDataIOBase>& pVal) = 0;
};

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Represents a callback used during decrypt operations (<see cref="ICKMCryptoHelper"/>)
/// to specify that a CKM header has been found and to allow the caller to perform some
/// processing on the header.</summary>
////////////////////////////////////////////////////////////////////////////////////////////////////
class VEILFILESUPPORT_EXPORT ICryptoHelperDecryptCallback
{
public:
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>The header has been found.</summary>
	///
	/// <param name="headerBase">[in] The header.</param>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool HeaderFound(std::shared_ptr<ICmsHeaderBase> headerBase) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>The header has been verified.</summary>
	///
	/// <param name="headerBase">[in] The header.</param>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool HeaderVerified(std::shared_ptr<ICmsHeaderBase> headerBase) = 0;
};

/// <summary>A higher level encryption/decryption/hash processing class.</summary>
class VEILFILESUPPORT_EXPORT ICryptoHelper
{
public:
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Compute a hash of the specified data.</summary>
	///
	/// <param name="data">		The data to hash.</param>
	/// <param name="algorithm">The hash algorithm.</param>
	/// <param name="hash">		[out] The hash value.</param>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool HashData(const tscrypto::tsCryptoData &data, tscrypto::TS_ALG_ID algorithm, tscrypto::tsCryptoData &hash) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Computes an Hmac of the specified data.</summary>
	///
	/// <param name="data">		The data to hash.</param>
	/// <param name="key">		The key for the HMAC.</param>
	/// <param name="algorithm">The HMAC algorithm.</param>
	/// <param name="hash">		[out] The hash value.</param>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool HmacData(const tscrypto::tsCryptoData &data, const tscrypto::tsCryptoData &key, tscrypto::TS_ALG_ID algorithm, tscrypto::tsCryptoData &hash) = 0;

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>(CKM 7)Encrypts the data in the CKM 7 stream.</summary>
	///
	/// <param name="comp">			The compression type.</param>
	/// <param name="algorithm">	The encryption algorithm.</param>
	/// <param name="hashAlgorithm">The hash algorithm.</param>
	/// <param name="header">		[in,out] The CKM header.</param>
	/// <param name="prependHeader">true to prepend the header on the data stream.</param>
	/// <param name="forcedIvec">   The forced ivec.</param>
	/// <param name="reader">		[in] The input data stream.</param>
	/// <param name="writer">		[in] The output data stream.</param>
	/// <param name="SignHeader">   true to sign header.</param>
	/// <param name="bindData">		true to bind the data to the header.</param>
	/// <param name="DataFormat">   The data format.</param>
	/// <param name="randomIvec">   true for a random ivec.</param>
	/// <param name="paddingType">  Type of the padding.</param>
	/// <param name="blockSize">	(optional) size of the block to process.</param>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool EncryptStream(CompressionType comp, tscrypto::TS_ALG_ID algorithm, tscrypto::TS_ALG_ID hashAlgorithm,
		std::shared_ptr<ICmsHeaderBase> header, bool prependHeader, const tscrypto::tsCryptoData &forcedIvec,
		std::shared_ptr<IDataReader> reader, std::shared_ptr<IDataWriter> writer,
		bool SignHeader, bool bindData, CMSFileFormatIds DataFormat, bool randomIvec,
		tscrypto::SymmetricPaddingType paddingType, int blockSize = 5000000) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Decrypts a stream of data and returns the header.</summary>
	///
	/// <param name="header">[in,out] On input the CKM header to use or NULL to read the header from the input data, on output the CKM header.</param>
	/// <param name="reader">[in] The input data stream.</param>
	/// <param name="writer">[in] The output data stream.</param>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool DecryptStream(std::shared_ptr<ICmsHeaderBase> header, std::shared_ptr<IDataReader> reader, std::shared_ptr<IDataWriter> writer, bool headerIncludedInStream) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Checks a data stream to see if it begins with a CKM 7 header</summary>
	///
	/// <param name="stream">[in] The input data stream.</param>
	/// <param name="pVal">  [out] The CKM header found at the beginning of the data stream.</param>
	///
	/// <returns>true if a header was found, false if not.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool    StreamStartsWithCkmHeader(std::shared_ptr<IDataReader> stream, std::shared_ptr<ICmsHeaderBase>& pVal) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Performs all validations of the header and data that can be done publically (no private or secret keys needed).</summary>
	///
	/// <param name="reader">[in] The input data stream.</param>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool ValidateFileContents_PublicOnly(std::shared_ptr<IDataReader> reader) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the callback interface that is to be used on encrypt/decrypt operations.</summary>
	///
	/// <param name="setTo">[in] The callback interface.</param>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool SetOperationStatusCallback(std::shared_ptr<IFileVEILOperationStatus> setTo) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the current task information.</summary>
	///
	/// <param name="taskNumber">The task number.</param>
	/// <param name="taskCount"> Number of tasks.</param>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool SetTaskInformation(int taskNumber, int taskCount) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the Decrypt Helper callback interface.</summary>
	///
	/// <param name="setTo">[in] the Decrypt Helper callback interface.</param>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool SetDecryptCallback(std::shared_ptr<ICryptoHelperDecryptCallback> setTo) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Calculates a header identity value that is used to bind the data to the header.</summary>
	///
	/// <param name="header">[in] The CKM header.</param>
	///
	/// <returns>The calculated header identity.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual tscrypto::tsCryptoData ComputeHeaderIdentity(std::shared_ptr<ICmsHeader> header) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Pads the CKM header to the specified byte size.</summary>
	///
	/// <param name="header">[in] The CKM header to pad.</param>
	/// <param name="size">  The size in bytes of the final header.</param>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool padHeaderToSize(std::shared_ptr<ICmsHeaderBase> header, uint32_t size) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Modifies a CKM 7 header and preloads the encryption parameters in preparation of
	/// creating the working key.</summary>
	///
	/// <param name="header7">		[in,out] The CKM 7 header.</param>
	/// <param name="comp">			The compression type.</param>
	/// <param name="algorithm">	The encryption algorithm.</param>
	/// <param name="hashAlgorithm">The hash algorithm.</param>
	/// <param name="SignHeader">   true to sign the header.</param>
	/// <param name="bindData">		true to bind the data to the header.</param>
	/// <param name="DataFormat">   The data format.</param>
	/// <param name="randomIvec">   true for a random ivec.</param>
	/// <param name="paddingType">  Type of encryption padding.</param>
	/// <param name="blockSize">	Size of the block to process.</param>
	/// <param name="fileSize">		Size of the file.</param>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool PrepareHeader(std::shared_ptr<ICmsHeader> header7, CompressionType comp, tscrypto::TS_ALG_ID algorithm, tscrypto::TS_ALG_ID hashAlgorithm, bool SignHeader, bool bindData,
		CMSFileFormatIds DataFormat, bool randomIvec, tscrypto::SymmetricPaddingType paddingType, int blockSize, int64_t fileSize) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Gets the size in bytes that is reserved for the CKM header in the data stream.</summary>
	///
	/// <returns>The size in bytes that is reserved for the CKM header in the data stream.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual uint32_t   ReservedHeaderLength() const = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Sets the ICKMKeyGenCallback callback interface.</summary>
	///
	/// <param name="callback">[in] The callback interface.</param>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool SetKeyGenCallback(std::shared_ptr<IKeyGenCallback> callback) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Encrypts a stream with the specified symmetric key.</summary>
	///
	/// <param name="comp">		  The compression type.</param>
	/// <param name="algorithm">  The encryption algorithm.</param>
	/// <param name="hashOid">	  The hash algorithm oid.</param>
	/// <param name="key">		  The symmetric key.</param>
	/// <param name="forcedIvec"> The forced ivec.</param>
	/// <param name="reader">	  [in] The input data stream.</param>
	/// <param name="writer">	  [in] The output data stream.</param>
	/// <param name="DataFormat"> The data format.</param>
	/// <param name="paddingType">The type of data padding needed.</param>
	/// <param name="authData">   The header identity data.</param>
	/// <param name="finalHash">  [out] The final data hash.</param>
	/// <param name="blockSize">  (optional) size of the block to process.</param>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool EncryptStreamWithKey(CompressionType comp, tscrypto::TS_ALG_ID algorithm, const tscrypto::tsCryptoData &hashOid,
		const tscrypto::tsCryptoData &key, const tscrypto::tsCryptoData &forcedIvec, std::shared_ptr<IDataReader> reader, std::shared_ptr<IDataWriter> writer,
		CMSFileFormatIds DataFormat, tscrypto::SymmetricPaddingType paddingType, const tscrypto::tsCryptoData &authData, tscrypto::tsCryptoData &finalHash, int blockSize = 5000000) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Decrypts a data stream using the specified symmetric key.</summary>
	///
	/// <param name="reader">	  [in] The input data stream.</param>
	/// <param name="writer">	  [in] The output data stream.</param>
	/// <param name="comp">		  The compression type.</param>
	/// <param name="algorithm">  The encryption algorithm.</param>
	/// <param name="hashOid">	  The hash algorithm oid.</param>
	/// <param name="key">		  The symmetric key.</param>
	/// <param name="forcedIvec"> The forced ivec.</param>
	/// <param name="DataFormat"> The data format.</param>
	/// <param name="paddingType">The type of data padding needed.</param>
	/// <param name="authData">   The header identity.</param>
	/// <param name="finalHash">  The final data hash.</param>
	/// <param name="blockSize">  (optional) size of the block to process.</param>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool DecryptStreamWithKey(std::shared_ptr<IDataReader> reader, std::shared_ptr<IDataWriter> writer, CompressionType comp,
		tscrypto::TS_ALG_ID algorithm, const tscrypto::tsCryptoData &hashOid, const tscrypto::tsCryptoData &key, const tscrypto::tsCryptoData &forcedIvec, CMSFileFormatIds DataFormat,
		tscrypto::SymmetricPaddingType paddingType, const tscrypto::tsCryptoData &authData, const tscrypto::tsCryptoData &finalHash, int blockSize = 5000000) = 0;

	/**
	* \brief Callback, called when the a session is needed.
	*
	* \param [in,out] callback The callback interface object.
	*
	* \return .
	*/
	virtual bool SetSessionCallback(std::shared_ptr<IFileVEILSessionCallback> callback) = 0;
	
	// Added 7.0.7
	virtual bool GenerateWorkingKey(std::shared_ptr<ICmsHeader>& header, std::shared_ptr<IKeyGenCallback> callback, tscrypto::tsCryptoData& workingKey) = 0;
	virtual bool RegenerateWorkingKey(std::shared_ptr<ICmsHeader>& header, tscrypto::tsCryptoData& workingKey) = 0;

	// Added 7.0.43
	virtual tscrypto::tsCryptoString failureReason() = 0;
};

/*! @brief Enumeration that defines the compression action to take
*
* This enumeration contains the actions that are to be performed on the compression object
*/
typedef enum {
	compAct_Run,        /*!< Normal operational mode */
	compAct_Flush,      /*!< Flush the current compression data to the output buffer */
	compAct_Finish      /*!< Finish the compression and flush all data to the output buffer */
} CompressionAction;

/*! @brief Basic compression interface
*
* This interface defines the common interface for the compression algorithms supported in the CKM Runtime
*/
class VEILFILESUPPORT_EXPORT ICompression
{
public:
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Initialize a compress operation.</summary>
	///
	/// <param name="level">The level (must be between 1 and 9, or 0 for default).</param>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool CompressInit(int level) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Incrementally compress the specified data and return any completed data.</summary>
	///
	/// <param name="inBuff"> input data to be compressed.</param>
	/// <param name="outBuff">[out] Destination for any compressed data.</param>
	/// <param name="action"> The action.</param>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool Compress(const tscrypto::tsCryptoData &inBuff, tscrypto::tsCryptoData &outBuff, CompressionAction action) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Finalize the compression, return the last of the compressed data and clear the state of this object.</summary>
	///
	/// <param name="outBuff">[out] Destination for any compressed data.</param>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool CompressFinal(tscrypto::tsCryptoData &outBuff) = 0;

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Start a decompress operation.</summary>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool DecompressInit() = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Incrementally decompress the specified data and return any completed data.</summary>
	///
	/// <param name="inBuff"> input data to be decompressed.</param>
	/// <param name="outBuff">[out] Destination for any decompressed data.</param>
	/// <param name="action"> The action.</param>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool Decompress(const tscrypto::tsCryptoData &inBuff, tscrypto::tsCryptoData &outBuff, CompressionAction action) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Finalize the decompression, return the last of the decompressed data and clear the state of this object.</summary>
	///
	/// <param name="outBuff">[out] Destination for any decompressed data.</param>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool DecompressFinal(tscrypto::tsCryptoData &outBuff) = 0;
};

class VEILFILESUPPORT_EXPORT IEncryptProcessor : public IReservedLength
{
public:
	virtual bool EncryptUsingKey(const tscrypto::tsCryptoData &key, int format, int blocksize, tscrypto::TS_ALG_ID encryptionAlg, const tscrypto::tsCryptoData &hashOid, CompressionType compType,
		const tscrypto::tsCryptoData &ivec, tscrypto::SymmetricPaddingType padding, const tscrypto::tsCryptoData &authData, tscrypto::tsCryptoData &finalHash) = 0;
};

/// <summary>Represents a helper object used in the data decryption process for CKM 7.</summary>
class VEILFILESUPPORT_EXPORT IDecryptProcessor
{
public:
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Prevalidates the data.</summary>
	///
	/// <param name="header">[in] The CKM header.</param>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool PrevalidateData(std::shared_ptr<ICmsHeaderBase> header) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Decrypts the data with the specified key.</summary>
	///
	/// <param name="key">   The key.</param>
	/// <param name="header">[in] The CKM header.</param>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool DecryptData(const tscrypto::tsCryptoData &key, std::shared_ptr<ICmsHeaderBase>& header) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Prevalidates the data hash.</summary>
	///
	/// <param name="finalHash">The final hash.</param>
	/// <param name="hashOid">  The hash algorithm oid.</param>
	/// <param name="authData"> The header identity.</param>
	/// <param name="format">   The data format used.</param>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool PrevalidateDataHash(const tscrypto::tsCryptoData &finalHash, const tscrypto::tsCryptoData &hashOid, const tscrypto::tsCryptoData &authData, int format) = 0;
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Decrypts the data using the specified key.</summary>
	///
	/// <param name="key">			The key.</param>
	/// <param name="format">		Describes the format used.</param>
	/// <param name="blocksize">	The block size in bytes.</param>
	/// <param name="encryptionAlg">The encryption algorithm.</param>
	/// <param name="hashOid">		The hash algorithm oid.</param>
	/// <param name="compType">		Type of compression.</param>
	/// <param name="ivec">			The ivec.</param>
	/// <param name="padding">		The padding.</param>
	/// <param name="authData">		The header identity.</param>
	/// <param name="finalHash">	The final hash.</param>
	///
	/// <returns>S_OK for success or a standard COM error for failure.</returns>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool DecryptUsingKey(const tscrypto::tsCryptoData &key, int format, int blocksize, tscrypto::TS_ALG_ID encryptionAlg, const tscrypto::tsCryptoData &hashOid, CompressionType compType,
		const tscrypto::tsCryptoData &ivec, tscrypto::SymmetricPaddingType padding, const tscrypto::tsCryptoData &authData, const tscrypto::tsCryptoData &finalHash) = 0;
};

/// <summary>Defines the interface used to initialize, terminate and use this component.</summary>
class VEILFILESUPPORT_EXPORT IVEILFileSupportDllInterface
{
public:
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Initializes the FileVEIL support component.</summary>
    ///
    /// <returns>S_OK for success or a standard COM error code for failure.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool InitializeVEILFileSupport() = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Terminates the FileVEIL support component.</summary>
    ///
    /// <returns>S_OK for success or a standard COM error code for failure.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool TerminateVEILFileSupport() = 0;
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>Gets the FileVEIL support factory.</summary>
    ///
    /// <param name="pVal">[in,out] The created object.</param>
    ///
    /// <returns>The FileVEIL support factory.</returns>
    ////////////////////////////////////////////////////////////////////////////////////////////////////
	virtual bool GetVEILFileSupportFactory(std::shared_ptr<IVEILFileSupportFactory>& pVal) = 0;
};

/*! \cond DO_NOT_DOCUMENT */
typedef std::shared_ptr<IVEILFileSupportDllInterface> (*GetVEILFileSupportDllInterfaceFn)();
/*! \endcond */


#if (__GNUC__ >= 4) && !defined(__APPLE__)
extern "C"
#endif
std::shared_ptr<IVEILFileSupportDllInterface> VEILFILESUPPORT_EXPORT GetVEILFileSupportDllInterface();
std::shared_ptr<ICryptoHelper> VEILFILESUPPORT_EXPORT CreateCryptoHelper(std::shared_ptr<IKeyVEILSession> session);
std::shared_ptr<ICompression> VEILFILESUPPORT_EXPORT CreateCompressor(CompressionType type);
std::shared_ptr<IFileVEILOperations> VEILFILESUPPORT_EXPORT CreateFileVEILOperationsObject();
tscrypto::tsCryptoData VEILFILESUPPORT_EXPORT computeHeaderIdentity(std::shared_ptr<ICmsHeader> header);

#endif // VEILFILESUPPORT_H_INCLUDED
