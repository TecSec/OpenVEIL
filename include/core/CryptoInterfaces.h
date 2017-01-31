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

#ifndef __CORE_CRYPTO_H_INCLUDED
#define __CORE_CRYPTO_H_INCLUDED

#pragma once

//namespace tscrypto {
//	struct AlgorithmIdentifier;
//}

namespace tscrypto {

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Retrieves algorithm name/OID/ID from the algorithm object.</summary>
	///
	/// <remarks>All of the cryptographic objects created by this module implement this interface
	/// 		 to allow for the caller to query the object for its name, OID and TecSec ID.</remarks>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	class VEILCORE_API AlgorithmInfo
	{
	public:

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the algorithm name.</summary>
		///
		/// <returns>null if it fails, else.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoString AlgorithmName() const = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the algorithm oid.</summary>
		///
		/// <returns>null if it fails, else.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoString AlgorithmOID() const = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the TecSec assigned algorithm identifier.</summary>
		///
		/// <returns>the TecSec assigned algorithm identifier.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual TS_ALG_ID AlgorithmID() const = 0;
	};

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Allows the caller to perform self tests on a given algorithm.</summary>
	///
	/// <remarks>This interfaces is implemented by all of the algorithm objects constructed by
	/// 		 this module.  This interface allows the caller to perform summary or detailed
	/// 		 self tests for the algorithm.  The state of the algorithm object will likely be
	/// 		 changed by the self tests.</remarks>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	class VEILCORE_API Selftest
	{
	public:

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Executes the built in self tests for this algorithm.</summary>
		///
		/// <remarks>This function is used to force the algorithm to run its self tests.  If the tests
		/// 		 fail then the module will be marked as non-operational.</remarks>
		///
		/// <param name="runDetailedTests">true to run detailed tests.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool runTests(bool runDetailedTests) = 0;
	};

	/// <summary>Allows an object to host specialized self tests for another algorithm that uses this algorithm</summary>
	class VEILCORE_API TSExtensibleSelfTest
	{
	public:
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Executes the self tests for operation.</summary>
		///
		/// <param name="baseProtocolName">Name of the base protocol.</param>
		/// <param name="baseProtocol">	   [in] The base protocol interface pointer.</param>
		/// <param name="runDetailedTests">true to run detailed tests.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool RunSelfTestsFor(const tsCryptoStringBase &baseProtocolName, std::shared_ptr<tscrypto::ICryptoObject> baseProtocol, bool runDetailedTests) = 0;
	};

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>Allows the caller to define a block counter mode incrementor object that can be
	/// 		 passed to the Symmetric algorithm.</summary>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	class VEILCORE_API CounterModeIncrementor
	{
	public:

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Called before the block is processed.  Allows for pre-block incrementing.</summary>
		///
		/// <param name="iv">		  [in,out] The iv.</param>
		/// <param name="ivLength">   Length of the iv.</param>
		/// <param name="inputBlock"> The input block.</param>
		/// <param name="blockLength">Length of the block.</param>
		/// <param name="blockNumber">The block number.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool preProcess(uint8_t *iv, size_t ivLength, const uint8_t *inputBlock, size_t blockLength, uint64_t blockNumber) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Called after the block is processed.  Allows for post-block incrementing.</summary>
		///
		/// <param name="iv">		  [in,out] The iv.</param>
		/// <param name="ivLength">   Length of the iv.</param>
		/// <param name="inputBlock"> The input block.</param>
		/// <param name="outputBlock">The output block.</param>
		/// <param name="blockLength">Length of the block.</param>
		/// <param name="blockNumber">The block number.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool postProcess(uint8_t *iv, size_t ivLength, const uint8_t *inputBlock, const uint8_t *outputBlock, size_t blockLength, uint64_t blockNumber) = 0;
	};

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>used to access the functionality of a symmetric encryption algorithm</summary>
	///
	/// <remarks>This interface is implemented by all symmetric encryption/decryption algorithms
	/// 		 in this library.
	///
	/// 		 This class is a referenced counted class that uses the underlying principles of
	/// 		 COM objects to control the lifetime of the object.  It also supports the querying
	/// 		 of interfaces using the techniques defined in COM.</remarks>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	class VEILCORE_API ICKMSymmetricPad
	{
	public:
		virtual bool PadData(tsCryptoData& dataToPad, int blocksize) = 0;
		virtual bool UnpadData(tsCryptoData& dataToUnpad, int blocksize) = 0;
	};

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>used to access the functionality of a symmetric encryption algorithm</summary>
	///
	/// <remarks>This interface is implemented by all symmetric encryption/decryption algorithms
	/// 		 in this library.
	///
	/// 		 This class is a referenced counted class that uses the underlying principles of
	/// 		 COM objects to control the lifetime of the object.  It also supports the querying
	/// 		 of interfaces using the techniques defined in COM.</remarks>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	class VEILCORE_API Symmetric
	{
	public:
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Retrieves the current block size</summary>
		///
		/// <remarks>This function is used to retrieve the current block size that the symmetric
		/// 		 algorithm is currently using.  Any given algorithm may be capable of supporting
		/// 		 multiple block sizes.  Use the supportsBlockLength function to see if a given
		/// 		 block size is supported.</remarks>
		///
		/// <returns>the current block size in bytes.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t getBlockSize() = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Creates a random key for this algorithm</summary>
		///
		/// <remarks>This function is used to create a random key that will function properly for the
		/// 		 specified symmetric algorithm.  The algorithm must be one of the algorithm IDs
		/// 		 that are implemented by the class that implements this interface.  If you create
		/// 		 a DES object, and then ask for the creation of an AES key, the call will fail.</remarks>
		///
		/// <param name="keyLengthInBits">The key length in bits.</param>
		/// <param name="key">			  [in,out] The key.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool createKey(size_t keyLengthInBits, tsCryptoData &key) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Creates a random IVEC for this key</summary>
		///
		/// <remarks>This function is used to create a random IVEC.</remarks>
		///
		/// <param name="ivec">[in,out] the generated ivec value.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool createIVEC(tsCryptoData &ivec) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Initializes the encryption/decryption process</summary>
		///
		/// <remarks>This function is used to start an encryption or decryption session.  It
		/// 		 establishes the key, keysize, IVEC, and mode of operation that is to be used.
		/// 		 This function shall validate that the parameters are acceptable before proceeding
		/// 		 with the operation.
		///
		/// 		 In the case of algorithms like TDES that have parity bits, this function will
		/// 		 validate that the parity bits are set properly.  If not this function will fail.</remarks>
		///
		/// <param name="forEncrypt">If true, then configure for encrypt.  Otherwise configure for decrypt.</param>
		/// <param name="mode">		 Specifies the mode of operation that shall be used for this session.</param>
		/// <param name="key">		 The key that shall be used (big endian form)</param>
		/// <param name="ivec">		 The IVEC that will start this session.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool init(bool forEncrypt, SymmetricMode mode, const tsCryptoData &key, const tsCryptoData &ivec) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Processes one or more blocks of data</summary>
		///
		/// <remarks>This function is used to pass one or more blocks of data to the symmetric
		/// 		 algorithm for processing.  The type of processing is defined by the parameters
		/// 		 used in the init function.</remarks>
		///
		/// <param name="in_Data"> The source data to be processed.</param>
		/// <param name="out_Data">[in,out] Where the processed data is to be put.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool update(const tsCryptoData &in_Data, tsCryptoData &out_Data) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Finishes the encryption/decryption process</summary>
		///
		/// <remarks>This function is used to clean up resources and keys after the
		/// 		 encryption/decryption process has been completed.  By calling this function, all
		/// 		 keys are securely deleted and the algorithm can be used for another
		/// 		 encryption/decryption.</remarks>
		///
		/// <param name="out_Data">[in,out] The final block of data.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool finish(tsCryptoData &out_Data) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Retrieves the current IVEC from the base algorithm context</summary>
		///
		/// <remarks>This function retrieves the current IVEC value from the symmetric algorithm.
		/// 		 This value will normally change after each block that is encrypted/decrypted if
		/// 		 an IVEC based mode is used.</remarks>
		///
		/// <param name="ivec">[in,out] The destination that will hold the IVEC value.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool getIVEC(tsCryptoData &ivec) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets a new IVEC into the base algorithm context</summary>
		///
		/// <remarks>This function changes the value of the IVEC that will be used for the next block.</remarks>
		///
		/// <param name="ivec">The new IVEC value.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool setIVEC(const tsCryptoData &ivec) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Queries the algorithm to see if a specified block length is supported.</summary>
		///
		/// <remarks>This function is used to see if the underlying algorithm supports a given block
		/// 		 length.</remarks>
		///
		/// <param name="in_blockLength">The block length in bytes that is desired.</param>
		///
		/// <returns>true if the specified block length is supported.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool supportsBlockLength(size_t in_blockLength) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Queries the algorithm to see if a specified key length is supported.</summary>
		///
		/// <remarks>This function is used to see if the underlying algorithm supports a given key
		/// 		 size.</remarks>
		///
		/// <param name="in_keyLength">The key size in bits that is desired.</param>
		///
		/// <returns>true if the specified key length is supported.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool supportsKeyLength(size_t in_keyLength) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Query if 'key' is usable key.</summary>
		///
		/// <param name="key">The key to test.</param>
		///
		/// <returns>true if usable key, false if not.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool isUsableKey(const tsCryptoData &key) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Converts a byte array into a key buffer</summary>
		///
		/// <remarks>This function is used to convert a raw byte stream into a key that is suitable
		/// 		 for this algorithm. For algorithms like TDES, the parity bits are computed and
		/// 		 set properly in the key.</remarks>
		///
		/// <param name="keyBitStrength">The key bit strength.</param>
		/// <param name="data">			 The data.</param>
		/// <param name="key">			 [in,out] The key.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool bytesToKey(size_t keyBitStrength, const tsCryptoData &data, tsCryptoData &key) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the block count.</summary>
		///
		/// <remarks>This function is used to retrieve the number of blocks that have been processed
		/// 		 by this object. The block count is important for some algorithms that are at end
		/// 		 of life.  For instance the TDES algorithm is limited to roughly 1000000 blocks
		/// 		 for the two key version.</remarks>
		///
		/// <returns>The block count.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual uint64_t getBlockCount() const = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets a block count.</summary>
		///
		/// <remarks>This function is used to set the number of blocks that have been processed by
		/// 		 this key. The block count is important for some algorithms that are at end of
		/// 		 life.  For instance the TDES algorithm is limited to roughly 1000000 blocks for
		/// 		 the two key version.</remarks>
		///
		/// <param name="setTo">The starting block count.</param>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual void setBlockCount(uint64_t setTo) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Registers the counter mode incrementor described by pObj.</summary>
		///
		/// <remarks>This function allows the caller to register their own functionality that is to be
		/// 		 used when the CTR mode of operation is used on this algorithm.  By default the IV
		/// 		 is treated as a big-endian number and is incremented by one for each block
		/// 		 processed.</remarks>
		///
		/// <param name="pObj">[in,out] If non-null, the object to use, otherwise use the built in
		/// 				   incrementor.</param>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual void registerCounterModeIncrementor(std::shared_ptr<CounterModeIncrementor> pObj) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets ivec size for the specified mode.</summary>
		///
		/// <param name="mode">The mode.</param>
		///
		/// <returns>The ivec size for mode.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t getIVECSizeForMode(SymmetricMode mode) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the padding type.</summary>
		///
		/// <returns>The padding type.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual SymmetricPaddingType getPaddingType() = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the padding type.</summary>
		///
		/// <param name="setTo">The padding type.</param>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual void setPaddingType(SymmetricPaddingType setTo) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Processes one or more blocks of data</summary>
		///
		/// <remarks>This function is used to pass one or more blocks of data to the symmetric
		/// 		 algorithm for processing.  The type of processing is defined by the parameters
		/// 		 used in the init function. All padding operations will be performed on the data
		/// 		 and final will be called internally.</remarks>
		///
		/// <param name="in_Data"> The source data to be processed.</param>
		/// <param name="out_Data">[in,out] Where the processed data is to be put.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool updateAndFinish(const tsCryptoData &in_Data, tsCryptoData &out_Data) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the minimum key size in bits.</summary>
		///
		/// <returns>the minimum key size in bits.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t minimumKeySizeInBits() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the maximum key size in bits.</summary>
		///
		/// <returns>The maximum key size in bits.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t maximumKeySizeInBits() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the key size increment in bits.</summary>
		///
		/// <returns>The key size increment in bits.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t keySizeIncrementInBits() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the custom pad interface.</summary>
		///
		/// <param name="setTo"> The custom pad interface.</param>
		/// <returns>A standard COM error code or S_OK for success.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool setCustomPadInterface(std::shared_ptr<ICKMSymmetricPad> setTo) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the custom pad interface.</summary>
		///
		/// <param name="pVal"> The custom pad interface.</param>
		/// <returns>A standard COM error code or S_OK for success.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool getCustomPadInterface(std::shared_ptr<ICKMSymmetricPad> pVal) const = 0;
		/**
		* \brief Retrieve the current encryption/decryption mode of operation
		*/
		virtual SymmetricMode getCurrentMode() const = 0;
		virtual bool reserved1(uint8_t* data) = 0;
		virtual size_t currentKeySizeInBits() const = 0;
	};

	/// <summary>
	/// Class SymmetricEffectiveKeySize.
	/// </summary>
	class VEILCORE_API SymmetricEffectiveKeySize
	{
	public:
		/// <summary>
		/// Finalizes an instance of the <see cref="SymmetricEffectiveKeySize"/> class.
		/// </summary>
		virtual ~SymmetricEffectiveKeySize() {}
		/// <summary>
		/// Gets the size of the effective key.
		/// </summary>
		/// <returns>size_t.</returns>
		virtual size_t GetEffectiveKeySize() = 0;
		/// <summary>
		/// Sets the size of the effective key in bits.
		/// </summary>
		/// <param name="setTo">The set to.</param>
		virtual void SetEffectiveKeySize(size_t setTo) = 0;
	};
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>used to access the functionality of the hash and HMAC algorithms</summary>
	///
	/// <remarks>This class provides access to one or more Hash functions and the matching HMAC
	/// 		 functions for the same hash functions.  If the initialize function is used, then
	/// 		 the Hash function is specified.  If the initializeKeyedHash is called, then this
	/// 		 class is configured for HMAC mode.
	///
	/// 		 This class is a referenced counted class that uses the underlying principles of
	/// 		 COM objects to control the lifetime of the object.  It also supports the querying
	/// 		 of interfaces using the techniques defined in COM.</remarks>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	class VEILCORE_API Hash
	{
	public:
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Initiates a hash operation</summary>
		///
		/// <remarks>This function is used to start a hash operation.  This is the first of a three
		/// 		 step process to create a hash of data.  The second step is update and the last
		/// 		 step is final.</remarks>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool initialize() = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Processes another block of data through the hash or HMAC operation.</summary>
		///
		/// <remarks>This function is the second of three steps to create a hash of data.  This
		/// 		 function should be called one or more times until all of the data has been
		/// 		 processed.</remarks>
		///
		/// <param name="data">The data to process.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool update(const tsCryptoData &data) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Finishes the hash or HMAC operation and returns the result</summary>
		///
		/// <remarks>This function is the third of three steps to create a hash of data.  This
		/// 		 function should be called after all of the data has been processed through calls
		/// 		 to update.</remarks>
		///
		/// <param name="digest">[in,out] Where the Hash or HMAC shall be placed (or NULL to get the
		/// 					 length of the Hash or HMAC)</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool finish(tsCryptoData &digest) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets block size.</summary>
		///
		/// <returns>The block size.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t GetBlockSize() = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets digest size.</summary>
		///
		/// <returns>The digest size.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t GetDigestSize() = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the minimum key size in bits.</summary>
		///
		/// <returns>the minimum key size in bits.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t minimumKeySizeInBits() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the maximum key size in bits.</summary>
		///
		/// <returns>the maximum key size in bits.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t maximumKeySizeInBits() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the key size increment in bits.</summary>
		///
		/// <returns>the key size increment in bits.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t keySizeIncrementInBits() const = 0;
	};

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>used to access the functionality of the HMAC algorithm.</summary>
	///
	/// <remarks>This class provides access to HMAC functions for a hash function.
	///
	/// This class is a referenced counted class that uses the underlying principles of COM objects
	/// to control the lifetime of the object.  It also supports the querying of interfaces using the
	/// techniques defined in COM.</remarks>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	class VEILCORE_API MessageAuthenticationCode
	{
	public:
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Initiates an HMAC operation.</summary>
		///
		/// <remarks>This function is used to start an HMAC operation.  This is the first of a three step
		/// process to create an HMAC of data.  The second step is update and the last step is final.</remarks>
		///
		/// <param name="key">The key.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool initialize(const tsCryptoData &key) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Processes another block of data through the HMAC operation.</summary>
		///
		/// <remarks>This function is the second of three steps to create an HMAC of data.  This function
		/// should be called one or more times until all of the data has been processed.</remarks>
		///
		/// <param name="data">The data to process.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool update(const tsCryptoData &data) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Finishes the HMAC operation and returns the result.</summary>
		///
		/// <remarks>This function is the third of three steps to create an HMAC of data.  This function
		/// should be called after all of the data has been processed through calls to update.</remarks>
		///
		/// <param name="digest">[in,out] Where the HMAC shall be placed (or NULL to get the length of the
		/// Hash or HMAC)</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool finish(tsCryptoData &digest) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets block size.</summary>
		///
		/// <returns>The block size.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////

		virtual size_t GetBlockSize() = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets digest size.</summary>
		///
		/// <returns>The digest size.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////

		virtual size_t GetDigestSize() = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Query if 'key' is usable key.</summary>
		///
		/// <param name="key">The key.</param>
		///
		/// <returns>true if usable key, false if not.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool isUsableKey(const tsCryptoData &key) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Determines if this algorithm requires a key.</summary>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool requiresKey() const = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the minimum key size in bits.</summary>
		///
		/// <returns>the minimum key size in bits.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t minimumKeySizeInBits() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the maximum key size in bits.</summary>
		///
		/// <returns>the maximum key size in bits.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t maximumKeySizeInBits() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the key size increment in bits.</summary>
		///
		/// <returns>the key size increment in bits.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t keySizeIncrementInBits() const = 0;
	};

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>used to access the functionality of MAC algorithms that need a nonce.</summary>
	///
	/// <remarks>This class provides access to MAC functions for a hash function.
	///
	/// This class is a referenced counted class that uses the underlying principles of COM objects
	/// to control the lifetime of the object.  It also supports the querying of interfaces using the
	/// techniques defined in COM.</remarks>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	class VEILCORE_API MAC2 : public MessageAuthenticationCode
	{
	public:
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets MAC length in bytes.</summary>
		///
		/// <returns>The MAC length in bytes.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t get_MacLengthInBytes() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets MAC length in bytes.</summary>
		///
		/// <param name="setTo">The mac length in bytes.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_MacLengthInBytes(size_t setTo) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the nonce.</summary>
		///
		/// <returns>The nonce.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_Nonce() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets a nonce.</summary>
		///
		/// <param name="setTo">The nonce value.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_Nonce(const tsCryptoData &setTo) = 0;
	};

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>This interface defines the functionality of the CCM and GMAC/GCM modes of operation
	/// for the AES algorithm.</summary>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	class VEILCORE_API CCM_GCM
	{
	public:

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Initializes the CCM or GCM operation.</summary>
		///
		/// <param name="key">The key to use.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool initialize(const tsCryptoData &key) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Terminates the operation and frees/clears all of the internal state (including the
		/// key information).</summary>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool finish() = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Compute the authentication tag and encrypt the message in one function call</summary>
		///
		/// <remarks>This function is used to create the authentication tag and encrypt the message in one
		/// function call. Internally this function is the equivalent of <see cref="startMessage"/>, <see cref="authenticateHeader"/>,
		/// <see cref="encrypt"/> and <see cref="computeTag"/>.</v>
		///
		/// <param name="nonce">			The nonce.</param>
		/// <param name="header">			The header.</param>
		/// <param name="data">				[in,out] The data.</param>
		/// <param name="requiredTagLength">Length of the required tag.</param>
		/// <param name="tag">				[in,out] The tag.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool encryptMessage(const tsCryptoData &nonce, const tsCryptoData &header, tsCryptoData &data, size_t requiredTagLength, tsCryptoData &tag) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Validate the authentication tag and decrypt the message in one function call.</summary>
		///
		/// <remarks>This function is used to validate the authentication tag and decrypt the message in one
		/// function call. Internally this function is the equivalent of
		/// <see cref="startMessage"/>, <see cref="authenticateHeader"/>, <see cref="decrypt"/>,
		/// <see cref="computeTag"/> and compare the tag with the stored tag.</remarks>
		///
		/// <param name="nonce"> The nonce.</param>
		/// <param name="header">The header.</param>
		/// <param name="data">  [in,out] The data.</param>
		/// <param name="tag">   The tag.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool decryptMessage(const tsCryptoData &nonce, const tsCryptoData &header, tsCryptoData &data, const tsCryptoData &tag) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Start the encryption/decryption process</summary>
		///
		/// <remarks>This function is used to begin the process of encrypting or decrypting a message using the
		/// multipart function calls:
		/// - <see cref="startMessage"/>
		/// - <see cref="authenticateHeader"/>
		/// - <see cref="encrypt"/> or <see cref="decrypt"/>
		/// - <see cref="computeTag"/>.</remarks>
		///
		/// <param name="nonce">		The nonce.</param>
		/// <param name="headerLength"> Length of the header.</param>
		/// <param name="messageLength">Length of the message.</param>
		/// <param name="tagLength">	Length of the tag.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool startMessage(const tsCryptoData &nonce, uint64_t headerLength, uint64_t messageLength, size_t tagLength) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Processes the header of the message.</summary>
		///
		/// <param name="header">The header.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool authenticateHeader(const tsCryptoData &header) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Encrypts the message data and returns it in data. This function may be called
		/// multiple times.</summary>
		///
		/// <param name="data">[in,out] The data.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool encrypt(tsCryptoData &data) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Decrypts the message data and returns it in data. This function may be called
		/// multiple times.</summary>
		///
		/// <param name="data">[in,out] The data.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool decrypt(tsCryptoData &data) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Calculates the authentication tag based on the key and processed data.</summary>
		///
		/// <param name="requiredTagLength">Length of the required tag.</param>
		/// <param name="tag">				[out] The tag.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool computeTag(size_t requiredTagLength, tsCryptoData &tag) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the minimum key size in bits.</summary>
		///
		/// <returns>the minimum key size in bits.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t minimumKeySizeInBits() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the maximum key size in bits.</summary>
		///
		/// <returns>the maximum key size in bits.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t maximumKeySizeInBits() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the key size increment in bits.</summary>
		///
		/// <returns>the key size increment in bits.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t keySizeIncrementInBits() const = 0;
	};

	typedef enum Kdf_feedbackCounterLocation { Kdf_NoCounter, Kdf_BeforeIter, Kdf_AfterIter, Kdf_AfterFixed } Kdf_feedbackCounterLocation;

	/// <summary>This interface defines the functionality for the Key Derivation functions.</summary>
	class VEILCORE_API KeyDerivationFunction
	{
	public:
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Initializes this object.</summary>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool initialize() = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Initializes the with key.</summary>
		///
		/// <param name="key">The key.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool initializeWithKey(const tsCryptoData &key) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Derive a key based on x9.63 in counter mode</summary>
		///
		/// <param name="Z">			  The shared secret.</param>
		/// <param name="otherInfo">	  Other information related to this key derivation.</param>
		/// <param name="outputBitLength">Length in bits of the output.</param>
		/// <param name="output">		  [in,out] The output.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool Derive_X9_63_Counter(const tsCryptoData &Z, const tsCryptoData &otherInfo, size_t outputBitLength, tsCryptoData &output) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Derive a key based on NIST SP800-108 in counter mode</summary>
		///
		/// <param name="containsBitLength">true to include the bit length in the source data.</param>
		/// <param name="bytesOfBitLength"> Number of the bytes to store the bit size.</param>
		/// <param name="containsLabel">	true - contains a label.</param>
		/// <param name="counterLocation">	The starting offset for the counter (0 for beginning of data, -1 or larger than data size for the end of the data).</param>
		/// <param name="counterByteLength">Length in bytes of the counter.</param>
		/// <param name="Label">			The label.</param>
		/// <param name="Context">			The context.</param>
		/// <param name="outputBitLength">  Length of the output key in bits.</param>
		/// <param name="output">			[in,out] The output key.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool Derive_SP800_108_Counter(bool containsBitLength, size_t bytesOfBitLength, bool containsLabel, int32_t counterLocation, size_t counterByteLength, const tsCryptoData &Label, const tsCryptoData &Context, size_t outputBitLength, tsCryptoData &output) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Derive a key based on NIST SP800-108 in feedback mode</summary>
		///
		/// <param name="includeCounter"> true to include, false to exclude the counter.</param>
		/// <param name="feedbackIV">	  The feedback iv.</param>
		/// <param name="Label">		  The label.</param>
		/// <param name="Context">		  The context.</param>
		/// <param name="outputBitLength">Length of the output key in bits.</param>
		/// <param name="output">		  [in,out] The output key.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool Derive_SP800_108_Feedback(Kdf_feedbackCounterLocation counterLocation, uint32_t counterByteLength, bool containsBitLength, uint32_t bytesOfBitLength, bool containsLabel, const tsCryptoData &feedbackIV, const tsCryptoStringBase &Label, const tsCryptoData &Context, size_t outputBitLength, tsCryptoData &output) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Derive a key using the NIST SP800-56A standard in counter mode.</summary>
		///
		/// <param name="Z">			  The shared secret.</param>
		/// <param name="otherInfo">	  Other information related to the key derivation.</param>
		/// <param name="outputBitLength">Length of the output key in bits.</param>
		/// <param name="output">		  [in,out] The output key.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool Derive_SP800_56A_Counter(const tsCryptoData &Z, const tsCryptoData &otherInfo, size_t outputBitLength, tsCryptoData &output) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Derive a key using the NIST SP800-56A standard in feedback mode.</summary>
		///
		/// <param name="includeCounter"> true to include, false to exclude the counter.</param>
		/// <param name="feedbackIV">	  The feedback iv.</param>
		/// <param name="Z">			  The shared secret.</param>
		/// <param name="otherInfo">	  Other information related to the key derivation.</param>
		/// <param name="outputBitLength">Length of the output key in bits.</param>
		/// <param name="output">		  [in,out] The output key.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool Derive_SP800_56A_Feedback(bool includeCounter, const tsCryptoData &feedbackIV, const tsCryptoData &Z, const tsCryptoData &otherInfo, size_t outputBitLength, tsCryptoData &output) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Derive a key using the algorithm in GlobalPlatform SCP03</summary>
		///
		/// <param name="type">			  The key type to create</param>
		/// <param name="outputBitLength">Length of the output key in bits.</param>
		/// <param name="Context">		  The context.</param>
		/// <param name="output">		  [in,out] The output key.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool Derive_SCP03(uint8_t type, size_t outputBitLength, const tsCryptoData &Context, tsCryptoData &output) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>The internal routine that actually performs the derivation.  This function is called
		/// by the other derivation functions.</summary>
		///
		/// <param name="includeCounter">  true to include, false to exclude the counter.</param>
		/// <param name="useFeedback">	   true to use feedback.</param>
		/// <param name="feedbackIV">	   The feedback iv.</param>
		/// <param name="Context">		   The context.</param>
		/// <param name="counterLength">   Length of the counter in bytes.</param>
		/// <param name="counterStart">	   The counter start.</param>
		/// <param name="feedbackPosition">The feedback position.</param>
		/// <param name="outputBitLength"> Length of the output key in bits.</param>
		/// <param name="output">		   [in,out] The output key.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool Derive_Raw(bool includeCounter, bool useFeedback, const tsCryptoData &feedbackIV, const tsCryptoData &Context, size_t counterLength, size_t counterStart, size_t feedbackPosition, size_t outputBitLength, tsCryptoData &output) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Finalizes this object.</summary>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool finish() = 0;
		virtual size_t GetBlockSize() = 0;
		virtual size_t GetDigestSize() = 0;
	};

	/// <summary>Defines an interface for Key Transport</summary>
	class VEILCORE_API KeyTransport
	{
	public:
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Initializes this object with a symmetric key.</summary>
		///
		/// <param name="key">The key.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool initializeWithSymmetricKey(const tsCryptoData &key) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Wrap a key</summary>
		///
		/// <param name="inputData"> The key to wrap.</param>
		/// <param name="pad">		 The pad.</param>
		/// <param name="outputData">[in,out] The wrapped ke.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool Wrap(const tsCryptoData &inputData, const tsCryptoData &pad, tsCryptoData &outputData) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Unwrap a key</summary>
		///
		/// <param name="inputData"> The wrapped key.</param>
		/// <param name="pad">		 The pad.</param>
		/// <param name="outputData">[in,out] The unwrapped key.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool Unwrap(const tsCryptoData &inputData, const tsCryptoData &pad, tsCryptoData &outputData) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Determine if we can wrap the specified key.</summary>
		///
		/// <param name="keyToWrap">The key to wrap.</param>
		///
		/// <returns>true if we can wrap, false if not.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool CanWrap(const tsCryptoData &keyToWrap) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Determine if we can unwrap the specified wrapped key.</summary>
		///
		/// <param name="keyToUnwrap">The key to unwrap.</param>
		///
		/// <returns>true if we can unwrap, false if not.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool CanUnwrap(const tsCryptoData &keyToUnwrap) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the minimum key size in bits.</summary>
		///
		/// <returns>the minimum key size in bits.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t minimumKeySizeInBits() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the maximum key size in bits.</summary>
		///
		/// <returns>the maximum key size in bits.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t maximumKeySizeInBits() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the key size increment in bits.</summary>
		///
		/// <returns>the key size increment in bits.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t keySizeIncrementInBits() const = 0;
	};

	/// <summary>This interface defines the basic functionality for all asymmetric keys.</summary>
	class VEILCORE_API AsymmetricKey
	{
	public:
		/// <summary>Clears this object to its blank/initial state.</summary>
		virtual void Clear() = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the key size.</summary>
		///
		/// <returns>The key size in bits.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t KeySize() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Query if this object has a public key loaded.</summary>
		///
		/// <returns>true if public key loaded, false if not.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool IsPublicLoaded() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Query if this object has a private key loaded.</summary>
		///
		/// <returns>true if private key loaded, false if not.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool IsPrivateLoaded() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Query if the public key is verified.</summary>
		///
		/// <returns>true if public key is verified, false if not.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool IsPublicVerified() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Query if the private key is verified.</summary>
		///
		/// <returns>true if private key is verified, false if not.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool IsPrivateVerified() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Query if this object has a public key.</summary>
		///
		/// <returns>true if public key exists, false if not.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool HasPublicKey() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Query if this object has a private key.</summary>
		///
		/// <returns>true if private key exists, false if not.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool HasPrivateKey() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>validates the keys loaded in this object</summary>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool ValidateKeys() = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Compares the parameters of this object and 'secondKey' to see if they can be used
		/// together.</summary>
		///
		/// <param name="secondKey">[in] the second key to compare.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool KeysAreCompatible(std::shared_ptr<AsymmetricKey> secondKey) const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Generates a key pair based on the parameters stored in this object.</summary>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool generateKeyPair(bool forSignature = false) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Determine if we can compute a shared secret with the keys in this object.</summary>
		///
		/// <returns>true if we can compute z coordinate, false if not.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool CanComputeZ() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Calculates the shared secret.</summary>
		///
		/// <param name="secondKey">[in] the second key.</param>
		/// <param name="Z">		[out] The destination of the shared secret.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool ComputeZ(std::shared_ptr<AsymmetricKey> secondKey, tsCryptoData &Z) const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Returns the validation failure reason.</summary>
		///
		/// <returns>the validation failure reason.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual ValidationFailureType ValidationFailureReason() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Encodes the keys in this object and returns it.</summary>
		///
		/// <returns>The encoded blob that holds the contents of the keys in this object.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData toByteArray() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Initializes this object from the blob in the byte array.</summary>
		///
		/// <param name="data">The encoded key material.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool fromByteArray(const tsCryptoData &data) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the minimum key size in bits.</summary>
		///
		/// <returns>the minimum key size in bits.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t minimumKeySizeInBits() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the maximum key size in bits.</summary>
		///
		/// <returns>the maximum key size in bits.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t maximumKeySizeInBits() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the key size increment in bits.</summary>
		///
		/// <returns>the key size increment in bits.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t keySizeIncrementInBits() const = 0;
		virtual std::shared_ptr<AsymmetricKey> generateNewKeyPair(bool forSignature = false) const = 0;
		virtual bool signatureKey() const = 0;
		virtual bool encryptionKey() const = 0;
		virtual bool prehashSignatures() const = 0;
		virtual void set_signatureKey(bool setTo) = 0;
		virtual void set_encryptionKey(bool setTo) = 0;
	};

	/// <summary>Provides the functionality for Elliptic Curve key pairs.</summary>
	class VEILCORE_API EccKey : public AsymmetricKey
	{
	public:
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the name of the elliptic curve.</summary>
		///
		/// <returns>The elliptic curve name.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoString get_curveName() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the private key value.</summary>
		///
		/// <returns>The private key value.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_PrivateValue() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the private key value.</summary>
		///
		/// <param name="data">The private key value (big endian).</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_PrivateValue(const tsCryptoData &data) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the public x coordinate.</summary>
		///
		/// <returns>The public x coordinate.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_PublicX() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the public y coordinate.</summary>
		///
		/// <returns>The public y coordinate.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_PublicY() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the public key as an uncompressed point.</summary>
		///
		/// <returns>The point.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_Point() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the public key as an uncompressed point.</summary>
		///
		/// <param name="data">the public key as an uncompressed point.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_Point(const tsCryptoData &data) = 0;
	};

	/// <summary>Defines cryptographic primitives for Elliptic Curve and Diffie-Hellman</summary>
	class VEILCORE_API DhEccPrimitives
	{
	public:
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sign using data.</summary>
		///
		/// <param name="data">The data (hash) to sign.</param>
		/// <param name="r">   [out] The r component of the signature.</param>
		/// <param name="s">   [out] The s component of the signature.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool SignUsingData(const tsCryptoData &data, tsCryptoData &r, tsCryptoData &s) const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Verify signature for data.</summary>
		///
		/// <param name="data">The data (hash) to verify.</param>
		/// <param name="r">   The const tsCryptoData &amp; to process.</param>
		/// <param name="s">   The const tsCryptoData &amp; to process.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool VerifySignatureForData(const tsCryptoData &data, const tsCryptoData &r, const tsCryptoData &s) const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Compute the shared secret</summary>
		///
		/// <param name="publicPointOrKey">The public key.</param>
		/// <param name="Z">			   [out] The destination for the shared secret.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool DH(const tsCryptoData &publicPointOrKey, tsCryptoData &Z) const = 0;
	};

	/// <summary>Performs signature creation and verification</summary>
	class VEILCORE_API Signer
	{
	public:
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Initializes this object.</summary>
		///
		/// <param name="key">[in,out] The key to use in the signature creation/verification (public for
		/// verification and private for signature)</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool initialize(std::shared_ptr<AsymmetricKey> key) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sign the supplied hash</summary>
		///
		/// <param name="hashData"> The hash to sign.</param>
		/// <param name="signature">[in,out] The signature.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool signHash(const tsCryptoData &hashData, tsCryptoData &signature) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Incrementally hash data to hash for the <see cref="sign"/>/<see cref="verify"/> operation</summary>
		///
		/// <param name="data">The data to hash.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool update(const tsCryptoData &data) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Finalizes the hash from the calls to <see cref="update"/> and then signs the hash.</summary>
		///
		/// <param name="signature">[in,out] The signature.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool sign(tsCryptoData &signature) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Verifies a signature based on the hash supplied</summary>
		///
		/// <param name="hashData"> The hash to verify.</param>
		/// <param name="signature">The signature to verify.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool verifyHash(const tsCryptoData &hashData, const tsCryptoData &signature) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Finalizes the hash from the calls to <see cref="update"/> and then verifies the hash.</summary>
		///
		/// <param name="signature">[in] The signature.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool verify(const tsCryptoData &signature) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Finalizes this object.</summary>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool finish() = 0;
		virtual size_t GetHashBlockSize() = 0;
		virtual size_t GetHashDigestSize() = 0;
	};

	/// <summary>Declares the Password Based Key Derivation interface.</summary>
	class VEILCORE_API PbKdf
	{
	public:
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Pkcs 5 pbkdf 2.</summary>
		///
		/// <param name="hmacName">	   Name of the hmac algorithm.</param>
		/// <param name="password">	   The password.</param>
		/// <param name="salt">		   The salt.</param>
		/// <param name="counter">	   The counter.</param>
		/// <param name="key">		   [out] The key.</param>
		/// <param name="keyLenNeeded">The key length needed in bytes.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool PKCS5_PBKDF2(const tsCryptoStringBase &hmacName, const tsCryptoData &password, const tsCryptoData &salt, size_t counter, tsCryptoData &key, size_t keyLenNeeded) const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Pkcs 5 pbkdf 2 with MAC.</summary>
		///
		/// <param name="hmacName">	   Name of the hmac algorithm.</param>
		/// <param name="password">	   The password.</param>
		/// <param name="salt">		   The salt.</param>
		/// <param name="counter">	   The counter.</param>
		/// <param name="key">		   [out] The key.</param>
		/// <param name="keyLenNeeded">The key length needed in bytes.</param>
		/// <param name="mac">		   [out] The MAC.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool PKCS5_PBKDF2_With_Mac(const tsCryptoStringBase &hmacName, const tsCryptoData &password, const tsCryptoData &salt, size_t counter, tsCryptoData &key, size_t keyLenNeeded, tsCryptoData &mac) const = 0;
		/// <summary>
		/// PKCS12s the PBKDF_ ASCII.
		/// </summary>
		/// <param name="hashAlg">The hash alg.</param>
		/// <param name="password">The password.</param>
		/// <param name="id">The diversification ID (1 - Key, 2 - IV, 3 - Mac Key).</param>
		/// <param name="salt">The salt.</param>
		/// <param name="iter">The iteration count.</param>
		/// <param name="outputLengthInBits">The output length in bits.</param>
		/// <param name="Key">The key.</param>
		/// <returns>success if true.</returns>
		virtual bool Pkcs12Pbkdf_Ascii(const tsCryptoStringBase& hashAlg, const tsCryptoStringBase& password, uint8_t id, const tsCryptoData& salt, size_t iter, size_t outputLengthInBits, tsCryptoData& Key) const = 0;
		/// <summary>
		/// Computes a key from a password in a manner compatible with PEM files.
		/// </summary>
		/// <param name="hashName">Name of the hash.</param>
		/// <param name="password">The password.</param>
		/// <param name="iv">The iv.</param>
		/// <param name="keyLenInBytes">The key length in bytes.</param>
		/// <param name="Key">The key.</param>
		/// <returns>true for Success.</returns>
		virtual bool PBKDF1(const tsCryptoStringBase& hashName, const tsCryptoStringBase & password, const tsCryptoData & iv, int keyLenInBytes, tsCryptoData& Key) const = 0;
	};

	/// <summary>Computes the server authentication blob.</summary>
	class VEILCORE_API ServerAuthenticationCalculator
	{
	public:
		virtual bool computeServerAuthenticationParameters(const tsCryptoData& authInfo, tsCryptoData& authenticationParameters, tsCryptoData& storedKey) = 0;
		virtual bool validateServerAuthenticationParameters(const tsCryptoData& authInfo, const tsCryptoData& authenticationParameters, const tsCryptoData& storedKey) = 0;
	};


	class VEILCORE_API authenticationResponderKeyHandler
	{
	public:
		virtual bool keyServer() = 0;
		virtual tsCryptoData getKey(const tsCryptoData& keyId) = 0;
		virtual tsCryptoData computeZ(const tsCryptoData& keyId, const tsCryptoData& ephemeralPublic) = 0;
		// Added 7.0.41
		virtual tsCryptoString getKeyType(const tsCryptoData& keyId) = 0;
	};

	/// <summary>Computes the responder authentication.</summary>
	class VEILCORE_API AuthenticationResponder
	{
	public:
		virtual bool computeResponderValues(const tsCryptoData& responderParameters, const tsCryptoData& storedKey, authenticationResponderKeyHandler* keyAccess, tsCryptoData& responderMITMProof, tsCryptoData& sessionKey) = 0;
	};

	/// <summary>Computes the client authentication blob.</summary>
	class VEILCORE_API AuthenticationInitiator
	{
	public:
		virtual bool computeInitiatorValues(const tsCryptoData& initiatorParameters, const tsCryptoData& authenticationInformation, tsCryptoData& responderParameters, tsCryptoData& responderMITMProof, tsCryptoData& sessionKey) = 0;
		virtual bool testInitiatorValues(const tsCryptoData& initiatorParameters, const tsCryptoData& authenticationInformation, const tsCryptoData& KGK, const tsCryptoData& ephPriv,
			const tsCryptoData& ephPub, const tsCryptoData& responderParameters, const tsCryptoData& responderMITMProof, const tsCryptoData& sessionKey) = 0;
	};

	class VEILCORE_API authenticationInitiatorTunnelKeyHandler
	{
	public:
		virtual tsCryptoData getAuthenticationInformation(const tsCryptoData& serverRequirements) = 0;
	};

	class VEILCORE_API authenticationControlDataCommunications
	{
	public:
		virtual bool sendControlData(const tsCryptoData& dest) = 0;
		virtual void stateChanged(bool isActive, uint32_t currentState) = 0;
		virtual void failed(const char *message) = 0;
		virtual void loggedOut() = 0;
		virtual void setCloseAfterTransmit() = 0;
		virtual bool shouldCloseAfterTransmit() = 0;
		virtual bool sendReceivedData(const tsCryptoData& dest) = 0;
	};

	/// <summary>Implements the initiator end of a CKM based tunnel using CkmAuth as the key negotiation.</summary>
	class VEILCORE_API IClientTunnel
	{
	public:
		virtual ~IClientTunnel()
		{
		}
		virtual bool GetMessageAuthBitSize(int &pVal) = 0;
		virtual bool GetMessageAuth(tsCryptoData& pVal) = 0;
		virtual bool TunnelActive() = 0;
		virtual bool StartTunnel(const char* username, authenticationInitiatorTunnelKeyHandler* authHandler, authenticationControlDataCommunications* ctrlChannel) = 0;
		virtual bool StopTunnel() = 0;
		virtual bool Logout() = 0;
		virtual bool ReceiveData(const tsCryptoData& src) = 0;
		virtual bool SendData(const tsCryptoData& src) = 0;
		virtual bool GetMessageEncryptionAlg(tscrypto::_POD_AlgorithmIdentifier& alg) = 0;
		virtual bool GetMessageHashAlg(tscrypto::_POD_AlgorithmIdentifier& alg) = 0;
		virtual bool SetOnPacketRecievedCallback(std::function<void(uint8_t packetType, const uint8_t* data, uint32_t dataLen)> func) = 0;
		virtual bool SetOnPacketSentCallback(std::function<void(uint8_t packetType, const uint8_t* data, uint32_t dataLen)> func) = 0;
		virtual bool useCompression() = 0;
		virtual void useCompression(bool setTo) = 0;
	};

	/// <summary>This interface defines the operations for an RSA key pair.</summary>
	class VEILCORE_API RsaKey : public AsymmetricKey
	{
	public:
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the public modulus.</summary>
		///
		/// <returns>The public modulus.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_PublicModulus() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the public modulus.</summary>
		///
		/// <param name="data">The data.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_PublicModulus(const tsCryptoData &data) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the public exponent.</summary>
		///
		/// <returns>The public exponent.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_Exponent() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the public exponent.</summary>
		///
		/// <param name="data">The public exponent.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_Exponent(const tsCryptoData &data) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the private exponent.</summary>
		///
		/// <returns>The private exponent.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_PrivateExponent() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the private exponent.</summary>
		///
		/// <param name="data">The private exponent.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_PrivateExponent(const tsCryptoData &data) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the first prime p.</summary>
		///
		/// <returns>The prime p.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_p() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the first prime p.</summary>
		///
		/// <param name="data">The prime p.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_p(const tsCryptoData &data) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the second prime q.</summary>
		///
		/// <returns>The prime q.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_q() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the second prime q.</summary>
		///
		/// <param name="data">The prime q.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_q(const tsCryptoData &data) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets coefficient 1 (d mod p)</summary>
		///
		/// <returns>Coefficient 1.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_dp() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets coefficient 1</summary>
		///
		/// <param name="data">Coefficient 1.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_dp(const tsCryptoData &data) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets coefficient 2 (d mod q)</summary>
		///
		/// <returns>Coefficient 2.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_dq() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets coefficient 2</summary>
		///
		/// <param name="data">Coefficient 2.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_dq(const tsCryptoData &data) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the inverse of q component of the RSA private key (CRT form)</summary>
		///
		/// <returns>The inverse of q.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_qInv() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the inverse of q.</summary>
		///
		/// <param name="data">The inverse of q.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_qInv(const tsCryptoData &data) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Generates an RSA key pair using the specified prime generation and hash.</summary>
		///
		/// <param name="primeType">	  Type of the prime to generate.</param>
		/// <param name="hashName">		  Name of the hash.</param>
		/// <param name="keyLengthInBits">The key length in bits.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool generateKeyPair(RSA_Key_Gen_Type primeType, const tsCryptoStringBase &hashName, size_t keyLengthInBits, bool forSignature = false) = 0;
		virtual bool reserved1() = 0;
		virtual bool reserved2() = 0;
		virtual bool reserved3() = 0;

	private:
		using AsymmetricKey::generateKeyPair;
	};

	/// <summary>The interface that provides access to the RSA Key Generation parameters</summary>
	class VEILCORE_API RsaKeyGenerationParameters : public RsaKey
	{
	public:
		// B.3.2

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the seed.</summary>
		///
		/// <returns>The seed.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_Seed() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the seed.</summary>
		///
		/// <param name="data">The seed.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_Seed(const tsCryptoData &data) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets p1.</summary>
		///
		/// <returns>p1.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_p1() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets p1.</summary>
		///
		/// <param name="data">p1.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_p1(const tsCryptoData &data) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets p2.</summary>
		///
		/// <returns>p2.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_p2() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets p2.</summary>
		///
		/// <param name="data">p2.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_p2(const tsCryptoData &data) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets q1.</summary>
		///
		/// <returns>q1.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_q1() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets q1.</summary>
		///
		/// <param name="data">q1.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_q1(const tsCryptoData &data) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets q2.</summary>
		///
		/// <returns>q2.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_q2() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets q2.</summary>
		///
		/// <param name="data">q2.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_q2(const tsCryptoData &data) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets Xp.</summary>
		///
		/// <returns>Xp.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_Xp() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets Xp.</summary>
		///
		/// <param name="data">Xp.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_Xp(const tsCryptoData &data) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets Xq.</summary>
		///
		/// <returns>Xq.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_Xq() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets Xq.</summary>
		///
		/// <param name="data">Xq.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_Xq(const tsCryptoData &data) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets Xp1.</summary>
		///
		/// <returns>Xp1.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_Xp1() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets Xp1.</summary>
		///
		/// <param name="data">Xp1.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_Xp1(const tsCryptoData &data) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets Xp2.</summary>
		///
		/// <returns>Xp2.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_Xp2() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets Xp2.</summary>
		///
		/// <param name="data">Xp2.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_Xp2(const tsCryptoData &data) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets Xq1.</summary>
		///
		/// <returns>Xq1.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_Xq1() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets Xq1.</summary>
		///
		/// <param name="data">Xq1.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_Xq1(const tsCryptoData &data) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets Xq2.</summary>
		///
		/// <returns>Xq2.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_Xq2() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets Xq2.</summary>
		///
		/// <param name="data">Xq2.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_Xq2(const tsCryptoData &data) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets bit length 1.</summary>
		///
		/// <returns>bit length 1.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t get_bitlength1() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets bit length 1.</summary>
		///
		/// <param name="data">bit length 1.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_bitlength1(size_t setTo) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets bit length 2.</summary>
		///
		/// <returns>bit length 2.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t get_bitlength2() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets bit length 2.</summary>
		///
		/// <param name="data">bit length 2.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_bitlength2(size_t setTo) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets bit length 3.</summary>
		///
		/// <returns>bit length 3.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t get_bitlength3() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets bit length 3.</summary>
		///
		/// <param name="data">bit length 3.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_bitlength3(size_t setTo) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets bit length 4.</summary>
		///
		/// <returns>bit length 4.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t get_bitlength4() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets bit length 4.</summary>
		///
		/// <param name="data">bit length 4.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_bitlength4(size_t setTo) = 0;
	};

	/// <summary>Provides access to the encryption and decryption primitives for RSA</summary>
	class VEILCORE_API RsaPrimitives
	{
	public:
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Encryption primitive.</summary>
		///
		/// <param name="inputData"> The padded data to encrypt.</param>
		/// <param name="outputData">[out] The encrypted data.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool EncryptPrimitive(const tsCryptoData &inputData, tsCryptoData &outputData) const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Decryption primitive.</summary>
		///
		/// <param name="inputData"> Then encrypted data.</param>
		/// <param name="outputData">[out] The decrypted data including padding.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool DecryptPrimitive(const tsCryptoData &inputData, tsCryptoData &outputData) const = 0;
	};

	/// <summary>Holds a Diffie-Hellman parameter set</summary>
	/// <remarks>Set Seed, Counter, Prime, Subprime, Generator for parameter validations.</remarks>
	class VEILCORE_API DhParameters
	{
	public:
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the prime.</summary>
		///
		/// <returns>The prime.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_prime() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the prime.</summary>
		///
		/// <param name="setTo">The prime.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_prime(const tsCryptoData &setTo) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the subprime.</summary>
		///
		/// <returns>The subprime.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_subprime() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the subprime.</summary>
		///
		/// <param name="setTo">The subprime.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_subprime(const tsCryptoData &setTo) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the generator.</summary>
		///
		/// <returns>The generator.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_generator() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the generator.</summary>
		///
		/// <param name="setTo">The generator.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_generator(const tsCryptoData &setTo) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the first seed.</summary>
		///
		/// <returns>The first seed.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_firstSeed() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the first seed.</summary>
		///
		/// <param name="setTo">The first seed.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_firstSeed(const tsCryptoData &setTo) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the p seed.</summary>
		///
		/// <returns>The p seed.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_pSeed() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the p seed.</summary>
		///
		/// <param name="setTo">The p seed.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_pSeed(const tsCryptoData &setTo) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets q seed.</summary>
		///
		/// <returns>The q seed.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_qSeed() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the q seed.</summary>
		///
		/// <param name="setTo">The q seed.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_qSeed(const tsCryptoData &setTo) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the generator factor.</summary>
		///
		/// <returns>The generator factor.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_generatorFactor() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the generator factor.</summary>
		///
		/// <param name="setTo">The generator factor.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_generatorFactor(const tsCryptoData &setTo) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the p generation counter.</summary>
		///
		/// <returns>The p generation counter.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t get_pgen_counter() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the p generation counter.</summary>
		///
		/// <param name="setTo">The p generation counter.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_pgen_counter(size_t setTo) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the q generation counter.</summary>
		///
		/// <returns>The q generation counter.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t get_qgen_counter() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the q generation counter.</summary>
		///
		/// <param name="setTo">The q generation counter.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_qgen_counter(size_t setTo) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Generates the probable prime parameters.</summary>
		///
		/// <param name="hashAlgName">		Name of the hash algorithm.</param>
		/// <param name="primeBitLength">   Length of the prime in bits.</param>
		/// <param name="subprimeBitLength">Length of the subprime in bits.</param>
		/// <param name="seedLen">			Length of the seed in bytes.</param>
		/// <param name="optionalFirstSeed">The optional first seed.</param>
		/// <param name="index">			Zero-based index of the generator.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool generateProbablePrimeParameters(const tsCryptoStringBase &hashAlgName, size_t primeBitLength, size_t subprimeBitLength, size_t seedLen, const tsCryptoData &optionalFirstSeed, uint8_t index) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Generates the provable prime parameters.</summary>
		///
		/// <param name="hashAlgName">		Name of the hash algorithm.</param>
		/// <param name="primeBitLength">   Length of the prime in bits.</param>
		/// <param name="subprimeBitLength">Length of the subprime in bits.</param>
		/// <param name="seedLen">			Length of the seed in bytes.</param>
		/// <param name="optionalFirstSeed">The optional first seed.</param>
		/// <param name="index">			Zero-based index of the generator.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool generateProvablePrimeParameters(const tsCryptoStringBase &hashAlgName, size_t primeBitLength, size_t subprimeBitLength, size_t seedLen, const tsCryptoData &optionalFirstSeed, uint8_t index) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Validate parameters and generator.</summary>
		///
		/// <param name="hashAlgName">		  Name of the hash algorithm.</param>
		/// <param name="primeType">		  Type of the prime generation used.</param>
		/// <param name="verifiableGenerator">true to verify the generator.</param>
		/// <param name="index">			  Zero-based index of the generator.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool validateParametersAndGenerator(const tsCryptoStringBase &hashAlgName, DH_Param_Gen_Type primeType, bool verifiableGenerator, uint8_t index) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Validate parameters.</summary>
		///
		/// <param name="hashAlgName">Name of the hash algorithm.</param>
		/// <param name="primeType">  Type of the prime generator.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool validateParameters(const tsCryptoStringBase &hashAlgName, DH_Param_Gen_Type primeType) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Validate the generator.</summary>
		///
		/// <param name="hashAlgName">		  Name of the hash algorithm.</param>
		/// <param name="verifiableGenerator">true if this is a verifiable generator.</param>
		/// <param name="index">			  Zero-based index of the generator.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool validateGenerator(const tsCryptoStringBase &hashAlgName, bool verifiableGenerator, uint8_t index) = 0;
		/// <summary>Clears this object to its blank/initial state.</summary>
		virtual void Clear() = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the bit size of the parameter set.</summary>
		///
		/// <returns>the bit size of the parameter set.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t ParameterSize() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Determines if we have primes loaded.</summary>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool PrimesLoaded() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Determines if we have the generator loaded.</summary>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool GeneratorLoaded() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Determines if the primes are verified.</summary>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool PrimesVerified() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Determines if the generator is verified.</summary>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool GeneratorVerified() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Compares the specified parameter set to this object to see if they are compatible for
		/// shared secret generation.</summary>
		///
		/// <param name="obj">The object to compare</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool ParametersAreCompatible(std::shared_ptr<DhParameters> obj) const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Calculates the generator.</summary>
		///
		/// <param name="hashAlgName">Name of the hash algorithm.</param>
		/// <param name="seed">		  The seed.</param>
		/// <param name="index">	  Zero-based index of the generator.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool computeGenerator(const tsCryptoStringBase &hashAlgName, const tsCryptoData &seed, uint8_t index) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Converts this object to a byte array.</summary>
		///
		/// <returns>This object as a tsCryptoData.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData toByteArray() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Populates this object from the given from byte array.</summary>
		///
		/// <param name="data">The byte array.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool fromByteArray(const tsCryptoData &data) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the minimum key size in bits.</summary>
		///
		/// <returns>the minimum key size in bits.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t minimumKeySizeInBits() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the maximum key size in bits.</summary>
		///
		/// <returns>the maximum key size in bits.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t maximumKeySizeInBits() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the key size increment in bits.</summary>
		///
		/// <returns>the key size increment in bits.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t keySizeIncrementInBits() const = 0;
		virtual std::shared_ptr<AsymmetricKey> generateKeyPair(bool forSignature = false) = 0;
	};

	/// <summary>Holds and provides functionality for Diffie-Hellman key pairs</summary>
	class VEILCORE_API DhKey : public AsymmetricKey
	{
	public:
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the domain parameter set.</summary>
		///
		/// <param name="obj">[out] The domain parameter set.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual std::shared_ptr<DhParameters> get_DomainParameters() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the domain parameter set.</summary>
		///
		/// <param name="setTo">[in] The domain parameter set.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_DomainParameters(std::shared_ptr<DhParameters> setTo) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the private key.</summary>
		///
		/// <returns>The private key (big endian).</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_PrivateKey() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the private key.</summary>
		///
		/// <param name="data">The private key (big endian).</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_PrivateKey(const tsCryptoData &data) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the public key.</summary>
		///
		/// <returns>The public key (big endian).</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_PublicKey() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the public key.</summary>
		///
		/// <param name="data">The public key (big endian).</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_PublicKey(const tsCryptoData &data) = 0;
	};

	/// <summary>Computes a prime that is only probably a prime (high assurance but no proof)</summary>
	class VEILCORE_API ProbablePrime
	{
	public:
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Generates a prime number.</summary>
		///
		/// <param name="bitLength">  Length of the prime in bits.</param>
		/// <param name="rounds">	  The number of rounds to perform when checking the prime.</param>
		/// <param name="strongPrime">true if a strong prime is required.</param>
		/// <param name="prime">	  [in,out] The prime.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool GeneratePrime(size_t bitLength, size_t rounds, bool strongPrime, tsCryptoData &prime) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Calculates the number of rounds needed.</summary>
		///
		/// <param name="forRSA">			true if primes for RSA key gen are needed.</param>
		/// <param name="primebitLength">   Length of the prime in bits.</param>
		/// <param name="subprimebitLength">Length of the subprime in bits.</param>
		/// <param name="use100Probability">true to use 100 probability.</param>
		/// <param name="subprimeRounds">   [in,out] The subprime rounds.</param>
		/// <param name="primeRounds">		[in,out] The prime rounds.</param>
		/// <param name="useStrong">		[in,out] The use strong.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool ComputeRounds(bool forRSA, size_t primebitLength, size_t subprimebitLength, bool use100Probability, size_t &subprimeRounds, size_t &primeRounds, bool &useStrong) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>C.2 or C.3. Checks if a number is composite (not prime)</summary>
		///
		/// <param name="rounds">	  The rounds.</param>
		/// <param name="strongPrime">true for strong prime checking.</param>
		/// <param name="candidate">  The candidate number (big endian).</param>
		///
		/// <returns>true if composite, false if not.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool IsComposite(size_t rounds, bool strongPrime, const tsCryptoData &candidate) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Query if the number is composite and not power of a prime.</summary>
		///
		/// <param name="rounds">	  The rounds.</param>
		/// <param name="strongPrime">true for strong prime checking.</param>
		/// <param name="candidate">  The candidate number (big endian).</param>
		///
		/// <returns>true if composite and not power of a prime, false if not.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool IsCompositeAndNotPowerOfAPrime(size_t rounds, bool strongPrime, const tsCryptoData &candidate) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Computes the next number that is a prime</summary>
		///
		/// <param name="rounds">	  The rounds.</param>
		/// <param name="strongPrime">true for strong prime checking.</param>
		/// <param name="value">	  [in,out] The number.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool NextPrime(size_t rounds, bool strongPrime, tsCryptoData &value) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>C.9. Computes a prime that is a composite of smaller primes and is only probably a
		/// prime (high assurance but no proof)</summary>
		///
		/// <param name="primeLengthInBits">The prime length in bits.</param>
		/// <param name="primeRounds">		The prime rounds.</param>
		/// <param name="r1">				The r1 factor.</param>
		/// <param name="r2">				The r2 factor.</param>
		/// <param name="exponent">			The exponent.</param>
		/// <param name="X">				[in,out] The X factor.</param>
		/// <param name="prime">			[out] The prime.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool ComputeCompositePrime(size_t primeLengthInBits, size_t primeRounds, const tsCryptoData &r1, const tsCryptoData &r2, const tsCryptoData &exponent, tsCryptoData &X, tsCryptoData &prime) = 0;
	};

	/// <summary>Computes a prime that is provably a prime</summary>
	class VEILCORE_API ProvablePrime
	{
	public:
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Generates a prime that is provably prime</summary>
		///
		/// <param name="bitLength">		Length of the prime in bits.</param>
		/// <param name="hashName">			Name of the hash.</param>
		/// <param name="seed">				[in,out] The seed.</param>
		/// <param name="prime">			[in,out] The prime.</param>
		/// <param name="prime_gen_counter">[in,out] The prime generation counter.</param>
		/// <param name="prime_seed">		[in,out] The prime seed.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool GeneratePrime(size_t bitLength, const tsCryptoStringBase &hashName, const tsCryptoData &seed, tsCryptoData &prime, size_t &prime_gen_counter, size_t strength, tsCryptoData &primeSeed) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>C.10. Construct a provably prime number using multiple smaller prime numbers</summary>
		///
		/// <param name="bitLength">  Length of the prime number in bits.</param>
		/// <param name="hashName">   Name of the hash.</param>
		/// <param name="p1BitLength">Length of the subprime p1 in bits.</param>
		/// <param name="p2BitLength">Length of the subprime p2 in bits.</param>
		/// <param name="firstSeed">  [in,out] The first seed.</param>
		/// <param name="exponent">   The exponent.</param>
		/// <param name="p1">		  [in,out] The subprime p1.</param>
		/// <param name="p2">		  [in,out] The subprime p2.</param>
		/// <param name="p">		  [in,out] The prime p.</param>
		/// <param name="pSeed">	  [in,out] The seed.</param>
		/// <param name="counter">	  [in,out] The counter.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool ConstructPrimeFromFactors(size_t bitLength, const tsCryptoStringBase &hashName, size_t p1BitLength, size_t p2BitLength, tsCryptoData &firstSeed, const tsCryptoData &exponent, tsCryptoData &p1, tsCryptoData &p2, tsCryptoData &p, tsCryptoData &pSeed, size_t &counter, size_t strength) = 0;
	};

	/// <summary>Encrypts and decrypts secret keys using PKCS 1 v 2.1 OAEP padding</summary>
	class VEILCORE_API RsaOAEP
	{
	public:
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Encrypt a secret key using OAEP</summary>
		///
		/// <param name="key">			  [in] The RSA key used to encrypt the data (public key).</param>
		/// <param name="keyData">		  The secret key to protect.</param>
		/// <param name="additionalInput">The AdditionalInfo field used in the encryption.</param>
		/// <param name="outputData">	  [out] The encrypted secret key.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool Generate(std::shared_ptr<RsaKey> key, const tsCryptoData &keyData, const tsCryptoData &additionalInput, tsCryptoData &outputData) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Decrypts a secret key using OAEP</summary>
		///
		/// <param name="key">			  [in] The RSA key used to decrypt the protected secret key (private key).</param>
		/// <param name="cipherData">	  The encrypted secret key.</param>
		/// <param name="additionalInput">The AdditionalInfo field used in the encryption.</param>
		/// <param name="keyData">		  [out] The decrypted secret key.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool Recover(std::shared_ptr<RsaKey> key, const tsCryptoData &cipherData, const tsCryptoData &additionalInput, tsCryptoData &keyData) = 0;
	};

}
#include "TSALG.h"

namespace tscrypto {
	class VEILCORE_API ISslCertSelector
	{
	public:
		virtual ~ISslCertSelector() {}
		virtual tsCryptoData GetServerCertForAlgorithm(SSL_CIPHER algorithm) = 0;
		virtual std::shared_ptr<tscrypto::ICryptoObject> GetPrivateKeyAlgorithmForCert(const tsCryptoData& cert) = 0;
		virtual tsCryptoData GetIssuerForCert(const tsCryptoData& cert) = 0;
	};

	class VEILCORE_API ISslHandshake_Client
	{
	public:
		virtual ~ISslHandshake_Client() {}
		virtual void RegisterCertificateVerifier(std::function<SSL_AlertDescription(const tsCryptoDataList& certificate, SSL_CIPHER cipher)> func) = 0;
		virtual void RegisterClientPSK(std::function<bool(const tsCryptoData& hint, tsCryptoData& identity, tsCryptoData& psk)> func) = 0;
		virtual void RegisterPasswordCallback(std::function<bool(tsCryptoData& password)> setTo) = 0;
		virtual void setCiphersSupported(SSL_CIPHER* list, size_t count) = 0;
	};

	class VEILCORE_API IAlgorithmList
	{
	public:
		virtual ~IAlgorithmList() {}
		virtual size_t count() const = 0;

		// Enumerator style
		virtual bool next() = 0;
		virtual bool restart() = 0;
		virtual TS_ALG_ID algId() const = 0;
		virtual tsCryptoString oid() const = 0;
		virtual tsCryptoString name() const = 0;
		virtual CryptoAlgType algFlags() const = 0;

		// Indexable style
		virtual TS_ALG_ID algId(size_t index) const = 0;
		virtual tsCryptoString oid(size_t index) const = 0;
		virtual tsCryptoString name(size_t index) const = 0;
		virtual CryptoAlgType algFlags(size_t index) const = 0;
	};

	class VEILCORE_API IAlgorithmListManager
	{
	public:
		virtual ~IAlgorithmListManager() {}

		virtual size_t size() const = 0;

		virtual TS_ALG_ID algId(size_t index) const = 0;
		virtual tsCryptoString oid(size_t index) const = 0;
		virtual tsCryptoString name(size_t index) const = 0;
		virtual CryptoAlgType algFlags(size_t index) const = 0;

		virtual std::shared_ptr<tscrypto::IAlgorithmList> GetAlgorithmList(CryptoAlgType flags, bool matchAllFlags) = 0;

		virtual TS_ALG_ID LookUpAlgID(const tsCryptoStringBase& algName) const = 0;
		virtual tsCryptoString LookUpAlgOID(const tsCryptoStringBase& algName) const = 0;
		virtual tsCryptoString OIDtoAlgName(const tsCryptoStringBase& oid) const = 0;
		virtual TS_ALG_ID OIDtoID(const tsCryptoStringBase& OID) const = 0;
		virtual tsCryptoString IDtoOID(TS_ALG_ID id) const = 0;
	};

	class VEILCORE_API IAlgorithmListManagerWriter : public IAlgorithmListManager
	{
	public:
		virtual ~IAlgorithmListManagerWriter() {}

		virtual void RemoveAlgorithmById(TS_ALG_ID algId) = 0;
		virtual void RemoveAlgorithmByOid(const tsCryptoStringBase& oid) = 0;
		virtual void RemoveAlgorithmByOid(const tsCryptoData& oid) = 0;
		virtual void RemoveAlgorithmByName(const tsCryptoStringBase& name) = 0;

		virtual bool AddAlgorithm(TS_ALG_ID algId, const tsCryptoStringBase& oid, const tsCryptoStringBase& name, CryptoAlgType algFlags) = 0;
	};

	VEILCORE_API void AddKeySizeFunction(std::function<bool(TS_ALG_ID AlgID, size_t& pVal)> fn);
	VEILCORE_API void AddAlg2ModeFunction(std::function<bool(TS_ALG_ID AlgID, SymmetricMode& pVal)> fn);
	VEILCORE_API void AddAlg2KeyTypeFunction(std::function<bool(TS_ALG_ID AlgID, KeyType& pVal)> fn);
	VEILCORE_API void AddBlockSizeFunction(std::function<bool(TS_ALG_ID AlgID, size_t& pVal)> fn);
	VEILCORE_API void AddIVECSizeFunction(std::function<bool(TS_ALG_ID AlgID, size_t& pVal)> fn);
	VEILCORE_API void AddSignNameFunction(std::function<tsCryptoString(TS_ALG_ID signAlgorithm)> fn);

	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// <summary>used to access the functionality of the Extended Output Functions (SHAKE128/SHAKE256)</summary>
	///
	/// <remarks>This class marks the hash as an Extended Output Function</remarks>
	////////////////////////////////////////////////////////////////////////////////////////////////////
	class VEILCORE_API XOF : public Hash
	{
	public:
	};

	/// <summary>Performs a Diffie-Hellman style key agreement (includes ECC).</summary>
	class VEILCORE_API KAS
	{
	public:
		/// <summary>Clears this object to its blank/initial state.</summary>
		virtual void clear() = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the name of the Key Derivation Function.</summary>
		///
		/// <returns>The kdf name.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoString get_KdfName() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the name of the Key Derivation Function.</summary>
		///
		/// <param name="name">The kdf name.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_KdfName(const tsCryptoStringBase &name) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the identifier for the party called U.</summary>
		///
		/// <returns>The ID for u.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_IDu() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the identifier for the party called U.</summary>
		///
		/// <param name="data">The ID for u.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_IDu(const tsCryptoData &data) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the identifier for the party called V.</summary>
		///
		/// <returns>The ID for v.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_IDv() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the identifier for the party called V.</summary>
		///
		/// <param name="data">The ID for v.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_IDv(const tsCryptoData &data) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the kc key length in bits.</summary>
		///
		/// <returns>The kc key length in bits.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t get_KcKeyLengthInBits() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the kc key length in bits.</summary>
		///
		/// <param name="setTo">The kc key length in bits.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_KcKeyLengthInBits(size_t setTo) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the kc algorithm name.</summary>
		///
		/// <returns>The kc algorithm name.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoString get_KcAlgorithmName() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the kc algorithm name.</summary>
		///
		/// <param name="name">The kc algorithm name.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_KcAlgorithmName(const tsCryptoStringBase &name) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the kc suffix for party U.</summary>
		///
		/// <returns>The kc suffix for party U.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_KcSuffixU() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the kc suffix for party U.</summary>
		///
		/// <param name="data">the kc suffix for party U.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_KcSuffixU(const tsCryptoData &data) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the kc suffix for party V</summary>
		///
		/// <returns>The kc suffix for party V.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_KcSuffixV() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the kc suffix for party V</summary>
		///
		/// <param name="data">The kc suffix for party V.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_KcSuffixV(const tsCryptoData &data) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the kc length in bits.</summary>
		///
		/// <returns>The kc length in bits.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t get_KcLengthInBits() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the kc length in bits.</summary>
		///
		/// <param name="setTo">The kc length in bits.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_KcLengthInBits(size_t setTo) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the prefix for the OtherInfo field</summary>
		///
		/// <returns>The prefix for the OtherInfo field.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_OtherInfoPrefix() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the prefix for the OtherInfo field</summary>
		///
		/// <param name="data">The prefix for the OtherInfo field.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_OtherInfoPrefix(const tsCryptoData &data) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the suffix for the OtherInfo field</summary>
		///
		/// <returns>The suffix for the OtherInfo field.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_OtherInfoSuffix() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the suffix for the OtherInfo field</summary>
		///
		/// <param name="data">The suffix for the OtherInfo field.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_OtherInfoSuffix(const tsCryptoData &data) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the nonce used for CCM.</summary>
		///
		/// <returns>The nonce used for CCM.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_CCMNonce() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the nonce used for CCM</summary>
		///
		/// <param name="data">The nonce used for CCM.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_CCMNonce(const tsCryptoData &data) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Computes a CCM nonce.</summary>
		///
		/// <param name="nonceBitLength">Length of the nonce in bits.</param>
		/// <param name="nonce">		 [in,out] The nonce.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool computeCCMNonce(size_t nonceBitLength, tsCryptoData &nonce) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the CCM tag length in bytes.</summary>
		///
		/// <returns>The CCM tag length in bytes.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t get_CCMTagLengthInBytes() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the CCM tag length in bytes.</summary>
		///
		/// <param name="setTo">The CCM tag length in bytes.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_CCMTagLengthInBytes(size_t setTo) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the nonce for party U.</summary>
		///
		/// <returns>The nonce for party U.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_NonceU() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the nonce for party U</summary>
		///
		/// <param name="data">The nonce for party U.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_NonceU(const tsCryptoData &data) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Computes a nonce for party U.</summary>
		///
		/// <param name="nonceBitLength">Length of the nonce in bits.</param>
		/// <param name="nonce">		 [in,out] The nonce.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool computeNonceU(size_t nonceBitLength, tsCryptoData &nonce) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets nonce for party V</summary>
		///
		/// <returns>The nonce for party V.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData get_NonceV() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets the nonce for party V</summary>
		///
		/// <param name="data">The nonce for party V.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool set_NonceV(const tsCryptoData &data) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Computes a nonce for party V</summary>
		///
		/// <param name="nonceBitLength">Length of the nonce in bits.</param>
		/// <param name="nonce">		 [in,out] The nonce.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool computeNonceV(size_t nonceBitLength, tsCryptoData &nonce) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Initializes this object.</summary>
		///
		/// <param name="isPartyU">		 true if this object is party U.</param>
		/// <param name="kmLengthInBits">The km length in bits.</param>
		/// <param name="staticKey">	 [in] If non-null, the static key.</param>
		/// <param name="ephemeralKey">  [in] If non-null, the ephemeral key.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool initialize(bool isPartyU, size_t kmLengthInBits, /*IN*/ std::shared_ptr<AsymmetricKey> staticKey, /*INOUT*/ std::shared_ptr<AsymmetricKey> ephemeralKey) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Finals this object.</summary>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool finish() = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Sets kc direction.</summary>
		///
		/// <param name="bilateral">	   true if bilateral.</param>
		/// <param name="unilateralFromMe">true if unilateral from me.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool setKCDirection(bool bilateral, bool unilateralFromMe) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Computes the shared secret</summary>
		///
		/// <param name="otherStaticKey">[in] If non-null, the other static key.</param>
		/// <param name="otherEphemeral">[in] If non-null, the other ephemeral.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool computeZ(std::shared_ptr<AsymmetricKey> otherStaticKey, std::shared_ptr<AsymmetricKey> otherEphemeral) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Calculates the MAC.</summary>
		///
		/// <param name="mac">[in,out] The MAC.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool computeMac(tsCryptoData &mac) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Verifies the MAC.</summary>
		///
		/// <param name="mac">The MAC.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool verifyMac(const tsCryptoData &mac) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Retrieves the keying material.</summary>
		///
		/// <param name="keyingMaterial">[in,out] The keying material.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool retrieveKeyingMaterial(tsCryptoData &keyingMaterial) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the shared secret</summary>
		///
		/// <param name="data">[in,out] The shared secret.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool get_Z(tsCryptoData &data) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the MAC data.</summary>
		///
		/// <param name="data">[in,out] The MAC.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool get_MacData(tsCryptoData &data) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the other MAC data.</summary>
		///
		/// <param name="data">[in,out] The MAC.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool get_OtherMacData(tsCryptoData &data) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the other information data.</summary>
		///
		/// <param name="data">[in,out] The data.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool get_OtherInfo(tsCryptoData &data) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Calculates the shared secret for other information</summary>
		///
		/// <param name="otherInfo">	 The otherinfo field.</param>
		/// <param name="otherStaticKey">[in,out] If non-null, the other static key.</param>
		/// <param name="otherEphemeral">[in,out] If non-null, the other ephemeral.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool computeZForOtherInfo(const tsCryptoData &otherInfo, std::shared_ptr<AsymmetricKey> otherStaticKey, std::shared_ptr<AsymmetricKey> otherEphemeral) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the dkm value.</summary>
		///
		/// <param name="data">[in,out] The DKM value.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool get_DKM(tsCryptoData &data) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Computes a MAC for the specified data</summary>
		///
		/// <param name="data">The data.</param>
		/// <param name="mac"> [in,out] The MAC.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool computeMacForData(const tsCryptoData &data, tsCryptoData &mac) = 0;
	};

	/// <summary>Performs an RSA Shared Value Exchange</summary>
	class VEILCORE_API RsaSVE
	{
	public:
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Generates a random shared secret value and encrypts it.</summary>
		///
		/// <param name="key">		 [in] The RSA key that is used to encrypt the generated secret.</param>
		/// <param name="Z">		 [out] The generated secret.</param>
		/// <param name="cipherText">[out] The encrypted generated secret.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool Generate(std::shared_ptr<RsaKey> key, tsCryptoData &Z, tsCryptoData &cipherText) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Decrypts the encrypted generated secret and returns the recovered secret value</summary>
		///
		/// <param name="key">		 [in] The RSA key that is used to decrypt the generated secret.</param>
		/// <param name="cipherText">The encrypted generated secret.</param>
		/// <param name="Z">		 [in,out] The generated secret.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool Recover(std::shared_ptr<RsaKey> key, const tsCryptoData &cipherText, tsCryptoData &Z) = 0;
	};

	class VEILCORE_API RsaKemKws
	{
	public:
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Wraps the specified secret key using RSA and a key derivation function</summary>
		///
		/// <param name="key">			 [in] The RSA key used in the wrap (public key).</param>
		/// <param name="KDFname">		 The name of the Key Derivation Function.</param>
		/// <param name="kdfOtherInfo">  The OtherInfo field used in the KDF.</param>
		/// <param name="KeyWrapName">   The algorithm name of the key wrap.</param>
		/// <param name="kwkBits">		 The number of bits to use for the key wrap key.</param>
		/// <param name="keyData">		 The secret key that is to be wrapped.</param>
		/// <param name="additionalInfo">The additionalInfo field used in the key wrapping.</param>
		/// <param name="cipherText">	 [out] The wrapped secret key.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool Wrap(std::shared_ptr<RsaKey> key, const tsCryptoStringBase &KDFname, const tsCryptoData &kdfOtherInfo, const tsCryptoStringBase &KeyWrapName, size_t kwkBits, const tsCryptoData &keyData, const tsCryptoData &additionalInfo, tsCryptoData &cipherText) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Unwraps the wrapped secret key</summary>
		///
		/// <param name="key">			 [in] The RSA key used in the unwrap (private key).</param>
		/// <param name="KDFname">		 Name of the Key Derivation Function.</param>
		/// <param name="kdfOtherInfo">  The OtherInfo field used in the KDF.</param>
		/// <param name="KeyWrapName">   Name of the key wrap algorithm.</param>
		/// <param name="kwkBits">		 The size of the key wrapping key in bits.</param>
		/// <param name="cipherText">	 The wrapped secret.</param>
		/// <param name="additionalInfo">The additionalInfo field used in the key wrapping.</param>
		/// <param name="keyData">		 [out] The secret key.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool Unwrap(std::shared_ptr<RsaKey> key, const tsCryptoStringBase &KDFname, const tsCryptoData &kdfOtherInfo, const tsCryptoStringBase &KeyWrapName, size_t kwkBits, const tsCryptoData &cipherText, const tsCryptoData &additionalInfo, tsCryptoData &keyData) = 0;
	};

	/// <summary>Key transport using RSA and OAEP</summary>
	class VEILCORE_API KtsOaep
	{
	public:
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Encrypts a secret key using the unauthenticated mode (no MACs)</summary>
		///
		/// <param name="key">			  [in] The recipient's RSA public key.</param>
		/// <param name="keyData">		  The secret key.</param>
		/// <param name="additionalInput">The additionalInput field (optional).</param>
		/// <param name="outputData">	  [out] The encrypted key.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool GenerateBasic(std::shared_ptr<RsaKey> key, const tsCryptoData &keyData, const tsCryptoData &additionalInput, tsCryptoData &outputData) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Decrypts a secret key using the unauthenticated mode (no MACs)</summary>
		///
		/// <param name="key">			  [in] The recipient's RSA private key.</param>
		/// <param name="cipherData">	  The encrypted key.</param>
		/// <param name="additionalInput">The additionalInput field (optional but must match the value used
		/// by the originator).</param>
		/// <param name="keyData">		  [in,out] Information describing the key.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool RecoverBasic(std::shared_ptr<RsaKey> key, const tsCryptoData &cipherData, const tsCryptoData &additionalInput, tsCryptoData &keyData) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Encrypts a secret key and creates a confirmation MAC.</summary>
		///
		/// <param name="key">			  [in] The recipient's RSA public key.</param>
		/// <param name="keyData">		  The secret key.</param>
		/// <param name="additionalInput">The additionalInput field (optional).</param>
		/// <param name="outputData">		 [out] The encrypted secret key.</param>
		/// <param name="macKeyLengthInBits">The MAC key length in bits.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool GenerateKeyConfirmation(std::shared_ptr<RsaKey> key, const tsCryptoData &keyData, const tsCryptoData &additionalInput, tsCryptoData &outputData, size_t macKeyLengthInBits) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Recovers the secret key and creates a confirmation MAC.</summary>
		///
		/// <param name="key">			     [in] The recipient's RSA private key.</param>
		/// <param name="cipherData">		 The encrypted secret key.</param>
		/// <param name="additionalInput">The additionalInput field (optional).</param>
		/// <param name="macKeyLengthInBits">The MAC key length in bits.</param>
		/// <param name="macTagLength">		 Length of the MAC tag.</param>
		/// <param name="macName">			 Name of the MAC algorithm.</param>
		/// <param name="IDu">				 The identifier for party U.</param>
		/// <param name="IDv">				 The identifier for party V.</param>
		/// <param name="Text">				 The text.</param>
		/// <param name="keyData">			 [out] The recovered secret key.</param>
		/// <param name="macTag">			 [out] The MAC tag.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool RecoverKeyConfirmation(std::shared_ptr<RsaKey> key, const tsCryptoData &cipherData, const tsCryptoData &additionalInput, size_t macKeyLengthInBits, size_t macTagLength, const tsCryptoStringBase &macName, const tsCryptoData &IDu, const tsCryptoData &IDv, const tsCryptoData &Text, tsCryptoData &keyData, tsCryptoData &macTag) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Validates key confirmation MAC from the recipient.</summary>
		///
		/// <param name="macName">Name of the MAC algorithm.</param>
		/// <param name="IDu">	  The identifier for party U.</param>
		/// <param name="IDv">	  The identifier for party V.</param>
		/// <param name="Text">   The text.</param>
		/// <param name="macTag"> The MAC tag.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool ValidateKeyConfirmation(const tsCryptoStringBase &macName, const tsCryptoData &IDu, const tsCryptoData &IDv, const tsCryptoData &Text, const tsCryptoData &macTag) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Recovers the secret key and creates a confirmation MAC.</summary>
		///
		/// <remarks>This function is provided for the case where the core functionality of RSA KTS is
		/// needed but the protocol somehow deviates from this implementation.  This is a helper function.</remarks>
		///
		/// <param name="key">				 [in] The recipient's RSA private key.</param>
		/// <param name="cipherData">		 The encrypted secret key.</param>
		/// <param name="additionalInput">   The additionalInput field (optional).</param>
		/// <param name="macKeyLengthInBits">The MAC key length in bits.</param>
		/// <param name="macTagLength">		 Length of the MAC tag.</param>
		/// <param name="macName">			 Name of the MAC algorithm.</param>
		/// <param name="macData">			 The raw data to MAC.</param>
		/// <param name="keyData">			 [out] The recovered secret key.</param>
		/// <param name="macTag">			 [out] The MAC tag.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool RecoverKeyConfirmation_Raw(std::shared_ptr<RsaKey> key, const tsCryptoData &cipherData, const tsCryptoData &additionalInput, size_t macKeyLengthInBits, size_t macTagLength, const tsCryptoStringBase &macName, const tsCryptoData &macData, tsCryptoData &keyData, tsCryptoData &macTag) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Validates key confirmation MAC from the recipient.</summary>
		///
		/// <remarks>This function is provided for the case where the core functionality of RSA KTS is
		/// needed but the protocol somehow deviates from this implementation.  This is a helper function.</remarks>
		///
		/// <param name="macName">Name of the MAC algorithm.</param>
		/// <param name="macData">The raw data to MAC.</param>
		/// <param name="macTag"> The MAC tag.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool ValidateKeyConfirmation_Raw(const tsCryptoStringBase &macName, const tsCryptoData &macData, const tsCryptoData &macTag) = 0;
	};

	/// <summary>RSA Key Transport using key wrap</summary>
	class VEILCORE_API KtsKemKws
	{
	public:
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Creates the encrypted secret for the non-confirmation use case</summary>
		///
		/// <param name="key">			 [in] The recipient's RSA public key.</param>
		/// <param name="KDFname">		 The algorithm name of the Key Derivation Function.</param>
		/// <param name="kdfOtherInfo">  The OtherInfo field.</param>
		/// <param name="KeyWrapName">   Name of the key wrap algorithm.</param>
		/// <param name="kwkBits">		 The key wrapping key length in bits.</param>
		/// <param name="keyData">		 The secret key to transport.</param>
		/// <param name="additionalInput">The additionalInput field (optional).</param>
		/// <param name="cipherText">	 [out] The encrypted secret key.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool GenerateBasic(std::shared_ptr<RsaKey> key, const tsCryptoStringBase &KDFname, const tsCryptoData &kdfOtherInfo, const tsCryptoStringBase &KeyWrapName, size_t kwkBits, const tsCryptoData &keyData, const tsCryptoData &additionalInfo, tsCryptoData &cipherText) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Recovers the secret key for the non-confirmation use case</summary>
		///
		/// <param name="key">			 [in] The recipient's RSA private key.</param>
		/// <param name="KDFname">		 The algorithm name of the Key Derivation Function.</param>
		/// <param name="kdfOtherInfo">  The OtherInfo field.</param>
		/// <param name="KeyWrapName">   Name of the key wrap algorithm.</param>
		/// <param name="kwkBits">		 The key wrapping key length in bits.</param>
		/// <param name="cipherText">	 The encrypted secret key.</param>
		/// <param name="additionalInfo">The additionalInput field (optional).</param>
		/// <param name="keyData">		 [out] The decrypted secret key.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool RecoverBasic(std::shared_ptr<RsaKey> key, const tsCryptoStringBase &KDFname, const tsCryptoData &kdfOtherInfo, const tsCryptoStringBase &KeyWrapName, size_t kwkBits, const tsCryptoData &cipherText, const tsCryptoData &additionalInfo, tsCryptoData &keyData) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Creates the encrypted secret for the confirmation use case.</summary>
		///
		/// <param name="key">				 [in] The recipient's RSA public key.</param>
		/// <param name="KDFname">			 The algorithm name of the Key Derivation Function.</param>
		/// <param name="kdfOtherInfo">		 The OtherInfo field.</param>
		/// <param name="KeyWrapName">		 Name of the key wrap algorithm.</param>
		/// <param name="kwkBits">			 The key wrapping key length in bits.</param>
		/// <param name="keyData">			 The secret key to transport.</param>
		/// <param name="additionalInfo">	 The additionalInput field (optional).</param>
		/// <param name="cipherText">		 [out] The encrypted secret key.</param>
		/// <param name="macKeyLengthInBits">The MAC key length in bits.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool GenerateKeyConfirmation(std::shared_ptr<RsaKey> key, const tsCryptoStringBase &KDFname, const tsCryptoData &kdfOtherInfo, const tsCryptoStringBase &KeyWrapName, size_t kwkBits, const tsCryptoData &keyData, const tsCryptoData &additionalInfo, tsCryptoData &cipherText, size_t macKeyLengthInBits) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Recovers the secret key for the non-confirmation use case.</summary>
		///
		/// <param name="key">				 [in] The recipient's RSA private key.</param>
		/// <param name="KDFname">			 The algorithm name of the Key Derivation Function.</param>
		/// <param name="kdfOtherInfo">		 The OtherInfo field.</param>
		/// <param name="KeyWrapName">		 Name of the key wrap algorithm.</param>
		/// <param name="kwkBits">			 The key wrapping key length in bits.</param>
		/// <param name="cipherText">		 The encrypted secret key.</param>
		/// <param name="additionalInfo">	 The additionalInput field (optional).</param>
		/// <param name="macKeyLengthInBits">The MAC key length in bits.</param>
		/// <param name="macTagLength">		 Length of the MAC tag.</param>
		/// <param name="macName">			 Name of the MAC algorithm.</param>
		/// <param name="IDu">				 The identifier for party U.</param>
		/// <param name="IDv">				 The identifier for party V.</param>
		/// <param name="Text">				 The text.</param>
		/// <param name="macTag">			 [in,out] The MAC tag.</param>
		/// <param name="keyData">			 [out] The decrypted secret key.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool RecoverKeyConfirmation(std::shared_ptr<RsaKey> key, const tsCryptoStringBase &KDFname, const tsCryptoData &kdfOtherInfo, const tsCryptoStringBase &KeyWrapName, size_t kwkBits, const tsCryptoData &cipherText, const tsCryptoData &additionalInfo, size_t macKeyLengthInBits, size_t macTagLength, const tsCryptoStringBase &macName, const tsCryptoData &IDu, const tsCryptoData &IDv, const tsCryptoData &Text, tsCryptoData &macTag, tsCryptoData &keyData) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Validate the key confirmation.</summary>
		///
		/// <param name="macName">Name of the MAC algorithm.</param>
		/// <param name="IDu">	  The identifier for party U.</param>
		/// <param name="IDv">	  The identifier for party V.</param>
		/// <param name="Text">   The text.</param>
		/// <param name="macTag"> The MAC tag.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool ValidateKeyConfirmation(const tsCryptoStringBase &macName, const tsCryptoData &IDu, const tsCryptoData &IDv, const tsCryptoData &Text, const tsCryptoData &macTag) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Recovers the secret key for the non-confirmation use case.</summary>
		///
		/// <remarks>This function is provided for the case where the core functionality of RSA Key
		/// Transport with Key Wrap is needed but the protocol somehow deviates from this implementation.
		/// This is a helper function.</remarks>
		///
		/// <param name="key">				 [in] The recipient's RSA private key.</param>
		/// <param name="KDFname">			 The algorithm name of the Key Derivation Function.</param>
		/// <param name="kdfOtherInfo">		 The OtherInfo field.</param>
		/// <param name="KeyWrapName">		 Name of the key wrap algorithm.</param>
		/// <param name="kwkBits">			 The key wrapping key length in bits.</param>
		/// <param name="cipherText">		 The encrypted secret key.</param>
		/// <param name="additionalInfo">	 The additionalInput field (optional).</param>
		/// <param name="macKeyLengthInBits">The MAC key length in bits.</param>
		/// <param name="macTagLength">		 Length of the MAC tag.</param>
		/// <param name="macName">			 Name of the MAC algorithm.</param>
		/// <param name="macData">			 The full data buffer to MAC.</param>
		/// <param name="macTag">			 [in,out] The MAC tag.</param>
		/// <param name="keyData">			 [in,out] The secret key.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool RecoverKeyConfirmation_Raw(std::shared_ptr<RsaKey> key, const tsCryptoStringBase &KDFname, const tsCryptoData &kdfOtherInfo, const tsCryptoStringBase &KeyWrapName, size_t kwkBits, const tsCryptoData &cipherText, const tsCryptoData &additionalInfo, size_t macKeyLengthInBits, size_t macTagLength, const tsCryptoStringBase &macName, const tsCryptoData &macData, tsCryptoData &macTag, tsCryptoData &keyData) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Validate the key confirmation.</summary>
		///
		/// <remarks>This function is provided for the case where the core functionality of RSA Key
		/// Transport with Key Wrap is needed but the protocol somehow deviates from this implementation.
		/// This is a helper function.</remarks>
		///
		/// <param name="macName">Name of the MAC algorithm.</param>
		/// <param name="macData">The full data buffer to MAC.</param>
		/// <param name="macTag"> The MAC tag.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool ValidateKeyConfirmation_Raw(const tsCryptoStringBase &macName, const tsCryptoData &macData, const tsCryptoData &macTag) = 0;
	};

	/// <summary>Performs the RSA Key Agreement Scheme 1 protocol</summary>
	class VEILCORE_API RsaKAS1
	{
	public:
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Initializes this object.</summary>
		///
		/// <param name="IDu">				 The identity information for party U.</param>
		/// <param name="IDv">				 The identity information for party V.</param>
		/// <param name="hasText">			 true if this object has text.</param>
		/// <param name="Text">				 The text.</param>
		/// <param name="macKeyLengthInBits">The MAC key length in bits.</param>
		/// <param name="MACAlgorithmName">  Name of the MAC algorithm.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool initialize(const tsCryptoData &IDu, const tsCryptoData &IDv, bool hasText, const tsCryptoData &Text, size_t macKeyLengthInBits, const tsCryptoStringBase &MACAlgorithmName) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Finalizes this object.</summary>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool finish() = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Uses the specified key to generate the first message for the recipient (Step 1 for originator)</summary>
		///
		/// <param name="key">				 [in] The RSA key for the recipient (public key).</param>
		/// <param name="partOneToRecipient">[out] The first message for the recipient.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool GenerateFirstPart(std::shared_ptr<RsaKey> key, tsCryptoData &partOneToRecipient) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Calculates the secret for the originator. (Step 2 for the originator if MACs are not used)</summary>
		///
		/// <param name="nonce">		  The nonce from the recipient.</param>
		/// <param name="KDFname">		  The algorithm name for the Key Derivation Function.</param>
		/// <param name="secretBitLength">Length of the secret value in bits.</param>
		/// <param name="secret">		  [in,out] The secret value.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool ComputeSecretForOriginator(const tsCryptoData &nonce, const tsCryptoStringBase &KDFname, size_t secretBitLength, tsCryptoData &secret) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Calculates the secret and validates the MAC. (Step 2 for the originator if MACs are used)</summary>
		///
		/// <param name="nonce">		  The nonce.</param>
		/// <param name="KDFname">		  The algorithm name for the Key Derivation Function.</param>
		/// <param name="secretBitLength">Length of the secret value in bits.</param>
		/// <param name="macTag">		  The MAC tag.</param>
		/// <param name="secret">		  [out] The secret value.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool ComputeSecretAndValidateMac(const tsCryptoData &nonce, const tsCryptoStringBase &KDFname, size_t secretBitLength, const tsCryptoData &macTag, tsCryptoData &secret) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Uses the specified key to recover the first message from the originator. (Step 1 for Recipient)</summary>
		///
		/// <param name="key">					[in] The RSA key for the recipient (private key).</param>
		/// <param name="partOneFromOriginator">The first message from the originator.</param>
		/// <param name="nonceToOriginator">	[out] The nonce to send to the originator.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool RecoverPartOne(std::shared_ptr<RsaKey> key, const tsCryptoData &partOneFromOriginator, tsCryptoData &nonceToOriginator) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Calculates the secret for the recipient. (Step 2 for the recipient if MACs are not used)</summary>
		///
		/// <param name="KDFname">		  The algorithm name of the Key Derivation Function.</param>
		/// <param name="secretBitLength">Length of the secret value in bits.</param>
		/// <param name="secret">		  [out] The secret value.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool ComputeSecretForRecipient(const tsCryptoStringBase &KDFname, size_t secretBitLength, tsCryptoData &secret) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Calculates the secret and MAC. (Step 2 for recipient if MACs are used)</summary>
		///
		/// <remarks>When MACs are used to validate the key agreement then this function is used and the
		/// MAC must be sent to the originator.</remarks>
		///
		/// <param name="nonce">		  The nonce.</param>
		/// <param name="KDFname">		  The algorithm name of the Key Derivation Function.</param>
		/// <param name="secretBitLength">Length of the secret value in bits.</param>
		/// <param name="secret">		  [out] The secret value.</param>
		/// <param name="macTag">		  [out] The MAC tag.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool ComputeSecretAndMac(const tsCryptoData &nonce, const tsCryptoStringBase &KDFname, size_t secretBitLength, tsCryptoData &secret, tsCryptoData &macTag) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>The underlying routine used to compute a secret value.</summary>
		///
		/// <remarks>This function is provided for the case where the core functionality of RSA KAS1 is
		/// needed but the protocol somehow deviates from this implementation.  This is a helper function.</remarks>
		///
		/// <param name="otherInfo">	  The OtherInfo field.</param>
		/// <param name="KDFname">		  The algorithm name for the Key Derivation Function.</param>
		/// <param name="secretBitLength">Length of the secret key in bits.</param>
		/// <param name="secret">		  [out] The secret key.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool ComputeSecret_Raw(const tsCryptoData &otherInfo, const tsCryptoStringBase &KDFname, size_t secretBitLength, tsCryptoData &secret) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Calculates the secret key and validates the MAC.</summary>
		///
		/// <remarks>This function is provided for the case where the core functionality of RSA KAS1 is
		/// needed but the protocol somehow deviates from this implementation.  This is a helper function.</remarks>
		///
		/// <param name="otherInfo">	  The OtherInfo field.</param>
		/// <param name="KDFname">		  The algorithm name for the Key Derivation Function.</param>
		/// <param name="secretBitLength">Length of the secret key in bits.</param>
		/// <param name="macTag">		  The MAC tag.</param>
		/// <param name="secret">		  [out] The secret key.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool ComputeSecretAndValidateMac_Raw(const tsCryptoData &otherInfo, const tsCryptoStringBase &KDFname, size_t secretBitLength, const tsCryptoData &macTag, tsCryptoData &secret) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Calculates the secret key and MAC.</summary>
		///
		/// <remarks>This function is provided for the case where the core functionality of RSA KAS1 is
		/// needed but the protocol somehow deviates from this implementation.  This is a helper function.</remarks>
		///
		/// <param name="otherInfo">	  The OtherInfo field.</param>
		/// <param name="KDFname">		  The algorithm name for the Key Derivation Function.</param>
		/// <param name="secretBitLength">Length of the secret key in bits.</param>
		/// <param name="secret">		  [out] The secret key.</param>
		/// <param name="macTag">		  [out] The MAC tag.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool ComputeSecretAndMac_Raw(const tsCryptoData &otherInfo, const tsCryptoStringBase &KDFname, size_t secretBitLength, tsCryptoData &secret, tsCryptoData &macTag) = 0;
	};

	/// <summary>Performs the RSA Key Agreement Scheme 2 protocol</summary>
	class VEILCORE_API RsaKAS2
	{
	public:
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Initializes this object for simplified use (non-confirmation).</summary>
		///
		/// <param name="secretLengthInBits">The secret length in bits.</param>
		/// <param name="kdfName">			 Name of the kdf algorithm.</param>
		/// <param name="IDu">				 The identifier for party U.</param>
		/// <param name="IDv">				 The identifier for party V.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool initialize(size_t secretLengthInBits, const tsCryptoStringBase &kdfName, const tsCryptoData &IDu, const tsCryptoData &IDv) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Initializes this object for confirmation.</summary>
		///
		/// <param name="secretLengthInBits">The secret length in bits.</param>
		/// <param name="kdfName">			 Name of the kdf algorithm.</param>
		/// <param name="IDu">				 The identifier for party U.</param>
		/// <param name="IDv">				 The identifier for party V.</param>
		/// <param name="forBilateral">		 true if bilateral mode.</param>
		/// <param name="macName">			 Name of the MAC algorithm.</param>
		/// <param name="macLengthInBytes">  The MAC length in bytes.</param>
		/// <param name="macKeyLengthInBits">The MAC key length in bits.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool initializeForConfirmation(size_t secretLengthInBits, const tsCryptoStringBase &kdfName, const tsCryptoData &IDu, const tsCryptoData &IDv, bool forBilateral, const tsCryptoStringBase &macName, size_t macLengthInBytes, size_t macKeyLengthInBits) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Finalizes this object.</summary>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool finish() = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Generates the first message from the originator to the recipient.</summary>
		///
		/// <param name="keyPartyV">		 [in] The RSA public key for the recipient.</param>
		/// <param name="partOneToRecipient">[out] The message for the recipient.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool GenerateFirstPart(std::shared_ptr<RsaKey> keyPartyV, tsCryptoData &partOneToRecipient) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Receives the first message, validates it and generates the reply from the recipient to the originator.</summary>
		///
		/// <param name="keyPartyU">		  [in] The RSA public key for party U.</param>
		/// <param name="keyPartyV">		  [in] The RSA private key for party V.</param>
		/// <param name="partOneToRecipient"> The first message from the originator.</param>
		/// <param name="partTwoToOriginator">[out] The new message to send to the originator.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool GenerateSecondPart(std::shared_ptr<RsaKey> keyPartyU, std::shared_ptr<RsaKey> keyPartyV, const tsCryptoData &partOneToRecipient, tsCryptoData &partTwoToOriginator) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Receive and validate the second message from the recipient.</summary>
		///
		/// <param name="keyPartyU">		   [in] The RSA private key from party U.</param>
		/// <param name="partTwoFromRecipient">The message from the recipient.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool ReceiveSecondPart(std::shared_ptr<RsaKey> keyPartyU, const tsCryptoData &partTwoFromRecipient) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Generates a MAC for the originator.</summary>
		///
		/// <param name="optionalData">The optionalData field.</param>
		/// <param name="macTag">	   [out] The MAC tag.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool GenerateOriginatorMac(const tsCryptoData &optionalData, tsCryptoData &macTag) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Generates a MAC for the recipient.</summary>
		///
		/// <param name="optionalData">The optionalData field.</param>
		/// <param name="macTag">	   [out] The MAC tag.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool GenerateRecipientMac(const tsCryptoData &optionalData, tsCryptoData &macTag) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Validates a MAC for the originator.</summary>
		///
		/// <param name="optionalData">The optionalData field.</param>
		/// <param name="macTag">	   [in] The MAC tag.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool ValidateOriginatorMac(const tsCryptoData &optionalData, const tsCryptoData &macTag) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Validates a MAC for the recipient.</summary>
		///
		/// <param name="optionalData">The optionalData field.</param>
		/// <param name="macTag">	   [in] The MAC tag.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool ValidateRecipientMac(const tsCryptoData &optionalData, const tsCryptoData &macTag) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the secret value.</summary>
		///
		/// <param name="optionalData">The optionalData field.</param>
		///
		/// <returns>The secret value.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData GetSecret(const tsCryptoData &optionalData) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Generates an originator MAC using the specified byte array.</summary>
		///
		/// <remarks>This function is provided for the case where the core functionality of RSA KAS2 is
		/// needed but the protocol somehow deviates from this implementation.  This is a helper function.</remarks>
		///
		/// <param name="otherData">The full data block to use.</param>
		/// <param name="macTag">   [out] The MAC tag.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool GenerateOriginatorMac_Raw(const tsCryptoData &otherData, tsCryptoData &macTag) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Generates a recipient MAC using the specified byte array.</summary>
		///
		/// <remarks>This function is provided for the case where the core functionality of RSA KAS2 is
		/// needed but the protocol somehow deviates from this implementation.  This is a helper function.</remarks>
		///
		/// <param name="otherData">The full data block to use.</param>
		/// <param name="macTag">   [out] The MAC tag.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool GenerateRecipientMac_Raw(const tsCryptoData &otherData, tsCryptoData &macTag) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Validates an originator MAC using the specified byte array.</summary>
		///
		/// <remarks>This function is provided for the case where the core functionality of RSA KAS2 is
		/// needed but the protocol somehow deviates from this implementation.  This is a helper function.</remarks>
		///
		/// <param name="otherData">The full data block to use.</param>
		/// <param name="macTag">   [out] The MAC tag.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool ValidateOriginatorMac_Raw(const tsCryptoData &otherData, const tsCryptoData &macTag) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Validates a recipient MAC using the specified byte array.</summary>
		///
		/// <remarks>This function is provided for the case where the core functionality of RSA KAS2 is
		/// needed but the protocol somehow deviates from this implementation.  This is a helper function.</remarks>
		///
		/// <param name="otherData">The full data block to use.</param>
		/// <param name="macTag">   [out] The MAC tag.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool ValidateRecipientMac_Raw(const tsCryptoData &otherData, const tsCryptoData &macTag) = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the secret value using the specified byte array</summary>
		///
		/// <remarks>This function is provided for the case where the core functionality of RSA KAS2 is
		/// needed but the protocol somehow deviates from this implementation.  This is a helper function.</remarks>
		///
		/// <param name="otherData">The full data block to use.</param>
		///
		/// <returns>The secret raw.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual tsCryptoData GetSecret_Raw(const tsCryptoData &otherData) = 0;
	};

	/// <summary>This interface defines the methods used for the AES XTS algorithm.</summary>
	class VEILCORE_API XTS
	{
	public:
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Initializes the XTS process.</summary>
		///
		/// <param name="key">		 The key.</param>
		/// <param name="forEncrypt">true to encrypt.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool initialize(const tsCryptoData &key, bool forEncrypt) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Performs the block encrypt or decrypt operation using a user specified "IVEC".</summary>
		///
		/// <param name="sector">		   [in,out] The sector.</param>
		/// <param name="sectorSizeInBits">The sector size in bits.</param>
		/// <param name="sectorAddress">   The sector address.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool update(tsCryptoData &sector, size_t sectorSizeInBits, const tsCryptoData &sectorAddress) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Performs the block encrypt or decrypt operation using the sector address.</summary>
		///
		/// <param name="sector">		   [in,out] The sector.</param>
		/// <param name="sectorSizeInBits">The sector size in bits.</param>
		/// <param name="sectorAddress">   The sector address.</param>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool updateByAddress(tsCryptoData &sector, size_t sectorSizeInBits, uint64_t sectorAddress) = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>performs cleanup and destroys the internal state set in the initialize function.</summary>
		///
		/// <returns>true if it succeeds, false if it fails.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual bool finish() = 0;

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the minimum key size in bits.</summary>
		///
		/// <returns>the minimum key size in bits.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t minimumKeySizeInBits() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the maximum key size in bits.</summary>
		///
		/// <returns>the maximum key size in bits.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t maximumKeySizeInBits() const = 0;
		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// <summary>Gets the key size increment in bits.</summary>
		///
		/// <returns>the key size increment in bits.</returns>
		////////////////////////////////////////////////////////////////////////////////////////////////////
		virtual size_t keySizeIncrementInBits() const = 0;
	};
	class VEILCORE_API TSALG_Access
	{
	public:
		virtual ~TSALG_Access() {}
		virtual const void* Descriptor() const = 0;
		virtual void* getKeyPair() const = 0;
		virtual uint8_t* getWorkspace() const = 0;
		virtual void* detachFromKeyPair() = 0;
		virtual void* cloneKeyPair() const = 0;
	};
}

#endif // __CORE_CRYPTO_H_INCLUDED

