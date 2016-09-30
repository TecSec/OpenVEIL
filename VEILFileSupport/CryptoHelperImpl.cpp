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

#include "stdafx.h"

static bool gDebugCryptoHelper = true;

std::shared_ptr<IKeyGenCallback> CreateEncryptProcessor(DWORD taskCount, DWORD currentTask, std::shared_ptr<IFileVEILOperationStatus> status, std::shared_ptr<IDataReader> reader, std::shared_ptr<IDataWriter> writer, bool prependHeader);

class HIDDEN CCKMCryptoHelperImpl :
	public ICryptoHelper,
	public IFifoStreamReaderCallback,
	public tsmod::IObject
{
public:
	CCKMCryptoHelperImpl(std::shared_ptr<IKeyVEILSession> session);
	virtual ~CCKMCryptoHelperImpl();

	virtual bool HashData(const tscrypto::tsCryptoData &data, TS_ALG_ID algorithm, tscrypto::tsCryptoData &hash);
	virtual bool HmacData(const tscrypto::tsCryptoData &data, const tscrypto::tsCryptoData &key, TS_ALG_ID algorithm, tscrypto::tsCryptoData &hash);

	virtual bool EncryptStream(CompressionType comp, TS_ALG_ID algorithm, TS_ALG_ID hashAlgorithm, std::shared_ptr<ICmsHeaderBase> header, bool prependHeader, const tscrypto::tsCryptoData &forcedIvec,
		std::shared_ptr<IDataReader> reader, std::shared_ptr<IDataWriter> writer, bool SignHeader, bool bindData, CMSFileFormatIds DataFormat, bool randomIvec,
		SymmetricPaddingType paddingType, int blockSize);
	virtual bool EncryptStreamWithKey(CompressionType comp, TS_ALG_ID algorithm, const tscrypto::tsCryptoData &hashOid, const tscrypto::tsCryptoData &key, const tscrypto::tsCryptoData &forcedIvec,
		std::shared_ptr<IDataReader> reader, std::shared_ptr<IDataWriter> writer, CMSFileFormatIds DataFormat, SymmetricPaddingType paddingType, const tscrypto::tsCryptoData &authData,
		tscrypto::tsCryptoData &finalHash, int blockSize);
	virtual bool DecryptStream(std::shared_ptr<ICmsHeaderBase> header, std::shared_ptr<IDataReader> reader, std::shared_ptr<IDataWriter> writer, bool headerIncludedInStream);
	virtual bool DecryptStreamWithKey(std::shared_ptr<IDataReader> reader, std::shared_ptr<IDataWriter> writer, CompressionType comp,
		TS_ALG_ID algorithm, const tscrypto::tsCryptoData &hashOid, const tscrypto::tsCryptoData &key, const tscrypto::tsCryptoData &forcedIvec, CMSFileFormatIds DataFormat,
		SymmetricPaddingType paddingType, const tscrypto::tsCryptoData &authData, const tscrypto::tsCryptoData &finalHash, int blockSize);
	virtual bool    StreamStartsWithCkmHeader(std::shared_ptr<IDataReader> stream, std::shared_ptr<ICmsHeaderBase>& pVal);
	virtual bool ValidateFileContents_PublicOnly(std::shared_ptr<IDataReader> reader);
	virtual bool SetOperationStatusCallback(std::shared_ptr<IFileVEILOperationStatus> setTo);
	virtual bool SetTaskInformation(int taskNumber, int taskCount);
	virtual bool SetDecryptCallback(std::shared_ptr<ICryptoHelperDecryptCallback> setTo);
	virtual tscrypto::tsCryptoData ComputeHeaderIdentity(std::shared_ptr<ICmsHeader> header) {
		return computeHeaderIdentity(header);
	}
	virtual bool padHeaderToSize(std::shared_ptr<ICmsHeaderBase> header, DWORD size);
	virtual bool PrepareHeader(std::shared_ptr<ICmsHeader> header7, CompressionType comp, TS_ALG_ID algorithm, TS_ALG_ID hashAlgorithm, bool SignHeader, bool bindData,
		CMSFileFormatIds DataFormat, bool randomIvec, SymmetricPaddingType paddingType, int blockSize, int64_t fileSize);
	virtual DWORD   ReservedHeaderLength() const;
	virtual bool SetKeyGenCallback(std::shared_ptr<IKeyGenCallback> callback);
	virtual bool SetSessionCallback(std::shared_ptr<IFileVEILSessionCallback> callback);

	// IFifoStreamReaderCallback
	virtual bool DataAvailable(std::shared_ptr<IFifoStream> fifo);

	virtual bool GenerateWorkingKey(std::shared_ptr<ICmsHeader>& header, std::shared_ptr<IKeyGenCallback> callback, tscrypto::tsCryptoData& workingKey);
	virtual bool RegenerateWorkingKey(std::shared_ptr<ICmsHeader>& header, tscrypto::tsCryptoData& workingKey);

protected:
	bool computeAlgParams(TS_ALG_ID algorithm, tscrypto::tsCryptoData &workingKey, KeyType &keyType, tscrypto::tsCryptoData &ivec,
		std::shared_ptr<Symmetric>& alg, int &keySize, int &blockSize);
	bool DecryptHashed(const tscrypto::tsCryptoData &key, std::shared_ptr<ICmsHeader>& header, int headerSize, int blocksize, bool hashPlainText,
		std::shared_ptr<IDataReader>& reader, std::shared_ptr<IDataWriter>& writer);
	bool DecryptEncAuthData(const tscrypto::tsCryptoData &key, std::shared_ptr<ICmsHeader>& header, int headerSize, int blocksize,
		std::shared_ptr<IDataReader>& reader, std::shared_ptr<IDataWriter>& writer);
	bool padHeaderToSize(std::shared_ptr<ICmsHeader>& header, DWORD size);


private:
	typedef enum CH_STATE {
		chs_nonFifo,
		chs_FindHeader,
		chs_ValidateHeaderDecrypt,
		chs_ProcessHashedDataDecrypt,
		chs_ProcessEncAuthLengthDecrypt,
		chs_ProcessEncAuthBlockDecrypt,
		chs_FinishDecryptHashed,
		chs_FinishDecryptEncAuth,
		chs_Shutdown,
	} CH_STATE;


	WaitableBool ProcessFifoFindHeader(std::shared_ptr<IFifoStream>& stream);
	WaitableBool ProcessFifoValidateHeaderDecrypt(std::shared_ptr<IFifoStream>& stream);
	WaitableBool ProcessFifoProcessHashedDataDecrypt(std::shared_ptr<IFifoStream>& stream);
	WaitableBool ProcessFifoProcessEncAuthLengthDecrypt(std::shared_ptr<IFifoStream>& stream);
	WaitableBool ProcessFifoProcessEncAuthBlockDecrypt(std::shared_ptr<IFifoStream>& stream);
	WaitableBool ProcessFifoFinishDecryptHashed(std::shared_ptr<IFifoStream>& stream);
	WaitableBool ProcessFifoFinishDecryptEncAuth(std::shared_ptr<IFifoStream>& stream);

	WaitableBool InitializeDecryptCtHashed(std::shared_ptr<IFifoStream>& stream, const tscrypto::tsCryptoData &wk);
	WaitableBool InitializeDecryptPtHashed(std::shared_ptr<IFifoStream>& stream, const tscrypto::tsCryptoData &wk);
	WaitableBool InitializeDecryptCtHashed(std::shared_ptr<IFifoStream>& stream, const tscrypto::tsCryptoData &wk, const tscrypto::tsCryptoData &finalHash,
		const tscrypto::tsCryptoData &hashOid, TS_ALG_ID encAlg, CompressionType compType, const tscrypto::tsCryptoData &authData, const tscrypto::tsCryptoData &ivec, int64_t filesize,
		SymmetricPaddingType paddingType);
	WaitableBool InitializeDecryptPtHashed(std::shared_ptr<IFifoStream>& stream, const tscrypto::tsCryptoData &wk, const tscrypto::tsCryptoData &finalHash,
		const tscrypto::tsCryptoData &hashOid, TS_ALG_ID encAlg, CompressionType compType, const tscrypto::tsCryptoData &authData, const tscrypto::tsCryptoData &ivec, int64_t filesize,
		SymmetricPaddingType paddingType);
	WaitableBool InitializeDecryptHashed(std::shared_ptr<IFifoStream>& stream, const tscrypto::tsCryptoData &wk);
	WaitableBool InitializeDecryptEncAuth(std::shared_ptr<IFifoStream>& stream, const tscrypto::tsCryptoData &wk);
	WaitableBool InitializeDecryptHashed(std::shared_ptr<IFifoStream>& stream, const tscrypto::tsCryptoData &wk, const tscrypto::tsCryptoData &finalHash,
		const tscrypto::tsCryptoData &hashOid, TS_ALG_ID encAlg, CompressionType compType, const tscrypto::tsCryptoData &authData, const tscrypto::tsCryptoData &ivec, int64_t filesize,
		SymmetricPaddingType paddingType);
	WaitableBool InitializeDecryptEncAuth(std::shared_ptr<IFifoStream>& stream, const tscrypto::tsCryptoData &wk, const tscrypto::tsCryptoData &finalHash,
		const tscrypto::tsCryptoData &hashOid, TS_ALG_ID encAlg, CompressionType compType, const tscrypto::tsCryptoData &authData, const tscrypto::tsCryptoData &ivec, int64_t filesize,
		SymmetricPaddingType paddingType);

	void ClearFifoVariables();

private:
	std::shared_ptr<IKeyVEILSession>	m_session;
	tscrypto::tsCryptoData								m_input;
	tscrypto::tsCryptoData								m_output;
	std::shared_ptr<ICmsHeader>         m_cmsHeader;
	tscrypto::tsCryptoData								m_key;
	std::shared_ptr<Hash>				m_hasher;
	std::shared_ptr<ICompression>       m_compressor;
	//bool                                m_decrypting;
	//bool                                m_finished;
	//uint64_t                            m_plaintextDataProcessed;
	tscrypto::tsCryptoData								m_workingKey;
	//int									m_blockSize;
	//bool                                m_foundHeader;
	std::shared_ptr<IFileVEILOperationStatus>		m_status;
	int									m_taskNumber;
	int									m_taskCount;
	DWORD                               m_reservedHeaderLength;
	std::shared_ptr<ICryptoHelperDecryptCallback> m_decryptCallback;
	std::shared_ptr<IFileVEILSessionCallback>  m_sessionCallback;

	// FIFO stream handling variables
	CH_STATE							m_fifoState;
	std::shared_ptr<IFifoStream>		m_reader;
	std::shared_ptr<IDataWriter>		m_writer;
	int									m_headerLenNeeded;
	std::shared_ptr<IDecryptProcessor>	m_processor;
	bool								m_prependHeader;
	bool								m_hashPlainText;

	tscrypto::tsCryptoData								m_tmp;
	tscrypto::tsCryptoData								m_tmp2;
	tscrypto::tsCryptoData								m_finalHash;
	std::shared_ptr<MessageAuthenticationCode>				m_fifoHasher;
	std::shared_ptr<Symmetric>			m_symEnc;
	std::shared_ptr<CCM_GCM>			m_gcm;
	std::shared_ptr<KeyDerivationFunction> m_kdf;
	std::shared_ptr<IKeyGenCallback>	m_keyGenCallback;
	tscrypto::tsCryptoData								m_authHeader;
	tscrypto::tsCryptoData								m_encIvec;
	tscrypto::tsCryptoData								m_counter;
	int64_t								m_fileSize;
	bool								m_hasFileSize;
	int									m_oldPercent;
	int									m_chunksize;
};

std::shared_ptr<ICryptoHelper> CreateCryptoHelper(std::shared_ptr<IKeyVEILSession> session)
{
	return ::TopServiceLocator()->Finish<ICryptoHelper>(new CCKMCryptoHelperImpl(session));
}
//bool CCKMCryptoHelperImpl::Create(ICKMSession *session, ICKMCryptoHelper **pVal)
//{
//	if (pVal == NULL)
//		return E_POINTER;
//
//	ICKMCryptoHelper *helper = new CCKMCryptoHelperImpl(session);
//
//	if (helper == NULL)
//		return E_OUTOFMEMORY;
//
//	return helper->QueryInterface(__uuidof(ICKMCryptoHelper), (void**)pVal);
//}
//
//bool CCKMCryptoHelperImpl::Create(ICKMNonCryptoGroupKeyGenerator *builder, ICKMCryptoHelper **pVal)
//{
//	if (pVal == NULL)
//		return E_POINTER;
//
//	ICKMCryptoHelper *helper = new CCKMCryptoHelperImpl(builder);
//
//	if (helper == NULL)
//		return E_OUTOFMEMORY;
//
//	return helper->QueryInterface(__uuidof(ICKMCryptoHelper), (void**)pVal);
//}

CCKMCryptoHelperImpl::CCKMCryptoHelperImpl(std::shared_ptr<IKeyVEILSession> session)
	:
	m_session(session),
	//m_decrypting(false),
	//m_foundHeader(false),
	m_taskNumber(0),
	m_taskCount(0),
	m_reservedHeaderLength(0),
	m_fifoState(chs_nonFifo),
	m_headerLenNeeded(0),
	m_prependHeader(false),
	m_hashPlainText(false)
{
}

CCKMCryptoHelperImpl::~CCKMCryptoHelperImpl(void)
{
}

bool CCKMCryptoHelperImpl::SetKeyGenCallback(std::shared_ptr<IKeyGenCallback> callback)
{
	m_keyGenCallback.reset();
	m_keyGenCallback = callback;
	return true;
}

bool CCKMCryptoHelperImpl::SetSessionCallback(std::shared_ptr<IFileVEILSessionCallback> callback)
{
	m_sessionCallback.reset();
	m_sessionCallback = callback;
	return true;
}

bool CCKMCryptoHelperImpl::HashData(const tscrypto::tsCryptoData &data, TS_ALG_ID algorithm, tscrypto::tsCryptoData &hash)
{
	std::shared_ptr<Hash> hasher = std::dynamic_pointer_cast<Hash>(CryptoFactory(algorithm));

	if (!hasher || !hasher->initialize() || !hasher->update(data) || !hasher->finish(hash))
		return false;

	return true;
}

bool CCKMCryptoHelperImpl::HmacData(const tscrypto::tsCryptoData &data, const tscrypto::tsCryptoData &key, TS_ALG_ID algorithm, tscrypto::tsCryptoData &hash)
{
	std::shared_ptr<MessageAuthenticationCode> hasher = std::dynamic_pointer_cast<MessageAuthenticationCode>(CryptoFactory(algorithm));

	if (!hasher || !hasher->initialize(key) || !hasher->update(data) || !hasher->finish(hash))
		return false;

	return true;
}

bool CCKMCryptoHelperImpl::computeAlgParams(TS_ALG_ID algorithm, tscrypto::tsCryptoData &workingKey, KeyType &keyType, tscrypto::tsCryptoData &ivec, std::shared_ptr<Symmetric>& alg, int &keySize, int &blockSize)
{
	size_t ivecLen;
	std::shared_ptr<tsmod::IObject> iunk;
	size_t KS;

	if (!(alg = std::dynamic_pointer_cast<Symmetric>(CryptoFactory(algorithm))))
	{
		return false;
	}

	blockSize = (int)alg->getBlockSize();
	KS = CryptoKeySize(algorithm);
	keySize = (int)KS >> 3;
	ivecLen = alg->getIVECSizeForMode(Alg2Mode(algorithm));

	ivec.clear();

	keyType = Alg2KeyType(algorithm);
	if (ivecLen > 0)
		ivec.assign(&workingKey.rawData()[keySize], ivecLen);

	return true;
}

bool CCKMCryptoHelperImpl::EncryptStream(CompressionType comp, TS_ALG_ID algorithm, TS_ALG_ID hashAlgorithm,
	std::shared_ptr<ICmsHeaderBase> Header, bool prependHeader, const tscrypto::tsCryptoData &forcedIvec,
	std::shared_ptr<IDataReader> reader, std::shared_ptr<IDataWriter> writer,
	bool SignHeader, bool bindData, CMSFileFormatIds DataFormat, bool randomIvec,
	SymmetricPaddingType paddingType, int blockSize)
{
	TSDECLARE_FUNCTIONExt(true);

	std::shared_ptr<ICmsHeaderBase> header2;
	std::shared_ptr<ICmsHeader> header7;
	std::shared_ptr<IKeyGenCallback> callback;
	std::shared_ptr<ICkmOperations> ops;
	int64_t fileSize = 0;

	m_reservedHeaderLength = 0;
	m_fifoState = chs_nonFifo;
	m_headerLenNeeded = 0;
	if (!Header)
	{
		LOG(DebugError, "The CKM Header is missing.");
		return TSRETURN_ERROR(("Bad Header"), false);
	}

	if (!(header7 = std::dynamic_pointer_cast<ICmsHeader>(Header)) || !(ops = std::dynamic_pointer_cast<ICkmOperations>(header7)))
	{
		LOG(DebugError, "The specified CKM Header is incomplete or invalid.");
		return TSRETURN_ERROR(("Bad Header"), false);
	}

	//
	// Now get the length of the source file
	//
	if (reader->AllowsRandomAccess())
		fileSize = reader->DataLength();
	else
		fileSize = -1;

	if (!ops->PrepareHeader(comp, algorithm, hashAlgorithm, SignHeader, bindData, DataFormat, forcedIvec.size() == 0 && randomIvec, paddingType, blockSize, fileSize))
		return TSRETURN_ERROR(("Returns ~~"), false);

	//LOG(CkmDevOnly , "Header after prepare" << endl << indent << TSHeaderToString(header7) << endl << outdent);

	if (forcedIvec.size() > 0)
	{
		header7->SetIVEC(forcedIvec);
	}

	if (!header7->SetDataName(reader->DataName().c_str()))
	{
		LOG(DebugInfo1, "WARNING:  Unable to save the original file name.  Continuing to process the file.");
	}

	if (!(callback = CreateEncryptProcessor(m_taskCount, m_taskNumber, m_status, reader, writer, prependHeader)))
	{
		LOG(DebugError, "Unable to create the encryption processor.");
		return TSRETURN_ERROR(("Unable to create the encryption processor"), false);
	}

	if (!!m_keyGenCallback)
		callback->SetNextCallback(m_keyGenCallback);

	if (!!header7)
	{
		if (!m_session && header7->NeedsSession())
		{
			if (!!m_sessionCallback)
			{
				if (!(m_sessionCallback->GetSessionForHeader(true, Header, 0, m_session)))
				{
					LOG(DebugError, "No session");
					return TSRETURN_ERROR(("Returns ~~"), false);
				}
			}
		}
	}
	if (!m_session)
	{
		LOG(DebugError, "Unable to generate the working key and encrypted data - No session.");
		return TSRETURN_ERROR(("Unable to generate the working key and encrypted data."), false);
	}
	else
	{
		tscrypto::tsCryptoData wk;

		if (!ops->GenerateWorkingKey(m_session, callback, wk))
		{
			LOG(DebugError, "Unable to generate the working key and encrypted data - GenerateWorkingKey.");
			return TSRETURN_ERROR(("Unable to generate the working key and encrypted data."), false);
		}
	}

	m_reservedHeaderLength = std::dynamic_pointer_cast<IReservedLength>(callback)->ReservedHeaderLength();

	if (prependHeader)
	{
		if (writer->CanPrepend())
		{
			if (!writer->Prepend(header7->ToBytes()))
			{
				LOG(DebugError, "Unable to save the header to the output file.");
				return TSRETURN_ERROR(("Unable to save the header to the output file"), false);
			}
		}
		else
		{
			//
			// Now we need to go back and pad the header in preparation of writing it into the reserved space
			//
			if (!(padHeaderToSize(header7, std::dynamic_pointer_cast<IReservedLength>(callback)->ReservedHeaderLength())))
			{
				LOG(DebugError, "Unable to create a CKM header of the reserved size.");
				return TSRETURN_ERROR(("FAILED"), false);
			}

			if (!writer->WriteData(header7->ToBytes()))
			{
				LOG(DebugError, "Unable to save the header to the output file.");
				return TSRETURN_ERROR(("Unable to save the header to the output file"), false);
			}
		}
	}
	return TSRETURN(("OK"), true);
}

bool CCKMCryptoHelperImpl::EncryptStreamWithKey(CompressionType comp, TS_ALG_ID algorithm, const tscrypto::tsCryptoData &hashOid, const tscrypto::tsCryptoData &key, const tscrypto::tsCryptoData &forcedIvec,
	std::shared_ptr<IDataReader> reader, std::shared_ptr<IDataWriter> writer, CMSFileFormatIds DataFormat, SymmetricPaddingType paddingType, const tscrypto::tsCryptoData &authData, tscrypto::tsCryptoData &finalHash, int blockSize)
{
	TSDECLARE_FUNCTIONExt(true);

	std::shared_ptr<IKeyGenCallback> callback;
//	int64_t fileSize = 0;

	m_reservedHeaderLength = 0;
	m_fifoState = chs_nonFifo;
	m_headerLenNeeded = 0;

	//
	// Now get the length of the source file
	//
//	if (reader->AllowsRandomAccess())
//		fileSize = reader->DataLength();
//	else
//		fileSize = -1;

	if (!(callback = CreateEncryptProcessor(m_taskCount, m_taskNumber, m_status, reader, writer, false)))
	{
		LOG(DebugError, "Unable to create the encryption processor.");
		return TSRETURN_ERROR(("Unable to create the encryption processor"), false);
	}

	if (!!m_keyGenCallback)
		callback->SetNextCallback(m_keyGenCallback);

	m_reservedHeaderLength = 0;

	if (!(std::dynamic_pointer_cast<IEncryptProcessor>(callback)->EncryptUsingKey(key, DataFormat,
		blockSize, algorithm, hashOid, comp, forcedIvec, paddingType, authData, finalHash)))
		return TSRETURN_ERROR(("Unable to create the encryption processor"), false);
	return TSRETURN(("OK"), true);
}

bool CCKMCryptoHelperImpl::DecryptStream(std::shared_ptr<ICmsHeaderBase> header, std::shared_ptr<IDataReader> reader, std::shared_ptr<IDataWriter> writer, bool headerIncludedInStream)
{
	TSDECLARE_FUNCTIONExt(true);

	int format = 0;
	int blocksize = 0;
	std::shared_ptr<ICmsHeader> header7;
	int64_t outputFileSize = -1;
	tscrypto::tsCryptoData wk;
	//	std::shared_ptr<IKeyGenCallback> callback;
	std::shared_ptr<IDecryptProcessor> processor;
	bool prependHeader = false;
	std::shared_ptr<IFifoStream> fifo;
	bool retVal;
	std::shared_ptr<ICkmOperations> ops;

	m_fifoState = chs_nonFifo;
	m_headerLenNeeded = 0;
	if (!reader || !writer)
	{
		return TSRETURN(("E_INVALIDARG"), false);
	}

	fifo = std::dynamic_pointer_cast<IFifoStream>(reader);

	ClearFifoVariables();

	if (!!fifo)
	{
		// This is a FIFO reader.  That means we need to split the operations up and always check for enough data.  Special handling needed.
		// For this to work we must use the callback system

		m_reader = fifo;
		m_writer = writer;
		m_fifoState = chs_FindHeader;
		fifo->SetReaderCallback(std::dynamic_pointer_cast<IFifoStreamReaderCallback>(_me.lock()));
		if (!!header)
			m_cmsHeader = std::dynamic_pointer_cast<ICmsHeader>(header);
		m_prependHeader = !!m_cmsHeader;
		if (m_prependHeader)
			m_fifoState = chs_ValidateHeaderDecrypt;

		return TSRETURN(("Returns ~~"), DataAvailable(fifo));
	}

	if (!header)
	{
		std::shared_ptr<ICmsHeaderBase> headerBase;

		LOG(DebugInfo3, "Decrypting stream");

		if (!StreamStartsWithCkmHeader(reader, headerBase))
		{
			LOG(DebugInfo1, "The stream is not encrypted.");
			return TSRETURN(("OK"), true);
		}
		header = headerBase;
		if (!!m_decryptCallback)
		{
			if (!(m_decryptCallback->HeaderFound(headerBase)))
			{
				return TSRETURN_ERROR(("Returns ~~"), false);
			}
		}
		prependHeader = true;
	}
	else if (headerIncludedInStream)
		prependHeader = true;

	if (!(header7 = std::dynamic_pointer_cast<ICmsHeader>(header)) || !(ops = std::dynamic_pointer_cast<ICkmOperations>(header)))
	{
		return TSRETURN(("E_INVALIDARG"), false);
	}

	if (!(processor = std::dynamic_pointer_cast<IDecryptProcessor>(CreateEncryptProcessor(m_taskCount, m_taskNumber, m_status, reader, writer, prependHeader))))
	{
		LOG(DebugError, "Unable to create the decryption processor.");
		return TSRETURN_ERROR(("Unable to create the decryption processor"), false);
	}

	if (!!header7)
	{
		if (!m_session && header7->NeedsSession())
		{
			if (!!m_sessionCallback)
			{
				if (!(m_sessionCallback->GetSessionForHeader(false, header, 0, m_session)))
				{
					LOG(DebugError, "No session.");
					return TSRETURN_ERROR(("No session"), false);
				}
			}
		}
	}
	// Regenerate the working key
	if (!m_session)
	{
		LOG(DebugError, "Unable to regenerate the working key and encrypted data.");
		return TSRETURN_ERROR(("Unable to regenerate the working key and encrypted data."), false);
	}
	else
	{
		Asn1::CTS::_POD_CkmCombineParameters params;

		if (header7->HasHeaderSigningPublicKey())
		{
			if (!header7->ValidateSignature())
			{
				LOG(DebugError, "The header has been modified and is no longer trusted.");
				return false;
			}
		}

		if (!ops->RegenerateWorkingKey(m_session, wk))
		{
			LOG(DebugError, "Unable to regenerate the working key and encrypted data.");
			return TSRETURN_ERROR(("Unable to regenerate the working key and encrypted data."), false);
		}
		if (!header7->HasHeaderSigningPublicKey())
		{
			if (!header7->ValidateMAC(wk))
			{
				LOG(DebugError, "Invalid header detected");
				return false;
			}
		}
	}

	if (!(processor->PrevalidateData(header)))
	{
		LOG(DebugError, "The data does not match the data signature.");
		return TSRETURN_ERROR(("The data does not match the data signature."), false);
	}

	if (!!m_decryptCallback)
	{
		if (!(m_decryptCallback->HeaderVerified(header)))
		{
			return TSRETURN_ERROR(("Returns ~~"), false);
		}
	}

	outputFileSize = header7->GetFileLength();
	if (outputFileSize == 0)
		outputFileSize = -1;

	if (reader->AllowsRandomAccess())
		reader->GoToPosition(0);


	if (!header7->GetDataFormat(blocksize, format))
	{
		blocksize = 0;
		format = TS_FORMAT_CMS_PT_HASHED;
	}

	switch (format)
	{
	case TS_FORMAT_CMS_CT_HASHED:
		retVal = DecryptHashed(wk, header7, prependHeader ? header7->PaddedHeaderSize() : 0, blocksize, false, reader, writer);
		break;
	case TS_FORMAT_CMS_PT_HASHED:
		retVal = DecryptHashed(wk, header7, prependHeader ? header7->PaddedHeaderSize() : 0, blocksize, true, reader, writer);
		break;
	case TS_FORMAT_CMS_ENC_AUTH:
		retVal = DecryptEncAuthData(wk, header7, prependHeader ? header7->PaddedHeaderSize() : 0, blocksize, reader, writer);
		break;
	default:
		LOG(DebugError, "Error:  Unrecognized file format.");
		return TSRETURN_ERROR(("Bad File"), false);
	}
	if (!retVal)
	{
		return TSRETURN_ERROR(("Invalid data"), false);
	}

	return TSRETURN(("OK"), true);
}

bool CCKMCryptoHelperImpl::DecryptStreamWithKey(std::shared_ptr<IDataReader> reader, std::shared_ptr<IDataWriter> writer, CompressionType comp,
	TS_ALG_ID algorithm, const tscrypto::tsCryptoData &hashOid, const tscrypto::tsCryptoData &key, const tscrypto::tsCryptoData &forcedIvec, CMSFileFormatIds DataFormat,
	SymmetricPaddingType paddingType, const tscrypto::tsCryptoData &authData, const tscrypto::tsCryptoData &finalHash, int blockSize)
{
	TSDECLARE_FUNCTIONExt(true);

	std::shared_ptr<IKeyGenCallback> callback;
	std::shared_ptr<IDecryptProcessor> processor;
	std::shared_ptr<IFifoStream> fifo;
	WaitableBool retVal;

	m_fifoState = chs_nonFifo;
	m_headerLenNeeded = 0;
	if (!reader || !writer)
	{
		return TSRETURN(("E_INVALIDARG"), false);
	}

	fifo = std::dynamic_pointer_cast<IFifoStream>(reader);

	ClearFifoVariables();

	if (!!fifo)
	{
		// This is a FIFO reader.  That means we need to split the operations up and always check for enough data.  Special handling needed.
		// For this to work we must use the callback system

		m_reader = fifo;
		m_writer = writer;
		m_fifoState = chs_FindHeader;
		fifo->SetReaderCallback(std::dynamic_pointer_cast<IFifoStreamReaderCallback>(_me.lock()));
		m_prependHeader = false;

		fifo->SetReaderCallback(std::dynamic_pointer_cast<IFifoStreamReaderCallback>(_me.lock()));

		if (!(m_processor = std::dynamic_pointer_cast<IDecryptProcessor>(CreateEncryptProcessor(m_taskCount, m_taskNumber, m_status, reader, writer, false))))
		{
			if (gDebugCryptoHelper) { LOG(DebugError, "Unable to create the decryption processor."); }
			return TSRETURN_ERROR(("Unable to create the decryption processor"), false);
		}

		if (!(m_processor->PrevalidateDataHash(finalHash, hashOid, authData, DataFormat)))
		{
			if (gDebugCryptoHelper) { LOG(DebugError, "The data does not match the data signature."); }
			return TSRETURN_ERROR(("The data does not match the data signature."), false);
		}

		if (!!m_decryptCallback)
		{
			std::shared_ptr<ICmsHeaderBase> headerBase;

			if (!(m_decryptCallback->HeaderVerified(headerBase)))
			{
				return TSRETURN_ERROR(("Returns ~~"), false);
			}
		}

		switch (DataFormat)
		{
		case TS_FORMAT_CMS_CT_HASHED:
			retVal = InitializeDecryptCtHashed(fifo, key, finalHash, hashOid, algorithm, comp, authData, forcedIvec, 0, paddingType);
			break;
		case TS_FORMAT_CMS_PT_HASHED:
			retVal = InitializeDecryptPtHashed(fifo, key, finalHash, hashOid, algorithm, comp, authData, forcedIvec, 0, paddingType);
			break;
		case TS_FORMAT_CMS_ENC_AUTH:
			retVal = InitializeDecryptEncAuth(fifo, key, finalHash, hashOid, algorithm, comp, authData, forcedIvec, 0, paddingType);
			break;
		default:
			LOG(DebugError, "Error:  Unrecognized file format.");
			return TSRETURN_ERROR(("Bad File"), false);
		}
		if (retVal != wait_true)
			return TSRETURN_ERROR(("Error ~~"), false);

		return TSRETURN(("Returns ~~"), DataAvailable(fifo));
	}

	if (!(processor = std::dynamic_pointer_cast<IDecryptProcessor>(CreateEncryptProcessor(m_taskCount, m_taskNumber, m_status, reader, writer, false))))
	{
		LOG(DebugError, "Unable to create the decryption processor.");
		return TSRETURN_ERROR(("Unable to create the decryption processor"), false);
	}

	//if (FAILED(hr = processor->PrevalidateData(*header)))
	//{
	//    LOG(DebugError , "The data does not match the data signature." );
	//    return TSRETURN_ERROR(("The data does not match the data signature."), hr);
	//}

	//if (!!m_decryptCallback)
	//{
	//	if (FAILED(hr = m_decryptCallback->HeaderVerified(*header)))
	//	{
	//		return TSRETURN_ERROR(("Returns ~~"),hr);
	//	}
	//}

	if (reader->AllowsRandomAccess())
		reader->GoToPosition(0);

	if (!processor->DecryptUsingKey(key, DataFormat, blockSize, algorithm, hashOid, comp, forcedIvec, paddingType, authData, finalHash))
	{
		return TSRETURN_ERROR(("Invalid data"), false);
	}

	return TSRETURN(("OK"), true);
}

bool CCKMCryptoHelperImpl::DecryptEncAuthData(const tscrypto::tsCryptoData &_key, std::shared_ptr<ICmsHeader>& header, int headerSize, int blocksize,
	std::shared_ptr<IDataReader>& reader, std::shared_ptr<IDataWriter>& writer)
{
	TSDECLARE_FUNCTIONExt(true);

	tscrypto::tsCryptoData key(_key);
	tscrypto::tsCryptoData len, tmp, tmp2;
	std::shared_ptr<MessageAuthenticationCode> hasher;
	std::shared_ptr<CCM_GCM> enc;
	SymmetricMode encMode;
	std::shared_ptr<KeyDerivationFunction> kdf;
	std::shared_ptr<ICompression> compressor;
	size_t encKeySize = 0, ivecSize = 0, encBlocksize;
	tscrypto::tsCryptoData encKey, macKey, encIvec, ivec, counter, authHeader, tag;
	int64_t fileSize = 0;
	bool hasFileSize = false;
	int percent;
	int oldPercent = -1;

	fileSize = (int64_t)header->GetFileLength();
	hasFileSize = (fileSize > 0);

	if (header->GetDataHash().size() != 0)
	{
		if (!(hasher = std::dynamic_pointer_cast<MessageAuthenticationCode>(CryptoFactory(header->GetDataHashOID().ToOIDString()))))
			return TSRETURN_ERROR(("Unable to create the data hash algorithm."), false);
	}

	TS_ALG_ID encAlg = header->GetEncryptionAlgorithmID();
	encMode = Alg2Mode(encAlg);

	if (!(kdf = std::dynamic_pointer_cast<KeyDerivationFunction>(CryptoFactory("KDF-SHA512"))))
	{
		LOG(DebugError, "The specified encryption file format requires the use of a key derivation function that is not available.");
		return TSRETURN_ERROR(("The specified encryption file format requires the use of a key derivation function that is not available."), false);
	}

	switch (encMode)
	{
	case _SymmetricMode::CKM_SymMode_CCM:
	case _SymmetricMode::CKM_SymMode_GCM:
		if (!(enc = std::dynamic_pointer_cast<CCM_GCM>(CryptoFactory(header->GetEncryptionAlgorithmOID().ToOIDString()))))
		{
			LOG(DebugError, "Unable to create the required data encryption algorithm.");
			return TSRETURN_ERROR(("Unable to create the required data encryption algorithm."), false);
		}
		break;
	default:
		LOG(DebugError, "The specified encryption file format requires the use of an authenticated encryption mode.");
		return TSRETURN_ERROR(("The specified encryption file format requires the use of an authenticated encryption mode."), false);
	}

	encKeySize = CryptoKeySize(encAlg);
	ivecSize = CryptoIVECSize(encAlg);
	encBlocksize = CryptoBlockSize(encAlg);

	if (encKeySize == 0 || encBlocksize == 0)
	{
		LOG(DebugError, "Unable to retrieve the required data encryption algorithm parameters.");
		return TSRETURN_ERROR(("Unable to retrieve the required data encryption algorithm parameters."), false);
	}

	if (key.size() * 8 < (uint32_t)encKeySize)
	{
		LOG(DebugError, "The encryption key is too short.");
		return TSRETURN_ERROR(("The encryption key is too short."), false);
	}

	switch (header->GetCompressionType())
	{
	case ct_BZ2:
	case ct_zLib:
		if (!(compressor = CreateCompressor(header->GetCompressionType())))
		{
			LOG(DebugError, "The compression type is not recognized.");
			return TSRETURN_ERROR(("The compression type is not recognized."), false);
		}
		break;
	case ct_None:
		break;
	default:
		LOG(DebugError, "The compression type is not recognized.");
		return TSRETURN_ERROR(("The compression type is not recognized."), false);
	}
	encKey = key.substring(0, encKeySize / 8);
	key.erase(0, encKey.size());

	authHeader = ComputeHeaderIdentity(header);

	if (!!hasher)
	{
		if (hasher->requiresKey())
		{
			int maxKeySize = (int)hasher->maximumKeySizeInBits();

			if (maxKeySize < 0 || maxKeySize > 65535 || (size_t)maxKeySize > encKeySize)
				maxKeySize = (int)encKeySize;

			if (key.size() * 8 < (uint32_t)maxKeySize)
			{
				LOG(DebugError, "The encryption key is too short.");
				return TSRETURN_ERROR(("The encryption key is too short."), false);
			}

			macKey = key.substring(0, maxKeySize / 8);
			key.erase(0, macKey.size());
		}
		if (!hasher->initialize(macKey))
		{
			LOG(DebugError, "Unable to create the required data hash algorithm.");
			return TSRETURN_ERROR(("Unable to create the required data hash algorithm"), false);
		}
		macKey.clear();
	}

	reader->GoToPosition(headerSize);

	if (ivecSize > 0)
	{
		encIvec = header->GetIVEC();

		if (encIvec.size() == 0)
		{
			// IVEC comes from the working key.
			if (key.size() < (uint32_t)ivecSize)
			{
				LOG(DebugError, "The encryption key is too short.");
				return TSRETURN_ERROR(("The encryption key is too short."), false);
			}

			encIvec = key.substring(0, ivecSize);
			key.erase(0, encIvec.size());
		}
	}

	encIvec += encKey;

	counter.resize(4);

	while (!reader->IsEndOfFile())
	{
		if (hasFileSize)
			percent = (int)((100 * writer->CurrentPosition()) / fileSize);
		else
			percent = (int)((100 * writer->CurrentPosition()) / (writer->CurrentPosition() + blocksize));

		if (percent != oldPercent && !!m_status)
		{
			tscrypto::tsCryptoString task;

			task << "Decrypt " << header->GetDataName();

			if (!(m_status->Status(task.c_str(), m_taskNumber, m_taskCount, percent)))
			{
				LOG(DebugError, "Operation cancelled");
				return TSRETURN_ERROR(("Cancelled"), false);
			}
			oldPercent = percent;
		}

		if (!reader->ReadData(4, len))
		{
			return false;
		}
		if (len.size() == 0 && reader->IsEndOfFile())
			break;
		if (!!hasher)
		{
			if (!hasher->update(len))
			{
				LOG(DebugError, "Unable to compute the data hash.");
				return TSRETURN_ERROR(("Unable to compute the data hash."), false);
			}
		}

#if (BYTE_ORDER == LITTLE_ENDIAN)
		len.reverse();
#endif
		if (!reader->ReadData(*(int32_t *)len.c_str(), tmp))
		{
			LOG(DebugError, "Data format invalid.");
			return TSRETURN_ERROR(("Data format invalid."), false);
		}
		if (tmp.size() > 16)
		{
			tag.assign(&tmp.c_str()[tmp.size() - 16], 16);
			tmp.resize(tmp.size() - 16);
		}
		else
		{
			LOG(DebugError, "Data format invalid.");
			return TSRETURN_ERROR(("Data format invalid."), false);
		}

		if (!!hasher && !hasher->update(tag))
		{
			LOG(DebugError, "Unable to compute the data hash.");
			return TSRETURN_ERROR(("Unable to compute the data hash."), false);
		}

		// Each block is treated as a new encryption (new ivec, new key).
		counter.increment();
		if (!kdf->Derive_SP800_56A_Counter(encIvec, counter, 256 + 96, ivec))
		{
			LOG(DebugError, "The decryption key is too short.");
			return TSRETURN_ERROR(("The decryption key is too short."), false);
		}
		// Each block is treated as a new encryption (new ivec, same key).  We only need to initialize once.
		if (!enc->initialize(ivec.substring(0, 32)))
		{
			LOG(DebugError, "Unable to initialize the bulk data encryptor.");
			return TSRETURN_ERROR(("Unable to initialize the bulk data encryptor."), false);
		}
		ivec.erase(0, 32);
		if (!enc->decryptMessage(ivec, authHeader, tmp, tag))
		{
			LOG(DebugError, "Unable to decrypt the file.  The tag does not match the computed value.");
			return TSRETURN_ERROR(("FAILED"), false);
		}

		if (!!compressor)
		{
			if (!(compressor->DecompressInit()) ||
				!(compressor->Decompress(tmp, tmp2, compAct_Run)) ||
				!(compressor->DecompressFinal(tmp)))
			{
				LOG(DebugError, "Unable to decrypt the file.  The decompression operation failed.");
				return TSRETURN_ERROR(("FAILED"), false);
			}
			tmp.insert(0, tmp2);
		}
		if (tmp.size() > 0)
		{
			LOG(DebugInfo3, "Writing " << tmp.size() << " bytes of data to the output file");

			if (!writer->WriteData(tmp))
			{
				LOG(DebugError, "Unable to write the decrypted data into the output file.");
				return TSRETURN_ERROR(("FAILED"), false);
			}
		}
	}

	if (!!m_status)
	{
		tscrypto::tsCryptoString task;

		task << "Decrypt " << header->GetDataName();

		if (!(m_status->Status(task.c_str(), m_taskNumber, m_taskCount, 100)))
		{
			LOG(DebugError, "Operation cancelled");
			return TSRETURN_ERROR(("Cancelled"), false);
		}
	}

	if (!!hasher)
	{
		if (!hasher->finish(tmp))
		{
			LOG(DebugError, "Unable to compute the data hash.");
			return TSRETURN_ERROR(("Unable to compute the data hash."), false);
		}

		if (tmp.compare(header->GetDataHash()) != 0)
		{
			LOG(DebugError, "Unable to decrypt the file - data hash invalid.");
			return TSRETURN_ERROR(("Unable to decrypt the file - data hash invalid"), false);
		}
	}
	return TSRETURN(("OK"), true);
}

bool CCKMCryptoHelperImpl::DecryptHashed(const tscrypto::tsCryptoData &_key, std::shared_ptr<ICmsHeader>& header, int headerSize, int blocksize, bool hashPlainText,
	std::shared_ptr<IDataReader>& reader, std::shared_ptr<IDataWriter>& writer)
{
	TSDECLARE_FUNCTIONExt(true);

	tscrypto::tsCryptoData key(_key);
	tscrypto::tsCryptoData tmp, tmp2;
	std::shared_ptr<MessageAuthenticationCode> hasher;
	std::shared_ptr<Symmetric> enc;
	SymmetricMode encMode;
	std::shared_ptr<ICompression> compressor;
	size_t encKeySize = 0, ivecSize = 0, encBlocksize;
	tscrypto::tsCryptoData encKey, macKey, encIvec, ivec, counter, authHeader, tag;
	int64_t fileSize = 0;
	bool hasFileSize = false;
	int percent;
	int oldPercent = -1;

	fileSize = (int64_t)header->GetFileLength();
	hasFileSize = (fileSize > 0);

	if (header->GetDataHash().size() != 0)
	{
		if (!(hasher = std::dynamic_pointer_cast<MessageAuthenticationCode>(CryptoFactory(header->GetDataHashOID().ToOIDString()))))
			return TSRETURN_ERROR(("Unable to create the data hash algorithm."), false);
	}

	TS_ALG_ID encAlg = header->GetEncryptionAlgorithmID();
	encMode = Alg2Mode(encAlg);

	if (!(enc = std::dynamic_pointer_cast<Symmetric>(CryptoFactory(header->GetEncryptionAlgorithmOID().ToOIDString()))))
	{
		LOG(DebugError, "Unable to create the required data encryption algorithm.");
		return TSRETURN_ERROR(("Unable to create the required data encryption algorithm."), false);
	}

	encKeySize = CryptoKeySize(encAlg);
	ivecSize = CryptoIVECSize(encAlg);
	encBlocksize = CryptoBlockSize(encAlg);

	if (encKeySize == 0 || encBlocksize == 0)
	{
		LOG(DebugError, "Unable to retrieve the required data encryption algorithm parameters.");
		return TSRETURN_ERROR(("Unable to retrieve the required data encryption algorithm parameters."), false);
	}

	if (key.size() * 8 < (uint32_t)encKeySize)
	{
		LOG(DebugError, "The encryption key is too short.");
		return TSRETURN_ERROR(("The encryption key is too short."), false);
	}

	switch (header->GetCompressionType())
	{
	case ct_BZ2:
	case ct_zLib:
		if (!(compressor = CreateCompressor(header->GetCompressionType())))
		{
			LOG(DebugError, "The compression type is not recognized.");
			return TSRETURN_ERROR(("The compression type is not recognized."), false);
		}
		break;
	case ct_None:
		break;
	default:
		LOG(DebugError, "The compression type is not recognized.");
		return TSRETURN_ERROR(("The compression type is not recognized."), false);
	}
	encKey = key.substring(0, encKeySize / 8);
	key.erase(0, encKey.size());

	if (!!hasher)
	{
		authHeader = ComputeHeaderIdentity(header);

		if (hasher->requiresKey())
		{
			int maxKeySize = (int)hasher->maximumKeySizeInBits();

			if (maxKeySize < 0 || maxKeySize > 65535 || (size_t)maxKeySize > encKeySize)
				maxKeySize = (int)encKeySize;

			if (key.size() * 8 < (uint32_t)maxKeySize)
			{
				LOG(DebugError, "The encryption key is too short.");
				return TSRETURN_ERROR(("The encryption key is too short."), false);
			}

			macKey = key.substring(0, maxKeySize / 8);
			key.erase(0, macKey.size());
		}
		if (!hasher->initialize(macKey) || !hasher->update(authHeader))
		{
			LOG(DebugError, "Unable to create the required data hash algorithm.");
			return TSRETURN_ERROR(("Unable to create the required data hash algorithm"), false);
		}
		macKey.clear();
	}

	reader->GoToPosition(headerSize);

	if (ivecSize > 0)
	{
		encIvec = header->GetIVEC();

		if (encIvec.size() == 0)
		{
			// IVEC comes from the working key.
			if (key.size() < (uint32_t)ivecSize)
			{
				LOG(DebugError, "The encryption key is too short.");
				return TSRETURN_ERROR(("The encryption key is too short."), false);
			}

			encIvec = key.substring(0, ivecSize);
			key.erase(0, encIvec.size());
		}
	}

	// Each block is treated as a new encryption (new ivec, same key).  We only need to initialize once.
	if (!enc->init(false, encMode, encKey, encIvec))
	{
		LOG(DebugError, "Unable to initialize the bulk data encryptor.");
		return TSRETURN_ERROR(("Unable to initialize the bulk data encryptor."), false);
	}

	counter.resize(4);

	enc->setPaddingType(header->GetPaddingType());

	if (!!compressor)
	{
		if (!(compressor->DecompressInit()))
		{
			LOG(DebugError, "Unable to decrypt the file.  The decompression operation failed.");
			return TSRETURN_ERROR(("FAILED"), false);
		}
	}

	while (!reader->IsEndOfFile())
	{
		if (hasFileSize)
			percent = (int)((100 * writer->CurrentPosition()) / fileSize);
		else
			percent = (int)((100 * writer->CurrentPosition()) / (writer->CurrentPosition() + blocksize));

		if (percent != oldPercent && !!m_status)
		{
			tscrypto::tsCryptoString task;

			task << "Decrypt " << header->GetDataName();

			if (!(m_status->Status(task.c_str(), m_taskNumber, m_taskCount, percent)))
			{
				LOG(DebugError, "Operation cancelled");
				return TSRETURN_ERROR(("Cancelled"), false);
			}
			oldPercent = percent;
		}

		if (!reader->ReadData(blocksize, tmp))
		{
			LOG(DebugError, "Data format invalid.");
			return TSRETURN_ERROR(("Data format invalid."), false);
		}
		if (tmp.size() == 0 && reader->IsEndOfFile())
			break;

		if (!!hasher && !hashPlainText)
		{
			if (!hasher->update(tmp))
			{
				LOG(DebugError, "Unable to compute the data hash.");
				return TSRETURN_ERROR(("Unable to compute the data hash."), false);
			}
		}

		if (tmp.size() <= 0)
		{
			LOG(DebugError, "Data format invalid.");
			return TSRETURN_ERROR(("Data format invalid."), false);
		}

		if (!enc->update(tmp, tmp))
		{
			LOG(DebugError, "Unable to decrypt the file.  The decryption operation failed.");
			return TSRETURN_ERROR(("FAILED"), false);
		}

		if (!!compressor)
		{
			if (!(compressor->Decompress(tmp, tmp2, compAct_Run)))
			{
				LOG(DebugError, "Unable to decrypt the file.  The decompression operation failed.");
				return TSRETURN_ERROR(("FAILED"), false);
			}
			tmp = tmp2;
		}
		if (tmp.size() > 0)
		{
			if (!!hasher && hashPlainText)
			{
				if (!hasher->update(tmp))
				{
					LOG(DebugError, "Unable to compute the data hash.");
					return TSRETURN_ERROR(("Unable to compute the data hash."), false);
				}
			}

			LOG(DebugInfo3, "Writing " << tmp.size() << " bytes of data to the output file");

			if (!writer->WriteData(tmp))
			{
				LOG(DebugError, "Unable to write the decrypted data into the output file.");
				return TSRETURN_ERROR(("FAILED"), false);
			}
		}
	}

	if (!!m_status)
	{
		tscrypto::tsCryptoString task;

		task << "Decrypt " << header->GetDataName();

		if (!(m_status->Status(task.c_str(), m_taskNumber, m_taskCount, 100)))
		{
			LOG(DebugError, "Operation cancelled");
			return TSRETURN_ERROR(("Cancelled"), false);
		}
	}

	if (!enc->finish(tmp))
	{
		LOG(DebugError, "Unable to decrypt the file.  The decryption operation could not finish.");
		return TSRETURN_ERROR(("FAILED"), false);
	}
	if (!!compressor)
	{
		tmp2.clear();
		if (tmp.size() > 0)
		{
			if (!(compressor->Decompress(tmp, tmp2, compAct_Run)))
			{
				LOG(DebugError, "Unable to decrypt the file.  The decompression operation failed.");
				return TSRETURN_ERROR(("FAILED"), false);
			}
		}
		tmp.clear();
		if (!(compressor->DecompressFinal(tmp)))
		{
			LOG(DebugError, "Unable to decrypt the file.  The decompression operation failed.");
			return TSRETURN_ERROR(("FAILED"), false);
		}
		tmp.insert(0, tmp2);
	}
	if (tmp.size() > 0)
	{
		if (!!hasher && hashPlainText)
		{
			if (!hasher->update(tmp))
			{
				LOG(DebugError, "Unable to compute the data hash.");
				return TSRETURN_ERROR(("Unable to compute the data hash."), false);
			}
		}

		LOG(DebugInfo3, "Writing " << tmp.size() << " bytes of data to the output file");

		if (!writer->WriteData(tmp))
		{
			LOG(DebugError, "Unable to write the decrypted data into the output file.");
			return TSRETURN_ERROR(("FAILED"), false);
		}
	}

	if (!!hasher)
	{
		if (!hasher->finish(tmp))
		{
			LOG(DebugError, "Unable to compute the data hash.");
			return TSRETURN_ERROR(("Unable to compute the data hash."), false);
		}

		if (tmp.compare(header->GetDataHash()) != 0)
		{
			LOG(DebugError, "Unable to decrypt the file - data hash invalid.");
			return TSRETURN_ERROR(("Unable to decrypt the file - data hash invalid"), false);
		}
	}
	return TSRETURN(("OK"), true);
}

bool    CCKMCryptoHelperImpl::StreamStartsWithCkmHeader(std::shared_ptr<IDataReader> stream, std::shared_ptr<ICmsHeaderBase>& pVal)
{
	tscrypto::tsCryptoData contents;
	std::shared_ptr<ICmsHeaderBase> header;
	int len;
	int headerLen = 0;
	int64_t fileLength;
	std::shared_ptr<tsmod::IObject> iunk;

	if (!stream)
		return false;

	fileLength = stream->DataLength();

	if (fileLength > 20480)
		len = 20480;
	else
		len = (int)fileLength;

	stream->PeekData(len, contents);
	if (contents.size() != (uint32_t)len)
	{
		return false;
	}
	if (!(ExtractHeaderFromStream(contents.c_str(), len, &headerLen, iunk)) || !(header = std::dynamic_pointer_cast<ICmsHeaderBase>(iunk)) || headerLen == 0)
	{
		return false;
	}

	stream->ReadData(headerLen, contents);

	pVal = header;
	return true;
}

bool CCKMCryptoHelperImpl::ValidateFileContents_PublicOnly(std::shared_ptr<IDataReader> reader)
{
	TSDECLARE_FUNCTIONExt(true);

	std::shared_ptr<ICmsHeaderBase> header;
	bool hr;

	LOG(DebugInfo3, "Validating file '" << reader->DataName() << "'");

	if (!StreamStartsWithCkmHeader(reader, header))
	{
		LOG(DebugInfo1, "The file '" << reader->DataName() << "' is not encrypted.");
		return TSRETURN(("OK"), true);
	}

	std::shared_ptr<ICmsHeader> header7;

	if (!(header7 = std::dynamic_pointer_cast<ICmsHeader>(header)))
	{
		LOG(DebugInfo1, "The file '" << reader->DataName() << "' has an unrecognized header format.");
		return TSRETURN(("FAIL"), false);
	}

	if (header7->HasHeaderSigningPublicKey())
	{
		if (!header7->ValidateSignature())
		{
			LOG(DebugInfo1, "The file '" << reader->DataName() << "' has a header that has been modified");
			return TSRETURN(("FAIL"), false);
		}
	}
	else
	{
		LOG(DebugInfo1, "CKM 7 header with HMAC - Header was not validated as no working key regeneration will be performed in this operation.");
	}

	std::shared_ptr<IDecryptProcessor> processor;

	reader->GoToPosition(0);

	std::shared_ptr<IDataWriter> emptyWriter;
	if (!(processor = std::dynamic_pointer_cast<IDecryptProcessor>(CreateEncryptProcessor(m_taskCount, m_taskNumber, m_status, reader, emptyWriter, true))))
	{
		LOG(DebugError, "Unable to create the decryption processor.");
		return TSRETURN_ERROR(("Unable to create the decryption processor"), false);
	}

	if (!(hr = processor->PrevalidateData(header)))
	{
		LOG(DebugError, "ERROR:  The file has been modified.");
		return TSRETURN_ERROR(("The file has been modified."), false);
	}
	return TSRETURN(("OK"), true);
}

bool CCKMCryptoHelperImpl::SetOperationStatusCallback(std::shared_ptr<IFileVEILOperationStatus> setTo)
{
	m_status.reset();
	m_status = setTo;
	return true;
}

bool CCKMCryptoHelperImpl::SetTaskInformation(int taskNumber, int taskCount)
{
	m_taskNumber = taskNumber;
	m_taskCount = taskCount;
	return true;
}

tscrypto::tsCryptoData computeHeaderIdentity(std::shared_ptr<ICmsHeader> header)
{
	std::shared_ptr<ICkmOperations> ops = std::dynamic_pointer_cast<ICkmOperations>(header);

	if (!ops)
		return tscrypto::tsCryptoData();
	return ops->ComputeHeaderIdentity();
}

bool CCKMCryptoHelperImpl::PrepareHeader(std::shared_ptr<ICmsHeader> header7, CompressionType comp, TS_ALG_ID algorithm, TS_ALG_ID hashAlgorithm, bool SignHeader, bool bindData,
	CMSFileFormatIds DataFormat, bool randomIvec, SymmetricPaddingType paddingType, int blockSize, int64_t fileSize)
{
	std::shared_ptr<ICkmOperations> ops = std::dynamic_pointer_cast<ICkmOperations>(header7);

	if (!ops)
		return false;
	return ops->PrepareHeader(comp, algorithm, hashAlgorithm, SignHeader, bindData, DataFormat, randomIvec, paddingType, blockSize, fileSize);
}

bool CCKMCryptoHelperImpl::padHeaderToSize(std::shared_ptr<ICmsHeaderBase> header, DWORD size)
{
	std::shared_ptr<ICmsHeader> header7;

	if (!(header7 = std::dynamic_pointer_cast<ICmsHeader>(header)))
		return false;
	return padHeaderToSize(header7, size);
}

bool CCKMCryptoHelperImpl::padHeaderToSize(std::shared_ptr<ICmsHeader>& header, DWORD size)
{
	std::shared_ptr<ICkmOperations> ops = std::dynamic_pointer_cast<ICkmOperations>(header);

	if (!ops)
		return false;
	return ops->padHeaderToSize(size);
}

DWORD   CCKMCryptoHelperImpl::ReservedHeaderLength() const
{
	return m_reservedHeaderLength;
}

WaitableBool CCKMCryptoHelperImpl::ProcessFifoFindHeader(std::shared_ptr<IFifoStream>& fifo)
{
	TSDECLARE_FUNCTIONExt(true);

	tscrypto::tsCryptoData contents;
	std::shared_ptr<tsmod::IObject> iunk;
	int headerLen = 0;

	if (!fifo)
		return TSRETURN_ERROR(("E_POINTER"), wait_false);

	if (m_headerLenNeeded == 0)
	{
		if (!fifo->PeekData(200, contents) || contents.size() < 200)
			return TSRETURN(("true"), wait_true);

		if (!ExtractHeaderLength(contents.c_str(), (int)contents.size(), &m_headerLenNeeded))
			return TSRETURN_ERROR(("Returns ~~"), wait_false);
	}

	if (fifo->RemainingData() < m_headerLenNeeded)
		return TSRETURN(("E_PENDING"), wait_pending);

	if (!fifo->ReadData(m_headerLenNeeded, contents))
	{
		m_fifoState = chs_nonFifo;
		return TSRETURN_ERROR(("false"), wait_false);
	}
	if (!(ExtractHeaderFromStream(contents.c_str(), (int)contents.size(), &headerLen, iunk)) || !(m_cmsHeader = std::dynamic_pointer_cast<ICmsHeader>(iunk)))
	{
		return TSRETURN_ERROR(("Returns ~~"), wait_false);
	}
	if (!!m_decryptCallback)
	{
		if (!(m_decryptCallback->HeaderFound(std::dynamic_pointer_cast<ICmsHeaderBase>(m_cmsHeader))))
		{
			return TSRETURN_ERROR(("Returns ~~"), wait_false);
		}
	}

	m_fifoState = chs_ValidateHeaderDecrypt;
	return TSRETURN(("S_OK"), wait_true);
}

WaitableBool CCKMCryptoHelperImpl::ProcessFifoValidateHeaderDecrypt(std::shared_ptr<IFifoStream>& fifo)
{
	TSDECLARE_FUNCTIONExt(true);

	std::shared_ptr<IDataReader> reader;
	std::shared_ptr<IDataWriter> writer;
	tscrypto::tsCryptoData wk;
	int format = TS_FORMAT_CMS_ENC_AUTH;
	std::shared_ptr<ICmsHeaderBase> headerBase;
	WaitableBool hr;

	if (!(reader = std::dynamic_pointer_cast<IDataReader>(m_reader)) ||
		!(writer = std::dynamic_pointer_cast<IDataWriter>(m_writer)) ||
		!(m_processor = std::dynamic_pointer_cast<IDecryptProcessor>(CreateEncryptProcessor(m_taskCount, m_taskNumber, m_status, reader, writer, m_prependHeader))))
	{
		if (gDebugCryptoHelper) { LOG(DebugError, "Unable to create the decryption processor."); }
		return TSRETURN_ERROR(("Unable to create the decryption processor"), wait_false);
	}

	if (!!m_cmsHeader)
	{
		headerBase = std::dynamic_pointer_cast<ICmsHeaderBase>(m_cmsHeader);
		if (!m_session && m_cmsHeader->NeedsSession())
		{
			if (!!m_sessionCallback)
			{
				if (!(m_sessionCallback->GetSessionForHeader(false, headerBase, 0, m_session)))
				{
					if (gDebugCryptoHelper) { LOG(DebugError, "No session."); }
					return TSRETURN_ERROR(("No session"), wait_false);
				}
			}
		}
	}
	// Regenerate the working key
	if (!m_session)
	{
		if (gDebugCryptoHelper) { LOG(DebugError, "Unable to regenerate the working key and encrypted data."); }
		return TSRETURN_ERROR(("Unable to regenerate the working key and encrypted data."), wait_false);
	}
	else
	{
		std::shared_ptr<ICkmOperations> ops;

		if (!(ops = std::dynamic_pointer_cast<ICkmOperations>(m_cmsHeader)) ||
			!ops->RegenerateWorkingKey(m_session, wk))
		{
			if (gDebugCryptoHelper) { LOG(DebugError, "Unable to regenerate the working key and encrypted data."); }
			return TSRETURN_ERROR(("Unable to regenerate the working key and encrypted data."), wait_false);
		}
	}

	if (!(m_processor->PrevalidateData(headerBase)))
	{
		if (gDebugCryptoHelper) { LOG(DebugError, "The data does not match the data signature."); }
		return TSRETURN_ERROR(("The data does not match the data signature."), wait_false);
	}

	if (!!m_decryptCallback)
	{
		if (!(m_decryptCallback->HeaderVerified(headerBase)))
		{
			return TSRETURN_ERROR(("Returns ~~"), wait_false);
		}
	}

	if (!m_cmsHeader->GetDataFormat(m_chunksize, format))
	{
		m_chunksize = 5000000;
		format = TS_FORMAT_CMS_PT_HASHED;
	}

	switch (format)
	{
	case TS_FORMAT_CMS_CT_HASHED:
		hr = InitializeDecryptCtHashed(fifo, wk);
		break;
	case TS_FORMAT_CMS_PT_HASHED:
		hr = InitializeDecryptPtHashed(fifo, wk);
		break;
	case TS_FORMAT_CMS_ENC_AUTH:
		hr = InitializeDecryptEncAuth(fifo, wk);
		break;
	default:
		LOG(DebugError, "Error:  Unrecognized file format.");
		return TSRETURN_ERROR(("Bad File"), wait_false);
	}
	return TSRETURN(("Returns ~~"), hr);
}

WaitableBool CCKMCryptoHelperImpl::InitializeDecryptCtHashed(std::shared_ptr<IFifoStream>& fifo, const tscrypto::tsCryptoData &wk)
{
	TSDECLARE_FUNCTIONExt(true);

	m_fifoState = chs_ProcessHashedDataDecrypt;
	m_hashPlainText = false;
	return TSRETURN(("Returns ~~"), InitializeDecryptHashed(fifo, wk));
}
WaitableBool CCKMCryptoHelperImpl::InitializeDecryptCtHashed(std::shared_ptr<IFifoStream>& fifo, const tscrypto::tsCryptoData &wk, const tscrypto::tsCryptoData &finalHash,
	const tscrypto::tsCryptoData &hashOid, TS_ALG_ID encAlg, CompressionType compType, const tscrypto::tsCryptoData &authData, const tscrypto::tsCryptoData &ivec, int64_t filesize,
	SymmetricPaddingType paddingType)
{
	TSDECLARE_FUNCTIONExt(true);

	m_fifoState = chs_ProcessHashedDataDecrypt;
	m_hashPlainText = false;
	return TSRETURN(("Returns ~~"), InitializeDecryptHashed(fifo, wk, finalHash, hashOid, encAlg, compType, authData, ivec, filesize, paddingType));
}

WaitableBool CCKMCryptoHelperImpl::InitializeDecryptPtHashed(std::shared_ptr<IFifoStream>& fifo, const tscrypto::tsCryptoData &wk)
{
	TSDECLARE_FUNCTIONExt(true);

	m_fifoState = chs_ProcessHashedDataDecrypt;
	m_hashPlainText = true;
	return TSRETURN(("Returns ~~"), InitializeDecryptHashed(fifo, wk));
}
WaitableBool CCKMCryptoHelperImpl::InitializeDecryptPtHashed(std::shared_ptr<IFifoStream>& fifo, const tscrypto::tsCryptoData &wk, const tscrypto::tsCryptoData &finalHash,
	const tscrypto::tsCryptoData &hashOid, TS_ALG_ID encAlg, CompressionType compType, const tscrypto::tsCryptoData &authData, const tscrypto::tsCryptoData &ivec, int64_t filesize,
	SymmetricPaddingType paddingType)
{
	TSDECLARE_FUNCTIONExt(true);

	m_fifoState = chs_ProcessHashedDataDecrypt;
	m_hashPlainText = true;
	return TSRETURN(("Returns ~~"), InitializeDecryptHashed(fifo, wk, finalHash, hashOid, encAlg, compType, authData, ivec, filesize, paddingType));
}

WaitableBool CCKMCryptoHelperImpl::InitializeDecryptHashed(std::shared_ptr<IFifoStream>& fifo, const tscrypto::tsCryptoData &wk)
{
	int64_t filesize;
	tscrypto::tsCryptoData finalHash;
	tscrypto::tsCryptoData hashOid;
	TS_ALG_ID encAlg;
	CompressionType compType;
	tscrypto::tsCryptoData authData;
	tscrypto::tsCryptoData ivec;
	SymmetricPaddingType paddingType;

	filesize = (int64_t)m_cmsHeader->GetFileLength();
	finalHash = m_cmsHeader->GetDataHash();
	if (finalHash.size() != 0)
	{
		hashOid = m_cmsHeader->GetDataHashOID();
	}

	encAlg = m_cmsHeader->GetEncryptionAlgorithmID();
	compType = m_cmsHeader->GetCompressionType();
	authData = ComputeHeaderIdentity(m_cmsHeader);
	ivec = m_cmsHeader->GetIVEC();
	paddingType = m_cmsHeader->GetPaddingType();
	return InitializeDecryptHashed(fifo, wk, finalHash, hashOid, encAlg, compType, authData, ivec, filesize, paddingType);
}
WaitableBool CCKMCryptoHelperImpl::InitializeDecryptHashed(std::shared_ptr<IFifoStream>& fifo, const tscrypto::tsCryptoData &wk, const tscrypto::tsCryptoData &finalHash,
	const tscrypto::tsCryptoData &hashOid, TS_ALG_ID encAlg, CompressionType compType, const tscrypto::tsCryptoData &authData, const tscrypto::tsCryptoData &ivec, int64_t filesize,
	SymmetricPaddingType paddingType)
{
	TSDECLARE_FUNCTIONExt(true);

	size_t encKeySize = 0;
	size_t ivecSize = 0;
	size_t encBlocksize = 0;
	tscrypto::tsCryptoData encKey;
	tscrypto::tsCryptoData workingKey(wk);

	MY_UNREFERENCED_PARAMETER(fifo);

	m_finalHash = finalHash;
	m_fileSize = filesize;
	m_hasFileSize = (m_fileSize > 0);

	if (finalHash.size() != 0)
	{
		if (!(m_fifoHasher = std::dynamic_pointer_cast<MessageAuthenticationCode>(CryptoFactory(hashOid.ToOIDString()))))
			return TSRETURN_ERROR(("Unable to create the data hash algorithm."), wait_false);
	}

	SymmetricMode encMode = Alg2Mode(encAlg);

	if (!(m_symEnc = std::dynamic_pointer_cast<Symmetric>(CryptoFactory(encAlg))))
	{
		LOG(DebugError, "Unable to create the required data encryption algorithm.");
		return TSRETURN_ERROR(("Unable to create the required data encryption algorithm."), wait_false);
	}

	encKeySize = CryptoKeySize(encAlg);
	ivecSize = CryptoIVECSize(encAlg);
	encBlocksize = CryptoBlockSize(encAlg);

	if (encKeySize == 0 || encBlocksize == 0)
	{
		LOG(DebugError, "Unable to retrieve the required data encryption algorithm parameters.");
		return TSRETURN_ERROR(("Unable to retrieve the required data encryption algorithm parameters."), wait_false);
	}

	if ((int)(workingKey.size() * 8) < encKeySize)
	{
		LOG(DebugError, "The encryption key is too short.");
		return TSRETURN_ERROR(("The encryption key is too short."), wait_false);
	}

	switch (compType)
	{
	case ct_BZ2:
	case ct_zLib:
		if (!(m_compressor = CreateCompressor(compType)))
		{
			LOG(DebugError, "The compression type is not recognized.");
			return TSRETURN_ERROR(("The compression type is not recognized."), wait_false);
		}
		break;
	case ct_None:
		break;
	default:
		LOG(DebugError, "The compression type is not recognized.");
		return TSRETURN_ERROR(("The compression type is not recognized."), wait_false);
	}
	encKey.assign(workingKey.c_str(), encKeySize / 8);
	workingKey.erase(0, encKey.size());

	if (!!m_fifoHasher)
	{
		tscrypto::tsCryptoData macKey;

		m_authHeader = authData;

		if (m_fifoHasher->requiresKey())
		{
			int maxKeySize = (int)m_fifoHasher->maximumKeySizeInBits();

			if (maxKeySize < 0 || maxKeySize > 65535 || (size_t)maxKeySize > encKeySize)
				maxKeySize = (int)encKeySize;

			if ((int)(workingKey.size() * 8) < maxKeySize)
			{
				LOG(DebugError, "The encryption key is too short.");
				return TSRETURN_ERROR(("The encryption key is too short."), wait_false);
			}

			macKey.assign(workingKey.c_str(), maxKeySize / 8);
			workingKey.erase(0, macKey.size());
		}
		if (!m_fifoHasher->initialize(macKey) || !m_fifoHasher->update(m_authHeader))
		{
			LOG(DebugError, "Unable to create the required data hash algorithm.");
			return TSRETURN_ERROR(("Unable to create the required data hash algorithm"), wait_false);
		}
		macKey.clear();
	}

	if (ivecSize > 0)
	{
		m_encIvec = ivec;

		if (m_encIvec.size() == 0)
		{
			// IVEC comes from the working key.
			if ((int)(workingKey.size()) < ivecSize)
			{
				LOG(DebugError, "The encryption key is too short.");
				return TSRETURN_ERROR(("The encryption key is too short."), wait_false);
			}

			m_encIvec.assign(workingKey.c_str(), ivecSize);
			workingKey.erase(0, m_encIvec.size());
		}
	}

	// Each block is treated as a new encryption (new ivec, same key).  We only need to initialize once.
	if (!m_symEnc->init(false, encMode, encKey, m_encIvec))
	{
		LOG(DebugError, "Unable to initialize the bulk data encryptor.");
		return TSRETURN_ERROR(("Unable to initialize the bulk data encryptor."), wait_false);
	}

	m_counter.resize(4);

	m_symEnc->setPaddingType(paddingType);

	if (!!m_compressor)
	{
		if (!(m_compressor->DecompressInit()))
		{
			LOG(DebugError, "Unable to decrypt the file.  The decompression operation failed.");
			return TSRETURN_ERROR(("FAILED"), wait_false);
		}
	}
	m_fifoState = chs_ProcessHashedDataDecrypt;
	return TSRETURN(("S_OK"), wait_true);
}

WaitableBool CCKMCryptoHelperImpl::ProcessFifoProcessHashedDataDecrypt(std::shared_ptr<IFifoStream>& fifo)
{
	TSDECLARE_FUNCTIONExt(true);

	int percent;

	for (;;)
	{
		if (!!m_status)
		{
			if (m_hasFileSize)
				percent = (int)((100 * m_writer->CurrentPosition()) / m_fileSize);
			else
				percent = (int)((100 * m_writer->CurrentPosition()) / (m_writer->CurrentPosition() + m_chunksize));

			if (percent != m_oldPercent)
			{
				tscrypto::tsCryptoString task;

				task << "Decrypt";

				if (!(m_status->Status(task.c_str(), m_taskNumber, m_taskCount, percent)))
				{
					LOG(DebugError, "Operation cancelled");
					return TSRETURN_ERROR(("Cancelled"), wait_false);
				}
				m_oldPercent = percent;
			}
		}

		if (fifo->IsWriterFinished() || fifo->RemainingData() >= m_chunksize)
		{
			if (!fifo->ReadData(m_chunksize, m_tmp))
			{
				LOG(DebugError, "Data format invalid.");
				return TSRETURN_ERROR(("Data format invalid."), wait_false);
			}
		}
		else if (!fifo->IsWriterFinished())
		{
			return TSRETURN(("E_PENDING"), wait_pending);
		}
		if (m_tmp.size() == 0 && fifo->IsEndOfFile())
		{
			m_fifoState = chs_FinishDecryptHashed;
			return TSRETURN(("S_OK"), wait_true);
		}

		if (!!m_fifoHasher && !m_hashPlainText)
		{
			if (!m_fifoHasher->update(m_tmp))
			{
				LOG(DebugError, "Unable to compute the data hash.");
				return TSRETURN_ERROR(("Unable to compute the data hash."), wait_false);
			}
		}

		if (m_tmp.size() <= 0)
		{
			LOG(DebugError, "Data format invalid.");
			return TSRETURN_ERROR(("Data format invalid."), wait_false);
		}

		if (!m_symEnc->update(m_tmp, m_tmp))
		{
			LOG(DebugError, "Unable to decrypt the file.  The decryption operation failed.");
			return TSRETURN_ERROR(("FAILED"), wait_false);
		}

		if (!!m_compressor)
		{
			if (!(m_compressor->Decompress(m_tmp, m_tmp2, compAct_Run)))
			{
				LOG(DebugError, "Unable to decrypt the file.  The decompression operation failed.");
				return TSRETURN_ERROR(("FAILED"), wait_false);
			}
			m_tmp = m_tmp2;
		}
		if (m_tmp.size() > 0)
		{
			if (!!m_fifoHasher && m_hashPlainText)
			{
				if (!m_fifoHasher->update(m_tmp))
				{
					LOG(DebugError, "Unable to compute the data hash.");
					return TSRETURN_ERROR(("Unable to compute the data hash."), wait_false);
				}
			}

			LOG(DebugInfo3, "Writing " << m_tmp.size() << " bytes of data to the output file");

			if (!m_writer->WriteData(m_tmp))
			{
				LOG(DebugError, "Unable to write the decrypted data into the output file.");
				return TSRETURN_ERROR(("FAILED"), wait_false);
			}
		}
	}
}

WaitableBool CCKMCryptoHelperImpl::ProcessFifoFinishDecryptHashed(std::shared_ptr<IFifoStream>& fifo)
{
	MY_UNREFERENCED_PARAMETER(fifo);

	TSDECLARE_FUNCTIONExt(true);

	m_fifoState = chs_Shutdown;
	if (!!m_status)
	{
		tscrypto::tsCryptoString task;

		task << "Decrypt";

		if (!(m_status->Status(task.c_str(), m_taskNumber, m_taskCount, 100)))
		{
			LOG(DebugError, "Operation cancelled");
			return TSRETURN_ERROR(("Cancelled"), wait_false);
		}
	}

	if (!m_symEnc->finish(m_tmp))
	{
		LOG(DebugError, "Unable to decrypt the file.  The decryption operation could not finish.");
		return TSRETURN_ERROR(("FAILED"), wait_false);
	}
	if (!!m_compressor)
	{
		m_tmp2.clear();
		if (m_tmp.size() > 0)
		{
			if (!(m_compressor->Decompress(m_tmp, m_tmp2, compAct_Run)))
			{
				LOG(DebugError, "Unable to decrypt the file.  The decompression operation failed.");
				return TSRETURN_ERROR(("FAILED"), wait_false);
			}
		}
		m_tmp.clear();
		if (!(m_compressor->DecompressFinal(m_tmp)))
		{
			LOG(DebugError, "Unable to decrypt the file.  The decompression operation failed.");
			return TSRETURN_ERROR(("FAILED"), wait_false);
		}
		m_tmp.insert(0, m_tmp2);
	}
	if (m_tmp.size() > 0)
	{
		if (!!m_fifoHasher && m_hashPlainText)
		{
			if (!m_fifoHasher->update(m_tmp))
			{
				LOG(DebugError, "Unable to compute the data hash.");
				return TSRETURN_ERROR(("Unable to compute the data hash."), wait_false);
			}
		}

		LOG(DebugInfo3, "Writing " << m_tmp.size() << " bytes of data to the output file");

		if (!m_writer->WriteData(m_tmp))
		{
			LOG(DebugError, "Unable to write the decrypted data into the output file.");
			return TSRETURN_ERROR(("FAILED"), wait_false);
		}
	}

	if (!!m_fifoHasher)
	{
		if (!m_fifoHasher->finish(m_tmp))
		{
			LOG(DebugError, "Unable to compute the data hash.");
			return TSRETURN_ERROR(("Unable to compute the data hash."), wait_false);
		}

		if (m_tmp.compare(m_finalHash) != 0)
		{
			LOG(DebugError, "Unable to decrypt the file - data hash invalid.");
			return TSRETURN_ERROR(("Unable to decrypt the file - data hash invalid"), wait_false);
		}
	}
	return TSRETURN(("OK"), wait_true);
}

WaitableBool CCKMCryptoHelperImpl::InitializeDecryptEncAuth(std::shared_ptr<IFifoStream>& fifo, const tscrypto::tsCryptoData &wk)
{
	int64_t filesize;
	tscrypto::tsCryptoData finalHash;
	tscrypto::tsCryptoData hashOid;
	TS_ALG_ID encAlg;
	CompressionType compType;
	tscrypto::tsCryptoData authData;
	tscrypto::tsCryptoData ivec;
	SymmetricPaddingType paddingType;

	filesize = (int64_t)m_cmsHeader->GetFileLength();
	finalHash = m_cmsHeader->GetDataHash();
	if (finalHash.size() != 0)
	{
		hashOid = m_cmsHeader->GetDataHashOID();
	}

	encAlg = m_cmsHeader->GetEncryptionAlgorithmID();
	compType = m_cmsHeader->GetCompressionType();
	authData = ComputeHeaderIdentity(m_cmsHeader);
	ivec = m_cmsHeader->GetIVEC();
	paddingType = m_cmsHeader->GetPaddingType();
	return InitializeDecryptEncAuth(fifo, wk, finalHash, hashOid, encAlg, compType, authData, ivec, filesize, paddingType);
}
WaitableBool CCKMCryptoHelperImpl::InitializeDecryptEncAuth(std::shared_ptr<IFifoStream>& fifo, const tscrypto::tsCryptoData &wk, const tscrypto::tsCryptoData &finalHash,
	const tscrypto::tsCryptoData &hashOid, TS_ALG_ID encAlg, CompressionType compType, const tscrypto::tsCryptoData &authData, const tscrypto::tsCryptoData &ivec, int64_t filesize,
	SymmetricPaddingType paddingType)
{
	MY_UNREFERENCED_PARAMETER(paddingType);
	MY_UNREFERENCED_PARAMETER(fifo);

	TSDECLARE_FUNCTIONExt(true);

	size_t encKeySize, ivecSize, encBlocksize;
	tscrypto::tsCryptoData workingKey(wk);
	tscrypto::tsCryptoData encKey;

	m_finalHash = finalHash;
	m_fileSize = filesize;
	m_hasFileSize = (m_fileSize > 0);

	if (finalHash.size() != 0)
	{
		if (!(m_fifoHasher = std::dynamic_pointer_cast<MessageAuthenticationCode>(CryptoFactory(hashOid.ToOIDString()))))
			return TSRETURN_ERROR(("Unable to create the data hash algorithm."), wait_false);
	}

	SymmetricMode encMode = Alg2Mode(encAlg);

	if (!(m_kdf = std::dynamic_pointer_cast<KeyDerivationFunction>(CryptoFactory("KDF-SHA512"))))
	{
		LOG(DebugError, "The specified encryption file format requires the use of a key derivation function that is not available.");
		return TSRETURN_ERROR(("The specified encryption file format requires the use of a key derivation function that is not available."), wait_false);
	}

	switch (encMode)
	{
	case _SymmetricMode::CKM_SymMode_CCM:
	case _SymmetricMode::CKM_SymMode_GCM:
		if (!(m_gcm = std::dynamic_pointer_cast<CCM_GCM>(CryptoFactory(encAlg))))
		{
			LOG(DebugError, "Unable to create the required data encryption algorithm.");
			return TSRETURN_ERROR(("Unable to create the required data encryption algorithm."), wait_false);
		}
		break;
	default:
		LOG(DebugError, "The specified encryption file format requires the use of an authenticated encryption mode.");
		return TSRETURN_ERROR(("The specified encryption file format requires the use of an authenticated encryption mode."), wait_false);
	}


	encKeySize = CryptoKeySize(encAlg);
	ivecSize = CryptoIVECSize(encAlg);
	encBlocksize = CryptoBlockSize(encAlg);

	if (encKeySize == 0 || encBlocksize == 0)
	{
		LOG(DebugError, "Unable to retrieve the required data encryption algorithm parameters.");
		return TSRETURN_ERROR(("Unable to retrieve the required data encryption algorithm parameters."), wait_false);
	}

	if ((int)(workingKey.size() * 8) < encKeySize)
	{
		LOG(DebugError, "The encryption key is too short.");
		return TSRETURN_ERROR(("The encryption key is too short."), wait_false);
	}

	switch (compType)
	{
	case ct_BZ2:
	case ct_zLib:
		if (!(m_compressor = CreateCompressor(compType)))
		{
			LOG(DebugError, "The compression type is not recognized.");
			return TSRETURN_ERROR(("The compression type is not recognized."), wait_false);
		}
		break;
	case ct_None:
		break;
	default:
		LOG(DebugError, "The compression type is not recognized.");
		return TSRETURN_ERROR(("The compression type is not recognized."), wait_false);
	}
	encKey.assign(workingKey.c_str(), encKeySize / 8);
	workingKey.erase(0, encKey.size());

	m_authHeader = authData;

	if (!!m_fifoHasher)
	{
		tscrypto::tsCryptoData macKey;

		if (m_fifoHasher->requiresKey())
		{
			int maxKeySize = (int)m_fifoHasher->maximumKeySizeInBits();

			if (maxKeySize < 0 || maxKeySize > 65535 || (size_t)maxKeySize > encKeySize)
				maxKeySize = (int)encKeySize;

			if ((int)(workingKey.size() * 8) < maxKeySize)
			{
				LOG(DebugError, "The encryption key is too short.");
				return TSRETURN_ERROR(("The encryption key is too short."), wait_false);
			}

			macKey.assign(workingKey.c_str(), maxKeySize / 8);
			workingKey.erase(0, macKey.size());
		}
		if (!m_fifoHasher->initialize(macKey))
		{
			LOG(DebugError, "Unable to create the required data hash algorithm.");
			return TSRETURN_ERROR(("Unable to create the required data hash algorithm"), wait_false);
		}
		macKey.clear();
	}

	if (ivecSize > 0)
	{
		m_encIvec = ivec;

		if (m_encIvec.size() == 0)
		{
			// IVEC comes from the working key.
			if ((int)(workingKey.size()) < ivecSize)
			{
				LOG(DebugError, "The encryption key is too short.");
				return TSRETURN_ERROR(("The encryption key is too short."), wait_false);
			}

			m_encIvec.assign(workingKey.c_str(), ivecSize);
			workingKey.erase(0, m_encIvec.size());
		}
	}

	m_encIvec += encKey;

	m_counter.resize(4);

	m_fifoState = chs_ProcessEncAuthLengthDecrypt;
	return TSRETURN(("true"), wait_true);
}

WaitableBool CCKMCryptoHelperImpl::ProcessFifoProcessEncAuthLengthDecrypt(std::shared_ptr<IFifoStream>& fifo)
{
	TSDECLARE_FUNCTIONExt(true);

	tscrypto::tsCryptoData len;

	if (fifo->IsEndOfFile())
	{
		m_fifoState = chs_FinishDecryptEncAuth;
		return TSRETURN(("true"), wait_true);
	}

	if (fifo->RemainingData() < 4)
	{
		if (fifo->IsWriterFinished())
			return TSRETURN(("false - wrong length"), wait_false);
		return TSRETURN(("E_PENDING"), wait_pending);
	}

	if (!fifo->ReadData(4, len) || len.size() != 4)
	{
		return TSRETURN(("false - read failure"), wait_false);
	}
	if (!!m_fifoHasher)
	{
		if (!m_fifoHasher->update(len))
		{
			LOG(DebugError, "Unable to compute the data hash.");
			return TSRETURN_ERROR(("Unable to compute the data hash."), wait_false);
		}
	}

#if (BYTE_ORDER == LITTLE_ENDIAN)
	len.reverse();
#endif
	m_chunksize = *(int *)len.c_str();

	if (m_chunksize < 17)
	{
		LOG(DebugError, "The file format is incorrect.");
		return TSRETURN_ERROR(("The file format is incorrect."), wait_false);
	}

	m_fifoState = chs_ProcessEncAuthBlockDecrypt;

	return TSRETURN(("true"), wait_true);
}

WaitableBool CCKMCryptoHelperImpl::ProcessFifoProcessEncAuthBlockDecrypt(std::shared_ptr<IFifoStream > & fifo)
{
	TSDECLARE_FUNCTIONExt(true);

	int percent;
	bool hr;
	tscrypto::tsCryptoData tag;
	tscrypto::tsCryptoData ivec;

	if (fifo->RemainingData() < m_chunksize)
	{
		if (fifo->IsWriterFinished())
			return TSRETURN(("false - wrong length"), wait_false);
		return TSRETURN(("E_PENDING"), wait_pending);
	}

	if (!!m_status)
	{
		if (m_hasFileSize)
			percent = (int)((100 * m_writer->CurrentPosition()) / m_fileSize);
		else
			percent = (int)((100 * m_writer->CurrentPosition()) / (m_writer->CurrentPosition() + m_chunksize));

		if (percent != m_oldPercent && !!m_status)
		{
			tscrypto::tsCryptoString task;

			task << "Decrypt";

			if (!(m_status->Status(task.c_str(), m_taskNumber, m_taskCount, percent)))
			{
				LOG(DebugError, "Operation cancelled");
				return TSRETURN_ERROR(("Cancelled"), wait_false);
			}
			m_oldPercent = percent;
		}
	}

	if (!fifo->ReadData(m_chunksize, m_tmp))
	{
		LOG(DebugError, "Data format invalid.");
		return TSRETURN_ERROR(("Data format invalid."), wait_false);
	}
	tag.assign(&m_tmp.c_str()[m_tmp.size() - 16], 16);
	m_tmp.resize(m_tmp.size() - 16);

	if (!!m_fifoHasher && !m_fifoHasher->update(tag))
	{
		LOG(DebugError, "Unable to compute the data hash.");
		return TSRETURN_ERROR(("Unable to compute the data hash."), wait_false);
	}

	// Each block is treated as a new encryption (new ivec, same key).  Compute the new ivec here
	m_counter.increment();
	if (!m_kdf->Derive_SP800_56A_Counter(m_encIvec, m_counter, 256 + 96, ivec))
	{
		LOG(DebugError, "The decryption key is too short.");
		return TSRETURN_ERROR(("The decryption key is too short."), wait_false);
	}
	// Each block is treated as a new encryption (new ivec, new key).
	if (!m_gcm->initialize(ivec.substring(0, 32)))
	{
		LOG(DebugError, "Unable to initialize the bulk data encryptor.");
		return TSRETURN_ERROR(("Unable to initialize the bulk data encryptor."), wait_false);
	}
	ivec.erase(0, 32);
	if (!m_gcm->decryptMessage(ivec, m_authHeader, m_tmp, tag))
	{
		LOG(DebugError, "Unable to decrypt the file.  The tag does not match the computed value.");
		return TSRETURN_ERROR(("FAILED"), wait_false);
	}

	if (!!m_compressor)
	{
		if (!(hr = m_compressor->DecompressInit()) ||
			!(hr = m_compressor->Decompress(m_tmp, m_tmp2, compAct_Run)) ||
			!(hr = m_compressor->DecompressFinal(m_tmp)))
		{
			LOG(DebugError, "Unable to decrypt the file.  The decompression operation failed.");
			return TSRETURN_ERROR(("FAILED"), wait_false);
		}
		m_tmp.insert(0, m_tmp2);
	}
	if (m_tmp.size() > 0)
	{
		LOG(DebugInfo3, "Writing " << m_tmp.size() << " bytes of data to the output file");

		if (!m_writer->WriteData(m_tmp))
		{
			LOG(DebugError, "Unable to write the decrypted data into the output file.");
			return TSRETURN_ERROR(("FAILED"), wait_false);
		}
	}
	m_fifoState = chs_ProcessEncAuthLengthDecrypt;
	return TSRETURN(("true"), wait_true);
}


WaitableBool CCKMCryptoHelperImpl::ProcessFifoFinishDecryptEncAuth(std::shared_ptr<IFifoStream>& fifo)
{
	MY_UNREFERENCED_PARAMETER(fifo);

	TSDECLARE_FUNCTIONExt(true);

	if (!!m_status)
	{
		tscrypto::tsCryptoString task;

		task << "Decrypt";

		if (!(m_status->Status(task.c_str(), m_taskNumber, m_taskCount, 100)))
		{
			LOG(DebugError, "Operation cancelled");
			return TSRETURN_ERROR(("Cancelled"), wait_false);
		}
	}

	if (!!m_fifoHasher)
	{
		if (!m_fifoHasher->finish(m_tmp))
		{
			LOG(DebugError, "Unable to compute the data hash.");
			return TSRETURN_ERROR(("Unable to compute the data hash."), wait_false);
		}

		if (m_tmp.compare(m_finalHash) != 0)
		{
			LOG(DebugError, "Unable to decrypt the file - data hash invalid.");
			return TSRETURN_ERROR(("Unable to decrypt the file - data hash invalid"), wait_false);
		}
	}
	m_fifoState = chs_Shutdown;
	return TSRETURN(("OK"), wait_true);
}

bool CCKMCryptoHelperImpl::DataAvailable(std::shared_ptr<IFifoStream> fifo)
{
	TSDECLARE_FUNCTIONExt(true);

	WaitableBool hr;

	for (;;)
	{
		switch (m_fifoState)
		{
		case chs_nonFifo:
		default:
			return false;
		case chs_FindHeader:
			hr = ProcessFifoFindHeader(fifo);
			break;
		case chs_ValidateHeaderDecrypt:
			hr = ProcessFifoValidateHeaderDecrypt(fifo);
			break;
		case chs_FinishDecryptHashed:
			hr = ProcessFifoFinishDecryptHashed(fifo);
			break;
		case chs_FinishDecryptEncAuth:
			hr = ProcessFifoFinishDecryptEncAuth(fifo);
			break;
		case chs_ProcessEncAuthBlockDecrypt:
			hr = ProcessFifoProcessEncAuthBlockDecrypt(fifo);
			break;
		case chs_ProcessEncAuthLengthDecrypt:
			hr = ProcessFifoProcessEncAuthLengthDecrypt(fifo);
			break;
		case chs_ProcessHashedDataDecrypt:
			hr = ProcessFifoProcessHashedDataDecrypt(fifo);
			break;
		}
		if (hr == wait_pending)
			return TSRETURN(("true"), true);
		if (!(hr))
		{
			ClearFifoVariables();
			return TSRETURN(("Returns ~~"), hr == wait_true);
		}
		if (m_fifoState == chs_Shutdown)
		{
			if (fifo->IsEndOfFile())
			{
				std::shared_ptr<IFifoStream> wFifo;

				if (!!(wFifo = std::dynamic_pointer_cast<IFifoStream>(m_writer)))
				{
					wFifo->WriterDone();
				}
				ClearFifoVariables();
				return TSRETURN(("true"), true);
			}
			return TSRETURN(("false"), false);
		}
	}
}

void CCKMCryptoHelperImpl::ClearFifoVariables()
{
	m_reader.reset();
	m_writer.reset();
	m_processor.reset();
	m_prependHeader = false;
	m_hashPlainText = false;
	m_cmsHeader.reset();

	m_tmp.clear();
	m_tmp2.clear();
	m_hasher.reset();
	m_symEnc.reset();
	m_compressor.reset();
	//    tscrypto::tsCryptoData encKey, macKey, encIvec, ivec, counter, authHeader, tag;
	m_fileSize = 0;
	m_hasFileSize = false;
	m_oldPercent = -1;
	m_authHeader.clear();
	m_finalHash.clear();
	m_encIvec.clear();
	m_counter.clear();
	m_chunksize = 0;

	m_gcm.reset();
	m_kdf.reset();
}

bool CCKMCryptoHelperImpl::SetDecryptCallback(std::shared_ptr<ICryptoHelperDecryptCallback> setTo)
{
	m_decryptCallback.reset();
	m_decryptCallback = setTo;
	return true;
}

bool CCKMCryptoHelperImpl::GenerateWorkingKey(std::shared_ptr<ICmsHeader>& header, std::shared_ptr<IKeyGenCallback> callback, tscrypto::tsCryptoData& workingKey)
{
	std::shared_ptr<ICkmOperations> ops = std::dynamic_pointer_cast<ICkmOperations>(header);

	if (!ops)
		return false;
	return ops->GenerateWorkingKey(m_session, callback, workingKey);
}
bool CCKMCryptoHelperImpl::RegenerateWorkingKey(std::shared_ptr<ICmsHeader>& header, tscrypto::tsCryptoData& workingKey)
{
	std::shared_ptr<ICkmOperations> ops = std::dynamic_pointer_cast<ICkmOperations>(header);

	if (!ops)
		return false;
	return ops->RegenerateWorkingKey(m_session, workingKey);
}

