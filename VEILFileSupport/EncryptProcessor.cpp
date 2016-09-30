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

//#define HEADER_SIZE_MULTIPLE 384
//#define HEADER_SIZE_FUDGE    260
#define HEADER_SIZE_MULTIPLE 512
#define HEADER_SIZE_FUDGE    450

class EncryptProcessor : public IKeyGenCallback, public IDecryptProcessor, public IFifoStreamReaderCallback, public tsmod::IObject, public IEncryptProcessor
{
public:
	EncryptProcessor(DWORD taskCount, DWORD currentTask, std::shared_ptr<IFileVEILOperationStatus> status, std::shared_ptr<IDataReader> reader, std::shared_ptr<IDataWriter> writer, bool prependHeader);
	virtual ~EncryptProcessor();

	// IKeyGenCallback
	virtual bool FinishHeader(const tscrypto::tsCryptoData &key, std::shared_ptr<ICmsHeaderBase> header);
	virtual bool SetNextCallback(std::shared_ptr<IKeyGenCallback> callback);

	virtual bool EncryptUsingKey(const tscrypto::tsCryptoData &key, int format, int blocksize, tscrypto::TS_ALG_ID encryptionAlg, const tscrypto::tsCryptoData &hashOid, CompressionType compType,
		const tscrypto::tsCryptoData &ivec, tscrypto::SymmetricPaddingType padding, const tscrypto::tsCryptoData &authData, tscrypto::tsCryptoData &finalHash);

	int ReservedHeaderLength() const { return m_headerLen; }

	// IDecryptProcessor
	virtual bool PrevalidateData(std::shared_ptr<ICmsHeaderBase> header);
	virtual bool DecryptData(const tscrypto::tsCryptoData &key, std::shared_ptr<ICmsHeaderBase>& header);
	virtual bool PrevalidateDataHash(const tscrypto::tsCryptoData &finalHash, const tscrypto::tsCryptoData &hashOid, const tscrypto::tsCryptoData &authData, int format);
	virtual bool DecryptUsingKey(const tscrypto::tsCryptoData &key, int format, int blocksize, tscrypto::TS_ALG_ID encryptionAlg, const tscrypto::tsCryptoData &hashOid, CompressionType compType,
		const tscrypto::tsCryptoData &ivec, tscrypto::SymmetricPaddingType padding,
		const tscrypto::tsCryptoData &authData, const tscrypto::tsCryptoData &finalHash);

	// IFifoStreamCallback
	virtual bool DataAvailable(std::shared_ptr<IFifoStream> reader);

protected:
	void LogError(tscrypto::tsCryptoString error, ...);
	bool ProcessHashed(const tscrypto::tsCryptoData &key, std::shared_ptr<ICmsHeader> header7, int blocksize, bool hashPlainText, std::shared_ptr<IFifoStream> fifo);
	bool ProcessHashed(const tscrypto::tsCryptoData &key, int blocksize, bool hashPlainText, std::shared_ptr<IFifoStream> fifo, tscrypto::TS_ALG_ID encryptionAlg, const tscrypto::tsCryptoData &hashOid, CompressionType compType, const tscrypto::tsCryptoData &ivec, tscrypto::SymmetricPaddingType padding, const tscrypto::tsCryptoData &authData, tscrypto::tsCryptoData &finalHash);
	bool ProcessEncAuthHashed(const tscrypto::tsCryptoData &key, std::shared_ptr<ICmsHeader> header7, int blocksize, std::shared_ptr<IFifoStream> fifo);
	bool ProcessEncAuthHashed(const tscrypto::tsCryptoData &key, int blocksize, std::shared_ptr<IFifoStream> fifo, tscrypto::TS_ALG_ID encryptionAlg, const tscrypto::tsCryptoData &hashOid, CompressionType compType, const tscrypto::tsCryptoData &ivec, tscrypto::SymmetricPaddingType padding, const tscrypto::tsCryptoData &authData, tscrypto::tsCryptoData &finalHash);
	bool ValidateEncAuthFormat(std::shared_ptr<ICmsHeader> header, int64_t headerSize, int64_t fileSize);
	bool ValidateHashedFormat(std::shared_ptr<ICmsHeader> header, int64_t headerSize, int64_t fileSize, bool plaintext);
	bool ValidateEncAuthFormat(const tscrypto::tsCryptoData &finalhash, const tscrypto::tsCryptoData &hashOid, const tscrypto::tsCryptoData &authData, int64_t fileSize);
	bool ValidateHashedFormat(const tscrypto::tsCryptoData &finalhash, const tscrypto::tsCryptoData &hashOid, const tscrypto::tsCryptoData &authData, int64_t fileSize, bool plaintext);
	bool DecryptEncAuthData(const tscrypto::tsCryptoData &key, std::shared_ptr<ICmsHeader> header, int headerSize, int blocksize, std::shared_ptr<IFifoStream> fifo);
	bool DecryptEncAuthData(const tscrypto::tsCryptoData &key, int blocksize, std::shared_ptr<IFifoStream> fifo,
		tscrypto::TS_ALG_ID encAlg, const tscrypto::tsCryptoData &hashOid, CompressionType compType, const tscrypto::tsCryptoData &ivec, tscrypto::SymmetricPaddingType padding, const tscrypto::tsCryptoData &authData, const tscrypto::tsCryptoData &finalHash);
	bool DecryptHashed(const tscrypto::tsCryptoData &key, std::shared_ptr<ICmsHeader> header, int headerSize, int blocksize, bool hashPlainText, std::shared_ptr<IFifoStream> fifo);
	bool DecryptHashed(const tscrypto::tsCryptoData &key, int blocksize, bool hashPlainText, std::shared_ptr<IFifoStream> fifo, tscrypto::TS_ALG_ID encryptionAlg, const tscrypto::tsCryptoData &hashOid, CompressionType compType, const tscrypto::tsCryptoData &ivec, tscrypto::SymmetricPaddingType padding, const tscrypto::tsCryptoData &authData, const tscrypto::tsCryptoData &finalHash);

	bool DecryptEncAuthPart(std::shared_ptr<IFifoStream> fifo);
	bool DecryptHashedPart(std::shared_ptr<IFifoStream> fifo);
	bool EncryptEncAuthPart(std::shared_ptr<IFifoStream> fifo);
	bool EncryptHashedPart(std::shared_ptr<IFifoStream> fifo);
	void ClearStreamVariables();

private:
	std::shared_ptr<IDataReader> m_reader;
	std::shared_ptr<IDataWriter> m_writer;
	std::shared_ptr<IFileVEILOperationStatus> m_status;
	std::shared_ptr<IKeyGenCallback> m_nextCallback;
	const DWORD                                        m_taskCount;
	const DWORD                                        m_currentTask;
	int m_headerLen;
	bool m_prependHeader;

	// BEGIN - Stream callback variables
	bool m_processingEncrypt;
	CMSFileFormatIds m_format;
	std::shared_ptr<tscrypto::MessageAuthenticationCode> m_hasher;
	std::shared_ptr<ICompression> m_compressor;
	int64_t m_fileSize;
	bool m_hasFileSize;
	int m_blocksize;
	int m_oldPercent;
	int m_nextLen;
	tscrypto::tsCryptoData m_workingBuffer;
	tscrypto::tsCryptoData m_workingBuffer2;
	tscrypto::tsCryptoString m_taskName;
	// GCM parts
	std::shared_ptr<tscrypto::CCM_GCM> m_gcm;
	std::shared_ptr<tscrypto::KeyDerivationFunction> m_kdf;
	tscrypto::tsCryptoData m_counter;
	tscrypto::tsCryptoData m_encIvec;
	tscrypto::tsCryptoData m_authHeader;
	// SYM parts
	std::shared_ptr<tscrypto::Symmetric> m_enc;
	bool m_hashPlainText;
	// END - Stream callback variables

    EncryptProcessor& operator=(const EncryptProcessor&) = delete;
};

std::shared_ptr<IKeyGenCallback> CreateEncryptProcessor(DWORD taskCount, DWORD currentTask, std::shared_ptr<IFileVEILOperationStatus> status, std::shared_ptr<IDataReader> reader, std::shared_ptr<IDataWriter> writer, bool prependHeader)
{
	return ::TopServiceLocator()->Finish<IKeyGenCallback>(new EncryptProcessor(taskCount, currentTask, status, reader, writer, prependHeader));
}

EncryptProcessor::EncryptProcessor(DWORD taskCount, DWORD currentTask, std::shared_ptr<IFileVEILOperationStatus> status, std::shared_ptr<IDataReader> reader, std::shared_ptr<IDataWriter> writer,
	bool prependHeader)
	:
	m_reader(reader),
	m_writer(writer),
	m_status(status),
	m_taskCount(taskCount),
	m_currentTask(currentTask),
	m_headerLen(0),
	m_prependHeader(prependHeader),
	m_processingEncrypt(false),
	m_fileSize(0),
	m_hasFileSize(false),
	m_blocksize(0),
	m_oldPercent(-1),
	m_hashPlainText(false)
{
}

EncryptProcessor::~EncryptProcessor(void)
{
	ClearStreamVariables();
}

bool EncryptProcessor::FinishHeader(const tscrypto::tsCryptoData &key, std::shared_ptr<ICmsHeaderBase> header)
{
	TSDECLARE_FUNCTIONExt(true);

	tscrypto::tsCryptoData clearText;
	tscrypto::tsCryptoData cipherText;
	tscrypto::tsCryptoString sTempFile;
	std::shared_ptr<ICryptoHelper> helper;
	std::shared_ptr<ICmsHeader> header7;
	std::shared_ptr<ICmsHeaderBase> header2;
	std::shared_ptr<IFifoStream> fifo;
	bool retVal;

	ClearStreamVariables();
	m_processingEncrypt = true;
	m_oldPercent = -1;
	if (!!m_reader)
	{
		if (!!(fifo = std::dynamic_pointer_cast<IFifoStream>(m_reader)))
		{
			fifo->SetReaderCallback(std::dynamic_pointer_cast<IFifoStreamReaderCallback>(_me.lock()));
		}
	}

	if (!(header7 = std::dynamic_pointer_cast<ICmsHeader>(header)))
	{
		LogError("An error occurred while retrieving the encryption header for file '%s'.", sTempFile.c_str());
		return TSRETURN_ERROR(("FAILED"), false);
	}

	if (m_writer->AllowsRandomAccess())
		m_writer->GoToPosition(0);

	//
	// Now determine the size of the header to reserve at the beginning of the file.
	//
	if (m_prependHeader && !m_writer->CanPrepend())
	{
		tscrypto::tsCryptoData tmpHeaderData;
		tmpHeaderData = header7->ToBytes();
		m_headerLen = (int)tmpHeaderData.size();

		m_headerLen += HEADER_SIZE_FUDGE;

		m_headerLen = ((m_headerLen + HEADER_SIZE_MULTIPLE - 1) / HEADER_SIZE_MULTIPLE) * HEADER_SIZE_MULTIPLE;

		LOG(DebugInfo3, "Reserving " << m_headerLen << " bytes for the header");

		tmpHeaderData.resize(m_headerLen);
		//
		// Reserve the space for the header now.
		//
		if (!m_writer->WriteData(tmpHeaderData))
		{
			LogError("An error occurred while reserving space for the encryption header in file '%s'.", sTempFile.c_str());
			return TSRETURN_ERROR(("FAILED"), false);
		}
	}
	else
	{
		m_headerLen = 0;
	}

	int blocksize = 0, format = 0;

	if (!header7->GetDataFormat(blocksize, format))
	{
		blocksize = 5000000;
		format = TS_FORMAT_CMS_CT_HASHED;
	}

	m_format = (CMSFileFormatIds)format;
	switch (format)
	{
	case TS_FORMAT_CMS_CT_HASHED:
		retVal = ProcessHashed(key, header7, blocksize, false, fifo);
		break;
	case TS_FORMAT_CMS_ENC_AUTH:
		retVal = ProcessEncAuthHashed(key, header7, blocksize, fifo);
		break;
	case TS_FORMAT_CMS_PT_HASHED:
		retVal = ProcessHashed(key, header7, blocksize, true, fifo);
		break;
	default:
		LogError("An invalid encryption format was specified for file '%s'.", sTempFile.c_str());
		return TSRETURN_ERROR(("FAILED"), false);
	}
	ClearStreamVariables();

	if (m_writer->AllowsRandomAccess())
		m_writer->GoToPosition(0);

	if (!retVal)
		return TSRETURN_ERROR(("Returns ~~"), false);

	if (!!m_nextCallback)
	{
		if (!m_nextCallback->FinishHeader(key, header))
		{
			return TSRETURN_ERROR(("Returns ~~"), false);
		}
	}
	return TSRETURN(("OK"), true);
}
bool EncryptProcessor::EncryptUsingKey(const tscrypto::tsCryptoData &key, int format, int blocksize, tscrypto::TS_ALG_ID encryptionAlg, const tscrypto::tsCryptoData &hashOid, CompressionType compType,
	const tscrypto::tsCryptoData &ivec, tscrypto::SymmetricPaddingType padding, const tscrypto::tsCryptoData &authData, tscrypto::tsCryptoData &finalHash)
{
	TSDECLARE_FUNCTIONExt(true);

	tscrypto::tsCryptoData clearText;
	tscrypto::tsCryptoData cipherText;
	tscrypto::tsCryptoString sTempFile;
	std::shared_ptr<IFifoStream> fifo;
	bool retVal;

	ClearStreamVariables();
	m_processingEncrypt = true;
	m_oldPercent = -1;
	if (!!m_reader)
	{
		if (!!(fifo = std::dynamic_pointer_cast<IFifoStream>(m_reader)))
		{
			fifo->SetReaderCallback(std::dynamic_pointer_cast<IFifoStreamReaderCallback>(_me.lock()));
		}
	}

	if (m_writer->AllowsRandomAccess())
		m_writer->GoToPosition(0);

	m_format = (CMSFileFormatIds)format;
	switch (format)
	{
	case TS_FORMAT_CMS_CT_HASHED:
		retVal = ProcessHashed(key, blocksize, false, fifo, encryptionAlg, hashOid, compType, ivec, padding, authData, finalHash);
		break;
	case TS_FORMAT_CMS_ENC_AUTH:
		retVal = ProcessEncAuthHashed(key, blocksize, fifo, encryptionAlg, hashOid, compType, ivec, padding, authData, finalHash);
		break;
	case TS_FORMAT_CMS_PT_HASHED:
		retVal = ProcessHashed(key, blocksize, true, fifo, encryptionAlg, hashOid, compType, ivec, padding, authData, finalHash);
		break;
	default:
		LogError("An invalid encryption format was specified for file '%s'.", sTempFile.c_str());
		return TSRETURN_ERROR(("FAILED"), false);
	}
	ClearStreamVariables();

	if (m_writer->AllowsRandomAccess())
		m_writer->GoToPosition(0);

	if (!retVal)
		return TSRETURN_ERROR(("Returns ~~"), false);

	return TSRETURN(("OK"), true);
}

void EncryptProcessor::LogError(tscrypto::tsCryptoString error, ...)
{
	va_list args;
	tscrypto::tsCryptoString msg;

	if (error.size() == 0)
		return;
	msg.resize(10240);
	va_start(args, error);
	// 06/15/2010 KRR C4996
	//    vsnprintf(msg.rawData(), 10240, error, args);
	TsVsnPrintf(msg.rawData(), 10240, error, args);
	//	vsnprintf( buff, sizeof(buff) - 1, formatstring, args);

	va_end(args);
	LOG(DebugError, msg);
	if (!!m_status)
	{
		m_status->FailureReason(msg.c_str());
	}
}

bool EncryptProcessor::SetNextCallback(std::shared_ptr<IKeyGenCallback> callback)
{
	m_nextCallback.reset();
	m_nextCallback = callback;
	return true;
}

bool EncryptProcessor::EncryptHashedPart(std::shared_ptr<IFifoStream> fifo)
{
	MY_UNREFERENCED_PARAMETER(fifo);
	TSDECLARE_FUNCTIONExt(true);

	int percent = 0;

	while (!m_reader->IsEndOfFile())
	{
		if (m_hasFileSize)
			percent = (int)((100 * m_reader->CurrentPosition()) / m_fileSize);
		else
			percent = (int)((100 * m_reader->CurrentPosition()) / (m_reader->CurrentPosition() + m_blocksize));

		if (percent != m_oldPercent && !!m_status)
		{
			if (!(m_status->Status(m_taskName.c_str(), m_currentTask, m_taskCount, percent)))
			{
				LogError("Operation cancelled");
				return TSRETURN_ERROR(("Cancelled"), false);
			}
			m_oldPercent = percent;
		}
		if (!m_hasFileSize || m_fileSize - m_reader->CurrentPosition() > m_blocksize)
		{
			m_workingBuffer.resize(m_blocksize);
		}
		else
		{
			m_workingBuffer.resize((int)(m_fileSize - m_reader->CurrentPosition()));
		}

		if (!m_reader->ReadData((int)m_workingBuffer.size(), m_workingBuffer))
		{
			LogError("Unable to read the entire input file.");
			return TSRETURN_ERROR(("FAILED"), false);
		}

		LOG(DebugInfo3, "Processing " << m_workingBuffer.size() << " bytes of data");

		if (m_workingBuffer.size() > 0)
		{
			if (m_hashPlainText)
			{
				if (!!m_hasher)
				{
					m_hasher->update(m_workingBuffer);
				}
			}

			if (!!m_compressor)
			{
				if (!(m_compressor->Compress(m_workingBuffer, m_workingBuffer2, compAct_Run)))
				{
					LogError("Unable to encrypt the file.");
					return TSRETURN_ERROR(("FAILED"), false);
				}
				m_workingBuffer = m_workingBuffer2;
			}
			if (m_workingBuffer.size() > 0)
			{
				if (!m_enc->update(m_workingBuffer, m_workingBuffer))
				{
					LogError("Unable to encrypt the file.");
					return TSRETURN_ERROR(("FAILED"), false);
				}

				if (!m_hashPlainText)
				{
					if (!!m_hasher)
					{
						m_hasher->update(m_workingBuffer);
					}
				}
				if (m_workingBuffer.size() > 0)
				{
					LOG(DebugInfo3, "Writing " << m_workingBuffer.size() << " bytes of data to the output file");

					if (!m_writer->WriteData(m_workingBuffer))
					{
						LogError("Unable to write the encrypted data into the output file.");
						return TSRETURN_ERROR(("FAILED"), false);
					}
				}
			}
		}
		else
			return TSRETURN(("OK"), true);
	}
	return TSRETURN(("OK"), true);
}

bool EncryptProcessor::ProcessHashed(const tscrypto::tsCryptoData &_key, std::shared_ptr<ICmsHeader> header7, int blocksize, bool hashPlainText, std::shared_ptr<IFifoStream> fifo)
{
	TSDECLARE_FUNCTIONExt(true);

	const BYTE *key = _key.c_str();
	size_t keyLen = (int)_key.size();
	int percent = 0;
	int64_t inOffset = 0;
	tscrypto::TS_ALG_ID encAlg = _TS_ALG_ID::TS_ALG_INVALID;
//	SymmetricMode encMode;
	size_t encKeySize = 0, ivecSize = 0, encBlocksize;
	tscrypto::tsCryptoData encKey, macKey;

	m_fileSize = (int64_t)header7->GetFileLength();
	m_hasFileSize = (m_fileSize > 0);
	m_blocksize = blocksize;

	encAlg = header7->GetEncryptionAlgorithmID();
//	encMode = Alg2Mode(encAlg);

	if (!(m_enc = std::dynamic_pointer_cast<Symmetric>(CryptoFactory(encAlg))))
	{
		LogError("Unable to create the required data encryption algorithm.");
		return TSRETURN_ERROR(("Unable to create the required data encryption algorithm."), false);
	}
	encKeySize = CryptoKeySize(encAlg);
	ivecSize = m_enc->getIVECSizeForMode(Alg2Mode(encAlg));
	encBlocksize = m_enc->getBlockSize();
	if (encKeySize == 0 || encBlocksize == 0)
	{
		LogError("Unable to retrieve the required data encryption algorithm parameters.");
		return TSRETURN_ERROR(("Unable to retrieve the required data encryption algorithm parameters."), false);
	}

	if (keyLen * 8 < encKeySize)
	{
		LogError("The encryption key is too short.");
		return TSRETURN_ERROR(("The encryption key is too short."), false);
	}

	switch (header7->GetCompressionType())
	{
	case ct_BZ2:
	case ct_zLib:
		if (!(m_compressor = CreateCompressor(header7->GetCompressionType())))
		{
			LogError("The compression type is not recognized.");
			return TSRETURN_ERROR(("The compression type is not recognized."), false);
		}
		m_compressor->CompressInit(9);
		break;
	case ct_None:
		break;
	default:
		LogError("The compression type is not recognized.");
		return TSRETURN_ERROR(("The compression type is not recognized."), false);
	}
	encKey.assign(key, encKeySize / 8);
	keyLen -= (int)encKeySize / 8;
	key += encKeySize / 8;

	if (header7->GetDataHashOID().size() > 0)
	{
		m_authHeader = computeHeaderIdentity(header7);

		if (!(m_hasher = std::dynamic_pointer_cast<MessageAuthenticationCode>(CryptoFactory(header7->GetDataHashOID().ToOIDString()))))
		{
			LogError("Unable to create the required data hash algorithm.");
			return TSRETURN_ERROR(("Unable to create the required data hash algorithm"), false);
		}
		if (m_hasher->requiresKey())
		{
			int maxKeySize = (int)m_hasher->maximumKeySizeInBits();

			if (maxKeySize < 0 || maxKeySize > 65535 || (size_t)maxKeySize > encKeySize)
				maxKeySize = (int)encKeySize;

			if (keyLen * 8 < (size_t)maxKeySize)
			{
				LogError("The encryption key is too short.");
				return TSRETURN_ERROR(("The encryption key is too short."), false);
			}

			macKey.assign(key, maxKeySize / 8);
			keyLen -= maxKeySize / 8;
			key += maxKeySize / 8;
		}
		if (!m_hasher->initialize(macKey) || !m_hasher->update(m_authHeader))
		{
			LogError("Unable to create the required data hash algorithm.");
			return TSRETURN_ERROR(("Unable to create the required data hash algorithm"), false);
		}
		macKey.clear();
	}

	if (ivecSize > 0)
	{
		m_encIvec = header7->GetIVEC();

		if (m_encIvec.size() == 0)
		{
			// IVEC comes from the working key.
			if (keyLen < ivecSize)
			{
				LogError("The encryption key is too short.");
				return TSRETURN_ERROR(("The encryption key is too short."), false);
			}

			m_encIvec.assign(key, ivecSize);
			keyLen -= (int)ivecSize;
			key += ivecSize;
		}
	}

	m_encIvec += encKey;

	m_enc->setPaddingType(header7->GetPaddingType());

	m_taskName << "Encrypt " << header7->GetDataName();
	//
	// Now go through the source file and encrypt it.
	//
	if (fifo != NULL)
	{
		if (!fifo->ProcessAllData())
		{
			LogError("Unable to encrypt the file.");
			return TSRETURN_ERROR(("FAILED"), false);
		}
	}
	else
	{
		while (!m_reader->IsEndOfFile())
		{
			if (m_hasFileSize)
				percent = (int)((100 * inOffset) / m_fileSize);
			else
				percent = (int)((100 * inOffset) / (inOffset + m_blocksize));

			if (percent != m_oldPercent && !!m_status)
			{
				tscrypto::tsCryptoString task;

				task << "Encrypt " << header7->GetDataName();

				if (!(m_status->Status(task.c_str(), m_currentTask, m_taskCount, percent)))
				{
					LogError("Operation cancelled");
					return TSRETURN_ERROR(("Cancelled"), false);
				}
				m_oldPercent = percent;
			}
			if (!m_hasFileSize || m_fileSize - inOffset > blocksize)
			{
				m_workingBuffer.resize(m_blocksize);
			}
			else
			{
				m_workingBuffer.resize((int)(m_fileSize - inOffset));
			}
			inOffset += m_workingBuffer.size();

			if (!m_reader->ReadData((int)m_workingBuffer.size(), m_workingBuffer))
			{
				LogError("Unable to read the entire input file.");
				return TSRETURN_ERROR(("FAILED"), false);
			}

			LOG(DebugInfo3, "Processing " << m_workingBuffer.size() << " bytes of data");

			if (m_workingBuffer.size() > 0)
			{
				if (m_hashPlainText)
				{
					if (!!m_hasher)
					{
						m_hasher->update(m_workingBuffer);
					}
				}

				if (!!m_compressor)
				{
					if (!(m_compressor->Compress(m_workingBuffer, m_workingBuffer2, compAct_Run)))
					{
						LogError("Unable to encrypt the file.");
						return TSRETURN_ERROR(("FAILED"), false);
					}
					m_workingBuffer = m_workingBuffer2;
				}
				if (m_workingBuffer.size() > 0)
				{
					if (!m_enc->update(m_workingBuffer, m_workingBuffer))
					{
						LogError("Unable to encrypt the file.");
						return TSRETURN_ERROR(("FAILED"), false);
					}

					if (!hashPlainText)
					{
						if (!!m_hasher)
						{
							m_hasher->update(m_workingBuffer);
						}
					}
					if (m_workingBuffer.size() > 0)
					{
						LOG(DebugInfo3, "Writing " << m_workingBuffer.size() << " bytes of data to the output file");

						if (!m_writer->WriteData(m_workingBuffer))
						{
							LogError("Unable to write the encrypted data into the output file.");
							return TSRETURN_ERROR(("FAILED"), false);
						}
					}
				}
			}
		}
	}
	if (!!m_status)
	{
		tscrypto::tsCryptoString task;

		task << "Encrypt " << header7->GetDataName();

		if (!(m_status->Status(task.c_str(), m_currentTask, m_taskCount, 100)))
		{
			LogError("Operation cancelled");
			return TSRETURN_ERROR(("Cancelled"), false);
		}
	}

	m_workingBuffer.clear();
	if (!!m_compressor)
	{
		if (!(m_compressor->CompressFinal(m_workingBuffer)))
		{
			LogError("Unable to encrypt the file.");
			return TSRETURN_ERROR(("FAILED"), false);
		}
	}
	if (m_workingBuffer.size() > 0)
	{
		if (!m_enc->update(m_workingBuffer, m_workingBuffer))
		{
			LogError("Unable to encrypt the file.");
			return TSRETURN_ERROR(("FAILED"), false);
		}
	}
	if (!m_enc->finish(m_workingBuffer2))
	{
		LogError("Unable to encrypt the file.");
		return TSRETURN_ERROR(("FAILED"), false);
	}
	m_workingBuffer += m_workingBuffer2;

	if (m_workingBuffer.size() > 0)
	{
		if (!hashPlainText)
		{
			if (!!m_hasher)
			{
				m_hasher->update(m_workingBuffer);
			}
		}

		LOG(DebugInfo3, "Writing " << m_workingBuffer.size() << " bytes of data to the output file");

		if (!m_writer->WriteData(m_workingBuffer))
		{
			LogError("Unable to write the encrypted data into the output file.");
			return TSRETURN_ERROR(("FAILED"), false);
		}
	}
	m_workingBuffer2.clear();
	m_workingBuffer.clear();

	if (!!m_hasher)
	{
		if (!m_hasher->finish(m_workingBuffer2))
		{
			LogError("Unable to retrieve the data hash.");
			return TSRETURN_ERROR(("FAILED"), false);
		}
		header7->SetDataHash(m_workingBuffer2);
	}
	return TSRETURN(("OK"), true);
}
bool EncryptProcessor::ProcessHashed(const tscrypto::tsCryptoData &_key, int blocksize, bool hashPlainText, std::shared_ptr<IFifoStream > fifo,
	tscrypto::TS_ALG_ID encAlg, const tscrypto::tsCryptoData &hashOid, CompressionType compType, const tscrypto::tsCryptoData &ivec, tscrypto::SymmetricPaddingType padding,
	const tscrypto::tsCryptoData &authData, tscrypto::tsCryptoData &finalHash)
{
	TSDECLARE_FUNCTIONExt(true);

	const BYTE *key = _key.c_str();
	int keyLen = (int)_key.size();
	int percent = 0;
	int64_t inOffset = 0;
	SymmetricMode encMode;
	size_t encKeySize = 0, ivecSize = 0, encBlocksize;
	tscrypto::tsCryptoData encKey, macKey;

	if (m_reader->KnowsRemainingData())
		m_fileSize = m_reader->RemainingData();
	else
		m_fileSize = 0;
	m_hasFileSize = (m_fileSize > 0);
	m_blocksize = blocksize;

	encMode = Alg2Mode(encAlg);

	if (!(m_enc = std::dynamic_pointer_cast<Symmetric>(CryptoFactory(encAlg))))
	{
		LogError("Unable to create the required data encryption algorithm.");
		return TSRETURN_ERROR(("Unable to create the required data encryption algorithm."), false);
	}

	encKeySize = CryptoKeySize(encAlg);
	ivecSize = m_enc->getIVECSizeForMode(encMode);
	encBlocksize = m_enc->getBlockSize();
	if (encKeySize == 0 || encBlocksize == 0)
	{
		LogError("Unable to retrieve the required data encryption algorithm parameters.");
		return TSRETURN_ERROR(("Unable to retrieve the required data encryption algorithm parameters."), false);
	}

	if (keyLen * 8 < (int)encKeySize)
	{
		LogError("The encryption key is too short.");
		return TSRETURN_ERROR(("The encryption key is too short."), false);
	}

	switch (compType)
	{
	case ct_BZ2:
	case ct_zLib:
		if (!(m_compressor = CreateCompressor(compType)))
		{
			LogError("The compression type is not recognized.");
			return TSRETURN_ERROR(("The compression type is not recognized."), false);
		}
		m_compressor->CompressInit(9);
		break;
	case ct_None:
		break;
	default:
		LogError("The compression type is not recognized.");
		return TSRETURN_ERROR(("The compression type is not recognized."), false);
	}
	encKey.assign(key, encKeySize / 8);
	keyLen -= (int)encKeySize / 8;
	key += encKeySize / 8;

	if (hashOid.size() > 0)
	{
		m_authHeader = authData;

		if (!(m_hasher = std::dynamic_pointer_cast<MessageAuthenticationCode>(CryptoFactory(hashOid.ToOIDString()))))
		{
			LogError("Unable to create the required data hash algorithm.");
			return TSRETURN_ERROR(("Unable to create the required data hash algorithm"), false);
		}
		if (m_hasher->requiresKey())
		{
			int maxKeySize = (int)m_hasher->maximumKeySizeInBits();

			if (maxKeySize < 0 || maxKeySize > 65535 || (size_t)maxKeySize > encKeySize)
				maxKeySize = (int)encKeySize;

			if (keyLen * 8 < maxKeySize)
			{
				LogError("The encryption key is too short.");
				return TSRETURN_ERROR(("The encryption key is too short."), false);
			}

			macKey.assign(key, maxKeySize / 8);
			keyLen -= maxKeySize / 8;
			key += maxKeySize / 8;
		}
		if (!m_hasher->initialize(macKey) || !m_hasher->update(m_authHeader))
		{
			LogError("Unable to create the required data hash algorithm.");
			return TSRETURN_ERROR(("Unable to create the required data hash algorithm"), false);
		}
		macKey.clear();
	}

	if (ivecSize > 0)
	{
		m_encIvec = ivec;

		if (m_encIvec.size() == 0)
		{
			// IVEC comes from the working key.
			if ((size_t)keyLen < ivecSize)
			{
				LogError("The encryption key is too short.");
				return TSRETURN_ERROR(("The encryption key is too short."), false);
			}

			m_encIvec.assign(key, ivecSize);
			keyLen -= (int)ivecSize;
			key += ivecSize;
		}
	}

	m_encIvec += encKey;

	m_enc->setPaddingType(padding);

	m_taskName << "Encrypt";
	//
	// Now go through the source file and encrypt it.
	//
	if (fifo != NULL)
	{
		if (!(fifo->ProcessAllData()))
		{
			LogError("Unable to encrypt the data.");
			return TSRETURN_ERROR(("FAILED"), false);
		}
	}
	else
	{
		while (!m_reader->IsEndOfFile())
		{
			if (m_hasFileSize)
				percent = (int)((100 * inOffset) / m_fileSize);
			else
				percent = (int)((100 * inOffset) / (inOffset + m_blocksize));

			if (percent != m_oldPercent && !!m_status)
			{
				tscrypto::tsCryptoString task;

				task << "Encrypt";

				if (!(m_status->Status(task.c_str(), m_currentTask, m_taskCount, percent)))
				{
					LogError("Operation cancelled");
					return TSRETURN_ERROR(("Cancelled"), false);
				}
				m_oldPercent = percent;
			}
			if (!m_hasFileSize || m_fileSize - inOffset > blocksize)
			{
				m_workingBuffer.resize(m_blocksize);
			}
			else
			{
				m_workingBuffer.resize((int)(m_fileSize - inOffset));
			}
			inOffset += m_workingBuffer.size();

			if (!m_reader->ReadData((int)m_workingBuffer.size(), m_workingBuffer))
			{
				LogError("Unable to read the entire input file.");
				return TSRETURN_ERROR(("FAILED"), false);
			}

			LOG(DebugInfo3, "Processing " << m_workingBuffer.size() << " bytes of data");

			if (m_workingBuffer.size() > 0)
			{
				if (m_hashPlainText)
				{
					if (!!m_hasher)
					{
						m_hasher->update(m_workingBuffer);
					}
				}

				if (!!m_compressor)
				{
					if (!(m_compressor->Compress(m_workingBuffer, m_workingBuffer2, compAct_Run)))
					{
						LogError("Unable to encrypt the file.");
						return TSRETURN_ERROR(("FAILED"), false);
					}
					m_workingBuffer = m_workingBuffer2;
				}
				if (m_workingBuffer.size() > 0)
				{
					if (!m_enc->update(m_workingBuffer, m_workingBuffer))
					{
						LogError("Unable to encrypt the file.");
						return TSRETURN_ERROR(("FAILED"), false);
					}

					if (!hashPlainText)
					{
						if (!!m_hasher)
						{
							m_hasher->update(m_workingBuffer);
						}
					}
					if (m_workingBuffer.size() > 0)
					{
						LOG(DebugInfo3, "Writing " << m_workingBuffer.size() << " bytes of data to the output file");

						if (!m_writer->WriteData(m_workingBuffer))
						{
							LogError("Unable to write the encrypted data into the output file.");
							return TSRETURN_ERROR(("FAILED"), false);
						}
					}
				}
			}
		}
	}
	if (!!m_status)
	{
		tscrypto::tsCryptoString task;

		task << "Encrypt";

		if (!(m_status->Status(task.c_str(), m_currentTask, m_taskCount, 100)))
		{
			LogError("Operation cancelled");
			return TSRETURN_ERROR(("Cancelled"), false);
		}
	}

	m_workingBuffer.clear();
	if (!!m_compressor)
	{
		if (!(m_compressor->CompressFinal(m_workingBuffer)))
		{
			LogError("Unable to encrypt the file.");
			return TSRETURN_ERROR(("FAILED"), false);
		}
	}
	if (m_workingBuffer.size() > 0)
	{
		if (!m_enc->update(m_workingBuffer, m_workingBuffer))
		{
			LogError("Unable to encrypt the file.");
			return TSRETURN_ERROR(("FAILED"), false);
		}
	}
	if (!m_enc->finish(m_workingBuffer2))
	{
		LogError("Unable to encrypt the file.");
		return TSRETURN_ERROR(("FAILED"), false);
	}
	m_workingBuffer += m_workingBuffer2;

	if (m_workingBuffer.size() > 0)
	{
		if (!hashPlainText)
		{
			if (!!m_hasher)
			{
				m_hasher->update(m_workingBuffer);
			}
		}

		LOG(DebugInfo3, "Writing " << m_workingBuffer.size() << " bytes of data to the output file");

		if (!m_writer->WriteData(m_workingBuffer))
		{
			LogError("Unable to write the encrypted data into the output file.");
			return TSRETURN_ERROR(("FAILED"), false);
		}
	}
	m_workingBuffer2.clear();
	m_workingBuffer.clear();

	if (!!m_hasher)
	{
		if (!m_hasher->finish(m_workingBuffer2))
		{
			LogError("Unable to retrieve the data hash.");
			return TSRETURN_ERROR(("FAILED"), false);
		}
		finalHash = m_workingBuffer2;
	}
	return TSRETURN(("OK"), true);
}

bool EncryptProcessor::EncryptEncAuthPart(std::shared_ptr<IFifoStream> fifo)
{
	TSDECLARE_FUNCTIONExt(true);

	int percent = 0;
	int chunkSize;
	tscrypto::tsCryptoData ivec, tag;

	//
	// Now go through the source file and encrypt it.
	//
	while (!m_reader->IsEndOfFile())
	{
		if (m_hasFileSize)
			percent = (int)((100 * m_reader->CurrentPosition()) / m_fileSize);
		else
			percent = (int)((100 * m_reader->CurrentPosition()) / (m_reader->CurrentPosition() + m_blocksize));

		if (percent != m_oldPercent && !!m_status)
		{
			if (!(m_status->Status(m_taskName.c_str(), m_currentTask, m_taskCount, percent)))
			{
				LogError("Operation cancelled");
				return TSRETURN_ERROR(("Cancelled"), false);
			}
			m_oldPercent = percent;
		}
		if (fifo != NULL && !fifo->IsWriterFinished() && m_reader->RemainingData() < m_blocksize)
			return TSRETURN(("OK"), true);

		if ((fifo != NULL && !fifo->IsWriterFinished()) || !m_hasFileSize || m_fileSize - m_reader->CurrentPosition() > m_blocksize)
		{
			m_workingBuffer.resize(m_blocksize);
		}
		else
		{
			m_workingBuffer.resize((int)(m_fileSize - m_reader->CurrentPosition()));
		}

		if (m_workingBuffer.size() == 0)
			break;

		if (!m_reader->ReadData((int)m_workingBuffer.size(), m_workingBuffer))
		{
			if (m_workingBuffer.size() == 0 && m_reader->IsEndOfFile())
				break;
			LogError("Unable to read the entire input file.");
			return TSRETURN_ERROR(("FAILED"), false);
		}

		LOG(DebugInfo3, "Processing " << m_workingBuffer.size() << " bytes of data");

		if (m_workingBuffer.size() > 0)
		{
			if (!!m_compressor)
			{
				m_workingBuffer2.clear();
				if (!(m_compressor->CompressInit(9)) ||
					!(m_compressor->Compress(m_workingBuffer, m_workingBuffer2, compAct_Run)) ||
					!(m_compressor->CompressFinal(m_workingBuffer)))
				{
					LogError("Unable to encrypt the file.");
					return TSRETURN_ERROR(("FAILED"), false);
				}
				m_workingBuffer.insert(0, m_workingBuffer2);
			}
			if (m_workingBuffer.size() > 0)
			{
				// Each block is treated as a new encryption (new ivec, same key).  Compute the new ivec here
				m_counter.increment();
				tscrypto::tsCryptoData encKey;

				if (!m_kdf->Derive_SP800_56A_Counter(m_encIvec, m_counter, 256 + 96, ivec))
				{
					LogError("The encryption key is too short.");
					return TSRETURN_ERROR(("The encryption key is too short."), false);
				}
				if (!m_gcm->initialize(ivec.substring(0, 32)))
				{
					LogError("Unable to initialize the encryption engine.");
					return TSRETURN_ERROR(("Unable to initialize the encryption engine."), false);
				}
				ivec.erase(0, 32);

				if (!m_gcm->encryptMessage(ivec, m_authHeader, m_workingBuffer, 16, tag))
				{
					LogError("Unable to encrypt the file.");
					return TSRETURN_ERROR(("FAILED"), false);
				}

				chunkSize = (int)(m_workingBuffer.size() + tag.size());
				m_workingBuffer2.assign((uint8_t*)&chunkSize, sizeof(chunkSize));
#if (BYTE_ORDER == LITTLE_ENDIAN)
				m_workingBuffer2.reverse();
#endif
				if (!!m_hasher)
				{
					m_hasher->update(m_workingBuffer2);
					m_hasher->update(tag);
				}

				if (m_workingBuffer.size() > 0)
				{
					LOG(DebugInfo3, "Writing " << m_workingBuffer.size() << " bytes of data to the output file");

					if (!m_writer->WriteData(m_workingBuffer2) || !m_writer->WriteData(m_workingBuffer) || !m_writer->WriteData(tag))
					{
						LogError("Unable to write the encrypted data into the output file.");
						return TSRETURN_ERROR(("FAILED"), false);
					}
				}
			}
		}
	}

	return TSRETURN(("OK"), true);
}

bool EncryptProcessor::ProcessEncAuthHashed(const tscrypto::tsCryptoData &_key, std::shared_ptr<ICmsHeader> header7, int blocksize, std::shared_ptr<IFifoStream> fifo)
{
	TSDECLARE_FUNCTIONExt(true);

	const BYTE *key = _key.c_str();
	int keyLen = (int)_key.size();
	int percent = 0;
	tscrypto::TS_ALG_ID encAlg = _TS_ALG_ID::TS_ALG_INVALID;
	SymmetricMode encMode;
	size_t encKeySize = 0, ivecSize = 0, encBlocksize;
	tscrypto::tsCryptoData encKey, macKey, ivec, tag;
	int chunkSize;

	ClearStreamVariables();
	m_processingEncrypt = true;

	m_fileSize = (int64_t)header7->GetFileLength();
	m_hasFileSize = (m_fileSize > 0);
	m_blocksize = blocksize;
	m_taskName << "Encrypt " << header7->GetDataName();

	encAlg = header7->GetEncryptionAlgorithmID();
	encMode = Alg2Mode(encAlg);

	if (!(m_kdf = std::dynamic_pointer_cast<KeyDerivationFunction>(CryptoFactory("KDF-SHA512"))))
	{
		LogError("The specified encryption file format requires the use of a key derivation function that is not available.");
		return TSRETURN_ERROR(("The specified encryption file format requires the use of a key derivation function that is not available."), false);
	}

	switch (encMode)
	{
	case _SymmetricMode::CKM_SymMode_CCM:
	case _SymmetricMode::CKM_SymMode_GCM:
		if (!(m_gcm = std::dynamic_pointer_cast<CCM_GCM>(CryptoFactory(encAlg))))
		{
			LogError("Unable to create the required data encryption algorithm.");
			return TSRETURN_ERROR(("Unable to create the required data encryption algorithm."), false);
		}
		break;
	default:
		LogError("The specified encryption file format requires the use of an authenticated encryption mode.");
		return TSRETURN_ERROR(("The specified encryption file format requires the use of an authenticated encryption mode."), false);
	}

	encKeySize = CryptoKeySize(encAlg);
	ivecSize = CryptoIVECSize(encAlg);
	encBlocksize = CryptoBlockSize(encAlg);

	if (encKeySize == 0 || encBlocksize == 0)
	{
		LogError("Unable to retrieve the required data encryption algorithm parameters.");
		return TSRETURN_ERROR(("Unable to retrieve the required data encryption algorithm parameters."), false);
	}

	if ((size_t)keyLen * 8 < encKeySize)
	{
		LogError("The encryption key is too short.");
		return TSRETURN_ERROR(("The encryption key is too short."), false);
	}

	switch (header7->GetCompressionType())
	{
	case ct_BZ2:
	case ct_zLib:
		if (!(m_compressor = CreateCompressor(header7->GetCompressionType())))
		{
			LogError("The compression type is not recognized.");
			return TSRETURN_ERROR(("The compression type is not recognized."), false);
		}
		break;
	case ct_None:
		break;
	default:
		LogError("The compression type is not recognized.");
		return TSRETURN_ERROR(("The compression type is not recognized."), false);
	}
	encKey.assign(key, encKeySize / 8);
	keyLen -= (int)encKeySize / 8;
	key += encKeySize / 8;

	m_authHeader = computeHeaderIdentity(header7);

	if (header7->GetDataHashOID().size() > 0)
	{
		if (!(m_hasher = std::dynamic_pointer_cast<MessageAuthenticationCode>(CryptoFactory(header7->GetDataHashOID().ToOIDString()))))
		{
			LogError("Unable to create the required data hash algorithm.");
			return TSRETURN_ERROR(("Unable to create the required data hash algorithm"), false);
		}
		if (m_hasher->requiresKey())
		{
			int maxKeySize = (int)m_hasher->maximumKeySizeInBits();

			if (maxKeySize < 0 || maxKeySize > 65535 || (size_t)maxKeySize > encKeySize)
				maxKeySize = (int)encKeySize;

			if (keyLen * 8 < maxKeySize)
			{
				LogError("The encryption key is too short.");
				return TSRETURN_ERROR(("The encryption key is too short."), false);
			}

			macKey.assign(key, maxKeySize / 8);
			keyLen -= maxKeySize / 8;
			key += maxKeySize / 8;
		}
		if (!m_hasher->initialize(macKey))
		{
			LogError("Unable to create the required data hash algorithm.");
			return TSRETURN_ERROR(("Unable to create the required data hash algorithm"), false);
		}
		macKey.clear();
	}

	if (ivecSize > 0)
	{
		m_encIvec = header7->GetIVEC();

		if (m_encIvec.size() == 0)
		{
			// IVEC comes from the working key.
			if ((size_t)keyLen < ivecSize)
			{
				LogError("The encryption key is too short.");
				return TSRETURN_ERROR(("The encryption key is too short."), false);
			}

			m_encIvec.assign(key, ivecSize);
			keyLen -= (int)ivecSize;
			key += ivecSize;
		}
	}

	m_encIvec += encKey;

	m_counter.resize(4);
	if (fifo != NULL)
	{
		if (!(fifo->ProcessAllData()))
		{
			LogError("Unable to encrypt the file.");
			return TSRETURN_ERROR(("FAILED"), false);
		}
	}
	else
	{
		//
		// Now go through the source file and encrypt it.
		//
		while (!m_reader->IsEndOfFile())
		{
			if (m_hasFileSize)
				percent = (int)((100 * m_reader->CurrentPosition()) / m_fileSize);
			else
				percent = (int)((100 * m_reader->CurrentPosition()) / (m_reader->CurrentPosition() + m_blocksize));

			if (percent != m_oldPercent && !!m_status)
			{
				if (!(m_status->Status(m_taskName.c_str(), m_currentTask, m_taskCount, percent)))
				{
					LogError("Operation cancelled");
					return TSRETURN_ERROR(("Cancelled"), false);
				}
				m_oldPercent = percent;
			}
			if (!m_hasFileSize || m_fileSize - m_reader->CurrentPosition() > blocksize)
			{
				m_workingBuffer.resize(blocksize);
			}
			else
			{
				m_workingBuffer.resize((int)(m_fileSize - m_reader->CurrentPosition()));
			}

			if (m_workingBuffer.size() == 0)
				break;

			if (!m_reader->ReadData((int)m_workingBuffer.size(), m_workingBuffer))
			{
				if (m_workingBuffer.size() == 0 && m_reader->IsEndOfFile())
					break;
				LogError("Unable to read the entire input file.");
				return TSRETURN_ERROR(("FAILED"), false);
			}

			LOG(DebugInfo3, "Processing " << m_workingBuffer.size() << " bytes of data");

			if (m_workingBuffer.size() > 0)
			{
				if (!!m_compressor)
				{
					m_workingBuffer2.clear();
					if (!(m_compressor->CompressInit(9)) ||
						!(m_compressor->Compress(m_workingBuffer, m_workingBuffer2, compAct_Run)) ||
						!(m_compressor->CompressFinal(m_workingBuffer)))
					{
						LogError("Unable to encrypt the file.");
						return TSRETURN_ERROR(("FAILED"), false);
					}
					m_workingBuffer.insert(0, m_workingBuffer2);
				}
				if (m_workingBuffer.size() > 0)
				{
					// Each block is treated as a new encryption (new ivec, same key).  Compute the new ivec here
					m_counter.increment();
					if (!m_kdf->Derive_SP800_56A_Counter(m_encIvec, m_counter, 256 + 96, ivec))
					{
						LogError("The encryption key is too short.");
						return TSRETURN_ERROR(("The encryption key is too short."), false);
					}

					// Each block is treated as a new encryption (new ivec, new key).
					if (!m_gcm->initialize(ivec.substring(0, 32)))
					{
						LogError("Unable to initialize the bulk data encryptor.");
						return TSRETURN_ERROR(("Unable to initialize the bulk data encryptor."), false);
					}
					ivec.erase(0, 32);

					if (!m_gcm->encryptMessage(ivec, m_authHeader, m_workingBuffer, 16, tag))
					{
						LogError("Unable to encrypt the file.");
						return TSRETURN_ERROR(("FAILED"), false);
					}

					chunkSize = (int)(m_workingBuffer.size() + tag.size());
					m_workingBuffer2.assign((uint8_t*)&chunkSize, sizeof(chunkSize));
#if (BYTE_ORDER == LITTLE_ENDIAN)
					m_workingBuffer2.reverse();
#endif
					if (!!m_hasher)
					{
						m_hasher->update(m_workingBuffer2);
						m_hasher->update(tag);
					}

					if (m_workingBuffer.size() > 0)
					{
						LOG(DebugInfo3, "Writing " << m_workingBuffer.size() << " bytes of data to the output file");

						if (!m_writer->WriteData(m_workingBuffer2) || !m_writer->WriteData(m_workingBuffer) || !m_writer->WriteData(tag))
						{
							LogError("Unable to write the encrypted data into the output file.");
							return TSRETURN_ERROR(("FAILED"), false);
						}
					}
				}
			}
		}
	}
	if (!!m_status)
	{
		if (!(m_status->Status(m_taskName.c_str(), m_currentTask, m_taskCount, 100)))
		{
			LogError("Operation cancelled");
			return TSRETURN_ERROR(("Cancelled"), false);
		}
	}

	if (!!m_hasher)
	{
		if (!m_hasher->finish(m_workingBuffer2))
		{
			LogError("Unable to retrieve the data hash.");
			return TSRETURN_ERROR(("FAILED"), false);
		}
		LOG(CkmDevOnly, "Data hash " << m_workingBuffer2);

		header7->SetDataHash(m_workingBuffer2);
	}
	return TSRETURN(("OK"), true);
}
bool EncryptProcessor::ProcessEncAuthHashed(const tscrypto::tsCryptoData &_key, int blocksize, std::shared_ptr<IFifoStream> fifo, tscrypto::TS_ALG_ID encAlg, const tscrypto::tsCryptoData &hashOid, CompressionType compType,
	const tscrypto::tsCryptoData &_ivec, tscrypto::SymmetricPaddingType padding, const tscrypto::tsCryptoData &authData, tscrypto::tsCryptoData &finalHash)
{
	MY_UNREFERENCED_PARAMETER(padding);

	TSDECLARE_FUNCTIONExt(true);

	int percent = 0;
	SymmetricMode encMode;
	size_t encKeySize = 0, ivecSize = 0, encBlocksize;
	tscrypto::tsCryptoData encKey, macKey, ivec, tag;
	int chunkSize;
	const BYTE *key = _key.c_str();
	int keyLen = (int)_key.size();

	ClearStreamVariables();
	m_processingEncrypt = true;

	if (m_reader->KnowsRemainingData())
		m_fileSize = m_reader->RemainingData();
	else
		m_fileSize = 0;
	m_hasFileSize = (m_fileSize > 0);
	m_blocksize = blocksize;
	m_taskName << "Encrypt";

	encMode = Alg2Mode(encAlg);

	if (!(m_kdf = std::dynamic_pointer_cast<KeyDerivationFunction>(CryptoFactory("KDF-SHA512"))))
	{
		LogError("The specified encryption file format requires the use of a key derivation function that is not available.");
		return TSRETURN_ERROR(("The specified encryption file format requires the use of a key derivation function that is not available."), false);
	}

	switch (encMode)
	{
	case _SymmetricMode::CKM_SymMode_CCM:
	case _SymmetricMode::CKM_SymMode_GCM:
		if (!(m_gcm = std::dynamic_pointer_cast<CCM_GCM>(CryptoFactory(encAlg))))
		{
			LogError("Unable to create the required data encryption algorithm.");
			return TSRETURN_ERROR(("Unable to create the required data encryption algorithm."), false);
		}
		break;
	default:
		LogError("The specified encryption file format requires the use of an authenticated encryption mode.");
		return TSRETURN_ERROR(("The specified encryption file format requires the use of an authenticated encryption mode."), false);
	}

	encKeySize = CryptoKeySize(encAlg);
	ivecSize = CryptoIVECSize(encAlg);
	encBlocksize = CryptoBlockSize(encAlg);
	if (encKeySize == 0 || encBlocksize == 0)
	{
		LogError("Unable to retrieve the required data encryption algorithm parameters.");
		return TSRETURN_ERROR(("Unable to retrieve the required data encryption algorithm parameters."), false);
	}

	if ((size_t)keyLen * 8 < encKeySize)
	{
		LogError("The encryption key is too short.");
		return TSRETURN_ERROR(("The encryption key is too short."), false);
	}

	switch (compType)
	{
	case ct_BZ2:
	case ct_zLib:
		if (!(m_compressor = CreateCompressor(compType)))
		{
			LogError("The compression type is not recognized.");
			return TSRETURN_ERROR(("The compression type is not recognized."), false);
		}
		break;
	case ct_None:
		break;
	default:
		LogError("The compression type is not recognized.");
		return TSRETURN_ERROR(("The compression type is not recognized."), false);
	}
	encKey.assign(key, encKeySize / 8);
	keyLen -= (int)encKeySize / 8;
	key += encKeySize / 8;

	m_authHeader = authData;

	if (hashOid.size() > 0)
	{
		if (!(m_hasher = std::dynamic_pointer_cast<MessageAuthenticationCode>(CryptoFactory(hashOid.ToOIDString()))))
		{
			LogError("Unable to create the required data hash algorithm.");
			return TSRETURN_ERROR(("Unable to create the required data hash algorithm"), false);
		}
		if (m_hasher->requiresKey())
		{
			int maxKeySize = (int)m_hasher->maximumKeySizeInBits();

			if (maxKeySize < 0 || maxKeySize > 65535 || (size_t)maxKeySize > encKeySize)
				maxKeySize = (int)encKeySize;

			if (keyLen * 8 < maxKeySize)
			{
				LogError("The encryption key is too short.");
				return TSRETURN_ERROR(("The encryption key is too short."), false);
			}

			macKey.assign(key, maxKeySize / 8);
			keyLen -= maxKeySize / 8;
			key += maxKeySize / 8;
		}
		if (!m_hasher->initialize(macKey))
		{
			LogError("Unable to create the required data hash algorithm.");
			return TSRETURN_ERROR(("Unable to create the required data hash algorithm"), false);
		}
		macKey.clear();
	}

	if (ivecSize > 0)
	{
		m_encIvec = _ivec;

		if (m_encIvec.size() == 0)
		{
			// IVEC comes from the working key.
			if ((size_t)keyLen < ivecSize)
			{
				LogError("The encryption key is too short.");
				return TSRETURN_ERROR(("The encryption key is too short."), false);
			}

			m_encIvec.assign(key, ivecSize);
			keyLen -= (int)ivecSize;
			key += ivecSize;
		}
	}

	m_encIvec += encKey;

	m_counter.resize(4);
	if (fifo != NULL)
	{
		if (!(fifo->ProcessAllData()))
		{
			LogError("Unable to encrypt the file.");
			return TSRETURN_ERROR(("FAILED"), false);
		}
	}
	else
	{
		//
		// Now go through the source file and encrypt it.
		//
		while (!m_reader->IsEndOfFile())
		{
			if (m_hasFileSize)
				percent = (int)((100 * m_reader->CurrentPosition()) / m_fileSize);
			else
				percent = (int)((100 * m_reader->CurrentPosition()) / (m_reader->CurrentPosition() + m_blocksize));

			if (percent != m_oldPercent && !!m_status)
			{
				if (!(m_status->Status(m_taskName.c_str(), m_currentTask, m_taskCount, percent)))
				{
					LogError("Operation cancelled");
					return TSRETURN_ERROR(("Cancelled"), false);
				}
				m_oldPercent = percent;
			}
			if (!m_hasFileSize || m_fileSize - m_reader->CurrentPosition() > blocksize)
			{
				m_workingBuffer.resize(blocksize);
			}
			else
			{
				m_workingBuffer.resize((int)(m_fileSize - m_reader->CurrentPosition()));
			}

			if (m_workingBuffer.size() == 0)
				break;

			if (!m_reader->ReadData((int)m_workingBuffer.size(), m_workingBuffer))
			{
				if (m_workingBuffer.size() == 0 && m_reader->IsEndOfFile())
					break;
				LogError("Unable to read the entire input file.");
				return TSRETURN_ERROR(("FAILED"), false);
			}

			LOG(DebugInfo3, "Processing " << m_workingBuffer.size() << " bytes of data");

			if (m_workingBuffer.size() > 0)
			{
				if (!!m_compressor)
				{
					m_workingBuffer2.clear();
					if (!(m_compressor->CompressInit(9)) ||
						!(m_compressor->Compress(m_workingBuffer, m_workingBuffer2, compAct_Run)) ||
						!(m_compressor->CompressFinal(m_workingBuffer)))
					{
						LogError("Unable to encrypt the file.");
						return TSRETURN_ERROR(("FAILED"), false);
					}
					m_workingBuffer.insert(0, m_workingBuffer2);
				}
				if (m_workingBuffer.size() > 0)
				{
					// Each block is treated as a new encryption (new ivec, same key).  Compute the new ivec here
					m_counter.increment();
					if (!m_kdf->Derive_SP800_56A_Counter(m_encIvec, m_counter, 256 + 96, ivec))
					{
						LogError("The encryption key is too short.");
						return TSRETURN_ERROR(("The encryption key is too short."), false);
					}

					// Each block is treated as a new encryption (new ivec, new key).
					if (!m_gcm->initialize(ivec.substring(0, 32)))
					{
						LogError("Unable to initialize the bulk data encryptor.");
						return TSRETURN_ERROR(("Unable to initialize the bulk data encryptor."), false);
					}
					ivec.erase(0, 32);

					if (!m_gcm->encryptMessage(ivec, m_authHeader, m_workingBuffer, 16, tag))
					{
						LogError("Unable to encrypt the file.");
						return TSRETURN_ERROR(("FAILED"), false);
					}

					chunkSize = (int)(m_workingBuffer.size() + tag.size());
					m_workingBuffer2.assign((uint8_t*)&chunkSize, sizeof(chunkSize));
#if (BYTE_ORDER == LITTLE_ENDIAN)
					m_workingBuffer2.reverse();
#endif
					if (!!m_hasher)
					{
						m_hasher->update(m_workingBuffer2);
						m_hasher->update(tag);
					}

					if (m_workingBuffer.size() > 0)
					{
						LOG(DebugInfo3, "Writing " << m_workingBuffer.size() << " bytes of data to the output file");

						if (!m_writer->WriteData(m_workingBuffer2) || !m_writer->WriteData(m_workingBuffer) || !m_writer->WriteData(tag))
						{
							LogError("Unable to write the encrypted data into the output file.");
							return TSRETURN_ERROR(("FAILED"), false);
						}
					}
				}
			}
		}
	}
	if (!!m_status)
	{
		if (!(m_status->Status(m_taskName.c_str(), m_currentTask, m_taskCount, 100)))
		{
			LogError("Operation cancelled");
			return TSRETURN_ERROR(("Cancelled"), false);
		}
	}

	if (!!m_hasher)
	{
		if (!m_hasher->finish(m_workingBuffer2))
		{
			LogError("Unable to retrieve the data hash.");
			return TSRETURN_ERROR(("FAILED"), false);
		}
		finalHash = m_workingBuffer2;
	}
	return TSRETURN(("OK"), true);
}

bool EncryptProcessor::DecryptData(const tscrypto::tsCryptoData &key, std::shared_ptr<ICmsHeaderBase>& header)
{
	TSDECLARE_FUNCTIONExt(true);

	int format;
	int blocksize;
	std::shared_ptr<ICmsHeader> header7;
	bool retVal;
	std::shared_ptr<IFifoStream> fifo;

	ClearStreamVariables();
	m_processingEncrypt = false;
	m_oldPercent = -1;
	m_nextLen = 0;

	if (header == NULL)
		return false;

	if (m_reader != NULL)
	{
		if (!!(fifo = std::dynamic_pointer_cast<IFifoStream>(m_reader)))
		{
			fifo->SetReaderCallback(std::dynamic_pointer_cast<IFifoStreamReaderCallback>(_me.lock()));
		}
	}

	if (!(header7 = std::dynamic_pointer_cast<ICmsHeader>(header)))
	{
		LogError("Error:  header is invalid");
		return TSRETURN_ERROR(("Bad Header"), false);
	}

	if (!header7->GetDataFormat(blocksize, format))
	{
		blocksize = 0;
		format = TS_FORMAT_CMS_PT_HASHED;
	}

	m_format = (CMSFileFormatIds)format;
	switch (format)
	{
	case TS_FORMAT_CMS_CT_HASHED:
		retVal = DecryptHashed(key, header7, header7->PaddedHeaderSize(), blocksize, false, fifo);
		break;
	case TS_FORMAT_CMS_PT_HASHED:
		retVal = DecryptHashed(key, header7, header7->PaddedHeaderSize(), blocksize, true, fifo);
		break;
	case TS_FORMAT_CMS_ENC_AUTH:
		retVal = DecryptEncAuthData(key, header7, header7->PaddedHeaderSize(), blocksize, fifo);
		break;
	default:
		LogError("Error:  Unrecognized file format.");
		return TSRETURN_ERROR(("Bad File"), false);
	}
	ClearStreamVariables();

	if (!retVal)
	{
		return TSRETURN_ERROR(("Invalid data"), false);
	}

	return TSRETURN_ERROR(("OK"), true);
}
bool EncryptProcessor::DecryptUsingKey(const tscrypto::tsCryptoData &key, int format, int blocksize, tscrypto::TS_ALG_ID encAlg, const tscrypto::tsCryptoData &hashOid, CompressionType compType,
	const tscrypto::tsCryptoData &ivec, tscrypto::SymmetricPaddingType padding, const tscrypto::tsCryptoData &authData, const tscrypto::tsCryptoData &finalHash)
{
	TSDECLARE_FUNCTIONExt(true);

	std::shared_ptr<IFifoStream> fifo;
	bool retVal;

	ClearStreamVariables();
	m_processingEncrypt = false;
	m_oldPercent = -1;
	m_nextLen = 0;

	if (m_reader != NULL)
	{
		if (!!(fifo = std::dynamic_pointer_cast<IFifoStream>(m_reader)))
		{
			fifo->SetReaderCallback(std::dynamic_pointer_cast<IFifoStreamReaderCallback>(_me.lock()));
		}
	}

	m_format = (CMSFileFormatIds)format;
	switch (format)
	{
	case TS_FORMAT_CMS_CT_HASHED:
		retVal = DecryptHashed(key, blocksize, false, fifo, encAlg, hashOid, compType, ivec, padding, authData, finalHash);
		break;
	case TS_FORMAT_CMS_PT_HASHED:
		retVal = DecryptHashed(key, blocksize, true, fifo, encAlg, hashOid, compType, ivec, padding, authData, finalHash);
		break;
	case TS_FORMAT_CMS_ENC_AUTH:
		retVal = DecryptEncAuthData(key, blocksize, fifo, encAlg, hashOid, compType, ivec, padding, authData, finalHash);
		break;
	default:
		LogError("Error:  Unrecognized file format.");
		return TSRETURN_ERROR(("Bad File"), false);
	}
	ClearStreamVariables();

	if (!retVal)
	{
		return TSRETURN_ERROR(("Invalid data"), false);
	}

	return TSRETURN_ERROR(("OK"), true);
}

bool EncryptProcessor::DecryptEncAuthPart(std::shared_ptr<IFifoStream> fifo)
{
	TSDECLARE_FUNCTIONExt(true);

	int percent;
	tscrypto::tsCryptoData len, tag, ivec;

	while (!m_reader->IsEndOfFile())
	{
		if (m_hasFileSize)
			percent = (int)((100 * m_writer->CurrentPosition()) / m_fileSize);
		else
			percent = (int)((100 * m_writer->CurrentPosition()) / (m_writer->CurrentPosition() + m_blocksize));

		if (percent != m_oldPercent && !!m_status)
		{
			if (!(m_status->Status(m_taskName.c_str(), m_currentTask, m_taskCount, percent)))
			{
				LogError("Operation cancelled");
				return TSRETURN_ERROR(("Cancelled"), false);
			}
			m_oldPercent = percent;
		}

		if (m_reader->RemainingData() < 20)
			return TSRETURN(("OK"), true);

		if (m_nextLen == 0)
		{
			if (!m_reader->ReadData(4, len))
			{
				return TSRETURN_ERROR(("Returns ~~"), false);
			}
			if (len.size() == 0 && m_reader->IsEndOfFile())
				break;
			if (!!m_hasher)
			{
				if (!m_hasher->update(len))
				{
					LogError("Unable to compute the data hash.");
					return TSRETURN_ERROR(("Unable to compute the data hash."), false);
				}
			}

#if (BYTE_ORDER == LITTLE_ENDIAN)
			len.reverse();
#endif
			m_nextLen = *(int32_t *)len.c_str();
		}

		if (m_reader->RemainingData() < m_nextLen && !m_reader->IsEndOfFile() && fifo != NULL && !fifo->IsWriterFinished())
		{
			// Wait for enough data to process
			return TSRETURN(("OK"), true);
		}

		if (!m_reader->ReadData(*(int32_t *)len.c_str(), m_workingBuffer))
		{
			LogError("Data format invalid.");
			return TSRETURN_ERROR(("Data format invalid."), false);
		}
		if (m_workingBuffer.size() > 16)
		{
			m_workingBuffer.assign(&m_workingBuffer.c_str()[m_workingBuffer.size() - 16], 16);
			m_workingBuffer.resize(m_workingBuffer.size() - 16);
		}
		else
		{
			LogError("Data format invalid.");
			return TSRETURN_ERROR(("Data format invalid."), false);
		}

		if (!!m_hasher && !m_hasher->update(tag))
		{
			LogError("Unable to compute the data hash.");
			return TSRETURN_ERROR(("Unable to compute the data hash."), false);
		}

		// Each block is treated as a new encryption (new ivec, new key).  Compute the new ivec here
		m_counter.increment();

		if (!m_kdf->Derive_SP800_56A_Counter(m_encIvec, m_counter, 256 + 96, ivec))
		{
			LogError("The decryption key is too short.");
			return TSRETURN_ERROR(("The decryption key is too short."), false);
		}

		// Each block is treated as a new encryption (new ivec, new key).
		if (!m_gcm->initialize(ivec.substring(0, 32)))
		{
			LogError("Unable to initialize the bulk data encryptor.");
			return TSRETURN_ERROR(("Unable to initialize the bulk data encryptor."), false);
		}
		ivec.erase(0, 32);
		if (!m_gcm->decryptMessage(ivec, m_authHeader, m_workingBuffer, tag))
		{
			LogError("Unable to decrypt the file.  The tag does not match the required value.");
			return TSRETURN_ERROR(("FAILED"), false);
		}

		if (!!m_compressor)
		{
			if (!(m_compressor->DecompressInit()) ||
				!(m_compressor->Decompress(m_workingBuffer, m_workingBuffer2, compAct_Run)) ||
				!(m_compressor->DecompressFinal(m_workingBuffer)))
			{
				LogError("Unable to decrypt the file.  The decompression operation failed.");
				return TSRETURN_ERROR(("FAILED"), false);
			}
			m_workingBuffer.insert(0, m_workingBuffer2);
		}
		if (m_workingBuffer.size() > 0)
		{
			LOG(DebugInfo3, "Writing " << m_workingBuffer.size() << " bytes of data to the output file");

			if (!m_writer->WriteData(m_workingBuffer))
			{
				LogError("Unable to write the decrypted data into the output file.");
				return TSRETURN_ERROR(("FAILED"), false);
			}
		}
	}
	return TSRETURN(("OK"), true);
}

bool EncryptProcessor::DecryptEncAuthData(const tscrypto::tsCryptoData &_key, std::shared_ptr<ICmsHeader> header, int headerSize, int blocksize, std::shared_ptr<IFifoStream> fifo)
{
	TSDECLARE_FUNCTIONExt(true);

	tscrypto::tsCryptoData len;
	SymmetricMode encMode;
	size_t encKeySize = 0, ivecSize = 0, encBlocksize;
	tscrypto::tsCryptoData encKey, macKey, ivec, tag;
	int percent;
	const BYTE *key = _key.c_str();
	int keyLen = (int)_key.size();

	m_fileSize = (int64_t)header->GetFileLength();
	m_hasFileSize = (m_fileSize > 0);
	m_blocksize = blocksize;

	if (header->GetDataHash().size() != 0)
	{
		if (!(m_hasher = std::dynamic_pointer_cast<MessageAuthenticationCode>(CryptoFactory(header->GetDataHashOID().ToOIDString()))))
			return TSRETURN_ERROR(("Unable to create the data hash algorithm."), false);
	}

	tscrypto::TS_ALG_ID encAlg = header->GetEncryptionAlgorithmID();
	encMode = Alg2Mode(encAlg);

	if (!(m_kdf = std::dynamic_pointer_cast<KeyDerivationFunction>(CryptoFactory("KDF-SHA512"))))
	{
		LogError("The specified encryption file format requires the use of a key derivation function that is not available.");
		return TSRETURN_ERROR(("The specified encryption file format requires the use of a key derivation function that is not available."), false);
	}

	switch (encMode)
	{
	case _SymmetricMode::CKM_SymMode_CCM:
	case _SymmetricMode::CKM_SymMode_GCM:
		if (!(m_gcm = std::dynamic_pointer_cast<CCM_GCM>(CryptoFactory(header->GetEncryptionAlgorithmOID().ToOIDString()))))
		{
			LogError("Unable to create the required data encryption algorithm.");
			return TSRETURN_ERROR(("Unable to create the required data encryption algorithm."), false);
		}
		break;
	default:
		LogError("The specified encryption file format requires the use of an authenticated encryption mode.");
		return TSRETURN_ERROR(("The specified encryption file format requires the use of an authenticated encryption mode."), false);
	}

	encKeySize = CryptoKeySize(encAlg);
	ivecSize = CryptoIVECSize(encAlg);
	encBlocksize = CryptoBlockSize(encAlg);

	if (encKeySize == 0 || encBlocksize == 0)
	{
		LogError("Unable to retrieve the required data encryption algorithm parameters.");
		return TSRETURN_ERROR(("Unable to retrieve the required data encryption algorithm parameters."), false);
	}

	if ((size_t)keyLen * 8 < encKeySize)
	{
		LogError("The encryption key is too short.");
		return TSRETURN_ERROR(("The encryption key is too short."), false);
	}

	switch (header->GetCompressionType())
	{
	case ct_BZ2:
	case ct_zLib:
		if (!(m_compressor = CreateCompressor(header->GetCompressionType())))
		{
			LogError("The compression type is not recognized.");
			return TSRETURN_ERROR(("The compression type is not recognized."), false);
		}
		break;
	case ct_None:
		break;
	default:
		LogError("The compression type is not recognized.");
		return TSRETURN_ERROR(("The compression type is not recognized."), false);
	}
	encKey.assign(key, encKeySize / 8);
	keyLen -= (int)encKeySize / 8;
	key += encKeySize / 8;

	m_authHeader = computeHeaderIdentity(header);

	if (!!m_hasher)
	{
		if (m_hasher->requiresKey())
		{
			int maxKeySize = (int)m_hasher->maximumKeySizeInBits();

			if (maxKeySize < 0 || maxKeySize > 65535 || (size_t)maxKeySize > encKeySize)
				maxKeySize = (int)encKeySize;

			if (keyLen * 8 < maxKeySize)
			{
				LogError("The encryption key is too short.");
				return TSRETURN_ERROR(("The encryption key is too short."), false);
			}

			macKey.assign(key, maxKeySize / 8);
			keyLen -= maxKeySize / 8;
			key += maxKeySize / 8;
		}
		if (!m_hasher->initialize(macKey))
		{
			LogError("Unable to create the required data hash algorithm.");
			return TSRETURN_ERROR(("Unable to create the required data hash algorithm"), false);
		}
		macKey.clear();
	}

	m_reader->GoToPosition(headerSize);

	if (ivecSize > 0)
	{
		m_encIvec = header->GetIVEC();

		if (m_encIvec.size() == 0)
		{
			// IVEC comes from the working key.
			if ((size_t)keyLen < ivecSize)
			{
				LogError("The encryption key is too short.");
				return TSRETURN_ERROR(("The encryption key is too short."), false);
			}

			m_encIvec.assign(key, ivecSize);
			keyLen -= (int)ivecSize;
			key += ivecSize;
		}
	}

	m_encIvec += encKey;

	m_counter.resize(4);

	m_taskName << "Decrypt " << header->GetDataName();
	if (fifo != NULL)
	{
		if (!(fifo->ProcessAllData()))
		{
			LogError("Unable to decrypt the file.  ProcessAllData failed");
			return TSRETURN_ERROR(("FAILED"), false);
		}
	}
	else
	{
		while (!m_reader->IsEndOfFile())
		{
			if (m_hasFileSize)
				percent = (int)((100 * m_writer->CurrentPosition()) / m_fileSize);
			else
				percent = (int)((100 * m_writer->CurrentPosition()) / (m_writer->CurrentPosition() + m_blocksize));

			if (percent != m_oldPercent && !!m_status)
			{
				if (!(m_status->Status(m_taskName.c_str(), m_currentTask, m_taskCount, percent)))
				{
					LogError("Operation cancelled");
					return TSRETURN_ERROR(("Cancelled"), false);
				}
				m_oldPercent = percent;
			}

			if (!m_reader->ReadData(4, len))
			{
				return false;
			}
			if (len.size() == 0 && m_reader->IsEndOfFile())
				break;
			if (!!m_hasher)
			{
				if (!m_hasher->update(len))
				{
					LogError("Unable to compute the data hash.");
					return TSRETURN_ERROR(("Unable to compute the data hash."), false);
				}
			}

#if (BYTE_ORDER == LITTLE_ENDIAN)
			len.reverse();
#endif
			if (!m_reader->ReadData(*(int32_t *)len.c_str(), m_workingBuffer))
			{
				LogError("Data format invalid.");
				return TSRETURN_ERROR(("Data format invalid."), false);
			}
			if (m_workingBuffer.size() > 16)
			{
				tag.assign(&m_workingBuffer.c_str()[m_workingBuffer.size() - 16], 16);
				m_workingBuffer.resize(m_workingBuffer.size() - 16);
			}
			else
			{
				LogError("Data format invalid.");
				return TSRETURN_ERROR(("Data format invalid."), false);
			}

			if (!!m_hasher && !m_hasher->update(tag))
			{
				LogError("Unable to compute the data hash.");
				return TSRETURN_ERROR(("Unable to compute the data hash."), false);
			}

			// Each block is treated as a new encryption (new ivec, same key).  Compute the new ivec here
			m_counter.increment();
			if (!m_kdf->Derive_SP800_56A_Counter(m_encIvec, m_counter, 256 + 96, ivec))
			{
				LogError("The decryption key is too short.");
				return TSRETURN_ERROR(("The decryption key is too short."), false);
			}
			if (!m_gcm->initialize(ivec.substring(0, 32)))
			{
				LogError("Unable to initialize the decryption engine.");
				return TSRETURN_ERROR(("Unable to initialize the decryption engine."), false);
			}
			ivec.erase(0, 32);
			if (!m_gcm->decryptMessage(ivec, m_authHeader, m_workingBuffer, tag))
			{
				LogError("Unable to decrypt the file.  The tag does not match the computed value.");
				return TSRETURN_ERROR(("FAILED"), false);
			}

			if (!!m_compressor)
			{
				if (!(m_compressor->DecompressInit()) ||
					!(m_compressor->Decompress(m_workingBuffer, m_workingBuffer2, compAct_Run)) ||
					!(m_compressor->DecompressFinal(m_workingBuffer)))
				{
					LogError("Unable to decrypt the file.  The decompression operation failed.");
					return TSRETURN_ERROR(("FAILED"), false);
				}
				m_workingBuffer.insert(0, m_workingBuffer2);
			}
			if (m_workingBuffer.size() > 0)
			{
				LOG(DebugInfo3, "Writing " << m_workingBuffer.size() << " bytes of data to the output file");

				if (!m_writer->WriteData(m_workingBuffer))
				{
					LogError("Unable to write the decrypted data into the output file.");
					return TSRETURN_ERROR(("FAILED"), false);
				}
			}
		}
	}


	if (!!m_status)
	{
		if (!(m_status->Status(m_taskName.c_str(), m_currentTask, m_taskCount, 100)))
		{
			LogError("Operation cancelled");
			return TSRETURN_ERROR(("Cancelled"), false);
		}
	}

	if (!!m_hasher)
	{
		if (!m_hasher->finish(m_workingBuffer))
		{
			LogError("Unable to compute the data hash.");
			return TSRETURN_ERROR(("Unable to compute the data hash."), false);
		}

		if (m_workingBuffer.compare(header->GetDataHash()) != 0)
		{
			LogError("Unable to decrypt the file - data hash invalid.");
			return TSRETURN_ERROR(("Unable to decrypt the file - data hash invalid"), false);
		}
	}
	return TSRETURN_ERROR(("OK"), true);
}
bool EncryptProcessor::DecryptEncAuthData(const tscrypto::tsCryptoData &_key, int blocksize, std::shared_ptr<IFifoStream> fifo,
	tscrypto::TS_ALG_ID encAlg, const tscrypto::tsCryptoData &hashOid, CompressionType compType, const tscrypto::tsCryptoData &_ivec, tscrypto::SymmetricPaddingType padding, const tscrypto::tsCryptoData &authData, const tscrypto::tsCryptoData &finalHash)
{
	MY_UNREFERENCED_PARAMETER(padding);

	TSDECLARE_FUNCTIONExt(true);

	tscrypto::tsCryptoData len;
	SymmetricMode encMode;
	size_t encKeySize = 0, ivecSize = 0, encBlocksize;
	tscrypto::tsCryptoData encKey, macKey, ivec, tag;
	int percent;
	const BYTE *key = _key.c_str();
	int keyLen = (int)_key.size();

	if (m_reader->KnowsRemainingData())
		m_fileSize = m_reader->RemainingData();
	else
		m_fileSize = 0;
	m_hasFileSize = (m_fileSize > 0);
	m_blocksize = blocksize;

	if (hashOid.size() != 0)
	{
		if (!(m_hasher = std::dynamic_pointer_cast<MessageAuthenticationCode>(CryptoFactory(hashOid.ToOIDString()))))
			return TSRETURN_ERROR(("Unable to create the data hash algorithm."), false);
	}

	encMode = Alg2Mode(encAlg);

	if (!(m_kdf = std::dynamic_pointer_cast<KeyDerivationFunction>(CryptoFactory("KDF-SHA512"))))
	{
		LogError("The specified encryption file format requires the use of a key derivation function that is not available.");
		return TSRETURN_ERROR(("The specified encryption file format requires the use of a key derivation function that is not available."), false);
	}

	switch (encMode)
	{
	case _SymmetricMode::CKM_SymMode_CCM:
	case _SymmetricMode::CKM_SymMode_GCM:
		if (!(m_gcm = std::dynamic_pointer_cast<CCM_GCM>(CryptoFactory(encAlg))))
		{
			LogError("Unable to create the required data encryption algorithm.");
			return TSRETURN_ERROR(("Unable to create the required data encryption algorithm."), false);
		}
		break;
	default:
		LogError("The specified encryption file format requires the use of an authenticated encryption mode.");
		return TSRETURN_ERROR(("The specified encryption file format requires the use of an authenticated encryption mode."), false);
	}

	encKeySize = CryptoKeySize(encAlg);
	ivecSize = CryptoIVECSize(encAlg);
	encBlocksize = CryptoBlockSize(encAlg);

	if (encKeySize == 0 || encBlocksize == 0)
	{
		LogError("Unable to retrieve the required data encryption algorithm parameters.");
		return TSRETURN_ERROR(("Unable to retrieve the required data encryption algorithm parameters."), false);
	}

	if ((size_t)keyLen * 8 < encKeySize)
	{
		LogError("The encryption key is too short.");
		return TSRETURN_ERROR(("The encryption key is too short."), false);
	}

	switch (compType)
	{
	case ct_BZ2:
	case ct_zLib:
		if (!(m_compressor = CreateCompressor(compType)))
		{
			LogError("The compression type is not recognized.");
			return TSRETURN_ERROR(("The compression type is not recognized."), false);
		}
		break;
	case ct_None:
		break;
	default:
		LogError("The compression type is not recognized.");
		return TSRETURN_ERROR(("The compression type is not recognized."), false);
	}
	encKey.assign(key, encKeySize / 8);
	keyLen -= (int)encKeySize / 8;
	key += encKeySize / 8;

	m_authHeader = authData;

	if (!!m_hasher)
	{
		if (m_hasher->requiresKey())
		{
			int maxKeySize = (int)m_hasher->maximumKeySizeInBits();

			if (maxKeySize < 0 || maxKeySize > 65535 || (size_t)maxKeySize > encKeySize)
				maxKeySize = (int)encKeySize;

			if (keyLen * 8 < maxKeySize)
			{
				LogError("The encryption key is too short.");
				return TSRETURN_ERROR(("The encryption key is too short."), false);
			}

			macKey.assign(key, maxKeySize / 8);
			keyLen -= maxKeySize / 8;
			key += maxKeySize / 8;
		}
		if (!m_hasher->initialize(macKey))
		{
			LogError("Unable to create the required data hash algorithm.");
			return TSRETURN_ERROR(("Unable to create the required data hash algorithm"), false);
		}
		macKey.clear();
	}

	m_reader->GoToPosition(0);

	if (ivecSize > 0)
	{
		m_encIvec = _ivec;

		if (m_encIvec.size() == 0)
		{
			// IVEC comes from the working key.
			if ((size_t)keyLen < ivecSize)
			{
				LogError("The encryption key is too short.");
				return TSRETURN_ERROR(("The encryption key is too short."), false);
			}

			m_encIvec.assign(key, ivecSize);
			keyLen -= (int)ivecSize;
			key += ivecSize;
		}
	}

	m_encIvec += encKey;

	m_counter.resize(4);

	m_taskName << "Decrypt";
	if (fifo != NULL)
	{
		if (!(fifo->ProcessAllData()))
		{
			LogError("Unable to decrypt the file.  ProcessAllData failed");
			return TSRETURN_ERROR(("FAILED"), false);
		}
	}
	else
	{
		while (!m_reader->IsEndOfFile())
		{
			if (m_hasFileSize)
				percent = (int)((100 * m_writer->CurrentPosition()) / m_fileSize);
			else
				percent = (int)((100 * m_writer->CurrentPosition()) / (m_writer->CurrentPosition() + m_blocksize));

			if (percent != m_oldPercent && !!m_status)
			{
				if (!(m_status->Status(m_taskName.c_str(), m_currentTask, m_taskCount, percent)))
				{
					LogError("Operation cancelled");
					return TSRETURN_ERROR(("Cancelled"), false);
				}
				m_oldPercent = percent;
			}

			if (!m_reader->ReadData(4, len))
			{
				return false;
			}
			if (len.size() == 0 && m_reader->IsEndOfFile())
				break;
			if (!!m_hasher)
			{
				if (!m_hasher->update(len))
				{
					LogError("Unable to compute the data hash.");
					return TSRETURN_ERROR(("Unable to compute the data hash."), false);
				}
			}

#if (BYTE_ORDER == LITTLE_ENDIAN)
			len.reverse();
#endif
			if (!m_reader->ReadData(*(int32_t *)len.c_str(), m_workingBuffer))
			{
				LogError("Data format invalid.");
				return TSRETURN_ERROR(("Data format invalid."), false);
			}
			if (m_workingBuffer.size() > 16)
			{
				tag.assign(&m_workingBuffer.c_str()[m_workingBuffer.size() - 16], 16);
				m_workingBuffer.resize(m_workingBuffer.size() - 16);
			}
			else
			{
				LogError("Data format invalid.");
				return TSRETURN_ERROR(("Data format invalid."), false);
			}

			if (!!m_hasher && !m_hasher->update(tag))
			{
				LogError("Unable to compute the data hash.");
				return TSRETURN_ERROR(("Unable to compute the data hash."), false);
			}

			// Each block is treated as a new encryption (new ivec, same key).  Compute the new ivec here
			m_counter.increment();
			if (!m_kdf->Derive_SP800_56A_Counter(m_encIvec, m_counter, 256 + 96, ivec))
			{
				LogError("The decryption key is too short.");
				return TSRETURN_ERROR(("The decryption key is too short."), false);
			}
			if (!m_gcm->initialize(ivec.substring(0, 32)))
			{
				LogError("Unable to initialize the decryption engine.");
				return TSRETURN_ERROR(("Unable to initialize the decryption engine."), false);
			}
			ivec.erase(0, 32);
			if (!m_gcm->decryptMessage(ivec, m_authHeader, m_workingBuffer, tag))
			{
				LogError("Unable to decrypt the file.  The tag does not match the computed value.");
				return TSRETURN_ERROR(("FAILED"), false);
			}

			if (!!m_compressor)
			{
				if (!(m_compressor->DecompressInit()) ||
					!(m_compressor->Decompress(m_workingBuffer, m_workingBuffer2, compAct_Run)) ||
					!(m_compressor->DecompressFinal(m_workingBuffer)))
				{
					LogError("Unable to decrypt the file.  The decompression operation failed.");
					return TSRETURN_ERROR(("FAILED"), false);
				}
				m_workingBuffer.insert(0, m_workingBuffer2);
			}
			if (m_workingBuffer.size() > 0)
			{
				LOG(DebugInfo3, "Writing " << m_workingBuffer.size() << " bytes of data to the output file");

				if (!m_writer->WriteData(m_workingBuffer))
				{
					LogError("Unable to write the decrypted data into the output file.");
					return TSRETURN_ERROR(("FAILED"), false);
				}
			}
		}
	}


	if (!!m_status)
	{
		if (!(m_status->Status(m_taskName.c_str(), m_currentTask, m_taskCount, 100)))
		{
			LogError("Operation cancelled");
			return TSRETURN_ERROR(("Cancelled"), false);
		}
	}

	if (!!m_hasher)
	{
		if (!m_hasher->finish(m_workingBuffer))
		{
			LogError("Unable to compute the data hash.");
			return TSRETURN_ERROR(("Unable to compute the data hash."), false);
		}

		if (m_workingBuffer.compare(finalHash) != 0)
		{
			LogError("Unable to decrypt the file - data hash invalid.");
			return TSRETURN_ERROR(("Unable to decrypt the file - data hash invalid"), false);
		}
	}
	return TSRETURN_ERROR(("OK"), true);
}

bool EncryptProcessor::DecryptHashedPart(std::shared_ptr<IFifoStream> fifo)
{
	MY_UNREFERENCED_PARAMETER(fifo);

	TSDECLARE_FUNCTIONExt(true);

	int percent;
	tscrypto::tsCryptoData len, tag, ivec;

	while (!m_reader->IsEndOfFile())
	{
		if (m_hasFileSize)
			percent = (int)((100 * m_writer->CurrentPosition()) / m_fileSize);
		else
			percent = (int)((100 * m_writer->CurrentPosition()) / (m_writer->CurrentPosition() + m_blocksize));

		if (percent != m_oldPercent && !!m_status)
		{
			if (!(m_status->Status(m_taskName.c_str(), m_currentTask, m_taskCount, percent)))
			{
				LogError("Operation cancelled");
				return TSRETURN_ERROR(("Cancelled"), false);
			}
			m_oldPercent = percent;
		}

		if (!m_reader->ReadData(m_blocksize, m_workingBuffer))
		{
			LogError("Data format invalid.");
			return TSRETURN_ERROR(("Data format invalid."), false);
		}
		if (m_workingBuffer.size() == 0)
			return TSRETURN(("OK"), true);

		if (!!m_hasher && !m_hashPlainText)
		{
			if (!m_hasher->update(m_workingBuffer))
			{
				LogError("Unable to compute the data hash.");
				return TSRETURN_ERROR(("Unable to compute the data hash."), false);
			}
		}

		if (m_workingBuffer.size() <= 0)
		{
			LogError("Data format invalid.");
			return TSRETURN_ERROR(("Data format invalid."), false);
		}

		if (!m_enc->update(m_workingBuffer, m_workingBuffer))
		{
			LogError("Unable to decrypt the file.  The decryption process failed.");
			return TSRETURN_ERROR(("FAILED"), false);
		}

		if (!!m_compressor)
		{
			if (!(m_compressor->Decompress(m_workingBuffer, m_workingBuffer2, compAct_Run)))
			{
				LogError("Unable to decrypt the file.  The decompression operation failed.");
				return TSRETURN_ERROR(("FAILED"), false);
			}
			m_workingBuffer = m_workingBuffer2;
		}
		if (m_workingBuffer.size() > 0)
		{
			if (!!m_hasher && m_hashPlainText)
			{
				if (!m_hasher->update(m_workingBuffer))
				{
					LogError("Unable to compute the data hash.");
					return TSRETURN_ERROR(("Unable to compute the data hash."), false);
				}
			}

			LOG(DebugInfo3, "Writing " << m_workingBuffer.size() << " bytes of data to the output file");

			if (!m_writer->WriteData(m_workingBuffer))
			{
				LogError("Unable to write the decrypted data into the output file.");
				return TSRETURN_ERROR(("FAILED"), false);
			}
		}
	}
	return TSRETURN(("OK"), true);
}

bool EncryptProcessor::DecryptHashed(const tscrypto::tsCryptoData &_key, std::shared_ptr<ICmsHeader> header, int headerSize, int blocksize, bool hashPlainText, std::shared_ptr<IFifoStream> fifo)
{
	TSDECLARE_FUNCTIONExt(true);

	SymmetricMode encMode;
	size_t encKeySize = 0, ivecSize = 0, encBlocksize;
	tscrypto::tsCryptoData encKey, macKey, ivec, tag;
	int percent;
	const BYTE *key = _key.c_str();
	int keyLen = (int)_key.size();

	m_fileSize = (int64_t)header->GetFileLength();
	m_hasFileSize = (m_fileSize > 0);
	m_hashPlainText = hashPlainText;
	m_blocksize = blocksize;

	if (header->GetDataHash().size() != 0)
	{
		if (!(m_hasher = std::dynamic_pointer_cast<MessageAuthenticationCode>(CryptoFactory(header->GetDataHashOID().ToOIDString()))))
			return TSRETURN_ERROR(("Unable to create the data hash algorithm."), false);
	}

	tscrypto::TS_ALG_ID encAlg = header->GetEncryptionAlgorithmID();
	encMode = Alg2Mode(encAlg);

	if (!(m_enc = std::dynamic_pointer_cast<Symmetric>(CryptoFactory(header->GetEncryptionAlgorithmOID().ToOIDString()))))
	{
		LogError("Unable to create the required data encryption algorithm.");
		return TSRETURN_ERROR(("Unable to create the required data encryption algorithm."), false);
	}

	encKeySize = CryptoKeySize(encAlg);
	ivecSize = CryptoIVECSize(encAlg);
	encBlocksize = CryptoBlockSize(encAlg);

	if (encKeySize == 0 || encBlocksize == 0)
	{
		LogError("Unable to retrieve the required data encryption algorithm parameters.");
		return TSRETURN_ERROR(("Unable to retrieve the required data encryption algorithm parameters."), false);
	}

	if ((size_t)keyLen * 8 < encKeySize)
	{
		LogError("The encryption key is too short.");
		return TSRETURN_ERROR(("The encryption key is too short."), false);
	}

	switch (header->GetCompressionType())
	{
	case ct_BZ2:
	case ct_zLib:
		if (!(m_compressor = CreateCompressor(header->GetCompressionType())))
		{
			LogError("The compression type is not recognized.");
			return TSRETURN_ERROR(("The compression type is not recognized."), false);
		}
		break;
	case ct_None:
		break;
	default:
		LogError("The compression type is not recognized.");
		return TSRETURN_ERROR(("The compression type is not recognized."), false);
	}
	encKey.assign(key, encKeySize / 8);
	keyLen -= (int)encKeySize / 8;
	key += encKeySize / 8;

	if (!!m_hasher)
	{
		m_authHeader = computeHeaderIdentity(header);

		if (m_hasher->requiresKey())
		{
			int maxKeySize = (int)m_hasher->maximumKeySizeInBits();

			if (maxKeySize < 0 || maxKeySize > 65535 || (size_t)maxKeySize > encKeySize)
				maxKeySize = (int)encKeySize;

			if (keyLen * 8 < maxKeySize)
			{
				LogError("The encryption key is too short.");
				return TSRETURN_ERROR(("The encryption key is too short."), false);
			}

			macKey.assign(key, maxKeySize / 8);
			keyLen -= maxKeySize / 8;
			key += maxKeySize / 8;
		}
		if (!m_hasher->initialize(macKey) || !m_hasher->update(m_authHeader))
		{
			LogError("Unable to create the required data hash algorithm.");
			return TSRETURN_ERROR(("Unable to create the required data hash algorithm"), false);
		}
		macKey.clear();
	}

	m_reader->GoToPosition(headerSize);

	if (ivecSize > 0)
	{
		m_encIvec = header->GetIVEC();

		if (m_encIvec.size() == 0)
		{
			// IVEC comes from the working key.
			if ((size_t)keyLen < ivecSize)
			{
				LogError("The encryption key is too short.");
				return TSRETURN_ERROR(("The encryption key is too short."), false);
			}

			m_encIvec.assign(key, ivecSize);
			keyLen -= (int)ivecSize;
			key += ivecSize;
		}
	}

	// Each block is treated as a new encryption (new ivec, same key).  We only need to initialize once.
	if (!m_enc->init(false, encMode, encKey, m_encIvec))
	{
		LogError("Unable to initialize the bulk data encryptor.");
		return TSRETURN_ERROR(("Unable to initialize the bulk data encryptor."), false);
	}

	m_counter.resize(4);

	m_enc->setPaddingType(header->GetPaddingType());

	if (!!m_compressor)
	{
		if (!(m_compressor->DecompressInit()))
		{
			LogError("Unable to decrypt the file.  The decompression operation failed.");
			return TSRETURN_ERROR(("FAILED"), false);
		}
	}

	m_taskName << "Decrypt " << header->GetDataName();
	if (fifo != NULL)
	{
		if (!(fifo->ProcessAllData()))
		{
			LogError("Unable to decrypt the file.  ProcessAllData failed");
			return TSRETURN_ERROR(("FAILED"), false);
		}
	}
	else
	{
		while (!m_reader->IsEndOfFile())
		{
			if (m_hasFileSize)
				percent = (int)((100 * m_writer->CurrentPosition()) / m_fileSize);
			else
				percent = (int)((100 * m_writer->CurrentPosition()) / (m_writer->CurrentPosition() + blocksize));

			if (percent != m_oldPercent && !!m_status)
			{
				if (!(m_status->Status(m_taskName.c_str(), m_currentTask, m_taskCount, percent)))
				{
					LogError("Operation cancelled");
					return TSRETURN_ERROR(("Cancelled"), false);
				}
				m_oldPercent = percent;
			}

			if (!m_reader->ReadData(blocksize, m_workingBuffer))
			{
				LogError("Data format invalid.");
				return TSRETURN_ERROR(("Data format invalid."), false);
			}
			if (m_workingBuffer.size() == 0 && m_reader->IsEndOfFile())
				break;

			if (!!m_hasher && !m_hashPlainText)
			{
				if (!m_hasher->update(m_workingBuffer))
				{
					LogError("Unable to compute the data hash.");
					return TSRETURN_ERROR(("Unable to compute the data hash."), false);
				}
			}

			if (m_workingBuffer.size() <= 0)
			{
				LogError("Data format invalid.");
				return TSRETURN_ERROR(("Data format invalid."), false);
			}

			if (!m_enc->update(m_workingBuffer, m_workingBuffer))
			{
				LogError("Unable to decrypt the file.  The decryption operation failed.");
				return TSRETURN_ERROR(("FAILED"), false);
			}

			if (!!m_compressor)
			{
				if (!(m_compressor->Decompress(m_workingBuffer, m_workingBuffer2, compAct_Run)))
				{
					LogError("Unable to decrypt the file.  The decompression operation failed.");
					return TSRETURN_ERROR(("FAILED"), false);
				}
				m_workingBuffer = m_workingBuffer2;
			}
			if (m_workingBuffer.size() > 0)
			{
				if (!!m_hasher && m_hashPlainText)
				{
					if (!m_hasher->update(m_workingBuffer))
					{
						LogError("Unable to compute the data hash.");
						return TSRETURN_ERROR(("Unable to compute the data hash."), false);
					}
				}

				LOG(DebugInfo3, "Writing " << m_workingBuffer.size() << " bytes of data to the output file");

				if (!m_writer->WriteData(m_workingBuffer))
				{
					LogError("Unable to write the decrypted data into the output file.");
					return TSRETURN_ERROR(("FAILED"), false);
				}
			}
		}
	}

	if (!!m_status)
	{
		if (!(m_status->Status(m_taskName.c_str(), m_currentTask, m_taskCount, 100)))
		{
			LogError("Operation cancelled");
			return TSRETURN_ERROR(("Cancelled"), false);
		}
	}

	if (!m_enc->finish(m_workingBuffer))
	{
		LogError("Unable to decrypt the file.  The decryption operation could not finish.");
		return TSRETURN_ERROR(("FAILED"), false);
	}
	if (!!m_compressor)
	{
		m_workingBuffer2.clear();
		if (m_workingBuffer.size() > 0)
		{
			if (!(m_compressor->Decompress(m_workingBuffer, m_workingBuffer2, compAct_Run)))
			{
				LogError("Unable to decrypt the file.  The decompression operation failed.");
				return TSRETURN_ERROR(("FAILED"), false);
			}
		}
		m_workingBuffer.clear();
		if (!(m_compressor->DecompressFinal(m_workingBuffer)))
		{
			LogError("Unable to decrypt the file.  The decompression operation failed.");
			return TSRETURN_ERROR(("FAILED"), false);
		}
		m_workingBuffer.insert(0, m_workingBuffer2);
	}
	if (m_workingBuffer.size() > 0)
	{
		if (!!m_hasher && hashPlainText)
		{
			if (!m_hasher->update(m_workingBuffer))
			{
				LogError("Unable to compute the data hash.");
				return TSRETURN_ERROR(("Unable to compute the data hash."), false);
			}
		}

		LOG(DebugInfo3, "Writing " << m_workingBuffer.size() << " bytes of data to the output file");

		if (!m_writer->WriteData(m_workingBuffer))
		{
			LogError("Unable to write the decrypted data into the output file.");
			return TSRETURN_ERROR(("FAILED"), false);
		}
	}

	if (!!m_hasher)
	{
		if (!m_hasher->finish(m_workingBuffer))
		{
			LogError("Unable to compute the data hash.");
			return TSRETURN_ERROR(("Unable to compute the data hash."), false);
		}

		if (m_workingBuffer.compare(header->GetDataHash()) != 0)
		{
			LogError("Unable to decrypt the file - data hash invalid.");
			return TSRETURN_ERROR(("Unable to decrypt the file - data hash invalid"), false);
		}
	}
	return TSRETURN_ERROR(("OK"), true);
}
bool EncryptProcessor::DecryptHashed(const tscrypto::tsCryptoData &_key, int blocksize, bool hashPlainText, std::shared_ptr<IFifoStream> fifo,
	tscrypto::TS_ALG_ID encAlg, const tscrypto::tsCryptoData &hashOid, CompressionType compType, const tscrypto::tsCryptoData &_ivec, tscrypto::SymmetricPaddingType padding, const tscrypto::tsCryptoData &authData, const tscrypto::tsCryptoData &finalHash)
{
	TSDECLARE_FUNCTIONExt(true);

	SymmetricMode encMode;
	size_t encKeySize = 0, ivecSize = 0, encBlocksize;
	tscrypto::tsCryptoData encKey, macKey, ivec, tag;
	int percent;
	const BYTE *key = _key.c_str();
	int keyLen = (int)_key.size();

	if (m_reader->KnowsRemainingData())
		m_fileSize = m_reader->RemainingData();
	else
		m_fileSize = 0;
	m_hasFileSize = (m_fileSize > 0);
	m_hashPlainText = hashPlainText;
	m_blocksize = blocksize;

	if (hashOid.size() != 0)
	{
		if (!(m_hasher = std::dynamic_pointer_cast<MessageAuthenticationCode>(CryptoFactory(hashOid.ToOIDString()))))
			return TSRETURN_ERROR(("Unable to create the data hash algorithm."), false);
	}

	encMode = Alg2Mode(encAlg);

	if (!(m_enc = std::dynamic_pointer_cast<Symmetric>(CryptoFactory(encAlg))))
	{
		LogError("Unable to create the required data encryption algorithm.");
		return TSRETURN_ERROR(("Unable to create the required data encryption algorithm."), false);
	}

	encKeySize = CryptoKeySize(encAlg);
	ivecSize = CryptoIVECSize(encAlg);
	encBlocksize = CryptoBlockSize(encAlg);

	if (encKeySize == 0 || encBlocksize == 0)
	{
		LogError("Unable to retrieve the required data encryption algorithm parameters.");
		return TSRETURN_ERROR(("Unable to retrieve the required data encryption algorithm parameters."), false);
	}

	if ((size_t)keyLen * 8 < encKeySize)
	{
		LogError("The encryption key is too short.");
		return TSRETURN_ERROR(("The encryption key is too short."), false);
	}

	switch (compType)
	{
	case ct_BZ2:
	case ct_zLib:
		if (!(m_compressor = CreateCompressor(compType)))
		{
			LogError("The compression type is not recognized.");
			return TSRETURN_ERROR(("The compression type is not recognized."), false);
		}
		break;
	case ct_None:
		break;
	default:
		LogError("The compression type is not recognized.");
		return TSRETURN_ERROR(("The compression type is not recognized."), false);
	}
	encKey.assign(key, encKeySize / 8);
	keyLen -= (int)encKeySize / 8;
	key += encKeySize / 8;

	if (!!m_hasher)
	{
		m_authHeader = authData;

		if (m_hasher->requiresKey())
		{
			int maxKeySize = (int)m_hasher->maximumKeySizeInBits();

			if (maxKeySize < 0 || maxKeySize > 65535 || (size_t)maxKeySize > encKeySize)
				maxKeySize = (int)encKeySize;

			if (keyLen * 8 < maxKeySize)
			{
				LogError("The encryption key is too short.");
				return TSRETURN_ERROR(("The encryption key is too short."), false);
			}

			macKey.assign(key, maxKeySize / 8);
			keyLen -= maxKeySize / 8;
			key += maxKeySize / 8;
		}
		if (!m_hasher->initialize(macKey) || !m_hasher->update(m_authHeader))
		{
			LogError("Unable to create the required data hash algorithm.");
			return TSRETURN_ERROR(("Unable to create the required data hash algorithm"), false);
		}
		macKey.clear();
	}

	m_reader->GoToPosition(0);

	if (ivecSize > 0)
	{
		m_encIvec = _ivec;

		if (m_encIvec.size() == 0)
		{
			// IVEC comes from the working key.
			if ((size_t)keyLen < ivecSize)
			{
				LogError("The encryption key is too short.");
				return TSRETURN_ERROR(("The encryption key is too short."), false);
			}

			m_encIvec.assign(key, ivecSize);
			keyLen -= (int)ivecSize;
			key += ivecSize;
		}
	}

	// Each block is treated as a new encryption (new ivec, same key).  We only need to initialize once.
	if (!m_enc->init(false, encMode, encKey, m_encIvec))
	{
		LogError("Unable to initialize the bulk data encryptor.");
		return TSRETURN_ERROR(("Unable to initialize the bulk data encryptor."), false);
	}

	m_counter.resize(4);

	m_enc->setPaddingType(padding);

	if (!!m_compressor)
	{
		if (!(m_compressor->DecompressInit()))
		{
			LogError("Unable to decrypt the file.  The decompression operation failed.");
			return TSRETURN_ERROR(("FAILED"), false);
		}
	}

	m_taskName << "Decrypt";
	if (fifo != NULL)
	{
		if (!(fifo->ProcessAllData()))
		{
			LogError("Unable to decrypt the file.  ProcessAllData failed");
			return TSRETURN_ERROR(("FAILED"), false);
		}
	}
	else
	{
		while (!m_reader->IsEndOfFile())
		{
			if (m_hasFileSize)
				percent = (int)((100 * m_writer->CurrentPosition()) / m_fileSize);
			else
				percent = (int)((100 * m_writer->CurrentPosition()) / (m_writer->CurrentPosition() + blocksize));

			if (percent != m_oldPercent && !!m_status)
			{
				if (!(m_status->Status(m_taskName.c_str(), m_currentTask, m_taskCount, percent)))
				{
					LogError("Operation cancelled");
					return TSRETURN_ERROR(("Cancelled"), false);
				}
				m_oldPercent = percent;
			}

			if (!m_reader->ReadData(blocksize, m_workingBuffer))
			{
				LogError("Data format invalid.");
				return TSRETURN_ERROR(("Data format invalid."), false);
			}
			if (m_workingBuffer.size() == 0 && m_reader->IsEndOfFile())
				break;

			if (!!m_hasher && !m_hashPlainText)
			{
				if (!m_hasher->update(m_workingBuffer))
				{
					LogError("Unable to compute the data hash.");
					return TSRETURN_ERROR(("Unable to compute the data hash."), false);
				}
			}

			if (m_workingBuffer.size() <= 0)
			{
				LogError("Data format invalid.");
				return TSRETURN_ERROR(("Data format invalid."), false);
			}

			if (!m_enc->update(m_workingBuffer, m_workingBuffer))
			{
				LogError("Unable to decrypt the file.  The decryption operation failed.");
				return TSRETURN_ERROR(("FAILED"), false);
			}

			if (!!m_compressor)
			{
				if (!(m_compressor->Decompress(m_workingBuffer, m_workingBuffer2, compAct_Run)))
				{
					LogError("Unable to decrypt the file.  The decompression operation failed.");
					return TSRETURN_ERROR(("FAILED"), false);
				}
				m_workingBuffer = m_workingBuffer2;
			}
			if (m_workingBuffer.size() > 0)
			{
				if (!!m_hasher && m_hashPlainText)
				{
					if (!m_hasher->update(m_workingBuffer))
					{
						LogError("Unable to compute the data hash.");
						return TSRETURN_ERROR(("Unable to compute the data hash."), false);
					}
				}

				LOG(DebugInfo3, "Writing " << m_workingBuffer.size() << " bytes of data to the output file");

				if (!m_writer->WriteData(m_workingBuffer))
				{
					LogError("Unable to write the decrypted data into the output file.");
					return TSRETURN_ERROR(("FAILED"), false);
				}
			}
		}
	}

	if (!!m_status)
	{
		if (!(m_status->Status(m_taskName.c_str(), m_currentTask, m_taskCount, 100)))
		{
			LogError("Operation cancelled");
			return TSRETURN_ERROR(("Cancelled"), false);
		}
	}

	if (!m_enc->finish(m_workingBuffer))
	{
		LogError("Unable to decrypt the file.  The decryption operation could not finish.");
		return TSRETURN_ERROR(("FAILED"), false);
	}
	if (!!m_compressor)
	{
		m_workingBuffer2.clear();
		if (m_workingBuffer.size() > 0)
		{
			if (!(m_compressor->Decompress(m_workingBuffer, m_workingBuffer2, compAct_Run)))
			{
				LogError("Unable to decrypt the file.  The decompression operation failed.");
				return TSRETURN_ERROR(("FAILED"), false);
			}
		}
		m_workingBuffer.clear();
		if (!(m_compressor->DecompressFinal(m_workingBuffer)))
		{
			LogError("Unable to decrypt the file.  The decompression operation failed.");
			return TSRETURN_ERROR(("FAILED"), false);
		}
		m_workingBuffer.insert(0, m_workingBuffer2);
	}
	if (m_workingBuffer.size() > 0)
	{
		if (!!m_hasher && hashPlainText)
		{
			if (!m_hasher->update(m_workingBuffer))
			{
				LogError("Unable to compute the data hash.");
				return TSRETURN_ERROR(("Unable to compute the data hash."), false);
			}
		}

		LOG(DebugInfo3, "Writing " << m_workingBuffer.size() << " bytes of data to the output file");

		if (!m_writer->WriteData(m_workingBuffer))
		{
			LogError("Unable to write the decrypted data into the output file.");
			return TSRETURN_ERROR(("FAILED"), false);
		}
	}

	if (!!m_hasher)
	{
		if (!m_hasher->finish(m_workingBuffer))
		{
			LogError("Unable to compute the data hash.");
			return TSRETURN_ERROR(("Unable to compute the data hash."), false);
		}

		if (m_workingBuffer.compare(finalHash) != 0)
		{
			LogError("Unable to decrypt the file - data hash invalid.");
			return TSRETURN_ERROR(("Unable to decrypt the file - data hash invalid"), false);
		}
	}
	return TSRETURN_ERROR(("OK"), true);
}

bool EncryptProcessor::PrevalidateData(std::shared_ptr<ICmsHeaderBase> header)
{
	TSDECLARE_FUNCTIONExt(true);

	int format;
	int blocksize;
	std::shared_ptr<ICmsHeader> header7;
	int64_t origPosition;
	bool retVal;

	if (header == NULL)
		return false;
	if (!(header7 = std::dynamic_pointer_cast<ICmsHeader>(header)))
	{
		LogError("Error:  header is invalid");
		return TSRETURN_ERROR(("Bad Header"), false);
	}

	if (!header7->GetDataFormat(blocksize, format))
	{
		blocksize = 0;
		format = TS_FORMAT_CMS_PT_HASHED;
	}

	if (!m_reader->AllowsRandomAccess())
		return TSRETURN_ERROR(("FALSE"), true);

	origPosition = m_reader->CurrentPosition();

	switch (format)
	{
	case TS_FORMAT_CMS_CT_HASHED:
		retVal = ValidateHashedFormat(header7, header7->PaddedHeaderSize(), m_reader->DataLength(), false);
		break;
	case TS_FORMAT_CMS_PT_HASHED:
		retVal = ValidateHashedFormat(header7, header7->PaddedHeaderSize(), m_reader->DataLength(), true);
		break;
	case TS_FORMAT_CMS_ENC_AUTH:
		retVal = ValidateEncAuthFormat(header7, header7->PaddedHeaderSize(), m_reader->DataLength());
		break;
	default:
		LogError("Error:  Unrecognized file format.");
		return TSRETURN_ERROR(("Bad File"), false);
	}
	m_reader->GoToPosition(origPosition);

	if (!retVal)
	{
		return TSRETURN_ERROR(("Invalid format"), false);
	}

	return TSRETURN_ERROR(("OK"), true);
}

bool EncryptProcessor::PrevalidateDataHash(const tscrypto::tsCryptoData &finalHash, const tscrypto::tsCryptoData &hashOid, const tscrypto::tsCryptoData &authData, int format)
{
	TSDECLARE_FUNCTIONExt(true);

	int64_t origPosition;
	bool retVal;

	if (!m_reader->AllowsRandomAccess())
		return TSRETURN_ERROR(("FALSE"), true);

	origPosition = m_reader->CurrentPosition();

	switch (format)
	{
	case TS_FORMAT_CMS_CT_HASHED:
		retVal = ValidateHashedFormat(finalHash, hashOid, authData, m_reader->DataLength(), false);
		break;
	case TS_FORMAT_CMS_PT_HASHED:
		retVal = ValidateHashedFormat(finalHash, hashOid, authData, m_reader->DataLength(), true);
		break;
	case TS_FORMAT_CMS_ENC_AUTH:
		retVal = ValidateEncAuthFormat(finalHash, hashOid, authData, m_reader->DataLength());
		break;
	default:
		LogError("Error:  Unrecognized file format.");
		return TSRETURN_ERROR(("Bad File"), false);
	}
	m_reader->GoToPosition(origPosition);

	if (!retVal)
	{
		return TSRETURN_ERROR(("Invalid format"), false);
	}

	return TSRETURN_ERROR(("OK"), true);
}

bool EncryptProcessor::ValidateEncAuthFormat(std::shared_ptr<ICmsHeader> header, int64_t headerSize, int64_t fileSize)
{
	tscrypto::tsCryptoData tmp;
	std::shared_ptr<MessageAuthenticationCode> hasher;

	// Validate file data signature here

	if (header->GetDataHash().size() == 0)
		return true;

	if (!m_reader->AllowsRandomAccess())
		return true;

	if (!(hasher = std::dynamic_pointer_cast<MessageAuthenticationCode>(CryptoFactory(header->GetDataHashOID().ToOIDString()))))
		return false;

	if (hasher->requiresKey())
		return true;

	if (!hasher->initialize(tscrypto::tsCryptoData()))
		return false;

	m_reader->GoToPosition(headerSize);

	while (m_reader->CurrentPosition() < fileSize)
	{
		if (!m_reader->ReadData(4, tmp))
		{
			return false;
		}
		if (!hasher->update(tmp))
			return false;

#if (BYTE_ORDER == LITTLE_ENDIAN)
		tmp.reverse();
#endif
		if (*(int32_t*)tmp.c_str() < 16 || m_reader->CurrentPosition() + *(int32_t*)tmp.c_str() > fileSize)
			return false;

		m_reader->GoToPosition(m_reader->CurrentPosition() + *(int32_t*)tmp.c_str() - 16);

		if (!m_reader->ReadData(16, tmp))
		{
			return false;
		}
		if (!hasher->update(tmp))
			return false;
	}
	if (!hasher->finish(tmp))
		return false;

	if (tmp.compare(header->GetDataHash()) != 0)
		return false;
	return true;
}
bool EncryptProcessor::ValidateEncAuthFormat(const tscrypto::tsCryptoData &finalhash, const tscrypto::tsCryptoData &hashOid, const tscrypto::tsCryptoData &authData, int64_t fileSize)
{
	MY_UNREFERENCED_PARAMETER(authData);

	tscrypto::tsCryptoData tmp;
	std::shared_ptr<MessageAuthenticationCode> hasher;

	// Validate file data signature here

	if (finalhash.size() == 0)
		return true;

	if (!m_reader->AllowsRandomAccess())
		return true;

	if (!(hasher = std::dynamic_pointer_cast<MessageAuthenticationCode>(CryptoFactory(hashOid.ToOIDString()))))
		return false;

	if (hasher->requiresKey())
		return true;

	if (!hasher->initialize(tscrypto::tsCryptoData()))
		return false;

	while (m_reader->CurrentPosition() < fileSize)
	{
		if (!m_reader->ReadData(4, tmp))
		{
			return false;
		}
		if (!hasher->update(tmp))
			return false;

#if (BYTE_ORDER == LITTLE_ENDIAN)
		tmp.reverse();
#endif
		if (*(int32_t*)tmp.c_str() < 16 || m_reader->CurrentPosition() + *(int32_t*)tmp.c_str() > fileSize)
			return false;

		m_reader->GoToPosition(m_reader->CurrentPosition() + *(int32_t*)tmp.c_str() - 16);

		if (!m_reader->ReadData(16, tmp))
		{
			return false;
		}
		if (!hasher->update(tmp))
			return false;
	}
	if (!hasher->finish(tmp))
		return false;

	if (tmp.compare(finalhash) != 0)
		return false;
	return true;
}

bool EncryptProcessor::ValidateHashedFormat(std::shared_ptr<ICmsHeader> header, int64_t headerSize, int64_t fileSize, bool plaintext)
{
	tscrypto::tsCryptoData tmp;
	std::shared_ptr<MessageAuthenticationCode> hasher;

	// Validate file data signature here

	if (header->GetDataHash().size() == 0)
		return true;

	if (!m_reader->AllowsRandomAccess() || plaintext)
		return true;

	if (!(hasher = std::dynamic_pointer_cast<MessageAuthenticationCode>(CryptoFactory(header->GetDataHashOID().ToOIDString()))))
		return false;

	if (hasher->requiresKey())
		return true;

	if (!hasher->initialize(tscrypto::tsCryptoData()))
		return false;

	m_reader->GoToPosition(headerSize);

	tscrypto::tsCryptoData authHeader = computeHeaderIdentity(header);

	if (!hasher->update(authHeader))
		return false;

	while (m_reader->CurrentPosition() < fileSize)
	{
		if (!m_reader->ReadData(65536, tmp))
		{
			return false;
		}
		if (!hasher->update(tmp))
			return false;
	}
	if (!hasher->finish(tmp))
		return false;

	if (tmp.compare(header->GetDataHash()) != 0)
		return false;
	return true;
}
bool EncryptProcessor::ValidateHashedFormat(const tscrypto::tsCryptoData &finalhash, const tscrypto::tsCryptoData &hashOid, const tscrypto::tsCryptoData &authData, int64_t fileSize, bool plaintext)
{
	tscrypto::tsCryptoData tmp;
	std::shared_ptr<MessageAuthenticationCode> hasher;

	// Validate file data signature here

	if (finalhash.size() == 0)
		return true;

	if (!m_reader->AllowsRandomAccess() || plaintext)
		return true;

	if (!(hasher = std::dynamic_pointer_cast<MessageAuthenticationCode>(CryptoFactory(hashOid.ToOIDString()))))
		return false;

	if (hasher->requiresKey())
		return true;

	if (!hasher->initialize(tscrypto::tsCryptoData()))
		return false;

	if (!hasher->update(authData))
		return false;

	while (m_reader->CurrentPosition() < fileSize)
	{
		if (!m_reader->ReadData(65536, tmp))
		{
			return false;
		}
		if (!hasher->update(tmp))
			return false;
	}
	if (!hasher->finish(tmp))
		return false;

	if (tmp.compare(finalhash) != 0)
		return false;
	return true;
}

bool EncryptProcessor::DataAvailable(std::shared_ptr<IFifoStream> fifo)
{
	TSDECLARE_FUNCTIONExt(true);

	bool retVal;

	if (fifo == NULL || !m_writer)
		return TSRETURN_ERROR(("E_POINTER"), false);

	if (m_processingEncrypt)
	{
		switch (m_format)
		{
		case TS_FORMAT_CMS_CT_HASHED:
		case TS_FORMAT_CMS_PT_HASHED:
			retVal = EncryptHashedPart(fifo);
			break;
		case TS_FORMAT_CMS_ENC_AUTH:
			retVal = EncryptEncAuthPart(fifo);
			break;
		default:
			return TSRETURN_ERROR(("Returns ~~"), false);
		}
	}
	else
	{
		switch (m_format)
		{
		case TS_FORMAT_CMS_PT_HASHED:
		case TS_FORMAT_CMS_CT_HASHED:
			retVal = DecryptHashedPart(fifo);
			break;
		case TS_FORMAT_CMS_ENC_AUTH:
			retVal = DecryptEncAuthPart(fifo);
			break;
		default:
			return TSRETURN_ERROR(("Returns ~~"), false);
		}
	}
	if (!retVal)
	{
		return TSRETURN_ERROR(("Returns ~~"), false);
	}
	return TSRETURN(("OK"), true);
}

void EncryptProcessor::ClearStreamVariables()
{
	m_processingEncrypt = false;
	m_format = TS_FORMAT_CMS_ENC_AUTH;
	m_hasher.reset();
	m_compressor.reset();
	m_fileSize = 0;
	m_hasFileSize = false;
	m_blocksize = 0;
	m_oldPercent = -1;
	m_nextLen = 0;
	m_workingBuffer.clear();
	m_workingBuffer2.clear();
	m_taskName.clear();
	// GCM parts
	m_gcm.reset();
	m_kdf.reset();
	m_counter.clear();
	m_encIvec.clear();
	m_authHeader.clear();
	// SYM parts
	m_enc.reset();
	m_hashPlainText = false;
}
