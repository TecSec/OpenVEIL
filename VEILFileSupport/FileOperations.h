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

#ifndef FILEOPERATIONS_H_INCLUDED
#define FILEOPERATIONS_H_INCLUDED

class FileVEILOperationsImpl : public IFileVEILOperations, public tsmod::IObject
{
public:
	FileVEILOperationsImpl();
	virtual bool SetStatusInterface(std::shared_ptr<IFileVEILOperationStatus> status) override;
	virtual bool SetSession(std::shared_ptr<IKeyVEILSession> session) override;
	virtual bool SetKeyGenCallback(std::shared_ptr<IKeyGenCallback> callback) override;

    virtual bool secureDelete(const tscrypto::tsCryptoString& inFilename, int inDeletePasses) override;
	virtual bool GetStreamNames(const tscrypto::tsCryptoString& sFile, std::shared_ptr<IVEILFileList>& pVal) override;

	virtual bool  FileStartsWithCmsHeader(const tscrypto::tsCryptoString& filename, std::shared_ptr<ICmsHeaderBase>& pVal) override;
	virtual bool    StreamStartsWithCmsHeader(std::shared_ptr<IDataReader> stream, std::shared_ptr<ICmsHeaderBase>& pVal) override;

	virtual bool EncryptFile(const tscrypto::tsCryptoString& sFile, const tscrypto::tsCryptoString& sEncrFile, std::shared_ptr<ICmsHeader> header, CompressionType comp, tscrypto::TS_ALG_ID algorithm, tscrypto::TS_ALG_ID hashAlgorithm,
		bool SignHeader, bool bindData, CMSFileFormatIds DataFormat, bool randomIvec, tscrypto::SymmetricPaddingType paddingType, int blockSize) override;
	virtual bool EncryptStream(std::shared_ptr<IDataReader> sFile, std::shared_ptr<IDataWriter> sEncrFile, std::shared_ptr<ICmsHeader> header, CompressionType comp, tscrypto::TS_ALG_ID algorithm,
		tscrypto::TS_ALG_ID hashAlgorithm, bool SignHeader, bool bindData, CMSFileFormatIds DataFormat, bool randomIvec, tscrypto::SymmetricPaddingType paddingType, int blockSize) override;
	virtual bool EncryptFileAndStreams(const tscrypto::tsCryptoString& sFile, const tscrypto::tsCryptoString& sEncrFile, std::shared_ptr<ICmsHeader> header, CompressionType comp, tscrypto::TS_ALG_ID algorithm, tscrypto::TS_ALG_ID hashAlgorithm,
		bool SignHeader, bool bindData, CMSFileFormatIds DataFormat, bool randomIvec, tscrypto::SymmetricPaddingType paddingType, int blockSize) override;

	virtual bool DecryptStream(std::shared_ptr<IDataReader> sFile, std::shared_ptr<IDataWriter> sDecrFile) override;
	virtual bool DecryptFileAndStreams(const tscrypto::tsCryptoString& sFile, const tscrypto::tsCryptoString& sDecrFile) override;

	virtual bool ValidateFileContents_PublicOnly( const tscrypto::tsCryptoString& sFile ) override;
	virtual bool SetSessionCallback(std::shared_ptr<IFileVEILSessionCallback> callback) override;
	virtual bool DecryptStreamWithHeader(std::shared_ptr<IDataReader> sFile, std::shared_ptr<IDataWriter> sDecrFile, std::shared_ptr<ICmsHeaderBase>& header) override;
	virtual bool EncryptCryptoData(const tscrypto::tsCryptoData &inputData, tscrypto::tsCryptoData &outputData, std::shared_ptr<ICmsHeader> header, CompressionType comp, tscrypto::TS_ALG_ID algorithm, tscrypto::TS_ALG_ID hashAlgorithm,
		bool SignHeader, bool bindData, CMSFileFormatIds DataFormat, bool randomIvec, tscrypto::SymmetricPaddingType paddingType, int blockSize) override;
    virtual bool RecoverKeys(const tscrypto::tsCryptoString& inputFile, FileVEILFileOp_recoveredKeyList& keys) override;
	virtual bool DecryptCryptoData(const tscrypto::tsCryptoData &inputData, tscrypto::tsCryptoData &outputData) override;
	virtual bool DecryptCryptoDataWithHeader(const tscrypto::tsCryptoData &inputData, tscrypto::tsCryptoData &outputData, std::shared_ptr<ICmsHeaderBase>& header) override;
	virtual bool  DataStartsWithCmsHeader(const tscrypto::tsCryptoData& contents, std::shared_ptr<ICmsHeaderBase>& pVal) override;

private:
	virtual ~FileVEILOperationsImpl();
    bool secureDeleteEntireFile(const tscrypto::tsCryptoString& inFilename, int inDeletePasses);
    bool secureDeleteFile(const tscrypto::tsCryptoString& inFilename, int inDeletePasses);
    bool secureDeleteStreams(const tscrypto::tsCryptoString& inFilename, int inDeletePasses);
	bool EncryptSignFile(const tscrypto::tsCryptoString &sFilename, const tscrypto::tsCryptoString &sEncryptedFilename, const tscrypto::tsCryptoString &lpszTempFile, std::shared_ptr<ICmsHeader> Header, CompressionType comp, tscrypto::TS_ALG_ID algorithm,
		tscrypto::TS_ALG_ID hashAlgorithm, bool SignHeader, bool bindData, CMSFileFormatIds DataFormat, bool randomIvec, tscrypto::SymmetricPaddingType paddingType, int blockSize);
	bool EncryptSignStream(std::shared_ptr<IDataReader> inputData, std::shared_ptr<IDataWriter> outputData, std::shared_ptr<ICmsHeader> Header, CompressionType comp, tscrypto::TS_ALG_ID algorithm,
		tscrypto::TS_ALG_ID hashAlgorithm, bool SignHeader, bool bindData, CMSFileFormatIds DataFormat, bool randomIvec, tscrypto::SymmetricPaddingType paddingType, int blockSize);
    bool DecryptVerify(const tscrypto::tsCryptoString &sFilename, const tscrypto::tsCryptoString &sDecryptedFilename, const tscrypto::tsCryptoString &lpszTempFile);
	bool DecryptVerify(std::shared_ptr<ICmsHeader> header, const tscrypto::tsCryptoString &sFilename, const tscrypto::tsCryptoString &sDecryptedFilename, const tscrypto::tsCryptoString &lpszTempFile, const tscrypto::tsCryptoString &sTempFile, bool headerIncluded);
	bool DecryptVerify(std::shared_ptr<ICmsHeader> header, std::shared_ptr<IDataReader> reader, std::shared_ptr<IDataWriter> writer, bool headerIncluded);
    void    LogError(tscrypto::tsCryptoString error, ...);
	bool PrepareHeader(std::shared_ptr<ICmsHeader> header7, CompressionType comp, tscrypto::TS_ALG_ID algorithm, tscrypto::TS_ALG_ID hashAlgorithm, bool SignHeader, bool bindData,
							CMSFileFormatIds DataFormat, bool randomIvec, tscrypto::SymmetricPaddingType paddingType, int blockSize, int64_t fileSize);
    bool RegenerateStreamKey(const tscrypto::tsCryptoString &sFilename, tscrypto::tsCryptoData& headerSignature, tscrypto::tsCryptoData& workingKey);

    std::shared_ptr<IFileVEILOperationStatus>    m_status;
    std::shared_ptr<IKeyVEILSession>             m_session;
	std::shared_ptr<IKeyGenCallback>             m_keyGenCallback;
	std::shared_ptr<IFileVEILSessionCallback>    m_sessionCallback;
    DWORD                                        m_taskCount;
    DWORD                                        m_currentTask;
};

#endif // FILEOPERATIONS_H_INCLUDED
