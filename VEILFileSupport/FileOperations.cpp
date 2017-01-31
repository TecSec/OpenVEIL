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

#include "stdafx.h"
#include "FileOperations.h"
#include "FileVEILFileList.h"

// used by secure delete functions
#define BLOCK_SIZE    65536u
#define PF_BLOCK_SIZE 65536u
#define HEADER_SIZE_MULTIPLE 512
#define HEADER_SIZE_FUDGE    450

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

FileVEILOperationsImpl::FileVEILOperationsImpl()
{
}

FileVEILOperationsImpl::~FileVEILOperationsImpl()
{
}

bool  FileVEILOperationsImpl::SetStatusInterface(std::shared_ptr<IFileVEILOperationStatus> status)
{
	m_status.reset();
	if (status != NULL)
		m_status = status;
	return true;
}

bool  FileVEILOperationsImpl::SetSession(std::shared_ptr<IKeyVEILSession> session)
{
	//if (!!m_session)
	//	m_session->Close();
	m_session.reset();
	if (session != NULL)
		m_session = session;
	return true;
}

bool  FileVEILOperationsImpl::SetKeyGenCallback(std::shared_ptr<IKeyGenCallback> callback)
{
	m_keyGenCallback.reset();
	m_keyGenCallback = callback;
	return true;
}

bool  FileVEILOperationsImpl::SetSessionCallback(std::shared_ptr<IFileVEILSessionCallback> callback)
{
	m_sessionCallback.reset();
	m_sessionCallback = callback;
	return true;
}

bool  FileVEILOperationsImpl::secureDelete(const tscrypto::tsCryptoString& inFilename, int inDeletePasses)
{
	TSDECLARE_FUNCTIONExt(true);
	m_currentTask = 1;
	if ((inDeletePasses < 3) || (inDeletePasses > 200))
	{
		LogError("Invalid delete pass argument value of %d.  It must be between 3 and 200");
		return TSRETURN_ERROR(("inDeletePasses is not valid"), false);
	}

	/* secure delete any named data streams if supported by this filesystem */
	if (!secureDeleteEntireFile(inFilename, inDeletePasses))
		return TSRETURN_ERROR(("Returns ~~"), false);

	return TSRETURN(("OK"), true);
}

bool  FileVEILOperationsImpl::GetStreamNames(const tscrypto::tsCryptoString& sFile, std::shared_ptr<IVEILFileList>& pVal)
{
	TSDECLARE_FUNCTIONExt(true);
	tscrypto::tsCryptoStringList list = CreateTsAsciiList();

	if (!::GetStreamNames(sFile, list))
		return TSRETURN_ERROR(("Returns ~~"), false);

	pVal = ::TopServiceLocator()->Finish<IVEILFileList>(new FileVEILFileListImpl());
	if (!pVal)
		return TSRETURN_ERROR(("Returns ~~"), false);

	size_t count = list->size();
	for (size_t index = 0; index < count; index++)
	{
		pVal->AddFile(list->at(index));
	}
	return TSRETURN(("OK"), true);
}

/******************************************************************************
 * CKMPrivate_Utils::secureDeleteFile()
 *
 * Parameters:  inFilename - [in] name of file to secure delete
 *              inDeletePasses - [in] number of "cleaning" passes to make
 *
 * Returns:	    Nothing
 *
 * Throws:		CKMUTL_FILE_ERROR, CKMUTL_CANNOT_DELETE_FILE
 *
 * Description: Securely delete the supplied file by overwriting its
 *              data with 111s and 000s.  Do this a number of times specified by
 *              inDeletePasses.
 *****************************************************************************/
bool FileVEILOperationsImpl::secureDeleteFile(const tscrypto::tsCryptoString& inFilename, int inDeletePasses)
{
	TSDECLARE_FUNCTIONExt(true);

	tscrypto::tsCryptoData buffer;
	BYTE *ptr;
	int index;
	int64_t fileSize = 0, numBlocks = 0, block;

	buffer.resize(BLOCK_SIZE);
	if (!internalGenerateRandomBits(buffer.rawData(), BLOCK_SIZE * 8, false, nullptr, 0))
		return false;

	buffer.resize(2 * BLOCK_SIZE, 0xff);
	buffer.resize(3 * BLOCK_SIZE, 0);
#ifdef WIN32

	HANDLE hFile;
	DWORD dwSize;
	int oldPercent = -1;
	int percent = 0;

	hFile = CreateFileA(inFilename.c_str(), GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		LogError("Unable to open file with write permissions for file " + inFilename);
		return TSRETURN_ERROR(("Access Denied"), false);
	}

	BY_HANDLE_FILE_INFORMATION bhfi;
	if (!GetFileInformationByHandle(hFile, &bhfi))
	{
		CloseHandle(hFile);
		LogError("Unable to get file information to determine size");
		return TSRETURN_ERROR(("Invalid Argument"), false);
	}
	fileSize = (((int64_t)bhfi.nFileSizeHigh) << 32) | bhfi.nFileSizeLow;
	numBlocks = fileSize / BLOCK_SIZE;
	if (fileSize % BLOCK_SIZE)
		numBlocks++;

	/* loop through file overwriting with ones, zeroes, or random values */
	for (index = 1; index <= (int)inDeletePasses; index++)
	{
		if (1 == (index % 3))
			ptr = &buffer.rawData()[BLOCK_SIZE];
		else if (2 == (index % 3))
			ptr = &buffer.rawData()[0];
		else
			ptr = &buffer.rawData()[2 * BLOCK_SIZE];

		/* overwrite with either ones or zeroes */
		for (block = 0; block < numBlocks; block++)
		{
			percent = (int)(((int64_t)100 * ((index - 1) * numBlocks + block)) / (inDeletePasses * numBlocks));

			if (percent != oldPercent && !!m_status)
			{
				tscrypto::tsCryptoString task;

				task << "Overwriting pass " << index << " for " << inFilename;

				if (!(m_status->Status(task.c_str(), m_currentTask, m_taskCount, percent)))
				{
					LogError("Operation cancelled");
					return TSRETURN_ERROR(("Cancelled"), false);
				}
				oldPercent = percent;
			}
			if (!WriteFile(hFile, ptr, BLOCK_SIZE, &dwSize, NULL) || dwSize != BLOCK_SIZE)
			{
				LogError("Operation failed (write)");
				return TSRETURN_ERROR(("Write Failed"), false);
			}
		}

		/* flush the changes to disk and seek back to the top */
		percent = (int)((100 * (index - 1) / inDeletePasses));
		if (percent != oldPercent && !!m_status)
		{
			tscrypto::tsCryptoString task;

			task << "Flushing pass " << index << " for " << inFilename;

			if (!(m_status->Status(task.c_str(), m_currentTask, m_taskCount, percent)))
			{
				LogError("Operation cancelled");
				return TSRETURN_ERROR(("Cancelled"), false);
			}
			oldPercent = percent;
		}
		FlushFileBuffers(hFile);
		SetFilePointer(hFile, 0, 0, FILE_BEGIN);
	}
	/* close and delete the file */
	CloseHandle(hFile);
	if (!!m_status)
	{
		tscrypto::tsCryptoString task;

		task << "Deleting " << inFilename;

		if (!(m_status->Status(task.c_str(), m_currentTask, m_taskCount, 100)))
		{
			LogError("Operation cancelled");
			return TSRETURN_ERROR(("Cancelled"), false);
		}
	}
#ifdef HAVE__UNLINK
	if (_unlink(inFilename.c_str()))
#else
	if (unlink(inFilename.c_str()))
#endif
	{
		LogError("Unable to delete file '%s'", inFilename.c_str());
		return TSRETURN_ERROR(("Delete Failed"), false);
	}

#else /* Unix */

	int result;
	FILE * pInFile;
	struct stat statBuf;

	/* stat the file to determine file size in bytes */
	if (stat(inFilename.c_str(), &statBuf) != 0)
	{
		LogError("Unable to determine file size.");
		return TSRETURN_ERROR(("Unable to determine file size."), false);
	}

	fileSize = statBuf.st_size;
	int32_t remaining = (int32_t)(fileSize % BLOCK_SIZE);
	numBlocks = fileSize / BLOCK_SIZE;

	/* Open the file to overwrite */
	pInFile = fopen(inFilename.c_str(), "w");
	if (pInFile == NULL)
	{
		LogError("Unable to open file for writing.  Cannot securely delete.");
		return TSRETURN_ERROR(("Unable to open file for writing.  Cannot securely delete."), false);
	}

	/* loop through file overwriting with ones or zeroes */
	for (index = 1; index <= (int)inDeletePasses; index++)
	{
		if (1 == (index % 3))
			ptr = &buffer.rawData()[BLOCK_SIZE];
		else if (2 == (index % 3))
			ptr = &buffer.rawData()[0];
		else
			ptr = &buffer.rawData()[2 * BLOCK_SIZE];

		/* overwrite with either ones or zeroes */
		for(block = 0; block < numBlocks; block++)
			fwrite(ptr, 1, BLOCK_SIZE, pInFile);
		fwrite(ptr, 1, remaining, pInFile);

		/* flush the changes to disk and seek back to the top */
		fflush(pInFile);
		fseek(pInFile, 0, SEEK_SET);
	}

	/* close and delete the file */
	fclose(pInFile);
	if ( (result = unlink(inFilename.c_str())) != 0 )
	{
		LogError("Unable to delete the file.");
		return TSRETURN_ERROR(("Unable to delete the file."), false);
	}

#endif /* WIN32 or Unix */

	return TSRETURN(("OK"), true);
}

/******************************************************************************
 * CKMPrivate_Utils::secureDeleteStreams()
 *
 * Parameters:  inFilename - [in] name of file with streams to delete
 *              inDeletePasses - [in] number of "cleaning" passes to make
 *
 * Returns:	    Nothing
 * Throws:		Nothing
 *
 * Description: Securely delete all streams belonging to the supplied
 *              file by overwriting them with 111s and 000s.
 *
 * Note:        Does not exist under Unix, which has no alternate stream support
 *****************************************************************************/
bool FileVEILOperationsImpl::secureDeleteStreams(const tscrypto::tsCryptoString& inFilename, int inDeletePasses)
{
	TSDECLARE_FUNCTIONExt(true);

#ifdef WIN32
	// if we aren't on an NT platform, bail out now (no streams to delete)
	//OSVERSIONINFO osvi;
	//ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
	//osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

	//if (! GetVersionEx ( (OSVERSIONINFO *) &osvi))
	//{
	//    return TSRETURN(("OK"),true);
	//}
	//else if (osvi.dwPlatformId != VER_PLATFORM_WIN32_NT)
	//{
	//    return TSRETURN(("OK"),true);
	//}

	int index;
	HANDLE hFile;
	BOOL bContinue;
	void * ctx = NULL;
	WIN32_STREAM_ID sid;
	DWORD dwRead, lo, hi;

	// open the file whose streams we want to delete
	if (INVALID_HANDLE_VALUE == (hFile = CreateFileA(inFilename.c_str(), GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, 0)))
	{
		LogError("Unable to open the specified file.  " + inFilename);
		return TSRETURN_ERROR(("Invalid filename"), true);
	}

	// we have to build a list of named files to delete, and then close the
	// original file. The streams can't be written when the main file is open
	int streamCnt = 0;
	tscrypto::tsCryptoStringList streamList = CreateTsAsciiList();

	CryptoUtf16 streamName;
	tscrypto::tsCryptoString tmpStr;

	// read the first 20 bytes of the stream (all but the last field)
	while ((bContinue = BackupRead(hFile, (LPBYTE)&sid,
		sizeof(sid) - sizeof(WCHAR *), &dwRead, FALSE, FALSE, &ctx)) != FALSE)
	{
		// if we are done or there was no data read, break out
		if (!bContinue || !dwRead)
			break;

		// if this stream is named Alternate Data, delete it
		if (sid.dwStreamId == BACKUP_ALTERNATE_DATA && sid.dwStreamNameSize > 0)
		{
			// get the name of the stream (Wide-Char format)
			streamName.clear();
			streamName.resize(sid.dwStreamNameSize / sizeof(ts_wchar));

			BackupRead(hFile, (byte *)streamName.data(), sid.dwStreamNameSize, &dwRead, FALSE, FALSE, &ctx);

			if (wcslen(streamName.c_str()) >= 6 && wcscmp(&streamName[wcslen(streamName.c_str()) - 6], L":$DATA") == 0)
			{
				streamName.resize(streamName.size() - 6);
			}

			tmpStr = inFilename + streamName.toUtf8();
			streamList->push_back(tmpStr);
		}

		// seek to the end of this stream so we can check the next one
		BackupSeek(hFile, sid.Size.LowPart, sid.Size.HighPart, &lo, &hi, &ctx);
	}

	// free memory allocated by BackupRead and close the file
	BackupRead(hFile, (LPBYTE)&sid, 0, &dwRead, TRUE, FALSE, &ctx);
	CloseHandle(hFile);

	m_taskCount += streamCnt;

	// now go through the list we built and secureDelete each stream
	for (index = 0; index < streamCnt; index++)
	{
		// ignore exceptions and move on to the next one
		LOG(DebugInfo1, "CKMPrivate_Utils::secureDeleteStreams() securedelete stream " << streamList->at(index));
		if (!secureDeleteFile(streamList->at(index), inDeletePasses))
			return TSRETURN(("Returns ~~"), false);
		m_currentTask++;
	}

#endif /* WIN32 */
	return TSRETURN(("OK"), true);
}

void FileVEILOperationsImpl::LogError(tscrypto::tsCryptoString error, ...)
{
	va_list args;
	tscrypto::tsCryptoString msg;

	if (error == NULL)
		return;
	va_start(args, error);
	msg.FormatArg(error, args);
	va_end(args);
	LOG(DebugError, msg);
	if (!!m_status)
	{
		m_status->FailureReason(msg.c_str());
	}
}

bool FileVEILOperationsImpl::secureDeleteEntireFile(const tscrypto::tsCryptoString& inFilename, int inDeletePasses)
{
	TSDECLARE_FUNCTIONExt(true);

	/* secure delete any named data streams if supported by this filesystem */
	if (!secureDeleteStreams(inFilename, inDeletePasses))
		return TSRETURN_ERROR(("Returns ~~"), false);

	/* secure delete the file itself */
	if (!secureDeleteFile(inFilename, inDeletePasses))
		return TSRETURN_ERROR(("Returns ~~"), false);

	return TSRETURN(("OK"), true);
}

bool FileVEILOperationsImpl::DecryptVerify(const tscrypto::tsCryptoString &sFilename, const tscrypto::tsCryptoString &sDecryptedFilename, const tscrypto::tsCryptoString &lpszTempFile)
{
	TSDECLARE_FUNCTIONExt(true);

	tscrypto::tsCryptoString sTempFile;
	std::shared_ptr<ICmsHeaderBase> header;

	if (lpszTempFile.size() > 0)
	{
		sTempFile = lpszTempFile;
	}
	else
	{
		sTempFile = sDecryptedFilename;
		sTempFile += ".tmp";
	}

	LOG(DebugInfo3, "Decrypting file '" << sFilename.c_str() << "'");

	if (!FileStartsWithCmsHeader(sFilename.c_str(), header))
	{
		LOG(DebugInfo1, "The file '" << sFilename << "' is not encrypted.");
		return TSRETURN(("FAIL"), false);
	}

	std::shared_ptr<ICmsHeader> header7 = std::dynamic_pointer_cast<ICmsHeader>(header);

	if (!header7)
	{
		LOG(DebugInfo1, "The file '" << sFilename << "' has an unrecognized header format.");
		return TSRETURN(("FAIL"), false);
	}

	return TSRETURN(("OK"), DecryptVerify(header7, sFilename, sDecryptedFilename, lpszTempFile, sTempFile, true));
}

bool FileVEILOperationsImpl::DecryptVerify(std::shared_ptr<ICmsHeader> header, const tscrypto::tsCryptoString &sFilename, const tscrypto::tsCryptoString &sDecryptedFilename, const tscrypto::tsCryptoString &lpszTempFile, const tscrypto::tsCryptoString &sTempFile, bool headerIncluded)
{
	TSDECLARE_FUNCTIONExt(true);

	std::shared_ptr<IDataReader> reader;
	std::shared_ptr<IDataWriter> writer;
	tscrypto::tsCryptoString outputFilename;

	// Get output filename
	if (sDecryptedFilename.size() > 0)
	{
		outputFilename = sDecryptedFilename;
	}
	else
	{
		outputFilename = header->GetDataName();
		if (outputFilename.size() == 0)
		{
			LogError("Unable to retrieve the original file name from the encrypted file.");
			return TSRETURN_ERROR(("false"), false);
		}
	}
	std::shared_ptr<IDataIOBase> ioBase;

	if (!(reader = std::dynamic_pointer_cast<IDataReader>(CreateFileReader(sFilename))))
	{
		xp_DeleteFile(sTempFile);
		LogError("Error occured trying to open input file '%s'.", sFilename.c_str());
		return TSRETURN_ERROR(("Bad File"), false);
	}
	ioBase.reset();

	if (!(writer = std::dynamic_pointer_cast<IDataWriter>(CreateDataWriter(sTempFile))))
	{
		reader->Close();
		xp_DeleteFile(sTempFile);
		LogError("Error occured trying to open input file '%s'.", sFilename.c_str());
		return TSRETURN_ERROR(("Bad File"), false);
	}
	ioBase.reset();

	std::shared_ptr<ICryptoHelper> helper;

	if (!m_session && header->NeedsSession())
	{
		if (!!m_sessionCallback)
		{
			if (!m_sessionCallback->GetSessionForHeader(false, std::dynamic_pointer_cast<ICmsHeaderBase>(header), 0, m_session))
			{
				LogError("No session.");
				reader->Close();
				xp_DeleteFile(sTempFile);
				return TSRETURN_ERROR(("Returns ~~"), false);
			}
		}
	}
	if (!m_session)
	{
		LogError("Unable to retrieve the cryptographic helper object from the CKM Runtime.");
		reader->Close();
		xp_DeleteFile(sTempFile);
		return TSRETURN_ERROR(("Returns ~~"), false);
	}
	else
	{
		if (!(helper = CreateCryptoHelper(m_session)))
		{
			LogError("Unable to retrieve the cryptographic helper object from the CKM Runtime.");
			reader->Close();
			xp_DeleteFile(sTempFile);
			return TSRETURN_ERROR(("Returns ~~"), false);
		}
	}

	helper->SetOperationStatusCallback(m_status);
	helper->SetTaskInformation(m_currentTask, m_taskCount);
	if (!!m_keyGenCallback)
		helper->SetKeyGenCallback(m_keyGenCallback);

	std::shared_ptr<ICmsHeaderBase> headerBase; // TODO:  Issue with new code for disconnected streams.     = header;

	if (!(helper->DecryptStream(headerBase, reader, writer, headerIncluded)))
	{
		LogError("Unable to decrypt the data.");
		return TSRETURN_ERROR(("Unable to decrypt the data."), false);
	}

	reader->Close();
	writer->Close();
	reader.reset();
	writer.reset();

	if (lpszTempFile.size() == 0)
	{
		xp_DeleteFile(sDecryptedFilename);

		// Copy the temp file to the destination file
		// According to Jeffrey Richter, "...MoveFile() does not support
		// the moving/renaming of streams."
		// (http://www.microsoft.com/msj/1198/ntfs/ntfs.aspx)
		//if(!MoveFile(sTempFile, sEncryptedFilename))
		if (!xp_RenameFile(sTempFile, sDecryptedFilename))
		{
			tscrypto::tsCryptoString msg;

			switch (errno)
			{
			case EACCES:
				msg = "The destination file already exists";
				break;
			case ENOENT:
				msg = "The source file does not exist";
				break;
			case EINVAL:
				if ((xp_GetFileAttributes(sDecryptedFilename.c_str()) & XP_FILE_ATTRIBUTE_DIRECTORY) != 0)
					msg = "There is a directory called " + sDecryptedFilename + " already.";
				else
					msg = "The file name contains invalid characters";
				break;
			default:
				msg = "An unknown error has occurred while creating the decrypted file.";
				break;
			}
			// Process any inserts in lpMsgBuf.
			// ...
			// Check to see if this was a file permissions error
			DWORD dwAttributes = ::xp_GetFileAttributes(sDecryptedFilename.c_str());

			if (dwAttributes & XP_FILE_ATTRIBUTE_READONLY)
				LogError("The specified output file cannot be accessed because it has Read Only permissions.");
			//else if(dwAttributes & FILE_ATTRIBUTE_SYSTEM)
			//	SetErrorMessage("The specified output file cannot be accessed because it is used exclusively by the Operating System.");
			//else if(dwAttributes & FILE_ATTRIBUTE_HIDDEN)
			//	SetErrorMessage("The specified output file cannot be accessed because it has the Hidden file attribute set.");
			else
				LogError(msg.c_str());

			secureDeleteEntireFile(sTempFile.c_str(), 3);
			return TSRETURN_ERROR(("FAILED"), false);
		}

		xp_DeleteFile(sTempFile);
		//CKMUtility::secureDelete((CKMString)sTempFile);
	}
	return TSRETURN(("OK"), true);
}

bool  FileVEILOperationsImpl::FileStartsWithCmsHeader(const tscrypto::tsCryptoString& filename, std::shared_ptr<ICmsHeaderBase>& pVal)
{
	FILE *infile;
	tscrypto::tsCryptoData contents;
	std::shared_ptr<ICmsHeaderBase> header;
	std::shared_ptr<tsmod::IObject> iunk;
	int len;
	int headerLen = 0;
	int64_t fileLength;
	// 06/15/2010 krr c4996
	errno_t err;

	fileLength = xp_GetFileSize(filename);

	// 06/15/2010 KRR C4996
	//	infile = fopen(filename, "rb");
	err = fopen_s(&infile, filename.c_str(), ("rb"));

	if (infile == NULL || err != 0)
		return false;

	if (fileLength > 20480)
		len = 20480;
	else
		len = (int)fileLength;

	contents.resize(len);
	if ((int)fread(contents.rawData(), 1, len, infile) != len)
	{
		fclose(infile);
		return false;
	}
	fclose(infile);
	if (!ExtractHeaderFromStream(contents.c_str(), len, &headerLen, iunk) ||
		!(header = std::dynamic_pointer_cast<ICmsHeader>(iunk)) ||
		headerLen == 0)
	{
		return false;
	}

	pVal = header;
	return true;
}

bool  FileVEILOperationsImpl::EncryptFile(const tscrypto::tsCryptoString& sFile, const tscrypto::tsCryptoString& sEncrFile, std::shared_ptr<ICmsHeader> header, CompressionType comp, TS_ALG_ID algorithm, TS_ALG_ID hashAlgorithm, bool SignHeader, bool bindData, CMSFileFormatIds DataFormat, bool randomIvec, SymmetricPaddingType paddingType, int blockSize)
{
	bool retVal = false;
	tscrypto::tsCryptoString sTempFile;

	// Delete temp file, in case it exists.
	sTempFile = sEncrFile;
	sTempFile += ".tmp";
	xp_DeleteFile(sTempFile.c_str());

	m_taskCount = 1;
	m_currentTask = 1;

	// Encrypt main stream
	retVal = EncryptSignFile(sFile, sEncrFile, "", header, comp, algorithm, hashAlgorithm, SignHeader, bindData, DataFormat, randomIvec, paddingType, blockSize);

	return retVal;
}

bool  FileVEILOperationsImpl::EncryptFileAndStreams(const tscrypto::tsCryptoString& sFile, const tscrypto::tsCryptoString& sEncrFile, std::shared_ptr<ICmsHeader> header, CompressionType comp, TS_ALG_ID algorithm, TS_ALG_ID hashAlgorithm, bool SignHeader, bool bindData, CMSFileFormatIds DataFormat, bool randomIvec, SymmetricPaddingType paddingType, int blockSize)
{
	TSDECLARE_FUNCTIONExt(true);

	bool retVal = false;
	tscrypto::tsCryptoStringList streamList = CreateTsAsciiList();
	tscrypto::tsCryptoString sTempFile;

	m_taskCount = 1;
	m_currentTask = 1;
	// Delete temp file, in case it exists.
	sTempFile = sEncrFile;
	sTempFile += ".tmp";
	xp_DeleteFile(sTempFile.c_str());

	// Enumerate all streams associated with given file.
	if (::GetStreamNames(sFile, streamList))
	{
		// Encrypt each stream.
		size_t Pos;
		tscrypto::tsCryptoString sStream;
		tscrypto::tsCryptoString sEncrStream;
		tscrypto::tsCryptoString sTempStream;
		tscrypto::tsCryptoString sNamedStream;
		size_t streamCount;

		streamCount = streamList->size();
		m_taskCount += (DWORD)streamCount;

		for (Pos = 0; Pos < streamCount; Pos++)
		{
			sNamedStream = streamList->at(Pos);
			sStream = sFile + sNamedStream;
			sEncrStream = sEncrFile + sNamedStream;
			sTempStream = sTempFile + sNamedStream;
			retVal = EncryptSignFile(sStream, sEncrStream, sTempStream, header, comp, algorithm, hashAlgorithm, SignHeader, bindData, DataFormat, randomIvec, paddingType, blockSize);
			m_currentTask++;
		}
	}

	// Encrypt main stream last, for proper copying/deleting of temp file.
	retVal = EncryptSignFile(sFile, sEncrFile, "", header, comp, algorithm, hashAlgorithm, SignHeader, bindData, DataFormat, randomIvec, paddingType, blockSize);

	return TSRETURN(("Returns ~~"), retVal);
}

bool  FileVEILOperationsImpl::DecryptCryptoData(const tscrypto::tsCryptoData &inputData, tscrypto::tsCryptoData &outputData)
{
	TSDECLARE_FUNCTIONExt(true);

	std::shared_ptr<ICmsHeaderBase> header;

	return TSRETURN(("Returns ~~"), DecryptCryptoDataWithHeader(inputData, outputData, header));
}

bool FileVEILOperationsImpl::DecryptCryptoDataWithHeader(const tscrypto::tsCryptoData &inputData, tscrypto::tsCryptoData &outputData, std::shared_ptr<ICmsHeaderBase>& header)
{
	TSDECLARE_FUNCTIONExt(true);

	std::shared_ptr<IVEILFileSupportDllInterface> iface;
	std::shared_ptr<IVEILFileSupportFactory> factory;
	std::shared_ptr<IDataIOBase> input;
	std::shared_ptr<ICkmPersistable> inPersist;
	std::shared_ptr<IDataIOBase> output;
	std::shared_ptr<ICkmPersistable> outPersist;
	std::shared_ptr<IDataReader> reader;
	std::shared_ptr<IDataWriter> writer;

	header.reset();

	if (!(iface = GetVEILFileSupportDllInterface()) ||
		!(iface->GetVEILFileSupportFactory(factory)) ||
		!factory->CreateMemoryStream(input) ||
		!(inPersist = std::dynamic_pointer_cast<ICkmPersistable>(input)) ||
		!factory->CreateMemoryStream(output) ||
		!(outPersist = std::dynamic_pointer_cast<ICkmPersistable>(output)) ||
		!(reader = std::dynamic_pointer_cast<IDataReader>(input)) ||
		!(writer = std::dynamic_pointer_cast<IDataWriter>(output)))
	{
		return TSRETURN_ERROR(("FALSE - Unable to set up the data streams"), false);
	}
	if (!inPersist->FromBytes(inputData))
		return TSRETURN_ERROR(("FALSE - Unable to populate the input data stream"), false);

	if (!DecryptStreamWithHeader(reader, writer, header))
	{
		return TSRETURN_ERROR(("FALSE - Unable to encrypt the data"), false);
	}
	outputData = outPersist->ToBytes();
	return TSRETURN(("OK"), true);
}
bool  FileVEILOperationsImpl::DataStartsWithCmsHeader(const tscrypto::tsCryptoData& contents, std::shared_ptr<ICmsHeaderBase>& pVal)
{
	std::shared_ptr<ICmsHeaderBase> header;
	std::shared_ptr<tsmod::IObject> iunk;
	int headerLen = 0;

	if (!ExtractHeaderFromStream(contents.c_str(), MIN((int)contents.size(), 20480), &headerLen, iunk) ||
		!(header = std::dynamic_pointer_cast<ICmsHeader>(iunk)) ||
		headerLen == 0)
	{
		return false;
	}

	pVal = header;
	return true;
}
bool  FileVEILOperationsImpl::EncryptCryptoData(const tscrypto::tsCryptoData &inputData, tscrypto::tsCryptoData &outputData, std::shared_ptr<ICmsHeader> header,
	CompressionType comp, TS_ALG_ID algorithm, TS_ALG_ID hashAlgorithm, bool SignHeader, bool bindData, CMSFileFormatIds DataFormat,
	bool randomIvec, SymmetricPaddingType paddingType, int blockSize)
{
	TSDECLARE_FUNCTIONExt(true);

	std::shared_ptr<IVEILFileSupportDllInterface> iface;
	std::shared_ptr<IVEILFileSupportFactory> factory;
	std::shared_ptr<IDataIOBase> input;
	std::shared_ptr<ICkmPersistable> inPersist;
	std::shared_ptr<IDataIOBase> output;
	std::shared_ptr<ICkmPersistable> outPersist;
	std::shared_ptr<IDataReader> reader;
	std::shared_ptr<IDataWriter> writer;

	if (!header)
		return TSRETURN_ERROR(("E_INVALIDARG - No encryption header"), false);

	if (!(iface = GetVEILFileSupportDllInterface()) ||
		!(iface->GetVEILFileSupportFactory(factory)) ||
		!factory->CreateMemoryStream(input) ||
		!(inPersist = std::dynamic_pointer_cast<ICkmPersistable>(input)) ||
		!factory->CreateMemoryStream(output) ||
		!(outPersist = std::dynamic_pointer_cast<ICkmPersistable>(output)) ||
		!(reader = std::dynamic_pointer_cast<IDataReader>(input)) ||
		!(writer = std::dynamic_pointer_cast<IDataWriter>(output)))
	{
		return TSRETURN_ERROR(("FALSE - Unable to set up the data streams"), false);
	}
	if (!inPersist->FromBytes(inputData))
		return TSRETURN_ERROR(("FALSE - Unable to populate the input data stream"), false);

	if (!EncryptStream(reader, writer, header, comp, algorithm, hashAlgorithm, SignHeader, bindData, DataFormat,
		randomIvec, paddingType, blockSize))
	{
		return TSRETURN_ERROR(("FALSE - Unable to encrypt the data"), false);
	}
	outputData = outPersist->ToBytes();
	return TSRETURN(("OK"), true);
}

bool  FileVEILOperationsImpl::EncryptStream(std::shared_ptr<IDataReader> sFile, std::shared_ptr<IDataWriter> sEncrFile, std::shared_ptr<ICmsHeader> header, CompressionType comp, TS_ALG_ID algorithm, TS_ALG_ID hashAlgorithm, bool SignHeader, bool bindData, CMSFileFormatIds DataFormat, bool randomIvec, SymmetricPaddingType paddingType, int blockSize)
{
	tscrypto::tsCryptoString sTempFile;

	m_taskCount = 1;
	m_currentTask = 1;

	// Encrypt main stream
	return EncryptSignStream(sFile, sEncrFile, header, comp, algorithm, hashAlgorithm, SignHeader, bindData, DataFormat, randomIvec, paddingType, blockSize);
}

bool FileVEILOperationsImpl::PrepareHeader(std::shared_ptr<ICmsHeader> header7, CompressionType comp, TS_ALG_ID algorithm, TS_ALG_ID hashAlgorithm, bool SignHeader, bool bindData,
	CMSFileFormatIds DataFormat, bool randomIvec, SymmetricPaddingType paddingType, int blockSize, int64_t fileSize)
{
	TSDECLARE_FUNCTIONExt(true);

	std::shared_ptr<ICryptoHelper> helper;

	if (!m_session)
	{
		if (!!m_sessionCallback)
		{
			if (!m_sessionCallback->GetSessionForHeader(true, std::dynamic_pointer_cast<ICmsHeaderBase>(header7), 0, m_session))
			{
				LogError("Unable to retrieve the cryptographic helper object from the CKM Runtime.");
				return TSRETURN_ERROR(("Returns ~~"), false);
			}
		}
	}
	if (!m_session)
	{
		LogError("Unable to retrieve the cryptographic helper object from the CKM Runtime.");
		return TSRETURN_ERROR(("Returns ~~"), false);
	}
	else
	{
		if (!(helper = CreateCryptoHelper(m_session)))
		{
			LogError("Unable to generate the working key and encrypted data - Unable to create the helper.");
			return TSRETURN_ERROR(("Unable to generate the working key and encrypted data."), false);
		}
	}

	helper->SetOperationStatusCallback(m_status);
	helper->SetTaskInformation(m_currentTask, m_taskCount);
	if (!!m_keyGenCallback)
		helper->SetKeyGenCallback(m_keyGenCallback);

	if (!helper->PrepareHeader(header7, comp, algorithm, hashAlgorithm, SignHeader, bindData,
		DataFormat, randomIvec, paddingType, blockSize, fileSize))
	{
		return TSRETURN_ERROR(("Returns ~~"), false);
	}
	return TSRETURN(("OK"), true);
}

bool FileVEILOperationsImpl::EncryptSignFile(const tscrypto::tsCryptoString &sFilename, const tscrypto::tsCryptoString &sEncryptedFilename, const tscrypto::tsCryptoString &lpszTempFile,
	std::shared_ptr<ICmsHeader> Header, CompressionType comp, TS_ALG_ID algorithm, TS_ALG_ID hashAlgorithm, bool SignHeader, bool bindData,
	CMSFileFormatIds DataFormat, bool randomIvec, SymmetricPaddingType paddingType, int blockSize)
{
	TSDECLARE_FUNCTIONExt(true);

	std::shared_ptr<IDataReader>   inputFile;
	std::shared_ptr<IDataWriter>   outputFile;
	std::shared_ptr<IDataIOBase>   ioBase;
	tscrypto::tsCryptoData buff;
	tscrypto::tsCryptoString sTempFile;

	if (lpszTempFile.size() > 0)
	{
		sTempFile = lpszTempFile;
	}
	else
	{
		sTempFile = sEncryptedFilename;
		sTempFile += ".tmp";
	}

	LOG(DebugInfo3, "Encrypting file '" << sFilename << "'");

	//
	// Now create the output file.
	//
	if (!(outputFile = std::dynamic_pointer_cast<IDataWriter>(CreateDataWriter(sTempFile.c_str()))))
	{
		LogError("Error occurred while creating temporary file '%s'.", sTempFile.c_str());
		return TSRETURN_ERROR(("FAILED"), false);
	}

	if (!(inputFile = std::dynamic_pointer_cast<IDataReader>(CreateFileReader(sFilename.c_str()))))
	{
		outputFile->Close();
		xp_DeleteFile(sTempFile);
		LogError("Error occurred trying to open input file '%s'.", sFilename.c_str());
		return TSRETURN_ERROR(("Bad File"), false);
	}

	if (!EncryptSignStream(inputFile, outputFile, Header, comp, algorithm, hashAlgorithm, SignHeader, bindData, DataFormat, randomIvec, paddingType, blockSize))
	{
		inputFile->Close();
		outputFile->Close();
		xp_DeleteFile(sTempFile);
		return TSRETURN_ERROR(("Returns ~~"), false);
	}
	inputFile->Close();
	outputFile->Close();

	if (lpszTempFile.size() == 0)
	{
		xp_DeleteFile(sEncryptedFilename);

		// Copy the temp file to the destination file
		// According to Jeffrey Richter, "...MoveFile() does not support
		// the moving/renaming of streams."
		// (http://www.microsoft.com/msj/1198/ntfs/ntfs.aspx)
		//if(!MoveFile(sTempFile, sEncryptedFilename))

		if (!xp_RenameFile(sTempFile, sEncryptedFilename))
		{
			tscrypto::tsCryptoString msg;

			switch (errno)
			{
			case EACCES:
				msg = "The destination file already exists";
				break;
			case ENOENT:
				msg = "The source file does not exist";
				break;
			case EINVAL:
				if ((xp_GetFileAttributes(sEncryptedFilename.c_str()) & XP_FILE_ATTRIBUTE_DIRECTORY) != 0)
					msg = "There is a directory called " + sEncryptedFilename + " already.";
				else
					msg = "The file name contains invalid characters";
				break;
			default:
				msg = "An unknown error has occurred while creating the encrypted file.";
				break;
			}
			// Process any inserts in lpMsgBuf.
			// ...
			// Check to see if this was a file permissions error
			DWORD dwAttributes = ::xp_GetFileAttributes(sEncryptedFilename.c_str());

			if (dwAttributes & XP_FILE_ATTRIBUTE_READONLY)
				LogError("The specified output file cannot be accessed because it has Read Only permissions.");
			//else if(dwAttributes & FILE_ATTRIBUTE_SYSTEM)
			//	SetErrorMessage("The specified output file cannot be accessed because it is used exclusively by the Operating System.");
			//else if(dwAttributes & FILE_ATTRIBUTE_HIDDEN)
			//	SetErrorMessage("The specified output file cannot be accessed because it has the Hidden file attribute set.");
			else
				LogError(msg.c_str());

			secureDeleteEntireFile(sTempFile.c_str(), 3);
			return TSRETURN_ERROR(("FAILED"), false);
		}

		xp_DeleteFile(sTempFile);
		//CKMUtility::secureDelete((CKMString)sTempFile);
	}
	return TSRETURN(("OK"), true);
}

bool FileVEILOperationsImpl::EncryptSignStream(std::shared_ptr<IDataReader> inputData, std::shared_ptr<IDataWriter> outputData, std::shared_ptr<ICmsHeader> Header, CompressionType comp, TS_ALG_ID algorithm,
	TS_ALG_ID hashAlgorithm, bool SignHeader, bool bindData, CMSFileFormatIds DataFormat, bool randomIvec, SymmetricPaddingType paddingType, int blockSize)
{
	TSDECLARE_FUNCTIONExt(true);

	std::shared_ptr<ICmsHeaderBase> header2;
	std::shared_ptr<ICmsHeader> header7;
	std::shared_ptr<IKeyGenCallback> callback;
	int64_t fileSize = 0;

	if (Header == NULL)
	{
		LogError("The CKM Header is missing.");
		return TSRETURN_ERROR(("Bad Header"), false);
	}

	if (!Header->DuplicateHeader(header2))
	{
		LogError("The specified CKM Header is incomplete or invalid.");
		return TSRETURN_ERROR(("Bad Header"), false);
	}
	if (!(header7 = std::dynamic_pointer_cast<ICmsHeader>(header2)))
	{
		LogError("The specified CKM Header is incomplete or invalid.");
		return TSRETURN_ERROR(("Bad Header"), false);
	}

	//
	// Now get the length of the source file
	//
	if (inputData->AllowsRandomAccess())
		fileSize = inputData->DataLength();
	else
		fileSize = -1;

	if (!PrepareHeader(header7, comp, algorithm, hashAlgorithm, SignHeader, bindData, DataFormat, randomIvec, paddingType, blockSize, fileSize))
	{
		LogError("The specified CKM Header could not be prepared for key generation.");
		return TSRETURN_ERROR(("Bad Header"), false);
	}

	//	CkmDevOnly << "Header after prepare" << endl << indent << TSHeaderToString(header7) << endl << outdent;

#ifdef HAVE_BSTR
	// TODO:  Implement Linux mime support here - libmagic
	{
		tscrypto::tsCryptoData tmp;
		CryptoUtf16 tmpBstr(inputData->DataName());
		LPWSTR mime = NULL;

		if (inputData->PeekData(4096, tmp))
		{
			if (FindMimeFromData(NULL, tmpBstr.c_str(), tmp.rawData(), (DWORD)tmp.size(), NULL, 3 /*FMFD_ENABLEMIMESNIFFING | FMFD_URLASFILENAME*/, &mime, 0) >= 0)
			{
				if (mime != NULL && mime[0] != 0)
				{
					header7->SetMimeType(CryptoUtf16(mime).toUtf8());
				}
			}
		}
	}
#endif // HAVE_BSTR

	std::shared_ptr<ICryptoHelper> helper;

	if (!m_session && header7->NeedsSession())
	{
		if (!!m_sessionCallback)
		{
			if (!(m_sessionCallback->GetSessionForHeader(true, header2, 0, m_session)))
			{
				LogError("No session.");
				return TSRETURN_ERROR(("Returns ~~"), false);
			}
		}
	}

	if (!m_session)
	{
		LogError("Unable to retrieve the cryptographic helper object from the CKM Runtime.");
		return TSRETURN_ERROR(("Returns ~~"), false);
	}
	else
	{
		if (!(helper = CreateCryptoHelper(m_session)))
		{
			LogError("Unable to generate the working key and encrypted data - Unable to create the helper.");
			return TSRETURN_ERROR(("Unable to generate the working key and encrypted data."), false);
		}
	}

	helper->SetOperationStatusCallback(m_status);
	helper->SetTaskInformation(m_currentTask, m_taskCount);
	if (!!m_keyGenCallback)
		helper->SetKeyGenCallback(m_keyGenCallback);

	if (!header7->SetDataName(inputData->DataName().c_str()))
	{
		LOG(DebugInfo1, "WARNING:  Unable to save the original file name.  Continuing to process the file.\n");
	}

	if (!helper->EncryptStream(comp, algorithm, hashAlgorithm, header2, true, tscrypto::tsCryptoData(), inputData, outputData, SignHeader,
		bindData, DataFormat, randomIvec, paddingType, blockSize))
	{
		LogError("Unable to encrypt the data.");
		return TSRETURN_ERROR(("Unable to encrypt the data."), false);
	}

	return TSRETURN(("OK"), true);
}

bool  FileVEILOperationsImpl::ValidateFileContents_PublicOnly(const tscrypto::tsCryptoString& sFile)
{
	TSDECLARE_FUNCTIONExt(true);

	std::shared_ptr<ICryptoHelper> helper;
	std::shared_ptr<IDataReader> reader;
	std::shared_ptr<IDataIOBase> ioBase;
	std::shared_ptr<IKeyVEILSession> empty;

	if (!(helper = CreateCryptoHelper(empty)))
	{
		LogError("Unable to create the decryption processor.");
		return TSRETURN_ERROR(("Unable to create the decryption processor"), false);
	}

	helper->SetOperationStatusCallback(m_status);
	helper->SetTaskInformation(m_currentTask, m_taskCount);
	if (!!m_keyGenCallback)
		helper->SetKeyGenCallback(m_keyGenCallback);

	if (!(reader = std::dynamic_pointer_cast<IDataReader>(CreateFileReader(sFile))))
	{
		LogError("Error occurred trying to open input file '%s'.", sFile.c_str());
		return TSRETURN_ERROR(("Bad File"), false);
	}

	if (!helper->ValidateFileContents_PublicOnly(reader))
	{
		LogError("ERROR:  The file has been modified.");
		return TSRETURN_ERROR(("The file has been modified."), false);
	}
	return TSRETURN(("OK"), true);
}

bool  FileVEILOperationsImpl::DecryptStream(std::shared_ptr<IDataReader> sFile, std::shared_ptr<IDataWriter> sDecrFile)
{
	TSDECLARE_FUNCTIONExt(true);

	std::shared_ptr<ICmsHeaderBase> header;

	return TSRETURN(("OK"), DecryptStreamWithHeader(sFile, sDecrFile, header));
}

bool     FileVEILOperationsImpl::StreamStartsWithCmsHeader(std::shared_ptr<IDataReader> stream, std::shared_ptr<ICmsHeaderBase>& pVal)
{
	tscrypto::tsCryptoData contents;
	std::shared_ptr<ICmsHeaderBase> header;
	std::shared_ptr<tsmod::IObject> iunk;
	int len;
	int headerLen = 0;
	int64_t fileLength;

	if (stream == NULL)
		return false;

	fileLength = stream->DataLength();

	if (fileLength > 20480)
		len = 20480;
	else
		len = (int)fileLength;

	stream->ReadData(len, contents);
	if (contents.size() != (uint32_t)len)
	{
		return false;
	}
	if (!ExtractHeaderFromStream(contents.c_str(), len, &headerLen, iunk) ||
		!(header = std::dynamic_pointer_cast<ICmsHeader>(iunk)) ||
		headerLen == 0)
	{
		return false;
	}

	if (stream->AllowsRandomAccess())
	{
		stream->GoToPosition(headerLen);
	}

	pVal = header;
	return true;
}

bool FileVEILOperationsImpl::DecryptVerify(std::shared_ptr<ICmsHeader> header, std::shared_ptr<IDataReader> reader, std::shared_ptr<IDataWriter> writer, bool headerIncluded)
{
	TSDECLARE_FUNCTIONExt(true);

	std::shared_ptr<ICryptoHelper> helper;

	if (!m_session && header->NeedsSession())
	{
		if (!!m_sessionCallback)
		{
			if (!(m_sessionCallback->GetSessionForHeader(false, std::dynamic_pointer_cast<ICmsHeaderBase>(header), 0, m_session)))
				return TSRETURN_ERROR(("Returns ~~"), false);
		}
	}

	// Regenerate the working key
	if (!m_session)
	{
		LogError("Unable to retrieve the cryptographic helper object from the CKM Runtime.");
		return TSRETURN_ERROR(("Returns ~~"), false);
	}
	else
	{
		if (!(helper = CreateCryptoHelper(m_session)))
		{
			LogError("Unable to retrieve the cryptographic helper object from the CKM Runtime.");
			return TSRETURN_ERROR(("Returns ~~"), false);
		}
	}

	if (!!m_keyGenCallback)
		helper->SetKeyGenCallback(m_keyGenCallback);
	if (!!m_sessionCallback)
		helper->SetSessionCallback(m_sessionCallback);

	std::shared_ptr<ICmsHeaderBase> headerBase = header;

	if (!helper->DecryptStream(headerBase, reader, writer, headerIncluded))
	{
		LogError("Unable to decrypt the data.");
		return TSRETURN_ERROR(("Unable to decrypt the data."), false);
	}

	return TSRETURN(("OK"), true);
}

bool  FileVEILOperationsImpl::DecryptStreamWithHeader(std::shared_ptr<IDataReader> sFile, std::shared_ptr<IDataWriter> sDecrFile, std::shared_ptr<ICmsHeaderBase>& header)
{
	TSDECLARE_FUNCTIONExt(true);

	bool headerPassedIn = false;

	LOG(DebugInfo3, "Decrypting stream");

	if (!header)
	{
		if (!StreamStartsWithCmsHeader(sFile, header))
		{
			LOG(DebugInfo1, "The stream is not encrypted.");
			return TSRETURN(("FALSE"), false);
		}
	}
	else
		headerPassedIn = true;

	std::shared_ptr<ICmsHeader> header7;

	if (!(header7 = std::dynamic_pointer_cast<ICmsHeader>(header)))
	{
		LOG(DebugInfo1, "The stream has an unrecognized header format.");
		return TSRETURN(("FAIL"), false);
	}

	return TSRETURN(("OK"), DecryptVerify(header7, sFile, sDecrFile, !headerPassedIn));
}

bool FileVEILOperationsImpl::RegenerateStreamKey(const tscrypto::tsCryptoString &sFilename, tscrypto::tsCryptoData& headerSignature, tscrypto::tsCryptoData& workingKey)
{
	TSDECLARE_FUNCTIONExt(true);

	std::shared_ptr<IDataReader> reader;
	std::shared_ptr<ICmsHeaderBase> headerBase;
	std::shared_ptr<ICmsHeader> header7;
	std::shared_ptr<IDataIOBase> ioBase;

	if (!(reader = std::dynamic_pointer_cast<IDataReader>(CreateFileReader(sFilename))))
	{
		LogError("Error occured trying to open input file '%s'.", sFilename.c_str());
		return TSRETURN_ERROR(("Bad File"), false);
	}
	headerSignature.clear();
	workingKey.clear();
	if (!StreamStartsWithCmsHeader(reader, headerBase))
	{
		return true;
	}
	if (!(header7 = std::dynamic_pointer_cast<ICmsHeader>(headerBase)))
	{
		return TSRETURN_ERROR(("Not a CKM7 header"), false);
	}

	if (!m_session && header7->NeedsSession())
	{
		if (!!m_sessionCallback)
		{
			if (!(m_sessionCallback->GetSessionForHeader(false, headerBase, 0, m_session)))
			{
				LogError("No session.");
				reader->Close();
				return TSRETURN_ERROR(("Returns ~~"), false);
			}
		}
	}
	if (!m_session)
	{
		LOG(DebugError, "Unable to regenerate the working key and encrypted data.");
		return TSRETURN_ERROR(("Unable to regenerate the working key and encrypted data."), false);
	}
	else
	{
		std::shared_ptr<ICkmOperations> ops = std::dynamic_pointer_cast<ICkmOperations>(header7);

		if (!ops || !ops->RegenerateWorkingKey(m_session, workingKey))
		{
			LOG(DebugError, "Unable to regenerate the working key and encrypted data.");
			return TSRETURN_ERROR(("Unable to regenerate the working key and encrypted data."), false);
		}
	}

	headerSignature = header7->GetSignature();

	return TSRETURN(("OK"), true);
}

bool  FileVEILOperationsImpl::RecoverKeys(const tscrypto::tsCryptoString& inputFile, FileVEILFileOp_recoveredKeyList& keys)
{
	tscrypto::tsCryptoStringList lStreams = CreateTsAsciiList();
	bool retVal = false;

	keys = CreateFileVEILFileOp_recoveredKeyList();
	// Enumerate all streams associated with given file.
	if (::GetStreamNames(inputFile, lStreams))
	{
		// Decrypt each stream.
		tscrypto::tsCryptoString sStream;
		tscrypto::tsCryptoString sNamedStream;
		tscrypto::tsCryptoData signature;
		tscrypto::tsCryptoData workingKey;
		size_t count;

		if ((retVal = RegenerateStreamKey(inputFile, signature, workingKey)) && signature.size() > 0 && workingKey.size() > 0)
		{
			FileVEILFileOp_recoveredKey rk;

			rk.key = workingKey;
			rk.signature = signature;
			keys->push_back(rk);
		}
		if (retVal)
		{
			count = lStreams->size();
			m_taskCount += (DWORD)count;

			for (size_t index = 0; index < count; index++)
			{
				sNamedStream = (lStreams->at(index));
				sStream = inputFile + sNamedStream;

				if ((retVal = RegenerateStreamKey(sStream, signature, workingKey)) && signature.size() > 0 && workingKey.size() > 0)
				{
					FileVEILFileOp_recoveredKey rk;

					rk.key = workingKey;
					rk.signature = signature;
					keys->push_back(rk);
				}

				if (!retVal)
					break;
			}
		}
	}

	return retVal;
}

bool FileVEILOperationsImpl::DecryptFileAndStreams(const tscrypto::tsCryptoString& sFile, const tscrypto::tsCryptoString& sDecrFile)
{
	tscrypto::tsCryptoStringList lStreams = CreateTsAsciiList();
	tscrypto::tsCryptoString sTempFile;
	bool retVal = false;

	m_taskCount = 1;
	m_currentTask = 1;

	// Delete temp file, in case it exists.
	sTempFile = sDecrFile;
	sTempFile += ".tmp";
	xp_DeleteFile(sTempFile.c_str());

	// Enumerate all streams associated with given file.
	if ((retVal = ::GetStreamNames(sFile, lStreams)) != false)
	{
		// Decrypt each stream.
		tscrypto::tsCryptoString sStream;
		tscrypto::tsCryptoString sDecrStream;
		tscrypto::tsCryptoString sTempStream;
		tscrypto::tsCryptoString sNamedStream;
		size_t count;

		count = lStreams->size();
		m_taskCount += (DWORD)count;

		for (size_t index = 0; index < count; index++)
		{
			sNamedStream = (lStreams->at(index));
			sStream = sFile + sNamedStream;
			sDecrStream = sDecrFile + sNamedStream;
			sTempStream = sTempFile + sNamedStream;

			if ((retVal = DecryptVerify(sStream, sDecrStream, sTempStream)) == false)
				break;
		}
	}

	// Decrypt main stream last, for proper copying/deleting of temp file.
	if (retVal)
	{
		retVal = DecryptVerify(sFile, sDecrFile, "");
	}

	return retVal;
}


std::shared_ptr<IFileVEILOperations> CreateFileVEILOperationsObject()
{
	return ::TopServiceLocator()->Finish<IFileVEILOperations>(new FileVEILOperationsImpl());
}
