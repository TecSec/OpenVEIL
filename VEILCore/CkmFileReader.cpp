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
#ifdef _WIN32
#include <share.h>
#endif

class HIDDEN CkmFileReaderImpl : public tsmod::IObject, public IDataReader, public IDataIOBase
{
public:
	CkmFileReaderImpl(const tscrypto::tsCryptoString& filename);

	// ICkmDataIOBase
	virtual bool IsValid() const;
	virtual bool AllowsRandomAccess() const;
	virtual bool IsEndOfFile() const;
	virtual bool KnowsRemainingData() const;
	virtual int64_t RemainingData() const;
	virtual int64_t DataLength() const;
	virtual int64_t CurrentPosition() const;
	virtual tscrypto::tsCryptoString DataName() const;
	virtual void SetDataName(const tscrypto::tsCryptoString& setTo);
	virtual void Close();

	// ICkmDataReader
	virtual bool GoToPosition(int64_t setTo);
	virtual int64_t Seek(int origin, int64_t position);
	virtual bool ReadData(int byteCount, tscrypto::tsCryptoData &data);
	virtual int  ReadData(int byteCount, int dataOffset, tscrypto::tsCryptoData &data);
	virtual bool PeekData(int byteCount, tscrypto::tsCryptoData &data);
	virtual int  PeekData(int byteCount, int dataOffset, tscrypto::tsCryptoData &data);

protected:
	virtual ~CkmFileReaderImpl(void);

private:
	FILE *m_inputFile;
	int64_t m_dataLength;
	tscrypto::tsCryptoString m_filename;
};

std::shared_ptr<IDataIOBase> CreateFileReader(const tscrypto::tsCryptoString& filename)
{
	return ::TopServiceLocator()->Finish<IDataIOBase>(new CkmFileReaderImpl(filename));
}

CkmFileReaderImpl::CkmFileReaderImpl(const tscrypto::tsCryptoString& filename) :
	m_inputFile(NULL),
	m_dataLength(0),
	m_filename(filename)
{
#ifdef _WIN32
	m_inputFile = _fsopen(filename.c_str(), ("rb"), _SH_DENYNO);
#else
    m_inputFile = fopen(filename.c_str(), "rb");
#endif
	if (m_inputFile != NULL)
	{
#ifdef HAVE__FSEEKI64
		_fseeki64(m_inputFile, 0, SEEK_END);
		m_dataLength = _ftelli64(m_inputFile);
		_fseeki64(m_inputFile, 0, SEEK_SET);
#else
		fseek(m_inputFile, 0, SEEK_END);
		m_dataLength = ftell(m_inputFile);
		fseek(m_inputFile, 0, SEEK_SET);
#endif // HAVE__FSEEKI64
	}
	else
	{
		m_filename.clear();
	}
}

CkmFileReaderImpl::~CkmFileReaderImpl(void)
{
	Close();
}

#pragma region ICkmDataIOBase
bool CkmFileReaderImpl::IsValid() const
{
	return m_inputFile != NULL;
}

bool CkmFileReaderImpl::AllowsRandomAccess() const
{
	return true;
}

bool CkmFileReaderImpl::IsEndOfFile() const
{
	if (m_inputFile == NULL)
		return true;
	return feof(m_inputFile) != 0;
}

bool CkmFileReaderImpl::KnowsRemainingData() const
{
	return true;
}

int64_t CkmFileReaderImpl::RemainingData() const
{
	return DataLength() - CurrentPosition();
}

int64_t CkmFileReaderImpl::DataLength() const
{
	return m_dataLength;
}

int64_t CkmFileReaderImpl::CurrentPosition() const
{
	if (m_inputFile == NULL)
		return 0;
#ifdef HAVE__FSEEKI64
	return _ftelli64(m_inputFile);
#else
	return ftell(m_inputFile);
#endif // HAVE__FSEEKI64
}

tscrypto::tsCryptoString CkmFileReaderImpl::DataName() const
{
	return m_filename;
}

void CkmFileReaderImpl::SetDataName(const tscrypto::tsCryptoString& setTo)
{
	m_filename = setTo;
}

void CkmFileReaderImpl::Close()
{
	if (m_inputFile != NULL)
		fclose(m_inputFile);
	m_inputFile = NULL;
}
#pragma endregion

#pragma region ICkmDataReader
bool CkmFileReaderImpl::GoToPosition(int64_t setTo)
{
	if (m_inputFile == NULL)
		return false;
#ifdef HAVE__FSEEKI64
	return _fseeki64(m_inputFile, setTo, SEEK_SET) == 0;
#else
	return fseek(m_inputFile, setTo, SEEK_SET) == 0;
#endif
}

int64_t CkmFileReaderImpl::Seek(int origin, int64_t position)
{
	if (m_inputFile == NULL)
		return CurrentPosition();

#ifdef HAVE__FSEEKI64
	_fseeki64(m_inputFile, position, origin);
#else
	fseek(m_inputFile, position, origin);
#endif
	return CurrentPosition();
}

bool CkmFileReaderImpl::ReadData(int byteCount, tscrypto::tsCryptoData &data)
{
	if (m_inputFile == NULL || byteCount < 1)
		return false;

	data.resize(byteCount);

	int count = (int)fread(data.rawData(), 1, byteCount, m_inputFile);

	data.resize(count);
	return ferror(m_inputFile) == 0;
}

int CkmFileReaderImpl::ReadData(int byteCount, int dataOffset, tscrypto::tsCryptoData &data)
{
	if (m_inputFile == NULL || dataOffset < 0 || byteCount < 1)
		return false;

	if (data.size() < (uint32_t)(dataOffset + byteCount))
	{
		data.resize(dataOffset + byteCount);
	}

	int count = (int)fread(&data.rawData()[dataOffset], 1, byteCount, m_inputFile);

	if (ferror(m_inputFile) != 0)
		count = -count;
	return count;
}
bool CkmFileReaderImpl::PeekData(int byteCount, tscrypto::tsCryptoData &data)
{
	if (m_inputFile == NULL || byteCount < 1)
		return false;

	data.resize(byteCount);

	int64_t currPos = CurrentPosition();
	int count = (int)fread(data.rawData(), 1, byteCount, m_inputFile);
	GoToPosition(currPos);

	data.resize(count);
	return ferror(m_inputFile) == 0;
}

int CkmFileReaderImpl::PeekData(int byteCount, int dataOffset, tscrypto::tsCryptoData &data)
{
	if (m_inputFile == NULL || dataOffset < 0 || byteCount < 1)
		return false;

	if (data.size() < (uint32_t)(dataOffset + byteCount))
	{
		data.resize(dataOffset + byteCount);
	}

	int64_t currPos = CurrentPosition();
	int count = (int)fread(&data.rawData()[dataOffset], 1, byteCount, m_inputFile);
	GoToPosition(currPos);

	if (ferror(m_inputFile) != 0)
		count = -count;
	return count;
}
#pragma endregion

