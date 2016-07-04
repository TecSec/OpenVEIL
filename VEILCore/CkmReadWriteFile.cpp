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
#endif // _WIN32

class HIDDEN CkmReadWriteFile :
	public tsmod::IObject,
	public IDataReader, public IDataWriter, public IDataIOBase
{
public:
	CkmReadWriteFile(const tscrypto::tsCryptoString& filename);
	virtual ~CkmReadWriteFile(void);

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

	// ICkmDataWriter
	virtual bool WriteData(const tscrypto::tsCryptoData &data);
	virtual bool WriteData(const tscrypto::tsCryptoData &data, int offset, int length);
	virtual bool Flush();
	virtual bool Truncate();
	virtual bool SetFileSize(int64_t setTo);
	virtual bool CanPrepend() const;
	virtual bool Prepend(const tscrypto::tsCryptoData &data);

private:
	FILE *m_file;
	int64_t m_dataLength;
	tscrypto::tsCryptoString m_filename;
};

std::shared_ptr<IDataIOBase> CreateReadWriteFile(const tscrypto::tsCryptoString& filename)
{
	return ::TopServiceLocator()->Finish<IDataIOBase>(new CkmReadWriteFile(filename));
}

CkmReadWriteFile::CkmReadWriteFile(const tscrypto::tsCryptoString& filename) :
    m_filename(filename),
    m_file(NULL),
    m_dataLength(0)
{
#ifdef _WIN32
    m_file = _fsopen(filename.c_str(), ("wb+"), _SH_DENYNO);
#else
    m_file = fopen(filename.c_str(), ("wb+"));
#endif // _WIN32
    if (m_file != NULL)
    {
#ifdef HAVE__FSEEKI64
        _fseeki64(m_file, 0, SEEK_END);
        m_dataLength = _ftelli64(m_file);
        _fseeki64(m_file, 0, SEEK_SET);
#else
        fseek(m_file, 0, SEEK_END);
        m_dataLength = ftell(m_file);
        fseek(m_file, 0, SEEK_SET);
#endif // HAVE__FSEEKI64
    }
    else
    {
        m_filename.clear();
    }
}

CkmReadWriteFile::~CkmReadWriteFile(void)
{
    Close();
}

#pragma region ICkmDataIOBase
bool CkmReadWriteFile::IsValid() const
{
    return m_file != NULL;
}

bool CkmReadWriteFile::AllowsRandomAccess() const
{
    return true;
}

bool CkmReadWriteFile::IsEndOfFile() const
{
    if (m_file == NULL)
        return true;
    return feof(m_file) != 0;
}

bool CkmReadWriteFile::KnowsRemainingData() const
{
    return true;
}

int64_t CkmReadWriteFile::RemainingData() const
{
    return DataLength() - CurrentPosition();
}

int64_t CkmReadWriteFile::DataLength() const
{
    return m_dataLength;
}

int64_t CkmReadWriteFile::CurrentPosition() const
{
    if (m_file == NULL)
        return 0;
#ifdef HAVE__FSEEKI64
    return _ftelli64(m_file);
#else
    return ftell(m_file);
#endif // HAVE__FSEEKI64
}

tscrypto::tsCryptoString CkmReadWriteFile::DataName() const
{
    return m_filename;
}

void CkmReadWriteFile::SetDataName(const tscrypto::tsCryptoString& setTo)
{
	m_filename = setTo;
}

void CkmReadWriteFile::Close()
{
    if (m_file != NULL)
        fclose(m_file);
    m_file = NULL;
}
#pragma endregion

#pragma region ICkmDataReader
bool CkmReadWriteFile::GoToPosition(int64_t setTo)
{
    if (m_file == NULL)
        return false;

#ifdef HAVE__FSEEKI64
    return _fseeki64(m_file, setTo, SEEK_SET) == 0;
#else
    return fseek(m_file, setTo, SEEK_SET) == 0;
#endif // HAVE__FSEEKI64
}

int64_t CkmReadWriteFile::Seek(int origin, int64_t position)
{
	if (m_file == NULL)
		return CurrentPosition();

#ifdef HAVE__FSEEKI64
	_fseeki64(m_file, position, origin);
#else
	fseek(m_file, position, origin);
#endif // HAVE__FSEEKI64
	return CurrentPosition();
}

bool CkmReadWriteFile::ReadData(int byteCount, tscrypto::tsCryptoData &data)
{
    if (m_file == NULL || byteCount < 1)
        return false;

    data.resize(byteCount);

    int count = (int)fread(data.rawData(), 1, byteCount, m_file);

    data.resize(count);
    return ferror(m_file) == 0;
}

int CkmReadWriteFile::ReadData(int byteCount, int dataOffset, tscrypto::tsCryptoData &data)
{
    if (m_file == NULL || dataOffset < 0 || byteCount < 1)
        return false;

    if (data.size() < (uint32_t)(dataOffset + byteCount))
    {
        data.resize(dataOffset + byteCount);
    }

    int count = (int)fread(&data.rawData()[dataOffset], 1, byteCount, m_file);

    if (ferror(m_file) != 0)
        count = -count;
    return count;
}
bool CkmReadWriteFile::PeekData(int byteCount, tscrypto::tsCryptoData &data)
{
    if (m_file == NULL || byteCount < 1)
        return false;

    data.resize(byteCount);

	int64_t currPos = CurrentPosition();
    int count = (int)fread(data.rawData(), 1, byteCount, m_file);
	GoToPosition(currPos);

    data.resize(count);
    return ferror(m_file) == 0;
}

int CkmReadWriteFile::PeekData(int byteCount, int dataOffset, tscrypto::tsCryptoData &data)
{
    if (m_file == NULL || dataOffset < 0 || byteCount < 1)
        return false;

    if (data.size() < (uint32_t)(dataOffset + byteCount))
    {
        data.resize(dataOffset + byteCount);
    }

	int64_t currPos = CurrentPosition();
    int count = (int)fread(&data.rawData()[dataOffset], 1, byteCount, m_file);
	GoToPosition(currPos);

    if (ferror(m_file) != 0)
        count = -count;
    return count;
}
#pragma endregion

#pragma region ICkmDataWriter
bool CkmReadWriteFile::WriteData(const tscrypto::tsCryptoData &data)
{
    if (m_file == NULL)
        return false;

    int count = (int)fwrite(data.c_str(), 1, data.size(), m_file);
    int64_t len = CurrentPosition();
    if (len > m_dataLength)
        m_dataLength = len;
    return count == (int)data.size();
}

bool CkmReadWriteFile::WriteData(const tscrypto::tsCryptoData &data, int offset, int length)
{
    if (m_file == NULL)
        return false;

    if (offset < 0 || length < 1 || offset + length < 1)
        return false;

    if (data.size() < (uint32_t)(offset + length))
        return false;

    int count = (int)fwrite(&data.c_str()[offset], 1, length, m_file);
    int64_t len = CurrentPosition();
    if (len > m_dataLength)
        m_dataLength = len;
    return count == length;
}

bool CkmReadWriteFile::Flush()
{
    if (m_file == NULL)
        return false;
    return fflush(m_file) == 0;
}

bool CkmReadWriteFile::Truncate()
{
    if (m_file == NULL || !AllowsRandomAccess())
        return false;
#ifdef _WIN32
    return (_chsize_s(_fileno(m_file), CurrentPosition()) == 0);
#else
    return (ftruncate(fileno(m_file), CurrentPosition()) == 0);
#endif // _WIN32
}

bool CkmReadWriteFile::SetFileSize(int64_t setTo)
{
    if (m_file == NULL || !AllowsRandomAccess() || setTo < 0)
        return false;
#ifdef _WIN32
    return (_chsize_s(_fileno(m_file), setTo) == 0);
#else
    return (ftruncate(fileno(m_file), setTo) == 0);
#endif // _WIN32
}

bool CkmReadWriteFile::CanPrepend() const
{
    return false;
}

bool CkmReadWriteFile::Prepend(const tscrypto::tsCryptoData &data)
{
    MY_UNREFERENCED_PARAMETER(data);
    return false;
}
#pragma endregion
