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
#ifdef _WIN32
#include <share.h>
#endif


class HIDDEN CkmReadAppendFile :
	public tsmod::IObject,
	public IFifoStream,
	public IDataReader,
	public IDataWriter, 
	public IDataIOBase
{
public:
	CkmReadAppendFile(const tscrypto::tsCryptoString& filename);

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

	// ICkmFifoStream
	virtual void WriterDone();
	virtual bool SetReaderCallback(std::shared_ptr<IFifoStreamReaderCallback> setTo);
	virtual bool SetWriterCallback(std::shared_ptr<IFifoStreamWriterCallback> setTo);
	virtual bool ProcessAllData();
	virtual bool IsWriterFinished() const;
	virtual bool UnreadData(const tscrypto::tsCryptoData &data);
	virtual bool UnreadData(const tscrypto::tsCryptoData &data, int offset, int length);
	virtual bool WriteDataAndFinish(const tscrypto::tsCryptoData &data);
	virtual bool WriteDataAndFinish(const tscrypto::tsCryptoData &data, int offset, int length);
	virtual int64_t BytesRead();
	virtual int64_t BytesWritten();
	virtual void Reset();
	virtual void ResetWriter();

protected:
	virtual ~CkmReadAppendFile(void);

private:
	FILE *m_file;
	int64_t m_dataLength;
	tscrypto::tsCryptoString m_filename;
	bool m_writerDone;
	std::shared_ptr<IFifoStreamReaderCallback> m_readerCallback;
	std::shared_ptr<IFifoStreamWriterCallback> m_writerCallback;
	mutable tscrypto::AutoCriticalSection m_accessLock;
	CryptoEvent m_writerDoneEvent;
	bool m_callbackReturn;
	int64_t m_bytesRead;
};

std::shared_ptr<IDataIOBase> CreateReadAppendFile(const tscrypto::tsCryptoString& filename)
{
	return ::TopServiceLocator()->Finish<IDataIOBase>(new CkmReadAppendFile(filename));
}

CkmReadAppendFile::CkmReadAppendFile(const tscrypto::tsCryptoString& filename) :
    m_file(NULL),
    m_dataLength(0),
    m_filename(filename),
    m_writerDone(false),
    m_writerDoneEvent(),
    m_callbackReturn(true),
    m_bytesRead(0)
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

CkmReadAppendFile::~CkmReadAppendFile(void)
{
    Close();
}

#pragma region ICkmDataIOBase
bool CkmReadAppendFile::IsValid() const
{
    return m_file != NULL;
}

bool CkmReadAppendFile::AllowsRandomAccess() const
{
    return true;
}

bool CkmReadAppendFile::IsEndOfFile() const
{
    TSDECLARE_METHODExt(raf_DebugFifoDetail);

    TSAUTOLOCKER locker(m_accessLock);

    if (m_file == NULL)
        return true;
    if (m_writerDone && feof(m_file) != 0)
    {
		if (raf_DebugFifoSummary) { LOG(FrameworkInfo1, "Is EOF for " << m_filename); }
        return TSRETURN(("True"),true);
    }
	if (raf_DebugFifoSummary) { LOG(FrameworkInfo1, "Is NOT EOF for " << m_filename); }
    return TSRETURN(("false"),false);
}

bool CkmReadAppendFile::KnowsRemainingData() const
{
    return m_writerDone;
}

int64_t CkmReadAppendFile::RemainingData() const
{
    TSDECLARE_METHODExt(raf_DebugFifoDetail);

    TSAUTOLOCKER locker(m_accessLock);

	if (raf_DebugFifoSummary) { LOG(FrameworkInfo1, m_dataLength - CurrentPosition() << " bytes remaining in " << m_filename); }
    return TSRETURN(("~~ bytes"),m_dataLength - CurrentPosition());
}

int64_t CkmReadAppendFile::DataLength() const
{
    TSDECLARE_METHODExt(raf_DebugFifoDetail);

    TSAUTOLOCKER locker(m_accessLock);

	if (raf_DebugFifoSummary) { LOG(FrameworkInfo1, m_dataLength << " bytes in " << m_filename); }
    return TSRETURN(("~~ bytes"),m_dataLength);
}

int64_t CkmReadAppendFile::CurrentPosition() const
{
    if (m_file == NULL)
        return 0;
#ifdef HAVE__FSEEKI64
    return _ftelli64(m_file);
#else
    return ftell(m_file);
#endif // HAVE__FSEEKI64
}

tscrypto::tsCryptoString CkmReadAppendFile::DataName() const
{
    return m_filename;
}

void CkmReadAppendFile::SetDataName(const tscrypto::tsCryptoString& setTo)
{
    MY_UNREFERENCED_PARAMETER(setTo);
    ResetWriter();
    fclose (m_file);
    xp_DeleteFile(m_filename);
#ifdef _WIN32
    m_file = _fsopen(setTo.c_str(), ("wb+"), _SH_DENYNO);
#else
    m_file = fopen(setTo.c_str(), ("wb+"));
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
        m_filename = setTo;
    }
    else
    {
        m_filename.clear();
    }
}

void CkmReadAppendFile::Close()
{
    TSAUTOLOCKER locker(m_accessLock);

    if (m_file != NULL)
        fclose(m_file);
    m_file = NULL;
    WriterDone();
    m_writerDoneEvent.Set();
}

bool CkmReadAppendFile::GoToPosition(int64_t setTo)
{
    TSAUTOLOCKER locker(m_accessLock);

    if (m_file == NULL)
        return false;

#ifdef HAVE__FSEEKI64
    return _fseeki64(m_file, setTo, SEEK_SET) == 0;
#else
    return fseek(m_file, setTo, SEEK_SET) == 0;
#endif // HAVE__FSEEKI64
}

int64_t CkmReadAppendFile::Seek(int origin, int64_t position)
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


#pragma endregion

#pragma region ICkmDataWriter
bool CkmReadAppendFile::WriteData(const tscrypto::tsCryptoData &data)
{
    TSDECLARE_METHODExt(raf_DebugFifoIODetail);

    std::shared_ptr<IFifoStreamReaderCallback> cb;
    int count = 0;

    if (m_file == NULL)
        return TSRETURN(("false"),false);

    {
        TSAUTOLOCKER locker(m_accessLock);

        if (m_writerDone)
            return TSRETURN(("false"),false);

        int64_t readPos = CurrentPosition();
#ifdef HAVE__FSEEKI64
        _fseeki64(m_file, 0, SEEK_END);
#else
        fseek(m_file, 0, SEEK_END);
#endif // HAVE__FSEEKI64
        count = (int)fwrite(data.c_str(), 1, data.size(), m_file);
        int64_t len = CurrentPosition();
#ifdef HAVE__FSEEKI64
        _fseeki64(m_file,readPos, SEEK_SET);
#else
        fseek(m_file, readPos, SEEK_SET);
#endif // HAVE__FSEEKI64
        if (len > m_dataLength)
            m_dataLength = len;
		if (raf_DebugFifoIOSummary) { LOG(FrameworkInfo1, "Wrote " << (int)data.size() << " bytes to " << m_filename); }
        cb = m_readerCallback;
        if (count != (int)data.size())
        {
            Close();
            return TSRETURN(("false"),false);
        }
    }
    if (!!cb)
    {
        if (!(m_callbackReturn = cb->DataAvailable(std::dynamic_pointer_cast<IFifoStream>(_me.lock()))))
        {
            Close();
            return TSRETURN(("false"),false);
        }
    }
    if (IsEndOfFile())
        m_writerDoneEvent.Set();
    return TSRETURN(("true - wrote %d bytes", data.size()),true);
}

bool CkmReadAppendFile::WriteData(const tscrypto::tsCryptoData &data, int offset, int length)
{
    TSDECLARE_METHODExt(raf_DebugFifoIODetail);

	std::shared_ptr<IFifoStreamReaderCallback> cb;
    int count = 0;

    if (m_file == NULL)
        return TSRETURN(("false"),false);

    {
        TSAUTOLOCKER locker(m_accessLock);

        if (m_writerDone)
            return TSRETURN(("false"),false);

        if (offset < 0 || length < 1 || offset + length < 1)
            return TSRETURN(("false"),false);

        if (data.size() < (uint32_t)(offset + length))
            return TSRETURN(("false"),false);

        int64_t readPos = CurrentPosition();
#ifdef HAVE__FSEEKI64
        _fseeki64(m_file, 0, SEEK_END);
#else
        fseek(m_file, 0, SEEK_END);
#endif // HAVE__FSEEKI64
        count = (int)fwrite(&data.c_str()[offset], 1, length, m_file);
        int64_t len = CurrentPosition();
#ifdef HAVE__FSEEKI64
        _fseeki64(m_file,readPos, SEEK_SET);
#else
        fseek(m_file, readPos, SEEK_SET);
#endif // HAVE__FSEEKI64
        if (len > m_dataLength)
            m_dataLength = len;
		if (raf_DebugFifoIOSummary) { LOG(FrameworkInfo1, "Wrote " << length << " bytes to " << m_filename); }
        cb = m_readerCallback;
        if (count != length)
        {
            Close();
            return TSRETURN(("false"),false);
        }
    }
    if (!!cb)
    {
		if (!(m_callbackReturn = cb->DataAvailable(std::dynamic_pointer_cast<IFifoStream>(_me.lock()))))
        {
            Close();
            return TSRETURN(("false"),false);
        }
    }
    if (IsEndOfFile())
        m_writerDoneEvent.Set();
    return TSRETURN(("true - wrote %d bytes", data.size()),true);
}

bool CkmReadAppendFile::Flush()
{
    TSDECLARE_METHODExt(raf_DebugFifoIODetail);

    if (!!m_readerCallback)
    {
		if (!(m_callbackReturn = m_readerCallback->DataAvailable(std::dynamic_pointer_cast<IFifoStream>(_me.lock()))))
        {
            Close();
            return TSRETURN(("false"),false);
        }
    }
    if (m_file == NULL)
        return false;
    if (fflush(m_file) != 0)
    {
        Close();
        return TSRETURN(("false"),false);
    }

    if (IsEndOfFile())
        m_writerDoneEvent.Set();
    return TSRETURN(("true"),true);
}

bool CkmReadAppendFile::Truncate()
{
    if (m_file == NULL)
        return false;
#ifdef _WIN32
    return (_chsize_s(_fileno(m_file), CurrentPosition()) == 0);
#else
    return (ftruncate(fileno(m_file), CurrentPosition()) == 0);
#endif // _WIN32
}

bool CkmReadAppendFile::SetFileSize(int64_t setTo)
{
    if (m_file == NULL || setTo < 0)
        return false;
#ifdef _WIN32
    return (_chsize_s(_fileno(m_file), setTo) == 0);
#else
    return (ftruncate(fileno(m_file), setTo) == 0);
#endif // _WIN32
}

bool CkmReadAppendFile::CanPrepend() const
{
    return false;
}

bool CkmReadAppendFile::Prepend(const tscrypto::tsCryptoData &data)
{
    MY_UNREFERENCED_PARAMETER(data);
    return false;
}
#pragma endregion

#pragma region ICkmDataReader
bool CkmReadAppendFile::ReadData(int byteCount, tscrypto::tsCryptoData &data)
{
    TSDECLARE_METHODExt(raf_DebugFifoIODetail);

    TSAUTOLOCKER locker(m_accessLock);

    if (m_file == NULL || byteCount < 0)
        return TSRETURN(("false"),false);

    data.resize(byteCount);

    int count = (int)fread(data.rawData(), 1, byteCount, m_file);

    data.resize(count);
//	m_bytesRead += count;
	if (raf_DebugFifoIOSummary) { LOG(FrameworkInfo1, "Read " << count << " bytes from " << m_filename) };

    bool retVal = (ferror(m_file) == 0);
    return TSRETURN(("Returns ~~ with %d bytes of data", count),retVal);
}

int CkmReadAppendFile::ReadData(int byteCount, int dataOffset, tscrypto::tsCryptoData &data)
{
    TSDECLARE_METHODExt(raf_DebugFifoIODetail);

    TSAUTOLOCKER locker(m_accessLock);

    if (m_file == NULL || byteCount < 0)
        return TSRETURN(("0"),0);

    if (dataOffset < 0 || byteCount < 1 || dataOffset + byteCount < 0)
        return TSRETURN(("0"),0);

    if (data.size() < (uint32_t)(dataOffset + byteCount))
    {
        data.resize(dataOffset + byteCount);
    }

    int count = (int)fread(&data.rawData()[dataOffset], 1, byteCount, m_file);

//	m_bytesRead += count;
	if (raf_DebugFifoIOSummary) { LOG(FrameworkInfo1, "Read " << count << " bytes from " << m_filename); }

    return TSRETURN(("Returns ~~ bytes of data"),count);
}
#pragma endregion

#pragma region ICkmFifoStream

void CkmReadAppendFile::WriterDone()
{
    TSDECLARE_METHODExt(raf_DebugFifoIODetail || raf_DebugFifoIOSummary);

    std::shared_ptr<IFifoStreamReaderCallback> cb;

    {
        TSAUTOLOCKER locker(m_accessLock);

        if (!m_writerDone)
        {
            m_writerDone = true;
            cb = m_readerCallback;
        }
    }
    if (!!cb && m_callbackReturn)
    {
        // Allow for final cleanup here
		if (!(m_callbackReturn = cb->DataAvailable(std::dynamic_pointer_cast<IFifoStream>(_me.lock()))))
        {
            Close();
            TSRETURN_V(("Done"));
            return ;
        }
    }

    if (IsEndOfFile())
        m_writerDoneEvent.Set();
    TSRETURN_V(("Done"));
}

bool CkmReadAppendFile::SetReaderCallback(std::shared_ptr<IFifoStreamReaderCallback> setTo)
{
    TSAUTOLOCKER locker(m_accessLock);

    m_readerCallback.reset();
    if (setTo != NULL)
        m_readerCallback = setTo;
    return true;
}

bool CkmReadAppendFile::SetWriterCallback(std::shared_ptr<IFifoStreamWriterCallback> setTo)
{
    TSAUTOLOCKER locker(m_accessLock);

    m_writerCallback.reset();
    if (setTo != NULL)
        m_writerCallback = setTo;
    return true;
}

bool CkmReadAppendFile::ProcessAllData()
{
    TSDECLARE_METHODExt(raf_DebugFifoDetail | raf_DebugFifoSummary);

    if (!!m_writerCallback)
    {
		bool retVal = m_writerCallback->ProduceData(std::dynamic_pointer_cast<IFifoStream>(_me.lock()));
        WriterDone();
        if (retVal)
            return TSRETURN(("Returns ~~"),false);

        if (!!m_readerCallback)
        {
            while (!IsEndOfFile())
            {
                if (m_callbackReturn)
                {
                    // Allow for final cleanup here
					if (!(m_callbackReturn = m_readerCallback->DataAvailable(std::dynamic_pointer_cast<IFifoStream>(_me.lock()))))
                    {
                        return TSRETURN(("Returns ~~"),m_callbackReturn);
                    }
                }
            }
        }
        return TSRETURN(("Returns ~~"),m_callbackReturn);
    }
    else
    {
        if (!m_writerDoneEvent.IsActive())
            return TSRETURN(("E_FAIL"),false);

        while (!IsEndOfFile())
        {
            switch (m_writerDoneEvent.WaitForEvent(60000))
            {
			case CryptoEvent::AlreadyLocked:
                break;
			case CryptoEvent::Failed:
                return TSRETURN_ERROR(("E_FAIL"),false);
			case CryptoEvent::Succeeded_Object1:
                return TSRETURN(("Returns ~~"),m_callbackReturn);
            default:
                break;
            }
        }
        return TSRETURN(("Returns from callback ~~"),m_callbackReturn);
    }
}

bool CkmReadAppendFile::IsWriterFinished() const
{
    return m_writerDone;
}

bool CkmReadAppendFile::PeekData(int byteCount, tscrypto::tsCryptoData &data)
{
    TSDECLARE_METHODExt(raf_DebugFifoIODetail);

    TSAUTOLOCKER locker(m_accessLock);

    if (m_file == NULL || byteCount < 0)
        return TSRETURN(("false"),false);

    data.resize(byteCount);

    int64_t readPos = CurrentPosition();
    int count = (int)fread(data.rawData(), 1, byteCount, m_file);
    GoToPosition(readPos);

    data.resize(count);
	if (raf_DebugFifoIOSummary) { LOG(FrameworkInfo1, "Read " << count << " bytes from " << m_filename); }

    bool retVal = (ferror(m_file) == 0);
    return TSRETURN(("Returns ~~ with %d bytes of data", count),retVal);
}

int CkmReadAppendFile::PeekData(int byteCount, int dataOffset, tscrypto::tsCryptoData &data)
{
    TSDECLARE_METHODExt(raf_DebugFifoIODetail);

    TSAUTOLOCKER locker(m_accessLock);

    if (m_file == NULL || byteCount < 0)
        return TSRETURN(("0"),0);

    if (dataOffset < 0 || byteCount < 1 || dataOffset + byteCount < 0)
        return TSRETURN(("0"),0);

    if (data.size() < (uint32_t)(dataOffset + byteCount))
    {
        data.resize(dataOffset + byteCount);
    }

    int64_t readPos = CurrentPosition();
    int count = (int)fread(&data.rawData()[dataOffset], 1, byteCount, m_file);
    GoToPosition(readPos);

	if (raf_DebugFifoIOSummary) { LOG(FrameworkInfo1, "Read " << count << " bytes from " << m_filename); }

    return TSRETURN(("Returns ~~ bytes of data"),count);
}
bool CkmReadAppendFile::UnreadData(const tscrypto::tsCryptoData &data)
{
    MY_UNREFERENCED_PARAMETER(data);
    return false;
}

bool CkmReadAppendFile::UnreadData(const tscrypto::tsCryptoData &data, int offset, int length)
{
    MY_UNREFERENCED_PARAMETER(data);
    MY_UNREFERENCED_PARAMETER(offset);
    MY_UNREFERENCED_PARAMETER(length);
    return false;
}

bool CkmReadAppendFile::WriteDataAndFinish(const tscrypto::tsCryptoData &data)
{
    TSDECLARE_METHODExt(raf_DebugFifoIODetail);

    std::shared_ptr<IFifoStreamReaderCallback> cb;
    int count = 0;

    if (m_file == NULL)
        return TSRETURN(("false"),false);

    {
        TSAUTOLOCKER locker(m_accessLock);

        if (m_writerDone)
            return TSRETURN(("false"),false);

        int64_t readPos = CurrentPosition();
#ifdef HAVE__FSEEKI64
        _fseeki64(m_file, 0, SEEK_END);
#else
        fseek(m_file, 0, SEEK_END);
#endif // HAVE__FSEEKI64
        count = (int)fwrite(data.c_str(), 1, data.size(), m_file);
        int64_t len = CurrentPosition();
#ifdef HAVE__FSEEKI64
        _fseeki64(m_file, readPos, SEEK_SET);
#else
        fseek(m_file, readPos, SEEK_SET);
#endif // HAVE__FSEEKI64
        if (len > m_dataLength)
            m_dataLength = len;
		if (raf_DebugFifoIOSummary) { LOG(FrameworkInfo1, "Wrote " << (int)data.size() << " bytes to " << m_filename); }
        cb = m_readerCallback;
        m_writerDone = true;
        if (count != (int)data.size())
        {
            Close();
            return TSRETURN(("false"),false);
        }
    }
    if (!!cb)
    {
		if (!(m_callbackReturn = cb->DataAvailable(std::dynamic_pointer_cast<IFifoStream>(_me.lock()))))
        {
            Close();
            return TSRETURN(("false"),false);
        }
    }
    if (IsEndOfFile())
        m_writerDoneEvent.Set();
    return TSRETURN(("true - wrote %d bytes", data.size()),true);
}

bool CkmReadAppendFile::WriteDataAndFinish(const tscrypto::tsCryptoData &data, int offset, int length)
{
    TSDECLARE_METHODExt(raf_DebugFifoIODetail);

    std::shared_ptr<IFifoStreamReaderCallback> cb;
    int count = 0;

    if (m_file == NULL)
        return TSRETURN(("false"),false);

    {
        TSAUTOLOCKER locker(m_accessLock);

        if (m_writerDone)
            return TSRETURN(("false"),false);

        if (offset < 0 || length < 1 || offset + length < 1)
            return TSRETURN(("false"),false);

        if (data.size() < (uint32_t)(offset + length))
            return TSRETURN(("false"),false);

        int64_t readPos = CurrentPosition();
#ifdef HAVE__FSEEKI64
        _fseeki64(m_file, 0, SEEK_END);
#else
        fseek(m_file, 0, SEEK_END);
#endif // HAVE__FSEEKI64
        count = (int)fwrite(&data.c_str()[offset], 1, length, m_file);
        int64_t len = CurrentPosition();
#ifdef HAVE__FSEEKI64
        _fseeki64(m_file, readPos, SEEK_SET);
#else
        fseek(m_file, readPos, SEEK_SET);
#endif // HAVE__FSEEKI64
        if (len > m_dataLength)
            m_dataLength = len;
		if (raf_DebugFifoIOSummary) { LOG(FrameworkInfo1, "Wrote " << length << " bytes to " << m_filename); }
        cb = m_readerCallback;
        m_writerDone = true;
        if (count != length)
        {
            Close();
            return TSRETURN(("false"),false);
        }
    }
    if (!!cb)
    {
		if (!(m_callbackReturn = cb->DataAvailable(std::dynamic_pointer_cast<IFifoStream>(_me.lock()))))
        {
            Close();
            return TSRETURN(("false"),false);
        }
    }
    if (IsEndOfFile())
        m_writerDoneEvent.Set();
    return TSRETURN(("true - wrote %d bytes", data.size()),true);
}

int64_t CkmReadAppendFile::BytesRead()
{
    TSDECLARE_METHODExt(raf_DebugFifoDetail);

	if (raf_DebugFifoSummary) { LOG(FrameworkInfo1, m_bytesRead << " bytes read from " << m_filename); }

    return TSRETURN(("~~ bytes read"),m_bytesRead);
}

int64_t CkmReadAppendFile::BytesWritten()
{
    TSDECLARE_METHODExt(raf_DebugFifoDetail);

	if (raf_DebugFifoSummary) {
		LOG(FrameworkInfo1, m_dataLength << " bytes written to " << m_filename);
	}

    return TSRETURN(("~~ bytes written"),m_dataLength);
}

void CkmReadAppendFile::Reset()
{
    TSDECLARE_METHODExt(raf_DebugFifoDetail);

    TSAUTOLOCKER locker(m_accessLock);

    Close();
    m_filename = "";
    m_writerDone = true;
    m_readerCallback.reset();
    m_writerCallback.reset();
    if (m_writerDoneEvent.IsActive())
        m_writerDoneEvent.WaitForEvent(XP_EVENT_TRY);
    m_callbackReturn = true;
    m_bytesRead = 0;
    m_dataLength = 0;
    TSRETURN_V(("Done"));
}
void CkmReadAppendFile::ResetWriter()
{
    TSAUTOLOCKER locker(m_accessLock);

    m_writerDone = false;
    GoToPosition(0);
    Truncate();
    m_bytesRead = 0;
    m_dataLength = 0;
    m_callbackReturn = true;
    if (m_writerDoneEvent.IsActive())
        m_writerDoneEvent.WaitForEvent(XP_EVENT_TRY);
}
#pragma endregion

