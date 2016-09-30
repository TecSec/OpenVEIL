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

using namespace tscrypto;

class HIDDEN CkmMemoryFifoStream : public IFifoStream, public IDataReader, public IDataWriter, public tsmod::IObject, public IDataIOBase
{
public:
	CkmMemoryFifoStream(void);

	// ICkmDataIOBase
	virtual bool IsValid() const;
	virtual bool AllowsRandomAccess() const;
	virtual bool IsEndOfFile() const;
	virtual bool KnowsRemainingData() const;
	virtual int64_t RemainingData() const;
	virtual int64_t DataLength() const;
	virtual int64_t CurrentPosition() const;
	virtual tscrypto::tsCryptoString DataName() const;
	virtual void Close();

	// ICkmDataReader
	virtual bool GoToPosition(int64_t setTo);
	virtual int64_t Seek(int origin, int64_t position);
	virtual bool ReadData(int byteCount, tscrypto::tsCryptoData &data);
	virtual int  ReadData(int byteCount, int dataOffset, tscrypto::tsCryptoData &data);

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
	virtual bool PeekData(int byteCount, tscrypto::tsCryptoData &data);
	virtual int  PeekData(int byteCount, int dataOffset, tscrypto::tsCryptoData &data);
	virtual bool UnreadData(const tscrypto::tsCryptoData &data);
	virtual bool UnreadData(const tscrypto::tsCryptoData &data, int offset, int length);
	virtual void SetDataName(const tscrypto::tsCryptoString& setTo);
	virtual bool WriteDataAndFinish(const tscrypto::tsCryptoData &data);
	virtual bool WriteDataAndFinish(const tscrypto::tsCryptoData &data, int offset, int length);
	virtual int64_t BytesRead();
	virtual int64_t BytesWritten();
	virtual void Reset();
	virtual void ResetWriter();

protected:
	virtual ~CkmMemoryFifoStream(void);

private:
	tscrypto::tsCryptoData m_data;
	tscrypto::tsCryptoString m_filename;
	bool m_writerDone;
	std::shared_ptr<IFifoStreamReaderCallback> m_readerCallback;
	std::shared_ptr<IFifoStreamWriterCallback> m_writerCallback;
	mutable tscrypto::AutoCriticalSection m_accessLock;
	tscrypto::CryptoEvent m_writerDoneEvent;
	bool m_callbackReturn;
	int64_t m_bytesRead;
};

std::shared_ptr<IDataIOBase> CreateMemoryFifoStream()
{
	return ::TopServiceLocator()->Finish<IDataIOBase>(new CkmMemoryFifoStream());
}

CkmMemoryFifoStream::CkmMemoryFifoStream(void) :
	m_filename("Memory"),
	m_writerDone(false),
	m_writerDoneEvent(),
	m_callbackReturn(true),
	m_bytesRead(0)
{
}

CkmMemoryFifoStream::~CkmMemoryFifoStream(void)
{
}


#pragma region ICkmDataIOBase
bool CkmMemoryFifoStream::IsValid() const
{
	return true;
}

bool CkmMemoryFifoStream::AllowsRandomAccess() const
{
	return false;
}

bool CkmMemoryFifoStream::IsEndOfFile() const
{
	TSDECLARE_METHODExt(DebugFifoDetail);

	TSAUTOLOCKER locker(m_accessLock);

	if (m_writerDone && m_data.size() == 0)
	{
		LOG(FrameworkInfo1, "Is EOF for " << m_filename);
		return TSRETURN(("True"),true);
	}
	LOG(FrameworkInfo1, "Is NOT EOF for " << m_filename);
	return TSRETURN(("false"),false);
}

bool CkmMemoryFifoStream::KnowsRemainingData() const
{
	return m_writerDone;
}

int64_t CkmMemoryFifoStream::RemainingData() const
{
	TSDECLARE_METHODExt(DebugFifoDetail);

	TSAUTOLOCKER locker(m_accessLock);

	if (DebugFifoSummary) { LOG(FrameworkInfo1, (int)m_data.size() << " bytes remaining in " << m_filename); }
	return TSRETURN(("~~ bytes"),m_data.size());
}

int64_t CkmMemoryFifoStream::DataLength() const
{
	TSDECLARE_METHODExt(DebugFifoDetail);

	TSAUTOLOCKER locker(m_accessLock);

	if (DebugFifoSummary) { LOG(FrameworkInfo1, (int)m_data.size() << " bytes remaining in " << m_filename); }
	return TSRETURN(("~~ bytes"),m_data.size());
}

int64_t CkmMemoryFifoStream::CurrentPosition() const
{
	return 0;
}

tscrypto::tsCryptoString CkmMemoryFifoStream::DataName() const
{
	return m_filename;
}

void CkmMemoryFifoStream::SetDataName(const tscrypto::tsCryptoString& setTo)
{
	m_filename = setTo;
}

void CkmMemoryFifoStream::Close()
{
	TSAUTOLOCKER locker(m_accessLock);

	m_data.clear();
	WriterDone();
	m_writerDoneEvent.Set();
}

bool CkmMemoryFifoStream::GoToPosition(int64_t setTo)
{
	MY_UNREFERENCED_PARAMETER(setTo);
	return false;
}

int64_t CkmMemoryFifoStream::Seek(int origin, int64_t position)
{
	MY_UNREFERENCED_PARAMETER(origin);
	MY_UNREFERENCED_PARAMETER(position);

	return false;
}



#pragma endregion

#pragma region ICkmDataWriter
bool CkmMemoryFifoStream::WriteData(const tscrypto::tsCryptoData &data)
{
	TSDECLARE_METHODExt(DebugFifoIODetail);

	std::shared_ptr<IFifoStreamReaderCallback> cb;

	{
		TSAUTOLOCKER locker(m_accessLock);

		if (m_writerDone)
			return TSRETURN(("false"),false);

		m_data += data;
		if (DebugFifoIOSummary) { LOG(FrameworkInfo1, "Wrote " << (int)data.size() << " bytes to " << m_filename); }
		cb = m_readerCallback;
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

bool CkmMemoryFifoStream::WriteData(const tscrypto::tsCryptoData &data, int offset, int length)
{
	TSDECLARE_METHODExt(DebugFifoIODetail);

	std::shared_ptr<IFifoStreamReaderCallback> cb;

	{
		TSAUTOLOCKER locker(m_accessLock);

		if (m_writerDone)
			return TSRETURN(("false"),false);

		if (offset < 0 || length < 1 || offset + length < 1)
			return TSRETURN(("false"),false);

		if (data.size() < (uint32_t)(offset + length))
			return TSRETURN(("false"),false);

		m_data.append(&data.c_str()[offset], length);
		if (DebugFifoIOSummary) { LOG(FrameworkInfo1, "Wrote " << length << " bytes to " << m_filename); }
		cb = m_readerCallback;
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
	return TSRETURN(("true - wrote %d bytes", length),true);
}

bool CkmMemoryFifoStream::Flush()
{
	TSDECLARE_METHODExt(DebugFifoIODetail);

	if (!!m_readerCallback)
	{
		if (!(m_callbackReturn = m_readerCallback->DataAvailable(std::dynamic_pointer_cast<IFifoStream>(_me.lock()))))
		{
			Close();
			return TSRETURN(("false"),false);
		}
	}
	if (IsEndOfFile())
		m_writerDoneEvent.Set();
	return TSRETURN(("true"),true);
}

bool CkmMemoryFifoStream::Truncate()
{
	return false;
}

bool CkmMemoryFifoStream::SetFileSize(int64_t setTo)
{
	MY_UNREFERENCED_PARAMETER(setTo);
	return false;
}

bool CkmMemoryFifoStream::CanPrepend() const
{
	return false;
}

bool CkmMemoryFifoStream::Prepend(const tscrypto::tsCryptoData &data)
{
	MY_UNREFERENCED_PARAMETER(data);
	return false;
}
#pragma endregion

#pragma region ICkmDataReader
bool CkmMemoryFifoStream::ReadData(int byteCount, tscrypto::tsCryptoData &data)
{
	TSDECLARE_METHODExt(DebugFifoIODetail);

	TSAUTOLOCKER locker(m_accessLock);

	if (byteCount < 0)
		return TSRETURN(("false"),false);

	int count = byteCount;
	if (count > (int)m_data.size())
		count = (int)(m_data.size());

	data.resize(count);

	if (count > 0)
	{
		memcpy(data.rawData(), m_data.c_str(), count);
		m_data.erase(0, count);
		m_bytesRead += count;
		if (DebugFifoIOSummary) { LOG(FrameworkInfo1, "Read " << count << " bytes from " << m_filename); }
	}
	return TSRETURN(("true - returned %d bytes", data.size()),true);
}

int CkmMemoryFifoStream::ReadData(int byteCount, int dataOffset, tscrypto::tsCryptoData &data)
{
	TSDECLARE_METHODExt(DebugFifoIODetail);

	TSAUTOLOCKER locker(m_accessLock);

	if (dataOffset < 0 || byteCount < 0 || dataOffset + byteCount < 0)
		return TSRETURN(("0"),0);

	int count = byteCount;
	if (count > (int)m_data.size())
		count = (int)(m_data.size());

	if (data.size() < (uint32_t)(dataOffset + count))
	{
		data.resize(dataOffset + count);
	}

	if (count > 0)
	{
		memcpy(&data.rawData()[dataOffset], m_data.c_str(), count);
		m_data.erase(0, count);
		m_bytesRead += count;
		if (DebugFifoIOSummary) { LOG(FrameworkInfo1, "Read " << count << " bytes from " << m_filename); }
	}
	return TSRETURN(("Returns ~~ bytes"),count);
}
#pragma endregion

#pragma region ICkmFifoStream
void CkmMemoryFifoStream::WriterDone()
{
	TSDECLARE_METHODExt(DebugFifoIODetail || DebugFifoIOSummary);

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

bool CkmMemoryFifoStream::SetReaderCallback(std::shared_ptr<IFifoStreamReaderCallback> setTo)
{
	TSAUTOLOCKER locker(m_accessLock);

	m_readerCallback.reset();
	if (setTo != NULL)
		m_readerCallback = setTo;
	return true;
}

bool CkmMemoryFifoStream::SetWriterCallback(std::shared_ptr<IFifoStreamWriterCallback> setTo)
{
	TSAUTOLOCKER locker(m_accessLock);

	m_writerCallback.reset();
	if (setTo != NULL)
		m_writerCallback = setTo;
	return true;
}

bool CkmMemoryFifoStream::ProcessAllData()
{
	TSDECLARE_METHODExt(DebugFifoDetail | DebugFifoSummary);

	std::shared_ptr<IFifoStream> This(std::dynamic_pointer_cast<IFifoStream>(_me.lock()));

    if (m_writerDone)
    {
        m_callbackReturn = true;
		if (!!m_readerCallback)
		{
			while (!IsEndOfFile())
			{
				if (m_callbackReturn)
				{
					// Allow for final cleanup here
					if (!(m_callbackReturn = m_readerCallback->DataAvailable(This)))
					{
						return TSRETURN(("Returns ~~"),m_callbackReturn);
					}
				}
			}
		}
		return TSRETURN(("Returns ~~"),m_callbackReturn);
    }
	else if (!!m_writerCallback)
	{
		bool retVal = m_writerCallback->ProduceData(This);
		WriterDone();
		if (!retVal)
			return TSRETURN(("Returns ~~"),false);

		if (!!m_readerCallback)
		{
			while (!IsEndOfFile())
			{
				if (m_callbackReturn)
				{
					// Allow for final cleanup here
					if (!(m_callbackReturn = m_readerCallback->DataAvailable(This)))
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
			if (!!m_readerCallback && IsEndOfFile())
			{
				if (!(m_callbackReturn = m_readerCallback->DataAvailable(This)))
				{
					break;
				}
			}
		}
		return TSRETURN(("Returns from callback ~~"),m_callbackReturn);
	}
}

bool CkmMemoryFifoStream::IsWriterFinished() const
{
	return m_writerDone;
}

bool CkmMemoryFifoStream::PeekData(int byteCount, tscrypto::tsCryptoData &data)
{
	TSDECLARE_METHODExt(DebugFifoIODetail);

	TSAUTOLOCKER locker(m_accessLock);

	if (byteCount < 1)
		return TSRETURN(("false"),false);

	int count = byteCount;
	if (count > (int)m_data.size())
		count = (int)(m_data.size());

	data.resize(count);

	if (count > 0)
	{
		memcpy(data.rawData(), m_data.c_str(), count);
		if (DebugFifoIOSummary) { LOG(FrameworkInfo1, "Peeked at " << count << " bytes from " << m_filename); }
	}
	return TSRETURN(("true"),true);
}

int CkmMemoryFifoStream::PeekData(int byteCount, int dataOffset, tscrypto::tsCryptoData &data)
{
	TSDECLARE_METHODExt(DebugFifoIODetail);

	TSAUTOLOCKER locker(m_accessLock);

	if (dataOffset < 0 || byteCount < 1 || dataOffset + byteCount < 0)
		return TSRETURN(("0"),0);

	int count = byteCount;
	if (count > (int)m_data.size())
		count = (int)(m_data.size());

	if (data.size() < (uint32_t)(dataOffset + count))
	{
		data.resize(dataOffset + count);
	}

	if (count > 0)
	{
		memcpy(&data.rawData()[dataOffset], m_data.c_str(), count);
		if (DebugFifoIOSummary) { LOG(FrameworkInfo1, "Peeked at " << count << " bytes from " << m_filename); }
	}
	return TSRETURN(("~~ bytes"),count);
}
bool CkmMemoryFifoStream::UnreadData(const tscrypto::tsCryptoData &data)
{
	TSDECLARE_METHODExt(DebugFifoIODetail);

	TSAUTOLOCKER locker(m_accessLock);

	if (m_writerDone)
		return TSRETURN(("false"),false);

	m_data.insert(0, data);
	m_bytesRead -= data.size();
	if (DebugFifoIOSummary) { LOG(FrameworkInfo1, "Returned " << (int)data.size() << " bytes to " << m_filename); }

	return TSRETURN(("true"),true);
}

bool CkmMemoryFifoStream::UnreadData(const tscrypto::tsCryptoData &data, int offset, int length)
{
	TSDECLARE_METHODExt(DebugFifoIODetail);

	TSAUTOLOCKER locker(m_accessLock);

	if (m_writerDone)
		return TSRETURN(("false"),false);

	if (offset < 0 || length < 1 || offset + length < 1)
		return TSRETURN(("false"),false);

	if (data.size() < (uint32_t)(offset + length))
		return TSRETURN(("false"),false);

	m_data.insert(0, &data.c_str()[offset], length);
	m_bytesRead -= length;
	if (DebugFifoIOSummary) { LOG(FrameworkInfo1, "Returned " << length << " bytes to " << m_filename); }
	return TSRETURN(("true"),true);
}

bool CkmMemoryFifoStream::WriteDataAndFinish(const tscrypto::tsCryptoData &data)
{
	TSDECLARE_METHODExt(DebugFifoIODetail);

	std::shared_ptr<IFifoStreamReaderCallback> cb;

	{
		TSAUTOLOCKER locker(m_accessLock);

		if (m_writerDone)
			return TSRETURN(("false"),false);

		m_data += data;
		if (DebugFifoIOSummary) { LOG(FrameworkInfo1, "Wrote " << (int)data.size() << " bytes to " << m_filename << " and finished"); }
		cb = m_readerCallback;
		m_writerDone = true;
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
	return TSRETURN(("true"),true);
}

bool CkmMemoryFifoStream::WriteDataAndFinish(const tscrypto::tsCryptoData &data, int offset, int length)
{
	TSDECLARE_METHODExt(DebugFifoIODetail);

	std::shared_ptr<IFifoStreamReaderCallback> cb;

	{
		TSAUTOLOCKER locker(m_accessLock);

		if (m_writerDone)
			return TSRETURN(("false"),false);

		if (offset < 0 || length < 1 || offset + length < 1)
			return TSRETURN(("false"),false);

		if (data.size() < (uint32_t)(offset + length))
			return TSRETURN(("false"),false);

		m_data.append(&data.c_str()[offset], length);
		if (DebugFifoIOSummary) { LOG(FrameworkInfo1, "Wrote " << length << " bytes to " << m_filename << " and finished"); }
		cb = m_readerCallback;
		m_writerDone = true;
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
	return TSRETURN(("true"),true);
}

int64_t CkmMemoryFifoStream::BytesRead()
{
	TSDECLARE_METHODExt(DebugFifoDetail);

	if (DebugFifoSummary) { LOG(FrameworkInfo1, m_bytesRead << " bytes read from " << m_filename); }

	return TSRETURN(("~~ bytes read"),m_bytesRead);
}

int64_t CkmMemoryFifoStream::BytesWritten()
{
	TSDECLARE_METHODExt(DebugFifoDetail);

	if (DebugFifoSummary) { LOG(FrameworkInfo1, m_bytesRead + m_data.size() << " bytes written to " << m_filename); }

	return TSRETURN(("~~ bytes written"),m_bytesRead + m_data.size());
}

void CkmMemoryFifoStream::Reset()
{
	TSDECLARE_METHODExt(DebugFifoDetail);

	TSAUTOLOCKER locker(m_accessLock);

	m_data.clear();
    m_filename = "Memory";
	m_writerDone = false;
	m_readerCallback.reset();
	m_writerCallback.reset();
	if (m_writerDoneEvent.IsActive())
		m_writerDoneEvent.WaitForEvent(XP_EVENT_TRY);
	m_callbackReturn = true;
	m_bytesRead = 0;
	TSRETURN_V(("Done"));
}
void CkmMemoryFifoStream::ResetWriter()
{
	TSAUTOLOCKER locker(m_accessLock);

	m_data.clear();
	m_writerDone = false;
	m_bytesRead = 0;
	m_callbackReturn = true;
	if (m_writerDoneEvent.IsActive())
		m_writerDoneEvent.WaitForEvent(XP_EVENT_TRY);
}

#pragma endregion

