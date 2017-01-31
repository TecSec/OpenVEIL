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

class HIDDEN CkmMemoryStream :
	public tsmod::IObject,
	public IDataReader, public IDataWriter, public ICkmPersistable, public IDataIOBase
{
public:
	CkmMemoryStream(void);

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

	// ICkmPersistable
	virtual tscrypto::tsCryptoData ToBytes();
	virtual bool FromBytes(const tscrypto::tsCryptoData &setTo);

protected:
	virtual ~CkmMemoryStream(void);

private:
	tscrypto::tsCryptoData m_data;
	tscrypto::tsCryptoString m_filename;
	int64_t m_position;
};

std::shared_ptr<IDataIOBase> CreateMemoryStream()
{
	return ::TopServiceLocator()->Finish<IDataIOBase>(new CkmMemoryStream());
}

CkmMemoryStream::CkmMemoryStream(void) :
	m_filename("Memory"),
	m_position(0)
{
}

CkmMemoryStream::~CkmMemoryStream(void)
{
}

#pragma region ICkmDataIOBase
bool CkmMemoryStream::IsValid() const
{
	return true;
}

bool CkmMemoryStream::AllowsRandomAccess() const
{
	return true;
}

bool CkmMemoryStream::IsEndOfFile() const
{
	if (m_position >= (int64_t)m_data.size())
		return true;
	return false;
}

bool CkmMemoryStream::KnowsRemainingData() const
{
	return true;
}

int64_t CkmMemoryStream::RemainingData() const
{
	return DataLength() - CurrentPosition();
}

int64_t CkmMemoryStream::DataLength() const
{
	return m_data.size();
}

int64_t CkmMemoryStream::CurrentPosition() const
{
	return m_position;
}

tscrypto::tsCryptoString CkmMemoryStream::DataName() const
{
	return m_filename;
}

void CkmMemoryStream::SetDataName(const tscrypto::tsCryptoString& setTo)
{
	m_filename = setTo;
}


void CkmMemoryStream::Close()
{
}
#pragma endregion

#pragma region ICkmDataWriter
bool CkmMemoryStream::GoToPosition(int64_t setTo)
{
	if (setTo < 0 || setTo > DataLength())
		return false;

	m_position = setTo;
	return false;
}

int64_t CkmMemoryStream::Seek(int origin, int64_t position)
{
	switch (origin)
	{
	case SEEK_SET:
		GoToPosition(position);
		break;
	case SEEK_END:
		GoToPosition(DataLength() + position);
		break;
	case SEEK_CUR:
		GoToPosition(CurrentPosition() + position);
		break;
	}
	return CurrentPosition();
}

bool CkmMemoryStream::WriteData(const tscrypto::tsCryptoData &data)
{
	if (m_data.size() - m_position < data.size())
	{
		uint32_t newSize = (uint32_t)(m_position + data.size());
		m_data.resize(newSize);
	}

	memcpy(&m_data.rawData()[(int)m_position], data.c_str(), data.size());
	m_position += data.size();
	return true;
}

bool CkmMemoryStream::WriteData(const tscrypto::tsCryptoData &data, int offset, int length)
{
	if (offset < 0 || length < 1 || offset + length < 1)
		return false;

	if (data.size() < (uint32_t)(offset + length))
		return false;

	if (m_data.size() - m_position < length)
	{
		uint32_t newSize = (uint32_t)(m_position + length);
		m_data.resize(newSize);
	}

	memcpy(&m_data.rawData()[(int)m_position], &data.c_str()[offset], length);
	m_position += length;
	return true;
}

bool CkmMemoryStream::Flush()
{
	return true;
}

bool CkmMemoryStream::Truncate()
{
	if (!AllowsRandomAccess())
		return false;
	m_data.resize((int)CurrentPosition());
	m_position = CurrentPosition();
	return 0;
}

bool CkmMemoryStream::SetFileSize(int64_t setTo)
{
	if (setTo < 0 || setTo > 0x7FFFFFFF)
		return false;
	if (!AllowsRandomAccess())
		return false;
	m_data.resize((size_t)setTo);
	return true;
}

bool CkmMemoryStream::CanPrepend() const
{
	return true;
}

bool CkmMemoryStream::Prepend(const tscrypto::tsCryptoData &data)
{
	if (data.size() == 0)
		return true;
	if (((int64_t)data.size()) + m_data.size() > 0x7FFFFFFF)
		return false;
	m_data.insert(0, data);
	return true;
}
#pragma endregion

#pragma region ICkmDataReader
bool CkmMemoryStream::ReadData(int byteCount, tscrypto::tsCryptoData &data)
{
	if (byteCount < 1)
		return false;

	int count = byteCount;
	if (count > m_data.size() - m_position)
		count = (int)(m_data.size() - m_position);

	data.resize(count);

	if (count > 0)
		memcpy(data.rawData(), &m_data.c_str()[(int)m_position], count);
	m_position += count;
	return true;
}

int CkmMemoryStream::ReadData(int byteCount, int dataOffset, tscrypto::tsCryptoData &data)
{
	if (dataOffset < 0 || byteCount < 1 || dataOffset + byteCount < 0)
		return false;

	int count = byteCount;
	if (count > m_data.size() - m_position)
		count = (int)(m_data.size() - m_position);

	if (data.size() < (uint32_t)(dataOffset + count))
	{
		data.resize(dataOffset + count);
	}

	if (count > 0)
		memcpy(&data.rawData()[dataOffset], &m_data.c_str()[(int)m_position], count);
	m_position += count;

	return count;
}
bool CkmMemoryStream::PeekData(int byteCount, tscrypto::tsCryptoData &data)
{
	if (byteCount < 1)
		return false;

	int count = byteCount;
	if (count > m_data.size() - m_position)
		count = (int)(m_data.size() - m_position);

	data.resize(count);

	if (count > 0)
		memcpy(data.rawData(), &m_data.c_str()[(int)m_position], count);
	return true;
}

int CkmMemoryStream::PeekData(int byteCount, int dataOffset, tscrypto::tsCryptoData &data)
{
	if (dataOffset < 0 || byteCount < 1 || dataOffset + byteCount < 0)
		return false;

	int count = byteCount;
	if (count > m_data.size() - m_position)
		count = (int)(m_data.size() - m_position);

	if (data.size() < (uint32_t)(dataOffset + count))
	{
		data.resize(dataOffset + count);
	}

	if (count > 0)
		memcpy(&data.rawData()[dataOffset], &m_data.c_str()[(int)m_position], count);

	return count;
}
#pragma endregion

#pragma region ICkmPersistable
tscrypto::tsCryptoData CkmMemoryStream::ToBytes()
{
	return m_data;
}

bool CkmMemoryStream::FromBytes(const tscrypto::tsCryptoData &setTo)
{
	m_data = setTo;
	m_position = 0;
	return true;
}

#pragma endregion

