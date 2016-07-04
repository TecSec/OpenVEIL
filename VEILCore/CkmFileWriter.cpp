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

class HIDDEN CkmFileWriter :
	public tsmod::IObject,
	public IDataWriter,
	public IDataIOBase
{
public:
	CkmFileWriter(const tscrypto::tsCryptoString& filename);

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

	// ICkmDataWriter
	virtual bool GoToPosition(int64_t setTo);
	virtual int64_t Seek(int origin, int64_t position);
	virtual bool WriteData(const tscrypto::tsCryptoData &data);
	virtual bool WriteData(const tscrypto::tsCryptoData &data, int offset, int length);
	virtual bool Flush();
	virtual bool Truncate();
	virtual bool SetFileSize(int64_t setTo);
	virtual bool CanPrepend() const;
	virtual bool Prepend(const tscrypto::tsCryptoData &data);

protected:
	virtual ~CkmFileWriter(void);

private:
	FILE *m_outputFile;
	int64_t m_dataLength;
	tscrypto::tsCryptoString m_filename;
};

std::shared_ptr<IDataIOBase> CreateDataWriter(const tscrypto::tsCryptoString& filename)
{
	return ::TopServiceLocator()->Finish<IDataIOBase>(new CkmFileWriter(filename));
}

CkmFileWriter::CkmFileWriter(const tscrypto::tsCryptoString& filename) :
	m_outputFile(NULL),
	m_dataLength(0),
	m_filename(filename)
{
#ifdef _WIN32
	m_outputFile = _fsopen(filename.c_str(), ("wb"), _SH_DENYNO);
#else
	m_outputFile = fopen(filename.c_str(), ("wb"));
#endif // _WIN32
	if (m_outputFile == NULL)
	{
		m_filename.clear();
	}
}

CkmFileWriter::~CkmFileWriter(void)
{
	Close();
}

#pragma region ICkmDataIOBase
bool CkmFileWriter::IsValid() const
{
	return m_outputFile != NULL;
}

bool CkmFileWriter::AllowsRandomAccess() const
{
	return true;
}

bool CkmFileWriter::IsEndOfFile() const
{
	if (m_outputFile == NULL)
		return true;
	return feof(m_outputFile) != 0;
}

bool CkmFileWriter::KnowsRemainingData() const
{
	return true;
}

int64_t CkmFileWriter::RemainingData() const
{
	return DataLength() - CurrentPosition();
}

int64_t CkmFileWriter::DataLength() const
{
	return m_dataLength;
}

int64_t CkmFileWriter::CurrentPosition() const
{
	if (m_outputFile == NULL)
		return 0;
#ifdef HAVE__FSEEKI64
	return _ftelli64(m_outputFile);
#else
	return ftell(m_outputFile);
#endif // HAVE__FSEEKI64
}

tscrypto::tsCryptoString CkmFileWriter::DataName() const
{
	return m_filename;
}

void CkmFileWriter::SetDataName(const tscrypto::tsCryptoString& setTo)
{
	m_filename = setTo;
}


void CkmFileWriter::Close()
{
	if (m_outputFile != NULL)
		fclose(m_outputFile);
	m_outputFile = NULL;
}
#pragma endregion

#pragma region ICkmDataWriter
bool CkmFileWriter::GoToPosition(int64_t setTo)
{
	if (m_outputFile == NULL)
		return false;

#ifdef HAVE__FSEEKI64
	return _fseeki64(m_outputFile, setTo, SEEK_SET) == 0;
#else
	return fseek(m_outputFile, setTo, SEEK_SET) == 0;
#endif // HAVE__FSEEKI64
}

int64_t CkmFileWriter::Seek(int origin, int64_t position)
{
	if (m_outputFile == NULL)
		return CurrentPosition();

#ifdef HAVE__FSEEKI64
	_fseeki64(m_outputFile, position, origin);
#else
	fseek(m_outputFile, position, origin);
#endif // HAVE__FSEEKI64
	return CurrentPosition();
}


bool CkmFileWriter::WriteData(const tscrypto::tsCryptoData &data)
{
	if (m_outputFile == NULL)
		return false;

	int count = (int)fwrite(data.c_str(), 1, data.size(), m_outputFile);
	int64_t len = CurrentPosition();
	if (len > m_dataLength)
		m_dataLength = len;
	return count == (int)data.size();
}

bool CkmFileWriter::WriteData(const tscrypto::tsCryptoData &data, int offset, int length)
{
	if (m_outputFile == NULL)
		return false;

	if (offset < 0 || length < 1 || offset + length < 1)
		return false;

	if (data.size() < (uint32_t)(offset + length))
		return false;

	int count = (int)fwrite(&data.c_str()[offset], 1, length, m_outputFile);
	int64_t len = CurrentPosition();
	if (len > m_dataLength)
		m_dataLength = len;
	return count == length;
}

bool CkmFileWriter::Flush()
{
	if (m_outputFile == NULL)
		return false;
	return fflush(m_outputFile) == 0;
}

bool CkmFileWriter::Truncate()
{
	if (m_outputFile == NULL || !AllowsRandomAccess())
		return false;
#ifdef _WIN32
	return (_chsize_s(_fileno(m_outputFile), CurrentPosition()) == 0);
#else
	return (ftruncate(fileno(m_outputFile), CurrentPosition()) == 0);
#endif // _WIN32
}

bool CkmFileWriter::SetFileSize(int64_t setTo)
{
	if (m_outputFile == NULL || !AllowsRandomAccess() || setTo < 0)
		return false;
#ifdef _WIN32
	return (_chsize_s(_fileno(m_outputFile), setTo) == 0);
#else
	return (ftruncate(fileno(m_outputFile), setTo) == 0);
#endif // _WIN32
}

bool CkmFileWriter::CanPrepend() const
{
	return false;
}

bool CkmFileWriter::Prepend(const tscrypto::tsCryptoData &data)
{
	MY_UNREFERENCED_PARAMETER(data);
	return false;
}


#pragma endregion


#pragma region tsStreamWriter
tsStreamWriter::tsStreamWriter(std::shared_ptr<IDataWriter> writer) :
	justHadNewline(true),
	numberBase(10),
	width(0),
	filler(' '),
	_writer(writer),
	_indentLevel(0)
{
	leftDoublePrecision = 4;
	rightDoublePrecision = 3;
}

tsStreamWriter::~tsStreamWriter(void)
{
}

void tsStreamWriter::resetSingleOps()
{
	numberBase = 10;
	width = 0;
	filler = ' ';
}

//#ifdef _WIN32
//void *tsStreamWriter::operator new(size_t bytes) { return FrameworkAllocator(bytes); }
//void tsStreamWriter::operator delete(void *ptr) { return FrameworkDeallocator(ptr); }
//#endif // _WIN32
//tsStreamWriter &tsStreamWriter::operator<< (tsStreamWriter &value)
//{
//    UNREFERENCED_PARAMETER(value);
//    return *this;
//}

tsStreamWriter &tsStreamWriter::operator<<(tsStreamWriter &(*_Pfn)(tsStreamWriter &obj))
{
	(*_Pfn)(*this);
	//resetSingleOps();
	return *this;
}

tsStreamWriter &tsStreamWriter::operator<< (const tscrypto::tsCryptoString &value)
{
	tscrypto::tsCryptoString data = value;

	processData(data);
	resetSingleOps();
	return *this;
}

tsStreamWriter &tsStreamWriter::operator<< (int16_t value)
{
	tscrypto::tsCryptoString data;

	if (numberBase == 16)
	{
		data.Format("%04hX", value);
	}
	else
		data.Format("%hd", value);
	processData(data);
	resetSingleOps();
	return *this;
}

tsStreamWriter &tsStreamWriter::operator<< (uint16_t value)
{
	tscrypto::tsCryptoString data;

	if (numberBase == 16)
	{
		data.Format("%04hX", value);
	}
	else
		data.Format("%hu", value);
	processData(data);
	resetSingleOps();
	return *this;
}

tsStreamWriter &tsStreamWriter::operator<< (uint8_t value)
{
	tscrypto::tsCryptoString data;

	if (numberBase == 16)
	{
		data.Format("%02hX", value);
	}
	else
		data.Format("%hu", value);
	processData(data);
	resetSingleOps();
	return *this;
}

tsStreamWriter &tsStreamWriter::operator<< (int32_t value)
{
	tscrypto::tsCryptoString data;

	if (numberBase == 16)
	{
		data.Format("%08X", value);
	}
	else
		data.Format("%d", value);
	processData(data);
	resetSingleOps();
	return *this;
}

tsStreamWriter &tsStreamWriter::operator<< (uint32_t value)
{
	tscrypto::tsCryptoString data;

	if (numberBase == 16)
	{
		data.Format("%08lX", value);
	}
	else
		data.Format("%lu", value);
	processData(data);
	resetSingleOps();
	return *this;
}

#ifdef _WIN32
tsStreamWriter &tsStreamWriter::operator<< (long value)
{
	tscrypto::tsCryptoString data;

	if (numberBase == 16)
	{
		data.Format("%08X", value);
	}
	else
		data.Format("%d", value);
	processData(data);
	resetSingleOps();
	return *this;
}

tsStreamWriter &tsStreamWriter::operator<< (unsigned long value)
{
	tscrypto::tsCryptoString data;

	if (numberBase == 16)
	{
		data.Format("%08lX", value);
	}
	else
		data.Format("%lu", value);
	processData(data);
	resetSingleOps();
	return *this;
}
#endif

tsStreamWriter &tsStreamWriter::operator<< (int8_t value)
{
	tscrypto::tsCryptoString data;
	data << value;

	processData(data);
	resetSingleOps();
	return *this;
}

tsStreamWriter &tsStreamWriter::operator<< (int64_t value)
{
	tscrypto::tsCryptoString data;

	if (numberBase == 16)
	{
		data.Format("%I64X", value);
		while (data.size() < 16)
			data.prepend('0');
	}
	else
		data.Format("%I64d", value);
	processData(data);
	resetSingleOps();
	return *this;
}

tsStreamWriter &tsStreamWriter::operator<< (uint64_t value)
{
	tscrypto::tsCryptoString data;

	if (numberBase == 16)
	{
		data.Format("%I64X", value);
		while (data.size() < 16)
			data.prepend('0');
	}
	else
		data.Format("%I64u", value);
	processData(data);
	resetSingleOps();
	return *this;
}

tsStreamWriter &tsStreamWriter::operator<< (double value)
{
	tscrypto::tsCryptoString data;

	data.Format("%*.*lf", leftDoublePrecision, rightDoublePrecision, value);
	processData(data);
	resetSingleOps();
	return *this;
}

tsStreamWriter &tsStreamWriter::operator<< (const tscrypto::tsCryptoData &value)
{
	tscrypto::tsCryptoString data;

	data = value.ToHexString();
	processData(data);
	resetSingleOps();
	return *this;
}

tsStreamWriter &tsStreamWriter::hexDump(tscrypto::tsCryptoData& data)
{
	tscrypto::tsCryptoString dump = data.ToHexDump();

	processData(dump);
	resetSingleOps();
	return *this;
}

//tsStreamWriter &tsStreamWriter::operator<< (const wchar_t *value)
//{
//	tscrypto::tsCryptoString data;
//	data << value;
//
//	processData(data);
//	resetSingleOps();
//	return *this;
//}

tsStreamWriter &tsStreamWriter::operator<< (const char *value)
{
	tscrypto::tsCryptoString data = value;

	processData(data);
	resetSingleOps();
	return *this;
}

tsStreamWriter &tsStreamWriter::ptr(const void *pointer)
{
	tscrypto::tsCryptoString data;

	data.Format("%p", pointer);
	processData(data);
	resetSingleOps();
	return *this;
}

//tsStreamWriter &tsStreamWriter::operator<< (void *value)
//{
//    tscrypto::tsCryptoString data;
//
//    data.Format("%p", value);
//    processData(data);
//	resetSingleOps();
//    return *this;
//}
//
//tsStreamWriter &tsStreamWriter::operator<< (const void *value)
//{
//    tscrypto::tsCryptoString data;
//
//    data.Format("%p", value);
//    processData(data);
//	resetSingleOps();
//    return *this;
//}

tsStreamWriter &tsStreamWriter::setbase(int numbase)
{
	if (numbase != 10 && numbase != 16)
		return *this;
	numberBase = numbase;
	return *this;
}

tsStreamWriter &tsStreamWriter::SetWidth(int setTo)
{
	width = setTo;
	return *this;
}

tsStreamWriter &tsStreamWriter::SetFiller(char setTo)
{
	filler = setTo;
	return *this;
}

tsStreamWriter &tsStreamWriter::SetFloatPrecision(int left, int right)
{
	leftDoublePrecision = left;
	rightDoublePrecision = right;
	return *this;
}

tsStreamWriter &tsStreamWriter::indent()
{
	_indentLevel++;
	return *this;
}

tsStreamWriter &tsStreamWriter::outdent()
{
	_indentLevel--;
	if (_indentLevel < 0)
		_indentLevel = 0;
	return *this;
}

tsStreamWriter &tsStreamWriter::setPrefix(const tscrypto::tsCryptoString& prfx)
{
	prefix = prfx;
	return *this;
}

void tsStreamWriter::processData(tscrypto::tsCryptoString &data)
{
	char *context = NULL;
	char *p;
	bool doWriteLine;
	tscrypto::tsCryptoString tmp;

	if (width < 0)
	{
		data = data.TruncOrPadRight(-width, filler);
	}
	else if (width > 0)
	{
		data = data.TruncOrPadLeft(width, filler);
	}

	data.Replace("\r\n", "\n");
	data.Replace("\r", "\n");

	if (data.size() > 0 && data[0] == '\n')
	{
		data.DeleteAt(0, 1);
		tmp = _partialLine;
		_partialLine.clear();
		if (_indentLevel > 0)
		{
			tmp.prepend(tscrypto::tsCryptoString(' ', _indentLevel * 2));
		}
		tmp << tscrypto::endl;
		_writer->WriteData(tmp.ToUTF8Data());
	}

	while (data.size() > 0)
	{
		doWriteLine = (TsStrChr(data.rawData(), '\n') != NULL);
		p = TsStrTok(data.rawData(), ("\n"), &context);
		tmp.clear();
		//if (justHadNewline && indentLevel > 0)
		//{
		//    tmp.resize(indentLevel * 2, ' ');
		//    if (prefix.size() > 0)
		//    {
		//        tmp.prepend(" ");
		//        tmp.prepend(prefix);
		//    }
		//    justHadNewline = false;
		//}
		tmp += p;
		if (p != NULL)
		{	// 10/11/11 krr added cast for warning C2220 strlen() so x64 would build
			data.DeleteAt(0, (uint32_t)TsStrLen(p) + 1);
		}
		else
		{
			data.DeleteAt(0, 1);
		}

		if (doWriteLine)
		{
			tmp.prepend(_partialLine);
			_partialLine.clear();
			tmp << tscrypto::endl;
			if (_indentLevel > 0)
			{
				tmp.prepend(tscrypto::tsCryptoString(' ', _indentLevel * 2));
			}
			_writer->WriteData(tmp.ToUTF8Data());
		}
		else
		{
			_partialLine << tmp;
		}
		justHadNewline = doWriteLine;
	}
}
#pragma endregion
