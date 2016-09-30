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



tsTraceStream::tsTraceStream(const tscrypto::tsCryptoStringBase& name, int level) :
    justHadNewline(true),
    numberBase(10),
	width(0),
	filler(' '),
	_name(name),
	_level(level)
{
    leftDoublePrecision = 4;
    rightDoublePrecision = 3;
}

tsTraceStream::~tsTraceStream(void)
{
}

void tsTraceStream::resetSingleOps()
{
	numberBase = 10;
	width = 0;
	filler = ' ';
}

//#ifdef _WIN32
//void *tsTraceStream::operator new(size_t bytes) { return FrameworkAllocator(bytes); }
//void tsTraceStream::operator delete(void *ptr) { return FrameworkDeallocator(ptr); }
//#endif // _WIN32
//tsTraceStream &tsTraceStream::operator<< (tsTraceStream &value)
//{
//    UNREFERENCED_PARAMETER(value);
//    return *this;
//}

tsTraceStream &tsTraceStream::operator<<(tsTraceStream &(*_Pfn)(tsTraceStream &obj))
{
    (*_Pfn)(*this);
	//resetSingleOps();
    return *this;
}

tsTraceStream &tsTraceStream::operator<< (const tscrypto::tsCryptoStringBase &value)
{
    tscrypto::tsCryptoString data = value;

    processData(data);
	resetSingleOps();
    return *this;
}

tsTraceStream &tsTraceStream::operator<< (int16_t value)
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

tsTraceStream &tsTraceStream::operator<< (uint16_t value)
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

tsTraceStream &tsTraceStream::operator<< (uint8_t value)
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

tsTraceStream &tsTraceStream::operator<< (int32_t value)
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

tsTraceStream &tsTraceStream::operator<< (uint32_t value)
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
tsTraceStream &tsTraceStream::operator<< (long value)
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

tsTraceStream &tsTraceStream::operator<< (unsigned long value)
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

tsTraceStream &tsTraceStream::operator<< (int8_t value)
{
    tscrypto::tsCryptoString data;
	data << value;

    processData(data);
	resetSingleOps();
    return *this;
}

tsTraceStream &tsTraceStream::operator<< (int64_t value)
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

tsTraceStream &tsTraceStream::operator<< (uint64_t value)
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

tsTraceStream &tsTraceStream::operator<< (double value)
{
    tscrypto::tsCryptoString data;

    data.Format("%*.*lf", leftDoublePrecision, rightDoublePrecision, value);
    processData(data);
	resetSingleOps();
    return *this;
}

tsTraceStream &tsTraceStream::operator<< (const tscrypto::tsCryptoData &value)
{
    tscrypto::tsCryptoString data;

    data = value.ToHexString();
    processData(data);
	resetSingleOps();
    return *this;
}

tsTraceStream &tsTraceStream::hexDump(tscrypto::tsCryptoData& data)
{
	tscrypto::tsCryptoString dump = data.ToHexDump();

	processData(dump);
	resetSingleOps();
	return *this;
}

//tsTraceStream &tsTraceStream::operator<< (const wchar_t *value)
//{
//    tscrypto::tsCryptoString data;
//	data << value;
//
//    processData(data);
//	resetSingleOps();
//    return *this;
//}

tsTraceStream &tsTraceStream::operator<< (const char *value)
{
    tscrypto::tsCryptoString data = value;

    processData(data);
	resetSingleOps();
    return *this;
}

tsTraceStream &tsTraceStream::ptr(const void *pointer)
{
    tscrypto::tsCryptoString data;

    data.Format("%p", pointer);
    processData(data);
	resetSingleOps();
    return *this;
}

//tsTraceStream &tsTraceStream::operator<< (void *value)
//{
//    tscrypto::tsCryptoString data;
//
//    data.Format("%p", value);
//    processData(data);
//	resetSingleOps();
//    return *this;
//}
//
//tsTraceStream &tsTraceStream::operator<< (const void *value)
//{
//    tscrypto::tsCryptoString data;
//
//    data.Format("%p", value);
//    processData(data);
//	resetSingleOps();
//    return *this;
//}

tsTraceStream &tsTraceStream::setbase(int numbase)
{
    if (numbase != 10 && numbase != 16)
        return *this;
    numberBase = numbase;
    return *this;
}

tsTraceStream &tsTraceStream::SetWidth(int setTo)
{
    width = setTo;
    return *this;
}

tsTraceStream &tsTraceStream::SetFiller(char setTo)
{
    filler = setTo;
    return *this;
}

tsTraceStream &tsTraceStream::SetFloatPrecision(int left, int right)
{
    leftDoublePrecision = left;
    rightDoublePrecision = right;
    return *this;
}

tsTraceStream &tsTraceStream::indent()
{
	tsLog::indent(_name.c_str(), _level);
    return *this;
}

tsTraceStream &tsTraceStream::outdent()
{
    tsLog::outdent(_name.c_str(), _level);
    return *this;
}

tsTraceStream &tsTraceStream::setPrefix(const tscrypto::tsCryptoStringBase& prfx)
{
    prefix = prfx;
    return *this;
}

void tsTraceStream::processData(tscrypto::tsCryptoStringBase &data)
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
		tsLog::WriteToLog(_name.c_str(), _level, tmp.c_str());
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
			tsLog::WriteToLog(_name.c_str(), _level, tmp.c_str());
        }
        else
        {
			_partialLine << tmp;
        }
        justHadNewline = doWriteLine;
    }
}
