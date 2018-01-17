//	Copyright (c) 2018, TecSec, Inc.
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

class HIDDEN CCkmBZ2Compression : public ICompression, public tsmod::IObject
{
public:
    CCkmBZ2Compression()
        :
        handle(nullptr)
    {
        handle = tsCreateConpressor("BZIP2");
    }

    virtual ~CCkmBZ2Compression()
    {
        tsFreeWorkspace(&handle);
    }

    virtual bool CompressInit(int level)
    {
        return tsCompressInit(handle, level);
    }
    virtual bool Compress(const tscrypto::tsCryptoData &inBuff, tscrypto::tsCryptoData &outBuff, CompressionAction action)
    {
        TSBYTE_BUFF buff = tsCreateBuffer();

        bool retVal = tsCompress(handle, inBuff.c_str(), (uint32_t)inBuff.size(), buff, (tsCompressionActionEnum)action);
        outBuff.clear();
        if (buff != NULL && tsBufferUsed(buff) > 0)
        {
            outBuff.assign(tsGetBufferDataPtr(buff), tsBufferUsed(buff));
        }
        tsFreeBuffer(&buff);
        return retVal;
    }
    virtual bool CompressFinal(tscrypto::tsCryptoData &outBuff)
    {
        TSBYTE_BUFF buff = tsCreateBuffer();

        bool retVal = tsCompressFinal(handle, buff);
        outBuff.clear();
        if (buff != NULL && tsBufferUsed(buff) > 0)
        {
            outBuff.assign(tsGetBufferDataPtr(buff), tsBufferUsed(buff));
        }
        tsFreeBuffer(&buff);
        return retVal;
    }

    virtual bool DecompressInit()
    {
        return tsDecompressInit(handle);
    }
    virtual bool Decompress(const tscrypto::tsCryptoData &inBuff, tscrypto::tsCryptoData &outBuff, CompressionAction action)
    {
        TSBYTE_BUFF buff = tsCreateBuffer();

        bool retVal = tsDecompress(handle, inBuff.c_str(), (uint32_t)inBuff.size(), buff, (tsCompressionActionEnum)action);
        outBuff.clear();
        if (buff != NULL && tsBufferUsed(buff) > 0)
        {
            outBuff.assign(tsGetBufferDataPtr(buff), tsBufferUsed(buff));
        }
        tsFreeBuffer(&buff);
        return retVal;
    }
    virtual bool DecompressFinal(tscrypto::tsCryptoData &outBuff)
    {
        TSBYTE_BUFF buff = tsCreateBuffer();

        bool retVal = tsDecompressFinal(handle, buff);
        outBuff.clear();
        if (buff != NULL && tsBufferUsed(buff) > 0)
        {
            outBuff.assign(tsGetBufferDataPtr(buff), tsBufferUsed(buff));
        }
        tsFreeBuffer(&buff);
        return retVal;
    }

private:
    TSCOMPRESSION handle;
};

class HIDDEN CCkmZLibCompression : public ICompression, public tsmod::IObject
{
public:
	CCkmZLibCompression()
		:
		handle(nullptr)
	{
        handle = tsCreateConpressor("ZLIB");
	}

	virtual ~CCkmZLibCompression()
    {
        tsFreeWorkspace(&handle);
    }

	virtual bool CompressInit(int level)
	{
        return tsCompressInit(handle, level);
	}
	virtual bool Compress(const tscrypto::tsCryptoData &inBuff, tscrypto::tsCryptoData &outBuff, CompressionAction action)
	{
        TSBYTE_BUFF buff = tsCreateBuffer();

        bool retVal = tsCompress(handle, inBuff.c_str(), (uint32_t)inBuff.size(), buff, (tsCompressionActionEnum)action);
        outBuff.clear();
        if (buff != NULL && tsBufferUsed(buff) > 0)
        {
            outBuff.assign(tsGetBufferDataPtr(buff), tsBufferUsed(buff));
        }
        tsFreeBuffer(&buff);
        return retVal;
	}
	virtual bool CompressFinal(tscrypto::tsCryptoData &outBuff)
	{
        TSBYTE_BUFF buff = tsCreateBuffer();

        bool retVal = tsCompressFinal(handle, buff);
        outBuff.clear();
        if (buff != NULL && tsBufferUsed(buff) > 0)
        {
            outBuff.assign(tsGetBufferDataPtr(buff), tsBufferUsed(buff));
        }
        tsFreeBuffer(&buff);
        return retVal;
	}

	virtual bool DecompressInit()
	{
        return tsDecompressInit(handle);
	}
	virtual bool Decompress(const tscrypto::tsCryptoData &inBuff, tscrypto::tsCryptoData &outBuff, CompressionAction action)
	{
        TSBYTE_BUFF buff = tsCreateBuffer();

        bool retVal = tsDecompress(handle, inBuff.c_str(), (uint32_t)inBuff.size(), buff, (tsCompressionActionEnum)action);
        outBuff.clear();
        if (buff != NULL && tsBufferUsed(buff) > 0)
        {
            outBuff.assign(tsGetBufferDataPtr(buff), tsBufferUsed(buff));
        }
        tsFreeBuffer(&buff);
        return retVal;
	}
	virtual bool DecompressFinal(tscrypto::tsCryptoData &outBuff)
	{
        TSBYTE_BUFF buff = tsCreateBuffer();

        bool retVal = tsDecompressFinal(handle, buff);
        outBuff.clear();
        if (buff != NULL && tsBufferUsed(buff) > 0)
        {
            outBuff.assign(tsGetBufferDataPtr(buff), tsBufferUsed(buff));
        }
        tsFreeBuffer(&buff);
        return retVal;
    }

private:
    TSCOMPRESSION handle;
};

class HIDDEN NoCompression : public ICompression, public tsmod::IObject
{
public:
	NoCompression(){}
	virtual ~NoCompression(){}

	virtual bool CompressInit(int level)
	{
        UNREFERENCED_PARAMETER(level);
		return true;
	}
	virtual bool Compress(const tscrypto::tsCryptoData &inBuff, tscrypto::tsCryptoData &outBuff, CompressionAction action)
	{
		outBuff = inBuff;
		return true;
	}
	virtual bool CompressFinal(tscrypto::tsCryptoData &outBuff)
	{
		outBuff.clear();
		return true;
	}

	virtual bool DecompressInit()
	{
		return true;
	}
	virtual bool Decompress(const tscrypto::tsCryptoData &inBuff, tscrypto::tsCryptoData &outBuff, CompressionAction action)
	{
		outBuff = inBuff;
		return true;
	}
	virtual bool DecompressFinal(tscrypto::tsCryptoData &outBuff)
	{
		outBuff.clear();
		return true;
	}
};

std::shared_ptr<ICompression> CreateCompressor(CompressionType type)
{
	switch (type)
	{
	case ct_None:
		return ::TopServiceLocator()->Finish<ICompression>(new NoCompression());
	case ct_zLib:
		return ::TopServiceLocator()->Finish<ICompression>(new CCkmZLibCompression());
	case ct_BZ2:
		return ::TopServiceLocator()->Finish<ICompression>(new CCkmBZ2Compression());
	}
	return nullptr;
}
