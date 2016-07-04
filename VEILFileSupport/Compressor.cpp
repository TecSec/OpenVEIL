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
#include "bzlib.h"
#include "zlib.h"

class HIDDEN CCkmBZ2Compression : public ICompression, public tsmod::IObject
{
public:
	CCkmBZ2Compression()
		:
		m_decompressStarted(false),
		m_compressStarted(false)
	{
		memset(&m_stream, 0, sizeof(m_stream));
		m_stream.bzalloc = NULL;
		m_stream.bzfree = NULL;
		m_stream.opaque = NULL;
	}
	virtual ~CCkmBZ2Compression(){}

	virtual bool CompressInit(int level)
	{
		if (m_compressStarted || m_decompressStarted)
			return false;

		m_outputData.erase();

		if (level == 0)
			level = 9;

		int ret = BZ2_bzCompressInit(&m_stream, level, 0, 0);

		if (ret != BZ_OK)
			return false;
		m_compressStarted = true;
		return true;
	}
	virtual bool Compress(const tscrypto::tsCryptoData &inBuff, tscrypto::tsCryptoData &outBuff, CompressionAction action)
	{
		int outputLength;
		//int ret;

		if (!m_compressStarted)
			return false;

		m_stream.avail_in = (unsigned int)inBuff.size();
		m_stream.next_in = (char *)inBuff.c_str();

		outBuff = m_outputData;
		m_outputData.clear();

		LOG(DebugInfo3, "bz2 Compress: input block size " << inBuff.size() << " with " << outBuff.size() << " bytes already in the output buffer");

		do
		{
			outputLength = (int)outBuff.size();
			outBuff.resize(outputLength + 16384);

			m_stream.avail_out = 16384;
			m_stream.next_out = (char*)&outBuff.rawData()[outputLength];

			/*ret =*/ BZ2_bzCompress(&m_stream, (action == compAct_Flush) ? BZ_FLUSH : ((action == compAct_Finish) ? BZ_FINISH : BZ_RUN));

			outBuff.resize(outputLength + 16384 - m_stream.avail_out);
		} while (m_stream.avail_out == 0);
		LOG(DebugInfo3, "output data size " << outBuff.size());
		return true;
	}
	virtual bool CompressFinal(tscrypto::tsCryptoData &outBuff)
	{
		outBuff = m_outputData;
		m_outputData.clear();

		if (m_compressStarted)
		{
			tscrypto::tsCryptoData data;

			do
			{
				data.resize(10240);
				m_stream.avail_in = 0;
				m_stream.next_in = nullptr;
				m_stream.avail_out = 10240;
				m_stream.next_out = (char *)data.rawData();

				BZ2_bzCompress(&m_stream, BZ_FINISH);

				if (m_stream.avail_out != 10240)
				{
					data.resize(10240 - m_stream.avail_out);
					outBuff += data;
				}
			} while (m_stream.avail_out != 10240);
			BZ2_bzCompressEnd(&m_stream);
		}

		m_compressStarted = false;

		LOG(DebugInfo3, "bz2 CompressFinal: output data size " << outBuff.size());
		return true;
	}

	virtual bool DecompressInit()
	{
		if (m_compressStarted || m_decompressStarted)
			return false;

		m_outputData.erase();

		int ret = BZ2_bzDecompressInit(&m_stream, 0, 0);

		if (ret != BZ_OK)
			return false;
		m_decompressStarted = true;
		return true;
	}
	virtual bool Decompress(const tscrypto::tsCryptoData &inBuff, tscrypto::tsCryptoData &outBuff, CompressionAction action)
	{
		int outputLength;
		int ret;

		if (!m_decompressStarted)
			return false;

		m_stream.avail_in = (unsigned int)inBuff.size();
		m_stream.next_in = (char *)inBuff.c_str();

		outBuff = m_outputData;
		m_outputData.clear();

		LOG(DebugInfo3, "bz2 Decompress: input block size " << inBuff.size() << " with " << outBuff.size() << " bytes already in the output buffer");

		do
		{
			outputLength = (int)outBuff.size();
			outBuff.resize(outputLength + 16384);

			m_stream.avail_out = 16384;
			m_stream.next_out = (char *)&outBuff.rawData()[outputLength];

			ret = BZ2_bzDecompress(&m_stream);
			switch (ret) {
			case BZ_SEQUENCE_ERROR :
			case BZ_PARAM_ERROR    :
			case BZ_IO_ERROR       :
			case BZ_UNEXPECTED_EOF :
			case BZ_OUTBUFF_FULL   :
			case BZ_CONFIG_ERROR   :
				ret = BZ_DATA_ERROR;     /* and fall through */
			case BZ_DATA_ERROR:
			case BZ_MEM_ERROR:
			case BZ_DATA_ERROR_MAGIC:
				(void)BZ2_bzDecompressEnd(&m_stream);
				return false;
			}

			outBuff.resize(outputLength + 16384 - m_stream.avail_out);
		} while (m_stream.avail_out == 0);

		LOG(DebugInfo3, "bz2 Decompress: output data size " << outBuff.size());
		return true;
	}
	virtual bool DecompressFinal(tscrypto::tsCryptoData &outBuff)
	{
		if (!m_decompressStarted)
			BZ2_bzDecompressEnd(&m_stream);
		m_decompressStarted = false;

		outBuff = m_outputData;
		m_outputData.clear();

		LOG(DebugInfo3, "bz2 DecompressFinal: output data size " << outBuff.size());

		return true;
	}

private:
	bz_stream	m_stream;
	tscrypto::tsCryptoData	    m_outputData;
	bool        m_decompressStarted;
	bool        m_compressStarted;
};

class HIDDEN CCkmZLibCompression : public ICompression, public tsmod::IObject
{
public:
	CCkmZLibCompression()
		:
		m_decompressStarted(false),
		m_compressStarted(false)
	{
		memset(&m_stream, 0, sizeof(m_stream));
		m_stream.zalloc = Z_NULL;
		m_stream.zfree = Z_NULL;
		m_stream.opaque = Z_NULL;
		m_stream.avail_in = 0;
		m_stream.next_in = Z_NULL;
	}

	virtual ~CCkmZLibCompression(){}

	virtual bool CompressInit(int level)
	{
		if (m_compressStarted || m_decompressStarted)
			return false;

		m_outputData.erase();
		int ret = deflateInit(&m_stream, level);

		if (ret != Z_OK)
			return false;
		m_compressStarted = true;
		return true;
	}
	virtual bool Compress(const tscrypto::tsCryptoData &inBuff, tscrypto::tsCryptoData &outBuff, CompressionAction action)
	{
		int outputLength;
//		int ret;

		if (!m_compressStarted)
			return false;

		if (inBuff.size() == 0)
		{
			return false;
		}

		m_stream.avail_in = (uInt)inBuff.size();
		m_stream.next_in = (BYTE*)inBuff.c_str();

		outBuff = m_outputData;
		m_outputData.clear();

		LOG(DebugInfo3, "zLib Compress: input block size " << inBuff.size() << " with " << outBuff.size() << " bytes already in the output buffer");

		do
		{
			outputLength = (int)outBuff.size();
			outBuff.resize(outputLength + 16384);

			m_stream.avail_out = 16384;
			m_stream.next_out = &outBuff.rawData()[outputLength];

			/*ret =*/ deflate(&m_stream, (action == compAct_Flush || action == compAct_Finish) ? Z_FINISH : Z_NO_FLUSH);
			outBuff.resize(outputLength + 16384 - m_stream.avail_out);
		} while (m_stream.avail_out == 0);
		LOG(DebugInfo3, "Compress: output block size " << outBuff.size());
		return true;
	}
	virtual bool CompressFinal(tscrypto::tsCryptoData &outBuff)
	{
		outBuff = m_outputData;
		m_outputData.clear();

		if (m_compressStarted)
		{
			tscrypto::tsCryptoData data;

			for (;;)
			{
				data.erase();
				data.resize(16384);
				m_stream.avail_in = 0;
				m_stream.next_in = NULL;
				m_stream.avail_out = 16384;
				m_stream.next_out = data.rawData();

				deflate(&m_stream, Z_FINISH);
				if (m_stream.avail_out != 16384)
				{
					data.resize(16384 - m_stream.avail_out);
					outBuff += data;
				}
				else
					break;
			}

			deflateEnd(&m_stream);
		}
		m_compressStarted = false;

		LOG(DebugInfo3, "zLib CompressFinal: output data size " << outBuff.size());
		return true;
	}

	virtual bool DecompressInit()
	{
		if (m_compressStarted || m_decompressStarted)
			return false;

		m_outputData.erase();
		int ret = inflateInit(&m_stream);

		if (ret != Z_OK)
			return false;
		m_decompressStarted = true;
		return true;
	}
	virtual bool Decompress(const tscrypto::tsCryptoData &inBuff, tscrypto::tsCryptoData &outBuff, CompressionAction action)
	{
		int outputLength;
		int ret;

		if (!m_decompressStarted)
			return false;

		m_stream.avail_in = (uInt)inBuff.size();
		m_stream.next_in = (BYTE*)inBuff.c_str();

		outBuff = m_outputData;
		m_outputData.clear();

		LOG(DebugInfo3, "zLib Decompress input block size " << inBuff.size() << " with " << outBuff.size() << " bytes already in the output buffer");
		do
		{
			outputLength = (int)outBuff.size();
			outBuff.resize(outputLength + 16384);

			m_stream.avail_out = 16384;
			m_stream.next_out = &outBuff.rawData()[outputLength];

			ret = inflate(&m_stream, Z_NO_FLUSH);
			switch (ret) {
			case Z_NEED_DICT:
				ret = Z_DATA_ERROR;     /* and fall through */
			case Z_DATA_ERROR:
			case Z_MEM_ERROR:
				if (m_stream.msg != NULL)
				{
					LOG(DebugError, m_stream.msg);
				}
				else
				{
					LOG(DebugError, "Undiagnosed decompression error");
				}
				(void)inflateEnd(&m_stream);
				return false;
			}

			outBuff.resize(outputLength + 16384 - m_stream.avail_out);
		} while (m_stream.avail_out == 0);

		LOG(DebugInfo3, "output buffer size = " << outBuff.size());

		return true;
	}
	virtual bool DecompressFinal(tscrypto::tsCryptoData &outBuff)
	{
		if (!m_decompressStarted)
			inflateEnd(&m_stream);
		m_decompressStarted = false;

		outBuff = m_outputData;
		m_outputData.clear();

		LOG(DebugInfo3, "zLib DecompressFinal: output buffer size = " << outBuff.size());

		return true;
	}

private:
	z_stream	m_stream;
	tscrypto::tsCryptoData	    m_outputData;
	bool        m_decompressStarted;
	bool        m_compressStarted;
};

class HIDDEN NoCompression : public ICompression, public tsmod::IObject
{
public:
	NoCompression(){}
	virtual ~NoCompression(){}

	virtual bool CompressInit(int level)
	{
		MY_UNREFERENCED_PARAMETER(level);
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
