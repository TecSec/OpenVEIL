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

class CkmWinscardReaderImpl : public ICkmWinscardReader, public tsmod::IObject
{
public:
	CkmWinscardReaderImpl(const tscrypto::tsCryptoString& readerName, const tscrypto::tsCryptoData &atr, uint32_t status) :
		m_readerName(readerName),
		m_atr(atr),
		m_status(status)
	{
	}
	virtual ~CkmWinscardReaderImpl(void){}

	virtual tscrypto::tsCryptoString  ReaderName() const
	{
		return m_readerName;
	}
	virtual tscrypto::tsCryptoData   ATR() const
	{
		return m_atr;
	}
	virtual uint32_t Status() const
	{
		return m_status;
	}
	virtual int  EventNumber() const
	{
		return m_status >> 16;
	}
	virtual bool Changed() const
	{
		return (m_status & 0x002) != 0;
	}
	virtual bool StateUnknown() const
	{
		return (m_status & 0x004) != 0;
	}
	virtual bool StateUnavailable() const
	{
		return (m_status & 0x008) != 0;
	}
	virtual bool Empty() const
	{
		return (m_status & 0x010) != 0;
	}
	virtual bool Present() const
	{
		return (m_status & 0x020) != 0;
	}
	virtual bool ATRMatch() const
	{
		return (m_status & 0x040) != 0;
	}
	virtual bool Exclusive() const
	{
		return (m_status & 0x080) != 0;
	}
	virtual bool InUse() const
	{
		return (m_status & 0x100) != 0;
	}
	virtual bool Mute() const
	{
		return (m_status & 0x200) != 0;
	}
	virtual bool Unpowered() const
	{
		return (m_status & 0x400) != 0;
	}

private:
	tscrypto::tsCryptoString m_readerName;
	tscrypto::tsCryptoData   m_atr;
	uint32_t       m_status;
};

std::shared_ptr<ICkmWinscardReader> CreateWinscardReader(const tscrypto::tsCryptoString& readerName, const tscrypto::tsCryptoData &atr, uint32_t status)
{
	return ::TopServiceLocator()->Finish<ICkmWinscardReader>(new CkmWinscardReaderImpl(readerName, atr, status));
}