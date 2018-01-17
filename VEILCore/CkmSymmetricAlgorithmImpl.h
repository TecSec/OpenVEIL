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

////////////////////////////////////////////////////////////////////////////////////////////////////
/// \file   CkmSymmetricAlgorithmImpl.h
///
/// \brief  Base class for symmetric algorithms
////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef __CKMSYMMETRICALGORITHMIMPL_H__
#define __CKMSYMMETRICALGORITHMIMPL_H__

#pragma once

class CkmSymmetricAlgorithmImpl : public Symmetric
{
public:
	CkmSymmetricAlgorithmImpl() :
		m_paddingType(pad_None),
		m_mode(CKM_SymMode_Default)
	{}
	virtual SymmetricPadType getPaddingType()
	{
		return m_paddingType;
	}
	virtual void setPaddingType(SymmetricPadType setTo)
	{
		m_paddingType = setTo;
	}
    virtual bool updateAndFinish(const tscrypto::tsCryptoData &in_Data, /* [retval][out] */ tscrypto::tsCryptoData &out_Data)
    {
        if (!gFipsState.operational())
            return false;

		if (!((Symmetric*)this)->update(in_Data, out_Data))
			return false;

		tscrypto::tsCryptoData tmp;
		if (!finish(tmp))
			return false;

		out_Data += tmp;

        return true;
    }

	size_t minimumKeySizeInBits() const
	{
        if (!gFipsState.operational())
            return 0;
        return ((Symmetric*)this)->minimumKeySizeInBits();
	}
	size_t maximumKeySizeInBits() const
	{
        if (!gFipsState.operational())
            return 0;
        return ((Symmetric*)this)->maximumKeySizeInBits();
	}
	size_t keySizeIncrementInBits() const
	{
        if (!gFipsState.operational())
            return 0;
        return ((Symmetric*)this)->keySizeIncrementInBits();
	}

	protected:
		virtual bool NeedsPadding()
		{
			if (getBlockSize() == 1 || m_paddingType == pad_None)
				return false;
			return true;
		}
		virtual bool PadData(tscrypto::tsCryptoData &data)
		{
			size_t blocksize = getBlockSize();
			size_t needed = blocksize - (data.size() % blocksize);

			if (blocksize == 1 || m_paddingType == pad_None)
				return true;

			switch (m_paddingType)
			{
			case pad_Pkcs5:
				data.resize(data.size() + needed, (uint8_t)needed);
				break;
			case pad_GP03:
				data += (uint8_t)0x80;
				needed--;
				if (needed)
					data.resize(data.size() + needed, 0);
				break;
			case pad_Zeros:
				data.resize(data.size() + needed, 0);
				break;
			case pad_FFs:
				data.resize(data.size() + needed, 0xff);
				break;
            case pad_Custom:
                if (!m_paddingInterface)
                    return false;
                return m_paddingInterface->PadData(data, (int)blocksize);
			default:
				return false;
			}
			return true;
		}
		virtual bool UnpadData(tscrypto::tsCryptoData &data)
		{
			size_t blocksize = getBlockSize();
			size_t lastChar = data.size() - 1;

			if (blocksize == 1 || m_paddingType == pad_None)
				return true;

			switch (m_paddingType)
			{
			case pad_Pkcs5:
				{
                uint8_t padLen = data[lastChar];

					if (padLen < 1 || padLen > blocksize || padLen > data.size())
						return false;

					for (size_t i = lastChar - padLen + 1; i <= lastChar; i++)
					{
						if (data[i] != padLen)
							return false;
					}
					data.resize(data.size() - padLen);
				}
				break;
			case pad_GP03:
				while (lastChar >= 0 && data[lastChar] == 0)
					lastChar--;
				if (lastChar < 0 || data[lastChar] != 0x80)
					return false;
				data.resize(lastChar);
				break;
			case pad_Zeros:
				while (lastChar >= 0 && data[lastChar] == 0)
					lastChar--;
				data.resize(lastChar + 1);
				break;
			case pad_FFs:
				while (lastChar >= 0 && data[lastChar] == 0xff)
					lastChar--;
				data.resize(lastChar + 1);
				break;
            case pad_Custom:
                if (!m_paddingInterface)
                    return false;
                return m_paddingInterface->UnpadData(data, (int)blocksize);
			default:
				return false;
			}
			return true;
		}
		virtual bool setCustomPadInterface(std::shared_ptr<ICKMSymmetricPad> setTo)
        {
            m_paddingInterface.reset();
            m_paddingInterface = setTo;
            if (setTo != nullptr)
                m_paddingType = pad_Custom;
            else
                m_paddingType = pad_None;
            return true;
        }
        virtual bool getCustomPadInterface(std::shared_ptr<ICKMSymmetricPad> pVal) const
        {
            if (!m_paddingInterface)
            {
                pVal.reset();
                return false;
            }
			pVal = m_paddingInterface;
            return true;
        }
		virtual SymmetricMode getCurrentMode() const
		{
			return m_mode;
		}

	protected:
		SymmetricMode m_mode;
	private:
		SymmetricPadType m_paddingType;
        std::shared_ptr<ICKMSymmetricPad> m_paddingInterface;
};

#endif // __CKMSYMMETRICALGORITHMIMPL_H__
