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
#include "CmsHeaderImpl.h"

static bool Terminate()
{
	std::shared_ptr<tsmod::IServiceLocator> servLoc = ::TopServiceLocator();

	servLoc->DeleteClass("CmsHeader");
	return true;
}

bool CMSHEADER_EXPORT InitializeCmsHeader()
{
	std::shared_ptr<tsmod::IServiceLocator> servLoc = ::TopServiceLocator();

	if (!servLoc->CanCreate("CmsHeader"))
	{
		servLoc->AddClass("CmsHeader", CreateCmsHeaderObject);
		AddSystemTerminationFunction(Terminate);
	}
	return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Extracts a header from the beginning of a data stream.</summary>
///
/// <param name="data">		   The data to process.</param>
/// <param name="dataLength">  Length of the data to process.</param>
/// <param name="headerLength">[out] The length of the header in the data stream.</param>
/// <param name="pVal">		   [out] The new header object.</param>
///
/// <returns>S_OK for success or a standard COM error for failure.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
bool CMSHEADER_EXPORT ExtractHeaderFromStream(const uint8_t *data, int dataLength, int *headerLength, std::shared_ptr<tsmod::IObject>& pVal)
{
	if (!InitializeCmsHeader())
		return false;

	pVal.reset();

	if (!ExtractHeaderLength(data, dataLength, headerLength))
	{
		return false;
	}

	if (*headerLength <= dataLength)
	{
		std::shared_ptr<ICmsHeader> obj2 = ::TopServiceLocator()->get_instance<ICmsHeader>("/CmsHeader");

		tscrypto::tsCryptoData tmp(data, *headerLength);

		if (!obj2->FromBytes(tmp))
		{
			LOG(FrameworkError, "CKMExtractHeaderFromStream: Header::FromBytes failed");
			obj2.reset();
			return false;
		}
		*headerLength = (int)obj2->PaddedHeaderSize();
		pVal = std::dynamic_pointer_cast<tsmod::IObject>(obj2);
		return true;
	}
	return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Extracts a header from the beginning of a data stream.</summary>
///
/// <param name="data">		   The data to process.</param>
/// <param name="dataLength">  Length of the data to process.</param>
/// <param name="headerLength">[out] The length of the header in the data stream.</param>
///
/// <returns>S_OK for success or a standard COM error for failure.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
bool ExtractHeaderLength(const uint8_t *data, int dataLength, int *headerLength)
{
	size_t length = 0;

	if (!InitializeCmsHeader())
		return false;

	if (data == nullptr || headerLength == nullptr)
		return false;
	if (dataLength < 50)
		return false;

	*headerLength = 0;

	if (data[0] == 0x30)
	{
		int tag;
		bool constructed;
        uint8_t type;
		size_t headerLen;

		if ((headerLen = TlvNode::ExtractTagAndLength(tscrypto::tsCryptoData(data, 10), 0, false, false, tag, constructed, type, length)) == 0 ||
			!constructed)
			return false;

		*headerLength = (int)(length + headerLen);
		return true;
	}
	else
		return false;
}
