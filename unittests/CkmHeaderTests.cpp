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

#include "gtest/gtest.h"
#include <climits>
#include <sstream>
#include "Asn1CkmHeader.h"
#include "CkmLoader.h"

static const char* TEST_HEADER1 = "30 82 01 E8 06 06 2A 86 48 CE 4C 04 02 01 00 02 01 07 81 10 25 0F 4E 30 E1 CB 84 4E 86 45 D7 0A C4 78 D7 EE 18 0F 32 30 31 34 30 32 31 30 31 38 30 35 30 33 5A 02 01 65 A2 82 01 6E 30 1D 06 09 67 2A 09 0A 03 00 02 02 08 04 10 CA B7 F4 E3 FA BB DB 46 8E 2F F6 84 91 6C A6 C0 30 1E 06 09 67 2A 09 0A 03 00 02 02 0B 04 11 30 0F 06 09 67 2A 09 0A 03 00 07 01 01 02 02 02 00 30 6E 06 09 67 2A 09 0A 03 00 02 02 06 01 01 FF 04 5E 30 5C 30 5A 30 58 04 10 83 CB 7E DC B2 45 12 43 BA 2A A0 10 AA 3B 5B 54 02 01 00 04 41 04 FB E0 B2 A1 FC 9A 9C B8 7A 60 48 9F AB 37 60 19 42 67 BC E5 58 00 9B 1D EF BF 05 73 6D D6 5F FF 03 02 28 83 16 0D D0 EE 09 33 95 13 9F E7 E3 DF 1A A7 40 A4 D3 18 5E 8E BD 78 4E 01 30 57 64 52 30 78 06 09 67 2A 09 0A 03 00 02 02 09 01 01 FF 04 68 30 66 30 64 30 62 04 10 CA B7 F4 E3 FA BB DB 46 8E 2F F6 84 91 6C A6 C0 02 01 00 02 01 00 04 48 30 46 02 21 00 D8 C0 7F 5D 20 D0 48 D2 69 59 71 38 D6 85 84 E5 98 DB C5 8E 46 1F A1 41 AC AE 20 A5 95 94 EC FD 02 21 00 95 4D 3A 22 9C 3A 24 34 24 44 AC E4 5B 6B FC 72 B8 82 46 69 69 96 13 0E DC 2C F2 E3 D4 C9 EB 90 30 43 06 09 67 2A 09 0A 03 00 02 02 07 01 01 FF 04 33 30 31 A3 2F 30 03 02 01 00 04 28 2D E6 C8 B8 E0 AC 04 45 80 AE A9 D1 36 DF 6D 59 9F E2 62 09 E8 E0 83 00 63 BA AB EE DF 1F 1A 71 55 35 EC 8B E4 00 2E BC 84 40 27 FB 97 2C C2 65 2D 87 AD 20 37 1D 72 FF 15 F4 20 F8 0E 4A A0 C6 7E 75 8D 13 EC 37 09 69 B9 0D 30 C3 04 55 EB 8E 6A 2B CE C7 AB EE 87 5A 4A 36 7D 6B 03 7A 87 7D 0A 89 01 AC 5A F6 04 91 09 75";
    //"30 82 01 ec 06 06 2a 86 48 ce 4c 04 02 01 00 02 01 07 81 10 25 0f 4e 30 e1 cb 84 4e 86 45 d7 0a c4 78 d7 ee 18 0f 32 30 31 34 30 32 31 30 31 38 30 35 30 33 5a 02 01 65 a2 82 01 72 30 1d 06 09 67 2a 09 0a 03 00 02 02 08 04 10 ca b7 f4 e3 fa bb db 46 8e 2f f6 84 91 6c a6 c0 30 1e 06 09 67 2a 09 0a 03 00 02 02 0b 04 11 30 0f 06 09 67 2a 09 0a 03 00 07 01 01 02 02 02 00 30 6e 06 09 67 2a 09 0a 03 00 02 02 06 01 01 ff 04 5e 30 5c 30 5a 30 58 04 10 83 cb 7e dc b2 45 12 43 ba 2a a0 10 aa 3b 5b 54 02 01 00 04 41 04 fb e0 b2 a1 fc 9a 9c b8 7a 60 48 9f ab 37 60 19 42 67 bc e5 58 00 9b 1d ef bf 05 73 6d d6 5f ff 03 02 28 83 16 0d d0 ee 09 33 95 13 9f e7 e3 df 1a a7 40 a4 d3 18 5e 8e bd 78 4e 01 30 57 64 52 30 78 06 09 67 2a 09 0a 03 00 02 02 09 01 01 ff 04 68 30 66 30 64 30 62 04 10 ca b7 f4 e3 fa bb db 46 8e 2f f6 84 91 6c a6 c0 02 01 00 02 01 00 04 48 30 46 02 21 00 d8 c0 7f 5d 20 d0 48 d2 69 59 71 38 d6 85 84 e5 98 db c5 8e 46 1f a1 41 ac ae 20 a5 95 94 ec fd 02 21 00 95 4d 3a 22 9c 3a 24 34 24 44 ac e4 5b 6b fc 72 b8 82 46 69 69 96 13 0e dc 2c f2 e3 d4 c9 eb 90 30 47 06 09 67 2a 09 0a 03 00 02 02 07 01 01 ff 04 37 30 35 30 33 a3 31 30 05 a0 03 80 01 00 04 28 2d e6 c8 b8 e0 ac 04 45 80 ae a9 d1 36 df 6d 59 9f e2 62 09 e8 e0 83 00 63 ba ab ee df 1f 1a 71 55 35 ec 8b e4 00 2e bc 84 40 27 fb 97 2c c2 65 2d 87 ad 20 37 1d 72 ff 15 f4 20 f8 0e 4a a0 c6 7e 75 8d 13 ec 37 09 69 b9 0d 30 c3 04 55 eb 8e 6a 2b ce c7 ab ee 87 5a 4a 36 7d 6b 03 7a 87 7d 0a 89 01 ac 5a f6 04 91 09 75";

TEST(CkmHeaderTests, Decode_Encode1_round_trip)
{
    tsCComPtr<ICKM7CmsHeader> header;
    tsCComPtr<ICKMHeaderFactory> factory;
    tsData output;

    if (FAILED(gLoadedCkmFunctions->headerFunctions->GetCKMHeaderFactory(&factory)) ||
        FAILED(factory->CreateCkm7CmsHeader(&header)))
    {
        ADD_FAILURE();
    }
    else
    {
        EXPECT_EQ(true, header->FromBytes(tsData(TEST_HEADER1, tsData::HEX)));
        output = header->ToBytes();
        EXPECT_EQ(tsData(TEST_HEADER1, tsData::HEX), output);
    }
}

