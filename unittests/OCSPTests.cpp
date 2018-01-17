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

using namespace tscrypto;

TEST(OCSP, request_parse_from_openssl)
{
    PKIX::OCSP::_POD_OCSPRequest req;
    tscrypto::tsCryptoData output;
	static const char *test_data = "30 68 30 66 30 3F 30 3D 30 3B 30 09 06 05 2B 0E 03 02 1A 05 00 04 14 2D 67 82 87 D7 E7 A8 54 E7 43 B2 23 DA 6A C5 34 CA 52 CB 24 04 14 FF 2C 0D ED 17 21 26 EA 62 02 38 97 AC CA 6D 91 86 52 5B 69 02 02 10 00 A2 23 30 21 30 1F 06 09 2B 06 01 05 05 07 30 01 02 04 12 04 10 58 DE DB BC 5C 7D E7 1D 23 0E 83 F9 E1 29 08 2C";

    EXPECT_EQ(true, req.Decode(tscrypto::tsCryptoData(test_data, tscrypto::tsCryptoData::HEX)));
    EXPECT_EQ(true, req.Encode(output));
    EXPECT_EQ(tscrypto::tsCryptoData(test_data, tscrypto::tsCryptoData::HEX), output);
}
