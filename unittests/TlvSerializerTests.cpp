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

#include "gtest/gtest.h"
#include <climits>
#include <sstream>

#include "Asn1ParserTest.h"
#include "Asn1ParserTest.inl"
#include "ParserTest2.h"
#include "ParserTest2.inl"

#define TEST_JSON

// {73290AFD-9335-4646-9F96-55CB28190CF7}
static const GUID FiefdomTest = { 0x73290afd, 0x9335, 0x4646, { 0x9f, 0x96, 0x55, 0xcb, 0x28, 0x19, 0xc, 0xf7 } };
// {39537F29-FEFF-4DD3-919C-0868FABBB6A6}
static const GUID AttrTest = { 0x39537f29, 0xfeff, 0x4dd3, { 0x91, 0x9c, 0x8, 0x68, 0xfa, 0xbb, 0xb6, 0xa6 } };
static const char *TestOidInfo = "B938745092384a75092374590237459273459723F571A923475903817459b234759827394572930475092374e597349F57234985";
static const char *TestEphemPub = "04912834792734982749827948720937401704719082374982374982734591309410974398273497230954";
static const char *TestSignature = "3006020100020100";
static const char *TestEncRandom = "54789439783457854378954389745378453879543789453897543789453278548794589789754954";
static const char *VersionedDataTest = "30 81 86 06 0A 67 2A 09 0A 03 00 09 05 10 00 02 01 00 0C 04 70 72 6F 76 0C 04 63 6F 6E 74 0C 03 41 6C 67 02 01 00 04 2B 04 91 28 34 79 27 34 98 27 49 82 79 48 72 09 37 40 17 04 71 90 82 37 49 82 37 49 82 73 45 91 30 94 10 97 43 98 27 34 97 23 09 54 04 34 B9 38 74 50 92 38 4A 75 09 23 74 59 02 37 45 92 73 45 97 23 F5 71 A9 23 47 59 03 81 74 59 B2 34 75 98 27 39 45 72 93 04 75 09 23 74 E5 97 34 9F 57 23 49 85";
static const char *VersionedDataTestEmpty = "30 1E 06 0A 67 2A 09 0A 03 00 09 05 10 00 02 01 00 0C 00 0C 00 0C 00 02 01 00 04 01 00 04 01 00";
static const char *PartTestData = "30 81 FE 02 01 07 02 01 03 04 10 FD 0A 29 73 35 93 46 46 9F 96 55 CB 28 19 0C F7 18 0F 32 30 31 34 30 31 30 31 31 32 33 31 34 39 5A 80 2B 04 91 28 34 79 27 34 98 27 49 82 79 48 72 09 37 40 17 04 71 90 82 37 49 82 37 49 82 73 45 91 30 94 10 97 43 98 27 34 97 23 09 54 01 01 FF 01 01 00 02 02 02 00 04 34 B9 38 74 50 92 38 4A 75 09 23 74 59 02 37 45 92 73 45 97 23 F5 71 A9 23 47 59 03 81 74 59 B2 34 75 98 27 39 45 72 93 04 75 09 23 74 E5 97 34 9F 57 23 49 85 A2 66 30 64 A3 38 30 1F 04 10 29 7F 53 39 FF FE D3 4D 91 9C 08 68 FA BB B6 A6 02 01 59 80 08 30 06 02 01 00 02 01 00 30 15 04 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 01 00 04 28 54 78 94 39 78 34 57 85 43 78 95 43 89 74 53 78 45 38 79 54 37 89 45 38 97 54 37 89 45 32 78 54 87 94 58 97 89 75 49 54";
static const char *TESTPART1 = "A0 81 96 02 01 07 02 01 03 04 10 FD 0A 29 73 35 93 46 46 9F 96 55 CB 28 19 0C F7 18 0F 32 30 31 34 30 31 30 31 31 32 33 31 34 39 5A 80 2B 04 91 28 34 79 27 34 98 27 49 82 79 48 72 09 37 40 17 04 71 90 82 37 49 82 37 49 82 73 45 91 30 94 10 97 43 98 27 34 97 23 09 54 01 01 FF 01 01 00 02 02 02 00 04 34 B9 38 74 50 92 38 4A 75 09 23 74 59 02 37 45 92 73 45 97 23 F5 71 A9 23 47 59 03 81 74 59 B2 34 75 98 27 39 45 72 93 04 75 09 23 74 E5 97 34 9F 57 23 49 85";
static const char *TESTPART2 = "02 01 07 02 01 03 04 10 FD 0A 29 73 35 93 46 46 9F 96 55 CB 28 19 0C F7 18 0F 32 30 31 34 30 31 30 31 31 32 33 31 34 39 5A 80 2B 04 91 28 34 79 27 34 98 27 49 82 79 48 72 09 37 40 17 04 71 90 82 37 49 82 37 49 82 73 45 91 30 94 10 97 43 98 27 34 97 23 09 54 01 01 FF 01 01 00 02 02 02 00 04 34 B9 38 74 50 92 38 4A 75 09 23 74 59 02 37 45 92 73 45 97 23 F5 71 A9 23 47 59 03 81 74 59 B2 34 75 98 27 39 45 72 93 04 75 09 23 74 E5 97 34 9F 57 23 49 85";
static const char *TESTPART3 = "30 81 96 02 01 07 02 01 03 04 10 FD 0A 29 73 35 93 46 46 9F 96 55 CB 28 19 0C F7 18 0F 32 30 31 34 30 31 30 31 31 32 33 31 34 39 5A 80 2B 04 91 28 34 79 27 34 98 27 49 82 79 48 72 09 37 40 17 04 71 90 82 37 49 82 37 49 82 73 45 91 30 94 10 97 43 98 27 34 97 23 09 54 01 01 FF 01 01 00 02 02 02 00 04 34 B9 38 74 50 92 38 4A 75 09 23 74 59 02 37 45 92 73 45 97 23 F5 71 A9 23 47 59 03 81 74 59 B2 34 75 98 27 39 45 72 93 04 75 09 23 74 E5 97 34 9F 57 23 49 85";
static const char *TESTPART4 = "02 01 06";

static void setupMiniHeader(Asn1Test::_POD_TP_MiniHeader& mh)
{
	tscrypto::tsCryptoData oidInfo(TestOidInfo, tscrypto::tsCryptoData::HEX);
	tscrypto::tsCryptoData ephemeralPublic(TestEphemPub, tscrypto::tsCryptoData::HEX);
	tscrypto::tsCryptoData signature(TestSignature, tscrypto::tsCryptoData::HEX);
	tscrypto::tsCryptoData encRandom(TestEncRandom, tscrypto::tsCryptoData::HEX);

	mh.clear();
	mh.set_ckmVersion(7);
	mh.set_creationDate(tscrypto::tsCryptoDate(2014, 01, 01, 12, 31, 49));
	mh.set_fiefdom(FiefdomTest);
	mh.set_keySizeInBits(512);
	mh.set_needsHeaderSignature(false);


	Asn1Test::_POD_TP_AttrGroup group;
	Asn1Test::_POD_TP_Attr attr;
	attr.set_attributeId(AttrTest);
	attr.set_keyVersion(89);
	attr.set_signature(signature);

	group.get_attributes().add(attr);
	group.set_encryptedRandom(encRandom);
	group.get_attributes().add(Asn1Test::_POD_TP_Attr());
	mh.get_attributeGroups().add(group);

	mh.set_oidInfo(oidInfo);
	mh.set_allowAsymetric(true);
	mh.set_currentKgkLevel(3);
	mh.set_EphemeralPublic(ephemeralPublic);
}

static bool checkMiniHeader(const Asn1Test::_POD_TP_MiniHeader& mh)
{
	tscrypto::tsCryptoData oidInfo(TestOidInfo, tscrypto::tsCryptoData::HEX);
	tscrypto::tsCryptoData ephemeralPublic(TestEphemPub, tscrypto::tsCryptoData::HEX);
	tscrypto::tsCryptoData signature(TestSignature, tscrypto::tsCryptoData::HEX);
	tscrypto::tsCryptoData encRandom(TestEncRandom, tscrypto::tsCryptoData::HEX);

	if (mh.get_ckmVersion() != 7 || mh.get_currentKgkLevel() != 3 || mh.get_creationDate().AsZuluTime() != "20140101123149Z" || mh.get_fiefdom() != FiefdomTest ||
		mh.get_keySizeInBits() != 512 || mh.get_needsHeaderSignature() != false || mh.get_oidInfo() != oidInfo || mh.get_allowAsymetric() != true ||
		!mh.exists_EphemeralPublic() || *mh.get_EphemeralPublic() != ephemeralPublic || mh.get_attributeGroups().size() != 1)
	{
		return false;
	}

	const Asn1Test::_POD_TP_AttrGroup& group = mh.get_attributeGroups().get_at(0);
	if (group.get_attributes().size() != 2)
		return false;

	const Asn1Test::_POD_TP_Attr& attr = group.get_attributes().get_at(0);
	if (attr.get_attributeId() != AttrTest || attr.get_keyVersion() != 89 || !attr.exists_signature() || *attr.get_signature() != signature)
		return false;
	const Asn1Test::_POD_TP_Attr& attr2 = group.get_attributes().get_at(1);
	if (attr2.get_attributeId() != GUID_NULL || attr2.get_keyVersion() != 0 || (attr2.exists_signature() && *attr2.get_signature() != tscrypto::tsCryptoData()))
		return false;
	if (group.get_encryptedRandom() != encRandom)
		return false;
	return true;
}

static void setupCMS (Asn1Test::CMS::_POD_ContentInfo& cms)
{
    tscrypto::tsCryptoData oidInfo(TestOidInfo, tscrypto::tsCryptoData::HEX);
    tscrypto::tsCryptoData ephemeralPublic(TestEphemPub, tscrypto::tsCryptoData::HEX);
    tscrypto::tsCryptoData signature(TestSignature, tscrypto::tsCryptoData::HEX);
    tscrypto::tsCryptoData encRandom(TestEncRandom, tscrypto::tsCryptoData::HEX);

    cms.set_OID(id_signedData);
    cms.set_VERSION(1);
	Asn1Test::_POD_AlgorithmIdentifier alg;
    alg.set_oid(tscrypto::tsCryptoData("54", tscrypto::tsCryptoData::HEX));
	cms.get_DigestAlgorithms().add(alg);

	cms.set_EncapContentInfo(Asn1Test::CMS::_POD_EncapsulatedContentInfo());
	cms.get_EncapContentInfo().set_eContentType("1.2.3.4");
	cms.get_EncapContentInfo().set_eContent(tscrypto::tsCryptoData("994455", tscrypto::tsCryptoData::HEX));

	Asn1Test::CMS::_POD_SignerInfo si;
	si.get_signerId().set_selectedItem(Asn1Test::CMS::_POD_SignerInfo_signerId::Choice_certHash);
	cms.get_SignerInfos().add(si);

    // cms.setbase64Certificates("MIIz==");


}

TEST(TlvSerializer, test1_data1)
{
	Asn1Test::_POD_Test1 t1;
	tscrypto::tsCryptoData output;
	//static const char *test_data = "30 79 02 01 04 0C 03 41 42 43 02 01 02 02 02 7E 00 04 02 45 FF 02 01 56 01 01 FF A1 08 06 01 9F 02 03 61 62 63 82 10 01 02 03 04 05 06 07 08 09 0A 0B 0C DD 0E 0F 10 18 0F 32 30 31 34 30 32 31 32 31 36 31 32 33 38 5A 05 00 D4 03 88 77 66 A3 03 02 01 89 A4 04 04 02 75 84 02 01 45 03 03 02 3F 04 A5 07 92 01 00 0C 02 01 02 A6 06 05 00 05 00 05 00 A7 06 80 01 02 02 01 06";
	//static const char *bad_test_data = "30 79 03 01 04 0C 03 41 42 43 02 01 02 02 02 7E 00 04 02 45 FF 02 01 56 01 01 FF A1 08 06 01 9F 02 03 61 62 63 82 10 01 02 03 04 05 06 07 08 09 0A 0B 0C DD 0E 0F 10 18 0F 32 30 31 34 30 32 31 32 31 36 31 32 33 38 5A 05 00 D4 03 88 77 66 A3 03 02 01 89 A4 04 04 02 75 84 02 01 45 03 03 02 3F 04 A5 07 92 01 00 0C 02 01 02 A6 06 05 00 05 00 05 00 A7 06 80 01 02 02 01 06";
	static const char *test_data = "30 71 02 01 04 0C 03 41 42 43 02 01 02 02 02 7E 00 04 02 45 FF 02 01 56 01 01 FF A1 08 06 01 9F 02 03 61 62 63 82 10 01 02 03 04 05 06 07 08 09 0A 0B 0C DD 0E 0F 10 18 0F 32 30 31 34 30 32 31 32 31 36 31 32 33 38 5A 05 00 D4 03 88 77 66 A3 03 02 01 89 A4 04 04 02 75 84 02 01 45 03 03 02 3F 04 A5 07 92 01 00 0C 02 01 02 A7 06 80 01 02 02 01 06";
	static const char *bad_test_data = "30 79 03 01 04 0C 03 41 42 43 02 01 02 02 02 7E 00 04 02 45 FF 02 01 56 01 01 FF A1 08 06 01 9F 02 03 61 62 63 82 10 01 02 03 04 05 06 07 08 09 0A 0B 0C DD 0E 0F 10 18 0F 32 30 31 34 30 32 31 32 31 36 31 32 33 38 5A 05 00 D4 03 88 77 66 A3 03 02 01 89 A4 04 04 02 75 84 02 01 45 03 03 02 3F 04 A5 07 92 01 00 0C 02 01 02 A7 06 80 01 02 02 01 06";
	static const char *basicPartsTestData = "A0 15 02 01 03 02 01 05 02 01 07 04 02 41 42 02 01 23 01 01 FF 05 00";

	EXPECT_EQ(true, t1.Decode(tscrypto::tsCryptoData(test_data, tscrypto::tsCryptoData::HEX)));
	EXPECT_EQ(true, t1.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData(test_data, tscrypto::tsCryptoData::HEX), output);
	EXPECT_EQ(false, t1.Decode(tscrypto::tsCryptoData(bad_test_data, tscrypto::tsCryptoData::HEX)));
	// Now test parts
	EXPECT_EQ(true, t1.Decode_BasicParts(tscrypto::tsCryptoData(basicPartsTestData, tscrypto::tsCryptoData::HEX)));
	EXPECT_EQ(true, t1.Encode_BasicParts(output));
	EXPECT_EQ(tscrypto::tsCryptoData(basicPartsTestData, tscrypto::tsCryptoData::HEX), output);
}
#ifdef TEST_JSON
TEST(TlvSerializer, test1_JSON)
{
	Asn1Test::_POD_Test1 t1;
	tscrypto::tsCryptoData output;
	tscrypto::JSONObject obj;
	//static const char *test_data = "30 79 02 01 04 0C 03 41 42 43 02 01 02 02 02 7E 00 04 02 45 FF 02 01 56 01 01 FF A1 08 06 01 9F 02 03 61 62 63 82 10 01 02 03 04 05 06 07 08 09 0A 0B 0C DD 0E 0F 10 18 0F 32 30 31 34 30 32 31 32 31 36 31 32 33 38 5A 05 00 D4 03 88 77 66 A3 03 02 01 89 A4 04 04 02 75 84 02 01 45 03 03 02 3F 04 A5 07 92 01 00 0C 02 01 02 A6 06 05 00 05 00 05 00 A7 06 80 01 02 02 01 06";
	//static const char *bad_test_data = "30 79 03 01 04 0C 03 41 42 43 02 01 02 02 02 7E 00 04 02 45 FF 02 01 56 01 01 FF A1 08 06 01 9F 02 03 61 62 63 82 10 01 02 03 04 05 06 07 08 09 0A 0B 0C DD 0E 0F 10 18 0F 32 30 31 34 30 32 31 32 31 36 31 32 33 38 5A 05 00 D4 03 88 77 66 A3 03 02 01 89 A4 04 04 02 75 84 02 01 45 03 03 02 3F 04 A5 07 92 01 00 0C 02 01 02 A6 06 05 00 05 00 05 00 A7 06 80 01 02 02 01 06";
	static const char *test_data = "30 71 02 01 04 0C 03 41 42 43 02 01 02 02 02 7E 00 04 02 45 FF 02 01 56 01 01 FF A1 08 06 01 67 02 03 61 62 63 82 10 01 02 03 04 05 06 07 08 09 0A 0B 0C DD 0E 0F 10 18 0F 32 30 31 34 30 32 31 32 31 36 31 32 33 38 5A 05 00 D4 03 88 77 66 A3 03 02 01 89 A4 04 04 02 75 84 02 01 45 03 03 02 3F 04 A5 07 92 01 00 0C 02 01 02 A7 06 80 01 02 02 01 06";
	static const char *basicPartsTestData = "A0 16 02 01 04 02 01 02 02 02 7E 00 04 02 45 FF 02 01 56 01 01 FF 05 00";
	static const char *goodJson = "{\"data1\":4,\"data2\":\"ABC\",\"data3\":2,\"data4\":32256,\"data5\":\"Rf8=\",\"data6\":86,\"data7\":true,\"data8\":{\"oid\":\"2.23\",\"value\":\"YWJj\"},\"data9\":\"{04030201-0605-0807-090A-0B0CDD0E0F10}\",\"data10\":\"2014-02-12T16:12:38+00:00\",\"nullfld\":null,\"data11\":{\"tag\":20,\"type\":3,\"data\":\"iHdm\"},\"data12\":[137],\"data13\":[\"dYQ=\"],\"choice1\":{\"alg\":69},\"data14\":\"Aj8E\",\"data15\":[{\"tag\":18,\"type\":2,\"data\":\"AA==\"},{\"tag\":12,\"type\":0,\"data\":\"AQI=\"}],\"data17\":[{\"data2\":2},{\"data1\":6}]}";
	static const char *goodBasicJson = "{\"data1\":4,\"data3\":2,\"data4\":32256,\"data5\":\"Rf8=\",\"data6\":86,\"data7\":true,\"nullfld\":null}";
	EXPECT_EQ(true, t1.Decode(tscrypto::tsCryptoData(test_data, tscrypto::tsCryptoData::HEX)));
	EXPECT_EQ(true, t1.toJSON(obj));

	EXPECT_EQ(tscrypto::tsCryptoString(goodJson), obj.ToJSON());

	//	EXPECT_EQ(false, t1.Decode(tscrypto::tsCryptoData(bad_test_data, tscrypto::tsCryptoData::HEX)));
		// Now test parts
	obj.clear();
	t1.clear();
	EXPECT_EQ(true, t1.BasicParts_fromJSON(goodBasicJson));
	EXPECT_EQ(true, t1.BasicParts_toJSON(obj));
	EXPECT_EQ(tscrypto::tsCryptoString(goodBasicJson), obj.ToJSON());
	EXPECT_EQ(true, t1.Encode_BasicParts(output));
	EXPECT_EQ(tscrypto::tsCryptoData(basicPartsTestData, tscrypto::tsCryptoData::HEX), output);
}
TEST(TlvSerializer, test1_JSON_roundTrip)
{
	Asn1Test::_POD_Test1 t1;
	tscrypto::tsCryptoData output;
	tscrypto::JSONObject obj;
	//static const char *test_data = "30 79 02 01 04 0C 03 41 42 43 02 01 02 02 02 7E 00 04 02 45 FF 02 01 56 01 01 FF A1 08 06 01 9F 02 03 61 62 63 82 10 01 02 03 04 05 06 07 08 09 0A 0B 0C DD 0E 0F 10 18 0F 32 30 31 34 30 32 31 32 31 36 31 32 33 38 5A 05 00 D4 03 88 77 66 A3 03 02 01 89 A4 04 04 02 75 84 02 01 45 03 03 02 3F 04 A5 07 92 01 00 0C 02 01 02 A6 06 05 00 05 00 05 00 A7 06 80 01 02 02 01 06";
	//static const char *bad_test_data = "30 79 03 01 04 0C 03 41 42 43 02 01 02 02 02 7E 00 04 02 45 FF 02 01 56 01 01 FF A1 08 06 01 9F 02 03 61 62 63 82 10 01 02 03 04 05 06 07 08 09 0A 0B 0C DD 0E 0F 10 18 0F 32 30 31 34 30 32 31 32 31 36 31 32 33 38 5A 05 00 D4 03 88 77 66 A3 03 02 01 89 A4 04 04 02 75 84 02 01 45 03 03 02 3F 04 A5 07 92 01 00 0C 02 01 02 A6 06 05 00 05 00 05 00 A7 06 80 01 02 02 01 06";
	static const char *test_data = "30 71 02 01 04 0C 03 41 42 43 02 01 02 02 02 7E 00 04 02 45 FF 02 01 56 01 01 FF A1 08 06 01 67 02 03 61 62 63 82 10 01 02 03 04 05 06 07 08 09 0A 0B 0C DD 0E 0F 10 18 0F 32 30 31 34 30 32 31 32 31 36 31 32 33 38 5A 05 00 D4 03 88 77 66 A3 03 02 01 89 A4 04 04 02 75 84 02 01 45 03 03 02 3F 04 A5 07 92 01 00 0C 02 01 02 A7 06 80 01 02 02 01 06";
	static const char *goodJson = "{\"data1\":4,\"data2\":\"ABC\",\"data3\":2,\"data4\":32256,\"data5\":\"Rf8=\",\"data6\":86,\"data7\":true,\"data8\":{\"oid\":\"2.23\",\"value\":\"YWJj\"},\"data9\":\"{04030201-0605-0807-090A-0B0CDD0E0F10}\",\"data10\":\"2014-02-12T16:12:38+00:00\",\"nullfld\":null,\"data11\":{\"tag\":20,\"type\":3,\"data\":\"iHdm\"},\"data12\":[137],\"data13\":[\"dYQ=\"],\"choice1\":{\"alg\":69},\"data14\":\"Aj8E\",\"data15\":[{\"tag\":18,\"type\":2,\"data\":\"AA==\"},{\"tag\":12,\"type\":0,\"data\":\"AQI=\"}],\"data17\":[{\"data2\":2},{\"data1\":6}]}";
	EXPECT_EQ(true, t1.Decode(tscrypto::tsCryptoData(test_data, tscrypto::tsCryptoData::HEX)));
	EXPECT_EQ(true, t1.toJSON(obj));

	EXPECT_EQ(tscrypto::tsCryptoString(goodJson), obj.ToJSON());

	t1.clear();
	EXPECT_EQ(true, t1.fromJSON(obj));
	EXPECT_EQ(tscrypto::tsCryptoData(test_data, tscrypto::tsCryptoData::HEX).ToHexStringWithSpaces(), t1.Encode().ToHexStringWithSpaces());
}
#endif // TEST_JSON

TEST(TlvSerializer, test2_data1)
{
	Asn1Test::_POD_Test2 t2;
	tscrypto::tsCryptoData output;
	static const char *test_data = "30 11 06 09 22 02 03 04 05 06 07 08 09 02 04 55 66 77 88";
	static const char *bad_test_data = "30 11 06 09 22 02 03 04 05 06 07 08 09 03 04 55 66 77 88";

	EXPECT_EQ(true, t2.Decode(tscrypto::tsCryptoData(test_data, tscrypto::tsCryptoData::HEX)));
	EXPECT_EQ(true, t2.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData("55 66 77 88", tscrypto::tsCryptoData::HEX), t2.get_value());
	EXPECT_EQ(tscrypto::tsCryptoData(test_data, tscrypto::tsCryptoData::HEX), output);
	EXPECT_EQ(false, t2.Decode(tscrypto::tsCryptoData(bad_test_data, tscrypto::tsCryptoData::HEX)));
}

TEST(TlvSerializer, test2_data2)
{
	Asn1Test::_POD_Test2 t2;
	tscrypto::tsCryptoData output;
	static const char *test_data = "30 12 06 09 22 02 03 04 05 06 07 08 09 02 05 00 88 66 77 88";
	static const char *bad_test_data = "30 12 06 09 22 02 03 04 05 06 07 08 09 04 05 00 88 66 77 88";

	EXPECT_EQ(true, t2.Decode(tscrypto::tsCryptoData(test_data, tscrypto::tsCryptoData::HEX)));
	EXPECT_EQ(true, t2.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData("88 66 77 88", tscrypto::tsCryptoData::HEX), t2.get_value());
	EXPECT_EQ(tscrypto::tsCryptoData(test_data, tscrypto::tsCryptoData::HEX), output);
	EXPECT_EQ(false, t2.Decode(tscrypto::tsCryptoData(bad_test_data, tscrypto::tsCryptoData::HEX)));
}

TEST(TlvSerializer, defaultVersion)
{
	Asn1Test::_POD_testOIDVersion data;

	EXPECT_EQ(1, data.get_VERSION());
	EXPECT_STREQ(Asn1Test::id_test1b_unittest, data.get_OID().ToOIDString().c_str());
	data.set_VERSION(4);
	data.set_OID(tscrypto::TECSEC_AES_128_CBC_OID);
	data.clear();
	EXPECT_EQ(1, data.get_VERSION());
	EXPECT_STREQ(Asn1Test::id_test1b_unittest, data.get_OID().ToOIDString().c_str());
}
TEST(TlvSerializer, testOIDVersion)
{
	Asn1Test::_POD_testOIDVersion data;
	tscrypto::tsCryptoData output;
	static const char* data1 = "30 08 06 03 2A 03 04 02 01 04";
	static const char* data2 = "30 08 06 03 2A 03 05 02 01 03";

	EXPECT_EQ(true, data.Decode_OIDVersion(tscrypto::tsCryptoData(data1, tscrypto::tsCryptoData::HEX)));
	EXPECT_EQ(4, data.get_data1());
	EXPECT_EQ(0, data.get_data2());
	EXPECT_EQ(true, data.Encode_OIDVersion(output));
	EXPECT_EQ(false, data.exists_data2());
	EXPECT_EQ(tscrypto::tsCryptoData(data1, tscrypto::tsCryptoData::HEX), output);
	EXPECT_STREQ(Asn1Test::id_test1_unittest, data.get_OID().ToOIDString().c_str());

	EXPECT_EQ(true, data.Decode_OIDVersion(tscrypto::tsCryptoData(data2, tscrypto::tsCryptoData::HEX)));
	EXPECT_EQ(4, data.get_data1()); // old data now remains (not cleared).  Allows for merging parts.
	EXPECT_EQ(3, data.get_data2());
	EXPECT_EQ(true, data.exists_data2());
	EXPECT_EQ(true, data.Encode_OIDVersion(output));
	EXPECT_EQ(tscrypto::tsCryptoData(data2, tscrypto::tsCryptoData::HEX), output);
	EXPECT_STREQ(Asn1Test::id_test1a_unittest, data.get_OID().ToOIDString().c_str());
}

TEST(TlvSerializer, testNumberVersion)
{
	Asn1Test::_POD_testOIDVersion data;
	tscrypto::tsCryptoData output;
	static const char* data1 = "30 06 02 01 00 02 01 04";
	static const char* data2 = "30 06 02 01 01 02 01 03";

	EXPECT_EQ(true, data.Decode_NumberVersion(tscrypto::tsCryptoData(data1, tscrypto::tsCryptoData::HEX)));
	EXPECT_EQ(4, data.get_data1());
	EXPECT_EQ(0, data.get_data2());
	EXPECT_EQ(false, data.exists_data2());
	EXPECT_EQ(true, data.Encode_NumberVersion(output));
	EXPECT_EQ(tscrypto::tsCryptoData(data1, tscrypto::tsCryptoData::HEX), output);
	EXPECT_STREQ(Asn1Test::id_test1b_unittest, data.get_OID().ToOIDString().c_str());
	EXPECT_EQ(0, data.get_VERSION());

	EXPECT_EQ(true, data.Decode_NumberVersion(tscrypto::tsCryptoData(data2, tscrypto::tsCryptoData::HEX)));
	EXPECT_EQ(4, data.get_data1()); // old data now remains (not cleared).  Allows for merging parts.
	EXPECT_EQ(3, data.get_data2());
	EXPECT_EQ(true, data.exists_data2());
	EXPECT_EQ(true, data.Encode_NumberVersion(output));
	EXPECT_EQ(tscrypto::tsCryptoData(data2, tscrypto::tsCryptoData::HEX), output);
	EXPECT_STREQ(Asn1Test::id_test1b_unittest, data.get_OID().ToOIDString().c_str());
	EXPECT_EQ(1, data.get_VERSION());
}

TEST(TlvSerializer, testBothVersion)
{
	Asn1Test::_POD_testOIDVersion data;
	tscrypto::tsCryptoData output;
	static const char* data1 = "30 0B 06 03 2A 03 06 02 01 00 02 01 04";
	static const char* data2 = "30 0B 06 03 2A 03 06 02 01 01 02 01 03";

	EXPECT_EQ(true, data.Decode(tscrypto::tsCryptoData(data1, tscrypto::tsCryptoData::HEX)));
	EXPECT_EQ(4, data.get_data1());
	EXPECT_EQ(0, data.get_data2());
	EXPECT_EQ(false, data.exists_data2());
	EXPECT_EQ(true, data.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData(data1, tscrypto::tsCryptoData::HEX), output);
	EXPECT_STREQ("1.2.3.6", data.get_OID().ToOIDString().c_str());
	EXPECT_EQ(0, data.get_VERSION());

	EXPECT_EQ(true, data.Decode(tscrypto::tsCryptoData(data2, tscrypto::tsCryptoData::HEX)));
	EXPECT_EQ(4, data.get_data1()); // old data now remains (not cleared).  Allows for merging parts.
	EXPECT_EQ(3, data.get_data2());
	EXPECT_EQ(true, data.exists_data2());
	EXPECT_EQ(true, data.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData(data2, tscrypto::tsCryptoData::HEX), output);
	EXPECT_STREQ("1.2.3.6", data.get_OID().ToOIDString().c_str());
	EXPECT_EQ(1, data.get_VERSION());
}

TEST(TlvSerializer, testDefaultData)
{
	Asn1Test::_POD_testOIDVersion data;
	tscrypto::tsCryptoData output;
	static const char* data1 = "30 06 02 01 00 02 01 2C";
	static const char* data2 = "30 03 02 01 00";

	data.clear();
	data.set_VERSION(0);
	data.set_data1(44);

	EXPECT_EQ(true, data.Encode_NumberVersion(output));
	EXPECT_EQ(tscrypto::tsCryptoData(data1, tscrypto::tsCryptoData::HEX), output);
	data.set_data1(0);
	EXPECT_EQ(true, data.Encode_NumberVersion(output));
	EXPECT_EQ(tscrypto::tsCryptoData(data2, tscrypto::tsCryptoData::HEX), output);
}

TEST(TlvSerializer, tooLittleData)
{
	Asn1Test::_POD_testOIDVersion data;
	tscrypto::tsCryptoData output;
	static const char* data1 = "30 05 06 03 2A 03 04";

	EXPECT_EQ(false, data.Decode(tscrypto::tsCryptoData(data1, tscrypto::tsCryptoData::HEX)));
}

TEST(TlvSerializer, ArrayOfInt)
{
	Asn1Test::_POD_ArrayOfInt ai;
	tscrypto::tsCryptoData output;

	ai.get_attributeIndices().add(1);
	ai.get_attributeIndices().add(3);
	ai.get_attributeIndices().add(7);

	EXPECT_EQ(true, ai.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData("30 0B AC 09 02 01 01 02 01 03 02 01 07", tscrypto::tsCryptoData::HEX), output);

	ai.clear();
	EXPECT_EQ(true, ai.Decode(output));
	EXPECT_EQ(true, ai.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData("30 0B AC 09 02 01 01 02 01 03 02 01 07", tscrypto::tsCryptoData::HEX), output);
}

TEST(TlvSerializer, OptArrayOfInt)
{
	Asn1Test::_POD_OptArrayOfInt ai;
	tscrypto::tsCryptoData output;

	if (!ai.exists_attributeIndices())
		ai.set_attributeIndices();
	ai.get_attributeIndices()->add(1);
	ai.get_attributeIndices()->add(3);
	ai.get_attributeIndices()->add(7);

	EXPECT_EQ(true, ai.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData("30 0B AC 09 45 01 01 45 01 03 45 01 07", tscrypto::tsCryptoData::HEX), output);

	ai.clear();
	EXPECT_EQ(true, ai.Decode(output));
	EXPECT_EQ(true, ai.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData("30 0B AC 09 45 01 01 45 01 03 45 01 07", tscrypto::tsCryptoData::HEX), output);
	ai.clear();
	EXPECT_EQ(false, ai.Decode(tscrypto::tsCryptoData("30 0B AC 09 45 01 01 20 01 03 45 01 07", tscrypto::tsCryptoData::HEX)));
}

TEST(TlvSerializer, OptArrayOfAny)
{
	Asn1Test::_POD_OptArrayOfAny ai;
	tscrypto::tsCryptoData output;

	if (!ai.exists_attributeIndices())
		ai.set_attributeIndices();
	ai.get_attributeIndices()->add(tscrypto::Asn1AnyField(5, tscrypto::TlvNode::Type_Application, tscrypto::tsCryptoData((uint8_t)1)));
	ai.get_attributeIndices()->add(tscrypto::Asn1AnyField(5, tscrypto::TlvNode::Type_Application, tscrypto::tsCryptoData((uint8_t)3)));
	ai.get_attributeIndices()->add(tscrypto::Asn1AnyField(5, tscrypto::TlvNode::Type_Application, tscrypto::tsCryptoData((uint8_t)7)));

	EXPECT_EQ(true, ai.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData("30 0B A1 09 45 01 01 45 01 03 45 01 07", tscrypto::tsCryptoData::HEX), output);

	ai.clear();
	EXPECT_EQ(true, ai.Decode(output));
	EXPECT_EQ(true, ai.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData("30 0B A1 09 45 01 01 45 01 03 45 01 07", tscrypto::tsCryptoData::HEX), output);
	ai.clear();
	EXPECT_EQ(true, ai.Decode(tscrypto::tsCryptoData("30 0B A1 09 45 01 01 02 01 03 45 01 07", tscrypto::tsCryptoData::HEX)));
	EXPECT_EQ(true, ai.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData("30 0B A1 09 45 01 01 02 01 03 45 01 07", tscrypto::tsCryptoData::HEX), output);
}
TEST(TlvSerializer, OptArrayOfBits)
{
	Asn1Test::_POD_OptArrayOfBits ai;
	tscrypto::tsCryptoData output;

	if (!ai.exists_attributeIndices())
		ai.set_attributeIndices();
	ai.get_attributeIndices()->add(tscrypto::Asn1Bitstring(0, tscrypto::tsCryptoData((uint8_t)1)));
	ai.get_attributeIndices()->add(tscrypto::Asn1Bitstring(1, tscrypto::tsCryptoData((uint8_t)3)));
	ai.get_attributeIndices()->add(tscrypto::Asn1Bitstring(2, tscrypto::tsCryptoData((uint8_t)7)));

	EXPECT_EQ(true, ai.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData("30 0E A1 0C 03 02 00 01 03 02 01 03 03 02 02 07", tscrypto::tsCryptoData::HEX), output);

	ai.clear();
	EXPECT_EQ(true, ai.Decode(output));
	EXPECT_EQ(true, ai.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData("30 0E A1 0C 03 02 00 01 03 02 01 03 03 02 02 07", tscrypto::tsCryptoData::HEX), output);
}
TEST(TlvSerializer, OptArrayOfDate)
{
	Asn1Test::_POD_OptArrayOfDate ai;
	tscrypto::tsCryptoData output;

	if (!ai.exists_attributeIndices())
		ai.set_attributeIndices();
	ai.get_attributeIndices()->add(tscrypto::tsCryptoDate("20130101000000Z", tscrypto::tsCryptoDate::Zulu));
	ai.get_attributeIndices()->add(tscrypto::tsCryptoDate("20190101000001Z", tscrypto::tsCryptoDate::Zulu));
	ai.get_attributeIndices()->add(tscrypto::tsCryptoDate("20150101000000Z", tscrypto::tsCryptoDate::Zulu));

	EXPECT_EQ(true, ai.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData("30 35 A1 33 18 0F 32 30 31 33 30 31 30 31 30 30 30 30 30 30 5A 18 0F 32 30 31 39 30 31 30 31 30 30 30 30 30 31 5A 18 0F 32 30 31 35 30 31 30 31 30 30 30 30 30 30 5A", tscrypto::tsCryptoData::HEX), output);

	ai.clear();
	EXPECT_EQ(true, ai.Decode(output));
	EXPECT_EQ(true, ai.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData("30 35 A1 33 18 0F 32 30 31 33 30 31 30 31 30 30 30 30 30 30 5A 18 0F 32 30 31 39 30 31 30 31 30 30 30 30 30 31 5A 18 0F 32 30 31 35 30 31 30 31 30 30 30 30 30 30 5A", tscrypto::tsCryptoData::HEX), output);
}
TEST(TlvSerializer, OptArrayOfGuid)
{
	Asn1Test::_POD_OptArrayOfGuid ai;
	tscrypto::tsCryptoData output;

	if (!ai.exists_attributeIndices())
		ai.set_attributeIndices();
	ai.get_attributeIndices()->add(GUID_NULL);
	ai.get_attributeIndices()->add(IID_IUnknown);

	EXPECT_EQ(true, ai.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData("30 26 A1 24 04 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04 10 00 00 00 00 00 00 00 00 C0 00 00 00 00 00 00 46", tscrypto::tsCryptoData::HEX), output);

	ai.clear();
	EXPECT_EQ(true, ai.Decode(output));
	EXPECT_EQ(true, ai.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData("30 26 A1 24 04 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04 10 00 00 00 00 00 00 00 00 C0 00 00 00 00 00 00 46", tscrypto::tsCryptoData::HEX), output);
}
TEST(TlvSerializer, OptArrayOfOctets)
{
	Asn1Test::_POD_OptArrayOfOctets ai;
	tscrypto::tsCryptoData output;

	if (!ai.exists_attributeIndices())
		ai.set_attributeIndices();
	ai.get_attributeIndices()->add(tscrypto::tsCryptoData("010203", tscrypto::tsCryptoData::HEX));
	ai.get_attributeIndices()->add(tscrypto::tsCryptoData("030201", tscrypto::tsCryptoData::HEX));
	ai.get_attributeIndices()->add(tscrypto::tsCryptoData("9988776655", tscrypto::tsCryptoData::HEX));

	EXPECT_EQ(true, ai.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData("30 13 A1 11 04 03 01 02 03 04 03 03 02 01 04 05 99 88 77 66 55", tscrypto::tsCryptoData::HEX), output);

	ai.clear();
	EXPECT_EQ(true, ai.Decode(output));
	EXPECT_EQ(true, ai.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData("30 13 A1 11 04 03 01 02 03 04 03 03 02 01 04 05 99 88 77 66 55", tscrypto::tsCryptoData::HEX), output);
}
TEST(TlvSerializer, OptArrayOfOID)
{
	Asn1Test::_POD_OptArrayOfOID ai;
	tscrypto::tsCryptoData output;

	if (!ai.exists_attributeIndices())
		ai.set_attributeIndices();
	ai.get_attributeIndices()->add(tscrypto::tsCryptoData(Asn1Test::id_test1_unittest,  tscrypto::tsCryptoData::OID));
	ai.get_attributeIndices()->add(tscrypto::tsCryptoData(Asn1Test::id_test1a_unittest, tscrypto::tsCryptoData::OID));
	ai.get_attributeIndices()->add(tscrypto::tsCryptoData(Asn1Test::id_test1b_unittest, tscrypto::tsCryptoData::OID));

	EXPECT_EQ(true, ai.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData("30 11 A1 0F 06 03 2A 03 04 06 03 2A 03 05 06 03 2A 03 06", tscrypto::tsCryptoData::HEX), output);

	ai.clear();
	EXPECT_EQ(true, ai.Decode(output));
	EXPECT_EQ(true, ai.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData("30 11 A1 0F 06 03 2A 03 04 06 03 2A 03 05 06 03 2A 03 06", tscrypto::tsCryptoData::HEX), output);
}
TEST(TlvSerializer, OptArrayOfStruct)
{
	Asn1Test::_POD_OptArrayOfStruct ai;
	Asn1Test::_POD_TP_Attr attr;
	tscrypto::tsCryptoData output;

	attr.set_attributeId(IID_IUnknown);
	attr.set_keyVersion(54);
	attr.set_signature(tscrypto::tsCryptoData("84932014958", tscrypto::tsCryptoData::HEX));

	if (!ai.exists_attributeIndices())
		ai.set_attributeIndices();
	ai.get_attributeIndices()->add(Asn1Test::_POD_TP_Attr());
	ai.get_attributeIndices()->add(attr);

	EXPECT_EQ(true, ai.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData("30 38 a1 36 30 15 04 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 01 00 30 1d 04 10 00 00 00 00 00 00 00 00 c0 00 00 00 00 00 00 46 02 01 36 80 06 08 49 32 01 49 58", tscrypto::tsCryptoData::HEX), output);

	ai.clear();
	EXPECT_EQ(true, ai.Decode(output));
	EXPECT_EQ(true, ai.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData("30 38 a1 36 30 15 04 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 01 00 30 1d 04 10 00 00 00 00 00 00 00 00 c0 00 00 00 00 00 00 46 02 01 36 80 06 08 49 32 01 49 58", tscrypto::tsCryptoData::HEX), output);
}
TEST(TlvSerializer, OptStruct)
{
	Asn1Test::_POD_OptStruct ai;
	Asn1Test::_POD_TP_Attr attr;
	tscrypto::tsCryptoData output;

	attr.set_attributeId(IID_IUnknown);
	attr.set_keyVersion(54);
	attr.set_signature(tscrypto::tsCryptoData("84932014958", tscrypto::tsCryptoData::HEX));

	EXPECT_EQ(true, ai.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData("10 00", tscrypto::tsCryptoData::HEX), output);

	ai.clear();
	ai.set_index(attr);
	EXPECT_EQ(true, ai.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData("30 1F 30 1D 04 10 00 00 00 00 00 00 00 00 C0 00 00 00 00 00 00 46 02 01 36 80 06 08 49 32 01 49 58", tscrypto::tsCryptoData::HEX), output);

	ai.clear();
	EXPECT_EQ(true, ai.Decode(output));
	EXPECT_EQ(true, ai.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData("30 1F 30 1D 04 10 00 00 00 00 00 00 00 00 C0 00 00 00 00 00 00 46 02 01 36 80 06 08 49 32 01 49 58", tscrypto::tsCryptoData::HEX), output);
}

// TEST(TlvSerializer, ChoiceWithSequence)
// {
//     Asn1Test::CMS::_POD_ChoiceWithSequence cs;
//     tscrypto::tsCryptoData output;
//
//     cs.get_testMe().set_selectedItem(Asn1Test::CMS::_POD_ChoiceWithSequence_testMe::Choice_Algorithm);
//     cs.get_testMe().get_Algorithm().set_oid(szOID_INFOSEC_mosaicIntegrity);
//
//     EXPECT_EQ(true, cs.Encode(output));
//     EXPECT_EQ(tscrypto::tsCryptoData("30 0F 63 0D 06 09 60 86 48 01 65 02 01 01 06 00 00", tscrypto::tsCryptoData::HEX), output);
//
//     cs.clear();
//     EXPECT_EQ(true, cs.Decode(tscrypto::tsCryptoData("30 0F 63 0D 06 09 60 86 48 01 65 02 01 01 06 00 00", tscrypto::tsCryptoData::HEX)));
//     EXPECT_EQ(true, cs.Encode(output));
//     EXPECT_EQ(tscrypto::tsCryptoData("30 0F 63 0D 06 09 60 86 48 01 65 02 01 01 06 00 00", tscrypto::tsCryptoData::HEX), output);
// }


TEST(TlvSerializer, RogerOrignalTest)
{
	Asn1Test::_POD_TP_MiniHeader mh;
	tscrypto::tsCryptoData output;

	setupMiniHeader(mh);

	EXPECT_EQ(true, mh.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData(PartTestData, tscrypto::tsCryptoData::HEX), output);

	mh.clear();
	//EXPECT_EQ(mh.Decode(output), true);
	//EXPECT_EQ(true, checkMiniHeader(mh));
	EXPECT_EQ(true, mh.Decode(tscrypto::tsCryptoData(PartTestData, tscrypto::tsCryptoData::HEX)));
	EXPECT_EQ(true, checkMiniHeader(mh));
}

TEST(TlvSerializer, EncodePartWithTags)
{
	Asn1Test::_POD_TP_MiniHeader mh;
	tscrypto::tsCryptoData output;

	EXPECT_EQ(true, mh.Decode(tscrypto::tsCryptoData(PartTestData, tscrypto::tsCryptoData::HEX)));
	EXPECT_EQ(true, checkMiniHeader(mh));

	EXPECT_EQ(true, mh.Encode_TestPart(output));
	EXPECT_EQ(tscrypto::tsCryptoData(TESTPART1, tscrypto::tsCryptoData::HEX), output);
}

TEST(TlvSerializer, DecodePartWithTags)
{
	Asn1Test::_POD_TP_MiniHeader mh;
	tscrypto::tsCryptoData output;

	EXPECT_EQ(true, mh.Decode_TestPart(tscrypto::tsCryptoData(TESTPART1, tscrypto::tsCryptoData::HEX)));
	EXPECT_EQ(true, mh.Encode_TestPart(output));
	EXPECT_EQ(tscrypto::tsCryptoData(TESTPART1, tscrypto::tsCryptoData::HEX), output);
}

TEST(TlvSerializer, DecodePartWithWrongTags)
{
	Asn1Test::_POD_TP_MiniHeader mh;

	EXPECT_EQ(false, mh.Decode_TestPart(tscrypto::tsCryptoData(TESTPART3, tscrypto::tsCryptoData::HEX)));
}

TEST(TlvSerializer, EncodePartWithoutWrapper)
{
	Asn1Test::_POD_TP_MiniHeader mh;
	tscrypto::tsCryptoData output;

	EXPECT_EQ(true, mh.Decode(tscrypto::tsCryptoData(PartTestData, tscrypto::tsCryptoData::HEX)));
	EXPECT_EQ(true, checkMiniHeader(mh));

	EXPECT_EQ(true, mh.Encode_TestPart2(output, true));
	EXPECT_EQ(tscrypto::tsCryptoData(TESTPART2, tscrypto::tsCryptoData::HEX), output);
}

TEST(TlvSerializer, DecodePartWithoutWrapper)
{
	Asn1Test::_POD_TP_MiniHeader mh;
	tscrypto::tsCryptoData output;

	EXPECT_EQ(true, mh.Decode_TestPart2(tscrypto::tsCryptoData(TESTPART2, tscrypto::tsCryptoData::HEX), true));
	EXPECT_EQ(true, mh.Encode_TestPart2(output, true));
	EXPECT_EQ(tscrypto::tsCryptoData(TESTPART2, tscrypto::tsCryptoData::HEX), output);
}

TEST(TlvSerializer, EncodePartWithoutTags)
{
	Asn1Test::_POD_TP_MiniHeader mh;
	tscrypto::tsCryptoData output;

	EXPECT_EQ(true, mh.Decode(tscrypto::tsCryptoData(PartTestData, tscrypto::tsCryptoData::HEX)));
	EXPECT_EQ(true, checkMiniHeader(mh));

	EXPECT_EQ(true, mh.Encode_TestPart3(output));
	EXPECT_EQ(tscrypto::tsCryptoData(TESTPART3, tscrypto::tsCryptoData::HEX), output);
}

TEST(TlvSerializer, DecodePartWithoutTags)
{
	Asn1Test::_POD_TP_MiniHeader mh;
	tscrypto::tsCryptoData output;

	EXPECT_EQ(true, mh.Decode_TestPart3(tscrypto::tsCryptoData(TESTPART3, tscrypto::tsCryptoData::HEX)));
	EXPECT_EQ(true, mh.Encode_TestPart3(output));
	EXPECT_EQ(tscrypto::tsCryptoData(TESTPART3, tscrypto::tsCryptoData::HEX), output);
}

TEST(TlvSerializer, EncodeSingleFieldPartWithoutTags)
{
	Asn1Test::_POD_TP_MiniHeader mh;
	tscrypto::tsCryptoData output;

	EXPECT_EQ(true, mh.Decode(tscrypto::tsCryptoData(PartTestData, tscrypto::tsCryptoData::HEX)));
	EXPECT_EQ(true, checkMiniHeader(mh));

	mh.set_ckmVersion(6);
	EXPECT_EQ(true, mh.Encode_TestPart4(output, true));
	EXPECT_EQ(tscrypto::tsCryptoData(TESTPART4, tscrypto::tsCryptoData::HEX), output);
}

TEST(TlvSerializer, DecodeSingleFieldPartWithoutTags)
{
	Asn1Test::_POD_TP_MiniHeader mh;
	tscrypto::tsCryptoData output;

	EXPECT_EQ(true, mh.Decode_TestPart4(tscrypto::tsCryptoData(TESTPART4, tscrypto::tsCryptoData::HEX), true));
	EXPECT_EQ(true, mh.Encode_TestPart4(output, true));
	EXPECT_EQ(tscrypto::tsCryptoData(TESTPART4, tscrypto::tsCryptoData::HEX), output);
}

TEST(TlvSerializer, RogerLargerOrignalTest)
{
    Asn1Test::CMS::_POD_ContentInfo cms;
    tscrypto::tsCryptoData output;

    setupCMS(cms);

    EXPECT_EQ(true, cms.Encode(output));
    EXPECT_EQ(tscrypto::tsCryptoData("30 42 06 09 2a 86 48 86 f7 0d 01 07 02 02 01 01 31 07 30 05 06 01 54 00 00 30 0a 06 03 2a 03 04 80 03 99 44 55 31 1d 30 1b 02 01 00 a1 08 30 04 06 00 00 00 04 00 30 04 06 00 00 00 30 04 06 00 00 00 04 00", tscrypto::tsCryptoData::HEX), output);
}
TEST(TlvSerializer, VersionedData)
{
	Asn1Test::_POD_MasterKeyBlob mkb;
	tscrypto::tsCryptoData output;

	mkb.set_OID(testTECSEC_DATA_KEY_STORAGE_MASTER);
	mkb.set_VERSION(0);
	mkb.set_AlgorithmName("Alg");
	mkb.set_ContainerName("cont");
	mkb.set_EDEK(tscrypto::tsCryptoData(TestOidInfo, tscrypto::tsCryptoData::HEX));
	mkb.set_KeySpec(0);
	mkb.set_ProviderName("prov");
	mkb.set_PublicKey(tscrypto::tsCryptoData(TestEphemPub, tscrypto::tsCryptoData::HEX));

	EXPECT_EQ(true, mkb.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData(VersionedDataTest, tscrypto::tsCryptoData::HEX), output);

	mkb.clear();
	output.clear();
	mkb.set_PublicKey(tscrypto::tsCryptoData("00", tscrypto::tsCryptoData::HEX));
	mkb.set_EDEK(tscrypto::tsCryptoData("00", tscrypto::tsCryptoData::HEX));
	EXPECT_EQ(true, mkb.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData(VersionedDataTestEmpty, tscrypto::tsCryptoData::HEX), output);

	output.clear();
	EXPECT_EQ(true, mkb.Decode(tscrypto::tsCryptoData(VersionedDataTest, tscrypto::tsCryptoData::HEX)));
	EXPECT_EQ(true, mkb.Encode(output));
	EXPECT_EQ(tscrypto::tsCryptoData(VersionedDataTest, tscrypto::tsCryptoData::HEX), output);
}

TEST(TlvSerializer, AnyFieldWithsequence)
{
	Asn1Test::_POD_AlgorithmIdentifier algField;
	Asn1Test::_POD_AEAD_Parameters params;
	tscrypto::Asn1AnyField any;
	tscrypto::tsCryptoData value;

	algField.set_oid("1.1.2.3.4.5");
	params.set_iv(tscrypto::tsCryptoData("112233445566", tscrypto::tsCryptoData::HEX));
	params.set_tagLength(tscrypto::tsCryptoData((uint8_t)16));

	any.tag = tscrypto::TlvNode::Tlv_Sequence;
	any.value = params.Encode(true);
	algField.set_Parameter(any);

	EXPECT_TRUE(algField.Encode(value));
	EXPECT_EQ(tscrypto::tsCryptoData("30 14 06 05 29 02 03 04 05 30 0b 04 06 11 22 33 44 55 66 02 01 10", tscrypto::tsCryptoData::HEX), value);
}

TEST(TlvSerializer, generateCert)
{
	std::shared_ptr<tscrypto::ICertificateIssuer> issuer;
	std::shared_ptr<tscrypto::EccKey> localhostKey;
	tscrypto::tsCryptoData localhostCert;

	issuer = tscrypto::CryptoLocator()->get_instance<tscrypto::ICertificateIssuer>("/CERTIFICATEISSUER");
	EXPECT_TRUE(!!issuer);
	issuer->setIssuerInformation("C=US,ST=Virginia,L=Centreville,O=Test,CN=localhost");
	ASSERT_TRUE(tscrypto::TSGenerateECCKeysByAlg(tscrypto::_TS_ALG_ID::TS_ALG_ECC_P384, localhostKey));

	issuer->NewCA(localhostKey, tscrypto::_TS_ALG_ID::TS_ALG_SHA512);
	tscrypto::CA_Crypto_Info crypto = issuer->getCryptoInformation();
	localhostCert = crypto.rootCert;
	EXPECT_NE(0, localhostCert.size());
}