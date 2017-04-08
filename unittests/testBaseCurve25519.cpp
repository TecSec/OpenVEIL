#include "stdafx.h"
#if 0
#include "crypto_scalarmult_curve25519.h"
#include "crypto_sign_ed25519.h"

#define DO_GEN_SPEED
#define DO_SIGN_SPEED

using namespace tscrypto;

extern "C"
bool generateARandomKeyValue(unsigned int length, unsigned char *data)
{
	return GenerateRandom(data, length);
}

TEST(curve25519, InitializeRuntime)
{
#if defined(_DEBUG) && defined(_MSC_VER)
	//_CrtSetBreakAlloc(176);
	//_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF); //  _CRTDBG_CHECK_ALWAYS_DF _CRTDBG_CHECK_EVERY_128_DF | _CRTDBG_DELAY_FREE_MEM_DF | |  
	//_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF | _CRTDBG_CHECK_ALWAYS_DF); //   _CRTDBG_CHECK_EVERY_128_DF | _CRTDBG_DELAY_FREE_MEM_DF | |  
#endif
	tsCryptoData hash;

	TSHash(tsCryptoData("73ef115a1dec6d91e1aa51c5e11708ead45b2419fb0313d9565ff39e1928a78f5a662b8c0c91247030f7bc934a5dac9412e99a556d40a6469beb40e7b2ff3c884bfd28537bf7dd8d05f45419cd96bb3e90fac8aad3e04eb6190c0eeb59eccfc5af7ab1b85264be71c66ac25e53085c70b5565620152c32b0388905b3f73689cf", tsCryptoData::HEX), hash, _TS_ALG_ID::TS_ALG_SHA1);
}
TEST(curve25519, InitializeNumber)
{
	tsCryptoData S_a("6A2CB91DA5FB77B12A99C0EB872F4CDF4566B25172C1163C7DA518730A6D0770", tsCryptoData::HEX);
	tsCryptoData P_a_output("85 20 F0 09 89 30 A7 54 74 8B 7D DC B4 3E F7 5A 0D BF 3A 0D 26 38 1A F4 EB A4 A9 8E AA 9B 4E 6A", tsCryptoData::HEX);
	tsCryptoData S_b("6BE088FF278B2F1CFDB6182629B13B6FE60E80838B7FE1794B8A4A627E08AB58", tsCryptoData::HEX);
	tsCryptoData P_b_output("DE 9E DB 7D 7B 7D C1 B4 D3 5B 61 C2 EC E4 35 37 3F 83 43 C8 5B 78 67 4D AD FC 7E 14 6F 88 2B 4F", tsCryptoData::HEX);
	tsCryptoData SS_output("4A 5D 9D 5B A4 CE 2D E1 72 8E 3B F4 80 35 0F 25 E0 7E 21 C9 47 D1 9E 33 76 F0 9B 3C 1E 16 17 42", tsCryptoData::HEX);
	tsCryptoData P_a, P_b, SS;

	SS.resize(S_a.size());
	P_a.resize(S_a.size());
	P_b.resize(S_b.size());

	S_a.reverse();
	S_b.reverse();

	EXPECT_EQ(0, crypto_scalarmult_curve25519_base(P_a.rawData(), S_a.c_str()));
	EXPECT_EQ(P_a_output, P_a);

	EXPECT_EQ(0, crypto_scalarmult_curve25519_base(P_b.rawData(), S_b.c_str()));
	EXPECT_EQ(P_b_output, P_b);

	EXPECT_EQ(0, crypto_scalarmult_curve25519(SS.rawData(), S_b.c_str(), P_a.c_str()));
	EXPECT_EQ(SS_output, SS);

	EXPECT_EQ(0, crypto_scalarmult_curve25519(SS.rawData(), S_a.c_str(), P_b.c_str()));
	EXPECT_EQ(SS_output, SS);
}

TEST(EdDSA25519, ValidatePK)
{
	tsCryptoData sk("b18e1d0045995ec3d010c387ccfeb984d783af8fbb0f40fa7db126d889f6dadd", tsCryptoData::HEX);
	tsCryptoData pk("77f48b59caeda77751ed138b0ec667ff50f8768c25d48309a8f386a2bad187fb", tsCryptoData::HEX);
	tsCryptoData Pk;
	tsCryptoData Sk;

	Pk.clear();
	Pk.resize(32);
	Sk.resize(64);
	EXPECT_EQ(0, generate_ed25519_keypair_from_seed(Pk.rawData(), Sk.rawData(), sk.c_str()));

	EXPECT_EQ(pk, Pk);
}
TEST(EdDSA25519, ValidatePK2)
{
	tsCryptoData sk("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", tsCryptoData::HEX);
	tsCryptoData pk("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", tsCryptoData::HEX);
	tsCryptoData Pk;
	tsCryptoData Sk;

	Pk.clear();
	Pk.resize(32);
	Sk.resize(64);
	EXPECT_EQ(0, generate_ed25519_keypair_from_seed(Pk.rawData(), Sk.rawData(), sk.c_str()));

	EXPECT_EQ(pk, Pk);
}
TEST(EdDSA25519, Sign)
{
	tsCryptoData sk("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", tsCryptoData::HEX);
	tsCryptoData msg("", tsCryptoData::HEX);
	tsCryptoData sig("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", tsCryptoData::HEX);
	tsCryptoData Sig;

	Sig.clear();
	Sig.resize(64);

	EXPECT_EQ(0, crypto_sign_ed25519_detached(Sig.rawData(), msg.c_str(), msg.size(), sk.c_str()));
	EXPECT_EQ(sig, Sig);
}
TEST(EdDSA25519, Verify)
{
	tsCryptoData pk("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", tsCryptoData::HEX);
	tsCryptoData msg("", tsCryptoData::HEX);
	tsCryptoData sig("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b", tsCryptoData::HEX);

	EXPECT_EQ(0, crypto_sign_ed25519_verify_detached(sig.c_str(), msg.c_str(), msg.size(), pk.c_str()));
}
#ifdef DO_GEN_SPEED
TEST(curve25519, Gen_1000) {
	tsCryptoData Sk;
	tsCryptoData Pk;

	for (int i = 0; i < 1000; i++)
	{
		Sk.resize(32);
		GenerateRandom(Sk.rawData(), 32);
		Sk[31] &= 0x7F;
		Sk[31] |= 64;
		Sk[0] &= 248;
		Pk.clear();
		Pk.resize(32);
		EXPECT_EQ(0, crypto_scalarmult_curve25519_base(Pk.rawData(), Sk.c_str()));
	}
}
TEST(ed25519, Gen_1000) {
	tsCryptoData Sk;
	tsCryptoData Pk;

	Sk.resize(64);
	Pk.resize(32);
	for (int i = 0; i < 1000; i++)
	{
		EXPECT_EQ(0, generate_ed25519_keypair(Pk.rawData(), Sk.rawData()));
	}
}
#endif // DO_GEN_SPEED
#ifdef DO_SIGN_SPEED
TEST(curve25519, Sign_1000) {
	tsCryptoData sk("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", tsCryptoData::HEX);
	tsCryptoData msg("af82", tsCryptoData::HEX);
	tsCryptoData sig("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a", tsCryptoData::HEX);
	tsCryptoData Sig;

	for (int i = 0; i < 1000; i++)
	{
		Sig.clear();
		Sig.resize(64);

		EXPECT_EQ(0, crypto_sign_ed25519_detached(Sig.rawData(), msg.c_str(), msg.size(), sk.c_str()));
	}
	EXPECT_EQ(sig, Sig);

}
TEST(curve25519, Verify_1000) {
	tsCryptoData sk("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", tsCryptoData::HEX);
	tsCryptoData msg("af82", tsCryptoData::HEX);
	tsCryptoData sig("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a", tsCryptoData::HEX);

	for (int i = 0; i < 1000; i++)
	{
		EXPECT_EQ(0, crypto_sign_ed25519_verify_detached(sig.rawData(), msg.c_str(), msg.size(), sk.c_str()));
	}
}
#endif // DO_SIGN_SPEED
#endif // 0