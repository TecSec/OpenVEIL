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
#include <sstream>

using namespace tscrypto;

#pragma warning(push)
#pragma warning(disable: 6326)

TEST(tsCryptoString, streaming101)
{
	tsCryptoString tmp;

	tmp << 0;
	EXPECT_STREQ("0", tmp.c_str());
#ifdef _MSC_VER
	tmp << 0L;
	EXPECT_STREQ("00", tmp.c_str());
#endif
	tmp << (int8_t)100;
	EXPECT_STREQ("00100", tmp.c_str());
	tmp << (int16_t)89;
	EXPECT_STREQ("0010089", tmp.c_str());
	tmp << (int32_t)234;
	EXPECT_STREQ("0010089234", tmp.c_str());
	tmp << (int64_t)34298;
	EXPECT_STREQ("001008923434298", tmp.c_str());
	tmp << "ddd";
	EXPECT_STREQ("001008923434298ddd", tmp.c_str());
	tmp << 'i';
	EXPECT_STREQ("001008923434298dddi", tmp.c_str());
	tmp << (uint8_t)255;
	EXPECT_STREQ("001008923434298dddi255", tmp.c_str());
	tmp << (uint16_t)-1;
	EXPECT_STREQ("001008923434298dddi25565535", tmp.c_str());
	tmp << (uint32_t)34;
	EXPECT_STREQ("001008923434298dddi2556553534", tmp.c_str());
	tmp << (uint64_t)8;
	EXPECT_STREQ("001008923434298dddi25565535348", tmp.c_str());
	tmp << cr;
	EXPECT_STREQ("001008923434298dddi25565535348\r", tmp.c_str());
	tmp << crlf;
	EXPECT_STREQ("001008923434298dddi25565535348\r\r\n", tmp.c_str());
	tmp << tscrypto::endl;
	EXPECT_STREQ("001008923434298dddi25565535348\r\r\n\n", tmp.c_str());
	tmp << tab;
	EXPECT_STREQ("001008923434298dddi25565535348\r\r\n\n\t", tmp.c_str());
	EXPECT_EQ(35, tmp.size());
	tmp << nullchar;
	EXPECT_EQ(36, tmp.size());

	tmp = (tsCryptoString().append("") << "0010089234" << (int64_t)34298 << "ddd" << 'i' << (uint8_t)255);
	EXPECT_STREQ("001008923434298dddi255", tmp.c_str());

}


TEST(tsCryptoString, RogerOrignalTest)
{
	tsCryptoString tmp;
	tmp = "Test";
	EXPECT_EQ(tmp, "Test");
#ifdef _MSC_VER
	tmp.append(0L);
	EXPECT_EQ(tmp, "Test0");
#endif
	tmp.clear();
}

TEST(tsCryptoString, Constructors)
{

	// tsCryptoString()
	{
		tsCryptoString tmp;
		ASSERT_EQ(0, tmp.size());
		ASSERT_STREQ("", tmp.c_str());
	}

	// tsCryptoString(tsCryptoString &&obj);
	{
		const char *data = "test";
		tsCryptoString tmp(data);
		ASSERT_EQ(4, tmp.size());
		tsCryptoString tmp2(std::move(tmp));
		ASSERT_EQ(0, tmp.size());
		ASSERT_EQ(4, tmp2.size());
		ASSERT_STREQ("", tmp.c_str());
		ASSERT_STREQ("test", tmp2.c_str());
	}

	{
		const char *data = "012345678901234567890123456789012345678901234567891"; // length = 51
		tsCryptoString tmp(data);
		ASSERT_EQ(51, tmp.size());
		tsCryptoString tmp2(std::move(tmp));
		ASSERT_EQ(0, tmp.size());
		ASSERT_EQ(51, tmp2.size());
		ASSERT_STREQ("", tmp.c_str());
		ASSERT_STREQ("012345678901234567890123456789012345678901234567891", tmp2.c_str());
	}

	// tsCryptoString(const_pointer data, size_type len);
	{
		const char *data = "test123";
		tsCryptoString tmp(data, 7);
		ASSERT_EQ(7, tmp.size());
		ASSERT_STREQ("test123", tmp.c_str());
	}
	{
		const char *data = "test123";
		tsCryptoString tmp(data, 0);
		ASSERT_EQ(0, tmp.size());
		ASSERT_STREQ("", tmp.c_str());
	}
	{
		const char *data = "test123";
		tsCryptoString tmp(data, 5);
		ASSERT_EQ(5, tmp.size());
		ASSERT_STREQ("test1", tmp.c_str());
	}
	{
		const char *data = "test" "\0" "123";
		tsCryptoString tmp(data, 8);
		ASSERT_EQ(8, tmp.size());
		ASSERT_EQ(0, memcmp("test" "\0" "123", tmp.rawData(), 8));
	}
	{
		const char *data = "test" "\0" "123";
		tsCryptoString tmp(data, 6);
		ASSERT_EQ(6, tmp.size());
		ASSERT_EQ(0, memcmp("test" "\0" "1", tmp.rawData(), 6));
	}
	{
		const char *data = "0123456789012345678901234567890123456789012345678"; //length = 49
		tsCryptoString tmp(data, 49);
		ASSERT_EQ(49, tmp.size());
		ASSERT_STREQ("0123456789012345678901234567890123456789012345678", tmp.c_str()); //this should be from m_default_data
	}
	{
		const char *data = "01234567890123456789012345678901234567890123456789"; //length = 50
		tsCryptoString tmp(data, 50);
		ASSERT_EQ(50, tmp.size());
		ASSERT_STREQ("01234567890123456789012345678901234567890123456789", tmp.c_str()); //this should be from m_data
	}
	{
		const char *data = "012345678901234567890123456789012345678901234567891"; //length = 51
		tsCryptoString tmp(data, 51);
		ASSERT_EQ(51, tmp.size());
		ASSERT_STREQ("012345678901234567890123456789012345678901234567891", tmp.c_str()); //this should be from m_data
	}

	// tsCryptoString(const tsCryptoString &obj);
	{
		const char *data = "test";
		tsCryptoString tmp(data);
		tsCryptoString tmp2(tmp);
		ASSERT_EQ(4, tmp.size());
		ASSERT_EQ(4, tmp2.size());
		ASSERT_STREQ("test", tmp.c_str());
		ASSERT_STREQ("test", tmp2.c_str());
	}
	{
		const char *data = "012345678901234567890123456789012345678901234567891"; //length = 51
		tsCryptoString tmp(data);
		tsCryptoString tmp2(tmp);
		ASSERT_EQ(51, tmp.size());
		ASSERT_EQ(51, tmp2.size());
		ASSERT_STREQ("012345678901234567890123456789012345678901234567891", tmp.c_str());
		ASSERT_STREQ("012345678901234567890123456789012345678901234567891", tmp2.c_str());
	}
	{
		const char *data = "test" "\0" "123";
		tsCryptoString tmp(data);
		tsCryptoString tmp2(tmp);
		ASSERT_EQ(4, tmp.size());
		ASSERT_EQ(4, tmp2.size());
		ASSERT_STREQ("test", tmp.c_str());
		ASSERT_STREQ("test", tmp2.c_str());
	}

	// tsCryptoString(const_pointer data);
	{
		tsCryptoString tmp("test123");
		ASSERT_EQ(7, tmp.size());
		ASSERT_STREQ("test123", tmp.c_str());
	}
	{
		tsCryptoString tmp("");
		ASSERT_EQ(0, tmp.size());
		ASSERT_STREQ("", tmp.c_str());
	}
	{
		tsCryptoString tmp("test" "\0" "123"); //this constructor will terminate at the '\0'
		ASSERT_EQ(4, tmp.size());
		ASSERT_EQ(0, memcmp("test", tmp.rawData(), 4));
	}
	{
		const char *data = "0123456789012345678901234567890123456789012345678"; //length = 49
		tsCryptoString tmp(data);
		ASSERT_EQ(49, tmp.size());
		ASSERT_STREQ("0123456789012345678901234567890123456789012345678", tmp.c_str()); //this should be from m_default_data
	}
	{
		const char *data = "01234567890123456789012345678901234567890123456789"; //length = 50
		tsCryptoString tmp(data);
		ASSERT_EQ(50, tmp.size());
		ASSERT_STREQ("01234567890123456789012345678901234567890123456789", tmp.c_str()); //this should be from m_data
	}
	{
		const char *data = "012345678901234567890123456789012345678901234567891"; //length = 51
		tsCryptoString tmp(data);
		ASSERT_EQ(51, tmp.size());
		ASSERT_STREQ("012345678901234567890123456789012345678901234567891", tmp.c_str()); //this should be from m_data
	}

	//tsCryptoString::tsCryptoString(long value)
	//{
	//    long l = 0;
	//    tsCryptoString tmp(l);
	//    std::ostringstream oss;
	//    oss << l;
	//    std::string str = oss.str();
	//    const char *p = str.c_str();
	//    ASSERT_STREQ(p, tmp.c_str());
	//}
	//{
	//    long l = LONG_MAX;
	//    tsCryptoString tmp(l);
	//    std::ostringstream oss;
	//    oss << l;
	//    std::string str = oss.str();
	//    const char *p = str.c_str();
	//    ASSERT_STREQ(p, tmp.c_str());
	//}
	//{
	//    long l = LONG_MIN;
	//    tsCryptoString tmp(l);
	//    std::ostringstream oss;
	//    oss << l;
	//    std::string str = oss.str();
	//    const char *p = str.c_str();
	//    ASSERT_STREQ(p, tmp.c_str());
	//}

	// tsCryptoString(value_type data, size_type numChars);
	{
		char data = 't';
		tsCryptoString tmp(data, 1);
		ASSERT_EQ(1, tmp.size());
		ASSERT_STREQ("t", tmp.c_str());
	}
	{
		char data = 't';
		tsCryptoString tmp(data, 0);
		ASSERT_EQ(0, tmp.size());
		ASSERT_STREQ("", tmp.c_str());
	}
	{
		char data = 't';
		tsCryptoString tmp(data, 5);
		ASSERT_EQ(5, tmp.size());
		ASSERT_STREQ("ttttt", tmp.c_str());
	}
	{
		char data = '\0';
		tsCryptoString tmp(data, 5);
		ASSERT_EQ(5, tmp.size());
		ASSERT_STREQ("", tmp.c_str());
	}
	{
		char data = 't';
		tsCryptoString tmp(data, 49); //length = 49
		ASSERT_EQ(49, tmp.size());
		ASSERT_STREQ("ttttttttttttttttttttttttttttttttttttttttttttttttt", tmp.c_str()); //this should be from m_default_data
	}
	{
		char data = 't';
		tsCryptoString tmp(data, 50); //length = 50
		ASSERT_EQ(50, tmp.size());
		ASSERT_STREQ("tttttttttttttttttttttttttttttttttttttttttttttttttt", tmp.c_str()); //this should be from m_default_data
	}
	{
		char data = 't';
		tsCryptoString tmp(data, 51); //length = 51
		ASSERT_EQ(51, tmp.size());
		ASSERT_STREQ("ttttttttttttttttttttttttttttttttttttttttttttttttttt", tmp.c_str()); //this should be from m_data
	}

	// tsCryptoString(std::initializer_list<value_type> init);
	{
		tsCryptoString tmp1( "asdf" );
		tsCryptoString tmp2({ 'a', 's', 'd', 'f' });

		EXPECT_EQ(tmp1, tmp2);
		EXPECT_EQ("asdf", tmp2);
		EXPECT_EQ('s', tmp2[1]);
	}

	// tsCryptoString(InputIt first, InputIt last);
	{
		tsCryptoString tmp1("This is the time for all good men to come to the aid of their country!");
		auto first = tmp1.begin();
		auto last = tmp1.begin();
		std::advance(first, 5);
		std::advance(last, 8);

		tsCryptoString tmp2(first, last);

		EXPECT_STREQ("is ", tmp2.c_str());
	}
}

TEST(tsCryptoString, Destructor)
{
	//todo
}

TEST(tsCryptoString, AssignmentOp)
{
	//tsCryptoString &tsCryptoString::operator= (tsCryptoString &&obj)
	{
		//todo
	}

	//tsCryptoString &tsCryptoString::operator= (const tsCryptoString &obj)
	{
		tsCryptoString tmp("Test");
		ASSERT_EQ(tmp, "Test");
		tsCryptoString tmp2;
		tmp2 = tmp;
		EXPECT_EQ(tmp2, "Test");
		EXPECT_EQ(tmp2, tmp);
	}
	{
		tsCryptoString tmp("test" "\0" "123", 8);
		ASSERT_EQ(8, tmp.size());
		ASSERT_EQ(0, memcmp(tmp.rawData(), "test" "\0" "123", 8));
		tsCryptoString tmp2;
		tmp2 = tmp;
		ASSERT_EQ(8, tmp2.size());
		EXPECT_EQ(0, memcmp(tmp2.rawData(), "test" "\0" "123", 8));
		EXPECT_EQ(tmp2, tmp);
	}
	{
		tsCryptoString tmp = NULL;
		ASSERT_EQ(tmp, "");
		tsCryptoString tmp2;
		tmp2 = tmp;
		EXPECT_EQ(tmp2, "");
		EXPECT_EQ(tmp2, tmp);
	}

	//tsCryptoString &tsCryptoString::operator= (const char *data) /* zero terminated */
	{
		tsCryptoString tmp;
		tmp = "Test";
		EXPECT_EQ(tmp, "Test");
	}
	{
		tsCryptoString tmp;
		tmp = "Te" "\0" "st"; // standard strings always terminate on a zero byte
		EXPECT_EQ(2, tmp.size());
		EXPECT_EQ(tmp, "Te");
	}
	{
		//todo
		const char *data = NULL;
		tsCryptoString tmp;
		tmp = data;
		EXPECT_EQ(tmp, "");
	}


	//tsCryptoString &tsCryptoString::operator= (const char data)
	{
		char data = 't';
		tsCryptoString tmp;
		tmp = data;
		EXPECT_EQ(tmp, "t");
	}

	//tsCryptoString &tsCryptoString::operator = (long Value)
	//{
	//    long data = 0;
	//    tsCryptoString tmp;
	//    tmp  data;
	//    EXPECT_EQ(tmp, "0");
	//}
	//{
	//    long data = LONG_MAX;
	//    std::ostringstream oss;
	//    oss << data;
	//    std::string str = oss.str();
	//    const char *p = str.c_str();
	//    tsCryptoString tmp;
	//    tmp = data;
	//    EXPECT_EQ(tmp, p);
	//}
	//{
	//    long data = LONG_MIN;
	//    std::ostringstream oss;
	//    oss << data;
	//    std::string str = oss.str();
	//    const char *p = str.c_str();
	//    tsCryptoString tmp;
	//    tmp = data;
	//    EXPECT_EQ(tmp, p);
	//}
}

TEST(tsCryptoString, EqualOp)
{
	//bool tsCryptoString::operator== (const tsCryptoString &obj) const
	{
		tsCryptoString tmp = "test";
		tsCryptoString tmp2 = "test";
		tsCryptoString tmp3 = "test123";
		EXPECT_TRUE(tmp == tmp2);
		EXPECT_FALSE(tmp2 == tmp3);
		EXPECT_FALSE(tmp == tmp3);
	}

	//bool tsCryptoString::operator== (const char *str) const
	{
		tsCryptoString tmp = "test";
		EXPECT_TRUE(tmp == "test");
		EXPECT_FALSE(tmp == "test123");
	}
	{
		tsCryptoString tmp = "test";
		EXPECT_FALSE(tsCryptoString() == tmp);
	}

	//inline testing
	{
		tsCryptoString tmp = "test";
		EXPECT_TRUE("test" == tmp);
		EXPECT_FALSE("test123" == tmp);
	}
}

TEST(tsCryptoString, NotEqualOp)
{
	//bool tsCryptoString::operator!= (const tsCryptoString &obj) const
	{
		tsCryptoString tmp = "test";
		tsCryptoString tmp2 = "test";
		tsCryptoString tmp3 = "test123";

		EXPECT_TRUE(tmp != tmp3);
		EXPECT_FALSE(tmp != tmp2);
	}

	//bool tsCryptoString::operator!= (const char *str) const
	{
		tsCryptoString tmp = "test";
		EXPECT_TRUE("test123" != tmp);
		EXPECT_FALSE("test" != tmp);
		EXPECT_TRUE(tmp != "test123");
		EXPECT_FALSE(tmp != "test");
	}
	{
		tsCryptoString tmp = "test";
		EXPECT_TRUE(tsCryptoString() != tmp);
	}
}

TEST(tsCryptoString, GreaterThanOp)
{
	tsCryptoString five = "5";

	//bool tsCryptoString::operator> (const tsCryptoString &obj) const
	{
		tsCryptoString four = "4";
		tsCryptoString five2 = "5";

		EXPECT_TRUE(five > four);
		EXPECT_FALSE(four > five);
		EXPECT_FALSE(five > five2);
	}

	//bool tsCryptoString::operator> (const char *str) const
	{
		const char *four = "4";
		const char *five2 = "5";
		const char *six = "6";

		EXPECT_TRUE(five > four);
		EXPECT_FALSE(five > six);
		EXPECT_FALSE(five > five2);
	}

	//inline testing
	{
		const char *four = "4";
		const char *five2 = "5";
		const char *six = "6";
		EXPECT_FALSE(four > five);
		EXPECT_TRUE(six > five);
		EXPECT_FALSE(five2 > five);
	}
}

TEST(tsCryptoString, GreaterThanEqualOp)
{
	tsCryptoString five = "5";

	//bool tsCryptoString::operator>= (const tsCryptoString &obj) const
	{
		tsCryptoString four = "4";
		tsCryptoString five2 = "5";

		EXPECT_TRUE(five >= four);
		EXPECT_FALSE(four >= five);
		EXPECT_TRUE(five >= five2);
	}

	//bool tsCryptoString::operator>= (const char *str) const
	{
		const char *four = "4";
		const char *five2 = "5";
		const char *six = "6";

		EXPECT_TRUE(five >= four);
		EXPECT_FALSE(five >= six);
		EXPECT_TRUE(five >= five2);
	}

	//inline testing
	{
		const char *four = "4";
		const char *five2 = "5";
		const char *six = "6";
		EXPECT_FALSE(four >= five);
		EXPECT_TRUE(six >= five);
		EXPECT_TRUE(five2 >= five);
	}
}

TEST(tsCryptoString, LessThanOp)
{
	tsCryptoString five = "5";

	//bool tsCryptoString::operator< (const tsCryptoString &obj) const
	{
		tsCryptoString five2 = "5";
		tsCryptoString six = "6";


		EXPECT_TRUE(five < six);
		EXPECT_FALSE(six < five);
		EXPECT_FALSE(five < five2);
	}

	//bool tsCryptoString::operator< (const char *str) const
	{
		const char *four = "4";
		const char *five2 = "5";
		const char *six = "6";

		EXPECT_TRUE(five < six);
		EXPECT_FALSE(five < four);
		EXPECT_FALSE(five < five2);
	}

	//inline testing
	{
		const char *four = "4";
		const char *five2 = "5";
		const char *six = "6";
		EXPECT_TRUE(four < five);
		EXPECT_FALSE(six < five);
		EXPECT_FALSE(five2 < five);
	}
}

TEST(tsCryptoString, LessThanEqualOp)
{
	tsCryptoString five = "5";

	//bool tsCryptoString::operator<= (const tsCryptoString &obj) const
	{
		tsCryptoString five2 = "5";
		tsCryptoString six = "6";


		EXPECT_TRUE(five <= six);
		EXPECT_FALSE(six <= five);
		EXPECT_TRUE(five <= five2);
	}

	//bool tsCryptoString::operator<= (const char *str) const
	{
		const char *four = "4";
		const char *five2 = "5";
		const char *six = "6";

		EXPECT_TRUE(five <= six);
		EXPECT_FALSE(five <= four);
		EXPECT_TRUE(five <= five2);
	}

	//inline testing
	{
		const char *four = "4";
		const char *five2 = "5";
		const char *six = "6";
		EXPECT_TRUE(four <= five);
		EXPECT_FALSE(six <= five);
		EXPECT_TRUE(five2 <= five);
	}
}

TEST(tsCryptoString, PlusEqualOp)
{
	//tsCryptoString &tsCryptoString::operator += (const tsCryptoString &obj)
	{
		{
			tsCryptoString tmp = "test";
			tsCryptoString tmp2 = "123";
			tmp += tmp2;
			EXPECT_STREQ("test123", tmp.c_str());
			EXPECT_STREQ("123", tmp2.c_str());
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString tmp2 = NULL;
			tmp += tmp2;
			EXPECT_STREQ("test", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString tmp2("\0" "123", 4);
			tmp += tmp2;
			EXPECT_EQ(0, memcmp("test" "\0" "123", tmp.c_str(), tmp.size()));
		}
	}


	//tsCryptoString &tsCryptoString::operator += (const char *data)
	{
		tsCryptoString tmp = "test";
		const char* tmp2 = "123";

		tmp += tmp2;
		EXPECT_STREQ("test123", tmp.c_str());
		EXPECT_STREQ("123", tmp2);
	}


	//tsCryptoString &tsCryptoString::operator += (char data)
	{
		tsCryptoString tmp = "test";
		char tmp2 = 'c';

		tmp += tmp2;
		EXPECT_STREQ("testc", tmp.c_str());
	}

	//tsCryptoString &tsCryptoString::operator += (long Value)
	//{
	//    tsCryptoString tmp = "test";
	//    long tmp2 = 123;

	//    tmp += tmp2;
	//    EXPECT_STREQ("test123", tmp.c_str());
	//    EXPECT_EQ(123, tmp2);
	//}
}

TEST(tsCryptoString, size)
{
	tsCryptoString tmp = "";
	EXPECT_EQ(0, tmp.size());

	tmp = "123";
	EXPECT_EQ(3, tmp.size());

	tmp = "012345678901234567890123456789012345678901234567891";
	EXPECT_EQ(51, tmp.size());

	tmp = "\0";
	EXPECT_EQ(0, tmp.size());
}

TEST(tsCryptoString, length)
{
	tsCryptoString tmp = "";
	EXPECT_EQ(0, tmp.length());

	tmp = "123";
	EXPECT_EQ(3, tmp.length());

	tmp = "012345678901234567890123456789012345678901234567891";
	EXPECT_EQ(51, tmp.length());

	tmp = "\0";
	EXPECT_EQ(0, tmp.length());
}

TEST(tsCryptoString, erase)
{
	tsCryptoString tmp = "test";
	tsCryptoString *tmpPtr = &tmp;
	size_t size = 4;

	if (tmpPtr == NULL)
	{
		FAIL();
	}
	EXPECT_EQ("test", tmp);
	EXPECT_EQ(0, memcmp("test", tmpPtr->c_str(), size));


	tmp.erase();
	EXPECT_EQ(0, tmp.size());
	EXPECT_STREQ("", tmp.c_str());
	EXPECT_EQ(0, memcmp("\0\0\0\0", tmpPtr->c_str(), size));
}

TEST(tsCryptoString, clear)
{
	tsCryptoString tmp = "test";
	tsCryptoString *tmpPtr = &tmp;
	size_t size = 4;

	if (tmpPtr == NULL)
	{
		FAIL();
	}
	EXPECT_EQ("test", tmp);
	EXPECT_EQ(0, memcmp("test", tmpPtr->c_str(), size));


	tmp.clear();
	EXPECT_EQ(0, tmp.size());
	EXPECT_STREQ("", tmp.c_str());
	EXPECT_EQ(0, memcmp("\0\0\0\0", tmpPtr->c_str(), size));
}

TEST(tsCryptoString, compare)
{
	//int tsCryptoString::compare(const tsCryptoString &_Str) const
	tsCryptoString five = "5";
	tsCryptoString four = "4";
	tsCryptoString five2 = "5";
	EXPECT_TRUE(four.compare(five) < 0);
	EXPECT_TRUE(five.compare(four) > 0);
	EXPECT_TRUE(five.compare(five2) == 0);
}

TEST(tsCryptoString, resize)
{
	//size_t tsCryptoString::resize(size_t newSize)
	{
		tsCryptoString tmp = "test";
		EXPECT_EQ(4, tmp.size());
		size_t newSize = 10;
		tmp.resize(newSize);
		EXPECT_EQ(newSize, tmp.size());
		EXPECT_STREQ("test", tmp.c_str());
		EXPECT_EQ(0, memcmp("test\0\0\0\0\0\0", tmp.c_str(), newSize));
	}
	{
		tsCryptoString tmp = "test";
		size_t oldSize = tmp.size();
		size_t newSize = 2;

		tmp.resize(newSize);

		EXPECT_EQ(4, oldSize);
		EXPECT_EQ(newSize, tmp.size());
		EXPECT_STREQ("te", tmp.c_str());

		EXPECT_EQ(0, memcmp("te\0\0", tmp.c_str(), oldSize));
	}
	{
		tsCryptoString tmp = "test";
		size_t oldSize = tmp.size();
		size_t newSize = oldSize;

		tmp.resize(newSize);

		EXPECT_EQ(4, oldSize);
		EXPECT_EQ(newSize, tmp.size());
		EXPECT_STREQ("test", tmp.c_str());
		EXPECT_EQ(0, memcmp("test", tmp.c_str(), oldSize));
	}
	{
		tsCryptoString tmp = "test";
		size_t oldSize = tmp.size();
		size_t newSize = 0;

		tmp.resize(newSize);

		EXPECT_EQ(4, oldSize);
		EXPECT_EQ(newSize, tmp.size());
		EXPECT_STREQ("\0", tmp.c_str());

		EXPECT_EQ(0, memcmp("\0\0\0\0", tmp.c_str(), oldSize));
	}


	//size_t tsCryptoString::resize(size_t newSize, char value)
	{
		tsCryptoString tmp = "test";
		char value = 'w';
		EXPECT_EQ(4, tmp.size());
		size_t newSize = 10;
		tmp.resize(newSize, value);
		EXPECT_EQ(newSize, tmp.size());
		EXPECT_STREQ("testwwwwww", tmp.c_str());
		EXPECT_EQ(0, memcmp("testwwwwww", tmp.c_str(), newSize));
	}
	{
		tsCryptoString tmp = "test";
		char value = 'w';
		size_t oldSize = tmp.size();
		size_t newSize = 2;

		tmp.resize(newSize, value);

		EXPECT_EQ(4, oldSize);
		EXPECT_EQ(newSize, tmp.size());
		EXPECT_STREQ("te", tmp.c_str());
		EXPECT_EQ(0, memcmp("te\0\0", tmp.c_str(), oldSize));
	}
	{
		tsCryptoString tmp = "test";
		char value = 'w';
		size_t oldSize = tmp.size();
		size_t newSize = oldSize;

		tmp.resize(newSize, value);

		EXPECT_EQ(4, oldSize);
		EXPECT_EQ(newSize, tmp.size());
		EXPECT_STREQ("test", tmp.c_str());
		EXPECT_EQ(0, memcmp("test", tmp.c_str(), oldSize));
	}
	{
		tsCryptoString tmp = "test";
		char value = 'w';
		size_t oldSize = tmp.size();
		size_t newSize = 0;

		tmp.resize(newSize, value);

		EXPECT_EQ(4, oldSize);
		EXPECT_EQ(newSize, tmp.size());
		EXPECT_STREQ("", tmp.c_str());
		EXPECT_EQ(0, memcmp("\0\0\0\0", tmp.c_str(), oldSize));
	}
}

TEST(tsCryptoString, at)
{
	//char &tsCryptoString::at(size_t index)
	{
		tsCryptoString tmp = "abc";
		EXPECT_EQ('a', tmp.at(0));
		EXPECT_EQ('b', tmp.at(1));
		EXPECT_EQ('c', tmp.at(2));
		EXPECT_THROW(tmp.at(3), tscrypto::OutOfRange);
	}

	//const char &tsCryptoString::at(size_t index) const
	{
		const tsCryptoString tmp = "abc";
		EXPECT_EQ('a', tmp.at(0));
		EXPECT_EQ('b', tmp.at(1));
		EXPECT_EQ('c', tmp.at(2));
		EXPECT_THROW(tmp.at(3), tscrypto::OutOfRange);
	}
}

TEST(tsCryptoString, c_at)
{
	const tsCryptoString tmp = "abc";
	EXPECT_EQ('a', tmp.at(0));
	EXPECT_EQ('b', tmp.at(1));
	EXPECT_EQ('c', tmp.at(2));
	EXPECT_THROW(tmp.at(3), tscrypto::OutOfRange);
}

TEST(tsCryptoString, rawData)
{
	{
		tsCryptoString tmp = "abc";
		EXPECT_STREQ("abc", tmp.rawData());
	}
	{
		tsCryptoString tmp = "012345678901234567890123456789012345678901234567891";
		EXPECT_STREQ("012345678901234567890123456789012345678901234567891", tmp.rawData());
	}
	{
		tsCryptoString tmp = "";
		EXPECT_STREQ("", tmp.rawData());
	}
}

TEST(tsCryptoString, data)
{
	{
		tsCryptoString tmp = "abc";
		EXPECT_STREQ("abc", tmp.data());
	}
	{
		tsCryptoString tmp = "012345678901234567890123456789012345678901234567891";
		EXPECT_STREQ("012345678901234567890123456789012345678901234567891", tmp.data());
	}
	{
		tsCryptoString tmp = "";
		EXPECT_STREQ("", tmp.data());
	}
}

TEST(tsCryptoString, c_str)
{
	{
		tsCryptoString tmp = "abc";
		EXPECT_STREQ("abc", tmp.c_str());
	}
	{
		tsCryptoString tmp = "012345678901234567890123456789012345678901234567891";
		EXPECT_STREQ("012345678901234567890123456789012345678901234567891", tmp.c_str());
	}
	{
		tsCryptoString tmp = "";
		EXPECT_STREQ("", tmp.c_str());
	}
}

TEST(tsCryptoString, assign)
{


	//tsCryptoString &tsCryptoString::assign (const char *newData, size_t size)
	{
		{
			tsCryptoString tmp = "abcd";
			const char *newData = "1234";
			tmp.assign(newData, 4);
			EXPECT_STREQ("1234", tmp.c_str());
		}
		{
			tsCryptoString tmp = "abcd";
			const char *newData = "12";
			tmp.assign(newData, 2);
			EXPECT_STREQ("12", tmp.c_str());
		}
		{
			tsCryptoString tmp = "abcd";
			const char *newData = "123456";
			tmp.assign(newData, 6);
			EXPECT_STREQ("123456", tmp.c_str());
		}
		{
			tsCryptoString tmp = "abcd";
			const char *newData = "123";
			tmp.assign(newData, 6);
			EXPECT_STREQ("123", tmp.c_str());
		}
		{
			//todo
			tsCryptoString tmp = "abcd";
			const char *newData = NULL;
			tmp.assign(newData, 0);
			EXPECT_STREQ("", tmp.c_str());
		}
	}


	//tsCryptoString &tsCryptoString::assign (size_t size, const char *newData)
	{
		{
			tsCryptoString tmp = "abcd";
			const char *newData = "1234";
			tmp.assign(newData, 4);
			EXPECT_STREQ("1234", tmp.c_str());
		}
		{
			tsCryptoString tmp = "abcd";
			const char *newData = "12";
			tmp.assign(newData, 2);
			EXPECT_STREQ("12", tmp.c_str());
		}
		{
			tsCryptoString tmp = "abcd";
			const char *newData = "123456";
			tmp.assign(newData, 6);
			EXPECT_STREQ("123456", tmp.c_str());
		}
		{
			tsCryptoString tmp = "abcd";
			const char *newData = "123";
			tmp.assign(newData, 6);
			EXPECT_STREQ("123", tmp.c_str());
		}
		{
			//todo
			tsCryptoString tmp = "abcd";
			const char *newData = NULL;
			tmp.assign(newData, 0);
			EXPECT_STREQ("", tmp.c_str());
		}
	}

	//tsCryptoString &tsCryptoString::assign (const tsCryptoString &obj)
	{
		{
			tsCryptoString tmp = "abcd";
			tsCryptoString newData = "1234";
			tmp.assign(newData);
			EXPECT_STREQ("1234", tmp.c_str());
		}
		{
			tsCryptoString tmp = "abcd";
			tsCryptoString newData = "12";
			tmp.assign(newData);
			EXPECT_STREQ("12", tmp.c_str());
		}
		{
			tsCryptoString tmp = "abcd";
			tsCryptoString newData = "123456";
			tmp.assign(newData);
			EXPECT_STREQ("123456", tmp.c_str());
		}
		{
			tsCryptoString tmp = "abcd";
			tsCryptoString newData = "123";
			tmp.assign(newData);
			EXPECT_STREQ("123", tmp.c_str());
		}
		{
			tsCryptoString tmp = "abcd";
			tsCryptoString newData = NULL;
			tmp.assign(newData);
			EXPECT_STREQ("", tmp.c_str());
		}
	}
}

//TEST(tsCryptoString, copyFrom)
//{
//	//todo: protected
//	//tsCryptoString tmp = "abc";
//	//tsCryptoString newTmp = "1234";
//	//tmp.copyFrom(newTmp);
//	//EXPECT_STREQ(newTmp, tmp);
//}

TEST(tsCryptoString, Prepend)
{

	//tsCryptoString &tsCryptoString::prepend(const char *data)
	{
		{
			tsCryptoString tmp = "test";
			const char *data = "123";
			tmp.prepend(data);
			EXPECT_STREQ("123test", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *data = "012345678901234567890123456789012345678901234567891"; // length = 51
			tmp.prepend(data);
			EXPECT_STREQ("012345678901234567890123456789012345678901234567891test", tmp.c_str());
		}
		{
			tsCryptoString tmp = "0123456789012345678901234567890123456789012345678"; // length = 49
			const char *data = "abcd";
			tmp.prepend(data);
			EXPECT_STREQ("abcd0123456789012345678901234567890123456789012345678", tmp.c_str());
		}
		{
			tsCryptoString tmp("t" "\0" "est", 5);
			const char *data = "123";
			tmp.prepend(data);
			ASSERT_EQ(8, tmp.size());
			EXPECT_EQ(memcmp("123t" "\0" "est", tmp.c_str(), tmp.size()), 0);
		}
		{
			tsCryptoString tmp = NULL;
			const char *data = "123";
			tmp.prepend(data);
			EXPECT_STREQ("123", tmp.c_str());
		}
		{
			//todo
			tsCryptoString tmp = "test";
			const char *data = NULL;
			tmp.prepend(data);
			EXPECT_STREQ("test", tmp.c_str());
		}
	}



	//tsCryptoString &tsCryptoString::prepend(const char *data, size_t len)
	{
		{
			tsCryptoString tmp = "test";
			const char *data = "123";
			tmp.prepend(data, 3); //correct size
			EXPECT_STREQ("123test", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char* data = "123";
			tmp.prepend(data, 1); //size less than size of data
			EXPECT_STREQ("1test", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char* data = "12";
			tmp.prepend(data, 0); //size = 0
			EXPECT_STREQ("test", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *data = "012345678901234567890123456789012345678901234567891"; // length = 51
			tmp.prepend(data, 51);
			EXPECT_STREQ("012345678901234567890123456789012345678901234567891test", tmp.c_str());
		}
		{
			tsCryptoString tmp = "0123456789012345678901234567890123456789012345678"; // length = 49
			const char *data = "abcd";
			tmp.prepend(data, 4);
			EXPECT_STREQ("abcd0123456789012345678901234567890123456789012345678", tmp.c_str());
		}
		{
			tsCryptoString tmp("t" "\0" "est", 5);
			const char *data = "123";
			tmp.prepend(data, 3);
			ASSERT_EQ(8, tmp.size());
			EXPECT_EQ(memcmp("123t" "\0" "est", tmp.c_str(), tmp.size()), 0);
		}
		{
			tsCryptoString tmp("t" "\0" "est", 5);
			const char *data = "123";
			tmp.prepend(data, 1);
			ASSERT_EQ(6, tmp.size());
			EXPECT_EQ(memcmp("1t" "\0" "est", tmp.c_str(), tmp.size()), 0);
		}
		{
			tsCryptoString tmp = NULL;
			const char *data = "123";
			tmp.prepend(data, 3);
			EXPECT_STREQ("123", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *data = NULL;
			tmp.prepend(data, 1);
			EXPECT_STREQ("test", tmp.c_str());
		}
	}


	//tsCryptoString &tsCryptoString::prepend(char data)
	{
		{
			tsCryptoString tmp = "test";
			char data = '1';
			tmp.prepend(data);
			EXPECT_STREQ("1test", tmp.c_str());
		}
		{
			tsCryptoString tmp = "01234567890123456789012345678901234567890123456789"; // length = 50
			char data = 'a';
			tmp.prepend(data);
			EXPECT_STREQ("a01234567890123456789012345678901234567890123456789", tmp.c_str());
		}
		{
			tsCryptoString tmp("t" "\0" "est", 5);
			char data = '1';
			size_t sizeBeforePrepend = tmp.size();
			tmp.prepend(data);
			EXPECT_EQ(++sizeBeforePrepend, tmp.size());
			EXPECT_EQ(memcmp("1t" "\0" "est", tmp.c_str(), tmp.size()), 0);
		}
		{
			tsCryptoString tmp = NULL;
			char data = '1';
			size_t sizeBeforePrepend = tmp.size();
			tmp.prepend(data);
			EXPECT_EQ(++sizeBeforePrepend, tmp.size());
			EXPECT_EQ(0, memcmp("1" "\0", tmp.c_str(), tmp.size()));
		}
		{
			tsCryptoString tmp = "test";
			char data = 0;
			size_t sizeBeforePrepend = tmp.size();
			tmp.prepend(data);
			EXPECT_EQ(sizeBeforePrepend, tmp.size());
			EXPECT_STREQ("test", tmp.c_str());

		}
	}

	//tsCryptoString &tsCryptoString::prepend(uint8_t data)
	{
		{
			tsCryptoString tmp = "test";
            uint8_t b = 0x31; //ascii byte for '1'
			tmp.prepend(b);
			EXPECT_STREQ("1test", tmp.c_str());
		}
		{
			tsCryptoString tmp = "01234567890123456789012345678901234567890123456789"; // length = 50
            uint8_t b = 0x31; //ascii byte for '1'
			tmp.prepend(b);
			EXPECT_STREQ("101234567890123456789012345678901234567890123456789", tmp.c_str());
		}
		{
			tsCryptoString tmp("t" "\0" "est", 5);
            uint8_t b = 0x31; //ascii byte for '1'
			size_t sizeBeforePrepend = tmp.size();
			tmp.prepend(b);
			EXPECT_EQ(++sizeBeforePrepend, tmp.size());
			EXPECT_EQ(memcmp("1t" "\0" "est", tmp.c_str(), tmp.size()), 0);
		}
		{
			tsCryptoString tmp = "test";
            uint8_t b = 0;
			size_t sizeBeforePrepend = tmp.size();
			tmp.prepend(b);
			EXPECT_EQ(++sizeBeforePrepend, tmp.size());
			EXPECT_EQ(0, memcmp("\0" "test", tmp.c_str(), tmp.size()));
			EXPECT_STREQ("", tmp.c_str());
		}
		{
			tsCryptoString tmp = NULL;
            uint8_t b = 0x31; //ascii byte for '1'
			size_t sizeBeforePrepend = tmp.size();
			tmp.prepend(b);
			EXPECT_EQ(++sizeBeforePrepend, tmp.size());
			EXPECT_STREQ("1", tmp.c_str());
		}
		{
			//todo is this correct?
			tsCryptoString tmp = "test";
            uint8_t b = 0; // NULL = 0
			size_t sizeBeforePrepend = tmp.size();
			tmp.prepend(b);
			EXPECT_EQ(++sizeBeforePrepend, tmp.size());
			EXPECT_EQ(0, memcmp("\0" "test", tmp.c_str(), tmp.size()));
		}
	}

	//tsCryptoString &tsCryptoString::prepend(const tsCryptoString &obj)
	{
		{
			tsCryptoString tmp = "test";
			tsCryptoString data = "123";
			tmp.prepend(data);
			EXPECT_STREQ("123test", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString data = "012345678901234567890123456789012345678901234567891"; // length = 51
			tmp.prepend(data);
			EXPECT_STREQ("012345678901234567890123456789012345678901234567891test", tmp.c_str());
		}
		{
			tsCryptoString tmp = "0123456789012345678901234567890123456789012345678"; // length = 49
			tsCryptoString data = "abcd";
			tmp.prepend(data);
			EXPECT_STREQ("abcd0123456789012345678901234567890123456789012345678", tmp.c_str());
		}
		{
			tsCryptoString tmp("t" "\0" "est", 5);
			tsCryptoString data = "123";
			tmp.prepend(data);
			ASSERT_EQ(8, tmp.size());
			EXPECT_EQ(memcmp("123t" "\0" "est", tmp.c_str(), tmp.size()), 0);
		}
		{
			tsCryptoString tmp("t" "\0" "est", 5);
			tsCryptoString data("1" "\0" "23", 4);
			tmp.prepend(data);
			ASSERT_EQ(9, tmp.size());
			EXPECT_EQ(memcmp("1" "\0" "23t" "\0" "est", tmp.c_str(), tmp.size()), 0);
		}
		{
			tsCryptoString tmp = NULL;
			tsCryptoString data = "123";
			tmp.prepend(data);
			EXPECT_STREQ("123", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString data = NULL;
			tmp.prepend(data);
			EXPECT_STREQ("test", tmp.c_str());
		}
	}

	//tsCryptoString &tsCryptoString::prepend(long Value)
	//{
	//    {
	//        tsCryptoString tmp = "test";
	//        long l = 123;
	//        tmp.prepend(l);
	//        EXPECT_STREQ("123test", tmp.c_str());
	//    }
	//    {
	//        tsCryptoString tmp = "0123456789012345678901234567890123456789012345678"; // length = 49
	//        long l = 123;
	//        tmp.prepend(l);
	//        EXPECT_STREQ("1230123456789012345678901234567890123456789012345678", tmp.c_str());
	//    }
	//    {
	//        tsCryptoString tmp("t" "\0" "est", 5);
	//        long l = 123;
	//        tmp.prepend(l);
	//        ASSERT_EQ(8, tmp.size());
	//        EXPECT_EQ(memcmp("123t" "\0" "est", tmp.c_str(), tmp.size()), 0);
	//    }
	//    {
	//        tsCryptoString tmp = NULL;
	//        long l = 123;
	//        size_t sizeBeforePrepend = tmp.size();
	//        tmp.prepend(l);
	//        EXPECT_TRUE(tmp.size() > ++sizeBeforePrepend);
	//        EXPECT_STREQ("123", tmp.c_str());
	//    }
	//    {
	//        tsCryptoString tmp = "test";
	//        long l = 0;
	//        size_t sizeBeforePrepend = tmp.size();
	//        tmp.prepend(l);
	//        EXPECT_EQ(++sizeBeforePrepend, tmp.size());
	//        EXPECT_EQ(0, memcmp("0test", tmp.c_str(), 5));
	//    }
	//}
}

TEST(tsCryptoString, Append)
{

	//tsCryptoString &tsCryptoString::append(const char *data)
	{
		{
			tsCryptoString tmp = "test";
			const char *data = "123";
			tmp.append(data);
			EXPECT_STREQ("test123", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *data = "012345678901234567890123456789012345678901234567891"; // length = 51
			tmp.append(data);
			EXPECT_STREQ("test012345678901234567890123456789012345678901234567891", tmp.c_str());
		}
		{
			tsCryptoString tmp = "0123456789012345678901234567890123456789012345678"; // length = 49
			const char *data = "abcd";
			tmp.append(data);
			EXPECT_STREQ("0123456789012345678901234567890123456789012345678abcd", tmp.c_str());
		}
		{
			tsCryptoString tmp = "abc";
			tsCryptoString obj = "\n";
			tmp.append(obj);
			EXPECT_EQ(4, tmp.size());
			EXPECT_STREQ("abc\n", tmp.c_str());
		}
		{
			tsCryptoString tmp = "abc";
			tsCryptoString obj = "\n" "123";
			tmp.append(obj);
			EXPECT_EQ(7, tmp.size());
			EXPECT_STREQ("abc\n123", tmp.c_str());
		}
		{
			tsCryptoString tmp("t" "\0" "est", 5);
			const char *data = "123";
			tmp.append(data);
			ASSERT_EQ(8, tmp.size());
			EXPECT_EQ(memcmp("t" "\0" "est123", tmp.c_str(), tmp.size()), 0);
		}
		{
			tsCryptoString tmp = NULL;
			const char *data = "123";
			tmp.append(data);
			EXPECT_STREQ("123", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *data = NULL;
			tmp.append(data);
			EXPECT_STREQ("test", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			tmp.append('5');
			EXPECT_STREQ("test5", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			tmp.append((int16_t)256);
			EXPECT_STREQ("test256", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			tmp.append((int32_t)65537);
			EXPECT_STREQ("test65537", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			tmp.append((int64_t)0x1FFFFFFFFLL);
			EXPECT_STREQ("test8589934591", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			tmp.append((uint8_t)50);
			EXPECT_STREQ("test50", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			tmp.append((uint16_t)-1);
			EXPECT_STREQ("test65535", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			tmp.append((uint32_t)65537);
			EXPECT_STREQ("test65537", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			tmp.append((uint64_t)0x1FFFFFFFFLL);
			EXPECT_STREQ("test8589934591", tmp.c_str());
		}

	}


	//tsCryptoString &tsCryptoString::append(const char *data, size_t len)
	{
		{
			tsCryptoString tmp = "test";
			const char *data = "123";
			tmp.append(data, 3); //correct size
			EXPECT_STREQ("test123", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char* data = "123";
			tmp.append(data, 1); //size less than size of data
			EXPECT_STREQ("test1", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char* data = "12";
			tmp.append(data, 5); //size greater than size of data
			EXPECT_STREQ("test12", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *data = "012345678901234567890123456789012345678901234567891"; // length = 51
			tmp.append(data, 51);
			EXPECT_STREQ("test012345678901234567890123456789012345678901234567891", tmp.c_str());
		}
		{
			tsCryptoString tmp = "0123456789012345678901234567890123456789012345678"; // length = 49
			const char *data = "abcd";
			tmp.append(data, 4);
			EXPECT_STREQ("0123456789012345678901234567890123456789012345678abcd", tmp.c_str());
		}
		{
			tsCryptoString tmp("t" "\0" "est", 5);
			const char *data = "123";
			tmp.append(data, 3);
			ASSERT_EQ(8, tmp.size());
			EXPECT_EQ(memcmp("t" "\0" "est123", tmp.c_str(), tmp.size()), 0);
		}
		{
			tsCryptoString tmp("t" "\0" "est", 5);
			const char *data = "123";
			tmp.append(data, 1);
			ASSERT_EQ(6, tmp.size());
			EXPECT_EQ(memcmp("t" "\0" "est1", tmp.c_str(), tmp.size()), 0);
		}
		{
			tsCryptoString tmp = NULL;
			const char *data = "123";
			tmp.append(data, 3);
			EXPECT_STREQ("123", tmp.c_str());
		}
		{
			//todo
			tsCryptoString tmp = "test";
			const char *data = NULL;
			tmp.append(data, 1);
			EXPECT_STREQ("test", tmp.c_str());
		}
	}


	//tsCryptoString &tsCryptoString::append(char data)
	{
		{
			tsCryptoString tmp = "test";
			char data = '1';
			tmp.append(data);
			EXPECT_STREQ("test1", tmp.c_str());
		}
		{
			tsCryptoString tmp = "01234567890123456789012345678901234567890123456789"; // length = 50
			char data = 'a';
			tmp.append(data);
			EXPECT_STREQ("01234567890123456789012345678901234567890123456789a", tmp.c_str());
		}
		{
			tsCryptoString tmp("t" "\0" "est", 5);
			char data = '1';
			size_t sizeBeforAappend = tmp.size();
			tmp.append(data);
			EXPECT_EQ(++sizeBeforAappend, tmp.size());
			EXPECT_EQ(memcmp("t" "\0" "est1", tmp.c_str(), tmp.size()), 0);
		}
		{
			tsCryptoString tmp = NULL;
			char data = '1';
			size_t sizeBeforAappend = tmp.size();
			tmp.append(data);
			EXPECT_EQ(++sizeBeforAappend, tmp.size());
			EXPECT_EQ(0, memcmp("1", tmp.c_str(), tmp.size()));
		}
		{
			tsCryptoString tmp = "test";
			char data = 0;
			size_t sizeBeforAappend = tmp.size();
			tmp.append(data);
			EXPECT_EQ(sizeBeforAappend + 1, tmp.size());
			EXPECT_EQ(0, memcmp("test\0", tmp.c_str(), 5));
		}
	}

	//tsCryptoString &tsCryptoString::append(uint8_t data)
	{
		{
			tsCryptoString tmp = "test";
            uint8_t b = 0x31;
			tmp.append(b);
			EXPECT_STREQ("test49", tmp.c_str());
		}
		{
			tsCryptoString tmp("t" "\0" "est", 5);
            uint8_t b = 0x31; //ascii byte for '1'
			size_t sizeBeforeAppend = tmp.size();
			tmp.append(b);
			EXPECT_EQ(sizeBeforeAppend + 2, tmp.size());
			EXPECT_EQ(memcmp("t" "\0" "est49", tmp.c_str(), tmp.size()), 0);
		}
		{
			tsCryptoString tmp = "test";
			char b = 0;
			size_t sizeBeforeAppend = tmp.size();
			tmp.append(b);
			EXPECT_EQ(sizeBeforeAppend + 1, tmp.size());
			EXPECT_EQ(0, memcmp("test" "\0", tmp.c_str(), tmp.size()));
			EXPECT_STREQ("test", tmp.c_str());
		}
		{
			tsCryptoString tmp = NULL;
            uint8_t b = 0x31; //ascii byte for '1'
			size_t sizeBeforeAppend = tmp.size();
			tmp.append(b);
			EXPECT_EQ(sizeBeforeAppend + 2, tmp.size());
			EXPECT_STREQ("49", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			char b = 0;
			size_t sizeBeforeAppend = tmp.size();
			tmp.append(b);
			EXPECT_EQ(sizeBeforeAppend + 1, tmp.size());
			EXPECT_EQ(0, memcmp("test" "\0", tmp.c_str(), 5));
		}
	}

	//tsCryptoString &tsCryptoString::append(const tsCryptoString &obj)
	{
		{
			tsCryptoString tmp = "test";
			tsCryptoString data = "123";
			tmp.append(data);
			EXPECT_STREQ("test123", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString data = "012345678901234567890123456789012345678901234567891"; // length = 51
			tmp.append(data);
			EXPECT_STREQ("test012345678901234567890123456789012345678901234567891", tmp.c_str());
		}
		{
			tsCryptoString tmp = "0123456789012345678901234567890123456789012345678"; // length = 49
			tsCryptoString data = "abcd";
			tmp.append(data);
			EXPECT_STREQ("0123456789012345678901234567890123456789012345678abcd", tmp.c_str());
		}
		{
			tsCryptoString tmp("t" "\0" "est", 5);
			tsCryptoString data = "123";
			tmp.append(data);
			ASSERT_EQ(8, tmp.size());
			EXPECT_EQ(memcmp("t" "\0" "est123", tmp.c_str(), tmp.size()), 0);
		}
		{
			tsCryptoString tmp("t" "\0" "est", 5);
			tsCryptoString data("1" "\0" "23", 4);
			tmp.append(data);
			ASSERT_EQ(9, tmp.size());
			EXPECT_EQ(memcmp("t" "\0" "est1" "\0" "23", tmp.c_str(), tmp.size()), 0);
		}
		{
			tsCryptoString tmp = NULL;
			tsCryptoString data = "123";
			tmp.append(data);
			EXPECT_STREQ("123", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString data = NULL;
			tmp.append(data);
			EXPECT_STREQ("test", tmp.c_str());
		}
	}

	//tsCryptoString &tsCryptoString::append(long Value)
	//{
	//{
	//    tsCryptoString tmp = "test";
	//    long l = 123;
	//    tmp.append(l);
	//    EXPECT_STREQ("test123", tmp.c_str());
	//}
	//{
	//    tsCryptoString tmp = "0123456789012345678901234567890123456789012345678"; // length = 49
	//    long l = 123;
	//    tmp.append(l);
	//    EXPECT_STREQ("0123456789012345678901234567890123456789012345678123", tmp.c_str());
	//}
	//{
	//    tsCryptoString tmp("t" "\0" "est", 5);
	//    long l = 123;
	//    tmp.append(l);
	//    ASSERT_EQ(8, tmp.size());
	//    EXPECT_EQ(memcmp("t" "\0" "est123", tmp.c_str(), tmp.size()), 0);
	//}
	//{
	//    tsCryptoString tmp = NULL;
	//    long l = 123;
	//    size_t sizeBeforeAppend = tmp.size();
	//    tmp.append(l);
	//    EXPECT_TRUE(tmp.size() > ++sizeBeforeAppend);
	//    EXPECT_STREQ("123", tmp.c_str());
	//}
	//{
	//    tsCryptoString tmp = "test";
	//    long l = 0;
	//    size_t sizeBeforeAppend = tmp.size();
	//    tmp.append(l);
	//    EXPECT_EQ(++sizeBeforeAppend, tmp.size());
	//    EXPECT_EQ(0, memcmp("test0", tmp.c_str(), 5));
	//}
	//}
}

TEST(tsCryptoString, InsertAt)
{

	//tsCryptoString &tsCryptoString::InsertAt(size_t offset, char value)
	{
		{
			tsCryptoString tmp = "test";
			char c = '1';
			tmp.InsertAt(0, c);
			EXPECT_STREQ("1test", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			char c = '1';
			tmp.InsertAt(3, c);
			EXPECT_STREQ("tes1t", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			char c = '1';
			tmp.InsertAt(4, c);
			EXPECT_STREQ("test1", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			char c = '1';
			tmp.InsertAt(10, c); //index greater than size
			EXPECT_STREQ("test1", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			char c = 0;
			size_t sizeBeforeInsert = tmp.size();
			tmp.InsertAt(0, c);
			EXPECT_EQ(++sizeBeforeInsert, tmp.size());
			EXPECT_EQ(0, memcmp("\0" "test", tmp.c_str(), tmp.size()));
		}
		{
			tsCryptoString tmp = "test";
			char c = 0;
			size_t sizeBeforeInsert = tmp.size();
			tmp.InsertAt(3, c);
			EXPECT_EQ(++sizeBeforeInsert, tmp.size());
			EXPECT_EQ(0, memcmp("tes" "\0" "t", tmp.c_str(), tmp.size()));
		}
		{
			tsCryptoString tmp = "test";
			char c = 0;
			size_t sizeBeforeInsert = tmp.size();
			tmp.InsertAt(4, c);
			EXPECT_EQ(++sizeBeforeInsert, tmp.size());
			EXPECT_EQ(0, memcmp("test", tmp.c_str(), tmp.size()));
		}
		{
			tsCryptoString tmp = "test";
			char c = 0;
			size_t sizeBeforeInsert = tmp.size();
			tmp.InsertAt(10, c); //index greater than size
			EXPECT_EQ(++sizeBeforeInsert, tmp.size());
			EXPECT_EQ(0, memcmp("test", tmp.c_str(), tmp.size()));
		}
	}


	//tsCryptoString &tsCryptoString::InsertAt(size_t offset, const char *value, long len)
	{
		{
			tsCryptoString tmp = "test";
			const char *value = "123";
			tmp.InsertAt(0, value, 3);
			EXPECT_STREQ("123test", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *value = "123";
			tmp.InsertAt(3, value, 3);
			EXPECT_STREQ("tes123t", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *value = "123";
			tmp.InsertAt(4, value, 3);
			EXPECT_STREQ("test123", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *value = "123";
			tmp.InsertAt(10, value, 3); //index greater than size
			EXPECT_STREQ("test123", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *value = "123";
			tmp.InsertAt(0, value, 2);
			EXPECT_STREQ("12test", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *value = "123";
			tmp.InsertAt(3, value, 2);
			EXPECT_STREQ("tes12t", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *value = "123";
			tmp.InsertAt(4, value, 2);
			EXPECT_STREQ("test12", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *value = "123";
			tmp.InsertAt(10, value, 2); //index greater than size
			EXPECT_STREQ("test12", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *value = NULL; //empty string
			tmp.InsertAt(0, value, 1);
			EXPECT_STREQ("test", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *value = NULL; //empty string
			tmp.InsertAt(3, value, 1);
			EXPECT_STREQ("test", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *value = NULL; //empty string
			tmp.InsertAt(4, value, 1);
			EXPECT_STREQ("test", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *value = NULL; //empty string
			tmp.InsertAt(10, value, 1); //index greater than size
			EXPECT_STREQ("test", tmp.c_str());
		}
	}

	//tsCryptoString &tsCryptoString::InsertAt(size_t offset, const tsCryptoString &value)
	{
		{
			tsCryptoString tmp = "test";
			tsCryptoString value = "123";
			tmp.InsertAt(0, value);
			EXPECT_STREQ("123test", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString value = "123";
			tmp.InsertAt(3, value);
			EXPECT_STREQ("tes123t", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString value = "123";
			tmp.InsertAt(4, value);
			EXPECT_STREQ("test123", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString value = "123";
			tmp.InsertAt(10, value); //index greater than size
			EXPECT_STREQ("test123", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString value = NULL; //empty string
			tmp.InsertAt(0, value);
			EXPECT_STREQ("test", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString value = NULL; //empty string
			tmp.InsertAt(3, value);
			EXPECT_STREQ("test", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString value = NULL; //empty string
			tmp.InsertAt(4, value);
			EXPECT_STREQ("test", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString value = NULL; //empty string
			tmp.InsertAt(10, value); //index greater than size
			EXPECT_STREQ("test", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			int tmpOldSize = (int)tmp.size();
			tsCryptoString value("1" "\0" "23", 4);
			tmp.InsertAt(0, value);
			EXPECT_EQ(tmp.size(), tmpOldSize + value.size());
			EXPECT_EQ(0, memcmp("1" "\0" "23test", tmp.c_str(), tmp.size()));
		}
		{
			tsCryptoString tmp = "test";
			int tmpOldSize = (int)tmp.size();
			tsCryptoString value("1" "\0" "23", 4);
			tmp.InsertAt(3, value);
			EXPECT_EQ(tmp.size(), tmpOldSize + value.size());
			EXPECT_EQ(0, memcmp("tes1" "\0" "23t", tmp.c_str(), tmp.size()));
		}
		{
			tsCryptoString tmp = "test";
			int tmpOldSize = (int)tmp.size();
			tsCryptoString value("1" "\0" "23", 4);
			tmp.InsertAt(4, value);
			EXPECT_EQ(tmp.size(), tmpOldSize + value.size());
			EXPECT_EQ(0, memcmp("test1" "\0" "23", tmp.c_str(), tmp.size()));
		}
		{
			tsCryptoString tmp = "test";
			int tmpOldSize = (int)tmp.size();
			tsCryptoString value("1" "\0" "23", 4);
			tmp.InsertAt(10, value); //index greater than size
			EXPECT_EQ(tmp.size(), tmpOldSize + value.size());
			EXPECT_EQ(0, memcmp("test1" "\0" "23", tmp.c_str(), tmp.size()));
		}
	}
}

TEST(tsCryptoString, DeleteAt)
{
	{
		tsCryptoString tmp = "test";
		tmp.DeleteAt(0, 0);
		EXPECT_STREQ("test", tmp.c_str());
	}
	{
		tsCryptoString tmp = "test";
		tmp.DeleteAt(3, 0);
		EXPECT_STREQ("test", tmp.c_str());
	}
	{
		tsCryptoString tmp = "test";
		tmp.DeleteAt(0, 1);
		EXPECT_STREQ("est", tmp.c_str());
	}
	{
		tsCryptoString tmp = "test";
		tmp.DeleteAt(0, 2);
		EXPECT_STREQ("st", tmp.c_str());
	}
	{
		tsCryptoString tmp = "test";
		tmp.DeleteAt(0, 4);
		EXPECT_STREQ("", tmp.c_str());
	}
	{
		tsCryptoString tmp = "test";
		tmp.DeleteAt(0, 10);
		EXPECT_STREQ("", tmp.c_str());
	}
	{
		tsCryptoString tmp = "test";
		tmp.DeleteAt(3, 1);
		EXPECT_STREQ("tes", tmp.c_str());
	}
	{
		tsCryptoString tmp = "test";
		tmp.DeleteAt(2, 2);
		EXPECT_STREQ("te", tmp.c_str());
	}
	{
		tsCryptoString tmp = "test";
		tmp.DeleteAt(4, 1);
		EXPECT_STREQ("test", tmp.c_str());
	}
	{
		tsCryptoString tmp("te" "\0" "st", 5);
		tmp.DeleteAt(0, 2);
		EXPECT_EQ(0, memcmp("\0" "st", tmp.c_str(), tmp.size()));
	}
	{
		tsCryptoString tmp("te" "\0" "st", 5);
		tmp.DeleteAt(2, 2);
		EXPECT_EQ(0, memcmp("tet", tmp.c_str(), tmp.size()));
	}
}

TEST(tsCryptoString, Replace)
{

	//tsCryptoString &tsCryptoString::Replace(size_t i_Begin, size_t i_End, const char *i_newData, long i_newDataLength)
	{
		{
			tsCryptoString tmp = "test";
			const char *newdata = "1234";
			long newDataLength = 4;
			tmp.Replace(0, 4, newdata, newDataLength);
			EXPECT_STREQ("1234", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *newdata = "12";
			long newDataLength = 2;
			tmp.Replace(0, 1, newdata, newDataLength);
			EXPECT_STREQ("12st", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *newdata = "12";
			long newDataLength = 2;
			tmp.Replace(2, 3, newdata, newDataLength);
			EXPECT_STREQ("te12", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *newdata = "12";
			long newDataLength = 2;
			tmp.Replace(3, 4, newdata, newDataLength);
			EXPECT_STREQ("tes12", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *newdata = "12";
			long newDataLength = 2;
			tmp.Replace(4, 5, newdata, newDataLength); //i_begin out of bounds
			EXPECT_STREQ("test", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *newdata = "12";
			long newDataLength = 2;
			tmp.Replace(3, 2, newdata, newDataLength); //i_begin < i_end
			EXPECT_STREQ("test", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *newdata = "1";
			long newDataLength = 1;
			tmp.Replace(0, 3, newdata, newDataLength);
			EXPECT_STREQ("1", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *newdata = "1";
			long newDataLength = 1;
			tmp.Replace(0, 2, newdata, newDataLength);
			EXPECT_STREQ("1t", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *newdata = "12";
			long newDataLength = 1; //dataLength too small
			tmp.Replace(0, 0, newdata, newDataLength);
			EXPECT_STREQ("1est", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *newdata = "12";
			long newDataLength = 3; //dataLength too long
			tmp.Replace(0, 2, newdata, newDataLength);
			EXPECT_EQ(4, tmp.size());
			EXPECT_EQ(0, memcmp(tmp.c_str(), "12" "\0" "t", tmp.size()));
		}
		{
			tsCryptoString tmp = "test";
			const char *newdata = "12";
			long newDataLength = 3; //dataLength long
			tmp.Replace(3, 6, newdata, newDataLength); // i_end out of bounds
			EXPECT_EQ(6, tmp.size());
			EXPECT_EQ(0, memcmp(tmp.c_str(), "tes12", tmp.size()));
		}
	}

	//tsCryptoString &tsCryptoString::Replace(const char *find, const char *replacement, long count)
	{
		{
			tsCryptoString tmp = "test";
			const char *find = "e";
			const char *replace = "1";
			tmp.Replace(find, replace, 1);
			EXPECT_STREQ("t1st", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *find = "a"; //does not exist in tmp
			const char *replace = "1";
			tmp.Replace(find, replace, 1);
			EXPECT_STREQ("test", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *find = "t";
			const char *replace = "1";
			tmp.Replace(find, replace, 1);
			EXPECT_STREQ("1est", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *find = "t";
			const char *replace = "1";
			tmp.Replace(find, replace, 5);
			EXPECT_STREQ("1es1", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *find = "t";
			const char *replace = "1";
			tmp.Replace(find, replace, -1);
			EXPECT_STREQ("1es1", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *find = "t";
			const char *replace = "1";
			tmp.Replace(find, replace, 0);
			EXPECT_STREQ("test", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *find = "t";
			const char *replace = "123";
			tmp.Replace(find, replace, -1);
			EXPECT_STREQ("123es123", tmp.c_str());
		}
		{
			tsCryptoString tmp = "11111111";
			const char *find = "1";
			const char *replace = "22";
			tmp.Replace(find, replace, -1);
			EXPECT_STREQ("2222222222222222", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *find = "te";
			const char *replace = "12";
			tmp.Replace(find, replace, 1);
			EXPECT_STREQ("12st", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *find = "st";
			const char *replace = NULL;
			tmp.Replace(find, replace, 1);
			EXPECT_EQ(2, tmp.size());
			EXPECT_STREQ("te", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			const char *find = "e";
			const char *replace = NULL; //empty string
			tmp.Replace(find, replace, 1);
			EXPECT_EQ(3, tmp.size());
			EXPECT_STREQ("tst", tmp.c_str());
		}
	}
	//tsCryptoString &tsCryptoString::Replace(const tsCryptoString &find, const tsCryptoString &replacement, long count)
	{
		{
			tsCryptoString tmp = "test";
			tsCryptoString find = "e";
			tsCryptoString replace = "1";
			tmp.Replace(find, replace, 1);
			EXPECT_STREQ("t1st", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString find = "a"; //does not exist in tmp
			tsCryptoString replace = "1";
			tmp.Replace(find, replace, 1);
			EXPECT_STREQ("test", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString find = "t";
			tsCryptoString replace = "1";
			tmp.Replace(find, replace, 1);
			EXPECT_STREQ("1est", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString find = "t";
			tsCryptoString replace = "1";
			tmp.Replace(find, replace, 5);
			EXPECT_STREQ("1es1", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString find = "t";
			tsCryptoString replace = "1";
			tmp.Replace(find, replace, -1);
			EXPECT_STREQ("1es1", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString find = "t";
			tsCryptoString replace = "1";
			tmp.Replace(find, replace, 0);
			EXPECT_STREQ("test", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString find = "t";
			tsCryptoString replace = "123";
			tmp.Replace(find, replace, -1);
			EXPECT_STREQ("123es123", tmp.c_str());
		}
		{
			tsCryptoString tmp = "11111111";
			tsCryptoString find = "1";
			tsCryptoString replace = "22";
			tmp.Replace(find, replace, -1);
			EXPECT_STREQ("2222222222222222", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString find = "te";
			tsCryptoString replace = "12";
			tmp.Replace(find, replace, 1);
			EXPECT_STREQ("12st", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString find = "st";
			tsCryptoString replace = NULL;
			tmp.Replace(find, replace, 1);
			EXPECT_EQ(2, tmp.size());
			EXPECT_STREQ("te", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString find = "e";
			tsCryptoString replace = NULL; //empty string
			tmp.Replace(find, replace, 1);
			EXPECT_EQ(3, tmp.size());
			EXPECT_STREQ("tst", tmp.c_str());
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString find = "e";
			tsCryptoString replace("1" "\0" "23", 4);
			tmp.Replace(find, replace, -1);
			EXPECT_EQ(7, tmp.size());
			EXPECT_EQ(0, memcmp("t1" "\0" "23st", tmp.c_str(), tmp.size()));
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString find = "t";
			tsCryptoString replace("1" "\0" "23", 4);
			tmp.Replace(find, replace, -1);
			EXPECT_EQ(10, tmp.size());
			EXPECT_EQ(0, memcmp("1" "\0" "23es1" "\0" "23", tmp.c_str(), tmp.size()));
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString find = "z";
			tsCryptoString replace("1" "\0" "23", 4);
			tmp.Replace(find, replace, -1);
			EXPECT_EQ(4, tmp.size());
			EXPECT_STREQ("test", tmp.c_str());
		}
	}
}

TEST(tsCryptoString, find)
{

	//size_type find(value_type ch, size_type pos = 0) const;
	{
		{
			tsCryptoString tmp = "test";
			char c = 'e';
			size_t ptr = tmp.find(c, 0);
			EXPECT_EQ(1, ptr);
		}
		{
			tsCryptoString tmp = "test";
			char c = 't';
			size_t ptr = tmp.find(c, 0);
			EXPECT_EQ(0, ptr);
		}
		{
			tsCryptoString tmp = "test";
			char c = 't';
			size_t ptr = tmp.find(c, 1);
			EXPECT_EQ(3, ptr);
		}
		{
			tsCryptoString tmp = "test";
			char c = 'a';
			size_t ptr = tmp.find(c, 0);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp = "test";
			char c = 't';
			size_t ptr = tmp.find(c, 4);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp = "test";
			char c = 0;
			size_t ptr = tmp.find(c, 0);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp("t" "\0" "est", 5);
			char c = 0;
			size_t ptr = tmp.find(c, 0);
			EXPECT_EQ(1, ptr);
		}
	}

	// 	size_type find(const_pointer s, size_type pos = 0) const;
	{
		tsCryptoString tmp = "test";
		EXPECT_EQ(1, tmp.find("e", 0));
		EXPECT_EQ(1, tmp.find("e", 1));
		EXPECT_EQ(tsCryptoString::npos, tmp.find("e", 2));

		EXPECT_EQ(3, tmp.find("t", 1));
		EXPECT_EQ(1, tmp.find("es", 0));


		tmp = "testtest123";
		EXPECT_EQ(5, tmp.find("es", 3));
		EXPECT_EQ(5, tmp.find("es", 2));
		EXPECT_EQ(tsCryptoString::npos, tmp.find("eses", 0));

		tmp.assign("test" "\0" "test123", 12);
		EXPECT_THROW(tmp.find(nullptr, 0, 0), tscrypto::ArgumentNullException);
		EXPECT_EQ(tsCryptoString::npos, tmp.find("", 0));
	}

	// size_type find(const_pointer s, size_type pos, size_type count) const;
	{
		{
			tsCryptoString tmp = "test";
			const char *in_data = "e";
			size_t ptr = tmp.find(in_data, 0, 1);
			EXPECT_EQ(1, ptr);
		}
		{
			tsCryptoString tmp = "test";
			const char *in_data = "t";
			size_t ptr = tmp.find(in_data, 1, 1);
			EXPECT_EQ(3, ptr);
		}
		{
			tsCryptoString tmp = "test";
			const char *in_data = "es";
			size_t ptr = tmp.find(in_data, 0, 2);
			EXPECT_EQ(1, ptr);
		}
		{
			tsCryptoString tmp = "testtest123";
			const char *in_data = "es33";
			size_t ptr = tmp.find(in_data, 3, 2);
			EXPECT_EQ(5, ptr);
		}
		{
			tsCryptoString tmp = "testtest123";
			const char *in_data = "es";
			size_t ptr = tmp.find(in_data, 2, 2);
			EXPECT_EQ(5, ptr);
		}
		{
			tsCryptoString tmp = "testtest123";
			const char *in_data = "eses";
			size_t ptr = tmp.find(in_data, 0, 4);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp("test" "\0" "test123", 12);
			const char *in_data = NULL;
			EXPECT_THROW(tmp.find(in_data, 0, 0), tscrypto::ArgumentNullException);
		}
	}

	// size_type find(const tsCryptoString& str, size_type pos = 0) const;
	{
		{
			tsCryptoString tmp = "test";
			tsCryptoString in_data = "e";
			size_t ptr = tmp.find(in_data, 0);
			EXPECT_EQ(1, ptr);
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString in_data = "t";
			size_t ptr = tmp.find(in_data, 1);
			EXPECT_EQ(3, ptr);
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString in_data = "t";
			size_t ptr = tmp.find(in_data, 6);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString in_data = "es";
			size_t ptr = tmp.find(in_data, 0);
			EXPECT_EQ(1, ptr);
		}
		{
			tsCryptoString tmp = "testtest123";
			tsCryptoString in_data = "es";
			size_t ptr = tmp.find(in_data, 1);
			EXPECT_EQ(1, ptr);
		}
		{
			tsCryptoString tmp = "testtest123";
			tsCryptoString in_data = "es";
			size_t ptr = tmp.find(in_data, 2);
			EXPECT_EQ(5, ptr);
		}
		{
			tsCryptoString tmp = "testtest123";
			tsCryptoString in_data = "eses";
			size_t ptr = tmp.find(in_data, 0);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp = "testtest123";
			tsCryptoString in_data = NULL;
			size_t ptr = tmp.find(in_data, 0);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp("test" "\0" "test123", 12);
			tsCryptoString in_data = NULL;
			size_t ptr = tmp.find(in_data, 0);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp("test" "\0" "test123", 12);
			tsCryptoString in_data("\0", 1);
			size_t ptr = tmp.find(in_data, 0);
			EXPECT_EQ(4, ptr);
		}
		{
			tsCryptoString tmp("\0\0\0\0" "c", 5);
			tsCryptoString in_data("\0" "c", 2);
			size_t ptr = tmp.find(in_data, 0);
			EXPECT_EQ(3, ptr);
		}
	}
}

TEST(tsCryptoString, rfind)
{
	// size_type rfind(value_type ch, size_type pos = npos) const;
	{
		{
			tsCryptoString tmp = "test";
			char c = 'e';
			size_t ptr = tmp.rfind(c, tmp.length()); //start at index of size
			EXPECT_EQ(1, ptr);
		}
		{
			tsCryptoString tmp = "test";
			char c = 'e';
			size_t ptr = tmp.rfind(c, tmp.length() - 1); //start at correct last index
			EXPECT_EQ(1, ptr);
		}
		{
			tsCryptoString tmp = "test";
			char c = 't';
			size_t ptr = tmp.rfind(c, tmp.length() - 1);
			EXPECT_EQ(3, ptr);
		}
		{
			tsCryptoString tmp = "test";
			char c = 't';
			size_t ptr = tmp.rfind(c, tmp.length() - 2);
			EXPECT_EQ(0, ptr);
		}
		{
			tsCryptoString tmp = "test";
			char c = 'a';
			size_t ptr = tmp.rfind(c, tmp.length() - 1);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp = "test";
			char c = 't';
			size_t ptr = tmp.rfind(c, 0);
			EXPECT_EQ(0, ptr);
		}
		{
			tsCryptoString tmp = "test";
			char c = 0;
			size_t ptr = tmp.rfind(c, tmp.length() - 1);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp("t" "\0" "est", 5);
			char c = 0;
			size_t ptr = tmp.rfind(c, tmp.length() - 1);
			EXPECT_EQ(1, ptr);
		}
	}

	//size_type rfind(const_pointer s, size_type pos = npos) const;
	// TODO:  Need tests for this one




	// size_type rfind(const_pointer s, size_type pos, size_type count) const;
	{
		{
			tsCryptoString tmp = "test";
			const char *in_data = "e";
			size_t ptr = tmp.rfind(in_data, tmp.size() - 1, 1); //correct starting index
			EXPECT_EQ(1, ptr);
		}
		{
			tsCryptoString tmp = "test";
			const char *in_data = "e";
			size_t ptr = tmp.rfind(in_data, tmp.size() - 1, 2); //correct starting index
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp = "test";
			const char *in_data = "e";
			size_t ptr = tmp.rfind(in_data, tmp.size(), 1); //starting index one greater than tmp
			EXPECT_EQ(1, ptr);
		}
		{
			tsCryptoString tmp = "test";
			const char *in_data = "t";
			size_t ptr = tmp.rfind(in_data, tmp.size() - 1, 1);
			EXPECT_EQ(3, ptr);
		}
		{
			tsCryptoString tmp = "test";
			const char *in_data = "t";
			size_t ptr = tmp.rfind(in_data, tmp.size() - 1, 1);
			EXPECT_EQ(3, ptr);
		}
		{
			tsCryptoString tmp = "test";
			const char *in_data = "t";
			size_t ptr = tmp.rfind(in_data, tmp.size() - 2, 1);
			EXPECT_EQ(0, ptr);
		}
		{
			tsCryptoString tmp = "test";
			const char *in_data = "t";
			size_t ptr = tmp.rfind(in_data, tmp.size() - 1, 2);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp = "test";
			const char *in_data = "t";
			size_t ptr = tmp.rfind(in_data, tmp.size() - 2, 2);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp = "test";
			const char *in_data = "es";
			size_t ptr = tmp.rfind(in_data, tmp.size() - 1, 2);
			EXPECT_EQ(1, ptr);
		}
		{
			tsCryptoString tmp = "testtest123";
			const char *in_data = "es";
			size_t ptr = tmp.rfind(in_data, tmp.size() - 1, 2);
			EXPECT_EQ(5, ptr);
		}
		{
			tsCryptoString tmp = "testtest123";
			const char *in_data = "es";
			size_t ptr = tmp.rfind(in_data, 4, 2);
			EXPECT_EQ(1, ptr);
		}
		{
			tsCryptoString tmp = "testtest123";
			const char *in_data = "eses";
			size_t ptr = tmp.rfind(in_data, tmp.size() - 1, 2);
			EXPECT_EQ(5, ptr);
		}
		{
			tsCryptoString tmp = "testtest123";
			const char *in_data = "eses";
			size_t ptr = tmp.rfind(in_data, tmp.size() - 1, 3);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp = "testtest123";
			const char *in_data = NULL;
			EXPECT_THROW(tmp.rfind(in_data, tmp.size() - 1, 0), tscrypto::ArgumentNullException);
		}
	}


	// size_type rfind(const tsCryptoString& str, size_type pos = npos) const;
	{
		{
			tsCryptoString tmp = "test";
			tsCryptoString in_data = "e";
			size_t ptr = tmp.rfind(in_data, tmp.size());//start pos greater than size by 1
			EXPECT_EQ(1, ptr);
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString in_data = "e";
			size_t ptr = tmp.rfind(in_data, tmp.size() - 1);
			EXPECT_EQ(1, ptr);
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString in_data = "e";
			size_t ptr = tmp.rfind(in_data, 0);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString in_data = "es";
			size_t ptr = tmp.rfind(in_data, tmp.size() - 1);
			EXPECT_EQ(1, ptr);
		}
		{
			tsCryptoString tmp = "testtest123";
			tsCryptoString in_data = "eses";
			size_t ptr = tmp.rfind(in_data, tmp.size() - 1);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp = "testtest123";
			tsCryptoString in_data = NULL;
			size_t ptr = tmp.rfind(in_data, tmp.size() - 1);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp("test" "\0" "test123", 12);
			tsCryptoString in_data = NULL;
			size_t ptr = tmp.rfind(in_data, tmp.size() - 1);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp = "testtest123";
			tsCryptoString in_data("\0", 1);
			size_t ptr = tmp.rfind(in_data, tmp.size() - 1);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp("\0\0\0\0" "c", 5);
			tsCryptoString in_data("\0" "c", 2);
			size_t ptr = tmp.rfind(in_data, tmp.size() - 1);
			EXPECT_EQ(3, ptr);
		}
	}
}

TEST(tsCryptoString, find_first_not_of)
{

	//size_t  tsCryptoString::find_first_not_of(char in_data, size_t pos) const
	{
		{
			tsCryptoString tmp = "test";
			char in_data = 't';
			size_t ptr = tmp.find_first_not_of(in_data, 0);
			EXPECT_EQ(1, ptr);
		}
		{
			tsCryptoString tmp = "test";
			char in_data = 'c';
			size_t ptr = tmp.find_first_not_of(in_data, 0);
			EXPECT_EQ(0, ptr);
		}
		{
			tsCryptoString tmp = "test";
			char in_data = 't';
			size_t ptr = tmp.find_first_not_of(in_data, 1);
			EXPECT_EQ(1, ptr);
		}
		{
			tsCryptoString tmp = "test";
			char in_data = 'e';
			size_t ptr = tmp.find_first_not_of(in_data, 1);
			EXPECT_EQ(2, ptr);
		}
		{
			tsCryptoString tmp = "test";
			char in_data = 'e';
			size_t ptr = tmp.find_first_not_of(in_data, tmp.size());
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp = "a";
			char in_data = 'a';
			size_t ptr = tmp.find_first_not_of(in_data, 0);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp = "abcd";
			char in_data = 0;
			size_t ptr = tmp.find_first_not_of(in_data, 0);
			EXPECT_EQ(0, ptr);
		}
		{
			tsCryptoString tmp("\0" "abcd", 5);
			char in_data = 0;
			size_t ptr = tmp.find_first_not_of(in_data, 0);
			EXPECT_EQ(1, ptr);
		}
		{
			tsCryptoString tmp("a" "\0" "bcd", 5);
			char in_data = 'a';
			size_t ptr = tmp.find_first_not_of(in_data, 0);
			EXPECT_EQ(1, ptr);
		}
	}

	//size_t  tsCryptoString::find_first_not_of(const char *in_data, size_t pos, size_t count) const
	{
		{
			tsCryptoString tmp = "test";
			const char *in_data = "te";
			size_t ptr = tmp.find_first_not_of(in_data, 0);
			EXPECT_EQ(2, ptr);
		}
		{
			tsCryptoString tmp = "test";
			const char *in_data = "es";
			size_t ptr = tmp.find_first_not_of(in_data, 0);
			EXPECT_EQ(0, ptr);
		}
		{
			tsCryptoString tmp = "test";
			const char *in_data = "te";
			size_t ptr = tmp.find_first_not_of(in_data, 1);
			EXPECT_EQ(2, ptr);
		}
		{
			tsCryptoString tmp = "test";
			const char *in_data = "et";
			size_t ptr = tmp.find_first_not_of(in_data, 0);
			EXPECT_EQ(2, ptr);
		}
		{
			tsCryptoString tmp = "test";
			const char *in_data = "es";
			size_t ptr = tmp.find_first_not_of(in_data, 1);
			EXPECT_EQ(3, ptr);
		}
		{
			tsCryptoString tmp = "test";
			const char *in_data = "e";
			size_t ptr = tmp.find_first_not_of(in_data, tmp.size());
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp = "a";
			const char *in_data = "a";
			size_t ptr = tmp.find_first_not_of(in_data, 0);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp = "abcd";
			const char *in_data = NULL;
			size_t ptr = tmp.find_first_not_of(in_data, 0);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp("\0" "abcd", 5);
			const char *in_data = NULL;
			size_t ptr = tmp.find_first_not_of(in_data, 0);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp("ab" "\0" "cd", 5);
			const char *in_data = "ab";
			size_t ptr = tmp.find_first_not_of(in_data, 0);
			EXPECT_EQ(2, ptr);
		}
	}
	//size_t  tsCryptoString::find_first_not_of(const tsCryptoString &in_data, size_t pos, size_t count) const
	{
		{
			tsCryptoString tmp = "test";
			tsCryptoString in_data = "te";
			size_t ptr = tmp.find_first_not_of(in_data, 0);
			EXPECT_EQ(2, ptr);
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString in_data = "es";
			size_t ptr = tmp.find_first_not_of(in_data, 0);
			EXPECT_EQ(0, ptr);
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString in_data = "te";
			size_t ptr = tmp.find_first_not_of(in_data, 1);
			EXPECT_EQ(2, ptr);
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString in_data = "et";
			size_t ptr = tmp.find_first_not_of(in_data, 0);
			EXPECT_EQ(2, ptr);
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString in_data = "es";
			size_t ptr = tmp.find_first_not_of(in_data, 1);
			EXPECT_EQ(3, ptr);
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString in_data = "e";
			size_t ptr = tmp.find_first_not_of(in_data, tmp.size());
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp = "a";
			tsCryptoString in_data = "a";
			size_t ptr = tmp.find_first_not_of(in_data, 0);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp = "abcd";
			tsCryptoString in_data = NULL;
			size_t ptr = tmp.find_first_not_of(in_data, 0);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp("\0" "abcd", 5);
			tsCryptoString in_data = NULL;
			size_t ptr = tmp.find_first_not_of(in_data, 0);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp("ab" "\0" "cd", 5);
			tsCryptoString in_data = "ab";
			size_t ptr = tmp.find_first_not_of(in_data, 0);
			EXPECT_EQ(2, ptr);
		}
		{
			tsCryptoString tmp("\0\0\0\0" "c", 5);
			tsCryptoString in_data("\0", 1);
			size_t ptr = tmp.find_first_not_of(in_data, 0);
			EXPECT_EQ(4, ptr);
		}
		{
			tsCryptoString tmp("\0\0\0\0" "c", 5);
			tsCryptoString in_data("\0" "c", 2);
			size_t ptr = tmp.find_first_not_of(in_data, 0);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
	}
}

TEST(tsCryptoString, find_last_not_of)
{
	//size_t  tsCryptoString::find_last_not_of(char in_data, size_t pos) const
	{
		{
			tsCryptoString tmp = "test";
			char in_data = 't';
			size_t ptr = tmp.find_last_not_of(in_data, tmp.size() - 1);
			EXPECT_EQ(2, ptr);
		}
		{
			tsCryptoString tmp = "test";
			char in_data = 't';
			size_t ptr = tmp.find_last_not_of(in_data, tmp.size()); //position 1 saze too big
			EXPECT_EQ(2, ptr);
		}
		{
			tsCryptoString tmp = "test";
			char in_data = 't';
			size_t ptr = tmp.find_last_not_of(in_data, 100); //position too big
			EXPECT_EQ(2, ptr);
		}
		{
			tsCryptoString tmp = "test";
			char in_data = 'c';
			size_t ptr = tmp.find_last_not_of(in_data, tmp.size() - 1);
			EXPECT_EQ(3, ptr);
		}
		{
			tsCryptoString tmp = "test";
			char in_data = 'e';
			size_t ptr = tmp.find_last_not_of(in_data, 0);
			EXPECT_EQ(0, ptr);
		}
		{
			tsCryptoString tmp = "test";
			char in_data = 't';
			size_t ptr = tmp.find_last_not_of(in_data, 0);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp = "a";
			char in_data = 'a';
			size_t ptr = tmp.find_last_not_of(in_data, tmp.size() - 1);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp = "abcd";
			char in_data = 0;
			size_t ptr = tmp.find_last_not_of(in_data, tmp.size() - 1);
			EXPECT_EQ(3, ptr);
		}
		{
			tsCryptoString tmp("\0" "abcd", 5);
			char in_data = 0;
			size_t ptr = tmp.find_last_not_of(in_data, tmp.size() - 1);
			EXPECT_EQ(4, ptr);
		}
		{
			tsCryptoString tmp("a" "\0" "bcd", 5);
			char in_data = 'g';
			size_t ptr = tmp.find_last_not_of(in_data, tmp.size() - 1);
			EXPECT_EQ(4, ptr);
		}
	}


	//size_t  tsCryptoString::find_last_not_of(const char *in_data, size_t pos, size_t count) const
	{
		{
			tsCryptoString tmp = "test";
			const char *in_data = "te";
			size_t ptr = tmp.find_last_not_of(in_data, tmp.size() - 1);
			EXPECT_EQ(2, ptr);
		}
		{
			tsCryptoString tmp = "test";
			const char *in_data = "es";
			size_t ptr = tmp.find_last_not_of(in_data, tmp.size() - 1);
			EXPECT_EQ(3, ptr);
		}
		{
			tsCryptoString tmp = "test";
			const char *in_data = "ts";
			size_t ptr = tmp.find_last_not_of(in_data, tmp.size() - 1);
			EXPECT_EQ(1, ptr);
		}
		{
			tsCryptoString tmp = "test";
			const char *in_data = "a";
			size_t ptr = tmp.find_last_not_of(in_data, 0);
			EXPECT_EQ(0, ptr);
		}
		{
			tsCryptoString tmp = "a";
			const char *in_data = "a";
			size_t ptr = tmp.find_last_not_of(in_data, tmp.size() - 1);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp = "abcd";
			const char *in_data = NULL;
			size_t ptr = tmp.find_last_not_of(in_data, tmp.size() - 1);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp("\0" "abcd", 5);
			const char *in_data = NULL;
			size_t ptr = tmp.find_last_not_of(in_data, tmp.size() - 1);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp("ab" "\0" "cd", 5);
			const char *in_data = "ab";
			size_t ptr = tmp.find_last_not_of(in_data, tmp.size() - 1);
			EXPECT_EQ(4, ptr);
		}
		{
			tsCryptoString tmp("ab" "\0" "cd", 5);
			const char *in_data = "dc";
			size_t ptr = tmp.find_last_not_of(in_data, tmp.size() - 1);
			EXPECT_EQ(2, ptr);
		}
	}
	//size_t  tsCryptoString::find_last_not_of(const tsCryptoString &in_data, size_t pos, size_t count) const
	{

		{
			tsCryptoString tmp = "test";
			tsCryptoString in_data = "te";
			size_t ptr = tmp.find_last_not_of(in_data, tmp.size() - 1);
			EXPECT_EQ(2, ptr);
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString in_data = "es";
			size_t ptr = tmp.find_last_not_of(in_data, tmp.size() - 1);
			EXPECT_EQ(3, ptr);
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString in_data = "ts";
			size_t ptr = tmp.find_last_not_of(in_data, tmp.size() - 1);
			EXPECT_EQ(1, ptr);
		}
		{
			tsCryptoString tmp = "test";
			tsCryptoString in_data = "a";
			size_t ptr = tmp.find_last_not_of(in_data, 0);
			EXPECT_EQ(0, ptr);
		}
		{
			tsCryptoString tmp = "a";
			tsCryptoString in_data = "a";
			size_t ptr = tmp.find_last_not_of(in_data, tmp.size() - 1);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp = "abcd";
			tsCryptoString in_data = NULL;
			size_t ptr = tmp.find_last_not_of(in_data, tmp.size() - 1);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp("\0" "abcd", 5);
			tsCryptoString in_data = NULL;
			size_t ptr = tmp.find_last_not_of(in_data, tmp.size() - 1);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
		{
			tsCryptoString tmp("ab" "\0" "cd", 5);
			tsCryptoString in_data = "ab";
			size_t ptr = tmp.find_last_not_of(in_data, tmp.size() - 1);
			EXPECT_EQ(4, ptr);
		}
		{
			tsCryptoString tmp("ab" "\0" "cd", 5);
			tsCryptoString in_data = "dc";
			size_t ptr = tmp.find_last_not_of(in_data, tmp.size() - 1);
			EXPECT_EQ(2, ptr);
		}
		{
			tsCryptoString tmp("\0\0\0\0" "c", 5);
			tsCryptoString in_data("\0", 1);
			size_t ptr = tmp.find_last_not_of(in_data, tmp.size() - 1);
			EXPECT_EQ(4, ptr);
		}
		{
			tsCryptoString tmp("c" "\0\0\0\0", 5);
			tsCryptoString in_data("\0", 1);
			size_t ptr = tmp.find_last_not_of(in_data, tmp.size() - 1);
			EXPECT_EQ(0, ptr);
		}
		{
			tsCryptoString tmp("c" "\0\0\0\0", 5);
			tsCryptoString in_data("\0" "c", 2);
			size_t ptr = tmp.find_last_not_of(in_data, tmp.size() - 1);
			EXPECT_EQ(tsCryptoString::npos, ptr);
		}
	}
}

TEST(tsCryptoString, Format)
{


	//tsCryptoString &tsCryptoString::Format(const char *msg, ...)
	{
		//todo ...
		{
			tsCryptoString tmp;
			const char *msg = "abc";
			tmp.Format(msg);
			EXPECT_STREQ("abc", tmp.c_str());
		}
		{
			tsCryptoString tmp;
			const char *msg = "a\nbc";
			tmp.Format(msg);
			EXPECT_STREQ("a\nbc", tmp.c_str());
		}
	}
	//tsCryptoString &tsCryptoString::Format(const ts_wchar *msg, va_list arg)
	{
		//todo
	}
	//tsCryptoString &tsCryptoString::Format(const char *msg, va_list arg)
	{
		//todo
	}
}

TEST(tsCryptoString, ToUpper)
{
	//tsCryptoString &tsCryptoString::ToUpper()
	{
		{
			tsCryptoString tmp = "abc";
			tmp.ToUpper();
			EXPECT_STREQ("ABC", tmp.c_str());
		}
		{
			tsCryptoString tmp = "aBc";
			tmp.ToUpper();
			EXPECT_STREQ("ABC", tmp.c_str());
		}
		{
			tsCryptoString tmp = "abc123";
			tmp.ToUpper();
			EXPECT_STREQ("ABC123", tmp.c_str());
		}
		{
			tsCryptoString tmp = "ABC";
			tmp.ToUpper();
			EXPECT_STREQ("ABC", tmp.c_str());
		}
	}
}

TEST(tsCryptoString, ToLower)
{
	//tsCryptoString &tsCryptoString::ToLower()
	{
		{
			tsCryptoString tmp = "ABC";
			tmp.ToLower();
			EXPECT_STREQ("abc", tmp.c_str());
		}
		{
			tsCryptoString tmp = "aBc";
			tmp.ToLower();
			EXPECT_STREQ("abc", tmp.c_str());
		}
		{
			tsCryptoString tmp = "ABC123";
			tmp.ToLower();
			EXPECT_STREQ("abc123", tmp.c_str());
		}
		{
			tsCryptoString tmp = "abc";
			tmp.ToLower();
			EXPECT_STREQ("abc", tmp.c_str());
		}
	}
}

TEST(tsCryptoString, substring)
{
	//tsCryptoString tsCryptoString::substring(size_t start, size_t length) const
	{
		{
			tsCryptoString tmp = "abc123";
			tsCryptoString sub = tmp.substring(0, 3);
			EXPECT_STREQ("abc", sub.c_str());
		}
		{
			tsCryptoString tmp = "abc123";
			tsCryptoString sub = tmp.substring(3, 6);
			EXPECT_STREQ("123", sub.c_str());
		}
		{
			tsCryptoString tmp = "abc123";
			tsCryptoString sub = tmp.substring(0, 0);
			EXPECT_STREQ("", sub.c_str());
		}
		{
			tsCryptoString tmp = "abc123";
			tsCryptoString sub = tmp.substring(0, 1);
			EXPECT_STREQ("a", sub.c_str());
		}
		{
			tsCryptoString tmp = "abc123";
			tsCryptoString sub = tmp.substring(5, 1);
			EXPECT_STREQ("3", sub.c_str());
		}
		{
			tsCryptoString tmp = "abc123";
			tsCryptoString sub = tmp.substring(6, 1);
			EXPECT_STREQ("", sub.c_str());
		}
		{
			tsCryptoString tmp = "abc123";
			tsCryptoString sub = tmp.substring(5, 5);
			EXPECT_STREQ("3", sub.c_str());
		}
	}
}

TEST(tsCryptoString, right)
{
	//tsCryptoString tsCryptoString::right(size_t length) const
	{
		{
			tsCryptoString tmp = "abc123";
			tsCryptoString right = tmp.right(3);
			EXPECT_STREQ("123", right.c_str());
		}
		{
			tsCryptoString tmp = "abc123";
			tsCryptoString right = tmp.right(0);
			EXPECT_STREQ("", right.c_str());
		}
		{
			tsCryptoString tmp = "abc123";
			tsCryptoString right = tmp.right(6);
			EXPECT_STREQ("abc123", right.c_str());
		}
		{
			tsCryptoString tmp = "abc123";
			tsCryptoString right = tmp.right(10);
			EXPECT_STREQ("abc123", right.c_str());
		}
		{
			tsCryptoString tmp("ab" "\0" "12", 5);
			tsCryptoString right = tmp.right(2);
			EXPECT_STREQ("12", right.c_str());
		}
		{
			tsCryptoString tmp("ab" "\0" "12", 5);
			tsCryptoString right = tmp.right(4);
			EXPECT_EQ(0, memcmp("b" "\0" "12", right.c_str(), 4));
		}
	}
}

TEST(tsCryptoString, left)
{
	//tsCryptoString tsCryptoString::left(size_t length) const
	{
		{
			tsCryptoString tmp = "abc123";
			tsCryptoString left = tmp.left(3);
			EXPECT_STREQ("abc", left.c_str());
		}
		{
			tsCryptoString tmp = "abc123";
			tsCryptoString left = tmp.left(0);
			EXPECT_STREQ("", left.c_str());
		}
		{
			tsCryptoString tmp = "abc123";
			tsCryptoString left = tmp.left(6);
			EXPECT_STREQ("abc123", left.c_str());
		}
		{
			tsCryptoString tmp = "abc123";
			tsCryptoString left = tmp.left(10);
			EXPECT_STREQ("abc123", left.c_str());
		}
		{
			tsCryptoString tmp("ab" "\0" "12", 5);
			tsCryptoString left = tmp.left(2);
			EXPECT_STREQ("ab", left.c_str());
		}
		{
			tsCryptoString tmp("ab" "\0" "12", 5);
			tsCryptoString left = tmp.left(4);
			EXPECT_EQ(0, memcmp("ab" "\0" "1", left.c_str(), 4));
		}
	}
}

TEST(tsCryptoString, Trim)
{
	//tsCryptoString &tsCryptoString::Trim()
	{
		{
			tsCryptoString tmp("abc123\r");
			tmp.Trim();
			EXPECT_STREQ("abc123", tmp.c_str());
		}
		{
			tsCryptoString tmp("\rabc123");
			tmp.Trim();
			EXPECT_STREQ("abc123", tmp.c_str());
		}
		{
			tsCryptoString tmp("abc123       ");
			tmp.Trim();
			EXPECT_STREQ("abc123", tmp.c_str());
		}
		{
			tsCryptoString tmp("       abc123");
			tmp.Trim();
			EXPECT_STREQ("abc123", tmp.c_str());
		}
		{
			tsCryptoString tmp("abc123\n");
			tmp.Trim();
			EXPECT_STREQ("abc123", tmp.c_str());
		}
		{
			tsCryptoString tmp("\nabc123");
			tmp.Trim();
			EXPECT_STREQ("abc123", tmp.c_str());
		}
		{
			tsCryptoString tmp("abc123\t");
			tmp.Trim();
			EXPECT_STREQ("abc123", tmp.c_str());
		}
		{
			tsCryptoString tmp("\tabc123");
			tmp.Trim();
			EXPECT_STREQ("abc123", tmp.c_str());
		}
		{
			tsCryptoString tmp("abc123\r\n");
			tmp.Trim();
			EXPECT_STREQ("abc123", tmp.c_str());
		}
		{
			tsCryptoString tmp("\r\nabc123");
			tmp.Trim();
			EXPECT_STREQ("abc123", tmp.c_str());
		}
		{
			tsCryptoString tmp("abc\n123");
			tmp.Trim();
			EXPECT_STREQ("abc\n123", tmp.c_str());
		}
	}
	//tsCryptoString &tsCryptoString::Trim(const char *trimmers)
	{
		{
			tsCryptoString tmp("abc123");
			const char *trimmers = "abc";
			tmp.Trim(trimmers);
			EXPECT_STREQ("123", tmp.c_str());
		}
		{
			tsCryptoString tmp("abc123");
			const char *trimmers = "123";
			tmp.Trim(trimmers);
			EXPECT_STREQ("abc", tmp.c_str());
		}
		{
			tsCryptoString tmp("abc123\n\r");
			const char *trimmers = "\r";
			tmp.Trim(trimmers);
			EXPECT_STREQ("abc123\n", tmp.c_str());
		}
		{
			tsCryptoString tmp("abc123");
			const char *trimmers = "c";
			tmp.Trim(trimmers);
			EXPECT_STREQ("abc123", tmp.c_str());
		}
	}
}

TEST(tsCryptoString, PlusOp)
{
	{
		tsCryptoString tmp = "abc" + tsCryptoString("1");
		EXPECT_EQ(4, tmp.size());
		EXPECT_STREQ("abc1", tmp.c_str());
	}
	{
		tsCryptoString tmp = "abc" + tsCryptoString("\n");
		EXPECT_EQ(4, tmp.size());
		EXPECT_STREQ("abc\n", tmp.c_str());
		tmp = tmp + tsCryptoString("123");
		EXPECT_EQ(7, tmp.size());
		EXPECT_STREQ("abc\n123", tmp.c_str());

	}
	{
		tsCryptoString tmp = "\n" + tsCryptoString("123");
		EXPECT_EQ(4, tmp.size());
		EXPECT_STREQ("\n123", tmp.c_str());
	}
	{
		tsCryptoString tmp = "\n" + tsCryptoString(' ', 0);
		EXPECT_EQ(1, tmp.size());
		EXPECT_STREQ("\n", tmp.c_str());
	}
	{
		tsCryptoString tmp = "abc";
		tmp += "\n" + tsCryptoString(' ', 0);
		EXPECT_EQ(4, tmp.size());
		EXPECT_STREQ("abc\n", tmp.c_str());
	}
}

TEST(tsCryptoString, json)
{
	JSONObject list;
	static const char* json = "{\"tasks\":[{\"title\":\"Service Options\",\"classNames\":\"\",\"tooltip\":\"\",\"order\":1000,\"tasks\":[{\"name\":\"help\",\"title\":\"Help\",\"href\":\"javascript: veil.main.help('index');\",\"classNames\":\"\",\"tooltip\":\"Use this option to access the help index.\"},{\"name\":\"CreateFirstAdmin\",\"title\":\"Configure for Server\",\"tooltip\":\"Use this option to create the first administrator in server mode.\"},{\"name\":\"CreateFirstUser\",\"title\":\"Configure for Single User\",\"tooltip\":\"Use this option to create the first administrator in single user mode.\"},{\"name\":\"InitialSettings\",\"title\":\"Settings\",\"tooltip\":\"Use this option to configure KeyVEIL.\"},{\"name\":\"status\",\"title\":\"System Status\",\"href\":\"javascript: veil.main.loadDialog('status')\",\"classNames\":\"\",\"tooltip\":\"Use this option to retrieve status information for KeyVEIL.\"},{\"name\":\"refresh\",\"title\":\"Refresh\",\"href\":\"javascript: veil.main.loadNavigation();\",\"classNames\":\"\",\"tooltip\":\"Use this option to refresh the system for any changes in admin rights.\"}]}]}";
	
	list.FromJSON(json);

	tsCryptoString tmp = list.ToJSON();
	EXPECT_STREQ(json, tmp.c_str());
	EXPECT_STREQ(json, list.ToString().c_str());
}

TEST(tsCryptoString, CountedSplit)
{
	tsCryptoString tmp = "abcdefgh";
	tsCryptoStringList list = tmp.split("b");

	EXPECT_EQ(2, list->size());
	EXPECT_STREQ("a", list->at(0).c_str());
	EXPECT_STREQ("cdefgh", list->at(1).c_str());

	list = tmp.split("be", 3);

	EXPECT_EQ(3, list->size());
	EXPECT_STREQ("a", list->at(0).c_str());
	EXPECT_STREQ("cd", list->at(1).c_str());
	EXPECT_STREQ("fgh", list->at(2).c_str());

	list = tmp.split("bh", 2);

	EXPECT_EQ(2, list->size());
	EXPECT_STREQ("a", list->at(0).c_str());
	EXPECT_STREQ("cdefgh", list->at(1).c_str());

	list = tmp.split("bc", 2);

	EXPECT_EQ(2, list->size());
	EXPECT_STREQ("a", list->at(0).c_str());
	EXPECT_STREQ("cdefgh", list->at(1).c_str());

	list = tmp.split("bc", 3);

	EXPECT_EQ(2, list->size());
	EXPECT_STREQ("a", list->at(0).c_str());
	EXPECT_STREQ("defgh", list->at(1).c_str());

	list = tmp.split("bc", 3, true);

	EXPECT_EQ(3, list->size());
	EXPECT_STREQ("a", list->at(0).c_str());
	EXPECT_STREQ("", list->at(1).c_str());
	EXPECT_STREQ("defgh", list->at(2).c_str());

	list = tmp.split("bh", 3, true);

	EXPECT_EQ(3, list->size());
	EXPECT_STREQ("a", list->at(0).c_str());
	EXPECT_STREQ("cdefg", list->at(1).c_str());
	EXPECT_STREQ("", list->at(2).c_str());

	list = tmp.split("bh", 5, true);

	EXPECT_EQ(3, list->size());
	EXPECT_STREQ("a", list->at(0).c_str());
	EXPECT_STREQ("cdefg", list->at(1).c_str());
	EXPECT_STREQ("", list->at(2).c_str());


	list = tmp.split("bh", 5);

	EXPECT_EQ(2, list->size());
	EXPECT_STREQ("a", list->at(0).c_str());
	EXPECT_STREQ("cdefg", list->at(1).c_str());

}
#pragma warning(pop)
