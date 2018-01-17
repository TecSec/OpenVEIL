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
#include "math.h"

using namespace tscrypto;

tsCryptoDate tsCryptoDate::GetCurrentTime()
{
    TsDateStruct_t tm;
    tsGetNowInGMT(&tm);
    return tsCryptoDate(tm);
}
tsCryptoDate tsCryptoDate::DateFromZulu(const tsCryptoStringBase &zulu)
{
	tsCryptoDate tmp;

	return tmp.SetDateTimeFromZulu(zulu);
}

tsCryptoDate tsCryptoDate::DateFromZuluUTC(const tsCryptoStringBase &zulu)
{
	tsCryptoDate tmp;

	return tmp.SetDateTimeFromZuluUTC(zulu);
}

tsCryptoDate tsCryptoDate::DateFromISO8601(const tsCryptoStringBase &iso)
{
	tsCryptoDate tmp;

	return tmp.SetDateTimeFromISO8601(iso);
}

tsCryptoDate tsCryptoDate::DateFromODBC(const tsCryptoStringBase& odbc)
{
	tsCryptoString zulu;
	tsCryptoDate tmp;

	if (!ODBCDateToZulu(odbc, zulu))
		return tmp;
	tmp.SetDateTimeFromZulu(zulu);
	return tmp;
}


tsCryptoDate::tsCryptoDate() :
    m_status(invalid)
{
    memset(&m_dt, 0, sizeof(m_dt));
}

tsCryptoDate::tsCryptoDate(const tsCryptoDate& dateSrc)
{
    m_status = dateSrc.m_status;
    m_dt = dateSrc.m_dt;
}

tsCryptoDate::tsCryptoDate(const TsDateStruct_t& systimeSrc) :
    m_status (valid)
{
    m_dt = systimeSrc;
    CheckRange();
}

tsCryptoDate::tsCryptoDate(uint64_t filetimeSrc) :
    m_status(valid)
{
    memset(&m_dt, 0, sizeof(m_dt));
    tsFileTimeToDateStruct(filetimeSrc, &m_dt);
    CheckRange();
}

tsCryptoDate::tsCryptoDate(int nYear, int nMonth, int nDay, int nHour, int nMin, int nSec) :
    m_status(invalid)
{
    memset(&m_dt, 0, sizeof(m_dt));
    m_dt.year = (uint16_t)nYear;
    m_dt.month = (uint8_t)nMonth;
    m_dt.day = (uint8_t)nDay;
    m_dt.hour = (uint8_t)nHour;
    m_dt.minute = (uint8_t)nMin;
    m_dt.second = (uint8_t)nSec;
    CheckRange();
}

//#ifdef _WIN32
//tsCryptoDate::tsCryptoDate(DATE oleDate) :
//    m_status(invalid)
//{
//    memset(&m_dt, 0, sizeof(m_dt));
//    FromOleDate(oleDate);
//}
//#endif // _WIN32

tsCryptoDate::tsCryptoDate(const tsCryptoStringBase &src, ConversionType type) :
    m_status(invalid)
{
    memset(&m_dt, 0, sizeof(m_dt));
	switch (type)
	{
	case Zulu:
		SetDateTimeFromZulu(src);
		break;
	case ZuluUTC:
		SetDateTimeFromZuluUTC(src);
		break;
	case ISO8601:
		SetDateTimeFromISO8601(src);
		break;
	case ODBC:
		SetDateTimeFromODBC(src);
		break;
	default:
		m_status = invalid;
		break;
	}
}

tsCryptoDate::~tsCryptoDate()
{

}

//#ifdef _WIN32
//void *tsCryptoDate::operator new(size_t bytes)
//{
//    return FrameworkAllocator(bytes);
//}
//
//void tsCryptoDate::operator delete(void *ptr)
//{
//    return FrameworkDeallocator(ptr);
//}
//#endif // _WIN32

void tsCryptoDate::clear()
{
	m_status = invalid;
	memset(&m_dt, 0, sizeof(m_dt));
}

tsCryptoDate& tsCryptoDate::SetStatus(DateTimeStatus status)
{
    m_status = status;
	return *this;
}

tsCryptoDate::DateTimeStatus tsCryptoDate::GetStatus() const
{
    return m_status;
}

bool tsCryptoDate::GetAsSystemTime(TsDateStruct_t& sysTime) const
{
    if ( m_status != valid )
        return false;

    sysTime = m_dt;
    return true;
}
TsDateStruct_t tsCryptoDate::AsSystemTime() const
{
    if ( m_status != valid )
	{
		TsDateStruct_t dt;

		memset(&dt, 0, sizeof(m_dt));
        return dt;
	}

    return m_dt;
}

bool tsCryptoDate::GetAsZuluTime(tsCryptoStringBase &zTime) const
{
	zTime = AsZuluTime();
	return zTime.size() > 0;
}
bool tsCryptoDate::GetAsODBCTime(tsCryptoStringBase &sOdbc) const
{
	tsCryptoString zulu = AsZuluTime();
	return ZuluToODBCDate(zulu, sOdbc);
}
tsCryptoString tsCryptoDate::AsZuluTime() const
{
	tsCryptoString zTime;

    if ( m_status != valid )
        return zTime;

    zTime.Format("%04d%02d%02d%02d%02d%02dZ", m_dt.year, m_dt.month, m_dt.day, m_dt.hour, m_dt.minute, m_dt.second);
    return zTime;
}

tsCryptoString tsCryptoDate::AsODBCTime() const
{
	tsCryptoString zTime;
	tsCryptoString odbc;

	if (m_status != valid)
		return zTime;

	zTime.Format("%04d%02d%02d%02d%02d%02dZ", m_dt.year, m_dt.month, m_dt.day, m_dt.hour, m_dt.minute, m_dt.second);
	if (!ZuluToODBCDate(zTime, odbc))
		return "";
	return odbc;
}

bool tsCryptoDate::GetAsZuluUTCTime(tsCryptoStringBase &zTime) const
{
	zTime = AsZuluUTCTime();
	return zTime.size() > 0;
}
tsCryptoString tsCryptoDate::AsZuluUTCTime() const
{
	tsCryptoString zTime;

    if ( m_status != valid )
        return zTime;

    zTime.Format("%02d%02d%02d%02d%02d%02dZ", m_dt.year % 100, m_dt.month, m_dt.day, m_dt.hour, m_dt.minute, m_dt.second);
    return zTime;
}

bool tsCryptoDate::GetAsISO8601Time(tsCryptoStringBase &isoTime) const
{
	isoTime = AsISO8601Time();
	return isoTime.size() > 0;
}
tsCryptoString tsCryptoDate::AsISO8601Time() const
{
	tsCryptoString isoTime;

    if ( m_status != valid )
        return isoTime;

    isoTime.Format("%04d-%02d-%02dT%02d:%02d:%02dZ", m_dt.year, m_dt.month, m_dt.day, m_dt.hour, m_dt.minute, m_dt.second);
    return isoTime;
}

tsCryptoString tsCryptoDate::ToZuluTime() const
{
    tsCryptoString zTime;

    if ( m_status != valid )
        return zTime;

    zTime.Format("%04d%02d%02d%02d%02d%02dZ", m_dt.year, m_dt.month, m_dt.day, m_dt.hour, m_dt.minute, m_dt.second);
    return zTime;
}

tsCryptoString tsCryptoDate::ToODBC() const
{
	tsCryptoString zulu;
	tsCryptoString odbc;

	if (m_status != valid)
		return "";

	zulu = ToZuluTime();
	if (!ZuluToODBCDate(zulu, odbc))
		return "";
	return odbc;
}

tsCryptoString tsCryptoDate::ToZuluUTCTime() const
{
    tsCryptoString zTime;

    if ( m_status != valid )
        return zTime;

    zTime.Format("%02d%02d%02d%02d%02d%02dZ", m_dt.year, m_dt.month, m_dt.day, m_dt.hour, m_dt.minute, m_dt.second);
    return zTime;
}

tsCryptoString tsCryptoDate::ToISO8601Time() const
{
    tsCryptoString isoTime;

    if ( m_status != valid )
        return isoTime;

    isoTime.Format("%04d-%02d-%02dT%02d:%02d:%02d", m_dt.year, m_dt.month, m_dt.day, m_dt.hour, m_dt.minute, m_dt.second);
    return isoTime;
}

int tsCryptoDate::GetYear() const
{
    if (GetStatus() != valid)
        return 0;
    return m_dt.year;
}

int tsCryptoDate::GetMonth() const       // month of year (1 = Jan)
{
    if (GetStatus() != valid)
        return 0;
    return m_dt.month;
}

int tsCryptoDate::GetDay() const         // day of month (0-31)
{
    if (GetStatus() != valid)
        return 0;
    return m_dt.day;
}

int tsCryptoDate::GetHour() const        // hour in day (0-23)
{
    if (GetStatus() != valid)
        return 0;
    return m_dt.hour;
}

int tsCryptoDate::GetMinute() const      // minute in hour (0-59)
{
    if (GetStatus() != valid)
        return 0;
    return m_dt.minute;
}

int tsCryptoDate::GetSecond() const      // second in minute (0-59)
{
    if (GetStatus() != valid)
        return 0;
    return m_dt.second;
}

const tsCryptoDate& tsCryptoDate::operator=(const tsCryptoDate& dateSrc)
{
    if ( &dateSrc != this )
    {
        m_status = dateSrc.m_status;
        m_dt = dateSrc.m_dt;
    }
    return *this;
}

const tsCryptoDate& tsCryptoDate::operator=(const TsDateStruct_t& systimeSrc)
{
    m_status = valid;
    m_dt = systimeSrc;
    CheckRange();
    return *this;
}

const tsCryptoDate& tsCryptoDate::operator=(uint64_t filetimeSrc)
{
    m_status = valid;
    tsFileTimeToDateStruct(filetimeSrc, &m_dt);
    CheckRange();
    return *this;
}

bool tsCryptoDate::operator==(const tsCryptoDate& date) const
{
    if ( m_status != valid && date.m_status != valid )
        return true;

    if ( m_status != valid || date.m_status != valid )
        return false;

    if ( m_dt.year != date.m_dt.year )
        return false;

    if ( m_dt.month != date.m_dt.month )
        return false;

    if ( m_dt.day != date.m_dt.day )
        return false;

    if ( m_dt.hour != date.m_dt.hour )
        return false;

    if ( m_dt.minute != date.m_dt.minute )
        return false;

    if ( m_dt.second != date.m_dt.second )
        return false;

    //if ( m_dt.wMilliseconds != date.m_dt.wMilliseconds )
    //    return false;

    return true;
}

bool tsCryptoDate::operator!=(const tsCryptoDate& date) const
{
    if ( m_status != date.m_status )
        return true;

    if ( m_status != valid || date.m_status != valid )
        return false;

    if ( m_dt.year != date.m_dt.year )
        return true;

    if ( m_dt.month != date.m_dt.month )
        return true;

    if ( m_dt.day != date.m_dt.day )
        return true;

    if ( m_dt.hour != date.m_dt.hour )
        return true;

    if ( m_dt.minute != date.m_dt.minute )
        return true;

    if ( m_dt.second != date.m_dt.second )
        return true;

    //if ( m_dt.wMilliseconds != date.m_dt.wMilliseconds )
    //    return true;

    return false;
}

bool tsCryptoDate::operator<(const tsCryptoDate& date) const
{
    if ( m_status != valid || date.m_status != valid )
        return false;

    if ( m_dt.year < date.m_dt.year )
        return true;
    if ( m_dt.year > date.m_dt.year )
        return false;

    if ( m_dt.month < date.m_dt.month )
        return true;
    if ( m_dt.month > date.m_dt.month )
        return false;

    if ( m_dt.day < date.m_dt.day )
        return true;
    if ( m_dt.day > date.m_dt.day )
        return false;

    if ( m_dt.hour < date.m_dt.hour )
        return true;
    if ( m_dt.hour > date.m_dt.hour )
        return false;

    if ( m_dt.minute < date.m_dt.minute )
        return true;
    if ( m_dt.minute > date.m_dt.minute )
        return false;

    if ( m_dt.second < date.m_dt.second )
        return true;
    if ( m_dt.second > date.m_dt.second )
        return false;

    //if ( m_dt.wMilliseconds < date.m_dt.wMilliseconds )
    //    return true;
    //if ( m_dt.wMilliseconds > date.m_dt.wMilliseconds )
    //    return false;

    return false;
}

bool tsCryptoDate::operator>(const tsCryptoDate& date) const
{
    if ( m_status != valid || date.m_status != valid )
        return false;

    if ( m_dt.year > date.m_dt.year )
        return true;
    if ( m_dt.year < date.m_dt.year )
        return false;

    if ( m_dt.month > date.m_dt.month )
        return true;
    if ( m_dt.month < date.m_dt.month )
        return false;

    if ( m_dt.day > date.m_dt.day )
        return true;
    if ( m_dt.day < date.m_dt.day )
        return false;

    if ( m_dt.hour > date.m_dt.hour )
        return true;
    if ( m_dt.hour < date.m_dt.hour )
        return false;

    if ( m_dt.minute > date.m_dt.minute )
        return true;
    if ( m_dt.minute < date.m_dt.minute )
        return false;

    if ( m_dt.second > date.m_dt.second )
        return true;
    if ( m_dt.second < date.m_dt.second )
        return false;

    //if ( m_dt.wMilliseconds > date.m_dt.wMilliseconds )
    //    return true;
    //if ( m_dt.wMilliseconds < date.m_dt.wMilliseconds )
    //    return false;

    return false;
}

bool tsCryptoDate::operator<=(const tsCryptoDate& date) const
{
    return (*this < date) || (*this == date);
}

bool tsCryptoDate::operator>=(const tsCryptoDate& date) const
{
    return (*this > date) || (*this == date);
}

tsCryptoDate& tsCryptoDate::SetDateTime(int nYear, int nMonth, int nDay, int nHour, int nMin, int nSec)
{
    memset (&m_dt, 0, sizeof(m_dt));
    m_status = valid;
    m_dt.year = (uint16_t)nYear;
    m_dt.month = (uint8_t)nMonth;
    m_dt.day = (uint8_t)nDay;
    m_dt.hour = (uint8_t)nHour;
    m_dt.minute = (uint8_t)nMin;
    m_dt.second = (uint8_t)nSec;
    CheckRange();
	return *this;
}

tsCryptoDate& tsCryptoDate::SetDateTimeFromZulu(const tsCryptoStringBase &sZuluTime)
{
    memset (&m_dt, 0, sizeof(m_dt));
	if ( (sZuluTime.size() != 13 && sZuluTime.size() != 15) || sZuluTime[sZuluTime.size() - 1] != 'Z' || !AllNumbers(sZuluTime.c_str(), (int)sZuluTime.size() - 1) )
    {
        m_status = invalid;
        memset(&m_dt, 0, sizeof(m_dt));
    }
    else
    {
        m_status = valid;
        if ( sZuluTime.size() == 13 )
        {
            m_dt.year   = (sZuluTime[0]  - '0') * 10 + (sZuluTime[1]  - '0');
            m_dt.month  = (sZuluTime[2]  - '0') * 10 + (sZuluTime[3]  - '0');
            m_dt.day    = (sZuluTime[4]  - '0') * 10 + (sZuluTime[5]  - '0');
            m_dt.hour   = (sZuluTime[6]  - '0') * 10 + (sZuluTime[7]  - '0');
            m_dt.minute = (sZuluTime[8]  - '0') * 10 + (sZuluTime[9]  - '0');
            m_dt.second = (sZuluTime[10] - '0') * 10 + (sZuluTime[11] - '0');
            if ( m_dt.year < 50 )
                m_dt.year += 1900;
            else
                m_dt.year += 2000;
        }
        else
        {
            m_dt.year   = (sZuluTime[0]  - '0') * 1000 + (sZuluTime[1]  - '0') * 100 +
                           (sZuluTime[2]  - '0') * 10 + (sZuluTime[3]  - '0');
            m_dt.month  = (sZuluTime[4]  - '0') * 10 + (sZuluTime[5]  - '0');
            m_dt.day    = (sZuluTime[6]  - '0') * 10 + (sZuluTime[7]  - '0');
            m_dt.hour   = (sZuluTime[8]  - '0') * 10 + (sZuluTime[9]  - '0');
            m_dt.minute = (sZuluTime[10] - '0') * 10 + (sZuluTime[11] - '0');
            m_dt.second = (sZuluTime[12] - '0') * 10 + (sZuluTime[13] - '0');
        }
        CheckRange();
    }
	return *this;
}

tsCryptoDate& tsCryptoDate::SetDateTimeFromODBC(const tsCryptoStringBase &sOdbc)
{
	tsCryptoString zulu;

	this->clear();
	if (!ODBCDateToZulu(sOdbc, zulu))
		return *this;
	return SetDateTimeFromZulu(zulu);
}

tsCryptoDate& tsCryptoDate::SetDateTimeFromZuluUTC(const tsCryptoStringBase &sZuluTime)
{
    memset (&m_dt, 0, sizeof(m_dt));
    if ( (sZuluTime.size() != 13 && sZuluTime.size() != 15) || sZuluTime[sZuluTime.size() - 1] != 'Z' || !AllNumbers(sZuluTime.c_str(), (int)sZuluTime.size() - 1) )
    {
        m_status = invalid;
        memset(&m_dt, 0, sizeof(m_dt));
    }
    else
    {
        m_status = valid;
        if ( sZuluTime.size() == 13 )
        {
            m_dt.year   = (sZuluTime[0]  - '0') * 10 + (sZuluTime[1]  - '0');
            m_dt.month  = (sZuluTime[2]  - '0') * 10 + (sZuluTime[3]  - '0');
            m_dt.day    = (sZuluTime[4]  - '0') * 10 + (sZuluTime[5]  - '0');
            m_dt.hour   = (sZuluTime[6]  - '0') * 10 + (sZuluTime[7]  - '0');
            m_dt.minute = (sZuluTime[8]  - '0') * 10 + (sZuluTime[9]  - '0');
            m_dt.second = (sZuluTime[10] - '0') * 10 + (sZuluTime[11] - '0');
            if ( m_dt.year < 50 )
                m_dt.year += 1900;
            else
                m_dt.year += 2000;
        }
        else
        {
            m_dt.year   = (sZuluTime[0]  - '0') * 1000 + (sZuluTime[1]  - '0') * 100 +
                           (sZuluTime[2]  - '0') * 10 + (sZuluTime[3]  - '0');
            m_dt.month  = (sZuluTime[4]  - '0') * 10 + (sZuluTime[5]  - '0');
            m_dt.day    = (sZuluTime[6]  - '0') * 10 + (sZuluTime[7]  - '0');
            m_dt.hour   = (sZuluTime[8]  - '0') * 10 + (sZuluTime[9]  - '0');
            m_dt.minute = (sZuluTime[10] - '0') * 10 + (sZuluTime[11] - '0');
            m_dt.second = (sZuluTime[12] - '0') * 10 + (sZuluTime[13] - '0');
        }
        CheckRange();
    }
	return *this;
}

tsCryptoDate& tsCryptoDate::SetDateTimeFromISO8601(const tsCryptoStringBase &s8601)
{
    tsConvertBrowserDateTimeTotsDateStruct(s8601.c_str(), &m_dt);
    CheckRange();
	return *this;
}

tsCryptoDate& tsCryptoDate::SetDateTimeFromNow()
{
    m_status = valid;
    tsGetNowInGMT(&m_dt);
	return *this;
}

tsCryptoDate& tsCryptoDate::SetDate(uint32_t nYear, uint32_t nMonth, uint32_t nDay)
{
    m_dt.year = (uint16_t)nYear;
    m_dt.month = (uint8_t)nMonth;
    m_dt.day = (uint8_t)nDay;
    CheckRange();
	return *this;
}

tsCryptoDate& tsCryptoDate::SetTime(uint32_t nHour, uint32_t nMin, uint32_t nSec)
{
    m_dt.hour = (uint8_t)nHour;
    m_dt.minute = (uint8_t)nMin;
    m_dt.second = (uint8_t)nSec;
    CheckRange();
	return *this;
}

tsCryptoDate& tsCryptoDate::AddInterval(int32_t lDays, int32_t nHours, int32_t nMins, int32_t nSecs)
{
    uint64_t ft;

    if ( m_status != valid )
    {
        return *this;
    }
    if (!tsDateStructToFileTime(&m_dt, &ft))
        return *this;
    tsAdjustFileTime(&ft, lDays, nHours, nMins, nSecs);
    if (!tsFileTimeToDateStruct(ft, &m_dt))
        return *this;
    CheckRange();
    return *this;
}

void tsCryptoDate::CheckRange()
{
    m_status = valid;

    if ( m_dt.month > 0 )
    {
        if ( m_dt.year < 50 )
            m_dt.year += 2000;
        else if ( m_dt.year < 100 )
            m_dt.year += 1900;
    }

    if ( !tsDateStructIsValid(&m_dt, ts_false) )
    {
        memset(&m_dt, 0, sizeof(m_dt));
        m_status = invalid;
    }
}

bool tsCryptoDate::AllNumbers(const char *str, int len)
{
    for (int i = 0; i < len; i++ )
    {
        if ( str[i] < '0' || str[i] > '9' )
            return false;
    }
    return true;
}

//#ifdef _WIN32
//DATE tsCryptoDate::ToOleDate()
//{
//    DOUBLE dt;
//
//    if ( m_status != valid )
//        return 0;
//    if (SystemTimeToVariantTime(&m_dt, &dt) == 0)
//        return 0;
//    return dt;
//}
//
//bool tsCryptoDate::FromOleDate(DATE oleDate)
//{
//    m_status = invalid;
//    memset(&m_dt, 0, sizeof(m_dt));
//
//    if (!VariantTimeToSystemTime(oleDate, &m_dt))
//        return false;
//    CheckRange();
//    return m_status == valid;
//}
//#endif // _WIN32

static tsCryptoString get_date_in_user_format (const tsCryptoDate& time)
{
#ifdef _WIN32
    tsCryptoString strTmpFormat;
    tsCryptoString strDate;

    int num_chars = GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_SSHORTDATE, nullptr, 0);
	CryptoUtf16 szData;
    szData.resize(num_chars);
    GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_SSHORTDATE, szData.data(), num_chars);

    if (num_chars != 0)
    {
        tsCryptoString strTmp (szData.toUtf8());
        int ind = 0;
        int len = (int)strTmp.size();
        while (ind < len)
        {
            switch (strTmp[ind])
            {
                case 'y':
                {
                    int year_type = 0;
                    while (ind < len && strTmp[ind] == 'y'){
                        ind++;
                        year_type++;
                    }
                    ind--;
                    switch (year_type){
                        case 4: strTmpFormat.Format("%d", time.GetYear());
                                strDate += strTmpFormat; break;
                        case 2: strTmpFormat.Format("%02d", time.GetYear() % 100);
                                strDate += strTmpFormat; break;
                        case 1: strTmpFormat.Format("%d", time.GetYear() % 10);
                                strDate += strTmpFormat; break;
                    }
                    break;
                }
                case 'M':
                {
                    int month_type = 0;
                    while (ind < len && strTmp[ind] == 'M'){
                        ind++;
                        month_type++;
                    }
                    ind--;
                    switch (month_type){
                        case 4:
                        {
                            WCHAR szMonth[500]={0};
                            if (0<GetLocaleInfoW(LOCALE_USER_DEFAULT,
                                    LOCALE_SMONTHNAME1+time.GetMonth()-1, szMonth, 499)){
                                strDate += CryptoUtf16(szMonth).toUtf8();
                            }
                            break;
                        }
                        case 3:
                        {
                            WCHAR szMonth[500]={0};
                            if (0<GetLocaleInfoW(LOCALE_USER_DEFAULT,
                                   LOCALE_SABBREVMONTHNAME1+time.GetMonth()-1,
                                   szMonth, 499)){
                                strDate += CryptoUtf16(szMonth).toUtf8();
                            }
                            break;
                        }
                        case 2: strTmpFormat.Format("02d", time.GetMonth());
                                strDate += strTmpFormat; break;
                        case 1: strTmpFormat.Format("%d", time.GetMonth());
                                strDate += strTmpFormat; break;
                    }
                    break;
                }
                case 'd':
                {
                    int day_type = 0;
                    while (ind < len && strTmp[ind] == 'd'){
                        ind++;
                        day_type++;
                    }
                    ind--;
                    switch (day_type){
                        case 4:
                        {
                            uint32_t DayOfWeekFull[] = {
                                LOCALE_SDAYNAME7,   // Sunday
                                LOCALE_SDAYNAME1,
                                LOCALE_SDAYNAME2,
                                LOCALE_SDAYNAME3,
                                LOCALE_SDAYNAME4,
                                LOCALE_SDAYNAME5,
                                LOCALE_SDAYNAME6   // Saturday
                            };
                            WCHAR szDayOfWeek[500]={0};
                            if (0<GetLocaleInfoW(LOCALE_USER_DEFAULT,
                                    DayOfWeekFull[time.GetDayOfWeek()-1],
                                    szDayOfWeek, 499)){
                                strDate += CryptoUtf16(szDayOfWeek).toUtf8();
                            }
                            break;
                        }
                        case 3:
                        {
                            uint32_t DayOfWeekAbbr[] = {
                                LOCALE_SABBREVDAYNAME7,   // Sunday
                                LOCALE_SABBREVDAYNAME1,
                                LOCALE_SABBREVDAYNAME2,
                                LOCALE_SABBREVDAYNAME3,
                                LOCALE_SABBREVDAYNAME4,
                                LOCALE_SABBREVDAYNAME5,
                                LOCALE_SABBREVDAYNAME6   // Saturday
                            };
                            WCHAR szDayOfWeek[500]={0};
                            if (0<GetLocaleInfoW(LOCALE_USER_DEFAULT,
                                    DayOfWeekAbbr[time.GetDayOfWeek()-1],
                                    szDayOfWeek, 499)){
                                strDate += CryptoUtf16(szDayOfWeek).toUtf8();
                            }
                            break;
                        }
                        case 2: strTmpFormat.Format("%02d", time.GetDay());
                                strDate += strTmpFormat; break;
                        case 1: strTmpFormat.Format("%d", time.GetDay());
                                strDate += strTmpFormat; break;
                    }
                    break;
                }
                default:
                    strDate += strTmp[ind];
                    break;
            }
            ind++;
        }
    }

    if (strDate.size() == 0){
        strDate = time.AsZuluTime().substring(0, 8); // fallback mechanism
    }

    return strDate;
#else
    tsCryptoString strDate;

    // TODO: Need true locale based date conversions here.
    strDate.Format("%02d/%02d/%04d", time.GetMonth(), time.GetDay(), time.GetYear());
    return strDate;
#endif // _WIN32
}

static tsCryptoString get_time_in_user_format (const tsCryptoDate& time)
{
#ifdef _WIN32
    tsCryptoString strTmpFormat;
    tsCryptoString strTime;

    int num_chars = GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_STIMEFORMAT, nullptr, 0);
	CryptoUtf16 szData;
    szData.resize(num_chars);
    GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_STIMEFORMAT, szData.data(), num_chars);

    if (num_chars != 0)
    {
        tsCryptoString strTmp (szData.toUtf8());
        int ind = 0;
        int len = (int)strTmp.size();
        while (ind < len)
        {
            switch (strTmp[ind])
            {
                case 't':
                {
                    int time_marker_type = 0;
                    while (ind < len && strTmp[ind] == 't'){
                        ind++;
                        time_marker_type++;
                    }
                    ind--;
                    switch (time_marker_type){
                        case 2:
                        case 1:
                        {
                            WCHAR szTimemarker[500]={0};
                            LCTYPE am_or_pm = LOCALE_S1159; //AM
                            if (time.GetHour() >= 0 && time.GetHour() < 12){
                                am_or_pm = LOCALE_S1159; //AM
                            }else{
                                am_or_pm = LOCALE_S2359; //PM
                            }
                            if (0<GetLocaleInfoW(LOCALE_USER_DEFAULT,
                                           am_or_pm, szTimemarker, 499)){



                                if (time_marker_type == 1){
                                    strTime += CryptoUtf16(szTimemarker).toUtf8()[0];
                                }else{
                                    strTime += CryptoUtf16(szTimemarker).toUtf8();
                                }
                            }
                            break;
                        }
                    }
                    break;
                }
                case 's':
                {
                    int seconds_type = 0;
                    while (ind < len && strTmp[ind] == 's'){
                        ind++;
                        seconds_type++;
                    }
                    ind--;
                    switch (seconds_type){
                        case 2: strTmpFormat.Format("%02d", time.GetSecond());
                                strTime += strTmpFormat; break;
                        case 1: strTmpFormat.Format("%d", time.GetSecond());
                                strTime += strTmpFormat; break;
                    }
                    break;
                }
                case 'm':
                {
                    int minute_type = 0;
                    while (ind < len && strTmp[ind] == 'm'){
                        ind++;
                        minute_type++;
                    }
                    ind--;
                    switch (minute_type){
                        case 2: strTmpFormat.Format("%02d", time.GetMinute());
                                strTime += strTmpFormat; break;
                        case 1: strTmpFormat.Format("%d", time.GetMinute());
                                strTime += strTmpFormat; break;
                    }
                    break;
                }
                case 'H':
                {
                    int hour_type = 0;
                    while (ind < len && strTmp[ind] == 'H'){
                        ind++;
                        hour_type++;
                    }
                    ind--;
                    switch (hour_type){
                        case 2: strTmpFormat.Format("02d", time.GetHour());
                                strTime += strTmpFormat; break;
                        case 1: strTmpFormat.Format("%d", time.GetHour());
                                strTime += strTmpFormat; break;
                    }
                    break;
                }
                case 'h':
                {
                    int hour_12_format = time.GetHour() % 12;
                    if (hour_12_format==0){
                        hour_12_format = 12;
                    }
                    int hour_type = 0;
                    while (ind < len && strTmp[ind] == 'h'){
                        ind++;
                        hour_type++;
                    }
                    ind--;
                    switch (hour_type){
                        case 2: strTmpFormat.Format("02d", hour_12_format);
                                strTime += strTmpFormat; break;
                        case 1: strTmpFormat.Format("%d", hour_12_format);
                                strTime += strTmpFormat; break;
                    }
                    break;
                }
                default:
                    strTime += strTmp[ind];
                    break;
            }
            ind++;
        }
    }

    if (strTime.size() == 0){
        strTime = time.AsZuluTime().substring(8, 6); //fallback mechanism
    }

    return strTime;
#else
    tsCryptoString strDate;

    // TODO: Need true locale based date conversions here.
    strDate.Format("%02d:%02d:%02d", time.GetHour(), time.GetMinute(), time.GetSecond());
    return strDate;
#endif // _WIN32
}

tsCryptoString tsCryptoDate::ToString() const
{
    if (GetStatus() == invalid)
        return "";
	tsCryptoString tmp = get_date_in_user_format(*this).c_str();
	tmp.append(" ");
	tmp.append(get_time_in_user_format(*this).c_str());
	return tmp;
}

tsCryptoString tsCryptoDate::ToDateString() const
{
    if (GetStatus() == invalid)
        return "";
    return get_date_in_user_format(*this);
}

tsCryptoString tsCryptoDate::ToTimeString() const
{
    if (GetStatus() == invalid)
        return "";
    return get_time_in_user_format(*this);
}

tsCryptoDate tsCryptoDate::ToUTC() const
{
    TsDateStruct_t utc;

    if (GetStatus() == invalid)
        return *this;

    utc = m_dt;
    tsDateStructToGMT(&utc);
    return tsCryptoDate(utc);
}

tsCryptoDate tsCryptoDate::ToLocal() const
{
    TsDateStruct_t local;

    if (GetStatus() == invalid)
        return *this;

    local = m_dt;
    tsDateStructToLocal(&local);
    return tsCryptoDate(local);
}

int tsCryptoDate::GetDayOfWeek() const
{
    if (GetStatus() == invalid)
        return 0;

    return tsDateStructToJulian(&m_dt) % 7;
}

void tscrypto::TSZuluStringToTM(const tsCryptoStringBase &date, TsDateStruct_t &tm)
{
	const char *p;
	int i;

	memset(&tm, 0, sizeof(TsDateStruct_t));
	if (date.size() != 15 || date.c_str()[14] != 'Z')
		return;
	p = date.c_str();
	for (i = 0; i < 14; i++)
		if (p[i] < '0' || p[i] > '9')
			return;
	tm.year = (p[0] - '0') * 1000 + (p[1] - '0') * 100 +
		(p[2] - '0') * 10 + (p[3] - '0');
	tm.month = (p[4] - '0') * 10 + (p[5] - '0');
	tm.day = (p[6] - '0') * 10 + (p[7] - '0');
	tm.hour = (p[8] - '0') * 10 + (p[9] - '0');
	tm.minute = (p[10] - '0') * 10 + (p[11] - '0');
	tm.second = (p[12] - '0') * 10 + (p[13] - '0');
}

void tscrypto::TSTMToZuluString(const TsDateStruct_t &tm, tsCryptoStringBase &date)
{
	char buff[50];

    tsSnPrintf(buff, sizeof(buff), "%04u%02u%02u%02u%02u%02uZ", tm.year, tm.month, tm.day,
		tm.hour, tm.minute, tm.second);
	date = buff;
}

bool tscrypto::ODBCDateToZulu(const tsCryptoStringBase &odbc, tsCryptoStringBase &zulu)
{
	const char *p;

	p = odbc.c_str();

	if (odbc == NULL)
		return false;
	zulu.clear();
	while (*p != 0)
	{
		if (*p >= '0' && *p <= '9')
			zulu += *p;
		p++;
	}
	if (zulu.size() > 14)
		zulu.resize(14);
	zulu += "Z";
	if (zulu.size() != 15)
		return false;
	return ZuluTimeIsValid(zulu.c_str());
}

bool tscrypto::ZuluToODBCDate(const tsCryptoStringBase &zulu, tsCryptoStringBase &odbc)
{
	if (zulu.size() != 15 || zulu[14] != 'Z' || !ZuluTimeIsValid(zulu))
		return false;

	odbc = zulu;
	odbc.resize(14);
	odbc.InsertAt(12, ':');
	odbc.InsertAt(10, ':');
	odbc.InsertAt(8, ' ');
	odbc.InsertAt(6, '-');
	odbc.InsertAt(4, '-');
	return true;
}

bool tscrypto::ZuluTimeIsValid(const tsCryptoStringBase &zulu)
{
	TsDateStruct_t tm;

	TSZuluStringToTM(zulu, tm);
	return tsDateStructIsValid(&tm, ts_false);
}

bool tscrypto::isZulu(const tsCryptoStringBase &str)
{
	return (str.length() == 15) && (str.at(14) == 'Z');
}

bool tscrypto::isDateTime(const tsCryptoStringBase &str)
{
	//	int offset_sign_loc = (int)str.length() - 6;
	if (str.length() >= 24
		&& str.at(4) == '-'
		&& str.at(7) == '-'
		&& str.at(10) == 'T'
		&& str.at(13) == ':')
		//&& str.at(16) == ':'
		//&& (str.at(offset_sign_loc) == '+' || str.at(offset_sign_loc) == '-')
		//&& str.at(offset_sign_loc+3) == ':')
	{
		return true;
	}
	return false;
}

/*
* Parse the string into the TM.
* Convert TM to FileTime
* add/subtract the timezone different
* convert FileTime to TM
* convert TM to Zulu
*/

tsCryptoString tscrypto::DateTimeToZulu(const tsCryptoStringBase &_dateTime)
{
	tsCryptoString dateTime(_dateTime);

	if (dateTime == "0001-01-01T00:00:00" || dateTime == "00010101000000Z" || dateTime == "")
	{
		return "";
	}
	if (isZulu(dateTime))
	{
		return dateTime;
	}
	if (isDateTime(dateTime))
	{
		int year = 0, month = 0, day = 0;
		int hour = 0, min = 0, sec = 0, milli = 0;
		int offset_hour = 0, offset_min = 0;
		bool doAddition = true;

		// year
		tsCryptoString tmp = dateTime;
		tmp.resize(4);
		year = tsStrToInt(tmp.c_str());
		dateTime.DeleteAt(0, 5);

		if (year <100)
		{
			return "";
		}

		// month
		tmp = dateTime;
		tmp.resize(2);
		month = tsStrToInt(tmp.c_str());
		dateTime.DeleteAt(0, 3);

		// day
		tmp = dateTime;
		tmp.resize(2);
		day = tsStrToInt(tmp.c_str());
		dateTime.DeleteAt(0, 3);

		// hours
		tmp = dateTime;
		tmp.resize(2);
		hour = tsStrToInt(tmp.c_str());
		dateTime.DeleteAt(0, 3);

		// minutes
		tmp = dateTime;
		tmp.resize(2);
		min = tsStrToInt(tmp.c_str());
		dateTime.DeleteAt(0, 3);

		// seconds
		tmp = dateTime;
		tmp.resize(2);
		sec = tsStrToInt(tmp.c_str());
		dateTime.DeleteAt(0, 2);

		// milliseconds
		if (dateTime.size() > 0 && dateTime[0] == '.')
		{
			dateTime.DeleteAt(0, 1);
			tmp = dateTime;
			tmp.resize(3);
			milli = tsStrToInt(tmp.c_str());
			dateTime.DeleteAt(0, 3);
		}

		// Z or offset sign
		if (dateTime.size() > 0 && dateTime[0] == 'Z')
		{
			dateTime.DeleteAt(0, 1);
		}
		else
		{
			// offset_sign
			size_t sign_offset = dateTime.find('-');
			/* since offset is behind Zulu time we must add the offset */
			if (sign_offset == tsCryptoString::npos)
			{
				/* since offset is ahead of Zulu time we must subtract the offset */
				sign_offset = dateTime.find('+');
				doAddition = false;
			}
			if (sign_offset != tsCryptoString::npos)
				dateTime.DeleteAt(0, sign_offset + 1);

			// offset_hour
			tmp = dateTime;
			tmp.resize(2);
			offset_hour = tsStrToInt(tmp.c_str());
			dateTime.DeleteAt(0, 2);

			// Optional colon
			if (dateTime.size() > 0 && dateTime[0] == ':')
			{
				dateTime.DeleteAt(0, 1);
			}

			// offset_min
			tmp = dateTime;
			tmp.resize(2);
			offset_min = tsStrToInt(tmp.c_str());
		}

		TsDateStruct_t st;
		memset(&st, 0, sizeof(st));

		st.year = (uint16_t)year;
		st.month = (uint8_t)month;
		st.day = (uint8_t)day;
		st.hour = (uint8_t)hour;
		st.minute = (uint8_t)min;
		st.second = (uint8_t)sec;
		st.millisecond = (uint16_t)milli;

		uint64_t ft;
		memset(&ft, 0, sizeof(ft));

		if (!tsDateStructToFileTime(&st, &ft))
		{
			return "00010101000000Z"; // Bad date
		}
		if (doAddition)
		{
			tsAdjustFileTime(&ft, 0, offset_hour, offset_min, 0);
		}
		else
		{
			tsAdjustFileTime(&ft, 0, -offset_hour, -offset_min, 0);
		}

		if (!tsFileTimeToDateStruct(ft, &st))
		{
			return "00010101000000Z"; // Bad date
		}

		tsCryptoString result;
		TSTMToZuluString(st, result);
		return result;
	}
	return "00010101000000Z"; // Bad date
}

/*
* Parse the string into YYYY-MM-DDThh:mm:ss+00:00 format
*/

tsCryptoString tscrypto::ZuluToDateTime(const tsCryptoStringBase &_zuluTime)
{
	tsCryptoString zuluTime(_zuluTime);

	if (zuluTime == "00010101000000Z" || zuluTime == "0001-01-01T00:00:00" || zuluTime == "")
	{
		return "";
	}
	if (isDateTime(zuluTime))
	{
		tsCryptoString tmp = zuluTime;
		tmp.resize(4);
		int year = tsStrToInt(tmp.c_str());
		if (year <100)
		{
			return "";
		}
		return zuluTime;
	}
	if (isZulu(zuluTime))
	{
		tsCryptoString tmp;
		int i;

		for (i = 0; i < 4; ++i)
		{
			tmp.append(zuluTime.at(i));
		}
		zuluTime.DeleteAt(0, 4);

		tmp.append('-');

		for (i = 0; i < 2; ++i)
		{
			tmp.append(zuluTime.at(i));
		}
		zuluTime.DeleteAt(0, 2);

		tmp.append('-');

		for (i = 0; i < 2; ++i)
		{
			tmp.append(zuluTime.at(i));
		}
		zuluTime.DeleteAt(0, 2);

		tmp.append('T');

		for (i = 0; i < 2; ++i)
		{
			tmp.append(zuluTime.at(i));
		}
		zuluTime.DeleteAt(0, 2);

		tmp.append(':');

		for (i = 0; i < 2; ++i)
		{
			tmp.append(zuluTime.at(i));
		}
		zuluTime.DeleteAt(0, 2);

		tmp.append(':');

		for (i = 0; i < 2; ++i)
		{
			tmp.append(zuluTime.at(i));
		}
		zuluTime.DeleteAt(0, 2);

		tmp.append("+00:00");

		return tmp;
	}
	return ""; // Bad date
}


int64_t tscrypto::GetTicks()
{
    return tsGetTicks();
}
