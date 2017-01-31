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
#include "math.h"
#include "ConvertUTF.h"

using namespace tscrypto;

#pragma region Date helper functions
bool tscrypto::SystemTimeIsValid(SYSTEMTIME *tm)
{
    if ( tm == NULL )
        return false;
    if ( tm->wHour > 23 || tm->wMinute > 59 || tm->wSecond > 59 || tm->wDay > 31 || tm->wMonth > 12 || tm->wMonth < 1 ||
         tm->wYear > 9999 || tm->wYear < 1800 || tm->wMilliseconds > 999 )
        return false;
    if ( SYSTEMTIMEtoJulian(tm->wYear, tm->wMonth, tm->wDay) == 0 )
        return false;
    return true;
}

#define MAX_TIME_BUFFER_SIZE    128         // matches that in timecore.cpp
#define MIN_DATE                (-657434L)  // about year 100
#define MAX_DATE                2958465L    // about year 9999

// Half a second, expressed in days
#define HALF_SECOND  (1.0/172800.0)

// One-based array of days in year at month start
static int _MonthDays[13] =
	{0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365};

/////////////////////////////////////////////////////////////////////////////
// CCKMDate class HELPERS - implementation

int32_t tscrypto::SYSTEMTIMEtoJulian(WORD wYear, WORD wMonth, WORD wDay)
{
	bool bLeapYear;
	int nDaysInMonth;
	int32_t nDate;

	// Validate year and month (ignore day of week and milliseconds)
	if (wYear > 9999 || wMonth < 1 || wMonth > 12)
		return 0;

	//  Check for leap year and set the number of days in the month
	bLeapYear = ((wYear & 3) == 0) &&
		((wYear % 100) != 0 || (wYear % 400) == 0);

	nDaysInMonth =
		_MonthDays[wMonth] - _MonthDays[wMonth-1] +
		((bLeapYear && wDay == 29 && wMonth == 2) ? 1 : 0);

	// Finish validating the date
	if (wDay < 1 || wDay > nDaysInMonth)
	{
		return 0;
	}

	// Cache the date in days and time in fractional days

	//It is a valid date; make Jan 1, 1AD be 1
	nDate = wYear*365L + wYear/4 - wYear/100 + wYear/400 +
		_MonthDays[wMonth-1] + wDay;

	//  If leap year and it's before March, subtract 1:
	if (wMonth <= 2 && bLeapYear)
		--nDate;

	//  Offset so that 12/30/1899 is 0
	nDate -= 693959L;

	return nDate;
}

double tscrypto::SYSTEMTIMEtoJulian(WORD wYear, WORD wMonth, WORD wDay, WORD wHour, WORD wMinute, WORD wSecond, WORD wMillisecond)
{
	MY_UNREFERENCED_PARAMETER(wMillisecond);
	bool bLeapYear;
	int nDaysInMonth;
	int32_t nDate;

	// Validate year and month (ignore day of week and milliseconds)
	if (wYear > 9999 || wMonth < 1 || wMonth > 12)
		return 0;

	//  Check for leap year and set the number of days in the month
	bLeapYear = ((wYear & 3) == 0) &&
		((wYear % 100) != 0 || (wYear % 400) == 0);

	nDaysInMonth =
		_MonthDays[wMonth] - _MonthDays[wMonth-1] +
		((bLeapYear && wDay == 29 && wMonth == 2) ? 1 : 0);

	// Finish validating the date
	if (wDay < 1 || wDay > nDaysInMonth)
	{
		return 0;
	}

	// Cache the date in days and time in fractional days

	//It is a valid date; make Jan 1, 1AD be 1
	nDate = wYear*365L + wYear/4 - wYear/100 + wYear/400 +
		_MonthDays[wMonth-1] + wDay;

	//  If leap year and it's before March, subtract 1:
	if (wMonth <= 2 && bLeapYear)
		--nDate;

	//  Offset so that 12/30/1899 is 0
	nDate -= 693959L;

	return (double)nDate + ((double)wHour * 60.0 * 24.0 + (double)wMinute * 60.0 + (double)wSecond /*+ (double)wMillisecond / 1000.0*/ ) / (24.0 * 60.0 * 60.0);
}

bool tscrypto::JulianToSYSTEMTIME(double dtSrc, SYSTEMTIME *tmDest)
{
	// The legal range does not actually span year 0 to 9999.
	if (dtSrc > MAX_DATE || dtSrc < MIN_DATE) // about year 100 to about 9999
		return false;

	int32_t nDaysAbsolute;     // Number of days since 1/1/0
	int32_t nSecsInDay;        // Time in seconds since midnight
	int32_t nMinutesInDay;     // Minutes in day

	int32_t n400Years;         // Number of 400 year increments since 1/1/0
	int32_t n400Century;       // Century within 400 year block (0,1,2 or 3)
	int32_t n4Years;           // Number of 4 year increments since 1/1/0
	int32_t n4Day;             // Day within 4 year block
							//  (0 is 1/1/yr1, 1460 is 12/31/yr4)
	int32_t n4Yr;              // Year within 4 year block (0,1,2 or 3)
	bool bLeap4 = true;     // TRUE if 4 year block includes leap year

	double dblDate = dtSrc; // tempory serial date

	// Round to the second
	dblDate += ((dtSrc > 0.0) ? HALF_SECOND : -HALF_SECOND);

	nDaysAbsolute = (int32_t)dblDate + 693959L; // Add days from 1/1/0 to 12/30/1899

	dblDate = fabs(dblDate);
	nSecsInDay = (int32_t)((dblDate - floor(dblDate)) * 86400.);

	// Calculate the day of week (sun=1, mon=2...)
	//   -1 because 1/1/0 is Sat.  +1 because we want 1-based
//	tmDest->wDay = (int)((nDaysAbsolute - 1) % 7L) + 1;

	// Leap years every 4 yrs except centuries not multiples of 400.
	n400Years = (int32_t)(nDaysAbsolute / 146097L);

	// Set nDaysAbsolute to day within 400-year block
	nDaysAbsolute %= 146097L;

	// -1 because first century has extra day
	n400Century = (int32_t)((nDaysAbsolute - 1) / 36524L);

	// Non-leap century
	if (n400Century != 0)
	{
		// Set nDaysAbsolute to day within century
		nDaysAbsolute = (nDaysAbsolute - 1) % 36524L;

		// +1 because 1st 4 year increment has 1460 days
		n4Years = (int32_t)((nDaysAbsolute + 1) / 1461L);

		if (n4Years != 0)
			n4Day = (int32_t)((nDaysAbsolute + 1) % 1461L);
		else
		{
			bLeap4 = FALSE;
			n4Day = (int32_t)nDaysAbsolute;
		}
	}
	else
	{
		// Leap century - not special case!
		n4Years = (int32_t)(nDaysAbsolute / 1461L);
		n4Day = (int32_t)(nDaysAbsolute % 1461L);
	}

	if (bLeap4)
	{
		// -1 because first year has 366 days
		n4Yr = (n4Day - 1) / 365;

		if (n4Yr != 0)
			n4Day = (n4Day - 1) % 365;
	}
	else
	{
		n4Yr = n4Day / 365;
		n4Day %= 365;
	}

	// n4Day is now 0-based day of year. Save 1-based day of year, year number
	tmDest->wDay = (WORD)((int)n4Day + 1);
	tmDest->wYear = (WORD)(n400Years * 400 + n400Century * 100 + n4Years * 4 + n4Yr);

	// Handle leap year: before, on, and after Feb. 29.
	if (n4Yr == 0 && bLeap4)
	{
		// Leap Year
		if (n4Day == 59)
		{
			/* Feb. 29 */
			tmDest->wMonth = 2;
			tmDest->wDay = 29;
			goto DoTime;
		}

		// Pretend it's not a leap year for month/day comp.
		if (n4Day >= 60)
			--n4Day;
	}

	// Make n4DaY a 1-based day of non-leap year and compute
	//  month/day for everything but Feb. 29.
	++n4Day;

	// Month number always >= n/32, so save some loop time */
	for (tmDest->wMonth = (WORD)((n4Day >> 5) + 1);
		n4Day > _MonthDays[tmDest->wMonth]; tmDest->wMonth++);

	tmDest->wDay = (WORD)((int)(n4Day - _MonthDays[tmDest->wMonth-1]));

DoTime:
	if (nSecsInDay == 0)
		tmDest->wHour = tmDest->wMinute = tmDest->wSecond = tmDest->wMilliseconds = tmDest->wDayOfWeek = 0;
	else
	{
	    tmDest->wMilliseconds = 0;
		tmDest->wSecond = (int)nSecsInDay % 60L;
		nMinutesInDay = nSecsInDay / 60L;
		tmDest->wMinute = (int)nMinutesInDay % 60;
		tmDest->wHour = (WORD)((int)nMinutesInDay / 60);
	}

	return true;
}
#pragma endregion

tsCryptoDate tsCryptoDate::GetCurrentTime()
{
    SYSTEMTIME tm;
    GetSystemTime(&tm);
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

tsCryptoDate::tsCryptoDate(const SYSTEMTIME& systimeSrc) :
    m_status (valid)
{
    m_dt = systimeSrc;
    CheckRange();
}

tsCryptoDate::tsCryptoDate(const FILETIME& filetimeSrc) :
    m_status(valid)
{
    memset(&m_dt, 0, sizeof(m_dt));
    FileTimeToSystemTime(&filetimeSrc, &m_dt);
    CheckRange();
}

tsCryptoDate::tsCryptoDate(int nYear, int nMonth, int nDay, int nHour, int nMin, int nSec) :
    m_status(invalid)
{
    memset(&m_dt, 0, sizeof(m_dt));
    m_dt.wYear = (WORD)nYear;
    m_dt.wMonth = (WORD)nMonth;
    m_dt.wDay = (WORD)nDay;
    m_dt.wHour = (WORD)nHour;
    m_dt.wMinute = (WORD)nMin;
    m_dt.wSecond = (WORD)nSec;
    CheckRange();
}

#ifdef HAVE_WINDOWS_H
tsCryptoDate::tsCryptoDate(DATE oleDate) :
    m_status(invalid)
{
    memset(&m_dt, 0, sizeof(m_dt));
    FromOleDate(oleDate);
}
#endif // HAVE_WINDOWS_H

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

bool tsCryptoDate::GetAsSystemTime(SYSTEMTIME& sysTime) const
{
    if ( m_status != valid )
        return FALSE;

    sysTime = m_dt;
    return true;
}
SYSTEMTIME tsCryptoDate::AsSystemTime() const
{
    if ( m_status != valid )
	{
		SYSTEMTIME dt;

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

    zTime.Format("%04d%02d%02d%02d%02d%02dZ", m_dt.wYear, m_dt.wMonth, m_dt.wDay, m_dt.wHour, m_dt.wMinute, m_dt.wSecond);
    return zTime;
}

tsCryptoString tsCryptoDate::AsODBCTime() const
{
	tsCryptoString zTime;
	tsCryptoString odbc;

	if (m_status != valid)
		return zTime;

	zTime.Format("%04d%02d%02d%02d%02d%02dZ", m_dt.wYear, m_dt.wMonth, m_dt.wDay, m_dt.wHour, m_dt.wMinute, m_dt.wSecond);
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

    zTime.Format("%02d%02d%02d%02d%02d%02dZ", m_dt.wYear % 100, m_dt.wMonth, m_dt.wDay, m_dt.wHour, m_dt.wMinute, m_dt.wSecond);
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

    isoTime.Format("%04d-%02d-%02dT%02d:%02d:%02dZ", m_dt.wYear, m_dt.wMonth, m_dt.wDay, m_dt.wHour, m_dt.wMinute, m_dt.wSecond);
    return isoTime;
}

tsCryptoString tsCryptoDate::ToZuluTime() const
{
    tsCryptoString zTime;

    if ( m_status != valid )
        return zTime;

    zTime.Format("%04d%02d%02d%02d%02d%02dZ", m_dt.wYear, m_dt.wMonth, m_dt.wDay, m_dt.wHour, m_dt.wMinute, m_dt.wSecond);
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

    zTime.Format("%02d%02d%02d%02d%02d%02dZ", m_dt.wYear % 100, m_dt.wMonth, m_dt.wDay, m_dt.wHour, m_dt.wMinute, m_dt.wSecond);
    return zTime;
}

tsCryptoString tsCryptoDate::ToISO8601Time() const
{
    tsCryptoString isoTime;

    if ( m_status != valid )
        return isoTime;

    isoTime.Format("%04d-%02d-%02dT%02d:%02d:%02d", m_dt.wYear, m_dt.wMonth, m_dt.wDay, m_dt.wHour, m_dt.wMinute, m_dt.wSecond);
    return isoTime;
}

int tsCryptoDate::GetYear() const
{
    if (GetStatus() != valid)
        return 0;
    return m_dt.wYear;
}

int tsCryptoDate::GetMonth() const       // month of year (1 = Jan)
{
    if (GetStatus() != valid)
        return 0;
    return m_dt.wMonth;
}

int tsCryptoDate::GetDay() const         // day of month (0-31)
{
    if (GetStatus() != valid)
        return 0;
    return m_dt.wDay;
}

int tsCryptoDate::GetHour() const        // hour in day (0-23)
{
    if (GetStatus() != valid)
        return 0;
    return m_dt.wHour;
}

int tsCryptoDate::GetMinute() const      // minute in hour (0-59)
{
    if (GetStatus() != valid)
        return 0;
    return m_dt.wMinute;
}

int tsCryptoDate::GetSecond() const      // second in minute (0-59)
{
    if (GetStatus() != valid)
        return 0;
    return m_dt.wSecond;
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

const tsCryptoDate& tsCryptoDate::operator=(const SYSTEMTIME& systimeSrc)
{
    m_status = valid;
    m_dt = systimeSrc;
    CheckRange();
    return *this;
}

const tsCryptoDate& tsCryptoDate::operator=(const FILETIME& filetimeSrc)
{
    m_status = valid;
    FileTimeToSystemTime(&filetimeSrc, &m_dt);
    CheckRange();
    return *this;
}

bool tsCryptoDate::operator==(const tsCryptoDate& date) const
{
    if ( m_status != valid && date.m_status != valid )
        return true;

    if ( m_status != valid || date.m_status != valid )
        return false;

    if ( m_dt.wYear != date.m_dt.wYear )
        return false;

    if ( m_dt.wMonth != date.m_dt.wMonth )
        return false;

    if ( m_dt.wDay != date.m_dt.wDay )
        return false;

    if ( m_dt.wHour != date.m_dt.wHour )
        return false;

    if ( m_dt.wMinute != date.m_dt.wMinute )
        return false;

    if ( m_dt.wSecond != date.m_dt.wSecond )
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

    if ( m_dt.wYear != date.m_dt.wYear )
        return true;

    if ( m_dt.wMonth != date.m_dt.wMonth )
        return true;

    if ( m_dt.wDay != date.m_dt.wDay )
        return true;

    if ( m_dt.wHour != date.m_dt.wHour )
        return true;

    if ( m_dt.wMinute != date.m_dt.wMinute )
        return true;

    if ( m_dt.wSecond != date.m_dt.wSecond )
        return true;

    //if ( m_dt.wMilliseconds != date.m_dt.wMilliseconds )
    //    return true;

    return false;
}

bool tsCryptoDate::operator<(const tsCryptoDate& date) const
{
    if ( m_status != valid || date.m_status != valid )
        return false;

    if ( m_dt.wYear < date.m_dt.wYear )
        return true;
    if ( m_dt.wYear > date.m_dt.wYear )
        return false;

    if ( m_dt.wMonth < date.m_dt.wMonth )
        return true;
    if ( m_dt.wMonth > date.m_dt.wMonth )
        return false;

    if ( m_dt.wDay < date.m_dt.wDay )
        return true;
    if ( m_dt.wDay > date.m_dt.wDay )
        return false;

    if ( m_dt.wHour < date.m_dt.wHour )
        return true;
    if ( m_dt.wHour > date.m_dt.wHour )
        return false;

    if ( m_dt.wMinute < date.m_dt.wMinute )
        return true;
    if ( m_dt.wMinute > date.m_dt.wMinute )
        return false;

    if ( m_dt.wSecond < date.m_dt.wSecond )
        return true;
    if ( m_dt.wSecond > date.m_dt.wSecond )
        return false;

    //if ( m_dt.wMilliseconds < date.m_dt.wMilliseconds )
    //    return true;
    //if ( m_dt.wMilliseconds > date.m_dt.wMilliseconds )
    //    return false;

    return FALSE;
}

bool tsCryptoDate::operator>(const tsCryptoDate& date) const
{
    if ( m_status != valid || date.m_status != valid )
        return false;

    if ( m_dt.wYear > date.m_dt.wYear )
        return true;
    if ( m_dt.wYear < date.m_dt.wYear )
        return false;

    if ( m_dt.wMonth > date.m_dt.wMonth )
        return true;
    if ( m_dt.wMonth < date.m_dt.wMonth )
        return false;

    if ( m_dt.wDay > date.m_dt.wDay )
        return true;
    if ( m_dt.wDay < date.m_dt.wDay )
        return false;

    if ( m_dt.wHour > date.m_dt.wHour )
        return true;
    if ( m_dt.wHour < date.m_dt.wHour )
        return false;

    if ( m_dt.wMinute > date.m_dt.wMinute )
        return true;
    if ( m_dt.wMinute < date.m_dt.wMinute )
        return false;

    if ( m_dt.wSecond > date.m_dt.wSecond )
        return true;
    if ( m_dt.wSecond < date.m_dt.wSecond )
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
    m_dt.wYear = (WORD)nYear;
    m_dt.wMonth = (WORD)nMonth;
    m_dt.wDay = (WORD)nDay;
    m_dt.wHour = (WORD)nHour;
    m_dt.wMinute = (WORD)nMin;
    m_dt.wSecond = (WORD)nSec;
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
            m_dt.wYear   = (sZuluTime[0]  - '0') * 10 + (sZuluTime[1]  - '0');
            m_dt.wMonth  = (sZuluTime[2]  - '0') * 10 + (sZuluTime[3]  - '0');
            m_dt.wDay    = (sZuluTime[4]  - '0') * 10 + (sZuluTime[5]  - '0');
            m_dt.wHour   = (sZuluTime[6]  - '0') * 10 + (sZuluTime[7]  - '0');
            m_dt.wMinute = (sZuluTime[8]  - '0') * 10 + (sZuluTime[9]  - '0');
            m_dt.wSecond = (sZuluTime[10] - '0') * 10 + (sZuluTime[11] - '0');
            if ( m_dt.wYear < 50 )
                m_dt.wYear += 1900;
            else
                m_dt.wYear += 2000;
        }
        else
        {
            m_dt.wYear   = (sZuluTime[0]  - '0') * 1000 + (sZuluTime[1]  - '0') * 100 +
                           (sZuluTime[2]  - '0') * 10 + (sZuluTime[3]  - '0');
            m_dt.wMonth  = (sZuluTime[4]  - '0') * 10 + (sZuluTime[5]  - '0');
            m_dt.wDay    = (sZuluTime[6]  - '0') * 10 + (sZuluTime[7]  - '0');
            m_dt.wHour   = (sZuluTime[8]  - '0') * 10 + (sZuluTime[9]  - '0');
            m_dt.wMinute = (sZuluTime[10] - '0') * 10 + (sZuluTime[11] - '0');
            m_dt.wSecond = (sZuluTime[12] - '0') * 10 + (sZuluTime[13] - '0');
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
            m_dt.wYear   = (sZuluTime[0]  - '0') * 10 + (sZuluTime[1]  - '0');
            m_dt.wMonth  = (sZuluTime[2]  - '0') * 10 + (sZuluTime[3]  - '0');
            m_dt.wDay    = (sZuluTime[4]  - '0') * 10 + (sZuluTime[5]  - '0');
            m_dt.wHour   = (sZuluTime[6]  - '0') * 10 + (sZuluTime[7]  - '0');
            m_dt.wMinute = (sZuluTime[8]  - '0') * 10 + (sZuluTime[9]  - '0');
            m_dt.wSecond = (sZuluTime[10] - '0') * 10 + (sZuluTime[11] - '0');
            if ( m_dt.wYear < 50 )
                m_dt.wYear += 1900;
            else
                m_dt.wYear += 2000;
        }
        else
        {
            m_dt.wYear   = (sZuluTime[0]  - '0') * 1000 + (sZuluTime[1]  - '0') * 100 +
                           (sZuluTime[2]  - '0') * 10 + (sZuluTime[3]  - '0');
            m_dt.wMonth  = (sZuluTime[4]  - '0') * 10 + (sZuluTime[5]  - '0');
            m_dt.wDay    = (sZuluTime[6]  - '0') * 10 + (sZuluTime[7]  - '0');
            m_dt.wHour   = (sZuluTime[8]  - '0') * 10 + (sZuluTime[9]  - '0');
            m_dt.wMinute = (sZuluTime[10] - '0') * 10 + (sZuluTime[11] - '0');
            m_dt.wSecond = (sZuluTime[12] - '0') * 10 + (sZuluTime[13] - '0');
        }
        CheckRange();
    }
	return *this;
}

tsCryptoDate& tsCryptoDate::SetDateTimeFromISO8601(const tsCryptoStringBase &s8601)
{
    SetStatus(valid);
    #ifdef _WIN32
    DATE oleDate;





    if (VarDateFromStr(CryptoUtf16(s8601).data(), 0, LOCALE_NOUSEROVERRIDE, &oleDate) < 0)
    {
        SetStatus(invalid);
        memset(&m_dt, 0, sizeof(m_dt));
    }
	else if (!VariantTimeToSystemTime(oleDate, &m_dt))
	{
		SetStatus(invalid);
		memset(&m_dt, 0, sizeof(m_dt));
	}
	else
		m_dt.wMilliseconds = 0;
    #else
    struct tm outTime;

    memset(&outTime, 0, sizeof(struct tm));
    if (strptime(s8601.c_str(), "%Y-%m-%d %H:%M:%S", &outTime) == nullptr)
    {
        SetStatus(invalid);
        memset(&m_dt, 0, sizeof(m_dt));
    }
    else
    {
        m_dt.wYear = outTime.tm_year + 1900;
        m_dt.wMonth = outTime.tm_mon + 1;
        m_dt.wDayOfWeek = outTime.tm_wday;
        m_dt.wDay = outTime.tm_mday;
        m_dt.wHour = outTime.tm_hour;
        m_dt.wMinute = outTime.tm_min;
        m_dt.wSecond = outTime.tm_sec;
        m_dt.wMilliseconds = 0;
    }
    #endif
	return *this;
}

tsCryptoDate& tsCryptoDate::SetDateTimeFromNow()
{
    m_status = valid;
    GetSystemTime(&m_dt);
	return *this;
}

tsCryptoDate& tsCryptoDate::SetDate(uint32_t nYear, uint32_t nMonth, uint32_t nDay)
{
    m_dt.wYear = (WORD)nYear;
    m_dt.wMonth = (WORD)nMonth;
    m_dt.wDay = (WORD)nDay;
    CheckRange();
	return *this;
}

tsCryptoDate& tsCryptoDate::SetTime(uint32_t nHour, uint32_t nMin, uint32_t nSec)
{
    m_dt.wHour = (WORD)nHour;
    m_dt.wMinute = (WORD)nMin;
    m_dt.wSecond = (WORD)nSec;
    CheckRange();
	return *this;
}

tsCryptoDate& tsCryptoDate::AddInterval(int32_t lDays, int32_t nHours, int32_t nMins, int32_t nSecs)
{
    FILETIME ft;

    if ( m_status != valid )
    {
        return *this;
    }
    if (!SYSTEMTIMEToFileTime(&m_dt, &ft))
        return *this;
    AdjustFileTime(&ft, lDays, nHours, nMins, nSecs);
    if (!FileTimeToSystemTime(&ft, &m_dt))
        return *this;
    CheckRange();
    return *this;
}

void tsCryptoDate::CheckRange()
{
    m_status = valid;

    if ( m_dt.wMonth > 0 )
    {
        if ( m_dt.wYear < 50 )
            m_dt.wYear += 2000;
        else if ( m_dt.wYear < 100 )
            m_dt.wYear += 1900;
    }

    if ( !SystemTimeIsValid(&m_dt) )
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

#ifdef HAVE_WINDOWS_H
DATE tsCryptoDate::ToOleDate()
{
    DOUBLE dt;

    if ( m_status != valid )
        return 0;
    if (SystemTimeToVariantTime(&m_dt, &dt) == 0)
        return 0;
    return dt;
}

bool tsCryptoDate::FromOleDate(DATE oleDate)
{
    m_status = invalid;
    memset(&m_dt, 0, sizeof(m_dt));

    if (!VariantTimeToSystemTime(oleDate, &m_dt))
        return false;
    CheckRange();
    return m_status == valid;
}
#endif // HAVE_WINDOWS_H

static tsCryptoString get_date_in_user_format (const tsCryptoDate& time)
{
#ifdef HAVE_WINDOWS_H
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
                            UINT DayOfWeekFull[] = {
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
                            UINT DayOfWeekAbbr[] = {
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
#endif // HAVE_WINDOWS_H
}

static tsCryptoString get_time_in_user_format (const tsCryptoDate& time)
{
#ifdef HAVE_WINDOWS_H
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
#endif // HAVE_WINDOWS_H
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
#ifdef HAVE_WINDOWS_H
    SYSTEMTIME utc;

    if (GetStatus() == invalid)
        return *this;

    TzSpecificLocalTimeToSystemTime(nullptr, &m_dt, &utc);
    return tsCryptoDate(utc);
#else
    FILETIME ft;
    time_t sft;
    SYSTEMTIME newTime;

    SYSTEMTIMEToFileTime(&m_dt, &ft);
    time(&sft);
    ft -= mktime(localtime(&sft));
    ft += sft;
    FileTimeToSystemTime(&ft, &newTime);
    return tsCryptoDate(newTime);
#endif // HAVE_WINDOWS_H
}

tsCryptoDate tsCryptoDate::ToLocal() const
{
#ifdef HAVE_WINDOWS_H
    SYSTEMTIME local;

    if (GetStatus() == invalid)
        return *this;

    SystemTimeToTzSpecificLocalTime(nullptr, &m_dt, &local);
    return tsCryptoDate(local);
#else
    FILETIME ft;
    time_t sft;
    SYSTEMTIME newTime;

    SYSTEMTIMEToFileTime(&m_dt, &ft);
    time(&sft);
    ft += mktime(localtime(&sft));
    ft -= sft;
    FileTimeToSystemTime(&ft, &newTime);
    return tsCryptoDate(newTime);
#endif // HAVE_WINDOWS_H
}

int tsCryptoDate::GetDayOfWeek() const
{
    if (GetStatus() == invalid)
        return 0;

    return SYSTEMTIMEtoJulian(m_dt.wYear, m_dt.wMonth, m_dt.wDay) % 7;
}

void tscrypto::TSZuluStringToTM(const tsCryptoStringBase &date, SYSTEMTIME &tm)
{
	const char *p;
	int i;

	memset(&tm, 0, sizeof(SYSTEMTIME));
	if (date.size() != 15 || date.c_str()[14] != 'Z')
		return;
	p = date.c_str();
	for (i = 0; i < 14; i++)
		if (p[i] < '0' || p[i] > '9')
			return;
	tm.wYear = (p[0] - '0') * 1000 + (p[1] - '0') * 100 +
		(p[2] - '0') * 10 + (p[3] - '0');
	tm.wMonth = (p[4] - '0') * 10 + (p[5] - '0');
	tm.wDay = (p[6] - '0') * 10 + (p[7] - '0');
	tm.wHour = (p[8] - '0') * 10 + (p[9] - '0');
	tm.wMinute = (p[10] - '0') * 10 + (p[11] - '0');
	tm.wSecond = (p[12] - '0') * 10 + (p[13] - '0');
}

void tscrypto::TSTMToZuluString(const SYSTEMTIME &tm, tsCryptoStringBase &date)
{
	char buff[50];

#ifdef HAVE_SPRINTF_S
	sprintf_s(buff, sizeof(buff), "%04u%02u%02u%02u%02u%02uZ", tm.wYear, tm.wMonth, tm.wDay,
		tm.wHour, tm.wMinute, tm.wSecond);
#else
	sprintf(buff, "%04u%02u%02u%02u%02u%02uZ", tm.wYear, tm.wMonth, tm.wDay,
		tm.wHour, tm.wMinute, tm.wSecond);
#endif
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
	SYSTEMTIME tm;

	TSZuluStringToTM(zulu, tm);
	return SYSTEMTIMEIsValid(&tm);
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
		year = TsStrToInt(tmp.c_str());
		dateTime.DeleteAt(0, 5);

		if (year <100)
		{
			return "";
		}

		// month
		tmp = dateTime;
		tmp.resize(2);
		month = TsStrToInt(tmp.c_str());
		dateTime.DeleteAt(0, 3);

		// day
		tmp = dateTime;
		tmp.resize(2);
		day = TsStrToInt(tmp.c_str());
		dateTime.DeleteAt(0, 3);

		// hours
		tmp = dateTime;
		tmp.resize(2);
		hour = TsStrToInt(tmp.c_str());
		dateTime.DeleteAt(0, 3);

		// minutes
		tmp = dateTime;
		tmp.resize(2);
		min = TsStrToInt(tmp.c_str());
		dateTime.DeleteAt(0, 3);

		// seconds
		tmp = dateTime;
		tmp.resize(2);
		sec = TsStrToInt(tmp.c_str());
		dateTime.DeleteAt(0, 2);

		// milliseconds
		if (dateTime.size() > 0 && dateTime[0] == '.')
		{
			dateTime.DeleteAt(0, 1);
			tmp = dateTime;
			tmp.resize(3);
			milli = TsStrToInt(tmp.c_str());
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
			offset_hour = TsStrToInt(tmp.c_str());
			dateTime.DeleteAt(0, 2);

			// Optional colon
			if (dateTime.size() > 0 && dateTime[0] == ':')
			{
				dateTime.DeleteAt(0, 1);
			}

			// offset_min
			tmp = dateTime;
			tmp.resize(2);
			offset_min = TsStrToInt(tmp.c_str());
		}

		SYSTEMTIME st;
		memset(&st, 0, sizeof(st));

		st.wYear = (WORD)year;
		st.wMonth = (WORD)month;
		st.wDay = (WORD)day;
		st.wHour = (WORD)hour;
		st.wMinute = (WORD)min;
		st.wSecond = (WORD)sec;
		st.wMilliseconds = (WORD)milli;

		FILETIME ft;
		memset(&ft, 0, sizeof(ft));

		if (!SYSTEMTIMEToFileTime(&st, &ft))
		{
			return "00010101000000Z"; // Bad date
		}
		if (doAddition)
		{
			AdjustFileTime(&ft, 0, offset_hour, offset_min, 0);
		}
		else
		{
			AdjustFileTime(&ft, 0, -offset_hour, -offset_min, 0);
		}

		if (!FileTimeToSystemTime(&ft, &st))
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
		int year = TsStrToInt(tmp.c_str());
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


double tscrypto::diffsystemtime(SYSTEMTIME *date1, SYSTEMTIME *date2)
{
	int32_t jDate1;
	int32_t jDate2;
	double result;

	jDate1 = SYSTEMTIMEtoJulian(date1->wYear, date1->wMonth, date1->wDay);
	jDate2 = SYSTEMTIMEtoJulian(date2->wYear, date2->wMonth, date2->wDay);

	result = jDate1;
	result = result - jDate2;
	result = result * 24 * 60 * 60;

	jDate1 = date1->wHour * 60 * 60 + date1->wMinute * 60 + date1->wSecond;
	jDate2 = date2->wHour * 60 * 60 + date2->wMinute * 60 + date2->wSecond;
	result = result + (int)jDate1 - (int)jDate2;
	result = result + (((int)date1->wMilliseconds - (int)date2->wMilliseconds) / 1000.0);
	return result;
}

BOOL tscrypto::SYSTEMTIMEToFileTime(const SYSTEMTIME *tm, FILETIME *fileTm)
{
	if (tm == NULL || fileTm == NULL)
		return FALSE;

	__int64 tmp = 0;

#ifdef HAVE_WINDOWS_H
	tmp = SYSTEMTIMEtoJulian(tm->wYear, tm->wMonth, tm->wDay) * 24ll * 3600;
	tmp -= SYSTEMTIMEtoJulian(1601, 1, 1) * 24ll * 3600;
	tmp += tm->wHour * 3600 + tm->wMinute * 60 + tm->wSecond;
	tmp *= 1000;
	tmp += tm->wMilliseconds;
	tmp *= 10000; // take to 100 nanoseconds
	fileTm->dwHighDateTime = (tmp >> 32);
	fileTm->dwLowDateTime = (DWORD)(tmp & 0xFFFFFFFFull);
#else
	tmp = SYSTEMTIMEtoJulian(tm->wYear, tm->wMonth, tm->wDay) * 24ll * 3600;
	tmp -= SYSTEMTIMEtoJulian(1970, 1, 1) * 24ll * 3600;
	tmp += tm->wHour * 3600 + tm->wMinute * 60 + tm->wSecond;

	*fileTm = tmp;
#endif
	return TRUE;
}

void tscrypto::AdjustFileTime(FILETIME *fileTm, int days, int hours, int minutes, int seconds)
{
	if (fileTm == NULL)
		return;

#ifdef HAVE_WINDOWS_H
	int64_t ft = (((int64_t)fileTm->dwHighDateTime) << 32) | fileTm->dwLowDateTime;

	ft += days * 24ll * 36000000000ll;
	ft += hours * 36000000000ll + minutes * 600000000ll + seconds * 10000000ll;

	fileTm->dwHighDateTime = (ft >> 32);
	fileTm->dwLowDateTime = (DWORD)(ft & 0xFFFFFFFFull);
#else
	*fileTm += ((int64_t)days) * 60 * 60 * 24 + ((int64_t)hours) * 60 * 60 + ((int64_t)minutes) * 60 + seconds;
#endif // HAVE_WINDOWS_H
}

bool tscrypto::SYSTEMTIMEIsValid(SYSTEMTIME *tm)
{
	if (tm == NULL)
		return false;
	if (tm->wHour > 23 || tm->wMinute > 59 || tm->wSecond > 59 || tm->wDay > 31 || tm->wMonth > 12 || tm->wMonth < 1 ||
		tm->wYear > 9999 || tm->wYear < 1800 || tm->wMilliseconds > 999)
		return false;
	if (SYSTEMTIMEtoJulian(tm->wYear, tm->wMonth, tm->wDay) == 0)
		return false;
	return true;
}

int64_t tscrypto::GetTicks()
{
#ifdef HAVE_QUERYPERFORMANCECOUNTER
	LARGE_INTEGER li;
	static int64_t frequency = -1;

	if (frequency == -1)
	{
		QueryPerformanceFrequency(&li);
		frequency = li.QuadPart;
	}
	QueryPerformanceCounter(&li);
	return (li.QuadPart * 1000000) / frequency;
#elif defined(HAVE_GETTIMEOFDAY)
	struct timeval tv;

	if (gettimeofday(&tv, NULL) != 0)
		return 0;
	return ((__int64)tv.tv_sec) * 1000000 + tv.tv_usec;
#else
#error Not implemented
#endif
}
#ifndef HAVE_WINDOWS_H
EXPORT_SYMBOL BOOL GetSystemTime(SYSTEMTIME* s)
{
	time_t timeVal;
	struct tm outTime;

	if (s == nullptr || time(&timeVal) == (time_t)-1)
		return FALSE;
	if (gmtime_r(&timeVal, &outTime) == nullptr)
		return FALSE;
	s->wYear = outTime.tm_year + 1900;
	s->wMonth = outTime.tm_mon + 1;
	s->wDayOfWeek = outTime.tm_wday;
	s->wDay = outTime.tm_mday;
	s->wHour = outTime.tm_hour;
	s->wMinute = outTime.tm_min;
	s->wSecond = outTime.tm_sec;
	s->wMilliseconds = 0;
	return TRUE;
}
EXPORT_SYMBOL BOOL FileTimeToSystemTime(const FILETIME* ft, SYSTEMTIME* st)
{
	struct tm outTime;

	if (ft == nullptr || st == nullptr)
		return FALSE;
	if (gmtime_r(ft, &outTime) == nullptr)
		return FALSE;
	st->wYear = outTime.tm_year + 1900;
	st->wMonth = outTime.tm_mon + 1;
	st->wDayOfWeek = outTime.tm_wday;
	st->wDay = outTime.tm_mday;
	st->wHour = outTime.tm_hour;
	st->wMinute = outTime.tm_min;
	st->wSecond = outTime.tm_sec;
	st->wMilliseconds = 0;
	return TRUE;
}
#endif // HAVE_WINDOWS_H
