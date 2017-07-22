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

#ifdef _WIN32
#else
#ifdef MAC
#include <termios.h>
#else
#include <termio.h>
#endif
//#include <stropts.h>

static const char *BlackForeground = "\x1b[0;30m";
static const char *RedForeground = "\x1b[0;31m";
static const char *GreenForeground = "\x1b[0;32m";
static const char *YellowForeground = "\x1b[0;33m";
static const char *BlueForeground = "\x1b[0;34m";
static const char *PurpleForeground = "\x1b[0;35m";
static const char *CyanForeground = "\x1b[0;36m";
static const char *WhiteForeground = "\x1b[0;37m";

static const char *BoldBlackForeground = "\x1b[1;30m";
static const char *BoldRedForeground = "\x1b[1;31m";
static const char *BoldGreenForeground = "\x1b[1;32m";
static const char *BoldYellowForeground = "\x1b[1;33m";
static const char *BoldBlueForeground = "\x1b[1;34m";
static const char *BoldPurpleForeground = "\x1b[1;35m";
static const char *BoldCyanForeground = "\x1b[1;36m";
static const char *BoldWhiteForeground = "\x1b[1;37m";

static const char *BlackBackground = "\x1b[40m";
static const char *RedBackground = "\x1b[41m";
static const char *GreenBackground = "\x1b[42m";
static const char *YellowBackground = "\x1b[43m";
static const char *BlueBackground = "\x1b[44m";
static const char *PurpleBackground = "\x1b[45m";
static const char *CyanBackground = "\x1b[46m";
static const char *WhiteBackground = "\x1b[47m";
#endif

xp_console::xp_console() :
justHadNewline(true),
numberBase(10),
width(0),
filler(' '),
_indentLevel(0)
{
	leftDoublePrecision = 4;
	rightDoublePrecision = 3;
#ifdef _WIN32
	hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	if (!GetConsoleScreenBufferInfo(hConsole, &screenInfo))
	{
		screenInfo.wAttributes = 15;
		screenInfo.dwMaximumWindowSize.X = 80;
		screenInfo.dwMaximumWindowSize.Y = 24;
	}
	_currentColor = screenInfo.wAttributes;
#endif
}

xp_console::~xp_console(void)
{
#ifdef _WIN32
	SetConsoleTextAttribute(hConsole, screenInfo.wAttributes);
	hConsole = nullptr;
#endif
}

void xp_console::resetSingleOps()
{
	numberBase = 10;
	width = 0;
	filler = ' ';
}

xp_console &xp_console::operator<<(xp_console &(*_Pfn)(xp_console &obj))
{
	(*_Pfn)(*this);
	//resetSingleOps();
	return *this;
}

xp_console &xp_console::operator<< (const tscrypto::tsCryptoString &value)
{
	tscrypto::tsCryptoString data = value;

	processData(data);
	resetSingleOps();
	return *this;
}

xp_console &xp_console::operator<< (int16_t value)
{
	tscrypto::tsCryptoString data;

	if (numberBase == 16)
	{
		data.Format("%04hX", value);
	}
	else
		data.Format("%hd", value);
	processData(data);
	resetSingleOps();
	return *this;
}

xp_console &xp_console::operator<< (uint16_t value)
{
	tscrypto::tsCryptoString data;

	if (numberBase == 16)
	{
		data.Format("%04hX", value);
	}
	else
		data.Format("%hu", value);
	processData(data);
	resetSingleOps();
	return *this;
}

xp_console &xp_console::operator<< (uint8_t value)
{
	tscrypto::tsCryptoString data;

	if (numberBase == 16)
	{
		data.Format("%02hX", value);
	}
	else
		data.Format("%hu", value);
	processData(data);
	resetSingleOps();
	return *this;
}

xp_console &xp_console::operator<< (int32_t value)
{
	tscrypto::tsCryptoString data;

	if (numberBase == 16)
	{
		data.Format("%08X", value);
	}
	else
		data.Format("%d", value);
	processData(data);
	resetSingleOps();
	return *this;
}

xp_console &xp_console::operator<< (uint32_t value)
{
	tscrypto::tsCryptoString data;

	if (numberBase == 16)
	{
		data.Format("%08lX", value);
	}
	else
		data.Format("%lu", value);
	processData(data);
	resetSingleOps();
	return *this;
}

#ifdef _WIN32
xp_console &xp_console::operator<< (long value)
{
	tscrypto::tsCryptoString data;

	if (numberBase == 16)
	{
		data.Format("%08X", value);
	}
	else
		data.Format("%d", value);
	processData(data);
	resetSingleOps();
	return *this;
}

xp_console &xp_console::operator<< (unsigned long value)
{
	tscrypto::tsCryptoString data;

	if (numberBase == 16)
	{
		data.Format("%08lX", value);
	}
	else
		data.Format("%lu", value);
	processData(data);
	resetSingleOps();
	return *this;
}
#endif

xp_console &xp_console::operator<< (int8_t value)
{
	tscrypto::tsCryptoString data;
	data << value;

	processData(data);
	resetSingleOps();
	return *this;
}

xp_console &xp_console::operator<< (int64_t value)
{
	tscrypto::tsCryptoString data;

	if (numberBase == 16)
	{
		data.Format("%I64X", value);
		while (data.size() < 16)
			data.prepend('0');
	}
	else
		data.Format("%I64d", value);
	processData(data);
	resetSingleOps();
	return *this;
}

xp_console &xp_console::operator<< (uint64_t value)
{
	tscrypto::tsCryptoString data;

	if (numberBase == 16)
	{
		data.Format("%I64X", value);
		while (data.size() < 16)
			data.prepend('0');
	}
	else
		data.Format("%I64u", value);
	processData(data);
	resetSingleOps();
	return *this;
}

xp_console &xp_console::operator<< (double value)
{
	tscrypto::tsCryptoString data;

	data.Format("%*.*lf", leftDoublePrecision, rightDoublePrecision, value);
	processData(data);
	resetSingleOps();
	return *this;
}

xp_console &xp_console::operator<< (const tscrypto::tsCryptoData &value)
{
	tscrypto::tsCryptoString data;

	data = value.ToHexString();
	processData(data);
	resetSingleOps();
	return *this;
}

xp_console &xp_console::hexDump(tscrypto::tsCryptoData& data)
{
	tscrypto::tsCryptoString dump = data.ToHexDump();

	processData(dump);
	resetSingleOps();
	return *this;
}

//xp_console &xp_console::operator<< (const ts_wchar *value)
//{
//	tscrypto::tsCryptoString data;
//	data << value;
//
//	processData(data);
//	resetSingleOps();
//	return *this;
//}

xp_console &xp_console::operator<< (const char *value)
{
	tscrypto::tsCryptoString data = value;

	processData(data);
	resetSingleOps();
	return *this;
}

xp_console &xp_console::ptr(const void *pointer)
{
	tscrypto::tsCryptoString data;

	data.Format("%p", pointer);
	processData(data);
	resetSingleOps();
	return *this;
}

//xp_console &xp_console::operator<< (void *value)
//{
//    tscrypto::tsCryptoString data;
//
//    data.Format("%p", value);
//    processData(data);
//	resetSingleOps();
//    return *this;
//}
//
//xp_console &xp_console::operator<< (const void *value)
//{
//    tscrypto::tsCryptoString data;
//
//    data.Format("%p", value);
//    processData(data);
//	resetSingleOps();
//    return *this;
//}

xp_console &xp_console::setbase(int numbase)
{
	if (numbase != 10 && numbase != 16)
		return *this;
	numberBase = numbase;
	return *this;
}

xp_console &xp_console::SetWidth(int setTo)
{
	width = setTo;
	return *this;
}

xp_console &xp_console::SetFiller(char setTo)
{
	filler = setTo;
	return *this;
}

xp_console &xp_console::SetFloatPrecision(int left, int right)
{
	leftDoublePrecision = left;
	rightDoublePrecision = right;
	return *this;
}

xp_console &xp_console::indent()
{
	_indentLevel += 1;
	return *this;
}

xp_console &xp_console::outdent()
{
	_indentLevel -= 1;
	if (_indentLevel < 0)
		_indentLevel = 0;
	return *this;
}

xp_console &xp_console::setPrefix(const tscrypto::tsCryptoString& prfx)
{
	prefix = prfx;
	return *this;
}

void xp_console::processData(tscrypto::tsCryptoString &data)
{
	char *context = NULL;
	char *p;
	bool doWriteLine;
	tscrypto::tsCryptoString tmp;

	if (width < 0)
	{
		data = data.TruncOrPadRight(-width, filler);
	}
	else if (width > 0)
	{
		data = data.TruncOrPadLeft(width, filler);
	}

	data.Replace("\r\n", "\n");
	data.Replace("\r", "\n");

	if (data.size() > 0 && data[0] == '\n')
	{
		data.DeleteAt(0, 1);
		tmp = _partialLine;
		_partialLine.clear();

		if (_indentLevel > 0 && justHadNewline)
		{
			tmp.prepend(tscrypto::tsCryptoString(' ', _indentLevel * 2));
		}
#ifdef _WIN32
		SetConsoleTextAttribute(hConsole, _currentColor);
#endif
		std::cout << tmp.c_str() << std::endl;
		justHadNewline = true;
	}

	while (data.size() > 0)
	{
		doWriteLine = (TsStrChr(data.rawData(), '\n') != NULL);
		p = TsStrTok(data.rawData(), ("\n"), &context);
		tmp.clear();
		//if (justHadNewline && indentLevel > 0)
		//{
		//    tmp.resize(indentLevel * 2, ' ');
		//    if (prefix.size() > 0)
		//    {
		//        tmp.prepend(" ");
		//        tmp.prepend(prefix);
		//    }
		//    justHadNewline = false;
		//}
		tmp += p;
		if (p != NULL)
		{	// 10/11/11 krr added cast for warning C2220 strlen() so x64 would build
			data.DeleteAt(0, (uint32_t)TsStrLen(p) + 1);
		}
		else
		{
			data.DeleteAt(0, 1);
		}

		if (doWriteLine)
		{
			tmp.prepend(_partialLine);
			_partialLine.clear();

			if (_indentLevel > 0 && justHadNewline)
			{
				_partialLine.prepend(tscrypto::tsCryptoString(' ', _indentLevel * 2));
			}
#ifdef _WIN32
			SetConsoleTextAttribute(hConsole, _currentColor);
#endif
			std::cout << tmp.c_str() << std::endl;
			justHadNewline = true;
		}
		else
		{
			_partialLine << tmp;
		}
	}
}

void xp_console::HandleColorChange()
{
	if (_partialLine.size() > 0)
	{
		tscrypto::tsCryptoString tmp = _partialLine;
		_partialLine.clear();

		if (_indentLevel > 0 && justHadNewline)
		{
			tmp.prepend(tscrypto::tsCryptoString(' ', _indentLevel * 2));
		}
#ifdef _WIN32
		SetConsoleTextAttribute(hConsole, _currentColor);
#endif
		std::cout << tmp.c_str();
		justHadNewline = false;
	}
}

xp_console &xp_console::Black()
{
#ifdef _WIN32
	WORD newColor = (WORD)(0 | (_currentColor & 0xFFF0));
	if (newColor != _currentColor)
	{
		HandleColorChange();
		_currentColor = newColor;
	}
#else
    tscrypto::tsCryptoString tmp(BlackForeground);
	processData(tmp);
#endif
	return *this;
}
xp_console &xp_console::Red()
{
#ifdef _WIN32
	WORD newColor = (WORD)(FOREGROUND_RED | (_currentColor & 0xFFF0));
	if (newColor != _currentColor)
	{
		HandleColorChange();
		_currentColor = newColor;
	}
#else
    tscrypto::tsCryptoString tmp(RedForeground);
	processData(tmp);
#endif
	return *this;
}
xp_console &xp_console::Green()
{
#ifdef _WIN32
	WORD newColor = (WORD)(FOREGROUND_GREEN | (_currentColor & 0xFFF0));
	if (newColor != _currentColor)
	{
		HandleColorChange();
		_currentColor = newColor;
	}
#else
    tscrypto::tsCryptoString tmp(GreenForeground);
	processData(tmp);
#endif
	return *this;
}
xp_console &xp_console::Yellow()
{
#ifdef _WIN32
	WORD newColor = (WORD)(FOREGROUND_RED | FOREGROUND_GREEN | (_currentColor & 0xFFF0));
	if (newColor != _currentColor)
	{
		HandleColorChange();
		_currentColor = newColor;
	}
#else
    tscrypto::tsCryptoString tmp(YellowForeground);
	processData(tmp);
#endif
	return *this;
}
xp_console &xp_console::Blue()
{
#ifdef _WIN32
	WORD newColor = (WORD)(FOREGROUND_BLUE | (_currentColor & 0xFFF0));
	if (newColor != _currentColor)
	{
		HandleColorChange();
		_currentColor = newColor;
	}
#else
    tscrypto::tsCryptoString tmp(BlueForeground);
	processData(tmp);
#endif
	return *this;
}
xp_console &xp_console::Purple()
{
#ifdef _WIN32
	WORD newColor = (WORD)(FOREGROUND_RED | FOREGROUND_BLUE | (_currentColor & 0xFFF0));
	if (newColor != _currentColor)
	{
		HandleColorChange();
		_currentColor = newColor;
	}
#else
    tscrypto::tsCryptoString tmp(PurpleForeground);
	processData(tmp);
#endif
	return *this;
}
xp_console &xp_console::Cyan()
{
#ifdef _WIN32
	WORD newColor = (WORD)(FOREGROUND_BLUE | FOREGROUND_GREEN | (_currentColor & 0xFFF0));
	if (newColor != _currentColor)
	{
		HandleColorChange();
		_currentColor = newColor;
	}
#else
    tscrypto::tsCryptoString tmp(CyanForeground);
	processData(tmp);
#endif
	return *this;
}
xp_console &xp_console::White()
{
#ifdef _WIN32
	WORD newColor = (WORD)(FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_GREEN | (_currentColor & 0xFFF0));
	if (newColor != _currentColor)
	{
		HandleColorChange();
		_currentColor = newColor;
	}
#else
    tscrypto::tsCryptoString tmp(WhiteForeground);
	processData(tmp);
#endif
	return *this;
}
xp_console &xp_console::BoldBlack()
{
#ifdef _WIN32
	WORD newColor = (WORD)(0 | FOREGROUND_INTENSITY | (_currentColor & 0xFFF0));
	if (newColor != _currentColor)
	{
		HandleColorChange();
		_currentColor = newColor;
}
#else
    tscrypto::tsCryptoString tmp(BoldBlackForeground);
	processData(tmp);
#endif
	return *this;
}
xp_console &xp_console::BoldRed()
{
#ifdef _WIN32
	WORD newColor = (WORD)(FOREGROUND_RED | FOREGROUND_INTENSITY | (_currentColor & 0xFFF0));
	if (newColor != _currentColor)
	{
		HandleColorChange();
		_currentColor = newColor;
	}
#else
    tscrypto::tsCryptoString tmp(BoldRedForeground);
	processData(tmp);
#endif
	return *this;
}
xp_console &xp_console::BoldGreen()
{
#ifdef _WIN32
	WORD newColor = (WORD)(FOREGROUND_GREEN | FOREGROUND_INTENSITY | (_currentColor & 0xFFF0));
	if (newColor != _currentColor)
	{
		HandleColorChange();
		_currentColor = newColor;
	}
#else
    tscrypto::tsCryptoString tmp(BoldGreenForeground);
	processData(tmp);
#endif
	return *this;
}
xp_console &xp_console::BoldYellow()
{
#ifdef _WIN32
	WORD newColor = (WORD)(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY | (_currentColor & 0xFFF0));
	if (newColor != _currentColor)
	{
		HandleColorChange();
		_currentColor = newColor;
	}
#else
    tscrypto::tsCryptoString tmp(BoldYellowForeground);
	processData(tmp);
#endif
	return *this;
}
xp_console &xp_console::BoldBlue()
{
#ifdef _WIN32
	WORD newColor = (WORD)(FOREGROUND_BLUE | FOREGROUND_INTENSITY | (_currentColor & 0xFFF0));
	if (newColor != _currentColor)
	{
		HandleColorChange();
		_currentColor = newColor;
	}
#else
    tscrypto::tsCryptoString tmp(BoldBlueForeground);
	processData(tmp);
#endif
	return *this;
}
xp_console &xp_console::BoldPurple()
{
#ifdef _WIN32
	WORD newColor = (WORD)(FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY | (_currentColor & 0xFFF0));
	if (newColor != _currentColor)
	{
		HandleColorChange();
		_currentColor = newColor;
	}
#else
    tscrypto::tsCryptoString tmp(BoldPurpleForeground);
	processData(tmp);
#endif
	return *this;
}
xp_console &xp_console::BoldCyan()
{
#ifdef _WIN32
	WORD newColor = (WORD)(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY | (_currentColor & 0xFFF0));
	if (newColor != _currentColor)
	{
		HandleColorChange();
		_currentColor = newColor;
	}
#else
    tscrypto::tsCryptoString tmp(BoldCyanForeground);
	processData(tmp);
#endif
	return *this;
}
xp_console &xp_console::BoldWhite()
{
#ifdef _WIN32
	WORD newColor = (WORD)(FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY | (_currentColor & 0xFFF0));
	if (newColor != _currentColor)
	{
		HandleColorChange();
		_currentColor = newColor;
	}
#else
    tscrypto::tsCryptoString tmp(BoldWhiteForeground);
	processData(tmp);
#endif
	return *this;
}
xp_console &xp_console::Black_Background()
{
#ifdef _WIN32
	WORD newColor = (WORD)(0 | (_currentColor & 0xFF0F));
	if (newColor != _currentColor)
	{
		HandleColorChange();
		_currentColor = newColor;
	}
#else
    tscrypto::tsCryptoString tmp(BlackBackground);
	processData(tmp);
#endif
	return *this;
}
xp_console &xp_console::Red_Background()
{
#ifdef _WIN32
	WORD newColor = (WORD)(BACKGROUND_RED | (_currentColor & 0xFF0F));
	if (newColor != _currentColor)
	{
		HandleColorChange();
		_currentColor = newColor;
	}
#else
    tscrypto::tsCryptoString tmp(RedBackground);
	processData(tmp);
#endif
	return *this;
}
xp_console &xp_console::Green_Background()
{
#ifdef _WIN32
	WORD newColor = (WORD)(BACKGROUND_GREEN | (_currentColor & 0xFF0F));
	if (newColor != _currentColor)
	{
		HandleColorChange();
		_currentColor = newColor;
	}
#else
    tscrypto::tsCryptoString tmp(GreenBackground);
	processData(tmp);
#endif
	return *this;
}
xp_console &xp_console::Yellow_Background()
{
#ifdef _WIN32
	WORD newColor = (WORD)(BACKGROUND_RED | BACKGROUND_GREEN | (_currentColor & 0xFF0F));
	if (newColor != _currentColor)
	{
		HandleColorChange();
		_currentColor = newColor;
	}
#else
    tscrypto::tsCryptoString tmp(YellowBackground);
	processData(tmp);
#endif
	return *this;
}
xp_console &xp_console::Blue_Background()
{
#ifdef _WIN32
	WORD newColor = (WORD)(BACKGROUND_BLUE | (_currentColor & 0xFF0F));
	if (newColor != _currentColor)
	{
		HandleColorChange();
		_currentColor = newColor;
	}
#else
    tscrypto::tsCryptoString tmp(BlueBackground);
	processData(tmp);
#endif
	return *this;
}
xp_console &xp_console::Purple_Background()
{
#ifdef _WIN32
	WORD newColor = (WORD)(BACKGROUND_RED | BACKGROUND_BLUE | (_currentColor & 0xFF0F));
	if (newColor != _currentColor)
	{
		HandleColorChange();
		_currentColor = newColor;
	}
#else
    tscrypto::tsCryptoString tmp(PurpleBackground);
	processData(tmp);
#endif
	return *this;
}
xp_console &xp_console::Cyan_Background()
{
#ifdef _WIN32
	WORD newColor = (WORD)(BACKGROUND_BLUE | BACKGROUND_GREEN | (_currentColor & 0xFF0F));
	if (newColor != _currentColor)
	{
		HandleColorChange();
		_currentColor = newColor;
	}
#else
    tscrypto::tsCryptoString tmp(CyanBackground);
	processData(tmp);
#endif
	return *this;
}
xp_console &xp_console::White_Background()
{
#ifdef _WIN32
	WORD newColor = (WORD)(BACKGROUND_BLUE | BACKGROUND_GREEN | BACKGROUND_RED | (_currentColor & 0xFF0F));
	if (newColor != _currentColor)
	{
		HandleColorChange();
		_currentColor = newColor;
	}
#else
    tscrypto::tsCryptoString tmp(WhiteBackground);
	processData(tmp);
#endif
	return *this;
}

size_t xp_console::consoleWidth()
{
#ifdef _WIN32
	return screenInfo.dwMaximumWindowSize.X;
#else
	struct winsize w;
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);

	return w.ws_col;
#endif
}
size_t xp_console::consoleHeight()
{
#ifdef _WIN32
	return screenInfo.dwMaximumWindowSize.Y;
#else
	struct winsize w;
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);

	return w.ws_row;
#endif
}

#ifdef _WIN32
void xp_console::GetPin(tscrypto::tsCryptoString& enteredPin, uint32_t len, const tscrypto::tsCryptoString& prompt)
{
	DWORD md;
	HANDLE h;

	h = GetStdHandle(STD_INPUT_HANDLE);
	printf("%s\n", prompt.c_str());
	std::cout << std::flush;
	fflush(stdin);
	//	fflush(stdout);

	enteredPin.clear();
	enteredPin.resize(len);

	/* set no echo */
	GetConsoleMode(h, &md);
	SetConsoleMode(h, md & ~ENABLE_ECHO_INPUT);

	fgets(enteredPin.rawData(), len, stdin);
	enteredPin.resize(TsStrLen(enteredPin.c_str()));
	enteredPin.TrimEnd("\r\n");

	/* reset echo */
	SetConsoleMode(h, md);
	std::cout << std::flush;
	printf("\n");
	std::cout << std::flush;
}
#else
void xp_console::GetPin(tscrypto::tsCryptoString& enteredPin, uint32_t len, const tscrypto::tsCryptoString& prompt)
{
	fprintf(stdout, "\n%s\n", prompt.c_str());
	fflush(stdin);
	fflush(stdout);

	enteredPin.clear();
	enteredPin.resize(len + 5);

	{  // declare a new code block so I can declare these variables, but keep the printf above them.
#ifdef MAC
        struct termios t;
        
        tcgetattr(0, &t);
        t.c_lflag &= ~ECHO;
        tcsetattr(0, TCSANOW, &t);
        
        fgets(enteredPin.rawData(), len, stdin);
        
        t.c_lflag |= ECHO;
        tcsetattr(0, TCSANOW, &t);
        
#else
		struct termio savetty, settty;

		ioctl(0, TCGETA, &savetty);
		ioctl(0, TCGETA, &settty);
		settty.c_lflag &= ~ECHO;
		ioctl(0, TCSETAF, &settty);

		fgets(enteredPin.rawData(), len, stdin);

		ioctl(0, TCSETAF, &savetty);
#endif // MAC
	}

	printf("\n\n");

	enteredPin.resize(strlen(enteredPin.c_str()) - 1);
}
#endif
