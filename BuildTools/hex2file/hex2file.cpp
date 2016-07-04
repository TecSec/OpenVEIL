//	Copyright (c) 2016, TecSec, Inc.
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

// hex2file.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

int main(int argc, const char* argv[])
{
    std::fstream out;
    char buffer[1];
    bool hiDigit = true;
    unsigned char byte = 0;
    bool gotOne;
    std::istream *in = &std::cin;

    if ( argc != 2 && argc != 3 )
    {
        printf ("HEX2FILE <outputfile> [<inputfile>]\n"
            "Hex2file takes a hex string from standard input [or the optional input file] \n"
            "and converts it into binary data into the specified output file.\n");
        return 1;
    }
    if ( argc == 3 )
    {
		printf ("Input file '%s'\n", argv[2]);
        in = new std::fstream;
        ((std::fstream*)in)->open (argv[2], std::ios_base::in);
    }
	printf ("Output file '%s'\n", argv[1]);

    out.open(argv[1], std::ios_base::out | std::ios_base::trunc | std::ios_base::binary);

    if ( !out.is_open() )
    {
        printf ("Unable to open the output file '%s'\n", argv[1]);
        return 1;
    }

    do
    {
        in->read(buffer, 1);
        if ( in->good() )
        {
            gotOne = false;
            if ( (buffer[0] >= '0' && buffer[0] <= '9') )
            {
                byte = (unsigned char)((byte << 4) | ((buffer[0] - '0') & 0x0f));
                gotOne = true;
            }
            else if ( buffer[0] >= 'a' && buffer[0] <= 'f' )
            {
                byte = (unsigned char)((byte << 4) | ((buffer[0] - 'a' + 10) & 0x0f));
                gotOne = true;
            }
            else if (buffer[0] >= 'A' && buffer[0] <= 'F' )
            {
                byte = (unsigned char)((byte << 4) | ((buffer[0] - 'A' + 10) & 0x0f));
                gotOne = true;
            }
            else
            {}
            if ( gotOne )
            {
                hiDigit = !hiDigit;
                if ( hiDigit )
                {
                    out.write((const char *)&byte, 1);
                    byte = 0;
                }
            }
        }
    }
	while (in->good());
    if ( !hiDigit )
    {
        printf ("WARNING:  The hex stream had an odd number of hex digits.  The last nibble was\n"
                "          not saved.\n");
    }

    out.close();
	return 0;
}

