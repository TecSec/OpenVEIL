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

// file2hex.cpp : Defines the entry point for the console application.
//

#include "StdAfx.h"


static void usage ()
{
    printf ("USAGE:  File2Hex <FileName>\n\nThis application reads the file and outputs on stdout the hex of the file.\n");
}

int main(int argc, char* argv[])
{
	FILE *f = nullptr;
    char *buffer;
    DWORD size;
    DWORD red;

    if ( argc != 2 )
    {
        usage();
        return 1;
    }

	f = fopen(argv[1], "r");
	if (f == nullptr)
    {
        printf ("The specified file could not be opened.\n\n");
        usage();
        return 1;
    }
	fseek(f, 0, SEEK_END);
	size = ftell(f);
	fseek(f, 0, SEEK_SET);
	if ( size < 1 || size > 1000000 )
    {
        printf("The file is too large.\n\n");
        fclose(f);
        usage();
        return 1;
    }
    buffer = new char[size];
    if ( buffer == NULL )
    {
		fclose(f);
        printf ("The file is too large for available memory.\n\n");
        usage();
        return 1;
    }
	if (fread(buffer, 1, size, f) != size)
    {
		fclose(f);
        printf ("Unable to read the file contents.\n\n");
        usage();
        delete [] buffer;
        return 1;
    }
	fclose(f);

    for ( red = 0; red < size; red++ )
    {
        printf ("0x%02X,", buffer[red] & 0xff);
        if ( (red % 75) == 74)
            printf ("\n");
    }
    delete [] buffer;


	return 0;
}
