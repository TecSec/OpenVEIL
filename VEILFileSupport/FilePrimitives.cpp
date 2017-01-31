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

//static bool IsNTPlatform()
//{
//#ifdef _WIN32
//    bool bResult = true;
//
//    OSVERSIONINFO osvi;
//    ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
//    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
//
//    if (! GetVersionEx ( (OSVERSIONINFO *) &osvi))
//        bResult = FALSE;
//    else if (osvi.dwPlatformId != VER_PLATFORM_WIN32_NT)
//        bResult = FALSE;
//
//    return bResult;
//#else
//    #error Not implemented yet
//#endif
//}

#if 0
void EnumStreams(char *strFilePath)
{
	PVOID streamContext = 0;
	DWORD dwReadBytes, seek_high;
	WIN32_STREAM_ID streamHeader;
	WCHAR strStreamName[MAX_PATH];
	char strBuffer[1024];

	//Open the file for stream enumeration
	HANDLE hFile = CreateFileA(strFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Failed to open the file %s, Error=0x%.8x", strFilePath, GetLastError());
		return;
	}
	while (1)
	{
		//check if we have reached the end of file
		if (FALSE == BackupRead(hFile, (LPBYTE)&streamHeader, (LPBYTE)&streamHeader.cStreamName - (LPBYTE)&streamHeader, &dwReadBytes, FALSE, FALSE, &streamContext))
		{
			break;
		}

		//check if we have read the stream header properly
		if ((long)dwReadBytes != (LPBYTE)&streamHeader.cStreamName - (LPBYTE)&streamHeader)
			break;

		//we are interested only in alternate data streams
		if (streamHeader.dwStreamId == BACKUP_ALTERNATE_DATA)
		{
			if (streamHeader.dwStreamNameSize != 0)
			{
				if (BackupRead(hFile, (LPBYTE)strStreamName, streamHeader.dwStreamNameSize, &dwReadBytes, FALSE, FALSE, &streamContext))
				{
					strStreamName[streamHeader.dwStreamNameSize / 2] = L'\0';
					//
					//Reformat the stream file name ... :stream.txt:$DATA
					//
					sprintf_s(strBuffer, 1024, "%S", &strStreamName[1]);
					char *ptr = strchr(strBuffer, ':');
					if (ptr != NULL)
						*ptr = '\0';

					printf("\n Found Stream - %s", strBuffer);
				}
			}
		}

		// jump to the next stream header
		if (BackupSeek(hFile, 0, 0, &dwReadBytes, &seek_high, &streamContext) == FALSE)
		{
			//for any errors other than seek break out of loop
			if (GetLastError() != ERROR_SEEK)
			{
				// terminate BackupRead() loop
				BackupRead(hFile, 0, 0, &dwReadBytes, TRUE, FALSE, &streamContext);
				break;
			}

			streamHeader.Size.QuadPart -= dwReadBytes;
			streamHeader.Size.HighPart -= seek_high;

			BYTE buffer[4096];

			while (streamHeader.Size.QuadPart > 0)
			{

				if (dwReadBytes != sizeof(buffer) ||
					!BackupRead(hFile,
						buffer,
						sizeof(buffer),
						&dwReadBytes,
						FALSE,

						FALSE,
						&streamContext))
				{
					break;
				}

				streamHeader.Size.QuadPart -= dwReadBytes;

			} //end of inner while loop

		} //end of 'jump to next stream' if loop


	} //main while loop


	  //Finally clean up the buffers used for seeking
	if (streamContext)
		BackupRead(hFile, 0, 0, &dwReadBytes, TRUE, FALSE, &streamContext);


	CloseHandle(hFile);

	return;
}
#endif // 0

bool GetStreamNames (const tscrypto::tsCryptoString& filename, tscrypto::tsCryptoStringList &list)
{
	if (!list)
		list = CreateTsAsciiList();
    list->clear();

#ifdef _WIN32

    // Alternate file streams are only supported on NT platforms.
    //if ( !IsNTPlatform())
    //{
    //    return S_OK;
    //}

    HANDLE hFile;
    BOOL bContinue;
    void *lpContext = NULL;
    WIN32_STREAM_ID Sid;
    DWORD dwRead = 0;
    DWORD dwLowBytes = 0;
    DWORD dwHighBytes = 0;
	tscrypto::CryptoUtf16 buffer;

    // Open the file whose streams we want to enumerate.
    if ( INVALID_HANDLE_VALUE == ( hFile = CreateFileA ( filename.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0 )))
    {
        //DebugError << "Unable to open the source file." << endl;
        return false;
    }

    // Read the first 20 bytes of the stream (all but the last field)
    while ( (bContinue = ::BackupRead ( hFile, ( LPBYTE ) &Sid, (DWORD)((LPBYTE)&Sid.cStreamName - (LPBYTE)&Sid), &dwRead, FALSE, FALSE, &lpContext )) != FALSE )
    {
        // If we are done or there was no data read, break out
        if ( !bContinue || 0 == dwRead || (long)dwRead != (LPBYTE)&Sid.cStreamName - (LPBYTE)&Sid)
			break;

        // If this stream is named Alternate Data, get it's name.
        if ( BACKUP_ALTERNATE_DATA == Sid.dwStreamId && 0 < Sid.dwStreamNameSize )
        {
			buffer.clear();
			buffer.resize(Sid.dwStreamNameSize / 2);

			::BackupRead ( hFile, ( byte* )buffer.data(), Sid.dwStreamNameSize, &dwRead, FALSE, FALSE, &lpContext );

			if ( wcslen(buffer.data()) >= 6 && wcscmp(buffer.data() + (wcslen(buffer.data()) - 6), L":$DATA") == 0 )
                buffer.erase(buffer.size() - 6, 6);
			if (buffer == L":Zone.Identifier")
				buffer.clear();

            if ( !buffer.empty() )
            {
                list->push_back(buffer.toUtf8());
            }
        }

        // Seek to the end of this stream so we can check the next one.
        ::BackupSeek ( hFile, Sid.Size.LowPart, Sid.Size.HighPart,
                        &dwLowBytes, &dwHighBytes, &lpContext );
    }

    // free memory allocated by BackupRead and close the file
    ::BackupRead ( hFile, ( BYTE* ) &Sid, 0, &dwRead, TRUE, FALSE, &lpContext );
    CloseHandle ( hFile );
    return true;
#else
    // No other platforms at this time support Alternate Date Streams.
    return true;
#endif
}

