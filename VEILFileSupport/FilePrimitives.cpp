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


    // Open the file whose streams we want to enumerate.
    if ( INVALID_HANDLE_VALUE == ( hFile = CreateFileA ( filename.c_str(), GENERIC_READ,
         0, NULL, OPEN_EXISTING, 0, 0 )))
    {
        //DebugError << "Unable to open the source file." << endl;
        return false;
    }

    // Read the first 20 bytes of the stream (all but the last field)
    while ( (bContinue = ::BackupRead ( hFile, ( LPBYTE ) &Sid,
            sizeof ( Sid ) - sizeof ( WCHAR* ), &dwRead, FALSE, FALSE,
            &lpContext )) != FALSE )
    {
        // If we are done or there was no data read, break out
        if ( !bContinue || 0 == dwRead )
            break;

        // If this stream is named Alternate Data, get it's name.
        if ( BACKUP_ALTERNATE_DATA == Sid.dwStreamId &&
             0 < Sid.dwStreamNameSize )
        {
            WCHAR* pStreamName;
            pStreamName = ( WCHAR* ) malloc ( Sid.dwStreamNameSize * 3 );
            memset(pStreamName, 0, Sid.dwStreamNameSize * 3);

            if ( NULL == pStreamName )
                break;

            ::BackupRead ( hFile, ( byte* ) pStreamName,
                Sid.dwStreamNameSize, &dwRead, FALSE, FALSE, &lpContext );

			if (pStreamName[0] == ',' && pStreamName[1] == 0 && dwRead > 2)
				pStreamName[0] = 0;
            else if ( wcslen(pStreamName) >= 6 && wcscmp(&pStreamName[wcslen(pStreamName) - 6], L":$DATA") == 0 )
                pStreamName[wcslen(pStreamName) - 6] = 0;

            if ( pStreamName[0] )
            {
                list->push_back(CryptoUtf16(pStreamName).toUtf8());
            }

            if ( pStreamName )
            {
                free ( pStreamName );
                pStreamName = NULL;
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

