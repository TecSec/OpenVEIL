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


#ifndef TSLIST_H_INCLUDED
#define TSLIST_H_INCLUDED

#include "TSGrid.h"

extern ATOM TSListInstall(HINSTANCE dllInstance);

typedef enum LIST_MESSAGE_TYPE {
    RAL_INIT				= WM_USER+1,
//    RAL_LOADFILE			= WM_USER+2,
//    RAL_LOADMEM				= WM_USER+3,
    RAL_TEXTCOLOR			= WM_USER+4,
    RAL_BKCOLOR				= WM_USER+5,
    RAL_SETFONT				= WM_USER+6,
    RAL_FRAMECOLORLO		= WM_USER+7,
    RAL_FRAMECOLORHI		= WM_USER+8,
    RAL_COLORBACKGRD		= WM_USER+9,
    RAL_BITMAPBACKGRD		= WM_USER+10,
    RAL_SPEEDUPDOWN			= WM_USER+11,
    RAL_NOCOLUMNHEADER		= WM_USER+12,
    RAL_MOVEBUTTONSX		= WM_USER+13,
    RAL_CURBUTTONS			= WM_USER+14,
    RAL_CURLISTVIEW			= WM_USER+15,
    RAL_PROGRESSMODEL		= WM_USER+16,
    RAL_PROGRESSHEIGHT		= WM_USER+17,
    RAL_NOPROGRESS			= WM_USER+18,
    RAL_NO3DFRAME			= WM_USER+19,
    RAL_PROGRESSCOLORV		= WM_USER+20,
    RAL_PROGRESSCOLORH		= WM_USER+21,
} LIST_MESSAGE_TYPE;

/*
STYLE					equ WS_CHILD or WS_VISIBLE
EXSTYLE					equ 200h
IDB_BMP					equ 100

EXSTYLE_NONE			equ 0 ;options RaDasm
*/

typedef struct TSLIST {
	// Progressbar
	DWORD count;
	DWORD maxi;
	DWORD left;
	DWORD height;
	DWORD ModelColor;
	DWORD color1;       // ; c�t�s clairs
	DWORD color2;       // ; c�t�s sombres
	DWORD color3;       // ; haut
	DWORD color4;       // ; sol
	// end of Progressbar

	// ListView
	HWND hListView;
	HANDLE pOriginal;   // ; contient l'original de Cible
	HANDLE pData;       // ; utilis� dans LoadFileorMem
	HANDLE pIndex;      // ; utilis� dans LoadFileorMem et pour afficher la liste
	char *pTemp;        // ; contient Cible modifi� lorsque l'user veut descendre ou monter
	DWORD InStringCount;// ; conserve le nombre de lignes coup�es
	DWORD FrameColorLo;
	DWORD FrameColorHi;
	DWORD ButtonBackgrd;
	HBITMAP ButtonBkgBitmap;
	DWORD SleepUpDown;  // ; vitesse pour descendre/monter, d�faut: 40 ms
	DWORD totallignes;
	HICON hCursorB;
	HICON hCursorL;
	DWORD noProgress;
	DWORD no3dFrame;
	// end of ListView
} TSLIST;

#endif // TSLIST_H_INCLUDED
