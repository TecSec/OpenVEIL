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
#include <windows.h>
#include <commctrl.h>
#include "resource.h"
#include "TSList.h"

#define	szLView	("SysListView32")
#define szClassName	("TSLIST")
#define szToolTip ("TSList")
#define Bmp_Button_Class ("Bmp_Button_Class_Ex")
#define ButnImageClass ("STATIC")
#define STYLE_LINES				(4)

static WNDPROC lpLstView	= 0;
static DWORD compteur = 0;
static BOOL repeatsound	= TRUE;
static LVCOLUMNA pColumn = {0,};
static BOOL active = FALSE;
static HINSTANCE hInstance = 0;
static DWORD Temp = 0;

static LRESULT __stdcall BmpButnProc (HWND hWin, UINT uMsg, WPARAM wParam, LPARAM lParam);
static void Frame3D (HDC hDC, COLORREF btn_hi, COLORREF btn_lo, DWORD tx, DWORD ty, DWORD lx, DWORD ly, DWORD bdrWid);

//static void szMid(char *dest,char *src,DWORD start,DWORD end)
//{
//    memmove(dest, &src[start], end - start + 1);
//}

void DrawProgress (HDC hDC, HWND hWind, DWORD height_, DWORD pos, DWORD maxi_, DWORD left, DWORD top, DWORD modelcolor)
{
    DWORD	pixel;
    HBRUSH  hBrush1,hBrush2,hBrush3,hBrush4,hBrush5,hBrush6;
    HPEN    hPen1,hPen2,hPen3;
    HPEN    sPen1;
    HBRUSH  sBrush6;
    COLORREF sTxtColor;
    COLORREF sBkColor;
    POINT   szPoint[11];

	if (maxi_ < pos)
	{
        pos = maxi_;
	}

	hPen1 = CreatePen(PS_SOLID, 1, (COLORREF)0x0FFE0E0);
	hPen2 = CreatePen(PS_SOLID, 1, 0x00525229);
	hPen3 = CreatePen(PS_SOLID, 1, 0x00FFAEAE);

	TSLIST *listPtr = (TSLIST*)GetWindowLongPtr(hWind,0);

	if (listPtr->color1 != 0)
	{
        hBrush1 = CreateSolidBrush(listPtr->color1);
		hBrush2 = CreateSolidBrush(listPtr->color1);
		hBrush3 = CreateSolidBrush(listPtr->color3);
		hBrush4 = CreateSolidBrush(listPtr->color4);
		hBrush5 = CreateSolidBrush(listPtr->color2);
		hBrush6 = CreateSolidBrush(listPtr->color2);
	}
    else if (modelcolor == 0)
    {
		hBrush1 = CreateSolidBrush(0x00FFFFFF);
		hBrush2 = CreateSolidBrush(0x00FFFFFF);
		hBrush3 = CreateSolidBrush(0x00C18686);
		hBrush4 = CreateSolidBrush(0x00E7CFCF);
		hBrush5 = CreateSolidBrush(0x00EEDDDD);
		hBrush6 = CreateSolidBrush(0x00EEDDDD);
	}
    else if (modelcolor == 1)
    {
		hBrush1 = CreateSolidBrush(0x00D7AEAE);
		hBrush2 = CreateSolidBrush(0x00D7AEAE);
		hBrush3 = CreateSolidBrush(0x00D0A2A2);
		hBrush4 = CreateSolidBrush(0x00C99292);
		hBrush5 = CreateSolidBrush(0x00BC7878);
		hBrush6 = CreateSolidBrush(0x00BF8080);
	}
    else if (modelcolor == 2)
    {
		hBrush1 = CreateSolidBrush(0x00DFDFDF);
		hBrush2 = CreateSolidBrush(0x00DFDFDF);
		hBrush3 = CreateSolidBrush(0x00717100);
		hBrush4 = CreateSolidBrush(0x009F9F9F);
		hBrush5 = CreateSolidBrush(0x00B9B9B9);
		hBrush6 = CreateSolidBrush(0x00B9B9B9);
	}
    else if (modelcolor == 3)
    {
		hBrush1 = CreateSolidBrush(0x00F0E1EC);
		hBrush2 = CreateSolidBrush(0x00F0E1EC);
		hBrush3 = CreateSolidBrush(0x00E4BCCB);
		hBrush4 = CreateSolidBrush(0x00DFBFD8);
		hBrush5 = CreateSolidBrush(0x00E4C9DD);
		hBrush6 = CreateSolidBrush(0x00E4C9DD);
	}
    else if (modelcolor == 4)
    {
		hBrush1 = CreateSolidBrush(0x00FB3CB4);
		hBrush2 = CreateSolidBrush(0x00FB3CB4);
		hBrush3 = CreateSolidBrush(0x00FF93C9);
		hBrush4 = CreateSolidBrush(0x00EB0394);
		hBrush5 = CreateSolidBrush(0x00FB0DA2);
		hBrush6 = CreateSolidBrush(0x00FB0DA2);
	}
    else //if (modelcolor == 5)
    {
		hBrush1 = CreateSolidBrush(0x00D075D5);
		hBrush2 = CreateSolidBrush(0x00D075D5);
		hBrush3 = CreateSolidBrush(0x00E2AAE6);
		hBrush4 = CreateSolidBrush(0x00C85CCD);
		hBrush5 = CreateSolidBrush(0x00CB66D0);
		hBrush6 = CreateSolidBrush(0x00CB66D0);
    }

	sPen1 = (HPEN)SelectObject(hDC, hPen1);
	sBrush6 = (HBRUSH)SelectObject(hDC, hBrush6);

	top += 9;
	height_ -= 16;

    pixel = top + height_ - (pos * height_) / maxi_;

	sTxtColor = SetTextColor(hDC,0x80005C); // ;color text
	sBkColor = SetBkColor(hDC,GetSysColor(15));

    memset (szPoint, 0, sizeof(szPoint));

	szPoint[0].x = 20 + left;
	szPoint[0].y = pixel - 11;
	szPoint[1].x = 5 + left;
	szPoint[1].y = pixel - 6;
	szPoint[2].x = 5 + left;
	szPoint[2].y = top - 5;
	szPoint[3].x = 20 + left;
	szPoint[3].y = top;

	Polygon(hDC,szPoint,4);
	SelectObject(hDC,hBrush1);

    memset (szPoint, 0, sizeof(szPoint));

	szPoint[0].x = 20 + left;
	szPoint[0].y = pixel - 11;
	szPoint[1].x = 35 + left;
	szPoint[1].y = pixel - 6;
	szPoint[2].x = 35 + left;
	szPoint[2].y = top - 5;
	szPoint[3].x = 20 + left;
	szPoint[3].y = top;

	Polygon(hDC,szPoint,4);

    memset (szPoint, 0, sizeof(szPoint));

	szPoint[0].x = 5 + left;
	szPoint[0].y = top - 5;
	szPoint[1].x = 20 + left;
	szPoint[1].y = top - 10;
	szPoint[2].x = 35 + left;
	szPoint[2].y = top - 5;
	szPoint[3].x = 20 + left;
	szPoint[3].y = top;

	Polygon(hDC,szPoint,4);

	SelectObject(hDC, hPen1);
	SelectObject(hDC, hBrush5);


    memset (szPoint, 0, sizeof(szPoint));

	szPoint[0].x = 20 + left;
	szPoint[0].y = top + height_ + 5;
	szPoint[1].x = 5 + left;
	szPoint[1].y = top + height_;
	szPoint[2].x = 5 + left;
	szPoint[2].y = pixel - 6;
	szPoint[3].x = 20 + left;
	szPoint[3].y = pixel;

	Polygon(hDC,szPoint,4);

	SelectObject(hDC,hBrush2);

    memset (szPoint, 0, sizeof(szPoint));

	szPoint[0].x = 20 + left;
	szPoint[0].y = top + height_ + 5;
	szPoint[1].x = 35 + left;
	szPoint[1].y = top + height_;
	szPoint[2].x = 35 + left;
	szPoint[2].y = pixel - 6;
	szPoint[3].x = 20 + left;
	szPoint[3].y = pixel;

	Polygon(hDC,szPoint,4);

	SelectObject(hDC, hPen3);
	SelectObject(hDC, hBrush4);

    memset (szPoint, 0, sizeof(szPoint));

	szPoint[0].x = 20 + left;
	szPoint[0].y = top + height_ + 5;
	szPoint[1].x = 35 + left;
	szPoint[1].y = top + height_;
	szPoint[2].x = 20 + left;
	szPoint[2].y = top + height_ - 6;
	szPoint[3].x = 5 + left;
	szPoint[3].y = top + height_;

	Polygon(hDC,szPoint,4);

	SelectObject(hDC, hPen2);
	SelectObject(hDC, hBrush3);

    memset (szPoint, 0, sizeof(szPoint));

	szPoint[0].x = 20 + left;
	szPoint[0].y = pixel;
	szPoint[1].x = 5 + left;
	szPoint[1].y = pixel + 6;
	szPoint[2].x = 20 + left;
	szPoint[2].y = pixel + 11;
	szPoint[3].x = 35 + left;
	szPoint[3].y = pixel + 6;

	Polygon(hDC,szPoint,4);

	SelectObject(hDC,hPen1);

    memset (szPoint, 0, sizeof(szPoint));

	szPoint[0].x = 20 + left;
	szPoint[0].y = top + height_ + 5;
	szPoint[1].x = 5 + left;
	szPoint[1].y = top + height_;
	szPoint[2].x = 5 + left;
	szPoint[2].y = top + height_ + 5;
	szPoint[3].x = 20 + left;
	szPoint[3].y = top;
	szPoint[4].x = 20 + left;
	szPoint[4].y = top + height_ + 5;
	szPoint[5].x = 35 + left;
	szPoint[5].y = top + height_;
	szPoint[6].x = 35 + left;
	szPoint[6].y = top - 5;
	szPoint[7].x = 20 + left;
	szPoint[7].y = top;
	szPoint[8].x = 5 + left;
	szPoint[8].y = top - 5;
	szPoint[9].x = 20 + left;
	szPoint[9].y = top - 10;
	szPoint[10].x = 35 + left;
	szPoint[10].y = top + 6;

	Polygon(hDC,szPoint,11);

    DeleteObject(hPen1);
    DeleteObject(hPen2);
    DeleteObject(hPen3);
    DeleteObject(hBrush1);
    DeleteObject(hBrush2);
    DeleteObject(hBrush3);
    DeleteObject(hBrush4);
    DeleteObject(hBrush5);
    DeleteObject(hBrush6);

	// ReleaseDC(hWnd,hDC);
}

/*
comment &
	BmpButton original Macro modified by Faiseur
	--------------------------------------------

	Modified:

	- Send WM_COMMAND Message if WM_LBUTTONDOWN is pressed (original proc send message if WM_LBUTTONUP is pressed...)

	Added:

	- Send multiple WM_COMMAND  Message if WM_LBUTTONDOWN remain pressed (speed default is 40ms)
	- Speed of multiple WM_LBUTTONDOWN message can be modified by user
&
    .code

; ########################################################################
*/

static HWND BmpButtonEx (HWND hParent, DWORD topX, DWORD topY, const char *rnum1, const char *rnum2, DWORD IDs)
{
  //; parameters are,
  //; 1.  Parent handle
  //; 2/3 top X & Y co-ordinates
  //; 4/5 resource RALIST.ID numbers or identifiers for UP & DOWN bitmaps
  //; 6   RALIST.ID number for control

    HWND hButn1;
    HWND hImage;
    HMODULE hModule;
    DWORD wid;
    DWORD hgt;
    HBITMAP hBmpU;
    HBITMAP hBmpD;
    RECT Rct;
    WNDCLASSEXA wc;

    hModule = GetModuleHandle(NULL);
    hBmpU = LoadBitmapA(hModule,rnum1);
    hBmpD = LoadBitmapA(hModule,rnum2);

    wc.cbSize = sizeof(WNDCLASSEX);
    wc.style = CS_BYTEALIGNWINDOW;
    wc.lpfnWndProc = (WNDPROC)BmpButnProc;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 4 * sizeof(void *);
    wc.hInstance = hModule;
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE+1);
    wc.lpszMenuName = NULL;
    wc.lpszClassName = Bmp_Button_Class;
    wc.hIcon = NULL;
    wc.hCursor = LoadCursor(NULL,IDC_ARROW);
    wc.hIconSm = NULL;

    RegisterClassExA(&wc);

    hButn1 = CreateWindowExA(WS_EX_TRANSPARENT, Bmp_Button_Class, NULL, WS_CHILD | WS_VISIBLE, topX, topY, 100, 100,hParent,
            (HMENU)(INT_PTR)IDs, hModule, NULL);

    SetWindowLongPtr(hButn1,0,(LONG_PTR)hBmpU);
    SetWindowLongPtr(hButn1,sizeof(LONG_PTR),(LONG_PTR)hBmpD);

    hImage = CreateWindowExA(0, ButnImageClass, NULL, WS_CHILD | WS_VISIBLE | SS_BITMAP, 0, 0, 0, 0, hButn1, (HMENU)(INT_PTR)IDs,
            hModule,NULL);

    SendMessageA(hImage,STM_SETIMAGE,IMAGE_BITMAP,(LPARAM)hBmpU);

    GetWindowRect(hImage, &Rct);
    SetWindowLongPtr(hButn1,2*sizeof(LONG_PTR),(LONG_PTR)hImage);

    hgt = Rct.bottom - Rct.top;
    wid = Rct.right - Rct.left;

    SetWindowPos(hButn1,HWND_TOP,0,0,wid,hgt,SWP_NOMOVE);
    ShowWindow(hButn1,SW_SHOW);
    return hButn1;
}

//; ########################################################################

static LRESULT __stdcall BmpButnProc (HWND hWin, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    HBITMAP hBmpU;
    HBITMAP hBmpD;
    HWND hImage;
    HWND hParent;
//    DWORD IDs;
    DWORD ptX;
    DWORD ptY;
    DWORD bWid;
    DWORD bHgt;
    RECT Rct;
    static DWORD cFlag = 0; // a GLOBAL variable for the "clicked" setting

    switch (uMsg)
    {
    case WM_LBUTTONDOWN:
        hBmpD = (HBITMAP)GetWindowLongPtr(hWin,sizeof(LONG_PTR));
        hImage = (HWND)GetWindowLongPtr(hWin,2*sizeof(LONG_PTR));
        SendMessage(hImage,STM_SETIMAGE,IMAGE_BITMAP,(LPARAM)hBmpD);
        SetCapture(hWin);
        cFlag = 1;
        repeatsound = TRUE;
		hParent = GetParent(hWin);
		SendMessage(hParent,WM_COMMAND,GetDlgCtrlID(hWin),(LPARAM)hWin);
		SetTimer(hWin,999,((TSLIST*)GetWindowLongPtr(hParent,0))->SleepUpDown,0);
        break;
	case WM_TIMER:
        if (wParam == 999)
        {
            if (GetAsyncKeyState(VK_LBUTTON) != 0)
            {
                repeatsound = FALSE;
                hParent = GetParent(hWin);
                return SendMessage(hParent,WM_COMMAND,GetDlgCtrlID(hWin),(LPARAM)hWin);
            }
            KillTimer(hWin,999);
        }
        break;
	case WM_SETCURSOR:
		hParent = GetParent(hWin);
		if (((TSLIST*)GetWindowLongPtr(hParent,0))->hCursorB != 0)
		{
			SetCursor(((TSLIST*)GetWindowLongPtr(hParent,0))->hCursorB);
			return 0;
		}
        break;
    case WM_LBUTTONUP:
        if (cFlag == 0)
        {
            return 0;
        }
        else
        {
            cFlag = 0;
        }

        hBmpU = (HBITMAP)GetWindowLongPtr(hWin,0);
        hImage = (HWND)GetWindowLongPtr(hWin,2*sizeof(LONG_PTR));
        SendMessage(hImage,STM_SETIMAGE,IMAGE_BITMAP,(LPARAM)hBmpU);

        ptX = LOWORD(lParam);
        ptY = HIWORD(lParam);

        GetWindowRect(hWin, &Rct);
        bWid = Rct.right - Rct.left;
        bHgt = Rct.bottom - Rct.top;

        //; --------------------------------
        //; exclude button releases outside
        //; of the button rectangle from
        //; sending message back to parent
        //; --------------------------------

        if ( ptX > 0 && ptY > 0 )
        {
            if ( ptX < bWid )
            {
                if ( ptY < bHgt )
                {
                }
            }
        }
        ReleaseCapture();
        break;
    }

    return DefWindowProc(hWin,uMsg,wParam,lParam);
}

static LRESULT Paint_Proc (HWND hWin, HDC hDC)
{
    COLORREF btn_hi;
    COLORREF btn_lo;
    RECT Rct;

    //;  invoke GetSysColor,COLOR_BTNHIGHLIGHT
    TSLIST *listPtr = (TSLIST*)GetWindowLongPtr(hWin,0);
    btn_hi = listPtr->FrameColorHi;

    //; invoke GetSysColor,COLOR_BTNSHADOW
    btn_lo = listPtr->FrameColorLo;

	GetClientRect(hWin, &Rct);
	Rct.right -= 4;
	Rct.bottom -= 4;

    //; -----------------------------------------------------
    //; The following 2 calls draw the left window frame area
    //; -----------------------------------------------------
    Frame3D(hDC,btn_lo,btn_hi,4,4,Rct.right,Rct.bottom,6);
    Rct.right -= 4;
    Rct.bottom -= 4;
    Frame3D(hDC,btn_hi,btn_lo,8,8,Rct.right,Rct.bottom,4);

    return 0;
}

static void Frame3D (HDC hDC, COLORREF btn_hi, COLORREF btn_lo, DWORD tx, DWORD ty, DWORD lx, DWORD ly, DWORD bdrWid)
{
    HPEN hPen;
    HPEN hPen2;
    HPEN hpenOld;

    hPen = CreatePen(0,1,btn_hi);

    hpenOld = (HPEN)SelectObject(hDC,hPen);

    //; ------------

    DWORD tmply = ly;
    DWORD tmplx = lx;
    DWORD tmpty = ty;
    DWORD tmptx = tx;
    DWORD tmpbdrWid = bdrWid;

    do
    {

        MoveToEx(hDC,tmptx,tmpty,NULL);
        LineTo(hDC,tmplx,tmpty);

        MoveToEx(hDC,tmptx,tmpty,NULL);
        LineTo(hDC,tmptx,tmply);

        tmptx--;
        tmpty--;
        tmplx++;
        tmply++;

        tmpbdrWid--;
    }
    while (tmpbdrWid < 0x80000000);

    //; ------------
    hPen2 = CreatePen(0,1,btn_lo);
    SelectObject(hDC,hPen2);
    DeleteObject(hPen);
    //; ------------

    do
    {
        MoveToEx(hDC,tx,ly,NULL);
        LineTo(hDC,lx,ly);

        MoveToEx(hDC,lx,ty,NULL);
        ly++;
        LineTo(hDC,lx,ly);
        ly--;

        tx--;
        ty--;
        lx++;
        ly++;

        bdrWid--;
    }
    while (bdrWid < 0x80000000);

    //; ------------
    SelectObject(hDC,hpenOld);
    DeleteObject(hPen2);
}

//static LONG_PTR LoadFileorMem (TSLIST *listPtr, const char *Cible,DWORD Mode) // ; Mode == 1: LoadFile / Mode == 2: LoadMem / Mode == 3: update position but not update list (used with button)
//{
//    HANDLE hfile;
//    DWORD dwread,dwSize;
//
//	if (Mode == 1) // ; File
//	{
//		hfile = CreateFile(Cible,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN,0);
//		if (hfile == INVALID_HANDLE_VALUE)
//		{
//			return (LONG_PTR)hfile;
//		}
//		dwSize = GetFileSize(hfile,NULL);
//	}
//	else
//	{ // ; Mem
//		dwSize = lstrlen(Cible);
//	}
//
//	if (listPtr->pData != 0) // ; si l'utilisateur veut changer de liste on d�charge la m�moire utilis�e
//	{
//		VirtualFree(listPtr->pData,0,MEM_RELEASE);
//		VirtualFree(listPtr->pIndex,0,MEM_RELEASE);
//		if (Mode != 3)
//		{
//			VirtualFree(listPtr->pOriginal,0,MEM_RELEASE);
//		}
//	}
//
//	if (Mode != 3)
//	{
//		listPtr->pOriginal = VirtualAlloc(NULL,dwSize,MEM_COMMIT,PAGE_READWRITE);
//	}
//	listPtr->pData = VirtualAlloc(NULL,dwSize,MEM_COMMIT,PAGE_READWRITE);
//	listPtr->pIndex = VirtualAlloc(NULL,dwSize,MEM_COMMIT,PAGE_READWRITE);
//
//	if (Mode == 1) // ; File
//	{
//		ReadFile(hfile,listPtr->pData,dwSize, &dwread,NULL);
//		if (Mode != 3)
//		{
//			lstrcpyn((char*)listPtr->pOriginal,(const char *)listPtr->pData,dwSize);
//		}
//	}
//	else
//	{ // ; Mem
//		lstrcpyn((char*)listPtr->pData,Cible,dwSize);
//		if (Mode != 3)
//		{
//			lstrcpyn((char*)listPtr->pOriginal,Cible,dwSize);
//		}
//	}
//
//    char *source = (char *)listPtr->pData;
//    char *lineStart = source;
//	DWORD *dest = (DWORD*)listPtr->pIndex;
//
//    int size = dwSize;
//    int count = 0;
//	while (size != 0)
//	{
//	    char value = *source;
//
//		if (value == 9)
// 		{
//			*source = 0;
//			count++;
//		}
//		else if (value == 13)
//		{
//			*dest = (DWORD)lineStart;
//			*source = 0;
//			source[1] = 0;
//			lineStart = &source[2];
//			dest += 2;
//			count++;
//		}
//		source++;
//		size--;
//	}
//
//	listPtr->totallignes = count;
//
//	SendMessage(listPtr->hListView,LVM_SETITEMCOUNT,listPtr->totallignes,LVSICF_NOINVALIDATEALL + LVSICF_NOSCROLL);
//	if (Mode == 1) // ;File
//	{
//		CloseHandle(hfile);
//	}
//	return ERROR_SUCCESS;
//}

//static long InStringEx (DWORD StartPos, const char *pStr, const char *pSubStr,DWORD *pPos)
//{
//	const char *Str = pStr + StartPos; // esi
//	char src, dst;
//
//	const char *SubStr = pSubStr + *pPos - 1; // edi
//
//    for (;;)
//    {
//        SubStr++;
//        do
//        {
//            src = *Str;
//            Str++;
//            dst = *SubStr;
//            if ( src == 0 )
//            { // Not found
//                *pPos = (DWORD)(SubStr - pSubStr);
//                return -1;
//            }
//        } while (src != dst);
//        do
//        {
//            src = *Str;
//            Str++;
//            SubStr++;
//            dst = *SubStr;
//            if ( dst == 0 )
//            {   // Found
//                *pPos = 0;
//                return (long)(Str - pStr - 1);
//            }
//            if (src == 0)
//            { // Not found
//                *pPos = (DWORD)(SubStr - pSubStr);
//                return -1;
//            }
//        }
//        while (src == dst);
//        SubStr = pSubStr - 1;
//    }
//}

static LRESULT __stdcall ListViewProc	(HWND hWin, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	if (uMsg == WM_LBUTTONUP) // ; on enl�ve la surbrillance si double click
	{
		SetFocus(GetParent(hWin));
	}
	if (uMsg == WM_SETCURSOR) // ; on place le curseur pour la Listview
    {
        TSLIST *listPtr = (TSLIST*)GetWindowLongPtr(GetParent(hWin), 0);
		if (listPtr->hCursorL != 0)
		{
			SetCursor(listPtr->hCursorL);
			return 0;
		}
    }
	return CallWindowProc(lpLstView,hWin,uMsg,wParam,lParam);
}

//static void position(TSLIST *listPtr, HWND hWin)
//{
//	RECT InvRectangle;
//
//	if (listPtr->count < 1)
//	{
//		listPtr->count = 1;
//	}
//	GetClientRect(hWin, &InvRectangle);
//    InvRectangle.top =  InvRectangle.bottom - listPtr->height - 7; // hauteur maxi == position du bas - hauteur du rectangle - �paisseur 3Dframe
//	InvRectangle.right = 40;  // maxi � droite
//	InvRectangle.left = 0;  // position depuis la gauche
//	InvRectangle.bottom -= 10;
//	InvalidateRect(hWin, &InvRectangle,TRUE); // on rafra�chit uniquement la barre de progression pour �viter le clipping
//
//	if (repeatsound == TRUE) // ; on �vite de r�p�ter le bruitage
//	{
//		PlaySound(MAKEINTRESOURCE(906),0,SND_RESOURCE | SND_ASYNC | SND_NODEFAULT);
//	}
//}

//static int finContinue(TSLIST *listPtr)
//{
//    int perPage = (int)SendMessage(listPtr->hListView,LVM_GETCOUNTPERPAGE,0,0);
//    int startPos = 0;
//
//    while (perPage > 0)
//    {
//        startPos = InStringEx(startPos,listPtr->pTemp,"\n", &Temp);
//        if (startPos != -1)
//        {
//            perPage--;
//        }
//        else
//        {
//            break;
//        }
//    }
//    return startPos;
//}

static void prepare_redraw(TSLIST *listPtr, HWND hWin) // progressbar redraw only / rafra�chit uniquement la barre de progression pour �viter le clipping
{
    RECT InvRectangle;

	GetClientRect(hWin, &InvRectangle);
	InvRectangle.top = InvRectangle.bottom - listPtr->height - 7; // hauteur maxi == position du bas - hauteur du rectangle - �paisseur 3Dframe
	InvRectangle.right = 40; // maxi � droite
	InvRectangle.left = 0 ; // position depuis la gauche
	InvRectangle.bottom -= 10;
	InvalidateRect(hWin, &InvRectangle,TRUE);
}

static LRESULT __stdcall ControlProc (HWND hWin, UINT uMsg, WPARAM wParam,LPARAM lParam)
{
	RECT rect;
	PAINTSTRUCT ps;
	TSLIST *listPtr;

	switch (uMsg)
	{
	case WM_CREATE:
		GetClientRect(hWin, &rect);

		// Ok, DrawProress...
		listPtr = (TSLIST*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof (TSLIST));
		if (listPtr != nullptr)
		{
			SetWindowLongPtr(hWin, 0, (LONG_PTR)listPtr);
			listPtr->count = 50;
			listPtr->maxi = 100;
			listPtr->left = 5;
			listPtr->height = 30;
			listPtr->ModelColor = 0;
			listPtr->FrameColorHi = 0x00E8D0D0;
			listPtr->FrameColorLo = 0x00D5A8A8;
			listPtr->ButtonBackgrd = 0x00FFFFFF;
			listPtr->ButtonBkgBitmap = 0;
			listPtr->SleepUpDown = 40;

			rect.bottom -= 16;
			rect.right -= 50;
			listPtr->hListView = CreateWindowExA(WS_EX_CLIENTEDGE | WS_EX_RIGHTSCROLLBAR, szLView, 0, WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_NOSCROLL | WS_BORDER | LVS_OWNERDATA, 42, 9, rect.right, rect.bottom, hWin, 0, hInstance, 0);
			listPtr->hCursorB = 0;
			listPtr->hCursorL = 0;
			listPtr->noProgress = FALSE;
			listPtr->no3dFrame = FALSE;
			lpLstView = (WNDPROC)SetWindowLongPtr(listPtr->hListView, GWLP_WNDPROC, (LONG_PTR)ListViewProc);
		}
		else
			return FALSE;

		GetClientRect(hWin, &rect);
		if (rect.bottom > 150) // ; si fen�tre assez grande
		{
			rect.bottom >>= 1;
			BmpButtonEx(hWin,15,rect.bottom,MAKEINTRESOURCEA(901),MAKEINTRESOURCEA(905),1016); //	; Curseurs...
			rect.bottom += 35;
			BmpButtonEx(hWin,15,rect.bottom,MAKEINTRESOURCEA(903),MAKEINTRESOURCEA(905),1018);
			rect.bottom -= 62;
			BmpButtonEx(hWin,15,rect.bottom,MAKEINTRESOURCEA(902),MAKEINTRESOURCEA(905),1015);
			rect.bottom -= 35;
			BmpButtonEx(hWin,15,rect.bottom,MAKEINTRESOURCEA(904),MAKEINTRESOURCEA(905),1017);
		}

		SendMessage(listPtr->hListView,LVM_SETEXTENDEDLISTVIEWSTYLE,0,LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);
		SendMessage(listPtr->hListView,LVM_SETBKCOLOR,0,0x00B97171);
		SendMessage(listPtr->hListView,LVM_SETTEXTCOLOR,0,0x00FFFFFF);
		SendMessage(listPtr->hListView,LVM_SETTEXTBKCOLOR,0,0x00B97171);
        break;

	case WM_PAINT: // ; eax == brush / edi == hdc
        {
            HBRUSH brush, brush2;
            HDC hDC;

            hDC = BeginPaint(hWin, &ps);
            listPtr = (TSLIST*)GetWindowLongPtr(hWin,0);
            //; ********** background buttons
            if (listPtr->ButtonBkgBitmap != 0)
            {
                brush = CreatePatternBrush(listPtr->ButtonBkgBitmap);
            }
            else
            {
                brush = CreateSolidBrush(listPtr->ButtonBackgrd);
            }
            brush2 = (HBRUSH)SelectObject(hDC,brush);
            GetClientRect(hWin, &rect);
            Rectangle(hDC,0,0,50,rect.bottom);
            DeleteObject(SelectObject(hDC, brush2));
            //; ********** background	buttons
            if (listPtr->no3dFrame == FALSE)
            {
                Paint_Proc(hWin,hDC);
            }
            if (listPtr->noProgress == FALSE)
            {
                if (rect.bottom > 200)
                {
                    rect.bottom -= listPtr->height - 7;
                    // 							hdc,hWin,ColorHi,height,count,maxi,left,top,ModelColor
                    DrawProgress(hDC,hWin,listPtr->height,listPtr->count,listPtr->maxi,listPtr->left,rect.bottom,listPtr->ModelColor);
                }
            }
            EndPaint(hWin, &ps);
            break;
        }
	case WM_SIZE:
		listPtr = (TSLIST*)GetWindowLongPtr(hWin,0);
		if ((GetWindowLong(hWin,GWL_STYLE) & STYLE_LINES) != 0)
		{
			SendMessage(listPtr->hListView,LVM_SETEXTENDEDLISTVIEWSTYLE,0,LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);
		}
		else
		{
			SendMessage(listPtr->hListView,LVM_SETEXTENDEDLISTVIEWSTYLE,0,LVS_EX_FULLROWSELECT);
		}
        break;

	case WM_NOTIFY:
		listPtr = (TSLIST*)GetWindowLongPtr(hWin,0);
		if (((NMHDR*)lParam)->hwndFrom == listPtr->hListView)
		{
			if (((NMHDR*)lParam)->code == LVN_GETDISPINFOA)
			{
				if (listPtr->pData != 0)
				{
					((LV_DISPINFOA*)lParam)->item.pszText = (char *)(((((LV_DISPINFOA*)lParam)->item.iItem) << 3) + (DWORD*)listPtr->pIndex);
				}
			}
		}
        break;

	case WM_COMMAND:
#if 0
		if (wParam == 1015) // ; monter
		{
            listPtr = (TSLIST*)GetWindowLongPtr(hWin,0);
			if (listPtr->pTemp != 0)
			{
				VirtualFree(listPtr->pTemp,0,MEM_RELEASE);
			}
			listPtr->pTemp = (char*)VirtualAlloc(NULL,lstrlen((const char *)listPtr->pOriginal),MEM_COMMIT,PAGE_READWRITE);
			lstrcpyn(listPtr->pTemp,(char *)listPtr->pOriginal,lstrlen((const char *)listPtr->pOriginal));

			compteur = listPtr->InStringCount;
			if (compteur > 0)
			{
				compteur--;
				listPtr->InStringCount = compteur;
			}
			else
			{
				return (LRESULT)listPtr->pTemp;
			}
			while (compteur > 0)
			{
				szMid(listPtr->pTemp,listPtr->pTemp,InStringEx(0,listPtr->pTemp, "\n", &Temp),lstrlen((const char *)listPtr->pOriginal));
				compteur--;
			}
			LoadFileorMem(listPtr, listPtr->pTemp,3);
			InvalidateRect(listPtr->hListView,0,TRUE);
			//; update la position du rectangle
			listPtr->count++;
			position(listPtr, hWin);
		}
		else if (wParam == 1016) // ; descendre
		{
            listPtr = (TSLIST*)GetWindowLongPtr(hWin,0);
			if (lstrlen((char*)listPtr->pOriginal) == 0)
			{
				return 0;
			}
			if (listPtr->pTemp == 0)
			{
				listPtr->pTemp = (char*)VirtualAlloc(NULL,lstrlen((char*)listPtr->pOriginal),MEM_COMMIT,PAGE_READWRITE);
				lstrcpyn(listPtr->pTemp,(char*)listPtr->pOriginal,lstrlen((char*)listPtr->pOriginal));
			}

			// v�rifie s'il est utile de descendre encore
			int perPage = SendMessage(listPtr->hListView,LVM_GETCOUNTPERPAGE,0,0);
			int startPos;
			while (perPage > 0)
			{
				if ( (startPos = InStringEx(startPos,listPtr->pTemp,"\n", &Temp)) != -1)
				{
					perPage--;
				}
				else
				{
					return startPos;
				}
			}
			// v�rifie s'il est utile de descendre encore

			startPos = InStringEx(0,listPtr->pTemp,"\n", &Temp);
			if (startPos != -1)
			{
				listPtr->InStringCount++;
				szMid(listPtr->pTemp,listPtr->pTemp,startPos,lstrlen((char*)listPtr->pOriginal));
				LoadFileorMem(listPtr, listPtr->pTemp,3);
				InvalidateRect(listPtr->hListView,0,TRUE);
			}
			// update la position du rectangle
			listPtr->count--;
			position(listPtr, hWin);
		}
		else if (wParam == 1017) // ; debut
		{
            listPtr = (TSLIST*)GetWindowLongPtr(hWin,0);
			if (listPtr->InStringCount == 0)
			{
				return 0;
			}

			if (listPtr->pTemp != 0)
			{
				VirtualFree(listPtr->pTemp,0,MEM_RELEASE);
			}
			listPtr->pTemp = (char*)VirtualAlloc(NULL,lstrlen((char*)listPtr->pOriginal),MEM_COMMIT,PAGE_READWRITE);
			lstrcpyn(listPtr->pTemp,(char*)listPtr->pOriginal,lstrlen((char*)listPtr->pOriginal));
			listPtr->InStringCount = 0;
			LoadFileorMem(listPtr,listPtr->pTemp,3);
			InvalidateRect(listPtr->hListView,0,TRUE);
			// update la position du rectangle
			DWORD perPage = SendMessage(listPtr->hListView,LVM_GETCOUNTPERPAGE,0,0);
			if (perPage < listPtr->totallignes)
			{
				listPtr->count = listPtr->totallignes - perPage + 2;
			}
			else
			{
				listPtr->count = listPtr->totallignes;
			}
			position(listPtr, hWin);
		}
		else if (wParam == 1018) // fin
		{
		    int startPos;

            listPtr = (TSLIST*)GetWindowLongPtr(hWin,0);

			if (lstrlen((char*)listPtr->pOriginal) == 0)
			{
				return 0;
			}
			if (listPtr->pTemp == 0)
			{
				listPtr->pTemp = (char*)VirtualAlloc(NULL,lstrlen((char*)listPtr->pOriginal),MEM_COMMIT,PAGE_READWRITE);
				lstrcpyn(listPtr->pTemp,(char*)listPtr->pOriginal,lstrlen((char*)listPtr->pOriginal));
			}

			startPos = finContinue(listPtr);
			if (startPos == -1)
			{
				return startPos;
            }
			while (true)
			{
                startPos = InStringEx(0,listPtr->pTemp,"\n", &Temp);
                if (startPos != -1)
                {
                    listPtr->InStringCount++;
                    szMid(listPtr->pTemp,listPtr->pTemp,startPos,lstrlen((char*)listPtr->pOriginal));
                    startPos = finContinue(listPtr); // continue � descendre ?
                    if (startPos == -1)
                    {
                        LoadFileorMem(listPtr,listPtr->pTemp,3);
                        InvalidateRect(listPtr->hListView,0,TRUE);
                        // update la position du rectangle
                        listPtr->count = 0;
                        position(listPtr, hWin);
                        return 0; // RDBJ ????
                    }
                }
                else
                    break;
			}
			return startPos;
		}
#endif // 0
        break;

	case WM_DESTROY:
		listPtr = (TSLIST*)GetWindowLongPtr(hWin,0);
		if (listPtr->pData != 0)
		{
			VirtualFree(listPtr->pData,0,MEM_RELEASE);
			VirtualFree(listPtr->pOriginal,0,MEM_RELEASE);
			VirtualFree(listPtr->pIndex,0,MEM_RELEASE);
			VirtualFree(listPtr->pTemp,0,MEM_RELEASE);
		}
		HeapFree(GetProcessHeap(),0,listPtr);
		EndDialog(hWin,0);
        break;

	case RAL_INIT:
		listPtr = (TSLIST*)GetWindowLongPtr(hWin,0);
		active = TRUE; // signale que nous ne sommes pas dans Radasm Dialog
		pColumn.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
		GetClientRect(hWin, &rect);
		pColumn.cx = rect.right - 53;
		pColumn.fmt = (int)lParam;
		pColumn.pszText = (char *)wParam;
		SendMessage(listPtr->hListView,LVM_INSERTCOLUMNA,1,(LPARAM)&pColumn);
		return 0;

//	case RAL_LOADFILE:
//        {
//            listPtr = (TSLIST*)GetWindowLongPtr(hWin,0);
//            if (LoadFileorMem(listPtr,(char*)wParam,1) == (LONG_PTR)INVALID_HANDLE_VALUE)
//            {
//                return 0;
//            }
//            XP_Sleep(1);   // permet � Windows de modifier la liste avant LVM_GETCOUNTPERPAGE. Ainsi on r�cup�re le bon nombre de lignes avec LVM_GETCOUNTPERPAGE si elles ont chang� � cause de hFont
//            DWORD perPage = SendMessage(listPtr->hListView,LVM_GETCOUNTPERPAGE,0,0);
//            if (perPage < listPtr->totallignes)
//            {
//                perPage = listPtr->totallignes - perPage + 1;
//            }
//            else
//            {
//                perPage = listPtr->totallignes;
//            }
//            listPtr->maxi = perPage;
//            listPtr->count = perPage;
//            InvalidateRect(listPtr->hListView,0,FALSE);
//            break;
//        }
//	case RAL_LOADMEM:
//        {
//            listPtr = (TSLIST*)GetWindowLongPtr(hWin,0);
//            LoadFileorMem(listPtr,(char*)wParam,2);
//            XP_Sleep(1); // permet � Windows de modifier la liste avant LVM_GETCOUNTPERPAGE. Ainsi on r�cup�re le bon nombre de lignes avec LVM_GETCOUNTPERPAGE si elles ont chang� � cause de hFont
//            DWORD perPage = SendMessage(listPtr->hListView,LVM_GETCOUNTPERPAGE,0,0);
//
//            if (perPage < listPtr->totallignes)
//            {
//                perPage = listPtr->totallignes - perPage + 1;
//            }
//            else
//            {
//                perPage = listPtr->totallignes;
//            }
//            listPtr->maxi = perPage;
//            listPtr->count = perPage;
//            InvalidateRect(listPtr->hListView,0,FALSE);
//            break;
//        }
	case RAL_TEXTCOLOR:
		listPtr = (TSLIST*)GetWindowLongPtr(hWin,0);
		SendMessage(listPtr->hListView,LVM_SETTEXTCOLOR,0,lParam);
		break;

	case RAL_BKCOLOR:
		listPtr = (TSLIST*)GetWindowLongPtr(hWin,0);
		SendMessage(listPtr->hListView,LVM_SETBKCOLOR,0,lParam);
		SendMessage(listPtr->hListView,LVM_SETTEXTBKCOLOR,0,lParam);
		break;

	case RAL_SETFONT:
		listPtr = (TSLIST*)GetWindowLongPtr(hWin,0);
		SendMessage(listPtr->hListView,WM_SETFONT,wParam,TRUE);
		break;

	case RAL_FRAMECOLORLO:
		listPtr = (TSLIST*)GetWindowLongPtr(hWin,0);
		listPtr->FrameColorLo = (DWORD)lParam;
		break;

	case RAL_FRAMECOLORHI:
		listPtr = (TSLIST*)GetWindowLongPtr(hWin,0);
		listPtr->FrameColorHi = (DWORD)lParam;
		break;

	case RAL_COLORBACKGRD:
		listPtr = (TSLIST*)GetWindowLongPtr(hWin,0);
		listPtr->ButtonBackgrd = (DWORD)lParam;
		InvalidateRect(hWin,0,TRUE);
		break;

	case RAL_BITMAPBACKGRD:
		listPtr = (TSLIST*)GetWindowLongPtr(hWin,0);
		listPtr->ButtonBkgBitmap = (HBITMAP)lParam;
		InvalidateRect(hWin,0,TRUE);
		break;

	case RAL_SPEEDUPDOWN:
		listPtr = (TSLIST*)GetWindowLongPtr(hWin,0);
		listPtr->SleepUpDown = (DWORD)lParam;
		break;

	case RAL_NOCOLUMNHEADER:
		listPtr = (TSLIST*)GetWindowLongPtr(hWin,0);
		SetWindowLong(listPtr->hListView,GWL_STYLE,WS_CHILD | WS_VISIBLE | LVS_REPORT | WS_BORDER | LVS_NOCOLUMNHEADER | LVS_OWNERDATA); // �tange, LVS_NOCOLUMNHEADER n'est pas accept� si LVS_NOSCROLL actif
		SetWindowLong(listPtr->hListView,GWL_STYLE,WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_NOSCROLL | WS_BORDER | LVS_OWNERDATA);
		break;

	case RAL_MOVEBUTTONSX:
		GetClientRect(hWin, &rect);
		if (rect.bottom > 150) //; �vite un probl�me d'affichage si fen�tre trop petite
		{
			rect.bottom = (rect.bottom >> 1);
			MoveWindow(GetDlgItem(hWin, 1016),(int)wParam + 15,rect.bottom,(int)lParam,(int)lParam,TRUE);
			rect.bottom += 35;
			MoveWindow(GetDlgItem(hWin, 1018),(int)wParam + 15,rect.bottom,(int)lParam,(int)lParam,TRUE);
			rect.bottom -= 65;
			MoveWindow(GetDlgItem(hWin, 1015),(int)wParam + 15,rect.bottom,(int)lParam,(int)lParam,TRUE);
			rect.bottom -= 35;
			MoveWindow(GetDlgItem(hWin, 1017),(int)wParam + 15,rect.bottom,(int)lParam,(int)lParam,TRUE);
		}
        break;

	case WM_SETCURSOR:
		listPtr = (TSLIST*)GetWindowLongPtr(hWin,0);
		if (listPtr->hCursorB != 0)
		{
			SetCursor(listPtr->hCursorB);
			return 0;
		}
		break;

	case RAL_CURBUTTONS:
		listPtr = (TSLIST*)GetWindowLongPtr(hWin,0);
		listPtr->hCursorB = (HICON)wParam;
		return 0;

	case RAL_CURLISTVIEW:
		listPtr = (TSLIST*)GetWindowLongPtr(hWin,0);
		listPtr->hCursorL = (HICON)wParam;
		return 0;

	case RAL_PROGRESSMODEL:
		listPtr = (TSLIST*)GetWindowLongPtr(hWin,0);
		listPtr->ModelColor = (DWORD)wParam;
		prepare_redraw(listPtr, hWin);
		break;

	case RAL_PROGRESSHEIGHT:
		if (wParam < 20)
		{
			return 0;
		}
		listPtr = (TSLIST*)GetWindowLongPtr(hWin,0);
		listPtr->height = (DWORD)wParam;
		break;

	case RAL_NO3DFRAME:
		listPtr = (TSLIST*)GetWindowLongPtr(hWin,0);
		listPtr->no3dFrame = (DWORD)wParam;
		GetClientRect(hWin, &rect);
		if (wParam == TRUE)
		{
			rect.bottom -= 0;
			rect.right -= 43;
			rect.top = 0;
			listPtr->left = 1;
		}
		else
		{
			rect.bottom -= 16;
			rect.right -= 50;
			rect.top = 9;
			listPtr->left = 5;
		}
		MoveWindow(listPtr->hListView,42,rect.top,rect.right,rect.bottom,TRUE);
		InvalidateRect(hWin,0,TRUE);
		break;

	case RAL_NOPROGRESS:
		listPtr = (TSLIST*)GetWindowLongPtr(hWin,0);
		listPtr->noProgress = (DWORD)wParam;
		InvalidateRect(hWin,0,TRUE);
		break;

	case RAL_PROGRESSCOLORH:
		listPtr = (TSLIST*)GetWindowLongPtr(hWin,0);
		listPtr->color1 = (DWORD)wParam;
		listPtr->color2 = (DWORD)lParam;
		prepare_redraw(listPtr, hWin);
		break;

	case RAL_PROGRESSCOLORV:
		listPtr = (TSLIST*)GetWindowLongPtr(hWin,0);
		listPtr->color3 = (DWORD)wParam;
		listPtr->color4 = (DWORD)lParam;
		prepare_redraw(listPtr, hWin);
		break;

	}
	return DefWindowProc(hWin,uMsg,wParam,lParam);
}

ATOM TSListInstall(HINSTANCE /*hInst*/)
{
    WNDCLASSEXA wc;

    wc.cbSize = sizeof (WNDCLASSEX);
    wc.style = CS_HREDRAW | CS_VREDRAW | CS_GLOBALCLASS | CS_PARENTDC | CS_DBLCLKS;
    wc.lpfnWndProc = ControlProc;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = sizeof(void*);
    wc.hInstance = hInstance;
    wc.hbrBackground = 0;
    wc.lpszMenuName = 0;
    wc.lpszClassName = szClassName;
    wc.hIcon = 0;
    wc.hIconSm = 0;
    wc.hCursor = LoadCursor(NULL,IDC_ARROW);
    return RegisterClassExA(&wc);
}

