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


#ifndef __RAGRID_H__
#define __RAGRID_H__

#ifdef _MSC_VER
#pragma once
#endif

#ifdef __cplusplus
extern "C" {
#endif

//
// IMPORTANT The following functions must pass in a buffer of at least this size.
//    GM_GETCOLFORMAT
#define MAX_FORMAT_SIZE 64

//
// IMPORTANT The following functions must pass in a buffer of at least this size.
//    GM_GETCELLDATA, GM_GETHDRTEXT, GM_CELLCONVERT
#define MAX_CELL_SIZE 512

struct GRID_CREATE_STRUCT
{
	WORD size;
	COLORREF textColor;
	COLORREF backColor;
	COLORREF gridColor;
};

struct COLUMN
{
	int32_t colwt;					// Column width.
	INT_PTR lpszhdrtext; 			// Handle for the header text.
	int32_t halign;				// Header text alignment.
	int32_t calign; 				// Column text alignment.
	int32_t ctype;					// Column data type.
	int32_t ctextmax;				// Max text lenght for TYPE_EDITTEXT and TYPE_EDITint32_t.
	DWORD lpszformat;			// Format string handle for TYPE_EDITint32_t.
	HANDLE himl;				// Handle of image list. For the image columns and combobox only.
	int32_t hdrflag;				// Header flags. Set to ZERO or if initially sorted set to initial sort direction
	int32_t colxp;					// Column position. Internally used.
	HWND edthwnd;				// Column control handle. Internally used.
	LPARAM lParam;				// User defined 32 bit value.
};

struct ROWCOLOR
{
	COLORREF backcolor;
	COLORREF textcolor;
};

// Notifications
struct GRIDNOTIFY
{
	NMHDR nmhdr;
	int32_t col;		// Column
	int32_t row;		// Row
	HWND hwnd;		// Handle of column edit control
	void *lpdata;	// Pointer to data
	BOOL fcancel;	// Set to TRUE to cancel operation
};

typedef enum GRID_NOTIFY_TYPE {
	GN_HEADERCLICK		= 1,			// User clicked header
	GN_BUTTONCLICK		= 2,			// Sent when user clicks the button in a button cell
	GN_CHECKCLICK		= 3,			// Sent when user double clicks the checkbox in a checkbox cell
	GN_IMAGECLICK		= 4,			// Sent when user double clicks the image in an image cell
	GN_BEFORESELCHANGE	= 5,			// Sent when user request a selection change
	GN_AFTERSELCHANGE	= 6,			// Sent after a selection change
	GN_BEFOREEDIT		= 7,			// Sent before the cell edit control shows
	GN_AFTEREDIT		= 8,			// Sent when the cell edit control is about to close
	GN_BEFOREUPDATE		= 9,			// Sent before a cell updates grid data
	GN_AFTERUPDATE		= 10,			// Sent after grid data has been updated
	GN_USERCONVERT		= 11,			// Sent when user cell needs to be converted.
} GRID_NOTIFY_TYPE ;

// Messages
typedef enum GRID_MESSAGE_TYPE {
	GM_ADDCOL			= WM_USER+1,	// wParam=0, lParam=lpCOLUMN
	GM_ADDROW			= WM_USER+2,	// wParam=0, lParam=lpROWDATA (can be NULL)
	GM_INSROW			= WM_USER+3,	// wParam=nRow, lParam=lpROWDATA (can be NULL)
	GM_DELROW			= WM_USER+4,	// wParam=nRow, lParam=0
	GM_MOVEROW			= WM_USER+5,	// wParam=nFromRow, lParam=nToRow
	GM_COMBOADDSTRING	= WM_USER+6,	// wParam=nCol, lParam=lpszString
	GM_COMBOCLEAR		= WM_USER+7,	// wParam=nCol, lParam=0
	GM_GETCURSEL		= WM_USER+8,	// wParam=0, lParam=0
	GM_SETCURSEL		= WM_USER+9,	// wParam=nCol, lParam=nRow
	GM_GETCURCOL		= WM_USER+10,	// wParam=0, lParam=0
	GM_SETCURCOL		= WM_USER+11,	// wParam=nCol, lParam=0
	GM_GETCURROW		= WM_USER+12,	// wParam=0, lParam=0
	GM_SETCURROW		= WM_USER+13,	// wParam=nRow, lParam=0
	GM_GETCOLCOUNT		= WM_USER+14,	// wParam=0, lParam=0
	GM_GETROWCOUNT		= WM_USER+15,	// wParam=0, lParam=0
	GM_GETCELLDATA		= WM_USER+16,	// wParam=nRowCol, lParam=lpData
	GM_SETCELLDATA		= WM_USER+17,	// wParam=nRowCol, lParam=lpData (can be NULL)
	GM_GETCELLRECT		= WM_USER+18,	// wParam=nRowCol, lParam=lpRECT
	GM_SCROLLCELL		= WM_USER+19,	// wParam=0, lParam=0
	GM_GETBACKCOLOR		= WM_USER+20,	// wParam=0, lParam=0
	GM_SETBACKCOLOR		= WM_USER+21,	// wParam=nColor, lParam=0
	GM_GETGRIDCOLOR		= WM_USER+22,	// wParam=0, lParam=0
	GM_SETGRIDCOLOR		= WM_USER+23,	// wParam=nColor, lParam=0
	GM_GETTEXTCOLOR		= WM_USER+24,	// wParam=0, lParam=0
	GM_SETTEXTCOLOR		= WM_USER+25,	// wParam=nColor, lParam=0
	GM_ENTEREDIT		= WM_USER+26,	// wParam=nCol, lParam=nRow
	GM_ENDEDIT			= WM_USER+27,	// wParam=nRowCol, lParam=fCancel
	GM_GETCOLWIDTH		= WM_USER+28,	// wParam=nCol, lParam=0
	GM_SETCOLWIDTH		= WM_USER+29,	// wParam=nCol, lParam=nWidth
	GM_GETHDRHEIGHT		= WM_USER+30,	// wParam=0, lParam=0
	GM_SETHDRHEIGHT		= WM_USER+31,	// wParam=0, lParam=nHeight
	GM_GETROWHEIGHT		= WM_USER+32,	// wParam=0, lParam=0
	GM_SETROWHEIGHT		= WM_USER+33,	// wParam=0, lParam=nHeight
	GM_RESETCONTENT		= WM_USER+34,	// wParam=0, lParam=0                       Deletes the contents of the cells, not the cells themselves
	GM_COLUMNSORT		= WM_USER+35,	// wParam=nCol, lParam=0=Ascending, 1=Descending, 2=Invert
	GM_GETHDRTEXT		= WM_USER+36,	// wParam=nCol, lParam=lpBuffer
	GM_SETHDRTEXT		= WM_USER+37,	// wParam=nCol, lParam=lpszText
	GM_GETCOLFORMAT		= WM_USER+38,	// wParam=nCol, lParam=lpBuffer
	GM_SETCOLFORMAT		= WM_USER+39,	// wParam=nCol, lParam=lpszText
	GM_CELLCONVERT		= WM_USER+40,	// wParam=nRowCol, lParam=lpBuffer
	GM_RESETCOLUMNS		= WM_USER+41,	// wParam=0, lParam=0                       Deletes all columns and data
	GM_GETROWCOLOR		= WM_USER+42,	// wParam=nRow, lParam=lpROWCOLOR
	GM_SETROWCOLOR		= WM_USER+43,	// wParam=nRow, lParam=lpROWCOLOR
	GM_GETCOLDATA		= WM_USER+44,	// wParam=nCol, lParam=lpCOLUMN     ret 0 good, -1 bad
	GM_GETCELLITEMDATA  = WM_USER+45,   // wParam=nRowCol, lParam=0         ret itemData int
	GM_SETCELLITEMDATA  = WM_USER+46,   // wParam=nRowCol, lParam=ItemData
	GM_GETCELLBACKCOLOR = WM_USER+47,   // wParam=nRowCol, lParam=0         ret COLORREF
	GM_SETCELLBACKCOLOR = WM_USER+48,   // wParam=nRowCol, lParam=COLORREF
	GM_GETCELLBACKHILITE= WM_USER+49,   // wParam=nRowCol, lParam=0         ret COLORREF
	GM_SETCELLBACKHILITE= WM_USER+50,   // wParam=nRowCol, lParam=COLORREF
	GM_GETCELLHILITE    = WM_USER+51,   // wParam=nRowCol, lParam=0         ret COLORREF
	GM_SETCELLHILITE    = WM_USER+52,   // wParam=nRowCol, lParam=COLORREF
} GRID_MESSAGE_TYPE;


// Column alignment
typedef enum GRID_COLUMN_ALIGNMENT
{
	GA_ALIGN_LEFT		= 0,
	GA_ALIGN_CENTER		= 1,
	GA_ALIGN_RIGHT		= 2,
} GRID_COLUMN_ALIGNMENT;


// Column types
typedef enum GRID_COLUMN_TYPE
{
	TYPE_EDITTEXT		= 0,			// String
	TYPE_EDITint32_t		= 1,			// int32_t
	TYPE_CHECKBOX		= 2,			// int32_t
	TYPE_COMBOBOX		= 3,			// int32_t
	TYPE_HOTKEY			= 4,			// int32_t
	TYPE_BUTTON			= 5,			// String
	TYPE_IMAGE			= 6,			// int32_t
	TYPE_DATE			= 7,			// int32_t
	TYPE_TIME			= 8,			// int32_t
	TYPE_USER			= 9,			// 0=String, 1 to 512 bytes binary data
	TYPE_EDITBUTTON		= 10,			// String
	TYPE_SELTEXT        = 11,           // String (first char is + or -.  + is selected, - is unselected)
} GRID_COLUMN_TYPE;


// Column sorting
typedef enum GRID_COLUMN_SORT
{
	SORT_ASCENDING		= 0,
	SORT_DESCENDING		= 1,
	SORT_INVERT			= 2,
} GRID_COLUMN_SORT;


// Window styles
typedef enum GRID_WINDOW_STYLE
{
	STYLE_NOSEL			= 0x01, // No row select
	STYLE_NOFOCUS		= 0x02,
	STYLE_HGRIDLINES	= 0x04,
	STYLE_VGRIDLINES	= 0x08,
	STYLE_GRIDFRAME		= 0x10,
	STYLE_NOCOLSIZE		= 0x20,
} GRID_WINDOW_STYLE;


#define ODT_GRID  (6)


#ifdef RAGRID_DLL
	#define szRAGridClass	("TSGrid")
#else
	#define szRAGridClass	("MyTSGrid")
#endif

#ifdef __cplusplus
}
#endif

#endif //  __RAGRID_H__
