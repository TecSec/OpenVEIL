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
#include <windows.h>
#include <commctrl.h>
#include "TSGrid.h"
#include "resource.h"

#define MEM_SIZE (128*1024)

static HINSTANCE hInstance = NULL;

// Cancel edit update
static BOOL fCancelEdit = FALSE;

static HWND hfocus;
static WNDPROC lplstproc;

//#define DLGC_CODE	(DLGC_WANTARROWS | DLGC_WANTCHARS | DLGC_WANTALLKEYS)
#define DLGC_CODE	(DLGC_WANTCHARS  | DLGC_WANTALLKEYS)

// Grid structure (immediately followed by the column definitions in memory)
typedef struct GRID {
    int32_t    col				; // Current column.
    int32_t    row				; // Current row.
    DWORD   cols			; // Number of columns.
    DWORD   rows			; // Number of rows.
    int32_t    hdrht			; // Header height.
    int32_t    rowht			; // Row height.
    int32_t    ccx				; // Sum of column widths.
    int32_t    sbx				; // Horizontal scroll position.
    HWND    hpar			; // Handle of parent.
    HWND    hgrd			; // Handle of grid.
    int32_t    nid				; // ID of grid.
    HWND    hhdr			; // Handle of header.
    HWND    hlst			; // Handle of grid listbox.
    HWND    hsize			; // Handle of sizeing bar.
    HFONT   hfont			; // Handle of font
    int32_t    style			; // Grid style.
    HCURSOR hcur			; // Handle of resize cursor
    int32_t    colback			; // Back color
    int32_t    colgrid			; // Grid color
    int32_t    coltext			; // Text color
    int32_t    colcellback     ; // Cell background color
    int32_t    coltexthilite   ; // Text color for highlight
    int32_t    colcellbackhilite; // Cell background color for hilight
    HBRUSH  hbrback			; // Back brush
    HBRUSH  hbrcellback	    ; // Cell Back brush
    HBRUSH  hbrcellhilite   ; // Cell background hilight brush
    HPEN    hpengrd			; // Grid pen
    HWND    hedt			; // Handle of current edit control
    int32_t    edtrowcol		; // Row & Column of edit
    HANDLE  hmem			; // Handle of data memory.
    DWORD   rpmemfree		; // Relative pointer to next free.
    DWORD   memsize			; // Memory size.
    HANDLE  hstr			; // Handle of string memory.
    DWORD   rpstrfree		; // Relative pointer to next free.
    DWORD   strsize			; // Memory size.
    void *  lpdata			; // Button cell data
    int32_t    toprow			; //
    DWORD   itemmemsize		; //
    int32_t    rpitemdata		; // offset in hmem of the beginning of the row data pointers  - size = 2 dwords, 2 DWords per column (item value or pointer, itemData value)
							  // rpitemdata points after GRID.  Value of ((unsigned char*)GRID[1])[rpitemdata] is used in hmem
    // Data used while resizing a column
    int32_t    ncol            ; // Last column selected
    int32_t    nrow            ; // last row selected
    int32_t    fsame           ; // Selection was the same as prior
    int32_t    fonbtn          ; // The type of the button selected or FALSE
    int32_t    fSize           ; // Column resize state variable (0 none, 1 GetInfo, 2 Resize Started)
    int32_t    nSizeCol        ;
    int32_t    nSizeMin		;
    int32_t    nSizeOfs        ;
} GRID;

#define STYLE		(WS_CHILD | WS_VISIBLE | WS_TABSTOP | STYLE_HGRIDLINES | STYLE_VGRIDLINES | STYLE_NOSEL)
#define EXSTYLE		(WS_EX_CLIENTEDGE)

/* // Used by RadASM 1.2.0.5
CCDEF struct
    ID				dd ?		;Controls uniqe ID
    lptooltip		dd ?		;Pointer to tooltip text
    hbmp			dd ?		;Handle of bitmap
    lpcaption		dd ?		;Pointer to default caption text
    lpname			dd ?		;Pointer to default id-name text
    lpclass			dd ?		;Pointer to class text
    style			dd ?		;Default style
    exstyle			dd ?		;Default ex-style
    flist1			dd ?		;Property listbox 1
    flist2			dd ?		;Property listbox 2
    disable			dd ?		;Disable controls child windows. 0=No, 1=Use method 1, 2=Use method 2
CCDEF ends

;Used by RadASM 2.1.0.4
CCDEFEX struct
    ID				dd ?		;Controls uniqe ID
    lptooltip		dd ?		;Pointer to tooltip text
    hbmp			dd ?		;Handle of bitmap
    lpcaption		dd ?		;Pointer to default caption text
    lpname			dd ?		;Pointer to default id-name text
    lpclass			dd ?		;Pointer to class text
    style			dd ?		;Default style
    exstyle			dd ?		;Default ex-style
    flist1			dd ?		;Property listbox 1
    flist2			dd ?		;Property listbox 2
    flist3			dd ?		;Property listbox 3
    flist4			dd ?		;Property listbox 4
    lpproperty		dd ?		;Pointer to properties text to add
    lpmethod		dd ?		;Pointer to property methods
CCDEFEX ends*/

typedef enum PROP_STYLE_TYPE {
    PROP_STYLETRUEFALSE		= 1,
    PROP_EXSTYLETRUEFALSE	= 2,
    PROP_STYLEMULTI			= 3,
} PROP_STYLE_TYPE;

#define szStaticClass		("Static")
#define szListBoxClass		("ListBox")
#define szRAListClass		("TSList")
#define szEditClass			("Edit")
#define szHotKeyClass		("msctls_hotkey32")
#define szButtonClass		("Button")
#define szDateTimeClass		("SysDateTimePick32")

#define szToolTip			("RAGrid control")
//#define szCap				""
//#define szName				"IDC_GRD"

// Hotkey text
#define szCtrl				"Ctrl + "
#define szShift				"Shift + "
#define szAlt				"Alt + "


//#define szProperty			"GridLines,GridFrame,CellFocus,ShowSel,ColSize"
//#define PropertyGridLines	"None,Horizontal,Vertical,Both"

//struct ItemChanger {
//	DWORD item1And, item1Or, item2And, item2Or;
//};

//static struct ItemChanger PropertyGridLineStyles[3] = {
//	{-1 ^ (STYLE_HGRIDLINES | STYLE_VGRIDLINES), STYLE_HGRIDLINES, (DWORD)-1, 0},
//	{-1 ^ (STYLE_HGRIDLINES | STYLE_VGRIDLINES), STYLE_VGRIDLINES, (DWORD)-1, 0},
//	{-1 ^ (STYLE_HGRIDLINES | STYLE_VGRIDLINES), STYLE_HGRIDLINES | STYLE_VGRIDLINES, (DWORD)-1, 0},
//};

//struct ItemChanger PropertyGridFrame = {-1 ^ STYLE_GRIDFRAME,0, -1 ^ STYLE_GRIDFRAME,STYLE_GRIDFRAME};
//struct ItemChanger PropertyCellFocus = {-1 ^ STYLE_NOFOCUS,STYLE_NOFOCUS, -1 ^ STYLE_NOFOCUS,0};
//struct ItemChanger PropertyShowSel	 = {-1 ^ STYLE_NOSEL,STYLE_NOSEL, -1 ^ STYLE_NOSEL,0};
//struct ItemChanger PropertyColSize	 = {-1 ^ STYLE_NOCOLSIZE,STYLE_NOCOLSIZE, -1 ^ STYLE_NOCOLSIZE,0};

//static struct MethodPtrs {
//	PROP_STYLE_TYPE type;
//	const void *addr;
//} Methods[5] = {
//	{ PROP_STYLEMULTI,&PropertyGridLines},
//	{ PROP_STYLETRUEFALSE,&PropertyGridFrame},
//	{ PROP_STYLETRUEFALSE,&PropertyCellFocus},
//	{ PROP_STYLETRUEFALSE,&PropertyShowSel},
//	{ PROP_STYLETRUEFALSE,&PropertyColSize},
//};

//;Create an inited struct
//ccdef				CCDEF <280,offset szToolTip,0,offset szCap,offset szName,offset szRAGridClass,WS_CHILD or WS_VISIBLE or WS_TABSTOP or STYLE_HGRIDLINES or STYLE_VGRIDLINES or STYLE_NOSEL,WS_EX_CLIENTEDGE,11111101000111100000000001000000b,00010000000000011000000000000000b,1>
//ccdefex				CCDEFEX <280,offset szToolTip,0,offset szCap,offset szName,offset szRAGridClass,STYLE,EXSTYLE,11111101000111100000000001000000b,00010000000000011000000000000000b,00000000000000000000000000000000b,00000000000000000000000000000000b,offset szProperty,offset Methods>


// TODO:  Handle error cases
static HANDLE ExpandMem(HANDLE hMem1, DWORD nSize)
{
    DWORD newSize = nSize + MEM_SIZE;
    HANDLE hMem2 = GlobalAlloc(GMEM_MOVEABLE, newSize);

    if ( hMem2 == NULL )
        return NULL;

    void *dest = GlobalLock(hMem2);
    void *src = GlobalLock(hMem1);

    memcpy(dest, src, nSize);

    GlobalUnlock(hMem1);
    GlobalFree(hMem1);
    memset(&((unsigned char*)dest)[nSize], 0, MEM_SIZE);
    GlobalUnlock(hMem2);
    return hMem2;
}


static void GridGetText (GRID *grid, DWORD rpData, char *lpData, int dataLen)
{
    if ( rpData != 0 )
    {
        char *ptr = (char*)GlobalLock(grid->hstr);

        ptr += rpData;
        strcpy_s(lpData, dataLen, ptr);
        GlobalUnlock(grid->hstr);
    }
    else
    {
        lpData[0] = 0;
    }
}

static void GridGetFixed (GRID *grid, DWORD rpData, void *lpData, DWORD len)
{

    if ( rpData != 0 )
    {
        unsigned char *ptr = (unsigned char*)GlobalLock(grid->hstr);

        ptr += rpData;
        memcpy (lpData, ptr, len);
        GlobalUnlock(grid->hstr);
    }
    else
    {
        memset(lpData, 0, len);
    }
}

static DWORD GridAddText (GRID *grid, const char *lpData)
{
    DWORD len;

    if ( lpData != 0 )
    {
        len = (DWORD)strlen(lpData) + 1;
        if ( grid->hstr == NULL )
        {
            grid->hstr = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT,MEM_SIZE);
            grid->rpstrfree = 4;
            grid->strsize = MEM_SIZE;
        }
        DWORD posi = grid->rpstrfree;

        if ( posi + len > grid->strsize )
        {
            grid->hstr = ExpandMem(grid->hstr, grid->strsize);
            grid->strsize += MEM_SIZE;
        }
        char *data = (char*)GlobalLock(grid->hstr);

        data += posi;
        
        strcpy_s(data, len, lpData);
        grid->rpstrfree += len;
        GlobalUnlock(grid->hstr);
        return posi;
    }

    return 0;
}

static DWORD GridAddFixed (GRID *grid, const void *lpData, DWORD len)
{
    if (!grid->hstr)
    {
        grid->hstr = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT,MEM_SIZE);
        grid->rpstrfree = 4;
        grid->strsize = MEM_SIZE;
    }
    DWORD posi = grid->rpstrfree;

    if (posi + len > grid->strsize )
    {
        grid->hstr = ExpandMem(grid->hstr, grid->strsize);
        grid->strsize += MEM_SIZE;
    }
    unsigned char *data = (unsigned char*)GlobalLock(grid->hstr);

    data += posi;

    //
    // This function is used in the GridAddRowData function.  Each row data is up to 4 bytes per column.  For int32_ter data types the row data
    // contains the pointer to the actual data.
    //
    if ( len <= 4 )
    {
        // normal data
        memcpy(data, lpData, len);
    }
    else
    {
        // pointer to the data
        memcpy(data, *((const void **)lpData), len);
    }

    grid->rpstrfree += len;
    GlobalUnlock(grid->hstr);
    return posi;
}


static void GridAddPtr (GRID *grid,DWORD nData)
{
    if (!grid->hmem)
    {
        grid->hmem = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT,MEM_SIZE);
        grid->rpmemfree = 0;
        grid->memsize = MEM_SIZE;
    }

    DWORD posi = grid->rpmemfree;
    if (posi + 4 > grid->memsize)
    {
        grid->hmem = ExpandMem(grid->hmem,grid->memsize);
        grid->memsize += MEM_SIZE;
    }
    unsigned char *data = (unsigned char *)GlobalLock(grid->hmem);

    memcpy(&data[posi], &nData, 4);
    grid->rpmemfree += 4;
    GlobalUnlock(grid->hmem);
}

static DWORD GridAddRowData (GRID *grid, void *lpData)
{
    DWORD posi = grid->rpmemfree;
    DWORD col;
    COLUMN *colDefs;
    unsigned char *dataPtr = (unsigned char *)lpData;
    DWORD ptr;


    colDefs = (COLUMN *)(grid + 1); // Column definitions immediately follow the grid structure in memory.

    //
    // Reserve the ROWCOLOR struct for the row and default to unused
    //
    GridAddPtr(grid, (DWORD)-1);
    GridAddPtr(grid, (DWORD)-1);

    for (col = 0; col < grid->cols; col++)
    {
        if ( dataPtr != NULL )
        {
            switch (colDefs[col].ctype)
            {
            case TYPE_SELTEXT:
            case TYPE_EDITTEXT:
            case TYPE_BUTTON:
            case TYPE_EDITBUTTON:
                ptr = GridAddText(grid, *(const char**)dataPtr);
                break;
            case TYPE_USER:
                if ( colDefs[col].ctextmax == 0 )
                {
                    ptr = GridAddText(grid, *(const char**)dataPtr);
                }
                else
                {
                    ptr = GridAddFixed(grid, dataPtr, colDefs[col].ctextmax);
                }
                break;
            default:
                ptr = GridAddFixed(grid, dataPtr, 4);
                break;
            }
            dataPtr += 4;
        }
        else
        {
            ptr = 0;
        }

        GridAddPtr(grid, ptr); // Save the Cell Data
        GridAddPtr(grid, 0);   // Save the Cell Item Data
    }
    return posi;
}


static DWORD GridGetCellData (GRID *grid,DWORD rpData, DWORD nCol, void *lpData, int dataLen)
{
    COLUMN *colPtr;
    DWORD colType;
    DWORD colData;

    unsigned char *dataPtr = (unsigned char *)GlobalLock(grid->hmem);

    dataPtr += rpData + 2*4 + nCol * 8;

    colData = *(DWORD*)dataPtr;

    colPtr = ((COLUMN*)(grid + 1)) + nCol;
    colType = colPtr->ctype;

    switch (colType)
    {
    case TYPE_SELTEXT:
    case TYPE_EDITTEXT:
    case TYPE_BUTTON:
    case TYPE_EDITBUTTON:
        GridGetText(grid, colData, (char*)lpData, dataLen);
        break;

    case TYPE_USER:
        if ( colPtr->ctextmax == 0 )
        {
            GridGetText(grid, colData, (char*)lpData, dataLen);
        }
        else
        {
            if (dataLen < colPtr->ctextmax)
            {
                GridGetFixed(grid, colData, lpData, dataLen);
            }
            else
            {
                GridGetFixed(grid, colData, lpData, colPtr->ctextmax);
            }
        }
        break;

    default:
        if (dataLen < 4)
        {
            GridGetFixed(grid, colData, lpData, dataLen);
        }
        else
        {
            GridGetFixed(grid, colData, lpData, 4);
        }
        break;
    }

    GlobalUnlock(grid->hmem);
    return colType;
}

static DWORD GridGetCellItemData (GRID *grid,DWORD rpData, DWORD nCol)
{
    DWORD itemData;

    unsigned char *dataPtr = (unsigned char *)GlobalLock(grid->hmem);

    dataPtr += rpData + 2*4 + nCol * 8 + 4;

    itemData = *(DWORD*)dataPtr;

    GlobalUnlock(grid->hmem);
    return itemData;
}

static void GridGetRowColor (GRID *grid, DWORD rpData, ROWCOLOR *lpROWCOLOR)
{
    unsigned char *data = (unsigned char *)GlobalLock(grid->hmem);

    data += rpData;

    *lpROWCOLOR = *(ROWCOLOR*)data;
    GlobalUnlock(grid->hmem);
}

static void GridSetRowColor (GRID *grid, DWORD rpData, const ROWCOLOR *lpROWCOLOR)
{
    unsigned char *data = (unsigned char *)GlobalLock(grid->hmem);

    data += rpData;

    *(ROWCOLOR*)data = *lpROWCOLOR;
    GlobalUnlock(grid->hmem);
}

static void UpdateText(GRID *grid, DWORD *rpDest, void *source)
{
    int iTmp;

    if (source != NULL)
    {
        int len = (int)strlen((const char *)source) + 1;

        if (grid->rpstrfree + len > grid->strsize)
        {
            grid->hstr = ExpandMem(grid->hstr,grid->strsize);
            grid->strsize += MEM_SIZE;
        }

        char *data = (char *)GlobalLock(grid->hstr);

        iTmp = *rpDest;
        if ( iTmp != 0 )
        {
            iTmp = (int)strlen ((const char *)(data + iTmp)) + 1;
        }
        if (iTmp >= len)
        {
            strcpy_s((char *)(data + *rpDest), iTmp, (const char *)source);
        }
        else
        {
            int posi = grid->rpstrfree;

            *rpDest = posi;
            grid->rpstrfree += len;
            strcpy_s((char *)(data + posi), len, (const char *)source);
        }
        GlobalUnlock(grid->hstr);
    }
    else
    {
        *rpDest = 0;
    }
}

static void UpdateFixed(GRID *grid, DWORD *rpDest, void *source, int maxLen)
{
    if (source != NULL)
    {
        if (*rpDest == 0)
        {
            *rpDest = grid->rpstrfree;
            grid->rpstrfree += maxLen;

            if ( grid->rpstrfree > grid->strsize )
            {
                grid->hstr = ExpandMem(grid->hstr,grid->strsize);
                grid->strsize += MEM_SIZE;
            }
        }
        unsigned char *data = (unsigned char *)GlobalLock(grid->hstr);
        memcpy((data + *rpDest), source, maxLen);
        GlobalUnlock(grid->hstr);
    }
    else
    {
        *rpDest = 0;
    }
}

static void Updateint32_t(GRID *grid, DWORD *rpDest, int32_t source)
{
    if (*rpDest == 0)
    {
        *rpDest = grid->rpstrfree;
        grid->rpstrfree += 4;

        if ( grid->rpstrfree > grid->strsize )
        {
            grid->hstr = ExpandMem(grid->hstr,grid->strsize);
            grid->strsize += MEM_SIZE;
        }
    }
    unsigned char *data = (unsigned char *)GlobalLock(grid->hstr);
    *(int32_t*)(data + *rpDest) = source;
    GlobalUnlock(grid->hstr);
}

static void GridSetCellData (GRID *grid, DWORD rpData, DWORD nCol, void *lpData)
{
    unsigned char *data = (unsigned char *)GlobalLock(grid->hmem);
    COLUMN *colPtr;

    data += rpData + 2 * 4 + 8 * nCol;

    colPtr = ((COLUMN*)(grid + 1)) + nCol;
    switch (colPtr->ctype)
    {
    case TYPE_SELTEXT:
    case TYPE_EDITTEXT:
    case TYPE_BUTTON:
    case TYPE_EDITBUTTON:
        UpdateText(grid, (DWORD*)data, lpData);
        break;

    case TYPE_USER:
        if ( colPtr->ctextmax == 0 )
        {
            UpdateText(grid, (DWORD*)data, lpData);
        }
        else
        {
            UpdateFixed(grid, (DWORD*)data, lpData, colPtr->ctextmax);
        }
        break;

    default:
        Updateint32_t(grid, (DWORD*)data, *(int32_t*)lpData); // RDBJ ????
        break;
    }
    GlobalUnlock(grid->hmem);
}

static void GridSetCellItemData (GRID *grid, DWORD rpData, DWORD nCol, DWORD itemData)
{
    unsigned char *data = (unsigned char *)GlobalLock(grid->hmem);

    data += rpData + 2 * 4 + 8 * nCol + 4;

    *(DWORD *)data = itemData;
    GlobalUnlock(grid->hmem);
}


//static int SetItem (GRID *grid, DWORD nRow, DWORD dwItem)
//{
//	if (nRow < grid->rows)
//	{
//		((int *)(((unsigned char*)grid) + grid->rpitemdata))[nRow] = (int)dwItem;
//		return 0;
//	}
//	else
//	{
//		return LB_ERR;
//	}
//}
//
static int GetItem (GRID *grid, DWORD nRow)
{
    if (nRow < grid->rows)
    {
        return ((int *)(((unsigned char*)grid) + grid->rpitemdata))[nRow];
    }
    else
    {
        return LB_ERR;
    }
}

/*
GridSort proc uses ebx esi edi,hMem:DWORD,lpLBMem:DWORD,nCol:DWORD,fString:DWORD,fDescending:DWORD
    LOCAL	nVal:DWORD
    LOCAL	lpStrMem:DWORD
    LOCAL	nStr:DWORD

    mov		ebx,hMem
    mov		eax,grid->hpar
    mov		hpar,eax
    invoke GetWindowLong,eax,GWL_WNDPROC
    mov		lpwndproc,eax
    mov		eax,grid->hgrd
    mov		cis.hwndItem,eax
    mov		eax,grid->nid
    mov		cis.CtlID,eax
    mov		cis.CtlType,ODT_GRID
    invoke GlobalLock,grid->hstr
    mov		lpStrMem,eax
    invoke GlobalLock,grid->hmem
    mov		edi,nCol
    lea		edi,[edi*4+eax+2*4]
    mov		eax,grid->rows
;	dec		eax
;	invoke QuickSort,lpLBMem,0,eax,edi,lpStrMem,fString,fDescending
    invoke CombSort,lpLBMem,eax,edi,lpStrMem,fString,fDescending
    mov		ebx,hMem
    invoke GlobalUnlock,grid->hmem
    invoke GlobalUnlock,grid->hstr
    ret

GridSort endp

GridSortColumn proc uses ebx esi,hMem:DWORD,nCol:DWORD,nSort:DWORD

    mov		ebx,hMem
    mov		eax,grid->rpitemdata
    lea		esi,[ebx+eax]

    mov		ecx,nCol
    mov		eax,sizeof COLUMN
    mul		ecx

    lea		edx,[ebx+eax+sizeof GRID]
    mov		eax,[edx].COLUMN.ctype
    xor		ecx,ecx
    .if eax==TYPE_EDITTEXT || eax==TYPE_BUTTON || eax==TYPE_EDITBUTTON || (eax==TYPE_USER && ![edx].COLUMN.ctextmax)
        dec		ecx
    .elseif eax==TYPE_USER && [edx].COLUMN.ctextmax
        mov		ecx,[edx].COLUMN.ctextmax
    .endif
    .if nSort==SORT_ASCENDING
        and		[edx].COLUMN.hdrflag,-1 xor 2
        xor		edx,edx
    .elseif nSort==SORT_DESCENDING
        or		[edx].COLUMN.hdrflag,2
        xor		edx,edx
        inc		edx
    .else
        ;Sort invert
        xor		[edx].COLUMN.hdrflag,2
        mov		edx,[edx].COLUMN.hdrflag
        and		edx,2
    .endif
    invoke GridSort,ebx,esi,nCol,ecx,edx
    ret

GridSortColumn endp
*/

static void GridSort(GRID* grid, unsigned char* lpLBMem, DWORD nCol, int fString, bool fDescending)
{
    char *lpStrMem;

	lpLBMem;

    lpStrMem = (char*)GlobalLock(grid->hstr);
    unsigned char *dataPtr = (unsigned char *)GlobalLock(grid->hmem);

    //CombSort(itemData,grid->rows,lpStrMem + 2 * 4 + nCol * 4,lpStrMem,fString,fDescending)
    char *left;
	char *right;
	int leftIndex;
	int rightIndex;

	for (DWORD i = 0; i < grid->rows - 1; i++)
    {
		leftIndex = GetItem(grid, i) + 2 * 4 + 8 * nCol;
		left = &lpStrMem[*(DWORD*)&dataPtr[leftIndex]];
        for (DWORD j = i + 1; j < grid->rows; j++)
        {
            bool needsSwap = false;
			int comparison;
			rightIndex = GetItem(grid, j) + 2 * 4 + 8 * nCol;
			right = &lpStrMem[*(DWORD*)&dataPtr[rightIndex]];

            if (fString == 0)
            {
				comparison = memcmp(&dataPtr[leftIndex], &dataPtr[rightIndex], 4);
            }
            else if (fString == -1)
            {
				comparison = TsStriCmp(left, right);
            }
            else
            {
				comparison = TsStrniCmp(left, right, fString);
            }
			if (fDescending)
			{
				needsSwap = (comparison < 0 && *left != 0) || (*left == 0 && *right != 0);
			}
			else
			{
				needsSwap = (comparison > 0 && *right != 0) || (*left == 0 && *right != 0);
			}
            if (needsSwap)
            {
                int64_t tmp = *(int64_t*)&dataPtr[leftIndex];
                *(int64_t*)&dataPtr[leftIndex] = *(int64_t*)&dataPtr[rightIndex];
                *(int64_t*)&dataPtr[rightIndex] = tmp;
            }
        }
    }
    GlobalUnlock(grid->hmem);
    GlobalUnlock(grid->hstr);
}

static void GridSortColumn(GRID* grid, DWORD nCol, DWORD nSort)
{
	unsigned char *lpLBMem;
    COLUMN* col;
    int searchLen = 0;
    bool searchDirection;

    lpLBMem = (unsigned char*)(((unsigned char*)grid) + grid->rpitemdata);  // esi
	col = (COLUMN*)((unsigned char*)grid + sizeof(GRID) + sizeof(COLUMN) * nCol);    

    if (col->ctype == TYPE_EDITTEXT || col->ctype == TYPE_BUTTON || col->ctype == TYPE_SELTEXT || (col->ctype == TYPE_USER && col->ctextmax == 0))
    {
        searchLen = -1;
    }
    else if (col->ctype == TYPE_USER && col->ctextmax != 0)
    {
        searchLen = col->ctextmax;
    }

    if (nSort == SORT_ASCENDING)
    {
        col->hdrflag &= (-1 ^ 2);
        searchDirection = false;
    }
    else if (nSort == SORT_DESCENDING)
    {
        col->hdrflag |= 2;
        searchDirection = true;
    }
    else
    {
        // Invert
        col->hdrflag ^= 2;
        searchDirection = (col->hdrflag & 2) != 0;
    }

    GridSort(grid, lpLBMem,nCol,searchLen,searchDirection);
}

static HWND ShowHide (HWND hLst, BOOL fShow)
{
    if (fShow)
    {
        DWORD col, row;

        col = (DWORD)SendMessageA(hLst, GM_GETCURCOL, 0, 0);
        row = (DWORD)SendMessageA(hLst, GM_GETCURROW, 0, 0);
        return (HWND)SendMessageA(hLst, GM_ENTEREDIT,col,row);
    }
    else
    {
        return (HWND)SendMessageA(hLst,GM_ENDEDIT,0,TRUE);
    }
}

static void RelMemParent(HWND hWin)
{
    GlobalUnlock((HANDLE)GetWindowLongPtr(GetParent(hWin), 0));
}

static void RelMemHere(HWND hWin)
{
    GlobalUnlock((HANDLE)GetWindowLongPtr(hWin, 0));
}

static GRID *GetMemParent(HWND hWin)
{
    return (GRID*)GlobalLock((HANDLE)GetWindowLongPtr(GetParent(hWin), 0));
}

static GRID *GetMemHere(HWND hWin)
{
    return (GRID*)GlobalLock((HANDLE)GetWindowLongPtr(hWin, 0));
}

/*
;dtadd	dq 24*60*60*1000*1000*1000*1000*100
*/

static LRESULT __stdcall DateTimeProc (HWND hWin,UINT uMsg, WPARAM wParam,LPARAM lParam)
{
    HDC	hDC;
    RECT rect;
    SYSTEMTIME stime;
    FILETIME ftime;

    switch (uMsg)
    {
    case WM_NCPAINT:
    {
        GetWindowRect(hWin, &rect);
        rect.right -= rect.left;
        rect.left = 0;
        rect.bottom -= rect.top;
        rect.top = 0;
        hDC = GetWindowDC(hWin);

        FrameRect(hDC, &rect, (HBRUSH)GetStockObject(BLACK_BRUSH));
        rect.left++;
        rect.top++;
        rect.right--;
        rect.bottom--;

        HBRUSH brush = CreateSolidBrush(GetSysColor(COLOR_WINDOW));
        FrameRect(hDC, &rect,brush);
        DeleteObject(brush);
        ReleaseDC(hWin,hDC);
        return 0;
    }
    case WM_KEYDOWN:
        if (wParam == VK_RETURN)
        {
            ShowWindow(hWin,SW_HIDE);
            return 0;
        }
        else if (wParam == VK_ESCAPE)
        {
            fCancelEdit = TRUE;
            ShowWindow(hWin,SW_HIDE);
            fCancelEdit = FALSE;
            return 0;
        }
        break;
    case WM_CHAR:
        if (wParam == '+')
        {
            __int64 tmp;

            SendMessageA(hWin,DTM_GETSYSTEMTIME,0, (LPARAM)&stime);
            SystemTimeToFileTime(&stime, &ftime);
            memcpy(&tmp, &ftime, sizeof(tmp));

            tmp += 24LL*60*60*1000*1000*10;

            memcpy(&ftime, &tmp, sizeof(tmp));
            FileTimeToSystemTime(&ftime, &stime);
            SendMessageA(hWin,DTM_SETSYSTEMTIME,0, (LPARAM)&stime);
            return 0;
        }
        else if (wParam == '-')
        {
            __int64 tmp;

            SendMessageA(hWin,DTM_GETSYSTEMTIME,0, (LPARAM)&stime);
            SystemTimeToFileTime(&stime, &ftime);
            memcpy(&tmp, &ftime, sizeof(tmp));

            tmp -= 24LL*60*60*1000*1000*10;

            memcpy(&ftime, &tmp, sizeof(tmp));
            FileTimeToSystemTime(&ftime, &stime);
            SendMessageA(hWin,DTM_SETSYSTEMTIME,0, (LPARAM)&stime);
            return 0;
        }
        else if (wParam == 'T' || wParam == 't')
        {
            GetSystemTime(&stime);
            SendMessageA(hWin,DTM_SETSYSTEMTIME,0, (LPARAM)&stime);
            return 0;
        }
        break;
    case WM_SHOWWINDOW:
        if (!wParam && !fCancelEdit)
        {
            fCancelEdit = TRUE;
            SendMessageA(GetParent(GetParent(hWin)),GM_ENDEDIT,GetWindowLong(hWin,GWL_ID),FALSE);
            fCancelEdit = FALSE;
        }
        break;
    case WM_GETDLGCODE:
        return DLGC_CODE;
    }
    return CallWindowProc((WNDPROC)GetWindowLongPtr(hWin,GWLP_USERDATA),hWin,uMsg,wParam,lParam);
}


static LRESULT __stdcall LstProc (HWND hWin,UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    POINT pt;

    switch (uMsg)
    {
    case WM_CHAR:
        if (wParam == VK_RETURN)
        {
            fCancelEdit = FALSE;
            ShowWindow(hWin,SW_HIDE);
            return 0;
        }
        else if (wParam == VK_ESCAPE)
        {
            fCancelEdit = TRUE;
            ShowWindow(hWin,SW_HIDE);
            fCancelEdit = FALSE;
            return 0;
        }
        break;
    case WM_LBUTTONDOWN:
        fCancelEdit = FALSE;
        ShowWindow(hWin,SW_HIDE);
        return 0;
    case WM_MOUSEMOVE:
    {
        GetCursorPos(&pt);
        int item = LBItemFromPt(hWin,pt,TRUE);

        if (item != SendMessageA(hWin,LB_GETCURSEL,0,0))
        {
            SendMessageA(hWin,LB_SETCURSEL,item,0);
        }
        return 0;
    }
    case WM_ACTIVATE:
        if (LOWORD(wParam) != WA_INACTIVE)
        {
            hfocus = (HWND)lParam;
            SendMessageA(hfocus,WM_NCACTIVATE,TRUE,0);
        }
        else if ((HWND)lParam != hfocus)
        {
            SendMessageA(hfocus,WM_NCACTIVATE,FALSE,0);
        }
        break;
    case WM_SHOWWINDOW:
        if (!wParam && !fCancelEdit)
        {
            GRID *grid;

            fCancelEdit = TRUE;

            grid = (GRID*)GlobalLock((HANDLE)GetWindowLongPtr((HWND)GetWindowLongPtr(hWin, GWLP_USERDATA), 0));

            grid->ncol = grid->col;
            grid->nrow = grid->row;
            GlobalUnlock((HANDLE)GetWindowLongPtr((HWND)GetWindowLongPtr(hWin, GWLP_USERDATA), 0));

            SendMessageA((HWND)GetWindowLongPtr(hWin, GWLP_USERDATA),GM_ENDEDIT,grid->edtrowcol,FALSE);
            fCancelEdit = FALSE;
        }
        break;
    case WM_KILLFOCUS:
        ShowWindow(hWin,SW_HIDE);
        break;
    case WM_SETFOCUS:
        fCancelEdit = TRUE;
        break;
    case WM_GETDLGCODE:
        return DLGC_CODE;
    }
    return CallWindowProc(lplstproc,hWin,uMsg,wParam,lParam);
}

static LRESULT __stdcall HotProc (HWND hWin, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    HDC hDC;
    RECT rect;

    switch (uMsg)
    {
    case WM_NCPAINT:
    {
        GetWindowRect(hWin, &rect);
        rect.right -= rect.left;
        rect.left = 0;
        rect.bottom -= rect.top;
        rect.top = 0;
        hDC = GetWindowDC(hWin);

        FrameRect(hDC, &rect, (HBRUSH)GetStockObject(BLACK_BRUSH));
        rect.left++;
        rect.top++;
        rect.right--;
        rect.bottom--;

        HBRUSH brush = (HBRUSH)CreateSolidBrush(GetSysColor(COLOR_WINDOW));
        FrameRect(hDC, &rect, brush);
        DeleteObject(brush);
        ReleaseDC(hWin,hDC);
        return 0;
    }
    case WM_KEYDOWN:
        if (wParam == VK_RETURN)
        {
            ShowWindow(hWin,SW_HIDE);
            return 0;
        }
        else if (wParam == VK_ESCAPE)
        {
            fCancelEdit = TRUE;
            ShowWindow(hWin,SW_HIDE);
            fCancelEdit = FALSE;
            return 0;
        }
        break;
    case WM_SHOWWINDOW:
        if (!wParam && !fCancelEdit)
        {
            fCancelEdit = TRUE;
            SendMessageA(GetParent(GetParent(hWin)),GM_ENDEDIT,GetWindowLong(hWin,GWL_ID),FALSE);
            fCancelEdit = FALSE;
        }
        break;
    case WM_GETDLGCODE:
        return DLGC_CODE;
    }

    return CallWindowProc((WNDPROC)GetWindowLongPtr(hWin,GWLP_USERDATA),hWin,uMsg,wParam,lParam);
}


static LRESULT __stdcall EdtTextProc (HWND hWin, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
    case WM_CHAR:
        if (wParam == VK_RETURN)
        {
            ShowWindow(hWin,SW_HIDE);
            return 0;
        }
        else if (wParam == VK_ESCAPE)
        {
            fCancelEdit = TRUE;
            ShowWindow(hWin,SW_HIDE);
            fCancelEdit = FALSE;
            return 0;
        }
        break;
    case WM_SHOWWINDOW:
        if (!wParam && !fCancelEdit)
        {
            fCancelEdit = TRUE;
            SendMessageA(GetParent(GetParent(hWin)),GM_ENDEDIT,GetWindowLong(hWin,GWL_ID),FALSE);
            fCancelEdit = FALSE;
        }
        break;
    case WM_GETDLGCODE:
        return DLGC_CODE;
    }
    return CallWindowProc((WNDPROC)GetWindowLongPtr(hWin,GWLP_USERDATA),hWin,uMsg,wParam,lParam);
}

static LRESULT __stdcall Edtint32_tProc (HWND hWin, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
    case WM_CHAR:
        if (wParam == VK_RETURN)
        {
            ShowWindow(hWin,SW_HIDE);
            return 0;
        }
        else if (wParam == VK_ESCAPE)
        {
            fCancelEdit = TRUE;
            ShowWindow(hWin,SW_HIDE);
            fCancelEdit = FALSE;
            return 0;
        }
        break;
    case WM_SHOWWINDOW:
        if (!wParam && !fCancelEdit)
        {
            fCancelEdit = TRUE;
            SendMessageA(GetParent(GetParent(hWin)),GM_ENDEDIT,GetWindowLong(hWin,GWL_ID),FALSE);
            fCancelEdit = FALSE;
        }
        break;
    case WM_GETDLGCODE:
        return DLGC_CODE;
    }
    return CallWindowProc((WNDPROC)GetWindowLongPtr(hWin,GWLP_USERDATA),hWin,uMsg,wParam,lParam);
}


// --------------------------------------------------------------------------------

static LRESULT __stdcall GridHdrProc (HWND hWin, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    RECT	rect;
    GRIDNOTIFY	gn;
    GRID *grid;
    COLUMN *colPtr;

    switch (uMsg)
    {
    case WM_MOUSEMOVE:
        grid = GetMemParent(hWin);
        colPtr = (COLUMN *)(grid + 1);
        if ((grid->style & STYLE_NOCOLSIZE) == 0)
        {
            if (grid->fSize < 2)
            {
                if ((wParam & (MK_LBUTTON | MK_RBUTTON)) == 0)
                {
                    grid->fSize = 0;
                    int col = grid->cols;
                    while (col)
                    {
                        col--;

                        if (colPtr[col].colwt)
                        {
                            grid->nSizeMin = colPtr[col].colxp;
                            rect.left = colPtr[col].colwt + colPtr[col].colxp;

                            grid->nSizeOfs = LOWORD(lParam) - rect.left;

                            if (LOWORD(lParam) - 2 <= rect.left && LOWORD(lParam) + 4 >= rect.left)
                            {
                                grid->nSizeCol = col;
                                SetCursor(grid->hcur);
                                grid->fSize = 1;
                                break;
                            }
                        }
                    }
                }
            }
            else
            {
                GetClientRect(GetParent(hWin), &rect);

                int offset = ((short)lParam) - grid->nSizeOfs;

                if (offset < grid->nSizeMin)
                {
                    offset = grid->nSizeMin;
                }
                offset -= grid->sbx;
                MoveWindow(grid->hsize,offset,0,2,rect.bottom,TRUE);
                ShowWindow(grid->hsize,SW_SHOW);
            }
        }
        RelMemParent(hWin);
        return 0;
    case WM_LBUTTONDOWN:
        grid = GetMemParent(hWin);
        colPtr = (COLUMN *)(grid + 1);
        if ((grid->style & STYLE_NOCOLSIZE) == 0)
        {
            if (grid->fSize==1)
            {
                ShowHide(grid->hgrd,FALSE);
                grid->fSize = 2;
                SetCursor(grid->hcur);
                SendMessageA(hWin,WM_MOUSEMOVE,wParam,lParam);
            }
            else
            {
                DWORD col = 0;

                while (col < grid->cols)
                {
                    if (LOWORD(lParam) < colPtr->colxp + colPtr->colwt)
                    {
                        colPtr->hdrflag |= 1;
                        InvalidateRect(grid->hhdr,NULL,TRUE);
                        UpdateWindow(grid->hhdr);
                        break;
                    }
                    col++;
                    colPtr++;
                }
            }
            SetCapture(hWin);
        }
        RelMemParent(hWin);
        return 0;
    case WM_LBUTTONUP:
        grid = GetMemParent(hWin);
        colPtr = (COLUMN *)(grid + 1);
        if ((grid->style & STYLE_NOCOLSIZE) == 0)
        {
            if (grid->fSize)
            {
                grid->fSize = 0;
                colPtr += grid->nSizeCol;

                int offset = (short)(lParam) - grid->nSizeOfs;

                if (offset <= grid->nSizeMin)
                {
                    offset = grid->nSizeMin + 1;
                }
                offset -= grid->nSizeMin;

                colPtr->colwt = offset;

                offset = colPtr->colxp;

                DWORD col = grid->nSizeCol;

                while (col < grid->cols)
                {
                    colPtr->colxp = offset;
                    offset += colPtr->colwt;
                    grid->ccx = offset;
                    colPtr++;
                    col++;
                }
                ShowWindow(grid->hsize,SW_HIDE);
                SendMessageA(grid->hgrd,WM_SIZE,0,0);
                InvalidateRect(grid->hhdr,NULL,TRUE);
                UpdateWindow(grid->hhdr);
                InvalidateRect(grid->hlst,NULL,TRUE);
                UpdateWindow(grid->hlst);
            }
            else
            {
                DWORD col = 0;
                while (col < grid->cols)
                {
                    if ((colPtr->hdrflag & 1) != 0)
                    {
                        colPtr->hdrflag &= ~1;

                        gn.nmhdr.hwndFrom = grid->hgrd;
                        gn.nmhdr.idFrom = grid->nid;
                        gn.nmhdr.code = GN_HEADERCLICK;
                        gn.col = col;
                        gn.row = -1;
                        gn.hwnd = hWin;
                        gn.lpdata = 0;
                        gn.fcancel = 0;

                        InvalidateRect(grid->hhdr,NULL,TRUE);
                        UpdateWindow(grid->hhdr);
                        SendMessageA(grid->hpar,WM_NOTIFY,grid->nid, (LPARAM)&gn);
                        break;
                    }
                    col++;
                    colPtr++;
                }
            }
            ReleaseCapture();
        }
        RelMemParent(hWin);
        return 0;
    case WM_LBUTTONDBLCLK:
        ReleaseCapture();
        return 0;
    }
    return CallWindowProc((WNDPROC)GetWindowLongPtr(hWin,GWLP_USERDATA),hWin,uMsg,wParam,lParam);
}


static int GetItemRect(GRID *grid, DWORD nRow, LPRECT lpRect)
{
    if (nRow < grid->rows)
    {
        GetClientRect(grid->hlst,lpRect);
        lpRect->left += grid->sbx;
        lpRect->right += grid->sbx;
        lpRect->top = (nRow - grid->toprow) * grid->rowht;
        lpRect->bottom = lpRect->top + grid->rowht;
        return 0;
    }
    else
    {
        lpRect->left = lpRect->top = lpRect->right = lpRect->bottom = 0;
        return LB_ERR;
    }
}

static DWORD InsertItem (GRID *grid, DWORD nRow, DWORD dwItem)
{
    RECT	rect;
    DWORD row;
    DWORD *itemData;

    row = grid->rows;
    itemData = (DWORD *)(((unsigned char *)grid) + grid->rpitemdata);

    while (row > nRow)
    {
        row--;
        itemData[row + 1] = itemData[row];
    }
    itemData[row] = dwItem;

    grid->rows++;

    GetClientRect(grid->hlst, &rect);
    int oldBottom = rect.bottom;
    GetItemRect(grid, nRow, &rect);
    rect.bottom = oldBottom;
    InvalidateRect(grid->hlst, &rect,TRUE);
    return nRow;
}

static DWORD DeleteItem (GRID *grid, DWORD nRow)
{
    RECT rect;
    DWORD row = nRow;
    DWORD *itemData;

    if (row < grid->rows)
    {
        GetClientRect(grid->hlst, &rect);
        if (row != (DWORD)grid->toprow)
        {
            int oldBottom = rect.bottom;
            GetItemRect(grid, nRow, &rect);
            rect.bottom = oldBottom;
        }

        itemData = (DWORD *)(((unsigned char *)grid) + grid->rpitemdata);

        row = nRow;
        while (row < grid->rows)
        {
            itemData[row] = itemData[row + 1];
            row++;
        }
        grid->rows--;
        InvalidateRect(grid->hlst, &rect, TRUE);
        return grid->rows;
    }
    else
    {
        return (DWORD)LB_ERR;
    }
}

static void UpdateLastRowCol(GRID *grid)
{
    grid->ncol = grid->col;
    grid->nrow = grid->row;
}

static LRESULT __stdcall RAListProc (HWND hWin, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    PAINTSTRUCT ps;
    DRAWITEMSTRUCT di;
    HWND hPar;
    RECT rect;
    BYTE buffer[MAX_CELL_SIZE];
    DWORD ftmp;
    GRID *grid;

    if (uMsg >= WM_MOUSEFIRST && uMsg <= WM_MOUSELAST)
    {
        PostMessage(GetParent(hWin), uMsg, wParam, lParam); // reflect all mouse messages to the parent
    }
    switch (uMsg)
    {
    case WM_DRAWITEM:
        grid = GetMemParent(hWin);
        if (((DRAWITEMSTRUCT*)lParam)->itemID != (DWORD)LB_ERR)
        {
            COLUMN *colPtr;

            SetBkMode(((DRAWITEMSTRUCT*)lParam)->hDC,TRANSPARENT);

            colPtr = &((COLUMN *)((unsigned char *)(grid + 1)))[GetWindowLong(((DRAWITEMSTRUCT*)lParam)->hwndItem,GWL_ID)];

            if ((((DRAWITEMSTRUCT*)lParam)->itemState & ODS_SELECTED) == 0 )
            {
                SetTextColor(((DRAWITEMSTRUCT*)lParam)->hDC,grid->coltext);
                FillRect(((DRAWITEMSTRUCT*)lParam)->hDC, &((DRAWITEMSTRUCT*)lParam)->rcItem, grid->hbrback);
            }
            else
            {
                SetTextColor(((DRAWITEMSTRUCT*)lParam)->hDC, grid->coltexthilite);
                FillRect(((DRAWITEMSTRUCT*)lParam)->hDC, &((DRAWITEMSTRUCT*)lParam)->rcItem, grid->hbrcellhilite);
                if (colPtr->himl)
                {
                    CopyRect(&rect, &((DRAWITEMSTRUCT*)lParam)->rcItem);
                    rect.right = 18;
                    FillRect(((DRAWITEMSTRUCT*)lParam)->hDC, &rect, grid->hbrback);
                }
            }
            if (colPtr->himl)
            {
                CopyRect(&rect, &((DRAWITEMSTRUCT*)lParam)->rcItem);
                ((DRAWITEMSTRUCT*)lParam)->rcItem.left += 18;
                rect.left++;
                rect.right = rect.left + 16;

                HRGN rgn = CreateRectRgn(rect.left,rect.top,rect.right,rect.bottom);
                SelectClipRgn(((DRAWITEMSTRUCT*)lParam)->hDC,rgn);
                DeleteObject(rgn);
                ImageList_Draw((_IMAGELIST*)colPtr->himl,(int)((DRAWITEMSTRUCT*)lParam)->itemData,((DRAWITEMSTRUCT*)lParam)->hDC,rect.left,rect.top,ILD_NORMAL);
                SelectClipRgn(((DRAWITEMSTRUCT*)lParam)->hDC,NULL);
            }
            buffer[0] = 0;
            SendMessageA(((DRAWITEMSTRUCT*)lParam)->hwndItem,LB_GETTEXT,((DRAWITEMSTRUCT*)lParam)->itemID,(LPARAM)buffer);
            TextOutA(((DRAWITEMSTRUCT*)lParam)->hDC,((DRAWITEMSTRUCT*)lParam)->rcItem.left + 2,((DRAWITEMSTRUCT*)lParam)->rcItem.top + 1,(const char *)buffer,(int)TsStrLen((const char *)buffer));
            SetTextColor(((DRAWITEMSTRUCT*)lParam)->hDC,0);
        }
        RelMemParent(hWin);
        return 1;  // maybe break;

    case WM_CTLCOLORLISTBOX:
    {
        INT_PTR color;

        grid = GetMemParent(hWin);
        color = (INT_PTR)grid->hbrback;
        RelMemParent(hWin);
        return color;
    }
    case WM_PAINT:
    {
        DWORD selState;

        grid = GetMemParent(hWin);

        selState = ODS_SELECTED;
        if (GetFocus() == hWin)
        {
            selState = ODS_FOCUS | ODS_SELECTED;
        }
        HDC dc = BeginPaint(hWin,&ps);
        GetClientRect(grid->hgrd, &rect);


        rect.bottom -= grid->hdrht;
        int tmp = (grid->rows - grid->toprow) * grid->rowht; // edx

        rect.right += grid->sbx;

        if (grid->ccx + 1 < rect.right || tmp < rect.bottom)
        {
            if (grid->ccx + 1 < rect.right)
            {
                rect.left = grid->ccx + 1;

                FillRect(ps.hdc, &rect, grid->hbrback);
                rect.right = rect.left;
            }

            if (tmp < rect.bottom)
            {
                rect.top = tmp;
                rect.left = 0;
                FillRect(ps.hdc, &rect, grid->hbrback);
            }
        }


        hPar = GetParent(hWin);

        tmp = (ps.rcPaint.top / grid->rowht) * grid->rowht;
        DWORD row = grid->toprow + (ps.rcPaint.top / grid->rowht);

        while (tmp < ps.rcPaint.bottom)
        {
            if (row < grid->rows)
            {
                di.rcItem.top = tmp;
                di.rcItem.bottom = tmp + grid->rowht;
                di.rcItem.left = 0;
                di.rcItem.right = ps.rcPaint.right;
                di.hDC = dc;
                di.CtlType = ODT_LISTBOX;
                di.CtlID = 0;
                di.itemID = row;

                di.itemData = *(int32_t*)(((unsigned char *)(grid + 1)) + (grid->cols * sizeof(COLUMN)) + row * 4);

                di.hwndItem = hWin;
                di.itemAction = ODA_DRAWENTIRE;

                if (row == (DWORD)grid->row)
                {
                    di.itemState = selState;
                }
                else
                    di.itemState = 0;
                SendMessageA(hPar,WM_DRAWITEM,0,(LPARAM)&di);
            }
            tmp += grid->rowht;
            row++;
        }
        EndPaint(hWin, &ps);
        RelMemParent(hWin);
        return 0;
    }

    case WM_ERASEBKGND:
        return 0;

    case WM_KEYDOWN:
    {
        int scancode;
        DWORD col;
        DWORD row;
        COLUMN *colPtr;

        scancode = ((lParam >> 16) & 0x3ff);

        grid = GetMemParent(hWin);
        colPtr = (COLUMN *)((unsigned char *)(grid + 1));

        if (wParam == 0x27 && (scancode == 0x14D || scancode == 0x4D))
        { // Right
            col = grid->col + 1;
            while (col < grid->cols)
            {
                if ( colPtr[col].colwt != 0 )
                {
                    SendMessageA(grid->hgrd,GM_SETCURSEL,col,grid->row);
                    UpdateLastRowCol(grid);
                    break;
                }
                col++;
            }
            RelMemParent(hWin);
            return 0;
        }
        else if (wParam == 0x25 && (scancode == 0x14B || scancode == 0x4B))
        { // Left
            col = grid->col;
            while (col > 0)
            {
                col--;
                if ( colPtr[col].colwt != 0 )
                {
                    SendMessageA(grid->hgrd,GM_SETCURSEL,col,grid->row);
                    UpdateLastRowCol(grid);
                    break;
                }
            }
            RelMemParent(hWin);
            return 0;
        }
        else if (wParam == 0x28 && (scancode == 0x150 || scancode == 0x50))
        { // Down
            row = grid->row + 1;
            if (row < grid->rows)
            {
                SendMessageA(grid->hgrd,GM_SETCURSEL,grid->col,row);
                UpdateLastRowCol(grid);
            }
            RelMemParent(hWin);
            return 0;
        }
        else if (wParam == 0x26 && (scancode == 0x148 || scancode == 0x48))
        { // Up
            row = grid->row - 1;
            if (row < 0xffffffff )
            {
                SendMessageA(grid->hgrd,GM_SETCURSEL,grid->col,row);
                UpdateLastRowCol(grid);
            }
            RelMemParent(hWin);
            return 0;
        }
        else if (wParam == 0x21 && (scancode == 0x149 || scancode == 0x49))
        { // PgUp
            if (grid->row)
            {
                GetClientRect(hWin, &rect);

                row = grid->row - (rect.bottom / grid->rowht);

                if (row < 0)
                {
                    row = 0;
                }

                SendMessageA(grid->hgrd,GM_SETCURSEL,grid->col,row);
                UpdateLastRowCol(grid);
            }
            RelMemParent(hWin);
            return 0;
        }
        else if (wParam == 0x22 && (scancode == 0x151 || scancode == 0x51))
        { // PgDn
            GetClientRect(hWin, &rect);

            row = grid->row + (rect.bottom / grid->rowht);
            if (row >= grid->rows)
            {
                row = grid->rows - 1;
            }
            SendMessageA(grid->hgrd,GM_SETCURSEL,grid->col,row);
            UpdateLastRowCol(grid);
            RelMemParent(hWin);
            return 0;
        }
        else if (wParam == 0x24 && (scancode == 0x147 || scancode == 0x47))
        { // Home
            SendMessageA(grid->hgrd,GM_SETCURSEL,grid->col,0);
            UpdateLastRowCol(grid);
            RelMemParent(hWin);
            return 0;
        }
        else if (wParam == 0x23 && (scancode == 0x14F || scancode == 0x4F))
        { // End
            SendMessageA(grid->hgrd,GM_SETCURSEL,grid->col,grid->rows - 1);
            UpdateLastRowCol(grid);
            RelMemParent(hWin);
            return 0;
        }
        else
        {
            RelMemParent(hWin);
        }
        break;
    }
    case WM_CHAR:
        grid = GetMemParent(hWin);
        if (wParam == VK_TAB)
        {
            SendMessageA(grid->hpar,WM_NEXTDLGCTL,GetAsyncKeyState(VK_SHIFT),0);
        }
        else
        {
            HWND tmp = ShowHide(grid->hgrd,TRUE);

            if (wParam != VK_RETURN && tmp)
            {
                SendMessageA(tmp,WM_CHAR,wParam,lParam);
            }
        }
        RelMemParent(hWin);
        return 0;
    case WM_LBUTTONDOWN:
    {
        grid = GetMemParent(hWin);
        SetFocus(hWin);
        SetCapture(hWin);

        int oldNcol = grid->ncol;
        int oldNrow = grid->nrow;
        int tmp = 0;

        RAListProc(hWin,WM_MOUSEMOVE,wParam,lParam);

        if (oldNcol == grid->col && oldNrow == grid->row)
        {
            tmp++;
        }
        grid->fsame = tmp;

        COLUMN *colPtr;

        colPtr = &((COLUMN *)((unsigned char *)(grid + 1)))[grid->col];

        if ((colPtr->ctype == TYPE_CHECKBOX || colPtr->ctype == TYPE_SELTEXT) /*&& grid->fsame*/)
        {
            ShowHide(grid->hgrd,TRUE);
            ShowHide(grid->hgrd,FALSE);
        }
        RelMemParent(hWin);
        return 0;
    }
    case WM_LBUTTONUP:
        grid = GetMemParent(hWin);
        if (GetCapture() == hWin)
        {
            ReleaseCapture();
            if (grid->fonbtn && grid->fsame)
            {
                if (grid->fonbtn == TYPE_COMBOBOX || grid->fonbtn == TYPE_SELTEXT )
                {
                    grid->ncol = -1;
                    grid->nrow = -1;
                }
                grid->fsame = FALSE;
                ShowHide(grid->hgrd,TRUE);
                grid->fonbtn = FALSE;
            }
        }
        RelMemParent(hWin);
        return 0;
    case WM_MOUSEMOVE:
    {
        grid = GetMemParent(hWin);
        grid->fonbtn = FALSE;

        if (GetCapture() == hWin)
        {
            COLUMN *colPtr = (COLUMN*)(grid + 1);
            short x = lParam & 0xffff;
            short y = (lParam >> 16) & 0xffff;

            if (y < 0)
            {
                SendMessageA(grid->hgrd,WM_VSCROLL,SB_LINEUP,0);
                RelMemParent(hWin);
                return 0;
            }
            if (x < 0)
            {
                SendMessageA(grid->hgrd,WM_HSCROLL,SB_LINEUP,0);
                RelMemParent(hWin);
                return 0;
            }
            DWORD col = 0; // ecx
            int colOffset = 0; // edx

            while (col < grid->cols)
            {
                colOffset += colPtr->colwt;
                if (x >= colPtr->colxp && x <= colOffset)
                {
                    if (colPtr->ctype==TYPE_COMBOBOX || colPtr->ctype==TYPE_BUTTON || colPtr->ctype==TYPE_EDITBUTTON ||
                        colPtr->ctype==TYPE_SELTEXT)
                    {
                        if (x + grid->rowht >= colOffset)
                        {
                            grid->fonbtn = colPtr->ctype;
                        }
                    }
                    break;
                }
                colPtr++;
                col++;
            }
            if (col < grid->cols)
            {
                DWORD row = (y / grid->rowht) + grid->toprow;
                if (row < grid->rows)
                {
                    if (col != (DWORD)grid->ncol || row != (DWORD)grid->nrow)
                    {
                        grid->fsame = FALSE;
                        grid->fonbtn = FALSE;
                    }
                    grid->ncol = col;
                    grid->nrow = row;
                    SendMessageA(grid->hgrd,GM_SETCURSEL,col,row);
                }
            }
        }
        RelMemParent(hWin);
        return 0;
    }
    case WM_LBUTTONDBLCLK:
    {
        grid = GetMemParent(hWin);

        COLUMN *colPtr = ((COLUMN*)(grid + 1));

        if (colPtr[grid->col].ctype != TYPE_COMBOBOX)
        {
            ShowHide(grid->hgrd,TRUE);
        }
        else
        {
            DWORD col = 0;
            short x = (lParam & 0xffff);
            int colOffset = 0;

            ftmp = 0;
            while (col < grid->cols)
            {
                colOffset += colPtr->colwt;

                if (x >= colPtr->colxp && x <= colOffset)
                {
                    if (colPtr->ctype == TYPE_COMBOBOX || colPtr->ctype == TYPE_BUTTON || colPtr->ctype == TYPE_EDITBUTTON ||
                        colPtr->ctype == TYPE_SELTEXT )
                    {
                        x += (short)grid->rowht;
                        if (x >= colOffset)
                        {
                            ftmp = colPtr->ctype;
                        }
                    }
                    break;
                }
                colPtr++;
                col++;
            }
            if (ftmp)
            {
                SetCapture(hWin);
            }
            else
            {
                ShowHide(grid->hgrd,TRUE);
            }
        }
        RelMemParent(hWin);
        return 0;
    }
    case WM_SETFOCUS:
        grid = GetMemParent(hWin);
        if (grid->hedt != 0)
        {
            ShowWindow(grid->hedt,SW_HIDE);
            grid->hedt = 0;
        }
        GetItemRect(grid, grid->row, &rect);
        InvalidateRect(hWin, &rect,TRUE);
        RelMemParent(hWin);
        break;
    case WM_KILLFOCUS:
        grid = GetMemParent(hWin);
        GetItemRect(grid, grid->row, &rect);
        InvalidateRect(hWin, &rect,TRUE);
        RelMemParent(hWin);
        break;
    case WM_MOUSEWHEEL:
        SendMessageA(GetParent(hWin),uMsg,wParam,lParam);
        return 0;

    case WM_GETDLGCODE:
        return DLGC_CODE;
    }
    return DefWindowProc(hWin,uMsg,wParam,lParam);
}

static void DrawItemText(HDC mDC, const char *buffer, RECT &rect2, DWORD alignment)
{
    rect2.left += 3;
    rect2.top += 2;
    rect2.right -= 3;

    switch (alignment)
    {
    case GA_ALIGN_LEFT:
        alignment = DT_LEFT | DT_NOPREFIX;
        break;
    case GA_ALIGN_CENTER:
        alignment = DT_CENTER | DT_NOPREFIX;
        break;
    default:
        alignment = DT_RIGHT | DT_NOPREFIX;
    }

    DrawTextA(mDC, buffer,(int)TsStrLen(buffer), &rect2,alignment);
    rect2.left -= 3;
    rect2.top -= 2;
    rect2.right += 3;
}

static void DrawItemLine(GRID *grid, HDC mDC, DWORD col, RECT &rect2)
{
    col = col + 1 - grid->cols;
    if ((grid->style & STYLE_GRIDFRAME) == 0)
    {
        col--;
    }

    if ((grid->style & STYLE_VGRIDLINES) != 0 || !col)
    {
        MoveToEx(mDC,rect2.right,rect2.top,NULL);
        LineTo(mDC,rect2.right,rect2.bottom);
    }
}

static void Format(GRID *grid, DWORD formatString, char *buffer, int bufferLen)
{
    if ( formatString == 0 )
        return;

    char outputBuffer[MAX_CELL_SIZE];
    char format[MAX_FORMAT_SIZE];

    char *p = format;
    char *dest = &outputBuffer[sizeof(outputBuffer) - 2];
    char *source = buffer;

    GridGetText(grid,formatString,format, sizeof(format));

    int sourceLen = (int)strlen((const char*)buffer);
    int maskLen = (int)strlen((const char*)p);

    dest[1] = 0;
    while (sourceLen && maskLen)
    {
        BYTE b = source[sourceLen - 1];

        if (b != '-')
        {
            maskLen--;
            b = p[maskLen];
            if (b == '#')
            {
                sourceLen--;
                b = source[sourceLen];
            }
        }
        else
        {
            sourceLen = 0;
        }
        *dest = b;
        dest--;
    }

    dest++;
    
    strcpy_s((char *)buffer, bufferLen, (const char *)dest);
}

static void BinToDec (DWORD dwVal, char *lpAscii, int asciiLen)
{
    _itoa_s(dwVal, lpAscii, asciiLen, 10);
}

static DWORD DecToBin(BYTE* buffer)
{
    return atoi((const char *)buffer);
}

static void SetNotify(GRID *grid, HWND hWin, int itemID, int col, GRIDNOTIFY &gn)
{
    gn.nmhdr.hwndFrom = hWin;
    gn.nmhdr.idFrom = grid->nid;
    gn.hwnd = grid->hedt;
    gn.col = col;
    gn.row = itemID;
    gn.fcancel = FALSE;
}

static LRESULT RAGridDrawItem(GRID *grid, HWND hWin, DRAWITEMSTRUCT *drawItem)
{
    ROWCOLOR	rowcol;
    HDC	mDC;
    RECT	rect;
    RECT	rect2;
    COLUMN *colPtr = (COLUMN*)(grid + 1);
    DWORD	val = 0L;
    BYTE	buffer[MAX_CELL_SIZE];
    SYSTEMTIME	stime;
    FILETIME	ftime;
    GRIDNOTIFY	gn;
    DRAWITEMSTRUCT	dis;

    if (drawItem->hwndItem == grid->hlst)
    {
        if (drawItem->itemID != (DWORD)LB_ERR)
        {
            HBRUSH hbrCellBack;

            GridGetRowColor(grid,(DWORD)drawItem->itemData, &rowcol);
            drawItem->rcItem.right = grid->ccx + 1;
            CopyRect(&rect2, &drawItem->rcItem);
            mDC = CreateCompatibleDC(drawItem->hDC);

            HFONT fnt = (HFONT)SelectObject(mDC,grid->hfont);

            rect2.right -= rect2.left;
            rect2.left = 0;
            rect2.bottom -= rect2.top;
            rect2.top = 0;

            HBITMAP bmp = (HBITMAP)SelectObject(mDC,CreateCompatibleBitmap(drawItem->hDC,rect2.right,rect2.bottom));
            HPEN pen = (HPEN)SelectObject(mDC,grid->hpengrd);

            DWORD row = drawItem->itemID + 1 - grid->rows;
            if ((grid->style & STYLE_GRIDFRAME) == 0)
            {
                row--;
            }

            if (colPtr->ctype != TYPE_SELTEXT)
            {
                if ((grid->style & STYLE_HGRIDLINES) != 0 || !row)
                {
                    rect2.bottom--;
                    MoveToEx(mDC,rect2.left,rect2.bottom,NULL);
                    LineTo(mDC,rect2.right,rect2.bottom);
                }
            }

            SetBkMode(mDC,TRANSPARENT);
            int selStyle;
            if ( grid->style & STYLE_NOSEL)
            {
                selStyle = 0;
            }
            else
            {
                selStyle = ODS_SELECTED;
            }
            FillRect(mDC,&rect2,grid->hbrback);

            if ((drawItem->itemState & selStyle) == 0)
            {
                COLORREF color = rowcol.textcolor;
                if (color == (COLORREF)-1)
                {
                    color = grid->coltext;
                }
                SetTextColor(mDC,color);
                color = rowcol.backcolor;
                if (color == (COLORREF)-1)
                {
                    hbrCellBack = grid->hbrcellback;
                }
                else
                {
                    HBRUSH brush = CreateSolidBrush(color);
                    hbrCellBack = brush;
                    FillRect(mDC, &rect2,brush);
                    DeleteObject(brush);
                }
            }
            else
            {
                SetTextColor(mDC,grid->coltexthilite);
                hbrCellBack = grid->hbrcellhilite;
                FillRect(mDC, &rect2, grid->hbrcellhilite);
            }
            DWORD col = 0;
            while (col < grid->cols)
            {
                if (colPtr->colwt)
                {
                    rect2.left = colPtr->colxp;
                    rect2.right = rect2.left + colPtr->colwt;
                    buffer[0] = 0;
                    if (colPtr->ctype == TYPE_SELTEXT)
                    {
                        GridGetCellData(grid,(DWORD)drawItem->itemData,col, buffer, sizeof(buffer));
                        if ( buffer[0] == '-' )
                        {
                            FillRect(mDC,&rect2,hbrCellBack);
                            DrawItemText(mDC, (const char *)&buffer[1], rect2, colPtr->calign);
                            rect2.right -= colPtr->colwt;
                            DrawItemLine(grid, mDC, col, rect2);
                            rect2.right += colPtr->colwt;
                            DrawItemLine(grid, mDC, col, rect2);
                            if ((grid->style & STYLE_HGRIDLINES) != 0 || !row)
                            {
                                MoveToEx(mDC,rect2.left,rect2.bottom - 1,NULL);
                                LineTo(mDC,rect2.right,rect2.bottom - 1);
                            }
                        }
                        else if ( buffer[0] == '+' )
                        {
                            COLORREF oldTextColor = GetTextColor(mDC);

                            SetTextColor(mDC,grid->coltexthilite);
                            FillRect(mDC, &rect2, grid->hbrcellhilite);

                            DrawItemText(mDC, (const char *)&buffer[1], rect2, colPtr->calign);
                            SetTextColor(mDC,oldTextColor);

                            rect2.right -= colPtr->colwt;
                            DrawItemLine(grid, mDC, col, rect2);
                            rect2.right += colPtr->colwt;
                            DrawItemLine(grid, mDC, col, rect2);
                            if ((grid->style & STYLE_HGRIDLINES) != 0 || !row)
                            {
                                MoveToEx(mDC,rect2.left,rect2.bottom - 1,NULL);
                                LineTo(mDC,rect2.right,rect2.bottom - 1);
                            }
                        }
                    }
                    else if (colPtr->ctype == TYPE_EDITTEXT)
                    {
                        FillRect(mDC,&rect2,hbrCellBack);
                        GridGetCellData(grid,(DWORD)drawItem->itemData,col, buffer, sizeof(buffer));
                        DrawItemText(mDC, (const char *)buffer, rect2, colPtr->calign);
                        DrawItemLine(grid, mDC, col, rect2);
                    }
                    else if (colPtr->ctype == TYPE_EDITint32_t)
                    {
                        FillRect(mDC,&rect2,hbrCellBack);
                        GridGetCellData(grid,(DWORD)drawItem->itemData,col, &val, sizeof(val));
                        BinToDec(val,(char*)buffer, sizeof(buffer));

                        Format(grid, colPtr->lpszformat, (char*)buffer, sizeof(buffer));

                        DrawItemText(mDC, (const char *)buffer, rect2, colPtr->calign);
                        DrawItemLine(grid, mDC, col, rect2);
                    }
                    else if (colPtr->ctype == TYPE_CHECKBOX)
                    {
                        FillRect(mDC,&rect2,hbrCellBack);
                        GridGetCellData(grid,(DWORD)drawItem->itemData,col, &val, sizeof(val));
                        CopyRect(&rect, &rect2);

                        int center = (rect.bottom - rect.top - 13) >> 1;

                        rect.top += center;
                        rect.bottom = rect.top + 13;

                        if (colPtr->calign == GA_ALIGN_LEFT)
                        {
                            center++;
                            rect.left += center;
                            rect.right = rect.left + 13;
                        }
                        else if (colPtr->calign == GA_ALIGN_CENTER)
                        {
                        }
                        else if (colPtr->calign == GA_ALIGN_RIGHT)
                        {
                            rect.right -= center;
                            rect.left = rect.right - center - 13;
                        }
                        DrawFrameControl(mDC, &rect,DFC_BUTTON,DFCS_BUTTONCHECK | DFCS_FLAT | ((val) ? DFCS_CHECKED : 0));
                        DrawItemLine(grid, mDC, col, rect2);
                    }
                    else if (colPtr->ctype == TYPE_COMBOBOX)
                    {
                        FillRect(mDC,&rect2,hbrCellBack);
                        GridGetCellData(grid,(DWORD)drawItem->itemData,col, &val, sizeof(val));
                        DrawItemLine(grid, mDC, col, rect2);

                        if (col == (DWORD)grid->col)
                        {
                            CopyRect(&rect, &rect2);
                            rect.left = rect.right - 17;
//								mov		eax,rect.top
//								add		eax,17
//								mov		rect.bottom,eax
                            if ((drawItem->itemState & ODS_SELECTED) != 0)
                            {
                                rect2.right -= 17;
                                DrawFrameControl(mDC, &rect,DFC_SCROLL,DFCS_SCROLLDOWN | ((grid->fonbtn && grid->fsame) ? DFCS_PUSHED : 0));
                            }
                        }
                        buffer[0] = 0;
                        int item = 0;
                        for(;;)
                        {
                            int retVal = (int)SendMessageA(colPtr->edthwnd,LB_GETITEMDATA,item,0);

                            if ((DWORD)retVal == val || retVal == LB_ERR)
                                break;
                            item++;
                        }
                        if (item != LB_ERR)
                        {
                            SendMessageA(colPtr->edthwnd,LB_GETTEXT,item, (LPARAM)buffer);
                            if (colPtr->himl)
                            {
                                CopyRect(&rect, &rect2);
                                rect.left += 2;
                                rect.right = rect.left + 16;
                                HRGN rgn = CreateRectRgn(rect.left,rect.top,rect.right,rect.bottom);
                                SelectClipRgn(mDC,rgn);
                                DeleteObject(rgn);

                                ImageList_GetIconSize((_IMAGELIST*)colPtr->himl,(int*)&rect.right,(int*)&rect.bottom);
                                rect2.left += 19;

                                rect.top += (rect2.bottom - rect2.top - rect.bottom) >> 1;

                                ImageList_Draw((_IMAGELIST*)colPtr->himl,val,mDC,rect.left,rect.top,ILD_NORMAL);
                                SelectClipRgn(mDC,NULL);
                            }
                            DrawItemText(mDC, (const char *)buffer, rect2, colPtr->calign);
                        }
                    }
                    else if (colPtr->ctype == TYPE_HOTKEY)
                    {
                        FillRect(mDC,&rect2,hbrCellBack);
                        GridGetCellData(grid,(DWORD)drawItem->itemData,col, &val, sizeof(val));
                        if ((val & (HOTKEYF_CONTROL << 8)) != 0)
                        {
                            strcat_s((char *)buffer, sizeof(buffer), szCtrl);
                        }
                        if ((val & (HOTKEYF_SHIFT << 8)) != 0)
                        {
                            strcat_s((char*)buffer, sizeof(buffer), szShift);
                        }
                        if ((val & (HOTKEYF_ALT << 8)) != 0)
                        {
                            strcat_s((char*)buffer, sizeof(buffer), szAlt);
                        }

                        if ((val & 0xff) >= 'A' && (val & 0xff) <= 'Z')
                        {
                            char buf[2] = {(char)(val & 0xff), 0};
                            strcpy_s((char *)&buffer[strlen((const char *)buffer)], sizeof(buffer), buf);
                        }
                        else if ((val & 0xff) >= VK_F1 && (val & 0xff) <= VK_F12)
                        {
                            strcpy_s((char *)&buffer[strlen((const char *)buffer)], sizeof(buffer), "F");
                            BinToDec((val & 0xff) - VK_F1 + 1,(char*)&buffer[strlen((const char*)buffer)], (int)(sizeof(buffer) - strlen((const char*)buffer)));
                        }
                        DrawItemText(mDC, (const char *)buffer, rect2, colPtr->calign);
                        DrawItemLine(grid, mDC, col, rect2);
                    }
                    else if (colPtr->ctype == TYPE_BUTTON || colPtr->ctype == TYPE_EDITBUTTON)
                    {
                        FillRect(mDC,&rect2,hbrCellBack);
                        GridGetCellData(grid,(DWORD)drawItem->itemData,col,buffer, sizeof(buffer));
                        DrawItemLine(grid, mDC, col, rect2);
                        if ((drawItem->itemState & ODS_SELECTED) != 0)
                        {
                            if (col == (DWORD)grid->col)
                            {
                                CopyRect(&rect, &rect2);

                                rect2.right -= 17;
                                rect.left = rect.right - 17;
//									mov		rect.top,0
//									mov		rect.bottom,17
                                DrawFrameControl(mDC, &rect,DFC_BUTTON,DFCS_BUTTONPUSH | ((grid->fonbtn && grid->fsame) ? DFCS_PUSHED : 0));
                                COLORREF color = GetTextColor(mDC);
                                SetTextColor(mDC,0);
                                HFONT fnt = (HFONT)SelectObject(mDC,GetStockObject(SYSTEM_FONT));

                                TextOutA(mDC,rect.left + 2,0, "...",3);
                                SelectObject(mDC,fnt);
                                SetTextColor(mDC,color);
                            }
                        }
                        DrawItemText(mDC, (const char *)buffer, rect2, colPtr->calign);
                    }
                    else if (colPtr->ctype == TYPE_IMAGE)
                    {
                        FillRect(mDC,&rect2,hbrCellBack);
                        GridGetCellData(grid,(DWORD)drawItem->itemData,col, &val, sizeof(val));
                        DrawItemLine(grid, mDC, col, rect2);
                        if (colPtr->himl)
                        {
                            CopyRect(&rect,&rect2);
                            HRGN rgn = CreateRectRgn(rect.left,rect.top,rect.right,rect.bottom);
                            SelectClipRgn(mDC,rgn);
                            DeleteObject(rgn);
                            ImageList_GetIconSize((_IMAGELIST*)colPtr->himl, (int*)&rect.right, (int*)&rect.bottom);

                            if (colPtr->calign == GA_ALIGN_LEFT)
                            {
                            }
                            else if (colPtr->calign == GA_ALIGN_CENTER)
                            {
                                rect.left += ((rect2.right - rect2.left - rect.right) >> 1);
                            }
                            else
                            {
                                rect.left = (rect2.right - rect.right);
                            }
                            rect.top += ((rect2.bottom - rect2.top - rect.bottom) >> 1);
                            ImageList_Draw((_IMAGELIST*)colPtr->himl,val,mDC,rect.left,rect.top,ILD_NORMAL);
                            SelectClipRgn(mDC,NULL);
                        }
                    }
                    else if (colPtr->ctype == TYPE_DATE)
                    {
                        __int64 tmpdate;

                        FillRect(mDC,&rect2,hbrCellBack);
                        GridGetCellData(grid,(DWORD)drawItem->itemData,col, &val, sizeof(val));

                        //Days since 01.01.1601
                        tmpdate = val;
                        //Convert to number of 100 nano seconds since 01.01.1601
                        tmpdate *= 24*60*60;
                        tmpdate *= 1000*1000*10;

                        memcpy(&ftime, &tmpdate, sizeof(tmpdate));

                        FileTimeToSystemTime(&ftime, &stime);

                        if (colPtr->lpszformat)
                        {
                            GridGetText(grid,colPtr->lpszformat,(char*)&buffer[MAX_CELL_SIZE-MAX_FORMAT_SIZE], MAX_FORMAT_SIZE);
                            GetDateFormatA(0,0, &stime,(const char*)&buffer[MAX_CELL_SIZE-MAX_FORMAT_SIZE],(char*)buffer,sizeof(buffer));
                        }
                        else
                        {
                            GetDateFormatA(0,0, &stime,NULL,(char*)buffer,sizeof(buffer));
                        }
                        DrawItemText(mDC, (const char *)buffer, rect2, colPtr->calign);
                        DrawItemLine(grid, mDC, col, rect2);
                    }
                    else if (colPtr->ctype == TYPE_TIME)
                    {
                        GridGetCellData(grid,(DWORD)drawItem->itemData,col, &val, sizeof(val));

                        FillRect(mDC,&rect2,hbrCellBack);
                        stime.wYear = 2000;
                        stime.wMonth = 1;
                        stime.wDayOfWeek = 6;
                        stime.wDay = 1;
                        stime.wHour = (WORD)(val / (60*60));
                        stime.wMinute = ((val / 60) % 60);
                        stime.wSecond = (val % 60);
                        stime.wMilliseconds = 0;

                        if (colPtr->lpszformat)
                        {
                            GridGetText(grid,colPtr->lpszformat,(char*)&buffer[MAX_CELL_SIZE-MAX_FORMAT_SIZE], MAX_FORMAT_SIZE);
                            GetTimeFormatA(0,0, &stime,(char*)&buffer[MAX_CELL_SIZE-MAX_FORMAT_SIZE], (char*)buffer,sizeof (buffer));
                        }
                        else
                        {
                            GetTimeFormatA(0,0,&stime,NULL,(char*)buffer,sizeof(buffer));
                        }
                        DrawItemText(mDC, (const char *)buffer, rect2, colPtr->calign);
                        DrawItemLine(grid, mDC, col, rect2);
                    }
                    else if (colPtr->ctype == TYPE_USER)
                    {
                        GridGetCellData(grid,(DWORD)drawItem->itemData,col,buffer, sizeof(buffer));

                        FillRect(mDC,&rect2,hbrCellBack);
                        SetNotify(grid, hWin, drawItem->itemID, col, gn);
                        gn.nmhdr.code = GN_USERCONVERT;
                        gn.lpdata = buffer;
                        SendMessageA(grid->hpar,WM_NOTIFY,gn.nmhdr.idFrom, (LPARAM)&gn);
                        DrawItemLine(grid, mDC, col, rect2);
                        if (!gn.fcancel)
                        {
                            DrawItemText(mDC, (const char *)buffer, rect2, colPtr->calign);
                        }
                        else
                        {
                            dis.CtlID = grid->nid;

                            //Win98 strips off high word fron itemID so col must be stored in CtlType
                            dis.itemID = drawItem->itemID;
                            dis.CtlType = col;
                            dis.itemAction = ODA_DRAWENTIRE;
                            dis.itemState = 0;
                            dis.hwndItem = grid->hgrd;
                            dis.hDC = mDC;
                            CopyRect(&dis.rcItem, &rect2);
                            dis.rcItem.left++;
//								dec		dis.rcItem.right
                            dis.itemData = (ULONG_PTR)buffer;
                            SendMessageA(grid->hpar,WM_DRAWITEM,grid->nid,(LPARAM)&dis);
                        }
                    }
                    if (col == (DWORD)grid->col)
                    {
                        if ((grid->style & STYLE_NOFOCUS) == 0)
                        {
                            val = ODS_FOCUS;
                            if ((grid->style & STYLE_NOSEL) != 0)
                            {
                                val |= ODS_SELECTED;
                            }
                        }
                        if ((drawItem->itemState & val) != 0)
                        {
                            COLORREF color = GetTextColor(mDC);

                            SetTextColor(mDC,0);
                            CopyRect(&rect, &rect2);
                            if (grid->col)
                            {
                                rect.left++;
                            }
                            DrawFocusRect(mDC, &rect);
                            if ((drawItem->itemState & ODS_FOCUS) != 0)
                            {
                                rect.left++;
                                rect.top++;
                                rect.right--;
                                rect.bottom--;
                                DrawFocusRect(mDC, &rect);
                            }
                            SetTextColor(mDC,color);
                        }
                    }
                }
                colPtr++;
                col++;
            }
            BitBlt(drawItem->hDC,drawItem->rcItem.left,drawItem->rcItem.top,(drawItem->rcItem.right - drawItem->rcItem.left),
                    (drawItem->rcItem.bottom - drawItem->rcItem.top + 1),mDC,0,0,SRCCOPY);
            //Restore pen
            SelectObject(mDC,pen);
            //Restore bitmap and delete the old one
            DeleteObject(SelectObject(mDC,bmp));
            //Restore font
            SelectObject(mDC,fnt);
            DeleteDC(mDC);
        }
    }
    else if (drawItem->hwndItem == grid->hhdr)
    {
        int item;

        SetTextColor(drawItem->hDC,GetSysColor(COLOR_WINDOWTEXT));
        SetBkColor(drawItem->hDC,GetSysColor(COLOR_BTNFACE));
        ExtTextOut(drawItem->hDC,0,0,ETO_OPAQUE, &drawItem->rcItem,NULL,0,NULL);

        item = 0;
        int fCol = 0;
        while ((DWORD)item < grid->cols)
        {
            if (colPtr->colwt)
            {
                val = colPtr->colxp;
                if (fCol)
                {
                    val++;
                }
                drawItem->rcItem.left = val;
                val += colPtr->colwt;
                if (!fCol)
                {
                    val++;
                }
                fCol++;
                drawItem->rcItem.right = val;
                if ((colPtr->hdrflag & 1) != 0)
                {
                    val = EDGE_SUNKEN;
                }
                else
                {
                    val = EDGE_RAISED;
                }
                DrawEdge(drawItem->hDC, &drawItem->rcItem,val,BF_RECT);
                drawItem->rcItem.top += 2;
                drawItem->rcItem.left += 3;
                drawItem->rcItem.right -= 3;

                if (colPtr->lpszhdrtext)
                {
                    SendMessageA(hWin,GM_GETHDRTEXT,item,(LPARAM)buffer);

                    if (colPtr->halign == GA_ALIGN_LEFT)
                    {
                        val = DT_LEFT | DT_NOPREFIX;
                    }
                    else if (colPtr->halign == GA_ALIGN_CENTER)
                    {
                        val = DT_CENTER | DT_NOPREFIX;
                    }
                    else
                    {
                        val = DT_RIGHT | DT_NOPREFIX;
                    }
                    if ((colPtr->hdrflag & 1) != 0)
                    {
                        drawItem->rcItem.left++;
                        drawItem->rcItem.top++;
                        drawItem->rcItem.right++;
                        DrawTextA(drawItem->hDC,(char*)buffer,(int)strlen((char*)buffer), &drawItem->rcItem,val);
                        drawItem->rcItem.left--;
                        drawItem->rcItem.top--;
                        drawItem->rcItem.right--;
                    }
                    else
                    {
                        DrawTextA(drawItem->hDC,(char*)buffer,(int)strlen((char*)buffer), &drawItem->rcItem,val);
                    }
                }
                drawItem->rcItem.top -= 2;
            }
            colPtr++;
            item++;
            drawItem->rcItem.left = drawItem->rcItem.right + 3;
        }
        drawItem->rcItem.right = 9999;
        DrawEdge(drawItem->hDC, &drawItem->rcItem, EDGE_RAISED, BF_RECT);
    }
    return 0;
}

static void SetScroll(GRID *grid, HWND hWin)
{
    SCROLLINFO	sinf;
    RECT rect;
    int val;

    GetClientRect(hWin, &rect);
    if (rect.right && rect.bottom)
    {
        val = rect.bottom - grid->hdrht;
        if ( val < 0 )
            val = 0;
        sinf.cbSize = sizeof (sinf);
        sinf.fMask = SIF_ALL;
        sinf.nPage = ((val / grid->rowht) * grid->rowht);
        sinf.nMin = 0;
        val = grid->rows;
        if (val)
        {
            val--;
        }
        val++;
        sinf.nMax = (val * grid->rowht) - 1;
        sinf.nPos = grid->toprow * grid->rowht;
        SetScrollInfo(hWin,SB_VERT, &sinf,TRUE);
        sinf.nPage = rect.right;
        sinf.nMax = grid->ccx;
        sinf.nPos = grid->sbx;
        SetScrollInfo(hWin,SB_HORZ, &sinf,TRUE);
    }
}

static bool ExpandItemMem(GRID *grid, HWND hWin)
{
    DWORD itemDataOffset = (grid->rows + 1) * 4 + grid->rpitemdata;

    if (itemDataOffset > grid->itemmemsize)
    {
        HWND hlst = grid->hlst;
        DWORD itemmemsize = grid->itemmemsize;

        RelMemHere(hWin);
        itemmemsize += MEM_SIZE;
        HANDLE mem = GlobalReAlloc((HANDLE)GetWindowLongPtr(hWin,0),itemmemsize,GMEM_MOVEABLE);
        if (mem)
        {
            SetWindowLongPtr(hlst,0,(LONG_PTR)mem);
            SetWindowLongPtr(hWin,0,(LONG_PTR)mem);
            grid = GetMemHere(hWin);
            grid->itemmemsize = itemmemsize;
        }
        else
            return false;
    }
    return true;
}

static LRESULT __stdcall RAGridProc (HWND hWin, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    GRID *grid;
    RECT	rect;
    RECT	rect1;
    SCROLLINFO	sinf;
    GRIDNOTIFY	gn;
    LRESULT retVal = 0L;
    FILETIME ftime;
    SYSTEMTIME stime;

    switch (uMsg)
    {
    case WM_DRAWITEM:
        grid = GetMemHere(hWin);
        retVal = RAGridDrawItem(grid, hWin, (DRAWITEMSTRUCT*)lParam);
        RelMemHere(hWin);
        return 1;
    case WM_CTLCOLORLISTBOX:
        {
            HBRUSH brush;

            grid = GetMemHere(hWin);
            brush = grid->hbrback;
            RelMemHere(hWin);
            return (LRESULT)brush;
        }
    case WM_SIZE:
        grid = GetMemHere(hWin);
        GetClientRect(hWin, &rect);
        rect.right = 8192;
        rect.left -= grid->sbx;
        MoveWindow(grid->hhdr,rect.left,0,rect.right,grid->hdrht,TRUE);
        MoveWindow(grid->hlst,rect.left,grid->hdrht,rect.right,rect.bottom - grid->hdrht,TRUE);
        SetScroll(grid, hWin);
        RelMemHere(hWin);
        break;
    case WM_DESTROY:
        grid = GetMemHere(hWin);
        DestroyWindow(grid->hsize);
        DestroyWindow(grid->hhdr);
        DestroyWindow(grid->hlst);
        DestroyCursor(grid->hcur);
        if (grid->hbrback != (HBRUSH)(COLOR_WINDOW+1))
        {
            DeleteObject(grid->hbrback);
        }
        DeleteObject(grid->hbrcellback);
        DeleteObject(grid->hbrcellhilite);
        DeleteObject(grid->hpengrd);
        if (grid->hmem)
        {
            GlobalFree(grid->hmem);
        }
        if (grid->hstr)
        {
            GlobalFree(grid->hstr);
        }
        RelMemHere(hWin);
        GlobalFree((HANDLE)GetWindowLongPtr(hWin,0));
        SetWindowLongPtr(hWin,0,0);
        break;
    case WM_CREATE:
        {
            HANDLE mem = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT,MEM_SIZE);

            SetWindowLongPtr(hWin,0,(LONG_PTR)mem);
            grid = GetMemHere(hWin);
            grid->itemmemsize = MEM_SIZE;
            grid->hdrht = 18;
            grid->rowht = 18;
            grid->cols = 0;
            grid->rows = 0;

            grid->hpar = GetParent(hWin);
            grid->hgrd = hWin;
            grid->nid = GetWindowLong(hWin,GWL_ID);
            grid->style = GetWindowLong(hWin,GWL_STYLE);
            grid->hsize = CreateWindowExA(0,szStaticClass,NULL,WS_CHILD | WS_CLIPCHILDREN | WS_CLIPSIBLINGS | SS_BLACKRECT,0,0,0,0,hWin,NULL,hInstance,0);
            grid->hhdr = CreateWindowExA(0,szStaticClass,NULL,WS_VISIBLE | WS_CHILD | WS_CLIPCHILDREN | WS_CLIPSIBLINGS | SS_OWNERDRAW | SS_NOTIFY,0,0,0,0,hWin,NULL,hInstance,0);
            SetWindowLongPtr(grid->hhdr,GWLP_USERDATA,SetWindowLongPtr(grid->hhdr,GWLP_WNDPROC,(LONG_PTR)GridHdrProc));
            grid->hlst = CreateWindowExA(0,szRAListClass,NULL,WS_VISIBLE | WS_CHILD | WS_CLIPCHILDREN | WS_CLIPSIBLINGS | LBS_NOINTEGRALHEIGHT | LBS_OWNERDRAWFIXED | LBS_NOTIFY,0,0,0,0,hWin,NULL,hInstance,0);

            SetWindowLongPtr(grid->hlst,0,(LONG_PTR)mem);

            grid->hcur = LoadCursor(hInstance,MAKEINTRESOURCE(IDC_VSIZE));
            grid->colback = GetSysColor(COLOR_WINDOW);
            grid->hbrback = (HBRUSH)(COLOR_WINDOW+1);
            grid->colgrid = 0x0C0C0C0;
            grid->hpengrd = CreatePen(PS_SOLID,1,0x0C0C0C0);
            grid->coltext = GetSysColor(COLOR_WINDOWTEXT);
            grid->colcellback = grid->colback; // Cell background color
            grid->coltexthilite = GetSysColor(COLOR_HIGHLIGHTTEXT); // Text color for highlight
            grid->colcellbackhilite = GetSysColor(COLOR_HIGHLIGHT); // Cell background color for hilight
            grid->hbrcellhilite = CreateSolidBrush(grid->colcellbackhilite);
            grid->hbrcellback = CreateSolidBrush(grid->colcellback);

            grid->toprow = 0;
            grid->rpitemdata = sizeof (GRID);
            if (((CREATESTRUCT*)lParam)->lpCreateParams)
            {
                if (((GRID_CREATE_STRUCT*)((CREATESTRUCT*)lParam)->lpCreateParams)->size == 12)
                {
                    SendMessageA(hWin,GM_SETGRIDCOLOR,((GRID_CREATE_STRUCT*)((CREATESTRUCT*)lParam)->lpCreateParams)->gridColor,0);
                    SendMessageA(hWin,GM_SETBACKCOLOR,((GRID_CREATE_STRUCT*)((CREATESTRUCT*)lParam)->lpCreateParams)->backColor,0);
                    SendMessageA(hWin,GM_SETTEXTCOLOR,((GRID_CREATE_STRUCT*)((CREATESTRUCT*)lParam)->lpCreateParams)->textColor,0);
                }
            }
            RelMemHere(hWin);
            break;
        }
    case WM_SETFONT:
        grid = GetMemHere(hWin);
        grid->hfont = (HFONT)wParam;
        SendMessageA(grid->hhdr,WM_SETFONT,(WPARAM)grid->hfont,FALSE);
        SendMessageA(grid->hlst,WM_SETFONT,(WPARAM)grid->hfont,FALSE);
        RelMemHere(hWin);
        break;
    case WM_SETFOCUS:
        grid = GetMemHere(hWin);
        SetFocus(grid->hlst);
        RelMemHere(hWin);
        break;
    case WM_MOUSEWHEEL:
        if ((int)wParam < 0)
        {
            SendMessageA(hWin,WM_VSCROLL,SB_LINEDOWN,0);
            SendMessageA(hWin,WM_VSCROLL,SB_LINEDOWN,0);
            SendMessageA(hWin,WM_VSCROLL,SB_LINEDOWN,0);
        }
        else
        {
            SendMessageA(hWin,WM_VSCROLL,SB_LINEUP,0);
            SendMessageA(hWin,WM_VSCROLL,SB_LINEUP,0);
            SendMessageA(hWin,WM_VSCROLL,SB_LINEUP,0);
        }
        return 0;
    case WM_VSCROLL:
        {
            int curPos;
            int newPos;

            grid = GetMemHere(hWin);
            sinf.cbSize = sizeof (sinf);
            sinf.fMask = SIF_ALL;
            GetScrollInfo(hWin,SB_VERT, &sinf);

            curPos = grid->toprow * grid->rowht; // EAX   ECX is rowht
            newPos = curPos;
            switch (LOWORD(wParam))
            {
            case SB_THUMBTRACK:
            case SB_THUMBPOSITION:
                newPos = sinf.nTrackPos;
                break;
            case SB_LINEDOWN:
                newPos = curPos + grid->rowht;
                if (newPos > (int)(sinf.nMax - sinf.nPage + 1))
                {
                    newPos = sinf.nMax - sinf.nPage + 1;
                }
                break;
            case SB_LINEUP:
                newPos = curPos - grid->rowht;
                if ( newPos < 0 )
                {
                    newPos = 0;
                }
                break;
            case SB_PAGEDOWN:
                newPos = curPos + sinf.nPage;

                if (newPos > (int)(sinf.nMax - sinf.nPage + 1))
                {
                    newPos = sinf.nMax - sinf.nPage + 1;
                }
                break;
            case SB_PAGEUP:
                newPos = curPos - sinf.nPage;
                if ( newPos < 0 )
                {
                    newPos = 0;
                }
                break;
            case SB_BOTTOM:
                newPos = sinf.nMax;
                break;
            case SB_TOP:
                newPos = 0;
                break;
            }
            if (newPos != sinf.nPos)
            {
                sinf.nPos = newPos;
                grid->toprow = newPos / grid->rowht;
                SetScroll(grid, hWin);
                InvalidateRect(grid->hlst,NULL,TRUE);
            }
            RelMemHere(hWin);
            return 0;
        }
    case WM_HSCROLL:
        {
            int newPos;

            grid = GetMemHere(hWin);
            sinf.cbSize = sizeof (sinf);
            sinf.fMask = SIF_ALL;
            GetScrollInfo(hWin,SB_HORZ, &sinf);
            newPos = grid->sbx;
            switch (LOWORD(wParam))
            {
            case SB_THUMBTRACK:
            case SB_THUMBPOSITION:
                newPos = sinf.nTrackPos;
                break;
            case SB_LINEDOWN:
                newPos += 5;
                if (newPos > (int)(sinf.nMax - sinf.nPage + 1))
                {
                    newPos = sinf.nMax - sinf.nPage + 1;
                }
                break;
            case SB_LINEUP:
                newPos -= 5;
                if ( newPos < 0 )
                {
                    newPos = 0;
                }
                break;
            case SB_PAGEDOWN:
                newPos += sinf.nPage;
                if (newPos > (int)(sinf.nMax - sinf.nPage + 1))
                {
                    newPos = sinf.nMax - sinf.nPage + 1;
                }
                break;
            case SB_PAGEUP:
                newPos -= sinf.nPage;
                if ( newPos < 0 )
                {
                    newPos = 0;
                }
                break;
            case SB_BOTTOM:
                newPos = sinf.nMax;
                break;
            case SB_TOP:
                newPos = 0;
                break;
            }
            sinf.nPos = newPos;
            int diff = grid->sbx - newPos;
            grid->sbx = newPos;
            ScrollWindow(hWin,diff,0,NULL,NULL);
            SetScroll(grid, hWin);
            RelMemHere(hWin);
            return 0;
        }
    case GM_ADDCOL:
        grid = GetMemHere(hWin);
        if (!grid->hmem)
        {
            COLUMN *inColumn = (COLUMN*)lParam;
            COLUMN *outColumn = (COLUMN*)(((unsigned char *)grid) + grid->rpitemdata);

            *outColumn = *inColumn;
            outColumn->himl = 0;
            outColumn->colxp = 0;
            outColumn->edthwnd = 0;

            switch (outColumn->ctype)
            {
            case TYPE_SELTEXT:
                outColumn->edthwnd = 0;
                break;
            case TYPE_EDITTEXT:
                outColumn->edthwnd = CreateWindowExA(0, szEditClass,NULL,WS_CHILD | WS_BORDER | WS_CLIPCHILDREN | WS_CLIPSIBLINGS | ES_AUTOHSCROLL,0,0,0,0,grid->hlst,NULL,hInstance,0);
                SetWindowLongPtr(outColumn->edthwnd,GWLP_USERDATA,SetWindowLongPtr(outColumn->edthwnd,GWLP_WNDPROC, (LONG_PTR)EdtTextProc));
                if (!outColumn->ctextmax || outColumn->ctextmax > 511)
                {
                    outColumn->ctextmax = 511;
                }
                SendMessageA(outColumn->edthwnd,EM_LIMITTEXT,outColumn->ctextmax,0);
                break;
            case TYPE_EDITint32_t:
                outColumn->edthwnd = CreateWindowExA(0, szEditClass,NULL,WS_CHILD | WS_BORDER | WS_CLIPCHILDREN | WS_CLIPSIBLINGS | ES_AUTOHSCROLL | ES_RIGHT,0,0,0,0,grid->hlst,NULL,hInstance,0);
                SetWindowLongPtr(outColumn->edthwnd,GWLP_USERDATA,SetWindowLongPtr(outColumn->edthwnd,GWLP_WNDPROC, (LONG_PTR)Edtint32_tProc));
                if (!outColumn->ctextmax || outColumn->ctextmax > 11)
                {
                    outColumn->ctextmax = 11;
                }
                SendMessageA(outColumn->edthwnd,EM_LIMITTEXT,outColumn->ctextmax,0);
                break;
            case TYPE_COMBOBOX:
                outColumn->himl = inColumn->himl;
                outColumn->edthwnd = CreateWindowExA(0, szListBoxClass,NULL,WS_CHILD | WS_BORDER | WS_VSCROLL | WS_CLIPCHILDREN | WS_CLIPSIBLINGS | LBS_HASSTRINGS | LBS_SORT | LBS_OWNERDRAWFIXED,0,0,0,0,grid->hlst,NULL,hInstance,0);
                lplstproc = (WNDPROC)SetWindowLongPtr(outColumn->edthwnd,GWLP_WNDPROC, (LONG_PTR)LstProc);
                SetWindowLongPtr(outColumn->edthwnd,GWLP_USERDATA,(LONG_PTR)grid->hgrd);
                SetParent(outColumn->edthwnd,GetDesktopWindow());
                SetWindowLong(outColumn->edthwnd,GWL_STYLE,WS_POPUP | WS_BORDER | WS_VSCROLL | WS_CLIPCHILDREN | WS_CLIPSIBLINGS | LBS_HASSTRINGS | LBS_SORT | LBS_OWNERDRAWFIXED);
                break;
            case TYPE_HOTKEY:
                outColumn->edthwnd = CreateWindowExA(0, szHotKeyClass,NULL,WS_CHILD | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,0,0,0,0,grid->hlst,NULL,hInstance,0);
                SetWindowLongPtr(outColumn->edthwnd,GWLP_USERDATA,SetWindowLongPtr(outColumn->edthwnd,GWLP_WNDPROC, (LONG_PTR)HotProc));
                break;
            case TYPE_BUTTON:
                outColumn->edthwnd = 0;
                break;
            case TYPE_EDITBUTTON:
                outColumn->edthwnd = CreateWindowExA(0, szEditClass,NULL,WS_CHILD | WS_BORDER | WS_CLIPCHILDREN | WS_CLIPSIBLINGS | ES_AUTOHSCROLL,0,0,0,0,grid->hlst,NULL,hInstance,0);
                SetWindowLongPtr(outColumn->edthwnd,GWLP_USERDATA,SetWindowLongPtr(outColumn->edthwnd,GWLP_WNDPROC, (LONG_PTR)EdtTextProc));
                if (!outColumn->ctextmax || outColumn->ctextmax > 511)
                {
                    outColumn->ctextmax = 511;
                }
                SendMessageA(outColumn->edthwnd,EM_LIMITTEXT,outColumn->ctextmax,0);
                break;
            case TYPE_IMAGE:
                outColumn->himl = inColumn->himl;
                break;
            case TYPE_DATE:
                outColumn->edthwnd = CreateWindowExA(0, szDateTimeClass,NULL,WS_CHILD | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,0,0,0,0,grid->hlst,NULL,hInstance,0);
                SetWindowLongPtr(outColumn->edthwnd,GWLP_USERDATA,SetWindowLongPtr(outColumn->edthwnd,GWLP_WNDPROC, (LONG_PTR)DateTimeProc));
                break;
            case TYPE_TIME:
                outColumn->edthwnd = CreateWindowExA(0, szDateTimeClass,NULL,WS_CHILD | WS_CLIPCHILDREN | WS_CLIPSIBLINGS | DTS_TIMEFORMAT | DTS_UPDOWN,0,0,0,0,grid->hlst,NULL,hInstance,0);
                SetWindowLongPtr(outColumn->edthwnd,GWLP_USERDATA,SetWindowLongPtr(outColumn->edthwnd,GWLP_WNDPROC, (LONG_PTR)DateTimeProc));
                break;
            case TYPE_USER:
                outColumn->edthwnd = inColumn->edthwnd;
                if (outColumn->edthwnd)
                {
                    SetParent(outColumn->edthwnd,grid->hlst);
                }
                break;
            }
            if (outColumn->edthwnd)
            {
                SendMessageA(outColumn->edthwnd,WM_SETFONT,SendMessageA(grid->hlst,WM_GETFONT,0,0),FALSE);
            }
            outColumn->colxp = grid->ccx;
            grid->ccx += outColumn->colwt;
            int col = grid->cols;
            grid->cols++;
            grid->rpitemdata += sizeof (COLUMN);
            if (outColumn->lpszhdrtext)
            {
                SendMessageA(hWin,GM_SETHDRTEXT,col,(LPARAM)outColumn->lpszhdrtext);
            }
            if (outColumn->lpszformat)
            {
                SendMessageA(hWin,GM_SETCOLFORMAT,col,(LPARAM)outColumn->lpszformat);
            }
            SendMessageA(hWin,WM_SIZE,0,0);
            RelMemHere(hWin);
            return col;
        }
        else
        {
            // ** Error, data in grid
            RelMemHere(hWin);
            return LB_ERR;
        }
        break;
    case GM_ADDROW:
        grid = GetMemHere(hWin);
        if (grid->rows<65536)
        {
            if (ExpandItemMem(grid, hWin))
            {
                int row = GridAddRowData(grid,(void*)lParam);
                InsertItem(grid, grid->rows,row);
                SetScroll(grid, hWin);
                retVal = row;
            }
            else
            {
                retVal = LB_ERR;
            }
        }
        else
        {
            retVal = LB_ERR;
        }
        RelMemHere(hWin);
        return retVal;
    case GM_INSROW:
        grid = GetMemHere(hWin);
        if (grid->rows < 65536)
        {
            if (ExpandItemMem(grid, hWin))
            {
                retVal = GridAddRowData(grid,(void*)lParam);
                InsertItem(grid, (DWORD)wParam, (DWORD)retVal);
            }
            else
            {
                retVal = LB_ERR;
            }
        }
        else
        {
            retVal = LB_ERR;
        }
        RelMemHere(hWin);
        return retVal;
    case GM_DELROW:
        grid = GetMemHere(hWin);
        if (grid->rows)
        {
            DeleteItem(grid, (DWORD)wParam);
        }
        RelMemHere(hWin);
        return 0;
    case GM_MOVEROW:
        grid = GetMemHere(hWin);
        if (wParam < (WPARAM)grid->rows && lParam < (LPARAM)grid->rows)
        {
            int item = GetItem(grid, (DWORD)wParam);
            DeleteItem(grid,(DWORD)wParam);
            InsertItem(grid, (DWORD)lParam, item);
        }
        RelMemHere(hWin);
        return 0;
    case GM_COMBOADDSTRING:
        grid = GetMemHere(hWin);
        if (wParam < grid->cols)
        {
            COLUMN *colPtr = &(((COLUMN*)(grid + 1))[wParam]);
            if (colPtr->ctype==TYPE_COMBOBOX)
            {
                int32_t count = (int32_t)SendMessageA(colPtr->edthwnd,LB_GETCOUNT,0,0);
                SendMessageA(colPtr->edthwnd,LB_SETITEMDATA,SendMessageA(colPtr->edthwnd,LB_ADDSTRING,0,lParam),count);
            }
        }
        RelMemHere(hWin);
        return 0;
    case GM_COMBOCLEAR:
        grid = GetMemHere(hWin);
        if (wParam < grid->cols)
        {
            COLUMN *colPtr = &(((COLUMN*)(grid + 1))[wParam]);

            if (colPtr->ctype == TYPE_COMBOBOX)
            {
                SendMessageA(colPtr->edthwnd,LB_RESETCONTENT,0,0);
                InvalidateRect(grid->hlst,NULL,TRUE);
            }
        }
        RelMemHere(hWin);
        return 0;
    case GM_GETCURSEL:
        {
            DWORD val;

            grid = GetMemHere(hWin);
            val = (grid->row << 16) | grid->col;
            RelMemHere(hWin);
            return val;
        }
    case GM_SETCURSEL:
        grid = GetMemHere(hWin);
        if (wParam < (WPARAM)grid->cols && lParam < (LPARAM)grid->rows)
        {
            SetNotify(grid, hWin, (int)lParam, (int)wParam, gn);
            gn.nmhdr.code = GN_BEFORESELCHANGE;
            gn.lpdata = 0;
            SendMessageA(grid->hpar,WM_NOTIFY,gn.nmhdr.idFrom, (LPARAM)&gn);
            if (!gn.fcancel)
            {
                if ((DWORD)gn.row < grid->rows && (DWORD)gn.col < grid->cols)
                {
                    GetItemRect(grid, grid->row, &rect);
                    InvalidateRect(grid->hlst, &rect,TRUE);
                    grid->col = gn.col;
                    grid->row = gn.row;
                    GetItemRect(grid, grid->row, &rect);
                    InvalidateRect(grid->hlst, &rect,TRUE);
                    SendMessageA(hWin,GM_SCROLLCELL,0,0);
                }
                SetNotify(grid, hWin, grid->row, grid->col, gn);
                gn.nmhdr.code = GN_AFTERSELCHANGE;
                gn.lpdata = 0;
                SendMessageA(grid->hpar,WM_NOTIFY,gn.nmhdr.idFrom, (LPARAM)&gn);
                retVal = 1;
            }
            else
            {
                retVal = 0;
            }
        }
        else
        {
            retVal = 0;
        }
        RelMemHere(hWin);
        return retVal;
    case GM_GETCURCOL:
        grid = GetMemHere(hWin);
        retVal = grid->col;
        RelMemHere(hWin);
        return retVal;
    case GM_SETCURCOL:
        grid = GetMemHere(hWin);
        retVal = SendMessageA(hWin,GM_SETCURSEL,wParam,grid->row);
        RelMemHere(hWin);
        return retVal;
    case GM_GETCURROW:
        grid = GetMemHere(hWin);
        retVal = grid->row;
        RelMemHere(hWin);
        return retVal;
    case GM_SETCURROW:
        grid = GetMemHere(hWin);
        retVal = SendMessageA(hWin,GM_SETCURSEL,grid->col,wParam);
        RelMemHere(hWin);
        return retVal;
    case GM_GETCOLCOUNT:
        grid = GetMemHere(hWin);
        retVal = grid->cols;
        RelMemHere(hWin);
        return retVal;
    case GM_GETROWCOUNT:
        grid = GetMemHere(hWin);
        retVal = grid->rows;
        RelMemHere(hWin);
        return retVal;
    case GM_GETCELLDATA:
        {
            int item;

            grid = GetMemHere(hWin);
            item = GetItem(grid,HIWORD(wParam));
            retVal = GridGetCellData(grid,item,LOWORD(wParam),(void*)lParam, MAX_CELL_SIZE);
            RelMemHere(hWin);
            return retVal;
        }
    case GM_SETCELLDATA:
        grid = GetMemHere(hWin);
        SetNotify(grid, hWin, grid->row, grid->col, gn);
        gn.nmhdr.code = GN_BEFOREUPDATE;
        gn.lpdata = (void*)lParam;
        SendMessageA(grid->hpar,WM_NOTIFY,gn.nmhdr.idFrom, (LPARAM)&gn);
        if (!gn.fcancel)
        {
            GridSetCellData(grid,GetItem(grid, HIWORD(wParam)),LOWORD(wParam),(void*)gn.lpdata);
            GetItemRect(grid, HIWORD(wParam), &rect);
            InvalidateRect(grid->hlst, &rect,TRUE);
            gn.nmhdr.code = GN_AFTERUPDATE;
            SendMessageA(grid->hpar,WM_NOTIFY,gn.nmhdr.idFrom, (LPARAM)&gn);
        }
        RelMemHere(hWin);
        return 0;
    case GM_GETCELLRECT:
        grid = GetMemHere(hWin);
        rect.left = rect.top = rect.right = rect.bottom = 0;
        if (LOWORD(wParam) < grid->cols)
        {
            COLUMN *colPtr = &(((COLUMN*)(grid + 1))[LOWORD(wParam)]);

            if (HIWORD(wParam) < grid->rows)
            {
                GetItemRect(grid, HIWORD(wParam), &rect);
                rect.left = colPtr->colxp - grid->sbx;
                rect.right = rect.left + colPtr->colwt;
            }
        }
        CopyRect((LPRECT)lParam, &rect);
        RelMemHere(hWin);
        return 0;
    case GM_SCROLLCELL:
        grid = GetMemHere(hWin);
        GetClientRect(grid->hlst, &rect1);
        if (rect1.right && rect1.bottom)
        {
            SendMessageA(hWin,GM_GETCELLRECT,(grid->row << 16) | grid->col, (LPARAM)&rect);
            if (rect.top < 0)
            {
                grid->toprow = grid->row;
                InvalidateRect(grid->hlst,NULL,TRUE);
            }
            else
            {
                if (rect.bottom > rect1.bottom)
                {
                    grid->toprow += (rect.bottom - rect1.bottom) / grid->rowht + 1;
                    InvalidateRect(grid->hlst,NULL,TRUE);
                }
            }
            if (rect.left < 0)
            {
                ScrollWindow(hWin,-rect.left,0,NULL,NULL);
            }
            else
            {
                GetClientRect(hWin, &rect1);
                if (rect.right > rect1.right)
                {
                    int tmp = rect.right - rect1.right;
                    int tmp2 = grid->sbx + tmp;

                    if (rect.left < rect.right - rect1.right)
                    {
                        tmp = rect.left;
                        tmp2 = tmp + grid->sbx;
                    }
                    grid->sbx = tmp2;
                    tmp = -tmp;
                    ScrollWindow(hWin,tmp,0,NULL,NULL);
                }
            }
            SetScroll(grid, hWin);
        }
        else
        {
            grid->toprow = 0;
            InvalidateRect(grid->hlst,NULL,TRUE);
        }
        RelMemHere(hWin);
        return 0;
    case GM_GETBACKCOLOR:
        grid = GetMemHere(hWin);
        retVal = grid->colback;
        RelMemHere(hWin);
        return retVal;
    case GM_SETBACKCOLOR:
        grid = GetMemHere(hWin);
        if (grid->hbrback != (HBRUSH)(COLOR_WINDOW+1))
        {
            DeleteObject(grid->hbrback);
        }
        grid->colback = (int32_t)wParam;
        grid->hbrback = CreateSolidBrush(grid->colback);
        InvalidateRect(grid->hlst,NULL,TRUE);
        RelMemHere(hWin);
        return 0;
    case GM_GETGRIDCOLOR:
        grid = GetMemHere(hWin);
        retVal = grid->colgrid;
        RelMemHere(hWin);
        return retVal;
    case GM_SETGRIDCOLOR:
        grid = GetMemHere(hWin);
        DeleteObject(grid->hpengrd);
        grid->colgrid = (int32_t)wParam;
        grid->hpengrd = CreatePen(PS_SOLID,1,grid->colgrid);
        InvalidateRect(grid->hlst,NULL,TRUE);
        RelMemHere(hWin);
        return 0;
    case GM_GETTEXTCOLOR:
        grid = GetMemHere(hWin);
        retVal = grid->coltext;
        RelMemHere(hWin);
        return retVal;
    case GM_SETTEXTCOLOR:
        grid = GetMemHere(hWin);
        grid->coltext = (int32_t)wParam;
        InvalidateRect(grid->hlst,NULL,TRUE);
        RelMemHere(hWin);
        return 0;
    case GM_ENTEREDIT:
        grid = GetMemHere(hWin);
        if (grid->rows)
        {
            BYTE	buffer[MAX_CELL_SIZE];

            fCancelEdit = FALSE;
            SendMessageA(hWin,GM_SETCURSEL,wParam,lParam);
            SendMessageA(hWin,GM_GETCELLDATA,(grid->row << 16) | grid->col,(LPARAM)buffer);
            SendMessageA(hWin,GM_GETCELLRECT,(grid->row << 16) | grid->col, (LPARAM)&rect);
            SetNotify(grid, hWin, grid->row, grid->col, gn);

            gn.nmhdr.code = GN_BEFOREEDIT;


            gn.lpdata = buffer;
            COLUMN *colPtr = &(((COLUMN*)(grid + 1))[grid->col]);

            gn.hwnd = colPtr->edthwnd;

            SendMessageA(grid->hpar,WM_NOTIFY,gn.nmhdr.idFrom, (LPARAM)&gn);

            retVal = 0;
            if (!gn.fcancel)
            {
                if (colPtr->edthwnd && (colPtr->ctype != TYPE_EDITBUTTON || !grid->fonbtn))
                {
                    grid->edtrowcol = (grid->row << 16) | grid->col;
                    SetWindowLong(colPtr->edthwnd,GWL_ID,(grid->row << 16) | grid->col);
                    SendMessageA(colPtr->edthwnd,WM_SETFONT,(WPARAM)grid->hfont,FALSE);
                    GetClientRect(grid->hlst, &rect1);
                    rect.top--;
                    int colwt = colPtr->colwt + 1;
                    int rowht = grid->rowht + 1;

                    if (colPtr->ctype == TYPE_COMBOBOX)
                    {
                        rect.left = colPtr->colxp;
                        rect.top += rowht;
                        GetClientRect(GetDesktopWindow(), &rect1);
                        ScreenToClient(grid->hgrd, (POINT*)&rect1.right);
                        int count = (int)SendMessageA(colPtr->edthwnd,LB_GETCOUNT,0,0);
                        int height = (int)SendMessageA(colPtr->edthwnd,LB_GETITEMHEIGHT,0,0);
                        if (count > 10)
                        {
                            count = 10;
                        }
                        else if (!count)
                        {
                            count = 1;
                        }
                        if (height * count + 2 + rect.top + grid->rowht + 1 > rect1.bottom)
                        {
                            rect.top -= height * count + 2 + grid->rowht + 1;
                        }
                    }
                    switch (colPtr->ctype)
                    {
                    case TYPE_EDITTEXT:
                        MoveWindow(colPtr->edthwnd,colPtr->colxp,rect.top,colwt,rowht,TRUE);
                        SendMessageA(colPtr->edthwnd,WM_SETTEXT,0, (LPARAM)buffer);
                        SendMessageA(colPtr->edthwnd,EM_SETSEL,0,-1);
                        break;
                    case TYPE_EDITBUTTON:
                        colwt -= grid->rowht;
                        MoveWindow(colPtr->edthwnd,colPtr->colxp,rect.top,colwt,rowht,TRUE);
                        SendMessageA(colPtr->edthwnd,WM_SETTEXT,0, (LPARAM)buffer);
                        SendMessageA(colPtr->edthwnd,EM_SETSEL,0,-1);
                        break;
                    case TYPE_EDITint32_t:
                        MoveWindow(colPtr->edthwnd,colPtr->colxp,rect.top,colwt,rowht,TRUE);
                        BinToDec(*(DWORD*)buffer, (char*)buffer, sizeof(buffer));
                        SendMessageA(colPtr->edthwnd,WM_SETTEXT,0, (LPARAM)buffer);
                        SendMessageA(colPtr->edthwnd,EM_SETSEL,0,-1);
                        break;
                    case TYPE_COMBOBOX:
                        {
                            rect.left = colPtr->colxp;
                            ClientToScreen(grid->hlst, (POINT*)&rect);
                            MoveWindow(colPtr->edthwnd,rect.left,rect.top,colwt,rowht,TRUE);
                            int item = 0;

                            for(;;)
                            {
                                retVal = SendMessageA(colPtr->edthwnd,LB_GETITEMDATA,item,0);
                                if (retVal == *(int32_t*)buffer || retVal == LB_ERR)
                                    break;
                                item++;
                            }
                            if (retVal != LB_ERR)
                            {
                                retVal = SendMessageA(colPtr->edthwnd,LB_SETCURSEL,item,0);
                            }
                            break;
                        }
                    case TYPE_HOTKEY:
                        MoveWindow(colPtr->edthwnd,colPtr->colxp,rect.top,colwt,rowht,TRUE);
                        SendMessageA(colPtr->edthwnd,HKM_SETHOTKEY,*(DWORD*)buffer,0);
                        break;
                    case TYPE_DATE:
                        {
                            __int64 tmpdate;

                            MoveWindow(colPtr->edthwnd,colPtr->colxp,rect.top,colwt,rowht,TRUE);
                            // Days since 01.01.1601
                            tmpdate = *(DWORD*)buffer;
                            // Convert to number of 100 nano seconds since 01.01.1601
                            tmpdate *= 24*60*60;
                            tmpdate *= 1000*1000*10;
                            memcpy(&ftime, &tmpdate, sizeof(ftime));
                            FileTimeToSystemTime(&ftime, &stime);
                            SendMessageA(colPtr->edthwnd,DTM_SETSYSTEMTIME,0, (LPARAM)&stime);
                            break;
                        }
                    case TYPE_TIME:
                        {
                            DWORD tmptime;

                            MoveWindow(colPtr->edthwnd,colPtr->colxp,rect.top,colwt,rowht,TRUE);
                            tmptime = *(DWORD*)buffer;
                            stime.wYear = 2000;
                            stime.wMonth = 1;
                            stime.wDayOfWeek = 6;
                            stime.wDay = 1;
                            stime.wHour = (WORD)(tmptime / 3600);
                            stime.wMinute = (tmptime / 60) % 60;
                            stime.wSecond = tmptime % 60;
                            stime.wMilliseconds = 0;
                            SendMessageA(colPtr->edthwnd,DTM_SETSYSTEMTIME,0, (LPARAM)&stime);
                            break;
                        }
                    case TYPE_USER:
                        MoveWindow(colPtr->edthwnd,colPtr->colxp,rect.top,colwt,rowht,TRUE);
                        break;
                    }
                    ShowWindow(colPtr->edthwnd,SW_SHOW);
                    SetFocus(colPtr->edthwnd);
                    retVal = (LRESULT)colPtr->edthwnd;
                }
                else
                {
                    switch (colPtr->ctype)
                    {
                    case TYPE_SELTEXT:
                        if ( buffer[0] == '-' )
                        {
                            buffer[0] = '+';
                            SendMessageA(hWin,GM_SETCELLDATA,(grid->row << 16) | grid->col,(LPARAM)buffer);

                            SetNotify(grid, hWin, grid->row, grid->col, gn);
                            gn.nmhdr.code = GN_AFTEREDIT;
                            gn.lpdata = buffer;
                            SendMessageA(grid->hpar,WM_NOTIFY,gn.nmhdr.idFrom, (LPARAM)&gn);
                        }
                        else if ( buffer[0] == '+' )
                        {
                            buffer[0] = '-';
                            SendMessageA(hWin,GM_SETCELLDATA,(grid->row << 16) | grid->col,(LPARAM)buffer);

                            SetNotify(grid, hWin, grid->row, grid->col, gn);
                            gn.nmhdr.code = GN_AFTEREDIT;
                            gn.lpdata = buffer;
                            SendMessageA(grid->hpar,WM_NOTIFY,gn.nmhdr.idFrom, (LPARAM)&gn);
                        }
                        break;
                    case TYPE_CHECKBOX:
                        SetNotify(grid, hWin, grid->row, grid->col, gn);
                        gn.nmhdr.code = GN_CHECKCLICK;
                        gn.lpdata = buffer;
                        SendMessageA(grid->hpar,WM_NOTIFY,gn.nmhdr.idFrom, (LPARAM)&gn);
                        if (!gn.fcancel)
                        {
                            SendMessageA(hWin,GM_ENDEDIT,(grid->row << 16) | grid->col,FALSE);
                            InvalidateRect(grid->hlst, &rect,TRUE);
                        }
                        break;
                    case TYPE_IMAGE:
                        SetNotify(grid, hWin, grid->row, grid->col, gn);
                        gn.nmhdr.code = GN_IMAGECLICK;
                        gn.hwnd = (HWND)colPtr->himl;
                        gn.lpdata = buffer;
                        SendMessageA(grid->hpar,WM_NOTIFY,gn.nmhdr.idFrom, (LPARAM)&gn);
                        break;
                    case TYPE_BUTTON:
                    case TYPE_EDITBUTTON:
                        SetNotify(grid, hWin, grid->row, grid->col, gn);
                        gn.nmhdr.code = GN_BUTTONCLICK;
                        gn.lpdata = buffer;
                        SendMessageA(grid->hpar,WM_NOTIFY,gn.nmhdr.idFrom,(LPARAM)&gn);
                        if (!gn.fcancel)
                        {
                            grid->lpdata = buffer;
                            SendMessageA(hWin,GM_ENDEDIT,(grid->row << 16) | grid->col,FALSE);
                            InvalidateRect(grid->hlst, &rect,TRUE);
                        }
                        break;
                    }
                    retVal = 0;
                }
            }
        }
        grid->hedt = (HWND)retVal;
        RelMemHere(hWin);
        return retVal;
    case GM_ENDEDIT:
        {
            BYTE	buffer[MAX_CELL_SIZE];

            grid = GetMemHere(hWin);
            buffer[0] = 0;

            COLUMN *colPtr = &(((COLUMN*)(grid + 1))[LOWORD(wParam)]);

            if (!lParam)
            {
                if (grid->hedt)
                {
                    switch (colPtr->ctype)
                    {
                    case TYPE_EDITTEXT:
                    case TYPE_EDITBUTTON:
                        SendMessageA(grid->hedt,WM_GETTEXT,sizeof (buffer),(LPARAM) buffer);
                        break;
                    case TYPE_EDITint32_t:
                        SendMessageA(grid->hedt,WM_GETTEXT,sizeof (buffer),(LPARAM) buffer);
                        *(DWORD*)buffer = DecToBin(buffer);
                        break;
                    case TYPE_COMBOBOX:
                        *(DWORD*)buffer = (DWORD)SendMessageA(grid->hedt,LB_GETITEMDATA,SendMessageA(grid->hedt,LB_GETCURSEL,0,0),0);
                        break;
                    case TYPE_HOTKEY:
                        *(DWORD*)buffer = (DWORD)SendMessageA(grid->hedt,HKM_GETHOTKEY,0,0);
                        break;
                    case TYPE_DATE:
                        {
                            __int64 tmpdate;

                            SendMessageA(grid->hedt,DTM_GETSYSTEMTIME,0,(LPARAM) &stime);
                            SystemTimeToFileTime(&stime, &ftime);

                            memcpy(&tmpdate, &ftime, sizeof(tmpdate));

                            // Convert to days since 01.01.1601

                            tmpdate /= 10*1000*1000;
                            *(DWORD*)buffer = (DWORD)tmpdate;
                            break;
                        }
                    case TYPE_TIME:
                        SendMessageA(grid->hedt,DTM_GETSYSTEMTIME,0,(LPARAM) &stime);
                        *(DWORD*)buffer = stime.wHour * 60 * 60 + stime.wMinute * 60 + stime.wSecond;
                        break;
                    }
                }
                else
                {
                    if (colPtr->ctype == TYPE_CHECKBOX)
                    {
                        SendMessageA(hWin,GM_GETCELLDATA,wParam,(LPARAM) buffer);
                        *(DWORD*)buffer = ((*(DWORD*)buffer & 1) ^ 1);
                    }
                    else if (colPtr->ctype == TYPE_BUTTON || colPtr->ctype == TYPE_EDITBUTTON)
                    {
                        TsStrCpy((char*)buffer,sizeof(buffer), (const char *)grid->lpdata);
                    }
                    else if ( colPtr->ctype == TYPE_SELTEXT)
                    {
                        SendMessageA(hWin,GM_GETCELLDATA,wParam,(LPARAM) buffer);
                    }
                }
                SetNotify(grid, hWin, HIWORD(wParam), LOWORD(wParam), gn);
                gn.nmhdr.code = GN_AFTEREDIT;
                gn.lpdata = buffer;
                gn.hwnd = colPtr->edthwnd;
                SendMessageA(grid->hpar,WM_NOTIFY,gn.nmhdr.idFrom,(LPARAM)&gn);
                if (!gn.fcancel)
                {
                    SendMessageA(hWin,GM_SETCELLDATA,wParam,(LPARAM)buffer);
                    if (grid->hedt)
                    {
                        ShowWindow(grid->hedt,SW_HIDE);
                        grid->hedt = NULL;
                    }
                }
            }
            else
            {
                if (grid->hedt)
                {
                    ShowWindow(grid->hedt,SW_HIDE);
                    grid->hedt = NULL;
                }
            }
            RelMemHere(hWin);
            return 0;
        }
    case GM_GETCOLWIDTH:
        grid = GetMemHere(hWin);
        if (wParam < grid->cols)
        {
            COLUMN *colPtr = &(((COLUMN*)(grid + 1))[wParam]);
            retVal = colPtr->colwt;
        }
        else
        {
            retVal = 0;
        }
        RelMemHere(hWin);
        return retVal;
    case GM_SETCOLWIDTH:
        grid = GetMemHere(hWin);
        if (wParam < grid->cols)
        {
            COLUMN *colPtr = &(((COLUMN*)(grid + 1))[wParam]);
            DWORD offset;
            DWORD col = (DWORD)wParam;

            colPtr->colwt = (int32_t)lParam;
            offset = colPtr->colxp;
            while (col < grid->cols)
            {
                colPtr->colxp = offset;
                offset += colPtr->colwt;
                colPtr++;
                col++;
            }
            grid->ccx = offset;
            SendMessageA(hWin,WM_SIZE,0,0);
            InvalidateRect(grid->hhdr,NULL,TRUE);
            InvalidateRect(grid->hlst,NULL,TRUE);
        }
        RelMemHere(hWin);
        return 0;
    case GM_GETHDRHEIGHT:
        grid = GetMemHere(hWin);
        retVal = grid->hdrht;
        RelMemHere(hWin);
        return retVal;
    case GM_SETHDRHEIGHT:
        grid = GetMemHere(hWin);
        grid->hdrht = (int32_t)lParam;
        SendMessageA(hWin,WM_SIZE,0,0);
        InvalidateRect(grid->hhdr,NULL,TRUE);
        RelMemHere(hWin);
        return 0;
    case GM_GETROWHEIGHT:
        grid = GetMemHere(hWin);
        retVal = grid->rowht;
        RelMemHere(hWin);
        return retVal;
    case GM_SETROWHEIGHT:
        grid = GetMemHere(hWin);
        if (lParam)
        {
            grid->rowht = (int32_t)lParam;
            SendMessageA(hWin,WM_SIZE,0,0);
            InvalidateRect(grid->hlst,NULL,TRUE);
        }
        RelMemHere(hWin);
        return 0;
    case GM_RESETCONTENT:
        {
            unsigned char *mem;
            unsigned char *p;
            DWORD col;
            int remainingLen = 1024 * 64;

            grid = GetMemHere(hWin);
            COLUMN *colPtr = (((COLUMN*)(grid + 1)));

            mem = (unsigned char *)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT,1024*64);

            col = 0;
            p = mem;
            while (col < grid->cols)
            {
                if (colPtr[col].lpszhdrtext)
                {
                    GridGetText(grid,(DWORD)colPtr[col].lpszhdrtext,(char*)p, remainingLen);
                    remainingLen -= (int)(strlen((const char *)p) + 1);
                    p = p + strlen((const char *)p) + 1;
                }
                if (colPtr[col].lpszformat)
                {
                    GridGetText(grid,colPtr[col].lpszformat,(char*)p, remainingLen);
                    remainingLen -= (int)(strlen((const char *)p) + 1);
                    p = p + strlen((const char *)p) + 1;
                }
                col++;
            }
            ShowHide(grid->hgrd,FALSE);
            if (grid->hmem)
            {
                GlobalFree(grid->hmem);
                if (grid->hstr)
                {
                    GlobalFree(grid->hstr);
                }
                grid->toprow = 0;
                grid->hmem = 0;
                grid->rpmemfree = 0;
                grid->memsize = 0;
                grid->col = 0;
                grid->row = 0;
                grid->rows = 0;
                grid->hstr = 0;
                grid->rpstrfree = 0;
                grid->strsize = 0;
            }
            //DWORD *itemData = (DWORD*)(((unsigned char*)(grid + 1)) + grid->rpitemdata);

            p = mem;
            col = 0;
            while (col < grid->cols)
            {
                if (colPtr[col].lpszhdrtext)
                {
                    colPtr[col].lpszhdrtext = GridAddText(grid,(char*)p);
                    p = p + strlen((const char *)p) + 1;
                }
                if (colPtr[col].lpszformat)
                {
                    colPtr[col].lpszformat = GridAddText(grid,(char*)p);
                    p = p + strlen((const char *)p) + 1;
                }
                col++;
            }
            SendMessageA(hWin,WM_SIZE,0,0);
            InvalidateRect(grid->hlst,NULL,TRUE);
            GlobalFree(mem);
            RelMemHere(hWin);
            return 0;
        }
    case GM_COLUMNSORT:
        grid = GetMemHere(hWin);
        ShowHide(grid->hgrd,FALSE);
        if (grid->rows > 1)
        {
            if (wParam < grid->cols)
            {
                GridSortColumn(grid,(DWORD)wParam,(DWORD)lParam);
                InvalidateRect(grid->hlst,NULL,TRUE);
            }
        }
        RelMemHere(hWin);
        return 0;
    case GM_GETHDRTEXT:
        grid = GetMemHere(hWin);
        if (wParam < grid->cols)
        {
            COLUMN *colPtr = &(((COLUMN*)(grid + 1))[wParam]);

            if (colPtr->lpszhdrtext)
            {
                GridGetText(grid,(DWORD)colPtr->lpszhdrtext,(char*)lParam, MAX_CELL_SIZE);
            }
        }
        else
        {
            retVal = 0;
        }
        RelMemHere(hWin);
        return retVal;
    case GM_SETHDRTEXT:
        grid = GetMemHere(hWin);
        if (wParam < grid->cols)
        {
            COLUMN *colPtr = &(((COLUMN*)(grid + 1))[wParam]);

            if (lParam)
            {
                lParam = GridAddText(grid,(char*)lParam);
            }
            colPtr->lpszhdrtext = lParam;
            InvalidateRect(grid->hhdr,NULL,TRUE);
        }
        RelMemHere(hWin);
        return 0;
    case GM_GETCOLFORMAT:
        grid = GetMemHere(hWin);
        if (wParam < grid->cols)
        {
            COLUMN *colPtr = &(((COLUMN*)(grid + 1))[wParam]);

            retVal = colPtr->lpszformat;
            if (retVal)
            {
                GridGetText(grid,(DWORD)retVal,(char*)lParam, MAX_FORMAT_SIZE);
            }
        }
        else
        {
            retVal = 0;
        }
        RelMemHere(hWin);
        return retVal;
    case GM_SETCOLFORMAT:
        grid = GetMemHere(hWin);
        if (wParam < grid->cols)
        {
            COLUMN *colPtr = &(((COLUMN*)(grid + 1))[wParam]);

            retVal = lParam;
            if (retVal)
            {
                retVal = GridAddText(grid,(char*)lParam);
            }
            colPtr->lpszformat = (DWORD)retVal;
            InvalidateRect(grid->hlst,NULL,TRUE);
        }
        RelMemHere(hWin);
        return 0;
    case GM_CELLCONVERT:
        grid = GetMemHere(hWin);
        if (LOWORD(wParam) < grid->cols)
        {
            COLUMN *colPtr = &(((COLUMN*)(grid + 1))[LOWORD(wParam)]);
            unsigned char *p = (unsigned char *)lParam;
            DWORD val;

            p[0] = 0;
            switch (colPtr->ctype)
            {
            case TYPE_SELTEXT:
            case TYPE_EDITTEXT:
            case TYPE_BUTTON:
            case TYPE_EDITBUTTON:
                SendMessageA(hWin,GM_GETCELLDATA,wParam,lParam);
                break;
            case TYPE_EDITint32_t:
            case TYPE_IMAGE:
                SendMessageA(hWin,GM_GETCELLDATA,wParam,(LPARAM)&val);
                BinToDec(val,(char*)lParam, 10);
                break;
            case TYPE_CHECKBOX:
                SendMessageA(hWin,GM_GETCELLDATA,wParam,(LPARAM)&val);

                if (val)
                {
                    strcpy_s((char *)lParam, 6, "Yes");
                }
                else
                {
                    strcpy_s((char *)lParam, 6, "No");
                }
                break;
            case TYPE_COMBOBOX:
                {
                    int item;

                    SendMessageA(hWin,GM_GETCELLDATA,wParam,(LPARAM)&val);
                    item = 0;

                    for(;;)
                    {
                        retVal = SendMessageA(colPtr->edthwnd,LB_GETITEMDATA,item,0);
                        if (retVal == (int)val || retVal == LB_ERR)
                        {
                            break;
                        }
                        item++;
                    }
                    if (retVal != LB_ERR)
                    {
                        SendMessageA(colPtr->edthwnd,LB_GETTEXT,item,lParam);
                    }
                    break;
                }
            case TYPE_HOTKEY:
                SendMessageA(hWin,GM_GETCELLDATA,wParam,(LPARAM)&val);
                if ((val & (HOTKEYF_CONTROL << 8)) != 0)
                {
                    strcat_s((char*)lParam, strlen((char*)lParam) + 10, szCtrl);
                }
                if ((val & (HOTKEYF_SHIFT << 8)) != 0)
                {
                    strcat_s((char*)lParam, strlen((char*)lParam) + 10, szShift);
                }
                if ((val & (HOTKEYF_ALT << 8)) != 0)
                {
                    strcat_s((char*)lParam, strlen((char*)lParam) + 10, szAlt);
                }

                if ((val & 0xff) >= 'A' && (val & 0xff) <= 'Z')
                {
                    char buff[2] = {(char)val, 0};

                    strcat_s((char *)lParam, 2, buff);
                }
                else if ((val & 0xff) >= VK_F1 && (val & 0xff) <= VK_F12)
                {
                    char buff[4] = {'F', 0, 0, 0};

                    BinToDec((val & 0xff) - VK_F1 + 1,&buff[1], sizeof(buff) - 1);
                    strcat_s((char *)lParam, 4, buff);
                }
                break;
            case TYPE_DATE:
                {
                    __int64 tmpdate;
                    char buffer[MAX_CELL_SIZE];

                    SendMessageA(hWin,GM_GETCELLDATA,wParam,(LPARAM)&val);
                    // Days since 01.01.1601
                    tmpdate = val;
                    // Convert to number of 100 nano seconds since 01.01.1601
                    tmpdate *= 24*60*60;
                    tmpdate *= 1000*1000*10;
                    memcpy(&ftime, &tmpdate, sizeof(ftime));
                    FileTimeToSystemTime(&ftime, &stime);
                    if (colPtr->lpszformat)
                    {
                        GridGetText(grid,colPtr->lpszformat,&buffer[MAX_CELL_SIZE-MAX_FORMAT_SIZE], MAX_FORMAT_SIZE);
                        GetDateFormatA(0,0, &stime,&buffer[MAX_CELL_SIZE-MAX_FORMAT_SIZE],buffer,sizeof (buffer));
                    }
                    else
                    {
                        GetDateFormatA(0,0, &stime,NULL,buffer,sizeof (buffer));
                    }

                    strcpy_s((char *)lParam, MAX_FORMAT_SIZE, buffer);
                    break;
                }
            case TYPE_TIME:
                {
                    char buffer[MAX_CELL_SIZE];

                    SendMessageA(hWin,GM_GETCELLDATA,wParam,(LPARAM)&val);
                    stime.wYear = 2000;
                    stime.wMonth = 1;
                    stime.wDayOfWeek = 6;
                    stime.wDay = 1;
                    stime.wHour = (WORD)(val / 3600);
                    stime.wMinute = (val / 60) % 60;
                    stime.wSecond = (val % 60);
                    stime.wMilliseconds = 0;
                    if (colPtr->lpszformat)
                    {
                        GridGetText(grid,colPtr->lpszformat,&buffer[MAX_CELL_SIZE-MAX_FORMAT_SIZE], MAX_FORMAT_SIZE);
                        GetTimeFormatA(0,0, &stime,&buffer[MAX_CELL_SIZE-MAX_FORMAT_SIZE],buffer,sizeof (buffer));
                    }
                    else
                    {
                        GetTimeFormatA(0,0, &stime,NULL, buffer,sizeof (buffer));
                    }

                    strcpy_s((char *)lParam, MAX_FORMAT_SIZE, buffer);
                    break;
                }
            case TYPE_USER:
                {
                    char buffer[MAX_CELL_SIZE];

                    SendMessageA(hWin,GM_GETCELLDATA,wParam,(LPARAM)buffer);
                    SetNotify(grid, hWin, HIWORD(wParam), LOWORD(wParam), gn);
                    gn.nmhdr.code = GN_USERCONVERT;
                    gn.lpdata = buffer;
                    SendMessageA(grid->hpar,WM_NOTIFY,gn.nmhdr.idFrom, (LPARAM)&gn);
                    if (!gn.fcancel)
                    {
                        strcpy_s((char *)lParam, MAX_CELL_SIZE, buffer);
                    }
                    break;
                }
            }
        }
        else
        {
            unsigned char *p = (unsigned char *)lParam;

            p[0] = 0;
        }
        RelMemHere(hWin);
        return 0;
    case GM_RESETCOLUMNS:
        {
            DWORD cols;

            SendMessageA(hWin,GM_RESETCONTENT,0,0);
            grid = GetMemHere(hWin);
            COLUMN *colPtr = (((COLUMN*)(grid + 1)));
            cols = grid->cols;
            while (cols)
            {
                if (colPtr->edthwnd)
                {
                    DestroyWindow(colPtr->edthwnd);
                }
                colPtr++;
                cols--;
            }
            grid->cols = 0;
            grid->ccx = 0;
            grid->sbx = 0;
            grid->rpitemdata = sizeof(GRID);
            SendMessageA(hWin,WM_SIZE,0,0);
            InvalidateRect(grid->hhdr,NULL,TRUE);
            InvalidateRect(grid->hlst,NULL,TRUE);
            RelMemHere(hWin);
            return 0;
        }
    case GM_GETROWCOLOR:
        grid = GetMemHere(hWin);
        GridGetRowColor(grid,GetItem(grid,(DWORD)wParam),(ROWCOLOR*)lParam);
        RelMemHere(hWin);
        return 0;
    case GM_SETROWCOLOR:
        grid = GetMemHere(hWin);
        GridSetRowColor(grid,GetItem(grid,(DWORD)wParam),(ROWCOLOR*)lParam);
        RelMemHere(hWin);
        return 0;
    case GM_GETCOLDATA:
        grid = GetMemHere(hWin);
        if (wParam < grid->cols)
        {
            COLUMN *colPtr = &(((COLUMN*)(grid + 1))[wParam]);
            *(COLUMN*)lParam = *colPtr;
            retVal = 0;
        }
        else
        {
            retVal = -1;
        }
        RelMemHere(hWin);
        return retVal;
    case GM_GETCELLITEMDATA:
        grid = GetMemHere(hWin);
        retVal = GridGetCellItemData(grid,GetItem(grid, HIWORD(wParam)),LOWORD(wParam));
        RelMemHere(hWin);
        return retVal;
    case GM_SETCELLITEMDATA:
        grid = GetMemHere(hWin);
        GridSetCellItemData(grid,GetItem(grid, HIWORD(wParam)),LOWORD(wParam),(DWORD)lParam);
        GetItemRect(grid, HIWORD(wParam), &rect);
        InvalidateRect(grid->hlst, &rect,TRUE);
        RelMemHere(hWin);
        return 0;
    case GM_GETCELLBACKCOLOR : //= WM_USER+47,   // wParam=nRowCol, lParam=0         ret COLORREF
        grid = GetMemHere(hWin);
        retVal = grid->colcellback;
        DeleteObject(grid->hbrcellback);
        grid->hbrcellback = CreateSolidBrush(grid->colcellback);
        RelMemHere(hWin);
        return retVal;
    case GM_SETCELLBACKCOLOR : //= WM_USER+48,   // wParam=nRowCol, lParam=COLORREF
        grid = GetMemHere(hWin);
        grid->colcellback = (int32_t)wParam;
        InvalidateRect(grid->hlst,NULL,TRUE);
        RelMemHere(hWin);
        return 0;
    case GM_GETCELLBACKHILITE: //= WM_USER+49,   // wParam=nRowCol, lParam=0         ret COLORREF
        grid = GetMemHere(hWin);
        retVal = grid->colcellbackhilite;
        RelMemHere(hWin);
        return retVal;
    case GM_SETCELLBACKHILITE: //= WM_USER+50,   // wParam=nRowCol, lParam=COLORREF
        grid = GetMemHere(hWin);
        grid->colcellbackhilite = (int32_t)wParam;
        DeleteObject(grid->hbrcellhilite);
        grid->hbrcellhilite = CreateSolidBrush(grid->colcellbackhilite);
        InvalidateRect(grid->hlst,NULL,TRUE);
        RelMemHere(hWin);
        return 0;
    case GM_GETCELLHILITE    : //= WM_USER+51,   // wParam=nRowCol, lParam=0         ret COLORREF
        grid = GetMemHere(hWin);
        retVal = grid->coltexthilite;
        RelMemHere(hWin);
        return retVal;
    case GM_SETCELLHILITE    : //= WM_USER+52,   // wParam=nRowCol, lParam=COLORREF
        grid = GetMemHere(hWin);
        grid->coltexthilite = (int32_t)wParam;
        InvalidateRect(grid->hlst,NULL,TRUE);
        RelMemHere(hWin);
        return 0;

    case WM_USER+9999:
        {
            COLUMN	col;

            col.colwt = 100;
            col.lpszhdrtext = (INT_PTR)szToolTip;
            col.halign = 0;
            col.calign = 0;
            col.ctype = 0;
            col.ctextmax = 31;
            col.lpszformat = 0;
            col.himl = 0;
            col.hdrflag = 0;
            col.colxp = 0;
            col.edthwnd = 0;
            SendMessageA(hWin,GM_ADDCOL,0, (LPARAM)&col);
            SendMessageA(hWin,GM_ADDROW,0, (LPARAM)szToolTip);
            break;
        }
    }
    return DefWindowProc(hWin,uMsg,wParam,lParam);
}

// --------------------------------------------------------------------------------
// Create a windowclass for the user control
ATOM GridInstall(HINSTANCE hInst)
{
    WNDCLASSEXA wc;

    hInstance = hInst;

    wc.cbSize = sizeof(WNDCLASSEX);
    //IFDEF DLL
    //	mov		wc.style,CS_GLOBALCLASS or CS_HREDRAW or CS_VREDRAW
    //ELSE
    wc.style = CS_HREDRAW | CS_VREDRAW;

    wc.lpfnWndProc = &RAGridProc;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = sizeof(void*); 		// Holds memory handle
    wc.hInstance = hInst;
    wc.hbrBackground = NULL;
    wc.lpszMenuName = NULL;
    wc.lpszClassName = szRAGridClass;
    wc.hIcon = NULL;
    wc.hIconSm = NULL;
    wc.hCursor = LoadCursor(NULL,IDC_ARROW);
    RegisterClassExA(&wc);

    wc.style = CS_HREDRAW | CS_VREDRAW | CS_DBLCLKS;
    wc.lpfnWndProc = &RAListProc;
    wc.lpszClassName = szRAListClass;
    return RegisterClassExA(&wc);
}
