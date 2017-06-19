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

#ifndef _PROPERTYSHEET_H_
#define _PROPERTYSHEET_H_


/*!
 * Includes
 */

////@begin includes
#include "wx/propdlg.h"
////@end includes

/*!
 * Forward declarations
 */

////@begin forward declarations
////@end forward declarations

/*!
 * Control identifiers
 */

////@begin control identifiers
#define ID_PROPERTYSHEET 10000
#define SYMBOL_PROPERTYSHEETDLG_STYLE wxCAPTION
#define SYMBOL_PROPERTYSHEETDLG_TITLE _("PropertySheet")
#define SYMBOL_PROPERTYSHEETDLG_IDNAME ID_PROPERTYSHEET
#define SYMBOL_PROPERTYSHEETDLG_SIZE wxDefaultSize
#define SYMBOL_PROPERTYSHEETDLG_POSITION wxDefaultPosition
////@end control identifiers


/*!
 * PropertySheetDlg class declaration
 */

class PropertySheetDlg: public wxPropertySheetDialog
{    
    DECLARE_DYNAMIC_CLASS( PropertySheetDlg )
    DECLARE_EVENT_TABLE()

public:
    /// Constructors
    PropertySheetDlg();
    PropertySheetDlg( wxWindow* parent, wxWindowID id = SYMBOL_PROPERTYSHEETDLG_IDNAME, const wxString& caption = SYMBOL_PROPERTYSHEETDLG_TITLE, const wxPoint& pos = SYMBOL_PROPERTYSHEETDLG_POSITION, const wxSize& size = SYMBOL_PROPERTYSHEETDLG_SIZE, long style = SYMBOL_PROPERTYSHEETDLG_STYLE );

    /// Creation
    bool Create( wxWindow* parent, wxWindowID id = SYMBOL_PROPERTYSHEETDLG_IDNAME, const wxString& caption = SYMBOL_PROPERTYSHEETDLG_TITLE, const wxPoint& pos = SYMBOL_PROPERTYSHEETDLG_POSITION, const wxSize& size = SYMBOL_PROPERTYSHEETDLG_SIZE, long style = SYMBOL_PROPERTYSHEETDLG_STYLE );

    /// Destructor
    ~PropertySheetDlg();

    /// Initialises member variables
    void Init();

    /// Creates the controls and sizers
    void CreateControls();

////@begin PropertySheetDlg event handler declarations

////@end PropertySheetDlg event handler declarations

////@begin PropertySheetDlg member function declarations

    /// Retrieves bitmap resources
    wxBitmap GetBitmapResource( const wxString& name );

    /// Retrieves icon resources
    wxIcon GetIconResource( const wxString& name );
////@end PropertySheetDlg member function declarations

    /// Should we show tooltips?
    static bool ShowToolTips();

////@begin PropertySheetDlg member variables
////@end PropertySheetDlg member variables
};

#endif
    // _PROPERTYSHEET_H_
