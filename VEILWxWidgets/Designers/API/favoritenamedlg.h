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

#ifndef _FAVORITENAME_H_
#define _FAVORITENAME_H_


/*!
 * Includes
 */

////@begin includes
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
#define ID_FAVORITENAME 10000
#define ID_NAME 10001
#define SYMBOL_FAVORITENAMEDLG_STYLE wxCAPTION|wxRESIZE_BORDER|wxSYSTEM_MENU|wxCLOSE_BOX|wxTAB_TRAVERSAL
#define SYMBOL_FAVORITENAMEDLG_TITLE _("Favorite Name")
#define SYMBOL_FAVORITENAMEDLG_IDNAME ID_FAVORITENAME
#define SYMBOL_FAVORITENAMEDLG_SIZE wxSize(400, 300)
#define SYMBOL_FAVORITENAMEDLG_POSITION wxDefaultPosition
////@end control identifiers


/*!
 * FavoriteNameDlg class declaration
 */

class FavoriteNameDlg: public wxDialog
{    
    DECLARE_DYNAMIC_CLASS( FavoriteNameDlg )
    DECLARE_EVENT_TABLE()

public:
    /// Constructors
    FavoriteNameDlg();
    FavoriteNameDlg( wxWindow* parent, wxWindowID id = SYMBOL_FAVORITENAMEDLG_IDNAME, const wxString& caption = SYMBOL_FAVORITENAMEDLG_TITLE, const wxPoint& pos = SYMBOL_FAVORITENAMEDLG_POSITION, const wxSize& size = SYMBOL_FAVORITENAMEDLG_SIZE, long style = SYMBOL_FAVORITENAMEDLG_STYLE );

    /// Creation
    bool Create( wxWindow* parent, wxWindowID id = SYMBOL_FAVORITENAMEDLG_IDNAME, const wxString& caption = SYMBOL_FAVORITENAMEDLG_TITLE, const wxPoint& pos = SYMBOL_FAVORITENAMEDLG_POSITION, const wxSize& size = SYMBOL_FAVORITENAMEDLG_SIZE, long style = SYMBOL_FAVORITENAMEDLG_STYLE );

    /// Destructor
    ~FavoriteNameDlg();

    /// Initialises member variables
    void Init();

    /// Creates the controls and sizers
    void CreateControls();

////@begin FavoriteNameDlg event handler declarations

    /// wxEVT_INIT_DIALOG event handler for ID_FAVORITENAME
    void OnInitDialog( wxInitDialogEvent& event );

    /// wxEVT_COMMAND_TEXT_UPDATED event handler for ID_NAME
    void OnNameTextUpdated( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK
    void OnOkClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL
    void OnCancelClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_HELP
    void OnHelpClick( wxCommandEvent& event );

////@end FavoriteNameDlg event handler declarations

////@begin FavoriteNameDlg member function declarations

    /// Retrieves bitmap resources
    wxBitmap GetBitmapResource( const wxString& name );

    /// Retrieves icon resources
    wxIcon GetIconResource( const wxString& name );
////@end FavoriteNameDlg member function declarations

    /// Should we show tooltips?
    static bool ShowToolTips();

////@begin FavoriteNameDlg member variables
    wxTextCtrl* edtName;
    wxButton* btnOK;
    wxButton* btnCancel;
////@end FavoriteNameDlg member variables
	tscrypto::tsCryptoString    _name;

	tscrypto::tsCryptoString    get_name() const;
	void set_name(tscrypto::tsCryptoString setTo);
};

#endif
    // _FAVORITENAME_H_
