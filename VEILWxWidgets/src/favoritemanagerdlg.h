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

#ifndef _FAVORITEMANAGERDLG_H_
#define _FAVORITEMANAGERDLG_H_


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
#define ID_FAVORITEMANAGERDLG 10000
#define ID_FAVORITE_LIST 10001
#define ID_ADD_FAVORITE 10002
#define ID_EDIT_FAVORITE 10003
#define ID_DELETEFAVORITE 10004
#define ID_RENAMEFAVORITE 10005
#define SYMBOL_FAVORITEMANAGERDLG_STYLE wxDEFAULT_DIALOG_STYLE|wxCAPTION|wxRESIZE_BORDER|wxTAB_TRAVERSAL
#define SYMBOL_FAVORITEMANAGERDLG_TITLE _("Favorite Manager")
#define SYMBOL_FAVORITEMANAGERDLG_IDNAME ID_FAVORITEMANAGERDLG
#define SYMBOL_FAVORITEMANAGERDLG_SIZE wxSize(500, 350)
#define SYMBOL_FAVORITEMANAGERDLG_POSITION wxDefaultPosition
////@end control identifiers


/*!
 * FavoriteManagerDlg class declaration
 */

class FavoriteManagerDlg: public wxDialog
{    
    DECLARE_DYNAMIC_CLASS( FavoriteManagerDlg )
    DECLARE_EVENT_TABLE()

public:
    /// Constructors
    FavoriteManagerDlg();
    FavoriteManagerDlg( wxWindow* parent, wxWindowID id = SYMBOL_FAVORITEMANAGERDLG_IDNAME, const wxString& caption = SYMBOL_FAVORITEMANAGERDLG_TITLE, const wxPoint& pos = SYMBOL_FAVORITEMANAGERDLG_POSITION, const wxSize& size = SYMBOL_FAVORITEMANAGERDLG_SIZE, long style = SYMBOL_FAVORITEMANAGERDLG_STYLE );

    /// Creation
    bool Create( wxWindow* parent, wxWindowID id = SYMBOL_FAVORITEMANAGERDLG_IDNAME, const wxString& caption = SYMBOL_FAVORITEMANAGERDLG_TITLE, const wxPoint& pos = SYMBOL_FAVORITEMANAGERDLG_POSITION, const wxSize& size = SYMBOL_FAVORITEMANAGERDLG_SIZE, long style = SYMBOL_FAVORITEMANAGERDLG_STYLE );

    /// Destructor
    ~FavoriteManagerDlg();

    /// Initialises member variables
    void Init();

    /// Creates the controls and sizers
    void CreateControls();

////@begin FavoriteManagerDlg event handler declarations

    /// wxEVT_INIT_DIALOG event handler for ID_FAVORITEMANAGERDLG
    void OnInitDialog( wxInitDialogEvent& event );

    /// wxEVT_COMMAND_LISTBOX_SELECTED event handler for ID_FAVORITE_LIST
    void OnFavoriteListSelected( wxCommandEvent& event );

    /// wxEVT_COMMAND_LISTBOX_DOUBLECLICKED event handler for ID_FAVORITE_LIST
    void OnFavoriteListDoubleClicked( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_ADD_FAVORITE
    void OnAddFavoriteClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_EDIT_FAVORITE
    void OnEditFavoriteClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_DELETEFAVORITE
    void OnDeletefavoriteClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_RENAMEFAVORITE
    void OnRenamefavoriteClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_HELP
    void OnHelpClick( wxCommandEvent& event );

////@end FavoriteManagerDlg event handler declarations

////@begin FavoriteManagerDlg member function declarations

    /// Retrieves bitmap resources
    wxBitmap GetBitmapResource( const wxString& name );

    /// Retrieves icon resources
    wxIcon GetIconResource( const wxString& name );
////@end FavoriteManagerDlg member function declarations

    /// Should we show tooltips?
    static bool ShowToolTips();

////@begin FavoriteManagerDlg member variables
    wxListBox* _lstFavorites;
    wxButton* _btnAdd;
    wxButton* _btnEdit;
    wxButton* _btnDelete;
    wxButton* _btnRename;
////@end FavoriteManagerDlg member variables
	audienceSelector2Variables*                         _vars;

	void setVariables(audienceSelector2Variables* inVars);
	void ReloadFavorites();

protected:
	void updateControls();
	void OnFavChanges(wxCommandEvent& event);

};

#endif
    // _FAVORITEMANAGERDLG_H_
