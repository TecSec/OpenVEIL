//	Copyright (c) 2018, TecSec, Inc.
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

#ifndef _CHANGENAMEDLG_H_
#define _CHANGENAMEDLG_H_


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
#define ID_CHANGENAMEDLG 10000
#define wxID_CHANGE_NAME_TOP 10021
#define ID_CHANGENAME_NEWNAME 10001
#define SYMBOL_CHANGENAMEDLG_STYLE wxDEFAULT_DIALOG_STYLE|wxCAPTION|wxTAB_TRAVERSAL
#define SYMBOL_CHANGENAMEDLG_TITLE _("Change Name")
#define SYMBOL_CHANGENAMEDLG_IDNAME ID_CHANGENAMEDLG
#define SYMBOL_CHANGENAMEDLG_SIZE wxSize(400, 300)
#define SYMBOL_CHANGENAMEDLG_POSITION wxDefaultPosition
////@end control identifiers


/*!
 * ChangeNameDlg class declaration
 */

class ChangeNameDlg: public wxDialog
{    
    DECLARE_DYNAMIC_CLASS( ChangeNameDlg )
    DECLARE_EVENT_TABLE()

public:
    /// Constructors
    ChangeNameDlg();
    ChangeNameDlg( wxWindow* parent, wxWindowID id = SYMBOL_CHANGENAMEDLG_IDNAME, const wxString& caption = SYMBOL_CHANGENAMEDLG_TITLE, const wxPoint& pos = SYMBOL_CHANGENAMEDLG_POSITION, const wxSize& size = SYMBOL_CHANGENAMEDLG_SIZE, long style = SYMBOL_CHANGENAMEDLG_STYLE );

    /// Creation
    bool Create( wxWindow* parent, wxWindowID id = SYMBOL_CHANGENAMEDLG_IDNAME, const wxString& caption = SYMBOL_CHANGENAMEDLG_TITLE, const wxPoint& pos = SYMBOL_CHANGENAMEDLG_POSITION, const wxSize& size = SYMBOL_CHANGENAMEDLG_SIZE, long style = SYMBOL_CHANGENAMEDLG_STYLE );

    /// Destructor
    ~ChangeNameDlg();

    /// Initialises member variables
    void Init();

    /// Creates the controls and sizers
    void CreateControls();

////@begin ChangeNameDlg event handler declarations

    /// wxEVT_COMMAND_TEXT_UPDATED event handler for ID_CHANGENAME_NEWNAME
    void OnChangenameNewnameTextUpdated( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_HELP
    void OnHelpClick( wxCommandEvent& event );

////@end ChangeNameDlg event handler declarations

////@begin ChangeNameDlg member function declarations

    /// Retrieves bitmap resources
    wxBitmap GetBitmapResource( const wxString& name );

    /// Retrieves icon resources
    wxIcon GetIconResource( const wxString& name );
////@end ChangeNameDlg member function declarations

    /// Should we show tooltips?
    static bool ShowToolTips();

////@begin ChangeNameDlg member variables
    wxStaticText* lblDescription;
    wxStaticText* lblCurrentName;
    wxTextCtrl* edtNewName;
    wxButton* btnOk;
////@end ChangeNameDlg member variables
	uint32_t helpId;

	void SetDescription(const tscrypto::tsCryptoString& setTo);
	void SetOldName(const tscrypto::tsCryptoString& setTo);
	void SetNewName(const tscrypto::tsCryptoString& setTo);
	tscrypto::tsCryptoString GetNewName() const;
};

#endif
    // _CHANGENAMEDLG_H_
