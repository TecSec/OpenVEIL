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

#ifndef _KEYVEILLOGIN_H_
#define _KEYVEILLOGIN_H_


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
#define ID_KEYVEILLOGIN 10000
#define ID_URL 10001
#define ID_USERNAME 10002
#define ID_PASSWORD 10003
#define ID_STATUS 10007
#define SYMBOL_KEYVEILLOGINDLG_STYLE wxDEFAULT_DIALOG_STYLE|wxCAPTION|wxTAB_TRAVERSAL
#define SYMBOL_KEYVEILLOGINDLG_TITLE _("KeyVEIL Login")
#define SYMBOL_KEYVEILLOGINDLG_IDNAME ID_KEYVEILLOGIN
#define SYMBOL_KEYVEILLOGINDLG_SIZE wxDefaultSize
#define SYMBOL_KEYVEILLOGINDLG_POSITION wxDefaultPosition
////@end control identifiers

#define KEYVEIL_MIN_PIN_LEN 6
#define KEYVEIL_MAX_PIN_LEN 64

/*!
 * KeyVEILLoginDlg class declaration
 */

class KeyVEILLoginDlg: public wxDialog
{    
    DECLARE_DYNAMIC_CLASS( KeyVEILLoginDlg )
    DECLARE_EVENT_TABLE()

public:
    /// Constructors
    KeyVEILLoginDlg();
    KeyVEILLoginDlg( wxWindow* parent, wxWindowID id = SYMBOL_KEYVEILLOGINDLG_IDNAME, const wxString& caption = SYMBOL_KEYVEILLOGINDLG_TITLE, const wxPoint& pos = SYMBOL_KEYVEILLOGINDLG_POSITION, const wxSize& size = SYMBOL_KEYVEILLOGINDLG_SIZE, long style = SYMBOL_KEYVEILLOGINDLG_STYLE );

    /// Creation
    bool Create( wxWindow* parent, wxWindowID id = SYMBOL_KEYVEILLOGINDLG_IDNAME, const wxString& caption = SYMBOL_KEYVEILLOGINDLG_TITLE, const wxPoint& pos = SYMBOL_KEYVEILLOGINDLG_POSITION, const wxSize& size = SYMBOL_KEYVEILLOGINDLG_SIZE, long style = SYMBOL_KEYVEILLOGINDLG_STYLE );

    /// Destructor
    ~KeyVEILLoginDlg();

    /// Initialises member variables
    void Init();

    /// Creates the controls and sizers
    void CreateControls();

////@begin KeyVEILLoginDlg event handler declarations

    /// wxEVT_INIT_DIALOG event handler for ID_KEYVEILLOGIN
    void OnInitDialog( wxInitDialogEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_HELP
    void OnHelpClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK
    void OnOkClick( wxCommandEvent& event );

////@end KeyVEILLoginDlg event handler declarations

////@begin KeyVEILLoginDlg member function declarations

    /// Retrieves bitmap resources
    wxBitmap GetBitmapResource( const wxString& name );

    /// Retrieves icon resources
    wxIcon GetIconResource( const wxString& name );
////@end KeyVEILLoginDlg member function declarations

    /// Should we show tooltips?
    static bool ShowToolTips();

////@begin KeyVEILLoginDlg member variables
    wxTextCtrl* edtURL;
    wxTextCtrl* edtUsername;
    wxTextCtrl* edtPassword;
    wxStaticText* edtStatus;
////@end KeyVEILLoginDlg member variables

	keyVeilLoginVariables* _vars;

	int GetPinRetryCount(std::shared_ptr<IKeyVEILSession> session);
	void setVariables(keyVeilLoginVariables* inVars);
};

#endif
    // _KEYVEILLOGIN_H_
