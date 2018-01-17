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

#ifndef _ENTERPINDLG_H_
#define _ENTERPINDLG_H_


/*!
 * Includes
 */

////@begin includes
////@end includes

/*!
 * Forward declarations
 */

////@begin forward declarations
class PasswordGauge;
////@end forward declarations

/*!
 * Control identifiers
 */

////@begin control identifiers
#define ID_ENTERPIN 10000
#define ID_ENTERPIN_PASSWORD_EXPLAIN 10101
#define ID_ENTERPIN_OLD_PASSWORD 10001
#define ID_ENTERPIN_NEW_PASSWORD 10004
#define ID_ENTERPIN_VERIFY_PASSWORD 10002
#define ID_ENTERPIN_PASSWORD_STRENGTH 10003
#define ID_ENTERPIN_STATUS 10100
#define SYMBOL_ENTERPIN_STYLE wxDEFAULT_DIALOG_STYLE|wxCAPTION|wxTAB_TRAVERSAL
#define SYMBOL_ENTERPIN_TITLE _("Enter Password")
#define SYMBOL_ENTERPIN_IDNAME ID_ENTERPIN
#define SYMBOL_ENTERPIN_SIZE wxDefaultSize
#define SYMBOL_ENTERPIN_POSITION wxDefaultPosition
////@end control identifiers


/*!
 * EnterPin class declaration
 */

class EnterPin: public wxDialog
{    
    DECLARE_DYNAMIC_CLASS( EnterPin )
    DECLARE_EVENT_TABLE()

public:
    /// Constructors
    EnterPin();
    EnterPin( wxWindow* parent, wxWindowID id = SYMBOL_ENTERPIN_IDNAME, const wxString& caption = SYMBOL_ENTERPIN_TITLE, const wxPoint& pos = SYMBOL_ENTERPIN_POSITION, const wxSize& size = SYMBOL_ENTERPIN_SIZE, long style = SYMBOL_ENTERPIN_STYLE );

    /// Creation
    bool Create( wxWindow* parent, wxWindowID id = SYMBOL_ENTERPIN_IDNAME, const wxString& caption = SYMBOL_ENTERPIN_TITLE, const wxPoint& pos = SYMBOL_ENTERPIN_POSITION, const wxSize& size = SYMBOL_ENTERPIN_SIZE, long style = SYMBOL_ENTERPIN_STYLE );

    /// Destructor
    ~EnterPin();

    /// Initialises member variables
    void Init();

    /// Creates the controls and sizers
    void CreateControls();

////@begin EnterPin event handler declarations

    /// wxEVT_INIT_DIALOG event handler for ID_ENTERPIN
    void OnInitDialog( wxInitDialogEvent& event );

    /// wxEVT_COMMAND_TEXT_UPDATED event handler for ID_ENTERPIN_OLD_PASSWORD
    void OnEnterpinOldPasswordTextUpdated( wxCommandEvent& event );

    /// wxEVT_COMMAND_TEXT_UPDATED event handler for ID_ENTERPIN_NEW_PASSWORD
    void OnEnterpinNewPasswordTextUpdated( wxCommandEvent& event );

    /// wxEVT_COMMAND_TEXT_UPDATED event handler for ID_ENTERPIN_VERIFY_PASSWORD
    void OnEnterpinVerifyPasswordTextUpdated( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK
    void OnOkClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL
    void OnCancelClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_APPLY
    void OnApplyClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_HELP
    void OnHelpClick( wxCommandEvent& event );

////@end EnterPin event handler declarations

////@begin EnterPin member function declarations

    /// Retrieves bitmap resources
    wxBitmap GetBitmapResource( const wxString& name );

    /// Retrieves icon resources
    wxIcon GetIconResource( const wxString& name );
////@end EnterPin member function declarations

    /// Should we show tooltips?
    static bool ShowToolTips();

	void setExplanation(const tscrypto::tsCryptoString& setTo);
	void setStatus(const tscrypto::tsCryptoString& setTo);
	void setVariables(enterPinVariables* vars);

////@begin EnterPin member variables
    wxStaticText* lblExplain;
    wxStaticText* lblOldPassword;
    wxTextCtrl* edtOldPassword;
    wxStaticText* lblNewPassword;
    wxTextCtrl* edtNewPassword;
    wxStaticText* lblVerifyPassword;
    wxTextCtrl* edtVerifyPassword;
    wxStaticText* lblPasswordStrength;
    PasswordGauge* edtPasswordStrength;
    wxStaticText* lblStatus;
    wxButton* btnOK;
    wxButton* btnCancel;
    wxButton* btnAbout;
    wxButton* btnHelp;
////@end EnterPin member variables
	enterPinVariables* _vars;

	void configureControls();
};

#endif
    // _ENTERPINDLG_H_
