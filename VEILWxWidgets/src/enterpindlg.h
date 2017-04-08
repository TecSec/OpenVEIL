/////////////////////////////////////////////////////////////////////////////
// Name:        enterpindlg.h
// Purpose:     
// Author:      Roger Butler
// Modified by: 
// Created:     21/02/2017 18:07:43
// RCS-ID:      
// Copyright:   Copyright (c) 2017, TecSec, Inc.  
// Licence:     
/////////////////////////////////////////////////////////////////////////////

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
#define SYMBOL_ENTERPIN_STYLE wxCAPTION|wxRESIZE_BORDER|wxSYSTEM_MENU|wxCLOSE_BOX|wxTAB_TRAVERSAL
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
