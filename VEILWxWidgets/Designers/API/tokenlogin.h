/////////////////////////////////////////////////////////////////////////////
// Name:        tokenlogin.h
// Purpose:     
// Author:      Roger Butler
// Modified by: 
// Created:     09/02/2016 17:15:39
// RCS-ID:      
// Copyright:   Copyright (c) 2016, TecSec, Inc.  
// Licence:     
/////////////////////////////////////////////////////////////////////////////

#ifndef _TOKENLOGIN_H_
#define _TOKENLOGIN_H_


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
#define ID_TOKENLOGIN 10000
#define ID_TOKENNAME 10010
#define ID_TEXTCTRL 10001
#define ID_STATUS 10011
#define SYMBOL_TOKENLOGIN_STYLE wxCAPTION|wxRESIZE_BORDER|wxSYSTEM_MENU|wxCLOSE_BOX|wxTAB_TRAVERSAL
#define SYMBOL_TOKENLOGIN_TITLE _("Token Login")
#define SYMBOL_TOKENLOGIN_IDNAME ID_TOKENLOGIN
#define SYMBOL_TOKENLOGIN_SIZE wxSize(400, 300)
#define SYMBOL_TOKENLOGIN_POSITION wxDefaultPosition
////@end control identifiers


/*!
 * TokenLogin class declaration
 */

class TokenLogin: public wxDialog
{    
    DECLARE_DYNAMIC_CLASS( TokenLogin )
    DECLARE_EVENT_TABLE()

public:
    /// Constructors
    TokenLogin();
    TokenLogin( wxWindow* parent, wxWindowID id = SYMBOL_TOKENLOGIN_IDNAME, const wxString& caption = SYMBOL_TOKENLOGIN_TITLE, const wxPoint& pos = SYMBOL_TOKENLOGIN_POSITION, const wxSize& size = SYMBOL_TOKENLOGIN_SIZE, long style = SYMBOL_TOKENLOGIN_STYLE );

    /// Creation
    bool Create( wxWindow* parent, wxWindowID id = SYMBOL_TOKENLOGIN_IDNAME, const wxString& caption = SYMBOL_TOKENLOGIN_TITLE, const wxPoint& pos = SYMBOL_TOKENLOGIN_POSITION, const wxSize& size = SYMBOL_TOKENLOGIN_SIZE, long style = SYMBOL_TOKENLOGIN_STYLE );

    /// Destructor
    ~TokenLogin();

    /// Initialises member variables
    void Init();

    /// Creates the controls and sizers
    void CreateControls();

////@begin TokenLogin event handler declarations

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK
    void OnOkClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL
    void OnCancelClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_APPLY
    void OnApplyClick( wxCommandEvent& event );

////@end TokenLogin event handler declarations

////@begin TokenLogin member function declarations

    /// Retrieves bitmap resources
    wxBitmap GetBitmapResource( const wxString& name );

    /// Retrieves icon resources
    wxIcon GetIconResource( const wxString& name );
////@end TokenLogin member function declarations

    /// Should we show tooltips?
    static bool ShowToolTips();

////@begin TokenLogin member variables
    wxStaticText* lblTokenName;
    wxTextCtrl* edtPassword;
    wxStaticText* lblStatus;
    wxButton* btnOK;
    wxButton* btnCancel;
    wxButton* btnAbout;
////@end TokenLogin member variables
};

#endif
    // _TOKENLOGIN_H_
