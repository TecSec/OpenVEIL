/////////////////////////////////////////////////////////////////////////////
// Name:        keyveillogin.h
// Purpose:     
// Author:      Roger Butler
// Modified by: 
// Created:     09/02/2016 11:56:54
// RCS-ID:      
// Copyright:   Copyright (c) 2016, TecSec, Inc.  
// Licence:     
/////////////////////////////////////////////////////////////////////////////

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
#define SYMBOL_KEYVEILLOGIN_STYLE wxCAPTION|wxSYSTEM_MENU|wxCLOSE_BOX|wxTAB_TRAVERSAL
#define SYMBOL_KEYVEILLOGIN_TITLE _("KeyVEIL Login")
#define SYMBOL_KEYVEILLOGIN_IDNAME ID_KEYVEILLOGIN
#define SYMBOL_KEYVEILLOGIN_SIZE wxSize(400, 300)
#define SYMBOL_KEYVEILLOGIN_POSITION wxDefaultPosition
////@end control identifiers


/*!
 * KeyVEILLogin class declaration
 */

class KeyVEILLogin: public wxDialog
{    
    DECLARE_DYNAMIC_CLASS( KeyVEILLogin )
    DECLARE_EVENT_TABLE()

public:
    /// Constructors
    KeyVEILLogin();
    KeyVEILLogin( wxWindow* parent, wxWindowID id = SYMBOL_KEYVEILLOGIN_IDNAME, const wxString& caption = SYMBOL_KEYVEILLOGIN_TITLE, const wxPoint& pos = SYMBOL_KEYVEILLOGIN_POSITION, const wxSize& size = SYMBOL_KEYVEILLOGIN_SIZE, long style = SYMBOL_KEYVEILLOGIN_STYLE );

    /// Creation
    bool Create( wxWindow* parent, wxWindowID id = SYMBOL_KEYVEILLOGIN_IDNAME, const wxString& caption = SYMBOL_KEYVEILLOGIN_TITLE, const wxPoint& pos = SYMBOL_KEYVEILLOGIN_POSITION, const wxSize& size = SYMBOL_KEYVEILLOGIN_SIZE, long style = SYMBOL_KEYVEILLOGIN_STYLE );

    /// Destructor
    ~KeyVEILLogin();

    /// Initialises member variables
    void Init();

    /// Creates the controls and sizers
    void CreateControls();

////@begin KeyVEILLogin event handler declarations

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_HELP
    void OnHelpClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK
    void OnOkClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_APPLY
    void OnApplyClick( wxCommandEvent& event );

////@end KeyVEILLogin event handler declarations

////@begin KeyVEILLogin member function declarations

    /// Retrieves bitmap resources
    wxBitmap GetBitmapResource( const wxString& name );

    /// Retrieves icon resources
    wxIcon GetIconResource( const wxString& name );
////@end KeyVEILLogin member function declarations

    /// Should we show tooltips?
    static bool ShowToolTips();

////@begin KeyVEILLogin member variables
    wxTextCtrl* edtURL;
    wxTextCtrl* edtUsername;
    wxTextCtrl* edtPassword;
    wxStaticText* edtStatus;
////@end KeyVEILLogin member variables
};

#endif
    // _KEYVEILLOGIN_H_
