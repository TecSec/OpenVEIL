/////////////////////////////////////////////////////////////////////////////
// Name:        generalsettingshandler.h
// Purpose:     
// Author:      Roger Butler
// Modified by: 
// Created:     10/02/2016 14:45:17
// RCS-ID:      
// Copyright:   Copyright (c) 2017, TecSec, Inc.  
// Licence:     
/////////////////////////////////////////////////////////////////////////////

#ifndef _GENERALSETTINGSHANDLER_H_
#define _GENERALSETTINGSHANDLER_H_


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
#define ID_GENERALSETTINGSHANDLER 10000
#define ID_URL 10001
#define ID_USERNAME 10002
#define ID_ENCRYPTION 10003
#define ID_HASH 10004
#define ID_TEXTCTRL 10005
#define SYMBOL_GENERALSETTINGSHANDLER_STYLE wxCAPTION|wxRESIZE_BORDER|wxSYSTEM_MENU|wxCLOSE_BOX|wxTAB_TRAVERSAL
#define SYMBOL_GENERALSETTINGSHANDLER_TITLE _("GeneralSettingsHandler")
#define SYMBOL_GENERALSETTINGSHANDLER_IDNAME ID_GENERALSETTINGSHANDLER
#define SYMBOL_GENERALSETTINGSHANDLER_SIZE wxSize(460, 290)
#define SYMBOL_GENERALSETTINGSHANDLER_POSITION wxDefaultPosition
////@end control identifiers


/*!
 * GeneralSettingsHandler class declaration
 */

class GeneralSettingsHandler: public wxPanel
{    
    DECLARE_DYNAMIC_CLASS( GeneralSettingsHandler )
    DECLARE_EVENT_TABLE()

public:
    /// Constructors
    GeneralSettingsHandler();
    GeneralSettingsHandler( wxWindow* parent, wxWindowID id = SYMBOL_GENERALSETTINGSHANDLER_IDNAME, const wxString& caption = SYMBOL_GENERALSETTINGSHANDLER_TITLE, const wxPoint& pos = SYMBOL_GENERALSETTINGSHANDLER_POSITION, const wxSize& size = SYMBOL_GENERALSETTINGSHANDLER_SIZE, long style = SYMBOL_GENERALSETTINGSHANDLER_STYLE );

    /// Creation
    bool Create( wxWindow* parent, wxWindowID id = SYMBOL_GENERALSETTINGSHANDLER_IDNAME, const wxString& caption = SYMBOL_GENERALSETTINGSHANDLER_TITLE, const wxPoint& pos = SYMBOL_GENERALSETTINGSHANDLER_POSITION, const wxSize& size = SYMBOL_GENERALSETTINGSHANDLER_SIZE, long style = SYMBOL_GENERALSETTINGSHANDLER_STYLE );

    /// Destructor
    ~GeneralSettingsHandler();

    /// Initialises member variables
    void Init();

    /// Creates the controls and sizers
    void CreateControls();

////@begin GeneralSettingsHandler event handler declarations

    /// wxEVT_COMMAND_TEXT_UPDATED event handler for ID_URL
    void OnUrlTextUpdated( wxCommandEvent& event );

    /// wxEVT_COMMAND_TEXT_UPDATED event handler for ID_USERNAME
    void OnUsernameTextUpdated( wxCommandEvent& event );

    /// wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_ENCRYPTION
    void OnEncryptionSelected( wxCommandEvent& event );

    /// wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_HASH
    void OnHashSelected( wxCommandEvent& event );

    /// wxEVT_COMMAND_TEXT_UPDATED event handler for ID_TEXTCTRL
    void OnTextctrlTextUpdated( wxCommandEvent& event );

////@end GeneralSettingsHandler event handler declarations

////@begin GeneralSettingsHandler member function declarations

    /// Retrieves bitmap resources
    wxBitmap GetBitmapResource( const wxString& name );

    /// Retrieves icon resources
    wxIcon GetIconResource( const wxString& name );
////@end GeneralSettingsHandler member function declarations

    /// Should we show tooltips?
    static bool ShowToolTips();

////@begin GeneralSettingsHandler member variables
    wxTextCtrl* edtKeyVEILUrl;
    wxTextCtrl* edtKeyVEILUsername;
    wxChoice* cmbEncryption;
    wxChoice* cmbHash;
////@end GeneralSettingsHandler member variables
};

#endif
    // _GENERALSETTINGSHANDLER_H_
