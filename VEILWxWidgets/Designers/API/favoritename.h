/////////////////////////////////////////////////////////////////////////////
// Name:        favoritename.h
// Purpose:     
// Author:      Roger Butler
// Modified by: 
// Created:     09/02/2016 22:05:01
// RCS-ID:      
// Copyright:   Copyright (c) 2016, TecSec, Inc.  
// Licence:     
/////////////////////////////////////////////////////////////////////////////

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
#define SYMBOL_FAVORITENAME_STYLE wxCAPTION|wxRESIZE_BORDER|wxSYSTEM_MENU|wxCLOSE_BOX|wxTAB_TRAVERSAL
#define SYMBOL_FAVORITENAME_TITLE _("Favorite Name")
#define SYMBOL_FAVORITENAME_IDNAME ID_FAVORITENAME
#define SYMBOL_FAVORITENAME_SIZE wxSize(400, 300)
#define SYMBOL_FAVORITENAME_POSITION wxDefaultPosition
////@end control identifiers


/*!
 * FavoriteName class declaration
 */

class FavoriteName: public wxDialog
{    
    DECLARE_DYNAMIC_CLASS( FavoriteName )
    DECLARE_EVENT_TABLE()

public:
    /// Constructors
    FavoriteName();
    FavoriteName( wxWindow* parent, wxWindowID id = SYMBOL_FAVORITENAME_IDNAME, const wxString& caption = SYMBOL_FAVORITENAME_TITLE, const wxPoint& pos = SYMBOL_FAVORITENAME_POSITION, const wxSize& size = SYMBOL_FAVORITENAME_SIZE, long style = SYMBOL_FAVORITENAME_STYLE );

    /// Creation
    bool Create( wxWindow* parent, wxWindowID id = SYMBOL_FAVORITENAME_IDNAME, const wxString& caption = SYMBOL_FAVORITENAME_TITLE, const wxPoint& pos = SYMBOL_FAVORITENAME_POSITION, const wxSize& size = SYMBOL_FAVORITENAME_SIZE, long style = SYMBOL_FAVORITENAME_STYLE );

    /// Destructor
    ~FavoriteName();

    /// Initialises member variables
    void Init();

    /// Creates the controls and sizers
    void CreateControls();

////@begin FavoriteName event handler declarations

    /// wxEVT_COMMAND_TEXT_UPDATED event handler for ID_NAME
    void OnNameTextUpdated( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK
    void OnOkClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL
    void OnCancelClick( wxCommandEvent& event );

////@end FavoriteName event handler declarations

////@begin FavoriteName member function declarations

    /// Retrieves bitmap resources
    wxBitmap GetBitmapResource( const wxString& name );

    /// Retrieves icon resources
    wxIcon GetIconResource( const wxString& name );
////@end FavoriteName member function declarations

    /// Should we show tooltips?
    static bool ShowToolTips();

////@begin FavoriteName member variables
    wxTextCtrl* edtName;
    wxButton* btnOK;
    wxButton* btnCancel;
////@end FavoriteName member variables
};

#endif
    // _FAVORITENAME_H_
