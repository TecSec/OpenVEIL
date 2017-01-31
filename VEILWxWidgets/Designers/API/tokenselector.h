/////////////////////////////////////////////////////////////////////////////
// Name:        tokenselector.h
// Purpose:     
// Author:      Roger Butler
// Modified by: 
// Created:     09/02/2016 17:56:57
// RCS-ID:      
// Copyright:   Copyright (c) 2017, TecSec, Inc.  
// Licence:     
/////////////////////////////////////////////////////////////////////////////

#ifndef _TOKENSELECTOR_H_
#define _TOKENSELECTOR_H_


/*!
 * Includes
 */

////@begin includes
#include "wx/listctrl.h"
////@end includes

/*!
 * Forward declarations
 */

////@begin forward declarations
class wxListCtrl;
////@end forward declarations

/*!
 * Control identifiers
 */

////@begin control identifiers
#define ID_TOKENSELECTOR 10000
#define ID_EXPLANATION 10012
#define ID_TOKENS 10001
#define SYMBOL_TOKENSELECTOR_STYLE wxCAPTION|wxRESIZE_BORDER|wxSYSTEM_MENU|wxCLOSE_BOX|wxTAB_TRAVERSAL
#define SYMBOL_TOKENSELECTOR_TITLE _("Token Selector")
#define SYMBOL_TOKENSELECTOR_IDNAME ID_TOKENSELECTOR
#define SYMBOL_TOKENSELECTOR_SIZE wxSize(400, 300)
#define SYMBOL_TOKENSELECTOR_POSITION wxDefaultPosition
////@end control identifiers


/*!
 * TokenSelector class declaration
 */

class TokenSelector: public wxDialog
{    
    DECLARE_DYNAMIC_CLASS( TokenSelector )
    DECLARE_EVENT_TABLE()

public:
    /// Constructors
    TokenSelector();
    TokenSelector( wxWindow* parent, wxWindowID id = SYMBOL_TOKENSELECTOR_IDNAME, const wxString& caption = SYMBOL_TOKENSELECTOR_TITLE, const wxPoint& pos = SYMBOL_TOKENSELECTOR_POSITION, const wxSize& size = SYMBOL_TOKENSELECTOR_SIZE, long style = SYMBOL_TOKENSELECTOR_STYLE );

    /// Creation
    bool Create( wxWindow* parent, wxWindowID id = SYMBOL_TOKENSELECTOR_IDNAME, const wxString& caption = SYMBOL_TOKENSELECTOR_TITLE, const wxPoint& pos = SYMBOL_TOKENSELECTOR_POSITION, const wxSize& size = SYMBOL_TOKENSELECTOR_SIZE, long style = SYMBOL_TOKENSELECTOR_STYLE );

    /// Destructor
    ~TokenSelector();

    /// Initialises member variables
    void Init();

    /// Creates the controls and sizers
    void CreateControls();

////@begin TokenSelector event handler declarations

    /// wxEVT_COMMAND_LIST_ITEM_SELECTED event handler for ID_TOKENS
    void OnTokensSelected( wxListEvent& event );

    /// wxEVT_COMMAND_LIST_ITEM_DESELECTED event handler for ID_TOKENS
    void OnTokensDeselected( wxListEvent& event );

    /// wxEVT_COMMAND_LIST_ITEM_ACTIVATED event handler for ID_TOKENS
    void OnTokensItemActivated( wxListEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK
    void OnOkClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL
    void OnCancelClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_APPLY
    void OnApplyClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_HELP
    void OnHelpClick( wxCommandEvent& event );

////@end TokenSelector event handler declarations

////@begin TokenSelector member function declarations

    /// Retrieves bitmap resources
    wxBitmap GetBitmapResource( const wxString& name );

    /// Retrieves icon resources
    wxIcon GetIconResource( const wxString& name );
////@end TokenSelector member function declarations

    /// Should we show tooltips?
    static bool ShowToolTips();

////@begin TokenSelector member variables
    wxStaticText* lblExplanation;
    wxListCtrl* lstTokens;
    wxButton* btnRefresh;
////@end TokenSelector member variables
};

#endif
    // _TOKENSELECTOR_H_
