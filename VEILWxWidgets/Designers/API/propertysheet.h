/////////////////////////////////////////////////////////////////////////////
// Name:        propertysheet.h
// Purpose:     
// Author:      Roger Butler
// Modified by: 
// Created:     10/02/2016 14:42:00
// RCS-ID:      
// Copyright:   Copyright (c) 2017, TecSec, Inc.  
// Licence:     
/////////////////////////////////////////////////////////////////////////////

#ifndef _PROPERTYSHEET_H_
#define _PROPERTYSHEET_H_


/*!
 * Includes
 */

////@begin includes
#include "wx/propdlg.h"
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
#define ID_PROPERTYSHEET 10000
#define SYMBOL_PROPERTYSHEET_STYLE wxCAPTION|wxSYSTEM_MENU|wxCLOSE_BOX
#define SYMBOL_PROPERTYSHEET_TITLE _("PropertySheet")
#define SYMBOL_PROPERTYSHEET_IDNAME ID_PROPERTYSHEET
#define SYMBOL_PROPERTYSHEET_SIZE wxSize(400, 300)
#define SYMBOL_PROPERTYSHEET_POSITION wxDefaultPosition
////@end control identifiers


/*!
 * PropertySheet class declaration
 */

class PropertySheet: public wxPropertySheetDialog
{    
    DECLARE_DYNAMIC_CLASS( PropertySheet )
    DECLARE_EVENT_TABLE()

public:
    /// Constructors
    PropertySheet();
    PropertySheet( wxWindow* parent, wxWindowID id = SYMBOL_PROPERTYSHEET_IDNAME, const wxString& caption = SYMBOL_PROPERTYSHEET_TITLE, const wxPoint& pos = SYMBOL_PROPERTYSHEET_POSITION, const wxSize& size = SYMBOL_PROPERTYSHEET_SIZE, long style = SYMBOL_PROPERTYSHEET_STYLE );

    /// Creation
    bool Create( wxWindow* parent, wxWindowID id = SYMBOL_PROPERTYSHEET_IDNAME, const wxString& caption = SYMBOL_PROPERTYSHEET_TITLE, const wxPoint& pos = SYMBOL_PROPERTYSHEET_POSITION, const wxSize& size = SYMBOL_PROPERTYSHEET_SIZE, long style = SYMBOL_PROPERTYSHEET_STYLE );

    /// Destructor
    ~PropertySheet();

    /// Initialises member variables
    void Init();

    /// Creates the controls and sizers
    void CreateControls();

////@begin PropertySheet event handler declarations

////@end PropertySheet event handler declarations

////@begin PropertySheet member function declarations

    /// Retrieves bitmap resources
    wxBitmap GetBitmapResource( const wxString& name );

    /// Retrieves icon resources
    wxIcon GetIconResource( const wxString& name );
////@end PropertySheet member function declarations

    /// Should we show tooltips?
    static bool ShowToolTips();

////@begin PropertySheet member variables
////@end PropertySheet member variables
};

#endif
    // _PROPERTYSHEET_H_
