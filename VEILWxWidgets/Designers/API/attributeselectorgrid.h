/////////////////////////////////////////////////////////////////////////////
// Name:        attributeselectorgrid.h
// Purpose:     
// Author:      Roger Butler
// Modified by: 
// Created:     09/02/2016 22:54:52
// RCS-ID:      
// Copyright:   Copyright (c) 2017, TecSec, Inc.  
// Licence:     
/////////////////////////////////////////////////////////////////////////////

#ifndef _ATTRIBUTESELECTORGRID_H_
#define _ATTRIBUTESELECTORGRID_H_


/*!
 * Includes
 */

////@begin includes
#include "wx/grid.h"
////@end includes

/*!
 * Forward declarations
 */

////@begin forward declarations
class wxGrid;
////@end forward declarations

/*!
 * Control identifiers
 */

////@begin control identifiers
#define ID_ATTRIBUTESELECTORGRID 10000
#define ID_CRYPTOGROUPLIST 10001
#define ID_CRYPTOGROUP_STATIC 10013
#define ID_GRID 10002
#define SYMBOL_ATTRIBUTESELECTORGRID_STYLE wxCAPTION|wxRESIZE_BORDER|wxSYSTEM_MENU|wxCLOSE_BOX|wxTAB_TRAVERSAL
#define SYMBOL_ATTRIBUTESELECTORGRID_TITLE _("Attribute Selector")
#define SYMBOL_ATTRIBUTESELECTORGRID_IDNAME ID_ATTRIBUTESELECTORGRID
#define SYMBOL_ATTRIBUTESELECTORGRID_SIZE wxSize(400, 300)
#define SYMBOL_ATTRIBUTESELECTORGRID_POSITION wxDefaultPosition
////@end control identifiers


/*!
 * AttributeSelectorGrid class declaration
 */

class AttributeSelectorGrid: public wxDialog
{    
    DECLARE_DYNAMIC_CLASS( AttributeSelectorGrid )
    DECLARE_EVENT_TABLE()

public:
    /// Constructors
    AttributeSelectorGrid();
    AttributeSelectorGrid( wxWindow* parent, wxWindowID id = SYMBOL_ATTRIBUTESELECTORGRID_IDNAME, const wxString& caption = SYMBOL_ATTRIBUTESELECTORGRID_TITLE, const wxPoint& pos = SYMBOL_ATTRIBUTESELECTORGRID_POSITION, const wxSize& size = SYMBOL_ATTRIBUTESELECTORGRID_SIZE, long style = SYMBOL_ATTRIBUTESELECTORGRID_STYLE );

    /// Creation
    bool Create( wxWindow* parent, wxWindowID id = SYMBOL_ATTRIBUTESELECTORGRID_IDNAME, const wxString& caption = SYMBOL_ATTRIBUTESELECTORGRID_TITLE, const wxPoint& pos = SYMBOL_ATTRIBUTESELECTORGRID_POSITION, const wxSize& size = SYMBOL_ATTRIBUTESELECTORGRID_SIZE, long style = SYMBOL_ATTRIBUTESELECTORGRID_STYLE );

    /// Destructor
    ~AttributeSelectorGrid();

    /// Initialises member variables
    void Init();

    /// Creates the controls and sizers
    void CreateControls();

////@begin AttributeSelectorGrid event handler declarations

    /// wxEVT_GRID_CELL_LEFT_CLICK event handler for ID_GRID
    void OnCellLeftClick( wxGridEvent& event );

    /// wxEVT_GRID_CELL_CHANGED event handler for ID_GRID
    void OnCellChanged( wxGridEvent& event );

    /// wxEVT_GRID_SELECT_CELL event handler for ID_GRID
    void OnSelectCell( wxGridEvent& event );

    /// wxEVT_CHAR event handler for ID_GRID
    void OnGridChar( wxKeyEvent& event );

////@end AttributeSelectorGrid event handler declarations

////@begin AttributeSelectorGrid member function declarations

    /// Retrieves bitmap resources
    wxBitmap GetBitmapResource( const wxString& name );

    /// Retrieves icon resources
    wxIcon GetIconResource( const wxString& name );
////@end AttributeSelectorGrid member function declarations

    /// Should we show tooltips?
    static bool ShowToolTips();

////@begin AttributeSelectorGrid member variables
    wxChoice* cmbCG;
    wxGrid* edtGrid;
////@end AttributeSelectorGrid member variables
};

#endif
    // _ATTRIBUTESELECTORGRID_H_
