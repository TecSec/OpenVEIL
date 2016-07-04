/////////////////////////////////////////////////////////////////////////////
// Name:        attributeselectorgrid.cpp
// Purpose:     
// Author:      Roger Butler
// Modified by: 
// Created:     09/02/2016 22:54:52
// RCS-ID:      
// Copyright:   Copyright (c) 2016, TecSec, Inc.  
// Licence:     
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx/wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
#pragma hdrstop
#endif

#ifndef WX_PRECOMP
#include "wx/wx.h"
#endif

////@begin includes
////@end includes

#include "attributeselectorgrid.h"

////@begin XPM images
////@end XPM images


/*
 * AttributeSelectorGrid type definition
 */

IMPLEMENT_DYNAMIC_CLASS( AttributeSelectorGrid, wxDialog )


/*
 * AttributeSelectorGrid event table definition
 */

BEGIN_EVENT_TABLE( AttributeSelectorGrid, wxDialog )

////@begin AttributeSelectorGrid event table entries
    EVT_GRID_CELL_LEFT_CLICK( AttributeSelectorGrid::OnCellLeftClick )
    EVT_GRID_CELL_CHANGED( AttributeSelectorGrid::OnCellChanged )
    EVT_GRID_SELECT_CELL( AttributeSelectorGrid::OnSelectCell )
////@end AttributeSelectorGrid event table entries

END_EVENT_TABLE()


/*
 * AttributeSelectorGrid constructors
 */

AttributeSelectorGrid::AttributeSelectorGrid()
{
    Init();
}

AttributeSelectorGrid::AttributeSelectorGrid( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
    Init();
    Create(parent, id, caption, pos, size, style);
}


/*
 * AttributeSelectorGrid creator
 */

bool AttributeSelectorGrid::Create( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
////@begin AttributeSelectorGrid creation
    SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY|wxWS_EX_BLOCK_EVENTS);
    wxDialog::Create( parent, id, caption, pos, size, style );

    CreateControls();
    if (GetSizer())
    {
        GetSizer()->SetSizeHints(this);
    }
    Centre();
////@end AttributeSelectorGrid creation
    return true;
}


/*
 * AttributeSelectorGrid destructor
 */

AttributeSelectorGrid::~AttributeSelectorGrid()
{
////@begin AttributeSelectorGrid destruction
////@end AttributeSelectorGrid destruction
}


/*
 * Member initialisation
 */

void AttributeSelectorGrid::Init()
{
////@begin AttributeSelectorGrid member initialisation
    cmbCG = NULL;
    edtGrid = NULL;
////@end AttributeSelectorGrid member initialisation
}


/*
 * Control creation for AttributeSelectorGrid
 */

void AttributeSelectorGrid::CreateControls()
{    
////@begin AttributeSelectorGrid content construction
    AttributeSelectorGrid* itemDialog1 = this;

    wxFlexGridSizer* itemFlexGridSizer2 = new wxFlexGridSizer(0, 1, 0, 0);
    itemDialog1->SetSizer(itemFlexGridSizer2);

    wxFlexGridSizer* itemFlexGridSizer3 = new wxFlexGridSizer(0, 2, 0, 0);
    itemFlexGridSizer2->Add(itemFlexGridSizer3, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 0);

    wxStaticText* itemStaticText4 = new wxStaticText( itemDialog1, wxID_STATIC, _("CryptoGroup:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer3->Add(itemStaticText4, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxBoxSizer* itemBoxSizer5 = new wxBoxSizer(wxVERTICAL);
    itemFlexGridSizer3->Add(itemBoxSizer5, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxArrayString cmbCGStrings;
    cmbCG = new wxChoice( itemDialog1, ID_CRYPTOGROUPLIST, wxDefaultPosition, wxDefaultSize, cmbCGStrings, 0 );
    itemBoxSizer5->Add(cmbCG, 0, wxGROW|wxALL, 0);

    wxStaticText* itemStaticText7 = new wxStaticText( itemDialog1, ID_CRYPTOGROUP_STATIC, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
    itemBoxSizer5->Add(itemStaticText7, 0, wxGROW|wxALL, 5);

    itemFlexGridSizer3->AddGrowableCol(1);

    edtGrid = new wxGrid( itemDialog1, ID_GRID, wxDefaultPosition, wxSize(500, 250), wxSUNKEN_BORDER|wxHSCROLL|wxVSCROLL );
    edtGrid->SetDefaultColSize(80);
    edtGrid->SetDefaultRowSize(25);
    edtGrid->SetColLabelSize(25);
    edtGrid->SetRowLabelSize(0);
    edtGrid->CreateGrid(1, 1, wxGrid::wxGridSelectCells);
    itemFlexGridSizer2->Add(edtGrid, 0, wxGROW|wxALL, 5);

    wxStdDialogButtonSizer* itemStdDialogButtonSizer9 = new wxStdDialogButtonSizer;

    itemFlexGridSizer2->Add(itemStdDialogButtonSizer9, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);
    wxButton* itemButton10 = new wxButton( itemDialog1, wxID_OK, _("&OK"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStdDialogButtonSizer9->AddButton(itemButton10);

    wxButton* itemButton11 = new wxButton( itemDialog1, wxID_CANCEL, _("&Cancel"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStdDialogButtonSizer9->AddButton(itemButton11);

    itemStdDialogButtonSizer9->Realize();

    itemFlexGridSizer2->AddGrowableRow(1);
    itemFlexGridSizer2->AddGrowableCol(0);

    // Connect events and objects
    edtGrid->Connect(ID_GRID, wxEVT_CHAR, wxKeyEventHandler(AttributeSelectorGrid::OnGridChar), NULL, this);
////@end AttributeSelectorGrid content construction
}


/*
 * Should we show tooltips?
 */

bool AttributeSelectorGrid::ShowToolTips()
{
    return true;
}

/*
 * Get bitmap resources
 */

wxBitmap AttributeSelectorGrid::GetBitmapResource( const wxString& name )
{
    // Bitmap retrieval
////@begin AttributeSelectorGrid bitmap retrieval
    wxUnusedVar(name);
    return wxNullBitmap;
////@end AttributeSelectorGrid bitmap retrieval
}

/*
 * Get icon resources
 */

wxIcon AttributeSelectorGrid::GetIconResource( const wxString& name )
{
    // Icon retrieval
////@begin AttributeSelectorGrid icon retrieval
    wxUnusedVar(name);
    return wxNullIcon;
////@end AttributeSelectorGrid icon retrieval
}


/*
 * wxEVT_GRID_CELL_LEFT_CLICK event handler for ID_GRID
 */

void AttributeSelectorGrid::OnCellLeftClick( wxGridEvent& event )
{
////@begin wxEVT_GRID_CELL_LEFT_CLICK event handler for ID_GRID in AttributeSelectorGrid.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_GRID_CELL_LEFT_CLICK event handler for ID_GRID in AttributeSelectorGrid. 
}


/*
 * wxEVT_GRID_SELECT_CELL event handler for ID_GRID
 */

void AttributeSelectorGrid::OnSelectCell( wxGridEvent& event )
{
////@begin wxEVT_GRID_SELECT_CELL event handler for ID_GRID in AttributeSelectorGrid.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_GRID_SELECT_CELL event handler for ID_GRID in AttributeSelectorGrid. 
}


/*
 * wxEVT_CHAR event handler for ID_GRID
 */

void AttributeSelectorGrid::OnGridChar( wxKeyEvent& event )
{
////@begin wxEVT_CHAR event handler for ID_GRID in AttributeSelectorGrid.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_CHAR event handler for ID_GRID in AttributeSelectorGrid. 
}


/*
 * wxEVT_GRID_CELL_CHANGED event handler for ID_GRID
 */

void AttributeSelectorGrid::OnCellChanged( wxGridEvent& event )
{
////@begin wxEVT_GRID_CELL_CHANGED event handler for ID_GRID in AttributeSelectorGrid.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_GRID_CELL_CHANGED event handler for ID_GRID in AttributeSelectorGrid. 
}

