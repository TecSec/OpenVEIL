/////////////////////////////////////////////////////////////////////////////
// Name:        propertysheet.cpp
// Purpose:     
// Author:      Roger Butler
// Modified by: 
// Created:     10/02/2016 14:42:00
// RCS-ID:      
// Copyright:   Copyright (c) 2017, TecSec, Inc.  
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
#include "wx/bookctrl.h"
////@end includes

#include "propertysheet.h"

////@begin XPM images
////@end XPM images


/*
 * PropertySheet type definition
 */

IMPLEMENT_DYNAMIC_CLASS( PropertySheet, wxPropertySheetDialog )


/*
 * PropertySheet event table definition
 */

BEGIN_EVENT_TABLE( PropertySheet, wxPropertySheetDialog )

////@begin PropertySheet event table entries
////@end PropertySheet event table entries

END_EVENT_TABLE()


/*
 * PropertySheet constructors
 */

PropertySheet::PropertySheet()
{
    Init();
}

PropertySheet::PropertySheet( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
    Init();
    Create(parent, id, caption, pos, size, style);
}


/*
 * PropertySheet creator
 */

bool PropertySheet::Create( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
////@begin PropertySheet creation
    SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY|wxWS_EX_BLOCK_EVENTS);
    SetSheetStyle(wxPROPSHEET_DEFAULT);
    wxPropertySheetDialog::Create( parent, id, caption, pos, size, style );

    CreateButtons(wxOK|wxCANCEL|wxHELP);
    CreateControls();
    LayoutDialog();
    Centre();
////@end PropertySheet creation
    return true;
}


/*
 * PropertySheet destructor
 */

PropertySheet::~PropertySheet()
{
////@begin PropertySheet destruction
////@end PropertySheet destruction
}


/*
 * Member initialisation
 */

void PropertySheet::Init()
{
////@begin PropertySheet member initialisation
////@end PropertySheet member initialisation
}


/*
 * Control creation for PropertySheet
 */

void PropertySheet::CreateControls()
{    
////@begin PropertySheet content construction
    PropertySheet* itemPropertySheetDialog1 = this;

////@end PropertySheet content construction
}


/*
 * Should we show tooltips?
 */

bool PropertySheet::ShowToolTips()
{
    return true;
}

/*
 * Get bitmap resources
 */

wxBitmap PropertySheet::GetBitmapResource( const wxString& name )
{
    // Bitmap retrieval
////@begin PropertySheet bitmap retrieval
    wxUnusedVar(name);
    return wxNullBitmap;
////@end PropertySheet bitmap retrieval
}

/*
 * Get icon resources
 */

wxIcon PropertySheet::GetIconResource( const wxString& name )
{
    // Icon retrieval
////@begin PropertySheet icon retrieval
    wxUnusedVar(name);
    return wxNullIcon;
////@end PropertySheet icon retrieval
}
