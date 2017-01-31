/////////////////////////////////////////////////////////////////////////////
// Name:        favoritename.cpp
// Purpose:     
// Author:      Roger Butler
// Modified by: 
// Created:     09/02/2016 22:05:01
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
////@end includes

#include "favoritename.h"

////@begin XPM images
////@end XPM images


/*
 * FavoriteName type definition
 */

IMPLEMENT_DYNAMIC_CLASS( FavoriteName, wxDialog )


/*
 * FavoriteName event table definition
 */

BEGIN_EVENT_TABLE( FavoriteName, wxDialog )

////@begin FavoriteName event table entries
    EVT_TEXT( ID_NAME, FavoriteName::OnNameTextUpdated )
    EVT_BUTTON( wxID_OK, FavoriteName::OnOkClick )
    EVT_BUTTON( wxID_CANCEL, FavoriteName::OnCancelClick )
////@end FavoriteName event table entries

END_EVENT_TABLE()


/*
 * FavoriteName constructors
 */

FavoriteName::FavoriteName()
{
    Init();
}

FavoriteName::FavoriteName( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
    Init();
    Create(parent, id, caption, pos, size, style);
}


/*
 * FavoriteName creator
 */

bool FavoriteName::Create( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
////@begin FavoriteName creation
    SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY|wxWS_EX_BLOCK_EVENTS);
    wxDialog::Create( parent, id, caption, pos, size, style );

    CreateControls();
    if (GetSizer())
    {
        GetSizer()->SetSizeHints(this);
    }
    Centre();
////@end FavoriteName creation
    return true;
}


/*
 * FavoriteName destructor
 */

FavoriteName::~FavoriteName()
{
////@begin FavoriteName destruction
////@end FavoriteName destruction
}


/*
 * Member initialisation
 */

void FavoriteName::Init()
{
////@begin FavoriteName member initialisation
    edtName = NULL;
    btnOK = NULL;
    btnCancel = NULL;
////@end FavoriteName member initialisation
}


/*
 * Control creation for FavoriteName
 */

void FavoriteName::CreateControls()
{    
////@begin FavoriteName content construction
    FavoriteName* itemDialog1 = this;

    wxFlexGridSizer* itemFlexGridSizer2 = new wxFlexGridSizer(0, 1, 0, 0);
    itemDialog1->SetSizer(itemFlexGridSizer2);

    wxStaticText* itemStaticText3 = new wxStaticText( itemDialog1, wxID_STATIC, _("Enter the name by which this favorite shall be known:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer2->Add(itemStaticText3, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    edtName = new wxTextCtrl( itemDialog1, ID_NAME, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0 );
    edtName->SetMaxLength(50);
    itemFlexGridSizer2->Add(edtName, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStdDialogButtonSizer* itemStdDialogButtonSizer5 = new wxStdDialogButtonSizer;

    itemFlexGridSizer2->Add(itemStdDialogButtonSizer5, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);
    btnOK = new wxButton( itemDialog1, wxID_OK, _("&OK"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStdDialogButtonSizer5->AddButton(btnOK);

    btnCancel = new wxButton( itemDialog1, wxID_CANCEL, _("&Cancel"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStdDialogButtonSizer5->AddButton(btnCancel);

    itemStdDialogButtonSizer5->Realize();

////@end FavoriteName content construction
}


/*
 * Should we show tooltips?
 */

bool FavoriteName::ShowToolTips()
{
    return true;
}

/*
 * Get bitmap resources
 */

wxBitmap FavoriteName::GetBitmapResource( const wxString& name )
{
    // Bitmap retrieval
////@begin FavoriteName bitmap retrieval
    wxUnusedVar(name);
    return wxNullBitmap;
////@end FavoriteName bitmap retrieval
}

/*
 * Get icon resources
 */

wxIcon FavoriteName::GetIconResource( const wxString& name )
{
    // Icon retrieval
////@begin FavoriteName icon retrieval
    wxUnusedVar(name);
    return wxNullIcon;
////@end FavoriteName icon retrieval
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK
 */

void FavoriteName::OnOkClick( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK in FavoriteName.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK in FavoriteName. 
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL
 */

void FavoriteName::OnCancelClick( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL in FavoriteName.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL in FavoriteName. 
}


/*
 * wxEVT_COMMAND_TEXT_UPDATED event handler for ID_NAME
 */

void FavoriteName::OnNameTextUpdated( wxCommandEvent& event )
{
////@begin wxEVT_COMMAND_TEXT_UPDATED event handler for ID_NAME in FavoriteName.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_COMMAND_TEXT_UPDATED event handler for ID_NAME in FavoriteName. 
}

