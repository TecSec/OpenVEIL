/////////////////////////////////////////////////////////////////////////////
// Name:        aboutckm.cpp
// Purpose:     
// Author:      Roger Butler
// Modified by: 
// Created:     09/02/2016 10:26:30
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

#include "aboutckm.h"

////@begin XPM images
#include "../../src/tecseclogo.xpm"
////@end XPM images


/*
 * AboutCKM type definition
 */

IMPLEMENT_DYNAMIC_CLASS( AboutCKM, wxDialog )


/*
 * AboutCKM event table definition
 */

BEGIN_EVENT_TABLE( AboutCKM, wxDialog )

////@begin AboutCKM event table entries
////@end AboutCKM event table entries

END_EVENT_TABLE()


/*
 * AboutCKM constructors
 */

AboutCKM::AboutCKM()
{
    Init();
}

AboutCKM::AboutCKM( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
    Init();
    Create(parent, id, caption, pos, size, style);
}


/*
 * AboutCKM creator
 */

bool AboutCKM::Create( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
////@begin AboutCKM creation
    SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY|wxWS_EX_BLOCK_EVENTS);
    wxDialog::Create( parent, id, caption, pos, size, style );

    CreateControls();
    if (GetSizer())
    {
        GetSizer()->SetSizeHints(this);
    }
    Centre();
////@end AboutCKM creation
    return true;
}


/*
 * AboutCKM destructor
 */

AboutCKM::~AboutCKM()
{
////@begin AboutCKM destruction
////@end AboutCKM destruction
}


/*
 * Member initialisation
 */

void AboutCKM::Init()
{
////@begin AboutCKM member initialisation
////@end AboutCKM member initialisation
}


/*
 * Control creation for AboutCKM
 */

void AboutCKM::CreateControls()
{    
////@begin AboutCKM content construction
    AboutCKM* itemDialog1 = this;

    wxFlexGridSizer* itemFlexGridSizer2 = new wxFlexGridSizer(9, 1, 0, 0);
    itemDialog1->SetSizer(itemFlexGridSizer2);

    wxStaticBitmap* itemStaticBitmap3 = new wxStaticBitmap( itemDialog1, wxID_STATIC, itemDialog1->GetBitmapResource(wxT("../../src/tecseclogo.xpm")), wxDefaultPosition, wxSize(372, 73), 0 );
    itemFlexGridSizer2->Add(itemStaticBitmap3, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 0);

    wxStaticText* itemStaticText4 = new wxStaticText( itemDialog1, wxID_STATIC, wxGetTranslation(wxString(wxT("CKM ")) + (wxChar) 0x00AE), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer2->Add(itemStaticText4, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 0);

    wxStaticText* itemStaticText5 = new wxStaticText( itemDialog1, wxID_VERSIONSTRING, wxString("Version:  ") + wxString(VEILWXWINDOWS_FULL_VERSION), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer2->Add(itemStaticText5, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStaticText* itemStaticText6 = new wxStaticText( itemDialog1, wxID_COPYRIGHTSTRING, _(VEIL_COPYRIGHT), wxDefaultPosition, wxDefaultSize, 0 );
    itemStaticText6->Wrap(360);
    itemFlexGridSizer2->Add(itemStaticText6, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStaticText* itemStaticText7 = new wxStaticText( itemDialog1, wxID_VEILSUITE, _("The VEIL suite includes KeyVEIL, OpenVEIL, OpaqueVEIL and more."), wxDefaultPosition, wxDefaultSize, 0 );
    itemStaticText7->Wrap(360);
    itemFlexGridSizer2->Add(itemStaticText7, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStaticText* itemStaticText8 = new wxStaticText( itemDialog1, wxID_TM_LINE, _("VEIL, CKM and Constructive Key Management are registered trademarks of TecSec, Inc."), wxDefaultPosition, wxDefaultSize, 0 );
    itemStaticText8->Wrap(360);
    itemFlexGridSizer2->Add(itemStaticText8, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStaticText* itemStaticText9 = new wxStaticText( itemDialog1, wxID_WARNING_LINE, _("Warning: All VEIL and CKM programs are protected by copyright law and international treaties. Unauthorized reproduction or distribution of these programs or any portion of them may result in civil and criminal penalties, and will be prosecuted to the fullest extent possible under law."), wxDefaultPosition, wxDefaultSize, 0 );
    itemStaticText9->Wrap(360);
    itemFlexGridSizer2->Add(itemStaticText9, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStaticText* itemStaticText10 = new wxStaticText( itemDialog1, wxID_PATENTS, _("This product is protected by one or more of the following U.S. patents, as well as pending U.S. patent applications and foreign patents: \n5,369,702; 5,369,707; 5,375,169; 5,410,599; 5,432,851; 5,440,290; 5,680,452; 5,787,173; 5,898,781; 6,075,865; 6,229,445; 6,266,417; 6,490,680; 6,542,608; 6,549,623; 6,606,386; 6,608,901; 6,684,330; 6,694,433; 6,754,820; 6,845,453; 6,868,598; 7,016,495; 7,069,448; 7,079,653; 7,089,417; 7,095,851; 7,095,852; 7,111,173; 7,131,009; 7,178,030; 7,212,632; 7,490,240; 7,539,855; 7,738,660 ;7,817,800; 7,974,410; 8,077,870; 8,083,808; 8,285,991; 8,308,820; 8,712,046"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStaticText10->Wrap(360);
    itemFlexGridSizer2->Add(itemStaticText10, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxButton* itemButton11 = new wxButton( itemDialog1, wxID_OK, _("OK"), wxDefaultPosition, wxDefaultSize, 0 );
    itemButton11->SetDefault();
    itemFlexGridSizer2->Add(itemButton11, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

////@end AboutCKM content construction
}


/*
 * Should we show tooltips?
 */

bool AboutCKM::ShowToolTips()
{
    return true;
}

/*
 * Get bitmap resources
 */

wxBitmap AboutCKM::GetBitmapResource( const wxString& name )
{
    return ::GetBitmapResource(name);
}

/*
 * Get icon resources
 */

wxIcon AboutCKM::GetIconResource( const wxString& name )
{
	return ::GetIconResource(name);
}
