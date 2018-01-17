/////////////////////////////////////////////////////////////////////////////
// Name:        guidesignerforapiapp.cpp
// Purpose:     
// Author:      Roger Butler
// Modified by: 
// Created:     09/02/2016 10:25:55
// RCS-ID:      
// Copyright:   Copyright (c) 2018, TecSec, Inc.  
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

#include "guidesignerforapiapp.h"

////@begin XPM images
////@end XPM images


/*
 * Application instance implementation
 */

////@begin implement app
IMPLEMENT_APP( GuiDesignerForAPIApp )
////@end implement app


/*
 * GuiDesignerForAPIApp type definition
 */

IMPLEMENT_CLASS( GuiDesignerForAPIApp, wxApp )


/*
 * GuiDesignerForAPIApp event table definition
 */

BEGIN_EVENT_TABLE( GuiDesignerForAPIApp, wxApp )

////@begin GuiDesignerForAPIApp event table entries
////@end GuiDesignerForAPIApp event table entries

END_EVENT_TABLE()


/*
 * Constructor for GuiDesignerForAPIApp
 */

GuiDesignerForAPIApp::GuiDesignerForAPIApp()
{
    Init();
}


/*
 * Member initialisation
 */

void GuiDesignerForAPIApp::Init()
{
////@begin GuiDesignerForAPIApp member initialisation
////@end GuiDesignerForAPIApp member initialisation
}

/*
 * Initialisation for GuiDesignerForAPIApp
 */

bool GuiDesignerForAPIApp::OnInit()
{    
////@begin GuiDesignerForAPIApp initialisation
	// Remove the comment markers above and below this block
	// to make permanent changes to the code.

#if wxUSE_XPM
	wxImage::AddHandler(new wxXPMHandler);
#endif
#if wxUSE_LIBPNG
	wxImage::AddHandler(new wxPNGHandler);
#endif
#if wxUSE_LIBJPEG
	wxImage::AddHandler(new wxJPEGHandler);
#endif
#if wxUSE_GIF
	wxImage::AddHandler(new wxGIFHandler);
#endif
	AboutCKM* mainWindow = new AboutCKM(NULL);
	/* int returnValue = */ mainWindow->ShowModal();

	mainWindow->Destroy();
	// A modal dialog application should return false to terminate the app.
	return false;
////@end GuiDesignerForAPIApp initialisation

    return true;
}


/*
 * Cleanup for GuiDesignerForAPIApp
 */

int GuiDesignerForAPIApp::OnExit()
{    
////@begin GuiDesignerForAPIApp cleanup
	return wxApp::OnExit();
////@end GuiDesignerForAPIApp cleanup
}

