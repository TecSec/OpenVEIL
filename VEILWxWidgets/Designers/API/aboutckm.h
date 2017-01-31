//	Copyright (c) 2017, TecSec, Inc.
//
//	Redistribution and use in source and binary forms, with or without
//	modification, are permitted provided that the following conditions are met:
//	
//		* Redistributions of source code must retain the above copyright
//		  notice, this list of conditions and the following disclaimer.
//		* Redistributions in binary form must reproduce the above copyright
//		  notice, this list of conditions and the following disclaimer in the
//		  documentation and/or other materials provided with the distribution.
//		* Neither the name of TecSec nor the names of the contributors may be
//		  used to endorse or promote products derived from this software 
//		  without specific prior written permission.
//		 
//	ALTERNATIVELY, provided that this notice is retained in full, this product
//	may be distributed under the terms of the GNU General Public License (GPL),
//	in which case the provisions of the GPL apply INSTEAD OF those given above.
//		 
//	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
//	ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//	DISCLAIMED.  IN NO EVENT SHALL TECSEC BE LIABLE FOR ANY 
//	DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//	(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
//	LOSS OF USE, DATA OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
//	ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Written by Roger Butler

/////////////////////////////////////////////////////////////////////////////
// Name:        aboutckm.h
// Purpose:     
// Author:      Roger Butler
// Modified by: 
// Created:     09/02/2016 10:26:30
// RCS-ID:      
// Copyright:   Copyright (c) 2017, TecSec, Inc.  
// Licence:     
/////////////////////////////////////////////////////////////////////////////

#ifndef _ABOUTCKM_H_
#define _ABOUTCKM_H_


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
#define ID_ABOUTCKM 10000
#define wxID_VERSIONSTRING 10001
#define wxID_COPYRIGHTSTRING 10002
#define wxID_VEILSUITE 10003
#define wxID_TM_LINE 10004
#define wxID_WARNING_LINE 10005
#define wxID_PATENTS 10006
#define SYMBOL_ABOUTCKM_STYLE wxCAPTION|wxSYSTEM_MENU|wxCLOSE_BOX|wxTAB_TRAVERSAL
#define SYMBOL_ABOUTCKM_TITLE _("About CKM")
#define SYMBOL_ABOUTCKM_IDNAME ID_ABOUTCKM
#define SYMBOL_ABOUTCKM_SIZE wxSize(400, 300)
#define SYMBOL_ABOUTCKM_POSITION wxDefaultPosition
////@end control identifiers


/*!
 * AboutCKM class declaration
 */

class AboutCKM: public wxDialog
{    
    DECLARE_DYNAMIC_CLASS( AboutCKM )
    DECLARE_EVENT_TABLE()

public:
    /// Constructors
    AboutCKM();
    AboutCKM( wxWindow* parent, wxWindowID id = SYMBOL_ABOUTCKM_IDNAME, const wxString& caption = SYMBOL_ABOUTCKM_TITLE, const wxPoint& pos = SYMBOL_ABOUTCKM_POSITION, const wxSize& size = SYMBOL_ABOUTCKM_SIZE, long style = SYMBOL_ABOUTCKM_STYLE );

    /// Creation
    bool Create( wxWindow* parent, wxWindowID id = SYMBOL_ABOUTCKM_IDNAME, const wxString& caption = SYMBOL_ABOUTCKM_TITLE, const wxPoint& pos = SYMBOL_ABOUTCKM_POSITION, const wxSize& size = SYMBOL_ABOUTCKM_SIZE, long style = SYMBOL_ABOUTCKM_STYLE );

    /// Destructor
    ~AboutCKM();

    /// Initialises member variables
    void Init();

    /// Creates the controls and sizers
    void CreateControls();

////@begin AboutCKM event handler declarations

////@end AboutCKM event handler declarations

////@begin AboutCKM member function declarations

    /// Retrieves bitmap resources
    wxBitmap GetBitmapResource( const wxString& name );

    /// Retrieves icon resources
    wxIcon GetIconResource( const wxString& name );
////@end AboutCKM member function declarations

    /// Should we show tooltips?
    static bool ShowToolTips();

////@begin AboutCKM member variables
////@end AboutCKM member variables
};

#endif
    // _ABOUTCKM_H_
