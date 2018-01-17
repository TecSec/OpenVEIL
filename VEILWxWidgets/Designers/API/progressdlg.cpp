//	Copyright (c) 2018, TecSec, Inc.
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

// For compilers that support precompilation, includes "wx/wx.h".
#include "stdafx.h"

////@begin includes
////@end includes

////@begin XPM images
////@end XPM images


/*
 * ProgressDlg type definition
 */

IMPLEMENT_DYNAMIC_CLASS( ProgressDlg, wxDialog )


/*
 * ProgressDlg event table definition
 */

BEGIN_EVENT_TABLE( ProgressDlg, wxDialog )

////@begin ProgressDlg event table entries
    EVT_INIT_DIALOG( ProgressDlg::OnInitDialog )
    EVT_WINDOW_DESTROY( ProgressDlg::OnDestroy )
    EVT_BUTTON( wxID_CANCEL, ProgressDlg::OnCancelClick )
////@end ProgressDlg event table entries

END_EVENT_TABLE()


/*
 * ProgressDlg constructors
 */

ProgressDlg::ProgressDlg() : m_winDisabler(nullptr), m_pdStyle(0), m_wasCancelled(false), m_range(100)
{
    Init();
}

ProgressDlg::ProgressDlg( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style ) : m_winDisabler(nullptr), m_pdStyle(0), m_wasCancelled(false), m_range(100)
{
    Init();
    Create(parent, id, caption, pos, size, style);
}


/*
 * ProgressDlg creator
 */

bool ProgressDlg::Create( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
	m_parentTop = GetParentForModalDialog(parent, style);
	m_pdStyle = style;

////@begin ProgressDlg creation
    SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY|wxWS_EX_BLOCK_EVENTS);
    wxDialog::Create( parent, id, caption, pos, size, wxCAPTION | wxTAB_TRAVERSAL);

    CreateControls();
    if (GetSizer())
    {
        GetSizer()->SetSizeHints(this);
    }
    Centre();
////@end ProgressDlg creation
	DisableOtherWindows();
    return true;
}


/*
 * ProgressDlg destructor
 */

ProgressDlg::~ProgressDlg()
{
////@begin ProgressDlg destruction
////@end ProgressDlg destruction
}


/*
 * Member initialisation
 */

void ProgressDlg::Init()
{
////@begin ProgressDlg member initialisation
    _txtTask = NULL;
    _guage = NULL;
    _btnCancel = NULL;
////@end ProgressDlg member initialisation
}


/*
 * Control creation for ProgressDlg
 */

void ProgressDlg::CreateControls()
{    
////@begin ProgressDlg content construction
    ProgressDlg* itemDialog1 = this;

    wxBoxSizer* itemBoxSizer2 = new wxBoxSizer(wxVERTICAL);
    itemDialog1->SetSizer(itemBoxSizer2);

    _txtTask = new wxStaticText( itemDialog1, ID_TASK_NAME, _("Fill me in"), wxDefaultPosition, wxDefaultSize, 0 );
    itemBoxSizer2->Add(_txtTask, 0, wxGROW|wxALL, 5);

    _guage = new wxGauge( itemDialog1, ID_PROGRESS_GAUGE, 100, wxDefaultPosition, wxSize(200, -1), wxGA_HORIZONTAL );
    _guage->SetValue(1);
    itemBoxSizer2->Add(_guage, 0, wxGROW|wxALL, 5);

    wxStdDialogButtonSizer* itemStdDialogButtonSizer5 = new wxStdDialogButtonSizer;

    itemBoxSizer2->Add(itemStdDialogButtonSizer5, 0, wxGROW|wxALL, 5);
    _btnCancel = new wxButton( itemDialog1, wxID_CANCEL, _("&Cancel"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStdDialogButtonSizer5->AddButton(_btnCancel);

    itemStdDialogButtonSizer5->Realize();

    // Connect events and objects
    itemDialog1->Connect(ID_PROGRESSDLG, wxEVT_DESTROY, wxWindowDestroyEventHandler(ProgressDlg::OnDestroy), NULL, this);
////@end ProgressDlg content construction
}


/*
 * Should we show tooltips?
 */

bool ProgressDlg::ShowToolTips()
{
    return true;
}

/*
 * Get bitmap resources
 */

wxBitmap ProgressDlg::GetBitmapResource( const wxString& name )
{
    // Bitmap retrieval
////@begin ProgressDlg bitmap retrieval
    wxUnusedVar(name);
    return wxNullBitmap;
////@end ProgressDlg bitmap retrieval
}

/*
 * Get icon resources
 */

wxIcon ProgressDlg::GetIconResource( const wxString& name )
{
    // Icon retrieval
////@begin ProgressDlg icon retrieval
    wxUnusedVar(name);
    return wxNullIcon;
////@end ProgressDlg icon retrieval
}


/*
 * wxEVT_INIT_DIALOG event handler for ID_PROGRESSDLG
 */

void ProgressDlg::OnInitDialog( wxInitDialogEvent& event )
{
////@begin wxEVT_INIT_DIALOG event handler for ID_PROGRESSDLG in ProgressDlg.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_INIT_DIALOG event handler for ID_PROGRESSDLG in ProgressDlg. 
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL
 */

void ProgressDlg::OnCancelClick( wxCommandEvent& event )
{
	m_wasCancelled = true;
	event.StopPropagation();
}

void ProgressDlg::setTask(const char* taskName)
{
	_txtTask->SetLabel(taskName);
	Update();
}

void ProgressDlg::DisableOtherWindows()
{
	if (HasPDFlag(wxPD_APP_MODAL))
	{
		m_winDisabler = new wxWindowDisabler(this);
	}
	else
	{
		if (m_parentTop)
			m_parentTop->Disable();
		m_winDisabler = NULL;
	}
}

void ProgressDlg::ReenableOtherWindows()
{
	if (HasPDFlag(wxPD_APP_MODAL))
	{
		wxDELETE(m_winDisabler);
	}
	else
	{
		if (m_parentTop)
			m_parentTop->Enable();
	}
}

bool ProgressDlg::WasCancelled()
{
	wxSafeYield(this);
	return m_wasCancelled;
}
void ProgressDlg::ClearCancel()
{
	m_wasCancelled = false;
}

void ProgressDlg::SetRange(int setTo)
{
	m_range = setTo;
	_guage->SetRange(setTo);
	Update();

}
int ProgressDlg::GetValue()
{
	return _guage->GetValue();
}
void ProgressDlg::SetValue(int setTo)
{
	_guage->SetValue(setTo);
	Update();
}


/*
 * wxEVT_DESTROY event handler for ID_PROGRESSDLG
 */

void ProgressDlg::OnDestroy( wxWindowDestroyEvent& event )
{
    event.Skip();
	ReenableOtherWindows();
}

