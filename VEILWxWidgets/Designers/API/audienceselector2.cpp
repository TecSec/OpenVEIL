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

// For compilers that support precompilation, includes "wx/wx.h".
#include "stdafx.h"


////@begin XPM images
////@end XPM images


/*
 * AudienceSelector2 type definition
 */

IMPLEMENT_DYNAMIC_CLASS(AudienceSelector2, wxWizard )


/*
 * AudienceSelector2 event table definition
 */

BEGIN_EVENT_TABLE(AudienceSelector2, wxWizard )

////@begin AudienceSelector2 event table entries
    EVT_WIZARD_PAGE_CHANGED( ID_AUDIENCESELECTOR, AudienceSelector2::OnAudienceselectorPageChanged )
    EVT_WIZARD_PAGE_CHANGING( ID_AUDIENCESELECTOR, AudienceSelector2::OnAudienceselectorPageChanging )
    EVT_WIZARD_CANCEL( ID_AUDIENCESELECTOR, AudienceSelector2::OnAudienceselectorCancel )
    EVT_WIZARD_FINISHED( ID_AUDIENCESELECTOR, AudienceSelector2::OnAudienceselectorFinished )
    EVT_INIT_DIALOG( AudienceSelector2::OnInitDialog )
////@end AudienceSelector2 event table entries

END_EVENT_TABLE()


/*
 * AudienceSelector2 constructors
 */

AudienceSelector2::AudienceSelector2() : _vars(nullptr)
{
    Init();
}

AudienceSelector2::AudienceSelector2( wxWindow* parent, wxWindowID id, const wxPoint& pos ) : _vars(nullptr)
{
    Init();
    Create(parent, id, pos);
}

wxWizardPage *AudienceSelector2::GetFirstPage() const 
{ 
	if (_vars == nullptr || (((!_vars->_connector || !_vars->_connector->isConnected()) || _vars->_connector->errorCode() == 401 || _vars->_connector->errorCode() == 440) && !_vars->_hideKeyVEILLogin))
		return _keyVeilPage; 
	return _tokenPage;
}

void AudienceSelector2::setVariables(audienceSelector2Variables* inVars)
{
	_vars = inVars;

	if (_vars != nullptr && _tokenPage != nullptr)
	{
		if (_vars->_favoriteManager)
		{
			_tokenPage->SetNextPage(_accessGroupPage);
			_accessGroupPage->SetPrevPage(_tokenPage);
		}
	}
}

/*
 * AudienceSelector2 creator
 */

bool AudienceSelector2::Create( wxWindow* parent, wxWindowID id, const wxPoint& pos )
{
////@begin AudienceSelector2 creation
    SetExtraStyle(wxWS_EX_BLOCK_EVENTS|wxWIZARD_EX_HELPBUTTON);
    wxBitmap wizardBitmap(wxNullBitmap);
    wxWizard::Create( parent, id, _("Audience Selector"), wizardBitmap, pos, wxDEFAULT_DIALOG_STYLE|wxCAPTION|wxRESIZE_BORDER|wxSYSTEM_MENU|wxCLOSE_BOX );

    CreateControls();
	////@end AudienceSelector2 creation

	//SetIcon(wxICON(sample));

	// Allow the bitmap to be expanded to fit the page height
//	SetBitmapPlacement(wxWIZARD_VALIGN_CENTRE);

	// Enable scrolling adaptation
	SetLayoutAdaptationMode(wxDIALOG_ADAPTATION_MODE_ENABLED);

	//// a wizard page may be either an object of predefined class
	//m_page1 = new wxWizardPageSimple(this);

	///* wxStaticText *text = */ new wxStaticText(m_page1, wxID_ANY,
	//	wxT("This wizard doesn't help you\nto do anything at all.\n")
	//	wxT("\n")
	//	wxT("The next pages will present you\nwith more useless controls."),
	//	wxPoint(5, 5)
	//);

	//// ... or a derived class
	//wxRadioboxPage *page3 = new wxRadioboxPage(this);
	//wxValidationPage *page4 = new wxValidationPage(this);

	//// set the page order using a convenience function - could also use
	//// SetNext/Prev directly as below, but Chain() is shorter, avoids the risk
	//// of an error and can itself be chained, e.g. you could write
	//// page3.Chain(page4).Chain(page5) and so on.
	//page3->Chain(page4);

	//// this page is not a wxWizardPageSimple, so we use SetNext/Prev to insert
	//// it into the chain of pages
	//wxCheckboxPage *page2 = new wxCheckboxPage(this, m_page1, page3);
	//m_page1->SetNext(page2);
	//page3->SetPrev(page2);


	//// allow the wizard to size itself around the pages
	//GetPageAreaSizer()->Add(m_page1);

    return true;
}


/*
 * AudienceSelector2 destructor
 */

AudienceSelector2::~AudienceSelector2()
{
////@begin AudienceSelector2 destruction
////@end AudienceSelector2 destruction
}


/*
 * Member initialisation
 */

void AudienceSelector2::Init()
{
////@begin AudienceSelector2 member initialisation
    _keyVeilPage = NULL;
    _tokenPage = NULL;
    _favoriteSelectionPage = NULL;
    _accessGroupPage = NULL;
    _savePage = NULL;
////@end AudienceSelector2 member initialisation
}


/*
 * Control creation for AudienceSelector2
 */

void AudienceSelector2::CreateControls()
{    
	leftPanel = new wxPanel(this, wxID_ANY, wxDefaultPosition, wxDefaultSize);
	leftPanel->SetBackgroundColour(wxColour(199, 179, 159));
	m_sizerBmpAndPage->Add(
		leftPanel,
		0, 
		wxALL| wxEXPAND, // Border all around, top alignment
		0 // Border width
	);

	leftPanelSizer = new wxFlexGridSizer(0, 1, 10, 0);
	leftPanel->SetSizer(leftPanelSizer);


	////@begin AudienceSelector2 content construction
    AudienceSelector2* itemWizard1 = this;

    _keyVeilPage = new KeyVEILWizardPage( itemWizard1 );
    itemWizard1->GetPageAreaSizer()->Add(_keyVeilPage);

    _tokenPage = new TokenSelectionWizardPage( itemWizard1 );
    itemWizard1->GetPageAreaSizer()->Add(_tokenPage);

    _favoriteSelectionPage = new FavoriteSelectionPage( itemWizard1 );
    itemWizard1->GetPageAreaSizer()->Add(_favoriteSelectionPage);

    _accessGroupPage = new GroupEditorWizardPage( itemWizard1 );
    itemWizard1->GetPageAreaSizer()->Add(_accessGroupPage);

    _savePage = new SaveSelectionWizardPage( itemWizard1 );
    itemWizard1->GetPageAreaSizer()->Add(_savePage);

    wxWizardPageSimple* lastPage = NULL;
	////@end AudienceSelector2 content construction
	_keyVeilPage->SetName("Login KeyVEIL");
	_keyVeilPage->SetNextPage(_tokenPage);

	_tokenPage->SetName("Log into Token");
	_tokenPage->SetPrevPage(_keyVeilPage);
	_tokenPage->SetNextPage(_favoriteSelectionPage);

	_favoriteSelectionPage->SetName("Select Favorite");
	_favoriteSelectionPage->SetPrevPage(_tokenPage);
	_favoriteSelectionPage->SetNextPage(_accessGroupPage);

	_accessGroupPage->SetName("Select Groups");
	_accessGroupPage->SetPrevPage(_favoriteSelectionPage);
	_accessGroupPage->SetNextPage(_savePage);

	_savePage->SetName("Save as Favorite");
	_savePage->SetPrevPage(_accessGroupPage);

	if (_vars != nullptr)
	{
		if (_vars->_hideKeyVEILLogin)
		{
			_tokenPage->SetPrevPage(nullptr);
		}
		if (_vars->_favoriteManager)
		{
			_tokenPage->SetNextPage(_accessGroupPage);
			_accessGroupPage->SetPrevPage(_tokenPage);
		}
	}
}

void AudienceSelector2::setupLeftPanel()
{
	if (leftPanel == nullptr || leftPanelSizer == nullptr)
		return;

	int count = 1;
	int pageCount = 0;

	leftPanel->Freeze();

	for (int i = 0; i < leftPanelSizer->GetRows(); i++)
		if (leftPanelSizer->IsRowGrowable(i))
			leftPanelSizer->RemoveGrowableRow(i);
	if (leftPanelSizer->IsColGrowable(0))
		leftPanelSizer->RemoveGrowableCol(0);

	leftPanelSizer->Clear(true);

	wxWizardPage *page = GetCurrentPage();

	while (page != nullptr && page->GetPrev() != nullptr)
		page = page->GetPrev();

	m_firstpage = page;

	while (page != nullptr)
	{
		pageCount++;
		page = page->GetNext();
	}
	page = m_firstpage;

	leftPanelSizer->SetRows(pageCount + 2);

	leftPanelSizer->Add(5, 5, 0, wxALIGN_CENTER_HORIZONTAL | wxALIGN_CENTER_VERTICAL | wxALL, 5);

	while (page != nullptr)
	{
		wxStaticText* itemStaticText11 = new wxStaticText(leftPanel, wxID_STATIC, page->GetName(), wxDefaultPosition, wxDefaultSize, 0);
		if (page == GetCurrentPage())
		{
			wxFont font = itemStaticText11->GetFont();
			font.SetPointSize(font.GetPointSize() + 1);
			font.SetWeight(wxFONTWEIGHT_BOLD);
			itemStaticText11->SetFont(font);
		}
		leftPanelSizer->Add(itemStaticText11, 0, wxGROW | wxALIGN_CENTER_VERTICAL | wxLEFT | wxRIGHT, 25);
		count++;
		page = page->GetNext();
	}

	leftPanelSizer->Add(5, 5, 0, wxALIGN_CENTER_HORIZONTAL | wxALIGN_CENTER_VERTICAL | wxALL, 5);

	if (count > 1)
	{
		leftPanelSizer->AddGrowableRow(0);
		leftPanelSizer->AddGrowableRow(count);
	}
	leftPanelSizer->AddGrowableCol(0);
	leftPanelSizer->Layout();

	leftPanel->Thaw();
	leftPanel->Layout();
	Layout();

	const wxString label = GetCurrentPage()->GetNext() != nullptr ? _("&Next >") : _("&Finish");
	if (label != m_btnNext->GetLabel())
		m_btnNext->SetLabel(label);

	m_btnNext->SetDefault();
}

/*
 * Runs the wizard.
 */

bool AudienceSelector2::Run()
{
	m_firstpage = _keyVeilPage;

	(void)ShowPage(GetFirstPage(), true /* forward */);

	m_wasModal = true;

	return ShowModal() == wxID_OK;
}


/*
 * Should we show tooltips?
 */

bool AudienceSelector2::ShowToolTips()
{
    return true;
}

/*
 * Get bitmap resources
 */

wxBitmap AudienceSelector2::GetBitmapResource( const wxString& name )
{
	return ::GetBitmapResource(name);
}

/*
 * Get icon resources
 */

wxIcon AudienceSelector2::GetIconResource( const wxString& name )
{
	return ::GetIconResource(name);
}



/*
 * wxEVT_WIZARD_PAGE_CHANGED event handler for ID_AUDIENCESELECTOR
 */

void AudienceSelector2::OnAudienceselectorPageChanged( wxWizardEvent& event )
{
	setupLeftPanel();
    event.Skip();
}


/*
 * wxEVT_WIZARD_PAGE_CHANGING event handler for ID_AUDIENCESELECTOR
 */

void AudienceSelector2::OnAudienceselectorPageChanging( wxWizardEvent& event )
{
////@begin wxEVT_WIZARD_PAGE_CHANGING event handler for ID_AUDIENCESELECTOR in AudienceSelector2.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_WIZARD_PAGE_CHANGING event handler for ID_AUDIENCESELECTOR in AudienceSelector2. 
}


/*
 * wxEVT_WIZARD_FINISHED event handler for ID_AUDIENCESELECTOR
 */

void AudienceSelector2::OnAudienceselectorFinished( wxWizardEvent& event )
{
////@begin wxEVT_WIZARD_FINISHED event handler for ID_AUDIENCESELECTOR in AudienceSelector2.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_WIZARD_FINISHED event handler for ID_AUDIENCESELECTOR in AudienceSelector2. 
}


/*
 * wxEVT_INIT_DIALOG event handler for ID_AUDIENCESELECTOR
 */

void AudienceSelector2::OnInitDialog( wxInitDialogEvent& event )
{
////@begin wxEVT_INIT_DIALOG event handler for ID_AUDIENCESELECTOR in AudienceSelector2.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_INIT_DIALOG event handler for ID_AUDIENCESELECTOR in AudienceSelector2. 
}

/*
* wxEVT_WIZARD_CANCEL event handler for ID_AUDIENCESELECTOR
*/

void AudienceSelector2::OnAudienceselectorCancel(wxWizardEvent& event)
{
	if (wxTsMessageBox("Do you really want to cancel?", "Question",
		wxICON_QUESTION | wxYES_NO, (XP_WINDOW)this) != wxYES)
	{
		// not confirmed
		event.Veto();
	}
}

