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

////@begin includes
#include "wx/imaglist.h"
////@end includes

////@begin XPM images
////@end XPM images


/*
 * TokenSelectorDlg type definition
 */

IMPLEMENT_DYNAMIC_CLASS( TokenSelectorDlg, wxDialog )


/*
 * TokenSelectorDlg event table definition
 */

BEGIN_EVENT_TABLE( TokenSelectorDlg, wxDialog )

////@begin TokenSelectorDlg event table entries
    EVT_INIT_DIALOG( TokenSelectorDlg::OnInitDialog )
    EVT_LIST_ITEM_SELECTED( ID_TOKENS, TokenSelectorDlg::OnTokensSelected )
    EVT_LIST_ITEM_DESELECTED( ID_TOKENS, TokenSelectorDlg::OnTokensDeselected )
    EVT_LIST_ITEM_ACTIVATED( ID_TOKENS, TokenSelectorDlg::OnTokensItemActivated )
    EVT_BUTTON( wxID_OK, TokenSelectorDlg::OnOkClick )
    EVT_BUTTON( wxID_CANCEL, TokenSelectorDlg::OnCancelClick )
    EVT_BUTTON( wxID_HELP, TokenSelectorDlg::OnHelpClick )
////@end TokenSelectorDlg event table entries

END_EVENT_TABLE()


/*
 * TokenSelectorDlg constructors
 */

TokenSelectorDlg::TokenSelectorDlg() : _vars(nullptr), m_nLVWidth(0), m_bShowSlots(false), _nextId(0)
{
    Init();
}

TokenSelectorDlg::TokenSelectorDlg( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style ) : _vars(nullptr), m_nLVWidth(0), m_bShowSlots(false), _nextId(0)
{
    Init();
    Create(parent, id, caption, pos, size, style);
}


/*
 * TokenSelector creator
 */

bool TokenSelectorDlg::Create( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
////@begin TokenSelectorDlg creation
    SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY|wxWS_EX_BLOCK_EVENTS);
    wxDialog::Create( parent, id, caption, pos, size, style );

    CreateControls();
    if (GetSizer())
    {
        GetSizer()->SetSizeHints(this);
    }
    Centre();
////@end TokenSelectorDlg creation
    return true;
}


/*
 * TokenSelectorDlg destructor
 */

TokenSelectorDlg::~TokenSelectorDlg()
{
////@begin TokenSelectorDlg destruction
////@end TokenSelectorDlg destruction
}


/*
 * Member initialisation
 */

void TokenSelectorDlg::Init()
{
////@begin TokenSelectorDlg member initialisation
    lblExplanation = NULL;
    lstTokens = NULL;
    btnOK = NULL;
    btnCancel = NULL;
////@end TokenSelectorDlg member initialisation
}


/*
 * Control creation for TokenSelector
 */

void TokenSelectorDlg::CreateControls()
{    
////@begin TokenSelectorDlg content construction
    TokenSelectorDlg* itemDialog1 = this;

    wxFlexGridSizer* itemFlexGridSizer2 = new wxFlexGridSizer(0, 1, 0, 0);
    itemDialog1->SetSizer(itemFlexGridSizer2);

    lblExplanation = new wxStaticText( itemDialog1, ID_EXPLANATION, _("Select a Token.  Click Refresh to update the list after Tokens are added or changed."), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer2->Add(lblExplanation, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    lstTokens = new wxListCtrl( itemDialog1, ID_TOKENS, wxDefaultPosition, wxSize(100, 200), wxLC_REPORT|wxLC_SINGLE_SEL );
    if (TokenSelectorDlg::ShowToolTips())
        lstTokens->SetToolTip(_("Select the token that you want to use."));
    itemFlexGridSizer2->Add(lstTokens, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStdDialogButtonSizer* itemStdDialogButtonSizer5 = new wxStdDialogButtonSizer;

    itemFlexGridSizer2->Add(itemStdDialogButtonSizer5, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);
    btnOK = new wxButton( itemDialog1, wxID_OK, _("&OK"), wxDefaultPosition, wxDefaultSize, 0 );
    btnOK->SetDefault();
    itemStdDialogButtonSizer5->AddButton(btnOK);

    btnCancel = new wxButton( itemDialog1, wxID_CANCEL, _("&Cancel"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStdDialogButtonSizer5->AddButton(btnCancel);

    wxButton* itemButton8 = new wxButton( itemDialog1, wxID_HELP, _("&Help"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStdDialogButtonSizer5->AddButton(itemButton8);

    itemStdDialogButtonSizer5->Realize();

////@end TokenSelectorDlg content construction
}


/*
 * Should we show tooltips?
 */

bool TokenSelectorDlg::ShowToolTips()
{
    return true;
}

/*
 * Get bitmap resources
 */

wxBitmap TokenSelectorDlg::GetBitmapResource( const wxString& name )
{
	return ::GetBitmapResource(name);
}

/*
 * Get icon resources
 */

wxIcon TokenSelectorDlg::GetIconResource( const wxString& name )
{
	return ::GetIconResource(name);
}


///*
// * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_APPLY
// */
//
//void TokenSelectorDlg::OnApplyClick( wxCommandEvent& event )  was refresh
//{
//    CWaitCursor wc(this);
//
//    btnOK->Enable(false);
//    FreeTokenInfo();
//    FetchTokenInfo();
//
//    lstTokens->ClearAll();
//    InsertListViewItems();
//}
//
//
/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL
 */

void TokenSelectorDlg::OnCancelClick( wxCommandEvent& event )
{
	_session.reset();
    EndDialog(wxID_CANCEL);
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK
 */

void TokenSelectorDlg::OnOkClick( wxCommandEvent& event )
{
	std::shared_ptr<IToken> token;
	
	int sel = GetTokenItemParam(lstTokens->GetNextItem(-1, 1, wxLIST_STATE_SELECTED));

	_session.reset();
	if (_vars != nullptr && !!_vars->_connector && sel >= 0)
	{
		auto it = std::find_if(m_TokenVec.begin(), m_TokenVec.end(), [sel](TokenVecEntry& vec) { 
			return vec.id == sel; 
		});

		if (it != m_TokenVec.end())
		{
			token = _vars->_connector->token(it->serialNumber);
			if (!!token)
			{
				_session = token->openSession();
			}
		}
	}
    EndDialog(wxID_OK);
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_HELP
 */

void TokenSelectorDlg::OnHelpClick( wxCommandEvent& event )
{
	std::shared_ptr<IVEILHttpHelpRegistry> help = ::TopServiceLocator()->get_instance<IVEILHttpHelpRegistry>("/WxWin/HelpRegistry");

	if (!help)
	{
		wxTsMessageBox(("Help is not available at this time."), ("Status"), wxOK);
	}
	else
	{
		help->DisplayHelpForWindowId(winid_TokenSelector, (XP_WINDOW)this);
	}
}


/*
 * wxEVT_COMMAND_LIST_ITEM_SELECTED event handler for ID_TOKENS
 */

void TokenSelectorDlg::OnTokensSelected( wxListEvent& event )
{
    if (lstTokens->GetSelectedItemCount() > 0)
    {
        btnOK->Enable(true);
    }
    else
    {
        btnOK->Enable(false);
    }
}


/*
 * wxEVT_COMMAND_LIST_ITEM_DESELECTED event handler for ID_TOKENS
 */

void TokenSelectorDlg::OnTokensDeselected( wxListEvent& event )
{
    if (lstTokens->GetSelectedItemCount() > 0)
    {
        btnOK->Enable(true);
    }
    else
    {
        btnOK->Enable(false);
    }
}


/*
 * wxEVT_COMMAND_LIST_ITEM_ACTIVATED event handler for ID_TOKENS
 */

void TokenSelectorDlg::OnTokensItemActivated( wxListEvent& event )
{
    if (lstTokens->GetSelectedItemCount() > 0)
    {
        btnOK->Enable(true);
        OnOkClick(event);
    }
    else
    {
        btnOK->Enable(false);
    }
}


/*
 * wxEVT_INIT_DIALOG event handler for ID_TOKENSELECTOR
 */

void TokenSelectorDlg::OnInitDialog( wxInitDialogEvent& event )
{
	btnOK->Enable(false);

	{
		CWaitCursor wc(this);

		// free the internal token list first, just in case we are being displayed twice
		FreeTokenInfo();
		FetchTokenInfo();

		InitListView();
	}

	// TODO:  Implement me
	/*
	ARROWCURSOR;

	CWindow win;
	int heightChange;
	RECT oldRect = {0}, newRect = {0};

	NONCLIENTMETRICS ncm;
	memset(&ncm, 0, sizeof(ncm));
	ncm.cbSize = sizeof(ncm);
	SystemParametersInfo(SPI_GETNONCLIENTMETRICS, 0, &ncm, 0);
	HDC hDC = this->GetDC();
	HANDLE hFont = ::CreateFontIndirect(&ncm.lfMessageFont);
	::SelectObject(hDC, hFont);
	if (hFont)
	::DeleteObject(hFont);

	// get the current size of the explanation control
	win.Attach(GetDlgItem(IDC_EXPLANATION));
	win.GetWindowRect(&oldRect);

	// sometimes the width is calculated wrong, so we don't resize width
	int rightSide = oldRect.right;

	// calculate the height of the new text and find the delta
	heightChange = oldRect.bottom;
	::DrawText(hDC, m_reason,
	m_reason.size(), &oldRect,
	DT_CALCRECT |  DT_LEFT | DT_WORDBREAK);    // | DT_NOPREFIX
	heightChange = oldRect.bottom - heightChange;

	this->ReleaseDC(hDC);

	// resize the explanation control using the new height and
	// change the text of the explanation control
	oldRect.right = rightSide;
	this->ScreenToClient(&oldRect);
	win.MoveWindow(&oldRect, TRUE);
	win.SetWindowText(myExplanation);
	win.Detach();

	// resize the main dialog window
	this->GetWindowRect(&oldRect);
	oldRect.bottom += heightChange;
	this->MoveWindow(&oldRect, TRUE);

	// move the token list
	win.Attach(GetDlgItem(IDC_TOKEN_LIST));
	win.GetWindowRect(&oldRect);
	this->ScreenToClient(&oldRect);
	oldRect.top += heightChange;
	oldRect.bottom += heightChange;
	win.MoveWindow(&oldRect, TRUE);
	win.Detach();

	// move the refresh button
	win.Attach(GetDlgItem(IDREFRESH));
	win.GetWindowRect(&oldRect);
	this->ScreenToClient(&oldRect);
	oldRect.top += heightChange;
	oldRect.bottom += heightChange;
	win.MoveWindow(&oldRect, TRUE);
	win.Detach();

	// move the ok button
	win.Attach(GetDlgItem(wxID_OK));
	win.GetWindowRect(&oldRect);
	this->ScreenToClient(&oldRect);
	oldRect.top += heightChange;
	oldRect.bottom += heightChange;
	win.MoveWindow(&oldRect, TRUE);
	win.Detach();

	// move the cancel button
	win.Attach(GetDlgItem(wxID_CANCEL));
	win.GetWindowRect(&oldRect);
	this->ScreenToClient(&oldRect);
	oldRect.top += heightChange;
	oldRect.bottom += heightChange;
	win.MoveWindow(&oldRect, TRUE);
	win.Detach();
	*/
}

void TokenSelectorDlg::OnRefresh()
{
    wxCommandEvent evt;

    //OnApplyClick(evt);
}

void TokenSelectorDlg::InitListView()
{
    int rw;
    int maxCol = 3;
    char szString[3][20] = { ("Token Name"), ("Type"), ("Serial Number") };
    double fColWidths[3] = { 0.55, 0.30, 0.15 };

    //ListView_SetExtendedListViewStyle
    //	(m_hwndListView, LVS_EX_FULLROWSELECT | LVS_EX_LABELTIP);

    //empty the list
    lstTokens->ClearAll();
    m_nLVWidth = lstTokens->GetClientSize().GetWidth();
    rw = m_nLVWidth;

    lstTokens->SetImageList(&images, wxIMAGE_LIST_SMALL);

    //initialize the columns
    wxListItem lvColumn;

    lvColumn.SetAlign(wxLIST_FORMAT_LEFT);
    lvColumn.SetImage(-1);
    lvColumn.SetText("Token Name");
    lvColumn.SetWidth(int(m_nLVWidth * fColWidths[0]));
    lstTokens->InsertColumn(0, lvColumn);

    lvColumn.SetText("Type");
    lvColumn.SetWidth(int(m_nLVWidth * fColWidths[1]));
    lstTokens->InsertColumn(1, lvColumn);

    lvColumn.SetText("Serial Number");
    lvColumn.SetWidth(int(m_nLVWidth * fColWidths[2]));
    lstTokens->InsertColumn(2, lvColumn);

    btnOK->Enable(false);

    InsertListViewItems();
} // end InitListView
void TokenSelectorDlg::InsertListViewItems()
{
    TokenVec::iterator iter;
    int iCount;
    tscrypto::tsCryptoString slot;
    wxListItem item;
    long index;

    iCount = lstTokens->GetItemCount();

    for (iter = m_TokenVec.begin(); iter != m_TokenVec.end(); iter++)
    {
        item.SetText(iter->szTokenName.c_str());
        item.SetData(iter->id);
        item.m_itemId = iCount++;

        index = lstTokens->InsertItem(item);

        /* add the token type to the list ctrl */
        lstTokens->SetItem(index, 1, iter->szProviderType.c_str());

        /* if enabled, add the slot id to the list ctrl */
        if (m_bShowSlots) {
            slot.clear();
            slot << iter->serialNumber.ToHexString();
            lstTokens->SetItem(index, 2, slot.c_str());
        }

    }
} // end InsertListViewItems
void TokenSelectorDlg::FetchTokenInfo()
{
    tscrypto::tsCryptoString szTokenName;
    std::shared_ptr<IToken> token;

	if (_vars == nullptr)
		return;

    for (size_t i = 0; i < _vars->_connector->tokenCount(); i++)
    {
        token.reset();
        if (!!(token = _vars->_connector->token(i)) && (_vars->m_enterpriseOID == GUID_NULL || token->enterpriseId() == _vars->m_enterpriseOID))
        {
            TokenVecEntry vec;

            vec.enterpriseId = token->enterpriseId();
            vec.id = InterlockedIncrement(&_nextId);
            vec.serialNumber = token->serialNumber();
            vec.szProviderType = token->tokenType();
            vec.szTokenName = token->tokenName();
            vec.tokenId = token->id();

            m_TokenVec.push_back(vec);
        }
    }

    // TODO:  Implement me
    //    // If there is only one token, set the selection index to 0
    //    // (the first and only token in the list) and close the dialog
    //    if (m_bCloseNoChoice && (ListView_GetItemCount(m_hwndListView) == 1))
    //    {
    //        m_nSelectionIndex = GetTokenItemParam(0);
    //        EndDialog(wxID_OK);
    //    }
    //
} // end FetchTokenInfo
void TokenSelectorDlg::FreeTokenInfo()
{
    m_TokenVec.clear();
} // end FreeTokenInfo
int  TokenSelectorDlg::GetTokenItemParam(int index)
{
    if (index == -1)
    {
        LOG(DebugError, "Attempting to get the ItemData for index -1");
        return -1;
    }

    return lstTokens->GetItemData(index);
}
int  TokenSelectorDlg::GetTokenIndex(int itemId)
{
    int count, index;

    count = lstTokens->GetItemCount();

    for (index = 0; index < count; index++)
    {
        if (GetTokenItemParam(index) == itemId)
        {
            return index;
        }
    }
    //LOG(DebugError , "Did not find a token in the list with id " << itemId );
    return -1;
}
void TokenSelectorDlg::UpdateItemText(int index, const tscrypto::tsCryptoString& text)
{
    TSDECLARE_FUNCTIONExt(false);

    if (index < 0)
    {
        TSRETURN_ERROR_V(("Attempting to update the text for index %d with text '%s'", index, text.c_str()));
        return;
    }

    lstTokens->SetItemText(index, text.c_str());

    TSRETURN_V(("Updated index %d with text '%s'", index, text.c_str()));
    //ListView_SetItemText(m_hwndListView, index, 0, (char*)text);
}
void TokenSelectorDlg::AddTokenVecForToken(const tscrypto::tsCryptoData& serialNumber)
{
    std::shared_ptr<IToken> token;

	if (_vars == nullptr)
		return;

    if (!(token = _vars->_connector->token(serialNumber)))
        return;

    TokenVecEntry vec;

    vec.enterpriseId = token->enterpriseId();
    vec.id = InterlockedIncrement(&_nextId);
    vec.serialNumber = token->serialNumber();
    vec.szProviderType = token->tokenType();
    vec.szTokenName = token->tokenName();
    vec.tokenId = token->id();

    m_TokenVec.push_back(vec);
}

void TokenSelectorDlg::setVariables(tokenSelectorVariables* inVars)
{
    _vars = inVars;
}

std::shared_ptr<IKeyVEILSession> TokenSelectorDlg::Session()
{
	return _session;
}
