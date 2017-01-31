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


#include "stdafx.h"
//#include "help/VEILSystemHelp.h"
////@begin includes
#include "wx/listctrl.h"
////@end includes

/*!
 * Forward declarations
 */

 ////@begin forward declarations
class wxListCtrl;
////@end forward declarations

/*!
 * Control identifiers
 */

 ////@begin control identifiers
#define ID_TOKENSELECTOR 10000
#define ID_EXPLANATION 10012
#define ID_TOKENS 10001
#define SYMBOL_TOKENSELECTOR_STYLE wxCAPTION|wxSYSTEM_MENU|wxCLOSE_BOX|wxTAB_TRAVERSAL
#define SYMBOL_TOKENSELECTOR_TITLE _("Token Selector")
#define SYMBOL_TOKENSELECTOR_IDNAME ID_TOKENSELECTOR
#define SYMBOL_TOKENSELECTOR_SIZE wxSize(400, 300)
#define SYMBOL_TOKENSELECTOR_POSITION wxDefaultPosition
////@end control identifiers

class TokenSelector : public ITokenSelector, public tsmod::IObject, public wxDialog
{
	DECLARE_EVENT_TABLE()

public:
	TokenSelector() : hParent(XP_WINDOW_INVALID), m_enterpriseOID(GUID_NULL), m_tokenChangeCookie(0), m_nLVWidth(0), bInitialized(FALSE), m_nSelectionIndex(-1), _nextId(0), _cookie(0)
	{
		Init();
	}
	~TokenSelector()
	{
	}

	// wxDialog
	virtual bool Destroy() override
	{
		if (!!_connector && _cookie != 0)
		{
			_connector->RemoveKeyVEILChangeCallback(_cookie);
			_cookie = 0;
		}
		m_enterpriseOID = GUID_NULL;
		m_tokenChangeCookie = 0;
		m_nLVWidth = 0;
		bInitialized = FALSE;
		m_reason.clear();
		_nextId = 0;
		Me.reset();
		return true;
	}
	// IVEILWxUIBase
	virtual int  DisplayModal() override
	{
		if (hParent == XP_WINDOW_INVALID)
			hParent = (XP_WINDOW)wxTheApp->GetTopWindow();

		// Construct the dialog here
		Create((wxWindow*)hParent);

		int retVal = ShowModal();

		// Make sure you call Destroy
		Destroy();
		return retVal;
	}
	virtual int  DisplayModal(XP_WINDOW wnd) override
	{
		hParent = wnd;
		return DisplayModal();
	}

	// ITokenSelector
	virtual bool Start(std::shared_ptr<IKeyVEILConnector> connector, const GUID& enterpriseId, const tscrypto::tsCryptoString& reason, XP_WINDOW parent) override
	{
		Destroy();

		_connector = connector;
		m_enterpriseOID = enterpriseId;
		m_reason = reason;

		if (!!_connector)
		{
			_cookie = _connector->AddKeyVEILChangeCallback([this](JSONObject& eventData) {
				if (eventData.AsString("type") == "Token")
				{
					OnRefresh();
				}
			});
		}
		return true;
	}
	virtual std::shared_ptr<IKeyVEILSession> Session() override
	{
		std::shared_ptr<IKeyVEILSession> session;
		std::shared_ptr<IToken> token;

		if (m_nSelectionIndex < 0)
			return nullptr;

		auto it = std::find_if(m_TokenVec.begin(), m_TokenVec.end(), [this](TokenVecEntry& vec) { return vec.id == m_nSelectionIndex; });

		if (it == m_TokenVec.end())
			return nullptr;

		token = _connector->token(it->serialNumber);
		if (!token)
			return nullptr;

		return token->openSession();
	}


private:
	typedef struct TokenVecEntry {
		tscrypto::tsCryptoString szTokenName;
		tscrypto::tsCryptoString szProviderType;
		GUID tokenId;
		GUID enterpriseId;
		int id;
		tscrypto::tsCryptoData serialNumber;
	} TokenVecEntry;

	typedef std::vector<TokenVecEntry> TokenVec;
	size_t _cookie;

	void OnRefresh()
	{
		wxCommandEvent evt;

		OnApplyClick(evt);
	}

	void OnInitDialog()
	{
		btnOK->Enable(false);

		{
			CWaitCursor wc(this);

			// free the internal token list first, just in case we are being displayed twice
			FreeTokenInfo();
			FetchTokenInfo();

			InitListView();
		}
		bInitialized = TRUE;

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


		// TODO:  Implement change detection here
		//m_tokenChange = new TokenChangeDetector(hDlg);
		//m_tokenChangeCookie = gMonitor->RegisterChangeConsumer(m_tokenChange);
		//gConsumerCookieList.add(m_tokenChangeCookie);
		//SetTimer(hDlg, 1, 500, NULL);
	}
	void InitListView()
	{
		UINT rw;
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
		lvColumn.SetWidth(UINT(m_nLVWidth * fColWidths[0]));
		lstTokens->InsertColumn(0, lvColumn);

		lvColumn.SetText("Type");
		lvColumn.SetWidth(UINT(m_nLVWidth * fColWidths[1]));
		lstTokens->InsertColumn(1, lvColumn);

		lvColumn.SetText("Serial Number");
		lvColumn.SetWidth(UINT(m_nLVWidth * fColWidths[2]));
		lstTokens->InsertColumn(2, lvColumn);

		btnOK->Enable(false);

		InsertListViewItems();
	} // end InitListView
	void InsertListViewItems()
	{
		TokenVec::iterator iter;
		UINT iCount;
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
	void FetchTokenInfo()
	{
		tscrypto::tsCryptoString szTokenName;
		std::shared_ptr<IToken> token;

		for (size_t i = 0; i < _connector->tokenCount(); i++)
		{
			token.reset();
			if (!!(token = _connector->token(i)) && (m_enterpriseOID == GUID_NULL || token->enterpriseId() == m_enterpriseOID))
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
	void FreeTokenInfo()
	{
		m_TokenVec.clear();
	} // end FreeTokenInfo
	int  GetTokenItemParam(int index)
	{
		if (index == -1)
		{
			LOG(DebugError, "Attempting to get the ItemData for index -1");
			return -1;
		}

		return lstTokens->GetItemData(index);
	}
	int  GetTokenIndex(int itemId)
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
	void UpdateItemText(int index, const tscrypto::tsCryptoString& text)
	{
		TSDECLARE_FUNCTIONExt(false);

		if (index < 0)
		{
			TSRETURN_ERROR_V(("Attempting to update the text for index %d with text '%s'", index, text));
			return;
		}

		lstTokens->SetItemText(index, text.c_str());

		TSRETURN_V(("Updated index %d with text '%s'", index, text));
		//ListView_SetItemText(m_hwndListView, index, 0, (char*)text);
	}
	void AddTokenVecForToken(const tscrypto::tsCryptoData& serialNumber)
	{
		std::shared_ptr<IToken> token;

		if (!(token = _connector->token(serialNumber)))
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

	std::shared_ptr<IKeyVEILConnector> _connector;
	std::shared_ptr<TokenSelector> Me; // Keep me alive until Destroy is called
	XP_WINDOW            hParent;
	GUID                 m_enterpriseOID;
	// TODO:  Implement change detection std::shared_ptr<ICkmChangeConsumer> m_tokenChange;
	int m_tokenChangeCookie;
	DWORD                m_nLVWidth;
	bool                 m_bShowSlots;
	TokenVec             m_TokenVec;
	BOOL                 bInitialized;
	int                  m_nSelectionIndex;
	tscrypto::tsCryptoString              m_reason;
	long                 _nextId;
	wxImageList images;

	/// Creation
	bool Create(wxWindow* parent, wxWindowID id = SYMBOL_TOKENSELECTOR_IDNAME, const wxString& caption = SYMBOL_TOKENSELECTOR_TITLE, const wxPoint& pos = SYMBOL_TOKENSELECTOR_POSITION, const wxSize& size = SYMBOL_TOKENSELECTOR_SIZE, long style = SYMBOL_TOKENSELECTOR_STYLE)
	{
		Me = std::dynamic_pointer_cast<TokenSelector>(_me.lock());

		////@begin TokenSelector creation
		SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY | wxWS_EX_BLOCK_EVENTS);
		wxDialog::Create(parent, id, caption, pos, size, style);

		CreateControls();
		if (GetSizer())
		{
			GetSizer()->SetSizeHints(this);
		}
		Centre();
		////@end TokenSelector creation

		OnInitDialog();

		return true;
	}

	/// Initialises member variables
	void Init()
	{
		////@begin TokenSelector member initialisation
		lblExplanation = NULL;
		lstTokens = NULL;
		btnRefresh = NULL;
		btnOK = nullptr;
		btnCancel = nullptr;
		////@end TokenSelector member initialisation
	}

	/// Creates the controls and sizers
	void CreateControls()
	{
		////@begin TokenSelector content construction
		TokenSelector* itemDialog1 = this;

		wxFlexGridSizer* itemFlexGridSizer2 = new wxFlexGridSizer(0, 1, 0, 0);
		itemDialog1->SetSizer(itemFlexGridSizer2);

		lblExplanation = new wxStaticText(itemDialog1, ID_EXPLANATION, _("Select a Token.  Click Refresh to update the list after Tokens are added or changed."), wxDefaultPosition, wxDefaultSize, 0);
		itemFlexGridSizer2->Add(lblExplanation, 0, wxALIGN_CENTER_HORIZONTAL | wxALIGN_CENTER_VERTICAL | wxALL, 5);

		lstTokens = new wxListCtrl(itemDialog1, ID_TOKENS, wxDefaultPosition, wxSize(100, 200), wxLC_REPORT | wxLC_SINGLE_SEL);
		itemFlexGridSizer2->Add(lstTokens, 0, wxGROW | wxALIGN_CENTER_VERTICAL | wxALL, 5);

		wxStdDialogButtonSizer* itemStdDialogButtonSizer5 = new wxStdDialogButtonSizer;

		itemFlexGridSizer2->Add(itemStdDialogButtonSizer5, 0, wxALIGN_CENTER_HORIZONTAL | wxALIGN_CENTER_VERTICAL | wxALL, 5);
		btnOK = new wxButton(itemDialog1, wxID_OK, _("&OK"), wxDefaultPosition, wxDefaultSize, 0);
		btnOK->SetDefault();
		itemStdDialogButtonSizer5->AddButton(btnOK);

		btnCancel = new wxButton(itemDialog1, wxID_CANCEL, _("&Cancel"), wxDefaultPosition, wxDefaultSize, 0);
		btnCancel->SetName(wxT("btnCancel"));
		itemStdDialogButtonSizer5->AddButton(btnCancel);

		btnRefresh = new wxButton(itemDialog1, wxID_APPLY, _("&Refresh"), wxDefaultPosition, wxDefaultSize, 0);
		itemStdDialogButtonSizer5->AddButton(btnRefresh);

		wxButton* itemButton9 = new wxButton(itemDialog1, wxID_HELP, _("&Help"), wxDefaultPosition, wxDefaultSize, 0);
		itemStdDialogButtonSizer5->AddButton(itemButton9);

		itemStdDialogButtonSizer5->Realize();

		////@end TokenSelector content construction
	}

	////@begin TokenSelector event handler declarations

	/// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK
	void OnOkClick(wxCommandEvent& event)
	{
		m_nSelectionIndex = GetTokenItemParam(lstTokens->GetNextItem(-1, 1, wxLIST_STATE_SELECTED));
		EndDialog(wxID_OK);
	}

	/// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL
	void OnCancelClick(wxCommandEvent& event)
	{
		m_nSelectionIndex = -1;
		EndDialog(wxID_CANCEL);
	}

	/// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_APPLY
	void OnApplyClick(wxCommandEvent& event)
	{
		CWaitCursor wc(this);

		btnOK->Enable(false);
		FreeTokenInfo();
		FetchTokenInfo();

		lstTokens->ClearAll();
		InsertListViewItems();
	}

	/// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_HELP
	void OnHelpClick(wxCommandEvent& event)
	{
		tscrypto::tsCryptoString path;

		//if (!xp_PathSearch("CKMDesktop.chm", path))
		//{
		//	wxMessageBox(hDlg, ("We were unable to locate the help file for the VEIL system."), ("Error"), MB_OK);
		//}
		//else
		//{
		//	TS_HtmlHelp((XP_WINDOW)hDlg, path, HH_HELP_CONTEXT, IDH_TOKEN_SELECTOR);
		//}

		wxMessageBox("Help is not available at this time.", "Status", MB_OK);
	}


	/// wxEVT_COMMAND_LIST_ITEM_SELECTED event handler for ID_TOKENS
	void OnTokensSelected(wxListEvent& event)
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

	/// wxEVT_COMMAND_LIST_ITEM_DESELECTED event handler for ID_TOKENS
	void OnTokensDeselected(wxListEvent& event)
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

	/// wxEVT_COMMAND_LIST_ITEM_ACTIVATED event handler for ID_TOKENS
	void OnTokensItemActivated(wxListEvent& event)
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

	////@end TokenSelector event handler declarations

	////@begin TokenSelector member function declarations

		/*
		* Get bitmap resources
		*/

	wxBitmap GetBitmapResource(const wxString& name)
	{
		return ::GetBitmapResource(name);
	}

	/*
	* Get icon resources
	*/

	wxIcon GetIconResource(const wxString& name)
	{
		return ::GetIconResource(name);
	}

	////@end TokenSelector member function declarations

		/// Should we show tooltips?
	static bool ShowToolTips()
	{
		return true;
	}

private:
	////@begin TokenSelector member variables
	wxStaticText* lblExplanation;
	wxListCtrl* lstTokens;
	wxButton* btnRefresh;
	wxButton* btnOK;
	wxButton* btnCancel;
	////@end TokenSelector member variables
};

/*
 * TokenSelector event table definition
 */

BEGIN_EVENT_TABLE(TokenSelector, wxDialog)

////@begin TokenSelector event table entries
EVT_LIST_ITEM_SELECTED(ID_TOKENS, TokenSelector::OnTokensSelected)
EVT_LIST_ITEM_DESELECTED(ID_TOKENS, TokenSelector::OnTokensDeselected)
EVT_LIST_ITEM_ACTIVATED(ID_TOKENS, TokenSelector::OnTokensItemActivated)
EVT_BUTTON(wxID_OK, TokenSelector::OnOkClick)
EVT_BUTTON(wxID_CANCEL, TokenSelector::OnCancelClick)
EVT_BUTTON(wxID_APPLY, TokenSelector::OnApplyClick)
EVT_BUTTON(wxID_HELP, TokenSelector::OnHelpClick)
////@end TokenSelector event table entries

END_EVENT_TABLE()

tsmod::IObject* CreateTokenSelector()
{
	return dynamic_cast<tsmod::IObject*>(new TokenSelector());
}