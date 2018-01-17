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

#include "stdafx.h"
#include "resource.h"
#include "commctrl.h"

class TokenSelector : public ITokenSelector, public tsmod::IObject
{
public:
	TokenSelector() : hDlg(nullptr), hParent(nullptr), m_enterpriseOID(GUID_NULL), m_tokenChangeCookie(0), m_hwndListView(nullptr),
		m_nLVWidth(0), bInitialized(FALSE), m_nSelectionIndex(-1), _nextId(0), _cookie(0)
	{}
	~TokenSelector()
	{
		Destroy();
	}


	// IVEILUIBase
	virtual void Destroy()
	{
		hParent = nullptr;
		if (!!_connector && _cookie != 0)
		{
			_connector->RemoveKeyVEILChangeCallback(_cookie);
			_cookie = 0;
		}
		_connector.reset();
		hDlg = nullptr;
		m_enterpriseOID = GUID_NULL;
		//m_tokenChange.reset();
		m_tokenChangeCookie = 0;
		m_hwndListView = nullptr;
		m_nLVWidth = 0;
		m_TokenVec.clear();
		bInitialized = FALSE;
		m_nSelectionIndex = -1;
		m_reason.clear();
		_nextId = 0;
	}
	virtual int  DisplayModal()
	{
		if (hParent == NULL)
			hParent = GetActiveWindow();
		return (int)DialogBoxParamA((HINSTANCE)hDllInstance, MAKEINTRESOURCEA(IDD_TOKEN_SELECTOR), hParent, TokenSelectorProc, (LPARAM)this);
	}
	virtual int  DisplayModal(XP_WINDOW wnd)
	{
		hParent = (HWND)wnd;
		return DisplayModal();
	}

	// IKeyVEILLogIn
	virtual bool Start(std::shared_ptr<IKeyVEILConnector> connector, const GUID& enterpriseId, const tscrypto::tsCryptoString& reason, XP_WINDOW parent)
	{
		Destroy();

		_connector = connector;
		m_enterpriseOID = enterpriseId;
		m_reason = reason;

		if (!!_connector)
		{
			_cookie = _connector->AddKeyVEILChangeCallback([this](JSONObject& eventData){
				if (eventData.AsString("type") == "Token")
				{
					OnRefresh();
				}
			});
		}
		return true;
	}
	virtual std::shared_ptr<IKeyVEILSession> Session()
	{
		std::shared_ptr<IKeyVEILSession> session;
		std::shared_ptr<IToken> token;

		if (m_nSelectionIndex < 0)
			return nullptr;

		auto it = std::find_if(m_TokenVec.begin(), m_TokenVec.end(), [this](TokenVecEntry& vec){ return vec.id == m_nSelectionIndex; });

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

    intptr_t OnRefresh()
	{
		CWaitCursor wc;

		EnableWindow(GetDlgItem(hDlg, IDOK), FALSE);
		FreeTokenInfo();
		FetchTokenInfo();

		ListView_DeleteAllItems(m_hwndListView);
		InsertListViewItems();

		return FALSE;
	}
    intptr_t OnOK()
	{
		// 06/25/2010 KRR C4310 (WPARAM)
		m_nSelectionIndex = GetTokenItemParam(ListView_GetNextItem(m_hwndListView, -1, LVNI_SELECTED));
		EndDialog(hDlg, IDOK);
		return TRUE;
	}
    intptr_t OnCancel()
	{
		m_nSelectionIndex = -1;
		EndDialog(hDlg, IDCANCEL);
		return TRUE;
	}
    intptr_t OnHelp()
	{
		std::shared_ptr<IVEILHelpRegistry> help = ::TopServiceLocator()->get_instance<IVEILHelpRegistry>("/WinAPI/HelpRegistry");

		if (!help)
		{
			MessageBoxA(hDlg, ("Help is not available at this time."), ("Status"), MB_OK);
		}
		else
		{
			help->DisplayHelpForWindowId(winid_TokenSelector, (XP_WINDOW)hDlg);
		}
		return FALSE;
	}

	void OnWmDestroy()
	{
		// TODO:  Implement change detection here
		//if (m_tokenChangeCookie != 0)
		//{
		//	gMonitor->UnregisterChangeConsumer(m_tokenChangeCookie);
		//	for (int i = 0; i < (int)gConsumerCookieList.count(); i++)
		//	{
		//		if (gConsumerCookieList[i] == m_tokenChangeCookie)
		//		{
		//			gConsumerCookieList.removeAtIndex(i);
		//			break;
		//		}
		//	}
		//	m_tokenChangeCookie = 0;
		//}
		//m_tokenChange.Release();
		hDlg = NULL;
	}
    intptr_t OnInitDialog()
	{
		{
			CWaitCursor wc;

			// free the internal token list first, just in case we are being displayed twice
			FreeTokenInfo();
			FetchTokenInfo();

			//TODO: CenterWindow(CKMUI_Env::GetRootWindow());
			CreateListView();
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
		win.Attach(GetDlgItem(IDOK));
		win.GetWindowRect(&oldRect);
		this->ScreenToClient(&oldRect);
		oldRect.top += heightChange;
		oldRect.bottom += heightChange;
		win.MoveWindow(&oldRect, TRUE);
		win.Detach();

		// move the cancel button
		win.Attach(GetDlgItem(IDCANCEL));
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


		return 1;
	}
    intptr_t OnListItemChanged()
	{
		if (ListView_GetSelectedCount(m_hwndListView) > 0)
		{
			EnableWindow(GetDlgItem(hDlg, IDOK), TRUE);
		}
		else
		{
			EnableWindow(GetDlgItem(hDlg, IDOK), FALSE);
		}
		return FALSE;
	}
    intptr_t OnListItemActivate()
	{
		if (ListView_GetSelectedCount(m_hwndListView) > 0)
		{
			EnableWindow(GetDlgItem(hDlg, IDOK), TRUE);
		}
		else
		{
			EnableWindow(GetDlgItem(hDlg, IDOK), FALSE);
		}
		return FALSE;
	}

    intptr_t OnListItemDoubleclick()
	{
		if (ListView_GetSelectedCount(m_hwndListView) > 0)
		{
			EnableWindow(GetDlgItem(hDlg, IDOK), TRUE);
			OnOK();
		}
		else
		{
			EnableWindow(GetDlgItem(hDlg, IDOK), FALSE);
		}
		return FALSE;
	}

	void CreateListView()
	{
		RECT  rc;

		m_hwndListView = GetDlgItem(hDlg, IDC_TOKEN_LIST);
		GetClientRect(m_hwndListView, &rc);
		m_nLVWidth = rc.right - rc.left;
	} // end CreateListView
	void InitListView()
	{
		int i;
		UINT rw;
		int maxCol = 3;
		LV_COLUMNA lvColumn;
		char szString[3][20] = { ("Token Name"), ("Type"), ("Serial Number") };
		double fColWidths[3] = { 0.55, 0.30, 0.15 };

		ListView_SetExtendedListViewStyle
			(m_hwndListView, LVS_EX_FULLROWSELECT | LVS_EX_LABELTIP);

		//empty the list
		ListView_DeleteAllItems(m_hwndListView);
		rw = m_nLVWidth;

		//initialize the columns
		lvColumn.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
		lvColumn.fmt = LVCFMT_LEFT;
		for (i = 0; i < maxCol; i++)
		{
			if (i == maxCol - 1)
			{
				lvColumn.cx = rw;
			}
			else
			{
				lvColumn.cx = UINT(m_nLVWidth * fColWidths[i]);
			}

			rw -= lvColumn.cx;
			lvColumn.pszText = szString[i];
			ListView_InsertColumn(m_hwndListView, i, &lvColumn);
		}

		::EnableWindow(GetDlgItem(hDlg, IDOK), FALSE);

		InsertListViewItems();
	} // end InitListView
	void InsertListViewItems()
	{
		TokenVec::iterator iter;
		int index;
		LVITEMA lvi;
		UINT iCount;
		tscrypto::tsCryptoString slot;

		iCount = ListView_GetItemCount(m_hwndListView);

		for (iter = m_TokenVec.begin(); iter != m_TokenVec.end(); iter++)
		{
			/* add the token name to the list ctrl */
			memset(&lvi, '\0', sizeof(LVITEM));
			lvi.mask = LVIF_TEXT | LVIF_PARAM;
			lvi.iItem = iCount++;
			lvi.pszText = iter->szTokenName.rawData();
			lvi.lParam = iter->id;
			index = ListView_InsertItem(m_hwndListView, &lvi);

			/* add the token type to the list ctrl */
			ListView_SetItemText(m_hwndListView, index, 1, iter->szProviderType.rawData());

			/* if enabled, add the slot id to the list ctrl */
			if (m_bShowSlots) {
				slot.clear();
				slot << iter->serialNumber.ToHexString();
				ListView_SetItemText(m_hwndListView, index, 2, slot.rawData());
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
		//        EndDialog(IDOK);
		//    }
		//
	} // end FetchTokenInfo
	void FreeTokenInfo()
	{
		m_TokenVec.clear();
	} // end FreeTokenInfo
	int  GetTokenItemParam(int index)
	{
		LVITEM lvi;

		if (index == -1)
		{
			LOG(DebugError, "Attempting to get the ItemData for index -1");
			return -1;
		}

		memset(&lvi, 0, sizeof(lvi));
		lvi.mask = LVIF_PARAM;
		lvi.lParam = -1;
		lvi.iItem = index;
		if (!ListView_GetItem(m_hwndListView, &lvi))
		{
			//LOG(DebugError , "Failed to get the ItemData for index " << index );
			return -1;
		}
		return (int)lvi.lParam;
	}
	int  GetTokenIndex(int itemId)
	{
		int count, index;

		count = ListView_GetItemCount(m_hwndListView);

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
			TSRETURN_ERROR_V(("Attempting to update the text for index %d with text '%s'", index, text.c_str()));
			return;
		}

		if (!IsWindow(m_hwndListView))
		{
			TSRETURN_ERROR_V(("Invalid list window detected [%p]", m_hwndListView));
			return;
		}
		LV_ITEMA _lvi;

		memset(&_lvi, 0, sizeof(_lvi));
		_lvi.iSubItem = 0;
		_lvi.mask = LVIF_TEXT;
		_lvi.pszText = (char *)text.c_str();
		if (!SendMessage(m_hwndListView, LVM_SETITEMTEXT, index, (LPARAM)&_lvi))
		{
			TSRETURN_ERROR_V(("Unable to update the token list with text '%s' for index %d", text.c_str(), index));
			return;
		}

		TSRETURN_V(("Updated index %d with text '%s'", index, text.c_str()));
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

	static intptr_t CALLBACK	TokenSelectorProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
	{
		TokenSelector *params = (TokenSelector*)GetWindowLongPtr(hDlg, DWLP_USER);

		switch (msg)
		{
		case WM_INITDIALOG:
			params = (TokenSelector*)lParam;

			SetWindowLongPtr(hDlg, DWLP_USER, lParam);
			EnableWindow(GetDlgItem(hDlg, IDOK), FALSE);

			{
				HWINSTA station = GetProcessWindowStation();
				DWORD count;
				char buff[MAX_PATH + 1] = { 0, };

				memset(buff, 0, sizeof(buff));
				GetUserObjectInformationA(station, UOI_NAME, buff, sizeof(buff), &count);
				if (strstr(buff, "WinSta0") == NULL)
				{
					EndDialog(hDlg, IDCANCEL);
				}
			}
			params->hDlg = hDlg;
			return params->OnInitDialog();

		case WM_DESTROY:
			params->OnWmDestroy();
			break;

		case WM_COMMAND:
			if (HIWORD(wParam) == BN_CLICKED)
			{
				switch (LOWORD(wParam))
				{
				case IDREFRESH:
					return params->OnRefresh();
				case IDOK:
					return params->OnOK();
				case IDCANCEL:
					return params->OnCancel();
				}
			}
			break;
		case WM_NOTIFY:
		{
			NMHDR *hdr = (NMHDR*)lParam;

			if (wParam == IDC_TOKEN_LIST)
			{
				if (hdr->code == LVN_ITEMCHANGED)
				{
					return params->OnListItemChanged();
				}
				if (hdr->code == LVN_ITEMACTIVATE)
				{
					return params->OnListItemActivate();
				}
				if (hdr->code == NM_DBLCLK)
				{
					return params->OnListItemDoubleclick();
				}
			}
		}
		break;

		}
		return FALSE;
	}
	std::shared_ptr<IKeyVEILConnector> _connector;
	HWND                 hDlg;
	HWND                 hParent;
	GUID                 m_enterpriseOID;
	// TODO:  Implement change detection std::shared_ptr<ICkmChangeConsumer> m_tokenChange;
	int m_tokenChangeCookie;
	HWND                 m_hwndListView;
	DWORD                m_nLVWidth;
	bool                 m_bShowSlots;
	TokenVec             m_TokenVec;
	BOOL                 bInitialized;
	int                  m_nSelectionIndex;
	tscrypto::tsCryptoString              m_reason;
	long                 _nextId;
};

tsmod::IObject* CreateTokenSelector()
{
	return dynamic_cast<tsmod::IObject*>(new TokenSelector());
}