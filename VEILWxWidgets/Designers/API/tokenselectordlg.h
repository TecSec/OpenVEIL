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

#ifndef _TOKENSELECTOR_H_
#define _TOKENSELECTOR_H_


/*!
 * Includes
 */

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
#define SYMBOL_TOKENSELECTORDLG_STYLE wxDEFAULT_DIALOG_STYLE|wxCAPTION|wxRESIZE_BORDER|wxTAB_TRAVERSAL
#define SYMBOL_TOKENSELECTORDLG_TITLE _("Token Selector")
#define SYMBOL_TOKENSELECTORDLG_IDNAME ID_TOKENSELECTOR
#define SYMBOL_TOKENSELECTORDLG_SIZE wxSize(400, 300)
#define SYMBOL_TOKENSELECTORDLG_POSITION wxDefaultPosition
////@end control identifiers


/*!
 * TokenSelectorDlg class declaration
 */

class TokenSelectorDlg: public wxDialog
{    
    DECLARE_DYNAMIC_CLASS( TokenSelectorDlg )
    DECLARE_EVENT_TABLE()

public:
    /// Constructors
    TokenSelectorDlg();
    TokenSelectorDlg( wxWindow* parent, wxWindowID id = SYMBOL_TOKENSELECTORDLG_IDNAME, const wxString& caption = SYMBOL_TOKENSELECTORDLG_TITLE, const wxPoint& pos = SYMBOL_TOKENSELECTORDLG_POSITION, const wxSize& size = SYMBOL_TOKENSELECTORDLG_SIZE, long style = SYMBOL_TOKENSELECTORDLG_STYLE );

    /// Creation
    bool Create( wxWindow* parent, wxWindowID id = SYMBOL_TOKENSELECTORDLG_IDNAME, const wxString& caption = SYMBOL_TOKENSELECTORDLG_TITLE, const wxPoint& pos = SYMBOL_TOKENSELECTORDLG_POSITION, const wxSize& size = SYMBOL_TOKENSELECTORDLG_SIZE, long style = SYMBOL_TOKENSELECTORDLG_STYLE );

    /// Destructor
    ~TokenSelectorDlg();

    /// Initialises member variables
    void Init();

    /// Creates the controls and sizers
    void CreateControls();

////@begin TokenSelectorDlg event handler declarations

    /// wxEVT_INIT_DIALOG event handler for ID_TOKENSELECTOR
    void OnInitDialog( wxInitDialogEvent& event );

    /// wxEVT_COMMAND_LIST_ITEM_SELECTED event handler for ID_TOKENS
    void OnTokensSelected( wxListEvent& event );

    /// wxEVT_COMMAND_LIST_ITEM_DESELECTED event handler for ID_TOKENS
    void OnTokensDeselected( wxListEvent& event );

    /// wxEVT_COMMAND_LIST_ITEM_ACTIVATED event handler for ID_TOKENS
    void OnTokensItemActivated( wxListEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK
    void OnOkClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL
    void OnCancelClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_HELP
    void OnHelpClick( wxCommandEvent& event );

////@end TokenSelectorDlg event handler declarations

////@begin TokenSelectorDlg member function declarations

    /// Retrieves bitmap resources
    wxBitmap GetBitmapResource( const wxString& name );

    /// Retrieves icon resources
    wxIcon GetIconResource( const wxString& name );
////@end TokenSelectorDlg member function declarations

    /// Should we show tooltips?
    static bool ShowToolTips();

////@begin TokenSelectorDlg member variables
    wxStaticText* lblExplanation;
    wxListCtrl* lstTokens;
    wxButton* btnOK;
    wxButton* btnCancel;
////@end TokenSelectorDlg member variables

	wxImageList images;
	tokenSelectorVariables* _vars;

	typedef struct TokenVecEntry {
		tscrypto::tsCryptoString szTokenName;
		tscrypto::tsCryptoString szProviderType;
		GUID tokenId;
		GUID enterpriseId;
		int id;
		tscrypto::tsCryptoData serialNumber;
	} TokenVecEntry;

	typedef std::vector<TokenVecEntry> TokenVec;
	TokenVec             m_TokenVec;
	DWORD                m_nLVWidth;
	bool                 m_bShowSlots;
	std::shared_ptr<IKeyVEILSession> _session;
	long                 _nextId;


	void setVariables(tokenSelectorVariables* inVars);
	void OnRefresh();
	void InitListView();
	void InsertListViewItems();
	void FetchTokenInfo();
	void FreeTokenInfo();
	int  GetTokenItemParam(int index);
	int  GetTokenIndex(int itemId);
	void UpdateItemText(int index, const tscrypto::tsCryptoString& text);
	void AddTokenVecForToken(const tscrypto::tsCryptoData& serialNumber);
	std::shared_ptr<IKeyVEILSession> Session();
};

#endif
    // _TOKENSELECTOR_H_
