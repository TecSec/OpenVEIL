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

#ifndef _GENERALSETTINGSHANDLER_H_
#define _GENERALSETTINGSHANDLER_H_


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
#define ID_GENERALSETTINGSHANDLER 10000
#define ID_URL 10001
#define ID_USERNAME 10002
#define ID_ENCRYPTION 10003
#define ID_HASH 10004
#define ID_APP_IDS 10005
#define SYMBOL_GENERALSETTINGSPROPERTYPAGE_STYLE wxTAB_TRAVERSAL
#define SYMBOL_GENERALSETTINGSPROPERTYPAGE_TITLE _("General Settings")
#define SYMBOL_GENERALSETTINGSPROPERTYPAGE_IDNAME ID_GENERALSETTINGSHANDLER
#define SYMBOL_GENERALSETTINGSPROPERTYPAGE_SIZE wxSize(460, 290)
#define SYMBOL_GENERALSETTINGSPROPERTYPAGE_POSITION wxDefaultPosition
////@end control identifiers


/*!
 * GeneralSettingsPropertyPage class declaration
 */

class GeneralSettingsPropertyPage: public wxPanel
{    
    DECLARE_DYNAMIC_CLASS( GeneralSettingsPropertyPage )
    DECLARE_EVENT_TABLE()

public:
    /// Constructors
    GeneralSettingsPropertyPage();
    GeneralSettingsPropertyPage( wxWindow* parent, wxWindowID id = SYMBOL_GENERALSETTINGSPROPERTYPAGE_IDNAME, const wxString& caption = SYMBOL_GENERALSETTINGSPROPERTYPAGE_TITLE, const wxPoint& pos = SYMBOL_GENERALSETTINGSPROPERTYPAGE_POSITION, const wxSize& size = SYMBOL_GENERALSETTINGSPROPERTYPAGE_SIZE, long style = SYMBOL_GENERALSETTINGSPROPERTYPAGE_STYLE );

    /// Creation
    bool Create( wxWindow* parent, wxWindowID id = SYMBOL_GENERALSETTINGSPROPERTYPAGE_IDNAME, const wxString& caption = SYMBOL_GENERALSETTINGSPROPERTYPAGE_TITLE, const wxPoint& pos = SYMBOL_GENERALSETTINGSPROPERTYPAGE_POSITION, const wxSize& size = SYMBOL_GENERALSETTINGSPROPERTYPAGE_SIZE, long style = SYMBOL_GENERALSETTINGSPROPERTYPAGE_STYLE );

    /// Destructor
    ~GeneralSettingsPropertyPage();

    /// Initialises member variables
    void Init();

    /// Creates the controls and sizers
    void CreateControls();

////@begin GeneralSettingsPropertyPage event handler declarations

    /// wxEVT_COMMAND_TEXT_UPDATED event handler for ID_URL
    void OnUrlTextUpdated( wxCommandEvent& event );

    /// wxEVT_COMMAND_TEXT_UPDATED event handler for ID_USERNAME
    void OnUsernameTextUpdated( wxCommandEvent& event );

    /// wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_ENCRYPTION
    void OnEncryptionSelected( wxCommandEvent& event );

    /// wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_HASH
    void OnHashSelected( wxCommandEvent& event );

    /// wxEVT_COMMAND_TEXT_UPDATED event handler for ID_APP_IDS
    void OnAppIdsTextUpdated( wxCommandEvent& event );

////@end GeneralSettingsPropertyPage event handler declarations

////@begin GeneralSettingsPropertyPage member function declarations

    /// Retrieves bitmap resources
    wxBitmap GetBitmapResource( const wxString& name );

    /// Retrieves icon resources
    wxIcon GetIconResource( const wxString& name );
////@end GeneralSettingsPropertyPage member function declarations

    /// Should we show tooltips?
    static bool ShowToolTips();

////@begin GeneralSettingsPropertyPage member variables
    wxTextCtrl* edtKeyVEILUrl;
    wxTextCtrl* edtKeyVEILUsername;
    wxChoice* cmbEncryption;
    wxChoice* cmbHash;
    wxTextCtrl* edtAIDList;
////@end GeneralSettingsPropertyPage member variables
	std::weak_ptr<IVEILPropertySheet> _parentSheet;
	std::shared_ptr<BasicVEILPreferences> _prefs;
	bool _bDirty;
	tscrypto::TS_ALG_ID _Alg;
	tscrypto::TS_ALG_ID _HashAlg;
	tscrypto::tsCryptoString _url;
	tscrypto::tsCryptoString _username;
	tscrypto::tsCryptoString _aidList;
	bool _bDisplayMsgDlg;
	bool _bInitialized;

	void DisablePolicyField(wxWindow* hWnd, JsonConfigLocation location);
	void OnInitialize();
	void Initialization();
	void UpdateData(bool fromControls);
	int FindAlgByID(tscrypto::TS_ALG_ID alg);
	int FindHashAlgByID(tscrypto::TS_ALG_ID alg);
	void SetModified(BOOL bChanged = TRUE);

};

#endif
    // _GENERALSETTINGSHANDLER_H_
