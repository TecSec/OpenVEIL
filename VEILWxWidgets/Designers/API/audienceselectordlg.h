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

#ifndef _AUDIENCESELECTOR_H_
#define _AUDIENCESELECTOR_H_


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
#define ID_AUDIENCESELECTOR 10000
#define ID_FAVORITELIST 10001
#define ID_TOKENLIST 10002
#define ID_LOGIN_TOKEN 10003
#define ID_LISTBOX 10004
#define ID_ADD 10005
#define ID_EDIT 10006
#define ID_DELETE 10007
#define ID_CREATE_FAVORITE 10008
#define ID_DELETE_FAVORITE 10009
#define SYMBOL_AUDIENCESELECTORDLG_STYLE wxDEFAULT_DIALOG_STYLE|wxCAPTION|wxRESIZE_BORDER|wxTAB_TRAVERSAL
#define SYMBOL_AUDIENCESELECTORDLG_TITLE _("Audience Selector")
#define SYMBOL_AUDIENCESELECTORDLG_IDNAME ID_AUDIENCESELECTOR
#define SYMBOL_AUDIENCESELECTORDLG_SIZE wxSize(400, 350)
#define SYMBOL_AUDIENCESELECTORDLG_POSITION wxDefaultPosition
////@end control identifiers


/*!
 * AudienceSelectorDlg class declaration
 */

class AudienceSelectorDlg: public wxDialog
{    
    DECLARE_DYNAMIC_CLASS( AudienceSelectorDlg )
    DECLARE_EVENT_TABLE()

public:
    /// Constructors
    AudienceSelectorDlg();
    AudienceSelectorDlg( wxWindow* parent, wxWindowID id = SYMBOL_AUDIENCESELECTORDLG_IDNAME, const wxString& caption = SYMBOL_AUDIENCESELECTORDLG_TITLE, const wxPoint& pos = SYMBOL_AUDIENCESELECTORDLG_POSITION, const wxSize& size = SYMBOL_AUDIENCESELECTORDLG_SIZE, long style = SYMBOL_AUDIENCESELECTORDLG_STYLE );

    /// Creation
    bool Create( wxWindow* parent, wxWindowID id = SYMBOL_AUDIENCESELECTORDLG_IDNAME, const wxString& caption = SYMBOL_AUDIENCESELECTORDLG_TITLE, const wxPoint& pos = SYMBOL_AUDIENCESELECTORDLG_POSITION, const wxSize& size = SYMBOL_AUDIENCESELECTORDLG_SIZE, long style = SYMBOL_AUDIENCESELECTORDLG_STYLE );

    /// Destructor
    ~AudienceSelectorDlg();

    /// Initialises member variables
    void Init();

    /// Creates the controls and sizers
    void CreateControls();

////@begin AudienceSelectorDlg event handler declarations

    /// wxEVT_INIT_DIALOG event handler for ID_AUDIENCESELECTOR
    void OnInitDialog( wxInitDialogEvent& event );

    /// wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_FAVORITELIST
    void OnFavoritelistSelected( wxCommandEvent& event );

    /// wxEVT_COMMAND_CHOICE_SELECTED event handler for ID_TOKENLIST
    void OnTokenlistSelected( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_LOGIN_TOKEN
    void OnLoginTokenClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_LISTBOX_SELECTED event handler for ID_LISTBOX
    void OnListboxSelected( wxCommandEvent& event );

    /// wxEVT_COMMAND_LISTBOX_DOUBLECLICKED event handler for ID_LISTBOX
    void OnListboxDoubleClicked( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_ADD
    void OnAddClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_EDIT
    void OnEditClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_DELETE
    void OnDeleteClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_CREATE_FAVORITE
    void OnCreateFavoriteClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_DELETE_FAVORITE
    void OnDeleteFavoriteClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK
    void OnOkClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL
    void OnCancelClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_HELP
    void OnHelpClick( wxCommandEvent& event );

////@end AudienceSelectorDlg event handler declarations

////@begin AudienceSelectorDlg member function declarations

    /// Retrieves bitmap resources
    wxBitmap GetBitmapResource( const wxString& name );

    /// Retrieves icon resources
    wxIcon GetIconResource( const wxString& name );
////@end AudienceSelectorDlg member function declarations

    /// Should we show tooltips?
    static bool ShowToolTips();

////@begin AudienceSelectorDlg member variables
    wxChoice* cmbFavorites;
    wxChoice* cmbTokens;
    wxButton* _btnLogin;
    wxListBox* lstGroups;
    wxButton* btnAdd;
    wxButton* btnEdit;
    wxButton* btnDelete;
    wxButton* btnCreateFavorite;
    wxButton* btnDeleteFavorite;
    wxButton* btnOK;
    wxButton* btnCancel;
    wxButton* btnHelp;
////@end AudienceSelectorDlg member variables

    audienceSelector2Variables* _vars;
    int												_CurFavIndex;
    Asn1::CTS::_POD_CryptoGroup*					_ActiveCryptoGroup;
    int												_LastTokenSelection;
	bool											_initialized;
	std::shared_ptr<Asn1::CTS::_POD_Profile>		_profile;
	std::shared_ptr<IFavorite>						_favorite;
	std::vector<tscrypto::tsCryptoData>				_tokenSerialNumbers;
	std::vector<GUID>								_guidMap;

    void setVariables(audienceSelector2Variables* inVars);
	void InitSettings();
	void resetConsumer();
	Asn1::CTS::_POD_CryptoGroup* GetCGbyGuid(const GUID& id);
	int findCgByGuid(const GUID& id);
	bool LoadFavoriteForToken(std::shared_ptr<IFavorite> fav, std::shared_ptr<ICmsHeader> favHeader);
	void ClearAccessGroups();
	tscrypto::tsCryptoString BuildAttrsLine(std::shared_ptr<ICmsHeaderAttributeGroup> attrs);
	bool RebuildAccessGroupList();
	void SetItemSelected(int index);
	void AddGroupText(const char *text);
	bool QueryAndClearAccessGroups();
	bool ChangeToken();
	void UpdateDialogControls();
	void EnableDisableOK();
	bool InitTokenInfoList();
	void InitTokenComboBox();
	void OnTokenAdd(const tscrypto::tsCryptoData& serialNumber);
	void OnTokenRemove(const tscrypto::tsCryptoData& serialNumber);
	void OnTokenAdd(wxTokenEvent& event);
	void OnTokenRemove(wxTokenEvent& event);
	bool CheckAccessGroup(std::shared_ptr<ICmsHeaderAttributeGroup> newAttrs);
	void BuildIntList(std::shared_ptr<ICmsHeaderAttributeGroup> attrGroup, tscrypto::tsCryptoData &list);
	bool FindSelectedAccessGroup(std::shared_ptr<ICmsHeaderAccessGroup>& accessGroup, std::shared_ptr<ICmsHeaderAttributeGroup>& attrs);
	int findGuidIndex(const GUID& id, bool insert = false);
	void InitFavorites();
	void OnInitFavorites(wxCommandEvent& event);
	int  FindTokenOnComboBox(const tscrypto::tsCryptoData& serialNumber);
	std::shared_ptr<Asn1::CTS::_POD_Profile> GetProfile();
	bool HasProfile();
};

#endif
    // _AUDIENCESELECTOR_H_
