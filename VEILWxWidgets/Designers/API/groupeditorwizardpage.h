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

#ifndef _GROUPEDITORWIZARDPAGE_H_
#define _GROUPEDITORWIZARDPAGE_H_


/*!
 * Includes
 */

////@begin includes
#include "wx/wizard.h"
#include "wx/htmllbox.h"
////@end includes

/*!
 * Forward declarations
 */

////@begin forward declarations
class GroupEditorWizardPage;
class wxSimpleHtmlListBox;
////@end forward declarations

/*!
 * Control identifiers
 */

////@begin control identifiers
#define ID_SELECT_AUDIENCES 10003
#define ID_GROUP_LIST 10009
#define ID_ADD_GROUP 10010
#define ID_EDIT_GROUP 10011
#define ID_DELETE_GROUP 10012
////@end control identifiers


/*!
 * GroupEditorWizardPage class declaration
 */

class GroupEditorWizardPage: public wxWizardPageSimple
{    
    DECLARE_DYNAMIC_CLASS( GroupEditorWizardPage )
    DECLARE_EVENT_TABLE()

public:
    /// Constructors
    GroupEditorWizardPage();

    GroupEditorWizardPage( wxWizard* parent );

    /// Creation
    bool Create( wxWizard* parent );

    /// Destructor
    ~GroupEditorWizardPage();

    /// Initialises member variables
    void Init();

    /// Creates the controls and sizers
    void CreateControls();

////@begin GroupEditorWizardPage event handler declarations

    /// wxEVT_WIZARD_PAGE_CHANGED event handler for ID_SELECT_AUDIENCES
    void OnSelectAudiencesPageChanged( wxWizardEvent& event );

    /// wxEVT_WIZARD_PAGE_CHANGING event handler for ID_SELECT_AUDIENCES
    void OnSelectAudiencesPageChanging( wxWizardEvent& event );

    /// wxEVT_WIZARD_FINISHED event handler for ID_SELECT_AUDIENCES
    void OnSelectAudiencesFinished( wxWizardEvent& event );

    /// wxEVT_WIZARD_HELP event handler for ID_SELECT_AUDIENCES
    void OnSelectAudiencesHelp( wxWizardEvent& event );

    /// wxEVT_COMMAND_LISTBOX_SELECTED event handler for ID_GROUP_LIST
    void OnGroupListSelected( wxCommandEvent& event );

    /// wxEVT_COMMAND_LISTBOX_DOUBLECLICKED event handler for ID_GROUP_LIST
    void OnGroupListDoubleClicked( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_ADD_GROUP
    void OnAddGroupClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_EDIT_GROUP
    void OnEditGroupClick( wxCommandEvent& event );

    /// wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_DELETE_GROUP
    void OnDeleteGroupClick( wxCommandEvent& event );

////@end GroupEditorWizardPage event handler declarations

////@begin GroupEditorWizardPage member function declarations

    /// Gets the previous page
    virtual wxWizardPage* GetPrev() const;

    /// Gets the next page
    virtual wxWizardPage* GetNext() const;

    /// Retrieves bitmap resources
    wxBitmap GetBitmapResource( const wxString& name );

    /// Retrieves icon resources
    wxIcon GetIconResource( const wxString& name );
////@end GroupEditorWizardPage member function declarations

    /// Should we show tooltips?
    static bool ShowToolTips();

////@begin GroupEditorWizardPage member variables
    wxSimpleHtmlListBox* _groupList;
    wxButton* _btnAdd;
    wxButton* _btnEdit;
    wxButton* _btnDelete;
////@end GroupEditorWizardPage member variables
	Asn1::CTS::_POD_CryptoGroup* _ActiveCryptoGroup;
	std::shared_ptr<Asn1::CTS::_POD_Profile>		_profile;
	wxWizardPage* nextPage;
	wxWizardPage* prevPage;
	void SetNextPage(wxWizardPage* setTo) { nextPage = setTo; }
	void SetPrevPage(wxWizardPage* setTo) { prevPage = setTo; }

protected:
	int findCgByGuid(const GUID& id);
	Asn1::CTS::_POD_CryptoGroup* GetCGbyGuid(const GUID& id);
	std::shared_ptr<IKeyVEILSession> Session();
	bool HasSession() const;
	void Session(std::shared_ptr<IKeyVEILSession> setTo);
	std::shared_ptr<Asn1::CTS::_POD_Profile> GetProfile();
	bool HasProfile();
	bool RebuildAccessGroupList();
	tscrypto::tsCryptoString BuildAttrsLine(std::shared_ptr<ICmsHeaderAttributeGroup> attrs, bool isFirstLine);
	void AddGroupText(const char *text);
	void UpdateDialogControls();
	void SetItemSelected(int index);
	bool CheckAccessGroup(std::shared_ptr<ICmsHeaderAttributeGroup> newAttrs);
	void BuildIntList(std::shared_ptr<ICmsHeaderAttributeGroup> attrGroup, tscrypto::tsCryptoData &list);
	void EnableDisableOK();
	bool FindSelectedAccessGroup(std::shared_ptr<ICmsHeaderAccessGroup>& accessGroup, std::shared_ptr<ICmsHeaderAttributeGroup>& attrs);
};

#endif
    // _GROUPEDITORWIZARDPAGE_H_
