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
////@end includes

////@begin XPM images
////@end XPM images


/*
* GroupEditorWizardPage type definition
*/

IMPLEMENT_DYNAMIC_CLASS( GroupEditorWizardPage, wxWizardPageSimple )


/*
* GroupEditorWizardPage event table definition
*/

BEGIN_EVENT_TABLE(GroupEditorWizardPage, wxWizardPageSimple)

////@begin GroupEditorWizardPage event table entries
    EVT_WIZARD_PAGE_CHANGED( -1, GroupEditorWizardPage::OnSelectAudiencesPageChanged )
    EVT_WIZARD_PAGE_CHANGING( -1, GroupEditorWizardPage::OnSelectAudiencesPageChanging )
    EVT_WIZARD_FINISHED( ID_SELECT_AUDIENCES, GroupEditorWizardPage::OnSelectAudiencesFinished )
    EVT_WIZARD_HELP( -1, GroupEditorWizardPage::OnSelectAudiencesHelp )
    EVT_LISTBOX( ID_GROUP_LIST, GroupEditorWizardPage::OnGroupListSelected )
    EVT_LISTBOX_DCLICK( ID_GROUP_LIST, GroupEditorWizardPage::OnGroupListDoubleClicked )
    EVT_BUTTON( ID_ADD_GROUP, GroupEditorWizardPage::OnAddGroupClick )
    EVT_BUTTON( ID_EDIT_GROUP, GroupEditorWizardPage::OnEditGroupClick )
    EVT_BUTTON( ID_DELETE_GROUP, GroupEditorWizardPage::OnDeleteGroupClick )
////@end GroupEditorWizardPage event table entries

END_EVENT_TABLE()


/*
* GroupEditorWizardPage constructors
*/

GroupEditorWizardPage::GroupEditorWizardPage() : nextPage(nullptr), prevPage(nullptr)

{
    Init();
}

GroupEditorWizardPage::GroupEditorWizardPage(wxWizard* parent) : nextPage(nullptr), prevPage(nullptr)
{
    Init();
    Create(parent);
}


/*
 * GroupEditorWizardPage creator
 */

bool GroupEditorWizardPage::Create( wxWizard* parent )
{
////@begin GroupEditorWizardPage creation
    SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY);
    wxBitmap wizardBitmap(wxNullBitmap);
    wxWizardPage::Create( parent, wizardBitmap );

    CreateControls();
    if (GetSizer())
        GetSizer()->Fit(this);
////@end GroupEditorWizardPage creation
    return true;
}


/*
 * GroupEditorWizardPage destructor
 */

GroupEditorWizardPage::~GroupEditorWizardPage()
{
////@begin GroupEditorWizardPage destruction
////@end GroupEditorWizardPage destruction
}


/*
 * Member initialisation
 */

void GroupEditorWizardPage::Init()
{
////@begin GroupEditorWizardPage member initialisation
    _groupList = NULL;
    _btnAdd = NULL;
    _btnEdit = NULL;
    _btnDelete = NULL;
////@end GroupEditorWizardPage member initialisation
    _ActiveCryptoGroup = nullptr;
}


/*
 * Control creation for GroupEditorWizardPage
 */

void GroupEditorWizardPage::CreateControls()
{    
////@begin GroupEditorWizardPage content construction
    GroupEditorWizardPage* itemWizardPage1 = this;

    wxFlexGridSizer* itemFlexGridSizer2 = new wxFlexGridSizer(4, 1, 0, 0);
    itemWizardPage1->SetSizer(itemFlexGridSizer2);

    wxStaticText* itemStaticText3 = new wxStaticText( itemWizardPage1, wxID_STATIC, _("Select Access Groups"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStaticText3->SetFont(wxFont(8, wxFONTFAMILY_SWISS, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD, false, wxT("Tahoma")));
    itemFlexGridSizer2->Add(itemStaticText3, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStaticText* itemStaticText4 = new wxStaticText( itemWizardPage1, wxID_STATIC, _("Here is the list of access groups.  Press the 'Add' button to add another access group"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer2->Add(itemStaticText4, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxArrayString _groupListStrings;
    _groupList = new wxSimpleHtmlListBox( itemWizardPage1, ID_GROUP_LIST, wxDefaultPosition, wxDefaultSize, _groupListStrings, wxHLB_DEFAULT_STYLE );
    if (GroupEditorWizardPage::ShowToolTips())
        _groupList->SetToolTip(_("The current access groups are displayed here."));
    itemFlexGridSizer2->Add(_groupList, 0, wxGROW|wxALL, 5);

    wxFlexGridSizer* itemFlexGridSizer6 = new wxFlexGridSizer(1, 5, 0, 0);
    itemFlexGridSizer2->Add(itemFlexGridSizer6, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    itemFlexGridSizer6->Add(5, 5, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    _btnAdd = new wxButton( itemWizardPage1, ID_ADD_GROUP, _("Add..."), wxDefaultPosition, wxDefaultSize, 0 );
    if (GroupEditorWizardPage::ShowToolTips())
        _btnAdd->SetToolTip(_("Add another access group to the encryption recipe."));
    itemFlexGridSizer6->Add(_btnAdd, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    _btnEdit = new wxButton( itemWizardPage1, ID_EDIT_GROUP, _("Edit..."), wxDefaultPosition, wxDefaultSize, 0 );
    if (GroupEditorWizardPage::ShowToolTips())
        _btnEdit->SetToolTip(_("Edit the currently selected access group."));
    itemFlexGridSizer6->Add(_btnEdit, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxRIGHT|wxTOP|wxBOTTOM, 5);

    _btnDelete = new wxButton( itemWizardPage1, ID_DELETE_GROUP, _("Delete..."), wxDefaultPosition, wxDefaultSize, 0 );
    if (GroupEditorWizardPage::ShowToolTips())
        _btnDelete->SetToolTip(_("Delete the currently selected access group."));
    itemFlexGridSizer6->Add(_btnDelete, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxRIGHT|wxTOP|wxBOTTOM, 5);

    itemFlexGridSizer6->Add(5, 5, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    itemFlexGridSizer6->AddGrowableCol(0);
    itemFlexGridSizer6->AddGrowableCol(4);

    itemFlexGridSizer2->AddGrowableRow(2);
    itemFlexGridSizer2->AddGrowableCol(0);

////@end GroupEditorWizardPage content construction
}

/*
 * wxEVT_WIZARD_PAGE_CHANGED event handler for ID_SELECT_AUDIENCES
 */

void GroupEditorWizardPage::OnSelectAudiencesPageChanged( wxWizardEvent& event )
{
	event.Skip();
	_groupList->Enable(true);
	_btnAdd->Enable(true);
	_btnEdit->Enable(true);
	_btnDelete->Enable(true);

	if (!HasProfile())
	{
        wxBusyCursor busyCursor;
        wxWindowDisabler disabler;
        wxBusyInfo busyInfo(_("Retrieving token information..."));

        GetProfile();
    }
    if (HasProfile())
    {
        GUID cgID = GetProfile()->get_EnterpriseCryptoGroup();
		AudienceSelector2* wiz = dynamic_cast<AudienceSelector2*>(GetParent());

        _ActiveCryptoGroup = GetCGbyGuid(cgID);

		if (!!wiz->_vars->_header)
		{
			std::shared_ptr<ICmsHeaderCryptoGroup> group;

			// Validate the header here
			if (wiz->_vars->_header->GetCryptoGroupCount() == 0)
			{
				int val;
				wiz->_vars->_header->AddCryptoGroup(cgID, &val);
			}
			else if (!wiz->_vars->_header->GetCryptoGroupByGuid(cgID, group))
			{
				std::shared_ptr<ICmsHeaderExtension> ext;
				std::shared_ptr<ICmsHeaderAccessGroupExtension> groupList;
				int groupCount = 0;

				if (!!wiz->_vars->_header->GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext))
				{
					if (!!(groupList = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(ext)))
					{
						groupCount = groupList->GetAccessGroupCount();
					}
				}
				ext.reset();

				if (groupCount == 0)
				{
					wiz->_vars->_header->ClearCryptoGroupList();
					int val;
					wiz->_vars->_header->AddCryptoGroup(cgID, &val);
				}
				else
				{
					// TODO:  Disable or clear?

					if (wxTsMessageBox("The current token is for a different enterprise.  Do you want to clear this audience?", "Question", wxYES_NO | wxICON_QUESTION, (XP_WINDOW)this) == wxID_YES)
					{
						wiz->_vars->_header->Clear();
					}
					else
					{
						//_groupList->Enable(false);
						_btnAdd->Enable(false);
						_btnEdit->Enable(false);
						_btnDelete->Enable(false);
					}
				}
			}
		}

        RebuildAccessGroupList();
    }
	UpdateDialogControls();
}


/*
 * wxEVT_WIZARD_PAGE_CHANGING event handler for ID_SELECT_AUDIENCES
 */

void GroupEditorWizardPage::OnSelectAudiencesPageChanging( wxWizardEvent& event )
{
////@begin wxEVT_WIZARD_PAGE_CHANGING event handler for ID_SELECT_AUDIENCES in GroupEditorWizardPage.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_WIZARD_PAGE_CHANGING event handler for ID_SELECT_AUDIENCES in GroupEditorWizardPage. 
}


/*
 * wxEVT_WIZARD_FINISHED event handler for ID_SELECT_AUDIENCES
 */

void GroupEditorWizardPage::OnSelectAudiencesFinished( wxWizardEvent& event )
{
////@begin wxEVT_WIZARD_FINISHED event handler for ID_SELECT_AUDIENCES in GroupEditorWizardPage.
    // Before editing this code, remove the block markers.
    event.Skip();
////@end wxEVT_WIZARD_FINISHED event handler for ID_SELECT_AUDIENCES in GroupEditorWizardPage. 
}


/*
 * wxEVT_WIZARD_HELP event handler for ID_SELECT_AUDIENCES
 */

void GroupEditorWizardPage::OnSelectAudiencesHelp( wxWizardEvent& event )
{
	std::shared_ptr<IVEILHttpHelpRegistry> help = ::TopServiceLocator()->get_instance<IVEILHttpHelpRegistry>("/WxWin/HelpRegistry");
	AudienceSelector2* wiz = dynamic_cast<AudienceSelector2*>(GetParent());

	if (!help)
	{
		wxTsMessageBox(("Help is not available at this time."), ("Status"), wxOK);
	}
	else
	{
		if (wiz != nullptr && wiz->_vars != nullptr && wiz->_vars->_favoriteId != GUID_NULL)
		{
			help->DisplayHelpForWindowId(winid_FavEdit_GroupEditorPage, (XP_WINDOW)this);
		}
		else if (wiz != nullptr && wiz->_vars != nullptr && wiz->_vars->_favoriteManager)
		{
			help->DisplayHelpForWindowId(winid_FavAdd_GroupEditorPage, (XP_WINDOW)this);
		}
		else
			help->DisplayHelpForWindowId(winid_GroupEditorPage, (XP_WINDOW)this);
	}
}


/*
 * wxEVT_COMMAND_LISTBOX_SELECTED event handler for ID_GROUP_LIST
 */

void GroupEditorWizardPage::OnGroupListSelected( wxCommandEvent& event )
{
    UpdateDialogControls();
}


/*
 * wxEVT_COMMAND_LISTBOX_DOUBLECLICKED event handler for ID_GROUP_LIST
 */

void GroupEditorWizardPage::OnGroupListDoubleClicked( wxCommandEvent& event )
{
    OnEditGroupClick(event);
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_ADD_GROUP
 */

void GroupEditorWizardPage::OnAddGroupClick( wxCommandEvent& event )
{
	AudienceSelector2* wiz = dynamic_cast<AudienceSelector2*>(GetParent());
	
	// make sure we are logged in to the selected token
    if (!HasSession() || !Session()->IsLoggedIn())
    {
		wxTsMessageBox("You need to select a token first.", "Error", wxICON_HAND | wxOK);
        return;
    }

    // make sure we have the CryptoGroup object
    if (_ActiveCryptoGroup == nullptr)
    {
		wxTsMessageBox("OnGroupAdd: No Crypto Group selected, or selected Crypto Group is invalid.", "Error", wxICON_HAND | wxOK);
        return;
    }

    if (wiz == nullptr || wiz->_vars == nullptr || !wiz->_vars->_header)
    {
        //ConstructHeader();
        //if (!_header)
        return;
    }

    std::shared_ptr<ICmsHeaderAccessGroup> andGroup;
    std::shared_ptr<ICmsHeaderAttributeGroup> attrGroup;
    std::shared_ptr<ICmsHeaderExtension> ext;
    std::shared_ptr<ICmsHeaderAccessGroupExtension> groupList;

    if (!wiz->_vars->_header->GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext))
    {
        if (!wiz->_vars->_header->AddProtectedExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), true, ext))
        {
            wxTsMessageBox("OnGroupAdd: Unable to add a new access group list to the CKM Header.", "Error", wxICON_HAND | wxOK);
            return;
        }
    }
    if (!(groupList = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(ext)))
    {
        return;
    }
    ext.reset();

	if (groupList->GetAccessGroupCount() == 0)
	{
		wiz->_vars->_header->ClearCryptoGroupList();
		int val;
		wiz->_vars->_header->AddCryptoGroup(_ActiveCryptoGroup->get_Id(), &val);
	}

    if (!(groupList->AddAccessGroup(ag_Attrs, andGroup)) || !(attrGroup = std::dynamic_pointer_cast<ICmsHeaderAttributeGroup>(andGroup)))
    {
        wxTsMessageBox("OnGroupAdd: Unable to add a new attribute list to the CKM Header.", "Error", wxICON_HAND | wxOK);
        if (!!andGroup)
        {
            groupList->RemoveAccessGroup(groupList->GetAccessGroupCount() - 1);
            andGroup.reset();
        }
        return;
    }

    std::shared_ptr<ICmsHeaderAttributeListExtension> attrList;

    if (!wiz->_vars->_header->GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID), ext))
    {
        if (!wiz->_vars->_header->AddProtectedExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID), true, ext))
        {
            wxTsMessageBox("OnGroupAdd: Unable to add a new attribute list to the CKM Header.", "Error", wxICON_HAND | wxOK);
            return;
        }
    }

    if (!(attrList = std::dynamic_pointer_cast<ICmsHeaderAttributeListExtension>(ext)))
    {
        wxTsMessageBox("OnGroupAdd: Unable to add a new attribute list to the CKM Header.", "Error", wxICON_HAND | wxOK);
        return;
    }
    ext.reset();

    std::shared_ptr<IAttributeSelector> attrSel;

    if (!(attrSel = ::TopServiceLocator()->get_instance<IAttributeSelector>("/WxWin/AttributeSelectorGrid")))
    {
        attrGroup.reset();
        groupList->RemoveAccessGroup(groupList->GetAccessGroupCount() - 1);
        andGroup.reset();
    }
    else
    {
        if (!attrSel->Start(Session(), (XP_WINDOW)this, _ActiveCryptoGroup->get_Id(), attrGroup, attrList) || attrSel->DisplayModal() != wxID_OK)
        {
            attrGroup.reset();
            groupList->RemoveAccessGroup(groupList->GetAccessGroupCount() - 1);
            andGroup.reset();
        }
    }
    if (!!attrGroup)
    {
        // make sure we don't already have an identical access group
        if (!CheckAccessGroup(attrGroup)) {
            attrGroup.reset();
            groupList->RemoveAccessGroup(groupList->GetAccessGroupCount() - 1);
            andGroup.reset();
            wxTsMessageBox("You already have an access group with the same Attributes.", "Error", wxICON_HAND | wxOK);
            return;
        }
    }
    RebuildAccessGroupList();

    EnableDisableOK();
    return;
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_EDIT_GROUP
 */

void GroupEditorWizardPage::OnEditGroupClick( wxCommandEvent& event )
{
    int index;
	AudienceSelector2* wiz = dynamic_cast<AudienceSelector2*>(GetParent());

    std::shared_ptr<ICmsHeaderAttributeGroup> attrs;
    std::shared_ptr<ICmsHeaderAccessGroup> accessGroup;

    index = _groupList->GetSelection();
    if (-1 == index || wiz == nullptr || wiz->_vars == nullptr) {
        wxTsMessageBox("Unable to edit... No access group is selected.", "Error", wxICON_HAND | wxOK);
        return;
    }

    if (!FindSelectedAccessGroup(accessGroup, attrs))
    {
        wxTsMessageBox("Unable to edit... The selected access group was not located.", "Error", wxICON_HAND | wxOK);
        return;
    }

    std::shared_ptr<ICmsHeader> newHeader;

    if (!(newHeader = ::TopServiceLocator()->get_instance<ICmsHeader>("/CmsHeader")))
    {
        wxTsMessageBox("Unable to edit... Unable to create a CKM Header.", "Error", wxICON_HAND | wxOK);
        return;
    }

    std::shared_ptr<ICmsHeaderAccessGroup> andGroup;
    std::shared_ptr<ICmsHeaderAttributeGroup> attrGroup;
    std::shared_ptr<ICmsHeaderExtension> ext;
    std::shared_ptr<ICmsHeaderAccessGroupExtension> extGroup;

    if (!newHeader->GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext))
    {
        newHeader->AddProtectedExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), true, ext);
    }

    if (!ext || !(extGroup = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(ext)))
    {
        wxTsMessageBox("Unable to delete... The access group list is not available.", "Error", wxICON_HAND | wxOK);
        return;
    }
    ext.reset();

    if (!(extGroup->AddAccessGroup(ag_Attrs, andGroup)) || !(attrGroup = std::dynamic_pointer_cast<ICmsHeaderAttributeGroup>(andGroup)))
    {
        wxTsMessageBox("Unable to edit... Unable to add a new attribute list to the CKM Header.", "Error", wxICON_HAND | wxOK);
        return;
    }
    int count = (int)attrs->GetAttributeCount();
    for (int i = 0; i < count; i++)
    {
        attrGroup->AddAttributeIndex(attrs->GetAttributeIndex(i));
    }

    std::shared_ptr<ICmsHeaderAttributeListExtension> attrsList;

    if (!wiz->_vars->_header->GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID), ext))
    {
        if (!wiz->_vars->_header->AddProtectedExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID), true, ext))
        {
            wxTsMessageBox("Unable to edit... Unable to retrieve the attribute list.", "Error", wxICON_HAND | wxOK);
            return;
        }
    }

    if (!(attrsList = std::dynamic_pointer_cast<ICmsHeaderAttributeListExtension>(ext)))
    {
        wxTsMessageBox("Unable to edit... Unable to retrieve the attribute list.", "Error", wxICON_HAND | wxOK);
        return;
    }
    ext.reset();

    std::shared_ptr<IAttributeSelector> attrSel;

    if (!(attrSel = ::TopServiceLocator()->get_instance<IAttributeSelector>("/WxWin/AttributeSelectorGrid")))
    {
        return;
    }
    if (!attrSel->Start(Session(), (XP_WINDOW)this, _ActiveCryptoGroup->get_Id(), attrGroup, attrsList) || attrSel->DisplayModal() != wxID_OK)
    {
        return;
    }

    count = (int)attrGroup->GetAttributeCount();

    while (attrs->GetAttributeCount() > 0)
        attrs->RemoveAttributeIndex(0);
    for (int i = 0; i < count; i++)
    {
        attrs->AddAttributeIndex(attrGroup->GetAttributeIndex(i));
    }

    RebuildAccessGroupList();

    // remove the access group from the display list,
    SetItemSelected(index);
    UpdateDialogControls();
    EnableDisableOK();

    return;
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for ID_DELETE_GROUP
 */

void GroupEditorWizardPage::OnDeleteGroupClick( wxCommandEvent& event )
{
    int index;
	AudienceSelector2* wiz = dynamic_cast<AudienceSelector2*>(GetParent());

    index = _groupList->GetSelection();
    if (-1 == index)
    {
        wxTsMessageBox("Unable to delete... No access group is selected.", "Error", wxICON_HAND | wxOK);
        return;
    }

    std::shared_ptr<ICmsHeaderExtension> ext;
    std::shared_ptr<ICmsHeaderAccessGroupExtension> extGroup;
    std::shared_ptr<ICmsHeaderAccessGroup> andGroup;

    if (wiz == nullptr || wiz->_vars == nullptr || !wiz->_vars->_header->GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext) ||
        !(extGroup = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(ext)))
    {
        wxTsMessageBox("Unable to delete... The access group list is not available.", "Error", wxICON_HAND | wxOK);
        return;
    }
    ext.reset();

    uint32_t count = (uint32_t)extGroup->GetAccessGroupCount();
    for (uint32_t i = 0; i < count && index >= 0; i++)
    {
        andGroup.reset();
        if ((extGroup->GetAccessGroup(i, andGroup)) && (andGroup->GetAndGroupType() == ag_Attrs))
        {
            if (index == 0)
            {
                if (!(extGroup->RemoveAccessGroup(i)))
                {
                    wxTsMessageBox("Unable to delete... The selected access group was not located.", "Error", wxICON_HAND | wxOK);
                    return;
                }
                _groupList->Delete(index);
            }
            index--;
        }
    }

    RebuildAccessGroupList();

    // remove the access group from the display list,
    SetItemSelected(index);
    UpdateDialogControls();
    EnableDisableOK();

    return;
}


/*
* Should we show tooltips?
*/

bool GroupEditorWizardPage::ShowToolTips()
{
    return true;
}

/*
* Get bitmap resources
*/

wxBitmap GroupEditorWizardPage::GetBitmapResource(const wxString& name)
{
	return ::GetBitmapResource(name);
}

/*
* Get icon resources
*/

wxIcon GroupEditorWizardPage::GetIconResource(const wxString& name)
{
    // Icon retrieval
////@begin GroupEditorWizardPage icon retrieval
    wxUnusedVar(name);
    return wxNullIcon;
////@end GroupEditorWizardPage icon retrieval
}

std::shared_ptr<IKeyVEILSession> GroupEditorWizardPage::Session()
{
	AudienceSelector2* wiz = dynamic_cast<AudienceSelector2*>(GetParent());
	if (wiz == nullptr || wiz->_vars == nullptr)
        return nullptr;
    return wiz->_vars->_session;
}
bool GroupEditorWizardPage::HasSession() const
{
	AudienceSelector2* wiz = dynamic_cast<AudienceSelector2*>(GetParent());
	return wiz != nullptr && wiz->_vars != nullptr && !!wiz->_vars->_session;
}
void GroupEditorWizardPage::Session(std::shared_ptr<IKeyVEILSession> setTo)
{
	AudienceSelector2* wiz = dynamic_cast<AudienceSelector2*>(GetParent());

	if (wiz != nullptr)
	{
		wiz->_vars->_session.reset();
		_profile.reset();
		_ActiveCryptoGroup = nullptr;
		wiz->_vars->_session = setTo;
	}

}
std::shared_ptr<Asn1::CTS::_POD_Profile> GroupEditorWizardPage::GetProfile()
{
    if (!HasSession())
        return nullptr;
    if (!!_profile)
        return _profile;
    if (Session()->IsLoggedIn())
        _profile = Session()->GetProfile();
    return _profile;
}
bool GroupEditorWizardPage::HasProfile()
{
    return !!GetProfile();
}
Asn1::CTS::_POD_CryptoGroup* GroupEditorWizardPage::GetCGbyGuid(const GUID& id)
{
    if (!HasSession() || !HasProfile())
        return nullptr;

    for (size_t i = 0; i < GetProfile()->get_cryptoGroupList()->size(); i++)
    {
        if (GetProfile()->get_cryptoGroupList()->get_at(i).get_Id() == id)
        {
            return &GetProfile()->get_cryptoGroupList()->get_at(i);
        }
    }
    return nullptr;
}
int GroupEditorWizardPage::findCgByGuid(const GUID& id)
{
    if (!HasSession() || !HasProfile() || GetProfile()->get_cryptoGroupList()->size() == 0)
        return -1;

    for (size_t i = 0; i < GetProfile()->get_cryptoGroupList()->size(); i++)
    {
        if (GetProfile()->get_cryptoGroupList()->get_at(i).get_Id() == id)
            return (int)i;
    }
    return -1;
}

bool GroupEditorWizardPage::RebuildAccessGroupList()
{
    tscrypto::tsCryptoString line;
	AudienceSelector2* wiz = dynamic_cast<AudienceSelector2*>(GetParent());

    if (wiz != nullptr && wiz->_vars != nullptr && !!wiz->_vars->_header)
    {
        std::shared_ptr<ICmsHeaderAccessGroup>   andGroup;
        std::shared_ptr<ICmsHeaderAttributeGroup>  attrGroup;
        //			std::shared_ptr<ICmsHeaderPinGroup>  pinGroup;
        int accessGroupCount;
        int sel;
        int index;

        sel = (int)_groupList->GetSelection();
        _groupList->Clear();

        std::shared_ptr<ICmsHeaderExtension> ext;
        std::shared_ptr<ICmsHeaderAccessGroupExtension> extGroup;
        if (!wiz->_vars->_header->GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext))
        {
			wiz->_vars->_header->AddProtectedExtension(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), true, ext);
        }

        if (!ext || !(extGroup = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(ext)))
        {
            return true;
        }
        ext.reset();

        accessGroupCount = (int)extGroup->GetAccessGroupCount();
        for (index = 0; index < accessGroupCount; index++)
        {
            andGroup.reset();
            attrGroup.reset();
            //pinGroup.reset();

            if ((extGroup->GetAccessGroup(index, andGroup)))
            {
                if (andGroup->GetAndGroupType() == ag_Attrs && !!(attrGroup = std::dynamic_pointer_cast<ICmsHeaderAttributeGroup>(andGroup)))
                {
                    line = BuildAttrsLine(attrGroup, index == 0);
                    AddGroupText(line.c_str());
                }
                //else if (andGroup->GetAndGroupType() == ag_Pin &&
                //	SUCCEEDED(andGroup->QueryInterface(&pinGroup)))
                //{
                //	line = BuildPinLine(pinGroup);
                //	AddCertText(line.c_str());
                //}
            }
        }

        if (sel < 0 || sel >= (int)_groupList->GetCount())
        {
            sel = (int)_groupList->GetCount() - 1;
        }
        SetItemSelected(sel);
        //_groupList->Enable(accessGroupCount > 0);
    }
    UpdateDialogControls();
    return true;
}
tscrypto::tsCryptoString GroupEditorWizardPage::BuildAttrsLine(std::shared_ptr<ICmsHeaderAttributeGroup> attrs, bool isFirstLine)
{
    int index, idx;
    int count;
    GUID id;
    Asn1::CTS::_POD_Attribute* attr;
    std::shared_ptr<ICmsHeaderAttribute> headerAttr;
    std::shared_ptr<ICmsHeaderAttributeListExtension> attrList;
    std::shared_ptr<ICmsHeaderExtension> ext;
    tscrypto::tsCryptoString name;
    tscrypto::tsCryptoString list;
	AudienceSelector2* wiz = dynamic_cast<AudienceSelector2*>(GetParent());

    if (wiz == nullptr || wiz->_vars == nullptr || _ActiveCryptoGroup == nullptr || 
		!wiz->_vars->_header->GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ATTRIBUTELIST_EXT_OID, tscrypto::tsCryptoData::OID), ext) ||
        !(attrList = std::dynamic_pointer_cast<ICmsHeaderAttributeListExtension>(ext)))
    {
        return "";
    }
    ext.reset();
    count = (int)attrs->GetAttributeCount();
    for (index = 0; index < count; index++)
    {
        attr = nullptr;
        idx = attrs->GetAttributeIndex(index);
        headerAttr.reset();
        if (attrList->GetAttribute(idx, headerAttr))
        {
            id = headerAttr->GetAttributeGUID();

            attr = _ActiveCryptoGroup->get_AttributeById(id);
            if (!!attr)
            {
                name = attr->get_Name();
                if (name.size() == 0)
                {
                    name.Format("<attr %s>", TSGuidToString(id).c_str());
                }
            }
            else
            {
                name.Format("<attr %s>", TSGuidToString(id).c_str());
            }
            if (list.size() > 0)
            {
                list += " <strong>and</strong> ";
            }
            list += name;
        }
    }

    if (!isFirstLine && !list.empty())
    {
        list.prepend("<strong>OR</strong> (").append(")");;
    }
    else if (!list.empty())
    {
        list.prepend("     (").append(")");
    }
    return list;
}
void GroupEditorWizardPage::AddGroupText(const char *text)
{
    _groupList->Append(text);
    UpdateDialogControls();
}
void GroupEditorWizardPage::UpdateDialogControls()
{
    int index;
	AudienceSelector2* wiz = dynamic_cast<AudienceSelector2*>(GetParent());

	if (!_groupList->IsEnabled())
		return;

    // first make sure a cryptoGroup is selected
    if (!_ActiveCryptoGroup)
    {
        _btnAdd->Enable(false);
        _btnEdit->Enable(false);
        _btnDelete->Enable(false);
    }
    else
    {
        _btnAdd->Enable(true);
        // now see if a group is selected
        index = _groupList->GetSelection();
        if (-1 == index)
        {
            _btnEdit->Enable(false);
            _btnDelete->Enable(false);
        }
        else
        {
            _btnEdit->Enable(true);
            _btnDelete->Enable(true);
        }
    }
	FindWindowById(wxID_FORWARD, this->GetParent())->Enable(wiz != nullptr && wiz->_vars != nullptr && !!wiz->_vars->_header && _groupList->GetCount() > 0);
	_btnEdit->SetDefault();

    //if (_CurFavIndex == 0)
    //	btnCreateFavorite->SetLabel("Create &Favorite");
    //else
    //	btnCreateFavorite->SetLabel("Update &Favorite");
}
void GroupEditorWizardPage::SetItemSelected(int index)
{
    _groupList->SetSelection(index);
}
bool GroupEditorWizardPage::CheckAccessGroup(std::shared_ptr<ICmsHeaderAttributeGroup> newAttrs)
{
    int index;
    int matchCount = 0;
    tscrypto::tsCryptoData newList;
    tscrypto::tsCryptoData oldList;
    std::shared_ptr<ICmsHeaderAttributeGroup> attrs;
    std::shared_ptr<ICmsHeaderAccessGroup> andGroup;
    int attrListCount;
	AudienceSelector2* wiz = dynamic_cast<AudienceSelector2*>(GetParent());

    BuildIntList(newAttrs, newList);

    std::shared_ptr<ICmsHeaderExtension> ext;
    std::shared_ptr<ICmsHeaderAccessGroupExtension> groupList;

    if (wiz == nullptr || wiz->_vars == nullptr || 
		!wiz->_vars->_header->GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext) ||
        !(groupList = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(ext)))
    {
        return false;
    }

    attrListCount = (int)groupList->GetAccessGroupCount();
    for (index = 0; index < attrListCount; index++)
    {
        andGroup.reset();
        attrs.reset();

        if ((groupList->GetAccessGroup(index, andGroup)) && !!(attrs = std::dynamic_pointer_cast<ICmsHeaderAttributeGroup>(andGroup)))
        {
            BuildIntList(attrs, oldList);
            if (oldList.size() == newList.size() && memcmp(oldList.c_str(), newList.c_str(), oldList.size()) == 0)
            {
                matchCount++;
            }
        }
    }

    //
    // Since the access group is already added to the header, we expect to see one match.
    //
    if (matchCount != 1)
    {
        return false;
    }
    //
    // Now clear the attrs in the new attr list and put the sorted attrs into the list.
    //
    while (newAttrs->GetAttributeCount() > 0)
        newAttrs->RemoveAttributeIndex(0);

    for (index = 0; index < (int)newList.size() / 4; index++)
    {
        newAttrs->AddAttributeIndex(((DWORD*)newList.c_str())[index]);
    }
    return true;
}
void GroupEditorWizardPage::BuildIntList(std::shared_ptr<ICmsHeaderAttributeGroup> attrGroup, tscrypto::tsCryptoData &list)
{
    int attributeCount;
    DWORD *p;
    int insertedCount = 0;
    DWORD id;
    int i, j;

    attributeCount = (int)attrGroup->GetAttributeCount();
    list.erase();
    list.resize(attributeCount * 4);
    p = (DWORD*)list.rawData();

    for (i = 0; i < attributeCount; i++)
    {
        id = attrGroup->GetAttributeIndex(i);
        //
        // Now insert sort the value
        //
        for (j = 0; j < insertedCount; j++)
        {
            if (id < p[j])
            {
                memmove(&p[j + 1], &p[j], (insertedCount - j) * 4);
                p[j] = id;
                insertedCount++;
                break;
            }
        }
        if (j == insertedCount)
        {
            p[j] = id;
            insertedCount++;
        }
    }
}
void GroupEditorWizardPage::EnableDisableOK()
{
    //int attributeCount = 0;
    //BOOL bEnableOK = FALSE;
    //BOOL bEnableFav = FALSE;

    //attributeCount = _groupList->GetCount();

    ///* If there is more than one item in the list,...*/
    //if (attributeCount > 0)
    //{
    //	/* If there is one item and it is the "select cryptogroup" string, the box is really empty. */
    //	if (attributeCount == 1)
    //	{
    //		tscrypto::tsCryptoString name;

    //		name = _groupList->GetString(0).c_str().AsChar();
    //		if (TsStrCmp(name, AS_SEL_DOM_STR) != 0)
    //		{
    //			bEnableOK = TRUE;
    //			bEnableFav = TRUE;
    //		}
    //	}
    //	else
    //	{
    //		bEnableOK = TRUE;
    //		bEnableFav = TRUE;
    //	}
    //}

    //// TODO:  Implement me when we support PKI
    ////    if (mySelectedCertVector.size() > 0)
    ////	{
    ////        bEnableOK = TRUE;
    ////		bEnableFav = TRUE;
    ////	}
    //btnOK->Enable(bEnableOK != FALSE);
    //btnCreateFavorite->Enable(bEnableFav != FALSE);
    //btnDeleteFavorite->Enable(_CreateFavorites && _CurFavIndex > 0);
}
bool GroupEditorWizardPage::FindSelectedAccessGroup(std::shared_ptr<ICmsHeaderAccessGroup>& accessGroup, std::shared_ptr<ICmsHeaderAttributeGroup>& attrs)
{
    tscrypto::tsCryptoString line;
    std::shared_ptr<ICmsHeaderAccessGroup>   andGroup;
    std::shared_ptr<ICmsHeaderAttributeGroup>  attrGroup;
    int accessGroupCount;
    int sel;
    int index;
    tscrypto::tsCryptoString name;
	AudienceSelector2* wiz = dynamic_cast<AudienceSelector2*>(GetParent());

    if (wiz == nullptr || wiz->_vars == nullptr || !wiz->_vars->_header)
        return false;

    std::shared_ptr<ICmsHeaderExtension> ext;
    std::shared_ptr<ICmsHeaderAccessGroupExtension> extGroup;
    if (!wiz->_vars->_header->GetProtectedExtensionByOID(tscrypto::tsCryptoData(TECSEC_CKMHEADER_V7_ACCESSGROUPLIST_EXT_OID, tscrypto::tsCryptoData::OID), ext) ||
        !(extGroup = std::dynamic_pointer_cast<ICmsHeaderAccessGroupExtension>(ext)))
    {
        return false;
    }
    ext.reset();

    attrs.reset();
    accessGroup.reset();

    sel = _groupList->GetSelection();
    name = _groupList->GetString(sel).c_str().AsChar();

    accessGroupCount = (int)extGroup->GetAccessGroupCount();
    for (index = 0; index < accessGroupCount; index++)
    {
        andGroup.reset();
        attrGroup.reset();

        if ((extGroup->GetAccessGroup(index, andGroup)) &&
            andGroup->GetAndGroupType() == ag_Attrs &&
            !!(attrGroup = std::dynamic_pointer_cast<ICmsHeaderAttributeGroup>(andGroup)))
        {
            line = BuildAttrsLine(attrGroup, index == 0);
            if (TsStrCmp(line, name) == 0)
            {
                attrs = attrGroup;
                accessGroup = andGroup;
                return true;
            }
        }
    }

    return false;
}

bool GroupEditorWizardPage::skipMe()
{
	return false;
}


/*
 * Gets the previous page.
 */

wxWizardPage* GroupEditorWizardPage::GetPrev() const
{
	ISkippablePage* tokPg = dynamic_cast<ISkippablePage*>(prevPage);

	if (tokPg != nullptr && tokPg->skipMe())
		return prevPage->GetPrev();
	return prevPage;
}


/*
 * Gets the next page.
 */

wxWizardPage* GroupEditorWizardPage::GetNext() const
{
	ISkippablePage* tokPg = dynamic_cast<ISkippablePage*>(nextPage);

	if (tokPg != nullptr && tokPg->skipMe())
		return nextPage->GetNext();
	return nextPage;
}

