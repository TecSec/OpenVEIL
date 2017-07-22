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


////@begin includes
////@end includes

////@begin XPM images
////@end XPM images


/*
 * AttributeSelectorGrid type definition
 */

IMPLEMENT_DYNAMIC_CLASS( AttributeSelectorGrid, wxDialog )


/*
 * AttributeSelectorGrid event table definition
 */

BEGIN_EVENT_TABLE( AttributeSelectorGrid, wxDialog )

////@begin AttributeSelectorGrid event table entries
    EVT_BUTTON( wxID_OK, AttributeSelectorGrid::OnOkClick )
    EVT_BUTTON( wxID_CANCEL, AttributeSelectorGrid::OnCancelClick )
    EVT_BUTTON( wxID_HELP, AttributeSelectorGrid::OnHelpClick )
////@end AttributeSelectorGrid event table entries

END_EVENT_TABLE()


/*
		 * AttributeSelectorGrid constructors
 */

AttributeSelectorGrid::AttributeSelectorGrid()
{
	Init();
}

AttributeSelectorGrid::AttributeSelectorGrid( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
	Init();
	Create(parent, id, caption, pos, size, style);
}


/*
 * AttributeSelectorGrid creator
 */

bool AttributeSelectorGrid::Create( wxWindow* parent, wxWindowID id, const wxString& caption, const wxPoint& pos, const wxSize& size, long style )
{
////@begin AttributeSelectorGrid creation
    SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY|wxWS_EX_BLOCK_EVENTS);
    wxDialog::Create( parent, id, caption, pos, size, style );

	CreateControls();
	Centre();
////@end AttributeSelectorGrid creation
	OnInitDialog();
	return true;
}

/*
 * AttributeSelectorGrid destructor
 */

AttributeSelectorGrid::~AttributeSelectorGrid()
{
////@begin AttributeSelectorGrid destruction
////@end AttributeSelectorGrid destruction
}


void AttributeSelectorGrid::setVariables(attributeSelectorVariables* inVars)
{
	_vars = inVars;
}

/*
 * Member initialisation
 */

void AttributeSelectorGrid::Init()
{
////@begin AttributeSelectorGrid member initialisation
	_scrollGridWindow = NULL;
	_szGrids = NULL;
	btnOK = NULL;
////@end AttributeSelectorGrid member initialisation
	_cryptoGroup = nullptr;
	_vars = nullptr;
}


/*
 * Control creation for AttributeSelectorGrid
 */

void AttributeSelectorGrid::CreateControls()
{
////@begin AttributeSelectorGrid content construction
	AttributeSelectorGrid* itemDialog1 = this;

	wxFlexGridSizer* itemFlexGridSizer2 = new wxFlexGridSizer(0, 1, 0, 0);
	itemDialog1->SetSizer(itemFlexGridSizer2);

    wxStaticText* itemStaticText3 = new wxStaticText( itemDialog1, wxID_STATIC, _("Select the attributes for this access group:"), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer2->Add(itemStaticText3, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    _scrollGridWindow = new wxScrolledWindow( itemDialog1, ID_ATTR_SCROLLER, wxDefaultPosition, wxDefaultSize, wxSUNKEN_BORDER|wxHSCROLL|wxVSCROLL|wxTAB_TRAVERSAL );
	_scrollGridWindow->SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY);
    itemFlexGridSizer2->Add(_scrollGridWindow, 0, wxGROW|wxALL, 0);
	_scrollGridWindow->SetScrollbars(1, 1, 0, 0);
	_szGrids = new wxFlexGridSizer(0, 1, 0, 0);
	_scrollGridWindow->SetSizer(_szGrids);


	_szGrids->AddGrowableCol(0);

	_scrollGridWindow->SetMinSize(wxDefaultSize);

	wxStdDialogButtonSizer* itemStdDialogButtonSizer8 = new wxStdDialogButtonSizer;

    itemFlexGridSizer2->Add(itemStdDialogButtonSizer8, 0, wxGROW|wxALIGN_CENTER_VERTICAL|wxALL, 5);
    btnOK = new wxButton( itemDialog1, wxID_OK, _("&OK"), wxDefaultPosition, wxDefaultSize, 0 );
	btnOK->SetDefault();
	itemStdDialogButtonSizer8->AddButton(btnOK);

    wxButton* itemButton10 = new wxButton( itemDialog1, wxID_CANCEL, _("&Cancel"), wxDefaultPosition, wxDefaultSize, 0 );
	itemStdDialogButtonSizer8->AddButton(itemButton10);

    wxButton* itemButton11 = new wxButton( itemDialog1, wxID_HELP, _("&Help"), wxDefaultPosition, wxDefaultSize, 0 );
    itemStdDialogButtonSizer8->AddButton(itemButton11);

	itemStdDialogButtonSizer8->Realize();

	itemFlexGridSizer2->AddGrowableRow(1);
	itemFlexGridSizer2->AddGrowableCol(0);

////@end AttributeSelectorGrid content construction
//	edtGrid->Connect(ID_GRID, wxEVT_CHAR, wxKeyEventHandler(AttributeSelectorGrid::OnGridChar), NULL, this);
}


/*
 * Should we show tooltips?
 */

bool AttributeSelectorGrid::ShowToolTips()
{
	return true;
}

/*
 * Get bitmap resources
 */

wxBitmap AttributeSelectorGrid::GetBitmapResource( const wxString& name )
{
	return ::GetBitmapResource(name);
}

/*
 * Get icon resources
 */

wxIcon AttributeSelectorGrid::GetIconResource( const wxString& name )
{
	return ::GetIconResource(name);
}


/*
 * wxEVT_GRID_CELL_LEFT_CLICK event handler for ID_GRID
 */

void AttributeSelectorGrid::OnCellLeftClick( wxGridEvent& event )
{
	int col = event.GetCol();
	int row = event.GetRow();

	wxGrid *grid = dynamic_cast<wxGrid*>(event.GetEventObject());

	if (grid == nullptr)
		return;

	wxString name = grid->GetCellValue(row, col);
	tscrypto::tsCryptoString wName = name.c_str().AsChar();

	event.Skip();
	if (_vars == nullptr)
		return;
	if (wName.size() > 0)
	{
		if (wName[0] == '+')
		{
			_vars->_selectedAttributeCount--;
			wName[0] = '-';
			grid->SetCellValue(row, col, wName.c_str());
		}
		else if (wName[0] == '-')
		{
			_vars->_selectedAttributeCount++;
			wName[0] = '+';
			grid->SetCellValue(row, col, wName.c_str());
		}
		btnOK->Enable(_vars->_selectedAttributeCount > 0);
	}
}


/*
 * wxEVT_GRID_CELL_CHANGED event handler for ID_GRID
 */

void AttributeSelectorGrid::OnCellChanged( wxGridEvent& event )
{
	int col = event.GetCol();
	int row = event.GetRow();
	wxGrid *grid = dynamic_cast<wxGrid*>(event.GetEventObject());

	if (grid == nullptr)
		return;

	wxString name = grid->GetCellValue(row, col);
	tscrypto::tsCryptoString wName = name.c_str().AsChar();

	event.Skip();
	if (_vars != nullptr)
						{
		if (wName.size() > 0)
		{
			if (wName[0] == '-')
			{
				_vars->_selectedAttributeCount--;
			}
			else if (wName[0] == '+')
			{
				_vars->_selectedAttributeCount++;
			}
			btnOK->Enable(_vars->_selectedAttributeCount > 0);
						}
					}
}

void AttributeSelectorGrid::OnGridChar(wxKeyEvent& event)
{
	wxGrid *grid = nullptr;
	wxWindow* focus = FindFocus();

	while ((grid = dynamic_cast<wxGrid*>(focus)) == nullptr)
					{
		if (focus == nullptr || focus->GetParent() == nullptr)
						break;
		focus = focus->GetParent();
					}

	if (grid == nullptr)
		return;

	if (event.GetKeyCode() == ' ' || event.GetKeyCode() == '+' || event.GetKeyCode() == '-')
	{
		wxString name = grid->GetCellValue(grid->GetGridCursorRow(), grid->GetGridCursorCol());
		tscrypto::tsCryptoString wName = name.c_str().AsChar();

		event.StopPropagation();
		if (_vars != nullptr)
		{
			if (wName.size() > 0)
			{
				if (event.GetKeyCode() == '-' || (wName[0] == '+' && event.GetKeyCode() != '+'))
			{
					_vars->_selectedAttributeCount--;
					wName[0] = '-';
					grid->SetCellValue(grid->GetGridCursorRow(), grid->GetGridCursorCol(), wName.c_str());
				}
				else if (event.GetKeyCode() == '+' || (wName[0] == '-' && event.GetKeyCode() != '-'))
				{
					_vars->_selectedAttributeCount++;
					wName[0] = '+';
					grid->SetCellValue(grid->GetGridCursorRow(), grid->GetGridCursorCol(), wName.c_str());
				}
				btnOK->Enable(_vars->_selectedAttributeCount > 0);
				}
			}
		}
}

void AttributeSelectorGrid::OnOkClick(wxCommandEvent& event)
{
	Asn1::CTS::_POD_CryptoGroup* CryptoGroup = nullptr;
	int rowCount;
	int colCount;
	wxString name;

	event.StopPropagation();
	if (_vars != nullptr && !!_vars->_ckm7group && !!_vars->_attrsList)
	{
		CryptoGroup = GetCryptoGroup(_vars->_session, _vars->_cryptoGroupId);
		if (!CryptoGroup)
		{
			wxTsMessageBox("You must first select a cryptogroup.", "Error", wxOK);
			return;
		}

		while (_vars->_ckm7group->GetAttributeCount() > 0)
			_vars->_ckm7group->RemoveAttributeIndex(0);

		for (wxGrid* grid : _grids)
		{
			rowCount = grid->GetNumberRows();
			colCount = grid->GetNumberCols();

			for (int col = 0; col < colCount; col++)
			{
				for (int row = 0; row < rowCount; row++)
				{
					if (!grid->GetCellValue(row, col).IsEmpty())
		{
						name = grid->GetCellValue(row, col);
						if (name[0] == '+')
	{
							tscrypto::tsCryptoStringList parts = tscrypto::tsCryptoString(name.c_str().AsChar()).split("~");
							int id = 0;
							if (parts->size() > 1)
								id = TsStrToInt(parts->at(1).c_str());
							GUID attributeGuid = _GuidMap[id];

							int idx = FindAttrIndex(_vars->_attrsList, attributeGuid);

							if (idx >= 0)
								_vars->_ckm7group->AddAttributeIndex(idx);
						}
					}
				}
			}
		}
		_vars->_cryptoGroupId = CryptoGroup->get_Id();
	}
		else
	{
	}
	EndDialog(wxID_OK);
}

void AttributeSelectorGrid::OnCancelClick(wxCommandEvent& event)
{
	EndDialog(wxID_CANCEL);
}

void AttributeSelectorGrid::OnInitDialog()
{
	btnOK->Enable(false);

	if (_vars != nullptr)
	{
		Asn1::CTS::_POD_CryptoGroup* CryptoGroup = nullptr;
		tscrypto::tsCryptoString name;

		_profile = _vars->_session->GetProfile();

		CryptoGroup = GetCryptoGroupById(_vars->_session, _vars->_cryptoGroupId);
		if (!CryptoGroup)
	{
			EndDialog(wxID_CANCEL);
			return;
	}

		name = CryptoGroup->get_Name();

		FillGrid(CryptoGroup);
		MarkIncomingAttributes();
	}
	btnOK->Enable((_vars->_selectedAttributeCount > 0) ? true : false);
}

int AttributeSelectorGrid::FindAttrIndex(std::shared_ptr<ICmsHeaderAttributeListExtension> attrList, const GUID &id)
{
	int count = (int)attrList->GetAttributeCount();
	std::shared_ptr<ICmsHeaderAttribute> attr;

	for (int i = 0; i < count; i++)
	{
		attr.reset();
		if (attrList->GetAttribute(i, attr) && attr->GetAttributeGUID() == id)
			return i;
	}
	count = attrList->AddAttribute();
	attr.reset();
	if (attrList->GetAttribute(count, attr) && attr->SetAttributeGuid(id) && attr->SetCryptoGroupNumber(0))
		return count;
	return -1;
}

Asn1::CTS::_POD_CryptoGroup* AttributeSelectorGrid::GetCryptoGroupById(std::shared_ptr<IKeyVEILSession> session, const GUID& id)
{
	if (!_profile->exists_cryptoGroupList())
		return nullptr;

	for (size_t i = 0; i < _profile->get_cryptoGroupList()->size(); i++)
	{
		Asn1::CTS::_POD_CryptoGroup* group = &_profile->get_cryptoGroupList()->get_at(i);

		if (!!group && group->get_Id() == id)
			return group;
	}
	return nullptr;
}

Asn1::CTS::_POD_CryptoGroup* AttributeSelectorGrid::GetCryptoGroup(std::shared_ptr<IKeyVEILSession> session, size_t index)
{
	if (!_profile->exists_cryptoGroupList())
		return nullptr;

	if (index >= _profile->get_cryptoGroupList()->size())
		return nullptr;
	return &_profile->get_cryptoGroupList()->get_at(index);
}

Asn1::CTS::_POD_CryptoGroup* AttributeSelectorGrid::GetCryptoGroup(std::shared_ptr<IKeyVEILSession> session, const GUID& cgId)
{
	return GetCryptoGroupById(session, cgId);
}

void AttributeSelectorGrid::MarkIncomingAttributes()
{
		int count;
		wxString name;
		tscrypto::tsCryptoString wName;
		int rowCount;
		int colCount;
		int id = 0;

	if (_vars == nullptr || !_vars->_ckm7group || !_vars->_attrsList)
			return;

		// CKM 7
	count = (int)_vars->_ckm7group->GetAttributeCount();

	for (wxGrid* grid : _grids)
	{
		rowCount = grid->GetNumberRows();
		colCount = grid->GetNumberCols();

		for (int row = 0; row < rowCount; row++)
		{
			for (int col = 0; col < colCount; col++)
			{
				name = grid->GetCellValue(row, col);
				if (!name.empty())
				{
					tscrypto::tsCryptoStringList parts = tscrypto::tsCryptoString(name.c_str().AsChar()).split("~");
				if (parts->size() > 1)
						id = TsStrToInt(parts->at(1).c_str());
					wName = name.c_str().AsChar();
				if (wName[0] == '-')
				{
					GUID attributeGuid = _GuidMap[id];
					std::shared_ptr<ICmsHeaderAttribute> attr;

					for (int i = 0; i < count; i++)
					{
						attr.reset();

							if (_vars->_attrsList->GetAttribute(_vars->_ckm7group->GetAttributeIndex(i), attr) && attr->GetAttributeGUID() == attributeGuid)
						{
								_vars->_selectedAttributeCount++;
							wName[0] = '+';
								grid->SetCellValue(row, col, wName.c_str());
							break;
						}
					}
				}
			}
		}
	}
	}
}

std::vector<const Asn1::CTS::_POD_Category*> AttributeSelectorGrid::BuildCategoryList(const Asn1::CTS::_POD_Fiefdom* fiefdom)
{
	std::vector<const Asn1::CTS::_POD_Category*> tmp;

	for (size_t j = 0; j < fiefdom->get_CategoryList()->size(); j++)
		{
		tmp.push_back(&fiefdom->get_CategoryList()->get_at(j));
		}
		return tmp;
}

wxGrid* AttributeSelectorGrid::AddFiefdomGrid(const tsCryptoString& name)
{
	if (_grids.size() > 0)
	{
		wxStaticLine* itemStaticLine8 = new wxStaticLine(_scrollGridWindow, wxID_STATIC, wxDefaultPosition, wxDefaultSize, wxLI_HORIZONTAL);
		_szGrids->Add(itemStaticLine8, 0, wxALIGN_CENTER_HORIZONTAL | wxGROW | wxTOP | wxBOTTOM, 5);
	}
	wxStaticText* itemStaticText6 = new wxStaticText(_scrollGridWindow, wxID_STATIC, name.c_str(), wxDefaultPosition, wxDefaultSize, 0);
	_szGrids->Add(itemStaticText6, 0, wxGROW | wxALIGN_CENTER_VERTICAL | wxALL, 5);

	wxGrid* grid = new wxGrid(_scrollGridWindow, wxID_ANY, wxDefaultPosition, wxDefaultSize, wxSUNKEN_BORDER);
	grid->SetDefaultColSize(80);
	grid->SetDefaultRowSize(25);
	grid->SetColLabelSize(25);
	grid->SetRowLabelSize(0);
	_szGrids->Add(grid, 0, 0, 5);

	//	edtGrid->SetBackgroundColour(wxColour(0xf0f0f0));
	//	edtGrid->SetForegroundColour(wxColour((unsigned long)0));
	//	edtGrid->SetSelectionBackground(wxColour((unsigned long)0x000060));
	//	edtGrid->SetSelectionForeground(wxColour((unsigned long)0xFFFFFF));

	grid->Bind(wxEVT_CHAR, &AttributeSelectorGrid::OnGridChar, this);
	grid->Bind(wxEVT_GRID_CELL_LEFT_CLICK, &AttributeSelectorGrid::OnCellLeftClick, this);
	grid->Bind(wxEVT_GRID_CELL_CHANGED, &AttributeSelectorGrid::OnCellChanged, this);

	_grids.push_back(grid);

	return grid;
}

void AttributeSelectorGrid::FillGrid(Asn1::CTS::_POD_CryptoGroup* cryptoGroup)
{
		int count;
		int i;
	const Asn1::CTS::_POD_Category* cat;
		tscrypto::tsCryptoString name;
		int maxAttrCount = 0;
		int attributeCount = 0;
		//ROWCOLOR rowcolor = {0xFF0000, 0x00FFFF};

	_szGrids->Clear();
	_grids.clear();
		_GuidMap.clear();

	if (cryptoGroup != NULL && cryptoGroup->exists_FiefdomList())
	{
		std::vector<const Asn1::CTS::_POD_Category*>	catList;

		const Asn1::CTS::_POD_CryptoGroup_FiefdomList* fiefList = cryptoGroup->get_FiefdomList();
		for (size_t fiefItem = 0; fiefItem < fiefList->size(); fiefItem++)
		{
			const Asn1::CTS::_POD_Fiefdom& fief = fiefList->get_at(fiefItem);

			catList = BuildCategoryList(&fief);
			count = (int)catList.size();

			// First determine the size of the grid
			for (i = 0; i < count; i++)
			{
				cat = catList[i];

				attributeCount = (int)cat->get_AttributeList()->size();

				int removeCount = 0;
				for (int j = 0; j < attributeCount; j++)
				{
					const Asn1::CTS::_POD_Attribute& attr = cat->get_AttributeList()->get_at(j);
					if (!attr.get_hasWrite())
					{
						removeCount++;
					}
				}
				attributeCount -= removeCount;

				if (attributeCount > maxAttrCount)
				{
					maxAttrCount = attributeCount;
				}
				if (attributeCount == 0)
				{
					count--;
					catList.erase(catList.begin() + i);
					i--;
				}
			}
			if (catList.size() > 0)
			{
				wxGrid* grid = AddFiefdomGrid(fief.get_Name());


				if (grid != nullptr)
				{

			// Then create the columns and rows
					count = (int)catList.size();
			if (count == 0)
			{
				EndDialog(wxID_CANCEL);
				return;
			}
					grid->CreateGrid(maxAttrCount, count, wxGrid::wxGridSelectCells);
					grid->SetSelectionMode(wxGrid::wxGridSelectionModes::wxGridSelectCells);
					grid->EnableDragCell(false);
					grid->EnableDragColMove(false);
#ifndef SUPPORT_KEYBOARD_SELECTION
					grid->EnableEditing(false);
#else
					grid->EnableEditing(true);
#endif // SUPPORT_KEYBOARD_SELECTION
					//grid->Connect(ID_GRID, wxEVT_CHAR, wxKeyEventHandler(AttributeSelectorGrid::OnGridChar), NULL, this);

			// and finally populate the grid

			for (i = 0; i < count; i++)
			{
						cat = catList[i];
				name = cat->get_Name();

						grid->SetColLabelValue(i, name.c_str());
			}

			for (i = 0; i < count; i++)
			{
						cat = catList[i];
				if (cat != nullptr)
				{
					std::vector<tscrypto::tsCryptoString> names;
					//
					// Now populate the rows for this column
					//
					attributeCount = (int)cat->get_AttributeList()->size();
					for (int j = 0; j < attributeCount; j++)
					{
								const Asn1::CTS::_POD_Attribute& attr = cat->get_AttributeList()->get_at(j);
						name = attr.get_Name();
						name.prepend("-");

						if (attr.get_hasWrite())
						{
							GUID attributeGuid = attr.get_Id();
							_GuidMap.push_back(attributeGuid);

							name << "~" << (int)(_GuidMap.size() - 1);

							names.push_back(name);
						}
					}

					std::sort(names.begin(), names.end());

					int row = 0;
					for (const tscrypto::tsCryptoString& name : names)
					{
								grid->SetCellRenderer(row, i, new MyGridCellRenderer());
#ifdef SUPPORT_KEYBOARD_SELECTION
								grid->SetCellEditor(row, i, new MyGridCellEditor());
								grid->SetReadOnly(row, i, true);
#endif // SUPPORT_KEYBOARD_SELECTION
								grid->SetCellValue(row++, i, name.c_str());
					}
				}
			}
					grid->AutoSizeColumns();
					grid->AutoSizeRows();
		}
	}
	}
		}
		else
		count = 0;
}


/*
 * wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_HELP
	*/

void AttributeSelectorGrid::OnHelpClick( wxCommandEvent& event )
{
	std::shared_ptr<IVEILHttpHelpRegistry> help = ::TopServiceLocator()->get_instance<IVEILHttpHelpRegistry>("/WxWin/HelpRegistry");

	if (!help)
			{
		wxTsMessageBox(("Help is not available at this time."), ("Status"), wxOK);
		}
		else
		{
		help->DisplayHelpForWindowId(winid_AttributeSelector, (XP_WINDOW)this);
		}
}
	