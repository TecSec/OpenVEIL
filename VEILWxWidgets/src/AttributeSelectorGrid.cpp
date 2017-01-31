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
#include "wx/grid.h"
////@end includes

//#define SUPPORT_KEYBOARD_SELECTION

/*!
 * Forward declarations
 */

 ////@begin forward declarations
class wxGrid;
////@end forward declarations

/*!
 * Control identifiers
 */

 ////@begin control identifiers
#define ID_ATTRIBUTESELECTORGRID 10000
#define ID_CRYPTOGROUPLIST 10001
#define ID_CRYPTOGROUP_STATIC 10013
#define ID_GRID 10002
#define SYMBOL_ATTRIBUTESELECTORGRID_STYLE wxCAPTION|wxRESIZE_BORDER|wxSYSTEM_MENU|wxCLOSE_BOX|wxTAB_TRAVERSAL
#define SYMBOL_ATTRIBUTESELECTORGRID_TITLE _("Attribute Selector")
#define SYMBOL_ATTRIBUTESELECTORGRID_IDNAME ID_ATTRIBUTESELECTORGRID
#define SYMBOL_ATTRIBUTESELECTORGRID_SIZE wxSize(400, 300)
#define SYMBOL_ATTRIBUTESELECTORGRID_POSITION wxDefaultPosition
////@end control identifiers

#ifdef SUPPORT_KEYBOARD_SELECTION
class MyGridCellEditor : public wxGridCellEditor
{
public:
	MyGridCellEditor() { }


	// Inherited via wxGridCellEditor
	virtual void Create(wxWindow * parent, wxWindowID id, wxEvtHandler * evtHandler) override
	{
		m_control = new wxStaticText(parent, id, wxEmptyString,
			wxDefaultPosition, wxDefaultSize,
			wxNO_BORDER);


		wxGridCellEditor::Create(parent, id, evtHandler);
	}
	virtual void SetSize(const wxRect& r) wxOVERRIDE
	{
		bool resize = false;
		wxSize size = m_control->GetSize();
		wxCoord minSize = wxMin(r.width, r.height);

		// check if the checkbox is not too big/small for this cell
		wxSize sizeBest = m_control->GetBestSize();
		if (!(size == sizeBest))
		{
			// reset to default size if it had been made smaller
			size = sizeBest;

			resize = true;
		}

		if (size.x >= minSize || size.y >= minSize)
		{
			// leave 1 pixel margin
			size.x = size.y = minSize - 2;

			resize = true;
		}

		if (resize)
		{
			m_control->SetSize(size);
		}

		// position it in the centre of the rectangle (TODO: support alignment?)

#if defined(__WXGTK__) || defined (__WXMOTIF__)
		// the checkbox without label still has some space to the right in wxGTK,
		// so shift it to the right
		size.x -= 8;
#elif defined(__WXMSW__)
		// here too, but in other way
		size.x += 1;
		size.y -= 2;
#endif

		int hAlign = wxALIGN_CENTRE;
		int vAlign = wxALIGN_CENTRE;
		if (GetCellAttr())
			GetCellAttr()->GetAlignment(&hAlign, &vAlign);

		int x = 0, y = 0;
		if (hAlign == wxALIGN_LEFT)
		{
			x = r.x + 2;

#ifdef __WXMSW__
			x += 2;
#endif

			y = r.y + r.height / 2 - size.y / 2;
		}
		else if (hAlign == wxALIGN_RIGHT)
		{
			x = r.x + r.width - size.x - 2;
			y = r.y + r.height / 2 - size.y / 2;
		}
		else if (hAlign == wxALIGN_CENTRE)
		{
			x = r.x + r.width / 2 - size.x / 2;
			y = r.y + r.height / 2 - size.y / 2;
		}

		m_control->Move(x, y);
	}
	virtual void Show(bool show, wxGridCellAttr *attr = NULL) wxOVERRIDE
	{
		m_control->Show(show);

		if (show)
		{
			colBg = attr ? attr->GetBackgroundColour() : *wxLIGHT_GREY;
			colFg = attr ? attr->GetTextColour() : *wxLIGHT_GREY;

			setColors();
		}
	}
	virtual bool IsAcceptedKey(wxKeyEvent& event) wxOVERRIDE
	{
		if (wxGridCellEditor::IsAcceptedKey(event))
		{
			int keycode = event.GetKeyCode();
			switch (keycode)
			{
			case WXK_SPACE:
			case '+':
			case '-':
				return true;
			}
		}

		return false;
	}

	virtual void BeginEdit(int row, int col, wxGrid * grid) override
	{
		wxASSERT_MSG(m_control,
			wxT("The wxGridCellEditor must be created first!"));

		colSelBg = grid->GetSelectionBackground();
		colSelFg = grid->GetSelectionForeground();

		fullValue = grid->GetTable()->GetValue(row, col).mbc_str();
		if (fullValue[0] == '-')
			m_origValue = false;
		else if (fullValue[0] == '+')
			m_origValue = true;
		else
		{
			// do not try to be smart here and convert it to true or false
			// because we'll still overwrite it with something different and
			// this risks to be very surprising for the user code, let them
			// know about it
			wxFAIL_MSG(wxT("invalid value for a cell with bool editor!"));
		}
		m_newValue = m_origValue;

		tscrypto::tsCryptoStringList parts = fullValue.split("~");

		SBox()->SetLabel(&parts->at(0).c_str()[1]);
		SBox()->SetFocus();
	}

	virtual bool EndEdit(int row, int col, const wxGrid * grid, const wxString & oldval, wxString * newval) override
	{
		if (m_origValue == m_newValue)
			return false;

		m_origValue = m_newValue;

		if (newval)
			*newval = GetValue();

		return true;
	}

	virtual void ApplyEdit(int row, int col, wxGrid * grid) override
	{
		wxGridTableBase * const table = grid->GetTable();
		table->SetValue(row, col, GetValue());
	}

	virtual void Reset() override
	{
		wxASSERT_MSG(m_control,
			wxT("The wxGridCellEditor must be created first!"));

		m_newValue = m_origValue;
		setColors();
	}
	virtual void StartingClick() wxOVERRIDE
	{
		m_newValue = !m_newValue;
		setColors();
	}
	virtual void StartingKey(wxKeyEvent& event) wxOVERRIDE
	{
		int keycode = event.GetKeyCode();
		switch (keycode)
		{
		case WXK_SPACE:
			m_newValue = !m_newValue;
			setColors();
			break;

		case '+':
			m_newValue = true;
			setColors();
			break;

		case '-':
			m_newValue = false;
			setColors();
			break;
		}
	}

	virtual wxGridCellEditor * Clone() const override
	{
		return new MyGridCellEditor;
	}

	virtual wxString GetValue() const override
	{
		tscrypto::tsCryptoString tmp(fullValue);

		tmp[0] = (m_newValue ? '+' : '-');
		return tmp.c_str();
	}

protected:
	wxStaticText *SBox() const { return (wxStaticText *)m_control; }

	void setColors()
	{
		if (m_newValue)
		{
			SBox()->SetBackgroundColour(colSelBg);
			SBox()->SetForegroundColour(colSelFg);
		}
		else
		{
			SBox()->SetBackgroundColour(colBg);
			SBox()->SetForegroundColour(colFg);
		}
	}
private:
	bool m_newValue;
	bool m_origValue;
	tscrypto::tsCryptoString fullValue;
	wxColour colBg;
	wxColour colSelBg;
	wxColour colFg;
	wxColour colSelFg;

	wxDECLARE_NO_COPY_CLASS(MyGridCellEditor);
};
#endif // SUPPORT_KEYBOARD_SELECTION

class MyGridCellRenderer : public wxGridCellStringRenderer
{
public:
	virtual void Draw(wxGrid& grid,
		wxGridCellAttr& attr,
		wxDC& dc,
		const wxRect& rectCell,
		int row, int col,
		bool isSelected) wxOVERRIDE
	{
		wxRect rect = rectCell;
		rect.Inflate(-1);

		// erase only this cells background, overflow cells should have been erased
		wxGridCellRenderer::Draw(grid, attr, dc, rectCell, row, col, isSelected);

		int hAlign, vAlign;
		attr.GetAlignment(&hAlign, &vAlign);

		int overflowCols = 0;

		if (attr.GetOverflow())
		{
			int cols = grid.GetNumberCols();
			int best_width = GetBestSize(grid, attr, dc, row, col).GetWidth();
			int cell_rows, cell_cols;
			attr.GetSize(&cell_rows, &cell_cols); // shouldn't get here if <= 0
			if ((best_width > rectCell.width) && (col < cols) && grid.GetTable())
			{
				int i, c_cols, c_rows;
				for (i = col + cell_cols; i < cols; i++)
				{
					bool is_empty = true;
					for (int j = row; j < row + cell_rows; j++)
					{
						// check w/ anchor cell for multicell block
						grid.GetCellSize(j, i, &c_rows, &c_cols);
						if (c_rows > 0)
							c_rows = 0;
						if (!grid.GetTable()->IsEmptyCell(j + c_rows, i))
						{
							is_empty = false;
							break;
						}
					}

					if (is_empty)
					{
						rect.width += grid.GetColSize(i);
					}
					else
					{
						i--;
						break;
					}

					if (rect.width >= best_width)
						break;
				}

				overflowCols = i - col - cell_cols + 1;
				if (overflowCols >= cols)
					overflowCols = cols - 1;
			}

			if (overflowCols > 0) // redraw overflow cells w/ proper hilight
			{
				hAlign = wxALIGN_LEFT; // if oveflowed then it's left aligned
				wxRect clip = rect;
				clip.x += rectCell.width;
				// draw each overflow cell individually
				int col_end = col + cell_cols + overflowCols;
				if (col_end >= grid.GetNumberCols())
					col_end = grid.GetNumberCols() - 1;
				for (int i = col + cell_cols; i <= col_end; i++)
				{
					clip.width = grid.GetColSize(i) - 1;
					dc.DestroyClippingRegion();
					dc.SetClippingRegion(clip);

					SetTextColoursAndFont(grid, attr, dc,
						grid.IsInSelection(row, i));

					grid.DrawTextRectangle(dc, grid.GetCellValue(row, col),
						rect, hAlign, vAlign);
					clip.x += grid.GetColSize(i) - 1;
				}

				rect = rectCell;
				rect.Inflate(-1);
				rect.width++;
				dc.DestroyClippingRegion();
			}
		}

		// now we only have to draw the text

		wxString value = grid.GetCellValue(row, col);
		tscrypto::tsCryptoString val(value.mbc_str());

		if (val[0] == '-')
		{
			SetTextColoursAndFont(grid, attr, dc, isSelected);

			tscrypto::tsCryptoStringList parts = val.split("~");
			value = &parts->at(0).c_str()[1];
			grid.DrawTextRectangle(dc, value, rect, hAlign, vAlign);
		}
		else if (val[0] == '+')
		{
			SetTextColoursAndFontForSelected(grid, attr, dc, isSelected);

			tscrypto::tsCryptoStringList parts = val.split("~");
			value = &parts->at(0).c_str()[1];

			dc.DrawRectangle(rect);
			grid.DrawTextRectangle(dc, value, rect, hAlign, vAlign);
			//dc.SetPen(*wxGREEN_PEN);
			//dc.SetBrush(*wxTRANSPARENT_BRUSH);
			//dc.DrawEllipse(rect);
		}
		else
		{
			SetTextColoursAndFont(grid, attr, dc, isSelected);
			grid.DrawTextRectangle(dc, value, rect, hAlign, vAlign);
		}
	}
private:
	void SetTextColoursAndFontForSelected(const wxGrid& grid,
		const wxGridCellAttr& attr,
		wxDC& dc,
		bool isSelected)
	{
		dc.SetBackgroundMode(wxBRUSHSTYLE_SOLID);

		// TODO some special colours for attr.IsReadOnly() case?

		wxColour clr;
		if (grid.HasFocus())
			clr = wxSystemSettings::GetColour(wxSYS_COLOUR_BTNSHADOW);
		else
			clr = grid.GetSelectionBackground();
		dc.SetTextBackground(clr);
		dc.SetTextForeground(grid.GetSelectionForeground());
		dc.SetBrush(wxBrush(clr));

		dc.SetFont(attr.GetFont());
	}

};

class AttributeSelectorGrid : public IAttributeSelector, public tsmod::IObject, public wxDialog
{
	DECLARE_EVENT_TABLE()

public:
	AttributeSelectorGrid() : _parent(nullptr), _cryptoGroupId(GUID_NULL), _imageList(16, 16, false, 4), _cryptoGroup(nullptr), _selectedAttributeCount(0)
	{
		Init();
		_imageList.Add(GetBitmapResource("readwrit.xpm"));
	}
	virtual ~AttributeSelectorGrid() {}

	// wxDialog
	virtual bool Destroy() override
	{
		_parent = XP_WINDOW_INVALID;
		_session.reset();
		_cryptoGroupId = GUID_NULL;
		_ckm7group.reset();
		_attrsList.reset();
		_GuidMap.clear();
		_cryptoGroup = nullptr;
		_selectedAttributeCount = 0;
		_catList.clear();
		Me.reset();
		return true;
	}
	// IVEILWxUIBase
	virtual int  DisplayModal() override
	{
		if (_parent == XP_WINDOW_INVALID)
			_parent = (XP_WINDOW)wxTheApp->GetTopWindow();

		// Construct the dialog here
		Create((wxWindow*)_parent);

		int retVal = ShowModal();

		// Make sure you call Destroy
		Destroy();
		return retVal;
	}
	virtual int  DisplayModal(XP_WINDOW wnd) override
	{
		_parent = wnd;
		return DisplayModal();
	}

	// IAudienceSelector
	virtual bool Start(std::shared_ptr<IKeyVEILSession> session, XP_WINDOW parent, const GUID& CryptoGroupId, std::shared_ptr<ICmsHeaderAttributeGroup> group, std::shared_ptr<ICmsHeaderAttributeListExtension> attrList) override
	{
		if (session == NULL || group == NULL)
			return false;

		if (!session->IsLoggedIn())
			return false;

		_cryptoGroupId = CryptoGroupId;
		_ckm7group = group;
		_attrsList = attrList;
		_session = session;
		_selectedAttributeCount = 0;

		return true;
	}
protected:
	XP_WINDOW											_parent;
	std::shared_ptr<AttributeSelectorGrid>				Me; // Keep me alive until Destroy is called
	std::shared_ptr<IKeyVEILSession>					_session;
	GUID												_cryptoGroupId;
	std::shared_ptr<ICmsHeaderAttributeGroup>			_ckm7group;
	std::shared_ptr<ICmsHeaderAttributeListExtension>	_attrsList;
	std::vector<GUID>									_GuidMap;
	wxImageList											_imageList;
	Asn1::CTS::_POD_CryptoGroup*						_cryptoGroup;
	int													_selectedAttributeCount;
	std::vector<Asn1::CTS::_POD_Category*>				_catList;
	std::shared_ptr<Asn1::CTS::_POD_Profile>			_profile;

	void MarkIncomingAttributes()
	{
		int count;
		wxString name;
		tscrypto::tsCryptoString wName;
		int rowCount;
		int colCount;
		int id = 0;

		if (!_ckm7group || !_attrsList)
			return;

		// CKM 7
		count = (int)_ckm7group->GetAttributeCount();

		rowCount = edtGrid->GetNumberRows();
		colCount = edtGrid->GetNumberCols();

		for (int row = 0; row < rowCount; row++)
		{
			for (int col = 0; col < colCount; col++)
			{
				name = edtGrid->GetCellValue(row, col);
				tscrypto::tsCryptoStringList parts = tscrypto::tsCryptoString(name.mbc_str()).split("~");
				if (parts->size() > 1)
					id = TsStrToInt(parts->at(1));
				wName = name.mbc_str();
				if (wName[0] == '-')
				{
					GUID attributeGuid = _GuidMap[id];
					std::shared_ptr<ICmsHeaderAttribute> attr;

					for (int i = 0; i < count; i++)
					{
						attr.reset();

						if (_attrsList->GetAttribute(_ckm7group->GetAttributeIndex(i), attr) && attr->GetAttributeGUID() == attributeGuid)
						{
							_selectedAttributeCount++;
							wName[0] = '+';
							edtGrid->SetCellValue(row, col, wName.c_str());
							break;
						}
					}
				}
			}
		}
	}

	std::vector<Asn1::CTS::_POD_Category*> BuildCategoryList(Asn1::CTS::_POD_CryptoGroup* cryptoGroup)
	{
		std::vector<Asn1::CTS::_POD_Category*> tmp;

		for (size_t i = 0; i < cryptoGroup->get_FiefdomList()->size(); i++)
		{
			Asn1::CTS::_POD_Fiefdom& fief = cryptoGroup->get_FiefdomList()->get_at(i);
			for (size_t j = 0; j < fief.get_CategoryList()->size(); j++)
			{
				tmp.push_back(&fief.get_CategoryList()->get_at(j));
			}
		}
		return tmp;
	}

	void FillGrid(Asn1::CTS::_POD_CryptoGroup* cryptoGroup)
	{
		int count;
		int i;
		Asn1::CTS::_POD_Category* cat;
		tscrypto::tsCryptoString name;
		int maxAttrCount = 0;
		int attributeCount = 0;
		//ROWCOLOR rowcolor = {0xFF0000, 0x00FFFF};

		edtGrid->ClearGrid();
		if (edtGrid->GetNumberCols() > 0)
			edtGrid->DeleteCols(0, edtGrid->GetNumberCols());
		if (edtGrid->GetNumberRows() > 0)
			edtGrid->DeleteRows(0, edtGrid->GetNumberRows());
		edtGrid->SetBackgroundColour(wxColour(0xf0f0f0));
		edtGrid->SetForegroundColour(wxColour((unsigned long)0));
		edtGrid->SetSelectionBackground(wxColour((unsigned long)0x000060));
		edtGrid->SetSelectionForeground(wxColour((unsigned long)0xFFFFFF));

		//    SendMessage(hGrd,GM_SETTEXTCOLOR,0x000000,0);

		_GuidMap.clear();


		if (cryptoGroup != NULL)
		{
			_catList = BuildCategoryList(cryptoGroup);
			count = (int)_catList.size();

			// First determine the size of the grid
			for (i = 0; i < count; i++)
			{
				cat = _catList[i];

				attributeCount = (int)cat->get_AttributeList()->size();

				int removeCount = 0;
				for (int j = 0; j < attributeCount; j++)
				{
					Asn1::CTS::_POD_Attribute& attr = cat->get_AttributeList()->get_at(j);
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
					_catList.erase(_catList.begin() + i);
					i--;
				}
			}

			// Then create the columns and rows
			count = (int)_catList.size();
			if (count == 0)
			{
				EndDialog(wxID_CANCEL);
				return;
			}
			edtGrid->CreateGrid(maxAttrCount, count, wxGrid::wxGridSelectCells);
			edtGrid->SetSelectionMode(wxGrid::wxGridSelectionModes::wxGridSelectCells);
			edtGrid->EnableDragCell(false);
			edtGrid->EnableDragColMove(false);
#ifndef SUPPORT_KEYBOARD_SELECTION
			edtGrid->EnableEditing(false);
#endif // SUPPORT_KEYBOARD_SELECTION
			//edtGrid->Connect(ID_GRID, wxEVT_CHAR, wxKeyEventHandler(AttributeSelectorGrid::OnGridChar), NULL, this);

			// and finally populate the grid

			for (i = 0; i < count; i++)
			{
				cat = _catList[i];
				name = cat->get_Name();

				edtGrid->SetColLabelValue(i, name.c_str());
			}

			for (i = 0; i < count; i++)
			{
				cat = _catList[i];
				if (cat != nullptr)
				{
					std::vector<tscrypto::tsCryptoString> names;
					//
					// Now populate the rows for this column
					//
					attributeCount = (int)cat->get_AttributeList()->size();
					for (int j = 0; j < attributeCount; j++)
					{
						Asn1::CTS::_POD_Attribute& attr = cat->get_AttributeList()->get_at(j);
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
						edtGrid->SetCellRenderer(row, i, new MyGridCellRenderer());
#ifdef SUPPORT_KEYBOARD_SELECTION
						edtGrid->SetCellEditor(row, i, new MyGridCellEditor());
#endif // SUPPORT_KEYBOARD_SELECTION
						edtGrid->SetCellValue(row++, i, name.c_str());
					}
				}
			}
		}
		else
			count = 0;
	}

	Asn1::CTS::_POD_CryptoGroup* GetCryptoGroupById(std::shared_ptr<IKeyVEILSession> session, const GUID& id)
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

	Asn1::CTS::_POD_CryptoGroup* GetCryptoGroup(std::shared_ptr<IKeyVEILSession> session, size_t index)
	{
		if (!_profile->exists_cryptoGroupList())
			return nullptr;

		if (index >= _profile->get_cryptoGroupList()->size())
			return nullptr;
		return &_profile->get_cryptoGroupList()->get_at(index);
	}

	Asn1::CTS::_POD_CryptoGroup* GetCryptoGroup(std::shared_ptr<IKeyVEILSession> session, const GUID& cgId)
	{
		if (cgId == GUID_NULL)
		{
			return GetCryptoGroup(_session, (int)(intptr_t)cmbCG->GetClientData(cmbCG->GetSelection()));
		}
		else
			return GetCryptoGroupById(session, cgId);
	}

	int FindAttrIndex(std::shared_ptr<ICmsHeaderAttributeListExtension> attrList, const GUID &id)
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
	void OnInitDialog()
	{
		btnOK->Enable(false);

		if (_cryptoGroupId == GUID_NULL)
		{
			Asn1::CTS::_POD_CryptoGroup* CryptoGroup = nullptr;
			int count;
			int i;
			tscrypto::tsCryptoString name;

			lblCG->Enable(false);
			lblCG->Show(false);
			cmbCG->Enable(true);
			cmbCG->Show(true);

			_profile = _session->GetProfile();

			count = (int)_profile->get_cryptoGroupList()->size();
			for (i = 0; i < count; i++)
			{
				CryptoGroup = nullptr;
				CryptoGroup = &_profile->get_cryptoGroupList()->get_at(i);
				name = CryptoGroup->get_Name();
				cmbCG->Append(name.c_str(), (void*)(intptr_t)i);
			}
			if (cmbCG->GetCount() > 0)
			{
				cmbCG->SetSelection(0);

				CryptoGroup = GetCryptoGroup(_session, _cryptoGroupId);
				FillGrid(CryptoGroup);
			}
		}
		else
		{
			Asn1::CTS::_POD_CryptoGroup* CryptoGroup = nullptr;
			tscrypto::tsCryptoString name;

			lblCG->Enable(true);
			lblCG->Show(true);
			cmbCG->Enable(false);
			cmbCG->Show(false);

			CryptoGroup = GetCryptoGroupById(_session, _cryptoGroupId);
			if (!CryptoGroup)
			{
				EndDialog(wxID_CANCEL);
				return;
			}

			name = CryptoGroup->get_Name();
			lblCG->SetLabel(name.c_str());

			FillGrid(CryptoGroup);
			MarkIncomingAttributes();
		}
		btnOK->Enable((_selectedAttributeCount > 0) ? true : false);
	}

	/// Creation
	bool Create(wxWindow* parent, wxWindowID id = SYMBOL_ATTRIBUTESELECTORGRID_IDNAME, const wxString& caption = SYMBOL_ATTRIBUTESELECTORGRID_TITLE, const wxPoint& pos = SYMBOL_ATTRIBUTESELECTORGRID_POSITION, const wxSize& size = SYMBOL_ATTRIBUTESELECTORGRID_SIZE, long style = SYMBOL_ATTRIBUTESELECTORGRID_STYLE)
	{
		Me = std::dynamic_pointer_cast<AttributeSelectorGrid>(_me.lock());

		////@begin AttributeSelectorGrid creation
		SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY | wxWS_EX_BLOCK_EVENTS);
		wxDialog::Create(parent, id, caption, pos, size, style);

		CreateControls();
		if (GetSizer())
		{
			GetSizer()->SetSizeHints(this);
		}
		Centre();
		////@end AttributeSelectorGrid creation
		OnInitDialog();
		return true;
	}
	/// Initialises member variables
	void Init()
	{
		////@begin AttributeSelectorGrid member initialisation
		cmbCG = NULL;
		lblCG = NULL;
		edtGrid = NULL;
		btnOK = NULL;
		////@end AttributeSelectorGrid member initialisation	
	}

	/// Creates the controls and sizers
	void CreateControls()
	{
		////@begin AttributeSelectorGrid content construction
		AttributeSelectorGrid* itemDialog1 = this;

		wxFlexGridSizer* itemFlexGridSizer2 = new wxFlexGridSizer(0, 1, 0, 0);
		itemDialog1->SetSizer(itemFlexGridSizer2);

		wxFlexGridSizer* itemFlexGridSizer3 = new wxFlexGridSizer(0, 2, 0, 0);
		itemFlexGridSizer2->Add(itemFlexGridSizer3, 0, wxGROW | wxALIGN_CENTER_VERTICAL | wxALL, 0);

		wxStaticText* itemStaticText4 = new wxStaticText(itemDialog1, wxID_STATIC, _("CryptoGroup:"), wxDefaultPosition, wxDefaultSize, 0);
		itemFlexGridSizer3->Add(itemStaticText4, 0, wxALIGN_CENTER_HORIZONTAL | wxALIGN_CENTER_VERTICAL | wxALL, 5);

		wxBoxSizer* itemBoxSizer5 = new wxBoxSizer(wxVERTICAL);
		itemFlexGridSizer3->Add(itemBoxSizer5, 0, wxGROW | wxALIGN_CENTER_VERTICAL | wxALL, 5);

		wxArrayString cmbCGStrings;
		cmbCG = new wxChoice(itemDialog1, ID_CRYPTOGROUPLIST, wxDefaultPosition, wxDefaultSize, cmbCGStrings, 0);
		itemBoxSizer5->Add(cmbCG, 0, wxGROW | wxALL, 0);

		lblCG = new wxStaticText(itemDialog1, ID_CRYPTOGROUP_STATIC, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0);
		itemBoxSizer5->Add(lblCG, 0, wxGROW | wxALL, 5);

		itemFlexGridSizer3->AddGrowableCol(1);

		edtGrid = new wxGrid(itemDialog1, ID_GRID, wxDefaultPosition, wxSize(500, 250), wxSUNKEN_BORDER | wxHSCROLL | wxVSCROLL);
		edtGrid->SetDefaultColSize(80);
		edtGrid->SetDefaultRowSize(25);
		edtGrid->SetColLabelSize(25);
		edtGrid->SetRowLabelSize(0);
		itemFlexGridSizer2->Add(edtGrid, 0, wxGROW|wxALL, 5);

		wxStdDialogButtonSizer* itemStdDialogButtonSizer9 = new wxStdDialogButtonSizer;

		itemFlexGridSizer2->Add(itemStdDialogButtonSizer9, 0, wxALIGN_CENTER_HORIZONTAL | wxALIGN_CENTER_VERTICAL | wxALL, 5);
		btnOK = new wxButton(itemDialog1, wxID_OK, _("&OK"), wxDefaultPosition, wxDefaultSize, 0);
		btnOK->SetDefault();
		itemStdDialogButtonSizer9->AddButton(btnOK);

		wxButton* itemButton11 = new wxButton(itemDialog1, wxID_CANCEL, _("&Cancel"), wxDefaultPosition, wxDefaultSize, 0);
		itemStdDialogButtonSizer9->AddButton(itemButton11);

		itemStdDialogButtonSizer9->Realize();

   	 	itemFlexGridSizer2->AddGrowableRow(1);
    	itemFlexGridSizer2->AddGrowableCol(0);

		////@end AttributeSelectorGrid content construction
	}

	////@begin AttributeSelectorGrid event handler declarations

		/// wxEVT_GRID_CELL_LEFT_CLICK event handler for ID_GRID
	void OnCellLeftClick(wxGridEvent& event)
	{
		int col = event.GetCol();
		int row = event.GetRow();
		wxString name = edtGrid->GetCellValue(row, col);
		tscrypto::tsCryptoString wName = name.mbc_str();

		event.Skip();
		if (wName.size() > 0)
		{
			if (wName[0] == '+')
			{
				_selectedAttributeCount--;
				wName[0] = '-';
				edtGrid->SetCellValue(row, col, wName.c_str());
			}
			else if (wName[0] == '-')
			{
				_selectedAttributeCount++;
				wName[0] = '+';
				edtGrid->SetCellValue(row, col, wName.c_str());
			}
			btnOK->Enable(_selectedAttributeCount > 0);
		}
	}

	/*
	* wxEVT_GRID_SELECT_CELL event handler for ID_GRID
	*/
	void AttributeSelectorGrid::OnSelectCell(wxGridEvent& event)
	{
		event.Skip();
	}

	void OnOkClick(wxCommandEvent& event)
	{
		Asn1::CTS::_POD_CryptoGroup* CryptoGroup = nullptr;
		int rowCount;
		int colCount;
		wxString name;

		event.StopPropagation();
		if (!!_ckm7group && !!_attrsList)
		{
			CryptoGroup = GetCryptoGroup(_session, _cryptoGroupId);
			if (!CryptoGroup)
			{
				wxMessageBox("You must first select a cryptogroup.", "Error", MB_OK);
				return;
			}

			while (_ckm7group->GetAttributeCount() > 0)
				_ckm7group->RemoveAttributeIndex(0);

			rowCount = edtGrid->GetNumberRows();
			colCount = edtGrid->GetNumberCols();

			for (int col = 0; col < colCount; col++)
			{
				for (int row = 0; row < rowCount; row++)
				{
					if (!edtGrid->GetCellValue(row, col).IsEmpty())
					{
					name = edtGrid->GetCellValue(row, col);
					if (name[0] == '+')
					{
						tscrypto::tsCryptoStringList parts = tscrypto::tsCryptoString(name.mbc_str()).split("~");
						int id = 0;
						if (parts->size() > 1)
							id = TsStrToInt(parts->at(1));
						GUID attributeGuid = _GuidMap[id];

						int idx = FindAttrIndex(_attrsList, attributeGuid);

						if (idx >= 0)
							_ckm7group->AddAttributeIndex(idx);
						}
					}
				}
			}
			_cryptoGroupId = CryptoGroup->get_Id();
		}
		else
		{
		}
		EndDialog(wxID_OK);
	}

	void OnCancelClick(wxCommandEvent& event)
	{
		EndDialog(wxID_CANCEL);
	}

	void OnCGSelChange(wxCommandEvent& event)
	{
		Asn1::CTS::_POD_CryptoGroup* CryptoGroup = nullptr;

		CryptoGroup = GetCryptoGroup(_session, _cryptoGroupId);
		FillGrid(CryptoGroup);
	}

	/*
	 * wxEVT_CHAR event handler for ID_GRID
	 */
	
	/*
	 * wxEVT_GRID_CELL_CHANGED event handler for ID_GRID
	 */
	
	void AttributeSelectorGrid::OnCellChanged( wxGridEvent& event )
	{
		int col = event.GetCol();
		int row = event.GetRow();
		wxString name = edtGrid->GetCellValue(row, col);
		tscrypto::tsCryptoString wName = name.mbc_str();

		event.Skip();
		if (wName.size() > 0)
		{
			if (wName[0] == '-')
			{
				_selectedAttributeCount--;
			}
			else if (wName[0] == '+')
			{
				_selectedAttributeCount++;
			}
			btnOK->Enable(_selectedAttributeCount > 0);
		}
	}
	
	////@end AttributeSelectorGrid event handler declarations

		/// Should we show tooltips?
	static bool ShowToolTips()
	{
		return true;
	}

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

private:
	////@begin AttributeSelectorGrid member variables
	wxChoice* cmbCG;
	wxStaticText* lblCG;
	wxGrid* edtGrid;
	wxButton* btnOK;
	////@end AttributeSelectorGrid member variables
};

/*
 * AttributeSelectorGrid event table definition
 */

BEGIN_EVENT_TABLE(AttributeSelectorGrid, wxDialog)

////@begin AttributeSelectorGrid event table entries
EVT_GRID_CELL_LEFT_CLICK(AttributeSelectorGrid::OnCellLeftClick)
EVT_GRID_CELL_CHANGED( AttributeSelectorGrid::OnCellChanged )
EVT_GRID_SELECT_CELL(AttributeSelectorGrid::OnSelectCell)
EVT_BUTTON(wxID_OK, AttributeSelectorGrid::OnOkClick)
EVT_BUTTON(wxID_CANCEL, AttributeSelectorGrid::OnCancelClick)
EVT_CHOICE(ID_CRYPTOGROUPLIST, AttributeSelectorGrid::OnCGSelChange)
////@end AttributeSelectorGrid event table entries

END_EVENT_TABLE()

tsmod::IObject* CreateAttributeSelectorGrid()
{
	return dynamic_cast<tsmod::IObject*>(new AttributeSelectorGrid());
}