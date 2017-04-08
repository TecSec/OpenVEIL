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


// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#include "VEIL.h"
#include "VEILCmsHeader.h"
#include "VEILwxWidgets.h"

#include "wx/grid.h"
#include "wx/wizard.h"
#include "wx/propdlg.h"
#include "wx/bookctrl.h"

#define SUPPORT_KEYBOARD_SELECTION

class wxTokenEvent : public wxCommandEvent
{
public:
	// how was this help event generated?
	enum ChangeType
	{
		Type_Unknown,    // unrecognized event source
		Type_Add,
		Type_Remove,
		Type_Change
	};

	wxTokenEvent(wxEventType type = wxEVT_NULL,
		wxWindowID winid = 0,
		const wxPoint& pt = wxDefaultPosition,
		ChangeType origin = Type_Unknown)
		: wxCommandEvent(type, winid),
		m_pos(pt),
		m_origin(origin)
	{ }
	wxTokenEvent(const wxTokenEvent& event)
		: wxCommandEvent(event),
		m_pos(event.m_pos),
		m_tokenName(event.m_tokenName),
		m_origin(event.m_origin)
	{ }

	// Position of event (in screen coordinates)
	const wxPoint& GetPosition() const { return m_pos; }
	void SetPosition(const wxPoint& pos) { m_pos = pos; }

	// Optional link to further help
	const wxString& GetTokenName() const { return m_tokenName; }
	void SetTokenName(const wxString& link) { m_tokenName = link; }

	virtual wxEvent *Clone() const wxOVERRIDE { return new wxTokenEvent(*this); }

	// optional indication of the event source
	ChangeType GetChangeType() const { return m_origin; }
	void SetChangeType(ChangeType origin) { m_origin = origin; }

protected:
	wxPoint   m_pos;
	wxString  m_tokenName;
	ChangeType m_origin;

private:
	//wxDECLARE_DYNAMIC_CLASS_NO_ASSIGN(wxTokenEvent);
};
typedef void (wxEvtHandler::*wxTokenEventFunction)(wxTokenEvent&);
#define wxTokenEventHandler(func) wxEVENT_HANDLER_CAST(wxTokenEventFunction, func)
#define EVT_TOKEN_CHANGE(winid, func) wx__DECLARE_EVT1(wxEVT_HELP, winid, wxTokenEventHandler(func))

struct audienceSelector2Variables
{
	std::shared_ptr<ICmsHeader>						_header;
	std::shared_ptr<IKeyVEILConnector>				_connector;
	std::shared_ptr<IToken>							_token;
	std::shared_ptr<IKeyVEILSession>				_session;
	bool                                            _favoriteManager;
	tscrypto::tsCryptoString                        _favoriteName;
	GUID                                            _favoriteId;
	bool                                            _hideKeyVEILLogin;
};

struct attributeSelectorVariables
{
	std::shared_ptr<IKeyVEILSession>					_session;
	GUID												_cryptoGroupId;
	std::shared_ptr<ICmsHeaderAttributeGroup>			_ckm7group;
	std::shared_ptr<ICmsHeaderAttributeListExtension>	_attrsList;
	int													_selectedAttributeCount;
};

struct tokenLoginVariables
{
	std::shared_ptr<IKeyVEILSession> _session;
	//ICKMSessionSSO *sso;
	int								 _minLen;
	int								 _maxLen;
	tscrypto::tsCryptoString		 _pinBuffer;
};

struct keyVeilLoginVariables
{
	std::shared_ptr<IKeyVEILConnector>	_connector;
	tscrypto::tsCryptoString			_url;
	tscrypto::tsCryptoString			_username;
	tscrypto::tsCryptoString			_pinBuffer;
};

struct tokenSelectorVariables
{
	std::shared_ptr<IKeyVEILConnector>	_connector;
	GUID								m_enterpriseOID;
	tscrypto::tsCryptoString            m_reason;
	std::shared_ptr<IKeyVEILSession>    m_session;
};

struct enterPinVariables
{
	std::function<bool(std::shared_ptr<IEnterPin>, const tscrypto::tsCryptoString&)> pinTesterFn;
	std::function<int(std::shared_ptr<IEnterPin>, const tscrypto::tsCryptoString&)> pinStrengthFn;
	bool m_creatingPin;
	bool m_changingPin;
	tscrypto::tsCryptoString m_oldPin;
	tscrypto::tsCryptoString m_pin;
	std::shared_ptr<IEnterPin> DlgWrapper;
	uint32_t minLen;
	uint32_t maxLen;
	uint32_t weakStrength;
	uint32_t strongStrength;
	uint32_t maxStrength;
	uint32_t helpId;
};

#include "attributeselectorgrid.h"
#include "AttributeSelectorGridWrapper.h"

#include "groupeditorwizardpage.h"
#include "keyveilwizardpage.h"
#include "saveselectionwizardpage.h"
#include "tokenselectionwizardpage.h"

#include "audienceselector2.h"
#include "audienceselector2Wrapper.h"

#include "favoritemanagerdlg.h"
#include "FavoriteManagerWrapper.h"

#include "tokenlogindlg.h"
#include "keyveillogindlg.h"
#include "favoriteselectionpage.h"
#include "favoritenamedlg.h"
#include "tokenselectordlg.h"
#include "aboutckm.h"
#include "audienceselectordlg.h"
#include "VEILwxWidgetsVersion.h"

#include "propertysheetdlg.h"
#include "progressdlg.h"

#include "enterpindlg.h"
#include "changenamedlg.h"

#include "veilfilepropertypage.h"
#include "generalsettingspropertypage.h"

using namespace tscrypto;

extern XP_MODULE hDllInstance;
//extern WXBITMAP logo;

extern tsmod::IObject* CreateAudienceSelector();
extern tsmod::IObject* CreateFavoriteEditer();
extern tsmod::IObject* CreateAttributeSelectorGrid();
extern tsmod::IObject* CreateTokenLogIn();
extern tsmod::IObject* CreateAboutCkm();
extern tsmod::IObject* CreateKeyVEILLogIn();
extern tsmod::IObject* CreateTokenSelector();
extern tsmod::IObject* CreateFavoriteName();
extern tsmod::IObject* CreateProgressDlg();
extern tsmod::IObject* CreateVEILPropertySheet();
extern tsmod::IObject* CreateGeneralSettingsPage();
extern tsmod::IObject* CreateVEILFileSettingsPage();
extern tsmod::IObject* CreateAudienceSelector2();
extern tsmod::IObject* CreateFavoriteManager();
extern tsmod::IObject* CreateEnterPinDlg();
extern tsmod::IObject* CreateChangeName();
extern tsmod::IObject* CreateWxHelpRegistry();

class CWaitCursor
{
public:
	CWaitCursor(wxWindow* window)
	{
		_window = window;
		window->GetCursor();
		window->SetCursor(wxCursor(wxCURSOR_WAIT));
	}
	~CWaitCursor()
	{
		_window->SetCursor(oldCursor);
	}
private:
	wxCursor oldCursor;
	wxWindow* _window;
};


extern const char * tecseclogo_xpm[1825];

/// Retrieves bitmap resources
wxBitmap GetBitmapResource(const wxString& name);

/// Retrieves icon resources
wxIcon GetIconResource(const wxString& name);


#ifdef SUPPORT_KEYBOARD_SELECTION
class MyGridCellEditor : public wxGridCellEditor
{
public:
	MyGridCellEditor() 
	{
	}


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

		fullValue = grid->GetTable()->GetValue(row, col).c_str().AsChar();
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
		tscrypto::tsCryptoString val(value.c_str().AsChar());

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

