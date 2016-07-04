//	Copyright (c) 2016, TecSec, Inc.
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

/*!
 * Control identifiers
 */

 ////@begin control identifiers
#define ID_FAVORITENAME 10000
#define ID_NAME 10001
#define SYMBOL_FAVORITENAME_STYLE wxCAPTION|wxSYSTEM_MENU|wxCLOSE_BOX|wxTAB_TRAVERSAL
#define SYMBOL_FAVORITENAME_TITLE _("Favorite Name")
#define SYMBOL_FAVORITENAME_IDNAME ID_FAVORITENAME
#define SYMBOL_FAVORITENAME_SIZE wxSize(400, 300)
#define SYMBOL_FAVORITENAME_POSITION wxDefaultPosition
////@end control identifiers

class FavoriteName : public IFavoriteName, public tsmod::IObject, public wxDialog
{
	DECLARE_EVENT_TABLE()

public:
	FavoriteName() : _parent(nullptr)
	{
		Init();
	}
	virtual ~FavoriteName() {}

	// wxDialog
	virtual bool Destroy() override
	{
		_parent = XP_WINDOW_INVALID;
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

	// IFavoriteName
	virtual bool Start(XP_WINDOW parent) override
	{
		Destroy();

		_parent = parent;
		return true;
	}
	virtual tscrypto::tsCryptoString Name() override
	{
		return _name;
	}
	virtual void Name(const tscrypto::tsCryptoString& setTo) override
	{
		_name = setTo;
	}
protected:
	XP_WINDOW  _parent;
	std::shared_ptr<FavoriteName> Me; // Keep me alive until Destroy is called
	tscrypto::tsCryptoString    _name;

	void OnInitDialog()
	{
		edtName->SetValue(_name.c_str());
		btnOK->Enable(edtName->GetValue().size() > 0);
	}

	/// Creation
	bool Create(wxWindow* parent, wxWindowID id = SYMBOL_FAVORITENAME_IDNAME, const wxString& caption = SYMBOL_FAVORITENAME_TITLE, const wxPoint& pos = SYMBOL_FAVORITENAME_POSITION, const wxSize& size = SYMBOL_FAVORITENAME_SIZE, long style = SYMBOL_FAVORITENAME_STYLE)
	{
		Me = std::dynamic_pointer_cast<FavoriteName>(_me.lock());

		////@begin FavoriteName creation
		SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY | wxWS_EX_BLOCK_EVENTS);
		wxDialog::Create(parent, id, caption, pos, size, style);

		CreateControls();
		if (GetSizer())
		{
			GetSizer()->SetSizeHints(this);
		}
		Centre();
		////@end FavoriteName creation

		OnInitDialog();

		return true;
	}

	/// Initialises member variables
	void Init()
	{
		////@begin FavoriteName member initialisation
		edtName = NULL;
		btnOK = NULL;
		btnCancel = NULL;
		////@end FavoriteName member initialisation
	}

	/// Creates the controls and sizers
	void CreateControls()
	{
		////@begin FavoriteName content construction
		FavoriteName* itemDialog1 = this;

		wxFlexGridSizer* itemFlexGridSizer2 = new wxFlexGridSizer(0, 1, 0, 0);
		itemDialog1->SetSizer(itemFlexGridSizer2);

		wxStaticText* itemStaticText3 = new wxStaticText(itemDialog1, wxID_STATIC, _("Enter the name by which this favorite shall be known:"), wxDefaultPosition, wxDefaultSize, 0);
		itemFlexGridSizer2->Add(itemStaticText3, 0, wxALIGN_CENTER_HORIZONTAL | wxALIGN_CENTER_VERTICAL | wxALL, 5);

		edtName = new wxTextCtrl(itemDialog1, ID_NAME, wxEmptyString, wxDefaultPosition, wxDefaultSize, 0);
		edtName->SetMaxLength(50);
		itemFlexGridSizer2->Add(edtName, 0, wxGROW | wxALIGN_CENTER_VERTICAL | wxALL, 5);

		wxStdDialogButtonSizer* itemStdDialogButtonSizer5 = new wxStdDialogButtonSizer;

		itemFlexGridSizer2->Add(itemStdDialogButtonSizer5, 0, wxALIGN_CENTER_HORIZONTAL | wxALIGN_CENTER_VERTICAL | wxALL, 5);
		btnOK = new wxButton(itemDialog1, wxID_OK, _("&OK"), wxDefaultPosition, wxDefaultSize, 0);
		btnOK->SetDefault();
		itemStdDialogButtonSizer5->AddButton(btnOK);

		btnCancel = new wxButton(itemDialog1, wxID_CANCEL, _("&Cancel"), wxDefaultPosition, wxDefaultSize, 0);
		itemStdDialogButtonSizer5->AddButton(btnCancel);

		itemStdDialogButtonSizer5->Realize();

		////@end FavoriteName content construction
	}

	////@begin FavoriteName event handler declarations

		/// wxEVT_COMMAND_TEXT_UPDATED event handler for ID_NAME
	void OnNameTextUpdated(wxCommandEvent& event)
	{
		btnOK->Enable(edtName->GetValue().size() > 0);
	}

	/// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_OK
	void OnOkClick(wxCommandEvent& event)
	{
		event.StopPropagation();

		_name = edtName->GetValue().mbc_str();
		_name.Trim();
		if (_name.size() == 0)
		{
			wxMessageBox(tscrypto::tsCryptoString().Format("The favorite name is empty.").c_str(), "Error", MB_ICONSTOP | MB_OK);
			return;
		}

		EndDialog(wxID_OK);
	}

	/// wxEVT_COMMAND_BUTTON_CLICKED event handler for wxID_CANCEL
	void OnCancelClick(wxCommandEvent& event)
	{
		EndDialog(wxID_CANCEL);
	}

	////@end FavoriteName event handler declarations

	////@begin FavoriteName member function declarations

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
	////@end FavoriteName member function declarations

		/// Should we show tooltips?
	static bool ShowToolTips()
	{
		return true;
	}

private:
	////@begin FavoriteName member variables
	wxTextCtrl* edtName;
	wxButton* btnOK;
	wxButton* btnCancel;
	////@end FavoriteName member variables
};

/*
 * FavoriteName event table definition
 */

BEGIN_EVENT_TABLE(FavoriteName, wxDialog)

////@begin FavoriteName event table entries
EVT_TEXT(ID_NAME, FavoriteName::OnNameTextUpdated)
EVT_BUTTON(wxID_OK, FavoriteName::OnOkClick)
EVT_BUTTON(wxID_CANCEL, FavoriteName::OnCancelClick)
////@end FavoriteName event table entries

END_EVENT_TABLE()

tsmod::IObject* CreateFavoriteName()
{
	return dynamic_cast<tsmod::IObject*>(new FavoriteName());
}