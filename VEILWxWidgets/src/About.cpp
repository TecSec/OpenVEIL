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
#include "VEILwxWidgetsVersion.h"

////@begin control identifiers
#define ID_ABOUTCKM 10000
#define wxID_VERSIONSTRING 10001
#define wxID_COPYRIGHTSTRING 10002
#define wxID_VEILSUITE 10003
#define wxID_TM_LINE 10004
#define wxID_WARNING_LINE 10005
#define wxID_PATENTS 10006
#define SYMBOL_ABOUTCKM_STYLE wxCAPTION|wxSYSTEM_MENU|wxCLOSE_BOX|wxTAB_TRAVERSAL
#define SYMBOL_ABOUTCKM_TITLE _("About CKM")
#define SYMBOL_ABOUTCKM_IDNAME ID_ABOUTCKM
#define SYMBOL_ABOUTCKM_SIZE wxSize(400, 300)
#define SYMBOL_ABOUTCKM_POSITION wxDefaultPosition
////@end control identifiers

class AboutCkm : public IVEILWxUIBase, public tsmod::IObject, public wxDialog
{
	DECLARE_EVENT_TABLE()

public:
	AboutCkm() : _parent(nullptr)
	{
		Init();
	}
	virtual ~AboutCkm() {}

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

protected:
	XP_WINDOW				  _parent;
	std::shared_ptr<AboutCkm> Me; // Keep me alive until Destroy is called

	/// Creation
	bool Create(wxWindow* parent, wxWindowID id = SYMBOL_ABOUTCKM_IDNAME, const wxString& caption = SYMBOL_ABOUTCKM_TITLE, const wxPoint& pos = SYMBOL_ABOUTCKM_POSITION, const wxSize& size = SYMBOL_ABOUTCKM_SIZE, long style = SYMBOL_ABOUTCKM_STYLE)
	{
		Me = std::dynamic_pointer_cast<AboutCkm>(_me.lock());

		////@begin AboutCKM creation
		SetExtraStyle(wxWS_EX_VALIDATE_RECURSIVELY | wxWS_EX_BLOCK_EVENTS);
		wxDialog::Create(parent, id, caption, pos, size, style);

		CreateControls();
		if (GetSizer())
		{
			GetSizer()->SetSizeHints(this);
		}
		Centre();
		////@end AboutCKM creation
		return true;
	}
	/// Initialises member variables
	void Init()
	{

	}

	/// Creates the controls and sizers
	void CreateControls()
	{
		////@begin AboutCKM content construction
		AboutCkm* itemDialog1 = this;

		wxFlexGridSizer* itemFlexGridSizer2 = new wxFlexGridSizer(9, 1, 0, 0);
		itemDialog1->SetSizer(itemFlexGridSizer2);

    wxStaticBitmap* itemStaticBitmap3 = new wxStaticBitmap( itemDialog1, wxID_STATIC, itemDialog1->GetBitmapResource(wxT("../../src/tecseclogo.xpm")), wxDefaultPosition, wxSize(372, 73), 0 );
    itemFlexGridSizer2->Add(itemStaticBitmap3, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 0);

    wxStaticText* itemStaticText4 = new wxStaticText( itemDialog1, wxID_STATIC, wxGetTranslation(wxString(wxT("CKM ")) + (wxChar) 0x00AE), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer2->Add(itemStaticText4, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 0);

    wxStaticText* itemStaticText5 = new wxStaticText( itemDialog1, wxID_VERSIONSTRING, wxString("Version:  ") + wxString(VEILWXWINDOWS_FULL_VERSION), wxDefaultPosition, wxDefaultSize, 0 );
    itemFlexGridSizer2->Add(itemStaticText5, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStaticText* itemStaticText6 = new wxStaticText( itemDialog1, wxID_COPYRIGHTSTRING, _(VEIL_COPYRIGHT), wxDefaultPosition, wxDefaultSize, 0 );
		itemStaticText6->Wrap(360);
    itemFlexGridSizer2->Add(itemStaticText6, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStaticText* itemStaticText7 = new wxStaticText( itemDialog1, wxID_VEILSUITE, _("The VEIL suite includes KeyVEIL, OpenVEIL, OpaqueVEIL and more."), wxDefaultPosition, wxDefaultSize, 0 );
		itemStaticText7->Wrap(360);
    itemFlexGridSizer2->Add(itemStaticText7, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStaticText* itemStaticText8 = new wxStaticText( itemDialog1, wxID_TM_LINE, _("VEIL, CKM and Constructive Key Management are registered trademarks of TecSec, Inc."), wxDefaultPosition, wxDefaultSize, 0 );
		itemStaticText8->Wrap(360);
    itemFlexGridSizer2->Add(itemStaticText8, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStaticText* itemStaticText9 = new wxStaticText( itemDialog1, wxID_WARNING_LINE, _("Warning: All VEIL and CKM programs are protected by copyright law and international treaties. Unauthorized reproduction or distribution of these programs or any portion of them may result in civil and criminal penalties, and will be prosecuted to the fullest extent possible under law."), wxDefaultPosition, wxDefaultSize, 0 );
		itemStaticText9->Wrap(360);
    itemFlexGridSizer2->Add(itemStaticText9, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxStaticText* itemStaticText10 = new wxStaticText( itemDialog1, wxID_PATENTS, _("This product is protected by one or more of the following U.S. patents, as well as pending U.S. patent applications and foreign patents: \n5,369,702; 5,369,707; 5,375,169; 5,410,599; 5,432,851; 5,440,290; 5,680,452; 5,787,173; 5,898,781; 6,075,865; 6,229,445; 6,266,417; 6,490,680; 6,542,608; 6,549,623; 6,606,386; 6,608,901; 6,684,330; 6,694,433; 6,754,820; 6,845,453; 6,868,598; 7,016,495; 7,069,448; 7,079,653; 7,089,417; 7,095,851; 7,095,852; 7,111,173; 7,131,009; 7,178,030; 7,212,632; 7,490,240; 7,539,855; 7,738,660 ;7,817,800; 7,974,410; 8,077,870; 8,083,808; 8,285,991; 8,308,820; 8,712,046"), wxDefaultPosition, wxDefaultSize, 0 );
		itemStaticText10->Wrap(360);
    itemFlexGridSizer2->Add(itemStaticText10, 0, wxALIGN_LEFT|wxALIGN_CENTER_VERTICAL|wxALL, 5);

    wxButton* itemButton11 = new wxButton( itemDialog1, wxID_OK, _("OK"), wxDefaultPosition, wxDefaultSize, 0 );
		itemButton11->SetDefault();
    itemFlexGridSizer2->Add(itemButton11, 0, wxALIGN_CENTER_HORIZONTAL|wxALIGN_CENTER_VERTICAL|wxALL, 5);

		////@end AboutCKM content construction
	}

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
};

/*
* AboutCKM event table definition
*/

BEGIN_EVENT_TABLE(AboutCkm, wxDialog)

////@begin AboutCKM event table entries
////@end AboutCKM event table entries

END_EVENT_TABLE()

tsmod::IObject* CreateAboutCkm()
{
	return dynamic_cast<tsmod::IObject*>(new AboutCkm());
}