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

struct PageDescriptor
{
	PageDescriptor() : focusSet(false) {}

	tscrypto::tsCryptoString url;
	std::shared_ptr<IVEILPropertyPage> _page;
	bool focusSet;
};

class VEILPropertySheet : public IVEILPropertySheet, public tsmod::IObject, public wxPropertySheetDialog
{
public:
	VEILPropertySheet() : _parent(nullptr), notebook(nullptr), btnApply(nullptr)
	{
		_prefs = BasicVEILPreferences::Create();
		if (!!_prefs)
		{
			_prefs->loadValues();
			_prefs->StartMonitor();
		}
	}
	virtual ~VEILPropertySheet()
	{
	}

	// wxPropertySheetDialog
	virtual bool Destroy() override
	{
		_parent = XP_WINDOW_INVALID;
		for (PageDescriptor &pg : pages)
		{
			if (!!pg._page)
			{
				pg._page->Reset();
				pg._page->Destroy();
			}
			pg._page.reset();
			pg.focusSet = false;
		}
		notebook = nullptr;
		btnApply = nullptr;
		Me.reset();
		return true;
	}

	// Inherited via IVEILPropertySheet
	virtual void PageModified(bool setTo) override
	{
		if (btnApply != nullptr)
			btnApply->Enable(setTo);
	}
	virtual int DisplayModal(XP_WINDOW parent, PropertySheetType type) override
	{
		Destroy();
		_parent = parent;

		Me = std::dynamic_pointer_cast<VEILPropertySheet>(_me.lock());

		SetExtraStyle(wxDIALOG_EX_CONTEXTHELP | wxWS_EX_VALIDATE_RECURSIVELY);

		int tabImage1 = -1;
		int tabImage2 = -1;

		bool useToolBook = (type == ToolBook || type == ButtonToolBook);
		int resizeBorder = wxRESIZE_BORDER;

		if (useToolBook)
		{
			resizeBorder = 0;
			tabImage1 = 0;
			tabImage2 = 1;

			int sheetStyle = wxPROPSHEET_SHRINKTOFIT;
			if (type == ButtonToolBook)
				sheetStyle |= wxPROPSHEET_BUTTONTOOLBOOK;
			else
				sheetStyle |= wxPROPSHEET_TOOLBOOK;

			SetSheetStyle(sheetStyle);
			SetSheetInnerBorder(0);
			SetSheetOuterBorder(0);

			//// create a dummy image list with a few icons
			//const wxSize imageSize(32, 32);

			//m_imageList = new wxImageList(imageSize.GetWidth(), imageSize.GetHeight());
			//m_imageList->
			//	Add(wxArtProvider::GetIcon(wxART_INFORMATION, wxART_OTHER, imageSize));
			//m_imageList->
			//	Add(wxArtProvider::GetIcon(wxART_QUESTION, wxART_OTHER, imageSize));
			//m_imageList->
			//	Add(wxArtProvider::GetIcon(wxART_WARNING, wxART_OTHER, imageSize));
			//m_imageList->
			//	Add(wxArtProvider::GetIcon(wxART_ERROR, wxART_OTHER, imageSize));
		}
		//else
		//	m_imageList = NULL;

		Create((wxWindow*)_parent, wxID_ANY, _("Preferences"), wxDefaultPosition, wxDefaultSize,
			wxDEFAULT_DIALOG_STYLE | (int)wxPlatform::IfNot(wxOS_WINDOWS_CE, resizeBorder)
			);

		// If using a toolbook, also follow Mac style and don't create buttons
		if (!useToolBook)
			CreateButtons(wxOK | wxCANCEL | wxAPPLY |
				(int)wxPlatform::IfNot(wxOS_WINDOWS_CE, wxHELP)
				);

		notebook = GetBookCtrl();
		//notebook->SetImageList(m_imageList);

		// Instantiate the objects
		for (PageDescriptor& pg : pages)
		{
			if (!pg._page)
				pg._page = ::TopServiceLocator()->try_get_instance<IVEILPropertyPage>(pg.url.c_str());
		}

		// Now remove any from the list that we could not build
		pages.erase(std::remove_if(pages.begin(), pages.end(), [](PageDescriptor& pg) { return !pg._page; }), pages.end());

		bool selectMe = true;
		for (PageDescriptor& pg : pages)
		{
			pg._page->SetParent(Me);
			notebook->AddPage((wxPanel*)(wxWindow*)pg._page->CreatePage((XP_WINDOW)notebook), pg._page->Title().c_str(), selectMe);
			selectMe = false;
		}



		LayoutDialog();

		Connect(wxID_OK, wxEVT_BUTTON, wxCommandEventHandler(VEILPropertySheet::OnOkClicked), nullptr, (wxPropertySheetDialog*)this);
		Connect(wxID_CANCEL, wxEVT_BUTTON, wxCommandEventHandler(VEILPropertySheet::OnCancelClicked), nullptr, (wxPropertySheetDialog*)this);
		Connect(wxID_APPLY, wxEVT_BUTTON, wxCommandEventHandler(VEILPropertySheet::OnApplyClicked), nullptr, (wxPropertySheetDialog*)this);
		Connect(wxID_HELP, wxEVT_BUTTON, wxCommandEventHandler(VEILPropertySheet::OnHelpClicked), nullptr, (wxPropertySheetDialog*)this);
		notebook->Connect(wxEVT_NOTEBOOK_PAGE_CHANGING, wxNotebookEventHandler(VEILPropertySheet::OnPageChanging), nullptr, (wxPropertySheetDialog*)this);
		notebook->Connect(wxEVT_NOTEBOOK_PAGE_CHANGED, wxNotebookEventHandler(VEILPropertySheet::OnPageChanged), nullptr, (wxPropertySheetDialog*)this);

		btnApply = FindWindow(wxID_APPLY);

		if (btnApply != nullptr)
			btnApply->Enable(false);

		int retVal = ShowModal();
		// Make sure you call Destroy
		Destroy();
		return retVal;
	}
	virtual void AddStandardPage(StandardPropPage pageType) override
	{
		PageDescriptor page;

		switch (pageType)
		{
		case IVEILPropertySheet::VEILFileSettings:
			page.url = "/WxWin/VEILFileSettingsPage";
			pages.push_back(page);
			break;
		case IVEILPropertySheet::GeneralSettings:
			page.url = "/WxWin/GeneralSettingsPage";
			pages.push_back(page);
			break;
		}
	}
	virtual void AddCustomPage(const tscrypto::tsCryptoString& link) override
	{
		PageDescriptor page;

		if (pages.size() >= 10)
			return;

		page.url = link;
		pages.push_back(page);
	}
	virtual std::shared_ptr<BasicVEILPreferences> BasicPreferences() override
	{
		return _prefs;
	}
protected:
	void OnOkClicked(wxCommandEvent& evt)
	{
		int index = notebook->GetSelection();

		evt.StopPropagation();
		if (index >= 0 && index < pages.size())
		{
			if (pages[index]._page->Apply() != IVEILPropertyPage::NoError)
				return;
		}
		EndDialog(wxID_OK);
	}
	void OnCancelClicked(wxCommandEvent& evt)
	{
		int index = notebook->GetSelection();

		evt.StopPropagation();
		if (index >= 0 && index < pages.size())
		{
			if (pages[index]._page->QueryCancel())
			{
				return;
			}
		}
		EndDialog(wxID_CANCEL);
	}
	void OnApplyClicked(wxCommandEvent& evt)
	{
		int index = notebook->GetSelection();

		evt.StopPropagation();
		if (index >= 0 && index < pages.size())
		{
			pages[index]._page->Apply();
		}
	}
	void OnHelpClicked(wxCommandEvent& evt)
	{
		int index = notebook->GetSelection();

		evt.StopPropagation();
		if (index >= 0 && index < pages.size())
		{
			pages[index]._page->OnHelp();
		}
	}
	void OnPageChanging(wxNotebookEvent& evt)
	{
		int index = evt.GetOldSelection();

		evt.StopPropagation();
		if (index >= 0 && index < pages.size())
		{
			if (pages[index]._page->KillActive())
			{
				evt.Veto();
				return;
			}
			if (pages[index]._page->Apply() != IVEILPropertyPage::NoError)
			{
				evt.Veto();
				return;
			}
		}

		index = evt.GetSelection();
		if (index >= 0 && index < pages.size())
		{
			if (pages[index]._page->SetActive())
			{
				evt.Veto();
				return;
			}
		}
	}
	void OnPageChanged(wxNotebookEvent& evt)
	{
		int index = evt.GetSelection();

		evt.Skip();
		if (index >= 0 && index < pages.size())
		{
			if (!pages[index].focusSet)
			{
				pages[index]._page->QueryInitialFocus();
				pages[index].focusSet = true;
			}
		}
	}
protected:
	XP_WINDOW  _parent;
	std::shared_ptr<VEILPropertySheet> Me;
	std::vector<PageDescriptor> pages;
	std::shared_ptr<BasicVEILPreferences> _prefs;
	wxBookCtrlBase* notebook;
	wxWindow* btnApply;
};

tsmod::IObject* CreateVEILPropertySheet()
{
	return dynamic_cast<tsmod::IObject*>(new VEILPropertySheet());
}


