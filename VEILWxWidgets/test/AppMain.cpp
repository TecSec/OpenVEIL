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

IMPLEMENT_APP(MyApp)
bool MyApp::OnInit()
{
	MyFrame* frame = new MyFrame(wxT("GUI Test App"));

	InitializeVEILWxWidgets();

	GetChangeMonitor()->StartChangeMonitorThread();

	frame->Show(true);
	return true;
}

int MyApp::OnExit()
{
	if (HasChangeMonitor())
		GetChangeMonitor()->StopChangeMonitorThread();
	TerminateVEILSystem();
	return wxApp::OnExit();
}

const int ID_ABOUTCKM = wxID_HIGHEST + 1;
const int ID_KEYVEILLOGIN = ID_ABOUTCKM + 1;
const int ID_AUDIENCESELECTOR = ID_KEYVEILLOGIN + 1;
const int ID_FAVORITEMANAGER = ID_AUDIENCESELECTOR + 1;
const int ID_TOKENSELECTOR = ID_FAVORITEMANAGER + 1;
const int ID_FAVORITENAME = ID_TOKENSELECTOR + 1;
const int ID_PROPERTYSHEET = ID_FAVORITENAME + 1;

BEGIN_EVENT_TABLE(MyFrame, wxFrame)
	EVT_MENU(wxID_ABOUT, MyFrame::OnAbout)
	EVT_MENU(wxID_EXIT, MyFrame::OnQuit)
	EVT_MENU(ID_ABOUTCKM, MyFrame::OnAboutCkm)
	EVT_MENU(ID_KEYVEILLOGIN, MyFrame::OnKeyVEILLogin)
	EVT_MENU(ID_AUDIENCESELECTOR, MyFrame::OnAudienceSelector)
	EVT_MENU(ID_FAVORITEMANAGER, MyFrame::OnFavoriteManager)
	EVT_MENU(ID_TOKENSELECTOR, MyFrame::OnTokenSelector)
	EVT_MENU(ID_FAVORITENAME, MyFrame::OnFavoriteName)
	EVT_MENU(ID_PROPERTYSHEET, MyFrame::OnPropertySheet)
	END_EVENT_TABLE()

MyFrame::MyFrame(const wxString& title) : wxFrame(NULL, wxID_ANY, title)
{
	// Set the frame icon
	//SetIcon(wxIcon(mondrian_xpm));
	// Create a menu bar
	wxMenu *fileMenu = new wxMenu;
	wxMenu *guiMenu = new wxMenu;
	// The "About" item should be in the help menu
	wxMenu *helpMenu = new wxMenu;
	helpMenu->Append(wxID_ABOUT, wxT("&About...\tF1"),
		wxT("Show about dialog"));
	fileMenu->Append(wxID_EXIT, wxT("E&xit\tAlt - X"),
		wxT("Quit this program"));
	guiMenu->Append(ID_ABOUTCKM, wxT("&About CKM..."), wxT("Show the About CKM dialog"));
	guiMenu->Append(ID_KEYVEILLOGIN, wxT("&KeyVEIL Login..."), wxT("Show the KeyVEIL Login dialog"));
	guiMenu->Append(ID_AUDIENCESELECTOR, wxT("Audience &Selector..."), wxT("Show the Audience Selector"));
	guiMenu->Append(ID_FAVORITEMANAGER, wxT("&Favorite Manager..."), wxT("Show the Favorite Manager"));
	guiMenu->Append(ID_TOKENSELECTOR, wxT("&Token Selector..."), wxT("Show the Token Selector"));
	guiMenu->Append(ID_FAVORITENAME, wxT("Favorite &Name..."), wxT("Show the Favorite Name dialog"));
	guiMenu->Append(ID_PROPERTYSHEET, wxT("&Property sheet..."), wxT("Show the property sheet"));

	// Now append the freshly created menu to the menu bar...
	wxMenuBar *menuBar = new wxMenuBar();
	menuBar->Append(fileMenu, wxT("&File"));
	menuBar->Append(guiMenu, wxT("&GUI Windows"));
	menuBar->Append(helpMenu, wxT("&Help"));
	// ... and attach this menu bar to the frame
	SetMenuBar(menuBar);
	// Create a status bar just for fun
	CreateStatusBar(2);
	SetStatusText(wxT("Welcome to wxWidgets!"));
}
void MyFrame::OnQuit(wxCommandEvent& event)
{
	// Destroy the frame
	Close();
}
void MyFrame::OnAbout(wxCommandEvent& event)
{
	wxString msg;
	msg.Printf(wxT("Hello and welcome to %s"), wxVERSION_STRING);
	wxMessageBox(msg, wxT("About Minimal"), wxOK | wxICON_INFORMATION, this);
}
void MyFrame::OnAboutCkm(wxCommandEvent& event)
{
	std::shared_ptr<IVEILWxUIBase> dlg = ::TopServiceLocator()->get_instance<IVEILWxUIBase>("/WxWin/AboutCkm");

	dlg->DisplayModal();
}

void MyFrame::OnKeyVEILLogin(wxCommandEvent& event)
{
	std::shared_ptr<IVEILWxUIBase> dlg = ::TopServiceLocator()->get_instance<IVEILWxUIBase>("/WxWin/KeyVEILLogIn");
	std::shared_ptr<IKeyVEILLogin> logger = std::dynamic_pointer_cast<IKeyVEILLogin>(dlg);

	_connector.reset();
	dlg->DisplayModal((XP_WINDOW)this);
	_connector = logger->Connector();
}

void MyFrame::OnAudienceSelector(wxCommandEvent& event)
{
	std::shared_ptr<IVEILWxUIBase> dlg = ::TopServiceLocator()->get_instance<IVEILWxUIBase>("/WxWin/AudienceSelector");
	std::shared_ptr<IAudienceSelector> as = std::dynamic_pointer_cast<IAudienceSelector>(dlg);

	if (!_connector)
	{
		wxCommandEvent evt;

		OnKeyVEILLogin(evt);
	}
	if (!!_connector)
	{
		as->Start(_connector, (XP_WINDOW)this, "GUI Tester");
		dlg->DisplayModal((XP_WINDOW)this);
	}
}

void MyFrame::OnFavoriteManager(wxCommandEvent& event)
{
	std::shared_ptr<IVEILWxUIBase> dlg = ::TopServiceLocator()->get_instance<IVEILWxUIBase>("/WxWin/FavoriteEditor");
	std::shared_ptr<IAudienceSelector> as = std::dynamic_pointer_cast<IAudienceSelector>(dlg);

	if (!_connector)
	{
		wxCommandEvent evt;

		OnKeyVEILLogin(evt);
	}
	if (!!_connector)
	{
		as->Start(_connector, (XP_WINDOW)this, "GUI Tester");
		dlg->DisplayModal((XP_WINDOW)this);
	}
}

void MyFrame::OnTokenSelector(wxCommandEvent& event)
{
	std::shared_ptr<ITokenSelector> tokSel = ::TopServiceLocator()->get_instance<ITokenSelector>("/WxWin/TokenSelector");
	std::shared_ptr<IKeyVEILSession> sess;

	if (!_connector)
	{
		wxCommandEvent evt;

		OnKeyVEILLogin(evt);
	}
	if (tokSel->Start(_connector, GUID_NULL, "Select a token for testing", (XP_WINDOW)this) && tokSel->DisplayModal() == wxID_OK && !!(sess = tokSel->Session()))
	{
		wxMessageBox("Success");
	}
}

void MyFrame::OnPropertySheet(wxCommandEvent& event)
{
	std::shared_ptr<IVEILPropertySheet> propSht = ::TopServiceLocator()->get_instance<IVEILPropertySheet>("/WxWin/PropertySheet");

	propSht->AddStandardPage(IVEILPropertySheet::GeneralSettings);
	propSht->AddStandardPage(IVEILPropertySheet::VEILFileSettings);

	propSht->DisplayModal((XP_WINDOW)this);
}

void MyFrame::OnFavoriteName(wxCommandEvent& event)
{
	std::shared_ptr<IFavoriteName> dlg = ::TopServiceLocator()->get_instance<IFavoriteName>("/WxWin/FavoriteName");

	dlg->Name("Original Name");
	if (dlg->DisplayModal((XP_WINDOW)this) == wxID_OK)
	{
		wxMessageBox((tscrypto::tsCryptoString() << "Returned name: '" << dlg->Name() << "'").c_str());
	}
}
