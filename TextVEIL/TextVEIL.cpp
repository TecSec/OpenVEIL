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
// Written by Mike Capone

#include "stdafx.h"

IMPLEMENT_APP(TextVEIL) // A macro that tells wxWidgets to create an instance of our application 

int FRAME_WIDTH = 1000;
int FRAME_HEIGHT = 600;

bool TextVEIL::OnInit()
{
	MainFrame *MainWin = new MainFrame(_T("TextVEIL"), wxDefaultPosition, wxSize(FRAME_WIDTH, FRAME_HEIGHT));
	MainWin->Show(true); 
	SetTopWindow(MainWin);
	if (!InitializeVEILWxWidgets())
	{
		char *errorMsg = "Unable to initialize the VEIL wxWidgets.";
		wxMessageBox(errorMsg, "Error", wxOK | wxICON_ERROR);
		ERROR(errorMsg);
		return false;
	}
	if (!InitializeCmsHeader())
	{
		char *errorMsg = "Unable to initialize the CMS Header system.";
		wxMessageBox(errorMsg, "Error", wxOK | wxICON_ERROR);
		ERROR(errorMsg);
		return false;
	}

	return true;
}

#pragma region EventTable
BEGIN_EVENT_TABLE(MainFrame, wxFrame)
EVT_BUTTON(BUTTON_Encrypt, MainFrame::OnEncrypt)
EVT_BUTTON(BUTTON_Decrypt, MainFrame::OnDecrypt)
END_EVENT_TABLE()
#pragma endregion

MainFrame::MainFrame(const wxString &title, const wxPoint &pos, 
	const wxSize &size) : wxFrame((wxFrame*)NULL, -1, title, pos, size)
{
	int xPad = 5;
	
	// Buttons
	int buttonYPad = 10;
	EncryptBtn = new wxButton(this, BUTTON_Encrypt, _T("Encrypt"),
		wxPoint(xPad, buttonYPad), wxDefaultSize, 0);
	DecryptBtn = new wxButton(this, BUTTON_Decrypt, _T("Decrypt"), 
		wxPoint(100, buttonYPad), wxDefaultSize, 0);
	
	//Text Boxes
	int boxYPad = 50;
	int boxWidth = (FRAME_WIDTH / 2) - (xPad * 3);
	int boxHeight = FRAME_HEIGHT - (boxYPad * 2);
	EditBox = new wxTextCtrl(this, TEXT_Edit, "", 
		wxPoint(xPad, boxYPad),
		wxSize(boxWidth, boxHeight),
		wxTE_MULTILINE/* | wxTE_RICH*/, 
		wxDefaultValidator, wxTextCtrlNameStr);
	ReadOnlyBox = new wxTextCtrl(this, TEXT_ReadOnly, "", 
		wxPoint(boxWidth + (xPad * 2), boxYPad),
		wxSize(boxWidth, boxHeight),
		wxTE_MULTILINE /*| wxTE_RICH*/ | wxTE_READONLY,
		wxDefaultValidator, wxTextCtrlNameStr);
	
	ReadOnlyBox->SetBackgroundColour("#f0f0f0");
	EditBox->SetFocus();
}

#pragma region Helpers

bool MainFrame::CreateLogin()
{
	if (_connector && _connector->isConnected())
	{
		return true;
	}

	std::shared_ptr<IVEILWxUIBase> login_dlg = ::TopServiceLocator()->get_instance<IVEILWxUIBase>("/WxWin/KeyVEILLogIn");
	std::shared_ptr<IKeyVEILLogin> login = std::dynamic_pointer_cast<IKeyVEILLogin>(login_dlg);

	if (login_dlg->DisplayModal((XP_WINDOW)this) == wxID_CANCEL)
	{
		return false;
	}

	_connector = login->Connector();
	
	return true;
}

#pragma endregion

void MainFrame::OnEncrypt(wxCommandEvent& event)
{
	if (!CreateLogin())
	{
		return;
	}

	if (!_connector)
	{
		return;
	}

	std::shared_ptr<IVEILWxUIBase> aud_dlg = ::TopServiceLocator()->get_instance<IVEILWxUIBase>("/WxWin/AudienceSelector");
	std::shared_ptr<IAudienceSelector> aud = std::dynamic_pointer_cast<IAudienceSelector>(aud_dlg);

	aud->Start(_connector, (XP_WINDOW)this, "GUI Tester");

	if (aud_dlg->DisplayModal((XP_WINDOW)this) == wxID_CANCEL)
	{
		return;
	}

	std::shared_ptr<ICmsHeader> header = aud->Header();
	_session = aud->Session();

	std::shared_ptr<IFileVEILOperations> fileOps = CreateFileVEILOperationsObject();
	fileOps->SetSession(_session);

	tscrypto::tsCryptoData dataToEnc(EditBox->GetValue());
	tscrypto::tsCryptoData encData;

	if (!fileOps->EncryptCryptoData(dataToEnc, encData, header, ct_zLib,
		tscrypto::_TS_ALG_ID::TS_ALG_AES_GCM_256, tscrypto::_TS_ALG_ID::TS_ALG_INVALID, false, true,
		TS_FORMAT_CMS_ENC_AUTH, false, tscrypto::_SymmetricPaddingType::padding_None))
	{
		char *errorMsg = "Failed to encrypt.";
		wxMessageBox(errorMsg, "Error", wxOK | wxICON_ERROR);
		ERROR(errorMsg);
		return;
	}
	
	TSNamedBinarySectionList sections = CreateTSNamedBinarySectionList();
	TSNamedBinarySection section;

	section.Name = tscrypto::tsCryptoString("VEIL ENCRYPTED DATA");
	section.Contents = encData;
	sections->push_back(section);

	tscrypto::tsCryptoString armoredStr;
	if (!xp_WriteArmoredString(sections, armoredStr))
	{
		char *errorMsg = "Failed to create PEM encoded armored string.";
		wxMessageBox(errorMsg, "Error", wxOK | wxICON_ERROR);
		ERROR(errorMsg);
		return;
	}

	ReadOnlyBox->SetValue(armoredStr.c_str());
}

void MainFrame::OnDecrypt(wxCommandEvent& event)
{
	if (!CreateLogin())
	{
		return;
	}

	if (!_connector)
	{
		return;
	}

	if (!_session)
	{
		std::shared_ptr<ITokenSelector> tokSel = ::TopServiceLocator()->get_instance<ITokenSelector>("/WxWin/TokenSelector");
		tokSel->Start(_connector, GUID_NULL, "Select a token for testing", (XP_WINDOW)this);
		if (tokSel->DisplayModal() != wxID_OK)
		{
			return;
		}
		_session = tokSel->Session();
	}

	std::shared_ptr<ITokenLogin> tokenLogin = ::TopServiceLocator()->try_get_instance<ITokenLogin>("/WxWin/TokenLogIn");

	if (!tokenLogin || !tokenLogin->Start(_session, (XP_WINDOW)this))
	{
		return;
	}
	
	if (tokenLogin->DisplayModal() != wxID_OK)
	{
		return;
	}

	std::shared_ptr<IFileVEILOperations> fileOps = CreateFileVEILOperationsObject();
	fileOps->SetSession(_session);

	tscrypto::tsCryptoString inData(EditBox->GetValue().mb_str());
	
	TSNamedBinarySectionList sections = CreateTSNamedBinarySectionList();

	if (!xp_ReadArmoredString(inData, sections))
	{
		char *errorMsg = "Failed to read PEM encoded armored string.";
		wxMessageBox(errorMsg, "Error", wxOK | wxICON_ERROR);
		ERROR(errorMsg);
		return;
	}

	tscrypto::tsCryptoData outData;

	if (!fileOps->DecryptCryptoData(sections->at(0).Contents, outData))
	{
		char *errorMsg = "Failed to decrypt.";
		wxMessageBox(errorMsg, "Error", wxOK | wxICON_ERROR);
		ERROR(errorMsg);
		return;
	}

	ReadOnlyBox->SetValue(outData.c_str());
}
