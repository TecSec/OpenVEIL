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

class HIDDEN CProgressDlg : public IProgressDlg, public tsmod::IObject
{
public:
	CProgressDlg() :
		_dlg(nullptr),
		m_nLower(0),
		m_nUpper(0),
		m_nStep(0),
		m_nInitialPos(0),
		m_bInitialCancel(0),
		m_dwExitCode(0),
		m_bCancel(FALSE),
		m_bShowPercent(TRUE),
		m_bParentDisabled(FALSE),
		m_pParentWnd(NULL)
	{
		m_bCancel = FALSE;
		m_bShowPercent = TRUE;
		m_bParentDisabled = FALSE;

		m_nStep = 10;
		m_nLower = 0;
		m_nUpper = 100;
		m_dwExitCode = 0;
		m_nInitialPos = 0;
		m_bInitialCancel = TRUE;

		m_StatusMsg = "";
		m_WindowTitle = "Processing...";
	}
	~CProgressDlg()
	{
		Destroy();
	}

	virtual bool Destroy() override
	{
		if (_dlg != nullptr)
		{
			_dlg->Close();
			_dlg->Destroy();
		}
		_dlg = nullptr;
		return true;
	}
	virtual int   DisplayModal() override
	{
		if (_dlg != nullptr)
			_dlg->Show(true);
		return wxID_OK;
	}
	virtual int   DisplayModal(XP_WINDOW wnd) override
	{
		if (_dlg != nullptr)
			_dlg->Show(true);
		return wxID_OK;
	}

	virtual bool  Create(XP_WINDOW pParent) override
	{
		m_pParentWnd = pParent;
		_dlg = new ProgressDlg((wxWindow*)pParent, 10000, m_WindowTitle.c_str());
		_dlg->setTask(m_StatusMsg.c_str());

		return TRUE;
	}
	virtual bool  showWindow(BOOL bShow) override
	{
		if (_dlg != nullptr)
			_dlg->Show(bShow != FALSE);
		return true;
	}
	virtual bool  CheckCancelButton() override
	{
		if (_dlg == nullptr)
			return false;

		_dlg->ClearCancel();
		return _dlg->WasCancelled();
	}
	virtual void  SetRange(int nLower, int nUpper) override
	{
		/* Since the microsoft function only takes signed ints and we want to support unsigned ints,
		cast the input values to unsigned integers and divide by 2. */
		unsigned int castUpper;
		castUpper = ((unsigned int)nUpper);

		// if the args are reversed, swap them
		if (((unsigned int)nLower) > ((unsigned int)nUpper)) {
			m_nLower = castUpper;
			m_nUpper = nLower;
		}
		else {
			m_nLower = nLower;
			m_nUpper = castUpper;
		}

		m_nInitialPos = nLower;

		// make sure the control is instantiated
		if (_dlg == nullptr)
			return;

		_dlg->SetRange(m_nUpper - m_nLower);
		int nPos = _dlg->GetValue();

		if (nPos < m_nLower)
		{
			nPos = m_nLower;
		}
		else if (nPos > m_nUpper)
		{
			nPos = m_nUpper;
		}

		UpdatePercent(nPos);
	}
	virtual int   SetStep(int nStep) override
	{
		// Store for later use in calculating percentage.  Shift over 1 (divide by 2) to
		// decrease the step to correspond with our final range number.
		unsigned int tempint = (unsigned int)nStep;
		m_nStep = (tempint);

		// make sure the control is instantiated
		if (_dlg == nullptr)
			return 0;

		return 0;
	}
	virtual int   GetPos() override
	{
		if (_dlg == nullptr)
			return 0;

		return _dlg->GetValue();
	}
	virtual int   SetPos(int nPos) override
	{
		if (nPos < m_nLower)
			nPos = m_nLower;
		else if (nPos > m_nUpper)
			nPos = m_nUpper;

		m_nInitialPos = nPos;

		// make sure the control is instantiated
		if (_dlg == nullptr)
			return 0;

		_dlg->SetValue(nPos);
		UpdatePercent(nPos);
		return nPos;
	}
	virtual int   OffsetPos(int nPos) override
	{
		unsigned int tempPos = (unsigned int)nPos;

		m_nInitialPos += tempPos;

		// make sure the control is instantiated
		if (_dlg == nullptr)
			return 0;

		_dlg->SetValue(m_nInitialPos);
		UpdateOffsetPercent(m_nInitialPos);
		return m_nInitialPos;
	}
	virtual int   StepIt() override
	{
		m_nInitialPos += m_nStep;

		// make sure the control is instantiated
		if (_dlg == nullptr)
			return 0;

		_dlg->SetValue(m_nInitialPos);
		UpdatePercent(m_nInitialPos);
		return m_nInitialPos;
	}
	virtual void  SetStatusText(const tscrypto::tsCryptoString &sText) override
	{
		m_StatusMsg = sText;

		if (_dlg == nullptr)
			return;

		_dlg->setTask(sText.c_str());
		_dlg->Fit();
		_dlg->Update();
	}
	virtual void  SetWindowTitle(const tscrypto::tsCryptoString &sText) override
	{
		m_WindowTitle = sText;

		if (_dlg == nullptr)
			return;

		_dlg->SetTitle(sText.c_str());
	}
	//    virtual int   DisplayMessage(const tscrypto::tsCryptoString &sText);
	virtual int   DisplayMessage(const tscrypto::tsCryptoString &sText, int32_t lMB)
	{
		//    return MessageBoxA(m_hWnd, sText.c_str(), (""), MB_YESNO | MB_ICONINFORMATION);
		return wxTsMessageBox(sText.c_str(), (""), lMB | wxICON_INFORMATION, (XP_WINDOW)_dlg);
	}
	virtual void  SetShowPercent(bool bShowPercent) override
	{
		m_bShowPercent = bShowPercent;

		if (!bShowPercent) {
			if (_dlg != nullptr)
				_dlg->SetTitle(m_WindowTitle.c_str());
		}
		else {
			if (_dlg != nullptr)
				UpdatePercent(m_nInitialPos);
		}
	}
	virtual void  EnableCancelButton(bool bShowCancel) override
	{
		if (m_bInitialCancel == bShowCancel)
			return;

		m_bInitialCancel = bShowCancel;

		// make sure the control is instantiated
		if (_dlg == nullptr)
			return;

		if (_dlg->IsVisible())
		{
			showWindow(FALSE);
			showWindow(TRUE);
		}
	}

private:

	void UpdatePercent(int nCurrent)
	{
		tscrypto::tsCryptoString strBuf, strCur;

		if (!m_bShowPercent)
			return;

		int nPercent;
		//    HWND pWndPercent = GetDlgItem(m_hWnd, IDC_STATUSMSG);

		// determine the total range of movement of the progress control
		// (m_nLower should be smaller than m_nUpper, but we validate below)
		float nRange = (float)(m_nUpper - m_nLower);

		// adjust the current position based on the control's low boundry
		// (Current position should be greater than m_nLower)
		float nPosition = (float)(nCurrent - m_nLower);

		if (nCurrent == 0 || nRange <= 0 || nPosition <= 0) {
			nPercent = 0;
		}
		else {
			// turn the percentage into an integer value
			float fPercent = nPosition / nRange;
			nPercent = (int)(100 * fPercent);

			// Since the Progress Control can wrap, we will wrap the percentage
			// along with it. However, don't reset 100% back to 0%
			if (nPercent > 100)
				nPercent %= 100;
		}

		// Display the percentage
		strBuf.Format("%s %d%%", m_WindowTitle.c_str(), nPercent);

		// don't change the window text if the percentage hasn't changed
		strCur = _dlg->GetTitle().mbc_str().data();
		if (strCur != strBuf)
			_dlg->SetTitle(strBuf.c_str());
	}
	void UpdateOffsetPercent(int nNewPos)
	{
		tscrypto::tsCryptoString strBuf, strCur;

		if (!m_bShowPercent)
			return;

		int nPercent;
		//    HWND pWndPercent = GetDlgItem(m_hWnd, IDC_STATUSMSG);

		// determine the total range of movement of the progress control
		// (m_nLower should be smaller than m_nUpper, but we validate below)
		float nRange = (float)(m_nUpper - m_nLower);

		// adjust the current position based on the control's low boundry
		// (Current position should be greater than m_nLower)
		float nPosition = (float)(nNewPos - m_nLower);

		if (nNewPos == 0 || nRange <= 0 || nPosition <= 0) {
			nPercent = 0;
		}
		else {
			// turn the percentage into an integer value
			float fPercent = nPosition / nRange;
			nPercent = (int)(100 * fPercent);

			// DO NOT WRAP for Offset Update Percentage, but set more than 100% to 100%

			if (nPercent > 100)
				nPercent = 100;
		}

		// Display the percentage
		strBuf.Format("%s %d%%", m_WindowTitle.c_str(), nPercent);

		// don't change the window text if the percentage hasn't changed
		strCur = _dlg->GetTitle().mbc_str().data();
		if (strCur != strBuf)
			_dlg->SetTitle(strBuf.c_str());
	}

	//void PumpMessages()
	//{
	//	// Handle dialog messages
	//	MSG msg;
	//	while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
	//	{
	//		if (!IsDialogMessage(m_hWnd, &msg))
	//		{
	//			TranslateMessage(&msg);
	//			DispatchMessage(&msg);
	//		}
	//	}
	//}

	ProgressDlg* _dlg;
	int m_nLower;
	int m_nUpper;
	int m_nStep;
	int m_nInitialPos;
	bool m_bInitialCancel;

	tscrypto::tsCryptoString m_StatusMsg;
	tscrypto::tsCryptoString m_WindowTitle;

	DWORD m_dwExitCode;

	BOOL m_bCancel;
	BOOL m_bShowPercent;
	BOOL m_bParentDisabled;
	XP_WINDOW m_pParentWnd;
};

tsmod::IObject* CreateProgressDlg()
{
	return dynamic_cast<tsmod::IObject*>(new CProgressDlg());
}