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
#include "commctrl.h"
#include "resource.h"

#define	UWM_STEP_PROGRESS	WM_USER+1300
#define	UWM_SET_PROGRESS	WM_USER+1301
#define	UWM_CLOSE_PROGRESS  WM_USER+1302


class HIDDEN CProgressDlg : public IProgressDlg, public tsmod::IObject
{
public:
	CProgressDlg() :
		m_hWnd(NULL),
		m_nCaptionID(0),
		m_nTimer(0),
		m_nLower(0),
		m_nUpper(0),
		m_nStep(0),
		m_nInitialPos(0),
		m_bInitialCancel(0),
		m_dwExitCode(0),
		m_bCancel(FALSE),
		m_bShowPercent(TRUE),
		m_bParentDisabled(FALSE),
		m_pParentWnd(NULL),
		m_Progress(NULL)
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
		if (m_hWnd != NULL)
			DestroyWindow(m_hWnd);
	}

	virtual void  Destroy()
	{
		if (m_hWnd != NULL)
			PostMessage(m_hWnd, WM_CLOSE, 0, 0);
	}
	virtual int   DisplayModal()
	{
		showWindow(TRUE);
		return IDOK;
	}
	virtual int   DisplayModal(XP_WINDOW wnd)
	{
		showWindow(TRUE);
		return IDOK;
	}

	virtual bool  Create(XP_WINDOW pParent)
	{
		// Get the true parent of the dialog
		if (pParent != XP_WINDOW_INVALID && ::IsWindow((HWND)pParent))
			m_pParentWnd = HWND(pParent);
		else
			m_pParentWnd = NULL;

		// m_bParentDisabled is used to re-enable the parent window
		// when the dialog is destroyed. So we don't want to set
		// it to TRUE unless the parent was already enabled.

		if ((m_pParentWnd != NULL) && IsWindowEnabled(m_pParentWnd))
		{
			EnableWindow(m_pParentWnd, FALSE);
			m_bParentDisabled = TRUE;
		}

		m_hWnd = CreateDialogParamA((HINSTANCE)hDllInstance, MAKEINTRESOURCEA(IDD_PROGRESS), (HWND)pParent, (DLGPROC)DlgProc, (LPARAM)this);
		if (m_hWnd == NULL)
		{
			ReEnableParent();
			return FALSE;
		}

		return TRUE;
	}
	virtual bool  showWindow(BOOL bShow)
	{
		if (bShow)
			ShowWindow(m_hWnd, SW_SHOW);
		else
			ShowWindow(m_hWnd, SW_HIDE);
		return true;
	}
	virtual bool  CheckCancelButton()
	{
		// Reset m_bCancel to FALSE so that
		// CheckCancelButton returns FALSE until the user
		// clicks Cancel again. This will allow you to call
		// CheckCancelButton and still continue the operation.
		// If m_bCancel stayed TRUE, then the next call to
		// CheckCancelButton would always return TRUE
		BOOL bResult = m_bCancel;
		m_bCancel = FALSE;

		// make sure the control is instantiated
		if (::IsWindow(m_hWnd))
			// Process all pending messages
			PumpMessages();

		return (bResult != FALSE);
	}
	virtual void  SetRange(int nLower, int nUpper)
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
		if (!::IsWindow(m_hWnd))
			return;

		// set the control's range and then doublecheck the current position
		SendMessage(m_Progress, PBM_SETRANGE32, m_nLower, m_nUpper);
		int nPos = (int)SendMessage(m_Progress, PBM_GETPOS, 0, 0);

		if (nPos < m_nLower)
		{
			nPos = m_nLower;
		}
		else if (nPos > m_nUpper)
		{
			nPos = m_nUpper;
		}

		PumpMessages();
		SendMessage(m_Progress, PBM_SETPOS, nPos, 0);
		UpdatePercent(nPos);
	}
	virtual int   SetStep(int nStep)
	{
		// Store for later use in calculating percentage.  Shift over 1 (divide by 2) to
		// decrease the step to correspond with our final range number.
		unsigned int tempint = (unsigned int)nStep;
		m_nStep = (tempint);

		// make sure the control is instantiated
		if (!::IsWindow(m_Progress))
			return 0;

		return 0;
	}
	virtual int   GetPos()
	{
		if (!::IsWindow(m_Progress))
			return 0;

		return (int)SendMessage(m_Progress, PBM_GETPOS, 0, 0);
	}
	virtual int   SetPos(int nPos)
	{
		if (nPos < m_nLower)
			nPos = m_nLower;
		else if (nPos > m_nUpper)
			nPos = m_nUpper;

		m_nInitialPos = nPos;

		// make sure the control is instantiated
		if (!::IsWindow(m_Progress))
			return 0;

		PumpMessages();
		int iResult = (int)SendMessage(m_Progress, PBM_SETPOS, nPos, 0);
		UpdatePercent(nPos);
		return iResult;
	}
	virtual int   OffsetPos(int nPos)
	{
		unsigned int tempPos = (unsigned int)nPos;

		m_nInitialPos += tempPos;

		// make sure the control is instantiated
		if (!::IsWindow(m_Progress))
			return 0;

		PumpMessages();
		int iResult = (int)SendMessage(m_Progress, PBM_SETPOS, SendMessage(m_Progress, PBM_GETPOS, 0, 0) + tempPos, 0);
		UpdateOffsetPercent(iResult + nPos);
		return iResult;
	}
	virtual int   StepIt()
	{
		m_nInitialPos += m_nStep;

		// make sure the control is instantiated
		if (!::IsWindow(m_Progress))
			return 0;

		PumpMessages();
		int iResult = (int)SendMessage(m_Progress, PBM_SETPOS, SendMessage(m_Progress, PBM_GETPOS, 0, 0) + m_nStep, 0);
		UpdatePercent(iResult + m_nStep);
		return iResult;
	}
	virtual void  SetStatusText(const tscrypto::tsCryptoString &sText)
	{
		m_StatusMsg = sText;

		if (!::IsWindow(m_Progress))
			return;

		HWND pWndPercent = GetDlgItem(m_hWnd, IDC_STATUSMSG);
		SetWindowTextA(pWndPercent, sText.c_str());
		UpdateWindow(pWndPercent);
	}
	virtual void  SetWindowTitle(const tscrypto::tsCryptoString &sText)
	{
		m_WindowTitle = sText;

		if (!::IsWindow(m_Progress))
			return;

		SetWindowTextA(m_hWnd, sText.c_str());
	}
	//    virtual int   DisplayMessage(const tscrypto::tsCryptoString &sText);
	virtual int   DisplayMessage(const tscrypto::tsCryptoString &sText, int32_t lMB)
	{
		//    return MessageBoxA(m_hWnd, sText.c_str(), (""), MB_YESNO | MB_ICONINFORMATION);
		return MessageBoxA(m_hWnd, sText.c_str(), (""), lMB | MB_ICONINFORMATION);
	}
	virtual void  SetShowPercent(bool bShowPercent)
	{
		m_bShowPercent = bShowPercent;

		if (!bShowPercent) {
			if (::IsWindow(m_Progress))
				SetWindowTextA(m_hWnd, m_WindowTitle.c_str());
		}
		else {
			if (::IsWindow(m_Progress))
				UpdatePercent((int)SendMessage(m_Progress, PBM_GETPOS, 0, 0));
		}
	}
	virtual void  EnableCancelButton(bool bShowCancel)
	{
		m_bInitialCancel = bShowCancel;

		// make sure the control is instantiated
		if (!::IsWindow(m_Progress))
			return;

		EnableWindow(GetDlgItem(m_hWnd, IDCANCEL), bShowCancel);
	}

private:
	void ReEnableParent()
	{
		if (m_bParentDisabled && (m_pParentWnd != NULL) && (::IsWindow(m_pParentWnd)))
			EnableWindow(m_pParentWnd, TRUE);

		m_bParentDisabled = FALSE;
	}

	void OnCancel()
	{
		m_bCancel = TRUE;
	}
	void OnOK()
	{
	}
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
		strCur.resize(512);
		GetWindowTextA(m_hWnd, strCur.rawData(), (int)strCur.size());
		strCur.resize(TsStrLen(strCur));
		if (strCur != strBuf)
			SetWindowTextA(m_hWnd, strBuf.c_str());
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
		strCur.resize(512);
		GetWindowTextA(m_hWnd, strCur.rawData(), (int)strCur.size());
		strCur.resize(TsStrLen(strCur));
		if (strCur != strBuf)
			SetWindowTextA(m_hWnd, strBuf.c_str());
	}

	void PumpMessages()
	{
		// Handle dialog messages
		MSG msg;
		while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
		{
			if (!IsDialogMessage(m_hWnd, &msg))
			{
				TranslateMessage(&msg);
				DispatchMessage(&msg);
			}
		}
	}

	// Generated message map functions
	//{{AFX_MSG(ProgressDlg)
	BOOL OnInitDialog()
	{
		m_Progress = GetDlgItem(m_hWnd, IDC_PROGRESS);
		HWND m_stcText = GetDlgItem(m_hWnd, IDC_STATUSMSG);

		SendMessage(m_Progress, PBM_SETRANGE32, m_nLower, m_nUpper);
		SendMessage(m_Progress, PBM_SETPOS, m_nInitialPos, 0);

		//    m_stcText.SubclassDlgItem(IDC_STATUSMSG,this);
		//    m_stcText.SetPath(TRUE);
		SetWindowTextA(m_stcText, m_StatusMsg.c_str());

		EnableWindow(GetDlgItem(m_hWnd, IDCANCEL), m_bInitialCancel);

		SetWindowTextA(m_hWnd, m_WindowTitle.c_str());
		return TRUE;
	}
	LRESULT OnStepProgress(WPARAM, LPARAM)
	{
		return 0;
	}
	LRESULT OnSetProgress(WPARAM, LPARAM)
	{
		return 0;
	}
	LRESULT OnCloseProgress(WPARAM, LPARAM)
	{
		PostMessage(m_hWnd, WM_CLOSE, 0, 0);
		return 0;
	}
	void OnTimer(UINT nIDEvent)
	{
	}
	void OnCertStatus(WPARAM wParam, LPARAM lParam)
	{
	}

	static BOOL  DlgProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
	{
		CProgressDlg *This = (CProgressDlg *)GetWindowLongPtr(hWnd, DWLP_USER);
		//    BOOL handled = true;

		switch (msg)
		{
		case WM_INITDIALOG:
			SetWindowLongPtr(hWnd, DWLP_USER, lParam);
			This = (CProgressDlg *)lParam;
			This->m_hWnd = hWnd;
			return This->OnInitDialog();
		case WM_COMMAND:
			if (wParam == MAKEWPARAM(IDOK, BN_CLICKED))
			{
				This->OnOK();
			}
			else if (wParam == MAKEWPARAM(IDOK, BN_CLICKED))
			{
				This->OnCancel();
			}
			break;
		case UWM_STEP_PROGRESS:
			SetWindowLongPtr(hWnd, DWLP_MSGRESULT, This->OnStepProgress(wParam, lParam));
			return TRUE;
		case UWM_SET_PROGRESS:
			SetWindowLongPtr(hWnd, DWLP_MSGRESULT, This->OnSetProgress(wParam, lParam));
			return TRUE;
		case UWM_CLOSE_PROGRESS:
			SetWindowLongPtr(hWnd, DWLP_MSGRESULT, This->OnCloseProgress(wParam, lParam));
			return TRUE;
		case WM_TIMER:
			This->OnTimer((UINT)wParam);
			return TRUE;
		case WM_DESTROY:
			This->ReEnableParent();
			return FALSE;
		}
		return FALSE;
	}

	HWND m_hWnd;
	uint32_t m_nCaptionID;
	uint32_t m_nTimer;
	int m_nLower;
	int m_nUpper;
	int m_nStep;
	int m_nInitialPos;
	int m_bInitialCancel;

	tscrypto::tsCryptoString m_StatusMsg;
	tscrypto::tsCryptoString m_WindowTitle;

	DWORD m_dwExitCode;

	BOOL m_bCancel;
	BOOL m_bShowPercent;
	BOOL m_bParentDisabled;
	HWND m_pParentWnd;
	HWND m_Progress;
};

tsmod::IObject* CreateProgressDlg()
{
	return dynamic_cast<tsmod::IObject*>(new CProgressDlg());
}