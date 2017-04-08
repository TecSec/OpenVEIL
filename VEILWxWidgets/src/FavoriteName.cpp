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

class FavoriteNameWrapper : public IFavoriteName, public tsmod::IObject
{
public:
	FavoriteNameWrapper() : _parent(nullptr)
	{
	}
	virtual ~FavoriteNameWrapper() {}

	// wxDialog
	virtual bool Destroy() override
	{
		_parent = XP_WINDOW_INVALID;
		return true;
	}
	// IVEILWxUIBase
	virtual int  DisplayModal() override
	{
		std::shared_ptr<tsmod::IObject>	Me; // Keep me alive until Destroy is called

		if (_parent == XP_WINDOW_INVALID)
			_parent = (XP_WINDOW)wxTheApp->GetTopWindow();

		Me = _me.lock();

		// Construct the dialog here
		FavoriteNameDlg dlg;
		dlg.set_name(_name);
		dlg.Create((wxWindow*)_parent);

		int retVal = dlg.ShowModal();
		if (retVal == wxID_OK)
			_name = dlg.get_name();

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
	tscrypto::tsCryptoString    _name;
};

tsmod::IObject* CreateFavoriteName()
{
	return dynamic_cast<tsmod::IObject*>(new FavoriteNameWrapper());
}