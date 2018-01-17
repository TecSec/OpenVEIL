//	Copyright (c) 2018, TecSec, Inc.
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

#ifndef _FAVORITEMANAGERWRAPPER_H_
#define _FAVORITEMANAGERWRAPPER_H_


class FavoriteManagerWrapper : public IAudienceSelector, public tsmod::IObject
{
public:
	FavoriteManagerWrapper() : _dlg(nullptr), _cookie(0), _parent(XP_WINDOW_INVALID)
	{
		_vars._favoriteId = GUID_NULL;
		_vars._favoriteManager = false;
		_vars._hideKeyVEILLogin = false;
	}
	virtual ~FavoriteManagerWrapper()
	{
		Destroy();
	}
	virtual void OnConstructionFinished() override;

		// Inherited via IAudienceSelector
	virtual bool Destroy() override;
	virtual int DisplayModal() override;
	virtual int DisplayModal(XP_WINDOW wnd) override;
	virtual std::shared_ptr<IKeyVEILConnector> Connector() override;
	virtual void Connector(std::shared_ptr<IKeyVEILConnector> setTo) override;
	virtual std::shared_ptr<IKeyVEILSession> Session() override;
	virtual void Session(std::shared_ptr<IKeyVEILSession> setTo) override;
	virtual tscrypto::tsCryptoData HeaderData() override;
	virtual void HeaderData(const tscrypto::tsCryptoData & setTo) override;
	virtual std::shared_ptr<ICmsHeader> Header() override;
	virtual void Header(std::shared_ptr<ICmsHeader> setTo) override;
	virtual bool Start(std::shared_ptr<IKeyVEILConnector> connector, XP_WINDOW parent, const tscrypto::tsCryptoString & appName) override;
	virtual void HideKeyVEILLogin(bool setTo) override;
private:
	FavoriteManagerDlg* _dlg;
	XP_WINDOW										_parent;
	audienceSelector2Variables                      _vars;
	tscrypto::tsCryptoString						_AppName;
	size_t											_cookie;
};

#endif // _FAVORITEMANAGERWRAPPER_H_
