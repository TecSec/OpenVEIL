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

////////////////////////////////////////////////////////////////////////////////////////////////////
/// \file   FipsState.h
///
/// \brief  Declares the fips state class. 
////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef __FIPSSTATE_H__
#define __FIPSSTATE_H__

#pragma once

namespace tscrypto {
	////////////////////////////////////////////////////////////////////////////////////////////////////
	/// \class  FipsState
	///
	/// \brief  Fips state. 
	///
	/// \author Rogerb
	/// \date   12/4/2010
	////////////////////////////////////////////////////////////////////////////////////////////////////
	class VEILCORE_API FipsState
	{
	public:

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// \fn FipsState::FipsState(void);
		///
		/// \brief  Default constructor. 
		///
		/// \author Rogerb
		/// \date   12/4/2010
		////////////////////////////////////////////////////////////////////////////////////////////////////
		FipsState(void);

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// \fn FipsState::~FipsState(void);
		///
		/// \brief  Finaliser. 
		///
		/// \author Rogerb
		/// \date   12/4/2010
		////////////////////////////////////////////////////////////////////////////////////////////////////
		~FipsState(void);

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// \fn bool FipsState::selfTest();
		///
		/// \brief  Tests self. 
		///
		/// \author Rogerb
		/// \date   12/4/2010
		///
		/// \return true if the test passes, false if the test fails. 
		////////////////////////////////////////////////////////////////////////////////////////////////////
		bool selfTest();

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// \fn bool FipsState::detailedSelfTest();
		///
		/// \brief  Tests detailed self. 
		///
		/// \author Rogerb
		/// \date   12/4/2010
		///
		/// \return true if the test passes, false if the test fails. 
		////////////////////////////////////////////////////////////////////////////////////////////////////
		bool detailedSelfTest();

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// \fn void FipsState::testFailed();
		///
		/// \brief  Tests failed. 
		///
		/// \author Rogerb
		/// \date   12/4/2010
		////////////////////////////////////////////////////////////////////////////////////////////////////
		void testFailed();

		////////////////////////////////////////////////////////////////////////////////////////////////////
		/// \fn bool FipsState::operational() const;
		///
		/// \brief  Gets the operational. 
		///
		/// \author Rogerb
		/// \date   12/4/2010
		///
		/// \return true if it succeeds, false if it fails. 
		////////////////////////////////////////////////////////////////////////////////////////////////////
		bool operational() const;

	private:
		bool isOperational;
		bool wasTested;
	};

	extern VEILCORE_API FipsState gFipsState;
}

#endif // __FIPSSTATE_H__
