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

//////////////////////////////////////////////////////////////////////////////////
/// \file AppCommon\tsWinscardExports.h
/// \brief Defines a thin wrapper over PCSC to provide access to smart cards.
//////////////////////////////////////////////////////////////////////////////////

// tsWinscardExports.h

#ifndef TSWINSCARDEXPORTS_H_INCLUDE
#define TSWINSCARDEXPORTS_H_INCLUDE

#pragma once

#ifdef HAVE_SMARTCARD

#ifndef SCARD_E_SERVER_TOO_BUSY
    typedef LPSCARD_READERSTATE_A LPSCARD_READERSTATE;
    #define SCARD_E_SERVER_TOO_BUSY  0x80100031
#endif // _WIN32

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Initializes the PCSC wrapper.</summary>
///
/// <returns>true if it succeeds, false if it fails.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
bool tsWinscardInit(void);
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Terminates the PCSC wrapper.</summary>
///
/// <returns>true if it succeeds, false if it fails.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
bool tsWinscardRelease(void);

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Creates a connection (Context) to the PCSC subsystem.</summary>
///
/// <param name="dwScope">	  The scope of the connection.</param>
/// <param name="pvReserved1">Reserved.</param>
/// <param name="pvReserved2">Reserved.</param>
/// <param name="phContext">  The context handle used to access the other PCSC functions.</param>
///
/// <returns>A PCSC error code (For windows it is a standard OS error code).</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
LONG tsSCardEstablishContext(
    IN DWORD		   dwScope,
    IN LPCVOID		   pvReserved1,
    IN LPCVOID		   pvReserved2,
    OUT LPSCARDCONTEXT phContext);

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Releases a connection (Context) to the PCSC subsystem.</summary>
///
/// <param name="hContext">The context.</param>
///
/// <returns>A PCSC error code (For windows it is a standard OS error code).</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
LONG tsSCardReleaseContext(IN SCARDCONTEXT hContext);

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Ts card connect.</summary>
///
/// <param name="hContext">			   The context.</param>
/// <param name="szReader">			   The reader name.</param>
/// <param name="dwShareMode">		   The share mode.</param>
/// <param name="dwPreferredProtocols">The preferred protocols.</param>
/// <param name="phCard">			   The card connection handle.</param>
/// <param name="pdwActiveProtocol">   The active protocol for this connection.</param>
///
/// <returns>A PCSC error code (For windows it is a standard OS error code).</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
LONG tsSCardConnect(
    IN SCARDCONTEXT	  hContext,
    IN const		  char *szReader,
    IN DWORD		  dwShareMode,
    IN DWORD		  dwPreferredProtocols,
    OUT LPSCARDHANDLE phCard,
    OUT LPDWORD		  pdwActiveProtocol);

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Disconnects a connection to a card.</summary>
///
/// <param name="hCard">		The card handle to disconnect.</param>
/// <param name="dwDisposition">The disposition action.</param>
///
/// <returns>A PCSC error code (For windows it is a standard OS error code).</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
LONG tsSCardDisconnect(IN SCARDHANDLE hCard, IN DWORD dwDisposition);

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Send a command to the specified card.</summary>
///
/// <param name="hCard">		The card handle.</param>
/// <param name="pioSendPci">   The PCI information to use to send the command.</param>
/// <param name="pbSendBuffer"> The command data to send.</param>
/// <param name="cbSendLength"> The length of the command data.</param>
/// <param name="pioRecvPci">   The PCI information to use to receive the response.</param>
/// <param name="pbRecvBuffer"> Buffer for the response data.</param>
/// <param name="pcbRecvLength">Pointer to the length of the response.  On input the length of the buffer in bytes.  On output the number of bytes used.</param>
///
/// <returns>A PCSC error code (For windows it is a standard OS error code).</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
LONG tsSCardTransmit(
    IN SCARDHANDLE		   hCard,
    IN LPCSCARD_IO_REQUEST pioSendPci,
    IN LPCBYTE			   pbSendBuffer,
    IN DWORD			   cbSendLength,
    IN OUT				   LPSCARD_IO_REQUEST pioRecvPci,
    OUT LPBYTE			   pbRecvBuffer,
    IN OUT				   LPDWORD pcbRecvLength);

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Queries the PCSC subsystem to see if the specified readers have detected a change.</summary>
///
/// <param name="hContext">		 The context of the PCSC subsystem to query.</param>
/// <param name="dwTimeout">	 How long in milliseconds to wait.</param>
/// <param name="rgReaderStates">List of states of the readers.</param>
/// <param name="cReaders">		 How many readers to query.</param>
///
/// <returns>A PCSC error code (For windows it is a standard OS error code).</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
LONG tsSCardGetStatusChange(
    IN SCARDCONTEXT	hContext,
    IN DWORD		dwTimeout,
    IN OUT			LPSCARD_READERSTATE	rgReaderStates,
    IN DWORD		cReaders);

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Forces a reconnect and possible warm reset to the specified card.</summary>
///
/// <param name="hCard">			   The card connection handle.</param>
/// <param name="dwShareMode">		   The share mode.</param>
/// <param name="dwPreferredProtocols">The preferred protocols.</param>
/// <param name="dwInitialization">	   The initialization.</param>
/// <param name="pdwActiveProtocol">   The active protocol is returned here.</param>
///
/// <returns>A PCSC error code (For windows it is a standard OS error code).</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
LONG tsSCardReconnect(
    IN      SCARDHANDLE	hCard,
    IN      DWORD		dwShareMode,
    IN      DWORD		dwPreferredProtocols,
    IN      DWORD		dwInitialization,
    OUT     LPDWORD		pdwActiveProtocol);

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Gets an attribute from the specifed card.</summary>
///
/// <param name="hCard">	 The card connection handle.</param>
/// <param name="dwAttrId">  Identifier for the attribute.</param>
/// <param name="pbAttr">	 The buffer to hold the response.</param>
/// <param name="pcbAttrLen">Length of the response buffer on input and number of bytes stored on output.</param>
///
/// <returns>A PCSC error code (For windows it is a standard OS error code).</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
LONG tsSCardGetAttrib(
  SCARDHANDLE hCard,
  DWORD		  dwAttrId,
  LPBYTE	  pbAttr,
  LPDWORD	  pcbAttrLen);

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Gains exclusive use of the specified card.</summary>
///
/// <param name="hCard">The card connection handle.</param>
///
/// <returns>A PCSC error code (For windows it is a standard OS error code).</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
LONG tsSCardBeginTransaction(IN SCARDHANDLE hCard);

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Restores shared access to the specified card.</summary>
///
/// <param name="hCard">		The card connection handle.</param>
/// <param name="dwDisposition">The disposition.</param>
///
/// <returns>A PCSC error code (For windows it is a standard OS error code).</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
LONG tsSCardEndTransaction(IN SCARDHANDLE hCard, IN DWORD dwDisposition);

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Cancel any blocking operations on this context.</summary>
///
/// <param name="hContext">The context.</param>
///
/// <returns>A PCSC error code (For windows it is a standard OS error code).</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
LONG tsSCardCancel(IN SCARDCONTEXT hContext);

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Free memory allocated by the PCSC subsystem.</summary>
///
/// <param name="hContext">The context.</param>
/// <param name="pvMem">   The memory to deallocate.</param>
///
/// <returns>A PCSC error code (For windows it is a standard OS error code).</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
LONG tsSCardFreeMemory(IN SCARDCONTEXT hContext, IN LPCVOID pvMem);

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Test if the PCSC subsystem context is valid.</summary>
///
/// <param name="hContext">The context to test.</param>
///
/// <returns>A PCSC error code (For windows it is a standard OS error code).</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
LONG tsSCardIsValidContext(IN SCARDCONTEXT hContext);

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Returns the current state of the specified card.</summary>
///
/// <param name="hCard">The card to test.</param>
/// <param name="mszReaderNames">The names for this reader.</param>
/// <param name="pcchReaderLen">The length of the name buffer.</param>
/// <param name="pdwState">The card state.</param>
/// <param name="pdwProtocol">The card communication protocol.</param>
/// <param name="pbAtr">The ATR string buffer.</param>
/// <param name="pcbAtrLen">The length of the ATR string buffer.</param>
///
/// <returns>A PCSC error code (For windows it is a standard OS error code).</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
LONG tsSCardStatus(IN SCARDHANDLE hCard, OUT LPSTR mszReaderNames, IN OUT LPDWORD pcchReaderLen, OUT LPDWORD pdwState, OUT LPDWORD pdwProtocol, OUT LPBYTE pbAtr, OUT LPDWORD pcbAtrLen);

/// <summary>Defines information describing a reader.</summary>
typedef struct ReaderInfo
{
    tscrypto::tsCryptoString name;		///< The reader name
    uint32_t status;	///< The current status for the reader
    tscrypto::tsCryptoData atr;		///< The ATR string for the card (if any) in the reader
} ReaderInfo;


HANDLE tsSCardAccessStartedEvent(void);
void tsSCardReleaseStartedEvent(void);



/* ! @brief This type defines the different notification events that can be raised by the ::TS_ScanForChanges function */
//typedef enum TSWC_ChangeType {
//    TSWC_ReaderAdded = 1,		/*!< A reader has been added to the system */
//    TSWC_ReaderRemoved = 2,		/*!< A reader has been removed from the system */
//    TSWC_CardInserted = 3,		/*!< A card has been inserted into a reader */
//    TSWC_CardRemoved = 4,		/*!< The card has been removed from a reader */
//    TSWC_CardHandleInvalid = 5,	/*!< The indicated card handle has been invalidated */
//} TSWC_ChangeType;

// / <summary>Function pointer type for a function receives notifications for smart card changes.</summary>
//typedef void (* TSWC_ChangeConsumerFn)(IN void *userParams,
//                                                IN TSWC_ChangeType type,
//                                                IN const tscrypto::tsCryptoString &readerName,
//                                                IN void *otherParams);

class TSWC_ChangeConsumer
{
public:
    virtual void ReaderAdded(const tscrypto::tsCryptoString& readerName) = 0;
    virtual void ReaderRemoved(const tscrypto::tsCryptoString& readerName) = 0;
    virtual void CardInserted(const tscrypto::tsCryptoString& readerName) = 0;
    virtual void CardRemoved(const tscrypto::tsCryptoString& readerName) = 0;
};

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4231)
VEILSMARTCARD_TEMPLATE_EXTERN template class VEILSMARTCARD_EXPORT tscrypto::ICryptoContainerWrapper<ReaderInfo>;
VEILSMARTCARD_TEMPLATE_EXTERN template class VEILSMARTCARD_EXPORT std::shared_ptr<tscrypto::ICryptoContainerWrapper<ReaderInfo>>;
#pragma warning(pop)
#endif // _MSC_VER

typedef std::shared_ptr<tscrypto::ICryptoContainerWrapper<ReaderInfo>> ReaderInfoList;
extern VEILSMARTCARD_EXPORT ReaderInfoList CreateReaderInfoList();

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Register a smart card change consumer.</summary>
///
/// <param name="consumer">		 The function that receives the notifications.</param>
///
/// <returns>A cookie (alias) for this registered change consumer.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
uint32_t TSWC_RegisterChangeConsumer(std::shared_ptr<TSWC_ChangeConsumer> consumer);
//////////////////////////////////////////////////////////////////////////////////////////////////////
///// <summary>Gets the user parameters for the specified cookie.</summary>
/////
///// <param name="consumerCookie">The change consumer cookie.</param>
/////
///// <returns>null if it fails, else the user parameters.</returns>
//////////////////////////////////////////////////////////////////////////////////////////////////////
//void * TSWC_GetUserParams(uint32_t consumerCookie);
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Unregisters a change consumer for the specified cookie.</summary>
///
/// <param name="consumerCookie">The change consumer cookie.</param>
////////////////////////////////////////////////////////////////////////////////////////////////////
void TSWC_UnregisterChangeConsumer(uint32_t consumerCookie);
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>Returns the current list and status of the smart card readers in the system.</summary>
///
/// <returns>A list of.</returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
ReaderInfoList tsSCardReaderList();

#endif // HAVE_SMARTCARD

#endif	// ifndef TSWINSCARDEXPORTS_H_INCLUDE
