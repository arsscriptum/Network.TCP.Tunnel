// stdafx.h : include file for standard system include files,
//  or project specific include files that are used frequently, but
//      are changed infrequently
//

#if !defined(AFX_STDAFX_H__A9DB83DB_A9FD_11D0_BFD1_444553540000__INCLUDED_)
#define AFX_STDAFX_H__A9DB83DB_A9FD_11D0_BFD1_444553540000__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers
#define _WIN32_WINNT 0x0400
#pragma warning (disable:4018)
#if _MSC_VER >= 1300
#pragma warning (disable:4996)
#endif // _MSC_VER > 1300

// Windows Header Files:
#include <windows.h>
#include <wtypes.h>
#include <winsock2.h>
#include <wincrypt.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <lmcons.h>
#include <tchar.h>

// C RunTime Header Files
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <malloc.h>
#include <memory.h>

// Local Definitions

#ifndef STACK_SIZE_PARAM_IS_A_RESERVATION
#define STACK_SIZE_PARAM_IS_A_RESERVATION 0x00010000
#endif

#ifndef SO_EXCLUSIVEADDRUSE
#define SO_EXCLUSIVEADDRUSE ((int)(~SO_REUSEADDR)) /* disallow local address reuse */
#endif

/* Value used to declare an array of an unknown size */
#ifndef ANY_SIZE
    #define ANY_SIZE    1
#endif

/* TCP table classes */
typedef enum _TCP_TABLE_CLASS {
    TCP_TABLE_BASIC_LISTENER            = 0,
    TCP_TABLE_BASIC_CONNECTIONS         = 1,
    TCP_TABLE_BASIC_ALL                 = 2,
    TCP_TABLE_OWNER_PID_LISTENER        = 3,
    TCP_TABLE_OWNER_PID_CONNECTIONS     = 4,
    TCP_TABLE_OWNER_PID_ALL             = 5,
    TCP_TABLE_OWNER_MODULE_LISTENER     = 6,
    TCP_TABLE_OWNER_MODULE_CONNECTIONS  = 7,
    TCP_TABLE_OWNER_MODULE_ALL          = 8
} TCP_TABLE_CLASS;
typedef TCP_TABLE_CLASS *PTCP_TABLE_CLASS;

/* MIB TCP states */
typedef enum {
    MIB_TCP_STATE_CLOSED        = 1,
    MIB_TCP_STATE_LISTEN        = 2,
    MIB_TCP_STATE_SYN_SENT      = 3,
    MIB_TCP_STATE_SYN_RCVD      = 4,
    MIB_TCP_STATE_ESTAB         = 5,
    MIB_TCP_STATE_FIN_WAIT1     = 6,
    MIB_TCP_STATE_FIN_WAIT2     = 7,
    MIB_TCP_STATE_CLOSE_WAIT    = 8,
    MIB_TCP_STATE_CLOSING       = 9,
    MIB_TCP_STATE_LAST_ACK      = 10,
    MIB_TCP_STATE_TIME_WAIT     = 11,
    MIB_TCP_STATE_DELETE_TCB    = 12
} MIB_TCP_STATE;

/* MIB TCP row owner protocol identifier */
typedef struct _MIB_TCPROW_OWNER_PID {
    DWORD   dwState;
    DWORD   dwLocalAddr;
    DWORD   dwLocalPort;
    DWORD   dwRemoteAddr;
    DWORD   dwRemotePort;
    DWORD   dwOwningPid;
} MIB_TCPROW_OWNER_PID;
typedef MIB_TCPROW_OWNER_PID    *PMIB_TCPROW_OWNER_PID;

/* MIB TCP table owner protocol identifier */
typedef struct _MIB_TCPTABLE_OWNER_PID {
    DWORD                   dwNumEntries;
    MIB_TCPROW_OWNER_PID    table[ANY_SIZE];
} MIB_TCPTABLE_OWNER_PID;
typedef MIB_TCPTABLE_OWNER_PID  *PMIB_TCPTABLE_OWNER_PID;

#ifdef __cplusplus
extern "C" {
#endif

typedef DWORD (WINAPI * _PFNGetExtendedTcpTable)(
	PVOID pTcpTable,
	PDWORD pdwSize,
	BOOL bOrder,
	ULONG ulAf,
	TCP_TABLE_CLASS TableClass,
	ULONG Reserved
	);

static _PFNGetExtendedTcpTable _GetExtendedTcpTable=(_PFNGetExtendedTcpTable)GetProcAddress(LoadLibrary(_T("iphlpapi")),"GetExtendedTcpTable");

#ifdef __cplusplus
}
#endif

#ifndef CRYPTPROTECT_UI_FORBIDDEN

//
// CryptProtectData and CryptUnprotectData dwFlags
//
// for remote-access situations where ui is not an option
// if UI was specified on protect or unprotect operation, the call
// will fail and GetLastError() will indicate ERROR_PASSWORD_RESTRICTION
#define CRYPTPROTECT_UI_FORBIDDEN        0x1

//
// per machine protected data -- any user on machine where CryptProtectData
// took place may CryptUnprotectData
#define CRYPTPROTECT_LOCAL_MACHINE       0x4

typedef struct  _CRYPTPROTECT_PROMPTSTRUCT
{
    DWORD cbSize;
    DWORD dwPromptFlags;
    HWND  hwndApp;
    LPCWSTR szPrompt;
} CRYPTPROTECT_PROMPTSTRUCT, *PCRYPTPROTECT_PROMPTSTRUCT;

#endif // CRYPTPROTECT_UI_FORBIDDEN

#ifdef __cplusplus
extern "C" {
#endif

typedef BOOL (WINAPI * _PFNCryptProtectData)(
    IN              DATA_BLOB*      pDataIn,
    IN              LPCWSTR         szDataDescr,
    IN OPTIONAL     DATA_BLOB*      pOptionalEntropy,
    IN              PVOID           pvReserved,
    IN OPTIONAL     CRYPTPROTECT_PROMPTSTRUCT*  pPromptStruct,
    IN              DWORD           dwFlags,
    OUT             DATA_BLOB*      pDataOut            // out encr blob
    );

static _PFNCryptProtectData _CryptProtectData=(_PFNCryptProtectData)GetProcAddress(LoadLibrary(_T("crypt32")),"CryptProtectData");

typedef BOOL (WINAPI * _PFNCryptUnprotectData)(
    IN              DATA_BLOB*      pDataIn,             // in encr blob
    OUT OPTIONAL    LPWSTR*         ppszDataDescr,       // out
    IN OPTIONAL     DATA_BLOB*      pOptionalEntropy,
    IN              PVOID           pvReserved,
    IN OPTIONAL     CRYPTPROTECT_PROMPTSTRUCT*  pPromptStruct,
    IN              DWORD           dwFlags,
    OUT             DATA_BLOB*      pDataOut
    );

static _PFNCryptUnprotectData _CryptUnprotectData=(_PFNCryptUnprotectData)GetProcAddress(LoadLibrary(_T("crypt32")),"CryptUnprotectData");

#ifdef __cplusplus
}
#endif

// helper function to convert winsock errors to strings

static struct wsaerrorstrings_t {
    int code;
    const char *desc;
} _wsaerrorstrings[] =
{
    {
	WSA_E_CANCELLED, "Lookup cancelled."
    },
    {
	WSA_E_NO_MORE, "No more data available."
    },
    {
	WSAEACCES, "Permission denied."
    },
    {
	WSAEADDRINUSE, "Address already in use."
    },
    {
	WSAEADDRNOTAVAIL, "Cannot assign requested address."
    },
    {
	WSAEAFNOSUPPORT, "Address family not supported by protocol family."
    },
    {
	WSAEALREADY, "Operation already in progress."
    },
    {
	WSAEBADF, "Bad file number."
    },
    {
	WSAECANCELLED, "Operation cancelled."
    },
    {
	WSAECONNABORTED, "Software caused connection abort."
    },
    {
	WSAECONNREFUSED, "Connection refused."
    },
    {
	WSAECONNRESET, "Connection reset by peer."
    },
    {
	WSAEDESTADDRREQ, "Destination address required."
    },
    {
	WSAEDQUOT, "Disk quota exceeded."
    },
    {
	WSAEFAULT, "Bad address."
    },
    {
	WSAEHOSTDOWN, "Host is down."
    },
    {
	WSAEHOSTUNREACH, "No route to host."
    },
    {
	WSAEINPROGRESS, "Operation now in progress."
    },
    {
	WSAEINTR, "Interrupted function call."
    },
    {
	WSAEINVAL, "Invalid argument."
    },
    {
	WSAEINVALIDPROCTABLE, "Invalid procedure table from service provider."
    },
    {
	WSAEINVALIDPROVIDER, "Invalid service provider version number."
    },
    {
	WSAEISCONN, "Socket is already connected."
    },
    {
	WSAELOOP, "Too many levels of symbolic links."
    },
    {
	WSAEMFILE, "Too many open files."
    },
    {
	WSAEMSGSIZE, "Message too long."
    },
    {
	WSAENAMETOOLONG, "File name is too long."
    },
    {
	WSAENETDOWN, "Network is down."
    },
    {
	WSAENETRESET, "Network dropped connection on reset."
    },
    {
	WSAENETUNREACH, "Network is unreachable."
    },
    {
	WSAENOBUFS, "No buffer space available."
    },
    {
	WSAENOMORE, "No more data available."
    },
    {
	WSAENOPROTOOPT, "Bad protocol option."
    },
    {
	WSAENOTCONN, "Socket is not connected."
    },
    {
	WSAENOTEMPTY, "Directory is not empty."
    },
    {
	WSAENOTSOCK, "Socket operation on nonsocket."
    },
    {
	WSAEOPNOTSUPP, "Operation not supported."
    },
    {
	WSAEPFNOSUPPORT, "Protocol family not supported."
    },
    {
	WSAEPROCLIM, "Too many processes."
    },
    {
	WSAEPROTONOSUPPORT, "Protocol not supported."
    },
    {
	WSAEPROTOTYPE, "Protocol wrong type for socket."
    },
    {
	WSAEPROVIDERFAILEDINIT, "Unable to initialise a service provider."
    },
    {
	WSAEREFUSED, "Query failed because it was actively refused."
    },
    {
	WSAEREMOTE, "Too many levels of remote in path."
    },
    {
	WSAESHUTDOWN, "Cannot send after socket shutdown."
    },
    {
	WSAESOCKTNOSUPPORT, "Socket type not supported."
    },
    {
	WSAESTALE, "File handle reference is no longer available."
    },
    {
	WSAETIMEDOUT, "Connection timed out."
    },
    {
	WSAETOOMANYREFS, "Too many references."
    },
    {
	WSAEUSERS, "Too many users."
    },
    {
	WSAEWOULDBLOCK, "Resource temporarily unavailable."
    },
    {
	WSANOTINITIALISED, "Sockets not initialised."
    },
    {
	WSASERVICE_NOT_FOUND, "Service not found."
    },
    {
	WSASYSCALLFAILURE, "System call failure."
    },
    {
	WSASYSNOTREADY, "Network subsystem is unavailable."
    },
    {
	WSATYPE_NOT_FOUND, "Class type not found."
    },
    {
	WSAVERNOTSUPPORTED, "Winsock.dll version out of range."
    },
    {
	WSAEDISCON, "Graceful shutdown in progress."
    },
    {
	WSAHOST_NOT_FOUND, "No such host is known."
    },
    {
	WSATRY_AGAIN, "Host not found."
    },
    {
	WSANO_RECOVERY, "A non-recoverable error occurred during lookup."
    },
    {
	WSANO_DATA, "Requested name is valid but no data record was found."
    },
};

inline char * GetWSAErrorString(int code, char * buffer, int length)
{
	if(buffer && length >= 64)
	{
		for (int i=0; i != sizeof(_wsaerrorstrings) / sizeof(wsaerrorstrings_t); ++i)
		{
			if (_wsaerrorstrings[i].code == code)
			{
				strncpy(buffer, _wsaerrorstrings[i].desc, length - 1);
				return buffer;
			}
		}
		*buffer = '\0';
		if(FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS, NULL, code, 0, buffer, length - 1, NULL) > 0)
		{
			char * p = strchr(buffer, '\r');
			if(p != NULL) *p = '\0';
			p = strchr(buffer, '\n');
			if(p != NULL) *p = '\0';
			return buffer;
		}
		if(code & 0x80000000)
		{
			strcpy(buffer, "error 0x");
			_ultoa(code, &buffer[strlen(buffer)], 16);
		}
		else
		{
			strcpy(buffer, "error ");
			_ultoa(code, &buffer[strlen(buffer)], 10);
		}
		return buffer;
	}
	return "";
}

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_STDAFX_H__A9DB83DB_A9FD_11D0_BFD1_444553540000__INCLUDED_)
