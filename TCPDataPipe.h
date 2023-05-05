#if !defined(AFX_TCPDATAPIPE_H__EE799CFA_34FF_4FA6_A021_6B039F22A376__INCLUDED_)
#define AFX_TCPDATAPIPE_H__EE799CFA_34FF_4FA6_A021_6B039F22A376__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "resource.h"
#include "Sha256.h"
#include "AES.h"

#define MAX_PACKET_SIZE 1048576 /* variable from PACKET_PADDED_SIZE to 4294967295 */
#define PACKET_PADDED_SIZE 512 /* must be greater than PACKET_HEADER_SIZE */
#define PACKET_HEADER_SIZE 32 /* must be a multiple of 16 on a AES block (IV) boundary */
#define CLIENT_CHALLENGE_SIZE 32
#define RANDOM_CHALLENGE_SIZE (CLIENT_CHALLENGE_SIZE - sizeof(FILETIME))

#define WM_SYSTRAYNOTIFY WM_APP+1001

// Global Variables:

struct _GlobalHandles {
	HWND hMainWindow;
	HWND hClientPasswordPrompt;
	HINSTANCE hModuleInstance;
	HCRYPTPROV hGenerateRandom;
	HANDLE hServiceMainThread;
	HANDLE hServiceMainStoppedEvent;
	HANDLE hStopServiceEvent;
	HANDLE hStopClientListenerEvent;
	HANDLE hClientListenerThread;
	HANDLE hStopClientsEvent;
	SERVICE_STATUS_HANDLE hServiceHandle;
	SOCKET hSocketListener;
} g_handle = {
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	INVALID_SOCKET,
};

struct _ClientWindowMessageData {
	TCHAR szWindowMessages[4096];
	CRITICAL_SECTION csWindowMessages;
} g_clientmsgdata = {
	{0},
	{0},
};

struct _ShellData {
	NOTIFYICONDATA nidSysTray;
	UINT WM_TASKBARCREATED;
	BOOL bIconic;
} g_shelldata = {
	{sizeof(NOTIFYICONDATA), 0},
	RegisterWindowMessage(_T("TaskbarCreated")),
	FALSE,
};

struct _ChallengeData {
	BYTE abChallengeList[20000 * (1 + RANDOM_CHALLENGE_SIZE)];
	CRITICAL_SECTION csChallengeList;
} g_chdata = {
	{0},
	{0},
};

struct _IPBlacklistData { // any variables initialized to non-zero in here will increase size of object code by upto countof(alBlacklistIPAddress) * (sizeof(ULONG) + 1) bytes !!
	ULONG alBlacklistIPAddress[0x10000];
	BYTE abBlacklistIPCounter[0x10000];
	CRITICAL_SECTION csBlacklistIP;
} g_iplistdata = {
	{0},
	{0},
	{0},
};

struct _ClientParams {
	DWORD lpClientListenerThreadId;
	TCHAR szClientAuthenticationData[2048];
	ULONG ulClientListenIP;
	USHORT sClientListenPort;
	USHORT sClientRemoteTunneledPort;
	USHORT sClientRemoteAccessPort;
	ULONG ulClientRemoteAccessIP;
	TCHAR szClientPassword[256];
	BOOL bClientPasswordPrompt;
	BOOL bClientReconnectOnLoss;
	ULONG ulIdleTimeout;
	BYTE abEncryptionKey[AES_KEYSIZE_256];
} g_clientparams = {
	0,
	{0},
	INADDR_LOOPBACK,
	10000,
	3389,
	50000,
	0,
	{0},
	TRUE,
	FALSE,
	0,
	{0xf0,0x0f,0xf0,0x0f,0xf0,0x0f,0xf0,0x0f,0xf0,0x0f,0xf0,0x0f,0xf0,0x0f,0xf0,0x0f,0xf0,0x0f,0xf0,0x0f,0xf0,0x0f,0xf0,0x0f,0xf0,0x0f,0xf0,0x0f,0xf0,0x0f,0xf0,0x0f},
};

struct _ServerParams {
	TCHAR szServiceName[256];
	TCHAR szDisplayName[256];
	DWORD lpServiceMainThreadId;
	ULONG ulServerDestIP;
	ULONG ulServerListenIP;
	USHORT sServerListenPort;
	BOOL bBlacklistIPBlock;
	ULONG ulIdleTimeout;
} g_serverparams = {
	"TCPTUNNEL",
	"TCP Tunnel Service",
	0,
	INADDR_LOOPBACK,
	0,
	50000,
	TRUE,
	0,
};

struct ServerKeyChain
{
	BYTE key[AES_KEYSIZE_256];
	struct ServerKeyChain * next;
	ServerKeyChain() : next(NULL) {}
	~ServerKeyChain() { memset(key, 0, sizeof(key)); delete next; }
	void Clear() {
		memset(key, 0, sizeof(key));
		delete next;
		next = NULL;
	}
	ULONG Count(ULONG _offset = -1) {
		if(next == NULL)
			return -1 * _offset;
		return next->Count(_offset - 1);
	}
	ServerKeyChain * Find(ULONG _index) {
		if(_index == 0)
			return this;
		if(next)
			return next->Find(_index - 1);
		return NULL;
	}
	void SetKey(BYTE _key[AES_KEYSIZE_256], ULONG _index = 0) {
		if(_index != 0)
		{
			if(next == NULL)
				next = new ServerKeyChain();
			next->SetKey(_key, _index - 1);
		}
		else
		{
			memcpy(key, _key, sizeof(key));
		}
	}
} g_serverkeys;

LONG g_clientthreadcount = 0;
LONG g_serverthreadcount = 0;
BYTE g_clientrandpool[SHA_SIZE_256] = {0};

const BYTE IV_RECV[AES_BLOCK_SIZE] = {0xa5,0x5a,0xa5,0x5a,0xa5,0x5a,0xa5,0x5a,0xa5,0x5a,0xa5,0x5a,0xa5,0x5a,0xa5,0x5a};
const BYTE IV_SEND[AES_BLOCK_SIZE] = {0x5a,0xa5,0x5a,0xa5,0x5a,0xa5,0x5a,0xa5,0x5a,0xa5,0x5a,0xa5,0x5a,0xa5,0x5a,0xa5};

// Types:

struct CharHeapBuffer
{
	int size;
	char * buffer;
	CharHeapBuffer(int _size = 0) : buffer(NULL), size(0)
	{
		Allocate(_size);
	}
	CharHeapBuffer(const CharHeapBuffer&); // no copy construction allowed
	~CharHeapBuffer()
	{
		delete[] buffer;
	}
	bool Allocate(int _size)
	{
		delete[] buffer;
		buffer = _size > 0 ? new char[_size] : NULL;
		size = buffer != NULL ? _size : 0;
		return size > 0;
	}
	int Size() { return size; }
	char & operator[](int i)
	{
		return *(&buffer[i]);
	}
	operator char*()
	{
		return buffer;
	}
	operator unsigned char*()
	{
		return (unsigned char*)buffer;
	}
	const CharHeapBuffer& operator=(const CharHeapBuffer&); // no copy assignment allowed
};

// Forward declarations:

ATOM				MyRegisterClass(HINSTANCE hInstance, TCHAR * lpszClassName);
LRESULT CALLBACK	MainWndProc(HWND, UINT, WPARAM, LPARAM);
void				UpdateMenus(HWND hWnd);
void WINAPI			ServiceMain(DWORD dwArgc, LPTSTR* lpszArgv);
void WINAPI			ServiceHandler(DWORD fdwControl);

LRESULT CALLBACK	ClientConfigProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK	ServerConfigProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK	PasswordPromptProc(HWND, UINT, WPARAM, LPARAM);
ULONG WINAPI		ClientRandPoolThread(void* stopevent);

ULONG WINAPI		ClientListenerThread(void*);
ULONG WINAPI		ClientSocketThread(void* sockfd);
ULONG WINAPI		ServerSocketThread(void* sockfd);
ULONG WINAPI		ServerCloseSocketThread(void* sockfd);
int					ReadSocketData(SOCKET sockfd, char * buf, int length, ServerKeyChain & keys, unsigned char iv[AES_BLOCK_SIZE], ULONG & keyindex, ULONG & errcode, u_short & port);
int					ReadSocketData(SOCKET sockfd, char * buf, int length, const unsigned char * key, int keylength, unsigned char iv[AES_BLOCK_SIZE], ULONG & errcode, u_short & port);
bool				WriteSocketData(SOCKET sockfd, char * buf, int offset, int length, const unsigned char * key, int keylength, unsigned char iv[AES_BLOCK_SIZE], u_short port, int errcode);

void				OutputClientWindowMessage(char * msg, char * endmsg);
void				OutputServerMessage(char * msg, ...);

bool				AddChallengeList(const unsigned char challenge[RANDOM_CHALLENGE_SIZE]);
bool				GetBlacklist(u_long address);
void				UpdateBlacklist(u_long address, bool add);
void				ClearBlacklist();

void				ThreadReleaseCriticalSection(DWORD threadID);
BOOL				GetNameByPID(DWORD pid, char * name, int length);
BOOL				GetAddrProcessName(const struct sockaddr_in & addr, char * name, int length, int & pid);
BOOL				IsProcessConnected(const char * name, int pid);
BOOL				IsAddressConnected(ULONG addr);

int					AddRandomPadding(char * outdata, int outlength, int outoffset);
void				GenerateRandomData(int count, unsigned char * bytes);
void                DeriveServerSessionKey(const char * data, int length, unsigned char key[AES_KEYSIZE_256]);
int					ClientGenerateChallengeData(char * challenge1, int challengelength, char * authdata, int authlength);
bool                ClientVerifyChallengeDeriveKey(const char * authdata, int authlength, const char * challenge1, int challengelength, unsigned char key[AES_KEYSIZE_256]);
int                 ServerVerifyChallengeDeriveKey(const char * authdata, int authlength, char * outdata, int outlength, unsigned char key[AES_KEYSIZE_256]);
bool				DecodeServerConfigData(const char *data, char *name, int namelength, ServerKeyChain & keys, ULONG & localip, USHORT & localport, ULONG & destip, ULONG & timeout, BOOL & useblacklist);
int					EncodeServerConfigData(char *name, ServerKeyChain & keys, ULONG localip, USHORT localport, ULONG destip, ULONG timeout, BOOL useblacklist, CharHeapBuffer & data);
bool				DecryptClientConfigData(const char *data, const char *pwd, unsigned char * key, int keylength, ULONG & remoteip, USHORT & remoteport, USHORT & tunnelport, ULONG & localip, USHORT & localport, ULONG & timeout, BOOL & reconnect, BOOL & pwdprompt);
int					EncryptClientConfigData(unsigned char * key, int keylength, ULONG remoteip, USHORT remoteport, USHORT tunnelport, ULONG localip, USHORT localport, ULONG timeout, BOOL reconnect, BOOL pwdprompt, const char *pwd, CharHeapBuffer & data);
void				HeaderChecksum(char * data, int length, unsigned char * checksum, int checksumlength);
void				DataChecksum(char * data, int length, unsigned char * checksum, int checksumlength);

BOOL				GetConfigFilename(bool server, char * name, int length);
BOOL				GetConfigData(bool server, CharHeapBuffer & data, char * filepath, int filepathlength);
int					EncodeHeader(char * buf, int dataoffset, ULONG datalength, ULONG errcode, u_short port);
bool				DecodeHeader(char * buf, int length, unsigned char * data_checksum, ULONG & data_checksum_length, ULONG & data_length, ULONG & errcode, u_short & port);

inline ULONG		BytesToLong(BYTE * bytes);
inline void			LongToBytes(ULONG l, BYTE * bytes);
inline USHORT		BytesToUShort(BYTE * bytes);
inline void			UShortToBytes(USHORT s, BYTE * bytes);

#endif // !defined(AFX_TCPDATAPIPE_H__EE799CFA_34FF_4FA6_A021_6B039F22A376__INCLUDED_)
