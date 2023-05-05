// TCPDataPipe.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "resource.h"
#include "TCPDataPipe.h"

int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
	g_handle.hModuleInstance = hInstance;

	TCHAR szTitle[256] = {0};
	TCHAR szWindowClass[256] = {0};

	LoadString(hInstance, IDS_APP_TITLE, szTitle, sizeof(szTitle) / sizeof(szTitle[0]));
	LoadString(hInstance, IDC_TCPDATAPIPE, szWindowClass, sizeof(szWindowClass) / sizeof(szWindowClass[0]));

	// make szWindowClass unique for every path to executable file, for finding the associated window

	{
		const char * path = GetCommandLine();
		if(path)
		{
			strncat(szWindowClass, path, sizeof(szWindowClass) - strlen(szWindowClass) - 1);
			int i = strlen(szWindowClass);
			while(i > 0 && isspace(szWindowClass[--i]))
			{
				szWindowClass[i] = '\0'; // remove trailing spaces
			}
		}
		for(int i=0,n=strlen(szWindowClass);i!=n;++i)
		{
			szWindowClass[i] = tolower(szWindowClass[i]);
		}
		unsigned char digest[SHA_SIZE_256] = {0};
		sha256Digest((unsigned char *)szWindowClass, strlen(szWindowClass), digest);
		BytesToHexLower(digest, sizeof(digest), szWindowClass);
		szWindowClass[2 * sizeof(digest)] = '\0';
	}

	MyRegisterClass(hInstance, szWindowClass);

	if (lpCmdLine && strlen(lpCmdLine) > 0)
	{
		char * p = strchr(lpCmdLine, '/');
		if(!p)
		{
			p = strchr(lpCmdLine, '-');
		}
		if(p)
		{
			char * v = strchr(p++, ' ');
			char * e = v ? v + strlen(v) - 1 : p + strlen(p) - 1;
			if(v)
			{
				while(*v == ' ') ++v;
				while(*e == ' ') --e;
				*(e + 1) = '\0';
			}

			if(strnicmp(p, "pass", 4) == 0 || strnicmp(p, "password", 8) == 0)
			{
				if(v)
				{
					if(e - v > 0 && *v == '\"' && *e == '\"')
					{
						++v;
						*e = '\0';
					}
					strncpy(g_clientparams.szClientPassword, v, sizeof(g_clientparams.szClientPassword) - 1);
				}
			}
			else if(strnicmp(p, "help", 4) == 0 || strnicmp(p, "h", 1) == 0 || strnicmp(p, "?", 1) == 0)
			{
				MessageBox(GetForegroundWindow(), "Command line options\r\n\r\n/pass or /password: application password", g_serverparams.szDisplayName, MB_OK | MB_ICONINFORMATION);
				return 0;
			}
		}
	}

	InitializeCriticalSection(&g_iplistdata.csBlacklistIP);
	InitializeCriticalSection(&g_chdata.csChallengeList);
	InitializeCriticalSection(&g_clientmsgdata.csWindowMessages);

	struct CSPContext {
		CSPContext() {CryptAcquireContext(&g_handle.hGenerateRandom, NULL, NULL, PROV_RSA_FULL, 0);}
		~CSPContext() {CryptReleaseContext(g_handle.hGenerateRandom, 0);}
	} cspctxt;

	srand(GetTickCount());

	// service must not be installed as interact with desktop

	USEROBJECTFLAGS uof = {0};
	GetUserObjectInformation(GetProcessWindowStation(), UOI_FLAGS, &uof, sizeof(USEROBJECTFLAGS), NULL);

	if (uof.dwFlags & WSF_VISIBLE) 
	{
		// running client application

		struct Mutex {
			Mutex(const TCHAR * name) {handle = CreateMutex(NULL, FALSE, name); exists = GetLastError() != ERROR_SUCCESS;}
			~Mutex() {CloseHandle(handle);}
			HANDLE handle;
			bool exists;
		} mutex(szWindowClass);

		if(mutex.exists)
		{
			// find associated window and give it focus then exit

			HWND hwndFirst = FindWindow(szWindowClass, szTitle);
			if(hwndFirst)
			{
				HWND hwndPopup = GetLastActivePopup(hwndFirst);
				if(!IsWindowVisible(hwndFirst))
				{
					ShowWindow(hwndFirst, SW_SHOW);
				}
				else if(IsIconic(hwndFirst))
				{
					ShowWindow(hwndFirst, SW_RESTORE);
				}
				SetForegroundWindow(hwndFirst); // bring main window to top
				if(hwndFirst != hwndPopup)
				{
					SetForegroundWindow(hwndPopup); // a popup window is active
				}
			}
			return 0;
		}

		CharHeapBuffer data;
		if(GetConfigData(false, data, NULL, 0))
		{
			memcpy(g_clientparams.szClientAuthenticationData, (const TCHAR *)data, min(sizeof(g_clientparams.szClientAuthenticationData), data.Size()));
			unsigned char key[sizeof(g_clientparams.abEncryptionKey)] = {0};
			USHORT remoteport = 0, tunnelport = 0, localport = 0;
			ULONG remoteip = 0, localip = 0, timeout = 0;
			BOOL reconnect = FALSE, pwdprompt = FALSE;

			if(!DecryptClientConfigData(g_clientparams.szClientAuthenticationData, g_clientparams.szClientPassword, key, sizeof(key), remoteip, remoteport, tunnelport, localip, localport, timeout, reconnect, pwdprompt))
			{
				if(DialogBoxParam(hInstance, (LPCTSTR)IDD_PASSWORDPROMPT1, GetForegroundWindow(), (DLGPROC)PasswordPromptProc, 0) != IDOK)
				{
					return 0;
				}

				if(!DecryptClientConfigData(g_clientparams.szClientAuthenticationData, g_clientparams.szClientPassword, key, sizeof(key), remoteip, remoteport, tunnelport, localip, localport, timeout, reconnect, pwdprompt))
				{
					return 0;
				}
			}

			memcpy(g_clientparams.abEncryptionKey, key, sizeof(g_clientparams.abEncryptionKey));

			g_clientparams.sClientRemoteAccessPort = remoteport;
			g_clientparams.sClientRemoteTunneledPort = tunnelport;
			g_clientparams.ulClientListenIP = localip;
			g_clientparams.sClientListenPort = localport;
			g_clientparams.ulClientRemoteAccessIP = remoteip;
			g_clientparams.bClientReconnectOnLoss = reconnect;
			g_clientparams.bClientPasswordPrompt = pwdprompt;
			g_clientparams.ulIdleTimeout = timeout;
		}

		bool initialized = (strlen(g_clientparams.szClientAuthenticationData) > 0);

		// get the service name for restarting the service

		if(GetConfigData(true, data, NULL, 0))
		{
			USHORT port = 0;
			ULONG ip = 0, ip2 = 0, timeout = 0;
			BOOL useBlacklist = FALSE;
			ServerKeyChain keys;
			char name[sizeof(g_serverparams.szServiceName)] = {0};
			memcpy(name, g_serverparams.szServiceName, sizeof(name));

			if(DecodeServerConfigData(data, name, sizeof(name), keys, ip, port, ip2, timeout, useBlacklist))
			{
				memcpy(g_serverparams.szServiceName, name, sizeof(g_serverparams.szServiceName));
			}
		}

		// finally create the main window

		g_handle.hMainWindow = CreateWindow(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, NULL, NULL, hInstance, NULL);
		if(!g_handle.hMainWindow)
		{
			return 0;
		}

		UpdateMenus(g_handle.hMainWindow);
		ShowWindow(g_handle.hMainWindow, initialized ? SW_HIDE : SW_SHOWNORMAL);
		UpdateWindow(g_handle.hMainWindow);

		HACCEL hAccelTable = LoadAccelerators(hInstance, (LPCTSTR)IDC_TCPDATAPIPE);

		g_handle.hStopClientListenerEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		g_handle.hStopClientsEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

		WSADATA wsadata={0};
		WSAStartup(MAKEWORD(2,2), &wsadata);

		if(initialized)
		{
			g_shelldata.bIconic = TRUE;
			Shell_NotifyIcon(NIM_ADD, &g_shelldata.nidSysTray);
			g_handle.hClientListenerThread = CreateThread(NULL, 0, ClientListenerThread, (void *)0, 0, &g_clientparams.lpClientListenerThreadId);
		}

		// main message loop

		MSG msg = {0};
		while (GetMessage(&msg, NULL, 0, 0))
		{
			if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg)) 
			{
				TranslateMessage(&msg);
				DispatchMessage(&msg);
			}
		}

		SetEvent(g_handle.hStopClientListenerEvent);
		SetEvent(g_handle.hStopClientsEvent);

		SOCKET hSocket = g_handle.hSocketListener;
		g_handle.hSocketListener = INVALID_SOCKET;
		if(hSocket != INVALID_SOCKET)
		{
			closesocket(hSocket);
		}

		if(g_handle.hClientListenerThread)
		{
			if(WaitForSingleObject(g_handle.hClientListenerThread, 5000) == WAIT_TIMEOUT)
			{
				// hopefully never require this - stack page allocation is not freed,
				// DLL_THREAD_DETACH is not called for dlls, owned critical sections
				// are not released. Since exiting program this is not so important.
				TerminateThread(g_handle.hClientListenerThread, 0);
				ThreadReleaseCriticalSection(g_clientparams.lpClientListenerThreadId);
			}
			CloseHandle(g_handle.hClientListenerThread);
		}

		CloseHandle(g_handle.hStopClientListenerEvent);
		CloseHandle(g_handle.hStopClientsEvent);

		while(g_clientthreadcount > 0)
		{
			if(WaitForSingleObject(GetCurrentThread(), 1) != WAIT_TIMEOUT)
			{
				break;
			}
		}

		WSACleanup();

		return msg.wParam;
	}
	else
	{
		// load the server key stored with no password

		bool exists = false;

		CharHeapBuffer data;
		char path[_MAX_PATH + 128] = {0};

		if(GetConfigData(true, data, path, sizeof(path)))
		{
			USHORT port = 0;
			ULONG ip = 0, ipdest = 0, timeout = 0;
			BOOL useBlacklist = TRUE;
			char name[sizeof(g_serverparams.szServiceName)] = {0};
			memcpy(name, g_serverparams.szServiceName, sizeof(name));

			if(DecodeServerConfigData(data, name, sizeof(name), g_serverkeys, ip, port, ipdest, timeout, useBlacklist))
			{
				exists = true;
				g_serverparams.ulServerListenIP = ip;
				g_serverparams.sServerListenPort = port;
				g_serverparams.ulServerDestIP = ipdest;
				g_serverparams.ulIdleTimeout = timeout;
				g_serverparams.bBlacklistIPBlock = useBlacklist;
				memcpy(g_serverparams.szServiceName, name, sizeof(g_serverparams.szServiceName));
			}
		}

		if(!exists)
		{
			// generate random key and save to file

			g_serverkeys.Clear();

			GenerateRandomData(sizeof(g_serverkeys.key), g_serverkeys.key);

			CharHeapBuffer content;

			int length = EncodeServerConfigData(g_serverparams.szServiceName, g_serverkeys, g_serverparams.ulServerListenIP, g_serverparams.sServerListenPort, g_serverparams.ulServerDestIP, g_serverparams.ulIdleTimeout, g_serverparams.bBlacklistIPBlock, content);
			if(length > 0 && strlen(path) > 0)
			{
				FILE *fd = fopen(path, "wb");
				if(fd != NULL)
				{
					fwrite((const BYTE *)content, 1, length, fd);
					fclose(fd);
				}
			}
		}

		SERVICE_TABLE_ENTRY ste[2] =
		{
			{ g_serverparams.szServiceName, ServiceMain },
			{ NULL, NULL }
		};

		StartServiceCtrlDispatcher(ste);

		return 1;
	}
}

void OutputServerMessage(char * msg, ...)
{
	if(msg != NULL)
	{
		char * debugstring = NULL;
		int debugstringlen = 0;

		for(int i=0; i!=2; i++)
		{
			if(i==1)
			{
				debugstring = (char *)_alloca(debugstringlen + 3);
				*debugstring = '\0';
			}
			char * ptr = msg;
			va_list marker = NULL;
			va_start(marker, msg);
			while(ptr != NULL)
			{
				if(i==0)
				{
					char * p = strchr(ptr, '\r');
					if(p != NULL) *p = '\0';
					p = strchr(ptr, '\n');
					if(p != NULL) *p = '\0';
					debugstringlen += strlen(ptr);
				}
				else
				{
					strcat(debugstring, ptr);
				}
				ptr = va_arg(marker, char *);
			}
			va_end(marker);
		}

		strcat(debugstring, "\r\n");

		EnterCriticalSection(&g_clientmsgdata.csWindowMessages);

		OutputDebugString(debugstring);

		LeaveCriticalSection(&g_clientmsgdata.csWindowMessages);
	}
}

void WINAPI ServiceHandler(DWORD fdwControl)
{
	SERVICE_STATUS status = {0};

	status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	status.dwControlsAccepted = SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN;
	status.dwWin32ExitCode = NO_ERROR;

	if(fdwControl == SERVICE_CONTROL_STOP || fdwControl == SERVICE_CONTROL_SHUTDOWN)
	{
		OutputServerMessage("Stopping ", g_serverparams.szDisplayName, NULL);

		status.dwCurrentState = SERVICE_STOP_PENDING;
		status.dwWaitHint = 10000;
		SetServiceStatus(g_handle.hServiceHandle, &status);

		SetEvent(g_handle.hStopServiceEvent);
		closesocket(g_handle.hSocketListener);

		if(WaitForSingleObject(g_handle.hServiceMainStoppedEvent, 10000) == WAIT_TIMEOUT)
		{
			// hopefully never require this - stack page allocation is not freed,
			// DLL_THREAD_DETACH is not called for dlls, owned critical sections
			// are not released. Since exiting program this is not so important.
			TerminateThread(g_handle.hServiceMainThread, 0);
			ThreadReleaseCriticalSection(g_serverparams.lpServiceMainThreadId);
		}

		CloseHandle(g_handle.hServiceMainThread);
		CloseHandle(g_handle.hStopServiceEvent);

		OutputServerMessage(g_serverparams.szDisplayName, " stopped successfully", NULL);
	}
	else
	{
		status.dwCurrentState = SERVICE_RUNNING;
		SetServiceStatus(g_handle.hServiceHandle, &status);
	}
}

bool AddChallengeList(const unsigned char challenge[RANDOM_CHALLENGE_SIZE])
{
	EnterCriticalSection(&g_chdata.csChallengeList);
	bool res = true;

	BYTE * ptr = g_chdata.abChallengeList, * endptr = ptr + sizeof(g_chdata.abChallengeList)/sizeof(g_chdata.abChallengeList[0]), * lastptr = ptr;
	while(ptr != endptr && *ptr != 0)
	{
		if(memcmp(ptr + 1, challenge, RANDOM_CHALLENGE_SIZE) == 0)
		{
			res = false; // already exists
			break;
		}
		if(*ptr == 2)
		{
			lastptr = ptr; // the last added value
		}
		ptr += (1 + RANDOM_CHALLENGE_SIZE);
	}

	if(res)
	{
		*lastptr = 1; // not the last added value
		if(ptr == endptr)
		{
			lastptr += (1 + RANDOM_CHALLENGE_SIZE); // advance to next in list
			if(lastptr == endptr)
			{
				lastptr = g_chdata.abChallengeList;
			}
			*lastptr = 2; // the new last added value
			memcpy(lastptr + 1, challenge, RANDOM_CHALLENGE_SIZE);
		}
		else
		{
			*ptr = 2; // the new last added value
			memcpy(ptr + 1, challenge, RANDOM_CHALLENGE_SIZE);
		}
	}

	LeaveCriticalSection(&g_chdata.csChallengeList);
	return res;
}

bool GetBlacklist(u_long address)
{
	bool res = false;
	if(g_serverparams.bBlacklistIPBlock)
	{
		EnterCriticalSection(&g_iplistdata.csBlacklistIP);

		const BYTE maxcounter = 20; // 1 to 255

		ULONG * ptr = g_iplistdata.alBlacklistIPAddress, * endptr = ptr + min(sizeof(g_iplistdata.alBlacklistIPAddress)/sizeof(g_iplistdata.alBlacklistIPAddress[0]),sizeof(g_iplistdata.abBlacklistIPCounter)/sizeof(g_iplistdata.abBlacklistIPCounter[0]));
		while(ptr != endptr && *ptr != 0)
		{
			if(*ptr == address)
			{
				if(*(g_iplistdata.abBlacklistIPCounter + (ptr - g_iplistdata.alBlacklistIPAddress)) >= maxcounter)
				{
					res = true;
				}
				break;
			}
			ptr++;
		}

		LeaveCriticalSection(&g_iplistdata.csBlacklistIP);
	}
	return res;
}

void UpdateBlacklist(u_long address, bool add)
{
	if(g_serverparams.bBlacklistIPBlock)
	{
		EnterCriticalSection(&g_iplistdata.csBlacklistIP);

		ULONG * ptr = g_iplistdata.alBlacklistIPAddress, * endptr = ptr + min(sizeof(g_iplistdata.alBlacklistIPAddress)/sizeof(g_iplistdata.alBlacklistIPAddress[0]),sizeof(g_iplistdata.abBlacklistIPCounter)/sizeof(g_iplistdata.abBlacklistIPCounter[0])), * ipptr = NULL;
		while(ptr != endptr && *ptr != 0)
		{
			if(*ptr == address)
			{
				ipptr = ptr;
				if(add)
				{
					break;
				}
			}
			ptr++;
		}

		if(add)
		{
			if(!ipptr)
			{
				if(ptr == endptr)
				{
					ptr = g_iplistdata.alBlacklistIPAddress; // wrapround to start of list, overwrites first entry
				}
				*ptr = address;
				BYTE & counter = *(g_iplistdata.abBlacklistIPCounter + (ptr - g_iplistdata.alBlacklistIPAddress));
				counter = 1;
			}
			else
			{
				BYTE & counter = *(g_iplistdata.abBlacklistIPCounter + (ipptr - g_iplistdata.alBlacklistIPAddress));
				counter += 1;
			}
		}
		else
		{
			if(ipptr)
			{
				if(ipptr == ptr - 1)
				{
					*ipptr = 0; // erase last entry
				}
				else
				{
					*ipptr = *(ptr - 1); // copy last entry over current entry
					*(ptr - 1) = 0; // erase last entry
					BYTE & counter1 = *(g_iplistdata.abBlacklistIPCounter + (ipptr - g_iplistdata.alBlacklistIPAddress));
					BYTE & counter2 = *(g_iplistdata.abBlacklistIPCounter + (ptr - 1 - g_iplistdata.alBlacklistIPAddress));
					counter1 = counter2;
				}
			}
		}

		LeaveCriticalSection(&g_iplistdata.csBlacklistIP);
	}
}

void ClearBlacklist()
{
	if(g_serverparams.bBlacklistIPBlock)
	{
		EnterCriticalSection(&g_iplistdata.csBlacklistIP);

		memset(g_iplistdata.alBlacklistIPAddress, 0, sizeof(g_iplistdata.alBlacklistIPAddress));

		LeaveCriticalSection(&g_iplistdata.csBlacklistIP);
	}
}

// prevents lockup of threads when thread is suddenly terminated
void ThreadReleaseCriticalSection(DWORD threadID)
{
	if(threadID != 0)
	{
		CRITICAL_SECTION cs={0};

		InitializeCriticalSection(&cs);
		EnterCriticalSection(&cs);

		try
		{
			CRITICAL_SECTION_DEBUG * csd=cs.DebugInfo;
			if(csd)
			{
				PRTL_CRITICAL_SECTION_DEBUG list=(PRTL_CRITICAL_SECTION_DEBUG)((DWORD)csd->ProcessLocksList.Blink - (offsetof(_RTL_CRITICAL_SECTION_DEBUG, ProcessLocksList)));
				while(list && list->ProcessLocksList.Flink != csd->ProcessLocksList.Blink)
				{
					CRITICAL_SECTION * cs=list->CriticalSection;
					if(cs)
					{
						while(threadID==(DWORD)cs->OwningThread)
						{
							LeaveCriticalSection(cs);
						}
					}
					list=(PRTL_CRITICAL_SECTION_DEBUG)((DWORD)list->ProcessLocksList.Flink - (offsetof(_RTL_CRITICAL_SECTION_DEBUG, ProcessLocksList)));
				}
			}
		}
		catch(...)
		{}

		LeaveCriticalSection(&cs);
		DeleteCriticalSection(&cs);
	}
}

BOOL GetNameByPID(DWORD pid, char * name, int length)
{
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	BOOL bRet = FALSE;
	PROCESSENTRY32 pe32 = {sizeof(PROCESSENTRY32), 0};
	DWORD th32ProcessID = Process32First(hProcessSnap, &pe32);
	while(th32ProcessID)
	{
		if(pe32.th32ProcessID == pid)
		{
			if(pe32.szExeFile[0] != 0)
			{
				bRet = TRUE;
				if(length > 0)
				{
					strncpy(name, pe32.szExeFile, length - 1);
				}
			}
			break;
		}

		pe32.dwSize = sizeof(PROCESSENTRY32);
		th32ProcessID = Process32Next(hProcessSnap, &pe32);
	}

	CloseHandle(hProcessSnap);
	return bRet;
}

BOOL GetAddrProcessName(const struct sockaddr_in & addr, char * name, int length, int & pid)
{
	if(_GetExtendedTcpTable)
	{
		DWORD size = 0;
		_GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
		if(size == 0 || size > 0x200000)
		{
			return FALSE;
		}

		size += 50 * sizeof(MIB_TCPROW_OWNER_PID);
		MIB_TCPTABLE_OWNER_PID* pTCPInfo = (MIB_TCPTABLE_OWNER_PID*)LocalAlloc(LPTR, size);
		if(pTCPInfo == NULL)
		{
			return FALSE;
		}

		if(_GetExtendedTcpTable(pTCPInfo, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_SUCCESS)
		{
			LocalFree(pTCPInfo);
			return FALSE;
		}

		for(DWORD i = 0; i < pTCPInfo->dwNumEntries; i++)
		{
			MIB_TCPROW_OWNER_PID *owner = &pTCPInfo->table[i];
			if(owner->dwState == MIB_TCP_STATE_ESTAB && addr.sin_port == owner->dwLocalPort && addr.sin_addr.S_un.S_addr == owner->dwLocalAddr)
			{
				pid = owner->dwOwningPid;
				LocalFree(pTCPInfo);
				return GetNameByPID(pid, name, length);
			}
		}

		LocalFree(pTCPInfo);
	}
	return FALSE;
}

// function used to check for removal of old process information that is no longer valid or has a socket connected to this program

BOOL IsProcessConnected(const char * name, int pid)
{
	if(_GetExtendedTcpTable)
	{
		if(name == NULL)
		{
			return FALSE;
		}
		char* buf = (char*)LocalAlloc(LPTR, 256);
		if(buf == NULL)
		{
			return FALSE;
		}
		if(!GetNameByPID(pid, buf, 256) || stricmp(buf, name) != 0)
		{
			LocalFree(buf);
			return FALSE;
		}
		LocalFree(buf);
		buf = NULL;

		DWORD size = 0;
		_GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
		if(size == 0 || size > 0x200000)
		{
			return FALSE;
		}

		size += 50 * sizeof(MIB_TCPROW_OWNER_PID);
		MIB_TCPTABLE_OWNER_PID* pTCPInfo = (MIB_TCPTABLE_OWNER_PID*)LocalAlloc(LPTR, size);
		if(pTCPInfo == NULL)
		{
			return FALSE;
		}

		if(_GetExtendedTcpTable(pTCPInfo, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_SUCCESS)
		{
			LocalFree(pTCPInfo);
			return FALSE;
		}

		struct AddrList
		{
			DWORD addr;
			DWORD port;
			AddrList * next;
			void Add(DWORD _addr, DWORD _port)
			{
				if(next)
				{
					next->Add(_addr, _port);
				}
				else
				{
					addr = _addr;
					port = _port;
					next = new AddrList();
				}
			}
			bool Find(DWORD _addr, DWORD _port)
			{
				if(_addr == addr && _port == port)
				{
					return true;
				}
				if(next)
				{
					return next->Find(_addr, _port);
				}
				return false;
			}
			AddrList() : addr(0), port(0), next(0)
			{}
			~AddrList()
			{
				delete next;
			}
		};

		AddrList addrList;

		DWORD localid = GetCurrentProcessId();

		for(DWORD i = 0; i < pTCPInfo->dwNumEntries; i++)
		{
			MIB_TCPROW_OWNER_PID *owner = &pTCPInfo->table[i];
			if(owner->dwState == MIB_TCP_STATE_ESTAB && owner->dwOwningPid == localid)
			{
				addrList.Add(owner->dwLocalAddr, owner->dwLocalPort);
			}
		}

		for(DWORD j = 0; j < pTCPInfo->dwNumEntries; j++)
		{
			MIB_TCPROW_OWNER_PID *owner = &pTCPInfo->table[j];
			if(owner->dwState == MIB_TCP_STATE_ESTAB && owner->dwOwningPid == pid && addrList.Find(owner->dwRemoteAddr, owner->dwRemotePort))
			{
				LocalFree(pTCPInfo);
				return TRUE;
			}
		}

		LocalFree(pTCPInfo);
		return FALSE;
	}
	return FALSE; // defaults to false as GetExtendedTcpTable, which is the only way to do so, was never used to get connected pid in first place
}

// function used to check for removal of address information that no longer has a socket connection to this program

BOOL IsAddressConnected(ULONG addr)
{
	if(_GetExtendedTcpTable)
	{
		DWORD size = 0;
		_GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
		if(size == 0 || size > 0x200000)
		{
			return FALSE;
		}

		MIB_TCPTABLE_OWNER_PID* pTCPInfo = (MIB_TCPTABLE_OWNER_PID*)LocalAlloc(LPTR, size);
		if(pTCPInfo == NULL)
		{
			return FALSE;
		}

		if(_GetExtendedTcpTable(pTCPInfo, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_SUCCESS)
		{
			LocalFree(pTCPInfo);
			return FALSE;
		}

		DWORD pid = GetCurrentProcessId();

		for(DWORD i = 0; i < pTCPInfo->dwNumEntries; i++)
		{
			MIB_TCPROW_OWNER_PID *owner = &pTCPInfo->table[i];
			if(owner->dwState == MIB_TCP_STATE_ESTAB && owner->dwOwningPid == pid && owner->dwRemoteAddr == addr)
			{
				LocalFree(pTCPInfo);
				return TRUE;
			}
		}

		LocalFree(pTCPInfo);
		return FALSE;
	}
	return TRUE; // defaults to true, since a connected socket was previously determined but not using the GetExtendedTcpTable function
}

void GenerateRandomData(int count, unsigned char * bytes)
{
	CryptGenRandom(g_handle.hGenerateRandom, count, bytes);
	DWORD r[2] = {rand(), GetTickCount()};
	unsigned char digest[SHA_SIZE_256] = {0};
	sha256Digest((unsigned char *)r, sizeof(r), digest);
	for(int i = 0; i!= count; ++i)
	{
		bytes[i] ^= digest[i % sizeof(digest)];
	}
}

bool DecodeServerConfigData(const char *data, char *name, int namelength, ServerKeyChain & keys, ULONG & localip, USHORT & localport, ULONG & destip, ULONG & timeout, BOOL & useblacklist)
{
	// servicename:localip:localport:destip:timeout:useblacklist:key1:key2...:keyN:sha256digest

	memset(name, 0, namelength);
	keys.Clear();

	int datalength = (data ? strlen(data) : 0)/2;
	if(datalength > 0)
	{
		unsigned char * encdata = (unsigned char *)_alloca(datalength + 1);
		HexToBytes(data, 2 * datalength, encdata);

		if(_CryptUnprotectData)
		{
			DATA_BLOB dbKey = {0};
			DATA_BLOB dbEncKey = {datalength, encdata};
			LPWSTR pDescrOut = NULL;
			if(_CryptUnprotectData(&dbEncKey, &pDescrOut, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &dbKey) && dbKey.cbData>0)
			{
				datalength = min(datalength, dbKey.cbData);
				memcpy(encdata, dbKey.pbData, datalength);
			}
			else
			{
				return false;
			}
		}

		encdata[datalength] = '\0';

		unsigned char digest[SHA_SIZE_256] = {0};

		char * p = strrchr((char *)encdata, ':');;
		if(!p || (p - (char *)encdata) + 1 + (2 * sizeof(digest)) != datalength)
		{
			return false;
		}

		sha256Digest((unsigned char *)encdata, datalength - (1 + (2 * sizeof(digest))), digest);

		unsigned char datadigest[sizeof(digest)] = {0};
		HexToBytes((char *)&encdata[datalength - (2 * sizeof(digest))], 2 * sizeof(digest), datadigest);

		if(memcmp(datadigest, digest, sizeof(datadigest)) == 0)
		{
			p = (char *)encdata;
			int count = 0, keycount = 0;
			while(p)
			{
				char * q = count > 0 ? p + 1 : p;
				p = strchr(q, ':');
				if(p)
				{
					while(p > q && isspace(*q))
					{
						q += 1;
					}
					int len = p - q;
					switch(count)
					{
					case 0:
						{
							if(namelength > 1)
							{
								strncpy(name, q, min(len, namelength - 1));
							}
						}
						break;
					case 1:
						{
							BYTE bytes[4] = {0};
							HexToBytes(q, 2 * sizeof(bytes), bytes);
							localip = BytesToLong(bytes);
						}
						break;
					case 2:
						{
							BYTE bytes[2] = {0};
							HexToBytes(q, 2 * sizeof(bytes), bytes);
							localport = BytesToUShort(bytes);
						}
						break;
					case 3:
						{
							BYTE bytes[4] = {0};
							HexToBytes(q, 2 * sizeof(bytes), bytes);
							destip = BytesToLong(bytes);
						}
						break;
					case 4:
						{
							BYTE bytes[4] = {0};
							HexToBytes(q, 2 * sizeof(bytes), bytes);
							timeout = BytesToLong(bytes);
						}
						break;
					case 5:
						{
							BYTE bytes[1] = {0};
							HexToBytes(q, 2 * sizeof(bytes), bytes);
							useblacklist = bytes[0];
						}
						break;
					default:
						{
							BYTE key[sizeof(keys.key)] = {0};
							HexToBytes(q, min(2 * sizeof(key), len), key);
							keys.SetKey(key, keycount++);
						}
						break;
					}
				}

				++count;
			}
			return true;
		}
	}

	return false;
}

int EncodeServerConfigData(char *name, ServerKeyChain & keys, ULONG localip, USHORT localport, ULONG destip, ULONG timeout, BOOL useblacklist, CharHeapBuffer & data)
{
	// servicename:localip:localport:destip:timeout:useblacklist:key1:key2...:keyN:sha256digest

	unsigned char digest[SHA_SIZE_256] = {0};
	const int hexlength = (name ? strlen(name) : 0) + 1 + 2 * 4 + 1 + 2 * 2 + 1 + 2 * 4 + 1 + 2 * 4 + 1 + 2 * 1 + 1 + (2 * sizeof(keys.key) + 1) * keys.Count() + 2 * sizeof(digest);
	char * hex = (char *)_alloca(hexlength + 1);

	char * p = hex;

	if(name)
	{
		strcpy(p, name);
	}
	else
	{
		*p = '\0';
	}
	p += strlen(p);

	*p = ':';
	p += 1;

	BYTE bytesLong[4] = {0};

	LongToBytes(localip, bytesLong);
	BytesToHex(bytesLong, sizeof(bytesLong), p);
	p += 2 * sizeof(bytesLong);

	*p = ':';
	p += 1;

	BYTE bytesShort[2] = {0};

	UShortToBytes(localport, bytesShort);
	BytesToHex(bytesShort, sizeof(bytesShort), p);
	p += 2 * sizeof(bytesShort);

	*p = ':';
	p += 1;

	LongToBytes(destip, bytesLong);
	BytesToHex(bytesLong, sizeof(bytesLong), p);
	p += 2 * sizeof(bytesLong);

	*p = ':';
	p += 1;

	LongToBytes(timeout, bytesLong);
	BytesToHex(bytesLong, sizeof(bytesLong), p);
	p += 2 * sizeof(bytesLong);

	*p = ':';
	p += 1;

	bytesShort[0] = useblacklist ? 1 : 0;
	BytesToHex(bytesShort, 1, p);
	p += 2 * 1;

	for(int i=0,n=keys.Count();i<n;++i)
	{
		ServerKeyChain * k = keys.Find(i);
		if(k != NULL)
		{
			*p = ':';
			p += 1;

			BytesToHex(k->key, sizeof(k->key), p);
			p += 2 * sizeof(k->key);
		}
	}

	sha256Digest((unsigned char *)hex, p-hex, digest);

	*p = ':';
	p += 1;

	BytesToHex(digest, sizeof(digest), p);
	p += 2 * sizeof(digest);

	if(p - hex != hexlength)
	{
		return 0;
	}

	if(_CryptProtectData)
	{
		DATA_BLOB dbEncKey = {0};
		DATA_BLOB dbKey = {hexlength, (BYTE *)hex};
		if(_CryptProtectData(&dbKey, L"", NULL, NULL, NULL, CRYPTPROTECT_LOCAL_MACHINE|CRYPTPROTECT_UI_FORBIDDEN, &dbEncKey))
		{
			if(!data.Allocate(2 * dbEncKey.cbData + 1))
			{
				return 0;
			}

			BytesToHexLower(dbEncKey.pbData, dbEncKey.cbData, data);
			data[data.Size() - 1] = '\0';
			return data.Size() - 1;
		}
	}
	else
	{
		if(!data.Allocate(2 * hexlength + 1))
		{
			return 0;
		}

		BytesToHexLower((BYTE *)hex, hexlength, data);
		data[data.Size() - 1] = '\0';
		return data.Size() - 1;
	}

	return 0;
}

bool DecryptClientConfigData(const char *data, const char *pwd, unsigned char * key, int keylength, ULONG & remoteip, USHORT & remoteport, USHORT & tunnelport, ULONG & localip, USHORT & localport, ULONG & timeout, BOOL & reconnect, BOOL & pwdprompt)
{
	// key:remoteip:remoteport:tunnelport:localip:localport:timeout:reconnect:pwdprompt:sha256digest

	int datalength = (data ? strlen(data) : 0)/2;
	if(datalength > 0)
	{
		unsigned char * encdata = (unsigned char *)_alloca(datalength + 1);
		HexToBytes(data, 2 * datalength, encdata);

		unsigned char iv[AES_BLOCK_SIZE] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10};

		// KDF: compute key as: [repeated XOR sha256(pwd)] x 1000

		unsigned char tmp[SHA_SIZE_256] = {0}, pwdkey[SHA_SIZE_256] = {0};
		sha256Digest((const unsigned char *)pwd, pwd ? strlen(pwd) : 0, pwdkey);
		for(int i=0;i!=1000;++i)
		{
			memcpy(tmp, pwdkey, sizeof(tmp));
			sha256Digest(tmp, sizeof(tmp), pwdkey);
			for(int j=0;j!=sizeof(pwdkey);++j)
			{
				pwdkey[j] ^= tmp[j];
			}
		}

		if(!AESCBCDecrypt(pwdkey, sizeof(pwdkey), iv, sizeof(iv), encdata, encdata, datalength))
		{
			return false;
		}

		encdata[datalength] = '\0';

		unsigned char digest[SHA_SIZE_256] = {0};

		char * p = strrchr((char *)encdata, ':');;
		if(!p || (p - (char *)encdata) + 1 + (2 * sizeof(digest)) != datalength)
		{
			return false;
		}

		sha256Digest((unsigned char *)encdata, datalength - (1 + (2 * sizeof(digest))), digest);

		unsigned char datadigest[sizeof(digest)] = {0};
		HexToBytes((char *)&encdata[datalength - (2 * sizeof(digest))], 2 * sizeof(digest), datadigest);

		if(memcmp(datadigest, digest, sizeof(datadigest)) == 0)
		{
			p = (char *)encdata;
			int count = 0;
			while(p)
			{
				char * q = count > 0 ? p + 1 : p;
				p = strchr(q, ':');
				if(p)
				{
					while(p > q && isspace(*q))
					{
						q += 1;
					}
					int len = p - q;
					switch(count)
					{
					case 0:
						{
							HexToBytes(q, min(2 * keylength, len), key);
						}
						break;
					case 1:
						{
							BYTE bytes[4] = {0};
							HexToBytes(q, 2 * sizeof(bytes), bytes);
							remoteip = BytesToLong(bytes);
						}
						break;
					case 2:
						{
							BYTE bytes[2] = {0};
							HexToBytes(q, 2 * sizeof(bytes), bytes);
							remoteport = BytesToUShort(bytes);
						}
						break;
					case 3:
						{
							BYTE bytes[2] = {0};
							HexToBytes(q, 2 * sizeof(bytes), bytes);
							tunnelport = BytesToUShort(bytes);
						}
						break;
					case 4:
						{
							BYTE bytes[4] = {0};
							HexToBytes(q, 2 * sizeof(bytes), bytes);
							localip = BytesToLong(bytes);
						}
						break;
					case 5:
						{
							BYTE bytes[2] = {0};
							HexToBytes(q, 2 * sizeof(bytes), bytes);
							localport = BytesToUShort(bytes);
						}
						break;
					case 6:
						{
							BYTE bytes[4] = {0};
							HexToBytes(q, 2 * sizeof(bytes), bytes);
							timeout = BytesToLong(bytes);
						}
						break;
					case 7:
						{
							BYTE bytes[1] = {0};
							HexToBytes(q, 2 * sizeof(bytes), bytes);
							reconnect = bytes[0];
						}
						break;
					case 8:
						{
							BYTE bytes[1] = {0};
							HexToBytes(q, 2 * sizeof(bytes), bytes);
							pwdprompt = bytes[0];
						}
						break;
					}
				}

				++count;
			}
			return true;
		}
	}

	return false;
}

int EncryptClientConfigData(unsigned char * key, int keylength, ULONG remoteip, USHORT remoteport, USHORT tunnelport, ULONG localip, USHORT localport, ULONG timeout, BOOL reconnect, BOOL pwdprompt, const char *pwd, CharHeapBuffer & data)
{
	// key:remoteip:remoteport:tunnelport:localip:localport:timeout:reconnect:pwdprompt:sha256digest

	unsigned char digest[SHA_SIZE_256] = {0};
	const int hexlength = 2 * keylength + 1 + 2 * 4 + 1 + 2 * 2 + 1 + 2 * 2 + 1 + 2 * 4 + 1 + 2 * 2 + 1 + 2 * 4 + 1 + 2 * 1 + 1 + 2 * 1 + 1 + 2 * sizeof(digest);
	char * hex = (char *)_alloca(hexlength + 1);

	char * p = hex;

	BytesToHex(key, keylength, p);
	p += 2 * keylength;

	*p = ':';
	p += 1;

	BYTE bytesLong[4] = {0};

	LongToBytes(remoteip, bytesLong);
	BytesToHex(bytesLong, sizeof(bytesLong), p);
	p += 2 * sizeof(bytesLong);

	*p = ':';
	p += 1;

	BYTE bytesShort[2] = {0};

	UShortToBytes(remoteport, bytesShort);
	BytesToHex(bytesShort, sizeof(bytesShort), p);
	p += 2 * sizeof(bytesShort);

	*p = ':';
	p += 1;

	UShortToBytes(tunnelport, bytesShort);
	BytesToHex(bytesShort, sizeof(bytesShort), p);
	p += 2 * sizeof(bytesShort);

	*p = ':';
	p += 1;

	LongToBytes(localip, bytesLong);
	BytesToHex(bytesLong, sizeof(bytesLong), p);
	p += 2 * sizeof(bytesLong);

	*p = ':';
	p += 1;

	UShortToBytes(localport, bytesShort);
	BytesToHex(bytesShort, sizeof(bytesShort), p);
	p += 2 * sizeof(bytesShort);

	*p = ':';
	p += 1;

	LongToBytes(timeout, bytesLong);
	BytesToHex(bytesLong, sizeof(bytesLong), p);
	p += 2 * sizeof(bytesLong);

	*p = ':';
	p += 1;

	bytesShort[0] = reconnect ? 1 : 0;
	BytesToHex(bytesShort, 1, p);
	p += 2 * 1;

	*p = ':';
	p += 1;

	bytesShort[0] = pwdprompt ? 1 : 0;
	BytesToHex(bytesShort, 1, p);
	p += 2 * 1;

	sha256Digest((unsigned char *)hex, p-hex, digest);

	*p = ':';
	p += 1;

	BytesToHex(digest, sizeof(digest), p);
	p += 2 * sizeof(digest);

	if(p - hex != hexlength)
	{
		return 0;
	}

	unsigned char iv[AES_BLOCK_SIZE] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10};

	// KDF: compute key as: [repeated XOR sha256(pwd)] x 1000

	unsigned char tmp[SHA_SIZE_256] = {0}, pwdkey[SHA_SIZE_256] = {0};
	sha256Digest((const unsigned char *)pwd, pwd ? strlen(pwd) : 0, pwdkey);
	for(int i=0;i!=1000;++i)
	{
		memcpy(tmp, pwdkey, sizeof(tmp));
		sha256Digest(tmp, sizeof(tmp), pwdkey);
		for(int j=0;j!=sizeof(pwdkey);++j)
		{
			pwdkey[j] ^= tmp[j];
		}
	}

	if(!AESCBCEncrypt(pwdkey, sizeof(pwdkey), iv, sizeof(iv), (unsigned char *)hex, (unsigned char *)hex, hexlength))
	{
		return 0;
	}

	if(!data.Allocate(2 * hexlength + 1))
	{
		return 0;
	}

	BytesToHexLower((BYTE *)hex, hexlength, data);

	data[data.Size() - 1] = '\0';
	return data.Size() - 1;
}

BOOL GetConfigData(bool server, CharHeapBuffer & data, char * filepath, int filepathlength)
{
	if(filepath && filepathlength > 0)
	{
		*filepath = '\0';
	}

	char path[_MAX_PATH + 128] = {0};
	BOOL res = GetConfigFilename(server, path, sizeof(path));

	if(filepath && filepathlength > strlen(path))
	{
		strcpy(filepath, path);
	}

	if(res)
	{
		res = false;
		struct _stat st = {0};
		_stat(path, &st);
		if(st.st_size > 0 && data.Allocate(st.st_size + 1))
		{
			FILE *fd = fopen(path, "rb");
			if(fd != NULL)
			{
				int len = fread((BYTE *)data, 1, st.st_size, fd);
				fclose(fd);
				if(len > 0)
				{
					data[len] = '\0';
					res = true;
				}
			}
		}
	}

	return res;
}

BOOL GetConfigFilename(bool server, char * name, int length)
{
	if(!name || length <= _MAX_PATH)
	{
		return false;
	}

	if(GetModuleFileName(NULL, name, _MAX_PATH) == 0)
	{
		*name = '\0';
		return false;
	}

	char * endpath = strrchr(name,'\\');
	if(endpath == NULL)
	{
		*name = '\0';
		return false;
	}

	strcpy(endpath + 1, server ? "server.txt" : "client.txt");
	WIN32_FIND_DATA finddata = {0};
	HANDLE hFindFile = FindFirstFile(name, &finddata);

	if (hFindFile == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	strcpy(endpath + 1, finddata.cFileName);

	FindClose(hFindFile);
	return true;
}

inline ULONG BytesToLong(BYTE * bytes)
{
	return (bytes[0]<<24) + (bytes[1]<<16) + (bytes[2]<<8) + bytes[3];
}

inline void LongToBytes(ULONG l, BYTE * bytes)
{
	*bytes++ = (BYTE)(l>>24);
	*bytes++ = (BYTE)(l>>16);
	*bytes++ = (BYTE)(l>>8);
	*bytes++ = (BYTE)l;
}

inline USHORT BytesToUShort(BYTE * bytes)
{
	return (bytes[0]<<8) + bytes[1];
}

inline void UShortToBytes(USHORT s, BYTE * bytes)
{
	*bytes++ = (BYTE)(s>>8);
	*bytes++ = (BYTE)s;
}

void DataChecksum(char * data, int length, unsigned char * checksum, int checksumlength)
{
#ifdef USE_WEAK_CHECKSUM /* save CPU cycles */
	for (int k = 0; k < checksumlength; k++)
	{
		checksum[k] = k % 2 == 0 ? 0xc3 : 0x3c;
	}
	for (int i = 0; i < length; i++)
	{
		checksum[0] += (unsigned char)data[i];
		for (int j = 1; j < checksumlength; j++)
		{
			checksum[j] += checksum[j - 1];
		}
	}
#else
	unsigned char digest[SHA_SIZE_256] = {0};
	sha256Digest((BYTE *)data, length, digest);
	memcpy(checksum, digest, min(checksumlength, sizeof(digest)));
#endif
}

// maximum checksum length is 32 bytes

void HeaderChecksum(char * data, int length, unsigned char * checksum, int checksumlength)
{
	unsigned char digest[SHA_SIZE_256] = {0};
	sha256Digest((BYTE *)data, length, digest);
	memcpy(checksum, digest, min(checksumlength, sizeof(digest)));
}

int EncodeHeader(char * buf, int dataoffset, ULONG datalength, ULONG errcode, u_short port)
{
	// header: header_checksum (8 bytes) + data_checksum (8 bytes) + version_number (1 byte) + random_padding (5 bytes) + port (2 bytes) + error_code (4 bytes) + data_length (4 bytes)
	//
	// header_checksum: checksum(data_checksum + version_number + random_padding + port + error_code + data_length)
	// data_checksum: checksum(data)

	const char version_number = 0x01;

	if(dataoffset == PACKET_HEADER_SIZE)
	{
		buf[8+8] = version_number;
		GenerateRandomData(5, (BYTE *)&buf[8+8+1]);
		UShortToBytes(port, (BYTE *)&buf[8+8+1+5]);
		LongToBytes(errcode, (BYTE *)&buf[8+8+1+5+2]);
		LongToBytes(datalength, (BYTE *)&buf[8+8+1+5+2+4]);
		DataChecksum(&buf[PACKET_HEADER_SIZE], datalength, (BYTE *)&buf[8], 8);
		HeaderChecksum(&buf[8], PACKET_HEADER_SIZE - 8, (BYTE *)buf, 8);

		return PACKET_HEADER_SIZE + datalength;
	}

	return 0;
}

bool DecodeHeader(char * buf, int length, unsigned char * data_checksum, ULONG & data_checksum_length, ULONG & data_length, ULONG & errcode, u_short & port)
{
	const char version_number = 0x01;

	if(length >= PACKET_HEADER_SIZE && buf[8+8] == version_number)
	{
		unsigned char checksum[8] = {0};
		HeaderChecksum(&buf[8], PACKET_HEADER_SIZE-8, checksum, sizeof(checksum));
		if(memcmp(checksum, buf, sizeof(checksum)) == 0)
		{
			data_checksum_length = min(data_checksum_length, 8);
			memcpy(data_checksum, &buf[8], data_checksum_length);
			port = BytesToUShort((BYTE *)&buf[8+8+1+5]);
			errcode = BytesToLong((BYTE *)&buf[8+8+1+5+2]);
			data_length = BytesToLong((BYTE *)&buf[8+8+1+5+2+4]);
			return data_length <= MAX_PACKET_SIZE - PACKET_HEADER_SIZE;
		}
	}

	return false;
}

int ReadSocketData(SOCKET sockfd, char * buf, int length, ServerKeyChain & keys, unsigned char iv[AES_BLOCK_SIZE], ULONG & keyindex, ULONG & errcode, u_short & port)
{
	keyindex = -1; // initialize selected key to invalid value

	int n = recv(sockfd, buf, min(PACKET_HEADER_SIZE, length), 0);

	errcode = h_errno;

	if(n == PACKET_HEADER_SIZE)
	{
#ifdef _DEBUG
		if(PACKET_HEADER_SIZE % AES_BLOCK_SIZE != 0) { return 0; } // partial decryption/encryption must be on a block (IV) boundary
#endif
		char header[PACKET_HEADER_SIZE] = {0};

		// loop through keys until correct header checksum is obtained

		for(int i=0,n=keys.Count();i<n;++i)
		{
			ServerKeyChain * k = keys.Find(i);
			if(k != NULL)
			{
				unsigned char enciv[AES_BLOCK_SIZE];
				memcpy(enciv, iv, sizeof(enciv));

				if(AESCBCDecrypt(k->key, sizeof(k->key), enciv, sizeof(enciv), (unsigned char *)buf, (unsigned char *)header, PACKET_HEADER_SIZE))
				{
					unsigned char data_checksum[8] = {0};
					ULONG data_length = 0, data_checksum_length = sizeof(data_checksum);
					if(DecodeHeader(header, sizeof(header), data_checksum, data_checksum_length, data_length, errcode, port))
					{
						// found correct key

						keyindex = i;
						memcpy(iv, enciv, AES_BLOCK_SIZE);

						n = 0;
						if(data_length <= length) // continue until data of the verified length is obtained
						{
							while(n < data_length)
							{
								int nbuf = recv(sockfd, &buf[n], data_length-n, 0);
								if(nbuf <= 0)
								{
									break;
								}
								n += nbuf;
							}
						}

						if (n == data_length && AESCBCDecrypt(k->key, sizeof(k->key), iv, AES_BLOCK_SIZE, (unsigned char *)buf, (unsigned char *)buf, n))
						{
							unsigned char checksum[8] = {0};
							DataChecksum(buf, n, checksum, sizeof(checksum));
							if(memcmp(checksum, data_checksum, min(sizeof(checksum), data_checksum_length)) == 0)
							{
								return n;
							}
							else
							{
								return -1;
							}
						}

						// unable to receive all data

						return 0;
					}
				}
			}
		}

		return -1;
	}

	return 0;
}

int ReadSocketData(SOCKET sockfd, char * buf, int length, const unsigned char * key, int keylength, unsigned char iv[AES_BLOCK_SIZE], ULONG & errcode, u_short & port)
{
	int n = recv(sockfd, buf, min(PACKET_HEADER_SIZE, length), 0);

	errcode = h_errno;

	if(n == PACKET_HEADER_SIZE)
	{
#ifdef _DEBUG
		if(PACKET_HEADER_SIZE % AES_BLOCK_SIZE != 0) { return 0; } // partial decryption/encryption must be on a block (IV) boundary
#endif
		char header[PACKET_HEADER_SIZE] = {0};

		if(AESCBCDecrypt(key, keylength, iv, AES_BLOCK_SIZE, (unsigned char *)buf, (unsigned char *)header, PACKET_HEADER_SIZE))
		{
			unsigned char data_checksum[8] = {0};
			ULONG data_length = 0, data_checksum_length = sizeof(data_checksum);
			if(DecodeHeader(header, sizeof(header), data_checksum, data_checksum_length, data_length, errcode, port))
			{
				n = 0;
				if(data_length <= length) // continue until data of the verified length is obtained
				{
					while(n < data_length)
					{
						int nbuf = recv(sockfd, &buf[n], data_length-n, 0);
						if(nbuf <= 0)
						{
							break;
						}
						n += nbuf;
					}
				}
				if (n == data_length && AESCBCDecrypt(key, keylength, iv, AES_BLOCK_SIZE, (unsigned char *)buf, (unsigned char *)buf, n))
				{
					unsigned char checksum[8] = {0};
					DataChecksum(buf, n, checksum, sizeof(checksum));
					if(memcmp(checksum, data_checksum, min(sizeof(checksum), data_checksum_length)) == 0)
					{
						return n;
					}
					else
					{
						return -1;
					}
				}
			}
			else
			{
				return -1;
			}
		}
	}

	return 0;
}

bool WriteSocketData(SOCKET sockfd, char * buf, int offset, int length, const unsigned char * key, int keylength, unsigned char iv[AES_BLOCK_SIZE], u_short port, int errcode)
{
	// the 'offset' to the data leaves room for header, so data of 'length' bytes can be sent without copying to another buffer

	int n = EncodeHeader(buf, offset, length, errcode, port);
	if(n <= 0)
	{
		return false;
	}

	if(!AESCBCEncrypt(key, keylength, iv, AES_BLOCK_SIZE, (unsigned char *)buf, (unsigned char *)buf, n))
	{
		return false;
	}

	return send(sockfd, buf, n, 0) > 0;
}

int AddRandomPadding(char * outdata, int outlength, int outoffset)
{
	if (outlength > outoffset)
	{
		// add random padding
		int paddinglength = outlength - outoffset;
		unsigned char paddingkey[AES_KEYSIZE_256] = {0};
		unsigned char paddingiv[AES_BLOCK_SIZE] = {0};
		GenerateRandomData(sizeof(paddingkey), paddingkey);
		GenerateRandomData(sizeof(paddingiv), paddingiv);
		GenerateRandomData(paddinglength, (unsigned char *)(outdata + outoffset));
		if(!AESCBCEncrypt(paddingkey, sizeof(paddingkey), paddingiv, sizeof(paddingiv), (unsigned char *)(outdata + outoffset), (unsigned char *)(outdata + outoffset), paddinglength))
		{
			return 0;
		}
	}
	return outlength;
}

void DeriveServerSessionKey(const char * data, int length, unsigned char key[AES_KEYSIZE_256])
{
	// new_key = [repeated XOR sha256(data + old_key)] x 1000

	unsigned char * tmp = (unsigned char *)_alloca(length + AES_KEYSIZE_256);

	memcpy(tmp, data, length);
	memcpy(tmp + length, key, AES_KEYSIZE_256);
	sha256Digest(tmp, length + AES_KEYSIZE_256, key);

	for(int i=0;i!=1000;++i)
	{
		memcpy(tmp, key, AES_KEYSIZE_256);
		sha256Digest(tmp, AES_KEYSIZE_256, key);
		for(int j=0;j!=AES_KEYSIZE_256;++j)
		{
			key[j] ^= tmp[j];
		}
	}
}

int ClientGenerateChallengeData(char * challenge1, int challengelength, char * authdata, int authlength)
{
	// key negotiation:
	//  client sends: aes(sha256(challenge1) + challenge1 + random_padding, embedded key)

	if(authlength >= (PACKET_PADDED_SIZE - PACKET_HEADER_SIZE) && challengelength == CLIENT_CHALLENGE_SIZE)
	{
		// key negotiation:
		//  client sends: aes(sha256(challenge1) + challenge1 + random_padding, embedded key)
		//  server verifies: random part of challenge1 not in previous list and current date within a day
		//  server sends: aes(sha256(challenge1 + challenge2) + challenge2 + random_padding, embedded key)
		//  client/server calculates: session key = KDF(challenge1 + challenge2 + embedded key)
		//  client server encryption: aes cbc, initial iv = fixed value
		// challenge1 is the current date in 8 byte FILETIME format plus 24 bytes of random data, the date
		// is checked within a day so replay of challenge1 can be checked against a smaller list.

		unsigned char digest[SHA_SIZE_256] = {0};
		GenerateRandomData(challengelength - sizeof(FILETIME), (unsigned char *)challenge1 + sizeof(FILETIME));

		FILETIME ft = {0};
		GetSystemTimeAsFileTime(&ft);
		LongToBytes(ft.dwHighDateTime, (unsigned char *)challenge1);
		LongToBytes(ft.dwLowDateTime, (unsigned char *)challenge1 + sizeof(ft.dwHighDateTime));

		sha256Digest((unsigned char *)challenge1, challengelength, digest);

		memcpy(authdata, digest, sizeof(digest));
		memcpy(authdata + sizeof(digest), challenge1, challengelength);

		return AddRandomPadding(authdata, authlength, sizeof(digest) + challengelength);
	}

	return 0;
}

bool ClientVerifyChallengeDeriveKey(const char * authdata, int authlength, const char * challenge1, int challengelength, unsigned char key[AES_KEYSIZE_256])
{
	// key negotiation:
	//  on client side, validate aes(sha256(challenge1 + challenge2) + challenge2 + random_padding, embedded key)

	if(authlength == PACKET_PADDED_SIZE - PACKET_HEADER_SIZE) // check correct length of random padding is present
	{
		unsigned char digest[SHA_SIZE_256] = {0};

		const char * challenge2 = authdata + sizeof(digest);

		char * data = (char *)_alloca(2 * challengelength);
		memcpy(data, challenge1, challengelength);
		memcpy(data + challengelength, challenge2, challengelength);
		sha256Digest((unsigned char *)data, 2 * challengelength, digest);

		if(memcmp(digest, authdata, sizeof(digest)) != 0)
		{
			return false;
		}

		// KDF: compute new key as: [repeated XOR sha256(challenge1 + challenge2 + old_key)] x 1000

		DeriveServerSessionKey(data, 2 * challengelength, key);
		return true;
	}

	return false;
}

int ServerVerifyChallengeDeriveKey(const char * authdata, int authlength, char * outdata, int outlength, unsigned char key[AES_KEYSIZE_256])
{
	// key negotiation:
	//  on server side, validate aes(sha256(challenge1) + challenge1 + random_padding, embedded key)
	//  and calculate aes(sha256(challenge1 + challenge2) + challenge2 + random_padding, embedded key)

	if(authlength == PACKET_PADDED_SIZE - PACKET_HEADER_SIZE) // check correct length of random padding is present
	{
		unsigned char digest[SHA_SIZE_256] = {0};

		const char * challenge1 = authdata + sizeof(digest);
		char challenge[CLIENT_CHALLENGE_SIZE] = {0};

		sha256Digest((const unsigned char *)challenge1, sizeof(challenge), digest);

		if(memcmp(digest, authdata, sizeof(digest)) != 0)
		{
			return 0;
		}

		// verify challenge has not been used previously, to block re-transmission of old encrypted data

		ULARGE_INTEGER clienttime = {0};
		clienttime.HighPart = BytesToLong((unsigned char *)challenge1);
		clienttime.LowPart = BytesToLong((unsigned char *)challenge1 + sizeof(clienttime.HighPart));

		FILETIME ft = {0};
		GetSystemTimeAsFileTime(&ft);
		ULARGE_INTEGER servertime = {ft.dwLowDateTime, ft.dwHighDateTime};

		// time difference between server and client within span of +/- 1 day,
		// e.g. connection every 9 seconds for 2 days is < 20000 stored challenges.

		ULONGLONG seconds = (servertime.QuadPart > clienttime.QuadPart ? servertime.QuadPart - clienttime.QuadPart : clienttime.QuadPart - servertime.QuadPart) / 10000000;
		if(seconds > (24 * 3600) + 1800)
		{
			return 0;
		}

		if(!AddChallengeList((const unsigned char *)challenge1 + sizeof(FILETIME)))
		{
			return 0; // already exists
		}

		if(outlength < (PACKET_PADDED_SIZE - PACKET_HEADER_SIZE))
		{
			return 0;
		}

		// KDF: compute new key as: [repeated XOR sha256(challenge1 + challenge2 + old_key)] x 1000

		GenerateRandomData(sizeof(challenge), (unsigned char *)challenge);

		char data[2 * sizeof(challenge)] = {0};
		memcpy(data, challenge1, sizeof(challenge));
		memcpy(&data[sizeof(challenge)], challenge, sizeof(challenge));

		DeriveServerSessionKey(data, sizeof(data), key);

		// compute (sha256(challenge1 + challenge2) + challenge2)

		sha256Digest((unsigned char *)data, sizeof(data), digest);
		memcpy(outdata, digest, sizeof(digest));
		memcpy(&outdata[sizeof(digest)], challenge, sizeof(challenge));

		return AddRandomPadding(outdata, outlength, sizeof(digest) + sizeof(challenge));
	}

	return 0;
}

void OutputClientWindowMessage(char * msg, char * endmsg)
{
	int msglen = msg ? strlen(msg) : 0;
	if(msglen > 0)
	{
		SYSTEMTIME st = {0};
		GetLocalTime(&st);
		char localtime[14] = {0};
		WORD hour = st.wHour == 0 || st.wHour == 12 ? 12 : st.wHour % 12;
		if(hour < 10) localtime[0] = ' ';
		_ultoa(hour, &localtime[strlen(localtime)], 10);
		strcat(localtime, st.wMinute < 10 ? ":0" : ":");
		_ultoa(st.wMinute % 60, &localtime[strlen(localtime)], 10);
		strcat(localtime, st.wSecond < 10 ? ":0" : ":");
		_ultoa(st.wSecond % 60, &localtime[strlen(localtime)], 10);
		strcat(localtime, st.wHour < 12 ? " AM " : " PM ");

		EnterCriticalSection(&g_clientmsgdata.csWindowMessages);

		const int maxline = 40;
		char * ptr = strstr(g_clientmsgdata.szWindowMessages, "\r\n");
		if(ptr)
		{
			int count = 0;
			char * p = ptr;
			while(p)
			{
				++count;
				p = strstr(p + 1, "\r\n");
			}
			if(count>=maxline)
			{
				int len = strlen(g_clientmsgdata.szWindowMessages) - (ptr + 2 - g_clientmsgdata.szWindowMessages);
				memmove(g_clientmsgdata.szWindowMessages, ptr + 2, len);
				*(g_clientmsgdata.szWindowMessages + len) = '\0';
			}
		}
		int endmsglen = endmsg ? strlen(endmsg) : 0;
		int maxlen = ((sizeof(g_clientmsgdata.szWindowMessages)/sizeof(g_clientmsgdata.szWindowMessages[0])) / maxline) - strlen(localtime) - 2;
		if(msglen + endmsglen > maxlen)
		{
			if(endmsglen >= maxlen)
			{
				endmsglen -= maxlen;
				*(endmsg + endmsglen) = '\0';
			}
			if(msglen + endmsglen > maxlen)
			{
				msglen = maxlen - endmsglen;
				*(msg + msglen) = '\0';
			}
		}

		char * p = strchr(msg, '\r');
		if(p != NULL) *p = '\0';
		p = strchr(msg, '\n');
		if(p != NULL) *p = '\0';

		strcat(g_clientmsgdata.szWindowMessages, localtime);
		strcat(g_clientmsgdata.szWindowMessages, msg);
		if(endmsg)
		{
			strcat(g_clientmsgdata.szWindowMessages, endmsg);
		}
		strcat(g_clientmsgdata.szWindowMessages,"\r\n");

		InvalidateRect(g_handle.hMainWindow, NULL, TRUE);

		LeaveCriticalSection(&g_clientmsgdata.csWindowMessages);
	}
}

ULONG WINAPI ClientSocketThread(void* sockfd)
{
	struct ThreadCount
	{
		ThreadCount()
		{
			InterlockedIncrement(&g_clientthreadcount);
		}
		~ThreadCount()
		{
			InterlockedDecrement(&g_clientthreadcount);
		}
	} threadcount;

	SOCKET socklocal = (SOCKET)sockfd;

	u_short remoteport = g_clientparams.sClientRemoteTunneledPort;
	u_short remoteaccessport = g_clientparams.sClientRemoteAccessPort;
	u_long remoteaccessip = g_clientparams.ulClientRemoteAccessIP;
	bool reconnect = g_clientparams.bClientReconnectOnLoss ? true : false; // if reconnect is true, a repeating reconnect loop may result if it causes an application to keep retrying

	SOCKET sockremote = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	BYTE bSessionKey[sizeof(g_clientparams.abEncryptionKey)] = {0};
	BYTE ivrecv[sizeof(IV_SEND)] = {0};  // shared iv swapped between client and server
	BYTE ivsend[sizeof(IV_RECV)] = {0};

	char debugstring[256] = {0};

	CharHeapBuffer buf(MAX_PACKET_SIZE);

	bool connected = false;

	ULONG idletimeout = (g_clientparams.ulIdleTimeout == 0 || g_clientparams.ulIdleTimeout > 70000) ? -1 : 60000 * g_clientparams.ulIdleTimeout, idletime = 0, tickcount = GetTickCount();

	while((WaitForSingleObject(g_handle.hStopClientsEvent, 0) == WAIT_TIMEOUT) && (idletime < idletimeout))
	{
		ULONG tc = GetTickCount();
		idletime = tc - tickcount;

		if(!connected)
		{
			memcpy(bSessionKey, g_clientparams.abEncryptionKey, sizeof(bSessionKey));
			memcpy(ivrecv, IV_SEND, sizeof(ivrecv)); // copy initial server iv's
			memcpy(ivsend, IV_RECV, sizeof(ivsend));

			// handshake protocol

			char data[PACKET_PADDED_SIZE] = {0};
			char challenge[CLIENT_CHALLENGE_SIZE] = {0};
			int c = ClientGenerateChallengeData(challenge, sizeof(challenge), &data[PACKET_HEADER_SIZE], PACKET_PADDED_SIZE - PACKET_HEADER_SIZE);
			if(c > 0)
			{
				struct sockaddr_in addr = {0};
				addr.sin_family = AF_INET;
				addr.sin_addr.s_addr = htonl(remoteaccessip);
				addr.sin_port = htons(remoteaccessport);

				int tmp = 20000;
				setsockopt(sockremote, SOL_SOCKET, SO_RCVTIMEO, (char*)&tmp, sizeof(tmp));
				setsockopt(sockremote, SOL_SOCKET, SO_SNDTIMEO, (char*)&tmp, sizeof(tmp));

				int retry = 5; // number of retries
				ULONG ticks = GetTickCount();
				while(retry > 0 && connect(sockremote, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
				{
					int error = h_errno;
					ULONG t = GetTickCount() - ticks;
					if(error != WSAECONNREFUSED && error != WSAENETUNREACH && error != WSAETIMEDOUT)
					{
						// not retriable
						retry = 0;
					}
					else if(--retry > 0 && WaitForSingleObject(g_handle.hStopClientsEvent, (t < 2500 ? 3000 - t : 500)) != WAIT_TIMEOUT)
					{
						// space about 3 secs apart, abort if stopping client
						retry = 0;
					}
					ticks = GetTickCount();
				}

				if (retry > 0)
				{
					if (WriteSocketData(sockremote, data, PACKET_HEADER_SIZE, c, bSessionKey, sizeof(bSessionKey), ivsend, remoteport, 0))
					{
						ULONG errcode = 0;
						memset(data, 0, PACKET_HEADER_SIZE);
						c = ReadSocketData(sockremote, data, PACKET_PADDED_SIZE, bSessionKey, sizeof(bSessionKey), ivrecv, errcode, remoteport);
						if(c == PACKET_PADDED_SIZE - PACKET_HEADER_SIZE)
						{
							if(ClientVerifyChallengeDeriveKey(data, c, challenge, sizeof(challenge), bSessionKey))
							{
								connected = true;
							}
							else
							{
								data[PACKET_HEADER_SIZE] = '\0';
								strcpy(debugstring, "Server verify error (data: ");
								strcat(debugstring, data);
								OutputClientWindowMessage(debugstring, "...)");
							}
						}
						else
						{
							if(c == -1)
							{
								OutputClientWindowMessage("Server data checksum error", NULL);
							}
							else
							{
								if(c > 0)
								{
									data[PACKET_HEADER_SIZE] = '\0';
									strcpy(debugstring, "Server verify error (data: ");
									strcat(debugstring, data);
									OutputClientWindowMessage(debugstring, "...)");
								}
								else if(errcode != 0)
								{
									char msg[128] = {0};
									strcpy(debugstring, "Server data receive error: ");
									strcat(debugstring, GetWSAErrorString(errcode, msg, sizeof(msg)));
									OutputClientWindowMessage(debugstring, NULL);
								}
								else
								{
									OutputClientWindowMessage("Server data receive error", NULL);
								}
							}
						}
					}
					else
					{
						OutputClientWindowMessage("Server data send error", NULL);
					}
				}
				else
				{
					char msg[128] = {0};
					strcpy(debugstring, "Failed to connect to server: ");
					strcat(debugstring, GetWSAErrorString(h_errno, msg, sizeof(msg)));
					OutputClientWindowMessage(debugstring, NULL);
				}
			}

			if(!connected)
			{
				// failed to connect, exit main loop
				break;
			}
		}

		fd_set fds = {0};

		FD_ZERO(&fds);
		FD_SET(sockremote, &fds);
		FD_SET(socklocal, &fds);

		SOCKET maxsock = max(socklocal, sockremote);

		struct timeval tv = {1, 0};
		if (select(maxsock + 1, &fds, NULL, NULL, &tv) > 0)
		{
			tickcount = tc;

			if (FD_ISSET(socklocal, &fds))
			{
				int n = recv(socklocal, &buf[PACKET_HEADER_SIZE], MAX_PACKET_SIZE - PACKET_HEADER_SIZE, 0);
				if(n <= 0)
				{
					int error = h_errno;
					if(error != 0)
					{
						char msg[128] = {0};
						strcpy(debugstring, "Closing connection: ");
						strcat(debugstring, GetWSAErrorString(error, msg, sizeof(msg)));
						OutputClientWindowMessage(debugstring, NULL);
					}
					else
					{
						OutputClientWindowMessage("Closing connection", NULL);
					}
					break;
				}
#ifdef _DEBUG
				strcpy(debugstring, "Receive ");
				_ultoa(n, &debugstring[strlen(debugstring)], 10);
				OutputClientWindowMessage(debugstring, " bytes");
#endif
				if (!WriteSocketData(sockremote, buf, PACKET_HEADER_SIZE, n, bSessionKey, sizeof(bSessionKey), ivsend, remoteport, 0))
				{
					OutputClientWindowMessage("Server data send error", NULL);

					if(reconnect) // make attempt at silent server reconnection if connection is broken
					{
						closesocket(sockremote);
						WaitForSingleObject(g_handle.hStopClientsEvent, 50);
						if ((sockremote = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) != INVALID_SOCKET)
						{
							OutputClientWindowMessage("Server reconnection attempt", NULL);
							connected = false;
							continue;
						}
					}

					break;
				}
			}
			else if (FD_ISSET(sockremote, &fds))
			{
				ULONG errcode = 0;
				u_short port = 0;
				int n = ReadSocketData(sockremote, buf, MAX_PACKET_SIZE, bSessionKey, sizeof(bSessionKey), ivrecv, errcode, port);
				if(n <= 0)
				{
					if(n == -1)
					{
						OutputClientWindowMessage("Server data checksum error", NULL);
					}
					else
					{
						if(errcode != 0)
						{
							char msg[128] = {0};
							strcpy(debugstring, "Server connection closed: ");
							strcat(debugstring, GetWSAErrorString(errcode, msg, sizeof(msg)));
							OutputClientWindowMessage(debugstring, NULL);
						}
						else
						{
							OutputClientWindowMessage("Server connection closed", NULL);
						}
					}

					if(reconnect) // make attempt at silent server reconnection if connection is broken
					{
						closesocket(sockremote);
						WaitForSingleObject(g_handle.hStopClientsEvent, 50);
						if ((sockremote = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) != INVALID_SOCKET)
						{
							OutputClientWindowMessage("Server reconnection attempt", NULL);
							connected = false;
							continue;
						}
					}

					break;
				}

				// send reply data to localhost
				if (send(socklocal, buf, n, 0) <= 0)
				{
					int error = h_errno;
					if(error != 0)
					{
						char msg[128] = {0};
						strcpy(debugstring, "Connection closed: ");
						strcat(debugstring, GetWSAErrorString(error, msg, sizeof(msg)));
						OutputClientWindowMessage(debugstring, NULL);
					}
					else
					{
						OutputClientWindowMessage("Connection closed", NULL);
					}
					break;
				}
#ifdef _DEBUG
				strcpy(debugstring, "Sending ");
				_ultoa(n, &debugstring[strlen(debugstring)], 10);
				OutputClientWindowMessage(debugstring, " bytes");
#endif
			}
		}
	}

	if(idletime >= idletimeout)
	{
		OutputClientWindowMessage("Idle connection timeout", NULL);
	}

	// send RST
	struct linger l = {1, 0};
	setsockopt(socklocal, SOL_SOCKET, SO_LINGER, (const char *)&l, sizeof(l));
	closesocket(socklocal);

	if (sockremote != INVALID_SOCKET)
	{
		closesocket(sockremote);
	}

	return 0;
}

ULONG WINAPI ClientListenerThread(void*)
{
	struct LocalList // a linked list to store "don't ask me for password again" processes and addresses that access the client
	{
		char * name;
		int pid;
		int addr;
		struct LocalList * next;
		LocalList() : next(0), name(0), pid(0), addr(0)
		{}
		~LocalList()
		{
			delete[] name;
			delete next;
		}
		void Add(char * _name, int _pid)
		{
			int depth = 0;
			Add(_name, _pid, depth);
			if(depth > 5000)
			{
				// limit memory usage by deleting old stuff
				delete next;
				next = 0;
			}
		}
		void Add(char * _name, int _pid, int & depth)
		{
			if(_name != 0 && _pid != pid)
			{
				if(next == 0 || (name == 0 && addr == 0))
				{
					name = new char[strlen(_name) + 1];
					strcpy(name, _name);
					pid = _pid;
					if(next == 0)
					{
						next = new LocalList();
					}
				}
				else
				{
					depth++;
					next->Add(_name, _pid, depth);
				}
			}
		}
		void Add(int _addr)
		{
			int depth = 0;
			Add(_addr, depth);
			if(depth > 5000)
			{
				// limit memory usage by deleting old stuff
				delete next;
				next = 0;
			}
		}
		void Add(int _addr, int & depth)
		{
			if(_addr != addr)
			{
				if(next == 0 || (name == 0 && addr == 0))
				{
					addr = _addr;
					if(next == 0)
					{
						next = new LocalList();
					}
				}
				else
				{
					depth++;
					next->Add(_addr, depth);
				}
			}
		}
		bool Find(char * _name, int _pid)
		{
			if(_name != 0 && _pid == pid && name != 0 && stricmp(_name, name) == 0)
			{
				return true;
			}
			if(next)
			{
				return next->Find(_name, _pid);
			}
			return false;
		}
		bool Find(int _addr)
		{
			if(_addr == addr)
			{
				return true;
			}
			if(next)
			{
				return next->Find(_addr);
			}
			return false;
		}
		void RemoveAll()
		{
			pid = 0;
			addr = 0;
			delete[] name;
			name = 0;
			delete next;
			next = 0;
		}
		void Cleanup()
		{
			if(name != 0)
			{
				if(!IsProcessConnected(name, pid))
				{
					delete[] name;
					name = 0;
					pid = 0;
				}
			}
			else if(addr != 0)
			{
				if(!IsAddressConnected(addr))
				{
					addr = 0;
				}
			}
			if(next)
			{
				next->Cleanup();
			}
		}
	};

	if ((g_handle.hSocketListener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) != INVALID_SOCKET)
	{
		int tmp = 20000;
		setsockopt(g_handle.hSocketListener, SOL_SOCKET, SO_RCVTIMEO, (char*)&tmp, sizeof(tmp));
		setsockopt(g_handle.hSocketListener, SOL_SOCKET, SO_SNDTIMEO, (char*)&tmp, sizeof(tmp));

		struct sockaddr_in addr = {0};
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(g_clientparams.ulClientListenIP);
		addr.sin_port = htons(g_clientparams.sClientListenPort);

		if ((bind(g_handle.hSocketListener, (struct sockaddr *) &addr, sizeof(struct sockaddr_in)) == SOCKET_ERROR) || (listen(g_handle.hSocketListener, SOMAXCONN) == SOCKET_ERROR))
		{
			char debugstring[256] = {0};
			strcpy(debugstring, "Failed to initialize: ");
			GetWSAErrorString(h_errno, &debugstring[strlen(debugstring)], sizeof(debugstring) - strlen(debugstring));
			OutputClientWindowMessage(debugstring, NULL);

			closesocket(g_handle.hSocketListener);
			g_handle.hSocketListener = INVALID_SOCKET;
		}
	}
	else
	{
		char debugstring[256] = {0};
		strcpy(debugstring, "Failed to initialize socket: ");
		GetWSAErrorString(h_errno, &debugstring[strlen(debugstring)], sizeof(debugstring) - strlen(debugstring));
		OutputClientWindowMessage(debugstring, NULL);
	}

	if (g_handle.hSocketListener != INVALID_SOCKET)
	{
		char debugstring[512] = {0};
		char processname[256] = {0};
		struct sockaddr_in addr = {0};
		LocalList localList;

		strcpy(debugstring, "Client listening on ");
		addr.sin_addr.s_addr = htonl(g_clientparams.ulClientListenIP);
		strcat(debugstring, inet_ntoa(addr.sin_addr));
		strcat(debugstring, ":");
		_ultoa(g_clientparams.sClientListenPort, &debugstring[strlen(debugstring)], 10);
		OutputClientWindowMessage(debugstring, NULL);

		strcpy(debugstring, g_serverparams.szDisplayName);
		strcat(debugstring, ":");
		_ultoa(g_clientparams.sClientListenPort, &debugstring[strlen(debugstring)], 10);
		strncpy(g_shelldata.nidSysTray.szTip, debugstring, sizeof(g_shelldata.nidSysTray.szTip) - 1);
		Shell_NotifyIcon(NIM_MODIFY, &g_shelldata.nidSysTray);

		BOOL getpwd = g_clientparams.bClientPasswordPrompt;

		while(WaitForSingleObject(g_handle.hStopClientListenerEvent, 1000) == WAIT_TIMEOUT)
		{
			int addrlen = sizeof(struct sockaddr_in);
			int sockfd = accept(g_handle.hSocketListener, (struct sockaddr *) &addr, &addrlen);

			if (sockfd != INVALID_SOCKET)
			{
				if(getpwd != g_clientparams.bClientPasswordPrompt)
				{
					getpwd = g_clientparams.bClientPasswordPrompt;
					if(getpwd)
					{
						localList.RemoveAll();
					}
					else
					{
						localList.Cleanup();
					}
				}
				else
				{
					localList.Cleanup();
				}

				int pid = 0;
				bool auth = false;

				strcpy(debugstring, "Connection from ");

				processname[0] = '\0';
				if(!GetAddrProcessName(addr, processname, sizeof(processname), pid))
				{
					strcat(debugstring, inet_ntoa(addr.sin_addr));
					if(getpwd)
					{
						auth = localList.Find(addr.sin_addr.S_un.S_addr);
						if(!auth)
						{
							int x = DialogBoxParam(g_handle.hModuleInstance, (LPCTSTR)IDD_PASSWORDPROMPT2, GetForegroundWindow(), (DLGPROC)PasswordPromptProc, (LPARAM)debugstring);
							if(x == IDC_CHECKPASS)
							{
								auth = true;
								localList.Add(addr.sin_addr.S_un.S_addr);
							}
							else if(x == IDOK)
							{
								auth = true;
							}
						}
					}
					else
					{
						auth = true;
					}
				}
				else
				{
					strcat(debugstring, processname);
					if(getpwd)
					{
						auth = localList.Find(processname, pid);
						if(!auth)
						{
							int x = DialogBoxParam(g_handle.hModuleInstance, (LPCTSTR)IDD_PASSWORDPROMPT2, GetForegroundWindow(), (DLGPROC)PasswordPromptProc, (LPARAM)debugstring);
							if(x == IDC_CHECKPASS)
							{
								auth = true;
								localList.Add(processname, pid);
							}
							else if(x == IDOK)
							{
								auth = true;
							}
						}
					}
					else
					{
						auth = true;
					}
				}

				if(auth)
				{
					strcpy(debugstring, "Connection received: ");
					if(processname[0] != 0)
					{
						strcat(debugstring, processname);
					}
					else
					{
						strcat(debugstring, inet_ntoa(addr.sin_addr));
					}
					OutputClientWindowMessage(debugstring, NULL);

					CreateThread(NULL, 0, ClientSocketThread, (void *)sockfd, 0, 0);
				}
				else
				{
					strcpy(debugstring, "Connection refused: ");
					if(processname[0] != 0)
					{
						strcat(debugstring, processname);
					}
					else
					{
						strcat(debugstring, inet_ntoa(addr.sin_addr));
					}
					OutputClientWindowMessage(debugstring, NULL);

					closesocket(sockfd);
				}
			}
		}

		OutputClientWindowMessage("Client stopped", NULL);

		SOCKET hSocket = g_handle.hSocketListener;
		g_handle.hSocketListener = INVALID_SOCKET;
		if(hSocket != INVALID_SOCKET)
		{
			closesocket(hSocket);
		}
	}

	return 0;
}

ULONG WINAPI ServerSocketThread(void* sockfd)
{
	try
	{
		struct ThreadCount
		{
			ThreadCount()
			{
				InterlockedIncrement(&g_serverthreadcount);
			}
			~ThreadCount()
			{
				InterlockedDecrement(&g_serverthreadcount);
			}
		} threadcount;

		SOCKET sockremote = (SOCKET)sockfd;

		SOCKET socklocal = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		BYTE bSessionKey[sizeof(g_serverkeys.key)] = {0};
		BYTE ivrecv[sizeof(IV_RECV)] = {0};
		BYTE ivsend[sizeof(IV_SEND)] = {0};

		CharHeapBuffer buf(MAX_PACKET_SIZE);

		memcpy(ivrecv, IV_RECV, sizeof(ivrecv));
		memcpy(ivsend, IV_SEND, sizeof(ivsend));

		bool connected = false;

		u_short port = 0;
		ULONG keyindex = -1, errcode = 0;
		memset((char *)buf, 0, PACKET_HEADER_SIZE);
		int n = ReadSocketData(sockremote, buf, MAX_PACKET_SIZE, g_serverkeys, ivrecv, keyindex, errcode, port);
		const ServerKeyChain * pSessionKey = g_serverkeys.Find(keyindex);

		if(n <= 0 || pSessionKey == NULL)
		{
			if(n == -1)
			{
				struct sockaddr_in addr = {0};
				int addrlen = sizeof(struct sockaddr_in);
				getpeername(sockremote, (struct sockaddr *) &addr, &addrlen);
				UpdateBlacklist(addr.sin_addr.S_un.S_addr, true);

				buf[PACKET_HEADER_SIZE] = '\0';
				OutputServerMessage("Data checksum error (data: ", (const char *)buf, "...): ", inet_ntoa(addr.sin_addr), NULL);
			}
			else
			{
				if(errcode != 0)
				{
					char msg[128] = {0};
					OutputServerMessage("Remote connection closed: ", GetWSAErrorString(errcode, msg, sizeof(msg)), NULL);
				}
				else
				{
					OutputServerMessage("Remote connection closed", NULL);
				}
			}

			closesocket(socklocal);
			CreateThread(NULL, 0x10000, ServerCloseSocketThread, (void*)sockremote, STACK_SIZE_PARAM_IS_A_RESERVATION, 0);
		}
		else
		{
			// handshake protocol

			memcpy(bSessionKey, pSessionKey->key, sizeof(bSessionKey)); // copy the shared key to the session key

			n = ServerVerifyChallengeDeriveKey(buf, n, &buf[PACKET_HEADER_SIZE], PACKET_PADDED_SIZE - PACKET_HEADER_SIZE, bSessionKey);

			bool verified = false;

			if(n > 0)
			{
				verified = true;

				if (WriteSocketData(sockremote, buf, PACKET_HEADER_SIZE, n, pSessionKey->key, sizeof(pSessionKey->key), ivsend, port, 0))
				{
					struct sockaddr_in addr = {0};
					addr.sin_family = AF_INET;
					addr.sin_addr.s_addr = htonl(g_serverparams.ulServerDestIP);
					addr.sin_port = htons(port);

					if (connect(socklocal, (struct sockaddr *)&addr, sizeof(addr)) != SOCKET_ERROR)
					{
						connected = true;
					}
					else
					{
						// send back negative acknowledgement
						int error = h_errno;
						WriteSocketData(sockremote, buf, PACKET_HEADER_SIZE, 0, pSessionKey->key, sizeof(pSessionKey->key), ivsend, port, error != 0 ? error : WSABASEERR);
					}
				}
			}

			struct sockaddr_in addr = {0};
			int addrlen = sizeof(struct sockaddr_in);
			getpeername(sockremote, (struct sockaddr *) &addr, &addrlen);
			UpdateBlacklist(addr.sin_addr.S_un.S_addr, !verified);

			if(!connected)
			{
				if(verified)
				{
					OutputServerMessage("Connection closed: ", inet_ntoa(addr.sin_addr), NULL);
				}
				else
				{
					buf[PACKET_HEADER_SIZE] = '\0';
					OutputServerMessage("Connection authentication error (data: ", (const char *)buf, "...): ", inet_ntoa(addr.sin_addr), NULL);
				}

				closesocket(socklocal);
				if(!verified)
				{
					CreateThread(NULL, 0x10000, ServerCloseSocketThread, (void*)sockremote, STACK_SIZE_PARAM_IS_A_RESERVATION, 0);
				}
				else
				{
					closesocket(sockremote);
				}
			}
			else
			{
				OutputServerMessage("Connection authenticated: ", inet_ntoa(addr.sin_addr), NULL);
			}
		}

		if(connected)
		{
			ULONG idletimeout = (g_serverparams.ulIdleTimeout == 0 || g_serverparams.ulIdleTimeout > 70000) ? -1 : 60000 * g_serverparams.ulIdleTimeout, idletime = 0, tickcount = GetTickCount();

			while((WaitForSingleObject(g_handle.hStopServiceEvent, 0) == WAIT_TIMEOUT) && (idletime < idletimeout))
			{
				ULONG tc = GetTickCount();
				idletime = tc - tickcount;

				fd_set fds = {0};

				FD_ZERO(&fds);
				FD_SET(socklocal, &fds);
				FD_SET(sockremote, &fds);

				SOCKET maxsock = max(socklocal, sockremote);

				struct timeval tv = {1, 0};
				if (select(maxsock + 1, &fds, NULL, NULL, &tv) > 0)
				{
					tickcount = tc;

					if (FD_ISSET(sockremote, &fds))
					{
						u_short port = 0;
						ULONG errcode = 0;
						int n = ReadSocketData(sockremote, buf, MAX_PACKET_SIZE, bSessionKey, sizeof(bSessionKey), ivrecv, errcode, port);
						if(n <= 0)
						{
							if(n == -1)
							{
								OutputServerMessage("Data checksum error", NULL);
							}
							else
							{
								if(errcode != 0)
								{
									if(errcode != WSANOTINITIALISED)
									{
										char msg[128] = {0};
										OutputServerMessage("Remote connection closed: ", GetWSAErrorString(errcode, msg, sizeof(msg)), NULL);
									}
								}
								else
								{
									OutputServerMessage("Remote connection closed", NULL);
								}
							}
							break;
						}

						// send client data to localhost
						if (send(socklocal, buf, n, 0) <= 0)
						{
							int error = h_errno;
							if(error != 0)
							{
								if(error != WSANOTINITIALISED)
								{
									char msg[128] = {0};
									OutputServerMessage("Local connection closed: ", GetWSAErrorString(error, msg, sizeof(msg)), NULL);
								}
							}
							else
							{
								OutputServerMessage("Local connection closed", NULL);
							}
							break;
						}
#ifdef _DEBUG
						char debugstring[40] = {0};
						OutputServerMessage("Sending ", _ultoa(n, debugstring, 10), " bytes", NULL);
#endif
					}
					else if (FD_ISSET(socklocal, &fds))
					{
						int n = recv(socklocal, &buf[PACKET_HEADER_SIZE], MAX_PACKET_SIZE - PACKET_HEADER_SIZE, 0);
						if(n <= 0)
						{
							int error = h_errno;
							if(error != 0)
							{
								if(error != WSANOTINITIALISED)
								{
									char msg[128] = {0};
									OutputServerMessage("Closing local connection: ", GetWSAErrorString(error, msg, sizeof(msg)), NULL);
								}
							}
							else
							{
								OutputServerMessage("Closing local connection", NULL);
							}
							break;
						}
#ifdef _DEBUG
						char debugstring[40] = {0};
						OutputServerMessage("Receive ", _ultoa(n, debugstring, 10), " bytes", NULL);
#endif
						if (!WriteSocketData(sockremote, buf, PACKET_HEADER_SIZE, n, bSessionKey, sizeof(bSessionKey), ivsend, 0, 0))
						{
							OutputServerMessage("Remote data send error", NULL);
							break;
						}
					}
				}
			}

			if(idletime >= idletimeout)
			{
				OutputServerMessage("Idle connection timeout", NULL);
			}

			if(WaitForSingleObject(g_handle.hStopServiceEvent, 1) == WAIT_TIMEOUT)
			{
				closesocket(socklocal);
				closesocket(sockremote);
			}
		}
	}
	catch(...)
	{}

	return 0;
}

ULONG WINAPI ServerCloseSocketThread(void* sockfd)
{
	SOCKET s = (SOCKET)sockfd;
	if(WaitForSingleObject(g_handle.hStopServiceEvent, 10000) == WAIT_TIMEOUT)
	{
		try {
			struct linger l = {1, 0};
			setsockopt(s, SOL_SOCKET, SO_LINGER, (const char *)&l, sizeof(l));
			closesocket(s);
		} catch(...) {}
	}
	return 0;
}

void WINAPI ServiceMain(DWORD dwArgc, LPTSTR* lpszArgv)
{
	DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &g_handle.hServiceMainThread, 0, TRUE, DUPLICATE_SAME_ACCESS);
	g_serverparams.lpServiceMainThreadId = GetCurrentThreadId();

	g_handle.hStopServiceEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	g_handle.hServiceMainStoppedEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	g_handle.hServiceHandle = RegisterServiceCtrlHandler(g_serverparams.szServiceName, ServiceHandler);

	WSADATA wsadata = {0};
	WSAStartup(MAKEWORD(2,2), &wsadata);

	SERVICE_STATUS status = {0};

	status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	status.dwCurrentState = SERVICE_RUNNING;
	status.dwControlsAccepted = SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN;
	status.dwWin32ExitCode = NO_ERROR;

	SetServiceStatus(g_handle.hServiceHandle, &status);

	if ((g_handle.hSocketListener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) != INVALID_SOCKET)
	{
		int tmp = 20000;
		setsockopt(g_handle.hSocketListener, SOL_SOCKET, SO_RCVTIMEO, (char*)&tmp, sizeof(tmp));
		setsockopt(g_handle.hSocketListener, SOL_SOCKET, SO_SNDTIMEO, (char*)&tmp, sizeof(tmp));

		tmp = 1;
		setsockopt(g_handle.hSocketListener, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char*)&tmp, sizeof(tmp));

		struct sockaddr_in addr = {0};
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(g_serverparams.ulServerListenIP);
		addr.sin_port = htons(g_serverparams.sServerListenPort);

		if ((bind(g_handle.hSocketListener, (struct sockaddr *) &addr, sizeof(struct sockaddr_in)) == SOCKET_ERROR) || (listen(g_handle.hSocketListener, SOMAXCONN) == SOCKET_ERROR))
		{
			int error = h_errno;
			closesocket(g_handle.hSocketListener);
			g_handle.hSocketListener = INVALID_SOCKET;
			char msg[128] = {0};
			OutputServerMessage("Local port access error: ", GetWSAErrorString(error, msg, sizeof(msg)), NULL);
			status.dwWin32ExitCode = error != 0 ? error : ERROR_SERVICE_SPECIFIC_ERROR;
			status.dwServiceSpecificExitCode = error != 0 ? error : -2;
		}
	}
	else
	{
		int error = h_errno;
		char msg[128] = {0};
		OutputServerMessage("Socket error: ", GetWSAErrorString(error, msg, sizeof(msg)), NULL);
		status.dwWin32ExitCode = error != 0 ? error : ERROR_SERVICE_SPECIFIC_ERROR;
		status.dwServiceSpecificExitCode = error != 0 ? error : -1;
	}

	if (g_handle.hSocketListener != INVALID_SOCKET)
	{
		OutputServerMessage(g_serverparams.szDisplayName, " started successfully", NULL);

		ULONG tickcount = GetTickCount();

		while(WaitForSingleObject(g_handle.hStopServiceEvent, 1000) == WAIT_TIMEOUT)
		{
			// limit number of threads

			if(g_serverthreadcount > 50)
			{
				bool exit = false;
				while(!exit && g_serverthreadcount > 50)
				{
					exit = WaitForSingleObject(g_handle.hStopServiceEvent, 500) != WAIT_TIMEOUT;
				}

				if(exit)
				{
					break;
				}
			}

			struct sockaddr_in addr = {0};
			int addrlen = sizeof(struct sockaddr_in);
			int sockfd = accept(g_handle.hSocketListener, (struct sockaddr *) &addr, &addrlen);

			if (sockfd != INVALID_SOCKET)
			{
				// clear blacklist every 24 hours or so

				ULONG tc = GetTickCount();
				if(tc - tickcount > 24 * 3600000)
				{
					ClearBlacklist();
					tickcount = tc;
				}

				if(!GetBlacklist(addr.sin_addr.S_un.S_addr))
				{
					fd_set fds = {0};
					struct timeval tv = {10, 0};

					FD_ZERO(&fds);
					FD_SET(sockfd, &fds);

					if (select(sockfd + 1, &fds, NULL, NULL, &tv) > 0)
					{
						OutputServerMessage("Connection accepted: ", inet_ntoa(addr.sin_addr), NULL);

						CreateThread(NULL, 0, ServerSocketThread, (void *)sockfd, 0, 0);
					}
					else
					{
						OutputServerMessage("Connection dropped: ", inet_ntoa(addr.sin_addr), NULL);

						CreateThread(NULL, 0x10000, ServerCloseSocketThread, (void *)sockfd, STACK_SIZE_PARAM_IS_A_RESERVATION, 0);
					}
				}
				else
				{
					OutputServerMessage("Blacklist defense: ", inet_ntoa(addr.sin_addr), NULL);

					CreateThread(NULL, 0x10000, ServerCloseSocketThread, (void *)sockfd, STACK_SIZE_PARAM_IS_A_RESERVATION, 0);
				}
			}
		}
	}

	while(g_serverthreadcount > 0)
	{
		if(WaitForSingleObject(GetCurrentThread(), 1) != WAIT_TIMEOUT)
		{
			break;
		}
	}

	WSACleanup();

	status.dwCurrentState = SERVICE_STOPPED;
	SetServiceStatus(g_handle.hServiceHandle, &status);

	SetEvent(g_handle.hServiceMainStoppedEvent);
}

ATOM MyRegisterClass(HINSTANCE hInstance, TCHAR * lpszClassName)
{
	WNDCLASSEX wcex;

	wcex.cbSize = sizeof(WNDCLASSEX); 

	wcex.style			= CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc	= (WNDPROC)MainWndProc;
	wcex.cbClsExtra		= 0;
	wcex.cbWndExtra		= 0;
	wcex.hInstance		= hInstance;
	wcex.hIcon			= LoadIcon(hInstance, (LPCTSTR)IDI_TCPDATAPIPE);
	wcex.hCursor		= LoadCursor(NULL, IDC_ARROW);
	wcex.hbrBackground	= (HBRUSH)(COLOR_WINDOW+1);
	wcex.lpszMenuName	= (LPCSTR)IDC_TCPDATAPIPE;
	wcex.lpszClassName	= lpszClassName;
	wcex.hIconSm		= LoadIcon(wcex.hInstance, (LPCTSTR)IDI_SMALL);

	return RegisterClassEx(&wcex);
}

void UpdateMenus(HWND hWnd)
{
	HMENU hMenu = GetMenu(hWnd);

	SC_HANDLE sc1 = NULL;
	if(sc1 = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS))
	{
		SC_HANDLE sc2 = NULL;
		if(sc2 = OpenService(sc1, g_serverparams.szServiceName, SERVICE_QUERY_STATUS))
		{
			EnableMenuItem(hMenu, IDM_INSTALLSERVICE, MF_BYCOMMAND|MF_GRAYED);
			EnableMenuItem(hMenu, IDM_DELETESERVICE, MF_BYCOMMAND|MF_ENABLED);
			EnableMenuItem(hMenu, IDM_RESTARTSERVICE, MF_BYCOMMAND|MF_ENABLED);
			CloseServiceHandle(sc2);
		}
		else
		{
			EnableMenuItem(hMenu, IDM_INSTALLSERVICE, MF_BYCOMMAND|MF_ENABLED);
			EnableMenuItem(hMenu, IDM_DELETESERVICE, MF_BYCOMMAND|MF_GRAYED);
			EnableMenuItem(hMenu, IDM_RESTARTSERVICE, MF_BYCOMMAND|MF_GRAYED);
		}
		CloseServiceHandle(sc1);
		EnableMenuItem(hMenu, IDM_SERVERCONFIG, MF_BYCOMMAND|MF_ENABLED);
	}
	else
	{
		EnableMenuItem(hMenu, IDM_INSTALLSERVICE, MF_BYCOMMAND|MF_GRAYED);
		EnableMenuItem(hMenu, IDM_DELETESERVICE, MF_BYCOMMAND|MF_GRAYED);
		EnableMenuItem(hMenu, IDM_RESTARTSERVICE, MF_BYCOMMAND|MF_GRAYED);
		EnableMenuItem(hMenu, IDM_SERVERCONFIG, MF_BYCOMMAND|MF_GRAYED);
	}
}

LRESULT CALLBACK MainWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	static HCURSOR hcurAppStart = LoadCursor(NULL, IDC_APPSTARTING);
	static HCURSOR hcurStandard = LoadCursor(NULL, IDC_ARROW);
	static HMENU hMenuSysTray = CreatePopupMenu();

	switch (message) 
	{
	case WM_CREATE:
		{
			g_shelldata.nidSysTray.hWnd = hWnd;
			g_shelldata.nidSysTray.uID = 1;
			g_shelldata.nidSysTray.uCallbackMessage = WM_SYSTRAYNOTIFY;
			g_shelldata.nidSysTray.hIcon = LoadIcon(g_handle.hModuleInstance, MAKEINTRESOURCE(IDI_SMALL));
			g_shelldata.nidSysTray.uFlags = NIF_ICON|NIF_MESSAGE|NIF_TIP;
			strncpy(g_shelldata.nidSysTray.szTip, g_serverparams.szDisplayName, sizeof(g_shelldata.nidSysTray.szTip) - 1);
			InsertMenu(GetSystemMenu(hWnd, FALSE), SC_MINIMIZE, MF_BYCOMMAND, IDM_SYSTRAY, "Minimize To Tray");
			AppendMenu(hMenuSysTray, MF_STRING|MF_ENABLED, IDM_SYSTRAY, "Restore");
		}
		return DefWindowProc(hWnd, message, wParam, lParam);

	case WM_SYSCOMMAND:
		{
			switch (LOWORD(wParam))
			{
			case IDM_SYSTRAY:
				if(!g_shelldata.bIconic && Shell_NotifyIcon(NIM_ADD, &g_shelldata.nidSysTray))
				{
					g_shelldata.bIconic = TRUE;
					ShowWindow(hWnd, SW_HIDE);
				}
				break;
			default:
				return DefWindowProc(hWnd, message, wParam, lParam);
			}
		}
		break;

	case WM_COMMAND:
		{
			switch (LOWORD(wParam))
			{
			case IDM_SYSTRAY:
				if(g_shelldata.bIconic)
				{
					g_shelldata.bIconic = FALSE;
					Shell_NotifyIcon(NIM_DELETE, &g_shelldata.nidSysTray);
					ShowWindow(hWnd, SW_RESTORE);
				}
				else
				{
					if(Shell_NotifyIcon(NIM_ADD, &g_shelldata.nidSysTray))
					{
						g_shelldata.bIconic = TRUE;
						ShowWindow(hWnd, SW_HIDE);
					}
				}
				break;
			case IDM_DELETESERVICE:
				{
					SC_HANDLE sc1 = NULL;
					if(sc1 = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS))
					{
						SetCursor(hcurAppStart);

						SC_HANDLE sc2 = NULL;
						if(sc2 = OpenService(sc1, g_serverparams.szServiceName, SERVICE_ALL_ACCESS))
						{
							SERVICE_STATUS status = {0};
							if(QueryServiceStatus(sc2, &status) && status.dwCurrentState == SERVICE_RUNNING)
							{
								ControlService(sc2, SERVICE_CONTROL_STOP, &status);
								int i = 10;
								do
								{
									Sleep(500);
								}
								while(QueryServiceStatus(sc2, &status) && status.dwCurrentState == SERVICE_RUNNING && i-- > 0);
							}
							if(DeleteService(sc2))
							{
								CloseServiceHandle(sc2);
								MessageBox(hWnd, "Service removed successfully.", g_serverparams.szDisplayName, MB_OK | MB_ICONINFORMATION);
							}
							else
							{
								int error = GetLastError();

								CloseServiceHandle(sc2);

								if( error == ERROR_SERVICE_MARKED_FOR_DELETE)
								{
									MessageBox(hWnd, "Could not remove service as it is still in use.", g_serverparams.szDisplayName, MB_OK | MB_ICONERROR);
								}
								else
								{
									MessageBox(hWnd, "Could not remove service.", g_serverparams.szDisplayName, MB_OK | MB_ICONERROR);
								}
							}
						}
						else
						{
							if(GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST)
							{
								MessageBox(hWnd, "Service does not exist.", g_serverparams.szDisplayName, MB_OK | MB_ICONINFORMATION);
							}
							else
							{
								MessageBox(hWnd, "Could not open service.", g_serverparams.szDisplayName, MB_OK | MB_ICONERROR);
							}
						}

						SetCursor(hcurStandard);

						CloseServiceHandle(sc1);

						UpdateMenus(hWnd);
					}
					else
					{
						MessageBox(hWnd, "Could not open service manager.", g_serverparams.szDisplayName, MB_OK | MB_ICONERROR);
					}
				}
				break;
			case IDM_INSTALLSERVICE:
				{
					SC_HANDLE sc1 = NULL;
					if(sc1 = OpenSCManager( NULL, NULL, SC_MANAGER_ALL_ACCESS))
					{
						SC_HANDLE sc2 = NULL;
						if(sc2 = OpenService(sc1, g_serverparams.szServiceName, SERVICE_ALL_ACCESS))
						{
							CloseServiceHandle(sc2);
							MessageBox(hWnd, "Service already exists.", g_serverparams.szDisplayName, MB_OK | MB_ICONINFORMATION);
						}
						else
						{
							if(GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST)
							{
								char path[_MAX_PATH + 1] = {0};
								strncpy(path, GetCommandLine(), _MAX_PATH);
								int i = strlen(path);
								while(i > 0 && isspace(path[--i]))
								{
									path[i] = '\0'; // remove trailing spaces
								}

								sc2 = CreateService(sc1, g_serverparams.szServiceName, g_serverparams.szDisplayName, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_IGNORE, path, NULL, NULL, NULL, NULL, NULL);

								if(sc2 == NULL && GetLastError() == ERROR_DUPLICATE_SERVICE_NAME)
								{
									char displayname[256] = {0};
									strncpy(displayname, g_serverparams.szDisplayName, 250);
									strcat(displayname, " ");
									int offset = strlen(displayname);
									for(int i=1; sc2 == NULL && i < 100; ++i)
									{
										_ultoa(i, &displayname[offset], 10);
										sc2 = CreateService(sc1, g_serverparams.szServiceName, displayname, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_IGNORE, path, NULL, NULL, NULL, NULL, NULL);
									}
								}

								if(sc2 != NULL)
								{
									CloseServiceHandle(sc2);
									MessageBox(hWnd, "Service installed successfully.", g_serverparams.szDisplayName, MB_OK | MB_ICONINFORMATION);
								}
								else
								{
									MessageBox(hWnd, "Could not create service.", g_serverparams.szDisplayName, MB_OK | MB_ICONERROR);
								}
							}
							else
							{
								MessageBox(hWnd, "Could not open service.", g_serverparams.szDisplayName, MB_OK | MB_ICONERROR);
							}
						}

						CloseServiceHandle(sc1);

						UpdateMenus(hWnd);
					}
					else
					{
						MessageBox(hWnd, "Could not open service manager.", g_serverparams.szDisplayName, MB_OK | MB_ICONERROR);
					}
				}
				break;
			case IDM_RESTARTSERVICE:
				{
					SC_HANDLE sc1 = NULL;
					if(sc1 = OpenSCManager( NULL, NULL, SC_MANAGER_CONNECT|STANDARD_RIGHTS_READ))
					{
						SetCursor(hcurAppStart);

						SC_HANDLE sc2 = NULL;
						if(sc2 = OpenService(sc1, g_serverparams.szServiceName, SERVICE_START|SERVICE_STOP|SERVICE_QUERY_STATUS))
						{
							SERVICE_STATUS status = {0};
							if(QueryServiceStatus(sc2, &status) && status.dwCurrentState == SERVICE_RUNNING)
							{
								ControlService(sc2, SERVICE_CONTROL_STOP, &status);
								int i = 10;
								do
								{
									Sleep(500);
								}
								while(QueryServiceStatus(sc2, &status) && status.dwCurrentState == SERVICE_RUNNING && i-- > 0);
							}
							if(StartService(sc2, 0, 0))
							{
								Sleep(500);
								QueryServiceStatus(sc2, &status);
								if(status.dwCurrentState != SERVICE_RUNNING)
								{
									ULONG error = status.dwWin32ExitCode == ERROR_SERVICE_SPECIFIC_ERROR ? status.dwServiceSpecificExitCode : status.dwWin32ExitCode;

									char text[256] = {0};
									strcpy(text, "Service could not be started: ");
									GetWSAErrorString(error, &text[strlen(text)], sizeof(text) - strlen(text));

									MessageBox(hWnd, text, g_serverparams.szDisplayName, MB_OK | MB_ICONERROR);

								}
								else
								{
									MessageBox(hWnd, "Service started successfully.", g_serverparams.szDisplayName, MB_OK | MB_ICONINFORMATION);
								}
							}
							else
							{
								int error = GetLastError();
								if(error == ERROR_SERVICE_DISABLED  || error == ERROR_SERVICE_MARKED_FOR_DELETE)
								{
									// these error codes can occur if service was deleted before it stopped or had an open handle to it
									MessageBox(hWnd, "Service has been disabled or marked for removal.", g_serverparams.szDisplayName, MB_OK | MB_ICONERROR);
								}
								else
								{
									char text[256] = {0};
									strcpy(text, "Could not start service: ");
									GetWSAErrorString(error, &text[strlen(text)], sizeof(text) - strlen(text));

									MessageBox(hWnd, text, g_serverparams.szDisplayName, MB_OK | MB_ICONERROR);
								}
							}
							CloseServiceHandle(sc2);
						}
						else
						{
							if( GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST)
							{
								MessageBox(hWnd, "Service does not exist.", g_serverparams.szDisplayName, MB_OK | MB_ICONINFORMATION);
							}
							else
							{
								MessageBox(hWnd, "Could not open service.", g_serverparams.szDisplayName, MB_OK | MB_ICONERROR);
							}
						}

						SetCursor(hcurStandard);

						CloseServiceHandle(sc1);

						UpdateMenus(hWnd);
					}
					else
					{
						MessageBox(hWnd, "Could not open service manager.", g_serverparams.szDisplayName, MB_OK | MB_ICONERROR);
					}
				}
				break;
			case IDM_CLIENTCONFIG:
				if(DialogBox(g_handle.hModuleInstance, (LPCTSTR)IDD_CLIENTCONFIG, hWnd, (DLGPROC)ClientConfigProc) == IDOK)
				{
					if(strlen(g_clientparams.szClientAuthenticationData) > 0)
					{
						if(g_handle.hClientListenerThread)
						{
							SetEvent(g_handle.hStopClientListenerEvent);

							SOCKET hSocket = g_handle.hSocketListener;
							g_handle.hSocketListener = INVALID_SOCKET;
							if(hSocket != INVALID_SOCKET)
							{
								closesocket(hSocket);
							}

							if(WaitForSingleObject(g_handle.hClientListenerThread, 5000) == WAIT_TIMEOUT)
							{
								if(MessageBox(hWnd, "Client Listener Blocked. Restart?", g_serverparams.szDisplayName, MB_OKCANCEL | MB_ICONWARNING) == IDCANCEL)
								{
									break;
								}
								// hopefully never require this - let the user decide.
								TerminateThread(g_handle.hClientListenerThread, 0);
								ThreadReleaseCriticalSection(g_clientparams.lpClientListenerThreadId);
							}

							CloseHandle(g_handle.hClientListenerThread);
						}

						g_shelldata.bIconic = TRUE;
						Shell_NotifyIcon(NIM_ADD, &g_shelldata.nidSysTray);
						ShowWindow(g_handle.hMainWindow, SW_HIDE);

						ResetEvent(g_handle.hStopClientListenerEvent);
						g_handle.hClientListenerThread = CreateThread(NULL, 0, ClientListenerThread, (void *)0, 0, &g_clientparams.lpClientListenerThreadId);
					}
				}
				break;
			case IDM_SERVERCONFIG:
				DialogBox(g_handle.hModuleInstance, (LPCTSTR)IDD_SERVERCONFIG, hWnd, (DLGPROC)ServerConfigProc);
				break;
			case IDM_EXIT:
				DestroyWindow(hWnd);
				break;
			default:
				return DefWindowProc(hWnd, message, wParam, lParam);
			}
		}
		break;

	case WM_SHOWWINDOW:
		if(wParam && g_shelldata.bIconic)
		{
			g_shelldata.bIconic = FALSE;
			Shell_NotifyIcon(NIM_DELETE, &g_shelldata.nidSysTray);
			ShowWindow(hWnd, SW_RESTORE);
		}
		break;

	case WM_SYSTRAYNOTIFY:
		if (wParam == 1)
		{
			switch (lParam)
			{
			case WM_LBUTTONDBLCLK:
				if(g_shelldata.bIconic)
				{
					g_shelldata.bIconic = FALSE;
					Shell_NotifyIcon(NIM_DELETE, &g_shelldata.nidSysTray);
					ShowWindow(hWnd, SW_RESTORE);
				}
				break;

			case WM_RBUTTONUP:
			case WM_CONTEXTMENU:
				POINT point = {0};
				GetCursorPos(&point);
				SetForegroundWindow(hWnd);
				TrackPopupMenu(hMenuSysTray, TPM_LEFTALIGN|TPM_RIGHTBUTTON, point.x, point.y, 0, hWnd, NULL);
				PostMessage(hWnd, WM_NULL, 0, 0);
				break;
			}
		}
		return TRUE;

	case WM_PAINT:
		{
			PAINTSTRUCT ps = {0};
			HDC hdc = BeginPaint(hWnd, &ps);

			RECT rt = {0};
			GetClientRect(hWnd, &rt);
			DrawText(hdc, g_clientmsgdata.szWindowMessages, strlen(g_clientmsgdata.szWindowMessages), &rt, DT_LEFT);

			EndPaint(hWnd, &ps);
		}
		break;

	case WM_DESTROY:
		if(g_shelldata.bIconic)
		{
			g_shelldata.bIconic = Shell_NotifyIcon(NIM_DELETE, &g_shelldata.nidSysTray);
		}
		DestroyMenu(hMenuSysTray);
		g_handle.hMainWindow = NULL;
		if(g_handle.hClientPasswordPrompt)
		{
			PostMessage(g_handle.hClientPasswordPrompt,WM_CLOSE,0,0);
		}
		PostQuitMessage(0);
		break;

	default:
		if(message == g_shelldata.WM_TASKBARCREATED)
		{
			if (g_shelldata.bIconic)
			{
				g_shelldata.bIconic = Shell_NotifyIcon(NIM_ADD, &g_shelldata.nidSysTray);
			}
			return 0;
		}
		return DefWindowProc(hWnd, message, wParam, lParam);
   }

   return 0;
}

// message handler for dialog
LRESULT CALLBACK ClientConfigProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	const int maxpwdlength = sizeof(g_clientparams.szClientPassword) - 1;
	switch (message)
	{
	case WM_INITDIALOG:
		{
			if(strlen(g_clientparams.szClientAuthenticationData) > 0)
			{
				if(DialogBoxParam(g_handle.hModuleInstance, (LPCTSTR)IDD_PASSWORDPROMPT1, GetForegroundWindow(), (DLGPROC)PasswordPromptProc, 0) != IDOK)
				{
					EndDialog(hDlg, IDCANCEL);
					return TRUE;
				}
			}

			char hexkey[2 * sizeof(g_clientparams.abEncryptionKey) + 1] = {0};
			BytesToHex(g_clientparams.abEncryptionKey, sizeof(g_clientparams.abEncryptionKey), hexkey);
			SendDlgItemMessage(hDlg, IDC_EDITKEY, WM_SETTEXT, 0, (LPARAM)hexkey);

			SendDlgItemMessage(hDlg, IDC_EDITPASS, WM_SETTEXT, 0, (LPARAM)g_clientparams.szClientPassword);
			SendDlgItemMessage(hDlg, IDC_EDITPASS, EM_LIMITTEXT, maxpwdlength, 0);

			char buf[40] = {0};
			struct in_addr addr = {0};

			addr.s_addr = htonl(g_clientparams.ulClientListenIP);
			SendDlgItemMessage(hDlg, IDC_EDITLOCALIPADDR, WM_SETTEXT, 0, (LPARAM)inet_ntoa(addr));
			SendDlgItemMessage(hDlg, IDC_EDITLOCALPORT, WM_SETTEXT, 0, (LPARAM)_ultoa(g_clientparams.sClientListenPort, buf, 10));

			SendDlgItemMessage(hDlg, IDC_EDITREMOTEPORT, WM_SETTEXT, 0, (LPARAM)_ultoa(g_clientparams.sClientRemoteTunneledPort, buf, 10));

			addr.s_addr = htonl(g_clientparams.ulClientRemoteAccessIP);
			SendDlgItemMessage(hDlg, IDC_EDITREMOTEIPADDR, WM_SETTEXT, 0, (LPARAM)inet_ntoa(addr));
			SendDlgItemMessage(hDlg, IDC_EDITREMOTEIPPORT, WM_SETTEXT, 0, (LPARAM)_ultoa(g_clientparams.sClientRemoteAccessPort, buf, 10));

			SendDlgItemMessage(hDlg, IDC_EDITTIMEOUT, WM_SETTEXT, 0, (LPARAM)_ultoa(g_clientparams.ulIdleTimeout, buf, 10));

			SendDlgItemMessage(hDlg, IDC_CHECKRECONNECT, BM_SETCHECK, g_clientparams.bClientReconnectOnLoss ? BST_CHECKED : BST_UNCHECKED, 0);
			SendDlgItemMessage(hDlg, IDC_CHECKPASS, BM_SETCHECK, g_clientparams.bClientPasswordPrompt ? BST_CHECKED : BST_UNCHECKED, 0);

			SendDlgItemMessage(hDlg, IDC_EDITKEY, EM_LIMITTEXT, 127, 0);
			SendDlgItemMessage(hDlg, IDC_EDITLOCALIPADDR, EM_LIMITTEXT, 127, 0);
			SendDlgItemMessage(hDlg, IDC_EDITLOCALPORT, EM_LIMITTEXT, 127, 0);
			SendDlgItemMessage(hDlg, IDC_EDITREMOTEPORT, EM_LIMITTEXT, 127, 0);
			SendDlgItemMessage(hDlg, IDC_EDITREMOTEIPADDR, EM_LIMITTEXT, 127, 0);
			SendDlgItemMessage(hDlg, IDC_EDITREMOTEIPPORT, EM_LIMITTEXT, 127, 0);
		}
		return TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK) 
		{
			if(SendDlgItemMessage(hDlg, IDC_EDITKEY, WM_GETTEXTLENGTH, 0, 0) != 2 * sizeof(g_clientparams.abEncryptionKey))
			{
				char msg[100] = {0};
				strcpy(msg, "Key length is incorrect, should be ");
				_ultoa(2 * sizeof(g_clientparams.abEncryptionKey), &msg[strlen(msg)], 10);
				strcat(msg, " characters (no spaces).");
				MessageBox(hDlg, msg, g_serverparams.szDisplayName, MB_OK | MB_ICONERROR);
				return TRUE;
			}

			char data[1024] = {0};

			SendDlgItemMessage(hDlg, IDC_EDITKEY, WM_GETTEXT, sizeof(data) - 1, (LPARAM)data);

			BYTE key[sizeof(g_clientparams.abEncryptionKey)] = {0};
			HexToBytes(data, 2 * sizeof(key), key);

			char pwd[maxpwdlength + 1] = {0};
			SendDlgItemMessage(hDlg, IDC_EDITPASS, WM_GETTEXT, maxpwdlength, (LPARAM)pwd);

			SendDlgItemMessage(hDlg, IDC_EDITLOCALIPADDR, WM_GETTEXT, sizeof(data) - 1, (LPARAM)data);
			ULONG localip = ntohl(inet_addr(data));

			SendDlgItemMessage(hDlg, IDC_EDITLOCALPORT, WM_GETTEXT, sizeof(data) - 1, (LPARAM)data);
			USHORT localport = (USHORT)atoi(data);

			SendDlgItemMessage(hDlg, IDC_EDITREMOTEPORT, WM_GETTEXT, sizeof(data) - 1, (LPARAM)data);
			USHORT tunnelport = (USHORT)atoi(data);

			ULONG remoteip = 0;

			SendDlgItemMessage(hDlg, IDC_EDITREMOTEIPADDR, WM_GETTEXT, sizeof(data) - 1, (LPARAM)data);
			int i = strlen(data);
			while(i > 0 && isspace(data[--i]))
			{
				data[i] = '\0'; // remove trailing spaces
			}
			i = 0;
			while(isspace(data[i]))
			{
				++i; // skip leading spaces
			}
			if (isalpha(data[i]))
			{
				LPHOSTENT hostEntry = gethostbyname(&data[i]);
				if(!hostEntry)
				{
					char msg[256] = {0};
					strcpy(msg, "Unable to resolve hostname '");
					strcat(msg, &data[i]);
					strcat(msg, "'.");
					MessageBox(hDlg, msg, g_serverparams.szDisplayName, MB_OK | MB_ICONERROR);
					return TRUE;
				}
				remoteip = ntohl(((LPIN_ADDR)hostEntry->h_addr)->S_un.S_addr);
			}
			else
			{
				remoteip = ntohl(inet_addr(&data[i]));
			}

			SendDlgItemMessage(hDlg, IDC_EDITREMOTEIPPORT, WM_GETTEXT, sizeof(data) - 1, (LPARAM)data);
			USHORT remoteport = (USHORT)atoi(data);

			SendDlgItemMessage(hDlg, IDC_EDITTIMEOUT, WM_GETTEXT, sizeof(data) - 1, (LPARAM)data);
			ULONG timeout = atoi(data);

			BOOL reconnect = (BST_CHECKED == SendDlgItemMessage(hDlg, IDC_CHECKRECONNECT, BM_GETCHECK, 0, 0));
			BOOL pwdprompt = (BST_CHECKED == SendDlgItemMessage(hDlg, IDC_CHECKPASS, BM_GETCHECK, 0, 0));

			CharHeapBuffer content;

			int length = EncryptClientConfigData(key, sizeof(key), remoteip, remoteport, tunnelport, localip, localport, timeout, reconnect, pwdprompt, pwd, content);
			if(length > 0)
			{
				char path[_MAX_PATH + 128] = {0};
				GetConfigFilename(false, path, sizeof(path));
				if(strlen(path) == 0)
				{
					if(MessageBox(hDlg, "Error getting configuration filename. Continue?", g_serverparams.szDisplayName, MB_YESNO | MB_ICONWARNING) == IDNO)
					{
						return TRUE;
					}
				}
				else
				{
					FILE *fd = fopen(path, "wb");
					if(fd == NULL)
					{
						if(MessageBox(hDlg, "Error saving configuration file. Continue?", g_serverparams.szDisplayName, MB_YESNO | MB_ICONWARNING) == IDNO)
						{
							return TRUE;
						}
					}
					else
					{
						bool ok = (fwrite((const BYTE *)content, 1, length, fd) == length);
						fclose(fd);
						if(!ok)
						{
							if(MessageBox(hDlg, "Error writing configuration file. Continue?", g_serverparams.szDisplayName, MB_YESNO | MB_ICONWARNING) == IDNO)
							{
								return TRUE;
							}
						}
					}
				}

				strcpy(g_clientparams.szClientPassword, pwd);

				length = min(length, sizeof(g_clientparams.szClientAuthenticationData) - 1);
				memcpy(g_clientparams.szClientAuthenticationData, (const TCHAR *)content, length);
				*(g_clientparams.szClientAuthenticationData + length) = '\0';

				memcpy(g_clientparams.abEncryptionKey, key, sizeof(g_clientparams.abEncryptionKey));

				g_clientparams.sClientRemoteAccessPort = remoteport;
				g_clientparams.sClientRemoteTunneledPort = tunnelport;
				g_clientparams.ulClientListenIP = localip;
				g_clientparams.sClientListenPort = localport;
				g_clientparams.ulClientRemoteAccessIP = remoteip;
				g_clientparams.bClientReconnectOnLoss = reconnect;
				g_clientparams.bClientPasswordPrompt = pwdprompt;
				g_clientparams.ulIdleTimeout = timeout;
			}
			else
			{
				MessageBox(hDlg, "Error encoding configuration data.", g_serverparams.szDisplayName, MB_OK | MB_ICONERROR);
				return TRUE;
			}

			EndDialog(hDlg, LOWORD(wParam));
			return TRUE;
		}
		else if (LOWORD(wParam) == IDCANCEL) 
		{
			EndDialog(hDlg, LOWORD(wParam));
			return TRUE;
		}
		break;
	}
    return FALSE;
}

ULONG WINAPI ClientRandPoolThread(void* stopevent)
{
	BYTE buf[SHA_SIZE_256] = {0};

	struct input {
		HWND window;
		POINT cursor;
	} _old = {0}, _new = {0};

	while(WaitForSingleObject((HANDLE)stopevent, 200) == WAIT_TIMEOUT)
	{
		GetCursorPos(&_new.cursor);
		_new.window = GetForegroundWindow();

		if(memcmp(&_new, &_old, sizeof(_new)) != 0)
		{
			// spread input data and xor with existing random

			sha256Digest((BYTE *)&_new, sizeof(_new), buf);

			for(int i=0; i!=sizeof(g_clientrandpool); ++i)
			{
				g_clientrandpool[i] ^= buf[i % sizeof(buf)];
			}

			_old = _new;
		}
	}
	return 0;
}

// message handler for dialog
LRESULT CALLBACK ServerConfigProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	static HANDLE hRandPoolThread = NULL, hRandPoolEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	switch (message)
	{
	case WM_INITDIALOG:
		{
			bool init = false;

			hRandPoolThread = CreateThread(NULL, 0x10000, ClientRandPoolThread, (void *)hRandPoolEvent, STACK_SIZE_PARAM_IS_A_RESERVATION, 0);

			CharHeapBuffer data;
			if(GetConfigData(true, data, NULL, 0))
			{
				USHORT port = 0;
				ULONG ip = 0, ipdest = 0, timeout = 0;
				BOOL useBlacklist = TRUE;
				ServerKeyChain keys;
				char name[sizeof(g_serverparams.szServiceName)] = {0};

				if(DecodeServerConfigData(data, name, sizeof(name), keys, ip, port, ipdest, timeout, useBlacklist))
				{
					char hexkey[2 * sizeof(keys.key) + 1] = {0};

					int count = keys.Count();
					for(int i=0;i<count;++i)
					{
						ServerKeyChain * k = keys.Find(i);
						if(k != NULL)
						{
							BytesToHex(k->key, sizeof(k->key), hexkey);
							SendDlgItemMessage(hDlg, IDC_LISTKEY, CB_ADDSTRING, 0, (LPARAM)hexkey);
						}
					}

					count = SendDlgItemMessage(hDlg, IDC_LISTKEY, CB_GETCOUNT, 0, 0);

					if(count > 0)
					{
						char buf[100] = {"Keys("};
						_ultoa(count, &buf[strlen(buf)], 10);
						SendDlgItemMessage(hDlg, IDC_KEYLABEL, WM_SETTEXT, 0, (LPARAM)strcat(buf, "):"));
						SendDlgItemMessage(hDlg, IDC_LISTKEY, CB_SETCURSEL, 0, 0);
					}
					else
					{
						SendDlgItemMessage(hDlg, IDC_KEYLABEL, WM_SETTEXT, 0, (LPARAM)"Keys:");
					}

					EnableWindow(GetDlgItem(hDlg, IDC_REMOVEKEY), count > 0);

					struct in_addr addr = {0};
					addr.s_addr = htonl(ip);
					SendDlgItemMessage(hDlg, IDC_EDITREMOTEIPADDR, WM_SETTEXT, 0, (LPARAM)inet_ntoa(addr));

					char buf[40] = {0};
					SendDlgItemMessage(hDlg, IDC_EDITREMOTEIPPORT, WM_SETTEXT, 0, (LPARAM)_ultoa(port, buf, 10));

					struct in_addr addrd = {0};
					addrd.s_addr = htonl(ipdest);
					SendDlgItemMessage(hDlg, IDC_EDITDESTIPADDR, WM_SETTEXT, 0, (LPARAM)inet_ntoa(addrd));

					SendDlgItemMessage(hDlg, IDC_EDITSVCNAME, WM_SETTEXT, 0, (LPARAM)name);

					SendDlgItemMessage(hDlg, IDC_EDITTIMEOUT, WM_SETTEXT, 0, (LPARAM)_ultoa(timeout, buf, 10));

					SendDlgItemMessage(hDlg, IDC_CHECKBLACKLIST, BM_SETCHECK, useBlacklist ? BST_CHECKED : BST_UNCHECKED, 0);

					init = true;
				}
			}

			if(!init)
			{
				EnableWindow(GetDlgItem(hDlg, IDC_REMOVEKEY), FALSE);

				struct in_addr addr = {0};
				addr.s_addr = htonl(g_serverparams.ulServerListenIP);
				SendDlgItemMessage(hDlg, IDC_EDITREMOTEIPADDR, WM_SETTEXT, 0, (LPARAM)inet_ntoa(addr));

				char buf[40] = {0};
				SendDlgItemMessage(hDlg, IDC_EDITREMOTEIPPORT, WM_SETTEXT, 0, (LPARAM)_ultoa(g_serverparams.sServerListenPort, buf, 10));

				struct in_addr addrd = {0};
				addrd.s_addr = htonl(g_serverparams.ulServerDestIP);
				SendDlgItemMessage(hDlg, IDC_EDITDESTIPADDR, WM_SETTEXT, 0, (LPARAM)inet_ntoa(addrd));

				SendDlgItemMessage(hDlg, IDC_EDITSVCNAME, WM_SETTEXT, 0, (LPARAM)g_serverparams.szServiceName);

				SendDlgItemMessage(hDlg, IDC_EDITTIMEOUT, WM_SETTEXT, 0, (LPARAM)_ultoa(g_serverparams.ulIdleTimeout, buf, 10));

				SendDlgItemMessage(hDlg, IDC_CHECKBLACKLIST, BM_SETCHECK, g_serverparams.bBlacklistIPBlock ? BST_CHECKED : BST_UNCHECKED, 0);
			}

			SendDlgItemMessage(hDlg, IDC_EDITKEY, EM_LIMITTEXT, 127, 0);
			SendDlgItemMessage(hDlg, IDC_EDITREMOTEIPADDR, EM_LIMITTEXT, 127, 0);
			SendDlgItemMessage(hDlg, IDC_EDITREMOTEIPPORT, EM_LIMITTEXT, 127, 0);
			SendDlgItemMessage(hDlg, IDC_EDITDESTIPADDR, EM_LIMITTEXT, 127, 0);

			SendDlgItemMessage(hDlg, IDC_GENKEY, BM_SETIMAGE, IMAGE_ICON, (LPARAM)LoadIcon(g_handle.hModuleInstance, MAKEINTRESOURCE(IDI_KEY)));
		}
		return TRUE;

	case WM_DESTROY:
		SetEvent(hRandPoolEvent);
		WaitForSingleObject(hRandPoolThread, INFINITE);
		CloseHandle(hRandPoolThread);
		hRandPoolThread=NULL;
		break;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDC_LISTKEY)
		{
			if (HIWORD(wParam) == CBN_SELCHANGE)
			{
				int index = SendDlgItemMessage(hDlg, IDC_LISTKEY, CB_GETCURSEL, 0, 0);
				EnableWindow(GetDlgItem(hDlg, IDC_REMOVEKEY), index != CB_ERR);

				if(index != CB_ERR)
				{
					int len = SendDlgItemMessage(hDlg, IDC_LISTKEY, CB_GETLBTEXTLEN, index, 0);
					if(len > 0)
					{
						char * data = (char *)_alloca(len + 1);
						memset(data, 0, len + 1);
						SendDlgItemMessage(hDlg, IDC_LISTKEY, CB_GETLBTEXT, index, (LPARAM)data);
						SendDlgItemMessage(hDlg, IDC_EDITKEY, WM_SETTEXT, 0, (LPARAM)data);
					}
				}
			}
		}
		else if (LOWORD(wParam) == IDC_ADDKEY)
		{
			int len = SendDlgItemMessage(hDlg, IDC_EDITKEY, WM_GETTEXTLENGTH, 0, 0);
			char * data = (char *)_alloca(len + 1);
			memset(data, 0, len + 1);
			SendDlgItemMessage(hDlg, IDC_EDITKEY, WM_GETTEXT, len + 1, (LPARAM)data);
			len = strlen(data);
			while(len > 0 && isspace(data[--len]))
			{
				data[len] = '\0'; // remove trailing spaces
			}

			if(strlen(data) != 2 * sizeof(g_serverkeys.key))
			{
				char msg[100] = {"Key length is incorrect, should be "};
				_ultoa(2 * sizeof(g_serverkeys.key), &msg[strlen(msg)], 10);
				MessageBox(hDlg, strcat(msg, " characters (no spaces)."), g_serverparams.szDisplayName, MB_OK | MB_ICONERROR);
				return TRUE;
			}

			BYTE key[sizeof(g_serverkeys.key)] = {0};
			HexToBytes(data, 2 * sizeof(key), key);
			BytesToHex(key, sizeof(key), data);

			int index = CB_ERR, count = SendDlgItemMessage(hDlg, IDC_LISTKEY, CB_GETCOUNT, 0, 0);

			for (int i=0;i < count;++i)
			{
				int l = SendDlgItemMessage(hDlg, IDC_LISTKEY, CB_GETLBTEXTLEN, i, 0);
				if(l > 0)
				{
					char * s = (char *)_alloca(l + 1);
					memset(s, 0, l + 1);
					SendDlgItemMessage(hDlg, IDC_LISTKEY, CB_GETLBTEXT, i, (LPARAM)s);
					if(stricmp(s, data) == 0)
					{
						index = i;
						break;
					}
				}
			}

			char buf[100] = {"Keys("};
			_ultoa(index == CB_ERR ? count + 1 : count, &buf[strlen(buf)], 10);
			SendDlgItemMessage(hDlg, IDC_KEYLABEL, WM_SETTEXT, 0, (LPARAM)strcat(buf, "):"));

			SendDlgItemMessage(hDlg, IDC_LISTKEY, CB_SETCURSEL, index == CB_ERR ? SendDlgItemMessage(hDlg, IDC_LISTKEY, CB_ADDSTRING, 0, (LPARAM)data) : index, 0);

			SendDlgItemMessage(hDlg, IDC_EDITKEY, WM_SETTEXT, 0, 0);

			EnableWindow(GetDlgItem(hDlg, IDC_REMOVEKEY), TRUE);
		}
		else if (LOWORD(wParam) == IDC_REMOVEKEY)
		{
			int index = SendDlgItemMessage(hDlg, IDC_LISTKEY, CB_GETCURSEL, 0, 0);
			if(index != CB_ERR)
			{
				SendDlgItemMessage(hDlg, IDC_LISTKEY, CB_DELETESTRING, index, 0);
				int count = SendDlgItemMessage(hDlg, IDC_LISTKEY, CB_GETCOUNT, 0, 0);
				if(count > 0)
				{
					char buf[100] = {"Keys("};
					_ultoa(count, &buf[strlen(buf)], 10);
					SendDlgItemMessage(hDlg, IDC_KEYLABEL, WM_SETTEXT, 0, (LPARAM)strcat(buf, "):"));
					SendDlgItemMessage(hDlg, IDC_LISTKEY, CB_SETCURSEL, 0, 0);
				}
				else
				{
					SendDlgItemMessage(hDlg, IDC_KEYLABEL, WM_SETTEXT, 0, (LPARAM)"Keys:");
				}
				SendDlgItemMessage(hDlg, IDC_LISTKEY, CB_SETCURSEL, index==count?index-1:index, 0);
				EnableWindow(GetDlgItem(hDlg, IDC_REMOVEKEY), count > 0);
			}
		}
		else if (LOWORD(wParam) == IDC_GENKEY)
		{
			BYTE key[sizeof(g_serverkeys.key)] = {0};

			GenerateRandomData(sizeof(key), key);

			// add to random by xor-ing with existing keys, randomize index to each byte of key

			for (int i=0,n=SendDlgItemMessage(hDlg, IDC_LISTKEY, CB_GETCOUNT, 0, 0);i < n;++i)
			{
				int l = SendDlgItemMessage(hDlg, IDC_LISTKEY, CB_GETLBTEXTLEN, i, 0);
				if(l > 0)
				{
					char * s = (char *)_alloca(l + 1);
					memset(s, 0, l + 1);
					SendDlgItemMessage(hDlg, IDC_LISTKEY, CB_GETLBTEXT, i, (LPARAM)s);
					BYTE * b = (BYTE *)_alloca(l / 2);
					HexToBytes(s, l, b);
					for(int j=0; j!=sizeof(key); ++j)
					{
						key[j] ^= b[((UINT)rand()) % (l / 2)];
					}
				}
			}

			// add mouse input etc.

			for(int j=0; j!=sizeof(key); ++j)
			{
				key[j] ^= g_clientrandpool[j % sizeof(g_clientrandpool)];
			}

			char hexkey[2 * sizeof(key) + 1] = {0};
			BytesToHex(key, sizeof(key), hexkey);
			SendDlgItemMessage(hDlg, IDC_EDITKEY, WM_SETTEXT, 0, (LPARAM)hexkey);
		}
		else if (LOWORD(wParam) == IDOK)
		{
			int count = SendDlgItemMessage(hDlg, IDC_LISTKEY, CB_GETCOUNT, 0, 0);
			if(count <= 0)
			{
				MessageBox(hDlg, "No keys have been added.", g_serverparams.szDisplayName, MB_OK | MB_ICONERROR);
				SetFocus(GetDlgItem(hDlg, IDC_EDITKEY));
				return TRUE;
			}

			ServerKeyChain keys;

			for (int i=0,keycount=0;i < count;++i)
			{
				int l = SendDlgItemMessage(hDlg, IDC_LISTKEY, CB_GETLBTEXTLEN, i, 0);
				if(l == 2 * sizeof(keys.key))
				{
					char hexkey[2 * sizeof(keys.key) + 1] = {0};
					BYTE binkey[sizeof(keys.key)] = {0};
					SendDlgItemMessage(hDlg, IDC_LISTKEY, CB_GETLBTEXT, i, (LPARAM)hexkey);
					HexToBytes(hexkey, 2 * sizeof(binkey), binkey);
					keys.SetKey(binkey, keycount++);
				}
			}

			char data[1024] = {0};

			SendDlgItemMessage(hDlg, IDC_EDITSVCNAME, WM_GETTEXT, sizeof(data) - 1, (LPARAM)data);
			if(strlen(data) > 0)
			{
				// replace unwanted characters in service name
				for(int i=0,n=strlen(data);i!=n;++i)
				{
					char & c = data[i];
					if(!isalnum(c))
					{
						c = '_';
					}
				}

				strncpy(g_serverparams.szServiceName, data, sizeof(g_serverparams.szServiceName) - 1);
				UpdateMenus(g_handle.hMainWindow);
			}

			SendDlgItemMessage(hDlg, IDC_EDITREMOTEIPADDR, WM_GETTEXT, sizeof(data) - 1, (LPARAM)data);
			ULONG ip = ntohl(inet_addr(data));

			SendDlgItemMessage(hDlg, IDC_EDITREMOTEIPPORT, WM_GETTEXT, sizeof(data) - 1, (LPARAM)data);
			USHORT port = (USHORT)atoi(data);

			SendDlgItemMessage(hDlg, IDC_EDITDESTIPADDR, WM_GETTEXT, sizeof(data) - 1, (LPARAM)data);
			ULONG ipdest = ntohl(inet_addr(data));

			SendDlgItemMessage(hDlg, IDC_EDITTIMEOUT, WM_GETTEXT, sizeof(data) - 1, (LPARAM)data);
			ULONG timeout = atoi(data);

			BOOL checkbl = (BST_CHECKED == SendDlgItemMessage(hDlg, IDC_CHECKBLACKLIST, BM_GETCHECK, 0, 0));

			CharHeapBuffer content;

			int length = EncodeServerConfigData(g_serverparams.szServiceName, keys, ip, port, ipdest, timeout, checkbl, content);
			if(length > 0)
			{
				char path[_MAX_PATH + 128] = {0};
				GetConfigFilename(true, path, sizeof(path));
				if(strlen(path) == 0)
				{
					MessageBox(hDlg, "Error getting configuration filename.", g_serverparams.szDisplayName, MB_OK | MB_ICONERROR);
					return TRUE;
				}

				FILE *fd = fopen(path, "wb");
				if(fd == NULL)
				{
					MessageBox(hDlg, "Error opening configuration file.", g_serverparams.szDisplayName, MB_OK | MB_ICONERROR);
					return TRUE;
				}

				bool ok = (fwrite((const BYTE *)content, 1, length, fd) == length);
				fclose(fd);
				if(!ok)
				{
					MessageBox(hDlg, "Error writing configuration file.", g_serverparams.szDisplayName, MB_OK | MB_ICONERROR);
					return TRUE;
				}

				// not running server so no need to copy to server parameters
			}
			else
			{
				MessageBox(hDlg, "Error encoding configuration data.", g_serverparams.szDisplayName, MB_OK | MB_ICONERROR);
				return TRUE;
			}

			EndDialog(hDlg, LOWORD(wParam));
			return TRUE;
		}
		else if (LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hDlg, LOWORD(wParam));
			return TRUE;
		}
		break;
	}
    return FALSE;
}

// message handler for dialog
LRESULT CALLBACK PasswordPromptProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	const int maxpwdlength = sizeof(g_clientparams.szClientPassword) - 1;
	switch (message)
	{
	case WM_INITDIALOG:
		g_handle.hClientPasswordPrompt = hDlg;
		SendDlgItemMessage(hDlg, IDC_EDITPASS, EM_LIMITTEXT, maxpwdlength, 0);
		if(lParam)
		{
			SendDlgItemMessage(hDlg, IDC_MESSAGE, WM_SETTEXT, 0, lParam);

			SendDlgItemMessage(hDlg, IDC_EDITREMOTEIPPORT, EM_LIMITTEXT, 127, 0);
			SendDlgItemMessage(hDlg, IDC_EDITREMOTEPORT, EM_LIMITTEXT, 127, 0);

			char buf[128] = {0};

			_ultoa(g_clientparams.sClientRemoteAccessPort, buf, 10);
			SendDlgItemMessage(hDlg, IDC_EDITREMOTEIPPORT, WM_SETTEXT, 0, (LPARAM)buf);

			_ultoa(g_clientparams.sClientRemoteTunneledPort, buf, 10);
			SendDlgItemMessage(hDlg, IDC_EDITREMOTEPORT, WM_SETTEXT, 0, (LPARAM)buf);

			struct in_addr addr = {0};
			addr.s_addr = htonl(g_clientparams.ulClientRemoteAccessIP);
			strcpy(buf, inet_ntoa(addr));
			char * p = strrchr(buf, '.');
			strcpy(p ? p + 1 : buf, "*");

			SendDlgItemMessage(hDlg, IDC_EDITREMOTEIPADDR, WM_SETTEXT, 0, (LPARAM)buf);

			SendDlgItemMessage(hDlg, IDC_CHECKPASS, BM_SETCHECK, BST_CHECKED, 0);
		}
		return TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK) 
		{
			if(strlen(g_clientparams.szClientAuthenticationData) > 0)
			{
				char pwd[maxpwdlength + 1] = {0};
				SendDlgItemMessage(hDlg, IDC_EDITPASS, WM_GETTEXT, maxpwdlength, (LPARAM)pwd);

				unsigned char key[AES_KEYSIZE_256] = {0};
				USHORT remoteport = 0, tunnelport = 0, localport = 0;
				ULONG remoteip = 0, localip = 0, timeout = 0;
				BOOL reconnect = FALSE, pwdprompt = FALSE;

				if(DecryptClientConfigData(g_clientparams.szClientAuthenticationData, pwd, key, sizeof(key), remoteip, remoteport, tunnelport, localip, localport, timeout, reconnect, pwdprompt))
				{
					g_handle.hClientPasswordPrompt = NULL;
					strcpy(g_clientparams.szClientPassword, pwd);
					HWND hItem = GetDlgItem(hDlg, IDC_EDITREMOTEIPPORT);
					if(hItem)
					{
						char buf[128] = {0};
						SendDlgItemMessage(hDlg, IDC_EDITREMOTEIPPORT, WM_GETTEXT, sizeof(buf) - 1, (LPARAM)buf);
						int port = atoi(buf);
						if(port > 0 && port < 0x10000)
						{
							g_clientparams.sClientRemoteAccessPort = (USHORT)port;
						}
					}
					hItem = GetDlgItem(hDlg, IDC_EDITREMOTEPORT);
					if(hItem)
					{
						char buf[128] = {0};
						SendDlgItemMessage(hDlg, IDC_EDITREMOTEPORT, WM_GETTEXT, sizeof(buf) - 1, (LPARAM)buf);
						int port = atoi(buf);
						if(port > 0 && port < 0x10000)
						{
							g_clientparams.sClientRemoteTunneledPort = (USHORT)port;
						}
					}
					if(GetDlgItem(hDlg, IDC_CHECKPASS))
					{
						bool checkpass = (BST_CHECKED == SendDlgItemMessage(hDlg, IDC_CHECKPASS, BM_GETCHECK, 0, 0));
						EndDialog(hDlg, checkpass ? IDC_CHECKPASS : IDOK);
					}
					else
					{
						EndDialog(hDlg, IDOK);
					}
				}
				else
				{
					MessageBox(hDlg, "Password incorrect.", g_serverparams.szDisplayName, MB_OK | MB_ICONERROR);
				}
			}
			else
			{
				MessageBox(hDlg, "Configuration data not loaded.", g_serverparams.szDisplayName, MB_OK | MB_ICONERROR);
				g_handle.hClientPasswordPrompt = NULL;
				EndDialog(hDlg, IDCANCEL);
			}
			return TRUE;
		}
		else if (LOWORD(wParam) == IDCANCEL) 
		{
			g_handle.hClientPasswordPrompt = NULL;
			EndDialog(hDlg, IDCANCEL);
			return TRUE;
		}
		break;
	}
	return FALSE;
}
