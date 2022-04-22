#include <ntifs.h>
#include <ntddk.h>
#include <wdf.h>


#define CREATE_XVER(maj,min,build) maj ## , ## min ## , 0, ## build
#define CREATE_FVER(maj,min,build) maj ## . ## min ## .0. ## build
#define CREATE_PVER(maj,min,build) maj ## . ## min

UNICODE_STRING uszLogFile = RTL_CONSTANT_STRING(L"\\SystemRoot\\CreateProcessNotifyEx.log");
UNICODE_STRING uszNullString = RTL_CONSTANT_STRING(L"(NULL)");

UNICODE_STRING uszRuleWinword = RTL_CONSTANT_STRING(L"*WINWORD.EXE");
UNICODE_STRING uszRuleCommandline = RTL_CONSTANT_STRING(L"*CMD.EXE*");

typedef unsigned long DWORD;

// just for synchronization
ERESOURCE eResource;

// if we are logging into a file this should be true
BOOLEAN isLogging = FALSE;

// this refers to the log
HANDLE hLog = 0;

DRIVER_INITIALIZE
DriverEntry;

EVT_WDF_DRIVER_UNLOAD
DriverUnload;

VOID
CreateProcessNotifyRoutine(
	__inout PEPROCESS Process,
	__in HANDLE ProcessId,
	__in_opt PPS_CREATE_NOTIFY_INFO CreateInfo
);

NTSTATUS
initLog();

VOID
writeToLog(
	__in PUNICODE_STRING part1,
	__in PUNICODE_STRING part2,
	__in PUNICODE_STRING part3
	)
;
	
VOID
cleanup();