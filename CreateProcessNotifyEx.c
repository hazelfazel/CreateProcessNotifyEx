/*

	License:
	~~~~~~~~
	
	Copyright (c) 2018	Florian Rienhardt (florian@excubits.com)
						Excubits UG (haftungsbeschränkt)

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.

	
	Abstract:
	~~~~~~~~~
	
	A driver that registers a callback routine to be called whenever a process is
	created or deleted. This driver can be used for process creation monitoring. You
	can easily expand the driver to also block process creation attempts for specific
	parents invoking new processes. This might help to mitigate against typical
	attacks origination from office, browser and media playing tools. E.g. ask yourself
	"why should my text editor, pdf viewer or browser start cmd.exe or powershell.exe"?
	
	Please note, there exist techniques to bypass such process monitoring (in-memory
	attempts, reflective code loading). Hence, such a driver can only be _one_ part
	of a monitoring	and mitigation strategy. There is no claim to be bullet-proof!

	
*/


#include <CreateProcessNotifyEx.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#endif

NTSTATUS
DriverEntry(
	__in PDRIVER_OBJECT DriverObject,
	__in PUNICODE_STRING RegistryPath
)
{
	WDF_DRIVER_CONFIG config;
	NTSTATUS status;
						
	WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
	config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
	config.EvtDriverUnload = DriverUnload;

	status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
	if (NT_SUCCESS(status))
	{
		// initialize a resource variable we will use for synchronization
		ExInitializeResourceLite(&eResource);
		
		// open up or create the log
		status = initLog();
		if (NT_SUCCESS(status))
		{
			// register callback routine for process creation only
			// @todo: consider other notification routines too:
			//        PsSetCreateThreadNotifyRoutine and ExPsSetLoadImageNotifyRoutineEx
			status = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, FALSE);
			if (NT_SUCCESS(status))
			{
				DbgPrint("CreateProcNotifyEx.DriverEntry: We are ready now.\n");
			}
			else {
				DbgPrint("CreateProcNotifyEx.DriverEntry: Setting callback failed with status %08x\n", status);
				cleanup();
			}
		}
		else {
			DbgPrint("CreateProcNotifyEx.DriverEntry: Opening/Creating log failed with status %08x\n", status);
			cleanup();
		}
	}
	else {
		DbgPrint("CreateProcNotifyEx.DriverEntry: WdfDriverCreate failed with status %08x\n", status);
	}

	return status;
}

VOID
DriverUnload(
	__in WDFDRIVER Driver
)
{
	UNREFERENCED_PARAMETER(Driver);

	// we do not need to wait for actually running callbacks, as if Remove is TRUE,
	// the system waits for all in-flight callback routines to complete before returning :)
	PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, TRUE);
	DbgPrint("CreateProcNotifyEx.DriverUnload: Unregistered CreateProcessNotifyRoutine.\n");

	// cleanup variables
	cleanup();
	
	DbgPrint("CreateProcNotifyEx.DriverUnload: This is it.\n");
}

VOID
CreateProcessNotifyRoutine(
	__inout PEPROCESS Process,
	__in HANDLE ProcessId,
	__in_opt PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
	UNREFERENCED_PARAMETER(Process);
	UNREFERENCED_PARAMETER(ProcessId);

	if (CreateInfo)
	{
		NTSTATUS status;
		PUNICODE_STRING pImageFilename = NULL;
		PEPROCESS pProcess = NULL;
		BOOLEAN isWinword = FALSE;
		BOOLEAN isCmdExe = FALSE;
		
		// Lookup the PEPROCESS struct to obtain the image name of the creating process
		status = PsLookupProcessByProcessId(CreateInfo->CreatingThreadId.UniqueProcess, &pProcess);
		if (NT_SUCCESS(status))
		{
			status = SeLocateProcessImageName(pProcess, &pImageFilename);
			if (NT_SUCCESS(status)) {
				DbgPrint("CreateProcNotifyEx.CreateProcessNotify: CreatingProcess is %wZ.\n", pImageFilename);
			}
			ObDereferenceObject(pProcess);
		}

		// @todo: if the CreateInfo->FileOpenNameAvailable member is TRUE, string specifies the exact file name
		//        if it was FALSE, the OS might provide only a partial name
		DbgPrint("CreateProcNotifyEx.CreateProcessNotify: image filename is %wZ\n", CreateInfo->ImageFileName);

		// if command is not available, CreateInfo->CommandLine is NULL
		DbgPrint("CreateProcNotifyEx.CreateProcessNotify: command line is %wZ\n", CreateInfo->CommandLine);
		
		// @todo: in this demo we *do not* map internal device and path names to common UM naming scheme
		//		  so the log's content might look a bit weird
		writeToLog(pImageFilename, (PUNICODE_STRING)CreateInfo->ImageFileName, (PUNICODE_STRING)CreateInfo->CommandLine);
		
		// search for creating process winword.exe and command line cmd.exe to reject attempt
		// @todo: make it easier to use and configurable
		isWinword = FsRtlIsNameInExpression(&uszRuleWinword, pImageFilename, TRUE, NULL);
		isCmdExe = FsRtlIsNameInExpression(&uszRuleCommandline, (PUNICODE_STRING)CreateInfo->CommandLine, TRUE, NULL);
		if (isWinword && isCmdExe) {
			CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
			DbgPrint("CreateProcNotifyEx.CreateProcessNotify: ! ! ! attempt to start cmd.exe from winword.exe blocked.\n");
		}

		// don't forget to free the image filename
		if (pImageFilename != NULL) ExFreePool(pImageFilename);
	}
}

NTSTATUS
initLog()
{
	NTSTATUS status;

	OBJECT_ATTRIBUTES objAttrib = { 0 };
	IO_STATUS_BLOCK ioStatusBlock;

	//open or create the log
	InitializeObjectAttributes(&objAttrib, &uszLogFile, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	status = ZwCreateFile(&hLog, FILE_APPEND_DATA, &objAttrib, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (NT_SUCCESS(status)) {
		// if log was created, set UNICODE identifier so file will be opened as an UNICODE text file
		if (ioStatusBlock.Information == FILE_CREATED) {
			DWORD unicodeIdentifier = 0xFEFF;
			ZwWriteFile(hLog, NULL, NULL, NULL, &ioStatusBlock, &unicodeIdentifier, 2, NULL, NULL);
			DbgPrint("CreateProcNotifyEx.initLog: New log created.\n");
		}
		isLogging = TRUE;
		DbgPrint("CreateProcNotifyEx.initLog: Existing log successfully opened.\n");
	} else {
		isLogging = FALSE;
		DbgPrint("CreateProcNotifyEx.initLog: Could not open log with status %08x\n", status);
	}

	return status;
}

VOID
writeToLog(
	__in PUNICODE_STRING part1,
	__in PUNICODE_STRING part2,
	__in PUNICODE_STRING part3
	)
{
	if (isLogging)
	{
		IO_STATUS_BLOCK ioStatusBlock;
		WCHAR crlf[2] = { '\r', '\n' };
		WCHAR delimiter[1] = { '\t' };

		// "synchronize" write attempts to avoid mixed lines in the log
		ExAcquireResourceExclusiveLite(&eResource, TRUE);

		if (part1 != NULL) {
			ZwWriteFile(hLog, NULL, NULL, NULL, &ioStatusBlock, &*part1->Buffer, part1->Length, NULL, NULL);
		} else {
			ZwWriteFile(hLog, NULL, NULL, NULL, &ioStatusBlock, &*uszNullString.Buffer, uszNullString.Length, NULL, NULL);
		}

		ZwWriteFile(hLog, NULL, NULL, NULL, &ioStatusBlock, &delimiter, sizeof(delimiter), NULL, NULL);

		if (part2 != NULL) {
			ZwWriteFile(hLog, NULL, NULL, NULL, &ioStatusBlock, &*part2->Buffer, part2->Length, NULL, NULL);
		} else {
			ZwWriteFile(hLog, NULL, NULL, NULL, &ioStatusBlock, &*uszNullString.Buffer, uszNullString.Length, NULL, NULL);
		}

		ZwWriteFile(hLog, NULL, NULL, NULL, &ioStatusBlock, &delimiter, sizeof(delimiter), NULL, NULL);

		if (part3 != NULL) {
			ZwWriteFile(hLog, NULL, NULL, NULL, &ioStatusBlock, &*part3->Buffer, part3->Length, NULL, NULL);
		} else {
			ZwWriteFile(hLog, NULL, NULL, NULL, &ioStatusBlock, &*uszNullString.Buffer, uszNullString.Length, NULL, NULL);
		}

		ZwWriteFile(hLog, NULL, NULL, NULL, &ioStatusBlock, &crlf, sizeof(crlf), NULL, NULL);

		// release, next line can be written
		ExReleaseResourceLite(&eResource);
	}
}

VOID
cleanup()
{
	if (isLogging)
	{
		isLogging = FALSE;
		ZwClose(hLog);
	}
	
	ExDeleteResourceLite(&eResource);
}
