#include <stdint.h>
#include <Library/IoLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/ShellParameters.h>

#include "macros.h"
#include "mem.h"
#include "graphics.h"
#include "port80.h"

UINT8 *memmap;

struct _register {
	short unsigned int *name;
	UINT64 addr;
};
typedef struct _register register_t;

register_t registers[] = {
	{L"ACM_POLICY_STATUS", 0xFED30378}
};

void printRegisters()
{
	for ( volatile int i = 0; i < amountof ( registers ); i++ ) {
		register_t reg = registers[i];
		Print ( L"    *0x%X [%s] == 0x%X\n", reg.addr, reg.name, * ( UINT32 * ) reg.addr );
	}
}

EFI_STATUS exitBootServices (
    IN EFI_HANDLE        ImageHandle,
    IN EFI_SYSTEM_TABLE  *SystemTable
)
{
	// See https://stackoverflow.com/questions/39407280/uefi-simple-example-of-using-exitbootservices-with-gnu-efi
	UINTN mapKey, descriptorSize;
	UINT32 descriptorVersion;
	UINTN memmap_size = MEMMAP_SIZE * 2; // "*2" is defensive
	EXPECT ( EFI_SUCCESS, SystemTable->BootServices->GetMemoryMap ( &memmap_size, ( EFI_MEMORY_DESCRIPTOR* ) &memmap, &mapKey, &descriptorSize, &descriptorVersion ) );
	EXPECT ( EFI_SUCCESS, SystemTable->BootServices->ExitBootServices ( ImageHandle, mapKey ) );
	return EFI_SUCCESS;
}

// getArgs gets argc and argv.
EFI_STATUS getArgs (
    IN EFI_HANDLE        ImageHandle,
    IN EFI_SYSTEM_TABLE  *SystemTable,
    UINTN *argc,
    CHAR16 ***argv
)
{
	EFI_SHELL_PARAMETERS_PROTOCOL *EfiShellParametersProtocol = NULL;
	EXPECT ( EFI_SUCCESS, SystemTable->BootServices->OpenProtocol ( ImageHandle,
	         &gEfiShellParametersProtocolGuid,
	         ( VOID ** ) &EfiShellParametersProtocol,
	         ImageHandle,
	         NULL,
	         EFI_OPEN_PROTOCOL_GET_PROTOCOL ) );
	*argc = EfiShellParametersProtocol->Argc;
	*argv = EfiShellParametersProtocol->Argv;
	return EFI_SUCCESS;
}

void printRegistersUsing ( void ( *printU32 ) ( UINT32 u ) )
{
	for ( volatile int i = 0; i < amountof ( registers ); i++ ) {
		register_t reg = registers[i];
		printU32 ( * ( UINT32 * ) reg.addr );
	}
}

EFI_STATUS EFIAPI UefiMain (
    IN EFI_HANDLE        ImageHandle,
    IN EFI_SYSTEM_TABLE  *SystemTable
)
{
	Print ( L"Before ExitBootServices:\n" );
	printRegisters();
	UINTN argc;
	CHAR16 **argv;
	EXPECT ( EFI_SUCCESS, getArgs ( ImageHandle, SystemTable, &argc, &argv ) );

	if ( argc == 1 ) {
		return EFI_SUCCESS;
	}

	if ( argv[1][0] == 0 || argv[1][1] != 0 ) {
		return EFI_INVALID_PARAMETER;
	}

	char mode = argv[1][0];

	if ( mode != 'g' && mode != 'p' && mode != 'u' && mode != '*' ) {
		Print ( L"unexpected mode '%c'\n", mode );
		return EFI_INVALID_PARAMETER;
	}

	switch ( mode ) {
		case 'g':
		case '*':
			EXPECT ( EFI_SUCCESS, initGraphics ( ImageHandle, SystemTable ) );
	}

	Print ( L"ExitBootServices()...\n" );
	EXPECT ( EFI_SUCCESS, exitBootServices ( ImageHandle, SystemTable ) );

	switch ( mode ) {
		case 'p':
			printRegistersUsing ( printU32ThroughPort80 );
			break;

		case 'g':
			printRegistersUsing ( printU32ThroughGraphics );
			break;

		case '*':
			printRegistersUsing ( printU32ThroughPort80 );
			printRegistersUsing ( printU32ThroughGraphics );
			break;
	}

	// since we already executed ExitBootServices, it is not intended to return
	// to EFI shell ever, unfortunately.
	while ( 1 );

	return EFI_SUCCESS;
}
