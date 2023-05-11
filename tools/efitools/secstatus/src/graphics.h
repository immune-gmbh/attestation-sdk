#ifndef __SECSTATUS_GRAPHICS_H
#define __SECSTATUS_GRAPHICS_H

#include <Library/UefiLib.h>

#include "macros.h"
#include "mem.h"

extern void printU32ThroughGraphics ( UINT32 u );
extern EFI_STATUS initGraphics (
    IN EFI_HANDLE        ImageHandle,
    IN EFI_SYSTEM_TABLE  *SystemTable
);

#endif