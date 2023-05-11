#ifndef __SECSTATUS_MACROS_H
#define __SECSTATUS_MACROS_H

#define TOSTR(a) #a L""
#define EXPECT(expected, code) {EFI_STATUS status = code; if (status != expected) { Print(L"%s failed: %d != %d\n", TOSTR(code), status, expected); return status; }}
#define amountof(a) (sizeof(a)/sizeof(a[0]))

#endif