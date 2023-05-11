#include "port80.h"

void printU32ThroughPort80 ( UINT32 u )
{
	IoWrite8 ( 0x80, u >> 24 );

	for ( volatile int i = 0; i < 1000000; i++  );

	IoWrite8 ( 0x80, u >> 16 );

	for ( volatile int i = 0; i < 1000000; i++  );

	IoWrite8 ( 0x80, u >> 8 );

	for ( volatile int i = 0; i < 1000000; i++ );

	IoWrite8 ( 0x80, u );

	for ( volatile int i = 0; i < 1000000; i++ );
}