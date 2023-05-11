#include "graphics.h"

EFI_GRAPHICS_OUTPUT_PROTOCOL* gop;
UINT32 COL = 0, ROW = 0;

EFI_STATUS initGraphics (
    IN EFI_HANDLE        ImageHandle,
    IN EFI_SYSTEM_TABLE  *SystemTable
)
{
	// See https://forum.osdev.org/viewtopic.php?f=1&t=26796
	EFI_HANDLE* handle_buffer;
	UINTN handle_count = 0;
	UINTN mode_num;
	EFI_GRAPHICS_OUTPUT_MODE_INFORMATION* gop_mode_info;
	EXPECT ( EFI_SUCCESS, SystemTable->BootServices->LocateHandleBuffer ( ByProtocol,
	         &gEfiGraphicsOutputProtocolGuid,
	         NULL,
	         &handle_count,
	         &handle_buffer ) );
	EXPECT ( EFI_SUCCESS, SystemTable->BootServices->HandleProtocol ( handle_buffer[0],
	         &gEfiGraphicsOutputProtocolGuid,
	         ( VOID ** ) &gop ); );
	{
		EFI_STATUS status;
		UINTN size_of_info;

		for ( mode_num = 0;
		      ( status = gop->QueryMode ( gop, mode_num, &size_of_info, &gop_mode_info ) ) == EFI_SUCCESS;
		      mode_num++ ) {
			if ( gop_mode_info->HorizontalResolution == DESIRED_HREZ &&
			     gop_mode_info->VerticalResolution == DESIRED_VREZ &&
			     gop_mode_info->PixelFormat        == DESIRED_PIXEL_FORMAT )
				break;
		}

		EXPECT ( EFI_SUCCESS, status );
		EXPECT ( EFI_SUCCESS, gop->SetMode ( gop, mode_num ) );
	}
	return EFI_SUCCESS;
}

UINT32* pixelAddr ( UINTN x, UINTN y )
{
	return ( UINT32* ) gop->Mode->FrameBufferBase + ( x + DESIRED_HREZ * y );
}

void drawLine ( int x0, int y0, int x1, int y1, UINT32 color )
{
	// Yeah, this is ugly, feel free to redo.
	for ( int i = 0; i < 100; i++ ) {
		int x = x0 + ( ( x1 - x0 ) * i ) / 100;
		int y = y0 + ( ( y1 - y0 ) * i ) / 100;
		*pixelAddr ( x, y ) = color;
	}
}

void printLnThroughGraphics()
{
	COL = 0;
	ROW++;
}

#define DIGIT_WIDTH 20
#define DIGIT_HEIGHT 40
#define DIGIT_MARGIN 3
void printHexDigitThroughGraphics ( UINT8 digit )
{
	UINTN xs = COL * DIGIT_WIDTH + DIGIT_MARGIN;
	UINTN ys = ROW * DIGIT_HEIGHT + DIGIT_MARGIN;
	UINTN xe = ( COL + 1 ) * DIGIT_WIDTH - DIGIT_MARGIN;
	UINTN ye = ( ROW + 1 ) * DIGIT_HEIGHT - DIGIT_MARGIN;
	UINTN xc = ( xs + xe ) / 2;
	UINTN yc = ( ys + ye ) / 2;
	UINT32 color = 0x00ffffff;

	switch ( digit ) {
		case 0x0:
			drawLine ( xs, ys, xe, ys, color );
			drawLine ( xe, ys, xe, ye, color );
			drawLine ( xs, ye, xe, ye, color );
			drawLine ( xs, ys, xs, ye, color );
			break;

		case 0x1:
			drawLine ( xc, ys, xc, ye, color );
			break;

		case 0x2:
			drawLine ( xs, ys, xe, ys, color );
			drawLine ( xe, ys, xs, ye, color );
			drawLine ( xs, ye, xe, ye, color );
			break;

		case 0x3:
			drawLine ( xe, ys, xe, ye, color );
			drawLine ( xs, ys, xe, ys, color );
			drawLine ( xs, yc, xe, yc, color );
			drawLine ( xs, ye, xe, ye, color );
			break;

		case 0x4:
			drawLine ( xe, ye, xe, ys, color );
			drawLine ( xe, ys, xs, yc, color );
			drawLine ( xs, yc, xe, yc, color );
			break;

		case 0x5:
			drawLine ( xe, ys, xs, ys, color );
			drawLine ( xs, ys, xs, yc, color );
			drawLine ( xs, yc, xe, yc, color );
			drawLine ( xe, yc, xe, ye, color );
			drawLine ( xe, ye, xs, ye, color );
			break;

		case 0x6:
			drawLine ( xe, ys, xs, ys, color );
			drawLine ( xs, ys, xs, ye, color );
			drawLine ( xs, yc, xe, yc, color );
			drawLine ( xe, yc, xe, ye, color );
			drawLine ( xe, ye, xs, ye, color );
			break;

		case 0x7:
			drawLine ( xs, ys, xe, ys, color );
			drawLine ( xe, ys, xs, ye, color );
			break;

		case 0x8:
			drawLine ( xs, ys, xe, ys, color );
			drawLine ( xe, ys, xe, ye, color );
			drawLine ( xs, ye, xe, ye, color );
			drawLine ( xs, ys, xs, ye, color );
			drawLine ( xs, yc, xe, yc, color );
			break;

		case 0x9:
			drawLine ( xe, ys, xe, ye, color );
			drawLine ( xs, ye, xe, ye, color );
			drawLine ( xs, ys, xe, ys, color );
			drawLine ( xs, yc, xe, yc, color );
			drawLine ( xs, ys, xs, yc, color );
			break;

		case 0xa:
			drawLine ( xc, ys, xs, ye, color );
			drawLine ( xc, ys, xe, ye, color );
			drawLine ( ( xs + xc ) / 2, yc, ( xe + xc ) / 2, yc, color );
			break;

		case 0xb:
			drawLine ( xs, ys, xs, ye, color );
			drawLine ( xs, ys, xe, ( ys + yc ) / 2, color );
			drawLine ( xe, ( ys + yc ) / 2, xs, yc, color );
			drawLine ( xs, yc, xe, ( ye + yc ) / 2, color );
			drawLine ( xe, ( ye + yc ) / 2, xs, ye, color );
			break;

		case 0xc:
			drawLine ( xs, ys, xe, ys, color );
			drawLine ( xs, ys, xs, ye, color );
			drawLine ( xs, ye, xe, ye, color );
			break;

		case 0xd:
			drawLine ( xs, ys, xs, ye, color );
			drawLine ( xs, ys, xe, yc, color );
			drawLine ( xe, yc, xs, ye, color );
			break;

		case 0xe:
			drawLine ( xs, ys, xs, ye, color );
			drawLine ( xs, ys, xe, ys, color );
			drawLine ( xs, yc, xe, yc, color );
			drawLine ( xs, ye, xe, ye, color );
			break;

		case 0xf:
			drawLine ( xs, ys, xs, ye, color );
			drawLine ( xs, ys, xe, ys, color );
			drawLine ( xs, yc, xe, yc, color );
			break;

		default:
			drawLine ( xs, ys, xe, ye, 0x00ff00ff );
			break;
	}

	COL++;

	if ( COL > DESIRED_HREZ / DIGIT_WIDTH ) {
		COL = 0;
		ROW++;
	}
}

void printU32ThroughGraphics ( UINT32 u )
{
	for ( int digit = 7; digit >= 0; digit-- ) {
		UINT8 value = ( u >> ( 4 *  digit ) ) & 0x0f;
		printHexDigitThroughGraphics ( value );
	}

	printLnThroughGraphics();
}
