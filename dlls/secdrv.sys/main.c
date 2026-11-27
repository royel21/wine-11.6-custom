/*
 * Fake Macrovision SafeDisc driver (secdrv.sys)
 *
 * Answers the SafeDisc driver requests in place of the real driver, which
 * needs ring 0 and cannot run under Wine.
 *
 * The request handling is ported from SafeDiscShim:
 *   https://github.com/RibShark/SafeDiscShim
 *   Copyright 2024 RibShark
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <https://www.gnu.org/licenses>.
 *
 * Additional permission under GNU GPL version 3 section 7 (from
 * SafeDiscShim): if you modify this Program, or any covered work, by linking
 * or combining it with software containing any version of SafeDisc as
 * originally authored by Macrovision Solutions Corporation, the licensors
 * of this Program grant you additional permission to convey the resulting
 * work.
 */

#include <stdarg.h>

#include "ntstatus.h"
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "winioctl.h"
#include "ddk/wdm.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(secdrv);

#define IOCTL_SECDRV_MAIN      0xef002407
#define IOCTL_SECDRV_UNKNOWN   0xca002813

/* later SafeDisc versions pass a larger output buffer than they use */
#define SECDRV_LARGE_OUT_SIZE  0xc18

enum secdrv_command
{
    SECDRV_GET_DEBUG_REGISTER_INFO = 0x3c,
    SECDRV_GET_IDT_INFO            = 0x3d,
    SECDRV_SETUP_VERIFICATION      = 0x3e,
    SECDRV_COMMAND_3F              = 0x3f,
    SECDRV_COMMAND_40              = 0x40,
    SECDRV_COMMAND_41              = 0x41,
    SECDRV_COMMAND_42              = 0x42,
    SECDRV_COMMAND_43              = 0x43,
};

struct secdrv_in
{
    DWORD version_major;
    DWORD version_minor;
    DWORD version_patch;
    DWORD command;
    DWORD verification_data[0x100];
    DWORD extra_data_size;
    DWORD extra_data[0x40];
};

struct secdrv_out
{
    DWORD version_major;
    DWORD version_minor;
    DWORD version_patch;
    DWORD verification_data[0x100];
    DWORD extra_data_size;
    DWORD extra_data[0x80];
};

static DEVICE_OBJECT *secdrv_device;
static UNICODE_STRING secdrv_link = RTL_CONSTANT_STRING( L"\\DosDevices\\Secdrv" );

static void build_verification_data( DWORD *data )
{
    const KUSER_SHARED_DATA *shared = (const KUSER_SHARED_DATA *)0x7ffe0000;
    DWORD value = 0xf367ac7f;
    int i;

    /* SafeDisc compares this against the tick count it reads itself */
    data[0] = shared->TickCount.LowPart;

    for (i = 3; i > 0; i--)
    {
        value = 0x361962e9 - 0xd5acb1b * value;
        data[i] = value;
        data[0] ^= value;
    }
}

static BOOL process_main_ioctl( const struct secdrv_in *in, ULONG in_size,
                                struct secdrv_out *out, ULONG out_size )
{
    static BOOL version_logged;

    if (!in || !out)
    {
        WARN( "invalid buffers %p %p\n", in, out );
        return FALSE;
    }
    if (in_size != sizeof(*in))
    {
        WARN( "invalid input size %#lx\n", in_size );
        return FALSE;
    }
    if (out_size != sizeof(*out) && out_size != SECDRV_LARGE_OUT_SIZE)
    {
        WARN( "invalid output size %#lx\n", out_size );
        return FALSE;
    }

    if (!version_logged)
    {
        TRACE( "SafeDisc request version %lu.%02lu.%03lu\n",
               in->version_major, in->version_minor, in->version_patch );
        version_logged = TRUE;
    }

    /* report the latest driver version */
    out->version_major = 4;
    out->version_minor = 3;
    out->version_patch = 86;

    /* the latest driver returns these fixed values */
    switch (in->command)
    {
    case SECDRV_GET_DEBUG_REGISTER_INFO:
        out->extra_data_size = 4;
        out->extra_data[0] = 0x400;
        break;
    case SECDRV_GET_IDT_INFO:
        out->extra_data_size = 4;
        out->extra_data[0] = 0x2c8;
        break;
    case SECDRV_SETUP_VERIFICATION:
        out->extra_data_size = 4;
        out->extra_data[0] = 0x5278d11b;
        break;
    case SECDRV_COMMAND_3F:
        if (out_size != SECDRV_LARGE_OUT_SIZE || in->extra_data[0] > 0x60) return FALSE;
        out->extra_data_size = 4;
        out->extra_data[0] = 0;
        break;
    case SECDRV_COMMAND_40:
        if (out_size != SECDRV_LARGE_OUT_SIZE || !in->extra_data[0] || !in->extra_data[1])
            return FALSE;
        out->extra_data_size = 4;
        out->extra_data[0] = in->extra_data[1] <= 0x80 ? 0x56791283 : 0x587c1284;
        break;
    case SECDRV_COMMAND_41:
        if (out_size != SECDRV_LARGE_OUT_SIZE || !LOBYTE(in->extra_data[0])) return FALSE;
        out->extra_data_size = 4;
        break;
    case SECDRV_COMMAND_42:
        return FALSE;
    case SECDRV_COMMAND_43:
        if (in->extra_data[0] != 0x98a64100 || in->extra_data[1] > 7 || in->extra_data[1] == 4)
            return FALSE;
        out->extra_data_size = 4;
        out->extra_data[0] = 0;
        break;
    default:
        FIXME( "unhandled command %#lx\n", in->command );
        return FALSE;
    }

    TRACE( "command %#lx handled\n", in->command );
    build_verification_data( out->verification_data );
    return TRUE;
}

static NTSTATUS WINAPI dispatch_create_close( DEVICE_OBJECT *device, IRP *irp )
{
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest( irp, IO_NO_INCREMENT );
    return STATUS_SUCCESS;
}

static NTSTATUS WINAPI dispatch_ioctl( DEVICE_OBJECT *device, IRP *irp )
{
    IO_STACK_LOCATION *stack = IoGetCurrentIrpStackLocation( irp );
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG in_size = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG out_size = stack->Parameters.DeviceIoControl.OutputBufferLength;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    irp->IoStatus.Information = 0;

    switch (code)
    {
    case IOCTL_SECDRV_MAIN:
        /* METHOD_NEITHER */
        if (process_main_ioctl( stack->Parameters.DeviceIoControl.Type3InputBuffer, in_size,
                                irp->UserBuffer, out_size ))
        {
            irp->IoStatus.Information = out_size;
            status = STATUS_SUCCESS;
        }
        break;
    case IOCTL_SECDRV_UNKNOWN:
        FIXME( "ioctl %#lx not implemented\n", code );
        break;
    default:
        FIXME( "unknown ioctl %#lx\n", code );
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    irp->IoStatus.Status = status;
    IoCompleteRequest( irp, IO_NO_INCREMENT );
    return status;
}

static void WINAPI driver_unload( DRIVER_OBJECT *driver )
{
    TRACE( "(%p)\n", driver );

    IoDeleteSymbolicLink( &secdrv_link );
    IoDeleteDevice( secdrv_device );
}

NTSTATUS WINAPI DriverEntry( DRIVER_OBJECT *driver, UNICODE_STRING *path )
{
    UNICODE_STRING name = RTL_CONSTANT_STRING( L"\\Device\\Secdrv" );
    NTSTATUS status;

    TRACE( "(%p, %s)\n", driver, debugstr_w(path->Buffer) );

    if ((status = IoCreateDevice( driver, 0, &name, FILE_DEVICE_UNKNOWN, 0, FALSE, &secdrv_device )))
    {
        ERR( "failed to create device, status %#lx\n", status );
        return status;
    }

    if ((status = IoCreateSymbolicLink( &secdrv_link, &name )))
    {
        ERR( "failed to create symbolic link, status %#lx\n", status );
        IoDeleteDevice( secdrv_device );
        return status;
    }

    driver->MajorFunction[IRP_MJ_CREATE] = dispatch_create_close;
    driver->MajorFunction[IRP_MJ_CLOSE] = dispatch_create_close;
    driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = dispatch_ioctl;
    driver->DriverUnload = driver_unload;

    return STATUS_SUCCESS;
}
