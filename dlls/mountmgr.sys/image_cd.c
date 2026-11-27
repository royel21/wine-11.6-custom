/*
 * CD requests answered from the disc image loaded in the Winlator file manager
 *
 * The drive the file manager loads images into is a plain folder, so requests that need
 * the disc itself (table of contents, geometry, raw audio sectors) are answered from the
 * image the same way mcicda plays its audio.
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "parser.h"
#include "winternl.h"
#include "winioctl.h"
#include "ntddcdrm.h"

/* not in Wine's ntddcdrm.h yet, values from the Windows SDK */
#ifndef IOCTL_CDROM_GET_DRIVE_GEOMETRY_EX
#define IOCTL_CDROM_GET_DRIVE_GEOMETRY_EX CTL_CODE(IOCTL_CDROM_BASE, 0x0014, METHOD_BUFFERED, FILE_READ_ACCESS)
#endif
#ifndef IOCTL_CDROM_READ_TOC_EX
#define IOCTL_CDROM_READ_TOC_EX CTL_CODE(IOCTL_CDROM_BASE, 0x0015, METHOD_BUFFERED, FILE_READ_ACCESS)

#define CDROM_READ_TOC_EX_FORMAT_TOC     0x00
#define CDROM_READ_TOC_EX_FORMAT_SESSION 0x01

typedef struct _CDROM_READ_TOC_EX {
    UCHAR Format : 4;
    UCHAR Reserved1 : 3;
    UCHAR Msf : 1;
    UCHAR SessionTrack;
    UCHAR Reserved2;
    UCHAR Reserved3;
} CDROM_READ_TOC_EX;

typedef struct _CDROM_TOC_SESSION_DATA {
    UCHAR Length[2];
    UCHAR FirstCompleteSession;
    UCHAR LastCompleteSession;
    TRACK_DATA TrackData[1];
} CDROM_TOC_SESSION_DATA;
#endif

#include "ntddscsi.h"

#include "image_cd.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(mountmgr);
WINE_DECLARE_DEBUG_CHANNEL(cdimage);

#define RAW_SECTOR_SIZE 2352

static VirtualCD disc;
static WCHAR disc_path[MAX_PATH];
static BOOL disc_loaded;

/* the image file sectors are read from, kept open between requests */
struct image_file
{
    FILE *file;
    const WCHAR *path;
};

static struct image_file image_file;

static void close_image_file(void)
{
    if (image_file.file) fclose( image_file.file );
    image_file.file = NULL;
    image_file.path = NULL;
}

/* parse the image again only when the file manager loads another one */
static BOOL refresh_disc(void)
{
    WCHAR path[MAX_PATH] = {0};

    if (!GetCurrentDiscPath( path, MAX_PATH ) || !path[0])
    {
        close_image_file();
        disc_path[0] = 0;
        disc_loaded = FALSE;
        return FALSE;
    }
    if (!wcscmp( path, disc_path )) return disc_loaded;

    close_image_file();
    lstrcpynW( disc_path, path, MAX_PATH );
    disc_loaded = LoadCurrentDisc( &disc ) && disc.trackCount > 0;
    if (disc_loaded) TRACE_(cdimage)( "loaded %s, %d tracks\n", debugstr_w(path), disc.trackCount );
    else WARN( "can't parse disc image %s\n", debugstr_w(path) );
    return disc_loaded;
}

static LONG disc_end(void)
{
    return disc.tracks[disc.trackCount - 1].endLBA;
}

/* TOC addresses: MSF counts the 2 second lead-in, LBA is big-endian */
static void fill_address( UCHAR *address, LONG lba, BOOL msf )
{
    if (msf)
    {
        lba += 150;
        address[0] = 0;
        address[1] = lba / (60 * 75);
        address[2] = (lba / 75) % 60;
        address[3] = lba % 75;
    }
    else
    {
        address[0] = (lba >> 24) & 0xff;
        address[1] = (lba >> 16) & 0xff;
        address[2] = (lba >> 8) & 0xff;
        address[3] = lba & 0xff;
    }
}

static void fill_track( TRACK_DATA *data, int index, BOOL msf )
{
    BOOL leadout = index == disc.trackCount;
    const CDTrack *track = &disc.tracks[leadout ? index - 1 : index];

    memset( data, 0, sizeof(*data) );
    data->Adr = 1;
    data->Control = track->isAudio ? 0 : 4;
    data->TrackNumber = leadout ? 0xaa : track->trackNumber;
    fill_address( data->Address, leadout ? disc_end() : track->startLBA, msf );
}

static ULONG fill_toc( CDROM_TOC *toc, BOOL msf )
{
    ULONG size = FIELD_OFFSET( CDROM_TOC, TrackData[disc.trackCount + 1] );
    int i;

    memset( toc, 0, sizeof(*toc) );
    toc->Length[0] = (size - 2) >> 8;
    toc->Length[1] = (size - 2) & 0xff;
    toc->FirstTrack = disc.tracks[0].trackNumber;
    toc->LastTrack = disc.tracks[disc.trackCount - 1].trackNumber;
    for (i = 0; i <= disc.trackCount; i++) fill_track( &toc->TrackData[i], i, msf );
    return size;
}

/* the parser keeps no session numbers: report one session starting at the first track */
static ULONG fill_session( CDROM_TOC_SESSION_DATA *session, BOOL msf )
{
    ULONG size = sizeof(*session);

    memset( session, 0, size );
    session->Length[0] = (size - 2) >> 8;
    session->Length[1] = (size - 2) & 0xff;
    session->FirstCompleteSession = 1;
    session->LastCompleteSession = 1;
    fill_track( &session->TrackData[0], 0, msf );
    return size;
}

/* the same geometry Windows' cdrom.sys reports: 64 tracks of 32 sectors per cylinder */
static void fill_geometry( DISK_GEOMETRY *geometry )
{
    geometry->Cylinders.QuadPart = (disc_end() + 64 * 32 - 1) / (64 * 32);
    geometry->MediaType = RemovableMedia;
    geometry->TracksPerCylinder = 64;
    geometry->SectorsPerTrack = 32;
    geometry->BytesPerSector = 2048;
}

static NTSTATUS raw_read( const RAW_READ_INFO *request, void *out, ULONG out_len, ULONG_PTR *info )
{
    LONG lba = (LONG)(request->DiskOffset.QuadPart / 2048);
    const WCHAR *open_path = NULL;
    BYTE *buffer = out;
    FILE *file = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG i;
    int t;

    if ((ULONGLONG)request->SectorCount * RAW_SECTOR_SIZE > out_len) return STATUS_BUFFER_TOO_SMALL;

    for (i = 0; i < request->SectorCount; i++, lba++)
    {
        const CDTrack *track = NULL;

        for (t = 0; t < disc.trackCount; t++)
        {
            if (lba >= disc.tracks[t].startLBA && lba < disc.tracks[t].endLBA)
            {
                track = &disc.tracks[t];
                break;
            }
        }

        /* cooked 2048 byte images hold no raw sectors to return */
        if (!track || track->sectorSize < RAW_SECTOR_SIZE)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (!open_path || wcscmp( open_path, track->filePath ))
        {
            if (file) fclose( file );
            open_path = track->filePath;
            if (!(file = _wfopen( open_path, L"rb" )))
            {
                status = STATUS_DEVICE_DATA_ERROR;
                break;
            }
        }

        if (_fseeki64( file, track->fileOffset + (ULONGLONG)(lba - track->startLBA) * track->sectorSize, SEEK_SET ) ||
            fread( buffer, 1, RAW_SECTOR_SIZE, file ) != RAW_SECTOR_SIZE)
        {
            status = STATUS_DEVICE_DATA_ERROR;
            break;
        }
        buffer += RAW_SECTOR_SIZE;
    }

    if (file) fclose( file );
    *info = buffer - (BYTE *)out;
    TRACE_(cdimage)( "raw read lba %ld count %lu mode %u -> %#lx\n", (LONG)(request->DiskOffset.QuadPart / 2048),
                     request->SectorCount, request->TrackMode, status );
    return status;
}

/* where the user data starts in a sector of a track */
static ULONG data_offset( const CDTrack *track )
{
    if (track->sectorSize == 2048) return 0;
    if (!strncmp( track->mode, "MODE2", 5 )) return track->sectorSize == 2336 ? 8 : 24;
    return 16;
}

static int from_bcd( BYTE b )
{
    return (b >> 4) * 10 + (b & 15);
}

/* Some protected discs repeat a range of sector addresses, so their raw image holds
 * more sectors than addresses and the sectors after the repeated range are not at
 * their address. Raw sectors carry their address in the header; follow it to the
 * sector that really has the requested address. */
static LONGLONG sector_index( FILE *file, const CDTrack *track, LONG lba )
{
    static const BYTE sync[12] = {0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0};
    LONGLONG index = lba - track->startLBA;
    BYTE header[16];
    int tries;

    if (track->sectorSize < RAW_SECTOR_SIZE) return lba - track->startLBA;

    for (tries = 0; tries < 4 && index >= 0; tries++)
    {
        LONG found;

        if (_fseeki64( file, track->fileOffset + index * track->sectorSize, SEEK_SET ) ||
            fread( header, 1, sizeof(header), file ) != sizeof(header) ||
            memcmp( header, sync, sizeof(sync) ))
            break;
        found = (from_bcd( header[12] ) * 60 + from_bcd( header[13] )) * 75 + from_bcd( header[14] ) - 150;
        if (found == lba) return index;
        index += lba - found;
    }
    return lba - track->startLBA;
}

/* SCSI pass-through: MMC commands answered from the image
 *
 * Copy protections such as SafeDisc send their commands straight to the drive. Their
 * discs carry data sectors written with a wrong EDC on purpose; a drive reports a read
 * error for those on a normal read and returns them as they are on a raw read. Raw
 * images keep the wrong EDC, so the same is done here. */

/* the layout 32-bit callers use, told apart by its Length */
typedef struct
{
    USHORT Length;
    UCHAR  ScsiStatus;
    UCHAR  PathId;
    UCHAR  TargetId;
    UCHAR  Lun;
    UCHAR  CdbLength;
    UCHAR  SenseInfoLength;
    UCHAR  DataIn;
    ULONG  DataTransferLength;
    ULONG  TimeOutValue;
    ULONG  DataBufferOffset;
    ULONG  SenseInfoOffset;
    UCHAR  Cdb[16];
} SCSI_PASS_THROUGH32;

#define SCSI_STATUS_GOOD            0x00
#define SCSI_STATUS_CHECK_CONDITION 0x02

#define SENSE_NOT_READY       0x02
#define SENSE_MEDIUM_ERROR    0x03
#define SENSE_ILLEGAL_REQUEST 0x05

#define SENSE_SIZE 18

struct scsi_result
{
    UCHAR key, asc, ascq;
    ULONG len;  /* bytes of data returned */
};

static BYTE last_sense[SENSE_SIZE];

static void set_sense( struct scsi_result *result, UCHAR key, UCHAR asc, UCHAR ascq )
{
    result->key = key;
    result->asc = asc;
    result->ascq = ascq;
}

static void put_be16( BYTE *p, ULONG v )
{
    p[0] = v >> 8;
    p[1] = v;
}

static void put_be32( BYTE *p, ULONG v )
{
    p[0] = v >> 24;
    p[1] = v >> 16;
    p[2] = v >> 8;
    p[3] = v;
}

static ULONG get_be16( const BYTE *p )
{
    return (p[0] << 8) | p[1];
}

static ULONG get_be24( const BYTE *p )
{
    return (p[0] << 16) | (p[1] << 8) | p[2];
}

static ULONG get_be32( const BYTE *p )
{
    return ((ULONG)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

static void put_msf( BYTE *p, LONG lba )
{
    lba += 150;
    p[0] = lba / (60 * 75);
    p[1] = (lba / 75) % 60;
    p[2] = lba % 75;
}

static const CDTrack *find_track( LONG lba )
{
    int t;

    for (t = 0; t < disc.trackCount; t++)
        if (lba >= disc.tracks[t].startLBA && lba < disc.tracks[t].endLBA) return &disc.tracks[t];
    return NULL;
}

static BOOL is_mode2( const CDTrack *track )
{
    return !strncmp( track->mode, "MODE2", 5 );
}


/* reads the sector as the image stores it: 2352 raw bytes, or 2048 for cooked images */
static BOOL read_sector( struct image_file *image, const CDTrack *track, LONG lba, BYTE *sector )
{
    ULONG size = min( track->sectorSize, RAW_SECTOR_SIZE );

    if (!image->file || wcscmp( image->path, track->filePath ))
    {
        if (image->file) fclose( image->file );
        image->path = track->filePath;
        if (!(image->file = _wfopen( image->path, L"rb" ))) return FALSE;
    }
    return !_fseeki64( image->file, track->fileOffset + sector_index( image->file, track, lba ) * track->sectorSize,
                       SEEK_SET ) &&
           fread( sector, 1, size, image->file ) == size;
}

static DWORD edc_table[256];

static DWORD compute_edc( const BYTE *data, ULONG len )
{
    DWORD edc = 0;

    if (!edc_table[1])
    {
        DWORD i, j, v;

        for (i = 0; i < 256; i++)
        {
            for (v = i, j = 0; j < 8; j++) v = (v >> 1) ^ (v & 1 ? 0xd8018001 : 0);
            edc_table[i] = v;
        }
    }
    while (len--) edc = (edc >> 8) ^ edc_table[(edc ^ *data++) & 0xff];
    return edc;
}

static DWORD stored_edc( const BYTE *p )
{
    return p[0] | (p[1] << 8) | (p[2] << 16) | ((DWORD)p[3] << 24);
}

/* data sectors whose EDC does not match, the ones a drive fails to read */
static BOOL is_weak_sector( const CDTrack *track, const BYTE *sector )
{
    if (track->isAudio || track->sectorSize < RAW_SECTOR_SIZE) return FALSE;

    switch (sector[15])
    {
    case 1:
        return compute_edc( sector, 2064 ) != stored_edc( sector + 2064 );
    case 2:
        if (sector[18] & 0x20)  /* form 2, the EDC is optional */
            return stored_edc( sector + 2348 ) && compute_edc( sector + 16, 2332 ) != stored_edc( sector + 2348 );
        return compute_edc( sector + 16, 2056 ) != stored_edc( sector + 2072 );
    }
    return FALSE;
}

/* READ(10) and READ(12): the 2048 bytes of user data of each sector */
static void scsi_read( LONG lba, ULONG count, BYTE *data, ULONG data_len, struct scsi_result *result )
{
    BYTE sector[RAW_SECTOR_SIZE];
    ULONG i;

    for (i = 0; i < count; i++, lba++)
    {
        const CDTrack *track = find_track( lba );

        if (!track)
        {
            set_sense( result, SENSE_ILLEGAL_REQUEST, 0x21, 0x00 );  /* LBA out of range */
            break;
        }
        if (track->isAudio)
        {
            set_sense( result, SENSE_ILLEGAL_REQUEST, 0x64, 0x00 );  /* illegal mode for this track */
            break;
        }
        if (result->len + 2048 > data_len)
        {
            set_sense( result, SENSE_ILLEGAL_REQUEST, 0x24, 0x00 );
            break;
        }
        if (!read_sector( &image_file, track, lba, sector ))
        {
            set_sense( result, SENSE_MEDIUM_ERROR, 0x11, 0x00 );
            break;
        }
        if (is_weak_sector( track, sector ))
        {
            TRACE_(cdimage)( "sector %ld has a wrong EDC, reporting a read error\n", lba );
            set_sense( result, SENSE_MEDIUM_ERROR, 0x11, 0x05 );  /* L-EC uncorrectable error */
            break;
        }
        memcpy( data + result->len, sector + data_offset( track ), 2048 );
        result->len += 2048;
    }
}

/* READ CD: the fields of each sector the caller selected */
static void scsi_read_cd( const BYTE *cdb, BYTE *data, ULONG data_len, struct scsi_result *result )
{
    static BOOL warned_subchannel;
    BYTE sector[RAW_SECTOR_SIZE];
    LONG lba = get_be32( cdb + 2 );
    ULONG count = get_be24( cdb + 6 ), i;
    UCHAR type = (cdb[1] >> 2) & 7, flags = cdb[9], subchannel = cdb[10] & 7;
    ULONG c2_size = (flags & 6) == 2 ? 294 : (flags & 6) == 4 ? 296 : 0;
    ULONG sub_size = subchannel == 2 ? 16 : subchannel ? 96 : 0;

    for (i = 0; i < count; i++, lba++)
    {
        const CDTrack *track = find_track( lba );
        ULONG start[4], end[4], fields = 0, size = 0, f;

        if (!track)
        {
            set_sense( result, SENSE_ILLEGAL_REQUEST, 0x21, 0x00 );
            break;
        }
        if ((type == 1 && !track->isAudio) || (type > 1 && track->isAudio))
        {
            set_sense( result, SENSE_ILLEGAL_REQUEST, 0x64, 0x00 );
            break;
        }
        if (!read_sector( &image_file, track, lba, sector ))
        {
            set_sense( result, SENSE_MEDIUM_ERROR, 0x11, 0x00 );
            break;
        }

        if (track->isAudio)
        {
            if (flags & 0xf8)
            {
                start[fields] = 0;
                end[fields++] = RAW_SECTOR_SIZE;
            }
        }
        else if (track->sectorSize < RAW_SECTOR_SIZE)
        {
            if (flags & 0xe8)
            {
                FIXME_(cdimage)( "READ CD flags %#x need a raw image\n", flags );
                set_sense( result, SENSE_ILLEGAL_REQUEST, 0x24, 0x00 );
                break;
            }
            if (flags & 0x10)
            {
                start[fields] = 0;
                end[fields++] = 2048;
            }
        }
        else
        {
            BOOL mode2 = sector[15] == 2, form2 = mode2 && (sector[18] & 0x20);
            ULONG user_start = mode2 ? 24 : 16;
            ULONG user_end = !mode2 ? 2064 : form2 ? 2348 : 2072;

            /* mode 2 without the sub-header selected: user data starts after the header */
            if (mode2 && type == 3) user_start = 16, user_end = RAW_SECTOR_SIZE;

            if (is_weak_sector( track, sector ) && (flags & 0x10) && !(flags & 0x08))
            {
                TRACE_(cdimage)( "sector %ld has a wrong EDC, reporting a read error\n", lba );
                set_sense( result, SENSE_MEDIUM_ERROR, 0x11, 0x05 );
                break;
            }
            if (flags & 0x80)
            {
                start[fields] = 0;
                end[fields++] = 12;
            }
            if (flags & 0x60)
            {
                start[fields] = (flags & 0x20) ? 12 : 16;
                end[fields++] = (flags & 0x40) && mode2 ? 24 : 16;
            }
            if (flags & 0x10)
            {
                start[fields] = user_start;
                end[fields++] = user_end;
            }
            if ((flags & 0x08) && user_end < RAW_SECTOR_SIZE)
            {
                start[fields] = user_end;
                end[fields++] = RAW_SECTOR_SIZE;
            }
        }

        for (f = 0; f < fields; f++) size += end[f] - start[f];
        if (result->len + size + c2_size + sub_size > data_len)
        {
            set_sense( result, SENSE_ILLEGAL_REQUEST, 0x24, 0x00 );
            break;
        }
        for (f = 0; f < fields; f++)
        {
            memcpy( data + result->len, sector + start[f], end[f] - start[f] );
            result->len += end[f] - start[f];
        }
        /* the image holds no C2 errors and no sub-channel data */
        if (sub_size && !warned_subchannel)
        {
            FIXME_(cdimage)( "sub-channel %u not available, returning zeros\n", subchannel );
            warned_subchannel = TRUE;
        }
        memset( data + result->len, 0, c2_size + sub_size );
        result->len += c2_size + sub_size;
    }
}

static void scsi_read_toc( const BYTE *cdb, BYTE *reply, struct scsi_result *result )
{
    BOOL msf = cdb[1] & 2;
    UCHAR format = cdb[2] & 0x0f, first = cdb[6];
    BYTE *p = reply + 4;
    int i;

    if (!format && (cdb[9] >> 6)) format = cdb[9] >> 6;

    switch (format)
    {
    case 0:  /* TOC */
        for (i = 0; i <= disc.trackCount; i++)
        {
            BOOL leadout = i == disc.trackCount;
            const CDTrack *track = &disc.tracks[leadout ? i - 1 : i];
            UCHAR number = leadout ? 0xaa : track->trackNumber;

            if (first && first != 0xaa && number < first) continue;
            if (first == 0xaa && !leadout) continue;
            p[0] = 0;
            p[1] = 0x10 | (track->isAudio ? 0 : 4);
            p[2] = number;
            p[3] = 0;
            fill_address( p + 4, leadout ? disc_end() : track->startLBA, msf );
            p += 8;
        }
        if (p == reply + 4)
        {
            set_sense( result, SENSE_ILLEGAL_REQUEST, 0x24, 0x00 );
            return;
        }
        reply[2] = disc.tracks[0].trackNumber;
        reply[3] = disc.tracks[disc.trackCount - 1].trackNumber;
        break;
    case 1:  /* session info: one session starting at the first track */
        p[0] = 0;
        p[1] = 0x10 | (disc.tracks[0].isAudio ? 0 : 4);
        p[2] = disc.tracks[0].trackNumber;
        p[3] = 0;
        fill_address( p + 4, disc.tracks[0].startLBA, msf );
        p += 8;
        reply[2] = reply[3] = 1;
        break;
    case 2:  /* full TOC: the A0, A1 and A2 points, then the tracks */
    {
        const CDTrack *last = &disc.tracks[disc.trackCount - 1];
        UCHAR disc_type = is_mode2( &disc.tracks[0] ) ? 0x20 : 0x00;

        for (i = -3; i < disc.trackCount; i++)
        {
            const CDTrack *track = i == -3 ? &disc.tracks[0] : i < 0 ? last : &disc.tracks[i];

            memset( p, 0, 11 );
            p[0] = 1;
            p[1] = 0x10 | (track->isAudio ? 0 : 4);
            switch (i)
            {
            case -3: p[3] = 0xa0; p[8] = disc.tracks[0].trackNumber; p[9] = disc_type; break;
            case -2: p[3] = 0xa1; p[8] = last->trackNumber; break;
            case -1: p[3] = 0xa2; put_msf( p + 8, disc_end() ); break;
            default: p[3] = track->trackNumber; put_msf( p + 8, track->startLBA ); break;
            }
            p += 11;
        }
        reply[2] = reply[3] = 1;
        break;
    }
    default:
        FIXME_(cdimage)( "READ TOC format %u not supported\n", format );
        set_sense( result, SENSE_ILLEGAL_REQUEST, 0x24, 0x00 );
        return;
    }
    put_be16( reply, p - reply - 2 );
    result->len = p - reply;
}

static void scsi_mode_sense( const BYTE *cdb, BOOL ten, BYTE *reply, struct scsi_result *result )
{
    UCHAR page = cdb[2] & 0x3f;
    ULONG header = ten ? 8 : 4;
    BYTE *p = reply + header;

    if (page == 0x2a || page == 0x3f)
    {
        /* capabilities: reads CD-R/RW and CD-DA, 40x */
        memset( p, 0, 28 );
        p[0] = 0x2a;
        p[1] = 26;
        p[2] = 0x03;
        p[5] = 0x03;
        put_be16( p + 8, 7056 );
        put_be16( p + 14, 7056 );
        p += 28;
    }
    else if (page)
    {
        set_sense( result, SENSE_ILLEGAL_REQUEST, 0x24, 0x00 );
        return;
    }
    if (ten) put_be16( reply, p - reply - 2 );
    else reply[0] = p - reply - 1;
    result->len = p - reply;
}

#define INQUIRY_SIZE 36

static void fill_inquiry( BYTE *inquiry )
{
    memset( inquiry, 0, INQUIRY_SIZE );
    inquiry[0] = 0x05;  /* CD/DVD device */
    inquiry[1] = 0x80;  /* removable */
    inquiry[2] = 0x05;
    inquiry[3] = 0x02;
    inquiry[4] = INQUIRY_SIZE - 5;
    memcpy( inquiry + 8, IMAGE_CD_IDENTIFIER, 28 );
}

/* one bus with the drive at the address IOCTL_SCSI_GET_ADDRESS reports */
static NTSTATUS get_inquiry_data( BYTE *out, ULONG out_len, ULONG_PTR *info )
{
    ULONG offset = (sizeof(SCSI_ADAPTER_BUS_INFO) + 3) & ~3;
    ULONG size = offset + FIELD_OFFSET( SCSI_INQUIRY_DATA, InquiryData[INQUIRY_SIZE] );
    SCSI_ADAPTER_BUS_INFO *bus = (SCSI_ADAPTER_BUS_INFO *)out;
    SCSI_INQUIRY_DATA *unit = (SCSI_INQUIRY_DATA *)(out + offset);

    if (out_len < size) return STATUS_BUFFER_TOO_SMALL;

    memset( out, 0, size );
    bus->NumberOfBuses = 1;
    bus->BusData[0].NumberOfLogicalUnits = 1;
    bus->BusData[0].InitiatorBusId = IMAGE_CD_INITIATOR_ID;
    bus->BusData[0].InquiryDataOffset = offset;
    unit->DeviceClaimed = TRUE;
    unit->InquiryDataLength = INQUIRY_SIZE;
    unit->NextInquiryDataOffset = 0;
    fill_inquiry( unit->InquiryData );
    *info = size;
    return STATUS_SUCCESS;
}

static void scsi_command( const BYTE *cdb, BYTE *data, ULONG data_len, struct scsi_result *result )
{
    BYTE reply[512];
    BOOL use_reply = FALSE;

    memset( reply, 0, sizeof(reply) );

    switch (cdb[0])
    {
    case 0x00:  /* TEST UNIT READY */
    case 0x1b:  /* START STOP UNIT */
    case 0x1e:  /* PREVENT ALLOW MEDIUM REMOVAL */
    case 0x2b:  /* SEEK */
    case 0x35:  /* SYNCHRONIZE CACHE */
    case 0xbb:  /* SET CD SPEED */
    case 0xa7:  /* SET READ AHEAD */
        break;
    case 0x03:  /* REQUEST SENSE */
        memcpy( reply, last_sense, SENSE_SIZE );
        if (!reply[0]) reply[0] = 0x70, reply[7] = 10;
        result->len = SENSE_SIZE;
        use_reply = TRUE;
        break;
    case 0x12:  /* INQUIRY */
        if (cdb[1] & 1)
        {
            set_sense( result, SENSE_ILLEGAL_REQUEST, 0x24, 0x00 );
            break;
        }
        fill_inquiry( reply );
        result->len = INQUIRY_SIZE;
        use_reply = TRUE;
        break;
    case 0x25:  /* READ CAPACITY */
        put_be32( reply, disc_end() - 1 );
        put_be32( reply + 4, 2048 );
        result->len = 8;
        use_reply = TRUE;
        break;
    case 0x28:  /* READ(10) */
        scsi_read( get_be32( cdb + 2 ), get_be16( cdb + 7 ), data, data_len, result );
        break;
    case 0xa8:  /* READ(12) */
        scsi_read( get_be32( cdb + 2 ), get_be32( cdb + 6 ), data, data_len, result );
        break;
    case 0xbe:  /* READ CD */
        scsi_read_cd( cdb, data, data_len, result );
        break;
    case 0x43:  /* READ TOC/PMA/ATIP */
        scsi_read_toc( cdb, reply, result );
        use_reply = TRUE;
        break;
    case 0x1a:  /* MODE SENSE(6) */
        scsi_mode_sense( cdb, FALSE, reply, result );
        use_reply = TRUE;
        break;
    case 0x5a:  /* MODE SENSE(10) */
        scsi_mode_sense( cdb, TRUE, reply, result );
        use_reply = TRUE;
        break;
    case 0x46:  /* GET CONFIGURATION: current profile CD-ROM */
        put_be32( reply, 4 );
        put_be16( reply + 6, 0x0008 );
        result->len = 8;
        use_reply = TRUE;
        break;
    case 0x4a:  /* GET EVENT STATUS NOTIFICATION: media present */
        put_be16( reply, 6 );
        reply[2] = 4;
        reply[3] = 0x10;
        reply[5] = 0x02;
        result->len = 8;
        use_reply = TRUE;
        break;
    case 0x51:  /* READ DISC INFORMATION: one complete session */
        put_be16( reply, 32 );
        reply[2] = 0x0e;
        reply[3] = disc.tracks[0].trackNumber;
        reply[4] = 1;
        reply[5] = disc.tracks[0].trackNumber;
        reply[6] = disc.tracks[disc.trackCount - 1].trackNumber;
        reply[8] = is_mode2( &disc.tracks[0] ) ? 0x20 : 0x00;
        memset( reply + 16, 0xff, 8 );
        result->len = 34;
        use_reply = TRUE;
        break;
    case 0x42:  /* READ SUB-CHANNEL: no audio playing */
        reply[1] = 0x15;
        if (cdb[2] & 0x40)
        {
            put_be16( reply + 2, 12 );
            reply[4] = cdb[3];
            result->len = 16;
        }
        else result->len = 4;
        use_reply = TRUE;
        break;
    default:
        FIXME_(cdimage)( "SCSI command %#x not supported\n", cdb[0] );
        set_sense( result, SENSE_ILLEGAL_REQUEST, 0x20, 0x00 );  /* invalid command */
        break;
    }

    if (use_reply)
    {
        if (result->key) result->len = 0;
        result->len = min( result->len, data_len );
        if (result->len) memcpy( data, reply, result->len );
    }
}

static NTSTATUS scsi_pass_through( BYTE *buffer, ULONG in_len, ULONG out_len, ULONG_PTR *info )
{
    SCSI_PASS_THROUGH32 *spt32 = (SCSI_PASS_THROUGH32 *)buffer;
    SCSI_PASS_THROUGH *spt = (SCSI_PASS_THROUGH *)buffer;
    BOOL is32 = sizeof(void *) > 4 && in_len >= sizeof(*spt32) && spt32->Length == sizeof(*spt32);
    ULONG header = is32 ? sizeof(*spt32) : sizeof(*spt);
    ULONG_PTR data_offset;
    ULONG sense_offset, data_len, size = max( in_len, out_len ), sense_len, end;
    struct scsi_result result = {0};
    const UCHAR *cdb;
    BYTE *data = NULL;
    BYTE sense[SENSE_SIZE];

    if (in_len < header || out_len < header) return STATUS_INVALID_PARAMETER;

    data_offset = is32 ? spt32->DataBufferOffset : spt->DataBufferOffset;
    sense_offset = is32 ? spt32->SenseInfoOffset : spt->SenseInfoOffset;
    cdb = is32 ? spt32->Cdb : spt->Cdb;
    data_len = spt->DataTransferLength;
    sense_len = min( spt->SenseInfoLength, SENSE_SIZE );

    if (spt->CdbLength > 16) return STATUS_INVALID_PARAMETER;
    if (data_len)
    {
        if (data_offset > size || data_len > size - data_offset) return STATUS_INVALID_PARAMETER;
        data = buffer + data_offset;
    }
    if (sense_len && (sense_offset > out_len || sense_len > out_len - sense_offset)) sense_len = 0;

    if (spt->DataIn == SCSI_IOCTL_DATA_IN)
    {
        if (data_len && data_offset + data_len > out_len) data_len = out_len - data_offset;
        scsi_command( cdb, data, data_len, &result );
    }
    else if (cdb[0] == 0x00 || cdb[0] == 0x1b || cdb[0] == 0x1e || cdb[0] == 0x35 || cdb[0] == 0xbb ||
             cdb[0] == 0x55 /* MODE SELECT(10) */ || cdb[0] == 0x15 /* MODE SELECT(6) */)
        scsi_command( cdb, NULL, 0, &result );
    else
    {
        FIXME_(cdimage)( "SCSI command %#x writing data not supported\n", cdb[0] );
        set_sense( &result, SENSE_ILLEGAL_REQUEST, 0x20, 0x00 );
    }

    memset( sense, 0, sizeof(sense) );
    if (result.key)
    {
        sense[0] = 0x70;
        sense[2] = result.key;
        sense[7] = 10;
        sense[12] = result.asc;
        sense[13] = result.ascq;
    }
    memcpy( last_sense, sense, sizeof(sense) );

    spt->ScsiStatus = result.key ? SCSI_STATUS_CHECK_CONDITION : SCSI_STATUS_GOOD;
    spt->DataTransferLength = spt->DataIn == SCSI_IOCTL_DATA_IN ? result.len : 0;
    if (result.key && sense_len) memcpy( buffer + sense_offset, sense, sense_len );
    else sense_len = 0;
    spt->SenseInfoLength = sense_len;

    end = header;
    if (sense_len) end = max( end, sense_offset + sense_len );
    if (spt->DataTransferLength) end = max( end, data_offset + spt->DataTransferLength );
    *info = min( end, out_len );

    if (result.key)
        TRACE_(cdimage)( "cdb %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x len %lu -> sense %x/%02x/%02x, %lu bytes\n",
                         cdb[0], cdb[1], cdb[2], cdb[3], cdb[4], cdb[5], cdb[6], cdb[7], cdb[8], cdb[9],
                         data_len, result.key, result.asc, result.ascq, result.len );
    else
        TRACE_(cdimage)( "cdb %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x len %lu -> %lu bytes\n",
                         cdb[0], cdb[1], cdb[2], cdb[3], cdb[4], cdb[5], cdb[6], cdb[7], cdb[8], cdb[9],
                         data_len, result.len );
    return STATUS_SUCCESS;
}

NTSTATUS image_cd_read( ULONGLONG offset, void *out, ULONG len, ULONG_PTR *info )
{
    BYTE sector[RAW_SECTOR_SIZE];
    LONG lba = offset / 2048;
    BYTE *buffer = out;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG i;

    *info = 0;
    if (!refresh_disc()) return STATUS_NO_MEDIA_IN_DEVICE;
    if (offset % 2048 || len % 2048) return STATUS_INVALID_PARAMETER;
    /* like cdrom.sys, a read past the end of the disc fails as a whole */
    if (offset / 2048 + len / 2048 > (ULONGLONG)disc_end())
    {
        TRACE_(cdimage)( "read lba %s count %lu past the end %ld\n", wine_dbgstr_longlong(offset / 2048),
                         len / 2048, disc_end() );
        return STATUS_INVALID_PARAMETER;
    }

    for (i = 0; i < len / 2048; i++, lba++)
    {
        const CDTrack *track = find_track( lba );

        if (!track || track->isAudio)
        {
            if (!i) status = track ? STATUS_INVALID_DEVICE_REQUEST : STATUS_INVALID_PARAMETER;
            break;
        }
        if (!read_sector( &image_file, track, lba, sector ))
        {
            status = STATUS_DEVICE_DATA_ERROR;
            break;
        }
        /* a drive fails to read the sectors written with a wrong EDC */
        if (is_weak_sector( track, sector ))
        {
            TRACE_(cdimage)( "sector %ld has a wrong EDC, reporting a read error\n", lba );
            status = STATUS_DEVICE_DATA_ERROR;
            break;
        }
        memcpy( buffer, sector + data_offset( track ), 2048 );
        buffer += 2048;
    }

    *info = buffer - (BYTE *)out;
    TRACE_(cdimage)( "read lba %s count %lu -> %#lx, %Iu bytes\n", wine_dbgstr_longlong(offset / 2048), len / 2048,
                     status, *info );
    return status;
}

/* like Windows and the mountmgr code for real drives: the volume descriptor of the highest
 * type (a Joliet one over the primary one) gives the label and the serial number */
BOOL image_cd_volume_info( WCHAR *label, ULONG label_len, DWORD *serial )
{
    BYTE desc[2048], best[2048], sum[4] = {0};
    BOOL found = FALSE;
    ULONG_PTR size;
    int i, len;

    for (i = 16; i < 20; i++)
    {
        if (image_cd_read( i * 2048, desc, sizeof(desc), &size ) || memcmp( desc + 1, "CD001", 5 )) break;
        if (desc[0] == 0xff) break;  /* set terminator */
        if (!found || desc[0] > best[0])
        {
            memcpy( best, desc, sizeof(best) );
            found = TRUE;
        }
    }
    if (!found) return FALSE;

    if (best[88] == 0x25 && best[89] == 0x2f && (best[90] == 0x40 || best[90] == 0x43 || best[90] == 0x45))
    {
        /* Joliet: 16 big-endian UCS-2 characters */
        for (len = 0; len < 16 && len < label_len - 1; len++)
            label[len] = (best[40 + 2 * len] << 8) | best[41 + 2 * len];
    }
    else len = MultiByteToWideChar( CP_ACP, 0, (const char *)best + 40, 32, label, label_len - 1 );
    while (len && (label[len - 1] == ' ' || !label[len - 1])) len--;
    label[len] = 0;

    /* the serial number NT computes for CDs */
    for (i = 0; i < 2048; i += 4)
    {
        sum[0] += best[i];
        sum[1] += best[i + 1];
        sum[2] += best[i + 2];
        sum[3] += best[i + 3];
    }
    *serial = (sum[0] << 24) | (sum[1] << 16) | (sum[2] << 8) | sum[3];

    TRACE_(cdimage)( "descriptor type %u, label %s, serial %08lx\n", best[0], debugstr_w(label), *serial );
    return TRUE;
}

BOOL image_cd_ioctl( ULONG code, const void *in, ULONG in_len, void *out, ULONG out_len,
                     NTSTATUS *status, ULONG_PTR *info )
{
    *info = 0;

    switch (code)
    {
    case IOCTL_SCSI_GET_ADDRESS:
    case IOCTL_SCSI_GET_INQUIRY_DATA:
    case IOCTL_SCSI_PASS_THROUGH:
    case IOCTL_SCSI_PASS_THROUGH_DIRECT:
    case IOCTL_CDROM_GET_DRIVE_GEOMETRY:
    case IOCTL_CDROM_GET_DRIVE_GEOMETRY_EX:
    case IOCTL_DISK_GET_DRIVE_GEOMETRY:
    case IOCTL_DISK_GET_DRIVE_GEOMETRY_EX:
    case IOCTL_CDROM_READ_TOC:
    case IOCTL_CDROM_READ_TOC_EX:
    case IOCTL_CDROM_GET_LAST_SESSION:
    case IOCTL_CDROM_CHECK_VERIFY:
    case IOCTL_STORAGE_CHECK_VERIFY:
    case IOCTL_STORAGE_CHECK_VERIFY2:
    case IOCTL_CDROM_MEDIA_REMOVAL:
    case IOCTL_STORAGE_MEDIA_REMOVAL:
    case IOCTL_CDROM_RAW_READ:
        break;
    default:
        TRACE_(cdimage)( "ioctl %#lx left to the drive\n", code );
        return FALSE;
    }

    if (!refresh_disc()) return FALSE;

    switch (code)
    {
    case IOCTL_CDROM_GET_DRIVE_GEOMETRY:
    case IOCTL_DISK_GET_DRIVE_GEOMETRY:
    {
        DISK_GEOMETRY geometry;

        if (out_len < sizeof(geometry))
        {
            *status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        fill_geometry( &geometry );
        memcpy( out, &geometry, sizeof(geometry) );
        *info = sizeof(geometry);
        *status = STATUS_SUCCESS;
        break;
    }
    case IOCTL_CDROM_GET_DRIVE_GEOMETRY_EX:
    case IOCTL_DISK_GET_DRIVE_GEOMETRY_EX:
    {
        DISK_GEOMETRY_EX geometry = {{{0}}};
        ULONG len = FIELD_OFFSET( DISK_GEOMETRY_EX, Data );

        if (out_len < len)
        {
            *status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        fill_geometry( &geometry.Geometry );
        geometry.DiskSize.QuadPart = (LONGLONG)disc_end() * 2048;
        memcpy( out, &geometry, len );
        *info = len;
        *status = STATUS_SUCCESS;
        break;
    }
    case IOCTL_CDROM_READ_TOC:
    {
        CDROM_TOC toc;
        ULONG size = fill_toc( &toc, TRUE );

        *info = min( size, out_len );
        memcpy( out, &toc, *info );
        *status = STATUS_SUCCESS;
        break;
    }
    case IOCTL_CDROM_READ_TOC_EX:
    {
        const CDROM_READ_TOC_EX *request = in;

        if (in_len < sizeof(*request))
        {
            *status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (request->Format == CDROM_READ_TOC_EX_FORMAT_TOC)
        {
            CDROM_TOC toc;
            ULONG size = fill_toc( &toc, request->Msf );

            *info = min( size, out_len );
            memcpy( out, &toc, *info );
            *status = STATUS_SUCCESS;
        }
        else if (request->Format == CDROM_READ_TOC_EX_FORMAT_SESSION)
        {
            CDROM_TOC_SESSION_DATA session;
            ULONG size = fill_session( &session, request->Msf );

            *info = min( size, out_len );
            memcpy( out, &session, *info );
            *status = STATUS_SUCCESS;
        }
        else
        {
            FIXME( "TOC format %u not supported for disc images\n", request->Format );
            *status = STATUS_INVALID_DEVICE_REQUEST;
        }
        break;
    }
    case IOCTL_CDROM_GET_LAST_SESSION:
    {
        CDROM_TOC_SESSION_DATA session;
        ULONG size = fill_session( &session, TRUE );

        *info = min( size, out_len );
        memcpy( out, &session, *info );
        *status = STATUS_SUCCESS;
        break;
    }
    case IOCTL_CDROM_CHECK_VERIFY:
    case IOCTL_STORAGE_CHECK_VERIFY:
    case IOCTL_STORAGE_CHECK_VERIFY2:
    case IOCTL_CDROM_MEDIA_REMOVAL:
    case IOCTL_STORAGE_MEDIA_REMOVAL:
        *status = STATUS_SUCCESS; /* an image is always present and never locked */
        break;
    case IOCTL_CDROM_RAW_READ:
        if (in_len < sizeof(RAW_READ_INFO) || !out)
            *status = STATUS_INVALID_PARAMETER;
        else
            *status = raw_read( in, out, out_len, info );
        break;
    case IOCTL_SCSI_GET_ADDRESS:
    {
        SCSI_ADDRESS address = { sizeof(address), IMAGE_CD_SCSI_PORT, 0, 0, 0 };

        if (out_len < sizeof(address))
        {
            *status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        memcpy( out, &address, sizeof(address) );
        *info = sizeof(address);
        *status = STATUS_SUCCESS;
        break;
    }
    case IOCTL_SCSI_GET_INQUIRY_DATA:
        *status = get_inquiry_data( out, out_len, info );
        break;
    case IOCTL_SCSI_PASS_THROUGH:
        /* buffered: the request, the sense and the data share one buffer */
        *status = scsi_pass_through( out, in_len, out_len, info );
        break;
    case IOCTL_SCSI_PASS_THROUGH_DIRECT:
        /* the data buffer is an address in the caller, not in this process */
        FIXME_(cdimage)( "IOCTL_SCSI_PASS_THROUGH_DIRECT not supported for disc images\n" );
        *status = STATUS_NOT_SUPPORTED;
        break;
    }

    TRACE_(cdimage)( "ioctl %#lx -> %#lx, %Iu bytes\n", code, *status, *info );
    return TRUE;
}
