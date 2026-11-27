/*
 * CD requests answered from the disc image loaded in the Winlator file manager
 */

#ifndef __WINE_MOUNTMGR_IMAGE_CD_H
#define __WINE_MOUNTMGR_IMAGE_CD_H

/* where the image drive sits on the SCSI bus, the same in the requests and the registry */
#define IMAGE_CD_SCSI_PORT    1
#define IMAGE_CD_INITIATOR_ID 255
/* vendor (8), product (16) and revision (4) as INQUIRY returns them */
#define IMAGE_CD_IDENTIFIER   "WINE    CD-ROM IMAGE    1.0 "

/* returns FALSE when no image is loaded or the request is not one answered from an image */
extern BOOL image_cd_ioctl( ULONG code, const void *in, ULONG in_len, void *out, ULONG out_len,
                            NTSTATUS *status, ULONG_PTR *info );

/* the label and serial number Windows reports for the disc, from its ISO 9660 volume descriptor */
extern BOOL image_cd_volume_info( WCHAR *label, ULONG label_len, DWORD *serial );

/* reads the 2048 byte user data of the data sectors at a byte offset of the disc */
extern NTSTATUS image_cd_read( ULONGLONG offset, void *out, ULONG len, ULONG_PTR *info );

#endif
