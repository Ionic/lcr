/*****************************************************************************\
**                                                                           **
** PBX4Linux                                                                 **
**                                                                           **
**---------------------------------------------------------------------------**
** Copyright: Andreas Eversberg                                              **
**                                                                           **
** audio conversions for alaw and ulaw                                       **
**                                                                           **
\*****************************************************************************/ 

signed int *audio_law_to_s32;
unsigned char silence;

/* ulaw -> signed 16-bit */
static signed int audio_ulaw_to_s32[] =
{
	0xffff8284, 0xffff8684, 0xffff8a84, 0xffff8e84,
	0xffff9284, 0xffff9684, 0xffff9a84, 0xffff9e84,
	0xffffa284, 0xffffa684, 0xffffaa84, 0xffffae84,
	0xffffb284, 0xffffb684, 0xffffba84, 0xffffbe84,
	0xffffc184, 0xffffc384, 0xffffc584, 0xffffc784,
	0xffffc984, 0xffffcb84, 0xffffcd84, 0xffffcf84,
	0xffffd184, 0xffffd384, 0xffffd584, 0xffffd784,
	0xffffd984, 0xffffdb84, 0xffffdd84, 0xffffdf84,
	0xffffe104, 0xffffe204, 0xffffe304, 0xffffe404,
	0xffffe504, 0xffffe604, 0xffffe704, 0xffffe804,
	0xffffe904, 0xffffea04, 0xffffeb04, 0xffffec04,
	0xffffed04, 0xffffee04, 0xffffef04, 0xfffff004,
	0xfffff0c4, 0xfffff144, 0xfffff1c4, 0xfffff244,
	0xfffff2c4, 0xfffff344, 0xfffff3c4, 0xfffff444,
	0xfffff4c4, 0xfffff544, 0xfffff5c4, 0xfffff644,
	0xfffff6c4, 0xfffff744, 0xfffff7c4, 0xfffff844,
	0xfffff8a4, 0xfffff8e4, 0xfffff924, 0xfffff964,
	0xfffff9a4, 0xfffff9e4, 0xfffffa24, 0xfffffa64,
	0xfffffaa4, 0xfffffae4, 0xfffffb24, 0xfffffb64,
	0xfffffba4, 0xfffffbe4, 0xfffffc24, 0xfffffc64,
	0xfffffc94, 0xfffffcb4, 0xfffffcd4, 0xfffffcf4,
	0xfffffd14, 0xfffffd34, 0xfffffd54, 0xfffffd74,
	0xfffffd94, 0xfffffdb4, 0xfffffdd4, 0xfffffdf4,
	0xfffffe14, 0xfffffe34, 0xfffffe54, 0xfffffe74,
	0xfffffe8c, 0xfffffe9c, 0xfffffeac, 0xfffffebc,
	0xfffffecc, 0xfffffedc, 0xfffffeec, 0xfffffefc,
	0xffffff0c, 0xffffff1c, 0xffffff2c, 0xffffff3c,
	0xffffff4c, 0xffffff5c, 0xffffff6c, 0xffffff7c,
	0xffffff88, 0xffffff90, 0xffffff98, 0xffffffa0,
	0xffffffa8, 0xffffffb0, 0xffffffb8, 0xffffffc0,
	0xffffffc8, 0xffffffd0, 0xffffffd8, 0xffffffe0,
	0xffffffe8, 0xfffffff0, 0xfffffff8, 0xffffffff,
	0x00007d7c, 0x0000797c, 0x0000757c, 0x0000717c,
	0x00006d7c, 0x0000697c, 0x0000657c, 0x0000617c,
	0x00005d7c, 0x0000597c, 0x0000557c, 0x0000517c,
	0x00004d7c, 0x0000497c, 0x0000457c, 0x0000417c,
	0x00003e7c, 0x00003c7c, 0x00003a7c, 0x0000387c,
	0x0000367c, 0x0000347c, 0x0000327c, 0x0000307c,
	0x00002e7c, 0x00002c7c, 0x00002a7c, 0x0000287c,
	0x0000267c, 0x0000247c, 0x0000227c, 0x0000207c,
	0x00001efc, 0x00001dfc, 0x00001cfc, 0x00001bfc,
	0x00001afc, 0x000019fc, 0x000018fc, 0x000017fc,
	0x000016fc, 0x000015fc, 0x000014fc, 0x000013fc,
	0x000012fc, 0x000011fc, 0x000010fc, 0x00000ffc,
	0x00000f3c, 0x00000ebc, 0x00000e3c, 0x00000dbc,
	0x00000d3c, 0x00000cbc, 0x00000c3c, 0x00000bbc,
	0x00000b3c, 0x00000abc, 0x00000a3c, 0x000009bc,
	0x0000093c, 0x000008bc, 0x0000083c, 0x000007bc,
	0x0000075c, 0x0000071c, 0x000006dc, 0x0000069c,
	0x0000065c, 0x0000061c, 0x000005dc, 0x0000059c,
	0x0000055c, 0x0000051c, 0x000004dc, 0x0000049c,
	0x0000045c, 0x0000041c, 0x000003dc, 0x0000039c,
	0x0000036c, 0x0000034c, 0x0000032c, 0x0000030c,
	0x000002ec, 0x000002cc, 0x000002ac, 0x0000028c,
	0x0000026c, 0x0000024c, 0x0000022c, 0x0000020c,
	0x000001ec, 0x000001cc, 0x000001ac, 0x0000018c,
	0x00000174, 0x00000164, 0x00000154, 0x00000144,
	0x00000134, 0x00000124, 0x00000114, 0x00000104,
	0x000000f4, 0x000000e4, 0x000000d4, 0x000000c4,
	0x000000b4, 0x000000a4, 0x00000094, 0x00000084,
	0x00000078, 0x00000070, 0x00000068, 0x00000060,
	0x00000058, 0x00000050, 0x00000048, 0x00000040,
	0x00000038, 0x00000030, 0x00000028, 0x00000020,
	0x00000018, 0x00000010, 0x00000008, 0x00000000
};

/* alaw -> signed 16-bit */
static signed int audio_alaw_to_s32[] =
{
	0x000013fc, 0xffffec04, 0x00000144, 0xfffffebc,
	0x0000517c, 0xffffae84, 0x0000051c, 0xfffffae4,
	0x00000a3c, 0xfffff5c4, 0x00000048, 0xffffffb8,
	0x0000287c, 0xffffd784, 0x0000028c, 0xfffffd74,
	0x00001bfc, 0xffffe404, 0x000001cc, 0xfffffe34,
	0x0000717c, 0xffff8e84, 0x0000071c, 0xfffff8e4,
	0x00000e3c, 0xfffff1c4, 0x000000c4, 0xffffff3c,
	0x0000387c, 0xffffc784, 0x0000039c, 0xfffffc64,
	0x00000ffc, 0xfffff004, 0x00000104, 0xfffffefc,
	0x0000417c, 0xffffbe84, 0x0000041c, 0xfffffbe4,
	0x0000083c, 0xfffff7c4, 0x00000008, 0xfffffff8,
	0x0000207c, 0xffffdf84, 0x0000020c, 0xfffffdf4,
	0x000017fc, 0xffffe804, 0x0000018c, 0xfffffe74,
	0x0000617c, 0xffff9e84, 0x0000061c, 0xfffff9e4,
	0x00000c3c, 0xfffff3c4, 0x00000084, 0xffffff7c,
	0x0000307c, 0xffffcf84, 0x0000030c, 0xfffffcf4,
	0x000015fc, 0xffffea04, 0x00000164, 0xfffffe9c,
	0x0000597c, 0xffffa684, 0x0000059c, 0xfffffa64,
	0x00000b3c, 0xfffff4c4, 0x00000068, 0xffffff98,
	0x00002c7c, 0xffffd384, 0x000002cc, 0xfffffd34,
	0x00001dfc, 0xffffe204, 0x000001ec, 0xfffffe14,
	0x0000797c, 0xffff8684, 0x000007bc, 0xfffff844,
	0x00000f3c, 0xfffff0c4, 0x000000e4, 0xffffff1c,
	0x00003c7c, 0xffffc384, 0x000003dc, 0xfffffc24,
	0x000011fc, 0xffffee04, 0x00000124, 0xfffffedc,
	0x0000497c, 0xffffb684, 0x0000049c, 0xfffffb64,
	0x0000093c, 0xfffff6c4, 0x00000028, 0xffffffd8,
	0x0000247c, 0xffffdb84, 0x0000024c, 0xfffffdb4,
	0x000019fc, 0xffffe604, 0x000001ac, 0xfffffe54,
	0x0000697c, 0xffff9684, 0x0000069c, 0xfffff964,
	0x00000d3c, 0xfffff2c4, 0x000000a4, 0xffffff5c,
	0x0000347c, 0xffffcb84, 0x0000034c, 0xfffffcb4,
	0x000012fc, 0xffffed04, 0x00000134, 0xfffffecc,
	0x00004d7c, 0xffffb284, 0x000004dc, 0xfffffb24,
	0x000009bc, 0xfffff644, 0x00000038, 0xffffffc8,
	0x0000267c, 0xffffd984, 0x0000026c, 0xfffffd94,
	0x00001afc, 0xffffe504, 0x000001ac, 0xfffffe54,
	0x00006d7c, 0xffff9284, 0x000006dc, 0xfffff924,
	0x00000dbc, 0xfffff244, 0x000000b4, 0xffffff4c,
	0x0000367c, 0xffffc984, 0x0000036c, 0xfffffc94,
	0x00000f3c, 0xfffff0c4, 0x000000f4, 0xffffff0c,
	0x00003e7c, 0xffffc184, 0x000003dc, 0xfffffc24,
	0x000007bc, 0xfffff844, 0x00000008, 0xfffffff8,
	0x00001efc, 0xffffe104, 0x000001ec, 0xfffffe14,
	0x000016fc, 0xffffe904, 0x00000174, 0xfffffe8c,
	0x00005d7c, 0xffffa284, 0x000005dc, 0xfffffa24,
	0x00000bbc, 0xfffff444, 0x00000078, 0xffffff88,
	0x00002e7c, 0xffffd184, 0x000002ec, 0xfffffd14,
	0x000014fc, 0xffffeb04, 0x00000154, 0xfffffeac,
	0x0000557c, 0xffffaa84, 0x0000055c, 0xfffffaa4,
	0x00000abc, 0xfffff544, 0x00000058, 0xffffffa8,
	0x00002a7c, 0xffffd584, 0x000002ac, 0xfffffd54,
	0x00001cfc, 0xffffe304, 0x000001cc, 0xfffffe34,
	0x0000757c, 0xffff8a84, 0x0000075c, 0xfffff8a4,
	0x00000ebc, 0xfffff144, 0x000000d4, 0xffffff2c,
	0x00003a7c, 0xffffc584, 0x0000039c, 0xfffffc64,
	0x000010fc, 0xffffef04, 0x00000114, 0xfffffeec,
	0x0000457c, 0xffffba84, 0x0000045c, 0xfffffba4,
	0x000008bc, 0xfffff744, 0x00000018, 0xffffffe8,
	0x0000227c, 0xffffdd84, 0x0000022c, 0xfffffdd4,
	0x000018fc, 0xffffe704, 0x0000018c, 0xfffffe74,
	0x0000657c, 0xffff9a84, 0x0000065c, 0xfffff9a4,
	0x00000cbc, 0xfffff344, 0x00000094, 0xffffff6c,
	0x0000327c, 0xffffcd84, 0x0000032c, 0xfffffcd4
};

/* signed 16-bit -> Xlaw */
unsigned char audio_s16_to_law[65536];


/* table is used to generate s16_to_alaw */
static short audio_alaw_relations[] =
{
	0x8684, 0x55, 0x8a84, 0xd5, 0x8e84, 0x15, 0x9284, 0x95,
	0x9684, 0x75, 0x9a84, 0xf5, 0x9e84, 0x35, 0xa284, 0xb5,
	0xa684, 0x45, 0xaa84, 0xc5, 0xae84, 0x05, 0xb284, 0x85,
	0xb684, 0x65, 0xba84, 0xe5, 0xbe84, 0x25, 0xc184, 0xa5,
	0xc384, 0x5d, 0xc584, 0xdd, 0xc784, 0x1d, 0xc984, 0x9d,
	0xcb84, 0x7d, 0xcd84, 0xfd, 0xcf84, 0x3d, 0xd184, 0xbd,
	0xd384, 0x4d, 0xd584, 0xcd, 0xd784, 0x0d, 0xd984, 0x8d,
	0xdb84, 0x6d, 0xdd84, 0xed, 0xdf84, 0x2d, 0xe104, 0xad,
	0xe204, 0x51, 0xe304, 0xd1, 0xe404, 0x11, 0xe504, 0x91,
	0xe604, 0x71, 0xe704, 0xf1, 0xe804, 0x31, 0xe904, 0xb1,
	0xea04, 0x41, 0xeb04, 0xc1, 0xec04, 0x01, 0xed04, 0x81,
	0xee04, 0x61, 0xef04, 0xe1, 0xf004, 0x21, 0xf0c4, 0x59,
	0xf0c4, 0xa1, 0xf144, 0xd9, 0xf1c4, 0x19, 0xf244, 0x99,
	0xf2c4, 0x79, 0xf344, 0xf9, 0xf3c4, 0x39, 0xf444, 0xb9,
	0xf4c4, 0x49, 0xf544, 0xc9, 0xf5c4, 0x09, 0xf644, 0x89,
	0xf6c4, 0x69, 0xf744, 0xe9, 0xf7c4, 0x29, 0xf844, 0x57,
	0xf844, 0xa9, 0xf8a4, 0xd7, 0xf8e4, 0x17, 0xf924, 0x97,
	0xf964, 0x77, 0xf9a4, 0xf7, 0xf9e4, 0x37, 0xfa24, 0xb7,
	0xfa64, 0x47, 0xfaa4, 0xc7, 0xfae4, 0x07, 0xfb24, 0x87,
	0xfb64, 0x67, 0xfba4, 0xe7, 0xfbe4, 0x27, 0xfc24, 0x5f,
	0xfc24, 0xa7, 0xfc64, 0x1f, 0xfc64, 0xdf, 0xfc94, 0x9f,
	0xfcb4, 0x7f, 0xfcd4, 0xff, 0xfcf4, 0x3f, 0xfd14, 0xbf,
	0xfd34, 0x4f, 0xfd54, 0xcf, 0xfd74, 0x0f, 0xfd94, 0x8f,
	0xfdb4, 0x6f, 0xfdd4, 0xef, 0xfdf4, 0x2f, 0xfe14, 0x53,
	0xfe14, 0xaf, 0xfe34, 0x13, 0xfe34, 0xd3, 0xfe54, 0x73,
	0xfe54, 0x93, 0xfe74, 0x33, 0xfe74, 0xf3, 0xfe8c, 0xb3,
	0xfe9c, 0x43, 0xfeac, 0xc3, 0xfebc, 0x03, 0xfecc, 0x83,
	0xfedc, 0x63, 0xfeec, 0xe3, 0xfefc, 0x23, 0xff0c, 0xa3,
	0xff1c, 0x5b, 0xff2c, 0xdb, 0xff3c, 0x1b, 0xff4c, 0x9b,
	0xff5c, 0x7b, 0xff6c, 0xfb, 0xff7c, 0x3b, 0xff88, 0xbb,
	0xff98, 0x4b, 0xffa8, 0xcb, 0xffb8, 0x0b, 0xffc8, 0x8b,
	0xffd8, 0x6b, 0xffe8, 0xeb, 0xfff8, 0x2b, 0xfff8, 0xab,
	0x0008, 0x2a, 0x0008, 0xaa, 0x0018, 0xea, 0x0028, 0x6a,
	0x0038, 0x8a, 0x0048, 0x0a, 0x0058, 0xca, 0x0068, 0x4a,
	0x0078, 0xba, 0x0084, 0x3a, 0x0094, 0xfa, 0x00a4, 0x7a,
	0x00b4, 0x9a, 0x00c4, 0x1a, 0x00d4, 0xda, 0x00e4, 0x5a,
	0x00f4, 0xa2, 0x0104, 0x22, 0x0114, 0xe2, 0x0124, 0x62,
	0x0134, 0x82, 0x0144, 0x02, 0x0154, 0xc2, 0x0164, 0x42,
	0x0174, 0xb2, 0x018c, 0x32, 0x018c, 0xf2, 0x01ac, 0x72,
	0x01ac, 0x92, 0x01cc, 0x12, 0x01cc, 0xd2, 0x01ec, 0x52,
	0x01ec, 0xae, 0x020c, 0x2e, 0x022c, 0xee, 0x024c, 0x6e,
	0x026c, 0x8e, 0x028c, 0x0e, 0x02ac, 0xce, 0x02cc, 0x4e,
	0x02ec, 0xbe, 0x030c, 0x3e, 0x032c, 0xfe, 0x034c, 0x7e,
	0x036c, 0x9e, 0x039c, 0x1e, 0x039c, 0xde, 0x03dc, 0x5e,
	0x03dc, 0xa6, 0x041c, 0x26, 0x045c, 0xe6, 0x049c, 0x66,
	0x04dc, 0x86, 0x051c, 0x06, 0x055c, 0xc6, 0x059c, 0x46,
	0x05dc, 0xb6, 0x061c, 0x36, 0x065c, 0xf6, 0x069c, 0x76,
	0x06dc, 0x96, 0x071c, 0x16, 0x075c, 0xd6, 0x07bc, 0x56,
	0x07bc, 0xa8, 0x083c, 0x28, 0x08bc, 0xe8, 0x093c, 0x68,
	0x09bc, 0x88, 0x0a3c, 0x08, 0x0abc, 0xc8, 0x0b3c, 0x48,
	0x0bbc, 0xb8, 0x0c3c, 0x38, 0x0cbc, 0xf8, 0x0d3c, 0x78,
	0x0dbc, 0x98, 0x0e3c, 0x18, 0x0ebc, 0xd8, 0x0f3c, 0x58,
	0x0f3c, 0xa0, 0x0ffc, 0x20, 0x10fc, 0xe0, 0x11fc, 0x60,
	0x12fc, 0x80, 0x13fc, 0x00, 0x14fc, 0xc0, 0x15fc, 0x40,
	0x16fc, 0xb0, 0x17fc, 0x30, 0x18fc, 0xf0, 0x19fc, 0x70,
	0x1afc, 0x90, 0x1bfc, 0x10, 0x1cfc, 0xd0, 0x1dfc, 0x50,
	0x1efc, 0xac, 0x207c, 0x2c, 0x227c, 0xec, 0x247c, 0x6c,
	0x267c, 0x8c, 0x287c, 0x0c, 0x2a7c, 0xcc, 0x2c7c, 0x4c,
	0x2e7c, 0xbc, 0x307c, 0x3c, 0x327c, 0xfc, 0x347c, 0x7c,
	0x367c, 0x9c, 0x387c, 0x1c, 0x3a7c, 0xdc, 0x3c7c, 0x5c,
	0x3e7c, 0xa4, 0x417c, 0x24, 0x457c, 0xe4, 0x497c, 0x64,
	0x4d7c, 0x84, 0x517c, 0x04, 0x557c, 0xc4, 0x597c, 0x44,
	0x5d7c, 0xb4, 0x617c, 0x34, 0x657c, 0xf4, 0x697c, 0x74,
	0x6d7c, 0x94, 0x717c, 0x14, 0x757c, 0xd4, 0x797c, 0x54
};

/* generate tables for conversion of s16 to alaw/ulaw
 */
void generate_tables(char law)
{
	int i, j;

	if (law == 'a') {
		silence = 0x2a;
		audio_law_to_s32=audio_alaw_to_s32;
		/* generating alaw-table */
		i = j = 0;
		while(i < 65536) {
			if (i-32768 > audio_alaw_relations[j<<1])
				j++;
			if (j>255)
				j=255;
			audio_s16_to_law[(i-32768) & 0xffff]
				 = audio_alaw_relations[(j<<1)|1];
			i++;
		}
	} else {
		silence = 0xff;
		audio_law_to_s32=audio_ulaw_to_s32;
		/* generating ulaw-table */
		i = j = 0;
		while(i < 32768) {
			if (i-32768 > audio_ulaw_to_s32[j])
				j++;
			audio_s16_to_law[(i-32768) & 0xffff] = j;
			i++;
		}
		j = 255;
		while(i < 65536) {
			if (i-0x32768 > audio_ulaw_to_s32[j])
				j--;
			audio_s16_to_law[(i-32768) & 0xffff] = j;
			i++;
		}
	}
}


