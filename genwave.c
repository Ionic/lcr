
/* isdn 2 wave
  by jolly
*/

#include <stdio.h>
#include <string.h>
#include <math.h>


/* ulaw -> signed 16-bit */
static short isdn_audio_ulaw_to_s16[] =
{
	0x8284, 0x8684, 0x8a84, 0x8e84, 0x9284, 0x9684, 0x9a84, 0x9e84,
	0xa284, 0xa684, 0xaa84, 0xae84, 0xb284, 0xb684, 0xba84, 0xbe84,
	0xc184, 0xc384, 0xc584, 0xc784, 0xc984, 0xcb84, 0xcd84, 0xcf84,
	0xd184, 0xd384, 0xd584, 0xd784, 0xd984, 0xdb84, 0xdd84, 0xdf84,
	0xe104, 0xe204, 0xe304, 0xe404, 0xe504, 0xe604, 0xe704, 0xe804,
	0xe904, 0xea04, 0xeb04, 0xec04, 0xed04, 0xee04, 0xef04, 0xf004,
	0xf0c4, 0xf144, 0xf1c4, 0xf244, 0xf2c4, 0xf344, 0xf3c4, 0xf444,
	0xf4c4, 0xf544, 0xf5c4, 0xf644, 0xf6c4, 0xf744, 0xf7c4, 0xf844,
	0xf8a4, 0xf8e4, 0xf924, 0xf964, 0xf9a4, 0xf9e4, 0xfa24, 0xfa64,
	0xfaa4, 0xfae4, 0xfb24, 0xfb64, 0xfba4, 0xfbe4, 0xfc24, 0xfc64,
	0xfc94, 0xfcb4, 0xfcd4, 0xfcf4, 0xfd14, 0xfd34, 0xfd54, 0xfd74,
	0xfd94, 0xfdb4, 0xfdd4, 0xfdf4, 0xfe14, 0xfe34, 0xfe54, 0xfe74,
	0xfe8c, 0xfe9c, 0xfeac, 0xfebc, 0xfecc, 0xfedc, 0xfeec, 0xfefc,
	0xff0c, 0xff1c, 0xff2c, 0xff3c, 0xff4c, 0xff5c, 0xff6c, 0xff7c,
	0xff88, 0xff90, 0xff98, 0xffa0, 0xffa8, 0xffb0, 0xffb8, 0xffc0,
	0xffc8, 0xffd0, 0xffd8, 0xffe0, 0xffe8, 0xfff0, 0xfff8, 0x0000,
	0x7d7c, 0x797c, 0x757c, 0x717c, 0x6d7c, 0x697c, 0x657c, 0x617c,
	0x5d7c, 0x597c, 0x557c, 0x517c, 0x4d7c, 0x497c, 0x457c, 0x417c,
	0x3e7c, 0x3c7c, 0x3a7c, 0x387c, 0x367c, 0x347c, 0x327c, 0x307c,
	0x2e7c, 0x2c7c, 0x2a7c, 0x287c, 0x267c, 0x247c, 0x227c, 0x207c,
	0x1efc, 0x1dfc, 0x1cfc, 0x1bfc, 0x1afc, 0x19fc, 0x18fc, 0x17fc,
	0x16fc, 0x15fc, 0x14fc, 0x13fc, 0x12fc, 0x11fc, 0x10fc, 0x0ffc,
	0x0f3c, 0x0ebc, 0x0e3c, 0x0dbc, 0x0d3c, 0x0cbc, 0x0c3c, 0x0bbc,
	0x0b3c, 0x0abc, 0x0a3c, 0x09bc, 0x093c, 0x08bc, 0x083c, 0x07bc,
	0x075c, 0x071c, 0x06dc, 0x069c, 0x065c, 0x061c, 0x05dc, 0x059c,
	0x055c, 0x051c, 0x04dc, 0x049c, 0x045c, 0x041c, 0x03dc, 0x039c,
	0x036c, 0x034c, 0x032c, 0x030c, 0x02ec, 0x02cc, 0x02ac, 0x028c,
	0x026c, 0x024c, 0x022c, 0x020c, 0x01ec, 0x01cc, 0x01ac, 0x018c,
	0x0174, 0x0164, 0x0154, 0x0144, 0x0134, 0x0124, 0x0114, 0x0104,
	0x00f4, 0x00e4, 0x00d4, 0x00c4, 0x00b4, 0x00a4, 0x0094, 0x0084,
	0x0078, 0x0070, 0x0068, 0x0060, 0x0058, 0x0050, 0x0048, 0x0040,
	0x0038, 0x0030, 0x0028, 0x0020, 0x0018, 0x0010, 0x0008, 0x0000
};

/* alaw -> signed 16-bit */
static short isdn_audio_alaw_to_s16[] =
{
	0x13fc, 0xec04, 0x0144, 0xfebc, 0x517c, 0xae84, 0x051c, 0xfae4,
	0x0a3c, 0xf5c4, 0x0048, 0xffb8, 0x287c, 0xd784, 0x028c, 0xfd74,
	0x1bfc, 0xe404, 0x01cc, 0xfe34, 0x717c, 0x8e84, 0x071c, 0xf8e4,
	0x0e3c, 0xf1c4, 0x00c4, 0xff3c, 0x387c, 0xc784, 0x039c, 0xfc64,
	0x0ffc, 0xf004, 0x0104, 0xfefc, 0x417c, 0xbe84, 0x041c, 0xfbe4,
	0x083c, 0xf7c4, 0x0008, 0xfff8, 0x207c, 0xdf84, 0x020c, 0xfdf4,
	0x17fc, 0xe804, 0x018c, 0xfe74, 0x617c, 0x9e84, 0x061c, 0xf9e4,
	0x0c3c, 0xf3c4, 0x0084, 0xff7c, 0x307c, 0xcf84, 0x030c, 0xfcf4,
	0x15fc, 0xea04, 0x0164, 0xfe9c, 0x597c, 0xa684, 0x059c, 0xfa64,
	0x0b3c, 0xf4c4, 0x0068, 0xff98, 0x2c7c, 0xd384, 0x02cc, 0xfd34,
	0x1dfc, 0xe204, 0x01ec, 0xfe14, 0x797c, 0x8684, 0x07bc, 0xf844,
	0x0f3c, 0xf0c4, 0x00e4, 0xff1c, 0x3c7c, 0xc384, 0x03dc, 0xfc24,
	0x11fc, 0xee04, 0x0124, 0xfedc, 0x497c, 0xb684, 0x049c, 0xfb64,
	0x093c, 0xf6c4, 0x0028, 0xffd8, 0x247c, 0xdb84, 0x024c, 0xfdb4,
	0x19fc, 0xe604, 0x01ac, 0xfe54, 0x697c, 0x9684, 0x069c, 0xf964,
	0x0d3c, 0xf2c4, 0x00a4, 0xff5c, 0x347c, 0xcb84, 0x034c, 0xfcb4,
	0x12fc, 0xed04, 0x0134, 0xfecc, 0x4d7c, 0xb284, 0x04dc, 0xfb24,
	0x09bc, 0xf644, 0x0038, 0xffc8, 0x267c, 0xd984, 0x026c, 0xfd94,
	0x1afc, 0xe504, 0x01ac, 0xfe54, 0x6d7c, 0x9284, 0x06dc, 0xf924,
	0x0dbc, 0xf244, 0x00b4, 0xff4c, 0x367c, 0xc984, 0x036c, 0xfc94,
	0x0f3c, 0xf0c4, 0x00f4, 0xff0c, 0x3e7c, 0xc184, 0x03dc, 0xfc24,
	0x07bc, 0xf844, 0x0008, 0xfff8, 0x1efc, 0xe104, 0x01ec, 0xfe14,
	0x16fc, 0xe904, 0x0174, 0xfe8c, 0x5d7c, 0xa284, 0x05dc, 0xfa24,
	0x0bbc, 0xf444, 0x0078, 0xff88, 0x2e7c, 0xd184, 0x02ec, 0xfd14,
	0x14fc, 0xeb04, 0x0154, 0xfeac, 0x557c, 0xaa84, 0x055c, 0xfaa4,
	0x0abc, 0xf544, 0x0058, 0xffa8, 0x2a7c, 0xd584, 0x02ac, 0xfd54,
	0x1cfc, 0xe304, 0x01cc, 0xfe34, 0x757c, 0x8a84, 0x075c, 0xf8a4,
	0x0ebc, 0xf144, 0x00d4, 0xff2c, 0x3a7c, 0xc584, 0x039c, 0xfc64,
	0x10fc, 0xef04, 0x0114, 0xfeec, 0x457c, 0xba84, 0x045c, 0xfba4,
	0x08bc, 0xf744, 0x0018, 0xffe8, 0x227c, 0xdd84, 0x022c, 0xfdd4,
	0x18fc, 0xe704, 0x018c, 0xfe74, 0x657c, 0x9a84, 0x065c, 0xf9a4,
	0x0cbc, 0xf344, 0x0094, 0xff6c, 0x327c, 0xcd84, 0x032c, 0xfcd4
};


struct fmt {
	unsigned short	stereo; /* 1 = pcm, 2 = adpcm */
	unsigned short	channels; /* number of channels */
	unsigned int	sample_rate; /* sample rate */
	unsigned int	data_rate; /* data rate */
	unsigned short	bytes_sample; /* bytes per sample (all channels) */
	unsigned short	bits_sample; /* bits per sample (one channel) */
};

void write_law(FILE *fp, char *name, char law)
{
	unsigned char buffer[256];
	struct fmt fmt;
	FILE *lfp;
	unsigned int i;
	short sample;
	unsigned int size, wsize;

	if ((lfp=fopen(name,"r")))
	{
		/* get size */
		fseek(lfp, 0, SEEK_END);
		size = ftell(lfp);
		printf("samples: %ld\n", size);
		size += size;
		fseek(lfp, 0, SEEK_SET);

		wsize = 4+8+sizeof(fmt)+8+size+8+4+8+4;

		/* RIFF */
		fprintf(fp, "RIFF%c%c%c%c", (char)(wsize&0xff), (char)((wsize>>8)&0xff), (char)((wsize>>16)&0xff), (char)(wsize>>24));

		/* WAVE */
		fprintf(fp, "WAVE");

		/* fmt */
		fprintf(fp, "fmt %c%c%c%c", sizeof(fmt), 0, 0, 0);
		fmt.stereo = 1;
		fmt.channels = 1;
		fmt.sample_rate = 8000;
		fmt.data_rate = 16000;
		fmt.bytes_sample = 2;
		fmt.bits_sample = 16;
		fwrite(&fmt, sizeof(fmt), 1, fp);

		/* data */
		fprintf(fp, "data%c%c%c%c", (char)(size&0xff), (char)((size>>8)&0xff), (char)((size>>16)&0xff), (char)(size>>24));
		i = 0;
		while(i < size)
		{
			fread(buffer, 1, 1, lfp);
			if (law == 'a')
				sample = isdn_audio_alaw_to_s16[*buffer];
			else
				sample = isdn_audio_ulaw_to_s16[*buffer];
			fwrite(&sample, 2, 1, fp);
			i+=2;
		}

		/* cue */
		fprintf(fp, "cue %c%c%c%c%c%c%c%c", 4, 0, 0, 0, 0,0,0,0);
	
		/* LIST */
		fprintf(fp, "LIST%c%c%c%cadtl", 4, 0, 0, 0);
	
		fclose(lfp);
	}
}

int main(int argc, char *argv[])
{
	FILE *fp;

	if (argc <= 1)
	{
		usage:
		printf("Usage:\n");
		printf("%s ulaw2wave <alaw file> <wav file>\n", argv[0]);
		printf("%s alaw2wave <alaw file> <wav file>\n", argv[0]);
		return(0);
	}

	if (!strcmp(argv[1], "alaw2wave"))
	{
		if (argc <= 3)
			goto usage;
		if ((fp=fopen(argv[3],"w")))
		{
			write_law(fp,argv[2],'a');
			fclose(fp);
		} else
		{
			printf("Cannot open wave file %s\n",argv[3]);
		}
	} else
	if (!strcmp(argv[1], "ulaw2wave"))
	{
		if (argc <= 3)
			goto usage;
		if ((fp=fopen(argv[3],"w")))
		{
			write_law(fp,argv[2],'u');
			fclose(fp);
		} else
		{
			printf("Cannot open wave file %s\n",argv[3]);
		}
	} else
		goto usage;

	return(0);
}
