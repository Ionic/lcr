/*
 * SS5 signal decoder header file
 *
 */

#define SS5_DECODER_NPOINTS             80 /* size of goertzel window */

char ss5_decode(unsigned char *data, int len, double *quality);
void ss5_test_decode(void);

