/*****************************************************************************\
**                                                                           **
** Linux-Call-Router                                                         **
**                                                                           **
**---------------------------------------------------------------------------**
** Copyright: Andreas Eversberg                                              **
**                                                                           **
** data-over-voice                                                           **
**                                                                           **
\*****************************************************************************/ 

/*

Protocol description:

PCM: A bit is defined as sample value. A 1 is positive level, a 0 negative.
The bit rate is 8000 Hz.

PWM: A bit is defined by a duration between polarity change of signal. 4
samples duration is 0, 12 samples duration is 1.

GGGGGGGGGGGGG....
0LLLLLLLL
0DDDDDDDD
0DDDDDDDD
....
0CCCCCCCC
0CCCCCCCC
0CCCCCCCC
0CCCCCCCC
GGGGGGGGGGGGG....

G=guard / sync sequnce (bit=1)
L=length information (lsb first)
D=data (lsb first)
C=CRC (lsb first, network byte order)

*/

#include "main.h"

//#define DEBUG_DOV

#define DOV_PWM_LEVEL 819
#define DOV_PCM_LEVEL 100
#define DOV_PCM_GUARD 400
#define DOV_PWM_GUARD 34

#define DOV_TX_SEND_DELAY	3, 0
#define DOV_RX_LISTEN_TIMEOUT	30, 0

static unsigned int dov_crc32_table[256];

inline unsigned int dov_crc_reflect(unsigned int ref, unsigned char ch)
{
	unsigned int value = 0;
	int i;

	for (i = 1; i < ch + 1; i++) {
		if ((ref & 1))
			value |= 1 << (ch - i);
		ref >>= 1;
	}
	return value;
}


/*
 * initialize CRC table
 */
void dov_crc_init(void)
{
	unsigned int ulPolynomial = 0x04c11db7;
	int i, j;

	for (i = 0; i < 256; i++) {
		dov_crc32_table[i] = dov_crc_reflect(i, 8) << 24;
		for (j = 0; j < 8; j++)
			dov_crc32_table[i] = (dov_crc32_table[i] << 1) ^
				(dov_crc32_table[i] & (1 << 31) ?
					ulPolynomial : 0);
		dov_crc32_table[i] =
			dov_crc_reflect(dov_crc32_table[i], 32);
	}
}


/*
 * calculate CRC 32 of given data
 *
 * data: pointer to data
 * length: length of data
 * return: CRC 32
 */
unsigned int dov_crc32(unsigned char *data, int length)
{
	unsigned int crc = 0xffffffff;

	while (length--)
		crc = (crc >> 8) ^ dov_crc32_table[(crc & 0xff) ^ *data++];

	return crc ^ 0xffffffff;
}

int dov_tx_timer(struct lcr_timer *timer, void *instance, int index);
int dov_rx_timer(struct lcr_timer *timer, void *instance, int index);

void Port::dov_init(void)
{
#ifdef DEBUG_DOV
	printf("DOV: init\n");
#endif

	dov_crc_init();
	p_dov_tx = 0;
	p_dov_rx = 0;
	p_dov_tx_data = NULL;
	p_dov_rx_data = NULL;
	memset(&p_dov_tx_timer, 0, sizeof(p_dov_tx_timer));
        add_timer(&p_dov_tx_timer, dov_tx_timer, this, 0);
	memset(&p_dov_rx_timer, 0, sizeof(p_dov_rx_timer));
        add_timer(&p_dov_rx_timer, dov_rx_timer, this, 0);
}


void Port::dov_reset_tx(void)
{
#ifdef DEBUG_DOV
	printf("DOV: reset TX\n");
#endif

	if (p_dov_tx_data)
		FREE(p_dov_tx_data, p_dov_tx_data_length);
	p_dov_tx_data = NULL;
	p_dov_tx = 0;
	unsched_timer(&p_dov_tx_timer);
}

void Port::dov_reset_rx(void)
{
#ifdef DEBUG_DOV
	printf("DOV: reset RX\n");
#endif

	if (p_dov_rx_data)
		FREE(p_dov_rx_data, 255 + 5);
	p_dov_rx_data = NULL;
	p_dov_rx = 0;
	update_rxoff();
	unsched_timer(&p_dov_rx_timer);
}

void Port::dov_exit(void)
{
#ifdef DEBUG_DOV
	printf("DOV: exit\n");
#endif

	dov_reset_tx();
	del_timer(&p_dov_tx_timer);
	dov_reset_rx();
	del_timer(&p_dov_rx_timer);
}

void Port::dov_sendmsg(unsigned char *data, int length, enum dov_type type, int level)
{
	unsigned int crc;

#ifdef DEBUG_DOV
	printf("DOV: send message, start timer\n");
#endif

	dov_reset_tx();

	if (!length)
		return;
	p_dov_tx_data = (unsigned char *)MALLOC(length + 5);
	p_dov_tx_data[0] = length;
	memcpy(p_dov_tx_data + 1, data, length);
	crc = dov_crc32(data, length);
	p_dov_tx_data[length+1] = crc >> 24;
	p_dov_tx_data[length+2] = crc >> 16;
	p_dov_tx_data[length+3] = crc >> 8;
	p_dov_tx_data[length+4] = crc;
	p_dov_tx_data_length = length + 5;
	p_dov_tx_data_pos = 0;
	p_dov_tx_sync = 1;
	p_dov_tx_bit_pos = 0;
	p_dov_tx_pwm_pos = 0;

	p_dov_tx_type = type;
	if (level) {
		p_dov_up = audio_s16_to_law[(level) & 0xffff];
		p_dov_down = audio_s16_to_law[(-level) & 0xffff];
	} else if (type == DOV_TYPE_PWM) {
		p_dov_up = audio_s16_to_law[(DOV_PWM_LEVEL) & 0xffff];
		p_dov_down = audio_s16_to_law[(-DOV_PWM_LEVEL) & 0xffff];
	} else {
		p_dov_up = audio_s16_to_law[(DOV_PCM_LEVEL) & 0xffff];
		p_dov_down = audio_s16_to_law[(-DOV_PCM_LEVEL) & 0xffff];
	}

	schedule_timer(&p_dov_tx_timer, DOV_TX_SEND_DELAY);
}

int dov_tx_timer(struct lcr_timer *timer, void *instance, int index)
{
	class Port *port = (class Port *)instance;

#ifdef DEBUG_DOV
	printf("DOV: timer fires, now sending\n");
#endif

	port->p_dov_tx = 1;

	return 0;
}

int Port::dov_tx(unsigned char *data, int length)
{
	int left = 0;

	if (!p_dov_tx)
		return 0;

	switch (p_dov_tx_type) {
	case DOV_TYPE_PWM:
#ifdef DEBUG_DOV
		printf("DOV: prepare %d bytes of PWM data\n", length);
#endif
		left = dov_tx_pwm(data, length);
		break;
	case DOV_TYPE_PCM:
#ifdef DEBUG_DOV
		printf("DOV: prepare %d bytes of PCM data\n", length);
#endif
		left = dov_tx_pcm(data, length);
		break;
	}

	return length - left;
}

int Port::dov_tx_pwm(unsigned char *data, int length)
{
	while (length) {
		/* send sync / guard sequence */
		if (p_dov_tx_sync) {
			if (p_dov_tx_up) {
				while (p_dov_tx_pwm_pos < 12) {
					*data++ = p_dov_up;
					p_dov_tx_pwm_pos++;
					if (--length == 0)
						return 0;
				}
				p_dov_tx_up = 0;
			} else {
				while (p_dov_tx_pwm_pos < 12) {
					*data++ = p_dov_down;
					p_dov_tx_pwm_pos++;
					if (--length == 0)
						return 0;
				}
				p_dov_tx_up = 1;
			}
			p_dov_tx_pwm_pos = 0;
			if (++p_dov_tx_bit_pos == DOV_PWM_GUARD) {
#ifdef DEBUG_DOV
				printf("DOV: TX, done with guard\n");
#endif
				p_dov_tx_bit_pos = -1;
				if (p_dov_tx_sync == 2) {
					dov_reset_tx();
					return length;
				}
				p_dov_tx_sync = 0;
			}
			continue;
		}

		/* send start of byte */
		if (p_dov_tx_data_length == -1) {
			if (p_dov_tx_up) {
				while (p_dov_tx_pwm_pos < 4) {
					*data++ = p_dov_up;
					p_dov_tx_pwm_pos++;
					if (--length == 0)
						return 0;
				}
				p_dov_tx_up = 0;
			} else {
				while (p_dov_tx_pwm_pos < 4) {
					*data++ = p_dov_down;
					p_dov_tx_pwm_pos++;
					if (--length == 0)
						return 0;
				}
				p_dov_tx_up = 1;
			}
			p_dov_tx_pwm_pos = 0;
			p_dov_tx_bit_pos = 0;
			continue;
		}

		/* send data */
		if ((p_dov_tx_data[p_dov_tx_data_pos] >> p_dov_tx_bit_pos) & 1) {
			if (p_dov_tx_up) {
				while (p_dov_tx_pwm_pos < 12) {
					*data++ = p_dov_up;
					p_dov_tx_pwm_pos++;
					if (--length == 0)
						return 0;
				}
				p_dov_tx_up = 0;
			} else {
				while (p_dov_tx_pwm_pos < 12) {
					*data++ = p_dov_down;
					p_dov_tx_pwm_pos++;
					if (--length == 0)
						return 0;
				}
				p_dov_tx_up = 1;
			}
		} else {
			if (p_dov_tx_up) {
				while (p_dov_tx_pwm_pos < 4) {
					*data++ = p_dov_up;
					p_dov_tx_pwm_pos++;
					if (--length == 0)
						return 0;
				}
				p_dov_tx_up = 0;
			} else {
				while (p_dov_tx_pwm_pos < 4) {
					*data++ = p_dov_down;
					p_dov_tx_pwm_pos++;
					if (--length == 0)
						return 0;
				}
				p_dov_tx_up = 1;
			}
		}
		p_dov_tx_pwm_pos = 0;
		if (++p_dov_tx_bit_pos == 8) {
			p_dov_tx_bit_pos = -1;
#ifdef DEBUG_DOV
			printf("DOV: TX, done with byte %d\n", p_dov_tx_data[p_dov_tx_data_pos]);
#endif
			if (p_dov_tx_data_pos++ == p_dov_tx_data_length) {
				p_dov_tx_sync = 2;
			}
		}
	}

	return 0;
}

int Port::dov_tx_pcm(unsigned char *data, int length)
{
	while (length--) {
		/* send sync / guard sequence */
		if (p_dov_tx_sync) {
			*data++ = p_dov_up;
			if (++p_dov_tx_bit_pos == DOV_PCM_GUARD) {
#ifdef DEBUG_DOV
				printf("DOV: TX, done with guard\n");
#endif
				p_dov_tx_bit_pos = -1;
				if (p_dov_tx_sync == 2) {
					dov_reset_tx();
					return length;
				}
				p_dov_tx_sync = 0;
			}
			continue;
		}

		/* send start of byte */
		if (p_dov_tx_data_length == -1) {
			*data++ = p_dov_down;
			p_dov_tx_bit_pos = 0;
			continue;
		}

		/* send data */
		*data++ = (((p_dov_tx_data[p_dov_tx_data_pos] >> p_dov_tx_bit_pos) & 1)) ? p_dov_up : p_dov_down;
		if (++p_dov_tx_bit_pos == 8) {
			p_dov_tx_bit_pos = -1;
#ifdef DEBUG_DOV
			printf("DOV: TX, done with byte %d\n", p_dov_tx_data[p_dov_tx_data_pos]);
#endif
			if (p_dov_tx_data_pos++ == p_dov_tx_data_length) {
				p_dov_tx_sync = 2;
			}
		}
	}

	return 0;
}

void Port::dov_listen(enum dov_type type)
{
#ifdef DEBUG_DOV
	printf("DOV: start listening, start timer\n");
#endif

	dov_reset_rx();

	p_dov_rx_data = (unsigned char *)MALLOC(255 + 5);
	p_dov_rx_data_pos = 0;
	p_dov_rx_sync = 1;
	p_dov_rx_bit_pos = 0;
	p_dov_rx_pwm_pos = 0;
	p_dov_rx_pwm_duration = 0;
	p_dov_rx_pwm_polarity = 0;
	p_dov_rx_sync_word = 0;

	p_dov_rx_type = type;

	p_dov_rx = 1;
	update_rxoff();

	schedule_timer(&p_dov_rx_timer, DOV_RX_LISTEN_TIMEOUT);
}

int dov_rx_timer(struct lcr_timer *timer, void *instance, int index)
{
	class Port *port = (class Port *)instance;

#ifdef DEBUG_DOV
	printf("DOV: timer fires, now stop listening\n");
#endif

	port->dov_reset_rx();

	return 0;
}

void Port::dov_rx(unsigned char *data, int length)
{
	if (!p_dov_rx)
		return;

	switch (p_dov_rx_type) {
	case DOV_TYPE_PWM:
#ifdef DEBUG_DOV
		printf("DOV: received %d bytes of PWM data\n", length);
#endif
		dov_rx_pwm(data, length);
		break;
	case DOV_TYPE_PCM:
#ifdef DEBUG_DOV
		printf("DOV: received %d bytes of PCM data\n", length);
#endif
		dov_rx_pcm(data, length);
		break;
	}
}

void Port::dov_rx_pwm(unsigned char *data, int length)
{
	signed int sample;
	signed int level;

	while (length--) {
		sample = audio_law_to_s32[*data++];
		p_dov_rx_pwm_duration++;
		if (p_dov_rx_pwm_polarity == 1) {
			if (sample > 0)
				continue;
			p_dov_rx_pwm_polarity = 0;
			if (p_dov_rx_pwm_duration < 8)
				level = 0;
			else
				level = 1;
			p_dov_rx_pwm_duration = 0;
		} else {
			if (sample <= 0)
				continue;
			p_dov_rx_pwm_polarity = 1;
			if (p_dov_rx_pwm_duration < 8)
				level = 0;
			else
				level = 1;
			p_dov_rx_pwm_duration = 0;
		}

		/* catch sync */
		p_dov_rx_sync_word <<= 1;
		if (level > 0)
			p_dov_rx_sync_word |= 1;
		if ((p_dov_rx_sync_word & 0x1ff) == 0x1ff) {
			p_dov_rx_bit_pos = -1;
			p_dov_rx_sync = 1;
			p_dov_rx_data_pos = 0;
			continue;
		}
		/* wait for sync */
		if (!p_dov_rx_sync) {
			continue;
		}
		/* read start bit */
		if (p_dov_rx_bit_pos == -1) {
			/* check violation of start bit */
			if (level > 0) {
				p_dov_rx_sync = 0;
				continue;
			}
			p_dov_rx_bit_pos = 0;
			continue;
		}
		/* read data */
		p_dov_rx_data[p_dov_rx_data_pos] >>= 1;
		if (level > 0)
			p_dov_rx_data[p_dov_rx_data_pos] |= 128;
		if (++p_dov_rx_bit_pos == 8) {
#ifdef DEBUG_DOV
			printf("DOV: RX byte %d\n", p_dov_rx_data[p_dov_rx_data_pos]);
#endif
			p_dov_rx_bit_pos = -1;
			/* check for length,data,crc32 */
			if (++p_dov_rx_data_pos == p_dov_rx_data[0] + 5) {
				dov_message(p_dov_rx_data + 1, p_dov_rx_data[0]);
				p_dov_rx_sync = 0;
			}
		}
	}

}

void Port::dov_rx_pcm(unsigned char *data, int length)
{
	signed int level;

	while (length--) {
		level = audio_law_to_s32[*data++];
		/* catch sync */
		p_dov_rx_sync_word <<= 1;
		if (level > 0)
			p_dov_rx_sync_word |= 1;
		if ((p_dov_rx_sync_word & 0x1ff) == 0x1ff) {
			p_dov_rx_bit_pos = -1;
			p_dov_rx_sync = 1;
			p_dov_rx_data_pos = 0;
			continue;
		}
		/* wait for sync */
		if (!p_dov_rx_sync) {
			continue;
		}
		/* read start bit */
		if (p_dov_rx_bit_pos == -1) {
			/* check violation of start bit */
			if (level > 0) {
				p_dov_rx_sync = 0;
				continue;
			}
			p_dov_rx_bit_pos = 0;
			continue;
		}
		/* read data */
		p_dov_rx_data[p_dov_rx_data_pos] >>= 1;
		if (level > 0)
			p_dov_rx_data[p_dov_rx_data_pos] |= 128;
		if (++p_dov_rx_bit_pos == 8) {
#ifdef DEBUG_DOV
			printf("DOV: RX byte %d\n", p_dov_rx_data[p_dov_rx_data_pos]);
#endif
			p_dov_rx_bit_pos = -1;
			/* check for length,data,crc32 */
			if (++p_dov_rx_data_pos == p_dov_rx_data[0] + 5) {
				dov_message(p_dov_rx_data + 1, p_dov_rx_data[0]);
				p_dov_rx_sync = 0;
			}
		}
	}
}

void Port::dov_message(unsigned char *data, int length)
{
	unsigned int crc;
	struct lcr_msg *message;

	/* prevent receiving zeroes (due to line noise). this would cause 0 crc, which seems correct. */
	if (length == 0)
		return;

#ifdef DEBUG_DOV
	printf("DOV: received message\n");
#endif

	crc = dov_crc32(p_dov_rx_data + 1, p_dov_rx_data[0]);
	if (crc != (unsigned int) (	((p_dov_rx_data[length+1]) << 24) |
					((p_dov_rx_data[length+2]) << 16) |
					((p_dov_rx_data[length+3]) << 8) |
					(p_dov_rx_data[length+4]) ))
		return;

#ifdef DEBUG_DOV
	printf("DOV: crc OK\n");
#endif

	message = message_create(p_serial, ACTIVE_EPOINT(p_epointlist), PORT_TO_EPOINT, MESSAGE_DOV_INDICATION);
	message->param.dov.type = p_dov_rx_type;
	message->param.dov.length = p_dov_rx_data[0];
	memcpy(message->param.dov.data, p_dov_rx_data + 1, p_dov_rx_data[0]);
	PDEBUG(DEBUG_PORT, "PmISDN(%s) Data-Over-Voice message received (len=%d)\n", p_name, message->param.dov.length);
	message_put(message);

	dov_reset_rx();
}

