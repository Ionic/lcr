/*****************************************************************************\
**                                                                           **
** LCR                                                                       **
**                                                                           **
**---------------------------------------------------------------------------**
** Copyright: Andreas Eversberg                                              **
**                                                                           **
** ss5-port header file                                                      **
**                                                                           **
\*****************************************************************************/

#define SS5_DELAY_MUTE			50*8	/* time to wait until multing */

#define SS5_ENABLE			0x00000001 /* if ccitt5 is defined in interface.conf */
#define SS5_FEATURE_CONNECT		0x00000002 /* send connect to originator of the call */
#define SS5_FEATURE_NODISCONNECT	0x00000004 /* do not send disconnect to originator of call */
#define SS5_FEATURE_RELEASEGUARDTIMER	0x00000008 /* prevent blueboxing by forcing long duration of releas guard signal */
#define SS5_FEATURE_BELL		0x00000010 /* allow breaking and pulse dialing using 2600 Hz */
#define SS5_FEATURE_PULSEDIALING	0x00000020 /* outgoing exchange sends 2600 Hz pulses instead of mf tones */
#define SS5_FEATURE_DELAY		0x00000040 /* simulate round trip delay by delaying decoder output */
#define SS5_FEATURE_RELEASE		0x00000080 /* release if incomming exchange disconnets */
#define SS5_FEATURE_MUTE_RX		0x00000100 /* mute audio path when 2600/2400 Hz tones are detected */
#define SS5_FEATURE_MUTE_TX		0x00000200 /* mute audio path when 2600/2400 Hz tones are detected and reply tones are transmitted */
#define SS5_FEATURE_QUALITY		0x00000400 /* indicate quality of received digits */

/* SS5 port classes */
class Pss5 : public PmISDN
{
	public:
	Pss5(int type, struct mISDNport *mISDNport, char *portname, struct port_settings *settings, struct interface *interface, int channel, int exclusive, int mode);
	~Pss5();
	int message_epoint(unsigned int epoint_id, int message, union parameter *param);
	void set_tone(const char *dir, const char *name);

	int p_m_s_state; /* current signalling state */
	int p_m_s_signal; /* current state of current signal */
	char p_m_s_dial[64]; /* current dialing register */
	int p_m_s_digit_i; /* current digit of register counter */
	int p_m_s_pulsecount; /* counts pule dialing half cycles */
	char p_m_s_last_digit; /* stores last digit that was detected, to fill short signal losses */
	char p_m_s_last_digit_used; /* stores last digit that was used, to ignore short changes of signal due to noise */
	int p_m_s_signal_loss; /* sample counter for loss of signal check */
	int p_m_s_decoder_count; /* samples currently decoded */
	unsigned char p_m_s_decoder_buffer[SS5_DECODER_NPOINTS]; /* buffer for storing one goertzel window */
	unsigned char p_m_s_delay_digits[3000/SS5_DECODER_NPOINTS]; /* delay buffer for received digits */
	unsigned char p_m_s_delay_mute[SS5_DELAY_MUTE/SS5_DECODER_NPOINTS]; /* delay before mute, so a 'chirp' can be heared */
	int p_m_s_sample_nr; /* decoder's sample number, counter */
	double p_m_s_quality_value; /* quality report */
	int p_m_s_quality_count; /* quality report */
	int p_m_s_recog; /* sample counter to wait for signal recognition time */
	struct lcr_work p_m_s_queue;
	int p_m_s_queued_signal; /* queued signal */
	struct lcr_timer p_m_s_timer; /* dialing timeout */

	void new_state(int state);		/* set new state */
	void _new_ss5_state(int state, const char *func, int line);
	void _new_ss5_signal(int signal, const char *func, int line);
	void inband_receive(unsigned char *buffer, int len);
	int inband_send(unsigned char *buffer, int len);
	int inband_dial_mf(unsigned char *buffer, int len, int count);
	int inband_dial_pulse(unsigned char *buffer, int len, int count);
	void start_signal(int);
	void start_outgoing(void);
	void do_release(int cause, int location, int signal);
	void do_setup(char *digit, int complete);

	void seizing_ind(void);
	void digit_ind(char digit);
	void pulse_ind(int on);
	void proceed_to_send_ind(void);
	void busy_flash_ind(void);
	void answer_ind(void);
	void forward_ind(void);
	void clear_back_ind(void);
	void clear_forward_ind(void);
	void release_guard_ind(void);
	void double_seizure_ind(void);
	void forward_transfer_ind(void);
	void message_setup(unsigned int epoint_id, int message_id, union parameter *param);
	void message_connect(unsigned int epoint_id, int message_id, union parameter *param);
	void message_disconnect(unsigned int epoint_id, int message_id, union parameter *param);
	void message_release(unsigned int epoint_id, int message_id, union parameter *param);

	void register_timeout(void);
	void process_queue(void);

};

#define new_ss5_state(a) _new_ss5_state(a, __FUNCTION__, __LINE__)
#define new_ss5_signal(a) _new_ss5_signal(a, __FUNCTION__, __LINE__)

void ss5_create_channel(struct mISDNport *mISDNport, int i);
class Pss5 *ss5_hunt_line(struct mISDNport *mISDNport);

