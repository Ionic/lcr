
/* GSM port class */
class Pgsm_bs : public Pgsm
{
	public:
	Pgsm_bs(int type, char *portname, struct port_settings *settings, struct interface *interface);
	~Pgsm_bs();

	unsigned char *p_g_dtmf; /* DTMF tone generation (MS only) */
	int p_g_dtmf_index; /* DTMF tone generation index */

	void select_payload_type(struct gsm_mncc *mncc, unsigned char *payload_types, int *media_types, int *payloads, int max_payloads);
	void setup_ind(unsigned int msg_type, unsigned int callref, struct gsm_mncc *mncc);
	void call_conf_ind(unsigned int msg_type, unsigned int callref, struct gsm_mncc *gsm);
	void start_dtmf_ind(unsigned int msg_type, unsigned int callref, struct gsm_mncc *mncc);
	void stop_dtmf_ind(unsigned int msg_type, unsigned int callref, struct gsm_mncc *mncc);
	void hold_ind(unsigned int msg_type, unsigned int callref, struct gsm_mncc *mncc);
	void retr_ind(unsigned int msg_type, unsigned int callref, struct gsm_mncc *mncc);
	void enc_ie_facility(struct gsm_mncc *mncc, int operation_code, int error_code, unsigned char invoke_id);
	void facility_req(int operation_code, int error_code, unsigned char invoke_id);
	void facility_ind(unsigned int msg_type, unsigned int callref, struct gsm_mncc *mncc);
	void message_3pty(unsigned int epoint_id, int message_id, union parameter *param);
	void enc_ie_facility_ect(struct gsm_mncc *mncc, struct param_transfer *transfer);
	void message_transfer(unsigned int epoint_id, int message_id, union parameter *param);
	void message_setup(unsigned int epoint_id, int message_id, union parameter *param);
	int message_epoint(unsigned int epoint_id, int message_id, union parameter *param);
};

int gsm_bs_conf(struct gsm_conf *gsm_conf, char *conf_error);
int gsm_bs_exit(int rc);
int gsm_bs_init(struct interface *interface);

void gsm_trace_facility(unsigned char *fac_ie, unsigned char fac_len);

int message_bsc(struct lcr_gsm *lcr_gsm, int msg_type, void *arg);
