/*****************************************************************************\
**                                                                           **
** Linux Call Router                                                         **
**                                                                           **
**---------------------------------------------------------------------------**
** Copyright: Andreas Eversberg                                              **
**                                                                           **
** Administration tool header file                                           **
**                                                                           **
\*****************************************************************************/

#define SOCKET_NAME "%s/LCR.socket"

/* structures that define message between admin-tool and pbx */

enum { /* messages */
	ADMIN_REQUEST_CMD_INTERFACE,
	ADMIN_RESPONSE_CMD_INTERFACE,
	ADMIN_REQUEST_CMD_ROUTE,
	ADMIN_RESPONSE_CMD_ROUTE,
	ADMIN_REQUEST_CMD_DIAL,
	ADMIN_RESPONSE_CMD_DIAL,
	ADMIN_REQUEST_CMD_RELEASE,
	ADMIN_RESPONSE_CMD_RELEASE,
	ADMIN_REQUEST_CMD_BLOCK,
	ADMIN_RESPONSE_CMD_BLOCK,
	ADMIN_REQUEST_STATE,
	ADMIN_RESPONSE_STATE,
	ADMIN_RESPONSE_S_REMOTE,
	ADMIN_RESPONSE_S_INTERFACE,
	ADMIN_RESPONSE_S_PORT,
	ADMIN_RESPONSE_S_EPOINT,
	ADMIN_RESPONSE_S_JOIN,
	ADMIN_CALL_SETUP,
	ADMIN_CALL_SETUP_ACK,
	ADMIN_CALL_PROCEEDING,
	ADMIN_CALL_ALERTING,
	ADMIN_CALL_CONNECT,
	ADMIN_CALL_DISCONNECT,
	ADMIN_CALL_RELEASE,
	ADMIN_CALL_NOTIFY,
	ADMIN_CALL_PROGRESS,
	ADMIN_TRACE_REQUEST,
	ADMIN_TRACE_RESPONSE,
	ADMIN_MESSAGE,
};

struct admin_response_cmd {
	int		error;		/* error code 0 = ok*/
	char		message[256];	/* info / response text */
	int		block;
	int		portnum;
};

struct admin_response_state {
	char		version_string[64];
	struct tm	tm;
	char		logfile[128];
	int		interfaces;
	int		remotes;
	int		joins;
	int		epoints;
	int		ports;
};

struct admin_response_interface {
	char		interface_name[32];
	int		portnum;
	char		portname[64];
	int		block;
	int		ntmode;
	int		ptp;
	int		l1hold;
	int		l2hold;
	int		pri;
	int		extension;
	int		use; /* number of ports that use this interface */
	int		l1link; /* down(0) or up(1) */
	int		l2link; /* down(0) or up(1) */
	unsigned char	l2mask[16]; /* one bit for each tei */
	int		los, ais, rdi, slip_tx, slip_rx;
	int		channels;
	char		busy[256]; /* if port is idle(0) busy(1) */
	unsigned int	port[256]; /* current port */
	int		mode[256];
	char		out_channel[256];
	char		in_channel[256];
};

struct admin_response_remote {
	char 		name[32]; /* name of remote application */
};

struct admin_response_join {
	unsigned int	serial; /* join serial number */
	char		remote[32]; /* remote application name */
	unsigned int	partyline;
	unsigned int	threepty;
};

struct admin_response_epoint {
	unsigned int	serial;
	unsigned int	join; /* link to join */
//	int		join_notify; /* if relation notified on hold */
//	int		join_hold; /* if relation on hold */
	int		rx_state;
	int		tx_state;
	int		state;
	char		terminal[16];
	char		callerid[64];
	char		dialing[64];
	char		action[32];
	int		park; /* if parked */
	int		park_len;
	unsigned char	park_callid[8];
	int		crypt; /* crypt state */
};

struct admin_response_port {
	unsigned int	serial; /* port serial number */
	char		name[64]; /* name of port */
	unsigned int	epoint; /* link to epoint */
	int		state;
	int		isdn; /* if port is isdn */
	int		isdn_chan; /* bchannel number */
	int		isdn_hold; /* on hold */
	int		isdn_ces; /* ces to use (>=0)*/
};

struct admin_call {
	char		interface[64]; /* name of port */
	char		callerid[64]; /* use caller id */
	char		dialing[64]; /* number to dial */
	int		present; /* presentation */
	int		cause; /* cause to send */
	int		location;
	int		notify_progress;
	int		bc_capa;
	int		bc_mode;
	int		bc_info1;
	int		hlc;
	int		exthlc;
};

struct admin_trace_req {
	int		detail;
	char		category;
	int		port;
	char		interface[64];
	char		caller[34];
	char		dialing[64];
};

struct admin_trace_rsp {
	char		text[1024];
};

struct admin_msg {
	int		type; /* type of message */
	unsigned int	ref; /* reference to individual endpoints */
	union parameter	param; /* parameter union */
};

struct admin_message {
	int message; /* type of admin message */
	union u {
		struct admin_response_cmd	x;
		struct admin_response_state	s;
		struct admin_response_interface	i;
		struct admin_response_port	p;
		struct admin_response_epoint	e;
		struct admin_response_join	j;
		struct admin_response_remote	r;
		struct admin_call		call;
		struct admin_msg		msg;
		struct admin_trace_req		trace_req;
		struct admin_trace_rsp		trace_rsp;
	} u;
};

/* call states */
enum {
	ADMIN_STATE_IDLE,
	ADMIN_STATE_IN_SETUP,
	ADMIN_STATE_OUT_SETUP,
	ADMIN_STATE_IN_OVERLAP,
	ADMIN_STATE_OUT_OVERLAP,
	ADMIN_STATE_IN_PROCEEDING,
	ADMIN_STATE_OUT_PROCEEDING,
	ADMIN_STATE_IN_ALERTING,
	ADMIN_STATE_OUT_ALERTING,
	ADMIN_STATE_CONNECT,
	ADMIN_STATE_IN_DISCONNECT,
	ADMIN_STATE_OUT_DISCONNECT,
	ADMIN_STATE_RELEASE,
};
