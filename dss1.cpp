/*****************************************************************************\
**                                                                           **
** PBX4Linux                                                                 **
**                                                                           **
**---------------------------------------------------------------------------**
** Copyright: Andreas Eversberg                                              **
**                                                                           **
** mISDN dss1                                                                **
**                                                                           **
\*****************************************************************************/ 


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "main.h"
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
extern "C" {
#include <net_l2.h>
}

//#define CENTREX

#include "q931.h"
#include "ie.cpp"


/*
 * constructor
 */
Pdss1::Pdss1(int type, mISDNport *mISDNport, char *portname, struct port_settings *settings, int channel, int exclusive) : PmISDN(type, mISDNport, portname, settings, channel, exclusive)
{
	p_callerinfo.itype = (mISDNport->ifport->interface->extension)?INFO_ITYPE_ISDN:INFO_ITYPE_ISDN_EXTENSION;
	p_m_d_ntmode = mISDNport->ntmode;
	p_m_d_l3id = 0;
	p_m_d_ces = -1;
	p_m_d_queue = NULL;
	p_m_d_notify_pending = NULL;
	p_m_d_collect_cause = CAUSE_NOUSER;
	p_m_d_collect_location = LOCATION_PRIVATE_LOCAL;


	PDEBUG(DEBUG_ISDN, "Created new mISDNPort(%s). Currently %d objects use, %s port #%d\n", portname, mISDNport->use, (mISDNport->ntmode)?"NT":"TE", p_m_portnum);
}


/*
 * destructor
 */
Pdss1::~Pdss1()
{
	/* remove queued message */
	if (p_m_d_queue)
		message_free(p_m_d_queue);

	if (p_m_d_notify_pending)
		message_free(p_m_d_notify_pending);

	/* check how many processes are left */
	if (p_m_d_ntmode == 1)
	{
		if (p_m_mISDNport->nst.layer3->proc)
			PDEBUG(DEBUG_ISDN, "destroyed mISDNPort(%s). WARNING: There is still a layer 3 process left. Ignore this, if currently are other calls. This message is not an error!\n", p_name);
	}
}


/*
 * create layer 3 message
 */
static msg_t *create_l3msg(int prim, int mt, int dinfo, int size, int ntmode)
{
	int i = 0;
	msg_t *dmsg;
	Q931_info_t *qi;
	iframe_t *frm;

	if (!ntmode)
		size = sizeof(Q931_info_t)+2;

	while(i < 10)
	{
		if (ntmode)
		{
			dmsg = prep_l3data_msg(prim, dinfo, size, 256, NULL);
			if (dmsg)
			{
				return(dmsg);
			}
		} else
		{
			dmsg = alloc_msg(size+256+mISDN_HEADER_LEN+DEFAULT_HEADROOM);
			if (dmsg)
			{
				memset(msg_put(dmsg,size+mISDN_HEADER_LEN), 0, size+mISDN_HEADER_LEN);
				frm = (iframe_t *)dmsg->data;
				frm->prim = prim;
				frm->dinfo = dinfo;
				qi = (Q931_info_t *)(dmsg->data + mISDN_HEADER_LEN);
				qi->type = mt;
				return(dmsg);
			}
		}

		if (!i)
			PERROR("cannot allocate memory, trying again...\n");
		i++;
		usleep(50000);
	}
	PERROR("cannot allocate memory, system overloaded.\n");
	exit(-1);
}

msg_t *create_l2msg(int prim, int dinfo, int size) /* NT only */
{
	int i = 0;
	msg_t *dmsg;

	while(i < 10)
	{
		dmsg = prep_l3data_msg(prim, dinfo, size, 256, NULL);
		if (dmsg)
			return(dmsg);

		if (!i)
			PERROR("cannot allocate memory, trying again...\n");
		i++;
		usleep(50000);
	}
	PERROR("cannot allocate memory, system overloaded.\n");
	exit(-1);
}

/* isdn messaging */
static struct isdn_message {
	char *name;
	unsigned long value;
} isdn_message[] = {
	{"TIMEOUT", CC_TIMEOUT},
	{"SETUP", CC_SETUP},
	{"SETUP_ACK", CC_SETUP_ACKNOWLEDGE},
	{"PROCEEDING", CC_PROCEEDING},
	{"ALERTING", CC_ALERTING},
	{"CONNECT", CC_CONNECT},
	{"CONNECT RES", CC_CONNECT},
	{"CONNECT_ACK", CC_CONNECT_ACKNOWLEDGE},
	{"DISCONNECT", CC_DISCONNECT},
	{"RELEASE", CC_RELEASE},
	{"RELEASE_COMP", CC_RELEASE_COMPLETE},
	{"INFORMATION", CC_INFORMATION},
	{"PROGRESS", CC_PROGRESS},
	{"NOTIFY", CC_NOTIFY},
	{"SUSPEND", CC_SUSPEND},
	{"SUSPEND_ACK", CC_SUSPEND_ACKNOWLEDGE},
	{"SUSPEND_REJ", CC_SUSPEND_REJECT},
	{"RESUME", CC_RESUME},
	{"RESUME_ACK", CC_RESUME_ACKNOWLEDGE},
	{"RESUME_REJ", CC_RESUME_REJECT},
	{"HOLD", CC_HOLD},
	{"HOLD_ACK", CC_HOLD_ACKNOWLEDGE},
	{"HOLD_REJ", CC_HOLD_REJECT},
	{"RETRIEVE", CC_RETRIEVE},
	{"RETRIEVE_ACK", CC_RETRIEVE_ACKNOWLEDGE},
	{"RETRIEVE_REJ", CC_RETRIEVE_REJECT},
	{"FACILITY", CC_FACILITY},
	{"STATUS", CC_STATUS},
	{"RESTART", CC_RESTART},
	{"RELEASE_CR", CC_RELEASE_CR},
	{"NEW_CR", CC_NEW_CR},

	{NULL, 0},
};

static char *isdn_prim[4] = {
	" REQUEST",
	" CONFIRM",
	" INDICATION",
	" RESPONSE",
};


/*
 * isdn trace header
 */
void Pdss1::l3_trace_header(unsigned long prim, int direction_out)
{
	int i;
	char msgtext[64] = "<<UNKNOWN MESSAGE>>";

	/* select message and primitive text */
	i = 0;
	while(isdn_message[i].name)
	{
		if (isdn_message[i].value == (prim&0xffffff00))
		{
			SCPY(msgtext, isdn_message[i].name);
			break;
		}
		i++;
	}
	SCAT(msgtext, isdn_prim[prim&0x00000003]);

	/* add direction */
	if (direction && (prim&0xffffff00)!=CC_NEW_CR && (prim&0xffffff00)!=CC_RELEASE_CR)
	{
		if (p_m_ntmode)
		{
			if (direction == DIRECTION_OUT)
				SCAT(msgtext, " N->U");
			else
				SCAT(msgtext, " N<-U");
		} else
		{
			if (direction == DIRECTION_OUT)
				SCAT(msgtext, " U->N");
			else
				SCAT(msgtext, " U<-N");
		}
	}

	/* init trace with given values */
	start_trace(p_m_mISDNport->portnum,
		    p_m_mISDNport->ifport->interface,
		    nationalize(p_callerinfo.id, p_callerinfo.ntype),
		    p_dialinginfo.number,
		    direction,
		    CATEGORY_L3,
		    msgtext);
}


/*
 * if we received a first reply to the setup message,
 * we will check if we have now channel information 
 * return: <0: error, call is released, -cause is given
 *	    0: ok, nothing to do
 */
int Pdss1::received_first_reply_to_setup(unsigned long prim, int channel, int exclusive)
{
	int ret;
	int headerlen = (p_m_d_ntmode)?mISDNUSER_HEAD_SIZE:mISDN_HEADER_LEN;
	RELEASE_COMPLETE_t *release_complete;
	msg_t *dmsg;

	/* correct exclusive to 0, if no explicit channel was given */
	if (exclusive<0 || channel<=0)
		exclusive = 0;
	
	/* select scenario */
	if (p_m_b_channel && p_m_b_exclusive)
	{
		/*** we gave an exclusive channel (or if we are done) ***/

		/* if not first reply, we are done */
		if (p_state != PORT_STATE_OUT_SETUP)
			return(0);

		start_trace(p_m_mISDNport->portnum,
			    p_m_mISDNport->ifport->interface,
			    nationalize(p_callerinfo.id, p_callerinfo.ntype),
			    p_dialinginfo.number,
			    DIRECTION_OUT,
			    CATEGORY_CH,
			    "CHANNEL SELECTION (first reply to setup)");
		add_trace("channel", "request", "%d (forced)", p_m_b_channel);
		add_trace("channel", "reply", (channel>=0)?"%d":"(none)", channel);

		/* if give channel not accepted or not equal */
		if (channel!=-1 && p_m_b_channel!=channel)
		{
			add_trace("conclusion", NULL, "forced channel not accepted");
			end_trace();
			ret = -44;
			goto channelerror;
		}

		add_trace("conclusion", NULL, "channel was accepted");
		add_trace("connect", "channel", "%d", p_m_b_channel);
		end_trace();

		/* activate our exclusive channel */
		bchannel_activate(p_m_mISDNport, p_m_b_index);
	} else
	if (p_m_b_channel)
	{
		/*** we gave a non-exclusive channel ***/

		/* if not first reply, we are done */
		if (p_state != PORT_STATE_OUT_SETUP)
			return(0);

		start_trace(p_m_mISDNport->portnum,
			    p_m_mISDNport->ifport->interface,
			    nationalize(p_callerinfo.id, p_callerinfo.ntype),
			    p_dialinginfo.number,
			    DIRECTION_OUT,
			    CATEGORY_CH,
			    "CHANNEL SELECTION (first reply to setup)");
		add_trace("channel", "request", "%d (suggest)", p_m_b_channel);
		add_trace("channel", "reply", (channel>=0)?"%d":"(none)", channel);

		/* if channel was accepted as given */
		if (channel==-1 || p_m_b_channel==channel)
		{
			add_trace("conclusion", NULL, "channel was accepted as given");
			add_trace("connect", "channel", "%d", p_m_b_channel);
			end_trace();
			p_m_b_exclusive = 1; // we are done
			bchannel_activate(p_m_mISDNport, p_m_b_index);
			return(0);
		}

		/* if channel value is faulty */
		if (channel <= 0)
		{
			add_trace("conclusion", NULL, "illegal reply");
			end_trace();
			ret = -111; // protocol error
			goto channelerror;
		}

		/* if channel was not accepted, try to get it */
		PDEBUG(DEBUG_BCHANNEL, "- our suggested channel %d was not accepted, but %d was given.\n", p_m_b_channel, channel);
		ret = seize_bchannel(channel, 1); // exclusively
		add_trace("channel", "available", ret<0?"no":"yes");
		if (ret < 0)
		{
			add_trace("conclusion", NULL, "replied channel not available");
			end_trace();
			PDEBUG(DEBUG_BCHANNEL, "- the replied channel %d is not available (cause %d).\n", channel, -ret);
			goto channelerror;
		}
		add_trace("conclusion", NULL, "replied channel accepted");
		add_trace("connect", "channel", "%d", p_m_b_channel);
		end_trace();

		/* activate channel given by remote */
		bchannel_activate(p_m_mISDNport, p_m_b_index);
	} else
	if (p_m_b_reserve)
	{
		/*** we sent 'any channel acceptable' ***/

		/* if not first reply, we are done */
		if (p_state != PORT_STATE_OUT_SETUP)
			return(0);

		start_trace(p_m_mISDNport->portnum,
			    p_m_mISDNport->ifport->interface,
			    nationalize(p_callerinfo.id, p_callerinfo.ntype),
			    p_dialinginfo.number,
			    DIRECTION_OUT,
			    CATEGORY_CH,
			    "CHANNEL SELECTION (first reply to setup)");
		add_trace("channel", "request", "any");
		add_trace("channel", "reply", (channel>=0)?"%d":"(none)", channel);
		/* if no channel was replied */
		if (channel <= 0)
		{
			add_trace("conclusion", NULL, "no channel, protocol error");
			end_trace();
			ret = -111; // protocol error
			goto channelerror;
		}

		/* we will see, if our received channel is available */
		ret = seize_bchannel(channel, 1); // exclusively
		add_trace("channel", "available", ret<0?"no":"yes");
		if (ret < 0)
		{
			add_trace("conclusion", NULL, "replied channel not available");
			end_trace();
			goto channelerror;
		}
		add_trace("conclusion", NULL, "replied channel accepted");
		add_trace("connect", "channel", "%d", p_m_b_channel);
		end_trace();

		/* activate channel given by remote */
		bchannel_activate(p_m_mISDNport, p_m_b_index);
	} else
	{
		/*** we sent 'no channel available' ***/

		/* if not the first reply, but a connect, we are forced */
		if (prim==(CC_CONNECT | INDICATION) && p_state!=PORT_STATE_OUT_SETUP)
		{
			start_trace(p_m_mISDNport->portnum,
				    p_m_mISDNport->ifport->interface,
				    nationalize(p_callerinfo.id, p_callerinfo.ntype),
				    p_dialinginfo.number,
				    DIRECTION_OUT,
				    CATEGORY_CH,
				    "CHANNEL SELECTION (connect)");
			add_trace("channel", "request", "no-channel");
			add_trace("channel", "reply", (channel>=0)?"%d%s":"(none)", channel, exclusive?" (forced)":"");
			if (channel > 0)
			{
				goto use_from_connect;
			}
			ret = seize_bchannel(CHANNEL_ANY, 0); // any channel
			add_trace("channel", "available", ret<0?"no":"yes");
			if (ret < 0)
			{
				add_trace("conclusion", NULL, "no channel available during call-waiting");
				end_trace();
				goto channelerror;
			}
			add_trace("conclusion", NULL, "using channel %d", p_m_b_channel);
			add_trace("connect", "channel", "%d", p_m_b_channel);
			end_trace();
			p_m_b_exclusive = 1; // we are done

			/* activate channel given by remote */
			bchannel_activate(p_m_mISDNport, p_m_b_index);
			return(0);
		}
		
		/* if not first reply, we are done */
		if (p_state != PORT_STATE_OUT_SETUP)
			return(0);

		start_trace(p_m_mISDNport->portnum,
			    p_m_mISDNport->ifport->interface,
			    nationalize(p_callerinfo.id, p_callerinfo.ntype),
			    p_dialinginfo.number,
			    DIRECTION_OUT,
			    CATEGORY_CH,
			    "CHANNEL SELECTION (first reply to setup)");
		add_trace("channel", "request", "no-channel");
		add_trace("channel", "reply", (channel>=0)?"%d":"(none)", channel);
		/* if first reply has no channel, we are done */
		if (channel <= 0)
		{
			add_trace("conclusion", NULL, "no channel until connect");
			end_trace();
			return(0);
		}

		/* we will see, if our received channel is available */
		PDEBUG(DEBUG_BCHANNEL, "- our during call-waiting, we get channel %d as first reply.\n", channel);
		use_from_connect:
		ret = seize_bchannel(channel, exclusive);
		add_trace("channel", "available", ret<0?"no":"yes");
		if (ret < 0)
		{
			add_trace("conclusion", NULL, "replied channel not available");
			end_trace();
			goto channelerror;
		}
		add_trace("conclusion", NULL, "replied channel accepted");
		add_trace("connect", "channel", "%d", p_m_b_channel);
		end_trace();
		p_m_b_exclusive = 1; // we are done

		/* activate channel given by remote */
		bchannel_activate(p_m_mISDNport, p_m_b_index);
	}
	return(0);

	channelerror:
	dmsg = create_l3msg(CC_RELEASE_COMPLETE | REQUEST, MT_RELEASE_COMPLETE, p_m_d_l3id, sizeof(RELEASE_COMPLETE_t), p_m_d_ntmode);
	l3_trace_header(CC_RELEASE_COMPLETE | REQUEST, DIRECTION_OUT);

	release_complete = (RELEASE_COMPLETE_t *)(dmsg->data + headerlen);
	enc_ie_cause(&release_complete->CAUSE, dmsg, (p_m_d_ntmode)?LOCATION_PRIVATE_LOCAL:LOCATION_PRIVATE_REMOTE, -ret);
	end_trace();
	msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);
	new_state(PORT_STATE_RELEASE);
	p_m_delete = 1;
	return(-34); /* to epoint: no channel available */
}


/*
 * handles all indications
 */
/* CC_SETUP INDICATION */
void Pdss1::setup_ind(unsigned long prim, unsigned long dinfo, void *data)
{
	int headerlen = (p_m_d_ntmode)?mISDNUSER_HEAD_SIZE:mISDN_HEADER_LEN;
	SETUP_t *setup = (SETUP_t *)((unsigned long)data + headerlen);
	int type, plan, present, screen, reason;
	int coding, capability, mode, rate, multi, user, presentation, interpretation, hlc, exthlc;
	int exclusive, channel;
	int ret;
	msg_t *dmsg;
	unsigned char keypad[32] = "";
	unsigned char useruser[128];
	int useruser_len = 0, useruser_protocol;
	class Endpoint *epoint;
	struct message *message;

	/* callref from nt-lib */
	if (p_m_d_ntmode)
	{
		/* nt-library now gives us the id via CC_SETUP */
		if (dinfo&(~0xff) == 0xff00)
		{
			PERROR("fatal software error: l3-stack gives us a process id 0xff00-0xffff\n");
			exit(-1);
		}
		l3_trace_header(CC_NEW_CR | INDICATION, DIRECTION_IN);
		if (p_m_d_l3id)
			add_trace("callref", "old", "0x%x", p_m_d_l3id);
		add_trace("callref", "new", "0x%x", dinfo);
		end_trace();
		if (p_m_d_l3id&(~0xff) == 0xff00)
			p_m_mISDNport->procids[p_m_d_l3id&0xff] = 0;
		p_m_d_l3id = dinfo;
		p_m_d_ces = setup->ces;
	}

	l3_trace_header(prim, DIRECTION_IN);
	dec_ie_calling_pn(setup->CALLING_PN, (Q931_info_t *)((unsigned long)data+headerlen), &calling_type, &calling_plan, &calling_present, &calling_screen, (unsigned char *)p_callerinfo.id, sizeof(p_callerinfo.id));
	dec_ie_called_pn(setup->CALLED_PN, (Q931_info_t *)((unsigned long)data+headerlen), &called_type, &called_plan, (unsigned char *)p_dialinginfo.number, sizeof(p_dialinginfo.number));
	dec_ie_keypad(setup->KEYPAD, (Q931_info_t *)((unsigned long)data+headerlen), (unsigned char *)keypad, sizeof(keypad));
#ifdef CENTREX
	/* te-mode: CNIP (calling name identification presentation) */
	if (!p_m_d_ntmode)
		dec_facility_centrex(setup->FACILITY, (Q931_info_t *)((unsigned long)data+headerlen), (unsigned char *)p_callerinfo.name, sizeof(p_callerinfo.name));
#endif
	dec_ie_useruser(setup->USER_USER, (Q931_info_t *)((unsigned long)data+headerlen), &useruser_protocol, useruser, &useruser_len);
	dec_ie_complete(setup->COMPLETE, (Q931_info_t *)((unsigned long)data+headerlen), &p_dialinginfo.sending_complete);
	dec_ie_redir_nr(setup->REDIR_NR, (Q931_info_t *)((unsigned long)data+headerlen), &redir_type, &redir_plan, &redir_present, &redir_screen, &redir_reason, (unsigned char *)p_redirinfo.id, sizeof(p_redirinfo.id));
	dec_ie_channel_id(setup->CHANNEL_ID, (Q931_info_t *)((unsigned long)data+headerlen), &exclusive, &channel);
	dec_ie_hlc(setup->HLC, (Q931_info_t *)((unsigned long)data+headerlen), &hlc_coding, &interpretation, &presentation, &hlc, &exthlc);
	dec_ie_bearer(setup->BEARER, (Q931_info_t *)((unsigned long)data+headerlen), &bearer_coding, &capability, &mode, &rate, &multi, &user);
	end_trace();

	/* if blocked, release call */
	if (p_m_mISDNport->ifport->block)
	{
		RELEASE_COMPLETE_t *release_complete;

		printlog("---  port#%d is blocked.\n", mISDNport->ifport->portnum);
		dmsg = create_l3msg(CC_RELEASE_COMPLETE | REQUEST, MT_RELEASE_COMPLETE, dinfo, sizeof(RELEASE_COMPLETE_t), p_m_d_ntmode);
		l3_trace_header(CC_RELEASE_COMPLETE | REQUEST, DIRECTION_OUT);
		release_complete = (RELEASE_COMPLETE_t *)(dmsg->data + headerlen);
		enc_ie_cause(&release_complete->CAUSE, dmsg, (p_m_d_ntmode)?LOCATION_PRIVATE_LOCAL:LOCATION_PRIVATE_REMOTE, 27); /* temporary unavailable */
		add_trace("reason", NULL, "port blocked");
		end_trace();
		msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);
		new_state(PORT_STATE_RELEASE);
		p_m_delete = 1;
		return;
	}

	/* caller info */
	switch (present)
	{
		case 1:
		p_callerinfo.present = INFO_PRESENT_RESTRICTED;
		break;
		case 2:
		p_callerinfo.present = INFO_PRESENT_NOTAVAIL;
		break;
		default:
		p_callerinfo.present = INFO_PRESENT_ALLOWED;
		break;
	}
	switch (screen)
	{
		case 0:
		p_callerinfo.screen = INFO_SCREEN_USER;
		break;
		default:
		p_callerinfo.screen = INFO_SCREEN_NETWORK;
		break;
	}
	switch (type)
	{
		case -1:
		p_callerinfo.ntype = INFO_NTYPE_UNKNOWN;
		p_callerinfo.present = INFO_PRESENT_NOTAVAIL;
		p_callerinfo.screen = INFO_SCREEN_NETWORK;
		break;
		case 0x1:
		p_callerinfo.ntype = INFO_NTYPE_INTERNATIONAL;
		break;
		case 0x2:
		p_callerinfo.ntype = INFO_NTYPE_NATIONAL;
		break;
		case 0x4:
		p_callerinfo.ntype = INFO_NTYPE_SUBSCRIBER;
		break;
		default:
		p_callerinfo.ntype = INFO_NTYPE_UNKNOWN;
		break;
	}
	p_callerinfo.isdn_port = p_m_portnum;
	SCPY(p_callerinfo.interface, p_m_mISDNport->ifport->interface->name);

	/* dialing information */
	SCAT(p_dialinginfo.number, (char *)keypad);
	switch (type)
	{
		case 0x1:
		p_dialinginfo.ntype = INFO_NTYPE_INTERNATIONAL;
		break;
		case 0x2:
		p_dialinginfo.ntype = INFO_NTYPE_NATIONAL;
		break;
		case 0x4:
		p_dialinginfo.ntype = INFO_NTYPE_SUBSCRIBER;
		break;
		default:
		p_dialinginfo.ntype = INFO_NTYPE_UNKNOWN;
		break;
	}
	switch (present)
	{
		case 1:
		p_redirinfo.present = INFO_PRESENT_RESTRICTED;
		break;
		case 2:
		p_redirinfo.present = INFO_PRESENT_NOTAVAIL;
		break;
		default:
		p_redirinfo.present = INFO_PRESENT_ALLOWED;
		break;
	}
	switch (screen)
	{
		case 0:
		p_redirinfo.screen = INFO_SCREEN_USER;
		break;
		default:
		p_redirinfo.screen = INFO_SCREEN_NETWORK;
		break;
	}
	switch (reason)
	{
		case 1:
		p_redirinfo.reason = INFO_REDIR_BUSY;
		break;
		case 2:
		p_redirinfo.reason = INFO_REDIR_NORESPONSE;
		break;
		case 15:
		p_redirinfo.reason = INFO_REDIR_UNCONDITIONAL;
		break;
		case 10:
		p_redirinfo.reason = INFO_REDIR_CALLDEFLECT;
		break;
		case 9:
		p_redirinfo.reason = INFO_REDIR_OUTOFORDER;
		break;
		default:
		p_redirinfo.reason = INFO_REDIR_UNKNOWN;
		break;
	}
	switch (type)
	{
		case -1:
		p_redirinfo.ntype = INFO_NTYPE_UNKNOWN;
		p_redirinfo.present = INFO_PRESENT_NULL; /* not redirecting */
		p_redirinfo.reason = INFO_REDIR_UNKNOWN;
		break;
		case 0x1:
		p_redirinfo.ntype = INFO_NTYPE_INTERNATIONAL;
		break;
		case 0x2:
		p_redirinfo.ntype = INFO_NTYPE_NATIONAL;
		break;
		case 0x4:
		p_redirinfo.ntype = INFO_NTYPE_SUBSCRIBER;
		break;
		default:
		p_redirinfo.ntype = INFO_NTYPE_UNKNOWN;
		break;
	}
	p_redirinfo.isdn_port = p_m_portnum;

	/* bearer capability */
	switch (capability)
	{
		case -1:
		p_capainfo.bearer_capa = INFO_BC_AUDIO;
		user = (options.law=='a')?3:2;
		break;
		default:
		p_capainfo.bearer_capa = capability;
		break;
	}
	switch (mode)
	{
		case 2:
		p_capainfo.bearer_mode = INFO_BMODE_PACKET;
		break;
		default:
		p_capainfo.bearer_mode = INFO_BMODE_CIRCUIT;
		break;
	}
	switch (user)
	{
		case -1:
		p_capainfo.bearer_info1 = INFO_INFO1_NONE;
		break;
		default:
		p_capainfo.bearer_info1 = user + 0x80;
		break;
	}

	/* hlc */
	switch (hlc)
	{
		case -1:
		p_capainfo.hlc = INFO_HLC_NONE;
		break;
		default:
		p_capainfo.hlc = hlc + 0x80;
		break;
	}
	switch (exthlc)
	{
		case -1:
		p_capainfo.exthlc = INFO_HLC_NONE;
		break;
		default:
		p_capainfo.exthlc = exthlc + 0x80;
		break;
	}

	/* process channel */
	start_trace(p_m_mISDNport->portnum,
		    p_m_mISDNport->ifport->interface,
		    nationalize(p_callerinfo.id, p_callerinfo.ntype),
		    p_dialinginfo.number,
		    DIRECTION_IN,
		    CATEGORY_CH,
		    "CHANNEL SELECTION (setup)");
	if (exclusive<0)
		exclusive = 0;
	if (channel == CHANNEL_NO)
		add_trace("channel", "request", "no-channel");
	else
		add_trace("channel", "request", (channel>0)?"%d%s":"any", channel, exclusive?" (forced)":"");
	if (channel==CHANNEL_NO && p_type==PORT_TYPE_DSS1_TE_IN)
	{
		add_trace("conclusion", NULL, "incoming call-waiting not supported for TE-mode");
		end_trace();
		ret = -6; // channel unacceptable
		goto no_channel;
	}
	if (channel <= 0) /* not given, no channel, whatever.. */
		channel = CHANNEL_ANY; /* any channel */
	if (p_m_mISDNport->b_reserved >= p_m_mISDNport->b_num) // of out chan..
	{
		add_trace("channel", "reserved", "%d", p_m_mISDNport->b_reserved);
		add_trace("conclusion", NULL, "all channels are reserved");
		end_trace();
		ret = -34; // no channel
		goto no_channel;
	}
	if (channel == CHANNEL_ANY)
		goto get_from_list;
	if (channel > 0)
	{
		/* check for given channel in selection list */
		selchannel = ifport->channel_in;
		while(selchannel)
		{
			if (selchannel->channel == channel || selchannel->channel == CHANNEL_FREE)
				break;
			selchannel = selchannel->next;
		}
		if (!selchannel)
			channel = 0;

		/* exclusive channel requests must be in the list */
		if (exclusive)
		{
			if (!channel)
			{
				add_trace("conclusion", NULL, "exclusively requested channel not in list");
				end_trace();
				ret = 6; // unacceptable
				goto no_channel;
			}
			i = selchannel->channel-1-(selchannel->channel>=17);
			if (mISDNport->b_port[i] == NULL)
				goto use_channel;
			add_trace("conclusion", NULL, "exclusively requested channel is busy");
			end_trace();
			ret = 6; // unacceptable
			goto no_channel;
		}

		/* requested channels in list will be used */
		if (channel)
		{
			i = selchannel->channel-1-(selchannel->channel>=17);
			if (mISDNport->b_port[i] == NULL)
				goto use_channel;
		}

		/* if channel is not available or not in list, it must be searched */
		get_from_list:
		/* check for first free channel in list */
		channel = 0;
		selchannel = ifport->channel_in;
		while(selchannel)
		{
			switch(selchannel->channel)
			{
				case CHANNEL_FREE: /* free channel */
				add_trace("hunting", "channel", "free");
				if (mISDNport->b_inuse >= mISDNport->b_num)
					break; /* all channel in use or reserverd */
				/* find channel */
				i = 0;
				while(i < mISDNport->b_num)
				{
					if (mISDNport->b_port[i] == NULL)
					{
						channel = i+1+(i>=15);
						break;
					}
					i++;
				}
				break;

				default:
				add_trace("hunting", "channel", "%d", selchannel->channel);
				if (selchannel->channel<1 || selchannel->channel==16)
					break; /* invalid channels */
				i = selchannel->channel-1-(selchannel->channel>=17);
				if (i >= mISDNport->b_num)
					break; /* channel not in port */
				if (mISDNport->b_port[i] == NULL)
				{
					channel = selchannel->channel;
					break;
				}
				break;
			}
			if (channel)
				break; /* found channel */
			selchannel = selchannel->next;
		}
		if (!channel)
		{
			add_trace("conclusion", NULL, "no channel available");
			end_trace();
			ret = 6; // unacceptable
			goto no_channel;
		}
	}

	/* open channel */
	use_channel:
	ret = seize_bchannel(channel, 1);
	if (ret < 0)
	{
		add_trace("conclusion", NULL, "channel not available");
		end_trace();
		no_channel:
		RELEASE_COMPLETE_t *release_complete;

		dmsg = create_l3msg(CC_RELEASE_COMPLETE | REQUEST, MT_RELEASE_COMPLETE, dinfo, sizeof(RELEASE_COMPLETE_t), p_m_d_ntmode);
		l3_trace_header(CC_RELEASE_COMPLETE | REQUEST, DIRECTION_OUT);
		release_complete = (RELEASE_COMPLETE_t *)(dmsg->data + headerlen);
		enc_ie_cause(&release_complete->CAUSE, dmsg, (p_m_d_ntmode)?LOCATION_PRIVATE_LOCAL:LOCATION_PRIVATE_REMOTE, -ret);
		end_trace();
		msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);
		new_state(PORT_STATE_RELEASE);
		p_m_delete = 1;
		return;
	}
	add_trace("conclusion", NULL, "channel available");
	add_trace("connect", "channel", "%d", p_m_b_channel);
	end_trace();
	bchannel_activate(p_m_mISDNport, p_m_b_index);

	/* create endpoint */
	if (p_epointlist)
	{
		PERROR("SOFTWARE ERROR: incoming call but already got an endpoint, exitting...\n");
		exit(-1);
	}
	if (!(epoint = new Endpoint(p_serial, 0)))
	{
		RELEASE_COMPLETE_t *release_complete;

		dmsg = create_l3msg(CC_RELEASE_COMPLETE | REQUEST, MT_RELEASE_COMPLETE, dinfo, sizeof(RELEASE_COMPLETE_t), p_m_d_ntmode);
		l3_trace_header(CC_RELEASE_COMPLETE | REQUEST, DIRECTION_OUT);
		release_complete = (RELEASE_COMPLETE_t *)(dmsg->data + headerlen);
		enc_ie_cause(&release_complete->CAUSE, dmsg, (p_m_d_ntmode)?LOCATION_PRIVATE_LOCAL:LOCATION_PRIVATE_REMOTE, 41); /* temporary failure */
		end_trace();
		msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);
		new_state(PORT_STATE_RELEASE);
		p_m_delete = 1;
		return;
	}
	if (!(epoint->ep_app = new DEFAULT_ENDPOINT_APP(epoint)))
	{
		PERROR("no memory for application\n");
		exit(-1);
	}
	if (!(epointlist_new(epoint->ep_serial)))
	{
		PERROR("no memory for epointlist\n");
		exit(-1);
	}
	/* send setup message to endpoit */
	PDEBUG(DEBUG_ISDN, "Pdss1(%s) setup: %s->%s\n", p_name, p_callerinfo.id, p_dialinginfo.number);
	message = message_create(p_serial, ACTIVE_EPOINT(p_epointlist), PORT_TO_EPOINT, MESSAGE_SETUP);
	message->param.setup.isdn_port = p_m_portnum;
	message->param.setup.port_type = p_type;
	memcpy(&message->param.setup.dialinginfo, &p_dialinginfo, sizeof(struct dialing_info));
	memcpy(&message->param.setup.callerinfo, &p_callerinfo, sizeof(struct caller_info));
	memcpy(&message->param.setup.redirinfo, &p_redirinfo, sizeof(struct redir_info));
	memcpy(&message->param.setup.capainfo, &p_capainfo, sizeof(struct capa_info));
	memcpy(message->param.setup.useruser.data, &useruser, useruser_len);
	message->param.setup.useruser.len = useruser_len;
	message->param.setup.useruser.protocol = useruser_protocol;
	message_put(message);

	new_state(PORT_STATE_IN_SETUP);
}

/* CC_INFORMATION INDICATION */
void Pdss1::information_ind(unsigned long prim, unsigned long dinfo, void *data)
{
	int headerlen = (p_m_d_ntmode)?mISDNUSER_HEAD_SIZE:mISDN_HEADER_LEN;
	INFORMATION_t *information = (INFORMATION_t *)((unsigned long)data + headerlen);
	int type, plan;
	unsigned char keypad[32] = "";
	struct message *message;

	l3_trace_header(prim, DIRECTION_IN);
	dec_ie_called_pn(information->CALLED_PN, (Q931_info_t *)((unsigned long)data+headerlen), &type, &plan, (unsigned char *)p_dialinginfo.number, sizeof(p_dialinginfo.number));
	dec_ie_keypad(information->KEYPAD, (Q931_info_t *)((unsigned long)data+headerlen), (unsigned char *)keypad, sizeof(keypad));
	dec_ie_complete(information->COMPLETE, (Q931_info_t *)((unsigned long)data+headerlen), &p_dialinginfo.sending_complete);
	end_trace();

	SCAT(p_dialinginfo.number, (char *)keypad);
	switch (type)
	{
		case 0x1:
		p_dialinginfo.ntype = INFO_NTYPE_INTERNATIONAL;
		break;
		case 0x2:
		p_dialinginfo.ntype = INFO_NTYPE_NATIONAL;
		break;
		case 0x4:
		p_dialinginfo.ntype = INFO_NTYPE_SUBSCRIBER;
		break;
		default:
		p_dialinginfo.ntype = INFO_NTYPE_UNKNOWN;
		break;
	}
	message = message_create(p_serial, ACTIVE_EPOINT(p_epointlist), PORT_TO_EPOINT, MESSAGE_INFORMATION);
	memcpy(&message->param.information, &p_dialinginfo, sizeof(struct dialing_info));
	message_put(message);
	/* reset overlap timeout */
	new_state(p_state);
}

/* CC_SETUP_ACCNOWLEDGE INDICATION */
void Pdss1::setup_acknowledge_ind(unsigned long prim, unsigned long dinfo, void *data)
{
	int headerlen = (p_m_d_ntmode)?mISDNUSER_HEAD_SIZE:mISDN_HEADER_LEN;
	SETUP_ACKNOWLEDGE_t *setup_acknowledge = (SETUP_ACKNOWLEDGE_t *)((unsigned long)data + headerlen);
	int exclusive, channel;
	int coding, location, progress;
	int ret;
	struct message *message;

	l3_trace_header(prim, DIRECTION_IN);
	dec_ie_channel_id(setup_acknowledge->CHANNEL_ID, (Q931_info_t *)((unsigned long)data+headerlen), &exclusive, &channel);
	dec_ie_progress(setup_acknowledge->PROGRESS, (Q931_info_t *)((unsigned long)data+headerlen), &coding, &location, &progress);
	end_trace();

	/* process channel */
	ret = received_first_reply_to_setup(prim, exclusive, channel);
	if (ret < 0)
	{
		message = message_create(p_serial, ACTIVE_EPOINT(p_epointlist), PORT_TO_EPOINT, MESSAGE_RELEASE);
		message->param.disconnectinfo.cause = -ret;
		message->param.disconnectinfo.location = LOCATION_PRIVATE_LOCAL;
		message_put(message);
		new_state(PORT_STATE_RELEASE);
		p_m_delete = 1;
		return;
	}

	message = message_create(p_serial, ACTIVE_EPOINT(p_epointlist), PORT_TO_EPOINT, MESSAGE_OVERLAP);
	message_put(message);

	new_state(PORT_STATE_OUT_OVERLAP);
}

/* CC_PROCEEDING INDICATION */
void Pdss1::proceeding_ind(unsigned long prim, unsigned long dinfo, void *data)
{
	int headerlen = (p_m_d_ntmode)?mISDNUSER_HEAD_SIZE:mISDN_HEADER_LEN;
	CALL_PROCEEDING_t *proceeding = (CALL_PROCEEDING_t *)((unsigned long)data + headerlen);
	int exclusive, channel;
	int coding, location, progress;
	int ret;
	struct message *message;
	int notify = -1, type, plan, present;
	char redir[32];

	l3_trace_header(prim, DIRECTION_IN);
	dec_ie_channel_id(proceeding->CHANNEL_ID, (Q931_info_t *)((unsigned long)data+headerlen), &exclusive, &channel);
	dec_ie_progress(proceeding->PROGRESS, (Q931_info_t *)((unsigned long)data+headerlen), &coding, &location, &progress);
	dec_ie_notify(NULL/*proceeding->NOTIFY*/, (Q931_info_t *)((unsigned long)data+headerlen), &notify);
	dec_ie_redir_dn(proceeding->REDIR_DN, (Q931_info_t *)((unsigned long)data+headerlen), &type, &plan, &present, (unsigned char *)redir, sizeof(redir));
	end_trace();

	ret = received_first_reply_to_setup(prim, exclusive, channel);
	if (ret < 0)
	{
		message = message_create(p_serial, ACTIVE_EPOINT(p_epointlist), PORT_TO_EPOINT, MESSAGE_RELEASE);
		message->param.disconnectinfo.cause = -ret;
		message->param.disconnectinfo.location = LOCATION_PRIVATE_LOCAL;
		message_put(message);
		new_state(PORT_STATE_RELEASE);
		p_m_delete = 1;
		return;
	}
	message = message_create(p_serial, ACTIVE_EPOINT(p_epointlist), PORT_TO_EPOINT, MESSAGE_PROCEEDING);
	message_put(message);

	new_state(PORT_STATE_OUT_PROCEEDING);
	
	if (notify >= 0)
		notify |= 0x80;
	else
		notify = 0;
	if (type >= 0 || notify)
	{
		if (!notify && type >= 0)
			notify = 251;
		message = message_create(p_serial, ACTIVE_EPOINT(p_epointlist), PORT_TO_EPOINT, MESSAGE_NOTIFY);
		message->param.notifyinfo.notify = notify;
		SCPY(message->param.notifyinfo.id, redir);
		/* redirection number */
		switch (present)
		{
			case 1:
			message->param.notifyinfo.present = INFO_PRESENT_RESTRICTED;
			break;
			case 2:
			message->param.notifyinfo.present = INFO_PRESENT_NOTAVAIL;
			break;
			default:
			message->param.notifyinfo.present = INFO_PRESENT_ALLOWED;
			break;
		}
		switch (type)
		{
			case -1:
			message->param.notifyinfo.ntype = INFO_NTYPE_UNKNOWN;
			message->param.notifyinfo.present = INFO_PRESENT_NULL;
			break;
			case 1:
			message->param.notifyinfo.ntype = INFO_NTYPE_INTERNATIONAL;
			break;
			case 2:
			message->param.notifyinfo.ntype = INFO_NTYPE_NATIONAL;
			break;
			case 4:
			message->param.notifyinfo.ntype = INFO_NTYPE_SUBSCRIBER;
			break;
			default:
			message->param.notifyinfo.ntype = INFO_NTYPE_UNKNOWN;
			break;
		}
		message->param.notifyinfo.isdn_port = p_m_portnum;
		message_put(message);
	}
}

/* CC_ALERTING INDICATION */
void Pdss1::alerting_ind(unsigned long prim, unsigned long dinfo, void *data)
{
	int headerlen = (p_m_d_ntmode)?mISDNUSER_HEAD_SIZE:mISDN_HEADER_LEN;
	ALERTING_t *alerting = (ALERTING_t *)((unsigned long)data + headerlen);
	int exclusive, channel;
	int coding, location, progress;
	int ret;
	struct message *message;
	int notify = -1, type, plan, present;
	char redir[32];

	l3_trace_header(prim, DIRECTION_IN);
	dec_ie_channel_id(alerting->CHANNEL_ID, (Q931_info_t *)((unsigned long)data+headerlen), &exclusive, &channel);
	dec_ie_progress(alerting->PROGRESS, (Q931_info_t *)((unsigned long)data+headerlen), &coding, &location, &progress);
	dec_ie_notify(NULL/*alerting->NOTIFY*/, (Q931_info_t *)((unsigned long)data+headerlen), &notify);
	dec_ie_redir_dn(alerting->REDIR_DN, (Q931_info_t *)((unsigned long)data+headerlen), &type, &plan, &present, (unsigned char *)redir, sizeof(redir));
	end_trace();

	/* process channel */
	ret = received_first_reply_to_setup(prim, exclusive, channel);
	if (ret < 0)
	{
		message = message_create(p_serial, ACTIVE_EPOINT(p_epointlist), PORT_TO_EPOINT, MESSAGE_RELEASE);
		message->param.disconnectinfo.cause = -ret;
		message->param.disconnectinfo.location = LOCATION_PRIVATE_LOCAL;
		message_put(message);
		new_state(PORT_STATE_RELEASE);
		p_m_delete = 1;
		return;
	}
	message = message_create(p_serial, ACTIVE_EPOINT(p_epointlist), PORT_TO_EPOINT, MESSAGE_ALERTING);
	message_put(message);

	new_state(PORT_STATE_OUT_ALERTING);

	if (notify >= 0)
		notify |= 0x80;
	else
		notify = 0;
	if (type >= 0 || notify)
	{
		if (!notify && type >= 0)
			notify = 251;
		message = message_create(p_serial, ACTIVE_EPOINT(p_epointlist), PORT_TO_EPOINT, MESSAGE_NOTIFY);
		message->param.notifyinfo.notify = notify;
		SCPY(message->param.notifyinfo.id, redir);
		switch (present)
		{
			case 1:
			message->param.notifyinfo.present = INFO_PRESENT_RESTRICTED;
			break;
			case 2:
			message->param.notifyinfo.present = INFO_PRESENT_NOTAVAIL;
			break;
			default:
			message->param.notifyinfo.present = INFO_PRESENT_ALLOWED;
			break;
		}
		switch (type)
		{
			case -1:
			message->param.notifyinfo.ntype = INFO_NTYPE_UNKNOWN;
			message->param.notifyinfo.present = INFO_PRESENT_NULL;
			break;
			case 1:
			message->param.notifyinfo.ntype = INFO_NTYPE_INTERNATIONAL;
			break;
			case 2:
			message->param.notifyinfo.ntype = INFO_NTYPE_NATIONAL;
			break;
			case 4:
			message->param.notifyinfo.ntype = INFO_NTYPE_SUBSCRIBER;
			break;
			default:
			message->param.notifyinfo.ntype = INFO_NTYPE_UNKNOWN;
			break;
		}
		message->param.notifyinfo.isdn_port = p_m_portnum;
		message_put(message);
	}
}

/* CC_CONNECT INDICATION */
void Pdss1::connect_ind(unsigned long prim, unsigned long dinfo, void *data)
{
	int headerlen = (p_m_d_ntmode)?mISDNUSER_HEAD_SIZE:mISDN_HEADER_LEN;
	CONNECT_t *connect = (CONNECT_t *)((unsigned long)data + headerlen);
	int exclusive, channel;
	int type, plan, present, screen;
	int ret;
	msg_t *dmsg;
	struct message *message;
	int bchannel_before;
	CONNECT_ACKNOWLEDGE_t *connect_acknowledge;

	if (p_m_d_ntmode)
		p_m_d_ces = connect->ces;

	l3_trace_header(prim, DIRECTION_IN);
	dec_ie_channel_id(connect->CHANNEL_ID, (Q931_info_t *)((unsigned long)data+headerlen), &exclusive, &channel);
	dec_ie_connected_pn(connect->CONNECT_PN, (Q931_info_t *)((unsigned long)data+headerlen), &type, &plan, &present, &screen, (unsigned char *)p_connectinfo.id, sizeof(p_connectinfo.id));
#ifdef CENTREX
	/* te-mode: CONP (connected name identification presentation) */
	if (!p_m_d_ntmode)
		dec_facility_centrex(connect->FACILITY, (Q931_info_t *)((unsigned long)data+headerlen), (unsigned char *)p_connectinfo.name, sizeof(p_connectinfo.name));
#endif
	end_trace();

	/* select channel */
	bchannel_before = p_m_b_channel;
	ret = received_first_reply_to_setup(prim, exclusive, channel);
	if (ret < 0)
	{
		message = message_create(p_serial, ACTIVE_EPOINT(p_epointlist), PORT_TO_EPOINT, MESSAGE_RELEASE);
		message->param.disconnectinfo.cause = -ret;
		message->param.disconnectinfo.location = LOCATION_PRIVATE_LOCAL;
		message_put(message);
		new_state(PORT_STATE_RELEASE);
		p_m_delete = 1;
		return;
	}

	/* connect information */
	switch (present)
	{
		case 1:
		p_connectinfo.present = INFO_PRESENT_RESTRICTED;
		break;
		case 2:
		p_connectinfo.present = INFO_PRESENT_NOTAVAIL;
		break;
		default:
		p_connectinfo.present = INFO_PRESENT_ALLOWED;
		break;
	}
	switch (screen)
	{
		case 0:
		p_connectinfo.screen = INFO_SCREEN_USER;
		break;
		default:
		p_connectinfo.screen = INFO_SCREEN_NETWORK;
		break;
	}
	switch (type)
	{
		case 0x0:
		p_connectinfo.present = INFO_PRESENT_NULL; /* no COLP info */
		p_connectinfo.ntype = INFO_NTYPE_UNKNOWN;
		break;
		case 0x1:
		p_connectinfo.ntype = INFO_NTYPE_INTERNATIONAL;
		break;
		case 0x2:
		p_connectinfo.ntype = INFO_NTYPE_NATIONAL;
		break;
		case 0x4:
		p_connectinfo.ntype = INFO_NTYPE_SUBSCRIBER;
		break;
		default:
		p_connectinfo.ntype = INFO_NTYPE_UNKNOWN;
		break;
	}
	p_connectinfo.isdn_port = p_m_portnum;
	SCPY(p_connectingo.interface, p_m_mISDNport->ifport->interface->name);

	/* send connect acknowledge */
	dmsg = create_l3msg(CC_CONNECT | RESPONSE, MT_CONNECT, dinfo, sizeof(CONNECT_ACKNOWLEDGE_t), p_m_d_ntmode);
	l3_trace_header(CC_CONNECT | RESPONSE, DIRECTION_OUT);
	connect_acknowledge = (CONNECT_ACKNOWLEDGE_t *)(dmsg->data + headerlen);
	/* if we had no bchannel before, we send it now */
	if (!bchannel_before && p_m_b_channel)
		enc_ie_channel_id(&connect_acknowledge->CHANNEL_ID, dmsg, 1, p_m_b_channel);
	end_trace();
	msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);

	PDEBUG(DEBUG_ISDN, "Pdss1(%s) connect (to '%s' COLP: '%s')\n", p_name, p_dialinginfo.number, p_connectinfo.id);
	message = message_create(p_serial, ACTIVE_EPOINT(p_epointlist), PORT_TO_EPOINT, MESSAGE_CONNECT);
	memcpy(&message->param.connectinfo, &p_connectinfo, sizeof(struct connect_info));
	message_put(message);

	new_state(PORT_STATE_CONNECT);
}

/* CC_DISCONNECT INDICATION */
void Pdss1::disconnect_ind(unsigned long prim, unsigned long dinfo, void *data)
{
	int headerlen = (p_m_d_ntmode)?mISDNUSER_HEAD_SIZE:mISDN_HEADER_LEN;
	DISCONNECT_t *disconnect = (DISCONNECT_t *)((unsigned long)data + headerlen);
	int location, cause;
	int coding, proglocation, progress;
	struct message *message;

	l3_trace_header(prim, DIRECTION_IN);
	dec_ie_progress(disconnect->PROGRESS, (Q931_info_t *)((unsigned long)data+headerlen), &coding, &proglocation, &progress);
	dec_ie_cause(disconnect->CAUSE, (Q931_info_t *)((unsigned long)data+headerlen), &location, &cause);
	end_trace();

	if (cause < 0)
		cause = 16;

	/* release if we are remote sends us no tones */
	if (p_m_mISDNport->is_earlyb)
	{
		RELEASE_t *release;
		msg_t *dmsg;

		PDEBUG(DEBUG_ISDN, "Pdss1(%s) send release because remote disconnects AND provides no patterns (earlyb).\n", p_name);
		dmsg = create_l3msg(CC_RELEASE | REQUEST, MT_RELEASE, dinfo, sizeof(RELEASE_t), p_m_d_ntmode);
		release = (RELEASE_t *)(dmsg->data + headerlen);
		l3_trace_header(CC_RELEASE | REQUEST, DIRECTION_OUT);
		enc_ie_cause(&release->CAUSE, dmsg, (p_m_d_ntmode)?LOCATION_PRIVATE_LOCAL:LOCATION_PRIVATE_REMOTE, 16); /* normal */
		end_trace();
		msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);

		/* sending release to endpoint */
		while(p_epointlist)
		{
			message = message_create(p_serial, p_epointlist->epoint_id, PORT_TO_EPOINT, MESSAGE_RELEASE);
			message->param.disconnectinfo.cause = cause;
			message->param.disconnectinfo.location = location;
			message_put(message);
			/* remove epoint */
			free_epointlist(p_epointlist);
		}
		new_state(PORT_STATE_RELEASE);
		p_m_delete = 1;
		return;
	}

	/* sending disconnect to active endpoint and release to inactive endpoints */
	if (ACTIVE_EPOINT(p_epointlist))
	{
		message = message_create(p_serial, ACTIVE_EPOINT(p_epointlist), PORT_TO_EPOINT, MESSAGE_DISCONNECT);
		message->param.disconnectinfo.location = location;
		message->param.disconnectinfo.cause = cause;
		message_put(message);
	}
	while(INACTIVE_EPOINT(p_epointlist))
	{
		message = message_create(p_serial, INACTIVE_EPOINT(p_epointlist), PORT_TO_EPOINT, MESSAGE_RELEASE);
		message->param.disconnectinfo.location = location;
		message->param.disconnectinfo.cause = cause;
		message_put(message);
		/* remove epoint */
		free_epointid(INACTIVE_EPOINT(p_epointlist));
	}
	new_state(PORT_STATE_IN_DISCONNECT);
}

/* CC_DISCONNECT INDICATION */
void Pdss1::disconnect_ind_i(unsigned long prim, unsigned long dinfo, void *data)
{
	int headerlen = (p_m_d_ntmode)?mISDNUSER_HEAD_SIZE:mISDN_HEADER_LEN;
	DISCONNECT_t *disconnect = (DISCONNECT_t *)((unsigned long)data + headerlen);
	int location, cause;

	/* cause */
	l3_trace_header(prim, DIRECTION_IN);
	if (p_m_d_collect_cause > 0)
	{
		add_trace("old-cause", "location", "%d", p_m_d_collect_location);
		add_trace("old-cause", "value", "%d", p_m_d_collect_cause);
	}
	dec_ie_cause(disconnect->CAUSE, (Q931_info_t *)((unsigned long)data+headerlen), &location, &cause);
	end_trace();

	/* collect cause */
	if (cause == CAUSE_REJECTED) /* call rejected */
	{
		p_m_d_collect_cause = CAUSE_REJECTED;
		p_m_d_collect_location = location;
	} else
	if (cause==CAUSE_NORMAL && p_m_d_collect_cause!=CAUSE_REJECTED) /* reject via hangup */
	{
		p_m_d_collect_cause = CAUSE_NORMAL;
		p_m_d_collect_location = location;
	} else
	if (cause==CAUSE_BUSY && p_m_d_collect_cause!=CAUSE_REJECTED && p_m_d_collect_cause!=CAUSE_NORMAL) /* busy */
	{
		p_m_d_collect_cause = CAUSE_BUSY;
		p_m_d_collect_location = location;
	} else
	if (cause==CAUSE_OUTOFORDER && p_m_d_collect_cause!=CAUSE_BUSY && p_m_d_collect_cause!=CAUSE_REJECTED && p_m_d_collect_cause!=CAUSE_NORMAL) /* no L1 */
	{
		p_m_d_collect_cause = CAUSE_OUTOFORDER;
		p_m_d_collect_location = location;
	} else
	if (cause!=0 && cause!=CAUSE_NOUSER && p_m_d_collect_cause!=CAUSE_OUTOFORDER && p_m_d_collect_cause!=CAUSE_BUSY && p_m_d_collect_cause!=CAUSE_REJECTED && p_m_d_collect_cause!=CAUSE_NORMAL) /* anything if cause exists and not 18 */
	{
		p_m_d_collect_cause = cause;
		p_m_d_collect_location = location;
	}
	add_trace("new-cause", "location", "%d", p_m_d_collect_location);
	add_trace("new-cause", "value", "%d", p_m_d_collect_cause);

}

/* CC_RELEASE INDICATION */
void Pdss1::release_ind(unsigned long prim, unsigned long dinfo, void *data)
{
	int headerlen = (p_m_d_ntmode)?mISDNUSER_HEAD_SIZE:mISDN_HEADER_LEN;
	RELEASE_t *release = (RELEASE_t *)((unsigned long)data + headerlen);
	msg_t *dmsg;
	int location, cause;
	struct message *message;

	l3_trace_header(prim, DIRECTION_IN);
	dec_ie_cause(release->CAUSE, (Q931_info_t *)((unsigned long)data+headerlen), &location, &cause);
	end_trace();

	if (cause < 0)
		cause = 16;

	/* sending release to endpoint */
	while(p_epointlist)
	{
		message = message_create(p_serial, p_epointlist->epoint_id, PORT_TO_EPOINT, MESSAGE_RELEASE);
		message->param.disconnectinfo.cause = cause;
		message->param.disconnectinfo.location = location;
		message_put(message);
		/* remove epoint */
		free_epointlist(p_epointlist);
	}

	/* only in NT mode we must send release_complete, if we got a release confirm */
	if (prim == (CC_RELEASE | CONFIRM))
	{
		/* sending release complete */
		RELEASE_COMPLETE_t *release_complete;

		dmsg = create_l3msg(CC_RELEASE_COMPLETE | REQUEST, MT_RELEASE_COMPLETE, dinfo, sizeof(RELEASE_COMPLETE_t), p_m_d_ntmode);
		release_complete = (RELEASE_COMPLETE_t *)(dmsg->data + headerlen);
		l3_trace_header(CC_RELEASE_COMPLETE | REQUEST, DIRECTION_OUT);
		enc_ie_cause(&release_complete->CAUSE, dmsg, (p_m_d_ntmode)?LOCATION_PRIVATE_LOCAL:LOCATION_PRIVATE_REMOTE, 16);
		end_trace();
		msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);
	}

	new_state(PORT_STATE_RELEASE);
	p_m_delete = 1;
}

/* CC_RELEASE_COMPLETE INDICATION */
void Pdss1::release_complete_ind(unsigned long prim, unsigned long dinfo, void *data)
{
	int headerlen = (p_m_d_ntmode)?mISDNUSER_HEAD_SIZE:mISDN_HEADER_LEN;
	RELEASE_COMPLETE_t *release_complete = (RELEASE_COMPLETE_t *)((unsigned long)data + headerlen);
	int location, cause;
	struct message *message;

	l3_trace_header(prim, DIRECTION_IN);
	dec_ie_cause(release_complete->CAUSE, (Q931_info_t *)((unsigned long)data+headerlen), &location, &cause);
	end_trace();

	if (cause < 0)
		cause = 16;

	/* sending release to endpoint */
	while(p_epointlist)
	{
		message = message_create(p_serial, p_epointlist->epoint_id, PORT_TO_EPOINT, MESSAGE_RELEASE);
		message->param.disconnectinfo.cause = cause;
		message->param.disconnectinfo.location = location;
		message_put(message);
		/* remove epoint */
		free_epointlist(p_epointlist);
	}

	PDEBUG(DEBUG_ISDN, "Pdss1(%s) release_complete (cause %d)\n", p_name, cause);
	new_state(PORT_STATE_RELEASE);
	p_m_delete = 1;
}

/* T312 timeout  */
void Pdss1::t312_timeout(unsigned long prim, unsigned long dinfo, void *data)
{
	struct message *message;

	// trace is done at message_isdn()
	
	/* sending release to endpoint */
	while(p_epointlist)
	{
		message = message_create(p_serial, p_epointlist->epoint_id, PORT_TO_EPOINT, MESSAGE_RELEASE);
		message->param.disconnectinfo.cause = p_m_d_collect_cause;
		message->param.disconnectinfo.location = p_m_d_collect_location;
		message_put(message);
		/* remove epoint */
		free_epointlist(p_epointlist);
	}

	PDEBUG(DEBUG_ISDN, "Pdss1(%s) t312_timeout (collected cause %d location %d)\n", p_name, p_m_d_collect_cause, p_m_d_collect_location);
	new_state(PORT_STATE_RELEASE);
	p_m_delete = 1;
}

/* CC_NOTIFY INDICATION */
void Pdss1::notify_ind(unsigned long prim, unsigned long dinfo, void *data)
{
	int headerlen = (p_m_d_ntmode)?mISDNUSER_HEAD_SIZE:mISDN_HEADER_LEN;
	NOTIFY_t *notifying = (NOTIFY_t *)((unsigned long)data + headerlen);
	struct message *message;
	int notify, type, plan, present;

	l3_trace_header(prim, DIRECTION_IN);
	dec_ie_notify(notifying->NOTIFY, (Q931_info_t *)((unsigned long)data+headerlen), &notify);
	dec_ie_redir_dn(notifying->REDIR_DN, (Q931_info_t *)((unsigned long)data+headerlen), &type, &plan, &present, (unsigned char *)message->param.notifyinfo.id, sizeof(message->param.notifyinfo.id));
	end_trace();

	if (!ACTIVE_EPOINT(p_epointlist))
	{
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) there is no active endpoint to notify to.\n", p_name);
		return;
	}
	/* notification indicator */
	if (notify < 0)
		return;
	notify |= 0x80;
	message = message_create(p_serial, ACTIVE_EPOINT(p_epointlist), PORT_TO_EPOINT, MESSAGE_NOTIFY);
	message->param.notifyinfo.notify = notify;
	/* redirection number */
	switch (present)
	{
		case 1:
		message->param.notifyinfo.present = INFO_PRESENT_RESTRICTED;
		break;
		case 2:
		message->param.notifyinfo.present = INFO_PRESENT_NOTAVAIL;
		break;
		default:
		message->param.notifyinfo.present = INFO_PRESENT_ALLOWED;
		break;
	}
	switch (type)
	{
		case -1:
		message->param.notifyinfo.ntype = INFO_NTYPE_UNKNOWN;
		message->param.notifyinfo.present = INFO_PRESENT_NULL;
		break;
		case 1:
		message->param.notifyinfo.ntype = INFO_NTYPE_INTERNATIONAL;
		break;
		case 2:
		message->param.notifyinfo.ntype = INFO_NTYPE_NATIONAL;
		break;
		case 4:
		message->param.notifyinfo.ntype = INFO_NTYPE_SUBSCRIBER;
		break;
		default:
		message->param.notifyinfo.ntype = INFO_NTYPE_UNKNOWN;
		break;
	}
	message->param.notifyinfo.isdn_port = p_m_portnum;
	message_put(message);
}


/* CC_HOLD INDICATION */
void Pdss1::hold_ind(unsigned long prim, unsigned long dinfo, void *data)
{
	int headerlen = (p_m_d_ntmode)?mISDNUSER_HEAD_SIZE:mISDN_HEADER_LEN;
//	HOLD_t *hold = (HOLD_t *)((unsigned long)data + headerlen);
	struct message *message;
	HOLD_REJECT_t *hold_reject;
	HOLD_ACKNOWLEDGE_t *hold_acknowledge;
	msg_t *dmsg;
//	class Endpoint *epoint;

	l3_trace_header(prim, DIRECTION_IN);
	end_trace();

	if (!ACTIVE_EPOINT(p_epointlist) || p_m_hold)
	{

		PDEBUG(DEBUG_ISDN, "Pdss1(%s) there is no endpoint to notify hold OR we are already on hold, so we reject.\n", p_name);

		dmsg = create_l3msg(CC_HOLD_REJECT | REQUEST, MT_HOLD_REJECT, dinfo, sizeof(HOLD_REJECT_t), p_m_d_ntmode);
		hold_reject = (HOLD_REJECT_t *)(dmsg->data + headerlen);
		l3_trace_header(CC_HOLD_REJECT | REQUEST, DIRECTION_OUT);
		enc_ie_cause(&hold_reject->CAUSE, dmsg, (p_m_d_ntmode)?LOCATION_PRIVATE_LOCAL:LOCATION_PRIVATE_REMOTE, p_m_hold?101:31); /* normal unspecified / incompatible state */
		end_trace();
		msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);

		return;
	}

	/* notify the hold of call */
	message = message_create(p_serial, ACTIVE_EPOINT(p_epointlist), PORT_TO_EPOINT, MESSAGE_NOTIFY);
	message->param.notifyinfo.notify = INFO_NOTIFY_REMOTE_HOLD;
	message->param.notifyinfo.local = 1; /* call is held by supplementary service */
	message_put(message);

	/* deactivate bchannel */
	start_trace(p_m_mISDNport->portnum,
		    p_m_mISDNport->ifport->interface,
		    nationalize(p_callerinfo.id, p_callerinfo.ntype),
		    p_dialinginfo.number,
		    DIRECTION_OUT,
		    CATEGORY_CH,
		    "CHANNEL RELEASE (hold)");
	add_trace("disconnect", "channel", "%d", p_m_b_channel);
	end_trace();
	free_bchannel();
pr�fen, ob bei allen alloc_bchannel/free_bchannel ein trace erfolgt

	/* set hold state */
	p_m_hold = 1;
#if 0
	epoint = find_epoint_id(ACTIVE_EPOINT(p_epointlist));
	if (epoint && p_m_d_ntmode)
	{
		p_m_timeout = p_settings.tout_hold;
		time(&p_m_timer);
	}
#endif

	/* acknowledge hold */
	dmsg = create_l3msg(CC_HOLD_ACKNOWLEDGE | REQUEST, MT_HOLD_ACKNOWLEDGE, dinfo, sizeof(HOLD_ACKNOWLEDGE_t), p_m_d_ntmode);
	hold_acknowledge = (HOLD_ACKNOWLEDGE_t *)(dmsg->data + headerlen);
	l3_trace_header(CC_HOLD_ACKNOWLEDGE | REQUEST, DIRECTION_OUT);
	end_trace();
	msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);
}


/* CC_RETRIEVE INDICATION */
void Pdss1::retrieve_ind(unsigned long prim, unsigned long dinfo, void *data)
{
	int headerlen = (p_m_d_ntmode)?mISDNUSER_HEAD_SIZE:mISDN_HEADER_LEN;
	RETRIEVE_t *retrieve = (RETRIEVE_t *)((unsigned long)data + headerlen);
	RETRIEVE_REJECT_t *retrieve_reject;
	RETRIEVE_ACKNOWLEDGE_t *retrieve_acknowledge;
	struct message *message;
	int channel, exclusive, cause;
	msg_t *dmsg;
	int ret;

	l3_trace_header(prim, DIRECTION_IN);
	dec_ie_channel_id(retrieve->CHANNEL_ID, (Q931_info_t *)((unsigned long)data+headerlen), &exclusive, &channel);
	end_trace();

	if (!p_m_hold)
	{
		cause = 101; /* incompatible state */
		reject:
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) we are not on hold, so we reject (cazse %d).\n", p_name, cause);

		dmsg = create_l3msg(CC_RETRIEVE_REJECT | REQUEST, MT_RETRIEVE_REJECT, dinfo, sizeof(RETRIEVE_REJECT_t), p_m_d_ntmode);
		retrieve_reject = (RETRIEVE_REJECT_t *)(dmsg->data + headerlen);
		l3_trace_header(CC_RETRIEVE_REJECT | REQUEST, DIRECTION_OUT);
		enc_ie_cause(&retrieve_reject->CAUSE, dmsg, (p_m_d_ntmode)?LOCATION_PRIVATE_LOCAL:LOCATION_PRIVATE_REMOTE, cause);
		end_trace();
		msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);

		return;
	}

	/* notify the retrieve of call */
	message = message_create(p_serial, ACTIVE_EPOINT(p_epointlist), PORT_TO_EPOINT, MESSAGE_NOTIFY);
	message->param.notifyinfo.notify = INFO_NOTIFY_REMOTE_RETRIEVAL;
	message->param.notifyinfo.local = 1; /* call is retrieved by supplementary service */
	message_put(message);



mach den channel-kram, wie beim setup








	
	/* channel_id */
	start_trace(p_m_mISDNport->portnum,
		    p_m_mISDNport->ifport->interface,
		    nationalize(p_callerinfo.id, p_callerinfo.ntype),
		    p_dialinginfo.number,
		    DIRECTION_IN,
		    CATEGORY_CH,
		    "CHANNEL SELECTION (retrieve)");
	if (exclusive<0)
		exclusive = 0;
alle channels richtig convertieren 
	if (channel < 0)
		channel = -1; /* any channel */
	if (channel == ANY_CHANNEL)
		channel = -1; /* any channel */
	if (channel == CHANNEL_NO)
		add_trace("channel", "request", "no-channel");
	else
		add_trace("channel", "request", (channel>0)?"%d%s":"any", channel, exclusive?" (forced)":"");
	/* debug */
	if (channel==CHANNEL_NO && (p_type==PORT_TYPE_DSS1_TE_IN||p_type==PORT_TYPE_DSS1_TE_OUT))
	{
		add_trace("conclusion", NULL, "incoming call-waiting not supported for TE-mode");
		end_trace();
		cause = 6;
		goto reject;
	}
	/* open channel */
	ret = alloc_bchannel(channel, exclusive);
	if (ret < 0)
	{
		PDEBUG(DEBUG_BCHANNEL, "- channel is not available (cause=%d), so we send a retrieve_reject.\n", -ret);
		cause = -ret;
		goto reject;
	}















	
	/* set hold state */
	p_m_hold = 0;
	p_m_timeout = 0;

	/* acknowledge retrieve */
	dmsg = create_l3msg(CC_RETRIEVE_ACKNOWLEDGE | REQUEST, MT_RETRIEVE_ACKNOWLEDGE, dinfo, sizeof(RETRIEVE_ACKNOWLEDGE_t), p_m_d_ntmode);
	retrieve_acknowledge = (RETRIEVE_ACKNOWLEDGE_t *)(dmsg->data + headerlen);
	l3_trace_header(CC_RETRIEVE_ACKNOWLEDGE | REQUEST, DIRECTION_OUT);
	enc_ie_channel_id(&retrieve_acknowledge->CHANNEL_ID, dmsg, 1, p_m_b_channel);
	end_trace();
	msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);
}

/* CC_SUSPEND INDICATION */
void Pdss1::suspend_ind(unsigned long prim, unsigned long dinfo, void *data)
{
	int headerlen = (p_m_d_ntmode)?mISDNUSER_HEAD_SIZE:mISDN_HEADER_LEN;
	SUSPEND_t *suspend = (SUSPEND_t *)((unsigned long)data + headerlen);
	SUSPEND_ACKNOWLEDGE_t *suspend_acknowledge;
	SUSPEND_REJECT_t *suspend_reject;
	struct message *message;
	class Endpoint *epoint;
	unsigned char callid[8];
	int len;
	msg_t *dmsg;
	int ret = -31; /* normal, unspecified */

	l3_trace_header(prim, DIRECTION_IN);
	dec_ie_call_id(suspend->CALL_ID, (Q931_info_t *)((unsigned long)data+headerlen), callid, &len);
	end_trace();

	if (!ACTIVE_EPOINT(p_epointlist))
	{
		reject:
		dmsg = create_l3msg(CC_SUSPEND_REJECT | REQUEST, MT_SUSPEND_REJECT, dinfo, sizeof(SUSPEND_REJECT_t), p_m_d_ntmode);
		suspend_reject = (SUSPEND_REJECT_t *)(dmsg->data + headerlen);
		l3_trace_header(CC_SUSPEND_REJECT | REQUEST, DIRECTION_OUT);
		enc_ie_cause(&suspend_reject->CAUSE, dmsg, (p_m_d_ntmode)?LOCATION_PRIVATE_LOCAL:LOCATION_PRIVATE_REMOTE, -ret);
		end_trace();
		msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);

		return;
	}

	/* call id */
	if (len<0) len = 0;

	/* check if call id is in use */
	epoint = epoint_first;
	while(epoint)
	{
		if (epoint->ep_park)
		{
			if (epoint->ep_park_len == len)
			if (!memcmp(epoint->ep_park_callid, callid, len))
			{
				PDEBUG(DEBUG_ISDN, "Pdss1(%s) call id is in use, so we reject.\n", p_name);
				ret = -84; /* call id in use */
				goto reject;
			}
		}
		epoint = epoint->next;
	}

	/* notify the hold of call */
	message = message_create(p_serial, ACTIVE_EPOINT(p_epointlist), PORT_TO_EPOINT, MESSAGE_NOTIFY);
	message->param.notifyinfo.notify = INFO_NOTIFY_USER_SUSPENDED;
	message->param.notifyinfo.local = 1; /* call is held by supplementary service */
	message_put(message);

	/* deactivate bchannel */
	start_trace(p_m_mISDNport->portnum,
		    p_m_mISDNport->ifport->interface,
		    nationalize(p_callerinfo.id, p_callerinfo.ntype),
		    p_dialinginfo.number,
		    DIRECTION_OUT,
		    CATEGORY_CH,
		    "CHANNEL RELEASE (suspend)");
	add_trace("disconnect", "channel", "%d", p_m_b_channel);
	end_trace();
	free_bchannel();

	/* sending suspend to endpoint */
	while (p_epointlist)
	{
		message = message_create(p_serial, p_epointlist->epoint_id, PORT_TO_EPOINT, MESSAGE_SUSPEND);
		memcpy(message->param.parkinfo.callid, callid, sizeof(message->param.parkinfo.callid));
		message->param.parkinfo.len = len;
		message_put(message);
		/* remove epoint */
		free_epointlist(p_epointlist);
	}

	/* sending SUSPEND_ACKNOWLEDGE */
	dmsg = create_l3msg(CC_SUSPEND_ACKNOWLEDGE | REQUEST, MT_SUSPEND_ACKNOWLEDGE, dinfo, sizeof(SUSPEND_ACKNOWLEDGE_t), p_m_d_ntmode);
	suspend_acknowledge = (SUSPEND_ACKNOWLEDGE_t *)(dmsg->data + headerlen);
	l3_trace_header(CC_SUSPEND_ACKNOWLEDGE | REQUEST, DIRECTION_OUT);
	end_trace();
	msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);

	new_state(PORT_STATE_RELEASE);
	p_m_delete = 1;
}

/* CC_RESUME INDICATION */
void Pdss1::resume_ind(unsigned long prim, unsigned long dinfo, void *data)
{
	int headerlen = (p_m_d_ntmode)?mISDNUSER_HEAD_SIZE:mISDN_HEADER_LEN;
	RESUME_t *resume = (RESUME_t *)((unsigned long)data + headerlen);
	RESUME_REJECT_t *resume_reject;
	RESUME_ACKNOWLEDGE_t *resume_acknowledge;
	unsigned char callid[8];
	int len;
	int channel, exclusive;
	msg_t *dmsg;
	class Endpoint *epoint;
	struct message *message;
	int ret;

	/* callref from nt-lib */
	if (p_m_d_ntmode)
	{
		/* nt-library now gives us the id via CC_RESUME */
		if (dinfo&(~0xff) == 0xff00)
		{
			PERROR("fatal software error: l3-stack gives us a process id 0xff00-0xffff\n");
			exit(-1);
		}
		l3_trace_header(CC_NEW_CR | INDICATION, DIRECTION_IN);
		if (p_m_d_l3id)
			add_trace("callref", "old", "0x%x", p_m_d_l3id);
		add_trace("callref", "new", "0x%x", dinfo);
		end_trace();
		if (p_m_d_l3id&(~0xff) == 0xff00)
			p_m_mISDNport->procids[p_m_d_l3id&0xff] = 0;
		p_m_d_l3id = dinfo;
		p_m_d_ces = setup->ces;
	}

	l3_trace_header(prim, DIRECTION_IN);
	dec_ie_call_id(resume->CALL_ID, (Q931_info_t *)((unsigned long)data+headerlen), callid, &len);
	end_trace();

	/* if blocked, release call */
	if (p_m_mISDNport->ifport->block)
	{
		RELEASE_COMPLETE_t *release_complete;

		printlog("---  port#%d is blocked.\n", mISDNport->ifport->portnum);
		ret = -27;
		goto reject;
	}

	/* call id */
	if (len<0) len = 0;

	/* channel_id */
	exclusive = 0;
	channel = -1; /* any channel */

	/* hunt channel */
	ret = hunt_bchannel(channel, exclusive);
	if (ret < 0)
	{
		reject:
		dmsg = create_l3msg(CC_RESUME_REJECT | REQUEST, MT_RESUME_REJECT, dinfo, sizeof(RESUME_REJECT_t), p_m_d_ntmode);
		resume_reject = (RESUME_REJECT_t *)(dmsg->data + headerlen);
		l3_trace_header(CC_RESUME_REJECT | REQUEST, DIRECTION_OUT);
		enc_ie_cause(&resume_reject->CAUSE, dmsg, (p_m_d_ntmode)?LOCATION_PRIVATE_LOCAL:LOCATION_PRIVATE_REMOTE, -ret);
		if (ret == -27)
			add_trace("reason", NULL, "port blocked");
		end_trace();
		msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);
		new_state(PORT_STATE_RELEASE);
		p_m_delete = 1;
		return;
	}

	/* create endpoint */
	if (p_epointlist)
	{
		PERROR("SOFTWARE ERROR: incoming resume but already got an endpoint, exitting...\n");
		exit(-1);
	}
	ret = -85; /* no call suspended */
	epoint = epoint_first;
	while(epoint)
	{
		if (epoint->ep_park)
		{
			ret = -83; /* suspended call exists, but this not */
			if (epoint->ep_park_len == len)
			if (!memcmp(epoint->ep_park_callid, callid, len))
				break;
		}
		epoint = epoint->next;
	}
	if (!epoint)
	{
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) no suspended call, so we reject with cause %d.\n", p_name, ret);
		goto reject;
	}

	if (!(epointlist_new(epoint->ep_serial)))
	{
		PERROR("no memory for epointlist\n");
		exit(-1);
	}
	if (!(epoint->portlist_new(p_serial, p_type, p_m_mISDNport->is_earlyb)))
	{
		PERROR("no memory for portlist\n");
		exit(-1);
	}
	PDEBUG(DEBUG_ISDN, "Pdss1(%s) resume\n", p_name);
	message = message_create(p_serial, ACTIVE_EPOINT(p_epointlist), PORT_TO_EPOINT, MESSAGE_RESUME);
	message_put(message);

	/* notify the resume of call */
	message = message_create(p_serial, ACTIVE_EPOINT(p_epointlist), PORT_TO_EPOINT, MESSAGE_NOTIFY);
	message->param.notifyinfo.notify = INFO_NOTIFY_USER_RESUMED;
	message->param.notifyinfo.local = 1; /* call is retrieved by supplementary service */
	message_put(message);

	/* sending RESUME_ACKNOWLEDGE */
	dmsg = create_l3msg(CC_RESUME_ACKNOWLEDGE | REQUEST, MT_RESUME_ACKNOWLEDGE, dinfo, sizeof(RESUME_ACKNOWLEDGE_t), p_m_d_ntmode);
	resume_acknowledge = (RESUME_ACKNOWLEDGE_t *)(dmsg->data + headerlen);
	l3_trace_header(CC_RESUME_ACKNOWLEDGE | REQUEST, DIRECTION_OUT);
	enc_ie_channel_id(&resume_acknowledge->CHANNEL_ID, dmsg, 1, p_m_b_channel);
	end_trace();
	msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);

	new_state(PORT_STATE_CONNECT);
}


/* CC_FACILITY INDICATION */
void Pdss1::facility_ind(unsigned long prim, unsigned long dinfo, void *data)
{
	int headerlen = (p_m_d_ntmode)?mISDNUSER_HEAD_SIZE:mISDN_HEADER_LEN;
	FACILITY_t *facility = (FACILITY_t *)((unsigned long)data + headerlen);
	unsigned char facil[256];
	int facil_len;
	struct message *message;

	l3_trace_header(prim, DIRECTION_IN);
	dec_ie_facility(facility->FACILITY, (Q931_info_t *)((unsigned long)data+headerlen), facil, &facil_len);
	end_trace();

	/* facility */
	if (facil_len<=0)
		return;

	PDEBUG(DEBUG_ISDN, "Pdss1(%s) facility\n", p_name);
	message = message_create(p_serial, ACTIVE_EPOINT(p_epointlist), PORT_TO_EPOINT, MESSAGE_FACILITY);
	message->param.facilityinfo.len = facil_len;
	memcpy(message->param.facilityinfo.data, facil, facil_len);
	message_put(message);
}


/*
 * handler for isdn connections
 * incoming information are parsed and sent via message to the endpoint
 */
void Pdss1::message_isdn(unsigned long prim, unsigned long dinfo, void *data)
{
	int i;
	int new_l3id;
	int timer_hex=0;

	switch (prim)
	{
		case CC_TIMEOUT | INDICATION:
		l3_trace_header(prim, DIRECTION_IN);
		if (p_m_d_ntmode)
		{
			int headerlen = (p_m_d_ntmode)?mISDNUSER_HEAD_SIZE:mISDN_HEADER_LEN;
			timer_hex = *((int *)(((char *)data)+headerlen));
		}
		if (timer_hex)
			add_trace("timer", NULL, "%x", timer_hex);
		end_trace();
		if (timer_hex==0x312 && p_m_d_ntmode)
			t312_timeout(prim, dinfo, data);
		break;

		case CC_SETUP | INDICATION:
		PDEBUG((DEBUG_BCHANNEL|DEBUG_ISDN), "Pdss1(%s) setup\n", p_name);
		if (p_state != PORT_STATE_IDLE)
		{
			PDEBUG(DEBUG_ISDN, "Pdss1(%s) received setup again, IGNORING.\n", p_name);
			break;
		}
		setup_ind(prim, dinfo, data);
		break;

		case CC_SETUP | CONFIRM:
		if (p_m_d_ntmode)
		{
			l3_trace_header(CC_NEW_CR | INDICATION, DIRECTION_IN);
			add_trace("callref", "old", "0x%x", p_m_d_l3id);
			/* nt-library now gives us a new id via CC_SETUP_CONFIRM */
			if ((p_m_d_l3id&0xff00) != 0xff00)
				PERROR("    strange setup-procid 0x%x\n", p_m_d_l3id);
			p_m_d_l3id = *((int *)(((u_char *)data)+ mISDNUSER_HEAD_SIZE));
			add_trace("callref", "new", "0x%x", p_m_d_l3id);
			end_trace();
		}
		end_trace;
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) setup confirm (l3id=0x%x)\n", p_name, p_m_d_l3id);
		break;

		case CC_INFORMATION | INDICATION:
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) information\n", p_name);
		information_ind(prim, dinfo, data);
		break;

		case CC_SETUP_ACKNOWLEDGE | INDICATION:
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) setup acknowledge\n", p_name);
		if (p_state != PORT_STATE_OUT_SETUP)
		{
			PDEBUG(DEBUG_ISDN, "Pdss1(%s) received setup_acknowledge, but we are not in outgoing setup state, IGNORING.\n", p_name);
			break;
		}
		setup_acknowledge_ind(prim, dinfo, data);
		break;

		case CC_PROCEEDING | INDICATION:
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) proceeding\n", p_name);
		if (p_state != PORT_STATE_OUT_SETUP
		 && p_state != PORT_STATE_OUT_OVERLAP)
		{
			PDEBUG(DEBUG_ISDN, "Pdss1(%s) received proceeding, but we are not in outgoing setup OR overlap state, IGNORING.\n", p_name);
			break;
		}
		proceeding_ind(prim, dinfo, data);
		break;

		case CC_ALERTING | INDICATION:
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) alerting\n", p_name);
		if (p_state != PORT_STATE_OUT_SETUP
		 && p_state != PORT_STATE_OUT_OVERLAP
		 && p_state != PORT_STATE_OUT_PROCEEDING)
		{
			PDEBUG(DEBUG_ISDN, "Pdss1(%s) received alerting, but we are not in outgoing setup OR overlap OR proceeding state, IGNORING.\n", p_name);
			break;
		}
		alerting_ind(prim, dinfo, data);
		break;

		case CC_CONNECT | INDICATION:
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) connect\n", p_name);
		if (p_state != PORT_STATE_OUT_SETUP
		 && p_state != PORT_STATE_OUT_OVERLAP
		 && p_state != PORT_STATE_OUT_PROCEEDING
		 && p_state != PORT_STATE_OUT_ALERTING)
		{
			PDEBUG(DEBUG_ISDN, "Pdss1(%s) received alerting, but we are not in outgoing setup OR overlap OR proceeding OR ALERTING state, IGNORING.\n", p_name);
			break;
		}
		connect_ind(prim, dinfo, data);
		if (p_m_d_notify_pending)
		{
			PDEBUG(DEBUG_ISDN, "received or connect, so we send pending notify message.\n");
			message_notify(ACTIVE_EPOINT(p_epointlist), p_m_d_notify_pending->type, &p_m_d_notify_pending->param);
			message_free(p_m_d_notify_pending);
			p_m_d_notify_pending = NULL;
		}
		break;

		case CC_CONNECT_ACKNOWLEDGE | INDICATION:
		case CC_CONNECT | CONFIRM:
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) connect_acknowlege.\n", p_name);
		if (p_state == PORT_STATE_CONNECT_WAITING)
			new_state(PORT_STATE_CONNECT);
		if (p_m_d_notify_pending)
		{
			PDEBUG(DEBUG_ISDN, "received or connect-ack, so we send pending notify message.\n");
			message_notify(ACTIVE_EPOINT(p_epointlist), p_m_d_notify_pending->type, &p_m_d_notify_pending->param);
			message_free(p_m_d_notify_pending);
			p_m_d_notify_pending = NULL;
		}
		break;

		case CC_DISCONNECT | INDICATION:
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) disconnect\n", p_name);
		disconnect_ind(prim, dinfo, data);
		break;

		case CC_RELEASE | CONFIRM:
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) release confirm\n", p_name);
		case CC_RELEASE | INDICATION:
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) release\n", p_name);
		release_ind(prim, dinfo, data);
		break;

		case CC_RELEASE_COMPLETE | INDICATION:
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) release_complete.\n", p_name);
		release_complete_ind(prim, dinfo, data);
		break;

		case CC_RELEASE_COMPLETE | CONFIRM:
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) release_complete (confirm).\n", p_name);
		break;

		case CC_NOTIFY | INDICATION:
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) notify\n", p_name);
		notify_ind(prim, dinfo, data);
		break;

		case CC_HOLD | INDICATION:
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) hold\n", p_name);
		hold_ind(prim, dinfo, data);
		break;

		case CC_RETRIEVE | INDICATION:
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) retrieve\n", p_name);
		retrieve_ind(prim, dinfo, data);
		break;

		case CC_SUSPEND | INDICATION:
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) suspend\n", p_name);
		suspend_ind(prim, dinfo, data);
		break;

		case CC_RESUME | INDICATION:
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) resume\n", p_name);
		resume_ind(prim, dinfo, data);
		break;

		case CC_FACILITY | INDICATION:
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) facility\n", p_name);
		facility_ind(prim, dinfo, data);
		break;

		case CC_RELEASE_CR | INDICATION:
		l3_trace_header(CC_RELEASE_CR | INDICATION, DIRECTION_IN);
		add_trace("callref", NULL, "0x%x", p_m_d_l3id);
		end_trace();
		if (p_m_d_ntmode)
		{
			if ((p_m_d_l3id&0xff00) == 0xff00)
				p_m_mISDNport->procids[p_m_d_l3id&0xff] = 0;
		}
		p_m_d_l3id = 0;
		p_m_delete = 1;
		/* sending release to endpoint in case we still have an endpoint
		 * NOTE: this only happens if the stack releases due to layer1
		 * or layer2 breakdown. otherwhise a release is received first.
		 */
		while(p_epointlist)
		{
			struct message *message;
			message = message_create(p_serial, p_epointlist->epoint_id, PORT_TO_EPOINT, MESSAGE_RELEASE);
			message->param.disconnectinfo.cause = (p_m_d_collect_cause!=CAUSE_NOUSER)?p_m_d_collect_cause:CAUSE_UNSPECIFIED;
			message->param.disconnectinfo.location = (p_m_d_collect_cause!=CAUSE_NOUSER)?p_m_d_collect_location:LOCATION_PRIVATE_LOCAL;
			message_put(message);
			/* remove epoint */
			free_epointlist(p_epointlist);

			new_state(PORT_STATE_RELEASE);
		}
		break;

		case CC_NEW_CR | INDICATION:
		l3_trace_header(prim, DIRECTION_IN);
		if (p_m_d_l3id)
			add_trace("callref", "old", "0x%x", p_m_d_l3id);
		if (p_m_d_ntmode)
		{
			new_l3id = *((int *)(((u_char *)data+mISDNUSER_HEAD_SIZE)));
			if (((new_l3id&0xff00)!=0xff00) && ((p_m_d_l3id&0xff00)==0xff00))
				p_m_mISDNport->procids[p_m_d_l3id&0xff] = 0;
		} else
		{
			new_l3id = dinfo;
		}
		p_m_d_l3id = new_l3id;
		add_trace("callref", "new", "0x%x", p_m_d_l3id);
		end_trace();
		break;

		default:
		l3_trace_header(prim, DIRECTION_IN);
		add_trace("unhandled", "prim", "0x%x", prim);
		end_trace();
	}
}

void Pdss1::new_state(int state)
{
	class Endpoint *epoint;

	/* set timeout */
	epoint = find_epoint_id(ACTIVE_EPOINT(p_epointlist));
	if (epoint && p_m_d_ntmode)
	{
		if (state == PORT_STATE_IN_OVERLAP)
		{
			p_m_timeout = p_settings.tout_dialing;
			time(&p_m_timer);
		}
		if (state != p_state)
		{
			if (state == PORT_STATE_IN_SETUP
			 || state == PORT_STATE_IN_OVERLAP)
			{
				p_m_timeout = p_settings.tout_setup;
				time(&p_m_timer);
			}
			if (state == PORT_STATE_IN_PROCEEDING
			 || state == PORT_STATE_OUT_PROCEEDING)
			{
				p_m_timeout = p_settings.tout_proceeding;
				time(&p_m_timer);
			}
			if (state == PORT_STATE_IN_ALERTING
			 || state == PORT_STATE_OUT_ALERTING)
			{
				p_m_timeout = p_settings.tout_alerting;
				time(&p_m_timer);
			}
			if (state == PORT_STATE_CONNECT
			 || state == PORT_STATE_CONNECT_WAITING)
			{
				p_m_timeout = 0;
			}
			if (state == PORT_STATE_IN_DISCONNECT
			 || state == PORT_STATE_OUT_DISCONNECT)
			{
				p_m_timeout = p_settings.tout_disconnect;
				time(&p_m_timer);
			}
		}
	}
	
	Port::new_state(state);
}


/*
 * handler
 */
int Pdss1::handler(void)
{
	int ret;

	if ((ret = Port::handler()))
		return(ret);

	/* handle destruction */
	if (p_m_delete && p_m_d_l3id==0)
	{
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) doing pending release.\n", p_name);
		delete this;
		return(-1);
	}

	return(0);
}


/*
 * handles all messages from endpoint
 */
/* MESSAGE_INFORMATION */
void Pdss1::message_information(unsigned long epoint_id, int message_id, union parameter *param)
{
	int headerlen = (p_m_d_ntmode)?mISDNUSER_HEAD_SIZE:mISDN_HEADER_LEN;
	INFORMATION_t *information;
	msg_t *dmsg;

	if (param->information.number[0]) /* only if we have something to dial */
	{
		dmsg = create_l3msg(CC_INFORMATION | REQUEST, MT_INFORMATION, p_m_d_l3id, sizeof(INFORMATION_t), p_m_d_ntmode);
		l3_trace_header(CC_INFORMATION | REQUEST, DIRECTION_OUT);
		information = (INFORMATION_t *)(dmsg->data + headerlen);
		enc_ie_called_pn(&information->CALLED_PN, dmsg, 0, 1, (unsigned char *)param->information.number);
		end_trace();
		msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);
	}
	new_state(p_state);
}


int newteid = 0;

/* MESSAGE_SETUP */
void Pdss1::message_setup(unsigned long epoint_id, int message_id, union parameter *param)
{
	int headerlen = (p_m_d_ntmode)?mISDNUSER_HEAD_SIZE:mISDN_HEADER_LEN;
	INFORMATION_t *information;
	SETUP_t *setup;
	msg_t *dmsg;
	int plan, type, screen, present, reason;
	int capability, mode, rate, coding, user, presentation, interpretation, hlc, exthlc;
	int channel, exclusive;
	int i;
	struct epoint_list *epointlist;

	/* release if port is blocked */
	if (p_m_mISDNport->ifport->block)
	{
		message = message_create(p_serial, ACTIVE_EPOINT(p_epointlist), PORT_TO_EPOINT, MESSAGE_RELEASE);
		message->param.disconnectinfo.cause = 27; // temp. unavail.
		message->param.disconnectinfo.location = LOCATION_PRIVATE_LOCAL;
		message_put(message);
		new_state(PORT_STATE_RELEASE);
		p_m_delete = 1;
		return;
	}

	/* copy setup infos to port */
	memcpy(&p_callerinfo, &param->setup.callerinfo, sizeof(p_callerinfo));
	memcpy(&p_dialinginfo, &param->setup.dialinginfo, sizeof(p_dialinginfo));
	memcpy(&p_capainfo, &param->setup.capainfo, sizeof(p_capainfo));
	memcpy(&p_redirinfo, &param->setup.redirinfo, sizeof(p_redirinfo));
//		SCPY(&p_m_tones_dir, param->setup.ext.tones_dir);

	/* only display at connect state: this case happens if endpoint is in connected mode */
	if (p_state==PORT_STATE_CONNECT)
	{
		if (p_type!=PORT_TYPE_DSS1_NT_OUT
		 && p_type!=PORT_TYPE_DSS1_NT_IN)
			return;
		if (p_callerinfo.display[0])
		{
			/* sending information */
			dmsg = create_l3msg(CC_INFORMATION | REQUEST, MT_INFORMATION, p_m_d_l3id, sizeof(INFORMATION_t), p_m_d_ntmode);
			information = (INFORMATION_t *)(dmsg->data + headerlen);
			l3_trace_header(CC_INFORMATION | REQUEST, DIRECTION_OUT);
	 	 	if (p_m_d_ntmode)
				enc_ie_display(&information->DISPLAY, dmsg, (unsigned char *)p_callerinfo.display);
			end_trace();
			msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);
			return;
		}
	}

	/* attach only if not already */
	epointlist = p_epointlist;
	while(epointlist)
	{
		if (epointlist->epoint_id == epoint_id)
			break;
		epointlist = epointlist->next;
	}
	if (!epointlist)
	{
		if (!(epointlist_new(epoint_id)))
		{
			PERROR("no memory for epointlist\n");
			exit(-1);
		}
	}

	/* get channel */
	exclusive = 0;
	if (p_m_b_channel)
	{
		channel = p_m_b_channel;
		exclusive = p_m_b_exclusive;
	} else
		channel = CHANNEL_ANY;
	/* nt-port with no channel, not reserverd */
	if (!p_m_b_channel && !p_m_b_reserve && p_type==PORT_TYPE_DSS1_NT_OUT)
		channel = CHANNEL_NO;

	/* creating l3id */
	l3_trace_header(CC_NEW_CR | REQUEST, DIRECTION_OUT);
	if (p_m_d_ntmode)
	{
		i = 0;
		while(i < 0x100)
		{
			if (p_m_mISDNport->procids[i] == 0)
				break;
			i++;
		}
		if (i == 0x100)
		{
			struct message *message;

			add_trace("callref", NULL, "no free id");
			end_trace();
			message = message_create(p_serial, ACTIVE_EPOINT(p_epointlist), PORT_TO_EPOINT, MESSAGE_RELEASE);
			message->param.disconnectinfo.cause = 47;
			message->param.disconnectinfo.location = LOCATION_PRIVATE_LOCAL;
			message_put(message);
			new_state(PORT_STATE_RELEASE);
			p_m_delete = 1;
			return;
		}
		p_m_mISDNport->procids[i] = 1;
		p_m_d_l3id = 0xff00 | i;
	} else
	{
		iframe_t ncr;
		/* if we are in te-mode, we need to create a process first */
		if (newteid++ > 0x7fff)
			newteid = 0x0001;
		p_m_d_l3id = (entity<<16) | newteid;
		/* preparing message */
		ncr.prim = CC_NEW_CR | REQUEST; 
		ncr.addr = p_m_mISDNport->upper_id | FLG_MSG_DOWN;
		ncr.dinfo = p_m_d_l3id;
		ncr.len = 0;
		/* send message */
 		mISDN_write(mISDNdevice, &ncr, mISDN_HEADER_LEN+ncr.len, TIMEOUT_1SEC);
//		if (!dmsg)
//			goto nomem;
	}
	add_trace("callref", "new", "0x%x", p_m_d_l3id);
	end_trace();

	/* preparing setup message */
	dmsg = create_l3msg(CC_SETUP | REQUEST, MT_SETUP, p_m_d_l3id, sizeof(SETUP_t), p_m_d_ntmode);
	l3_trace_header(CC_SETUP | REQUEST, DIRECTION_OUT);
	setup = (SETUP_t *)(dmsg->data + headerlen);
	/* channel information */
	if (channel >= 0) /* it should */
	{
		enc_ie_channel_id(&setup->CHANNEL_ID, dmsg, exclusive, channel);
	}
	/* caller information */
	plan = 1;
	switch (p_callerinfo.ntype)
	{
		case INFO_NTYPE_INTERNATIONAL:
		type = 0x1;
		break;
		case INFO_NTYPE_NATIONAL:
		type = 0x2;
		break;
		case INFO_NTYPE_SUBSCRIBER:
		type = 0x4;
		break;
		default: /* INFO_NTYPE_UNKNOWN */
		type = 0x0;
		break;
	}
	switch (p_callerinfo.screen)
	{
		case INFO_SCREEN_USER:
		screen = 0;
		break;
		default: /* INFO_SCREEN_NETWORK */
		screen = 3;
		break;
	}
	switch (p_callerinfo.present)
	{
		case INFO_PRESENT_RESTRICTED:
		present = 1;
		break;
		case INFO_PRESENT_NOTAVAIL:
		present = 2;
		break;
		default: /* INFO_PRESENT_ALLOWED */
		present = 0;
		break;
	}
	if (type >= 0)
		enc_ie_calling_pn(&setup->CALLING_PN, dmsg, type, plan, present, screen, (unsigned char *)p_callerinfo.id);
	/* dialing information */
	if (p_dialinginfo.number[0]) /* only if we have something to dial */
	{
		enc_ie_called_pn(&setup->CALLED_PN, dmsg, 0, 1, (unsigned char *)p_dialinginfo.number);
	}
	/* sending complete */
	if (p_dialinginfo.sending_complete)
		enc_ie_complete(&setup->COMPLETE, dmsg, 1);
	/* sending user-user */
	if (param->setup.useruser.len)
	{
		enc_ie_useruser(&setup->USER_USER, dmsg, param->setup.useruser.protocol, param->setup.useruser.data, param->setup.useruser.len);
	}
	/* redirecting number */
	plan = 1;
	switch (p_redirinfo.ntype)
	{
		case INFO_NTYPE_INTERNATIONAL:
		type = 0x1;
		break;
		case INFO_NTYPE_NATIONAL:
		type = 0x2;
		break;
		case INFO_NTYPE_SUBSCRIBER:
		type = 0x4;
		break;
		default: /* INFO_NTYPE_UNKNOWN */
		type = 0x0;
		break;
	}
	switch (p_redirinfo.screen)
	{
		case INFO_SCREEN_USER:
		screen = 0;
		break;
		default: /* INFO_SCREE_NETWORK */
		screen = 3;
		break;
	}
	switch (p_redirinfo.reason)
	{
		case INFO_REDIR_BUSY:
		reason = 1;
		break;
		case INFO_REDIR_NORESPONSE:
		reason = 2;
		break;
		case INFO_REDIR_UNCONDITIONAL:
		reason = 15;
		break;
		case INFO_REDIR_CALLDEFLECT:
		reason = 10;
		break;
		case INFO_REDIR_OUTOFORDER:
		reason = 9;
		break;
		default: /* INFO_REDIR_UNKNOWN */
		reason = 0;
		break;
	}
	switch (p_redirinfo.present)
	{
		case INFO_PRESENT_NULL: /* no redir at all */
		present = -1;
		screen = -1;
		reason = -1;
		plan = -1;
		type = -1;
		break;
		case INFO_PRESENT_RESTRICTED:
		present = 1;
		break;
		case INFO_PRESENT_NOTAVAIL:
		present = 2;
		break;
		default: /* INFO_PRESENT_ALLOWED */
		present = 0;
		break;
	}
	/* sending redirecting number only in ntmode */
	if (type >= 0 && p_m_d_ntmode)
		enc_ie_redir_nr(&setup->REDIR_NR, dmsg, type, plan, present, screen, reason, (unsigned char *)p_redirinfo.id);
	/* bearer capability */
//printf("hlc=%d\n",p_capainfo.hlc);
	coding = 0;
	capability = p_capainfo.bearer_capa;
	mode = p_capainfo.bearer_mode;
	rate = (mode==INFO_BMODE_CIRCUIT)?0x10:0x00;
	switch (p_capainfo.bearer_info1)
	{
		case INFO_INFO1_NONE:
		user = -1;
		break;
		default:
		user = p_capainfo.bearer_info1 & 0x7f;
		break;
	}
	enc_ie_bearer(&setup->BEARER, dmsg, coding, capability, mode, rate, -1, user);
	/* hlc */
	if (p_capainfo.hlc)
	{
		coding = 0;
		interpretation = 4;
		presentation = 1;
		hlc = p_capainfo.hlc & 0x7f;
		exthlc = -1;
		if (p_capainfo.exthlc)
			exthlc = p_capainfo.exthlc & 0x7f;
		enc_ie_hlc(&setup->HLC, dmsg, coding, interpretation, presentation, hlc, exthlc);
	}

	/* display */
	if (p_callerinfo.display[0] && p_m_d_ntmode)
		enc_ie_display(&setup->DISPLAY, dmsg, (unsigned char *)p_callerinfo.display);
#ifdef CENTREX
	/* nt-mode: CNIP (calling name identification presentation) */
	if (p_callerinfo.name[0] && p_m_d_ntmode)
		enc_facility_centrex(&setup->FACILITY, dmsg, (unsigned char *)p_callerinfo.name, 1);
#endif
	end_trace();

	/* send setup message now */
	msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);

	new_state(PORT_STATE_OUT_SETUP);
}

/* MESSAGE_FACILITY */
void Pdss1::message_facility(unsigned long epoint_id, int message_id, union parameter *param)
{
	int headerlen = (p_m_d_ntmode)?mISDNUSER_HEAD_SIZE:mISDN_HEADER_LEN;
	FACILITY_t *facility;
	msg_t *dmsg;

	/* facility will not be sent to external lines */
	if (!p_m_d_ntmode)
		return;

	PDEBUG(DEBUG_ISDN, "Pdss1(%s) sending facility message\n", p_name);

	/* sending facility */
	dmsg = create_l3msg(CC_FACILITY | REQUEST, MT_FACILITY, p_m_d_l3id, sizeof(FACILITY_t), p_m_d_ntmode);
	facility = (FACILITY_t *)(dmsg->data + headerlen);
	l3_trace_header(CC_FACILITY | REQUEST, DIRECTION_OUT);
	enc_ie_facility(&facility->FACILITY, dmsg, (unsigned char *)param->facilityinfo.data, param->facilityinfo.len);
	end_trace();
	msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);
}

/* MESSAGE_NOTIFY */
void Pdss1::message_notify(unsigned long epoint_id, int message_id, union parameter *param)
{
	int headerlen = (p_m_d_ntmode)?mISDNUSER_HEAD_SIZE:mISDN_HEADER_LEN;
	INFORMATION_t *information;
	NOTIFY_t *notification;
	int notify;
	int plan, type = -1, present;
	msg_t *dmsg;

	PDEBUG(DEBUG_ISDN, "Pdss1(%s) sending information message\n", p_name);
	if (param->notifyinfo.notify>INFO_NOTIFY_NONE)
		notify = param->notifyinfo.notify & 0x7f;
	else
		notify = -1;
	if (p_state != PORT_STATE_CONNECT)
	{
		/* notify only allowed in active state */
		notify = -1;
	}
	if (notify >= 0)
	{
		plan = 1;
		switch (param->notifyinfo.ntype)
		{
			case INFO_NTYPE_INTERNATIONAL:
			type = 1;
			break;
			case INFO_NTYPE_NATIONAL:
			type = 2;
			break;
			case INFO_NTYPE_SUBSCRIBER:
			type = 4;
			break;
			default: /* INFO_NTYPE_UNKNOWN */
			type = 0;
			break;
		}
		switch (param->notifyinfo.present)
		{
			case INFO_PRESENT_NULL: /* no redir at all */
			present = -1;
			plan = -1;
			type = -1;
			break;
			case INFO_PRESENT_RESTRICTED:
			present = 1;
			break;
			case INFO_PRESENT_NOTAVAIL:
			present = 2;
			break;
			default: /* INFO_PRESENT_ALLOWED */
			present = 0;
			break;
		}
	}

	if (notify<0 && !param->notifyinfo.display[0])
	{
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) nothing to notify, nothing to display\n", p_name);
		return;
	}

	if (notify >= 0)
	{
		if (p_state!=PORT_STATE_CONNECT)
		{
			/* queue notification */
			PDEBUG(DEBUG_ISDN, "Pdss1(%s) queueing notification because isdn port is not active state.\n", p_name);
			if (p_m_d_notify_pending)
				message_free(p_m_d_notify_pending);
			p_m_d_notify_pending = message_create(ACTIVE_EPOINT(p_epointlist), p_serial, EPOINT_TO_PORT, message_id);
			memcpy(&p_m_d_notify_pending->param, param, sizeof(union parameter));
		} else
		{
			/* sending notification */
			dmsg = create_l3msg(CC_NOTIFY | REQUEST, MT_NOTIFY, p_m_d_l3id, sizeof(NOTIFY_t), p_m_d_ntmode);
			notification = (NOTIFY_t *)(dmsg->data + headerlen);
			l3_trace_header(CC_NOTIFY | REQUEST, DIRECTION_OUT);
			enc_ie_notify(&notification->NOTIFY, dmsg, notify);
			/* sending redirection number only in ntmode */
			if (type >= 0 && p_m_d_ntmode)
				enc_ie_redir_dn(&notification->REDIR_DN, dmsg, type, plan, present, (unsigned char *)param->notifyinfo.id);
			if (param->notifyinfo.display[0] && p_m_d_ntmode)
				enc_ie_display(&notification->DISPLAY, dmsg, (unsigned char *)param->notifyinfo.display);
			end_trace();
			msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);
		}
	} else if (p_m_d_ntmode)
	{
		/* sending information */
		dmsg = create_l3msg(CC_INFORMATION | REQUEST, MT_INFORMATION, p_m_d_l3id, sizeof(INFORMATION_t), p_m_d_ntmode);
		information = (INFORMATION_t *)(dmsg->data + headerlen);
		l3_trace_header(CC_INFORMATION | REQUEST, DIRECTION_OUT);
		enc_ie_display(&information->DISPLAY, dmsg, (unsigned char *)param->notifyinfo.display);
		end_trace();
		msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);
	}
}

/* MESSAGE_OVERLAP */
void Pdss1::message_overlap(unsigned long epoint_id, int message_id, union parameter *param)
{
	int headerlen = (p_m_d_ntmode)?mISDNUSER_HEAD_SIZE:mISDN_HEADER_LEN;
	SETUP_ACKNOWLEDGE_t *setup_acknowledge;
	msg_t *dmsg;

	/* sending setup_acknowledge */
	dmsg = create_l3msg(CC_SETUP_ACKNOWLEDGE | REQUEST, MT_SETUP_ACKNOWLEDGE, p_m_d_l3id, sizeof(SETUP_ACKNOWLEDGE_t), p_m_d_ntmode);
	setup_acknowledge = (SETUP_ACKNOWLEDGE_t *)(dmsg->data + headerlen);
	l3_trace_header(CC_SETUP_ACKNOWLEDGE | REQUEST, DIRECTION_OUT);
	/* channel information */
	if (p_state == PORT_STATE_IN_SETUP)
		enc_ie_channel_id(&setup_acknowledge->CHANNEL_ID, dmsg, 1, p_m_b_channel);
	/* progress information */
	if (p_capainfo.bearer_capa==INFO_BC_SPEECH
	 || p_capainfo.bearer_capa==INFO_BC_AUDIO
	 || p_capainfo.bearer_capa==INFO_BC_DATAUNRESTRICTED_TONES)
	if (p_m_mISDNport->is_tones)
		enc_ie_progress(&setup_acknowledge->PROGRESS, dmsg, 0, p_m_d_ntmode?1:5, 8);
	end_trace();
	msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);

	new_state(PORT_STATE_IN_OVERLAP);
}

/* MESSAGE_PROCEEDING */
void Pdss1::message_proceeding(unsigned long epoint_id, int message_id, union parameter *param)
{
	int headerlen = (p_m_d_ntmode)?mISDNUSER_HEAD_SIZE:mISDN_HEADER_LEN;
	CALL_PROCEEDING_t *proceeding;
	msg_t *dmsg;

	/* sending proceeding */
	dmsg = create_l3msg(CC_PROCEEDING | REQUEST, MT_CALL_PROCEEDING, p_m_d_l3id, sizeof(CALL_PROCEEDING_t), p_m_d_ntmode);
	proceeding = (CALL_PROCEEDING_t *)(dmsg->data + headerlen);
	l3_trace_header(CC_PROCEEDING | REQUEST, DIRECTION_OUT);
	/* channel information */
	if (p_state == PORT_STATE_IN_SETUP)
		enc_ie_channel_id(&proceeding->CHANNEL_ID, dmsg, 1, p_m_b_channel);
	/* progress information */
	if (p_capainfo.bearer_capa==INFO_BC_SPEECH
	 || p_capainfo.bearer_capa==INFO_BC_AUDIO
	 || p_capainfo.bearer_capa==INFO_BC_DATAUNRESTRICTED_TONES)
	if (p_m_mISDNport->is_tones)
		enc_ie_progress(&proceeding->PROGRESS, dmsg, 0, p_m_d_ntmode?1:5, 8);
	end_trace();
	msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);

	new_state(PORT_STATE_IN_PROCEEDING);
}

/* MESSAGE_ALERTING */
void Pdss1::message_alerting(unsigned long epoint_id, int message_id, union parameter *param)
{
	int headerlen = (p_m_d_ntmode)?mISDNUSER_HEAD_SIZE:mISDN_HEADER_LEN;
	ALERTING_t *alerting;
	msg_t *dmsg;

	/* NT-MODE in setup state we must send PROCEEDING first */
	if (p_m_d_ntmode && p_state==PORT_STATE_IN_SETUP)
	{
		CALL_PROCEEDING_t *proceeding;

		/* sending proceeding */
		dmsg = create_l3msg(CC_PROCEEDING | REQUEST, MT_CALL_PROCEEDING, p_m_d_l3id, sizeof(CALL_PROCEEDING_t), p_m_d_ntmode);
		proceeding = (CALL_PROCEEDING_t *)(dmsg->data + headerlen);
		l3_trace_header(CC_PROCEEDING | REQUEST, DIRECTION_OUT);
		/* channel information */
		enc_ie_channel_id(&proceeding->CHANNEL_ID, dmsg, 1, p_m_b_channel);
		/* progress information */
		if (p_capainfo.bearer_capa==INFO_BC_SPEECH
		 || p_capainfo.bearer_capa==INFO_BC_AUDIO
		 || p_capainfo.bearer_capa==INFO_BC_DATAUNRESTRICTED_TONES)
		enc_ie_progress(&proceeding->PROGRESS, dmsg, 0, p_m_d_ntmode?1:5, 8);
		end_trace();
		msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);
		new_state(PORT_STATE_IN_PROCEEDING);
	}

	/* sending alerting */
	dmsg = create_l3msg(CC_ALERTING | REQUEST, MT_ALERTING, p_m_d_l3id, sizeof(ALERTING_t), p_m_d_ntmode);
	alerting = (ALERTING_t *)(dmsg->data + headerlen);
	l3_trace_header(CC_ALERTING | REQUEST, DIRECTION_OUT);
	/* channel information */
	if (p_state == PORT_STATE_IN_SETUP)
		enc_ie_channel_id(&alerting->CHANNEL_ID, dmsg, 1, p_m_b_channel);
	/* progress information */
	if (p_capainfo.bearer_capa==INFO_BC_SPEECH
	 || p_capainfo.bearer_capa==INFO_BC_AUDIO
	 || p_capainfo.bearer_capa==INFO_BC_DATAUNRESTRICTED_TONES)
	if (p_m_mISDNport->is_tones)
		enc_ie_progress(&alerting->PROGRESS, dmsg, 0, p_m_d_ntmode?1:5, 8);
	end_trace();
	msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);

	new_state(PORT_STATE_IN_ALERTING);
}

/* MESSAGE_CONNECT */
void Pdss1::message_connect(unsigned long epoint_id, int message_id, union parameter *param)
{
	int headerlen = (p_m_d_ntmode)?mISDNUSER_HEAD_SIZE:mISDN_HEADER_LEN;
	INFORMATION_t *information;
	CONNECT_t *connect;
	int type, plan, present, screen;
	msg_t *dmsg;
	class Endpoint *epoint;

	/* NT-MODE in setup state we must send PROCEEDING first */
	if (p_m_d_ntmode && p_state==PORT_STATE_IN_SETUP)
	{
		CALL_PROCEEDING_t *proceeding;

		/* sending proceeding */
		dmsg = create_l3msg(CC_PROCEEDING | REQUEST, MT_CALL_PROCEEDING, p_m_d_l3id, sizeof(CALL_PROCEEDING_t), p_m_d_ntmode);
		proceeding = (CALL_PROCEEDING_t *)(dmsg->data + headerlen);
		l3_trace_header(CC_PROCEEDING | REQUEST, DIRECTION_OUT);
		/* channel information */
		enc_ie_channel_id(&proceeding->CHANNEL_ID, dmsg, 1, p_m_b_channel);
//		/* progress information */
//		if (p_capainfo.bearer_capa==INFO_BC_SPEECH
//		 || p_capainfo.bearer_capa==INFO_BC_AUDIO
//		 || p_capainfo.bearer_capa==INFO_BC_DATAUNRESTRICTED_TONES)
//		enc_ie_progress(&proceeding->PROGRESS, dmsg, 0, p_m_d_ntmode?1:5, 8);
		end_trace();
		msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);
		new_state(PORT_STATE_IN_PROCEEDING);
	}

	/* copy connected information */
	memcpy(&p_connectinfo, &param->connectinfo, sizeof(p_connectinfo));

	/* only display at connect state */
	if (p_state == PORT_STATE_CONNECT)
	if (p_connectinfo.display[0])
	{
		/* sending information */
		dmsg = create_l3msg(CC_INFORMATION | REQUEST, MT_INFORMATION, p_m_d_l3id, sizeof(INFORMATION_t), p_m_d_ntmode);
		information = (INFORMATION_t *)(dmsg->data + headerlen);
		l3_trace_header(CC_INFORMATION | REQUEST, DIRECTION_OUT);
		if (p_m_d_ntmode)
			enc_ie_display(&information->DISPLAY, dmsg, (unsigned char *)p_connectinfo.display);
		end_trace();
		msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);
		return;
	}

	if (p_state!=PORT_STATE_IN_SETUP && p_state!=PORT_STATE_IN_OVERLAP && p_state!=PORT_STATE_IN_PROCEEDING && p_state!=PORT_STATE_IN_ALERTING)
	{
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) connect command only possible in setup, proceeding or alerting state.\n", p_name);
		return;
	}

	/* preparing connect message */
	dmsg = create_l3msg(CC_CONNECT | REQUEST, MT_CONNECT, p_m_d_l3id, sizeof(CONNECT_t), p_m_d_ntmode);
	connect = (CONNECT_t *)(dmsg->data + headerlen);
	l3_trace_header(CC_CONNECT | REQUEST, DIRECTION_OUT);
	/* connect information */
	plan = 1;
	switch (p_connectinfo.ntype)
	{
		case INFO_NTYPE_INTERNATIONAL:
		type = 0x1;
		break;
		case INFO_NTYPE_NATIONAL:
		type = 0x2;
		break;
		case INFO_NTYPE_SUBSCRIBER:
		type = 0x4;
		break;
		default: /* INFO_NTYPE_UNKNOWN */
		type = 0x0;
		break;
	}
	switch (param->connectinfo.screen)
	{
		case INFO_SCREEN_USER:
		screen = 0;
		break;
		default: /* INFO_SCREE_NETWORK */
		screen = 3;
		break;
	}
	switch (p_connectinfo.present)
	{
		case INFO_PRESENT_NULL: /* no colp at all */
		present = -1;
		screen = -1;
		plan = -1;
		type = -1;
		break;
		case INFO_PRESENT_RESTRICTED:
		present = 1;
		break;
		case INFO_PRESENT_NOTAVAIL:
		present = 2;
		break;
		default: /* INFO_PRESENT_ALLOWED */
		present = 0;
		break;
	}
	if (type >= 0)
		enc_ie_connected_pn(&connect->CONNECT_PN, dmsg, type, plan, present, screen, (unsigned char *)p_connectinfo.id);
	/* display */
	if (p_connectinfo.display[0] && p_m_d_ntmode)
		enc_ie_display(&connect->DISPLAY, dmsg, (unsigned char *)p_connectinfo.display);
#ifdef CENTREX
	/* nt-mode: CONP (connected name identification presentation) */
	if (p_connectinfo.name[0] && p_m_d_ntmode)
		enc_facility_centrex(&connect->FACILITY, dmsg, (unsigned char *)p_connectinfo.name, 0);
#endif
	/* date & time */
	if (p_m_d_ntmode)
	{
		epoint = find_epoint_id(epoint_id);
		enc_ie_date(&connect->DATE, dmsg, now, p_settings.no_seconds);
	}
	end_trace();
	/* finally send message */
	msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);

	if (p_m_d_ntmode)
		new_state(PORT_STATE_CONNECT);
	else
		new_state(PORT_STATE_CONNECT_WAITING);
	set_tone("", NULL);
}

/* MESSAGE_DISCONNECT */
void Pdss1::message_disconnect(unsigned long epoint_id, int message_id, union parameter *param)
{
	int headerlen = (p_m_d_ntmode)?mISDNUSER_HEAD_SIZE:mISDN_HEADER_LEN;
	DISCONNECT_t *disconnect;
	RELEASE_COMPLETE_t *release_complete;
	msg_t *dmsg;
	struct message *message;
	char *p = NULL;

	/* we reject during incoming setup when we have no tones. also if we are in outgoing setup state */
	if ((p_state==PORT_STATE_IN_SETUP && !p_m_mISDNport->is_tones)
	 || p_state==PORT_STATE_OUT_SETUP)
	{
		/* sending release to endpoint */
		while(p_epointlist)
		{
			message = message_create(p_serial, p_epointlist->epoint_id, PORT_TO_EPOINT, MESSAGE_RELEASE);
			message->param.disconnectinfo.cause = 16;
			message->param.disconnectinfo.location = LOCATION_PRIVATE_LOCAL;
			message_put(message);
			/* remove epoint */
			free_epointlist(p_epointlist);
		}
		/* sending release */
		dmsg = create_l3msg(CC_RELEASE_COMPLETE | REQUEST, MT_RELEASE_COMPLETE, p_m_d_l3id, sizeof(RELEASE_COMPLETE_t), p_m_d_ntmode);
		release_complete = (RELEASE_COMPLETE_t *)(dmsg->data + headerlen);
		l3_trace_header(CC_RELEASE_COMPLETE | REQUEST, DIRECTION_OUT);
		/* send cause */
		enc_ie_cause(&release_complete->CAUSE, dmsg, (p_m_d_ntmode && param->disconnectinfo.location==LOCATION_PRIVATE_LOCAL)?LOCATION_PRIVATE_LOCAL:param->disconnectinfo.location, param->disconnectinfo.cause);
		end_trace();
		msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);
		new_state(PORT_STATE_RELEASE);
		p_m_delete = 1;
		return;
	}

	/* NT-MODE in setup state we must send PROCEEDING first */
	if (p_state==PORT_STATE_IN_SETUP)
	{
		CALL_PROCEEDING_t *proceeding;

		/* sending proceeding */
		dmsg = create_l3msg(CC_PROCEEDING | REQUEST, MT_CALL_PROCEEDING, p_m_d_l3id, sizeof(CALL_PROCEEDING_t), p_m_d_ntmode);
		proceeding = (CALL_PROCEEDING_t *)(dmsg->data + headerlen);
		l3_trace_header(CC_PROCEEDING | REQUEST, DIRECTION_OUT);
		/* channel information */
		enc_ie_channel_id(&proceeding->CHANNEL_ID, dmsg, 1, p_m_b_channel);
		/* progress information */
		if (p_capainfo.bearer_capa==INFO_BC_SPEECH
		 || p_capainfo.bearer_capa==INFO_BC_AUDIO
		 || p_capainfo.bearer_capa==INFO_BC_DATAUNRESTRICTED_TONES)
			enc_ie_progress(&proceeding->PROGRESS, dmsg, 0, p_m_d_ntmode?1:5, 8);
		end_trace();
		msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);
		new_state(PORT_STATE_IN_PROCEEDING);
	}

	/* sending disconnect */
	dmsg = create_l3msg(CC_DISCONNECT | REQUEST, MT_DISCONNECT, p_m_d_l3id, sizeof(DISCONNECT_t), p_m_d_ntmode);
	disconnect = (DISCONNECT_t *)(dmsg->data + headerlen);
	l3_trace_header(CC_DISCONNECT | REQUEST, DIRECTION_OUT);
	/* progress information */
	if (p_capainfo.bearer_capa==INFO_BC_SPEECH
	 || p_capainfo.bearer_capa==INFO_BC_AUDIO
	 || p_capainfo.bearer_capa==INFO_BC_DATAUNRESTRICTED_TONES)
	if (p_m_mISDNport->is_tones)
		enc_ie_progress(&disconnect->PROGRESS, dmsg, 0, p_m_d_ntmode?1:5, 8);
	/* send cause */
	enc_ie_cause(&disconnect->CAUSE, dmsg, (p_m_d_ntmode && param->disconnectinfo.location==LOCATION_PRIVATE_LOCAL)?LOCATION_PRIVATE_LOCAL:param->disconnectinfo.location, param->disconnectinfo.cause);
	/* send display */
	if (param->disconnectinfo.display[0])
		p = param->disconnectinfo.display;
	if (p) if (*p && p_m_d_ntmode)
		enc_ie_display(&disconnect->DISPLAY, dmsg, (unsigned char *)p);
	end_trace();
	msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);
	new_state(PORT_STATE_OUT_DISCONNECT);
}

/* MESSAGE_RELEASE */
void Pdss1::message_release(unsigned long epoint_id, int message_id, union parameter *param)
{
	int headerlen = (p_m_d_ntmode)?mISDNUSER_HEAD_SIZE:mISDN_HEADER_LEN;
	RELEASE_t *release;
	RELEASE_COMPLETE_t *release_complete;
	DISCONNECT_t *disconnect;
	msg_t *dmsg;
	class Endpoint *epoint;
	char *p = NULL;

	/* if we have incoming disconnected, we may release */
	if (p_state==PORT_STATE_IN_DISCONNECT
	 || p_state==PORT_STATE_OUT_DISCONNECT)
	{
		/* sending release */
		dmsg = create_l3msg(CC_RELEASE | REQUEST, MT_RELEASE, p_m_d_l3id, sizeof(RELEASE_t), p_m_d_ntmode);
		release = (RELEASE_t *)(dmsg->data + headerlen);
		l3_trace_header(CC_RELEASE | REQUEST, DIRECTION_OUT);
		/* send cause */
		enc_ie_cause(&release->CAUSE, dmsg, (p_m_d_ntmode && param->disconnectinfo.location==LOCATION_PRIVATE_LOCAL)?LOCATION_PRIVATE_LOCAL:param->disconnectinfo.location, param->disconnectinfo.cause);
		end_trace();
		msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);
		new_state(PORT_STATE_RELEASE);
		/* remove epoint */
		remove_endpoint:
		free_epointid(epoint_id);
		l3_trace_header(CC_RELEASE_CR | REQUEST, DIRECTION_OUT);
		add_trace("callref", "new", "0x%x", p_m_d_l3id);
		end_trace();
		if (p_m_d_ntmode)
		{
			if ((p_m_d_l3id&0xff00) == 0xff00)
				p_m_mISDNport->procids[p_m_d_l3id&0xff] = 0;
		}
		p_m_d_l3id = 0;
		p_m_delete = 1;
		return;
	}
	/* if we are on outgoing/incoming call setup, we may release complete */
	if (p_state==PORT_STATE_OUT_SETUP
	 || p_state==PORT_STATE_IN_SETUP
// NOTE: a bug in mISDNuser (see disconnect_req_out !!!)
	 || p_state==PORT_STATE_OUT_PROCEEDING)
	{
		/* sending release */
		dmsg = create_l3msg(CC_RELEASE_COMPLETE | REQUEST, MT_RELEASE_COMPLETE, p_m_d_l3id, sizeof(RELEASE_COMPLETE_t), p_m_d_ntmode);
		release_complete = (RELEASE_COMPLETE_t *)(dmsg->data + headerlen);
		l3_trace_header(CC_RELEASE | REQUEST, DIRECTION_OUT);
		/* send cause */
		enc_ie_cause(&release_complete->CAUSE, dmsg, (p_m_d_ntmode && param->disconnectinfo.location==LOCATION_PRIVATE_LOCAL)?LOCATION_PRIVATE_LOCAL:param->disconnectinfo.location, param->disconnectinfo.cause);
		end_trace();
		msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);
		new_state(PORT_STATE_RELEASE);
		goto remove_endpoint;
	}

	/* NT-MODE in setup state we must send PROCEEDING first */
	if (p_m_d_ntmode && p_state==PORT_STATE_IN_SETUP)
	{
		CALL_PROCEEDING_t *proceeding;

		/* sending proceeding */
		dmsg = create_l3msg(CC_PROCEEDING | REQUEST, MT_CALL_PROCEEDING, p_m_d_l3id, sizeof(CALL_PROCEEDING_t), p_m_d_ntmode);
		proceeding = (CALL_PROCEEDING_t *)(dmsg->data + headerlen);
		l3_trace_header(CC_PROCEEDING | REQUEST, DIRECTION_OUT);
		/* channel information */
		enc_ie_channel_id(&proceeding->CHANNEL_ID, dmsg, 1, p_m_b_channel);
		/* progress information */
		if (p_capainfo.bearer_capa==INFO_BC_SPEECH
		 || p_capainfo.bearer_capa==INFO_BC_AUDIO
		 || p_capainfo.bearer_capa==INFO_BC_DATAUNRESTRICTED_TONES)
			enc_ie_progress(&proceeding->PROGRESS, dmsg, 0, p_m_d_ntmode?1:5, 8);
		end_trace();
		msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);
	}

	/* sending disconnect */
	dmsg = create_l3msg(CC_DISCONNECT | REQUEST, MT_DISCONNECT, p_m_d_l3id, sizeof(DISCONNECT_t), p_m_d_ntmode);
	disconnect = (DISCONNECT_t *)(dmsg->data + headerlen);
	l3_trace_header(CC_DISCONNECT | REQUEST, DIRECTION_OUT);
	/* progress information */
	if (p_capainfo.bearer_capa==INFO_BC_SPEECH
	 || p_capainfo.bearer_capa==INFO_BC_AUDIO
	 || p_capainfo.bearer_capa==INFO_BC_DATAUNRESTRICTED_TONES)
	if (p_m_mISDNport->is_tones)
		enc_ie_progress(&disconnect->PROGRESS, dmsg, 0, p_m_d_ntmode?1:5, 8);
	/* send cause */
	enc_ie_cause(&disconnect->CAUSE, dmsg, (p_m_d_ntmode && param->disconnectinfo.location==LOCATION_PRIVATE_LOCAL)?LOCATION_PRIVATE_LOCAL:param->disconnectinfo.location, param->disconnectinfo.cause);
	/* send display */
	epoint = find_epoint_id(epoint_id);
	if (param->disconnectinfo.display[0])
		p = param->disconnectinfo.display;
	if (p) if (*p && p_m_d_ntmode)
		enc_ie_display(&disconnect->DISPLAY, dmsg, (unsigned char *)p);
	end_trace();
	msg_queue_tail(&p_m_mISDNport->downqueue, dmsg);
	new_state(PORT_STATE_RELEASE);
	free_epointid(epoint_id);
//	p_m_delete = 1;
}


/*
 * endpoint sends messages to the port
 */
int Pdss1::message_epoint(unsigned long epoint_id, int message_id, union parameter *param)
{
	struct message *message;

	if (PmISDN::message_epoint(epoint_id, message_id, param))
		return(1);

	switch(message_id)
	{
		case MESSAGE_INFORMATION: /* overlap dialing */
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) received dialing info '%s'.\n", p_name, param->information.number);
		if (p_type==PORT_TYPE_DSS1_NT_OUT
		 && p_state!=PORT_STATE_OUT_OVERLAP
		 && p_state!=PORT_STATE_CONNECT
		 && p_state!=PORT_STATE_OUT_DISCONNECT
		 && p_state!=PORT_STATE_IN_DISCONNECT)
		{
			PDEBUG(DEBUG_ISDN, "Pdss1(%s) (internal outgoing) ignoring information, invalid state.\n", p_name);
			break;
		}
		if (p_type==PORT_TYPE_DSS1_TE_OUT
		 && p_state!=PORT_STATE_OUT_OVERLAP
		 && p_state!=PORT_STATE_OUT_PROCEEDING
		 && p_state!=PORT_STATE_OUT_ALERTING
		 && p_state!=PORT_STATE_CONNECT
		 && p_state!=PORT_STATE_OUT_DISCONNECT
		 && p_state!=PORT_STATE_IN_DISCONNECT)
		{
			if (options.deb & DEBUG_ISDN)
				PERROR("Pdss1(%s) (external outgoing) ignoring information, invalid state.\n", p_name);
			break;
		}
		if ((p_type==PORT_TYPE_DSS1_NT_IN || p_type==PORT_TYPE_DSS1_TE_IN)
		 && p_state!=PORT_STATE_IN_OVERLAP
		 && p_state!=PORT_STATE_IN_PROCEEDING
		 && p_state!=PORT_STATE_IN_ALERTING
		 && p_state!=PORT_STATE_CONNECT
		 && p_state!=PORT_STATE_CONNECT_WAITING
		 && p_state!=PORT_STATE_OUT_DISCONNECT
		 && p_state!=PORT_STATE_IN_DISCONNECT)
		{
			PDEBUG(DEBUG_ISDN, "Pdss1(%s) (incoming) ignoring information, invalid state.\n", p_name);
			break;
		}
		message_information(epoint_id, message_id, param);
		break;

		case MESSAGE_SETUP: /* dial-out command received from epoint */
		PDEBUG((DEBUG_ISDN | DEBUG_BCHANNEL), "Pdss1(%s) isdn port received setup from '%s' to '%s'\n", p_name, param->setup.callerinfo.id, param->setup.dialinginfo.number);
		if (p_state!=PORT_STATE_IDLE
		 && p_state!=PORT_STATE_CONNECT)
		{
			PERROR("Pdss1(%s) ignoring setup because isdn port is not in idle state (or connected for sending display info).\n", p_name);
			break;
		}
		if (p_epointlist && p_state==PORT_STATE_IDLE)
		{
			PERROR("Pdss1(%s): software error: epoint pointer is set in idle state, how bad!! exitting.\n", p_name);
			exit(-1);
		}
		/* note: pri is a special case, because links must be up for pri */ 
		if (p_m_mISDNport->l1link || p_m_mISDNport->pri || !p_m_mISDNport->ntmode || p_state!=PORT_STATE_IDLE)
		{
			/* LAYER 1 is up, or we may send */
			message_setup(epoint_id, message_id, param);
		} else {
			iframe_t act;
			/* LAYER 1 id down, so we queue */
			p_m_d_queue = message_create(epoint_id, p_serial, EPOINT_TO_PORT, message_id);
			memcpy(&p_m_d_queue->param, param, sizeof(union parameter));
			/* attach us */
			if (!(epointlist_new(epoint_id)))
			{
				PERROR("no memory for epointlist\n");
				exit(-1);
			}
			/* activate link */
			PDEBUG(DEBUG_ISDN, "the L1 is down, we try to establish the link NT portnum=%d (%s).\n", p_m_mISDNport->portnum, p_name);
			act.prim = PH_ACTIVATE | REQUEST; 
			act.addr = p_m_mISDNport->upper_id | FLG_MSG_DOWN;
			act.dinfo = 0;
			act.len = 0;
			mISDN_write(mISDNdevice, &act, mISDN_HEADER_LEN+act.len, TIMEOUT_1SEC);
//			/* set timeout */
//			p_m_mISDNport->l1timeout = now+3;
		}
		break;

		case MESSAGE_NOTIFY: /* display and notifications */
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) isdn port with (caller id %s) received notification: display='%s' notify=%d phone=%s\n", p_name, p_callerinfo.id, param->notifyinfo.display, param->notifyinfo.notify, param->notifyinfo.id);
		message_notify(epoint_id, message_id, param);
		break;

		case MESSAGE_FACILITY: /* facility message */
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) isdn port with (caller id %s) received facility.\n", p_name, p_callerinfo.id);
		message_facility(epoint_id, message_id, param);
		break;

		case MESSAGE_OVERLAP: /* more information is needed */
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) isdn port with (caller id %s) received setup acknowledge\n", p_name, p_callerinfo.id);
		if (p_state!=PORT_STATE_IN_SETUP)
		{
			PDEBUG(DEBUG_ISDN, "Pdss1(%s) ignoring setup acknowledge because isdn port is not incoming setup state.\n", p_name);
			break;
		}
		message_overlap(epoint_id, message_id, param);
		break;

		case MESSAGE_PROCEEDING: /* call of endpoint is proceeding */
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) isdn port with (caller id %s) received proceeding\n", p_name, p_callerinfo.id);
		if (p_state!=PORT_STATE_IN_SETUP
		 && p_state!=PORT_STATE_IN_OVERLAP)
		{
			PDEBUG(DEBUG_ISDN, "Pdss1(%s) ignoring: proceeding command not possible in current state.\n", p_name);
			break;
		}
		message_proceeding(epoint_id, message_id, param);
		break;

		case MESSAGE_ALERTING: /* call of endpoint is ringing */
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) isdn port with (caller id %s) received alerting\n", p_name, p_callerinfo.id);
		if (p_state!=PORT_STATE_IN_SETUP
		 && p_state!=PORT_STATE_IN_OVERLAP
		 && p_state!=PORT_STATE_IN_PROCEEDING)
		{
			PDEBUG(DEBUG_ISDN, "Pdss1(%s) ignoring: alerting command not possible in current state.\n", p_name);
			break;
		}
		message_alerting(epoint_id, message_id, param);
		break;

		case MESSAGE_CONNECT: /* call of endpoint is connected */
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) isdn port with (caller id %s) received connect\n", p_name, p_callerinfo.id);
		if (p_state!=PORT_STATE_IN_SETUP
		 && p_state!=PORT_STATE_IN_OVERLAP
		 && p_state!=PORT_STATE_IN_PROCEEDING
		 && p_state!=PORT_STATE_IN_ALERTING
		 && !(p_state==PORT_STATE_CONNECT && p_m_d_ntmode))
		{
			PDEBUG(DEBUG_ISDN, "Pdss1(%s) ignoring: connect command not possible in current state.\n", p_name);
			break;
		}
		message_connect(epoint_id, message_id, param);
		break;

		case MESSAGE_DISCONNECT: /* call has been disconnected */
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) isdn port with (caller id %s) received disconnect cause=%d\n", p_name, p_callerinfo.id, param->disconnectinfo.cause);
		if (p_state!=PORT_STATE_IN_SETUP
		 && p_state!=PORT_STATE_IN_OVERLAP
		 && p_state!=PORT_STATE_IN_PROCEEDING
		 && p_state!=PORT_STATE_IN_ALERTING
		 && p_state!=PORT_STATE_OUT_SETUP
		 && p_state!=PORT_STATE_OUT_OVERLAP
		 && p_state!=PORT_STATE_OUT_PROCEEDING
		 && p_state!=PORT_STATE_OUT_ALERTING
		 && p_state!=PORT_STATE_CONNECT
		 && p_state!=PORT_STATE_CONNECT_WAITING)
		{
			PDEBUG(DEBUG_ISDN, "Pdss1(%s) ignoring: disconnect command not possible in current state.\n", p_name);
			break;
		}
		message_disconnect(epoint_id, message_id, param);
		break;

		case MESSAGE_RELEASE: /* release isdn port */
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) isdn port with (caller id %s) received release cause=%d\n", p_name, p_callerinfo.id, param->disconnectinfo.cause);
		if (p_state==PORT_STATE_RELEASE)
		{
			PDEBUG(DEBUG_ISDN, "Pdss1(%s) ignoring: release command not possible in RELEASE state.\n", p_name);
			break;
		}
		message_release(epoint_id, message_id, param);
		break;

		default:
		PDEBUG(DEBUG_ISDN, "Pdss1(%s) isdn port with (caller id %s) received a wrong message: %d\n", p_name, p_callerinfo.id, message);
	}

	return(1);
}



/*
 * data from isdn-stack (layer-3) to pbx (port class)
 */
/* NOTE: nt mode use mISDNuser_head_t as header */
int stack2manager_nt(void *dat, void *arg)
{
	class Port *port;
	class Pdss1 *pdss1;
	manager_t *mgr = (manager_t *)dat;
	msg_t *msg = (msg_t *)arg;
	mISDNuser_head_t *hh;
	struct mISDNport *mISDNport;
	char name[32];

	if (!msg || !mgr)
		return(-EINVAL);

	/* note: nst is the first data feld of mISDNport */
	mISDNport = (struct mISDNport *)mgr->nst;

	hh = (mISDNuser_head_t *)msg->data;
	PDEBUG(DEBUG_ISDN, "prim(0x%x) dinfo(0x%x) msg->len(%d)\n", hh->prim, hh->dinfo, msg->len);

	/* find Port object of type ISDN */
	port = port_first;
	while(port)
	{
		if (port->p_type == PORT_TYPE_DSS1_NT_IN || port->p_type == PORT_TYPE_DSS1_NT_OUT)
		{
			pdss1 = (class Pdss1 *)port;
//PDEBUG(DEBUG_ISDN, "comparing dinfo = 0x%x with l3id 0x%x\n", hh->dinfo, pdss1->p_m_d_l3id);
			/* check out correct stack */
			if (pdss1->p_m_mISDNport == mISDNport)
			/* check out correct id */
			if ((hh->dinfo&0xffff0000) == (pdss1->p_m_d_l3id&0xffff0000))
			{
				/* found port, the message belongs to */
				break;
			}
		}
		port = port->next;
	}
	if (port)
	{
		/* if process id is master process, but a child disconnects */
		if ((hh->dinfo&0x0000ff00)!=0x0000ff00 && (pdss1->p_m_d_l3id&0x0000ff00)==0x0000ff00 && hh->prim==(CC_DISCONNECT|INDICATION))
		{
			/* send special indication for child disconnect */
			pdss1->disconnect_ind_i(hh->prim, hh->dinfo, msg->data);
			free_msg(msg);
			return(0);
		}
		/* if process id and layer 3 id matches */
		if (hh->dinfo == pdss1->p_m_d_l3id)
		{
			pdss1->message_isdn(hh->prim, hh->dinfo, msg->data);
			free_msg(msg);
			return(0);
		}
	}

	/* d-message */
	switch(hh->prim)
	{
		case MGR_SHORTSTATUS | INDICATION:
		case MGR_SHORTSTATUS | CONFIRM:
		switch(hh->dinfo) {
			case SSTATUS_L2_ESTABLISHED:
			goto ss_estab;
			case SSTATUS_L2_RELEASED:
			goto ss_rel;
		}
		break;

		case DL_ESTABLISH | INDICATION:
		case DL_ESTABLISH | CONFIRM:
		ss_estab:
		PDEBUG(DEBUG_ISDN, "establish data link (DL) NT portnum=%d TEI=%d\n", mISDNport->portnum, hh->dinfo);
		if (mISDNport->ptp && hh->dinfo == 0)
		{
			if (mISDNport->l2establish)
			{
				mISDNport->l2establish = 0;
				PDEBUG(DEBUG_ISDN, "the link became active before l2establish timer expiry.\n");
			}
			mISDNport->l2link = 1;
			if (mISDNport->pri);
				mISDNport->l1link = 1; /* this is a hack, we also assume L1 to be active */
		}
		break;

		case DL_RELEASE | INDICATION:
		case DL_RELEASE | CONFIRM:
		ss_rel:
		PDEBUG(DEBUG_ISDN, "release data link (DL) NT portnum=%d TEI=%d\n", mISDNport->portnum, hh->dinfo);
		if (mISDNport->ptp && hh->dinfo == 0)
		{
			mISDNport->l2link = 0;
			time(&mISDNport->l2establish);
			PDEBUG(DEBUG_ISDN, "because we are ptp, we set a l2establish timer.\n");
		}
		break;

		case CC_SETUP | INDICATION:
		/* creating port object */
		SPRINT(name, "%s-%d-in", mISDNport->ifport->interface->name, mISDNport->portnum);
		if (!(pdss1 = new Pdss1(PORT_TYPE_DSS1_NT_IN, mISDNport, name, NULL, 0, 0)))
		{
			RELEASE_COMPLETE_t *release_complete;
			msg_t *dmsg;

			PERROR("FATAL ERROR: cannot create port object.\n");
			dmsg = create_l3msg(CC_RELEASE_COMPLETE | REQUEST, MT_RELEASE_COMPLETE, hh->dinfo, sizeof(RELEASE_COMPLETE_t), mISDNport->ntmode);
			release_complete = (RELEASE_COMPLETE_t *)(dmsg->data + mISDN_HEADER_LEN);
			enc_ie_cause_standalone(mISDNport->ntmode?&release_complete->CAUSE:NULL, dmsg, (mISDNport->ntmode)?LOCATION_PRIVATE_LOCAL:LOCATION_PRIVATE_REMOTE, 47);
			msg_queue_tail(&mISDNport->downqueue, dmsg);
			break;
		}
		pdss1->message_isdn(hh->prim, hh->dinfo, msg->data);
		break;

		case CC_RESUME | INDICATION:
		/* creating port object */
		SPRINT(name, "%s-%d-in", mISDNport->ifport->interface->name, mISDNport->portnum);
		if (!(pdss1 = new Pdss1(PORT_TYPE_DSS1_NT_IN, mISDNport, name, NULL)))
		{
			SUSPEND_REJECT_t *suspend_reject;
			msg_t *dmsg;

			PERROR("FATAL ERROR: cannot create port object.\n");
			dmsg = create_l3msg(CC_SUSPEND_REJECT | REQUEST, MT_SUSPEND_REJECT, hh->dinfo, sizeof(SUSPEND_REJECT_t), mISDNport->ntmode);
			suspend_reject = (SUSPEND_REJECT_t *)(dmsg->data + mISDN_HEADER_LEN);
			enc_ie_cause_standalone(mISDNport->ntmode?&suspend_reject->CAUSE:NULL, dmsg, (mISDNport->ntmode)?1:0, 47);
			msg_queue_tail(&mISDNport->downqueue, dmsg);
			break;
		}
		pdss1->message_isdn(hh->prim, hh->dinfo, msg->data);
		break;

		case CC_RELEASE_CR | INDICATION:
		PDEBUG(DEBUG_ISDN, "%s: unhandled message from stack: call ref released (l3id=0x%x)\n", __FUNCTION__, hh->dinfo);
		break;

		case CC_DISCONNECT | INDICATION:

		// fall throug
		default:
		PDEBUG(DEBUG_ISDN, "%s: unhandled message: prim(0x%x) dinfo(0x%x) msg->len(%d)\n", __FUNCTION__, hh->prim, hh->dinfo, msg->len);
		return(-EINVAL);
	}
	free_msg(msg);
	return(0);
}

/* NOTE: te mode use iframe_t as header */
int stack2manager_te(struct mISDNport *mISDNport, msg_t *msg)
{
	class Port *port;
	class Pdss1 *pdss1;
	iframe_t *frm;
	char name[32];

	if (!msg || !mISDNport)
		return(-EINVAL);
	frm = (iframe_t *)msg->data;
	PDEBUG(DEBUG_ISDN, "prim(0x%x) dinfo(0x%x) msg->len(%d)\n", frm->prim, frm->dinfo, msg->len);

	/* find Port object of type ISDN */
	port = port_first;
	while(port)
	{
		if (port->p_type == PORT_TYPE_DSS1_TE_IN || port->p_type == PORT_TYPE_DSS1_TE_OUT)
		{
			pdss1 = (class Pdss1 *)port;
//PDEBUG(DEBUG_ISDN, "comparing dinfo = 0x%x with l3id 0x%x\n", frm->dinfo, pdss1->p_m_d_l3id);
			/* check out correct stack */
			if (pdss1->p_m_mISDNport == mISDNport)
			/* check out correct id */
			if (frm->dinfo == pdss1->p_m_d_l3id)
			{
				/* found port, the message belongs to */
				break;
			}
		}
		port = port->next;
	}
	if (port)
	{
		pdss1->message_isdn(frm->prim, frm->dinfo, msg->data);
		free_msg(msg);
		return(0);
	}

	/* process new cr (before setup indication) */
//printf("prim = 0x%x, looking for 0x%x\n",frm->prim, (CC_NEW_CR | INDICATION));
	if (frm->prim == (CC_NEW_CR | INDICATION))
	{

		/* creating port object */
		SPRINT(name, "%s-%d-in", mISDNport->ifport->interface->name, mISDNport->portnum);
		if (!(pdss1 = new Pdss1(PORT_TYPE_DSS1_TE_IN, mISDNport, name, NULL)))
		{
			RELEASE_COMPLETE_t *release_complete;
			msg_t *dmsg;

			PERROR("FATAL ERROR: cannot create port object.\n");
			dmsg = create_l3msg(CC_RELEASE_COMPLETE | REQUEST, MT_RELEASE_COMPLETE, frm->dinfo, sizeof(RELEASE_COMPLETE_t), mISDNport->ntmode);
			release_complete = (RELEASE_COMPLETE_t *)(dmsg->data + mISDN_HEADER_LEN);
			enc_ie_cause_standalone(mISDNport->ntmode?&release_complete->CAUSE:NULL, dmsg, (mISDNport->ntmode)?LOCATION_PRIVATE_LOCAL:LOCATION_PRIVATE_REMOTE, 47);
			msg_queue_tail(&mISDNport->downqueue, dmsg);
			free_msg(msg);
			return(0);
		}
		/* l3id will be set from dinfo at message_isdn */
		pdss1->message_isdn(frm->prim, frm->dinfo, msg->data);
		free_msg(msg);
		return(0);
	}

	if (frm->prim == (CC_RELEASE_CR | INDICATION))
	{
		PDEBUG(DEBUG_ISDN, "unhandled message from stack: call ref released (l3id=0x%x)\n", frm->dinfo);
		free_msg(msg);
		return(0);
	}
	PDEBUG(DEBUG_ISDN, "unhandled message: prim(0x%x) dinfo(0x%x) msg->len(%d)\n", frm->prim, frm->dinfo, msg->len);
	return(-EINVAL);
}


/*
 * sending message that were queued during L1 activation
 * or releasing port if link is down
 */
void setup_queue(struct mISDNport *mISDNport, int link)
{
	class Port *port;
	class Pdss1 *pdss1;
	struct message *message;

	if (!mISDNport->ntmode)
		return;

	/* check all port objects for pending message */
	port = port_first;
	while(port)
	{
		if ((port->p_type&PORT_CLASS_mISDN_MASK) == PORT_CLASS_mISDN_DSS1)
		{
			pdss1 = (class Pdss1 *)port;
			if (pdss1->p_m_mISDNport == mISDNport)
			{
				if (pdss1->p_m_d_queue)
				{
					if (link)
					{
						PDEBUG(DEBUG_ISDN, "the L1 became active, so we send queued message for portnum=%d (%s).\n", mISDNport->portnum, pdss1->p_name);
						/* LAYER 1 is up, so we send */
						pdss1->message_setup(pdss1->p_m_d_queue->id_from, pdss1->p_m_d_queue->type, &pdss1->p_m_d_queue->param);
						message_free(pdss1->p_m_d_queue);
						pdss1->p_m_d_queue = NULL;
					} else
					{
						PDEBUG(DEBUG_ISDN, "the L1 became NOT active, so we release port for portnum=%d (%s).\n", mISDNport->portnum, pdss1->p_name);
						message = message_create(pdss1->p_serial, pdss1->p_m_d_queue->id_from, PORT_TO_EPOINT, MESSAGE_RELEASE);
						message->param.disconnectinfo.cause = 27;
						message->param.disconnectinfo.location = LOCATION_PRIVATE_LOCAL;
						message_put(message);
						pdss1->new_state(PORT_STATE_RELEASE);
						pdss1->p_m_delete = 1;
					}
				}
			}
		}
		port = port->next;
	}
}





